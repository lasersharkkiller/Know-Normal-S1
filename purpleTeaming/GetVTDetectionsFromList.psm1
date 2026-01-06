<#
  Module: GetVTDetectionsFromList

  Public function:
      Get-VTDetectionsFromList -InputPath <file> [-OutputRoot <dir>] [-RateDelayMs <int>] [-ApiKey <key>]

  Input file:
    - TXT: hashes / IOCs, one per line (we extract only hex hashes).
    - CSV: any columns, but we only use rows where Type == 'Hash'.
      * Hash is taken from the 'IOC' column if present.
      * If 'IOC' is not present, first non-Type column is used.

  Only hex hashes of length 32, 40, or 64 are used (MD5 / SHA1 / SHA256).
  For each hash, we query VT /files/{hash} and:
    - attributes.crowdsourced_yara_results
    - attributes.sigma_analysis_results

  For each YARA ruleset, we call /yara_rulesets/{ruleset_id} and save rule text.
  For each Sigma rule, we call /sigma_rules/{rule_id} and save the YAML rule text.

  Output structure:
    <OutputRoot>\Yara\<hash>\*.yara
    <OutputRoot>\Sigma\<hash>\*.yml
#>

# ==================== Internal helpers ====================

function Get-VTApiKeyInternal {
    param([string]$ApiKeyFromParam)

    if ($ApiKeyFromParam) { return $ApiKeyFromParam }

    try {
        $k = Get-Secret -Name 'VT_API_Key_1' -AsPlainText
        if ($k) { return $k }
    } catch { }

    if ($env:VT_API_KEY) { return $env:VT_API_KEY }

    $k = Read-Host 'Enter your VirusTotal API key (visible input)'
    if ([string]::IsNullOrWhiteSpace($k)) { return $null }
    return $k
}

function Get-HashesFromInputFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw ('Input not found: {0}' -f $Path)
    }

    # Only MD5 (32), SHA1 (40), SHA256 (64)
    $hashRegex = '[0-9A-Fa-f]{32,64}'
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $results = New-Object System.Collections.Generic.List[string]

    if ($ext -eq '.csv') {
        $rows = Import-Csv -Path $Path

        foreach ($row in $rows) {
            # Require a Type column, and it must be 'Hash' (case-insensitive)
            if ($row.PSObject.Properties.Name -contains 'Type') {
                $typeValue = [string]$row.Type
                if ($typeValue.Trim().ToLower() -ne 'hash') {
                    continue
                }
            } else {
                # If there is no Type column, skip this row entirely
                continue
            }

            # Prefer an 'IOC' column if it exists
            $candidate = $null
            if ($row.PSObject.Properties.Name -contains 'IOC') {
                $candidate = [string]$row.IOC
            } else {
                # Fallback: take first non-Type column as candidate
                foreach ($prop in $row.PSObject.Properties) {
                    if ($prop.Name -eq 'Type') { continue }
                    $candidate = [string]$prop.Value
                    break
                }
            }

            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

            $candidate = $candidate.Trim()
            if ($candidate -match $hashRegex -and ($candidate.Length -in 32,40,64)) {
                $results.Add($candidate.ToLower())
            }
        }
    }
    else {
        # TXT (or other) – scan each line for hashes
        $lines = Get-Content -Path $Path -ErrorAction Stop
        foreach ($line in $lines) {
            $val = [string]$line
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            $matches = [regex]::Matches($val, $hashRegex)
            foreach ($m in $matches) {
                $h = $m.Value
                if ($h.Length -in 32,40,64) {
                    $results.Add($h.ToLower())
                }
            }
        }
    }

    $unique = $results | Select-Object -Unique

    if ($unique.Count -eq 0) {
        throw ('No valid MD5/SHA1/SHA256 hashes (Type=Hash) found in {0}' -f $Path)
    }

    return $unique
}

function Invoke-VTGetInternal {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [int]$DelayMs = 0
    )

    try {
        $resp = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
        if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
        return $resp
    } catch {
        $status = $null
        if ($_.Exception -and $_.Exception.Response) {
            try { $status = $_.Exception.Response.StatusCode.value__ } catch { }
        }
        $msg = ('VT GET failed ({0}) for {1} : {2}' -f $status, $Uri, $_.Exception.Message)
        Write-Warning $msg
        return $null
    }
}

function Ensure-DirInternal {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function New-SafeFileNameInternal {
    param([string]$Name)

    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = "[{0}]" -f [Regex]::Escape($invalid)
    $safe = [Regex]::Replace($Name, $pattern, "_")

    if ($safe.Length -gt 120) {
        $safe = $safe.Substring(0, 120)
    }
    return $safe
}

# ==================== YARA / Sigma helpers ====================

function Get-VTDetectionsForHashInternal {
    param(
        [string]$Hash,
        [hashtable]$Headers,
        [int]$DelayMs = 0
    )

    $uri = 'https://www.virustotal.com/api/v3/files/{0}' -f $Hash
    $resp = Invoke-VTGetInternal -Uri $uri -Headers $Headers -DelayMs $DelayMs
    if (-not $resp) { return $null }

    $attr = $resp.data.attributes
    return [PSCustomObject]@{
        Hash         = $Hash
        FileInfo     = $resp
        YaraResults  = $attr.crowdsourced_yara_results
        SigmaResults = $attr.sigma_analysis_results
    }
}

function Save-YaraRulesInternal {
    param(
        [string]$Hash,
        [Array]$YaraResults,
        [string]$YaraRoot,
        [hashtable]$Headers,
        [int]$DelayMs = 0
    )

    if (-not $YaraResults -or $YaraResults.Count -eq 0) {
        Write-Verbose ("[{0}] No crowdsourced_yara_results." -f $Hash)
        return
    }

    $hashDir = Join-Path $YaraRoot $Hash
    Ensure-DirInternal -Path $hashDir

    # group by ruleset_id so we only fetch each once per hash
    $groups = $YaraResults | Group-Object -Property ruleset_id

    foreach ($g in $groups) {
        $rulesetId = $g.Name
        if (-not $rulesetId) { continue }

        $uri = 'https://www.virustotal.com/api/v3/yara_rulesets/{0}' -f $rulesetId
        $resp = Invoke-VTGetInternal -Uri $uri -Headers $Headers -DelayMs $DelayMs
        if (-not $resp) {
            Write-Warning ("[{0}] Failed to fetch YARA ruleset {1}" -f $Hash, $rulesetId)
            continue
        }

        $attr = $resp.data.attributes
        $rules = $attr.rules
        if (-not $rules) {
            Write-Warning ("[{0}] YARA ruleset {1} contained no rules text." -f $Hash, $rulesetId)
            continue
        }

        $rsName = if ($attr.name) { $attr.name } else { $rulesetId }
        $fileName = New-SafeFileNameInternal ("{0}_{1}.yara" -f $Hash, $rsName)
        $outPath = Join-Path $hashDir $fileName

        $rules | Out-File -FilePath $outPath -Encoding UTF8
        Write-Host ("[{0}] YARA ruleset {1} ({2}) -> {3}" -f $Hash, $rsName, $rulesetId, $outPath)
    }
}

function Save-SigmaRulesInternal {
    param(
        [string]$Hash,
        [Array]$SigmaResults,
        [string]$SigmaRoot,
        [hashtable]$Headers,
        [int]$DelayMs = 0
    )

    if (-not $SigmaResults -or $SigmaResults.Count -eq 0) {
        Write-Verbose ("[{0}] No sigma_analysis_results." -f $Hash)
        return
    }

    $hashDir = Join-Path $SigmaRoot $Hash
    Ensure-DirInternal -Path $hashDir

    # each result should have a rule_id; dedup them
    $ruleIds = $SigmaResults |
        Where-Object { $_.rule_id } |
        Select-Object -ExpandProperty rule_id -Unique

    foreach ($ruleId in $ruleIds) {
        $uri = 'https://www.virustotal.com/api/v3/sigma_rules/{0}' -f $ruleId
        $resp = Invoke-VTGetInternal -Uri $uri -Headers $Headers -DelayMs $DelayMs
        if (-not $resp) {
            Write-Warning ("[{0}] Failed to fetch Sigma rule {1}" -f $Hash, $ruleId)
            continue
        }

        $attr = $resp.data.attributes
        # VT Sigma rule object typically has 'rule' string containing YAML
        $ruleText = $attr.rule
        if (-not $ruleText) {
            Write-Warning ("[{0}] Sigma rule {1} had no 'rule' text." -f $Hash, $ruleId)
            continue
        }

        $title = if ($attr.title) { $attr.title } elseif ($attr.name) { $attr.name } else { $ruleId }
        $fileName = New-SafeFileNameInternal ("{0}_{1}.yml" -f $Hash, $title)
        $outPath = Join-Path $hashDir $fileName

        $ruleText | Out-File -FilePath $outPath -Encoding UTF8
        Write-Host ("[{0}] Sigma rule {1} ({2}) -> {3}" -f $Hash, $title, $ruleId, $outPath)
    }
}

# ==================== Public function ====================

function Get-VTDetectionsFromList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath,

        [string]$OutputRoot = ".\VT_Detections",

        [int]$RateDelayMs = 400,

        [string]$ApiKey
    )

    $vtKey = Get-VTApiKeyInternal -ApiKeyFromParam $ApiKey
    if (-not $vtKey) {
        Write-Error 'No VT API key available.'
        return
    }

    $headers = @{ 'x-apikey' = $vtKey }

    $hashes = Get-HashesFromInputFile -Path $InputPath
    Write-Host ("Loaded {0} unique hashes (Type=Hash) from {1}" -f $hashes.Count, $InputPath) -ForegroundColor Cyan

    # Prepare root dirs
    $root = Resolve-Path -Path $OutputRoot -ErrorAction SilentlyContinue
    if (-not $root) {
        Ensure-DirInternal -Path $OutputRoot
        $root = Resolve-Path -Path $OutputRoot
    }
    $rootPath = $root.Path

    $yaraRoot  = Join-Path $rootPath 'Yara'
    $sigmaRoot = Join-Path $rootPath 'Sigma'
    Ensure-DirInternal -Path $yaraRoot
    Ensure-DirInternal -Path $sigmaRoot

    $index = 0
    foreach ($hash in $hashes) {
        $index++
        Write-Host ("[{0}/{1}] Processing {2} ..." -f $index, $hashes.Count, $hash)

        $det = Get-VTDetectionsForHashInternal -Hash $hash -Headers $headers -DelayMs $RateDelayMs
        if (-not $det) { continue }

        if ($det.YaraResults) {
            Save-YaraRulesInternal -Hash $hash -YaraResults $det.YaraResults -YaraRoot $yaraRoot -Headers $headers -DelayMs $RateDelayMs
        } else {
            Write-Host ("[{0}] No crowdsourced_yara_results." -f $hash)
        }

        if ($det.SigmaResults) {
            Save-SigmaRulesInternal -Hash $hash -SigmaResults $det.SigmaResults -SigmaRoot $sigmaRoot -Headers $headers -DelayMs $RateDelayMs
        } else {
            Write-Host ("[{0}] No sigma_analysis_results." -f $hash)
        }
    }

    Write-Host ("Done. Output written to: {0}" -f $rootPath) -ForegroundColor Green
}

Export-ModuleMember -Function Get-VTDetectionsFromList