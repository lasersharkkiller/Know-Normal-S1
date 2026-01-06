function Get-SingleVTZippedSample{
<#
SYNOPSIS
  Ask VirusTotal to build a password-protected ZIP for a given SHA256, download it
#>

  [string]$sha256 = Read-Host -Prompt "Enter SHA256"
  [string]$OutZip = ".\$($sha256).zip"
  [string]$ZipPassword = "infected"
  [int]$PollSeconds = 4
  [int]$PollTimeoutSeconds = 600

# ---------- Helpers ----------
function Get-VTApiKey {
  try { return (Get-Secret -Name 'VT_API_Key_2' -AsPlainText) } catch { }
  if ($env:VT_API_KEY) { return $env:VT_API_KEY }
  return (Read-Host "Enter your VirusTotal API key (visible input)")
}

function VT-GET {
  param([string]$Uri, [hashtable]$Headers)
  return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
}

function VT-POST {
  param([string]$Uri, [hashtable]$Headers, [object]$BodyObject)
  $json = $BodyObject | ConvertTo-Json -Depth 8
  return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $json -ContentType "application/json" -ErrorAction Stop
}

# ---------- Setup ----------
$VTApiKey = Get-VTApiKey
if (-not $VTApiKey) {
  Write-Error "No VT API key provided."
  exit 1
}
$headers = @{ "x-apikey" = $VTApiKey }

# ---------- 1) Create the ZIP job ----------
$createUri = "https://www.virustotal.com/api/v3/intelligence/zip_files"

Write-Host "Submitting hash to VT to build a password-protected ZIP..." -ForegroundColor Cyan

try {
  $createResp = VT-POST -Uri $createUri -Headers $headers -BodyObject @{
    data = @{
      password = $ZipPassword
      hashes   = $sha256
    }
  }
} catch {
  Write-Error "Create ZIP request failed (requires Intelligence/Premium). Raw error: $($_.Exception.Message)"
  exit 1
}

$zipId = $createResp.data.id
if (-not $zipId) {
  Write-Error "No ZIP id returned by VT."
  exit 1
}

Write-Host "ZIP job id: $zipId (status: $($createResp.data.attributes.status))"

# ---------- 2) Poll until finished ----------
$infoUri  = "https://www.virustotal.com/api/v3/intelligence/zip_files/$zipId"
$deadline = (Get-Date).AddSeconds($PollTimeoutSeconds)
$lastInfo = $null

do {
  Start-Sleep -Seconds $PollSeconds
  try {
    $lastInfo = VT-GET -Uri $infoUri -Headers $headers
  } catch {
    Write-Warning "Polling failed once: $($_.Exception.Message)"
    continue
  }

  $status   = $lastInfo.data.attributes.status
  $progress = $lastInfo.data.attributes.progress
  $okCount  = [int]$lastInfo.data.attributes.files_ok
  $errCount = [int]$lastInfo.data.attributes.files_error

  Write-Host ("Status: {0}  Progress: {1}%  OK:{2}  Err:{3}" -f $status, $progress, $okCount, $errCount)

  if ($status -eq "finished") { break }
  if ((Get-Date) -gt $deadline) {
    Write-Error "Timeout waiting for ZIP to finish."
    exit 1
  }
} while ($true)

# ---------- 3) Determine which files actually made it ----------
$okListFromJob     = @()
$failedListFromJob = @()
$usedJobFileList   = $false

try {
  # Some tenants return per-file entries like: data.attributes.files: [{id: <sha256>, status: "ok"|"error"}]
  $filesArray = $lastInfo.data.attributes.files
  if ($filesArray) {
    foreach ($f in $filesArray) {
      if ($f.status -eq "ok")        { $okListFromJob     += $f.id }
      elseif ($f.status -eq "error") { $failedListFromJob += $f.id }
    }
    $usedJobFileList = $true
    Write-Host "Using per-file statuses returned by VT job." -ForegroundColor Green
  }
} catch {
  Write-Warning "Could not parse per-file list from job response: $($_.Exception.Message)"
}

$okSha256s     = @()
$failedSha256s = @()

if ($usedJobFileList) {
  $okSha256s     = $okListFromJob     | Select-Object -Unique
  $failedSha256s = $failedListFromJob | Select-Object -Unique
} else {
  # Fallback: we only know how many succeeded; assume first N validHashes are OK
  Write-Warning "Per-file list not available; falling back to first OK count from valid hashes."
  $okSha256s     = $validHashes | Select-Object -First $okCount
  $failedSha256s = $validHashes | Select-Object -Skip  $okCount
}

# ---------- 4) For OK files, pull metadata and build type stats + DLL entry points ----------
$typeCounts = @{}            # type_description => count
$dllRows    = New-Object System.Collections.Generic.List[object]

function Bump-TypeCount {
  param([string]$desc)
  if ([string]::IsNullOrWhiteSpace($desc)) { $desc = "Unknown" }
  if ($typeCounts.ContainsKey($desc)) { $typeCounts[$desc]++ } else { $typeCounts[$desc] = 1 }
}

foreach ($sha in $okSha256s) {
  try {
    $meta = VT-GET -Uri ("https://www.virustotal.com/api/v3/files/{0}" -f $sha) -Headers $headers
    $attr = $meta.data.attributes

    $typeDesc = $attr.type_description
    Bump-TypeCount -desc $typeDesc

    # Check if DLL and capture entry point (if available)
    $isDll = $false
    if ($typeDesc -match 'dll' -or $typeDesc -match 'DLL') { $isDll = $true }

    $entry = $null
    if ($attr.pe_info) {
      if ($attr.pe_info.entry_point)       { $entry = $attr.pe_info.entry_point }
      elseif ($attr.pe_info.entrypoint)    { $entry = $attr.pe_info.entrypoint }  # alternate field name

      # Heuristic: check IMAGE_FILE_DLL flag (0x2000) in characteristics if present
      if (-not $isDll -and $attr.pe_info.characteristics) {
        try {
          $chars = [int]$attr.pe_info.characteristics
          if ($chars -band 0x2000) { $isDll = $true }
        } catch { }
      }
    }

    if ($isDll) {
      $dllRows.Add([PSCustomObject]@{
        sha256          = $sha
        meaningful_name = $attr.meaningful_name
        entry_point     = $entry
      })
    }
  } catch {
    Write-Warning "Metadata fetch failed for $sha (still considered OK for the ZIP). $($_.Exception.Message)"
  }
}

# ---------- 5) Download the finished ZIP ----------
$dlUri = "https://www.virustotal.com/api/v3/intelligence/zip_files/$zipId/download"
Write-Host "Downloading ZIP -> $OutZip" -ForegroundColor Green

try {
  Invoke-WebRequest -Uri $dlUri -Headers $headers -OutFile $OutZip -UseBasicParsing -ErrorAction Stop
} catch {
  Write-Error "Failed to download ZIP: $($_.Exception.Message)"
  exit 1
}

$zipAbs = (Resolve-Path $OutZip).Path
Write-Host "Saved: $zipAbs" -ForegroundColor Green

# ---------- 6) Emit sidecar reports ----------
$timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

$statsObject = [PSCustomObject]@{
  zip_id                = $zipId
  requested             = $hashes.Count      # original total in file
  submitted_valid       = $validHashes.Count # actually sent to VT for ZIP
  missing_before_submit = $missingHashes.Count
  ok                    = $okSha256s.Count
  error                 = $failedSha256s.Count
  used_job_file_list    = $usedJobFileList
  created_at            = $timestamp
  out_zip               = $zipAbs
}
$statsPath = "$OutZip.stats.json"
$statsObject | ConvertTo-Json -Depth 6 | Out-File -FilePath $statsPath -Encoding UTF8

# File-type breakdown CSV
$typeCsv = $typeCounts.GetEnumerator() |
           Sort-Object -Property Name |
           ForEach-Object {
             [PSCustomObject]@{
               type_description = $_.Key
               count            = $_.Value
             }
           }
$typeCsvPath = "$OutZip.filetypes.csv"
$typeCsv | Export-Csv -Path $typeCsvPath -NoTypeInformation -Encoding UTF8

# DLL entry points CSV
$dllCsvPath = "$OutZip.dll_entrypoints.csv"
if ($dllRows.Count -gt 0) {
  $dllRows | Export-Csv -Path $dllCsvPath -NoTypeInformation -Encoding UTF8
} else {
  # Create an empty file with headers so automation doesn't break
  @([PSCustomObject]@{ sha256 = $null; meaningful_name = $null; entry_point = $null }) |
    Select-Object sha256, meaningful_name, entry_point |
    Export-Csv -Path $dllCsvPath -NoTypeInformation -Encoding UTF8
}

Write-Host "Stats JSON:      $((Resolve-Path $statsPath).Path)"
Write-Host "File types CSV:  $((Resolve-Path $typeCsvPath).Path)"
Write-Host "DLL entries CSV: $((Resolve-Path $dllCsvPath).Path)"
Write-Host $typeCsv
Write-Host "Done." -ForegroundColor Cyan

}