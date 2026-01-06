function Get-CertGapHuntVT{

$VTApi = Get-Secret -Name 'VT_API_Key_1' -AsPlainText
$VT_headers = @{
        "x-apikey" = $VTApi
        "Content-Type" = "application/json"
    }

$baseUrl = "https://www.virustotal.com/api/v3/intelligence/search?query="

#Note this looks for sample where certs have been revoked, but the main metadata fields which are somehow tied to the tags do not reflect revoked or expired
[int]$PageSize = 300
[int]$MaxItems = 300
[string]$Query = 'signature%3A%22Trust%20for%20this%20certificate%20or%20one%20of%20the%20certificates%20in%20the%20certificate%20chain%20has%20been%20revoked.%22%20positives%3A5%2B%20NOT%20tag%3A%22revoked-cert%22%20NOT%20tag%3A%22known-distributor%22%20NOT%20tag%3A%22invalid-signature%22&order=first_submission_date&limit='+$($MaxItems)+'&descriptors_only=false'
[string]$OutputFolder = "output"
$fileName = "vt_signer_breakdown.csv"
$outputFile = Join-Path $OutputFolder "$fileName"


$certGapHuntUri = "$($baseUrl)$($Query)&limit=$($MaxItems)&descriptors_only=false"
try {
        $certGapHuntResponse = Invoke-RestMethod -Uri $certGapHuntUri -Headers $VT_headers -Method Get
    }
catch {
    # Friendly error handling
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        Write-Host "File not found on VirusTotal (404)."
        return $false
    } elseif ($_.Exception.Response.StatusCode.value__ -eq 403) {
        Write-Host "Access denied. Make sure your API key is for VT Intelligence (Premium)."
        return $false
    } elseif ($_.Exception.Response.StatusCode.value__ -eq 429) {
        Write-Host "Rate limit exceeded."
        return $false
    } else {
        Write-Host " Error: $($_.Exception.Message) ."
        return $false
    }
}

#$certGapHuntResponse.data[0].attributes.sha256
#$certGapHuntResponse.data[0].attributes.signature_info
#$certGapHuntResponse.data[0].attributes.tags
#$certGapHuntResponse.data[0].attributes.crowdsourced_yara_results
#$certGapHuntResponse.data[0].attributes.popular_threat_classification.popular_threat_category
#$certGapHuntResponse.data[0].attributes.last_analysis_stats.malicious

#$certGapHuntResponse.data[0].attributes.signature_info."signers details".verified -eq 'Signed'
#BUT...
#$certGapHuntResponse.data[0].attributes.signature_info."signers details"  #-->
#.status : This certificate or one of the certificates in the certificate chain is not time valid.
#.name , ."serial number", ".thumbprint"
#$certGapHuntResponse.data[0].attributes.signature_info."counter signers details"  #-->
#.status : This certificate or one of the certificates in the certificate chain is not time valid., Trust for this certificate or one of the certificates in the certificate chain has been revoked

# --- Build flattened list of signers/countersigners with suspect statuses ---
$revokedPatterns = '(revoked|expired|not time valid)' # case-insensitive by default

$rows = foreach ($item in $certGapHuntResponse.data) {
    $attr = $item.attributes
    $sha = $attr.sha256
    $sig = $attr.signature_info

    # Helper to safely iterate collections (even if null or single object)
    function _asArray($x) { if ($null -eq $x) { @() } else { @($x) } }

    foreach ($sd in _asArray($sig.'signers details')) {
        if ($sd.status -match $revokedPatterns) {
            [pscustomobject]@{
                Type = 'Signer'
                Name = $sd.name
                Serial = $sd.'serial number'
                Thumbprint = $sd.thumbprint
                Status = $sd.status
                SHA256 = $sha
            }
        }
    }

    foreach ($csd in _asArray($sig.'counter signers details')) {
        if ($csd.status -match $revokedPatterns) {
            [pscustomobject]@{
                Type = 'CounterSigner'
                Name = $csd.name
                Serial = $csd.'serial number'
                Thumbprint = $csd.thumbprint
                Status = $csd.status
                SHA256 = $sha
            }
        }
    }
}

# --- Group by signer identity (prefer Thumbprint; fall back to Name+Serial) ---
$rowsWithKey = $rows | ForEach-Object {
    $key = if ($_.Thumbprint) { "TP::$($_.Thumbprint)" }
           elseif ($_.Name -or $_.Serial) { "NS::$($_.Name)|$($_.Serial)" }
           else { "UNK::" }
    $_ | Add-Member -NotePropertyName GroupKey -NotePropertyValue $key -PassThru
}

$grouped = $rowsWithKey |
    Group-Object -Property GroupKey |
    Sort-Object Count -Descending

# --- Produce a tidy summary table (and CSV) ---
$summary = $grouped | ForEach-Object {
    $g = $_.Group
    [pscustomobject]@{
        Count = $_.Count
        Thumbprint = ($g | Select-Object -First 1 -Expand Thumbprint)
        Name = ($g | Select-Object -First 1 -Expand Name)
        Serial = ($g | Select-Object -First 1 -Expand Serial)
        Types = ($g.Type | Sort-Object -Unique) -join ', '
        Unique_Statuses = ($g.Status | Sort-Object -Unique) -join ' | '
        Example_SHA256s = ($g.SHA256 | Select-Object -Unique -First 5) -join '; '
        Total_Unique_Samples = ($g.SHA256 | Select-Object -Unique).Count
    }
}

# On-screen preview
$summary | Format-Table -AutoSize

# Persist to CSV (same folder/filename you set)
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
$summary | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outputFile

Write-Host "Saved signer breakdown to $outputFile"

}