function Get-CheckThreatGrid {
    #ThreatGrid doesn't do an ip/domain repuation check like I thought it would
    param (
        [Parameter(Mandatory=$true)]
        $artifact,
        $type
    )

    # Threat Grid base API URL
    $ThreatGridApiKey = Get-Secret -Name 'ThreatGrid_API_Key' -AsPlainText
    $baseUrl = "https://panacea.threatgrid.com/api/v2"

    # Build API query URL for observables (IP enrichment)
    if ($type = "IPAddress") {
        $uri = "$baseUrl/search/submissions?api_key=$ThreatGridApiKey&ip=$artifact"
    } elseif ($type = "DomainName") {
        $uri = "$baseUrl/search/submissions?api_key=$ThreatGridApiKey&domain=$artifact"
    } else {
        Write-Host "Did not match an artifact type in the ThreatGrid submission"
        continue
    }

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop

        if ($response.data) {
            foreach ($entry in $response.data) {
                [PSCustomObject]@{
                    SampleID = $entry.item.analysis_id
                    ThreatScore = $entry.item.threat_score
                    Status = $entry.item.status
                    Submitted = $entry.item.ts
                }
            }
        } else {
            Write-Host "No data found for $artifact"
        }
    } catch {
        Write-Host "API query failed: $($_.Exception.Message)"
    }
}