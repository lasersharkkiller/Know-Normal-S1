function Get-CheckBulkIpsApiVoid{

    param (
        [Parameter(Mandatory=$true)]
        $process
    )

#Import-Module -Name "..\NewProcsModules\CheckBlockedCountries.psm1"
#Import-Module -Name "..\NewProcsModules\CheckSuspiciousASNs.psm1"

$dstIps = Get-Content output\$($process)-dstIps.json | ConvertFrom-Json
$outputCsv = "$($process)-ip_results_apivoid.csv"
$ApiVoidApi = "" # Replace with your APIVoid key
$apivoid_url = 'https://api.apivoid.com/v2/ip-reputation'
$ApiVoid_headers = @{
        "X-API-Key" = $ApiVoidApi
        "Content-Type" = "application/json"
    }

# Collect enriched results
$results = @()

foreach ($row in $dstIps) {
    $ip = $row.value[0]
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }

    # Clone original row
    $output = $row.PSObject.Copy()
    
    try {
        $ApiVoid_body = @{ ip = $ip } | ConvertTo-Json -Depth 3
        $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body
        
        #Check if it's in the blocked country list
        $existsInCountryBlockList = Get-CheckBlockedCountries -country $response.information.country_name.Trim().ToLower()

        #Check if it's in the suspicious ASNs list
        $existsInASNList = Get-CheckBlockedCountries asn $response.information.asn
<#            if ($existsInCountryBlockList -eq $true) {
                Write-Host "Country: " $response.information.country_name "exists in geo-block list." -ForegroundColor Red
            } else {
                Write-Host "Country: " $response.information.country_name
            }

            
            if ($existsInASNList -eq $true) {
                Write-Host "ISP is in suspicious list: " $response.information.isp -ForegroundColor Yellow
                Write-Host "ASN is in suspicious list: " $response.information.asn -ForegroundColor Yellow
            } else {
                Write-Host "ISP: " $response.information.isp
                Write-Host "ASN: " $response.information.asn
            }

            if ($response.anonymity.is_proxy -eq "true"){
                Write-Host "Is Proxy: " $response.anonymity.is_proxy -ForegroundColor Yellow
            }
            if ($response.anonymity.is_webproxy -eq "true"){
                Write-Host "Is Web Proxy: " $response.anonymity.is_webproxy -ForegroundColor Yellow
            }
            if ($response.anonymity.is_vpn -eq "true"){
                Write-Host "Is VPN: " $response.anonymity.is_vpn -ForegroundColor Yellow
            }
            if ($response.anonymity.is_hosting -eq "true"){
                Write-Host "Is Hosting: " $response.anonymity.is_hosting -ForegroundColor Yellow
            }
            if ($response.anonymity.is_proxy -eq "true"){
                Write-Host "Is Tor: " $response.anonymity.is_tor -ForegroundColor Yellow
            }#>
        if ($response.risk_score.result -eq 100) {
            Write-Host $ip " had a risk score of " $response.risk_score.result -ForegroundColor Red
        } elseif ($response.risk_score.result -gt 0) {
            Write-Host $ip " had a risk score of " $response.risk_score.result -ForegroundColor Yellow
        } else {
    
    }
        # Add enrichment fields
        $output | Add-Member -NotePropertyName RiskScore -NotePropertyValue $response.risk_score.result
        $output | Add-Member -NotePropertyName CountryName -NotePropertyValue $response.information.country_name
        $output | Add-Member -NotePropertyName IsGeoBlocked -NotePropertyValue $existsInCountryBlockList
        $output | Add-Member -NotePropertyName ISP -NotePropertyValue $response.information.isp
        $output | Add-Member -NotePropertyName ASN -NotePropertyValue $response.information.asn
        $output | Add-Member -NotePropertyName IsASNSuspicious -NotePropertyValue $existsInASNList
        $output | Add-Member -NotePropertyName IsProxy -NotePropertyValue $response.anonymity.is_proxy
        $output | Add-Member -NotePropertyName IsWebProxy -NotePropertyValue $response.anonymity.is_webproxy
        $output | Add-Member -NotePropertyName IsVPN -NotePropertyValue $response.anonymity.is_vpn
        $output | Add-Member -NotePropertyName IsHosting -NotePropertyValue $response.anonymity.is_hosting
        $output | Add-Member -NotePropertyName IsTor -NotePropertyValue $response.anonymity.is_tor

    } catch {
    }

    $results += $output
}

# Export enriched results to new CSV
$results | Export-Csv -Path $outputCsv -NoTypeInformation
Write-Host "Done! Results saved to $outputCsv"

}
