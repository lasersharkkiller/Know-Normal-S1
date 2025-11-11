function Get-CheckBulkIpsApiVoid{

    param (
        [Parameter(Mandatory=$true)]
        $process
    )

Import-Module -Name ".\NewProcsModules\CheckBlockedCountries.psm1"
Import-Module -Name ".\NewProcsModules\CheckSuspiciousASNs.psm1"
Import-Module -Name ".\nsm\S1IPtoDNS.psm1"

#$dstIps = Get-Content output\$($process)-dstIps.json | ConvertFrom-Json
$dstIps = Import-Csv -Path nsm\svc_now_external.csv | Select-Object -ExpandProperty dst.ip.address
$outputCsv = "$($process)-ip_results_apivoid.csv"
$ApiVoidApi = Get-Secret -Name 'APIVoid_API_Key' -AsPlainText
$apivoid_url = 'https://api.apivoid.com/v2/ip-reputation'
$ApiVoid_headers = @{
        "X-API-Key" = $ApiVoidApi
        "Content-Type" = "application/json"
    }

# Collect enriched results
$results = @()

$template = [PSCustomObject]@{
    ip              = ''
    RiskScore       = ''
    Country         = ''
    CountryName     = ''
    IsGeoBlocked    = ''
    ISP             = ''
    ASN             = ''
    IsASNSuspicious = ''
    IsProxy         = ''
    IsWebProxy      = ''
    IsVPN           = ''
    IsHosting       = ''
    IsTor           = ''
}

foreach ($row in $dstIps) {
    $ip = $row.value[0]
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }

    # Clone original row
    $output = $template.PSObject.Copy()
    
    try {
        $ApiVoid_body = @{ ip = $ip } | ConvertTo-Json -Depth 3
        $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body
    
<#            
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
            Write-Host "Pulling the DNS request related to $($ip) from $($process)"
            
            Get-S1IPtoDNS -process $process -ip $ip 

        } elseif ($response.risk_score.result -gt 0) {
            Write-Host $ip " had a risk score of " $response.risk_score.result -ForegroundColor Yellow
        } else {
    
    }
        # Add enrichment fields
        $output.ip =  $ip
        $output.RiskScore = $response.risk_score.result
        $output.CountryName = $response.information.country_name
        $output.ISP = $response.information.isp
        $output.ASN = $response.information.asn
        $output.IsProxy = $response.anonymity.is_proxy
        $output.IsWebProxy = $response.anonymity.is_webproxy
        $output.IsVPN = $response.anonymity.is_vpn
        $output.IsHosting = $response.anonymity.is_hosting
        $output.IsTor = $response.anonymity.is_tor

    } catch {
    }

    #Check if it's in the blocked country or sus ASN list
    $existsInCountryBlockList = Get-CheckBlockedCountries -country $response.information.country_name.Trim().ToLower()
    $existsInASNList = Get-CheckSuspiciousASNs -asn $response.information.asn

    $output.IsGeoBlocked = $existsInCountryBlockList
    $output.IsASNSuspicious = $existsInASNList

    if ($existsInCountryBlockList -eq $true) {
        Write-Host $ip "in Country: " $response.information.country_name "exists in geo-block list." -ForegroundColor Red
        Get-S1IPtoDNS -process $process -ip $ip
    } else {
                
    }

    if ($existsInASNList -eq $true) {
        Write-Host $ip " 's ISP is in suspicious list: " $response.information.isp " ASN: " $response.information.asn -ForegroundColor Yellow
    } else {
        
    }

    $results += $output
}

# Export enriched results to new CSV
$results | Export-Csv -Path $outputCsv -NoTypeInformation
Write-Host "Done! Results saved to $outputCsv"

}
