function Get-ProcessBulkIps{

Import-Module -Name ".\NewProcsModules\CheckBlockedCountries.psm1"
Import-Module -Name ".\NewProcsModules\CheckSuspiciousASNs.psm1"

$inputCsv = ".\nsm\input_ips.csv" # CSV with columns like: ip, source, timestamp, etc.
$outputCsv = ".\nsm\ip_results_apivoid.csv"
$ApiVoidApi = "" # Replace with your APIVoid key
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

# Read CSV input
$rows = Import-Csv -Path $inputCsv

foreach ($row in $rows) {
    $ip = $row.ip.Trim()
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }

    # Clone original row
    $output = $template.PSObject.Copy()
    
    try {
        $ApiVoid_body = @{ ip = $ip } | ConvertTo-Json -Depth 3
        $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body

        # Add enrichment fields
        $output.ip =  $row.ip
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

    #Check if it's in the blocked country list
    $existsInCountryBlockList = Get-CheckBlockedCountries -country $response.information.country_name
            
    #Check if it's in the suspicious ASNs list
    $existsInASNList = Get-CheckSuspiciousASNs -asn $response.information.asn
    
    $output.IsGeoBlocked = $existsInCountryBlockList
    $output.IsASNSuspicious = $existsInASNList
        

    $results += $output
}

# Export enriched results to new CSV
$results | Export-Csv -Path $outputCsv -NoTypeInformation

#Group Count By Risk Score
$results | Group-Object RiskScore | Sort-Object Count | ForEach-Object {
    [PSCustomObject]@{
        RiskScore   = $_.Name
        Count       = $_.Count
    }
} | Format-Table

#Group By GeoBlocked Countries
$results | Where-Object { $_.IsGeoBlocked -eq $true} | 
    Group-Object CountryName | Sort-Object Count |
    ForEach-Object {
        [PSCustomObject]@{
        Country   = $_.Name
        Count     = $_.Count
    }
    }

}
