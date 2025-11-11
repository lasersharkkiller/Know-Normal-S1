function Get-CheckDevoNetworkAttacks{

# ---- CONFIG ----
$accessToken = Get-Secret -Name 'Devo_Access_Token' -AsPlainText
$apiUrl = "https://apiv2-us.devo.com/search/query" # or apiv2.devo.com if you're in the EU
$outputCsv = ".\nsm\waf-ips_topAttacks.csv"

# ---- HEADERS ----
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

# ---- TIME RANGE ----
$startTime = (Get-Date).AddDays(-1).ToUniversalTime().ToString("o")
$endTime = (Get-Date).ToUniversalTime().ToString("o")

$devoQuery = @"
from my.app.f5.asm
select peek(rawMessage, re('X-Forwarded-For:\s+((?:\d{1,3}\.){3}\d{1,3})'),1) as _XFF
select isnotnull(_XFF) ? _XFF : ipClient as XFF
where 
(ispublic(ip4(XFF)) 
and isnull(lu("WAF_IPs_Allowed","IP",ip4(XFF)))
and isnull(lu("WAF_CIDR_Allowed","CIDR",ip4(XFF)))
), 
//https://equifax.atlassian.net/wiki/spaces/VM/pages/611344215/Approved+Scanning+IPs
weakhas(request, "Qualys")=false,
weakhas(request, "datadog")=false
select XFF
select ip4(XFF) as IP4
select mm2asn(IP4) as asn
select mm2isp(IP4) as isp
select mm2country(IP4) as country
select reputationscore(IP4) as reputationscore
"@

# ---- QUERY BODY ----
$body = @{
    query = $devoQuery
    limit = 1000000
    from = "1d"
} | ConvertTo-Json -Depth 3

# ---- SEND QUERY ----
try {
    $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body
    $response
} catch {
    Write-Error "API request failed: $($_.Exception.Message)"
}

# Export enriched results to new CSV
$response | Export-Csv -Path $outputCsv -NoTypeInformation

$response.object | Group-Object asn | Sort-Object Count | ForEach-Object {
     [PSCustomObject]@{
         asn   = $_.Name
         Count = $_.Count
     }
 } | Format-Table


}
