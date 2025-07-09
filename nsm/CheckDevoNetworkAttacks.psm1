function Get-CheckDevoNetworkAttacks{

# ---- CONFIG ----
$accessToken = "" # Provided by admin
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
from waf-table
select top attacks syntax
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
