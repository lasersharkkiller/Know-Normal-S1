function Get-CheckC6G-ip{

# ---- CONFIG ----
$c6g_clientId = "equifax-om105wokpc"
$c6g_apikey = Get-Secret -Name 'Cyber6Gil_API_Key'
$apiGetTokenUrl = "https://api.cybersixgill.com/auth/token"
$iocEnrichUrl = "https://api.cybersixgill.com/ioc/enrich"
$outputCsv = ".\output\c6g\c6g-ipEnrichment.csv"

# ---- GET TOKEN HEADERS ----
$getTokenHeaders = @{
    "Content-Type" = "application/x-www-form-urlencoded"
    "Cache-Control" = "no-cache"
}

# ---- GET TOKEN BODY ----
$getTokenBody = @{
    client_id = $c6g_clientId
    client_secret = $c6g_apikey
    grant_type = "client_credentials"
}

# ---- ATTEMPT GET TOKEN QUERY ----
try {
    $getTokenAttempt = Invoke-RestMethod -Uri $apiGetTokenUrl -Method Post -Headers $getTokenHeaders -Body $getTokenBody
    $getTokenAttempt
} catch {
    Write-Error "API request failed: $($_.Exception.Message)"
}
$c6gToken = $getTokenAttempt.access_token

# ---- HEADERS ----
$headers = @{
    "Content-Type" = "application/json"
    "Cache-Control" = "no-cache"
    "X-Channel-Id" = "d5cd46c205c20c87006b55a18b106428"
    "Authorization" = "Bearer $c6gToken"
}

# ---- TIME RANGE ----
#$startTime = (Get-Date).AddDays(-1).ToUniversalTime().ToString("o")
#$endTime = (Get-Date).ToUniversalTime().ToString("o")

# ---- QUERY BODY ----
$body = @{
    ioc_type = "ip"
    ioc_value = "172.64.149.23"
    limit = 50
    skip = 0
} | ConvertTo-Json -Depth 3

# ---- SEND QUERY ----
try {
    $response = Invoke-RestMethod -Uri $iocEnrichUrl -Method Post -Headers $headers -Body $body
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
