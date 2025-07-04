function Get-CheckDevoNetworkAttacks{

param (
        [Parameter(Mandatory=$true)]
        $artifacts,
        $type
    )

$devoToken = ""

$devoQuery = @"
query...
"@

$devoRegion = "https://us.devo.com"
$apiEndpoint = "$devoRegion/query"

# === BUILD REQUEST BODY ===
$body = @{
    query = $devoQuery
    mode = "sql"
    timeout = 60
    limit = 100
} | ConvertTo-Json -Depth 5

# === SEND REQUEST ===
$response = Invoke-RestMethod -Uri $apiEndpoint `
    -Method Post `
    -Headers @{ Authorization = "Bearer $devoToken" } `
    -ContentType "application/json" `
    -Body $body

# === OUTPUT RESULTS ===
$response.rows | Format-Table -AutoSize

}
