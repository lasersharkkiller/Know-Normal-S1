function Get-S1PullIpsForProcess{

Import-Module -Name ".\bulkipcheck\bulkipcheck.psm1"

$process = Read-Host "What process would you like to query outbound ips for"

# Define variables
$S1apiToken = ''
$baseUrl = 'https://usea1-equifax.company.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"
$query = "src.process.name = $($process) and event.category='ip' and not (dst.ip.address matches ('^172\.[1-3]','^10\.','^192\.168\.','^169\.254\.169\.','^20\.190\.','^40\.126\.','127\.0\.0')) | columns dst.ip.address |group count = count (dst.ip.address) by dst.ip.address | sort +count | limit 5000"
$now = (Get-Date)
$currentTime = $now.AddDays(0).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lastDayTime = $now.AddDays(-14).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $S1apiToken"
    'Content-Type' = 'application/json'
}

# Define the payload for the Power query
$params = @{
    "query" = $query
    'fromDate' = "$($lastDayTime)"
    'toDate' = "$($currentTime)"

} | ConvertTo-Json

# Step 1: Create the Power query
$dstIpsResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($dstIpsResponse -ne $null -and $dstIpsResponse.data.queryId) {
    $queryId = $dstIpsResponse.data.queryId
    Write-Output "Unverified Proc Query created successfully with Query ID: $queryId"
} else {
    Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query."
    continue
}

# Step 2: Poll the query status until it's complete
$queryStatusUrl = "$baseUrl/dv/events/pq-ping?queryId=$($queryId)"
$status = 'running'
while ($status -ne 'FINISHED') {
    try {
        $statusResponse = Invoke-RestMethod -Uri $queryStatusUrl -Method Get -Headers $headers
    }
    catch {
        Write-Host -ForegroundColor red "Could not poll S1, S1 API Issues. Trying again."
        $dstIpsResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

        
        if ($dstIpsResponse -ne $null -and $dstIpsResponse.data.queryId) {
            $queryId = $dstIpsResponse.data.queryId
            Write-Output "Dst Ip Query created successfully with Query ID: $queryId"
        } else {
            Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query."
            continue
        }
    }
    $status = $statusResponse.data.status
    $progress = $statusResponse.data.progress
    
    Write-Output "Current query progress: $progress"
    Start-Sleep -Seconds 5
}

# Step 3: Once the status is finished, retrieve the results
if ($status -eq 'FINISHED') {
    Write-Output "Query completed successfully."
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\$($process)-dstIps.json"

    Get-CheckBulkIpsApiVoid -process $process
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}
