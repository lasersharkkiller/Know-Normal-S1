function Get-SignedVerifiedInfo{

    param (
       [Parameter(Mandatory=$true)]
       $srcProcName,
       $timeToBaseline,
       $srcProcStoryline,
       $currentTime,
       $lastDayTime,
       $apiToken
    )



# Define variables
$apiToken = $apiToken
$baseUrl = 'https://site.sentinelone.net/web/api/v2.1'
$query = "src.process.storyline.id = '$srcProcStoryline' and src.process.name = '$srcProcName' | columns src.process.publisher, src.process.signedStatus, src.process.verifiedStatus  | group srcProcCount = count (src.process.publisher) by src.process.publisher,src.process.signedStatus, src.process.verifiedStatus  | sort -srcProcCount | limit 100"
#$siteId = 'your_site_id_here' # Replace with your actual Site ID (optional, depending on the scope of your query)
$pollingInterval = 1 # Interval in seconds to check the status of the query

# Define the endpoint URL for creating the Skylight query
$queryCreateUrl = "$baseUrl/dv/events/pq
"

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

# Define the payload for the Power query
$params = @{
    "query" = $query
    'fromDate' = "$($lastDayTime)"
    'toDate' = "$($currentTime)"

} | ConvertTo-Json

# Step 1: Create the Power query
$parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($parentProcResponse -ne $null -and $parentProcResponse.data.queryId) {
    $queryId = $parentProcResponse.data.queryId
    Write-Output "Signed / Verified Query created successfully with Query ID: $queryId"
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
        Write-Host -ForegroundColor red "Could not get alert signature info. S1 API Issues. Trying again in 60 seconds."
        Start-Sleep -Seconds 60
        $parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params
        $queryStatusUrl = "$baseUrl/dv/events/pq-ping?queryId=$($queryId)"
        
        if ($parentProcResponse -ne $null -and $parentProcResponse.data.queryId) {
            $queryId = $parentProcResponse.data.queryId
            Write-Output "Signed / Verified Query created successfully with Query ID: $queryId"
        } else {
            Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query."
            continue
        }
    }
    $status = $statusResponse.data.status
    $progress = $statusResponse.data.progress
    
    Write-Output "Current query progress: $progress"
    Start-Sleep -Seconds $pollingInterval
}

# Step 3: Once the status is finished, retrieve the results
if ($status -eq 'FINISHED') {
    Write-Output "Query completed successfully."
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\ProcSignedVerifiedInfo.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}
