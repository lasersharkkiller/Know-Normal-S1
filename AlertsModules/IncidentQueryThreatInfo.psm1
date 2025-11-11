function Get-ThreatExtraInfo{

    param (
        [Parameter(Mandatory=$true)]
        $endpointName,
        $fileSha1,
        $currentTime,
        $lastDayTime,
        $apiToken
    )


# Define variables
$apiToken = $apiToken
$baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
$query = "endpoint.name = '$endpointName' and tgt.file.sha1 = '$fileSha1' | columns src.process.pid, src.process.name, src.process.image.path, src.process.parent.name, src.process.storyline.id, src.process.signedStatus, src.process.publisher, src.process.verifiedStatus | group pidCount = count (src.process.pid) by src.process.pid, src.process.name, src.process.image.path, src.process.parent.name, src.process.storyline.id, src.process.signedStatus, src.process.publisher, src.process.verifiedStatus"
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
    Write-Output "Threat Extra Info Query created successfully with Query ID: $queryId"
} else {
    Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query. Trying again"
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
        Write-Host -ForegroundColor red "Could not get parent procs for the enterprise (surrounding the process from the alert). S1 API Issues. Trying again in 60 seconds."
        Start-Sleep -Seconds 60
        $parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params
        $queryStatusUrl = "$baseUrl/dv/events/pq-ping?queryId=$($queryId)"
        
        if ($parentProcResponse -ne $null -and $parentProcResponse.data.queryId) {
            $queryId = $parentProcResponse.data.queryId
            Write-Output "Threat Extra Info Query (for the alert) created successfully with Query ID: $queryId"
            $statusResponse = Invoke-RestMethod -Uri $queryStatusUrl -Method Get -Headers $headers
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
    #$statusResponse.data.data | ForEach-Object { $_.GetValue(0);$_.GetValue(1) } | Export-Csv -Path "parentProcs.csv"
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\incidentQueryThreatInfo.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}
