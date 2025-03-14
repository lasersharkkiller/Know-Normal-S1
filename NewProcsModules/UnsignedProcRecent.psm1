function Get-UnsignedProcsRecent{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays,
        $os
    )


# Define variables
$query = "src.process.signedStatus = 'unsigned' and endpoint.os = '$os' and src.process.name matches '^[a-zA-Z0-9_]' and src.process.image.sha256 matches '.' and NOT (src.process.name matches ('.rbf$','.tmp')) | columns src.process.name, src.process.signedStatus, src.process.image.sha256 | group procCount = estimate_distinct (src.process.name) by src.process.name,src.process.signedStatus, src.process.image.sha256 | sort +src.process.name | limit 50000"
Write-Host "Recent procs query"
$query
$now = (Get-Date)
$currentTime = $now.AddDays(0).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lastDayTime = $now.AddDays($queryDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Define the payload for the Power query
$params = @{
    "query" = $query
    'fromDate' = "$($lastDayTime)"
    'toDate' = "$($currentTime)"

} | ConvertTo-Json

# Step 1: Create the Power query
$unsignedProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($unsignedProcResponse -ne $null -and $unsignedProcResponse.data.queryId) {
    $queryId = $unsignedProcResponse.data.queryId
    Write-Output "Unsigned Proc Query created successfully with Query ID: $queryId"
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
        $unsignedProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

        
        if ($unsignedProcResponse -ne $null -and $unsignedProcResponse.data.queryId) {
            $queryId = $unsignedProcResponse.data.queryId
            Write-Output "Unsigned Process Query (Recent) created successfully with Query ID: $queryId"
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
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\unsignedProcsRecent.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}
