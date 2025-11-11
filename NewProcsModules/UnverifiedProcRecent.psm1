function Get-UnverifiedProcsRecent{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays
    )


# Define variables
#I am limiting my baseline to less than 120MB for now
$query = "src.process.verifiedStatus = 'unverified' and src.process.name matches '^[a-zA-Z0-9_]' and src.process.image.sha256 matches '.' and NOT (src.process.name matches ('.rbf$','.current$','.tmp') or site.name contains 'purple') src.process.image.size < 124857600 | columns src.process.name, src.process.verifiedStatus, src.process.image.sha256, src.process.publisher | group procCount = estimate_distinct (src.process.name) by src.process.name,src.process.verifiedStatus, src.process.image.sha256, src.process.publisher | sort +src.process.name | limit 10000"
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
$unverifiedProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($unverifiedProcResponse -ne $null -and $unverifiedProcResponse.data.queryId) {
    $queryId = $unverifiedProcResponse.data.queryId
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
        $unverifiedProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

        
        if ($unverifiedProcResponse -ne $null -and $unverifiedProcResponse.data.queryId) {
            $queryId = $unverifiedProcResponse.data.queryId
            Write-Output "Unverified Process Query (Recent) created successfully with Query ID: $queryId"
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
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\unverifiedProcsRecent.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}
