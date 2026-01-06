function Get-NewWinPublishersRecent{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays
    )


# Define variables
#
$query = "src.process.signedStatus = 'signed' and src.process.verifiedStatus = 'verified' endpoint.os = 'windows'| columns src.process.publisher | group pubCount = count (src.process.publisher) by src.process.publisher | sort +pubCount | limit 10000"
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
$WinPubProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($WinPubProcResponse -ne $null -and $WinPubProcResponse.data.queryId) {
    $queryId = $WinPubProcResponse.data.queryId
    Write-Output "SignedVerified Proc Query created successfully with Query ID: $queryId"
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
        $WinPubProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params
        
        if ($WinPubProcResponse -ne $null -and $WinPubProcResponse.data.queryId) {
            $queryId = $WinPubProcResponse.data.queryId
            Write-Output "SignedVerified Process Query (Recent) created successfully with Query ID: $queryId"
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
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\winPublishersRecent.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}