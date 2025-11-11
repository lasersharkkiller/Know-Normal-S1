function Get-SpecificProcPQ{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays,
        $procName
    )


# Define variables
#I am limiting my baseline to less than 30MB for now, bc anything 30MB+ S1 does not calculate the hash correctly for
#Note I am also excluding purple scope
$query = "src.process.name = '$procName' and src.process.image.sha256 matches '.' and NOT (src.process.name matches ('.rbf$','.tmp') or site.name contains 'purple') | columns src.process.name, src.process.signedStatus,  src.process.image.sha256, src.process.verifiedStatus, endpoint.os, src.process.publisher  | group procCount = count (src.process.name) by src.process.name, src.process.signedStatus, src.process.image.sha256, src.process.verifiedStatus, endpoint.os, src.process.publisher | sort +procCount | limit 10000"
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
$specificProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($specificProcResponse -ne $null -and $specificProcResponse.data.queryId) {
    $queryId = $specificProcResponse.data.queryId
    Write-Output "Proc Query created successfully with Query ID: $queryId"
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
        $specificProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

        
        if ($specificProcResponse -ne $null -and $specificProcResponse.data.queryId) {
            $queryId = $specificProcResponse.data.queryId
            Write-Output "Process Query (Recent) created successfully with Query ID: $queryId"
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
    $statusResponse.data.data | ConvertTo-Json | Out-File "output\specificProcQuery.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}
