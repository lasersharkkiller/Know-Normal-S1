function Get-FileFromS1{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays,
        $newHash,
        $accountid
    )


# Define variables
$query = "src.process.image.sha256 = '$newHash' | columns src.process.name, agent.uuid, src.process.image.path, account.id | group procCount = estimate_distinct (agent.uuid) by src.process.name, agent.uuid, src.process.image.path, account.id | sort +agent.uuid | limit 20"
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
$newProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($newProcResponse -ne $null -and $newProcResponse.data.queryId) {
    $queryId = $newProcResponse.data.queryId
    Write-Output "New Proc Query created successfully with Query ID: $queryId"
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
        $newProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

        
        if ($newProcResponse -ne $null -and $newProcResponse.data.queryId) {
            $queryId = $newProcResponse.data.queryId
            Write-Output "New Process Query created successfully with Query ID: $queryId"
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
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

#$statusResponse.data.data

$agentuuid = $statusResponse.data.data[0][1]
$accountId = $statusResponse.data.data[0][3]
$imagePath = $statusResponse.data.data[0][2]
#Track how many devices the hash was seen on
$hashCount = $statusResponse.data.Count
$hashCount
$password = "Infected123"

$findOtherAccountId = "https://usea1-equifax.sentinelone.net/web/api/v2.1/agents?accountIds=$accountId&uuid=$agentuuid"
$idResponse = Invoke-RestMethod -Uri $findOtherAccountId -Method Get -Headers $headers
$idforfilepull = $idResponse.data.id

$URI = "https://usea1-equifax.sentinelone.net/web/api/v2.1/agents/$idforfilepull/actions/fetch-files"

$Body = @{
    data = @{
        password = $password
        files = $imagePath
    }
}
$BodyJson = $Body | ConvertTo-Json
$fileUploadResponse = Invoke-RestMethod -Uri $URI -Method Post -Headers $headers -Body $BodyJson -ContentType "application/json"
    if ($idforfilepull -match "^\d") {
        return $idforfilepull
    } else {
        continue
    }
}
