function Get-NewWinPublisherFocused{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays,
        $publisher
    )


# Define variables

$query = "src.process.signedStatus = 'signed' and src.process.verifiedStatus = 'verified' and endpoint.os = 'windows' and src.process.publisher = '$($publisher)'| columns src.process.image.sha256, src.process.name | group pubCount = count (src.process.image.sha256) by src.process.image.sha256, src.process.name | sort +pubCount | limit 10000"
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
        Write-Host -ForegroundColor red "Could not poll S1, S1 API Issues. Waiting, then moving on."
        Start-Sleep -Seconds 60
        break
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
    Write-Output "$($publisher) process SHA-256's:"
    Write-Host $statusResponse.data.data
    
    $newHash = $statusResponse.data.data[0][0]
    $fileName = $statusResponse.data.data[0][1]
    Write-Host "Hash Check: $($newHash)"
    Write-Host "Filename Check: $($fileName)"
    $tryNextPull = $false

    #first check if it already exists in Intezer
    $tryNextPull = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\signedVerifiedProcsBaseline.json" -signatureStatus "SignedVerified" -publisher $publisher -ErrorAction silentlycontinue
    #if it's not in intezer, first try VT (before pulling with S1 - more efficient)
    if ($tryNextPull -eq $false){
        $pullFileFromVT = Get-PullFromVT -Sha256 $newHash -fileName $fileName -ErrorAction silentlycontinue
    }
    #Normally if it wasn't in either next we would try to pull with S1, but for efficiency do separately with named process
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}