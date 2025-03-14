function Get-UnsignedProcsBaseline{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays,
        $os
    )

# Check if output folder exists, if not create it
$folderPath = "output"
$baselineFile = "output\unsignedWinProcsBaseline.json"

if (Test-Path -Path $folderPath) {
    #Do nothing if it exists
} else {
    Write-Output "Folder does not exist. Creating..."
    New-Item -Path $folderPath -ItemType Directory
}

# Check for existing baseline
if ($os -eq "windows") {
    $baselineFile = "output\unsignedWinProcsBaseline.json"
} else {
    $baselineFile = "output\unsignedLinuxProcsBaseline.json"
}

if (Test-Path -Path $baselineFile) {
    # We load the existing baseline in the main function

} else {
    # Else create a baseline

    # Define variables
    $query = "src.process.signedStatus = 'unsigned' and endpoint.os = '$os' and src.process.name matches '^[a-zA-Z0-9_]' and src.process.image.sha256 matches '.' and NOT (src.process.name matches ('.rbf$','.current$','.tmp')) | columns src.process.name, src.process.verifiedStatus, src.process.image.sha256 | group procCount = estimate_distinct (src.process.name) by src.process.name,src.process.verifiedStatus, src.process.image.sha256 | sort +src.process.name | limit 10000"
    $now = (Get-Date)
    #For baseline timeframe go x number of days
    $currentTime = $now.AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $lastDayTime = $now.AddDays(-37).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

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
        Write-Output "Unverified Proc Baseline Query created successfully with Query ID: $queryId"
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
            $queryId = $unverifiedProcResponse.data.queryId
            Write-Output "When retrying the baseline, we are going to wait 60 seconds for the query to start"
            Start-Sleep -Seconds 60
        
            if ($unverifiedProcResponse -ne $null -and $unverifiedProcResponse.data.queryId) {
                $queryId = $unverifiedProcResponse.data.queryId
                Write-Output "Unverified Process Query (Baseline) created successfully with Query ID: $queryId"
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
        $statusResponse.data.data | ConvertTo-Json | Out-File "output\unverifiedProcsBaseline.json"
    } else {
        Write-Output "Query failed or was cancelled. Final status: $status"
    }

}

}
