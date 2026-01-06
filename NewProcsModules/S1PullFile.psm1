function Get-FileFromS1{

    param (
        [Parameter(Mandatory=$true)]
        $headers,
        $baseUrl,
        $queryCreateUrl,
        $pollingInterval,
        $queryDays,
        $newHash,
        $accountid,
        $type = $null
    )

Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Write-Host "newHash: $($newHash)" -ForegroundColor Cyan
# Define variables
if ($type -eq "driver") {
        $query = "tgt.file.sha256  = '$newHash' | columns driver.serviceName, agent.uuid, tgt.file.path, account.id, tgt.file.size, agent.version | group procCount = estimate_distinct (agent.uuid) by driver.serviceName, agent.uuid, tgt.file.path, account.id, tgt.file.size, agent.version | sort -agent.version| limit 200"
} else {
    $query = "src.process.image.sha256 = '$newHash' | columns src.process.name, agent.uuid, src.process.image.path, account.id, src.process.image.size, agent.version | group procCount = estimate_distinct (agent.uuid) by src.process.name, agent.uuid, src.process.image.path, account.id, src.process.image.size, agent.version | sort -agent.version| limit 200"
}
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

$agentuuid = $statusResponse.data.data[0][1]
$imagePath = $statusResponse.data.data[0][2]
$accountId = $statusResponse.data.data[0][3]
$srcProcImageSize = $statusResponse.data.data[0][4]
$agentVersion = $statusResponse.data.data[0][5]

#Track how many devices or locations the hash was seen on
$hashCount = $statusResponse.data.data.Count
$password = "Infected123"

#For Windows agents before version 24.1 both the SHA1 & SHA256 only calculated off the first 30MB
$targetVersion = [version]"24.1"

    if ($agentVersion -lt $targetVersion -and [long]$srcProcImageSize -gt 31457279) {
        #The Power Query sorts by -agent.version, so if the first one is less than 24.1 they all are
        Write-Host "This file is above 30MB and only agents below 24.1, which calculates the incorrect hash. Skipping for now." -Foregroundcolor Yellow
    } else {
        #After getting through a bit chunk of baseline, upping the limits significantly; Note powerquery limit is 200 for api calls
        $currentHost = 0
        if ($hashCount -gt 99) {
            $hashCount = 99
        }

        while ($currentHost -lt $hashCount) {
        
        if ($currentHost -lt $hashCount) {
            Write-Host "Attempting $($currentHost) of $($hashCount). Capped at 100 per hash."
            $agentuuid = $statusResponse.data.data[$currentHost][1]
            $imagePath = $statusResponse.data.data[$currentHost][2]
            $accountId = $statusResponse.data.data[$currentHost][3]
            $srcProcImageSize = $statusResponse.data.data[$currentHost][4]
            $agentVersion = $statusResponse.data.data[$currentHost][5]

            # --- Sometimes File Pathes Use \Device\HarddiskVolumeX\ Instead of C:\ ---
            if ($imagePath -match "^\\Device\\") {
                # Replaces '\Device\HarddiskVolumeX' with 'C:'
                $imagePath = $imagePath -replace "^\\Device\\HarddiskVolume\d+", "C:"
                Write-Host "Converted Device path to: $imagePath" -ForegroundColor Cyan
            }
            # -------------------------

            $findOtherAccountId = "https://usea1-equifax.sentinelone.net/web/api/v2.1/agents?accountIds=$accountId&uuid=$agentuuid"
            $idResponse = Invoke-RestMethod -Uri $findOtherAccountId -Method Get -Headers $headers
            $idforfilepull = $idResponse.data.id

            #Second check: If the host is online proceed
            if ($idResponse.data.isActive -eq "True") {
            $URI = "https://usea1-equifax.sentinelone.net/web/api/v2.1/agents/$idforfilepull/actions/fetch-files"

                $Body = @{
                    data = @{
                        password = $password
                        files = $imagePath
                    }
                }
                $BodyJson = $Body | ConvertTo-Json
                $fileUploadResponse
                try {
                    $fileUploadResponse = Invoke-RestMethod -Uri $URI -Method Post -Headers $headers -Body $BodyJson -ContentType "application/json"
                }
                catch {
                    $fileUploadResponse = $null
                }

                $retryCount = 0
                $maxRetries = 5

                if ($fileUploadResponse.data.success -match "True") {
                    $global:wasEmpty = $False
                    Get-S1Activities -S1GetActivitiesheaders $headers -baseUrl $baseUrl -agentId $idforfilepull -ErrorAction silentlycontinue
                    if ($wasEmpty -eq $False) {
                        return $idforfilepull
                    } else {
                        $currentHost++
                    }
                }

                while ($fileUploadResponse.data.success -notmatch "True") {
                    Start-Sleep -Seconds 20
                    $fileUploadResponse = Invoke-RestMethod -Uri $URI -Method Post -Headers $headers -Body $BodyJson -ContentType "application/json"
            
                    Write-Host "Primary Desc field:"
                    Write-Host $fileUploadResponse.data.primaryDescription

                    if ($fileUploadResponse.data.primaryDescription -match "successfully uploaded") {
                        $global:wasEmpty = $False
                        $wasEmpty = Get-S1Activities -S1GetActivitiesheaders $headers -baseUrl $baseUrl -agentId $idforfilepull -ErrorAction silentlycontinue    
                        if ($wasEmpty -eq $False) {
                            return $idforfilepull #previously break statement
                        } else {
                            $currentHost++
                        }
                    } elseif ($retryCount -ge $maxRetries) {
                        $currentHost++
                        break
                    } else {
                        $retryCount++
                    }
                }
            } else {
                Write-Host "Host uuid $($agentuuid) is offline, skipping." -ForegroundColor Yellow
                $currentHost++
            }
        } elseif ($currentHost -ge $hashCount) {
            return $idforfilepull #previously break statement
        } else {
            $currentHost++
            Write-Host "Next trying $($currentHost) of $($hashCount)"
        }}
    }
}