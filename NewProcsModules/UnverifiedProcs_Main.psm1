function Get-UnverifiedProcs{

Import-Module -Name ".\NewProcsModules\UnverifiedProcBaseline.psm1"
Import-Module -Name ".\NewProcsModules\UnverifiedProcRecent.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\S1PullFile.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"

# Define variables
$apiToken = 'eyJraWQiOiJ1cy1lYXN0LTEtcHJvZC0wIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJpYW4ubm9ydG9uQGVxdWlmYXguY29tIiwiaXNzIjoiYXV0aG4tdXMtZWFzdC0xLXByb2QiLCJkZXBsb3ltZW50X2lkIjoiNjc5NDgiLCJ0eXBlIjoidXNlciIsImV4cCI6MTc1MDUxMzA0NiwiaWF0IjoxNzQ3OTIxMDQ2LCJqdGkiOiJjZjQ3N2YzYy03ZWM1LTRkMmYtOTM0OC00NzVmZTA1NDRjZTgifQ.lFzgjVpAnajoQoRVNk5OVgAkwhNe765EsAT9g93TB4Ron6Z8bhFhx-uVQ9_ON5__WYitnML6sFodzuZx39R1Xw'
$baseUrl = 'https://site.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"

$pollingInterval = 1 # Interval in seconds to check the status of the query
$queryDays = -1 #How far back the query checks for new processes

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

#Unverified Procs  ###API LIMIT IS 1,000
Get-UnverifiedProcsBaseline -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

Get-UnverifiedProcsRecent -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

#Unverified Differential
$unverifiedProcsBaseline = Get-Content output\unverifiedProcsBaseline.json | ConvertFrom-Json
$unverifiedProcsRecent = Get-Content output\unverifiedProcsRecent.json | ConvertFrom-Json

foreach ($unvProcRecent in $unverifiedProcsRecent){
    foreach ($unvProcBaseline in $unverifiedProcsBaseline){
        if($unvProcRecent.value[2] -eq $unvProcBaseline.value[2]){
            $unvProcRecent.value[3] = 42
        }
    }
}
$filteredUnverifiedProcsRecent = $unverifiedProcsRecent | Where-Object {$_.value[3] -eq 1.0}
Write-Host ($filteredUnverifiedProcsRecent | Out-String) -ForegroundColor Cyan

foreach ($newProc in $filteredUnverifiedProcsRecent){
    $fileName = $newProc.value[0]
    $newHash = $newProc.value[2]
    [bool]$pullFileFromS1 = $false

    $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unverifiedProcsBaseline.json" -signatureStatus "unverified" -ErrorAction silentlycontinue
    if ($pullFileFromS1 -eq $false){
        $agentId = Get-FileFromS1 -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -newHash $newHash
    } else {
        continue
    }
}

}
