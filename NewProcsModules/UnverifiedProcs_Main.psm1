function Get-UnverifiedProcs{

Import-Module -Name ".\NewProcsModules\UnverifiedProcBaseline.psm1"
Import-Module -Name ".\NewProcsModules\UnverifiedProcRecent.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\S1PullFile.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\PullFromVT.psm1"

# Define variables
$apiToken = Get-Secret -Name 'S1_API_Key_2' -AsPlainText
$baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"

$pollingInterval = 1 # Interval in seconds to check the status of the query
$queryDays = -1 #How far back the query checks for new processes

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

#Unverified Procs  ###API LIMIT IS 1,000
#Get-UnverifiedProcsBaseline -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

Get-UnverifiedProcsRecent -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

#Unverified Differential
$unverifiedProcsBaseline = Get-Content output\unverifiedProcsBaseline.json | ConvertFrom-Json
$unverifiedProcsRecent = Get-Content output\unverifiedProcsRecent.json | ConvertFrom-Json

foreach ($unvProcRecent in $unverifiedProcsRecent){
    foreach ($unvProcBaseline in $unverifiedProcsBaseline){
        if($unvProcRecent.value[2] -eq $unvProcBaseline.value[2]){
            $unvProcRecent.value[-1] = 8675309
        }
    }
}
$filteredUnverifiedProcsRecent = $unverifiedProcsRecent | Where-Object {$_.value[-1] -ne 8675309}
Write-Host ($filteredUnverifiedProcsRecent | Out-String) -ForegroundColor Cyan

foreach ($newProc in $filteredUnverifiedProcsRecent){
    $fileName = $newProc.value[0]
    $newHash = $newProc.value[2]
    $publisher = $newProc.value[3]
    [bool]$pullFileFromS1 = $false
    [bool]$pullFileFromVT = $false

    #first check if it already exists in Intezer
    $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unverifiedProcsBaseline.json" -signatureStatus "unverified" -publisher $publisher -ErrorAction silentlycontinue
    #if it's not in intezer, first try VT (before pulling with S1 - more efficient)
    if ($pullFileFromS1 -eq $false){
        $pullFileFromVT = Get-PullFromVT -Sha256 $newHash -fileName $fileName -ErrorAction silentlycontinue
    }
    
    if ($pullFileFromS1 -eq $false -and $pullFileFromVT -eq $false){
        $agentId = Get-FileFromS1 -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -newHash $newHash -ErrorAction silentlycontinue
    } else {
        continue
    }
}

}
