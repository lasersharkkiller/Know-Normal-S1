function Get-SpecialCharsProcs{

Import-Module -Name ".\NewProcsModules\SpecialCharsProcRecent.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\S1PullFile.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\PullFromVT.psm1"

# Define variables
$apiToken = Get-Secret -Name 'S1_API_Key' -AsPlainText
$baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"

$pollingInterval = 1 # Interval in seconds to check the status of the query
$queryDays = -3 #How far back the query checks for new processes

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

#Unverified Procs  ###API LIMIT IS 1,000
#Get-UnverifiedProcsBaseline -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

Get-SpecialCharsProcsRecent -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

#Unverified Differential
$unverifiedProcsBaseline = Get-Content output\unverifiedProcsBaseline.json | ConvertFrom-Json
$verifiedProcsBaseline = Get-Content output\signedVerifiedProcsBaseline.json | ConvertFrom-Json
$specialCharsProcsRecent = Get-Content output\specialCharProcRecent.json | ConvertFrom-Json

foreach ($specialCharsProcRecent in $specialCharsProcsRecent){
    foreach ($unvProcBaseline in $unverifiedProcsBaseline){
        if($specialCharsProcRecent.value[2] -eq $unvProcBaseline.value[2]){
            $specialCharsProcRecent.value[-1] = 8675309
        }
    }
}

foreach ($specialCharsProcRecent in $specialCharsProcsRecent){
    foreach ($vProcBaseline in $verifiedProcsBaseline){
        if($specialCharsProcRecent.value[2] -eq $vProcBaseline.value[2]){
            $specialCharsProcRecent.value[-1] = 8675309
        }
    }
}

$filteredSCProcs = $specialCharsProcsRecent | Where-Object {$_.value[-1] -ne 8675309}
Write-Host ($filteredSCProcs | Out-String) -ForegroundColor Cyan

foreach ($newProc in $filteredSCProcs){
    $fileName = $newProc.value[0]
    $verifiedStatus = $newProc.value[1]
    $newHash = $newProc.value[2]
    $publisher = $newProc.value[3]
    [bool]$pullFileFromS1 = $false
    [bool]$pullFileFromVT = $false

    #first check if it already exists in Intezer
    if ($verifiedStatus -eq "unverified") {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unverifiedProcsBaseline.json" -signatureStatus "unverified" -publisher $publisher -ErrorAction silentlycontinue
    } else {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\signedVerifiedProcsBaseline.json" -signatureStatus "signedVerified" -publisher $publisher -ErrorAction silentlycontinue
    }
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