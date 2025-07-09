function Get-UnsignedProcs{

    param (
        [Parameter(Mandatory=$true)]
        $os
    )

Import-Module -Name ".\NewProcsModules\UnsignedProcBaseline.psm1"
Import-Module -Name ".\NewProcsModules\UnsignedProcRecent.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\S1PullFile.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\PullFromVT.psm1"

# Define variables
$apiToken = ''
$baseUrl = 'https://usea1-company.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"

$pollingInterval = 1 # Interval in seconds to check the status of the query
$queryDays = -1 #How far back the query checks for new processes

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

#Unsigned Procs  ###API LIMIT IS 1,000
Get-UnsignedProcsBaseline -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -os $os

Get-UnsignedProcsRecent -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -os $os

#Unsigned Differential
if ($os -eq "windows") {
    $unsignedProcsBaseline = Get-Content output\unsignedWinProcsBaseline.json | ConvertFrom-Json
    $unsignedProcsRecent = Get-Content output\unsignedProcsRecent.json | ConvertFrom-Json
} else {
    $unsignedProcsBaseline = Get-Content output\unsignedLinuxProcsBaseline.json | ConvertFrom-Json
    $unsignedProcsRecent = Get-Content output\unsignedProcsRecent.json | ConvertFrom-Json
}

foreach ($unsProcRecent in $unsignedProcsRecent){
    foreach ($unsProcBaseline in $unsignedProcsBaseline){
        if($unsProcRecent.value[2] -eq $unsProcBaseline.value[2]){
            $unsProcRecent.value[3] = 42
        }
    }
}
$filteredUnsignedProcsRecent = $unsignedProcsRecent | Where-Object {$_.value[3] -eq 1.0}
Write-Host ($filteredUnsignedProcsRecent | Out-String) -ForegroundColor Cyan

##Delete me
#[array]::Reverse($filteredUnsignedProcsRecent)

foreach ($newProc in $filteredUnsignedProcsRecent){
    $fileName = $newProc.value[0]
    $newHash = $newProc.value[2]
    [bool]$pullFileFromS1 = $false
    [bool]$pullFileFromVT = $false

    #first check if it already exists in Intezer
    if ($os -eq "windows") {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unsignedWinProcsBaseline.json" -signatureStatus "unsigned" -ErrorAction silentlycontinue
    } else {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unsignedLinuxProcsBaseline.json" -signatureStatus "unsigned" -ErrorAction silentlycontinue
    }
    
    #if it's not in intezer, first try VT (before pulling with S1 - more efficient)
    if ($pullFileFromS1 -eq $false){
        $pullFileFromVT = Get-PullFromVT -Sha256 $newHash -fileName $fileName -ErrorAction silentlycontinue
    }

    if ($pullFileFromS1 -eq $false -and $pullFileFromVT -eq $false){
        $agentId = Get-FileFromS1 -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -newHash $newHash
    } else {
        continue
    }
}

}
