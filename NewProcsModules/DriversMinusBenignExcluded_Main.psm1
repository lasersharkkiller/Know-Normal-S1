function Get-DriversMinusBenignExcluded{

Import-Module -Name ".\NewProcsModules\DriversMinusBenignExcludedRecent.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\S1PullFile.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\PullFromVT.psm1"

# Define variables
$apiToken = Get-Secret -Name 'S1_API_Key_2' -AsPlainText
$baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"

$pollingInterval = 1 # Interval in seconds to check the status of the query
$queryDays = -30 #How far back the query checks for new processes

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

#Mostly Unsigned Drivers but also others  ###API LIMIT IS 1,000
Get-driversMinusBenignExcluded_Recent -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

#Unverified Differential
$driversBaseline = Get-Content output\driversBaseline.json | ConvertFrom-Json
$driversRecent = Get-Content output\driversRecent.json | ConvertFrom-Json
Write-Host $driversBaseline
foreach ($driverRecent in $driversRecent){
    foreach ($driverBaseline in $driversBaseline){
        if($driverRecent.value[2] -eq $driverBaseline.value[2]){
            $driverRecent.value[-1] = 8675309
        }
    }
}
$filteredDriversRecent = $driversRecent | Where-Object {$_.value[-1] -ne 8675309}
Write-Host ($filteredDriversRecent | Out-String) -ForegroundColor Cyan

foreach ($newDriver in $filteredDriversRecent){
    $fileName = $newDriver.value[0]
    $signatureStatus = $newDriver.value[1]
    $newHash = $newDriver.value[2]
    $publisher = $newDriver.value[3]
    [bool]$pullFileFromS1 = $false
    [bool]$pullFileFromVT = $false

    #first check if it already exists in Intezer
    $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\driversBaseline.json" -signatureStatus $signatureStatus -publisher $publisher -ErrorAction silentlycontinue
    #if it's not in intezer, first try VT (before pulling with S1 - more efficient)
    if ($pullFileFromS1 -eq $false){
        $pullFileFromVT = Get-PullFromVT -Sha256 $newHash -fileName $fileName -ErrorAction silentlycontinue
    }
    
    if ($pullFileFromS1 -eq $false -and $pullFileFromVT -eq $false){
        $agentId = Get-FileFromS1 -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -newHash $newHash -type "driver" -ErrorAction silentlycontinue
    } else {
        continue
    }
}

}