function Get-NewWinPublishers{

Import-Module -Name ".\NewProcsModules\NewWinPublishersRecent.psm1"
Import-Module -Name ".\NewProcsModules\NewWinPublisherFocused.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\S1PullFile.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\PullFromVT.psm1"

# Define variables
$apiToken = Get-Secret -Name 'S1_API_Key' -AsPlainText
$baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"

$pollingInterval = 5 # Interval in seconds to check the status of the query
$queryDays = -1 #How far back the query checks for new processes

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

#To pull the baseline we pull from signedVerified baseline, NOT 
$winPublishersBaseline = Get-Content output\signedVerifiedProcsBaseline.json | ConvertFrom-Json
$uniquePublishers

try {
    # Create a new, empty array to hold the publisher names
    $publishers = @()

    # Loop through each entry in the winPublishersBaseline
    # The publisher is the 4th item in the 'value' array (index 3)
    foreach ($entry in $winPublishersBaseline) {
        # Add the publisher name to our list
        $publishers += $entry.value[3]
    }

    # Deduplicate the list and create the final unique array
    $uniquePublishers = $publishers | Sort-Object -Unique
    $uniquePublishers | ConvertTo-Json | Out-File "output\winPublishersBaseline.json"
}
catch {
    Write-Error "An error occurred: $_"
}

#Then get the recent publishers in the environment
Get-NewWinPublishersRecent -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays

#Unverified Differential
$winPublishersRecent = Get-Content output\winPublishersRecent.json | ConvertFrom-Json

foreach ($winPublisherRecent in $winPublishersRecent){
    foreach ($uniquePublisher in $uniquePublishers){
        if($winPublisherRecent.value[0] -eq $uniquePublisher){
            $winPublisherRecent.value[-1] = 8675309
        }
    }
}

Write-Host "--- New Publishers in the Environment---"
$filteredSCProcs = $winPublishersRecent | Where-Object {$_.value[-1] -ne 8675309}
Write-Host ($filteredSCProcs | Out-String) -ForegroundColor Cyan

foreach ($newProc in $filteredSCProcs){    
    $publisher = $newProc.value[0]
    Get-NewWinPublisherFocused -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -publisher $publisher
}

}