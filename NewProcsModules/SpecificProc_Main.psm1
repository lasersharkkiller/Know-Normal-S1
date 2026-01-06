function Get-SpecificProc{

    param (
        [Parameter(Mandatory=$true)]
        $procName
    )

Import-Module -Name ".\NewProcsModules\SpecificProcQuery.psm1"
Import-Module -Name ".\NewProcsModules\Intezer_Analyze_By_Hash.psm1"
Import-Module -Name ".\NewProcsModules\S1PullFile.psm1"
Import-Module -Name ".\NewProcsModules\S1GetActivities.psm1"
Import-Module -Name ".\NewProcsModules\PullFromVT.psm1"

# Define variables
$apiToken = Get-Secret -Name 'S1_API_Key' -AsPlainText
$baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"

$pollingInterval = 10 # Interval in seconds to check the status of the query
$queryDays = -5 #How far back the query checks for new processes

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

#Specific Procs Pull  ###API LIMIT IS 1,000
Get-SpecificProcPQ -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -procName $procName

$unsignedWinProcsBaseline = Get-Content output\unsignedWinProcsBaseline.json | ConvertFrom-Json
$unsignedLinuxProcsBaseline = Get-Content output\unsignedLinuxProcsBaseline.json | ConvertFrom-Json
$unverifedProcsBaseline = Get-Content output\unverifiedProcsBaseline.json | ConvertFrom-Json
$signedVerifedProcsBaseline = Get-Content output\signedVerifiedProcsBaseline.json | ConvertFrom-Json
$specifcProcPQ = Get-Content output\specificProcQuery.json | ConvertFrom-Json

foreach ($procHash in $specifcProcPQ){
    foreach ($unsProc in $unsignedWinProcsBaseline){
        if($procHash.value[2] -eq $unsProc.value[2]){
            $procHash.value[-1] = 8675309
        }
    }
    foreach ($unsProc in $unsignedLinuxProcsBaseline){
        if($procHash.value[2] -eq $unsProc.value[2]){
            $procHash.value[-1] = 8675309
        }
    }
    foreach ($unvProc in $unverifedProcsBaseline){
        if($procHash.value[2] -eq $unvProc.value[2]){
            $procHash.value[-1] = 8675309
        }
    }
    foreach ($svProc in $signedVerifedProcsBaseline){
        if($procHash.value[2] -eq $svProc.value[2]){
            $procHash.value[-1] = 8675309
        }
    }
}
$filteredSpecifcProcPQ = $specifcProcPQ | Where-Object {$_.value[-1] -ne 8675309}
#$sanityCheck = $specifcProcPQ | Where-Object {$_.value[-1] -eq 8675309}
Write-Host "Attempting to pull unbaselined processes:"
Write-Host ""
Write-Host ($filteredSpecifcProcPQ | Out-String) -ForegroundColor Cyan
#Write-Host "Next sanity check for what should be filtered out:"
#Write-Host ($sanityCheck | Out-String) -ForegroundColor Cyan

##Delete me
#[array]::Reverse($filteredSpecifcProcPQ)

foreach ($newProc in $filteredSpecifcProcPQ){
    Write-Host $newProc.value
    $fileName = $newProc.value[0]
    $signedStatus = $newProc.value[1]
    $newHash = $newProc.value[2]
    $verifiedStatus = $newProc.value[3]
    $os = $newProc.value[4]
    $publisher = $newProc.value[5]
    [bool]$pullFileFromS1 = $false
    [bool]$pullFileFromVT = $false

    #first check if it already exists in Intezer
    if ($signedStatus -eq "signed" -and $verifiedStatus -eq "verified") {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\signedVerifiedProcsBaseline.json" -signatureStatus "SignedVerified" -publisher $publisher -ErrorAction silentlycontinue
    } elseif ($verifiedStatus -eq "unverified") {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unverifiedProcsBaseline.json" -signatureStatus "unverified" -publisher $publisher -ErrorAction silentlycontinue
    } elseif ($os -eq "windows") {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unsignedWinProcsBaseline.json" -signatureStatus "unsigned" -publisher "none" -ErrorAction silentlycontinue
    } else {
        $pullFileFromS1 = Get-IntezerHash -checkHash $newHash -fileName $fileName -baseline "output\unsignedLinuxProcsBaseline.json" -signatureStatus "unsigned" -publisher "none" -ErrorAction silentlycontinue
    }

    if ($pullFileFromS1 -eq $false){
        #if it's not in intezer, first try VT (before pulling with S1 - more efficient)
        $pullFileFromVT = Get-PullFromVT -Sha256 $newHash -fileName $fileName -ErrorAction silentlycontinue
    }

    if ($pullFileFromS1 -eq $false -and $pullFileFromVT -eq $false){
        $agentId = Get-FileFromS1 -headers $headers -baseUrl $baseUrl -queryCreateUrl $queryCreateUrl -pollingInterval $pollingInterval -queryDays $queryDays -newHash $newHash
    } else {
        continue
    }
}

}