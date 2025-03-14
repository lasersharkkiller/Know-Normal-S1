function Get-StringsBaseline{
Import-Module -Name ".\stringsBaseline\PullStrings_for Hash_with_Intezer.psm1"

$unsignedProcsBaseline = Get-Content output\unsignedWinProcsBaseline.json | ConvertFrom-Json 
$unverifiedProcsBaseline = Get-Content output\unverifiedProcsBaseline.json | ConvertFrom-Json
$fileNames = (Get-ChildItem -Path "output-strings").BaseName

$base_url = 'https://analyze.intezer.com/api/v2-0'

$intezer_body = @{
    'api_key' = ''
}

$intezer_headers = @{
    'Authorization' = ''
}

$queryCreateUrl = $base_url + '/get-access-token'
try {
        $token = (Invoke-RestMethod -Method "POST" -Uri ($base_url + '/get-access-token') -Body ($intezer_body | ConvertTo-Json) -ContentType "application/json").result
        $intezer_headers['Authorization'] = 'Bearer ' + $token
    }
catch {
        Write-Host "Error retrieving JWT"
        return $false
    }

#Filter on hashes we have not pulled strings for yet (unverified)
foreach ($unvProc in $unverifiedProcsBaseline){
    foreach ($fileName in $fileNames){
        if($unvProc.value[2] -eq $fileName){
            Write-Host "We had a match and are filtering out"
            $unvProc.value[3] = 42
        }
    }
}
$filteredUnverifiedProcs = $unverifiedProcsBaseline | Where-Object {$_.value[3] -eq 1.0}
Write-Host "Unverified Procs that have not had strings baselined:" -ForegroundColor Yellow
Write-Host ($filteredUnverifiedProcs | Out-String) -ForegroundColor Cyan

#Filter on hashes we have not pulled strings for yet (unsigned)
foreach ($unsProc in $unsignedProcsBaseline){
    foreach ($fileName in $fileNames){
        if($unsProc.value[2] -eq $fileName){
            $unsProc.value[3] = 42
        }
    }
}
$filteredUnsignedProcs = $unsignedProcsBaseline | Where-Object {$_.value[3] -eq 1.0}
Write-Host "Unsigned Procs that have not had strings baselined:" -ForegroundColor Yellow
Write-Host ($filteredUnsignedProcs | Out-String) -ForegroundColor Cyan

#for each hash in unverified
foreach ($needsStrings in $filteredUnverifiedProcs) {
    $checkHash = $needsStrings.value[2]
    Get-StringsBaseline -intezer_headers $intezer_headers -checkHash $checkHash -ErrorAction silentlycontinue
}

#for each hash in unsigned
foreach ($needsStrings in $filteredUnsignedProcs) {
    $checkHash = $needsStrings.value[2]
    Get-StringsBaseline -intezer_headers $intezer_headers -checkHash $checkHash -ErrorAction silentlycontinue
}

}
