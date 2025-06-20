function Get-PullIntezerStrings{

    param (
        [Parameter(Mandatory=$true)]
        $checkHash,
        $intezer_headers
    )
    Write-Host "Trying $checkHash"
$base_url = 'https://analyze.intezer.com/api/v2-0'

$response = Invoke-RestMethod -Method "GET" -Uri ($base_url + '/files/' + $checkHash) -Headers $intezer_headers -ContentType "application/json"
$result_url = $base_url + $response.result_url

[bool]$checkIfPending = $true

while ($checkIfPending) {
    try{
        $result = Invoke-RestMethod -Method "GET" -Uri $result_url -Headers $intezer_headers -ErrorAction silentlycontinue
    }
    catch {
        Write-Host "Intezer doesn't already have" $checkHash "" -ForegroundColor Yellow
        break
    }

    if ($result.status -eq "queued"){
        continue
    } else {
    
        $findSubAnalysesId = (Invoke-RestMethod -Method "GET" -Uri ($result_url + '/sub-analyses') -Headers $intezer_headers).sub_analyses.sub_analysis_id
        $finalURL = $result_url + '/sub-analyses/' + $findSubAnalysesId + '/strings'
        $queryStrings = Invoke-RestMethod -Method "GET" -Uri $finalURL -Headers $intezer_headers
        $queryStrings | ConvertTo-Json | Out-File -FilePath "output-strings\$checkHash.json"

        return
    }
}
}
