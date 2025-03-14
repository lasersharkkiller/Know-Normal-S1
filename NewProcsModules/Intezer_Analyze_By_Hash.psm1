function Get-IntezerHash{

    param (
        [Parameter(Mandatory=$true)]
        $checkHash,
        $fileName
    )


$base_url = 'https://analyze.intezer.com/api/v2-0'

$intezer_body = @{
    'api_key' = ''
}

$hash = @{
    'hash' = $checkHash
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

$response = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/analyze-by-hash') -Headers $intezer_headers -Body ($hash | ConvertTo-Json) -ContentType "application/json"
$result_url = $base_url + $response.result_url

[bool]$checkIfPending = $true

while ($checkIfPending) {
    try{
        $result = Invoke-RestMethod -Method "GET" -Uri $result_url -Headers $intezer_headers -ErrorAction silentlycontinue
    }
    catch {
        Write-Host "Intezer doesn't already have" $fileName ", we need to pull with S1." -ForegroundColor Yellow
        return $false
    }

    if ($result.status -eq "queued"){
        continue
    } else {
        $textColor = "White"
        if ($result.result.verdict -eq "trusted") {
            $textColor = "Green"
        } elseif ($result.result.verdict -eq "no_threats"){
            $textColor = "Green"
        } elseif ($result.result.verdict -eq "suspicious"){
            $textColor = "Yellow"
        } elseif ($result.result.verdict -eq "suspicious"){
            $textColor = "Yellow"
        } elseif ($result.result.verdict -eq "malicious"){
            $textColor = "Red"
        }
        
        Write-Host "---" -ForegroundColor $textColor
        Write-Host "File Name: " $fileName -ForegroundColor $textColor
        Write-Host "Analysis URL: " $result.result.analysis_url -ForegroundColor $textColor
        Write-Host "Family Name: " $result.result.family_name -ForegroundColor $textColor
        Write-Host "Gene Types: " $result.result.gene_types -ForegroundColor $textColor
        Write-Host "SHA256: " $result.result.sha256 -ForegroundColor $textColor
        Write-Host "Verdict: " $result.result.verdict -ForegroundColor $textColor
        Write-Host "Sub-verdict: " $result.result.sub_verdict -ForegroundColor $textColor
        Write-Host "---" -ForegroundColor $textColor
        return $true
    }
}
}
