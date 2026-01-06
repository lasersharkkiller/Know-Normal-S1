function Get-PullIntezerStrings {
    param (
        [Parameter(Mandatory=$true)]
        $checkHash,
        
        $intezer_headers,
        
        # This is the new parameter causing the error. 
        # It defaults to the root folder if not specified.
        $OutputFolder = "output-baseline\IntezerStrings"
    )

    Write-Host "Trying $checkHash"
    $base_url = 'https://analyze.intezer.com/api/v2-0'

    # Ensure the output directory exists before we start
    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null
    }

    $response = Invoke-RestMethod -Method "GET" -Uri ($base_url + '/files/' + $checkHash) -Headers $intezer_headers -ContentType "application/json"
    $result_url = $base_url + $response.result_url

    [bool]$checkIfPending = $true

    while ($checkIfPending) {
        try {
            $result = Invoke-RestMethod -Method "GET" -Uri $result_url -Headers $intezer_headers -ErrorAction silentlycontinue
        }
        catch {
            Write-Host "Intezer doesn't already have" $checkHash "" -ForegroundColor Yellow
            break
        }

        if ($result.status -eq "queued"){
            continue
        } else {
            # Handle potential missing sub-analyses cleanly
            try {
                $subAnalyses = (Invoke-RestMethod -Method "GET" -Uri ($result_url + '/sub-analyses') -Headers $intezer_headers).sub_analyses
                
                # Logic to pick the correct sub-analysis ID (usually the last one is the code module)
                if ($subAnalyses -is [array]) {
                    $findSubAnalysesId = $subAnalyses[-1].sub_analysis_id
                } else {
                    $findSubAnalysesId = $subAnalyses.sub_analysis_id
                }

                $finalURL = $result_url + '/sub-analyses/' + $findSubAnalysesId + '/strings'
                $queryStrings = Invoke-RestMethod -Method "GET" -Uri $finalURL -Headers $intezer_headers
                
                # Dynamic Output Path using the new parameter
                $savePath = Join-Path -Path $OutputFolder -ChildPath "$checkHash.json"
                $queryStrings | ConvertTo-Json -Depth 10 | Out-File -FilePath $savePath
                
                Write-Host "  Saved to: $savePath" -ForegroundColor DarkGray
            }
            catch {
                Write-Warning "  Failed to retrieve strings for $checkHash"
            }

            return
        }
    }
}