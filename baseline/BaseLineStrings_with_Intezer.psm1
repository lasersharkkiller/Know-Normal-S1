function Get-StringsBaseline {
    # Remove external dependency - logic is now embedded below
    # Import-Module -Name ".\baseline\PullStrings_for Hash_with_Intezer.psm1" -Force
    
    $intezerAPI = Get-Secret -Name 'Intezer_API_Key' -AsPlainText

    $unverifiedProcsBaseline = Get-Content output\unverifiedProcsBaseline.json | ConvertFrom-Json
    $unsignedWinProcsBaseline = Get-Content output\unsignedWinProcsBaseline.json | ConvertFrom-Json
    $unsignedLinuxProcsBaseline = Get-Content output\unsignedLinuxProcsBaseline.json | ConvertFrom-Json
    $signedVerifiedProcsBaseline = Get-Content output\signedVerifiedProcsBaseline.json | ConvertFrom-Json
    $maliciousProcsBaseline = Get-Content output\maliciousProcsBaseline.json | ConvertFrom-Json
    
    # --- FOLDER CONFIGURATION ---
    $RootOutput      = ".\output-baseline\IntezerStrings"
    $MaliciousOutput = ".\output-baseline\IntezerStrings\malicious"

    # Create Directories
    if (-not (Test-Path $RootOutput)) { New-Item -ItemType Directory -Force -Path $RootOutput | Out-Null }
    if (-not (Test-Path $MaliciousOutput)) { New-Item -ItemType Directory -Force -Path $MaliciousOutput | Out-Null }

    # 1. Recursive check so we see files inside the 'malicious' subfolder too
    $existingHashes = (Get-ChildItem -Path $RootOutput -Recurse -File).BaseName

    $base_url = 'https://analyze.intezer.com/api/v2-0'
    $intezer_body = @{ 'api_key' = $intezerAPI }
    $intezer_headers = @{ 'Authorization' = '' }

    try {
        $token = (Invoke-RestMethod -Method "POST" -Uri ($base_url + '/get-access-token') -Body ($intezer_body | ConvertTo-Json) -ContentType "application/json").result
        $intezer_headers['Authorization'] = 'Bearer ' + $token
    }
    catch {
        Write-Host "Error retrieving JWT"
        return $false
    }

    # ---------------------------------------------------------
    # HELPER FUNCTION: Process-IntezerHash
    # Includes logic to Pull Strings AND Retry/Re-analyze if expired
    # ---------------------------------------------------------
    function Process-IntezerHash {
        param ($checkHash, $headers, $OutputFolder)

        Write-Host "Trying $checkHash"
        $base_url = 'https://analyze.intezer.com/api/v2-0'

        # Ensure output directory exists
        if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null }

        # Initial Attempt to get existing analysis
        try {
            $response = Invoke-RestMethod -Method "GET" -Uri ($base_url + '/files/' + $checkHash) -Headers $headers -ContentType "application/json" -ErrorAction Stop
            $result_url = $base_url + $response.result_url
        }
        catch {
            Write-Host "  Initial lookup failed (File not found or Error). Preparing to Analyze..." -ForegroundColor Yellow
            $result_url = $null 
        }

        # If we didn't get a URL (404), trigger analysis immediately
        if ($null -eq $result_url) {
            try {
                $analyzeBody = @{ hash = $checkHash }
                $analyzeResponse = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/analyze-by-hash') -Headers $headers -Body ($analyzeBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
                $result_url = $base_url + $analyzeResponse.result_url
                Write-Host "  Submitted for analysis..." -ForegroundColor Cyan
            }
            catch {
                Write-Warning "  Could not submit $checkHash for analysis. Skipping."
                return
            }
        }

        [bool]$checkIfPending = $true
        $retryCount = 0

        while ($checkIfPending) {
            try {
                $result = Invoke-RestMethod -Method "GET" -Uri $result_url -Headers $headers -ErrorAction Stop
            }
            catch {
                Write-Warning "  Error checking status for $checkHash"
                break
            }

            # Check Status
            if ($result.status -eq "queued" -or $result.status -eq "in_progress") {
                Start-Sleep -Seconds 5
                continue
            } else {
                # Analysis is done, try to retrieve Strings
                try {
                    $subAnalyses = (Invoke-RestMethod -Method "GET" -Uri ($result_url + '/sub-analyses') -Headers $headers).sub_analyses
                    
                    # Logic to pick the correct sub-analysis ID (Code module)
                    if ($subAnalyses -is [array]) {
                        $findSubAnalysesId = $subAnalyses[-1].sub_analysis_id
                    } else {
                        $findSubAnalysesId = $subAnalyses.sub_analysis_id
                    }

                    $finalURL = $result_url + '/sub-analyses/' + $findSubAnalysesId + '/strings'
                    $queryStrings = Invoke-RestMethod -Method "GET" -Uri $finalURL -Headers $headers -ErrorAction Stop
                    
                    # Success! Save File.
                    $savePath = Join-Path -Path $OutputFolder -ChildPath "$checkHash.json"
                    $queryStrings | ConvertTo-Json -Depth 10 | Out-File -FilePath $savePath
                    
                    Write-Host "  Saved to: $savePath" -ForegroundColor DarkGray
                    return
                }
                catch {
                    # --- RE-ANALYSIS LOGIC ---
                    # If retrieving strings failed, the sample might be expired/outdated.
                    if ($retryCount -eq 0) {
                        Write-Host "  Failed to retrieve strings (Sample likely outdated). Triggering Re-Analysis..." -ForegroundColor Yellow
                        $retryCount++
                        
                        try {
                            $analyzeBody = @{ hash = $checkHash }
                            # POST request forces a re-analysis
                            $analyzeResponse = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/analyze-by-hash') -Headers $headers -Body ($analyzeBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
                            
                            # Update the URL to track the NEW analysis
                            $result_url = $base_url + $analyzeResponse.result_url
                            
                            # Restart the loop to wait for this new analysis
                            Start-Sleep -Seconds 2
                            continue 
                        }
                        catch {
                            Write-Warning "  Re-analysis request failed: $_"
                            break
                        }
                    }
                    
                    Write-Warning "  Failed to retrieve strings for $checkHash after retry."
                    break
                }
            }
        }
    }

    # --- FILTERING LOGIC ---

    # Filter Unverified
    foreach ($unvProc in $unverifiedProcsBaseline){
        foreach ($existingHash in $existingHashes){
            if($unvProc.value[2] -eq $existingHash){
                $unvProc.value[-1] = 8675309
            }
        }
    }
    $filteredUnverifiedProcs = $unverifiedProcsBaseline | Where-Object {$_.value[-1] -ne 8675309}
    Write-Host "Unverified Procs that have not had strings baselined:" -ForegroundColor Yellow
    Write-Host ($filteredUnverifiedProcs | Out-String) -ForegroundColor Cyan

    # Filter Unsigned Win
    foreach ($unsProc in $unsignedWinProcsBaseline){
        foreach ($existingHash in $existingHashes){
            if($unsProc.value[2] -eq $existingHash){
                $unsProc.value[-1] = 8675309
            }
        }
    }
    $filteredUnsignedWinProcs = $unsignedWinProcsBaseline | Where-Object {$_.value[-1] -ne 8675309}
    Write-Host "Unsigned Win Procs that have not had strings baselined:" -ForegroundColor Yellow
    Write-Host ($filteredUnsignedWinProcs | Out-String) -ForegroundColor Cyan

    # Filter Unsigned Linux
    foreach ($unsProc in $unsignedLinuxProcsBaseline){
        foreach ($existingHash in $existingHashes){
            if($unsProc.value[2] -eq $existingHash){
                $unsProc.value[-1] = 8675309
            }
        }
    }
    $filteredUnsignedLinuxProcs = $unsignedLinuxProcsBaseline | Where-Object {$_.value[-1] -ne 8675309}
    Write-Host "Unsigned Linux Procs that have not had strings baselined:" -ForegroundColor Yellow
    Write-Host ($filteredUnsignedLinuxProcs | Out-String) -ForegroundColor Cyan

    # Filter Signed Verified
    foreach ($svProc in $signedVerifiedProcsBaseline){
        foreach ($existingHash in $existingHashes){
            if($svProc.value[2] -eq $existingHash){
                $svProc.value[-1] = 8675309
            }
        }
    }
    $filteredsignedVerifiedProcs = $signedVerifiedProcsBaseline | Where-Object {$_.value[-1] -ne 8675309}
    Write-Host "SignedVerified Procs that have not had strings baselined:" -ForegroundColor Yellow
    Write-Host ($filteredsignedVerifiedProcs | Out-String) -ForegroundColor Cyan

    # Filter Malicious
    foreach ($mProc in $maliciousProcsBaseline){
        foreach ($existingHash in $existingHashes){
            if($mProc.value[2] -eq $existingHash){
                $mProc.value[-1] = 8675309
            }
        }
    }
    $filteredMaliciousProcs = $maliciousProcsBaseline | Where-Object {$_.value[-1] -ne 8675309}
    Write-Host "Malicious Procs that have not had strings baselined:" -ForegroundColor Red
    Write-Host ($filteredMaliciousProcs | Out-String) -ForegroundColor Cyan

    # --- PROCESSING LOOPS (Updated to call the embedded helper) ---

    # 1. Unverified (ROOT FOLDER)
    foreach ($needsStrings in $filteredUnverifiedProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    # 2. Unsigned Win (ROOT FOLDER)
    foreach ($needsStrings in $filteredUnsignedWinProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    # 3. Unsigned Linux (ROOT FOLDER)
    foreach ($needsStrings in $filteredUnsignedLinuxProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    # 4. Signed Verified (ROOT FOLDER)
    foreach ($needsStrings in $filteredsignedVerifiedProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $RootOutput
    }

    # 5. Malicious (MALICIOUS FOLDER)
    Write-Host "Processing Malicious Hashes..." -ForegroundColor Red
    foreach ($needsStrings in $filteredMaliciousProcs) {
        Process-IntezerHash -checkHash $needsStrings.value[2] -headers $intezer_headers -OutputFolder $MaliciousOutput
    }
}
