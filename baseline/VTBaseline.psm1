function Get-VTBaseline {

    $attributionPattern = "equifax"
    Import-Module -Name ".\baseline\checkAttribution.psm1"

    $VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
    #$VTApi = Get-Secret -Name 'VT_API_Key_2' -AsPlainText
    $intezerAPI = Get-Secret -Name 'Intezer_API_Key' -AsPlainText
    $downloadPath = "C:\Users\ipn2\Downloads\"

    # --- FOLDER CONFIGURATION ---
    $mainReportPath = "output-baseline\VirusTotal-main"
    $behaviorsReportPath = "output-baseline\VirusTotal-behaviors"

    # Define Malicious Subfolders
    $mainReportPathMalicious = Join-Path $mainReportPath "malicious"
    $behaviorsReportPathMalicious = Join-Path $behaviorsReportPath "malicious"

    # Create All Directories
    if (-not (Test-Path $mainReportPath)) { New-Item -ItemType Directory -Path $mainReportPath | Out-Null }
    if (-not (Test-Path $behaviorsReportPath)) { New-Item -ItemType Directory -Path $behaviorsReportPath | Out-Null }
    if (-not (Test-Path $mainReportPathMalicious)) { New-Item -ItemType Directory -Path $mainReportPathMalicious | Out-Null }
    if (-not (Test-Path $behaviorsReportPathMalicious)) { New-Item -ItemType Directory -Path $behaviorsReportPathMalicious | Out-Null }
    # ----------------------------

    $VT_headers = @{
        "x-apikey"     = $VTApi
        "Content-Type" = "application/json"
    }
    $baseUrl = "https://www.virustotal.com/api/v3/files/"

    # Intezer Setup
    $intezer_body = @{ 'api_key' = $intezerAPI }
    $intezer_headers = @{}
    $intezerBaseUrl = "https://analyze.intezer.com/api/v2-0"

    try {
        $token = (Invoke-RestMethod -Method "POST" -Uri ($intezerBaseUrl + '/get-access-token') -Body ($intezer_body | ConvertTo-Json) -ContentType "application/json").result
        $intezer_headers['Authorization'] = 'Bearer ' + $token
    }
    catch {
        Write-Host "Error retrieving JWT"
        return $false
    }

    # Load Baselines
    $unverifiedProcsBaseline = Get-Content output\unverifiedProcsBaseline.json | ConvertFrom-Json
    $unsignedWinProcsBaseline = Get-Content output\unsignedWinProcsBaseline.json | ConvertFrom-Json
    $unsignedLinuxProcsBaseline = Get-Content output\unsignedLinuxProcsBaseline.json | ConvertFrom-Json
    $signedVerifiedProcsBaseline = Get-Content output\signedVerifiedProcsBaseline.json | ConvertFrom-Json
    $maliciousProcsBaseline = Get-Content output\maliciousProcsBaseline.json | ConvertFrom-Json
    $baselineVTExclusions = Get-Content output\baselineVTExclusions.json | ConvertFrom-Json
    $fileHash = ""

    # ---------------------------------------------------------
    # HELPER FUNCTION: Process-Hash
    # ---------------------------------------------------------
    function Process-Hash {
        param ($hash, $mainPath, $behaviorsPath, $downloadPath, $VT_headers, $intezer_headers)

        $mainFile = Join-Path $mainPath "$($hash).json"
        $behaveFile = Join-Path $behaviorsPath "$($hash).json"

        # Only process if either file is missing
        if (-not (Test-Path $mainFile) -or -not (Test-Path $behaveFile)) {
            
            # 1. Main Report
            if (-not (Test-Path $mainFile)) {
                Write-Host "Main report missing for $($hash). Querying VirusTotal..."
                try {
                    $url = "https://www.virustotal.com/api/v3/files/$($hash)"
                    $response = Invoke-RestMethod -Uri $url -Headers $VT_headers -Method Get
                    $response | ConvertTo-Json -Depth 6 | Set-Content -Path $mainFile
                }
                catch {
                    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                        Write-Host "File not found on VirusTotal, attempting download from Intezer."
                        try {
                            $intUrl = "https://analyze.intezer.com/api/v2-0/files/$($hash)/download"
                            Invoke-RestMethod -Uri $intUrl -Headers $intezer_headers -Method Get -OutFile "$($downloadPath)$($hash)"
                            Write-Host "Successfully downloaded file $($hash) from Intezer." -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to download from Intezer. Error: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    else { Write-Host " Error fetching main report: $($_.Exception.Message)" }
                }
            }

            # 2. Behaviors Report
            if (-not (Test-Path $behaveFile)) {
                Write-Host "Behaviors report missing for $($hash). Querying VirusTotal..."
                try {
                    $url = "https://www.virustotal.com/api/v3/files/$($hash)/behaviours"
                    $response = Invoke-RestMethod -Uri $url -Headers $VT_headers -Method Get
                    $response | ConvertTo-Json -Depth 10 | Set-Content -Path $behaveFile
                }
                catch {
                    Write-Host " Error fetching behaviors report: $($_.Exception.Message)"
                }
            }
            Start-Sleep 3
        }
    }

    # --- Loop 1: Unverified Baseline (Root Folder) ---
    Write-Host "Iterating Through Unverified Baseline..." -ForegroundColor Cyan
    foreach ($proc in $unverifiedProcsBaseline) {
        $fileHash = $($proc.value[2])
        $checkAttribution = Get-CheckAttribution -fileHash $fileHash -baselineWorkingWith $unverifiedProcsBaseline
        if ($checkAttribution -eq $False) {
            Process-Hash -hash $fileHash -mainPath $mainReportPath -behaviorsPath $behaviorsReportPath -downloadPath $downloadPath -VT_headers $VT_headers -intezer_headers $intezer_headers
        }
    }

    # --- Loop 2: Windows Unsigned Baseline (Root Folder) ---
    Write-Host "Iterating Through Windows Unsigned Baseline..." -ForegroundColor Cyan
    foreach ($proc in $unsignedWinProcsBaseline) {
        $fileHash = $($proc.value[2])
        $existsInExclusions = $baselineVTExclusions.value.Contains($fileHash)
        
        if ($existsInExclusions -eq $False) {
            $checkAttribution = Get-CheckAttribution -fileHash $fileHash -baselineWorkingWith $unsignedWinProcsBaseline
            if ($checkAttribution -eq $False) {
                Process-Hash -hash $fileHash -mainPath $mainReportPath -behaviorsPath $behaviorsReportPath -downloadPath $downloadPath -VT_headers $VT_headers -intezer_headers $intezer_headers
            }
        }
    }

    # --- Loop 3: Linux Unsigned Baseline (Root Folder) ---
    Write-Host "Iterating Through Linux Unsigned Baseline..." -ForegroundColor Cyan
    foreach ($proc in $unsignedLinuxProcsBaseline) {
        $fileHash = $($proc.value[2])
        $checkAttribution = Get-CheckAttribution -fileHash $fileHash -baselineWorkingWith $unsignedLinuxProcsBaseline
        if ($checkAttribution -eq $False) {
            Process-Hash -hash $fileHash -mainPath $mainReportPath -behaviorsPath $behaviorsReportPath -downloadPath $downloadPath -VT_headers $VT_headers -intezer_headers $intezer_headers
        }
    }

    # --- Loop 4: SignedVerified Baseline (Root Folder) ---
    Write-Host "Iterating Through SignedVerified Baseline..." -ForegroundColor Cyan
    foreach ($proc in $signedVerifiedProcsBaseline) {
        $fileHash = $($proc.value[2])
        $checkAttribution = Get-CheckAttribution -fileHash $fileHash -baselineWorkingWith $signedVerifiedProcsBaseline
        if ($checkAttribution -eq $False) {
            Process-Hash -hash $fileHash -mainPath $mainReportPath -behaviorsPath $behaviorsReportPath -downloadPath $downloadPath -VT_headers $VT_headers -intezer_headers $intezer_headers
        }
    }

    # --- Loop 5: Malicious Baseline (MALICIOUS SUBFOLDER) ---
    Write-Host "Iterating Through Malicious Baseline..." -ForegroundColor Cyan
    foreach ($proc in $maliciousProcsBaseline) {
        $fileHash = $($proc.value[2])
        # Note: We skip attribution checks for known malicious files and process them directly
        # Using the *Malicious* path variables defined at the top
        Process-Hash -hash $fileHash -mainPath $mainReportPathMalicious -behaviorsPath $behaviorsReportPathMalicious -downloadPath $downloadPath -VT_headers $VT_headers -intezer_headers $intezer_headers
    }
}