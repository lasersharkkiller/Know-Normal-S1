function Get-UploadDiffsToVT {

    # Ensure the module is available in the session
    Import-Module VirusTotalAnalyzer -ErrorAction SilentlyContinue

    $vtApiKey = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
    #$VTApi = Get-Secret -Name 'VT_API_Key_2' -AsPlainText
    
    # Get the path to the user's Downloads folder.
    $downloadsPath = Join-Path -Path $HOME -ChildPath 'Downloads'

    #================================================================================
    # SCRIPT LOGIC
    #================================================================================

    # --- 2. Get all files, excluding PDFs ---
    Write-Host "Scanning '$($downloadsPath)' for files to upload..." -ForegroundColor Cyan
    $filesToUpload = Get-ChildItem -Path $downloadsPath -File | Where-Object { $_.Extension -ne ".pdf" }

    if (-not $filesToUpload) {
        Write-Host "No files found to upload (excluding PDFs)." -ForegroundColor Green
        exit
    }

    Write-Host "Found $($filesToUpload.Count) files to upload." -ForegroundColor Green

    # --- 3. Loop through each file and upload it ---
    foreach ($file in $filesToUpload) {
        Write-Host "------------------------------------------------------------"
        Write-Host "Submitting: $($file.Name)"

        try {
            # Use the simple, reliable cmdlet to upload the file
            $analysis = New-VirusScan -ApiKey $vtApiKey -File $file.FullName
        }
        catch {
            # The module provides clear errors if something goes wrong.
            Write-Host "ERROR: Failed to upload '$($file.Name)'." -ForegroundColor Red
            Write-Host "Reason: $($_.Exception.Message)" -ForegroundColor Red
        }

        # --- IMPORTANT: Rate Limiting Delay ---
        # It's still wise to wait between uploads to respect the public API limits.
        Write-Host "Waiting 3 seconds to respect API rate limits..."
        Start-Sleep -Seconds 3
    }

    Write-Host "------------------------------------------------------------"
    Write-Host "Upload finished." -ForegroundColor Cyan
}