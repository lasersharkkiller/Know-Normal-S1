function Move-OrganizeBaselines {

    $BaseDir = ".\output-baseline"
    $MaliciousJsonPath = ".\output\maliciousProcsBaseline.json"

    # The specific folders to process
    $TargetFolders = @(
        "IntezerStrings", 
        "VirusTotal-behaviors", 
        "VirusTotal-main"
    )

    # ---------------------------------------

    Write-Host "Starting Local Organization and Deduplication..." -ForegroundColor Cyan

    # 1. Verify Baseline Exists
    if (-not (Test-Path $MaliciousJsonPath)) {
        Write-Error "Could not find baseline file at: $MaliciousJsonPath"
        return
    }

    # 2. Read and Parse the JSON Baseline
    try {
        $jsonContent = Get-Content -Path $MaliciousJsonPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to read JSON file. Check the format."
        return
    }

    # --- FIX: Extract hashes into a variable first to avoid parser errors ---
    # We grab index 2 from the 'value' array of each object
    [string[]]$MaliciousHashArray = $jsonContent | ForEach-Object { $_.value[2] }

    # Create a HashSet for fast lookup (Case-insensitive)
    $MaliciousHashes = [System.Collections.Generic.HashSet[string]]::new(
        $MaliciousHashArray, 
        [System.StringComparer]::OrdinalIgnoreCase
    )

    # 3. Process each target folder
    foreach ($folderName in $TargetFolders) {
        $currentSourcePath = Join-Path -Path $BaseDir -ChildPath $folderName
        $currentDestPath   = Join-Path -Path $currentSourcePath -ChildPath "malicious"

        Write-Host "`nProcessing folder: $folderName" -ForegroundColor Yellow

        # Check if the source folder exists first
        if (-not (Test-Path $currentSourcePath)) {
            Write-Warning "  Source folder not found: $currentSourcePath. Skipping..."
            continue
        }

        # Create the local 'malicious' subfolder if it doesn't exist
        if (-not (Test-Path $currentDestPath)) {
            New-Item -ItemType Directory -Force -Path $currentDestPath | Out-Null
            Write-Host "  Created subfolder: $currentDestPath" -ForegroundColor Gray
        }

        # --- A. MOVE LOGIC ---
        $moveCount = 0
        $missingCount = 0

        # Get all files in the source path (exclude the malicious subfolder itself)
        $sourceFiles = Get-ChildItem -Path $currentSourcePath -File | Where-Object { $_.Directory.Name -ne "malicious" }

        foreach ($file in $sourceFiles) {
            # Check if the file's base name (hash) is in our malicious list
            if ($MaliciousHashes.Contains($file.BaseName)) {
                $destFile = Join-Path -Path $currentDestPath -ChildPath $file.Name
                
                # Move the file (Force overwrites if it already exists in dest)
                Move-Item -Path $file.FullName -Destination $destFile -Force
                $moveCount++
            }
        }
        
        # Calculate missing count (hashes in baseline but no file found in either source or dest)
        foreach ($hash in $MaliciousHashes) {
            $srcPath = Join-Path -Path $currentSourcePath -ChildPath "$hash.json"
            $dstPath = Join-Path -Path $currentDestPath -ChildPath "$hash.json"
            if (-not (Test-Path $srcPath) -and -not (Test-Path $dstPath)) {
                $missingCount++
            }
        }

        Write-Host "  Files Moved:   $moveCount" -ForegroundColor Green
        if ($missingCount -gt 0) {
            Write-Host "  Files Missing: $missingCount (Baseline hash has no corresponding file)" -ForegroundColor DarkGray
        }

        # --- B. DEDUPLICATION LOGIC ---
        Write-Host "  Starting Deduplication..." -ForegroundColor Cyan
        
        # Get all files recursively in this folder structure (root + malicious subfolder)
        $allFiles = Get-ChildItem -Path $currentSourcePath -Recurse -File
        
        # Dictionary to track file hashes: Key = SHA256, Value = FilePath
        $fileHashes = @{}
        $dupeCount = 0

        foreach ($file in $allFiles) {
            try {
                # Calculate file hash (using SHA256 for collision resistance)
                $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                
                if ($fileHashes.ContainsKey($hash)) {
                    # Duplicate found!
                    
                    # Delete the current file (the duplicate)
                    Remove-Item -Path $file.FullName -Force
                    $dupeCount++
                }
                else {
                    # Add new unique file to dictionary
                    $fileHashes[$hash] = $file.FullName
                }
            }
            catch {
                Write-Warning "    Could not hash file: $($file.Name)"
            }
        }
        
        if ($dupeCount -gt 0) {
            Write-Host "  Duplicates Deleted: $dupeCount" -ForegroundColor Yellow
        } else {
            Write-Host "  No duplicates found." -ForegroundColor Gray
        }
    }

    Write-Host "`n--------------------------------" 
    Write-Host "Organization & Deduplication Complete." -ForegroundColor Green
}