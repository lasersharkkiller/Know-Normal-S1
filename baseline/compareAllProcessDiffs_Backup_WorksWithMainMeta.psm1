function Get-CompareAllProcessDiffs{

    [string]$BaselineFolderPath = ".\output\"
    [string]$HashFilesPath = ".\output-baseline\VirusTotal-main\"
    [string]$OutputFilePath = ".\output\process_differentials.txt"

    # --- ANSI Color Codes for File Output ---
    $esc = "$([char]27)"
    $colors = @{
        Green   = "$esc[92m"
        Yellow  = "$esc[93m"
        Red     = "$esc[91m"
        Magenta = "$esc[95m"
        Cyan    = "$esc[96m"
        Reset   = "$esc[0m"
    }

    # --- Step 1: Validate input paths ---
    if (-not (Test-Path -Path $BaselineFolderPath -PathType Container)) { Write-Error "Baseline folder not found at: $BaselineFolderPath."; return }
    if (-not (Test-Path -Path $HashFilesPath -PathType Container)) { Write-Error "Directory for main hash files not found at: $HashFilesPath"; return }

    Write-Host "Starting automated analysis for all processes..." -ForegroundColor Cyan

    try {
        # --- Step 2: Read master baseline files ---
        $baselineFileNames = @("unsignedLinuxProcsBaseline.json", "unsignedWinProcsBaseline.json", "unverifiedProcsBaseline.json")
        $masterData = [System.Collections.Generic.List[object]]::new()
        
        foreach ($fileName in $baselineFileNames) {
            $filePath = Join-Path -Path $BaselineFolderPath -ChildPath $fileName
            if (Test-Path $filePath) {
                $content = Get-Content -Path $filePath -Raw | ConvertFrom-Json
                $masterData.AddRange($content)
            } else {
                Write-Warning "Baseline file not found: $filePath. Skipping."
            }
        }

        if ($masterData.Count -eq 0) { Write-Error "No baseline files could be read from '$BaselineFolderPath'."; return }

        $groupedByProcess = $masterData | Group-Object -Property { $_.value[0] }
        Write-Host "`nFound $($groupedByProcess.Count) unique processes to analyze."
        $allProcessResults = [System.Collections.Generic.List[object]]::new()

        # --- Step 3: Loop through each unique process ---
        foreach ($processGroup in $groupedByProcess) {
            $currentProcessName = $processGroup.Name
            $hashes = $processGroup.Group | ForEach-Object { $_.value[2] }

            if ($null -eq $hashes -or $hashes.Count -lt 2) { continue }

            $allImports = [System.Collections.Generic.List[psobject]]::new()
            $allCerts = [System.Collections.Generic.List[psobject]]::new()
            $foundHashFilesForImports = [System.Collections.Generic.List[string]]::new()
            $foundHashFilesForCerts = [System.Collections.Generic.List[string]]::new()

            foreach ($hash in $hashes) {
                $hashFilePath = Join-Path -Path $HashFilesPath -ChildPath "$($hash).json"
                if (Test-Path $hashFilePath) {
                    $jsonContent = Get-Content -Path $hashFilePath -Raw | ConvertFrom-Json
                    
                    if ($null -eq $jsonContent -or $null -eq $jsonContent.data -or $null -eq $jsonContent.data.attributes) {
                        Write-Warning "Skipping invalid or empty report for hash: $hash"
                        continue
                    }

                    if ($null -ne $jsonContent.data.attributes.pe_info -and $null -ne $jsonContent.data.attributes.pe_info.import_list) {
                        if (-not $foundHashFilesForImports.Contains($hash)) { $foundHashFilesForImports.Add($hash) }
                        foreach ($importObject in $jsonContent.data.attributes.pe_info.import_list) {
                            if ($null -ne $importObject -and $null -ne $importObject.library_name) {
                                $allImports.Add([PSCustomObject]@{ Property = $importObject.library_name; SourceHash = $hash })
                            }
                        }
                    }

                    if ($null -ne $jsonContent.data.attributes.signature_info) {
                        if (-not $foundHashFilesForCerts.Contains($hash)) { $foundHashFilesForCerts.Add($hash) }
                        if ($null -ne $jsonContent.data.attributes.signature_info.verified) {
                            $allCerts.Add([PSCustomObject]@{ Property = "Verified Status = $($jsonContent.data.attributes.signature_info.verified)"; SourceHash = $hash })
                        }
                        if ($null -ne $jsonContent.data.attributes.signature_info.'signers details') {
                            foreach ($signer in $jsonContent.data.attributes.signature_info.'signers details') {
                                if ($null -ne $signer -and $null -ne $signer.name) {
                                    $allCerts.Add([PSCustomObject]@{ Property = "Signer Name = $($signer.name)"; SourceHash = $hash })
                                }
                            }
                        }
                    }
                }
            }

            # --- Step 4: Analyze collected data ---
            function Get-DifferentialAnalysis($dataList, $totalFiles) {
                if ($totalFiles -lt 2) { return @{ HasDifferences = $false; Results = $null } }
                $analysis = @{ HasDifferences = $false; Results = [System.Collections.Generic.List[object]]::new() }
                $groupedData = $dataList | Group-Object -Property Property
                foreach ($group in $groupedData) {
                    $sourceHashes = @($group.Group | Select-Object -ExpandProperty SourceHash -Unique)
                    $count = $sourceHashes.Count
                    $result = [PSCustomObject]@{ Property = $group.Name; Count = $count; SourceHashes = $sourceHashes; Color = 'Green'; Type = '[COMMON] ' }
                    if ($count -ne $totalFiles) {
                        $analysis.HasDifferences = $true
                        $result.Type = if ($count -eq 1) { '[UNIQUE] ' } else { '[PARTIAL]' }
                        $result.Color = if ($count -eq 1) { 'Red' } else { 'Yellow' }
                    }
                    $analysis.Results.Add($result)
                }
                return $analysis
            }

            $importAnalysis = Get-DifferentialAnalysis $allImports $foundHashFilesForImports.Count
            $certAnalysis = Get-DifferentialAnalysis $allCerts $foundHashFilesForCerts.Count

            if ($importAnalysis.HasDifferences -or $certAnalysis.HasDifferences) {
                $allProcessResults.Add([PSCustomObject]@{
                    ProcessName = $currentProcessName
                    ImportAnalysis = $importAnalysis
                    CertAnalysis = $certAnalysis
                    FilesComparedImports = $foundHashFilesForImports.Count
                    FilesComparedCerts = $foundHashFilesForCerts.Count
                })
            }
        }
        
        # --- Step 5: Output the report ---
        if ($allProcessResults.Count -gt 0) {
            $sortedResults = $allProcessResults | Sort-Object ProcessName
            
            $outputDir = Split-Path -Path $OutputFilePath -Parent
            if (-not (Test-Path -Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
            
            $fileHeader = "Differential Analysis Report - $(Get-Date)"; Set-Content -Path $OutputFilePath -Value $fileHeader; Add-Content -Path $OutputFilePath -Value ('-' * $fileHeader.Length)

            foreach ($result in $sortedResults) {
                $header = "DIFFERENCES FOUND for Process: $($result.ProcessName)"; $separator = '=' * $header.Length
                
                Write-Host "`n$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "`n$($colors.Magenta)$separator$($colors.Reset)"
                Write-Host $header -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$header$($colors.Reset)"
                Write-Host "$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$separator$($colors.Reset)"

                if ($result.ImportAnalysis.HasDifferences) {
                    $subHeader = "--- Analysis of 'import_list' (Compared across $($result.FilesComparedImports) files) ---"
                    Write-Host "`n$subHeader" -ForegroundColor Cyan; Add-Content -Path $OutputFilePath -Value "`n$($colors.Cyan)$subHeader$($colors.Reset)"
                    foreach ($item in $result.ImportAnalysis.Results) {
                        $line1 = "$($item.Type) $($item.Property)"; Write-Host $line1 -ForegroundColor $item.Color; Add-Content -Path $OutputFilePath -Value "$($colors[$item.Color])$line1$($colors.Reset)"
                        if ($item.Color -ne 'Green') {
                            $line2 = if ($item.Color -eq 'Red') { "       └─ Found only in: $($item.SourceHashes[0])" } else { "        └─ Found in $($item.Count) of $($result.FilesComparedImports) files: $($item.SourceHashes -join ', ')" }
                            Write-Host $line2; Add-Content -Path $OutputFilePath -Value $line2
                        }
                    }
                }

                if ($result.CertAnalysis.HasDifferences) {
                    $subHeader = "--- Analysis of 'signature_info' (Compared across $($result.FilesComparedCerts) files) ---"
                    Write-Host "`n$subHeader" -ForegroundColor Cyan; Add-Content -Path $OutputFilePath -Value "`n$($colors.Cyan)$subHeader$($colors.Reset)"
                    foreach ($item in $result.CertAnalysis.Results) {
                        $line1 = "$($item.Type) $($item.Property)"; Write-Host $line1 -ForegroundColor $item.Color; Add-Content -Path $OutputFilePath -Value "$($colors[$item.Color])$line1$($colors.Reset)"
                        if ($item.Color -ne 'Green') {
                            $line2 = if ($item.Color -eq 'Red') { "       └─ Found only in: $($item.SourceHashes[0])" } else { "        └─ Found in $($item.Count) of $($result.FilesComparedCerts) files: $($item.SourceHashes -join ', ')" }
                            Write-Host $line2; Add-Content -Path $OutputFilePath -Value $line2
                        }
                    }
                }
            }
            Write-Host "`n--- Full Analysis Complete. Report saved to '$OutputFilePath' ---" -ForegroundColor Green
        } else {
            Write-Host "`n--- Full Analysis Complete. No differences found in any processes. ---" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "An unexpected error occurred: $_"
        if ($_.Exception.InnerException) {
            Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }
}

