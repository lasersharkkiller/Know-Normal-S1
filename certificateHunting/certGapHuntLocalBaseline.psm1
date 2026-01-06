function Get-CertGapHuntLocalBaseline{

    [string]$HashFilesPath = ".\output-baseline\VirusTotal-main\"
    [string]$OutputFilePath = ".\output\certificate_anomalies.txt"
    
    # --- ANSI Color Codes for File Output ---
    $esc = "$([char]27)"
    $colors = @{
        Red     = "$esc[91m"
        Magenta = "$esc[95m"
        Reset   = "$esc[0m"
    }

    # --- Step 1: Validate input paths ---
    if (-not (Test-Path -Path $HashFilesPath -PathType Container)) {
        Write-Error "Directory for hash files not found at: $HashFilesPath"
        return
    }

    Write-Host "Starting certificate anomaly scan..." -ForegroundColor Cyan

    try {
        # MODIFIED: Step 2 now gets files directly from the VirusTotal-main folder.
        Write-Host "Searching for VT reports in '$HashFilesPath'..."
        $hashReportFiles = Get-ChildItem -Path $HashFilesPath -Filter "*.json"

        if ($null -eq $hashReportFiles) {
            Write-Error "No VirusTotal report (.json) files were found in '$HashFilesPath'."
            return
        }

        $anomaliesFound = [System.Collections.Generic.List[object]]::new()
        $totalHashes = ($hashReportFiles | Measure-Object).Count
        Write-Host "Analyzing $totalHashes total hashes for certificate anomalies..."

        # MODIFIED: The main loop now iterates through the report files directly.
        foreach ($reportFile in $hashReportFiles) {
            
            # MODIFIED: Hash is derived from the filename.
            $hash = $reportFile.BaseName
            
            $jsonContent = Get-Content -Path $reportFile.FullName -Raw | ConvertFrom-Json
            $signatureInfo = $jsonContent.data.attributes.signature_info

            # Primary Filter: Only check files that appear to be validly signed at the top level.
            if ($null -ne $signatureInfo -and $signatureInfo.verified -eq 'Valid. Signed.') {
                
                if ($null -ne $signatureInfo.'signers details') {
                    foreach ($signer in $signatureInfo.'signers details') {
                        $isExpired = $false
                        $isInvalidStatus = $false
                        
                        # Check 1: Status is not 'Valid'
                        if ($signer.status -ne 'Valid') {
                            $isInvalidStatus = $true
                        }

                        # Check 2: Expiration date is in the past
                        try {
                            $validToDate = [datetime]::Parse($signer.'valid to', [System.Globalization.CultureInfo]::InvariantCulture)
                            if ($validToDate -lt (Get-Date)) {
                                $isExpired = $true
                            }
                        } catch {
                            # Handle cases where the date might be malformed
                        }

                        if ($isExpired -or $isInvalidStatus) {
                            $reason = @()
                            if ($isInvalidStatus) { $reason += "Status is '$($signer.status)'" }
                            if ($isExpired) { $reason += "Expired on $($signer.'valid to')" }
                            
                            # MODIFIED: Get the process name from the report's 'names' attribute.
                            # Use a placeholder if the 'names' attribute is missing.
                            $processName = "Unknown Process"
                            if ($null -ne $jsonContent.data.attributes.names[0]) {
                                $processName = $jsonContent.data.attributes.names[0]
                            }

                            $anomaliesFound.Add([PSCustomObject]@{
                                ProcessName = $processName
                                Hash = $hash
                                SignerName = $signer.name
                                Reason = $reason -join '; '
                            })
                        }
                    }
                }
            }
        }
        
        # --- Step 4: Output the report (No changes needed here) ---
        if ($anomaliesFound.Count -gt 0) {
            $outputDir = Split-Path -Path $OutputFilePath -Parent
            if (-not (Test-Path -Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir | Out-Null
            }
            
            $fileHeader = "Certificate Anomaly Report - $(Get-Date)"
            Set-Content -Path $OutputFilePath -Value $fileHeader
            Add-Content -Path $OutputFilePath -Value ('-' * $fileHeader.Length)

            $groupedAnomalies = $anomaliesFound | Group-Object -Property ProcessName | Sort-Object Name

            foreach ($group in $groupedAnomalies) {
                $header = "ANOMALY DETECTED for Process: $($group.Name)"
                $separator = '=' * $header.Length
                
                Write-Host "`n$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "`n$($colors.Magenta)$separator$($colors.Reset)"
                Write-Host $header -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$header$($colors.Reset)"
                Write-Host "$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$separator$($colors.Reset)"

                foreach ($anomaly in $group.Group) {
                    $line1 = "Hash: $($anomaly.Hash)"
                    $line2 = "  └─ Signer: $($anomaly.SignerName)"
                    $line3 = "     └─ $($colors.Red)Reason: $($anomaly.Reason)$($colors.Reset)"
                    
                    Write-Host $line1
                    Write-Host $line2
                    Write-Host $line3
                    
                    Add-Content -Path $OutputFilePath -Value $line1, $line2
                    Add-Content -Path $OutputFilePath -Value "     └─ Reason: $($anomaly.Reason)"
                }
            }
            Write-Host "`n--- Scan Complete. Found $($anomaliesFound.Count) anomalies. Report saved to '$OutputFilePath' ---" -ForegroundColor Red
        } else {
            Write-Host "`n--- Scan Complete. No certificate anomalies found. ---" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "An unexpected error occurred: $_"
        if ($_.Exception.InnerException) {
            Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }

}