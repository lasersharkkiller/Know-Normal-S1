function Get-CompareSingleProcessDiffsSingleHash {
    param (
        [string]$ProcessName,
        [string]$TargetHash
    )
    
    # --- Configuration ---
    [string]$HashFilesPath = ".\output-baseline\VirusTotal-main\"
    [string]$BehaviorsFilesPath = ".\output-baseline\VirusTotal-behaviors\"
    [string]$OutputFilePath = ".\output\anomaly_report_($ProcessName)_($TargetHash.Substring(0,10)).txt"

    # --- ANSI Color Codes ---
    $colors = @{ Green = "$([char]27)[92m"; Yellow = "$([char]27)[93m"; Red = "$([char]27)[91m"; Magenta = "$([char]27)[95m"; Cyan = "$([char]27)[96m"; Reset = "$([char]27)[0m" }

    # --- Step 1: Validate paths ---
    if (-not (Test-Path -Path $HashFilesPath -PathType Container)) { Write-Error "Directory for main hash files not found at: $HashFilesPath"; return }
    if (-not (Test-Path -Path $BehaviorsFilesPath -PathType Container)) { Write-Error "Directory for behavior hash files not found at: $BehaviorsFilesPath"; return }

    Write-Host "Starting analysis for process: '$($ProcessName)', focusing on hash: '$($TargetHash)'" -ForegroundColor Cyan

    try {
        # --- Step 2: Find all hashes for the specified process ---
        Write-Host "Searching for reports related to '$($ProcessName)'..."
        $hashes = [System.Collections.Generic.List[string]]::new()
        $reportFiles = Get-ChildItem -Path $HashFilesPath -Filter "*.json"

        foreach ($file in $reportFiles) {
            $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($null -eq $jsonContent -or $null -eq $jsonContent.data -or $null -eq $jsonContent.data.attributes -or $null -eq $jsonContent.data.attributes.names) {
                continue
            }
            if ($jsonContent.data.attributes.names -contains $ProcessName) {
                $hashes.Add($file.BaseName)
            }
        }
        
        # --- MODIFIED: Logic to handle if TargetHash is not found by name ---
        $targetHashManuallyAdded = $false
        if ($TargetHash -notin $hashes) {
            Write-Host "Target hash '$($TargetHash)' not found by process name. Attempting to add it to the comparison set." -ForegroundColor Yellow
            $mainFileExists = Test-Path (Join-Path $HashFilesPath "$TargetHash.json")
            $behaviorsFileExists = Test-Path (Join-Path $BehaviorsFilesPath "$TargetHash.json")

            if (-not $mainFileExists -and -not $behaviorsFileExists) {
                Write-Error "The specified TargetHash '$TargetHash' was not found by process name, AND its report files do not exist in the baseline directories. Halting analysis."
                return
            }
            $hashes.Add($TargetHash)
            $targetHashManuallyAdded = $true
        }

        if ($hashes.Count -eq 0) { Write-Warning "No reports found for process '$ProcessName'."; return }
        if ($hashes.Count -lt 2) { Write-Warning "Fewer than two hashes found for comparison. Cannot perform a differential analysis."; return }
        
        Write-Host "Found $($hashes.Count) total hashes to compare for '$($ProcessName)'."

        # --- Step 3: Data Collection (Unchanged) ---
        $allData = @{ Imports = [System.Collections.Generic.List[psobject]]::new(); Certs = [System.Collections.Generic.List[psobject]]::new(); IPs = [System.Collections.Generic.List[psobject]]::new(); DnsLookups = [System.Collections.Generic.List[psobject]]::new(); ProcsCreated = [System.Collections.Generic.List[psobject]]::new(); ProcsTerminated = [System.Collections.Generic.List[psobject]]::new(); Urls = [System.Collections.Generic.List[psobject]]::new(); FilesOpened = [System.Collections.Generic.List[psobject]]::new() }
        $foundHashFiles = @{}
        # (Data collection logic remains here, unchanged)
        foreach ($hash in $hashes) {
            $mainHashFilePath = Join-Path -Path $HashFilesPath -ChildPath "$($hash).json"
            if (Test-Path $mainHashFilePath) {
                $mainJson = Get-Content -Path $mainHashFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -ne $mainJson -and $null -ne $mainJson.data -and $null -ne $mainJson.data.attributes) {
                    if ($null -ne $mainJson.data.attributes.pe_info -and $null -ne $mainJson.data.attributes.pe_info.import_list) {
                        if (-not $foundHashFiles.ContainsKey('Imports')) { $foundHashFiles['Imports'] = [System.Collections.Generic.List[string]]::new() }
                        if (-not $foundHashFiles['Imports'].Contains($hash)) { $foundHashFiles['Imports'].Add($hash) }
                        $mainJson.data.attributes.pe_info.import_list | ForEach-Object { if($null -ne $_ -and $_.PSObject.Properties.Name -contains 'library_name') { $allData.Imports.Add([PSCustomObject]@{ Property = $_.library_name; SourceHash = $hash }) } }
                    }
                    if ($null -ne $mainJson.data.attributes.signature_info) {
                        if (-not $foundHashFiles.ContainsKey('Certs')) { $foundHashFiles['Certs'] = [System.Collections.Generic.List[string]]::new() }
                        if (-not $foundHashFiles['Certs'].Contains($hash)) { $foundHashFiles['Certs'].Add($hash) }
                        if($mainJson.data.attributes.signature_info.PSObject.Properties.Name -contains 'verified') { $allData.Certs.Add([PSCustomObject]@{ Property = "Verified Status = $($mainJson.data.attributes.signature_info.verified)"; SourceHash = $hash }) }
                        if ($null -ne $mainJson.data.attributes.signature_info.'signers details') {
                            $mainJson.data.attributes.signature_info.'signers details' | ForEach-Object { if($null -ne $_ -and $_.PSObject.Properties.Name -contains 'name') { $allData.Certs.Add([PSCustomObject]@{ Property = "Signer Name = $($_.name)"; SourceHash = $hash }) } }
                        }
                    }
                }
            }
            $behaviorsFilePath = Join-Path -Path $BehaviorsFilesPath -ChildPath "$($hash).json"
            if (Test-Path $behaviorsFilePath) {
                $behaviorsJson = Get-Content -Path $behaviorsFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -ne $behaviorsJson -and $null -ne $behaviorsJson.data) {
                    foreach ($sandboxReport in $behaviorsJson.data) {
                        if ($null -ne $sandboxReport -and $null -ne $sandboxReport.attributes) {
                            if ($null -ne $sandboxReport.attributes.ip_traffic) {
                                if (-not $foundHashFiles.ContainsKey('IPs')) { $foundHashFiles['IPs'] = [System.Collections.Generic.List[string]]::new() }
                                if (-not $foundHashFiles['IPs'].Contains($hash)) { $foundHashFiles['IPs'].Add($hash) }
                                $sandboxReport.attributes.ip_traffic | ForEach-Object { if($null -ne $_ -and $_.PSObject.Properties.Name -contains 'destination_ip') { $allData.IPs.Add([PSCustomObject]@{ Property = $_.destination_ip; SourceHash = $hash }) } }
                            }
                            if ($null -ne $sandboxReport.attributes.processes_created) {
                                if (-not $foundHashFiles.ContainsKey('ProcsCreated')) { $foundHashFiles['ProcsCreated'] = [System.Collections.Generic.List[string]]::new() }
                                if (-not $foundHashFiles['ProcsCreated'].Contains($hash)) { $foundHashFiles['ProcsCreated'].Add($hash) }
                                $sandboxReport.attributes.processes_created | ForEach-Object { if($null -ne $_) { $allData.ProcsCreated.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                            }
                            if ($null -ne $sandboxReport.attributes.processes_terminated) {
                                if (-not $foundHashFiles.ContainsKey('ProcsTerminated')) { $foundHashFiles['ProcsTerminated'] = [System.Collections.Generic.List[string]]::new() }
                                if (-not $foundHashFiles['ProcsTerminated'].Contains($hash)) { $foundHashFiles['ProcsTerminated'].Add($hash) }
                                $sandboxReport.attributes.processes_terminated | ForEach-Object { if($null -ne $_) { $allData.ProcsTerminated.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                            }
                            if ($null -ne $sandboxReport.attributes.dns_lookups) {
                                if (-not $foundHashFiles.ContainsKey('DnsLookups')) { $foundHashFiles['DnsLookups'] = [System.Collections.Generic.List[string]]::new() }
                                if (-not $foundHashFiles['DnsLookups'].Contains($hash)) { $foundHashFiles['DnsLookups'].Add($hash) }
                                foreach($lookup in $sandboxReport.attributes.dns_lookups) {
                                    if ($null -ne $lookup -and $lookup.PSObject.Properties.Name -contains 'hostname') {
                                        $allData.DnsLookups.Add([PSCustomObject]@{ Property = "Hostname: $($lookup.hostname)"; SourceHash = $hash })
                                        if ($null -ne $lookup.resolved_ips) {
                                            $lookup.resolved_ips | ForEach-Object { if($null -ne $_) { $allData.DnsLookups.Add([PSCustomObject]@{ Property = "Resolved IP: $_"; SourceHash = $hash }) } }
                                        }
                                    }
                                }
                            }
                            if ($null -ne $sandboxReport.attributes.signature_matches) {
                                $urlSignature = $sandboxReport.attributes.signature_matches | Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains 'id' -and $_.id -eq "238" }
                                if ($null -ne $urlSignature) {
                                    if (-not $foundHashFiles.ContainsKey('Urls')) { $foundHashFiles['Urls'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['Urls'].Contains($hash)) { $foundHashFiles['Urls'].Add($hash) }
                                    $urlSignature.match_data | ForEach-Object { if($null -ne $_) { $allData.Urls.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }
                            }
                            if ($null -ne $sandboxReport.attributes.files_opened) {
                                if (-not $foundHashFiles.ContainsKey('FilesOpened')) { $foundHashFiles['FilesOpened'] = [System.Collections.Generic.List[string]]::new() }
                                if (-not $foundHashFiles['FilesOpened'].Contains($hash)) { $foundHashFiles['FilesOpened'].Add($hash) }
                                foreach ($file_path in $sandboxReport.attributes.files_opened) {
                                    if ($null -ne $file_path -and ($file_path.EndsWith(".exe", [System.StringComparison]::OrdinalIgnoreCase) -or $file_path.EndsWith(".dll", [System.StringComparison]::OrdinalIgnoreCase))) {
                                        $allData.FilesOpened.Add([PSCustomObject]@{ Property = $file_path; SourceHash = $hash })
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        # --- Step 4: Analysis and Reporting Functions (Unchanged) ---
        function Get-DifferentialAnalysis($dataList, $totalFiles) {
            if ($totalFiles -lt 2) { return @{ HasDifferences = $false; Results = $null } }
            $analysis = @{ HasDifferences = $false; Results = [System.Collections.Generic.List[object]]::new() }
            $groupedData = $dataList | Group-Object -Property Property
            foreach ($group in $groupedData) {
                $sourceHashes = @($group.Group | Select-Object -ExpandProperty SourceHash -Unique)
                $count = $sourceHashes.Count
                $result = [PSCustomObject]@{ Property = $group.Name; Count = $count; SourceHashes = $sourceHashes }
                if ($count -ne $totalFiles) {
                    $analysis.HasDifferences = $true
                }
                $analysis.Results.Add($result)
            }
            return $analysis
        }

        $analysisResults = @{}
        $analysisConfig = @{ Imports = "Analysis of 'import_list'"; Certs = "Analysis of 'signature_info'"; IPs = "Analysis of 'destination_ip'"; DnsLookups = "Analysis of 'dns_lookups'"; ProcsCreated = "Analysis of 'processes_created'"; ProcsTerminated = "Analysis of 'processes_terminated'"; Urls = "Analysis of URLs Found in Memory (Sig#238)"; FilesOpened = "Analysis of Files Opened (.exe/.dll)" }

        foreach($category in $analysisConfig.Keys){
            $fileCount = if($foundHashFiles.ContainsKey($category)){ ($foundHashFiles[$category] | Select-Object -Unique).Count } else { 0 }
            $analysisResults[$category] = Get-DifferentialAnalysis $allData[$category] $fileCount
        }
        
        # --- Reporting Section ---
        $anomaliesForTargetHash = @{}
        $anyAnomaliesFound = $false
        foreach ($category in $analysisResults.Keys) {
            $result = $analysisResults[$category]
            if ($result -and $result.HasDifferences) {
                $uniqueToTarget = $result.Results | Where-Object { $_.Count -eq 1 -and $_.SourceHashes[0] -eq $TargetHash }
                if ($uniqueToTarget) {
                    $anomaliesForTargetHash[$category] = $uniqueToTarget
                    $anyAnomaliesFound = $true
                }
            }
        }

        if ($anyAnomaliesFound) {
            $outputDir = Split-Path -Path $OutputFilePath -Parent
            if (-not (Test-Path -Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
            $fileHeader = "Anomaly Report for '$ProcessName' - Focusing on Hash '$TargetHash' - $(Get-Date)"
            Set-Content -Path $OutputFilePath -Value $fileHeader
            Add-Content -Path $OutputFilePath -Value ('-' * $fileHeader.Length)

            $header = "ANOMALIES FOUND for Hash: $TargetHash (Process: $ProcessName)"
            $separator = '=' * $header.Length
            Write-Host "`n$($separator)" -ForegroundColor Magenta; Add-Content -Path $($OutputFilePath) -Value "`n$separator"
            Write-Host $header -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value $header
            Write-Host "$($separator)" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value $separator
            
            # --- MODIFIED: Add note to the report if the hash was manually included ---
            if ($targetHashManuallyAdded) {
                $note = "NOTE: The target hash was not found under the name '$ProcessName' and was added manually to this analysis."
                Write-Host $note -ForegroundColor Yellow
                Add-Content -Path $OutputFilePath -Value $note
            }

            foreach ($category in $anomaliesForTargetHash.Keys) {
                $fileCount = if ($foundHashFiles.ContainsKey($category)) { ($foundHashFiles[$category] | Select-Object -Unique).Count } else { 0 }
                $subHeader = "--- $($analysisConfig[$category]) (Compared across $fileCount total files) ---"
                Write-Host "`n$subHeader" -ForegroundColor Cyan
                Add-Content -Path $OutputFilePath -Value "`n$subHeader"
                
                foreach ($item in $anomaliesForTargetHash[$category]) {
                    $line1 = "[UNIQUE] $($item.Property)"
                    Write-Host $line1 -ForegroundColor Red
                    Add-Content -Path $OutputFilePath -Value $line1
                    $line2 = "       └─ Found only in: $($item.SourceHashes[0])"
                    Write-Host $line2
                    Add-Content -Path $OutputFilePath -Value $line2
                }
            }
            Write-Host "`n--- Analysis Complete. Report saved to '$($OutputFilePath)' ---" -ForegroundColor Green
        } else {
            Write-Host "`n--- Analysis Complete. No unique anomalies found for hash '$($TargetHash)' when compared to other '$ProcessName' samples. ---" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "An unexpected error occurred: $_"
        if ($_.Exception.InnerException) { Write-Error "Inner Exception: $($_.Exception.InnerException.Message)" }
    }
}