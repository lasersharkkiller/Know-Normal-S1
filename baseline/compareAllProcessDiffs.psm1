function Get-CompareAllProcessDiffs {

    [string]$HashFilesPath = ".\output-baseline\VirusTotal-main\"
    [string]$BehaviorsFilesPath = ".\output-baseline\VirusTotal-behaviors\"
    [string]$OutputFilePath = ".\output\process_differentials.txt"

    # --- ANSI Color Codes ---
    $esc = "$([char]27)"
    $colors = @{ Green = "$([char]27)[92m"; Yellow = "$([char]27)[93m"; Red = "$([char]27)[91m"; Magenta = "$([char]27)[95m"; Cyan = "$([char]27)[96m"; Reset = "$([char]27)[0m" }

    # --- Step 1: Validate paths ---
    if (-not (Test-Path -Path $HashFilesPath -PathType Container)) { Write-Error "Directory for main hash files not found at: $HashFilesPath"; return }
    if (-not (Test-Path -Path $BehaviorsFilesPath -PathType Container)) { Write-Error "Directory for behavior hash files not found at: $BehaviorsFilesPath"; return }

    Write-Host "Starting automated analysis for all processes..." -ForegroundColor Cyan

    try {
        # --- Step 2: Dynamically discover all processes and their hashes ---
        Write-Host "Discovering processes from reports in '$HashFilesPath'..."
        $processToHashesMap = @{}
        $reportFiles = Get-ChildItem -Path $HashFilesPath -Filter "*.json"

        foreach ($file in $reportFiles) {
            $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($null -eq $jsonContent -or $null -eq $jsonContent.data -or $null -eq $jsonContent.data.attributes -or $null -eq $jsonContent.data.attributes.names) {
                continue
            }
            # A file can have multiple names; we associate the hash with each name.
            foreach ($processName in $jsonContent.data.attributes.names) {
                if (-not $processToHashesMap.ContainsKey($processName)) {
                    $processToHashesMap[$processName] = [System.Collections.Generic.List[string]]::new()
                }
                if (-not $processToHashesMap[$processName].Contains($file.BaseName)) {
                    $processToHashesMap[$processName].Add($file.BaseName)
                }
            }
        }
        
        Write-Host "Found $($processToHashesMap.Keys.Count) unique processes to analyze."
        $allProcessResults = [System.Collections.Generic.List[object]]::new()

        # --- Loop through each unique process ---
        foreach ($processName in $processToHashesMap.Keys | Sort-Object) {
            $hashes = $processToHashesMap[$processName]

            if ($hashes.Count -lt 2) { continue } # Skip processes with only one hash

            # --- Step 3: Data Collection ---
            $allData = @{
                Imports         = [System.Collections.Generic.List[psobject]]::new()
                Certs           = [System.Collections.Generic.List[psobject]]::new()
                IPs             = [System.Collections.Generic.List[psobject]]::new()
                DnsLookups      = [System.Collections.Generic.List[psobject]]::new()
                ProcsCreated    = [System.Collections.Generic.List[psobject]]::new()
                ProcsTerminated = [System.Collections.Generic.List[psobject]]::new()
                Urls            = [System.Collections.Generic.List[psobject]]::new()
                FilesOpened     = [System.Collections.Generic.List[psobject]]::new()
            }
            $foundHashFiles = @{}

            foreach ($hash in $hashes) {
                # Process Main Report
                $mainHashFilePath = Join-Path -Path $HashFilesPath -ChildPath "$($hash).json"
                if (Test-Path $mainHashFilePath) {
                    $mainJson = Get-Content -Path $mainHashFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($null -ne $mainJson -and $null -ne $mainJson.data -and $null -ne $mainJson.data.attributes) {
                        # Imports
                        if ($null -ne $mainJson.data.attributes.pe_info -and $null -ne $mainJson.data.attributes.pe_info.import_list) {
                            if (-not $foundHashFiles.ContainsKey('Imports')) { $foundHashFiles['Imports'] = [System.Collections.Generic.List[string]]::new() }
                            if (-not $foundHashFiles['Imports'].Contains($hash)) { $foundHashFiles['Imports'].Add($hash) }
                            $mainJson.data.attributes.pe_info.import_list | ForEach-Object { if($null -ne $_ -and $_.PSObject.Properties.Name -contains 'library_name') { $allData.Imports.Add([PSCustomObject]@{ Property = $_.library_name; SourceHash = $hash }) } }
                        }
                        # Certs
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

                # Process Behaviors Report
                $behaviorsFilePath = Join-Path -Path $BehaviorsFilesPath -ChildPath "$($hash).json"
                if (Test-Path $behaviorsFilePath) {
                    $behaviorsJson = Get-Content -Path $behaviorsFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($null -ne $behaviorsJson -and $null -ne $behaviorsJson.data) {
                        foreach ($sandboxReport in $behaviorsJson.data) {
                            if ($null -ne $sandboxReport -and $null -ne $sandboxReport.attributes) {
                                # IP Traffic
                                if ($null -ne $sandboxReport.attributes.ip_traffic) {
                                    if (-not $foundHashFiles.ContainsKey('IPs')) { $foundHashFiles['IPs'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['IPs'].Contains($hash)) { $foundHashFiles['IPs'].Add($hash) }
                                    $sandboxReport.attributes.ip_traffic | ForEach-Object { if($null -ne $_ -and $_.PSObject.Properties.Name -contains 'destination_ip') { $allData.IPs.Add([PSCustomObject]@{ Property = $_.destination_ip; SourceHash = $hash }) } }
                                }
                                # Processes Created
                                if ($null -ne $sandboxReport.attributes.processes_created) {
                                    if (-not $foundHashFiles.ContainsKey('ProcsCreated')) { $foundHashFiles['ProcsCreated'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['ProcsCreated'].Contains($hash)) { $foundHashFiles['ProcsCreated'].Add($hash) }
                                    $sandboxReport.attributes.processes_created | ForEach-Object { if($null -ne $_) { $allData.ProcsCreated.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }
                                # Processes Terminated
                                if ($null -ne $sandboxReport.attributes.processes_terminated) {
                                    if (-not $foundHashFiles.ContainsKey('ProcsTerminated')) { $foundHashFiles['ProcsTerminated'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['ProcsTerminated'].Contains($hash)) { $foundHashFiles['ProcsTerminated'].Add($hash) }
                                    $sandboxReport.attributes.processes_terminated | ForEach-Object { if($null -ne $_) { $allData.ProcsTerminated.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }
                                # DNS Lookups
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
                                # URLs Found In Memory from Signature #238
                                if ($null -ne $sandboxReport.attributes.signature_matches) {
                                    $urlSignature = $sandboxReport.attributes.signature_matches | Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains 'id' -and $_.id -eq "238" }
                                    if ($null -ne $urlSignature) {
                                        if (-not $foundHashFiles.ContainsKey('Urls')) { $foundHashFiles['Urls'] = [System.Collections.Generic.List[string]]::new() }
                                        if (-not $foundHashFiles['Urls'].Contains($hash)) { $foundHashFiles['Urls'].Add($hash) }
                                        $urlSignature.match_data | ForEach-Object { if($null -ne $_) { $allData.Urls.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                    }
                                }
                                # Files Opened (.exe/.dll)
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

            # --- Analysis Function ---
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

            # --- Run Dynamic Analysis ---
            $processResult = @{ ProcessName = $processName; AnyDifferences = $false; AnalysisResults = @{} }
            $analysisConfig = @{
                Imports         = "Analysis of 'import_list'"
                Certs           = "Analysis of 'signature_info'"
                IPs             = "Analysis of 'destination_ip'"
                DnsLookups      = "Analysis of 'dns_lookups'"
                ProcsCreated    = "Analysis of 'processes_created'"
                ProcsTerminated = "Analysis of 'processes_terminated'"
                Urls            = "Analysis of URLs Found in Memory (Sig#238)"
                FilesOpened     = "Analysis of Files Opened (.exe/.dll)"
            }

            foreach($category in $analysisConfig.Keys){
                $fileCount = if($foundHashFiles.ContainsKey($category)){ ($foundHashFiles[$category] | Select-Object -Unique).Count } else { 0 }
                $result = Get-DifferentialAnalysis $allData[$category] $fileCount
                $processResult.AnalysisResults[$category] = @{ Result = $result; FileCount = $fileCount }
                if($result -and $result.HasDifferences){
                    $processResult.AnyDifferences = $true
                }
            }

            if($processResult.AnyDifferences){
                $allProcessResults.Add($processResult)
            }
        }
        
        # --- Step 4: Dynamic Reporting ---
        if ($allProcessResults.Count -gt 0) {
            $outputDir = Split-Path -Path $OutputFilePath -Parent
            if (-not (Test-Path -Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
            $fileHeader = "Differential Analysis Report - $(Get-Date)"; Set-Content -Path $OutputFilePath -Value $fileHeader; Add-Content -Path $OutputFilePath -Value ('-' * $fileHeader.Length)
            
            function Write-AnalysisSection($analysis, $title, $totalFiles, $colors, $OutputFilePath) {
                if ($analysis -and $analysis.Results) {
                    $subHeader = "--- $title (Compared across $totalFiles files) ---"
                    Write-Host "`n$subHeader" -ForegroundColor Cyan; Add-Content -Path $OutputFilePath -Value "`n$($colors.Cyan)$subHeader$($colors.Reset)"
                    foreach ($item in $analysis.Results) {
                        $line1 = "$($item.Type) $($item.Property)"; Write-Host $line1 -ForegroundColor $item.Color; Add-Content -Path $OutputFilePath -Value "$($colors[$item.Color])$line1$($colors.Reset)"
                        if ($item.Color -ne 'Green') {
                            $line2 = if ($item.Color -eq 'Red') { "       └─ Found only in: $($item.SourceHashes[0])" } else { "        └─ Found in $($item.Count) of $totalFiles files: $($item.SourceHashes -join ', ')" }
                            Write-Host $line2; Add-Content -Path $OutputFilePath -Value $line2
                        }
                    }
                }
            }

            foreach($processResult in $allProcessResults){
                $header = "DIFFERENCES FOUND for Process: $($processResult.ProcessName)"; $separator = '=' * $header.Length
                Write-Host "`n$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "`n$($colors.Magenta)$separator$($colors.Reset)"
                Write-Host $header -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$header$($colors.Reset)"
                Write-Host "$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$separator$($colors.Reset)"

                foreach($category in $processResult.AnalysisResults.Keys){
                    $categoryResult = $processResult.AnalysisResults[$category]
                    if($categoryResult.Result -and $categoryResult.Result.HasDifferences){
                        Write-AnalysisSection $categoryResult.Result $analysisConfig[$category] $categoryResult.FileCount $colors $OutputFilePath
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
        if ($_.Exception.InnerException) { Write-Error "Inner Exception: $($_.Exception.InnerException.Message)" }
    }
}

