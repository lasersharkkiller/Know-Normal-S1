function Get-CompareSingleProcessDiffs {

    param (
        [Parameter(Mandatory = $true, HelpMessage = "The process name to query.")]
        [string]$ProcessName
    )
    
    [string]$HashFilesPath = ".\output-baseline\VirusTotal-main\"
    [string]$BehaviorsFilesPath = ".\output-baseline\VirusTotal-behaviors\"
    [string]$OutputFilePath = ".\output\singleProc_differentials.txt"

    # --- ANSI Color Codes ---
    $esc = "$([char]27)"
    $colors = @{ Green = "$([char]27)[92m"; Yellow = "$([char]27)[93m"; Red = "$([char]27)[91m"; Magenta = "$([char]27)[95m"; Cyan = "$([char]27)[96m"; Reset = "$([char]27)[0m" }

    # --- Step 1: Validate paths ---
    if (-not (Test-Path -Path $HashFilesPath -PathType Container)) { Write-Error "Directory for main hash files not found at: $HashFilesPath"; return }
    if (-not (Test-Path -Path $BehaviorsFilesPath -PathType Container)) { Write-Error "Directory for behavior hash files not found at: $BehaviorsFilesPath"; return }

    Write-Host "Starting analysis for process: $ProcessName" -ForegroundColor Cyan

    try {
        # --- Step 2: Find all hashes for the specified process ---
        Write-Host "Searching for reports related to '$ProcessName'..."
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

        if ($hashes.Count -eq 0) { Write-Warning "No reports found for process '$ProcessName'."; return }
        if ($hashes.Count -lt 2) { Write-Warning "Fewer than two hashes found for process '$ProcessName'. No comparison to perform."; return }
        
        Write-Host "Found $($hashes.Count) hashes to compare for '$ProcessName'."

        # --- Step 3: Data Collection ---
        $allData = @{
            Imports         = [System.Collections.Generic.List[psobject]]::new()
            Certs           = [System.Collections.Generic.List[psobject]]::new()
            IPs             = [System.Collections.Generic.List[psobject]]::new()
            DnsLookups      = [System.Collections.Generic.List[psobject]]::new()
            ProcsCreated    = [System.Collections.Generic.List[psobject]]::new()
            ProcsTerminated = [System.Collections.Generic.List[psobject]]::new()
            Urls            = [System.Collections.Generic.List[psobject]]::new()
            FilesOpened     = [System.Collections.Generic.List[psobject]]::new() # NEW CATEGORY
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
                            # URLs in Memory from Signature #238
                            if ($null -ne $sandboxReport.attributes.signature_matches) {
                                $urlSignature = $sandboxReport.attributes.signature_matches | Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains 'id' -and $_.id -eq "238" }
                                if ($null -ne $urlSignature) {
                                    if (-not $foundHashFiles.ContainsKey('Urls')) { $foundHashFiles['Urls'] = [System.Collections.Generic.List[string]]::new() }
                                    if (-not $foundHashFiles['Urls'].Contains($hash)) { $foundHashFiles['Urls'].Add($hash) }
                                    $urlSignature.match_data | ForEach-Object { if($null -ne $_) { $allData.Urls.Add([PSCustomObject]@{ Property = $_; SourceHash = $hash }) } }
                                }
                            }
                            # NEW: Files Opened (.exe/.dll)
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

        # --- Step 4: Analysis and Reporting Functions ---
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

        # MODIFIED: Dynamic Analysis Section
        $analysisResults = @{}
        $anyDifferencesFound = $false

        $analysisConfig = @{
            Imports         = "Analysis of 'import_list'"
            Certs           = "Analysis of 'signature_info'"
            IPs             = "Analysis of 'destination_ip'"
            DnsLookups      = "Analysis of 'dns_lookups'"
            ProcsCreated    = "Analysis of 'processes_created'"
            ProcsTerminated = "Analysis of 'processes_terminated'"
            Urls            = "Analysis of URLs Found in Memory (Sig#238)"
            FilesOpened     = "Analysis of Files Opened (.exe/.dll)" # NEW
        }

        foreach($category in $analysisConfig.Keys){
            $fileCount = if($foundHashFiles.ContainsKey($category)){ ($foundHashFiles[$category] | Select-Object -Unique).Count } else { 0 }
            $result = Get-DifferentialAnalysis $allData[$category] $fileCount
            $analysisResults[$category] = $result
            if($result -and $result.HasDifferences){
                $anyDifferencesFound = $true
            }
        }
        
        # MODIFIED: Dynamic Reporting Section
        if ($anyDifferencesFound) {
            $outputDir = Split-Path -Path $OutputFilePath -Parent
            if (-not (Test-Path -Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
            $fileHeader = "Differential Analysis Report for '$ProcessName' - $(Get-Date)"; Set-Content -Path $OutputFilePath -Value $fileHeader; Add-Content -Path $OutputFilePath -Value ('-' * $fileHeader.Length)
            $header = "DIFFERENCES FOUND for Process: $ProcessName"; $separator = '=' * $header.Length
            
            Write-Host "`n$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "`n$($colors.Magenta)$separator$($colors.Reset)"
            Write-Host $header -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$header$($colors.Reset)"
            Write-Host "$separator" -ForegroundColor Magenta; Add-Content -Path $OutputFilePath -Value "$($colors.Magenta)$separator$($colors.Reset)"
            
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

            foreach($category in $analysisResults.Keys){
                $result = $analysisResults[$category]
                if($result -and $result.HasDifferences){
                    $fileCount = if($foundHashFiles.ContainsKey($category)){ ($foundHashFiles[$category] | Select-Object -Unique).Count } else { 0 }
                    Write-AnalysisSection $result $analysisConfig[$category] $fileCount $colors $OutputFilePath
                }
            }
            
            Write-Host "`n--- Analysis Complete. Report saved to '$OutputFilePath' ---" -ForegroundColor Green
        } else {
            Write-Host "`n--- Analysis Complete. No differences found for '$ProcessName'. ---\" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "An unexpected error occurred: $_"
        if ($_.Exception.InnerException) { Write-Error "Inner Exception: $($_.Exception.InnerException.Message)" }
    }
}

