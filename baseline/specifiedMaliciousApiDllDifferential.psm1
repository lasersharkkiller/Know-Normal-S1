<#
.SYNOPSIS
    Prompts the user for a text file containing a specific list of hashes.
    Compares the API usage of those specific files against the full Baseline to find unique traits.
#>
function Get-SpecifiedApiDllDifferentialAnalysis {
    param (
        [Parameter(Mandatory=$false)]
        [string]$TargetHashList,
        
        [string]$BasePath = ".\output-baseline\VirusTotal-main",
        [string]$JsonExportPath = ".\baseline\TargetedAPIDifferentialAnalysis.json"
    )

    $MaliciousPath = Join-Path -Path $BasePath -ChildPath "malicious"
    
    # Ensure export directory exists
    $ExportDir = Split-Path -Path $JsonExportPath -Parent
    if (-not (Test-Path $ExportDir)) { New-Item -ItemType Directory -Force -Path $ExportDir | Out-Null }

    Write-Host "Starting TARGETED API/DLL Differential Analysis..." -ForegroundColor Cyan

    # --- 1. PROMPT LOGIC ---
    if ([string]::IsNullOrWhiteSpace($TargetHashList)) {
        Write-Host "[?] Please enter the full path to your Target Hash List (txt file):" -ForegroundColor Yellow
        $TargetHashList = Read-Host
    }

    # Clean path (remove quotes)
    $TargetHashList = $TargetHashList -replace '"', ''

    # --- SMART PATH FIX ---
    # If the exact path doesn't exist, try resolving it relative to the current directory
    if (-not (Test-Path $TargetHashList)) {
        $RelativePath = ".\$($TargetHashList.TrimStart('\'))"
        if (Test-Path $RelativePath) {
            $TargetHashList = $RelativePath
        }
    }

    if (-not (Test-Path $TargetHashList)) {
        Write-Error "Target list not found at: $TargetHashList"
        return
    }
    
    $TargetHashes = Get-Content -Path $TargetHashList
    Write-Host " Loaded $($TargetHashes.Count) target hashes from: $TargetHashList" -ForegroundColor Gray

    # --- 2. HELPER FUNCTION ---
    function Get-ApiCounts ($FileList) {
        $Counts = @{}
        $TotalFiles = 0

        foreach ($File in $FileList) {
            $TotalFiles++
            try {
                $Json = Get-Content -Path $File.FullName -Raw | ConvertFrom-Json
                $Imports = $Json.data.attributes.pe_info.import_list

                if ($Imports) {
                    foreach ($Dll in $Imports) {
                        $DllName = $Dll.library_name
                        foreach ($Func in $Dll.imported_functions) {
                            # Key format: "DLL!Function"
                            $Key = "$DllName!$Func"
                            if (-not $Counts.ContainsKey($Key)) { $Counts[$Key] = 0 }
                            $Counts[$Key]++
                        }
                    }
                }
            }
            catch { Write-Warning "Could not parse $($File.Name)" }
        }
        return @{ Counts = $Counts; Total = $TotalFiles }
    }

    # --- 3. COLLECT TARGET FILES ---
    $TargetFiles = @()
    foreach ($Hash in $TargetHashes) {
        $FilePath = Join-Path -Path $MaliciousPath -ChildPath "$Hash.json"
        if (Test-Path $FilePath) {
            $TargetFiles += Get-Item -Path $FilePath
        }
    }

    if ($TargetFiles.Count -eq 0) {
        Write-Warning "No analysis files found for the provided hashes. Have you run the VT Baseline script yet?"
        return
    }

    Write-Host " Scanning Target dataset..." -NoNewline
    $MalData = Get-ApiCounts -FileList $TargetFiles
    Write-Host " Done ($($MalData.Total) files found)." -ForegroundColor Green

    # --- 4. ANALYZE BASELINE ---
    Write-Host " Scanning Baseline dataset..." -NoNewline
    if (Test-Path $BasePath) {
        # Get files in root ONLY (using -File prevents recursion)
        $BaseFiles = Get-ChildItem -Path $BasePath -File -Filter "*.json"
        $BaseData  = Get-ApiCounts -FileList $BaseFiles
        Write-Host " Done ($($BaseData.Total) files)." -ForegroundColor Green
    } else {
        Write-Error "Baseline folder not found at $BasePath"
        return
    }

    # --- 5. CALCULATE RARITY ---
    Write-Host " Calculating Baseline Rarity..." -ForegroundColor Cyan
    $Results = @()

    foreach ($Api in $MalData.Counts.Keys) {
        $MalCount  = $MalData.Counts[$Api]
        
        # Check if this API exists in the baseline
        $BaseCount = if ($BaseData.Counts[$Api]) { $BaseData.Counts[$Api] } else { 0 }

        # Calculate Baseline Frequency
        $BaseFreqRaw = if ($BaseData.Total -gt 0) { $BaseCount / $BaseData.Total } else { 0 }
        $BaseFreqPercent = [Math]::Round($BaseFreqRaw * 100, 4)

        # Rarity Score (100 = Never seen in baseline)
        $RarityScore = 100 - $BaseFreqPercent

        $Results += [PSCustomObject]@{
            API_Name              = $Api
            Baseline_Rarity_Score = $RarityScore
            Baseline_Frequency    = "$BaseFreqPercent%"
            Baseline_Count        = $BaseCount
            Target_Count          = $MalCount
        }
    }

    # --- 6. EXPORT ---
    # Sort by Rarity Score Descending, then by Target Count Descending
    $SortedResults = $Results | Sort-Object Baseline_Rarity_Score, Target_Count -Descending

    # Console Output (Top 20)
    Write-Host "`nTop 20 APIs present in Target List but RAREST in Baseline:" -ForegroundColor Yellow
    $SortedResults | Select-Object -First 20 | Format-Table -AutoSize

    # JSON Export
    $SortedResults | ConvertTo-Json -Depth 4 | Set-Content -Path $JsonExportPath
    Write-Host "Full Targeted Analysis saved to: $JsonExportPath" -ForegroundColor Gray
}