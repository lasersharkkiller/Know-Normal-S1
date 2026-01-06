<#
.SYNOPSIS
    Identifies API imports found in Malicious files and ranks them by their 
    RARITY in the Baseline dataset. 
    Ignores how frequent the API is within the malicious set itself.
#>
function Get-MaliciousApiDllDifferentialAnalysis {
    param (
        [string]$BasePath = ".\output-baseline\VirusTotal-main",
        [string]$JsonExportPath = ".\baseline\APIDifferentialAnalysis.json"
    )

    $MaliciousPath = Join-Path -Path $BasePath -ChildPath "malicious"
    
    # Ensure export directory exists
    $ExportDir = Split-Path -Path $JsonExportPath -Parent
    if (-not (Test-Path $ExportDir)) { New-Item -ItemType Directory -Force -Path $ExportDir | Out-Null }

    Write-Host "Starting Baseline Rarity Analysis..." -ForegroundColor Cyan

    # 1. Define Helper to extract APIs
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

    # 2. Analyze Datasets
    if (-not (Test-Path $MaliciousPath)) { Write-Error "Malicious folder not found."; return }
    if (-not (Test-Path $BasePath)) { Write-Error "Baseline folder not found."; return }

    Write-Host " Scanning Malicious dataset..." -NoNewline
    $MalFiles = Get-ChildItem -Path $MaliciousPath -Filter "*.json"
    $MalData  = Get-ApiCounts -FileList $MalFiles
    Write-Host " Done ($($MalData.Total) files)." -ForegroundColor Green

    Write-Host " Scanning Baseline dataset..." -NoNewline
    # Get files in root ONLY (using -File prevents recursion)
    $BaseFiles = Get-ChildItem -Path $BasePath -File -Filter "*.json"
    $BaseData  = Get-ApiCounts -FileList $BaseFiles
    Write-Host " Done ($($BaseData.Total) files)." -ForegroundColor Green

    # 3. Calculate Rarity Logic
    Write-Host " Calculating Baseline Rarity..." -ForegroundColor Cyan
    $Results = @()

    # Iterate ONLY through APIs found in the Malicious dataset
    foreach ($Api in $MalData.Counts.Keys) {
        $MalCount  = $MalData.Counts[$Api]
        
        # Check if this API exists in the baseline
        $BaseCount = if ($BaseData.Counts[$Api]) { $BaseData.Counts[$Api] } else { 0 }

        # Calculate Baseline Frequency (Percentage)
        $BaseFreqRaw = if ($BaseData.Total -gt 0) { $BaseCount / $BaseData.Total } else { 0 }
        $BaseFreqPercent = [Math]::Round($BaseFreqRaw * 100, 4)

        # Baseline Rarity Score:
        # 100 = Unique to Malware (Never seen in baseline)
        # 0   = Extremely common in baseline
        $RarityScore = 100 - $BaseFreqPercent

        $Results += [PSCustomObject]@{
            API_Name              = $Api
            Baseline_Rarity_Score = $RarityScore
            Baseline_Frequency    = "$BaseFreqPercent%"
            Baseline_Count        = $BaseCount
            Malicious_Count       = $MalCount
        }
    }

    # 4. Sort and Export
    # Sort by Rarity Score Descending (Unique items first), then by Malicious Count Descending
    $SortedResults = $Results | Sort-Object Baseline_Rarity_Score, Malicious_Count -Descending

    # Console Output (Top 20 Unique/Rare APIs)
    Write-Host "`nTop 20 APIs present in Malware but RAREST in Baseline:" -ForegroundColor Yellow
    $SortedResults | Select-Object -First 20 | Format-Table -AutoSize

    # JSON Export
    $SortedResults | ConvertTo-Json -Depth 4 | Set-Content -Path $JsonExportPath
    Write-Host "Full JSON analysis saved to: $JsonExportPath" -ForegroundColor Gray
}