function Get-CheckWAFPerimeterAttacks {

    Import-Module ".\nsm\bulkipcheck.psm1"

    # ---- CONFIG ----
    $accessToken = Get-Secret -Name 'Devo_Access_Token' -AsPlainText
    $apiUrl      = "https://apiv2-us.devo.com/search/query"
    
    # Files
    $processName     = "waf" # Used for the bulkipcheck naming convention
    $rawDedupCsv     = "devoQueries\waf_topAttackers.csv"
    $finalEnrichedCsv= "devoQueries\waf_topAttackers_withEnrichedData.csv"
    
    # Bridge File for BulkIPCheck (Must match the expected path in source 23)
    $bridgeJson = "output\$($processName)-dstIps.json"

    # ---- HEADERS ----
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }

    # ---- DYNAMIC DATES ----
    $utcNow   = (Get-Date).ToUniversalTime()
    $timeNow  = $utcNow.ToString("yyyy-MM-dd HH:mm:ss.000")
    $timePrev = $utcNow.AddDays(-7).ToString("yyyy-MM-dd HH:mm:ss.000")

    Write-Host "Time Range: $timePrev to $timeNow" -ForegroundColor Gray

    # ---- DEVO QUERY ----
    $devoQuery = @"
from my.app.f5.asm
  where timestamp("$timePrev") <= eventdate < timestamp("$timeNow")
  select peek(rawMessage, re("X-Forwarded-For:\\s+((?:\\d{1,3}\\.){3}\\d{1,3})"), 1) as _XFF,
    isnotnull(_XFF) ? _XFF : ipClient as XFF
  where ispublic(ip4(XFF)) and isnull(lu("WAF_IPs_Allowed", "IP", ip4(XFF))) and isnull(lu("WAF_CIDR_Allowed", "CIDR", ip4(XFF))),
    (request ->> "Qualys") = false,
    (request ->> "datadog") = false
  group by XFF
  select count() as Count
"@ 
    $flatQuery = $devoQuery -replace "`r`n"," " -replace "`n"," "

    # ---- QUERY BODY ----
    $bodyObj = @{
        query = $flatQuery
        from  = "now()-1h"
        to    = "now()"
        mode  = @{ type = "csv" }
    }
    
    $bodyJson = $bodyObj | ConvertTo-Json -Depth 5
    $bodyJson = $bodyJson -replace "\\u003c", "<"

    # ---- STEP 1: EXECUTION ----
    Write-Host "Querying Devo Network Attacks..." -ForegroundColor Cyan
    
    try {
        $response = Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $bodyJson -TimeoutSec 300
        
        if ($null -eq $response) { Write-Warning "Empty response."; return }
        $rawData = $response | ConvertFrom-Csv
        
        if ($rawData.Count -eq 0) { Write-Warning "Query returned 0 results."; return }
        
        Write-Host "Raw Results: $($rawData.Count) IPs. Starting /24 Deduplication..." -ForegroundColor Cyan

        # ---- STEP 2: DEDUPLICATION WITH PROGRESS BAR ----
        
        # 2a. Pre-calculate groups (Fast)
        $groupedData = $rawData | 
            Select-Object *, @{Name="Subnet"; Expression={ ($_.XFF -split "\.")[0..2] -join "." }} |
            Group-Object Subnet
            
        # 2b. Process groups with Progress Bar
        $totalGroups = $groupedData.Count
        $counter = 0
        $dedupedData = @()

        foreach ($group in $groupedData) {
            $counter++
            
            # Update Progress every 10 items (to speed up processing)
            if ($counter % 10 -eq 0) {
                $percent = [math]::Round(($counter / $totalGroups) * 100)
                Write-Progress -Activity "Deduplicating Subnets" -Status "Processing Subnet $counter of $totalGroups" -PercentComplete $percent
            }

            # Logic: Keep IP with highest Count in the subnet
            $topIp = $group.Group | Sort-Object -Property @{Expression={[int]$_.Count}} -Descending | Select-Object -First 1
            $dedupedData += ($topIp | Select-Object XFF, Count)
        }
        Write-Progress -Activity "Deduplicating Subnets" -Completed

        # ---- STEP 3: EXPORT RAW DEDUPLICATED LIST ----
        $dedupedData | Export-Csv -Path $rawDedupCsv -NoTypeInformation -Encoding ASCII
        Write-Host "Saved deduplicated list to: $rawDedupCsv" -ForegroundColor Gray

        # ---- STEP 4: BRIDGE TO 'BULKIPCHECK' ----
        Write-Host "Preparing data for APIVoid Enrichment..." -ForegroundColor Cyan

        # 4b. Format data exactly as 'Get-CheckBulkIpsApiVoid' expects (Simple Array of Strings in JSON)
        # Source 28/29 implies it can handle a simple array of strings.
        $ipList = $dedupedData.XFF
        $ipList | ConvertTo-Json -Depth 2 | Set-Content -Path $bridgeJson -Encoding ASCII

        Write-Host "Bridge file created at: $bridgeJson" -ForegroundColor Gray

        # ---- STEP 5: RUN BULK IP CHECK ----
        Write-Host "Invoking Get-CheckBulkIpsApiVoid..." -ForegroundColor Cyan
        Get-CheckBulkIpsApiVoid -process $processName

        # ---- STEP 6: FINALIZE OUTPUT ----
        # The bulk script saves to: $PSScriptRoot\$($process)-ip_results_apivoid.csv
        $expectedOutput = "output\$($processName)-ip_results_apivoid.csv"

        if (Test-Path $expectedOutput) {
            Copy-Item -Path $expectedOutput -Destination $finalEnrichedCsv -Force
            Write-Host "`n------------------------------------------------" -ForegroundColor Green
            Write-Host "FINAL SUCCESS" -ForegroundColor Green
            Write-Host "Enriched Report: $finalEnrichedCsv" -ForegroundColor Green
            Write-Host "------------------------------------------------" -ForegroundColor Green
        } else {
            Write-Warning "Enrichment script finished, but could not find expected output file: $expectedOutput"
        }

    } catch {
        Write-Error "An error occurred."
        Write-Error "Details: $($_.Exception.Message)"
    }
}