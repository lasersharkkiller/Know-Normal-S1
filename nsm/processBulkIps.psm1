function Get-ProcessBulkIps {

    # Use $PSScriptRoot to find modules relative to this script's location
    Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckBlockedCountries.psm1"
    Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckSuspiciousASNs.psm1"

    $outputCsv = "$PSScriptRoot\bulk_ip_results.csv"
    $inputCsv  = "$PSScriptRoot\input_ips.csv"

    $ApiVoidApi = Get-Secret -Name 'APIVoid_API_Key' -AsPlainText
    $apivoid_url = 'https://api.apivoid.com/v2/ip-reputation'
    $ApiVoid_headers = @{
        "X-API-Key"    = $ApiVoidApi
        "Content-Type" = "application/json"
    }

    # Collect enriched results
    $results = @()

    $template = [PSCustomObject]@{
        ip              = ''
        RiskScore       = ''
        Country         = ''
        CountryName     = ''
        IsGeoBlocked    = ''
        ISP             = ''
        ASN             = ''
        IsASNSuspicious = ''
        IsProxy         = ''
        IsWebProxy      = ''
        IsVPN           = ''
        IsHosting       = ''
        IsTor           = ''
        IsResidential   = ''
        IsRelay         = ''
    }

    # Read CSV input
    if (Test-Path $inputCsv) {
        try {
            $rawIps = @(Import-Csv -Path $inputCsv | Select-Object -ExpandProperty ip -ErrorAction Stop)
        } catch {
            $rawIps = Get-Content $inputCsv
        }
    } else {
        Write-Error "Input file not found: $inputCsv"
        return
    }
    
    # --- PROGRESS BAR SETUP ---
    $counter = 0
    $totalIps = $rawIps.Count
    Write-Host "Starting check on $totalIps IPs..." -ForegroundColor Cyan

    foreach ($row in $rawIps) {
        $counter++
        
        # Handle input variations
        if ($row.ip) { $ip = $row.ip } 
        elseif ($row.value) { $ip = $row.value } 
        else { $ip = $row }
        
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }

        # Update Progress Bar
        $percent = ($counter / $totalIps) * 100
        Write-Progress -Activity "Checking IP Reputation" -Status "Processing IP $counter of $totalIps ($ip)" -PercentComplete $percent

        $output = $template.PSObject.Copy()
        $output.ip = $ip 
        
        try {
            $ApiVoid_body = @{ ip = $ip } | ConvertTo-Json -Depth 3
            $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body

            if ($null -eq $response -or $null -eq $response.information) {
                $countryName = "Unknown"; $asn = "Unknown"; $isp = "Unknown"; $riskScore = 0
            } else {
                $countryName = if ($response.information.country_name) { $response.information.country_name } else { "Unknown" }
                $asn = if ($response.information.asn) { $response.information.asn } else { "Unknown" }
                $isp = if ($response.information.isp) { $response.information.isp } else { "Unknown" }
                $riskScore = if ($response.risk_score.result) { $response.risk_score.result } else { 0 }

                # Enrichment
                $output.RiskScore = $riskScore
                $output.CountryName = $countryName
                $output.ISP = $isp
                $output.ASN = $asn
                $output.IsProxy = $response.anonymity.is_proxy
                $output.IsWebProxy = $response.anonymity.is_webproxy
                $output.IsVPN = $response.anonymity.is_vpn
                $output.IsHosting = $response.anonymity.is_hosting
                $output.IsTor = $response.anonymity.is_tor
                $output.IsResidential = $response.anonymity.is_residential_proxy
                $output.IsRelay = $response.anonymity.is_relay
            }

        } catch {
            $countryName = "Unknown"; $asn = "Unknown"; $riskScore = 0
        }

        # Check lists
        $existsInCountryBlockList = $false
        if ($countryName -ne "Unknown") {
            $existsInCountryBlockList = Get-CheckBlockedCountries -country $countryName.Trim().ToLower()
        }

        $existsInASNList = $false
        if ($asn -ne "Unknown") {
            $existsInASNList = Get-CheckSuspiciousASNs -asn $asn
        }
        
        $output.IsGeoBlocked = $existsInCountryBlockList
        $output.IsASNSuspicious = $existsInASNList 

        $results += $output
    }

    Write-Progress -Activity "Checking IP Reputation" -Completed

    $results | Export-Csv -Path $outputCsv -NoTypeInformation
    Write-Host "Results saved to $outputCsv" -ForegroundColor Green

    # --- SUMMARY TABLES ---

    # 1. GeoBlocked
    Write-Host "`n--- Geo-Blocked Country Hits ---" -ForegroundColor Cyan
    $results | Where-Object { $_.IsGeoBlocked -eq $true} | 
        Group-Object CountryName | Sort-Object Count -Descending |
        ForEach-Object { [PSCustomObject]@{ Country=$_.Name; Count=$_.Count } } | Format-Table -AutoSize

    # 2. Anonymity Categories
    Write-Host "`n--- IP Anonymity Category Counts ---" -ForegroundColor Cyan
    $categorySummary = @(
        [PSCustomObject]@{ Category = 'Proxy'; Count = ($results | Where-Object IsProxy).Count },
        [PSCustomObject]@{ Category = 'Web Proxy'; Count = ($results | Where-Object IsWebProxy).Count },
        [PSCustomObject]@{ Category = 'VPN'; Count = ($results | Where-Object IsVPN).Count },
        [PSCustomObject]@{ Category = 'Hosting / Data Center'; Count = ($results | Where-Object IsHosting).Count },
        [PSCustomObject]@{ Category = 'Tor Node'; Count = ($results | Where-Object IsTor).Count },
        [PSCustomObject]@{ Category = 'Residential Proxy'; Count = ($results | Where-Object IsResidential).Count },
        [PSCustomObject]@{ Category = 'Relay'; Count = ($results | Where-Object IsRelay).Count }
    )
    $categorySummary | Format-Table -AutoSize

    # 3. ISP Distribution (Single Table with Highlighting)
    Write-Host "`n--- ISP Distribution (Top 20) ---" -ForegroundColor Cyan
    Write-Host "Legend: " -NoNewline; Write-Host "Suspicious ASN " -ForegroundColor Yellow
    
    # Header
    $formatStr = "{0,-45} {1,-15} {2,10}"
    Write-Host ($formatStr -f "ISP Name", "ASN", "Count") -ForegroundColor Cyan
    Write-Host ("-" * 75) -ForegroundColor Cyan

    # Data
    $ispGroups = $results | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ISP) } | 
                 Group-Object ISP | Sort-Object Count -Descending | Select-Object -First 20

    foreach ($group in $ispGroups) {
        $name = $group.Name
        $asn  = $group.Group[0].ASN
        $cnt  = $group.Count
        
        # Check if ANY IP in this group was suspicious (ASN based)
        $isSuspicious = ($group.Group | Where-Object IsASNSuspicious -eq $true)
        
        if ($isSuspicious) {
            Write-Host ($formatStr -f $name, $asn, $cnt) -ForegroundColor Yellow
        } else {
            Write-Host ($formatStr -f $name, $asn, $cnt) -ForegroundColor Gray
        }
    }

    # 4. Risk Score Summary
    Write-Host "`n--- Risk Score Distribution ---" -ForegroundColor Cyan
    $results | Group-Object RiskScore | Sort-Object Count -Descending |
    ForEach-Object { [PSCustomObject]@{ RiskScore=$_.Name; Count=$_.Count } } | Format-Table -AutoSize

    # 5. High Risk IP Lists
    $Score100 = $results | Where-Object { $_.RiskScore -eq 100 }
    if ($Score100) {
        Write-Host "`n[CRITICAL] IPs with Risk Score 100" -ForegroundColor Red
        $Score100 | Select-Object ip, ISP, CountryName | Format-Table -AutoSize
    }

    $Score90 = $results | Where-Object { $_.RiskScore -ge 90 -and $_.RiskScore -lt 100 }
    if ($Score90) {
        Write-Host "`n[HIGH] IPs with Risk Score 90-99" -ForegroundColor Red
        $Score90 | Select-Object ip, ISP, CountryName | Format-Table -AutoSize
    }
}