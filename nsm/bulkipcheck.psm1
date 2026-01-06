function Get-CheckBulkIpsApiVoid {

    param (
        [Parameter(Mandatory=$true)]
        $process
    )

    # Use $PSScriptRoot to locate modules relative to this script
    Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckBlockedCountries.psm1"
    Import-Module -Name "$PSScriptRoot\..\NewProcsModules\CheckSuspiciousASNs.psm1"
    Import-Module -Name "$PSScriptRoot\S1IPtoDNS.psm1"

    # Define paths
    # Note: Input is the JSON file in the 'output' folder relative to script root
    $inputJson = ".\output\$($process)-dstIps.json"
    $outputCsv = ".\output\$($process)-ip_results_apivoid.csv"

    $ApiVoidApi = Get-Secret -Name 'APIVoid_API_Key' -AsPlainText
    $apivoid_url = 'https://api.apivoid.com/v2/ip-reputation'
    $ApiVoid_headers = @{
        "X-API-Key"    = $ApiVoidApi
        "Content-Type" = "application/json"
    }

    # Collect results
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

    # Read Input (JSON)
    if (Test-Path $inputJson) {
        try {
            $jsonContent = Get-Content $inputJson -Raw | ConvertFrom-Json
            
            # EXTRACT IP LOGIC
            if ($jsonContent[0].value -is [Array]) {
                $rawIps = $jsonContent | ForEach-Object { $_.value[0] }
            } else {
                $rawIps = $jsonContent
            }
        } catch {
            Write-Error "Failed to parse JSON input: $($_.Exception.Message)"
            return
        }
    } else {
        Write-Error "Input file not found: $inputJson"
        return
    }

    # --- PROGRESS BAR SETUP ---
    $counter = 0
    $totalIps = $rawIps.Count
    Write-Host "Starting check on $totalIps IPs for process '$process'..." -ForegroundColor Cyan

    foreach ($ip in $rawIps) {
        $counter++
        
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }

        # Update Progress Bar
        $percent = ($counter / $totalIps) * 100
        Write-Progress -Activity "Checking IP Reputation ($process)" -Status "Processing IP $counter of $totalIps ($ip)" -PercentComplete $percent

        $output = $template.PSObject.Copy()
        $output.ip = $ip 

        try {
            $ApiVoid_body = @{ ip = $ip } | ConvertTo-Json -Depth 3
            $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body
            
            # --- NULL CHECK ---
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
            Write-Warning "Error querying IP $ip"
            $countryName = "Unknown"; $asn = "Unknown"; $riskScore = 0
        }

        # Check Blocklists
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

        # --- ALERTS & ACTIONS ---

        if ($riskScore -eq 100) {
            Write-Host "`n[CRITICAL] $ip Risk Score: 100. Querying S1..." -ForegroundColor Red
            Get-S1IPtoDNS -process $process -ip $ip 
        }

        if ($existsInCountryBlockList -eq $true) {
            Write-Host "`n[GEO BLOCK] $ip ($countryName) is Geo-Blocked. Querying S1..." -ForegroundColor Red
            Get-S1IPtoDNS -process $process -ip $ip
        }

        if ($existsInASNList -eq $true) {
            Write-Host "`n[SUSP ASN] $ip matches Suspicious ASN List: $asn ($isp)" -ForegroundColor Yellow
        }

        $results += $output
    }
    
    Write-Progress -Activity "Checking IP Reputation ($process)" -Completed

    # Export CSV
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
        Write-Host "`n[HIGH] IPs with Risk Score 90-99" -ForegroundColor Magenta
        $Score90 | Select-Object ip, ISP, CountryName | Format-Table -AutoSize
    }
}