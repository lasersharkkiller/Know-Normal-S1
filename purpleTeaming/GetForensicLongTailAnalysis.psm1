function Get-ForensicLongTailAnalysis {

    #region --- Configuration ---
    # Import-Module -Name ".\purpleTeaming\checkIndicatorsForStats.psm1" # Uncomment if needed
    
    # Define variables
    # Ensure you have the secret management module or replace this with your API token string
    $apiToken = Get-Secret -Name 'S1_API_Key_2' -AsPlainText 
    
    $pollingInterval = 2 # Increased slightly as join queries can take longer
    $baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
    $outputJsonPath = ".\output\LongTailAnalysisResults.json"

    # Define the endpoint URL for creating the Skylight query
    $queryCreateUrl = "$($baseUrl)/dv/events/pq"
    #endregion

    #region --- Headers & User Input ---
    #Set up headers for authentication and content type
    $headers = @{
        'Authorization' = "ApiToken $apiToken"
        'Content-Type'  = 'application/json'
    }

    # Host Prompt
    $hostName = Read-Host "Enter the Endpoint Name"
    if ($hostName -eq "") {
        $hostName = $env:COMPUTERNAME
    }

    # Time Prompt
    $result = $null
    do {
        $s = Read-Host -Prompt 'Enter date or leave blank for today, Ex: 2025-02-25 or 2025-02-25 02:25:25'
        if ($s) {
            try {
                $result = Get-Date $s
                $result.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") | Out-Null
                break
            }
            catch [Management.Automation.PSInvalidCastException] {
                Write-Host "Date not valid"
            }
        }
        elseif ($s -eq "") {
            $result = (Get-Date)
            break
        }
        else {
            break
        }
    }
    while ($true)

    $currentTime = $result.AddDays(+1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $lastDayTime = $result.AddDays(-1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    Write-Host "`nTarget: $hostName" -ForegroundColor Cyan
    Write-Host "Timeframe: $lastDayTime to $currentTime" -ForegroundColor Cyan
    #endregion

    #region --- Query Definitions ---
    # Using Ordered Dictionary to maintain the flow of analysis
    $queries = [ordered]@{
        "Behavioral Indicators" = "|join a = (event.type = 'Behavioral Indicators' AND endpoint.name = '$($hostName)' | columns indicator.name), b = (event.type = 'Behavioral Indicators' | columns indicator.name, endpoint.name | group host_count = estimate_distinct(endpoint.name) by indicator.name | filter host_count < 50) on indicator.name | sort +host_count"

        "Driver Loads" = "|join a = (event.type = 'Driver Load' AND endpoint.name = '$($hostName)' | columns tgt.file.path), b = (event.type = 'Driver Load' | columns tgt.file.path, endpoint.name | group host_count = estimate_distinct(endpoint.name) by tgt.file.path | filter host_count < 50) on tgt.file.path"

        "Open Remote Process Handle" = "|join a = (event.type = 'Open Remote Process Handle' AND endpoint.name = '$($hostName)' | columns tgt.process.cmdline), b = (event.type = 'Open Remote Process Handle' | columns tgt.process.cmdline, endpoint.name | group host_count = estimate_distinct(endpoint.name) by tgt.process.cmdline | filter host_count < 50) on tgt.process.cmdline | sort +host_count"

        "Remote/Duplicate Threads" = "|join a = (event.type in ('Remote Thread Creation','Duplicate Remote Process Handle','Duplicate Thread Handle') AND endpoint.name = '$($hostName)' | columns src.process.cmdline), b = (event.type in ('Remote Thread Creation','Duplicate Remote Process Handle','Duplicate Thread Handle') | columns src.process.cmdline, endpoint.name | group host_count = estimate_distinct(endpoint.name) by src.process.cmdline | filter host_count < 50) on src.process.cmdline | sort +host_count"

        "Process Creation" = "|join a = (event.type = 'Process Creation' AND endpoint.name = '$($hostName)' | columns src.process.name), b = (event.type = 'Process Creation' | columns src.process.name, endpoint.name | group host_count = estimate_distinct(endpoint.name) by src.process.name | filter host_count < 50) on src.process.name | sort +host_count"

        "File Creation" = "|join a = (event.type = 'File Creation' AND endpoint.name = '$($hostName)' | columns tgt.file.name), b = (event.type = 'File Creation' | columns tgt.file.name, endpoint.name | group host_count = estimate_distinct(endpoint.name) by tgt.file.name | filter host_count < 50) on tgt.file.name | sort +host_count"

        "Network Connections (IP)" = "|join a = (event.type in ('IP Listen','IP Connect') AND endpoint.name = '$($hostName)' | columns dst.ip.address), b = (event.type in ('IP Listen','IP Connect') | columns dst.ip.address, endpoint.name | group host_count = estimate_distinct(endpoint.name) by dst.ip.address | filter host_count < 50) on dst.ip.address | sort +host_count"

        "DNS Requests" = "|join a = (event.type in ('DNS Resolved','DNS Unresolved') AND endpoint.name = '$($hostName)' | columns event.dns.request), b = (event.type in ('DNS Resolved','DNS Unresolved') | columns event.dns.request, endpoint.name | group host_count = estimate_distinct(endpoint.name) by event.dns.request | filter host_count < 50) on event.dns.request | sort +host_count"

        "HTTP Requests" = "|join a = (event.type in ('GET','POST','HEAD','CONNECT','DELETE','OPTIONS','PUT') AND endpoint.name = '$($hostName)' | columns url.address), b = (event.type in ('GET','POST') | columns url.address, endpoint.name | group host_count = estimate_distinct(endpoint.name) by url.address | filter host_count < 50) on url.address | sort +host_count"

        "Registry Modifications" = "|join a = (event.type in ('Registry Value Create','Registry Key Create') AND endpoint.name = '$($hostName)' | columns registry.keyPath), b = (event.type in ('Registry Value Create','Registry Key Create') | columns registry.keyPath, endpoint.name | group host_count = estimate_distinct(endpoint.name) by registry.keyPath | filter host_count < 50) on registry.keyPath | sort +host_count"

        "Command Scripts (under 4MB)" = "|join a = (event.type = 'Command Script' AND endpoint.name = '$($hostName)' and cmdScript.originalSize < 4000 | columns cmdScript.content), b = (event.type = 'Command Script' | columns cmdScript.content, endpoint.name | group host_count = estimate_distinct(endpoint.name) by cmdScript.content | filter host_count < 50) on cmdScript.content | sort +host_count"

        "Logins" = "|join a = (event.type = 'Login' AND endpoint.name = '$($hostName)' | columns src.process.name), b = (event.type = 'Login' | columns src.process.name , endpoint.name | group host_count = estimate_distinct(endpoint.name) by src.process.name | filter host_count < 50) on src.process.name | sort +host_count"

        "Task Activity" = "|join a = (event.type in ('Task Trigger','Task Start','Task Update') AND endpoint.name = '$($hostName)' | columns src.process.cmdline), b = (event.type in ('Task Trigger','Task Start','Task Update') | columns src.process.cmdline, endpoint.name | group host_count = estimate_distinct(endpoint.name) by src.process.cmdline | filter host_count < 50) on src.process.cmdline | sort +host_count"
    }
    #endregion

    #region --- Execution Loop ---
    $globalResults = @{}
    $totalAnalysisCount = $queries.Count
    $currentAnalysisIndex = 0

    Write-Host "`n--- Starting Long Tail Analysis ($totalAnalysisCount Artifact Types) ---" -ForegroundColor Yellow

    foreach ($key in $queries.Keys) {
        $currentAnalysisIndex++
        $queryString = $queries[$key]
        
        Write-Host "`n[$currentAnalysisIndex/$totalAnalysisCount] Analyzing: $key" -ForegroundColor Magenta

        # Define payload
        $params = @{
            "query"    = $queryString
            'fromDate' = "$($lastDayTime)"
            'toDate'   = "$($currentTime)"
        } | ConvertTo-Json

        # Post Query
        $queryId = $null
        try {
            $postResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params
            if ($postResponse.data.queryId) {
                $queryId = $postResponse.data.queryId
                Write-Host "  > Query started (ID: $queryId)" -ForegroundColor DarkGray
            } else {
                Write-Error "Failed to start query for $key"
                continue
            }
        }
        catch {
            Write-Error "API Error starting query for $key. Details: $_"
            continue
        }

        # Poll Status
        $queryStatusUrl = "$baseUrl/dv/events/pq-ping?queryId=$($queryId)"
        $status = 'running'
        
        while ($status -ne 'FINISHED') {
            try {
                $statusResponse = Invoke-RestMethod -Uri $queryStatusUrl -Method Get -Headers $headers
                $status = $statusResponse.data.status
                
                # Optional: Show progress bar or dots
                # Write-Host "." -NoNewline 
                Start-Sleep -Seconds $pollingInterval
            }
            catch {
                Write-Host "  > Polling error, retrying..." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }

        # Retrieve Data
        $dataSet = $statusResponse.data.data
        if ($dataSet) {
            $count = $dataSet.Count
            Write-Host "  > Analysis Complete. Found $count rare artifacts." -ForegroundColor Green
            
            # Add to global results
            $globalResults[$key] = $dataSet

            # Display top 3 for immediate visibility
            if ($count -gt 0) {
                Write-Host "    Top findings:" -ForegroundColor Gray
                $dataSet | Select-Object -First 3 | ForEach-Object {
                    # The array structure is usually [Artifact, Count]
                    # We print it nicely
                    Write-Host "    - ($($_[1]) hosts) $($_[0])"
                }
            }
        } else {
            Write-Host "  > No artifacts found matching criteria (<50 hosts)." -ForegroundColor Gray
            $globalResults[$key] = @() # Empty array
        }
    }
    #endregion

    #region --- Output Saving ---
    Write-Host "`n--- Analysis Complete ---" -ForegroundColor Yellow
    
    $outputDir = Split-Path $outputJsonPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    $globalResults | ConvertTo-Json -Depth 5 | Set-Content -Path $outputJsonPath
    Write-Host "Full results saved to: $outputJsonPath" -ForegroundColor Green
    
    # Optional: Open the file or folder
    # Invoke-Item $outputJsonPath
    #endregion
}