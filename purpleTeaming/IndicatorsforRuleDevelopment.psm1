function Get-IndicatorsforRuleDevelopment{

    #region --- Configuration ---
    Import-Module -Name ".\purpleTeaming\checkIndicatorsForStats.psm1"
    # Define variables
    $apiToken = Get-Secret -Name 'S1_API_Key_2' -AsPlainText
    $pollingInterval = 1 # Interval in seconds to check the status of the query
    $baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
    # MODIFIED: Added paths for baseline and output files
    $baselineCsvPath = ".\output\IndicatorsBaseline.csv"
    $outputJsonPath = ".\output\IndicatorResults.json"

    # Define the endpoint URL for creating the Skylight query
    $queryCreateUrl = "$($baseUrl)/dv/events/pq"

    # Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

# Host
$hostName = Read-Host "Enter the Endpoint Name"
if ($hostName -eq ""){
    $hostName = $env:COMPUTERNAME
}

#Time Prompt
$result = $null
  do {
    $s = Read-Host -Prompt 'Enter date or leave blank for today, Ex: 2025-02-25 or 2025-02-25 02:25:25'
    if ( $s ) {
      try {
        $result = Get-Date $s
        $result.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        break
      }
      catch [Management.Automation.PSInvalidCastException] {
        Write-Host "Date not valid"
      } 
    } elseif ($s -eq ""){
            $result = (Get-Date)#.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            break
    }
    else {
      break
    }
  }
  while ( $true )

$limit = 100
$currentTime = $result.AddDays(+1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lastDayTime = $result.AddDays(-1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$query = "endpoint.name = '$($hostName)' | columns indicator.name, src.process.name  | group indicatorCount = count (indicator.name) by indicator.name | sort -indicatorCount | limit 1000"

# Define the payload for the Power query
$params = @{
    "query" = $query
    'fromDate' = "$($lastDayTime)"
    'toDate' = "$($currentTime)"

} | ConvertTo-Json

#nextregion: Did threats (S1 rules) or alerts (custom star rules) trigger?
    #Try alerts (custom rules) first then threats
    $alertsList = "$baseUrl/cloud-detection/alerts"
    $threatsList = "$baseUrl/threats"
    $totalCount = 0
    
    $alertsUri = "$($alertsList)?limit=$($limit)&createdAt__gte=$($lastDayTime)&createdAt__lte=$($currentTime)&origAgentName__contains=$($hostName)"
    try {
        $alertsResponse = Invoke-RestMethod -Uri $alertsUri -Headers $headers -Method Get
    }
    catch {
        Write-Host -ForegroundColor red "Could not get alert data."
    }

    if($alertsResponse.data.Count -eq 0){
        Write-Host "S1 returned zero alerts for $hostName."
    } else{
        $totalCount += $alertsResponse.data.Count
    }

    #Next query threats
    $threatsUri = "$($threatsList)?limit=$($limit)&createdAt__gte=$($lastDayTime)&createdAt__lte=$($currentTime)&computerName__contains=$($hostName)"
    try {
            $threatsResponse = Invoke-RestMethod -Uri $threatsUri -Headers $headers -Method Get
        }
    catch {
            Write-Host -ForegroundColor red "Could not get threat data."
        }

    if($threatsResponse.data.Count -eq 0){
        Write-Host "S1 returned zero threats for $hostName."
    } else{
        $totalCount += $threatsResponse.data.Count
    }

#Nextregion: Check indicators
# Step 1: Create the Power query
$parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($parentProcResponse -ne $null -and $parentProcResponse.data.queryId) {
    $queryId = $parentProcResponse.data.queryId
    Write-Output "Indicators Query (for the alert) created successfully with Query ID: $queryId"
} else {
    Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query."
    continue
}

# Step 2: Poll the query status until it's complete
$queryStatusUrl = "$baseUrl/dv/events/pq-ping?queryId=$($queryId)"
$status = 'running'
while ($status -ne 'FINISHED') {
    try {
        $statusResponse = Invoke-RestMethod -Uri $queryStatusUrl -Method Get -Headers $headers
    }
    catch {
        Write-Host -ForegroundColor red "Could not get indicators for the alert. S1 API Issues. Trying again."
        $parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

        
        if ($parentProcResponse -ne $null -and $parentProcResponse.data.queryId) {
            $queryId = $parentProcResponse.data.queryId
            Write-Output "DNS Request Query (for the alert) created successfully with Query ID: $queryId"
        } else {
            Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query."
            continue
        }
    }

    $status = $statusResponse.data.status
    $progress = $statusResponse.data.progress
    
    Write-Output "Current query progress: $progress"
    Start-Sleep -Seconds $pollingInterval
}

    #region --- MODIFIED: Load Baseline Indicators ---
    if (-not (Test-Path $baselineCsvPath)) {
        Write-Error "Baseline file not found at '$baselineCsvPath'. Please ensure the file exists."
        return
    }
    Write-Host "Loading baseline indicators from '$baselineCsvPath'..." -ForegroundColor Cyan
    $baselineLookup = @{}
    try {
        Import-Csv -Path $baselineCsvPath | ForEach-Object {
            $baselineLookup[$_.Indicator] = $_.Effectiveness
        }
        Write-Host "Successfully loaded $($baselineLookup.Count) baselined indicators." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to read or process the baseline CSV file. Error: $_"
        return
    }
    #endregion

    #region --- MODIFIED: Step 3: Retrieve, process, and categorize the results ---
    if ($status -eq 'FINISHED') {
        Write-Output "Query completed successfully. Fetching results..."
        $allIndicators = $statusResponse.data.data

        if ($null -eq $allIndicators) {
            Write-Host "Query finished but returned no indicator data." -ForegroundColor Yellow
            return
        }

        # Prepare the structure for categorized results
        $categorizedResults = @{
            Super      = [System.Collections.Generic.List[string]]::new()
            Exceptions = [System.Collections.Generic.List[string]]::new()
            Noisy      = [System.Collections.Generic.List[string]]::new()
            New        = [System.Collections.Generic.List[string]]::new()
        }

        # Iterate through API results and categorize each indicator
        foreach ($indicatorDetails in $allIndicators) {
            $indicatorName = $indicatorDetails[0] # The indicator name is the first element
            
            if ($baselineLookup.ContainsKey($indicatorName)) {
                $category = $baselineLookup[$indicatorName]
                # Add to the correct category list, avoiding duplicates
                if (-not $categorizedResults[$category].Contains($indicatorName)) {
                    $categorizedResults[$category].Add($indicatorName)
                }
            }
            else {
                # This is a new indicator not in our baseline
                if (-not $categorizedResults['New'].Contains($indicatorName)) {
                    $categorizedResults['New'].Add($indicatorName)
                }
            }
        }

        # --- Display results (for indicator analysis) in the console ---
        Write-Host "`n--- Indicator Analysis Results ---" -ForegroundColor Magenta
        $categories = @("Noisy","Exceptions","Super","New")
        foreach ($category in $categories) {
            $color = switch ($category) {
                "Super"      { "Green" }
                "New"        { "Cyan" }
                "Exceptions" { "Yellow" }
                "Noisy"      { "Red" }
                default      { "White" }
            }
            Write-Host "`n--- $($category.ToUpper()) ---" -ForegroundColor $color
            if ($categorizedResults[$category].Count -gt 0) {
                $categorizedResults[$category] | ForEach-Object { Write-Host " - $_" }
            }
            else {
                Write-Host " (No indicators in this category)"
            }
        }

        # --- Display alerts/threats results in the console ---
        Write-Host "`n--- Alerts (Custom Star Rules) That Triggered ---" -ForegroundColor Magenta
        $alertsResponse.data.ruleInfo.name | Sort-Object | ForEach-Object { Write-Host " - $_" }

        Write-Host "`n--- Threats (S1 Alerts) That Triggered ---" -ForegroundColor Magenta
        $threatsResponse.data.threatInfo.threatName | Sort-Object | ForEach-Object { Write-Host " - $_" }

        # --- Save results to JSON file ---
        $outputDir = Split-Path $outputJsonPath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir | Out-Null
        }
        $categorizedResults | ConvertTo-Json | Set-Content -Path $outputJsonPath
        Write-Host "`Initial analysis complete. Results saved to '$outputJsonPath'" -ForegroundColor Green
        
        Write-Host "Next checking stats for New Indicators" -ForegroundColor Green
        foreach ($newIndicator in $categorizedResults['New']) {
            Write-Host $newIndicator
            Get-checkIndicatorsForStats -indicatorName $newIndicator -headers $headers
        }
    }
}
