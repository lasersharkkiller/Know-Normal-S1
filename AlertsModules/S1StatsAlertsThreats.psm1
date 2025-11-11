function Get-AlertsandThreatsStats{


# Step 1: Set up your API token and base URL
$API_TOKEN = Get-Secret -Name 'S1_API_Key' -AsPlainText
$BASE_URL = 'https://usea1-equifax.sentinelone.net'

# Step 2: Define the API endpoint for fetching alerts
$alertsList = "$BASE_URL/web/api/v2.1/cloud-detection/alerts"
$threatsList = "$BASE_URL/web/api/v2.1/threats"

# Step 3: Set up headers for authentication
$headers = @{
    'Authorization' = "Bearer $API_TOKEN"
    'Content-Type' = 'application/json'
}

# Step 4: Define the query parameters
# Time calculation
$currentTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lastDayTime = (Get-Date).AddDays(-3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$params = @{
    'limit' = 1000 # 1000 is the max for both
    'createdAt__gte' = "$($lastDayTime)"
    'createdAt__lte' = "$($currentTime)"
}

# Step 5: Retrieve the "alerts" - which S1 defines as custom star rules
$alertsUri = "$($alertsList)?limit=$($params.limit)&createdAt__gte=$($params.createdAt__gte)&createdAt__lte=$($params.createdAt__lte)"
$threatsUri = "$($threatsList)?limit=$($params.limit)&createdAt__gte=$($params.createdAt__gte)&createdAt__lte=$($params.createdAt__lte)"

# Step 6: Make the API request to fetch alerts and threats
$alertsResponse = Invoke-RestMethod -Uri $alertsUri -Headers $headers -Method Get
$threatsResponse = Invoke-RestMethod -Uri $threatsUri -Headers $headers -Method Get

# Step 7: Initialize a dictionary for aggregating alerts and threats
[PSCustomObject]$alertsAggregation = @{}
$alertsRuleCount = @{}
$query = @{}

[PSCustomObject]$threatsAggregation = @{}
$threatsRuleCount = @{}

# Step 8: Process the alert data to aggregate by rule name and source process name
foreach ($alert in $alertsResponse.data) {
    $ruleName = if ($alert.ruleInfo.name) { $alert.ruleInfo.name } else { 'Unknown Rule' }
    $sourceProcessName = if ($alert.sourceProcessInfo.name) { $alert.sourceProcessInfo.name } else { 'Unknown Source Process' }
    $ruleQuery = $alert.ruleInfo.s1ql

    if (-not $alertsAggregation.ContainsKey($ruleName)) {
        $alertsAggregation.$ruleName = @{}
        $alertsRuleCount[$ruleName] = 1
        $query[$ruleName] = $ruleQuery
    } else {$alertsRuleCount[$ruleName] += 1}

    if ($alertsAggregation[$ruleName].ContainsKey($sourceProcessName)) {
        $alertsAggregation[$ruleName][$sourceProcessName] += 1
    } else {
        $alertsAggregation[$ruleName][$sourceProcessName] = 1
    }

}

# Step 9: Process the threat data
foreach ($threat in $threatsResponse.data) {
    $threatName = if ($threat.threatinfo.threatName) { $threat.threatinfo.threatName } else { 'Unknown Threat' }
    $threatProcArgs = if ($threat.threatinfo.maliciousProcessArguments) { $threat.threatinfo.maliciousProcessArguments } else { 'No Process Arguments' }

    if (-not $threatsAggregation.ContainsKey($threatName)) {
        $threatsAggregation.$threatName = @{}
        $threatsRuleCount[$threatName] = 1
    } else {$threatsRuleCount[$threatName] += 1}

    if ($threatsAggregation[$threatName].ContainsKey($threatProcArgs)) {
        $threatsAggregation[$threatName][$threatProcArgs] += 1
    } else {
        $threatsAggregation[$threatName][$threatProcArgs] = 1
    }
}

# Step 10: Output the aggregated long alert results
foreach ($ruleName in $alertsAggregation.Keys) {
    Write-Output "Rule: $ruleName"
    Write-Output ""
    Write-Output "Query: $($query.$ruleName)"
    Write-Output ""
    foreach ($sourceProcessName in $alertsAggregation[$ruleName].Keys) {
        $count = $alertsAggregation[$ruleName][$sourceProcessName]
        Write-Output "$sourceProcessName Count: $count"
    }
    Write-Output "---"
}

# Step 10: Output the aggregated long threat results
foreach ($threatName in $threatsAggregation.Keys) {
    Write-Output "Rule: $threatName"
    Write-Output ""
    foreach ($threatProcArgs in $threatsAggregation[$threatName].Keys) {
        $count = $threatsAggregation[$threatName][$threatProcArgs]
        Write-Output "$threatProcArgs Count: $count"
    }
    Write-Output "---"
}

# Step 11: Quick glance at aggregated results for both alerts and threats
Write-Host "Alerts (Custom Star Rules):" -ForegroundColor green -BackgroundColor black
$alertsRuleCount.GetEnumerator() | Sort Value |Format-Table -AutoSize
Write-Output ""
Write-Output ""
Write-Host "Threats:" -ForegroundColor green -BackgroundColor black
$threatsRuleCount.GetEnumerator() | Sort Value |Format-Table -AutoSize
}
