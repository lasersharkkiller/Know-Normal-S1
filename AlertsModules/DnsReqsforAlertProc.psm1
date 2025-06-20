function Get-DnsReqsforAlertProc{

    param (
        [Parameter(Mandatory=$true)]
        $hostName,
        $srcProcName,
        $timeToBaseline,
        $currentTime,
        $lastDayTime,
        $apiToken
    )


# Define variables
$apiToken = $apiToken
$baseUrl = 'https://site.net/web/api/v2.1'
$query = "endpoint.name = '$hostName' and src.process.name = '$srcProcName' | columns event.dns.request  | group DnsReqCount = count (event.dns.request) by event.dns.request  | sort -DnsReqCount | limit 1000"
#$siteId = 'your_site_id_here' # Replace with your actual Site ID (optional, depending on the scope of your query)
$pollingInterval = 1 # Interval in seconds to check the status of the query

# Define the endpoint URL for creating the Skylight query
$queryCreateUrl = "$baseUrl/dv/events/pq
"

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $apiToken"
    'Content-Type' = 'application/json'
}

# Define the payload for the Power query
$params = @{
    "query" = $query
    'fromDate' = "$($lastDayTime)"
    'toDate' = "$($currentTime)"

} | ConvertTo-Json

# Step 1: Create the Power query
$parentProcResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($parentProcResponse -ne $null -and $parentProcResponse.data.queryId) {
    $queryId = $parentProcResponse.data.queryId
    Write-Output "DNS Request Query (for the alert) created successfully with Query ID: $queryId"
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
        Write-Host -ForegroundColor red "Could not get DNS Requests for the src proc alert. S1 API Issues. Trying again."
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

# Step 3: Once the status is finished, retrieve the results
if ($status -eq 'FINISHED') {
    Write-Output "Query completed successfully."

    # Initialize a hashtable to store unique domains
    $uniqueDomains = @{}

    # Process each row in the CSV
    foreach ($row in $statusResponse.data.data) {
        # Extract the domain from the current row
        $domain = $row[0]

        # Check and strip trailing period
        if ($domain.EndsWith('.')) {
            $domain = $domain.TrimEnd('.')
        }

        # Only add it the domain contains a "."
        if ($domain.Contains('.')){
            # Split the domain into parts
            $domainParts = $domain -split '\.'
        }

        # Reduce domain to root and one subdomain if necessary
        if ($domainParts.Count -gt 2) {
            $reducedDomain = $domainParts[-2..-1] -join '.'
        } else {
            $reducedDomain = $domain
        }

        # Add to hashtable to ensure uniqueness
        $uniqueDomains[$reducedDomain] = $true
    }

    # Convert the unique domain keys to a sorted array
    $sortedUniqueDomains = @($uniqueDomains.Keys | Sort-Object)

    # Create output object for CSV export
    $outputData = $sortedUniqueDomains | ForEach-Object {
        # Create a custom PSObject for each unique domain
        [PSCustomObject]@{request = $_}
    }

    # Export the unique and sorted domains to a new file
    #$outputData | Export-Csv -Path $outputCsvPath -NoTypeInformation
    $outputData | ConvertTo-Json | Out-File "output\DnsReqsforAlertProc.json"
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}
