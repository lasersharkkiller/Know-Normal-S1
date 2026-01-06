function Get-S1IPtoDNS{

    param (
        [Parameter(Mandatory=$true)]
        $process,
        $ip
    )

# Define variables
$S1apiToken = Get-Secret -Name 'S1_API_Key' -AsPlainText
$baseUrl = 'https://usea1-equifax.sentinelone.net/web/api/v2.1'
$queryCreateUrl = "$baseUrl/dv/events/pq"
$query = "(src.process.name = '$($process)' or src.process.parent.name = '$($process)') and event.dns.response contains '$($ip)' | columns event.dns.response, event.dns.request |group count = count (event.dns.response) by event.dns.response, event.dns.request | sort +count | limit 10"
$now = (Get-Date)
$currentTime = $now.AddDays(0).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lastDayTime = $now.AddDays(-14).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $S1apiToken"
    'Content-Type' = 'application/json'
}

# Define the payload for the Power query
$params = @{
    "query" = $query
    'fromDate' = "$($lastDayTime)"
    'toDate' = "$($currentTime)"

} | ConvertTo-Json

# Step 1: Create the Power query
$dstIpsResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

if ($dstIpsResponse -ne $null -and $dstIpsResponse.data.queryId) {
    $queryId = $dstIpsResponse.data.queryId
    Write-Output "IP to DNS Query created successfully with Query ID: $queryId"
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
        Write-Host -ForegroundColor red "Could not poll S1, S1 API Issues. Trying again."
        $dstIpsResponse = Invoke-RestMethod -Uri $queryCreateUrl -Method Post -Headers $headers -Body $params

        
        if ($dstIpsResponse -ne $null -and $dstIpsResponse.data.queryId) {
            $queryId = $dstIpsResponse.data.queryId
            Write-Output "Dst Ip Query created successfully with Query ID: $queryId"
        } else {
            Write-Output -ForegroundColor red "Failed to create the query. Please check your API token, endpoint, and query."
            continue
        }
    }
    $status = $statusResponse.data.status
    $progress = $statusResponse.data.progress
    
    Start-Sleep -Seconds 8
}

# Step 3: Once the status is finished, retrieve the results
if ($status -eq 'FINISHED') {
    Write-Output "Query completed successfully."
    Write-Host "DNS Response: " $statusResponse.data.data[-1][0]
    Write-Host "DNS Request: " $statusResponse.data.data[-1][1]
    $dnsRequest = $statusResponse.data.data[-1][1]
    $type = "DomainName"

    $checkAPIVoidforDNS = Get-CheckApiVoid -artifacts $dnsRequest -type $type
} else {
    Write-Output "Query failed or was cancelled. Final status: $status"
}

}