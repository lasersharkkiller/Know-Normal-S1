function Get-IntezerCheckUrl{
    param (
        [Parameter(Mandatory=$true)]
        $url
    )
Write-Host "Entering Check URL Function.."
$base_url = 'https://analyze.intezer.com/api/v2-0'

$urlHistoryBody = @{
    'url' = $url
    'exact_match' = $false
    'start_date' = 1664556354
    'end_date' = ([int](Get-Date -UFormat %s))
    'limit' = 10
}

$urlResults = @{}

#First we check url analyses history to see if it has been analyzed already:
$urlHistory = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/url-analyses/history') -Headers $intezer_headers -Body ($urlHistoryBody | ConvertTo-Json) -ContentType "application/json"
Write-Host "Results from urlHistory"
if ($urlHistory.total_count -eq 0) {
    Write-Host "No previous Intezer results for $url sending to Intezer for analysis"
} elseif ($urlHistory.total_count -eq 1) {
    $urlResults.Add("CreationTime", $urlHistory.analyses.analysis_creation_time)
    $urlResults.Add("DownloadedFile", $urlHistory.analyses.did_download_file)
    $urlResults.Add("ScannedUrl", $urlHistory.analyses.scanned_url)
    $urlResults.Add("Verdict", $urlHistory.analyses.verdict)
    $urlResults.Add("SubVerdict", $urlHistory.analyses.sub_verdict)
} else {
    $urlResults.Add("CreationTime", $urlHistory.analyses.analysis_creation_time[-1])
    $urlResults.Add("DownloadedFile", $urlHistory.analyses.did_download_file[-1])
    $urlResults.Add("ScannedUrl", $urlHistory.analyses.scanned_url[-1])
    $urlResults.Add("Verdict", $urlHistory.analyses.verdict[-1])
    $urlResults.Add("SubVerdict", $urlHistory.analyses.sub_verdict[-1])
}

Write-Host $urlHistory.analyses


[bool]$checkIfPending = $true

#WIP
}
