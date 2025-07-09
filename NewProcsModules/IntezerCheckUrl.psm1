function Get-IntezerCheckUrl{
    param (
        [Parameter(Mandatory=$true)]
        $url
    )
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

if ($urlHistory.total_count -eq 0) {
    Write-Host "No previous Intezer results for $url sending to Intezer for analysis"

    #If no previous analysis, send off for analysis
    $urlSubmitBody = @{
    'url' = $url
    'allow_offline_url' = $false
    'country' = 'united_states'
    'user_agent' = 'desktop'
    } | ConvertTo-Json

    $urlsubmissionResponse = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/url') -Headers $intezer_headers -Body $urlSubmitBody -ContentType "application/json"
    $queryUrl = $base_url + $urlsubmissionResponse.result_url

    if ($urlsubmissionResponse.status -eq "in_progress") {
        while ($urlsubmissionResponse.status -eq "in_progress") {
            Start-Sleep -Seconds 10
            $urlsubmissionResponse = Invoke-RestMethod -Uri $queryUrl -Headers $intezer_headers
            Write-Host "url sub response"
        }
    }

    $urlReturn = Invoke-RestMethod -Uri $queryUrl -Headers $intezer_headers

    Write-Host "Domain info: " $urlReturn.result.domain_info
    Write-Host "Scanned url: " $urlReturn.result.scanned_url
    Write-Host "Verdict: " $urlReturn.result.downloaded_file.analysis_summary
    Write-Host "Sub Verdict: " $urlReturn.result.summary.verdict_name
    Write-Host "-"
} elseif ($urlHistory.total_count -eq 1) {
    Write-Host $urlHistory.analyses.analysis_creation_time
    Write-Host "Did Download file? : " $urlHistory.analyses.did_download_file
    Write-Host "Scanned url: " $urlHistory.analyses.scanned_url
    if ($urlHistory.analyses[0].verdict -eq "no_threats") {
        Write-Host "Verdict: " $urlHistory.analyses.verdict -ForegroundColor Green
        Write-Host "Sub Verdict: " $urlHistory.analyses.sub_verdict -ForegroundColor Green
    } else {
        Write-Host "Verdict: " $urlHistory.analyses.verdict
        Write-Host "Sub Verdict: " $urlHistory.analyses.sub_verdict
    }
    Write-Host "-"
    
} else {
    Write-Host "Did Download file? : " $urlHistory.analyses[0].did_download_file
    Write-Host "Scanned url: " $urlHistory.analyses[0].scanned_url
    if ($urlHistory.analyses[0].verdict -eq "no_threats") {
        Write-Host "Verdict: " $urlHistory.analyses[0].verdict -ForegroundColor Green
        Write-Host "Sub Verdict: " $urlHistory.analyses[0].sub_verdict -ForegroundColor Green
    } else {
        Write-Host "Verdict: " $urlHistory.analyses[0].verdict
        Write-Host "Sub Verdict: " $urlHistory.analyses[0].sub_verdict
    }
    Write-Host "-"
}

}
