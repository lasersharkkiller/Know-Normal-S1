function Get-IntezerHash{
    param (
        [Parameter(Mandatory=$true)]
        $checkHash,
        $fileName,
        $baseline,
        $signatureStatus
    )
Import-Module -Name ".\NewProcsModules\DomainCleanup.psm1"
Import-Module -Name ".\NewProcsModules\IntezerCheckUrl.psm1"
Import-Module -Name ".\NewProcsModules\CheckApiVoid.psm1"

$trustedDomains = Import-Csv -Path "output\trustedDomains.csv" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true}
$SuspiciousDomains = Import-Csv -Path "output\suspiciousDomains.csv" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true}
$trustedIPs = Import-Csv -Path "output\trustedIPs.csv" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true }
$blockedIPs = "output\misp_ip_blocklist.txt" | Where-Object {($_.PSObject.Properties.Value | ForEach-Object {[string]::IsNullOrWhiteSpace($_) }) -notcontains $true }

$base_url = 'https://analyze.intezer.com/api/v2-0'

$intezer_body = @{
    'api_key' = ''
}

$hash = @{
    'hash' = $checkHash
}

$global:intezer_headers = @{
    'Authorization' = ''
}

$queryCreateUrl = $base_url + '/get-access-token'
try {
        $token = (Invoke-RestMethod -Method "POST" -Uri ($base_url + '/get-access-token') -Body ($intezer_body | ConvertTo-Json) -ContentType "application/json").result
        $intezer_headers['Authorization'] = 'Bearer ' + $token
    }
catch {
        Write-Host "Error retrieving JWT"
        return $false
    }
#Previously this re-analyzed the hash value, but eats up a file analysis license count. Attempting optimization. Plus it's so much quicker!
#$response = Invoke-RestMethod -Method "POST" -Uri ($base_url + '/analyze-by-hash') -Headers $intezer_headers -Body ($hash | ConvertTo-Json) -ContentType "application/json"
$response = Invoke-RestMethod -Method "GET" -Uri ($base_url + '/files/' + $checkHash) -Headers $intezer_headers -ContentType "application/json"
$result_url = $base_url + $response.result_url

[bool]$checkIfPending = $true

while ($checkIfPending) {
    try{
        $result = Invoke-RestMethod -Method "GET" -Uri $result_url -Headers $intezer_headers -ErrorAction silentlycontinue
    }
    catch {
        Write-Host "Intezer doesn't already have" $fileName ", we need to pull with S1." -ForegroundColor Yellow
        return $false
    }

    if ($result.status -eq "queued"){
        continue
    } else {
        $textColor = "White"
        if ($result.result.verdict -eq "trusted") {
            $textColor = "Green"

            $updateBaseline = Get-Content $baseline | ConvertFrom-Json
            
            $newEntry = @{
                value = @(
                    $fileName,
                    "unsigned",
                    $checkHash,
                    1.0
                 )
             }
                       
            $updateBaseline += $newEntry
            $updateBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baseline
        } elseif ($result.result.verdict -eq "no_threats"){
            $textColor = "Green"

            $updateBaseline = Get-Content $baseline | ConvertFrom-Json
            
            $newEntry = @{
                value = @(
                    $fileName,
                    $signatureStatus,
                    $checkHash,
                    1.0
                 )
             }
                       
            $updateBaseline += $newEntry
            $updateBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $baseline
        } elseif ($result.result.verdict -eq "suspicious"){
            $textColor = "Yellow"
        } elseif ($result.result.verdict -eq "malicious"){
            $textColor = "Red"
        }
        
        Write-Host "---" -ForegroundColor $textColor
        Write-Host "File Name: " $fileName -ForegroundColor $textColor
        Write-Host "Analysis URL: " $result.result.analysis_url -ForegroundColor $textColor
        Write-Host "Family Name: " $result.result.family_name -ForegroundColor $textColor
        Write-Host "Gene Types: " $result.result.gene_types -ForegroundColor $textColor
        Write-Host "SHA256: " $result.result.sha256 -ForegroundColor $textColor
        Write-Host "Verdict: " $result.result.verdict -ForegroundColor $textColor
        Write-Host "Sub-verdict: " $result.result.sub_verdict -ForegroundColor $textColor

        #First we extracted dynamic network artifact
        $analysis_id = $result.result.analysis_id
        $dynamicTTPUrl = $base_url + '/analyses/' + $analysis_id + '/dynamic-ttps'
        $dynamicTTPs = Invoke-RestMethod -Uri $dynamicTTPUrl -Headers $intezer_headers
        Write-Host $dynamicTTPs.result.data
        
        #First we extracted dynamic network artifact, now we extract static network artifacts
        #Static needs alot more cleaning up since the output is not clean like the dynamic output
        #Retrieve sub-analysis id
        $subAnalysisUrl = $base_url + '/analyses/' + $analysis_id + '/sub-analyses'
        $subAnalysisIdReport = Invoke-RestMethod -Uri $subAnalysisUrl -Headers $intezer_headers
        
        if ($subAnalysisIdReport.sub_analyses.Count -eq 1) {
            $subAnalysisId = $subAnalysisIdReport.sub_analyses.sub_analysis_id
        } else {
            $subAnalysisId = $subAnalysisIdReport.sub_analyses[-1].sub_analysis_id
        }

        #Now pull strings with sub-analysis id
        foreach ($subid in $subAnalysisIdReport.sub_analyses.sub_analysis_id) {
        $stringsUrl = $subAnalysisUrl + '/' + $subid + '/strings'
            try{
                $checkForNetworkStrings = (Invoke-RestMethod -Uri $stringsUrl -Headers $intezer_headers -ContentType "application/json").result.strings
                break
            }
            catch {
                Write-Host "Couldn't get the sub-analysis. for subanalysis id $subid" -ForegroundColor Yellow
            }
        }
        Write-Host "Intezer extracted network artifacts from strings: "
        $artifactDedupList = @()
        foreach ($string in $checkForNetworkStrings) {
            if ($string.tags -eq "network_artifact") {
                $artifact = $string.string_value
                #Sometimes Intezer doesn't extract strings cleanly so we need to do some cleanup
                $patterns = @("http","://",".com",".org",".io")
                if ($artifact -match "\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b") {
                    #if IPv4, first trim the ip back to a /24
                    $parts = $artifact -split '\.'
                    $trimmedArtifact = "$($parts[0]).$($parts[1]).$($parts[2])"
                    $ip = "$($parts[0]).$($parts[1]).$($parts[2]).$($parts[3])"
                    $existsInBlockedIPs = $false
                    $existsInTrustedIPs = $false

                    #We also need to check and see if it is an actual ip (saves on our api submissions)
                    $isValid = $true
                    try{
                        Resolve-DNSName -Name $ip | Out-Null
                        $isValid = $true
                    } catch {
                        $isValid = $false
                    }

                    if ($artifactDedupList -contains $trimmedArtifact) {
                            continue
                    } elseif ($artifact -like "*version*") {
                            continue
                    } elseif ($isValid -eq $false) {
                            continue
                    } elseif ($trimmedArtifact -match "*\.0\.0\.0$") {
                            continue
                    } else {
                        #Check Blocked IP List
                        
                        foreach ($row in $blockedIPs) {
                            #trim each ip back to a /24 to compare
                            $valueToCompare = $row
                            $parts = $valueToCompare -split '\.'
                            $trimmedBlockIP = "$($parts[0]).$($parts[1]).$($parts[2])"

                            if ($trimmedArtifact -match $trimmedBlockIP) {
                                $existsInBlockedIPs = $true
                                continue
                            } else {
                            }
                        }
                        if ($existsInTrustedIPs -eq $true){
                            Write-Host "$artifact is in the Blocked IPs, or matched a /24 from the first three octets." -ForegroundColor "Red"
                            continue
                        } else {
                            #continue on to check trusted ip list
                        }
                        
                        #Check list of Trusted IPs to save on API calls
                        
                        foreach ($row in $trustedIPs) {
                            $valueToCompare = $row.ip
                            $parts = $valueToCompare -split '\.'
                            $trimmedTrustedIP = "$($parts[0]).$($parts[1]).$($parts[2])"

                            if ($trimmedArtifact -match $trimmedTrustedIP) {
                                $existsInTrustedIPs = $true
                                continue
                            } else {
                            }
                        }
                    
                        if ($existsInTrustedIPs -eq $true){
                            Write-Host "$artifact is in the Trusted IPs" -ForegroundColor "Green"
                        } else {
                            #Check VirusTotal
                            $VTresults = Get-CheckAgainstVT -artifact $ip -type "IPAddress"
                            Write-Host $VTresults
                            
                            #Optional Get ASN info via Cymru
                            #$ASNinfo = Get-ASNCymru -artifact $ip -type "IPAddress"
                            #Write-Host $ASNinfo

                            #Check ApiVoid
                            $ApiVoidResults = Get-CheckApiVoid -artifact $ip -type "IPAddress"
                            Write-Host "ApiVoid Risk Score: " + $ApiVoidResults.risk_score.result
                        }
                        $artifactDedupList += $artifact
                    }
                } elseif ($patterns | Where-Object {$artifact -like "*$_*"}) {
                    #domain cleanup
                    $trimmedartifact = Get-DomainCleanup -domain $artifact
                    
                    #We also need to check and see if it is an actual domain (saves on our api submissions)
                    $isValid = $true
                    try{
                        Resolve-DNSName -Name $trimmedartifact | Out-Null
                        $isValid = $true
                    } catch {
                        $isValid = $false
                    }

                    if ($artifactDedupList -contains $trimmedartifact) {
                            continue
                    } elseif ($isValid -eq $false) {
                            continue
                    } else {

                        #Check list of Trusted Domains to save on API calls
                        $existsInTrustedDomains = $false
                        foreach ($row in $trustedDomains) {
                        
                            $valueToCompare = $row.domain
                            if ($trimmedartifact -match $valueToCompare) {
                                $existsInTrustedDomains = $true

                                continue
                            } else {
                            }
                        }

                        #Check list of Suspicious Domains
                        $existsInSuspiciousDomains = $false
                        if ($existsInTrustedDomains -eq $false) {
                            foreach ($row in $SuspiciousDomains) {
                                $valueToCompare = $row.domain
                                if ($trimmedartifact -match $valueToCompare) {
                                    $existsInSuspiciousDomains = $true
                                    continue
                                } else {
                                }
                            }
                        }

                        $extractedUrlRegex = 'https?:\/\/[^\s"]+'
                        $extractedUrl = [regex]::Matches($artifact, $extractedUrlRegex).Value
                        if ($existsInTrustedDomains -eq $true){
                            Write-Host "$trimmedartifact is in the Trusted Domains" -ForegroundColor "Green"
                        } elseif ($existsInSuspiciousDomains -eq $true){
                            Write-Host "$trimmedartifact is in the Suspicious Domains" -ForegroundColor "Yellow"
                            Write-Host "Conducting Deeper Analysis on full url:" -ForegroundColor "Yellow"
                            Get-IntezerCheckUrl -url $extractedUrl
                        } else {
                            #Check VirusTotal
                            $VTresults = Get-CheckAgainstVT -artifact $trimmedartifact -type "DomainName"
                            Write-Host $VTresults

                            #Optional Get ASN info via Cymru
                            #$ASNinfo = Get-ASNCymru -artifact $trimmedartifact -type "DomainName"
                            #Write-Host $ASNinfo

                            #Check ApiVoid
                            $ApiVoidResults = Get-CheckApiVoid -artifact $trimmedartifact -type "DomainName"
                            Write-Host "ApiVoid Risk Score: " + $ApiVoidResults.risk_score.result
                        }
                        $artifactDedupList += $trimmedartifact
                    }

                } 

            } else {
            }
        }
        
        Write-Host "---" -ForegroundColor $textColor
        return $true
    }
}
}
