function Get-AlertsandThreatsFunction{

Import-Module -Name ".\AlertsModules\ParentProc.psm1"
Import-Module -Name ".\AlertsModules\ProcSignature.psm1"
Import-Module -Name ".\AlertsModules\ProcSignatureSignedVerifedCheck.psm1"
Import-Module -Name ".\AlertsModules\ProcSignatureCompareToEnterprise.psm1"
Import-Module -Name ".\AlertsModules\ProcImagePath.psm1"
Import-Module -Name ".\AlertsModules\NetworkPortsforAlertProc.psm1"
Import-Module -Name ".\AlertsModules\NetworkPortsforEnterprise.psm1"
Import-Module -Name ".\AlertsModules\DstIPsforAlertProc.psm1"
Import-Module -Name ".\AlertsModules\DstIPsforEnterprise.psm1"
Import-Module -Name ".\AlertsModules\DnsReqsforAlertProc.psm1"
Import-Module -Name ".\AlertsModules\DnsReqsforEnterprise.psm1"
Import-Module -Name ".\AlertsModules\IndicatorsforAlertProc.psm1"
Import-Module -Name ".\AlertsModules\IndicatorsforEnterprise.psm1"
Import-Module -Name ".\AlertsModules\IncidentQueryThreatInfo.psm1"

#Global variable controlling PowerQuery Time
$timeToBaseline = 2

# S1 API token and base URL
$API_TOKEN = ''
$BASE_URL = 'https://usea1-company.sentinelone.net'
$alertsList = "$BASE_URL/web/api/v2.1/cloud-detection/alerts"
$threatsList = "$BASE_URL/web/api/v2.1/threats"

# Host
$hostName = Read-Host "Enter the Endpoint Name"
if ($hostName -eq ""){
    $hostName = $env:COMPUTERNAME
}

#Time Prompt
$result = $null
  do {
    $s = Read-Host -Prompt 'Enter date or leave blank for today, Ex: 2024-02-24 or 2024-02-24 02:24:24'
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

$currentTime = $result.AddDays(+1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$lastDayTime = $result.AddDays(-1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Check if output folder exists, if not create it
$folderPath = "output"

if (Test-Path -Path $folderPath) {
    #Do nothing if it exists
} else {
    Write-Output "Folder does not exist. Creating..."
    New-Item -Path $folderPath -ItemType Directory
}

# Set up headers for authentication and content type
$headers = @{
    'Authorization' = "ApiToken $API_TOKEN"
    'Content-Type' = 'application/json'
}

$params = @{
    'limit' = 100 # 1000 is the max
    'createdAt__gte' = "$($lastDayTime)"
    'createdAt__lte' = "$($currentTime)"
    'origAgentName__contains' = "$($hostName)"
}

#Try alerts or custom rules first then threats
$totalCount = 0
$alertsUri = "$($alertsList)?limit=$($params.limit)&createdAt__gte=$($params.createdAt__gte)&createdAt__lte=$($params.createdAt__lte)&origAgentName__contains=$($params.origAgentName__contains)"
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
$threatsUri = "$($threatsList)?limit=$($params.limit)&createdAt__gte=$($params.createdAt__gte)&createdAt__lte=$($params.createdAt__lte)&computerName__contains=$($params.origAgentName__contains)"
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

$alertOrThreat = ""
$choice = 0
if($totalCount -eq 0){
    Write-Host "There are no threats or alerts for $hostName."
    break
} 
if($totalCount -eq 1){
    continue
} else{

    $i = 0
    $lastAlertNumber = 0
    $lastThreatNumber = 0
    Write-Host "There are multiple alerts for $hostName . Please choose a number:"
    foreach ($alertName in $alertsResponse.data.ruleInfo.name)
    {
        Write-Host "$i : $alertName"
        $i++
        $lastAlertNumber = $i - 1
    }
    foreach ($threatName in $threatsResponse.data.threatInfo.threatName)
    {
        Write-Host "$i : $threatName ( $($threatsResponse.data.threatInfo.detectionType[($i - $lastAlertNumber - 1)]) )"
        $lastThreatNumber = $i
        $i++
    }
    [int]$userselection = Read-Host -Prompt 'Please choose a number: '
    if (($userselection -isnot [int])) { Throw 'You did not provide a number as input' }

    if(($userselection -lt $lastAlertNumber) -and ($lastAlertNumber -gt 0)){
        $alertOrThreat = "alert"
        $choice = $userselection
    } elseif($lastAlertNumber -eq 0){
        $alertOrThreat = "threat"
        $choice = $userselection
    } else {
        $alertOrThreat = "threat"
        $choice = $userselection - $lastAlertNumber - 1
    }
}

#fields returned by alerts vs threats are named differently
if($alertOrThreat -eq "alert"){
    #Get the pid of the source process in the log - use ruleName to mod later
    $ruleName = $alertsResponse.data.ruleInfo.name[$choice]
    [int]$pid = $alertsResponse.data.sourceProcessInfo.pid[$choice]

    #key fields
    $srcProcName = $alertsResponse.data.sourceProcessInfo.name[$choice]
    $srcProcParentName = $alertsResponse.data.sourceParentProcessInfo.name[$choice]
    $srcProcSigner = $alertsResponse.data.sourceProcessInfo.fileSignerIdentity[$choice]
    $srcProcPath = $alertsResponse.data.sourceProcessInfo.filePath[$choice]
    $srcProcStoryline = $alertsResponse.data.sourceProcessInfo.storyline[$choice]
    $os = $alertsResponse.data.agentDetectionInfo.osFamily[$choice]
}

$detectionEngine = ""
if($alertOrThreat -eq "threat"){
    $ruleName = $threatsResponse.data.threatInfo.threatName[$choice]
    $srcProcStoryline = $threatsResponse.data.threatInfo.storyline[$choice] #storyline does NOT match up in DeepViz on static or dynamic
    $os = $threatsResponse.data.agentRealTimeInfo.agentOsType[$choice]
    $srcProcName = $threatsResponse.data.threatInfo.originatorProcess[$choice]
    $isFileless = $threatsResponse.data.threatInfo.isFileless[$choice]

    #we're going to need these to query for addit data not returned by threat API (but is by alert API)
    $endpointName = $threatsResponse.data.agentRealtimeInfo.agentComputerName[$choice]
    $fileSha1 = $threatsResponse.data.threatInfo.sha1[0]
    $detectionEngine = $threatsResponse.data.threatInfo.detectionType[$choice] #when S1 web pivots they use an event type - but it doesn't match to any fields returned by API so we wont actually use this
    
    if($detectionEngine -eq "static"){
        Get-ThreatExtraInfo -endpointName $endpointName -fileSha1 $fileSha1 -currentTime $currentTime -lastDayTime $lastDayTime
        $ThreatExtraInfo = Get-Content output\incidentQueryThreatInfo.json | ConvertFrom-Json

        if($ThreatExtraInfo.Count -eq 0){
            Write-Host "There is no extra info."
            break
        } elseif($ThreatExtraInfo.Count -eq 1){
            [int]$pid = $ThreatExtraInfo.value[0]
            $srcProcName = $ThreatExtraInfo.value[1]
            $srcProcPath = $ThreatExtraInfo.value[2]
            $srcProcParentName = $ThreatExtraInfo.value[3]
            $srcProcStoryline = $ThreatExtraInfo.value[4]
            $srcProcSignedStatus = $ThreatExtraInfo.value[5]
            $srcProcSigner = $ThreatExtraInfo.value[6]
            $srcProcVerifiedStatus = $ThreatExtraInfo.value[7]
        } else {
            $j = 0
            $k = $ThreatExtraInfo.Count

            Write-Host ""
            Write-Host "There are multiple storylines for file $fileSha1. Please choose a number:"
            foreach ($ThreatInfo in $alertsResponse.data.ruleInfo.name)
            {
                
                if ($ThreatExtraInfo[$j].value[1] -eq ""){
                    Write-Host "$j : no value - probably don't choose this one"
                    $j++
                } else {
                    Write-Host "$j : $($ThreatExtraInfo[$j].value[1])"
                    $j++
                }
            }

            [int]$multiplestorylines = Read-Host -Prompt 'Please choose a number to analyze: '
            if (($multiplestorylines -isnot [int])) { Throw 'You did not provide a number as input' }
            
            $multiplestorylines = $multiplestorylines - 1

            [int]$pid = $ThreatExtraInfo[$multiplestorylines].value[0]
            $srcProcName = $ThreatExtraInfo[$multiplestorylines].value[1]
            $srcProcPath = $ThreatExtraInfo[$multiplestorylines].value[2]
            $srcProcParentName = $ThreatExtraInfo[$multiplestorylines].value[3]
            $srcProcStoryline = $ThreatExtraInfo[$multiplestorylines].value[4]
            $srcProcSignedStatus = $ThreatExtraInfo[$multiplestorylines].value[5]
            $srcProcSigner = $ThreatExtraInfo[$multiplestorylines].value[6]
            $srcProcVerifiedStatus = $ThreatExtraInfo[$multiplestorylines].value[7]
        }
    }
    
    if($detectionEngine -eq "dynamic"){
        #In my Sept 17th powershell ex (should be src proc) only shows in proc args, not src proc or tgt proc
    }
}

#Know Normal #1: Parent Process
Get-ParentProcs -srcProcName $srcProcName -timeToBaseline $timeToBaseline -os $os -currentTime $currentTime -lastDayTime $lastDayTime
$parentProcs = Get-Content output\parentProcs.json | ConvertFrom-Json
$parentProcsCount = $parentProcs.Count
$parentProcAlertCount = 1
$parentProcsTotalCount = 0

foreach ($parentProc in $parentProcs)
{
    if($srcProcParentName -eq $parentProc.value[0]){
        $parentProcAlertCount = $parentProc.value[1]
    }

    $parentProcsTotalCount += $parentProc.value[1]
}

#Know Normal #2 Part 1: Publisher Info
Get-ProcSigInfo -srcProcName $srcProcName -timeToBaseline $timeToBaseline -os $os -currentTime $currentTime -lastDayTime $lastDayTime
$procSigInfos = Get-Content output\ProcSigInfo.json | ConvertFrom-Json

#Know Normal #2 Part 2: Check if Signed / Verified
Get-SignedVerifiedInfo -srcProcName $srcProcName -timeToBaseline $timeToBaseline -srcProcStoryline $srcProcStoryline -currentTime $currentTime -lastDayTime $lastDayTime
$procSignedVerifiedInfo = Get-Content output\ProcSignedVerifiedInfo.json | ConvertFrom-Json

    #If the publisher is unverified, check to see if it might be attempting to masquerade as a legit publisher
    if ($procSignedVerifiedInfo.value[2] -eq "unverified"){
        $srcProcPublisher = $procSignedVerifiedInfo.value[0]
        Get-ProcSignatureCompareToEnterprise -srcProcPublisher $srcProcPublisher -currentTime $currentTime -lastDayTime $lastDayTime
        $procSignatureCompareToEnterprise = Get-Content output\ProcSignatureCompareToEnterprise.json | ConvertFrom-Json
    }

#Know Normal #3: Process Image Path
Get-ProcImagePath -srcProcName $srcProcName -timeToBaseline $timeToBaseline -os $os -currentTime $currentTime -lastDayTime $lastDayTime
$procImagePaths = Get-Content output\srcProcImagePaths.json | ConvertFrom-Json
$procImagePathsCount = $procImagePaths.Count
$procImagePathsAlertCount = 1
$procImagePathsTotalCount = 0

foreach ($procImagePath in $procImagePaths){
    if($srcProcPath -match [Regex]::Escape($procImagePath.key.value)){
        $procImagePathsAlertCount = $procImagePath.value
    }
    $procImagePathsTotalCount += $procImagePath.value
}

#Know Normal #4 Part 1: Network Ports for Source Process of Alerted Endpoint
Get-NetworkPortsforAlertProc -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -currentTime $currentTime -lastDayTime $lastDayTime
$procAlertNetworkPorts = Get-Content output\NetworkPortsforAlertProc.json | ConvertFrom-Json


#Know Normal #4 Part 2: Network Ports for Source Process in Environment
Get-NetworkPortsforEnterprise -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -os $os -currentTime $currentTime -lastDayTime $lastDayTime
$procEnterpriseNetworkPorts = Get-Content output\NetworkPortsforEnterprise.json | ConvertFrom-Json
$procEnterpriseNetworkPortsCount = $procEnterpriseNetworkPorts.Count
$procNetworkPortsAlertsCount = 1 ##This is the part I need to figure out down the road
$procEnterpriseNetworkPortsTotalCount = 0

foreach ($procAlertNetworkPort in $procAlertNetworkPorts){
    foreach ($procEnterpriseNetworkPort in $procEnterpriseNetworkPorts){
        if($procAlertNetworkPort.value[0] -eq $procEnterpriseNetworkPort.value[0]){
            $procAlertNetworkPort[0] | Add-Member -MemberType NoteProperty -Name "ExistsInEnterprise" -Value $True
        }
    }
}

#Tally the enterprise network port total count
foreach ($procEnterpriseNetworkPort in $procEnterpriseNetworkPorts){
    $procEnterpriseNetworkPortsTotalCount += $procEnterpriseNetworkPort.value[1]
}

#Know Normal #5 Part 1: Dst IPs for Source Process of Alerted Endpoint
Get-DstIPsforAlertProc -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -currentTime $currentTime -lastDayTime $lastDayTime
$procAlertDstIPs = Get-Content output\DstIpsforAlertProc.json | ConvertFrom-Json

#Know Normal #5 Part 2: Dst IPs for Source Process in Environment
Get-DstIPsforEnterprise -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -os $os -currentTime $currentTime -lastDayTime $lastDayTime
$procEnterpriseDstIPs = Get-Content output\DstIPsforEnterprise.json | ConvertFrom-Json
$procEnterpriseDstIPsCount = $procEnterpriseNetworkPorts.Count
$procDstIPsAlertsCount = 1 ##This is the part I need to figure out now
$procEnterpriseDstIPsTotalCount = 0

foreach ($procAlertDstIP in $procAlertDstIPs){
    foreach ($procEnterpriseDstIP in $procEnterpriseDstIPs){
        if($procAlertDstIP.value[0] -eq $procEnterpriseDstIP.value[0]){
            $procAlertDstIP[0] | Add-Member -MemberType NoteProperty -Name "ExistsInEnterprise" -Value $True
        }
    }
}

#Tally the enterprise network port total count
foreach ($procEnterpriseDstIP in $procEnterpriseDstIPs){
    $procEnterpriseDstIPsTotalCount += $procEnterpriseDstIP.value[1]
}

#Know Normal #6 Part 1: DNS Requests for Source Process of Alerted Endpoint
Get-DnsReqsforAlertProc -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -currentTime $currentTime -lastDayTime $lastDayTime
$procAlertDnsReqs = Get-Content output\DnsReqsforAlertProc.json | ConvertFrom-Json

#Know Normal #6 Part 2: DNS Requests for Source Process in Environment
Get-DnsReqsforEnterprise -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -os $os -currentTime $currentTime -lastDayTime $lastDayTime
$procEnterpriseDnsReqs = Get-Content output\DnsReqsforEnterprise.json | ConvertFrom-Json

foreach ($procAlertDnsReq in $procAlertDnsReqs){
    foreach ($procEnterpriseDnsReq in $procEnterpriseDnsReqs){
        if($procAlertDnsReq.request -eq $procEnterpriseDnsReq.request){
            $procAlertDnsReq[0] | Add-Member -MemberType NoteProperty -Name "ExistsInEnterprise" -Value $True
        }
    }
}

#Know Normal #7 Part 1: Indicators for Source Process of Alerted Endpoint
Get-IndicatorsforAlertProc -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -currentTime $currentTime -lastDayTime $lastDayTime
$procAlertIndicators = Get-Content output\IndicatorsforAlertProc.json | ConvertFrom-Json

#Know Normal #7 Part 2: Indicators for Source Process in Environment
Get-IndicatorsforEnterprise -hostName $hostName -srcProcName $srcProcName -timeToBaseline $timeToBaseline -os $os -currentTime $currentTime -lastDayTime $lastDayTime
$procEnterpriseIndicators = Get-Content output\IndicatorsforEnterprise.json | ConvertFrom-Json

foreach ($procAlertIndicator in $procAlertIndicators){
    foreach ($procEnterpriseIndicator in $procEnterpriseIndicators){
        if($procAlertIndicator.value[0] -eq $procEnterpriseIndicator.value[0]){
            $procAlertIndicator[0] | Add-Member -MemberType NoteProperty -Name "ExistsInEnterprise" -Value $True
        }
    }
}

#---
#Output the results:
#Ouput part #0: Queries
Write-Host "---"
Write-Host -ForegroundColor cyan "Query #1: Parent Processes"
Write-Host "endpoint.os = '$os' and src.process.name = '$srcProcName' | columns src.process.parent.name | group srcProcParentCount = count (src.process.parent.name) by src.process.parent.name | sort -srcProcParentCount | limit 100"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #2.1: Signer Identity in the Environment"
Write-Host "endpoint.os = '$os' and src.process.name = '$srcProcName' | columns src.process.publisher, src.process.signedStatus, src.process.verifiedStatus  | group srcProcCount = count (src.process.publisher) by src.process.publisher,src.process.signedStatus, src.process.verifiedStatus  | sort -srcProcCount | limit 100"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #2.2: Alert Signer: check verified/signed metadata"
Write-Host "src.process.storyline.id = '$srcProcStoryline' and src.process.name = '$srcProcName' | columns src.process.publisher, src.process.signedStatus, src.process.verifiedStatus  | group srcProcCount = count (src.process.publisher) by src.process.publisher,src.process.signedStatus, src.process.verifiedStatus  | sort -srcProcCount | limit 100"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #3: Process Image Path"
Write-Host "endpoint.os = '$os' and src.process.name = '$srcProcName' | columns src.process.image.path | group ImagePathCount = count (src.process.image.path) by src.process.image.path  | sort -ImagePathCount | limit 100"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #4.1: Ports of the Alert Source Process"
Write-Host "endpoint.name = '$hostName' and src.process.name = '$srcProcName' | columns dst.port.number  | group PortCount = count (dst.port.number) by dst.port.number  | sort -PortCount | limit 1000"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #4.2: Ports for the Src Proc in the Enterprise"
Write-Host "endpoint.os = '$os' and src.process.name = '$srcProcName' and not(endpoint.name = '$hostName') | columns dst.port.number  | group PortCount = count (dst.port.number) by dst.port.number  | sort -PortCount | limit 1000"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #5.1: Dst IPs of the Alert Source Process"
Write-Host "endpoint.name = '$hostName' and src.process.name = '$srcProcName' and not(dst.ip.address matches '^(10\\.|127.0.0.1|192.168.|172.|169.254)')| columns dst.ip.address  | group ipCount = count (dst.ip.address) by dst.ip.address | sort -ipCount | limit 1000"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #5.2: Dst IPs for the Src Proc in the Enterprise"
Write-Host "endpoint.os = '$os' and src.process.name = '$srcProcName' and not(endpoint.name = '$hostName' or dst.ip.address matches '^(10\\.|127.0.0.1|192.168.|172.|169.254)') | columns dst.ip.address  | group ipCount = count (dst.ip.address) by dst.ip.address  | sort -ipCount | limit 1000"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #6.1: DNS Requests of the Alert Source Process"
Write-Host "endpoint.name = '$hostName' and src.process.name = '$srcProcName' | columns event.dns.request  | group DnsReqCount = count (event.dns.request) by event.dns.request  | sort -DnsReqCount | limit 1000"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #6.2: DNS Requests for the Src Proc in the Enterprise"
Write-Host "endpoint.os = '$os' and src.process.name = '$srcProcName' and not(endpoint.name = '$hostName') | columns event.dns.request  | group DnsReqCount = count (event.dns.request) by event.dns.request  | sort -DnsReqCount | limit 1000"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #7.1: Indicators of the Alert Source Process"
Write-Host "endpoint.name = '$hostName' and src.process.name = '$srcProcName' | columns indicator.name  | group indicatorCount = count (indicator.name) by indicator.name | sort -indicatorCount | limit 100"
Write-Host ""
Write-Host -ForegroundColor cyan "Query #7.2: Indicators for the Src Proc in the Enterprise"
Write-Host "endpoint.os = '$os' and src.process.name = '$srcProcName' and not(endpoint.name = '$hostName') | columns indicator.name | group indicatorCount = count (indicator.name) by indicator.name  | sort -indicatorCount | limit 100"
Write-Host ""


#Output part 1 (Parent Process):
$parentProcPercentage = [math]::Round((($parentProcAlertCount / $parentProcsTotalCount) * 100),2)
Write-Host "---"
Write-Host -ForegroundColor cyan "Artifact #1: Parent Process"
Write-Host ""
    if ($parentProcsCount -lt 25){
        Write-Host "Parent Process of Alert: $srcProcParentName"
        Write-Host "# of Parent Procs in Environment: $parentProcsCount"
        Write-Host "Percentage of Parent Procs: $parentProcPercentage %"
        Write-Host "Even though it only accounts for $($parentProcPercentage) , there are quite a bit of parent processes."
    } ElseIf ($parentProcPercentage -lt 10){
        Write-Host -ForegroundColor red "Parent Process of Alert: $srcProcParentName"
        Write-Host -ForegroundColor red "# of Parent Procs in Environment: $parentProcsCount"
        Write-Host -ForegroundColor red "Percentage of Parent Procs: $parentProcPercentage %"
        Write-Host -ForegroundColor red "Even though it only accounts for $($parentProcPercentage) , there are quite a bit of parent processes."
    } Else{
        Write-Host "Parent Process of Alert: $srcProcParentName"
        Write-Host "# of Parent Procs in Environment: $parentProcsCount"
        Write-Host "Percentage of Parent Procs: $parentProcPercentage %"
    }
Write-Host "---"

#Output part 2 (Signer Identity):
Write-Host -ForegroundColor cyan "Artifact #2: Signer Identity"
Write-Host ""
#$SignerIdentityPercentage = [math]::Round((($sigInfosAlertCount / $sigInfosTotalCount) * 100),2)
    $signedCount = 0
    $unsignedCount = 0
    $verifiedcount = 0
    $unVerifiedCount = 0

    foreach($sigInfo in $procSignatureCompareToEnterprise){
        if($sigInfo.value[0] -eq "signed"){
            $signedCount += $sigInfo.value[2]
        } elseif($sigInfo.value[0] -eq "unsigned"){
            $unsignedCount += $sigInfo.value[2]
        }

        if($sigInfo.value[1] -eq "verified"){
            $verifiedcount += $sigInfo.value[2]
        } elseif($sigInfo.value[1] -eq "unverified"){
            $unVerifiedCount += $sigInfo.value[2]
        }
    }

    $totalsignedSampling = $unsignedCount + $signedCount
    $unsignedPercentage = $unsignedCount / $totalsignedSampling
    $totalverifiedSampling = $unVerifiedCount + $verifiedCount
    $unverifiedPercentage = $unVerifiedCount / $totalverifiedSampling

    Write-Host "Signer Identity of Alert: $srcProcSigner"
    
    #Signed/Unsigned color logic
    if ($procSignedVerifiedInfo.value[1] -eq "signed"){
        Write-Host -ForegroundColor green "Alert process is signed or unsigned: $($procSignedVerifiedInfo.value[1])"
    } ElseIf ($procSignedVerifiedInfo.value[1] -eq "unsigned"){
        Write-Host -ForegroundColor yellow "Alert process is signed or unsigned: $($procSignedVerifiedInfo.value[1])"
    } Else {
        Write-Host "Alert process is signed or unsigned: $($procSignedVerifiedInfo.value[1])"
    }

    if ($unsignedCount -eq 0) {
        Write-Host "There are $($unsignedCount) endpoints with unsigned out of $($totalsignedSampling) total endpoints"
    } elseif ($unsignedPercentage -lt .10) {
        Write-Host -ForegroundColor red "There are $($unsignedCount) endpoints with unsigned out of $($totalsignedSampling) total endpoints"
    } else {
        Write-Host "There are $($unsignedCount) endpoints with unsigned out of $($totalsignedSampling) total endpoints"
    }

    #Verified/Unverified color logic
    if ($procSignedVerifiedInfo.value[2] -eq "verified"){
        Write-Host -ForegroundColor green "Alert process signature is verified or unverified: $($procSignedVerifiedInfo.value[2])"
    } ElseIf ($procSignedVerifiedInfo.value[2] -eq "unverified"){
        Write-Host -ForegroundColor yellow "Alert process signature is verified or unverified: $($procSignedVerifiedInfo.value[2])"
        Write-Host -ForegroundColor yellow "A signed / unverified binary often indicates self signed."
    } Else {
        Write-Host "Alert process signature is verified or unverified: $($procSignedVerifiedInfo.value[2])"
    }

    if ($unVerifiedCount -eq 0) {
        Write-Host "There are $($unVerifiedCount) endpoints with unverified out of $($totalverifiedSampling) total endpoints"
    } elseif ($unverifiedPercentage -lt .10) {
        Write-Host -ForegroundColor red "There are $($unVerifiedCount) endpoints with unverified publisher $($srcProcSigner) out of $($totalverifiedSampling) total endpoints"
        Write-Host -ForegroundColor red "This could potentially be malware attempting to masquerade as a legitamite process."
    } else {
        Write-Host "There are $($unVerifiedCount) endpoints with unverified publisher $($srcProcSigner) out of $($totalverifiedSampling) total endpoints"
    }

Write-Host "---"

#Output part 3 (Image Path):
Write-Host -ForegroundColor cyan "Artifact #3: Image Path"
Write-Host ""
$ImagePathPercentage = [math]::Round((($procImagePathsAlertCount / $procImagePathsTotalCount) * 100),2)
Write-Host "Keep in mind with image path Sys32 for example can have a few different variations. This will need a deeper look."
Write-Host "Image Path of Alert: $srcProcPath"
Write-Host "# of Image Paths in Environment: $procImagePathsCount"
    if ($SignerIdentityPercentage -lt 10) {
        Write-Host -ForegroundColor red "Percentage of Image Paths: $ImagePathPercentage %"
    } else {
        Write-Host "Percentage of Image Paths: $ImagePathPercentage %"
    }
Write-Host "---"

#Output part 4 (Network Ports):
Write-Host -ForegroundColor cyan "Artifact #4: Network Ports"
Write-Host ""


Write-Host "Outputting any anomalous ports that were not seen in the top 1,000 for $($srcProcName):"
foreach ($procAlertNetworkPort in $procAlertNetworkPorts){
    if ($procAlertNetworkPort.ExistsInEnterprise -ne $True){
        if($procAlertNetworkPort.value[0] -eq ""){
        } else{
            Write-Host -ForegroundColor red "Port $($procAlertNetworkPort.value[0]) for $($srcProcName) is anomalous"
        }
    }
}
Write-Host "---"

#Output part 5 (Dst IPs):
Write-Host -ForegroundColor cyan "Artifact #5: Destination IPs"
Write-Host ""

Write-Host "Outputting any anomalous ips that were not seen in the top 1,000 for $($srcProcName):"
foreach ($procAlertDstIP in $procAlertDstIPs){
    if ($procAlertDstIP.ExistsInEnterprise -ne $True){
        if($procAlertDstIP.value[0] -eq ""){
        } else{
            Write-Host -ForegroundColor red "IP $($procAlertDstIP.value[0]) for $($srcProcName) is anomalous"
        }
    }
}
Write-Host "---"

#Output part 6 (DNS Requests):
Write-Host -ForegroundColor cyan "Artifact #6: DNS Requests"
Write-Host ""

Write-Host "Outputting any anomalous dns reqs (keep in mind sometimes cached) that were not seen in the top 1,000 for $($srcProcName):"
foreach ($procAlertDnsReq in $procAlertDnsReqs){
    if ($procAlertDnsReq.ExistsInEnterprise -ne $True){
        if($procAlertDnsReq.request -eq ""){
        } else{
            Write-Host -ForegroundColor red "Domain $($procAlertDnsReq.request) for $($srcProcName) is anomalous"
        }
    }
}
Write-Host "---"

#Output part 7 (Indicators):
Write-Host -ForegroundColor cyan "Artifact #7: Indicators"
Write-Host ""

Write-Host "Outputting any anomalous indicators for $($srcProcName):"
foreach ($procAlertIndicator in $procAlertIndicators){
    if ($procAlertIndicator.ExistsInEnterprise -ne $True){
        if($procAlertIndicator.value[0] -eq ""){
            } else{
                Write-Host -ForegroundColor red "Indicator $($procAlertIndicator.value[0]) for $($srcProcName) is anomalous"
            }
    }
}
Write-Host "---"

if($detectionEngine -eq "static"){
    Write-Host -ForegroundColor yellow "This was a static detection, these artifacts are centered around the originating process of the detection under the assumption that the malware itself was not allowed to detonate."
}

}
