function Get-CheckApiVoid{
    
param (
        [Parameter(Mandatory=$true)]
        $artifacts,
        $type
    )

Import-Module -Name ".\NewProcsModules\CheckBlockedCountries.psm1"
Import-Module -Name ".\NewProcsModules\CheckSuspiciousASNs.psm1"
    
foreach ($artifact in $artifacts) {
    $ApiVoidApi = ''

    $ApiVoid_headers = @{
        "X-API-Key" = $ApiVoidApi
        "Content-Type" = "application/json"
    }

    $apivoid_url
    $ApiVoid_body
    if ($type -eq "IPAddress") {
        $apivoid_url = 'https://api.apivoid.com/v2/ip-reputation'
        $ApiVoid_body = @{ ip = $artifact } | ConvertTo-Json -Depth 3
    } elseif ($type -eq "DomainName") {
        $apivoid_url = 'https://api.apivoid.com/v2/domain-reputation'
        $ApiVoid_body = @{ host = $artifact } | ConvertTo-Json
    }
    
    $privateIpsAndBogons = "^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|0\.0\.0\.0|255\.255\.255\.255)$"
    if (-not ($artifact -match $privateIpsAndBogons)) {try {
        $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body
        
        #json response is different for ip addr vs domain
        if ($type -eq "IPAddress") {
            
            #Check if it's in the blocked country list
            $existsInCountryBlockList = Get-CheckBlockedCountries -country $response.information.country_name.Trim().ToLower()
            if ($existsInCountryBlockList -eq $true) {
                Write-Host "Country: " $response.information.country_name "exists in geo-block list." -ForegroundColor Red
            } else {
                Write-Host "Country: " $response.information.country_name
            }

            #Check if it's in the suspicious ASNs list
            $existsInASNList = Get-CheckSuspiciousASNs -asn $response.information.asn
            if ($existsInASNList -eq $true) {
                Write-Host "ISP is in suspicious list: " $response.information.isp -ForegroundColor Yellow
                Write-Host "ASN is in suspicious list: " $response.information.asn -ForegroundColor Yellow
            } else {
                Write-Host "ISP: " $response.information.isp
                Write-Host "ASN: " $response.information.asn
            }

            if ($response.anonymity.is_proxy -eq "true"){
                Write-Host "Is Proxy: " $response.anonymity.is_proxy -ForegroundColor Yellow
            }
            if ($response.anonymity.is_webproxy -eq "true"){
                Write-Host "Is Web Proxy: " $response.anonymity.is_webproxy -ForegroundColor Yellow
            }
            if ($response.anonymity.is_vpn -eq "true"){
                Write-Host "Is VPN: " $response.anonymity.is_vpn -ForegroundColor Yellow
            }
            if ($response.anonymity.is_hosting -eq "true"){
                Write-Host "Is Hosting: " $response.anonymity.is_hosting -ForegroundColor Yellow
            }
            if ($response.anonymity.is_proxy -eq "true"){
                Write-Host "Is Tor: " $response.anonymity.is_tor -ForegroundColor Yellow
            }
        } elseif ($type -eq "DomainName") {
            #Check if it's in the Blocked Countries list
            $existsInCountryBlockList = Get-CheckBlockedCountries -country $response.server_details.country_name.Trim().ToLower()
            
            if ($existsInCountryBlockList -eq $true) {
                Write-Host "Country: " $response.server_details.country_name "exists in geo-block list." -ForegroundColor Red
            } else {
                Write-Host "Country: " $response.server_details.country_name
            }

            #Check if it's in the suspicious ASNs list
            $existsInASNList = Get-CheckSuspiciousASNs -asn $response.server_details.asn
            if ($existsInASNList -eq $true) {
                Write-Host "ISP is in suspicious list: " $response.server_details.isp -ForegroundColor Yellow
                Write-Host "ASN is in suspicious list: " $response.server_details.asn -ForegroundColor Yellow
            } else {
                Write-Host "ISP: " $response.server_details.isp
                Write-Host "ASN: " $response.server_details.asn
            }

            if ($response.category.is_free_hosting -eq "true"){
                Write-Host "Is Free Hosting: " $response.category.is_free_hosting -ForegroundColor Yellow
            }
            if ($response.category.is_anonymizer -eq "true"){
                Write-Host "Is Anonymizer: " $response.category.is_anonymizer -ForegroundColor Yellow
            }
            if ($response.category.is_url_shortener -eq "true"){
                Write-Host "Is URL Shortener: " $response.category.is_url_shortener -ForegroundColor Yellow
            }
            if ($response.category.is_free_dynamic_dns -eq "true"){
                Write-Host "Is Free Dynamic DNS: " $response.category.is_free_dynamic_dns -ForegroundColor Yellow
            }
            if ($response.category.is_code_sandbox -eq "true"){
                Write-Host "Is code sandbox: " $response.category.is_code_sandbox -ForegroundColor Yellow
            }
            if ($response.category.is_form_builder -eq "true"){
                Write-Host "Is form builder: " $response.category.is_form_builder -ForegroundColor Yellow
            }
            if ($response.category.is_free_file_sharing -eq "true"){
                Write-Host "Is free file sharing: " $response.category.is_free_file_sharing -ForegroundColor Yellow
            }
            if ($response.category.is_pastebin -eq "true"){
                Write-Host "Is pastebin: " $response.category.is_pastebin -ForegroundColor Yellow
            }
        }
        
        #Now highlight the overall risk score
        if ($response.risk_score.result -eq 0) {
            Write-Host "ApiVoid Risk Score: " $response.risk_score.result -ForegroundColor Green
        } elseif ($response.risk_score.result -lt 50) {
            Write-Host "ApiVoid Risk Score: " $response.risk_score.result -ForegroundColor Yellow
        } else {
            Write-Host "ApiVoid Risk Score: " $response.risk_score.result -ForegroundColor Red
        }
        
        return $response
    } catch {
        Write-Error "Request failed: $_"
    }} else {
        Write-Host $artifact " was a private ip or bogon, not sending for analysis"
    }
}
}
