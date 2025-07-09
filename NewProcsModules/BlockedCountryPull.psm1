function Get-BlockedCountryList{

Set-Variable -Name "countryBlockListGlobal"
#Download the blocklist
$countryBlocklistURL = "https://misp-site.com/ips_blocked_countries.txt"
    try {
        $countryBlocklist = Invoke-WebRequest -Uri $countryBlocklistURL -ErrorAction Stop
        #save to a local file bc it doesn't process this list as a proper array
        $countryBlocklist.Content > "output\country_blocklist.txt"
        #By reimporting it recognizes each line as the entry of an array .. yeah .. powershell ..
        $countryBlockListGlobal = Get-Content -Path "output\country_blocklist.txt" | ForEach-Object {
            $_.Trim().ToLower()
        }
    } catch {
        Write-Host "Unable to download the latest internal blocklist"
    }

}
