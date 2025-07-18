function Get-MispPull{

Set-Variable -Name "dedupedBlockList" -Scope Global
#Download the blocklist
$mispBlocklistURL = "http://site/ip_blocklist.txt"
    try {
        $mispBlocklist = Invoke-WebRequest -Uri $mispBlocklistURL -ErrorAction Stop
        #save to a local file bc it doesn't process this list as a proper array
        $mispBlocklist.Content > "output\misp_ip_blocklist.txt"
        #By reimporting it recognizes each line as the entry of an array .. yeah .. powershell ..
        $blockList = Get-Content -Path "output\misp_ip_blocklist.txt"
        #Dedup into /24s
        $dedupedBlockList = $blockList | ForEach-Object {
            $octets = $_ -split '\.'
            "$($octets[0]).$($octets[1]).$($octets[2])"
        } | Sort-Object -Unique
    } catch {
        Write-Host "Unable to download the latest internal blocklist"
    }

}
