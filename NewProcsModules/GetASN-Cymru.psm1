function Get-ASNCymru {
    param (
        [Parameter(Mandatory=$true)]
        $artifact,
        $type
    )

    $ip
    #Check if domain, and if it is resolve domain to IPv4 address
    if ($type -eq "DomainName") {
        $ip = [System.Net.Dns]::GetHostAddresses($artifact) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1

        if (-not $ip) {
            Write-Host "Could not resolve IPv4 address for $Domain"
            exit
        }
    } else {
        $ip = $artifact
    }

    # Reverse the IP octets
    $reversed = ($ip -split '\.')[-1..0] -join '.'
    $query1 = "$reversed.origin.asn.cymru.com"

    try {
        #The first result doesn't quite give us all the info we need
        $result1 = Resolve-DnsName -Name $query1 -Type TXT -ErrorAction Stop
        $info1 = ($result1.Strings -split '\|') | ForEach-Object { $_.Trim() }
        
        #We use the ASN Number to pull the rest of the info
        $query2 = "AS$($info1[0]).asn.cymru.com"
        $result2 = Resolve-DnsName -Name $query2 -Type TXT -ErrorAction Stop
        $info2 = ($result2.Strings -split '\|') | ForEach-Object { $_.Trim() }
        
        return [PSCustomObject]@{
            ASN = $info1[0]
            Country = $info1[1]
            Registry = $info1[2]
            #Allocated= $info[3]
            Owner = $info2[4]
        }
    } catch {
        Write-Host "Could not resolve ASN info for $ip with Cymru"
    }
}
