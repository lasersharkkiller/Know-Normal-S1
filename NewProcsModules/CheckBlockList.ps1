#http://cyber.sec.REDACTED_COMPANY.com/ip_blocklist.txt

Import-Module -Name ".\CheckIpsAgainstVT.psm1"

$CSV1 = Import-Csv -Path 'RDP_Connections.csv'
$reference = [System.Collections.Generic.HashSet[string]]::new(
    [string[]](Import-Csv -Path 'Blocklist.csv').'ip'.ForEach('Trim')
)

$results = foreach($line in $Csv1)
{
    $ip = $line.'ip'.Trim()
    [PSCustomObject]@{
        ip   = $ip
        ExistsInBlockList = ('Not Match', 'Match')[$reference.Contains($ip)]
    }
}

$results | Export-Csv -Path "RDP_Comparison.csv" -NoTypeInformation

Get-CheckNonMatchesAgainstVT -results $results
