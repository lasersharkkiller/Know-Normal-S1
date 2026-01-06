function Get-CheckSuspiciousASNs{

param (
        [Parameter(Mandatory=$true)]
        $asn
    )

$susASNList = Get-Content -Path "output\suspiciousASNs.txt" | ForEach-Object {
    $_.Trim().ToLower()
}

if ($susASNList -contains $asn) {
    return $true
} else {
    return $false
}
}