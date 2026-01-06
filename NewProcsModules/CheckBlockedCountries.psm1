function Get-CheckBlockedCountries{

param (
        [Parameter(Mandatory=$true)]
        $country
    )

$countryBlockList = Get-Content -Path "output\country_blocklist.txt" | ForEach-Object {
    $_.Trim().ToLower()
}

if ($countryBlockList -contains $country.Trim().ToLower()) {
    return $true
} else {
    return $false
}
}