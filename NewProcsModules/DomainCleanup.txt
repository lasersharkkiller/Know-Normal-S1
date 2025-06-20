function Get-DomainCleanup{

    param (
        [Parameter(Mandatory=$true)]
        $domain
    )

# Improved regex to capture full domain with subdomains
$regex = '(?i)(?:https?|ftp|ssh):\/\/((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:[:\/\s"\x00]|$)|\b((?:[a-z0-9-]+\.)+[a-z]{2,63})(?=\b|[^a-z0-9.-])'
                  
# Extract both from URL and standalone
$matches = [regex]::Matches($domain, $regex)

# Normalize and deduplicate
$domains = $matches | ForEach-Object {
    if ($_.Groups[1].Success) { $_.Groups[1].Value.ToLower() }
    elseif ($_.Groups[2].Success) { $_.Groups[2].Value.ToLower() }
} | Sort-Object -Unique

# Output
return $domains
}