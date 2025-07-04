function Get-CheckApiVoid{

param (
        [Parameter(Mandatory=$true)]
        $artifacts,
        $type
    )
    
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

    try {
        $response = Invoke-RestMethod -Method "POST" -Uri $apivoid_url -Headers $ApiVoid_headers -Body $ApiVoid_body

        return $response
    } catch {
        Write-Error "Request failed: $_"
    }
}
}
