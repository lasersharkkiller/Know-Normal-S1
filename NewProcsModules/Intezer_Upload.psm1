function Get-IntezerUpload{
param (
        [Parameter(Mandatory=$true)]
        $filePath
    )
# Windows PowerShell 5.1-compatible multipart upload to Intezer /analyze

$intezerApiKey = Get-Secret -Name 'Intezer_API_Key' -AsPlainText
$apiUrl = "https://analyze.intezer.com/api/v2-0" 

# --- Step 1: Get Access Token ---
Write-Host "Step 1: Requesting access token..." -ForegroundColor Cyan
try {
    $tokenRequest = @{
        uri     = "$apiUrl/get-access-token"
        method  = "POST"
        body    = @{api_key = $intezerApiKey} | ConvertTo-Json
        headers = @{"Content-Type" = "application/json"}
    }
    $tokenResponse = Invoke-RestMethod @tokenRequest
    $Token = $tokenResponse.result
    Write-Host "Success." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to get access token." -ForegroundColor Red
    Write-Host "Reason: $($_.Exception.Message)"
    exit
}

$Url      = "https://analyze.intezer.com/api/v2-0/analyze"

# Ensure TLS 1.2 (often required by modern APIs)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Use .NET HttpClient to build multipart/form-data
Add-Type -AssemblyName System.Net.Http

$client = [System.Net.Http.HttpClient]::new()
$client.DefaultRequestHeaders.Authorization =
    [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $Token)

$multipart = [System.Net.Http.MultipartFormDataContent]::new()

$fs = [System.IO.File]::OpenRead($filePath)
$fileContent = [System.Net.Http.StreamContent]::new($fs)
$fileContent.Headers.ContentType =
    [System.Net.Http.Headers.MediaTypeHeaderValue]::new("application/octet-stream")

$fileName = [System.IO.Path]::GetFileName($filePath)
# field name must be "file"
$multipart.Add($fileContent, "file", $fileName)

try {
    $resp = $client.PostAsync($Url, $multipart).Result
    Write-Host "HTTP $([int]$resp.StatusCode) $($resp.StatusCode) for $($filePath)"
    $body = $resp.Content.ReadAsStringAsync().Result

    # Try to pretty-print JSON if returned
    try {
        ($body | ConvertFrom-Json) | Format-List *
    } catch {
        $body
    }
}
finally {
    $fileContent.Dispose()
    $fs.Dispose()
    $multipart.Dispose()
    $client.Dispose()
    Get-ChildItem $filePath | Remove-Item -ErrorAction SilentlyContinue
}
}