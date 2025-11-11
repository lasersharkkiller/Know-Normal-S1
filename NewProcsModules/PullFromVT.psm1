function Get-PullFromVT{

param (
    [Parameter(Mandatory)][string]$Sha256,
    $fileName,
    [string]$OutputFolder = "files"
)

$VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
}

# VT Intelligence file download URL
$downloadUrl = "https://www.virustotal.com/intelligence/download/?hash=$Sha256&apikey=$VTApi"
$outputFile = Join-Path $OutputFolder "$($fileName)"

try {
    # Attempt to download the file
    #Invoke-WebRequest -Uri $downloadUrl -OutFile $outputFile -ErrorAction Stop
    
    #Invoke-WebRequest was super slow
    $startDownload = Start-Process curl.exe -ArgumentList "--fail --ssl-no-revoke -L $downloadUrl -o $outputFile" -NoNewWindow -Wait -PassThru
    #Write-Host "Start-Process curl.exe -ArgumentList --ssl-no-revoke -L " $downloadUrl " -o " $outputFile " -NoNewWindow -Wait -PassThru"

    if ((Test-Path $outputFile) -and ((Get-Item $outputFile).Length -gt 0)) {   #This was for Invoke-WebRequest
    #if($startDownload.ExitCode -eq 0 -and (Test-Path $outputFile)) { #This was for curl
        Write-Host "File downloaded: $outputFile"
        return $true
    } else {
        Write-Host "No data returned or file is empty, next trying to pull with S1."
        Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
        return $false
    }
}
catch {
    # Friendly error handling
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        Write-Host "File not found on VirusTotal (404), next trying to pull with S1."
        return $false
    } elseif ($_.Exception.Response.StatusCode.value__ -eq 403) {
        Write-Host "Access denied. Make sure your API key is for VT Intelligence (Premium), next trying to pull with S1."
        return $false
    } elseif ($_.Exception.Response.StatusCode.value__ -eq 429) {
        Write-Host "Rate limit exceeded. Try again later, next trying to pull with S1."
        return $false
    } else {
        Write-Host " Error: $($_.Exception.Message) , next trying to pull with S1."
        return $false
    }
}

}
