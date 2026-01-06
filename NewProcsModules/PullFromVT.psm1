function Get-PullFromVT {

param (
    [Parameter(Mandatory)][string]$Sha256,
    $fileName,
    [string]$OutputFolder = "files"
)

$VTApi = Get-Secret -Name 'VT_API_Key_1' -AsPlainText

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
}

# VT Intelligence file download URL
$downloadUrl = "https://www.virustotal.com/intelligence/download/?hash=$Sha256&apikey=$VTApi"
$outputFile = Join-Path $OutputFolder "$($fileName)"

# --- NEW LOGIC: Check for Name Collision and Hash Comparison ---
if (Test-Path $outputFile) {
    try {
        # Get hash of the existing local file
        $existingHash = (Get-FileHash -Path $outputFile -Algorithm SHA256).Hash

        # Compare existing hash with the requested hash (Case-insensitive)
        if ($existingHash -ne $Sha256) {
            # Hashes are DIFFERENT: Rename the new file to avoid overwriting the different existing file
            $count = 1
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
            $extension = [System.IO.Path]::GetExtension($fileName)
            
            # Loop until we find a filename that doesn't exist
            do {
                $newFileName = "{0} ({1}){2}" -f $baseName, $count, $extension
                $newFullPath = Join-Path $OutputFolder $newFileName
                $count++
            } while (Test-Path $newFullPath)
            
            # Update the output file path to the new unique name
            $outputFile = $newFullPath
            Write-Host "File with same name but different hash detected. Renaming download to: $($newFileName)"
        } else {
            # Hashes are the SAME: Proceed to overwrite as requested
            Write-Host "File with same name and hash detected. Overwriting..."
        }
    }
    catch {
        Write-Warning "Could not calculate hash of existing file. Proceeding with overwrite."
    }
}
# ----------------------------------------------------------------

try {
    # Attempt to download the file
    #Invoke-WebRequest was super slow
    $startDownload = Start-Process curl.exe -ArgumentList "--fail --ssl-no-revoke -L $downloadUrl -o `"$outputFile`"" -NoNewWindow -Wait -PassThru
    # Note: Added quotes around $outputFile in ArgumentList to handle spaces in filenames safely

    if ((Test-Path $outputFile) -and ((Get-Item $outputFile).Length -gt 0)) {   
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