function Get-S1Activities{

    param (
        [Parameter(Mandatory=$true)]
        $baseUrl,
        $headers
    )

# Define variables, note that activityType=80 is downloaded file
$now = (Get-Date)
$topoftheHour = $now.AddDays(0).ToUniversalTime().ToString("yyyy-MM-ddTHH:00:00.000000Z")
$activityURL = "$baseUrl/activities?activityTypes=80&agentIds=$agentIdsFromFilePulls&createdAt__gt=$topoftheHour"
$activityURL = $activityURL -replace(" ",",") #format for S1 API call
$activityURL
#Remove the application/json content type or we can't download
$newHeaders = @{
    'Authorization' = $headers.Authorization
}

# Step 1: find the DownloadUrl
$newActivityResponse = Invoke-RestMethod -Uri $activityURL -Method Get -Headers $headers

if ($newActivityResponse -ne $null) {
    $AgentIdForFileDownload = $newActivityResponse.data.agentid[-1]
    $downloadURL = $newActivityResponse.data.data.downloadUrl[-1]
    $uploadedFilename = $newActivityResponse.data.data.uploadedFilename[-1]

    #Download File
    $URI = "$baseUrl$downloadURL"
    $OutFile = $(Get-Location).Path + "\files\" + $uploadedFilename
        
    #For some reason this isn't working
    #$FileFetch = Invoke-WebRequest $URI -Method GET -Headers $newHeaders
    #$FileFetch | Get-Member
    #$ZipStream = New-Object System.IO.Memorystream
	#$ZipStream.Write($FileFetch.Content,0,$FileFetch.Content.Length)
	#$ZipFile = [System.IO.Compression.ZipArchive]::new($ZipStream)
    #[System.IO.File]::WriteAllBytes($OutFile, $FileFetch.Content)
	#Write-Host "File saved to $OutFile" -ForegroundColor Green
        
    #Trying a jenky workaround
    Start-Process "chrome" $URI
    $agentIdsFromFilePulls.Remove($AgentIdForFileDownload)

    #Move from Downloads - part of the jenky workaround
    $downloadsPath = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path
    #Note I tried filtering on Mark of the Web but oddly I'm not seeing a Zone.Identifier alternate stream, only $DATA
    $checkFolder = (Get-ChildItem -Filter "*.zip" -Path $downloadsPath).Count
    Get-ChildItem -Filter "*.zip" -Path $downloadsPath | Where-Object { $_.LastWriteTime -gt (Get-Date).AddSeconds(-300) } | Move-Item -Destination .\files\
    #Using 7z.exe instead of Expand-7zip bc PS module doesnt support extraction without file structure
    if ($checkFolder -eq 0){
        continue
    } else {
        & "C:\Program Files\7-Zip\7z.exe" e ".\files\*"  -o".\files" -p"Infected123" -aot -bso0
        Remove-Item -Path (".\files\manifest*",".\files\*.zip",".\files\.*",".\files\version*") -ErrorAction SilentlyContinue
    }

} else {
    continue
}
}
