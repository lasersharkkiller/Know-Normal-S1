function Get-S1Activities{

    param (
        [Parameter(Mandatory=$true)]
        $S1GetActivitiesheaders,
        $baseUrl,
        $agentId
    )
    
Import-Module -Name ".\NewProcsModules\DeleteDuplicates.psm1"

# Define variables, note that activityType=80 is downloaded file
$now = (Get-Date)
$topoftheHour = $now.AddDays(0).ToUniversalTime().ToString("yyyy-MM-ddTHH:00:00.000000Z")
$activityURL = "$baseUrl/activities?activityTypes=80&agentIds=$agentId&createdAt__gt=$topoftheHour"
$activityURL = $activityURL -replace(" ",",") #format for S1 API call

#Remove the application/json content type or we can't download
$newHeaders = @{
    'Authorization' = $S1GetActivitiesheaders.Authorization
}

# Step 1: find the DownloadUrl
$newActivityResponse
try {
    $newActivityResponse = Invoke-RestMethod -Uri $activityURL -Method Get -Headers $S1GetActivitiesheaders
}
catch {
    continue
}
$retryCount = 0
$maxRetries = 5

while ($newActivityResponse.data.primaryDescription -notmatch "successfully uploaded") {
    Start-Sleep -Seconds 30
    $newActivityResponse = Invoke-RestMethod -Uri $activityURL -Method Get -Headers $S1GetActivitiesheaders
    $retryCount++
    if ($retryCount -ge $maxRetries) {
        break
    }
}

if ($newActivityResponse.data.primaryDescription -match "successfully uploaded") {
    $AgentIdForFileDownload = $newActivityResponse.data.agentid
    $downloadURL = $newActivityResponse.data.data.downloadUrl
    $uploadedFilename = $newActivityResponse.data.data.uploadedFilename

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
        $binaryExts = @(".exe",".bin",".obj",".elf")
        Get-ChildItem ".\files" -File -Recurse | Where-Object { $binaryExts -notcontains $_.Extension.ToLower() } | Remove-Item -ErrorAction SilentlyContinue
        Get-DeleteDuplicates
    }
    Clear-Variable $newActivityResponse
} else {
    continue
}
}
