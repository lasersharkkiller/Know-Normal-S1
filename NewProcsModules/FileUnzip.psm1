function Get-FileUnzip {

    Import-Module -Name ".\NewProcsModules\FileMagicType.psm1" | Out-Null
    Import-Module -Name ".\NewProcsModules\DeleteDuplicates.psm1" | Out-Null
    Import-Module -Name ".\NewProcsModules\Intezer_Upload.psm1" | Out-Null

    #Move from Downloads - part of the jenky workaround
    $downloadsPath = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path
    #Note I tried filtering on Mark of the Web but oddly I'm not seeing a Zone.Identifier alternate stream, only $DATA
    $checkFolder = (Get-ChildItem -Filter "*.zip" -Path $downloadsPath).Count
    Get-ChildItem -Filter "*.zip" -Path $downloadsPath | Where-Object { $_.LastWriteTime -gt (Get-Date).AddSeconds(-3600) } | Move-Item -Destination .\files\
    #Using 7z.exe instead of Expand-7zip bc PS module doesnt support extraction without file structure
    if ($checkFolder -eq 0){
        $wasEmpty = $True
        return
    } else {
        & "C:\Program Files\7-Zip\7z.exe" e ".\files\*"  -o".\files" -p"Infected123" -aot -bso0 | Out-Null

        # Double check if returned empty file (only manifest.json from the zip file)
        $itemsInDirectory = Get-ChildItem -Path ".\files\"

        # Filter the items to find the specific files we're looking for.
        $manifestFile = $itemsInDirectory | Where-Object { $_.Name -eq 'manifest.json' }
        $zipFiles = $itemsInDirectory | Where-Object { $_.Extension -eq '.zip' }

        if ($itemsInDirectory.Count -eq 2 -and $manifestFile.Count -eq 1 -and $zipFiles.Count -eq 1) {
            Write-Host "The unzipped file only contains manifest.json." -ForegroundColor Yellow
            $itemsInDirectory | Remove-Item -Recurse -Force
            $global:wasEmpty = $True
            return
        }
        else {
            Write-Host "Contents found: $($itemsInDirectory.Name -join ', ')"
        }
        
        #Check the file header, don't rely on the extension (especially for linux)
        Get-FileMagicType

        $binaryExts = @(".exe",".bin",".obj",".elf")
        Get-ChildItem ".\files" -File -Recurse | Where-Object { $binaryExts -notcontains $_.Extension.ToLower() } | Remove-Item -ErrorAction SilentlyContinue | Out-Null
        
        #For each exe/bin/obj/elf submit to Intezer
        Get-ChildItem -Path ".\files\" -Include "*.exe", "*.elf", "*.bin", "*.obj" -Recurse -File | ForEach-Object {
            Write-Host "File to upload to Intezer: $($_.FullName)" -ForegroundColor Cyan
            $doubleCheckFileHash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash
            Write-Host "File's Hash: $($doubleCheckFileHash)"
            Get-IntezerUpload -filePath "$($_.FullName)"
        } | Out-Null
        
        #Get-DeleteDuplicates used to keep files but don't any more; used to have issues pulling the right hash - was due to version 24.1 and below
        # Get all items (files and folders) in the target directory.
        $deleteDirectory = Get-ChildItem -Path ".\files\" | Out-Null
        # Pipe the list of items to Remove-Item to delete them.
        $deleteDirectory | Remove-Item -Recurse -Force
        
        return
    }
}