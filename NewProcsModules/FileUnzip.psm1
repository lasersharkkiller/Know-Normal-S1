function Get-FileUnzip {

    Import-Module -Name ".\NewProcsModules\FileMagicType.psm1"
    Import-Module -Name ".\NewProcsModules\DeleteDuplicates.psm1"

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

        #Check the file header, don't rely on the extension (especially for linux)
        Get-FileMagicType

        $binaryExts = @(".exe",".bin",".obj",".elf")
        Get-ChildItem ".\files" -File -Recurse | Where-Object { $binaryExts -notcontains $_.Extension.ToLower() } | Remove-Item -ErrorAction SilentlyContinue
        Get-DeleteDuplicates
    }
}
