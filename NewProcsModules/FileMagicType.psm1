function Get-FileMagicType {
    $signatures = @{
        "FFD8FF" = "jpg";
        "89504E47" = "png";
        "47494638" = "gif";
        "25504446" = "pdf";
        "504B0304" = "zip"; # zip/docx/xlsx/pptx
        "4D5A" = "exe"; # exe/dll
        "52617221" = "rar";
        "1F8B08" = "gz";
        "377ABCAF271C" = "7z";
        "7F454C46" = "elf";
        "3C3F786D6C" = "xml";
    }

    $rootFolder = Join-Path $PSScriptRoot "..\files"

    if (-not (Test-Path $rootFolder)) {
        Write-Host "Folder not found: $rootFolder"
        return
    }

    Get-ChildItem -Path $rootFolder -File -Recurse | ForEach-Object {
        $file = $_

        try {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)[0..11]
            $hex = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""

            $trueType = "unknown"
            foreach ($sig in $signatures.Keys) {
                if ($hex.StartsWith($sig)) {
                    $trueType = $signatures[$sig]
                    break
                }
            }

            if ($trueType -ne "unknown") {
                $currentExt = [System.IO.Path]::GetExtension($file.Name).TrimStart('.').ToLower()
                if ($currentExt -ne $trueType) {
                    $baseName = $file.BaseName
                    $targetName = "$baseName.$trueType"
                    $targetPath = Join-Path $file.DirectoryName $targetName

                    if (-not (Test-Path $targetPath)) {
                        Rename-Item -Path $file.FullName -NewName $targetName
                        Write-Host "Renamed $($file.Name) to $targetName"
                    } else {
                        # Compare hashes
                        $existingHash = (Get-FileHash $targetPath -Algorithm SHA256).Hash
                        $incomingHash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash

                        if ($existingHash -eq $incomingHash) {
                            Write-Host "Duplicate file (same hash): $($file.Name) ➜ skipped + removed"
                            Remove-Item $file.FullName -Force
                        } else {
                            # Find next available name
                            $counter = 1
                            do {
                                $altName = "$baseName`_$counter.$trueType"
                                $altPath = Join-Path $file.DirectoryName $altName
                                $counter++
                            } while (Test-Path $altPath)

                            Rename-Item -Path $file.FullName -NewName $altName
                            Write-Host "Renamed duplicate with new hash: $($file.Name) ➜ $altName"
                        }
                    }
                } else {
                    Write-Host "Correct extension: $($file.Name)"
                }
            } else {
                #Write-Host "Unknown type: $($file.Name)"
            }

        } catch {
            Write-Host "Could not process $($file.Name): $($_.Exception.Message)"
        }
    }
    return
}
