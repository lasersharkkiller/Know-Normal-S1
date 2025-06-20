function Get-DeleteDuplicates{
# Delete duplicates based on hash
$folder = ".\files"
$hashTable = @{}

Get-ChildItem -Path $folder -File | ForEach-Object {
    $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
    $filePath = $_.FullName

    if ($hashTable.ContainsKey($hash.Hash)) {
        #Delete duplicates
        Remove-Item -Path $filePath -Force
    } else {
        #First time hash appears
        $hashTable[$hash.Hash] = $filePath
    }
}
}