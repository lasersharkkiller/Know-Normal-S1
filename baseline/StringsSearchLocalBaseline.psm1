function Get-StringsSearchLocalBaseline {

    # 1. Prompt the user for the string
    $SearchString = Read-Host -Prompt "Enter the string to search for"

    # 2. Define your paths (you can add more here easily)
    $TargetPaths = @(
        ".\output-baseline\IntezerStrings\",
        ".\output-baseline\VirusTotal-main\"
    )

    # 3. Search both paths recursively using the variable
    Get-ChildItem -Path $TargetPaths -Filter *.json -Recurse | Select-String -Pattern $SearchString
}

