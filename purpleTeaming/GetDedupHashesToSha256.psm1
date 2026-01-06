function Get-DedupHashesToSha256{
<#
.SYNOPSIS
    Intelligently de-duplicates an IOC CSV by first normalizing all file
    hashes (MD5, SHA1) to their SHA256 equivalent using the VirusTotal API.
.DESCRIPTION
    This script reads a CSV with an "IOC" column.
    1.  If an IOC is an MD5 or SHA1, it queries the VT API to find its
        corresponding SHA256. It then *replaces* the IOC value with the SHA256
        and uses this SHA256 as its "master ID".
    2.  If an IOC is a SHA256, it's used directly as the "master ID".
    3.  If an IOC is a domain or IP, it's also used directly as its "master ID".
    The script then de-duplicates the entire list based on this "master ID".
    The final output is a new CSV file containing only the *unique* rows,
    with all hash IOCs converted to SHA256.
#>

[string]$CsvPath = Read-Host -Prompt "Enter path to IOC list"

# --- Functions (from your .psm1) ---

# Helper function to get the API key
function Get-VTApiKey {
    $key = $env:VT_API_KEY
    if (-not $key) {
        try {
            # Tries to get from PowerShell Secret Management
            $key = (Get-Secret -Name 'VT_API_Key_1' -AsPlainText)
        }
        catch {
            # Falls back to a secure prompt
            $key = Read-Host "Enter your VirusTotal API key" -AsSecureString
            $key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($key))
        }
    }
    return $key
}

# Function to query VirusTotal for file metadata
function Get-VTFileReport {
    param (
        [string]$Hash,
        [string]$ApiKey
    )

    $uri = "https://www.virustotal.com/api/v3/files/$Hash"
    $headers = @{
        "x-apikey" = $ApiKey
    }

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        # Return the 'attributes' part of the report
        return $response.data.attributes
    }
    catch {
        Write-Warning "Failed to get report for $Hash. Error: $_"
        return $null
    }
}

# --- Main Script ---

Write-Host "Initializing hash conversion and de-duplication script..."
$apiKey = Get-VTApiKey

if (-not $apiKey) {
    Write-Error "API Key is required."
    return
}

# 1. Check if the CSV file exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "File not found: $CsvPath"
    return
}

# 2. Generate a new output file name
$fileInfo = Get-Item $CsvPath
$outputPath = Join-Path -Path $fileInfo.DirectoryName -ChildPath ($fileInfo.BaseName + "_converted_and_unique" + $fileInfo.Extension)

# 3. Import the CSV
try {
    $iocList = Import-Csv -Path $CsvPath
    Write-Host "Successfully imported $($iocList.Count) records from $CsvPath"
}
catch {
    Write-Error "Failed to import CSV. Make sure it's a valid CSV file. Error: $_"
    return
}

# 4. Use a HashSet (like your original) for de-duplication
$seenMasterIDs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$uniqueRows = [System.Collections.Generic.List[object]]::new()

$totalRows = 0
$duplicateRows = 0

Write-Host "---"
Write-Host "Beginning conversion and de-duplication pass..."
Write-Host "(This may take a while if there are many MD5/SHA1 hashes to translate)"
Write-Host "---"


# 5. Process each record
foreach ($row in $iocList) {
    $totalRows++
    $ioc = $row.IOC.Trim()
    $masterID = $ioc # Default master ID is the IOC itself (for IPs/Domains)

    # Check if the value looks like a SHA256 hash
    if ($ioc -match '^[A-Fa-f0-9]{64}$') {
        # $masterID is already $ioc, so no change needed.
    }
    # Check if it's an MD5 or SHA1
    elseif ($ioc -match '^[A-Fa-f0-9]{32}$' -or $ioc -match '^[A-Fa-f0-9]{40}$') {
        Write-Host "Found MD5/SHA1: $ioc. Attempting to translate..." -ForegroundColor Yellow
        
        $report = Get-VTFileReport -Hash $ioc -ApiKey $apiKey
        
        if ($report -and $report.sha256) {
            $masterID = $report.sha256
            Write-Host " -> Translated to: $masterID" -ForegroundColor Cyan
            
            # --- KEY CHANGE: DOING BOTH ---
            # 1. We set $masterID for de-duplication (like script 1)
            # 2. We ALSO update the $row object for the output (like script 2)
            $row.IOC = $masterID
            # --- END KEY CHANGE ---
            
            # Pause briefly to respect API rate limits
            Start-Sleep -Seconds 1
        }
        else {
            Write-Warning " -> Could not translate $ioc. Using original hash as master ID."
            # $masterID remains the original $ioc
        }
    }
    # Else: It's a Domain, IP, or other non-hash IOC.
    # We leave $masterID as the original $ioc, which is correct.

    # --- De-duplication Step ---
    # Try to add the master ID to the 'seen' set.
    if ($seenMasterIDs.Add($masterID)) {
        # This is a new, unique item. Add the entire *modified* row to our output list.
        $uniqueRows.Add($row)
    }
    else {
        # This master ID has been seen before (e.g., we already saw the SHA256
        # and now we've found the matching MD5).
        $duplicateRows++
        Write-Host "Skipping duplicate: $masterID (Original IOC: $ioc)" -ForegroundColor Gray
    }
}

# 6. Export the unique rows to the new CSV
try {
    # The $uniqueRows list now contains only unique rows, 
    # and all hash rows have their IOC column set to the SHA256.
    $uniqueRows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "---"
    Write-Host "Conversion and de-duplication complete." -ForegroundColor Green
    Write-Host "Processed: $totalRows rows"
    Write-Host "Removed:   $duplicateRows duplicates"
    Write-Host "Saved:     $($uniqueRows.Count) unique rows"
    Write-Host "New file saved to: $outputPath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to save output file: $_"
}

}