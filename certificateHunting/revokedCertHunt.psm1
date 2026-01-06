function Get-revokedCertHunt{

# --- Configuration ---
$searchPath = ".\output-baseline\VirusTotal-main\"
$outputDir = ".\output-baseline\Cert_Analysis_Results"

# --- Initialization ---
Write-Host "Starting certificate analysis in: $searchPath"
$jsonFiles = Get-ChildItem -Path $searchPath -Filter *.json -Recurse -ErrorAction SilentlyContinue

if (-not $jsonFiles) {
    Write-Error "No .json files found in '$searchPath'. Please check the path."
    return
}

if (-not (Test-Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory | Out-Null
}

$categories = @{
    "Revoked_Time_Expired"     = [System.Collections.Generic.HashSet[string]]::new()
    "Revoked_Not_Time_Expired" = [System.Collections.Generic.HashSet[string]]::new()
}

$fileCount = $jsonFiles.Count
$i = 0
$currentDate = Get-Date

# --- Processing Loop ---
foreach ($file in $jsonFiles) {
    $i++
    $hash = $file.BaseName
    Write-Progress -Activity "Processing VT JSON Files" -Status "Checking $hash" -PercentComplete (($i / $fileCount) * 100)
    
    $vtData = Get-Content -Path $file.FullName -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction SilentlyContinue -ErrorVariable parseError

    if ($parseError) {
        Write-Warning "Could not parse JSON: $($file.FullName)"
        continue
    }

    $isRevoked = $false
    $isExpired = $false
    
    # Ensure attributes exist
    if ($null -eq $vtData.data -or $null -eq $vtData.data.attributes) { continue }
    $attributes = $vtData.data.attributes
    $sigInfo = $attributes.signature_info

    # --- 1. Check Tags ---
    if ($null -ne $attributes.tags) {
        if ($attributes.tags -contains "revoked-cert" -or $attributes.tags -match "revoked-cert") {
            $isRevoked = $true
        }
    }

    # --- 2. Check Signature Info (Handling Spaces AND Underscores) ---
    if ($null -ne $sigInfo) {
        $statusStrings = [System.Collections.ArrayList]::new()
        
        # 2a. Check top-level 'verified'
        if ($sigInfo.verified) { $statusStrings.Add($sigInfo.verified) | Out-Null }

        # 2b. Helper to extract lists regardless of naming convention
        # We look for "signers_details" (API standard) AND "signers details" (Your file format)
        $signersLists = @(
            $sigInfo.signers_details, 
            $sigInfo."signers details", 
            $sigInfo.counter_signers_details, 
            $sigInfo."counter signers details",
            $sigInfo.certificate_details,
            $sigInfo."certificate details"
        )

        foreach ($list in $signersLists) {
            if ($null -ne $list) {
                foreach ($item in $list) {
                    # Collect Text Status
                    if ($item.status) { $statusStrings.Add($item.status) | Out-Null }
                    if ($item.verified) { $statusStrings.Add($item.verified) | Out-Null }

                    # Fallback: Date Check (valid to)
                    # If we haven't found a text confirmation of expiration, check the date math
                    if (-not $isExpired) {
                        $validTo = $null
                        # Check keys with spaces and underscores
                        if ($item."valid to") { $validTo = $item."valid to" }
                        elseif ($item.valid_to) { $validTo = $item.valid_to }

                        if ($validTo) {
                            try {
                                $certDate = [DateTime]::Parse($validTo)
                                if ($certDate -lt $currentDate) {
                                    $isExpired = $true
                                    # Write-Host "DEBUG: Date Expired detected on $hash ($validTo)"
                                }
                            } catch {
                                # Date parsing failed, ignore
                            }
                        }
                    }
                }
            }
        }

        # 2c. Analyze collected text strings
        $megaString = $statusStrings -join " "
        if ($megaString -like "*revoked*") { $isRevoked = $true }
        if ($megaString -like "*not time valid*") { $isExpired = $true }
        if ($megaString -like "*expired*") { $isExpired = $true }
    }

    # --- 3. Categorization ---
    if ($isRevoked) {
        if ($isExpired) {
            $categories["Revoked_Time_Expired"].Add($hash) | Out-Null
        } else {
            $categories["Revoked_Not_Time_Expired"].Add($hash) | Out-Null
        }
    }
}

Write-Progress -Activity "Processing VT JSON Files" -Completed

# --- Report Generation ---
Write-Output "---"
Write-Output "Certificate Status Report Complete"
Write-Output ""

Write-Output "## 1. Revoked (Time Expired)"
Write-Output "Hashes found: $($categories['Revoked_Time_Expired'].Count)"
$categories["Revoked_Time_Expired"] | Out-File -FilePath "$outputDir\hashes_revoked_time_expired.txt"
$categories["Revoked_Time_Expired"] # Display in console

Write-Output ""
Write-Output "## 2. Revoked (Not Time Expired)"
Write-Output "Hashes found: $($categories['Revoked_Not_Time_Expired'].Count)"
$categories["Revoked_Not_Time_Expired"] | Out-File -FilePath "$outputDir\hashes_revoked_not_time_expired.txt"
$categories["Revoked_Not_Time_Expired"] # Display in console

Write-Output ""
Write-Output "---"

}