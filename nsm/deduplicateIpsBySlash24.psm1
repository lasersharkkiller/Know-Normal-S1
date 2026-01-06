function Get-DeduplicateIpsBySlash24{

    # Configuration
    $InputFile = Read-Host -Prompt "Enter name/location of csv"
    $OutputFile = ".\nsm\input_ips.csv"

    # Process the CSV
    $RawData = Import-Csv -Path $InputFile

    # --- Auto-Detect Columns ---
    # Look for columns named 'XFF', 'ip', 'dst.ip.address', etc.
    $IpColumn = $RawData[0].PSObject.Properties.Name | Where-Object { $_ -match "ip" -or $_ -eq "XFF" } | Select-Object -First 1
    # Look for columns named 'Count', 'ipCount', '_count', etc.
    $CountColumn = $RawData[0].PSObject.Properties.Name | Where-Object { $_ -match "count" } | Select-Object -First 1

    if (-not $IpColumn) { Write-Error "Could not find IP column."; exit }
    Write-Host "Detected IP Column: '$IpColumn' | Count Column: '$CountColumn'" -ForegroundColor Cyan

    $RawData | 
        # 1. Create Subnet Key (First 3 octets)
        Select-Object *, @{Name="Subnet"; Expression={($_.$IpColumn -split "\.")[0..2] -join "."}} | 
    
        # 2. Group by Subnet
        Group-Object Subnet | 
    
        # 3. Sort by Count (Descending) and take the top 1
        ForEach-Object { 
            $_.Group | 
            # If a count column exists, sort by it. Otherwise just take the first one.
            Sort-Object -Property @{Expression={if($CountColumn){[int]$_.$CountColumn}else{1}}} -Descending | 
            Select-Object -First 1 
    } | 
    
    # 4. Export just the IP
    Select-Object @{Name="ip"; Expression={$_.$IpColumn}} | 
    Export-Csv -Path $OutputFile -NoTypeInformation -Encoding ASCII

    Write-Host "Done! Saved to $OutputFile"
}