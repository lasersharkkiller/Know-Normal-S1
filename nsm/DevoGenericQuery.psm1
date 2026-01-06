function Get-DevoGenericQuery{

    <#
.SYNOPSIS
    Queries Devo API for IP data and deduplicates by /24 subnet.
.DESCRIPTION
    1. Connects to Devo US API.
    2. Runs the specified LINQ query.
    3. Downloads results to CSV.
#>

# --- CONFIGURATION ---
$ApiToken = Get-Secret -Name 'Devo_Access_Token' -AsPlainText
$QueryFile = ".\nsm\devoQuery.txt"

$Lookback = "2d"                        # Time range (matches your dashboard link)
$OutFile  = "Final_Cleaned_IPs.csv"

# Devo US Endpoint
$Uri = "https://apiv2-us.devo.com/search/query"

# --- CHECK FOR QUERY FILE ---
if (-not (Test-Path $QueryFile)) {
    Write-Error "Could not find '$QueryFile'. Please create this file and paste your Devo query inside it."
    exit
}

# Read the query and collapse newlines into spaces (safe for API JSON)
$Query = (Get-Content $QueryFile) -join " "

# --- STEP 1: DOWNLOAD DATA FROM DEVO ---
Write-Host "Connecting to Devo API..." -ForegroundColor Cyan

$Headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type"  = "application/json"
}

$Body = @{
    "query" = $Query
    "from"  = "now()-$Lookback"
    "to"    = "now()"
    "mode"  = @{
        "type" = "csv"
    }
} | ConvertTo-Json

try {
    Write-Host "Executing Query (This may take a moment)..."
    $Response = Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Body -TimeoutSec 300
    
    # Save raw results temporarily
    $Response | Out-File ".\nsm\raw_devo_dump.csv" -Encoding ASCII
    Write-Host "Data downloaded successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to download from Devo. Check your API Token and Query syntax."
    Write-Host $_.Exception.Message
    exit
}

Write-Host "File saved to .\nsm\raw_devo_dump.csv" -ForegroundColor Cyan

}