function Get-CheckAgainstVT{

param (
        [Parameter(Mandatory=$true)]
        $artifacts,
        $type
    )

#Import-Module VirusTotalAnalyzer -Force
#https://github.com/EvotecIT/VirusTotalAnalyzer
$VTApi = ''

# Create an array to store the results
$VTresults = @()
Write-Host ""
# Loop through each hash
foreach ($artifact in $artifacts) {
    $report
    # Get the report from VirusTotal
    if ($type -eq "DomainName") {
        $report = Get-VirusReport -ApiKey $VTApi -DomainName $artifact
    } elseif ($type -eq "IPAddress") {
        $report = Get-VirusReport -ApiKey $VTApi -IPAddress $artifact
    } 
        # Extract Creation or Registration Date
        $parsedDate
        $ageDays

        # Match possible creation/registration date line
        $regPattern = 'Creation Date:\s*(.+)|Registered On:\s*(.+)|RegDate:\s*(.+)'
        $whoisText = $report.data.attributes.whois
        $classification
        $regDate

        if ($whoisText -match $regPattern) {
            if ($matches[1]) {
                $regDate = $matches[1]
            } elseif ($matches[2]) {
                $regDate = $matches[2]
            } elseif ($matches[3]) {
                $regDate = $matches[3]
            } else {
                $regDate = $null
        }
        }

        #VT Tags can be useful
        $tags = ($report.data.attributes.tags | ForEach-Object { $_.name }) -join ", "
        Write-Host "Tags: $tags"

        if ($regDate -ne $null) {
            Write-Host "Reg date: "
            Write-Host $regDate
            $parsedDate = [datetime]::Parse($regDate)
            Write-Host "Domain registered on: $parsedDate"
        }

        # Create an object to store the results
        Start-Sleep -Seconds 0.2
        $VTresult = [PSCustomObject]@{
            Artifact = $artifact
            Malicious = $report.data.attributes.last_analysis_stats.malicious
            Suspicious = $report.data.attributes.last_analysis_stats.suspicious
            Undetected = $report.data.attributes.last_analysis_stats.undetected
            Harmless = $report.data.attributes.last_analysis_stats.harmless
            ASN = $report.data.attributes.asn
            ASN_Owner = $report.data.attributes.as_owner
            Country = $report.data.attributes.country
        }

    # Add the result to the array
    $VTresults += $VTresult
    }

Write-Host $VTresults
}
