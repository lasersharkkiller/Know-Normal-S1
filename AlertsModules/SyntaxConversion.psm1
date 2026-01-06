function Get-SyntaxConversion{

# Define the file path
$filePath = "output\rule.txt"

# 1. READ CONTENT
$content = Get-Content -Path $filePath -Raw

# 2. SANITIZE WHITESPACE
$content = $content -replace '\s+', ' '

# 3. WHOLE WORD REPLACEMENTS (Strict)
$strictReplacements = @{
    "Url" = "url.address"
    "dns" = "event.dns.request"
    "Ref" = "http.request.referrer"
    "Id"  = "event.id"
}

foreach ($key in $strictReplacements.Keys) {
    $pattern = "(?<!\w)" + [regex]::Escape($key) + "(?!\w)"
    $content = $content -replace $pattern, $strictReplacements[$key]
}

# 4. STANDARD REPLACEMENTS (Ordered)
$replacements = [Ordered]@{
    # Operators
    " AND "                         = " and "
    " OR "                          = " or "
    " NOT "                         = " not "
    " IN "                          = " in "
    
    # Syntax
    "ContainsCIS"                   = "contains:anycase"
    "In Contains Anycase"           = "contains:anycase"
    "contains anycase"              = "contains:anycase"
    "in Contains"                   = "contains"
    "EXISTS"                        = "is not null"
    "RegExp"                        = "matches"
    '\"'                            = "\\"
    '"'                             = "'"
    
    # Process Field Mapping
    "srcProcParentName"             = "src.process.parent.name"
    "tgtProcParentName"             = "tgt.process.parent.name"
    "SrcProcParentSignedStatus"     = "src.process.parent.signedStatus"
    "SrcProcCmdScript"              = "cmdScript.content"
    "SrcProcCmdLine"                = "src.process.cmdline"
    "TgtProcCmdLine"                = "tgt.process.cmdline"
    "srcProcSignedStatus"           = "src.process.signedStatus"
    "srcProcVerifiedStatus"         = "src.process.verifiedStatus"
    "SrcProcPublisher"              = "src.process.publisher"
    "TgtProcPublisher"              = "tgt.process.publisher"
    "SrcProcImagePath"              = "src.process.image.path"
    "SrcProcIntegrityLevel"         = "src.process.integrityLevel"
    "srcProcName"                   = "src.process.name"
    "tgtProcName"                   = "tgt.process.name"
    "SrcProcSha1"                   = "src.process.image.sha1"
    "SrcProcMd5"                    = "src.process.image.md5"
    "SrcProcSha256"                 = "src.process.image.sha256"
    "TgtFileSha1"                   = "tgt.file.sha1"
    "TgtFileMd5"                    = "tgt.file.md5"
    "TgtFileSha256"                 = "tgt.file.sha256"
    "TgtFileIsSigned"               = "tgt.file.isSigned"
    "TgtFileExtension"              = "tgt.file.extension"
    "TgtFilePath"                   = "tgt.file.path"
    "FilePath"                      = "tgt.file.path"
    "DnsResponse"                   = "event.dns.response"
    "DnsRequest"                    = "event.dns.request"
    "DstIp"                         = "dst.ip.address"
    "SrcIp"                         = "src.ip.address"
    "DstPort"                       = "dst.port.number"
    "SrcPort"                       = "src.port.number"
    "DstMac"                        = "dst.mac.address"
    "SrcMac"                        = "src.mac.address"
    "RegKeyPath"                    = "registry.keyPath"
    "RegValueName"                  = "registry.value"
    "RegValueData"                  = "registry.data"
    "RegHive"                       = "registry.hive"
    "UserName"                      = "user.name"
    "UserDomain"                    = "user.domain"
    "LogonId"                       = "user.logonId"
    "IndicatorName"                 = "indicator.name"
    "IndicatorMetadata"             = "indicator.metadata"
    "ObjectType"                    = "event.category"
    "EventType"                     = "event.type"
    "EndpointName"                  = "endpoint.name"
}

foreach ($key in $replacements.Keys) {
    $content = $content -replace [regex]::Escape($key), $replacements[$key]
}

# 5. FIX OPERATOR SPACING
# Uses \b to avoid breaking words like 'contains' or 'cmdline'
$content = $content -replace '\b(and|or|not|in)\b', ' $1 ' 
$content = $content -replace '\)\s*(or|and)\s*\(', ') $1 ('

# 6. OPTIMIZATION: Consolidate 'OR' lists (Handling = and CONTAINS)
# This pattern matches: 
#   field op 'val1' OR field op 'val2'
#   Where 'op' can be "=" or "contains"
#
# (?<field>[\w\.]+)   -> Capture Field Name
# \s*(?<op>=|contains)\s* -> Capture Operator (= or contains)
# (?<q>['"])          -> Capture Quote
# (.*?)               -> Match Value 1
# \k<q>               -> Close Quote
# (?: ... )+          -> Repeat for OR statements

$pattern = "(?<field>[\w\.]+)\s*(?<op>=|contains)\s*(?<q>['""])(.*?)\k<q>(?:\s+or\s+\k<field>\s*\k<op>\s*\k<q>(.*?)\k<q>)+"

$matchesFound = [regex]::Matches($content, $pattern, "IgnoreCase")

foreach ($match in $matchesFound) {
    $field = $match.Groups['field'].Value
    $op    = $match.Groups['op'].Value
    
    # If the operator is '=', we usually want to switch to 'IN'
    # If the operator is 'contains', we keep 'contains' but use list format: contains ('a','b')
    $finalOp = if ($op -eq "=") { "in" } else { "contains" }

    # Extract values. Look for the operator followed by quotes.
    # We look for: (equals or contains) then spaces then 'value'
    $values = [regex]::Matches($match.Value, "(?:=|contains)\s*['""](.*?)['""]") | ForEach-Object { 
        "'" + $_.Groups[1].Value + "'" 
    }
    
    # Create new string: field in ('val1', 'val2') OR field contains ('val1', 'val2')
    $newString = "$field $finalOp ($($values -join ', '))"
    
    # Replace in the main content
    $content = $content.Replace($match.Value, $newString)
}

# 7. FINAL CLEANUP
$content = $content -replace '\s{2,}', ' '

# Write output
Set-Content -Path $filePath -Value $content

Write-Output $content
Write-Output ""
Write-Output "Output saved to: $($filePath)"

}
