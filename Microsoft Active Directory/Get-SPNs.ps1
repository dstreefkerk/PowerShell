# Get-SPNs.ps1
#
# List all SPNs in use within the current domain
# and output them into a PowerShell GridView
#
# Daniel Streefkerk - https://twitter.com/dstreefkerk

# Setup
$output = @()

# Search AD via ADSI
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(servicePrincipalName=*)"
$results = $search.Findall()
 
# Process Results
foreach ($result in $results) {
    $entry = $result.GetDirectoryEntry()
 
    foreach ($spn in $entry.servicePrincipalName) {
        $tempHash = [ordered]@{ "ObjectName" = $entry.name.Value
                                "DistinguishedName" = $entry.distinguishedName.Value
                                "Category" = $entry.objectCategory.Value
                                "SPN" = $spn
        }

        $output += New-Object -TypeName psobject -Property $tempHash
    }
}

$output | Out-GridView
