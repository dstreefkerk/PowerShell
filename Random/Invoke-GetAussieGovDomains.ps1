<#
.DESCRIPTION
	  Retrieve a list of Australian government (.gov.au) domains from
    the CKAN Data API at https://data.gov.au/
#>


# https://data.gov.au/dataset/ds-dga-4d5301b2-bc64-4774-b437-56a408836e57/details
$dataUri = 'https://data.gov.au/data/api/3/action/datastore_search?resource_id=507f8129-b84c-4215-ae7d-5aca364e4a0e&limit=2000'

# Basic function to strip the URL down to the bare FQDN
function GhettoCleanURL([string]$URL) {
    $output = $URL.Replace('https://','')
    $output = $output.Replace('http://','')
    $output = $output.Replace('www.','')
    $output = $output.Split('/')[0]

    return $output
}

# Query the API
$query = $null
try {
    $query = Invoke-RestMethod -Uri $dataUri -ErrorAction Stop
}
catch {
    throw "Error retrieving data from CKAN Data API"
}

# Check that the results are in an object format we expect
try {
    $query.result.records | Get-Member -ErrorAction Stop | Out-Null
}
catch {
    throw "The API returned an unexpected result, cannot continue"
}

# Grab the results, extract the domain, and only select unique .gov.au domains
$query.result.records | Select-Object Title,@{n='Domain';e={GhettoCleanURL($_.'Resource URL')}},Creator | Where-Object {$_.Domain -like '*.gov.au'} | Sort-Object -Property Domain -Unique
