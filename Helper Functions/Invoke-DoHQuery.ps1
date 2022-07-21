<#
.DESCRIPTION
	A quick concept script to query the Cloudflare DNS over HTTPS API at https://cloudflare-dns.com/dns-query

.SYNOPSIS
	Run DNS queries against DNS over HTTPS resolvers

.PARAMETER Name
	DNS Name to query for

.PARAMETER Type
	DNS Record Type to query for
	
.EXAMPLE
	.\Invoke-DoHQuery.ps1 -Name example.com -Type TXT

	Query Cloudflare DNS over HTTPS API for all TXT records for example.com

.INPUTS
	System.String

.OUTPUTS
	PSCustomObject with JSON data containing response to DNS over HTTPS query

.NOTES
	NAME:	 Invoke-DoHQuery.ps1
	AUTHOR:	 Daniel Streefkerk

	VERSION HISTORY:
		1.0 	21/07/2022 - Initial version. No changes or additions planned.
			
	TODO:
		- Nothing
#>

PARAM (
	[Parameter(Mandatory = $true, HelpMessage = "Specify a DNS Name to query for")]
	[ValidateNotNull()]
	[string]$Name,

    [Parameter(Mandatory = $false, HelpMessage = "Type of DNS record to query for. Defaults to an 'A' Record")]
	[ValidateSet("A", "TXT", "MX", "SOA", IgnoreCase = $true)]
	[string]$Type = "A"
)

$dohEndpoint = "https://cloudflare-dns.com/dns-query"

try {
    $dnsResponse = Invoke-RestMethod -Uri "$($dohEndpoint)?name=$($Name)&type=$($Type)" -Headers @{'accept' = 'application/dns-json'}
    
    if ($dnsResponse.Answer) {
        $dnsResponse.Answer
    } else {
        Write-Error "DNS over HTTPS query failed with return code $($dnsResponse.Status)"
    }
}
catch {
    Write-Error "An error occurred while trying to query DNS over HTTPs for $Name"
}