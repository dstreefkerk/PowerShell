<#
.DESCRIPTION
	Quick way of getting Brand Indicators for Message Identification (BIMI) records,
    rather than using Resolve-DNSName

    https://tools.ietf.org/id/draft-blank-ietf-bimi-00.html

.SYNOPSIS
	Retrieve BIMI records for a single domain, or a collection of domains

.PARAMETER DomainName
	Email domain to check
	
.EXAMPLE
	.\Invoke-GetBIMIRecord.ps1 -EmailDomain "agari.com"

	Retrieve BIMI Record for the domain agari.com

.INPUTS
	System.String

.OUTPUTS
	Selected.Microsoft.DnsClient.Commands.DnsRecord_TXT

.NOTES
	NAME:	 Invoke-GetBIMIRecord.ps1
	AUTHOR:	 Daniel Streefkerk
	WWW:	 https://daniel.streefkerkonline.com
	Twitter: @dstreefkerk

	REQUIREMENTS:
		
	VERSION HISTORY:
		1.0 29/07/2019
			- Initial Version
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True)]
    [string[]]$EmailDomain
)
process {
    foreach ($domain in $EmailDomain) {
        # As per https://tools.ietf.org/id/draft-blank-ietf-bimi-00.html#indicator-discovery

        # Note that we can only try to retrieve the default selector as specified by the standard
        # Like DKIM, if other selectors exist, they'll be arbitrary and decided by the implementor
        Resolve-DnsName -Name "default._bimi.$domain" -Type TXT -ErrorAction SilentlyContinue | Where-Object {$_.Strings -like '*v=BIMI1*'} -ErrorAction SilentlyContinue | Select-Object Name,Strings
    }
}