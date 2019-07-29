<#
.DESCRIPTION
	Quick way of getting MX records, rather than using Resolve-DNSName

.SYNOPSIS
	Retrieve MX records for a single domain, or a collection of domains 

.PARAMETER DomainName
	Email domain to check
	
.EXAMPLE
	.\Invoke-GetMXRecord.ps1 -EmailDomain "contoso.com"

	Retrieve MX Record details for the domain contoso.com

.INPUTS
	System.String

.OUTPUTS
	Selected.Microsoft.DnsClient.Commands.DnsRecord_MX

.NOTES
	NAME:	 Invoke-EmailRecon.ps1
	AUTHOR:	 Daniel Streefkerk
	WWW:	 https://daniel.streefkerkonline.com
	Twitter: @dstreefkerk

	REQUIREMENTS:

	VERSION HISTORY:
		1.0 27/06/2019
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
        Resolve-DnsName -Name $domain -Type MX | Sort-Object -Property Preference | Select-Object -Property Name,TTL,NameExchange,Preference
    }
}