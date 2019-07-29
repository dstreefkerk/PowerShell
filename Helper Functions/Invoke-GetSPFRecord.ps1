<#
.DESCRIPTION
	Quick way of getting SPF records, rather than using Resolve-DNSName

.SYNOPSIS
	Retrieve SPF records for a single domain, or a collection of domains 

.PARAMETER DomainName
	Email domain to check
	
.EXAMPLE
	.\Invoke-GetSPFRecord.ps1 -EmailDomain "contoso.com"

	Retrieve SPF Record details for the domain contoso.com

.INPUTS
	System.String

.OUTPUTS
	Microsoft.DnsClient.Commands.DnsRecord_TXT

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
        Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue
    }
}