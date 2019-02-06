<#
.DESCRIPTION
	A quick and dirty script to be used to automate the collection of 
    publicly-available email-related records

    For example; MX, SPF, DMARC records.

    It'll also try to make a determination about who's handling mail flow, and whether the domain
    is hosted on Exchange Online (sometimes ExOnline tenants pass their mail through filtering
    services like ProofPoint, Mimecast, etc)

    If the domain is hosted on Exchange Online, it'll also check whether DKIM is configured

.SYNOPSIS
	Perform email-based reconnaissance on a single domain, or a collection of domains 

.PARAMETER DomainName
	Email domain to check
	
.EXAMPLE
	.\Invoke-EmailRecon.ps1 -EmailDomain "contoso.com"

	Retrieve email details for the domain contoso.com

.EXAMPLE
	.\Invoke-EmailRecon.ps1 -EmailDomain "contoso.com",'fabrikam.com'

	Retrieve email details for multiple domains

.EXAMPLE
	.\Invoke-EmailRecon.ps1 -EmailDomain "contoso.com",'fabrikam.com' | Format-Table -AutoSize

	Retrieve email details for multiple domains, and format the results in a table

.EXAMPLE
	Get-Content C:\temp\domains.txt | .\Invoke-EmailRecon.ps1 | Format-Table -AutoSize

	Get a list of domains from a text file (single domain per line), retrieve the details, and format the results into a table

.EXAMPLE
	Get-Content C:\temp\domains.txt | .\Invoke-EmailRecon.ps1 | Export-Csv c:\temp\domains.csv -NoTypeInformation

	Get a list of domains from a text file (single domain per line), retrieve the details, and export the results to a CSV file

.INPUTS
	System.String

.OUTPUTS
	Custom PowerShell object containing email-related information collected from public DNS records

.NOTES
	NAME:	 Invoke-EmailRecon.ps1
	AUTHOR:	 Daniel Streefkerk
	WWW:	 https://daniel.streefkerkonline.com
	Twitter: @dstreefkerk

	REQUIREMENTS:
		- PowerShell 3.0, because we're using ordered PSObjects and the Resolve-DNSName cmdlet

	VERSION HISTORY:
		1.0 05/02/2019
			Initial Version, based on an old collection of stuff I've had lying around for ages
			
	TODO:
		- The code needs to be optimised as we're making many DNS queries for each domain. That'll come later in my rebuilt
          version of this script. I've been working on a modular version that uses plugins for some time now.
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True)]
    [string[]]$EmailDomain
)

begin {

    if ((Get-Command 'Resolve-DnsName' -ErrorAction SilentlyContinue) -eq $false) {
        throw "Couldn't locate the Resolve-DnsName PowerShell cmdlet, could not proceed"
    }

    if ($PSVersionTable.PSVersion.Major -lt 3) {
        throw "PowerShell 3.0 is required due to this script's use of ordered psobjects"
    }

    function Check-MxRecord ([string]$DomainName) {
        if ([string]::IsNullOrEmpty($DomainName)) {
            throw "No domain name specified for MX record check"
        }

        Resolve-DnsName -Name $DomainName -Type MX -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }

    function Check-SpfRecord ([string]$DomainName) {
        if ([string]::IsNullOrEmpty($DomainName)) {
            throw "No domain name specified for SPF record check"
        }

        $resolved = Resolve-DnsName -Name $DomainName -Type TXT #-ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        $resolved | Where-Object {$_.Strings -like '*v=spf1*'}
    }

    function Get-SpfRecordText ([string]$DomainName) {
        if ([string]::IsNullOrEmpty($DomainName)) {
            throw "No domain name specified for SPF record check"
        }

        $resolved = Resolve-DnsName -Name $DomainName -Type TXT #-ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        ($resolved | Where-Object {$_.Strings -like '*v=spf1*'}) | Select-Object -ExpandProperty Strings
    }

    function Check-DmarcRecord ([string]$DomainName) {
        if ([string]::IsNullOrEmpty($DomainName)) {
            throw "No domain name specified for DMARC record check"
        }

        $resolved = Resolve-DnsName -Name "_dmarc.$($DomainName)" -Type TXT -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        $resolved | Where-Object {$_.Strings -like '*v=DMARC1*'}
    }

    function Get-DmarcRecordText ([string]$DomainName) {
        if ([string]::IsNullOrEmpty($DomainName)) {
            throw "No domain name specified for DMARC record check"
        }

        $resolved = Resolve-DnsName -Name "_dmarc.$($DomainName)" -Type TXT -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        $resolved | Where-Object {$_.Strings -like '*v=DMARC1*'} | Select-Object -ExpandProperty Strings
    }

    function Determine-ExchangeOnline ([string]$DomainName) {
       $isOffice365Tenant = "No"
    
        $msoidRecord = Resolve-DnsName "msoid.$($DomainName)" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object {$_.NameHost -like '*clientconfig.microsoftonline*'}
        if ($msoidRecord) {$isOffice365Tenant = 'Possibly'}

        $txtVerificationRecord = Resolve-DnsName $DomainName -Type TXT -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object {$_.Strings -like 'MS=ms*'}
        if ($txtVerificationRecord) {$isOffice365Tenant = 'Possibly'}

        $mdmRecord = Resolve-DnsName -Name "enterpriseregistration.$DomainName" -Type CNAME -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object {$_.NameHost -eq 'enterpriseregistration.windows.net '}
        if ($mdmRecord) {$isOffice365Tenant = 'Likely'}

        $autoDiscoverRecord = Resolve-DnsName -Name "autodiscover.$DomainName" -Type CNAME -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object {$_.NameHost -eq 'autodiscover.outlook.com'}
        if ($autoDiscoverRecord) {$isOffice365Tenant = 'Yes'}

        $mxRecords = Check-MxRecord $DomainName | Where-Object {$_.Name -like '*mail.protection.outlook.com*'}
        if ($mxRecords) {$isOffice365Tenant = 'Yes'}

        $spfRecords = Check-SpfRecord $DomainName | Where-Object {$_.Strings -like '*spf.protection.outlook.com*'}
        if ($spfRecords) {$isOffice365Tenant = 'Yes'}

        $isOffice365Tenant
    }

    function Determine-MXHandler ([string]$DomainName) {
        $mx = Resolve-DnsName $DomainName -Type MX -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 
        $lowestPreferenceMX = $mx | Sort-Object -Property Preference | Select-Object -First 1 -ExpandProperty NameExchange -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        switch -Wildcard ($lowestPreferenceMX) {
            'aspmx*google.com' { $determination = "Google" }
            'au*mimecast*' { $determination = "Mimecast AU" }
            'eu*mimecast*' { $determination = "Mimecast EU" }
            '*in.mailcontrol.com' { $determination = "Forcepoint (Formerly Websense)" }
            '*iphmx*' { $determination = "Cisco Email Security (Formerly IronPort Cloud)" }
            '*mail.protection.outlook.com*' { $determination = "Microsoft Exchange Online" }
            '*messagelabs*' { $determination = "Symantec.Cloud" }
            '*mailguard*' { $determination = "Mailguard (AU)" }
            '*mpmailmx*' { $determination = "Manage Protect (AU/NZ)" }
            '*trendmicro*' { $determination = "Trend Micro" }
            '*pphosted*' { $determination = "Proofpoint" }
            '*securence*' { $determination = "Securence" }
            "*$DomainName" { $determination = "Self-Hosted"}
            "" { $determination = "NO MX RECORD FOUND"}

            $null { $determination = "NO MX RECORD FOUND"}
            Default { $determination = "Other/Undetermined" }
        }

        $determination
    }

    function Check-DnsNameAdministrator ([string]$DomainName) {
        Resolve-DnsName -Type SOA -Name $DomainName | Select-Object -ExpandProperty NameAdministrator
    }

    function Check-DnsHostingProvider ([string]$DomainName) {
        (Resolve-DnsName $DomainName -Type NS | Where-Object {$_.NameHost -ne $null} | Select-Object -ExpandProperty NameHost) -join ','
    }

    function Determine-O365DomainGuid ([string]$DomainName) {
        $isOffice365Tenant = Determine-ExchangeOnline -DomainName $DomainName
   
        if ($isOffice365Tenant -eq 'No') {
            "N/A"
        } else {
            $nameExchange = Resolve-DnsName -Name $DomainName -Type MX -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object {$_.NameExchange -ne $null} | Select-Object -ExpandProperty NameExchange
            $isMxHandlingWithEOP = $nameExchange.Contains('mail.protection.outlook.com')

            if ($isMxHandlingWithEOP -eq $false) {
                "Undetermined"
            } else {
                $nameExchange.Replace('.mail.protection.outlook.com','')
            }
        }
    }

    function Determine-O365Dkim ([string]$DomainName) {
        $isOffice365Tenant = Determine-ExchangeOnline -DomainName $DomainName
   
        if ($isOffice365Tenant -eq 'No') {
            "N/A"
        } else {
            $selector1,$selector2 = 1..2 | ForEach-Object {Resolve-DnsName "selector$_._domainkey.$DomainName" -ErrorAction SilentlyContinue | Where-Object {$_.NameHost -ne $null} | Select-Object -ExpandProperty NameHost}

            if (($selector1 -ne $null) -and ($selector2 -ne $null)) {
                $True
            } else {
                "Undetermined"
            }
        }
    }

}

process {
    foreach ($domain in $EmailDomain) {
        
        New-Object psobject -Property ([ordered]@{
                                        'Domain' = $domain;
                                        'MX Handler' = (Determine-MXHandler $domain);
                                        'SPF Record Exists?'= ((Check-SpfRecord -DomainName $domain) -ne $null);
                                        'SPF Record'= (Get-SpfRecordText -DomainName $domain);
                                        'DMARC Record Exists?'= ((Check-DmarcRecord -DomainName $domain) -ne $null);
                                        'DMARC Record' = (Get-DmarcRecordText -DomainName $domain);
                                        'DNS Registrar' = (Check-DnsNameAdministrator -DomainName $domain);
                                        'DNS Host' = (Check-DnsHostingProvider -DomainName $domain);
                                        'Exchange Online?'= (Determine-ExchangeOnline -DomainName $domain);
                                        'O365 Tenant Guid' = (Determine-O365DomainGuid -DomainName $domain);
                                        'O365 DKIM Enabled?' = (Determine-O365Dkim -DomainName $domain);
                                        })
    }
}

end {}
