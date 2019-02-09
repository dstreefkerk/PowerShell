<#
.DESCRIPTION
	A quick and dirty script to be used to automate the collection of 
    publicly-available email-related records

    For example; MX, SPF, DMARC, HTA-STS records.

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

.EXAMPLE
	Import-Csv C:\temp\companies.csv | Select-Object -ExpandProperty Email_Domain | C:\Scripts\Invoke-EmailRecon.ps1 | Out-GridView

	Get a list of domains from a CSV file that contains a column named 'Email_Domain, run our process across each one of them, and output the results to a GridView GUI control

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
			- Initial Version, based on an old collection of stuff I've had lying around for ages

        1.0 09/02/2019
            - Refactored to cut down on the number of DNS queries the script has to make. 55% increase in speed.
            - Added checks for MTA-STS record
            - Added visibility around SPF and DKIM modes
			
	TODO:
		- Add code comments and verbose logging
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

    function Check-SpfRecordExists ([psobject]$DNSData) {
        $DNSData.TXT | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue
    }

    function Get-SpfRecordText ([psobject]$DNSData) {
        $DNSData.TXT | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Strings -ErrorAction SilentlyContinue
    }

    function Determine-SpfRecordMode ([psobject]$DNSData) {
        $record = $DNSData.TXT | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue

        if ($record) {
            $recordData = $record | Select-Object -First 1 -ExpandProperty Strings
            switch -Wildcard ($recordData) {
                '*-all' { $determination = "FAIL" }
                '*+all' { $determination = "PASS" }
                '*~all' { $determination = "SOFTFAIL" }
                '*`?all' { $determination = "NEUTRAL" }

                Default { $determination = "Other/Undetermined" }
            }

            return $determination
        } else {
            return "N/A"
        }
    }

    function Check-DmarcRecordExists ([psobject]$DNSData) {
        $DNSData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue
    }

    function Get-DmarcRecordText ([psobject]$DNSData) {
        $DNSData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue
    }

    function Determine-DmarcPolicy ([psobject]$dnsData) {
        $record = $DNSData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue

        if ($record -eq $null) { return "N/A" }

        $domainPolicy = $record.Split(';') | Where-Object {$_ -like "* p=*"}

        if ($domainPolicy) {
            $domainPolicy = $domainPolicy.Replace(' ','')
            $domainPolicy = $domainPolicy.Replace('p=','')
            $domainPolicy.ToUpper()
        }
    }

    function Determine-DmarcSubdomainPolicy ([psobject]$dnsData) {
        $record = $DNSData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue

        if ($record -eq $null) { return "N/A" }

        $subDomainPolicy = $record.Split(';') | Where-Object {$_ -like "*sp=*"}

        if ($subDomainPolicy) {
            $subDomainPolicy = $subDomainPolicy.Replace(' ','')
            $subDomainPolicy = $subDomainPolicy.Replace('sp=','')
            $subDomainPolicy.ToUpper()
        }
    }

    function Determine-ExchangeOnline ([psobject]$DNSData) {
        $isOffice365Tenant = "No"
    
        $msoidRecord = $DNSData.MSOID | Where-Object {$_.NameHost -like '*clientconfig.microsoftonline*'} -ErrorAction SilentlyContinue
        if ($msoidRecord) {$isOffice365Tenant = 'Possibly'}

        $txtVerificationRecord = $DNSData.TXT | Where-Object {$_.Strings -like 'MS=ms*'} -ErrorAction SilentlyContinue
        if ($txtVerificationRecord) {$isOffice365Tenant = 'Possibly'}

        $mdmRecord = $DNSData.ENTERPRISEREGISTRATION | Where-Object {$_.NameHost -eq 'enterpriseregistration.windows.net '} -ErrorAction SilentlyContinue
        if ($mdmRecord) {$isOffice365Tenant = 'Likely'}

        $autoDiscoverRecord = $DNSData.AUTODISCOVER | Where-Object {$_.NameHost -eq 'autodiscover.outlook.com'} -ErrorAction SilentlyContinue
        if ($autoDiscoverRecord) {$isOffice365Tenant = 'Yes'}

        $mxRecords = $DNSData.MX | Where-Object {$_.Name -like '*mail.protection.outlook.com*'} -ErrorAction SilentlyContinue
        if ($mxRecords) {$isOffice365Tenant = 'Yes'}

        $spfRecords = Check-SpfRecordExists $DNSData | Where-Object {$_.Strings -like '*spf.protection.outlook.com*'}
        if ($spfRecords) {$isOffice365Tenant = 'Yes'}

        $isOffice365Tenant
    }

    function Determine-MXHandler ([psobject]$DNSData) {
        if ($DNSData.MX -eq $null) { return }

        $lowestPreferenceMX = $DNSData.MX | Sort-Object -Property Preference | Select-Object -First 1 -ExpandProperty NameExchange -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

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
            "*$($DNSData.SOA.Name)" { $determination = "Self-Hosted"}
            "" { $determination = "NO MX RECORD FOUND"}

            $null { $determination = "NO MX RECORD FOUND"}
            Default { $determination = "Other/Undetermined" }
        }

        return $determination
    }

    function Check-DnsNameAdministrator ([psobject]$DNSData) {
        $DNSData.SOA | Select-Object -First 1 -ExpandProperty NameAdministrator -ErrorAction SilentlyContinue
    }

    function Check-DnsHostingProvider ([psobject]$DNSData) {
        if ($DNSData.NS) {
            $nameServerRecords = ($DNSData.NS | Where-Object {$_.NameHost -ne $null} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue)

            if ($nameServerRecords) { $nameServerRecords -join ',' }
        }
    }

    function Determine-O365DomainGuid ([psobject]$DNSData) {
        $isOffice365Tenant = Determine-ExchangeOnline -DNSData $DNSData
   
        if ($isOffice365Tenant -eq 'No') { return "N/A" }

        $lowestPreferenceMX = $DNSData.MX | Where-Object {$_.NameExchange -ne $null} -ErrorAction SilentlyContinue | Sort-Object -Property Preference | Select-Object -First 1 -ErrorAction SilentlyContinue
        $nameExchange = $lowestPreferenceMX | Select-Object -ExpandProperty NameExchange -ErrorAction SilentlyContinue
            
        if ($nameExchange -eq $null) { return "Undetermined" }

        if ($nameExchange.Contains('mail.protection.outlook.com')) {
            $record = $nameExchange | Where-Object {$_ -like '*.mail.protection.outlook.com'} | Select -First 1
            if ($record) { $record.Replace('.mail.protection.outlook.com','') }
        } else { return "Undetermined" }
    }

    function Determine-O365Dkim ([psobject]$DNSData) {
        $isOffice365Tenant = Determine-ExchangeOnline -DNSData $DNSData
   
        if ($isOffice365Tenant -eq 'No') { return "N/A" } 

        if (($DNSData.O365DKIM.SELECTOR1 -ne $null) -and ($DNSData.O365DKIM.SELECTOR2 -ne $null)) {
            $True
        } else {
            $false
        }

    }

    function Check-MtaStsRecordExists ([psobject]$dnsData) {
        $mtaRecord = $dnsData.MTASTS | Where-Object {$_.Strings -like "v=STSv1*"} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue

        ($mtaRecord -ne $null)
    }

}

process {
    foreach ($domain in $EmailDomain) {

        # Collect DNS Records
        $ErrorActionPreference = 'SilentlyContinue'

        $dnsData = [psobject]@{
            DMARC = Resolve-DnsName -Name "_dmarc.$($domain)" -Type TXT
            MX = Resolve-DnsName -Name $domain -Type MX
            MTASTS = Resolve-DnsName -Name "_mta-sts.$domain" -Type TXT
            MSOID = Resolve-DnsName "msoid.$($domain)"
            TXT = Resolve-DnsName $domain -Type TXT
            ENTERPRISEREGISTRATION = Resolve-DnsName -Name "enterpriseregistration.$domain" -Type CNAME
            AUTODISCOVER = Resolve-DnsName -Name "autodiscover.$domain" -Type CNAME
            SOA = Resolve-DnsName -Type SOA -Name $domain
            NS = Resolve-DnsName $domain -Type NS
            O365DKIM = [psobject]@{
                SELECTOR1 = Resolve-DnsName "selector1._domainkey.$domain" -Type CNAME
                SELECTOR2 = Resolve-DnsName "selector2._domainkey.$domain" -Type CNAME
            }
        }

        $ErrorActionPreference = 'Continue'
        # Finish collecting DNS records
        
        New-Object psobject -Property ([ordered]@{
                                        'Domain' = $domain;
                                        'MX Handler' = (Determine-MXHandler $dnsData);
                                        'SPF Record Exists?' = ((Check-SpfRecordExists $dnsData) -ne $null);
                                        'SPF Record' = (Get-SpfRecordText $dnsData);
                                        'SPF Mechanism (Mode)' = (Determine-SpfRecordMode $dnsData);
                                        'DMARC Record Exists?'= ((Check-DmarcRecordExists $dnsData) -ne $null);
                                        'DMARC Record' = (Get-DmarcRecordText $dnsData);
                                        'DMARC Domain Policy' = (Determine-DmarcPolicy $dnsData);
                                        'DMARC Subdomain Policy' = (Determine-DmarcSubdomainPolicy $dnsData);
                                        'DNS Registrar' = (Check-DnsNameAdministrator $dnsData);
                                        'DNS Host' = (Check-DnsHostingProvider $dnsData);
                                        'Exchange Online?'= (Determine-ExchangeOnline $dnsData);
                                        'O365 Tenant Guid' = (Determine-O365DomainGuid $dnsData);
                                        'O365 DKIM Enabled?' = (Determine-O365Dkim $dnsData);
                                        'MTA-STS Record Exists?' = (Check-MtaStsRecordExists $dnsData)
                                        })
    }
}

end {}
