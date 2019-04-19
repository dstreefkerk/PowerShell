<#
.DESCRIPTION
	A quick and dirty script to be used to automate the collection of 
    publicly-available email-related records

    For example; MX, SPF, DMARC, HTA-STS records.

    It'll also try to make a determination about who's handling mail flow, and whether the domain
    is hosted on Exchange Online (sometimes ExOnline tenants pass their mail through filtering
    services like ProofPoint, Mimecast, etc)

    If the domain is hosted on Exchange Online, it'll also check whether DKIM is configured,
    and determine whether the domain is federated or not.

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

        2.0 09/02/2019
            - Refactored to cut down on the number of DNS queries the script has to make. 55% increase in speed.
            - Added checks for MTA-STS record
            - Added visibility around SPF and DKIM modes

        2.1 14/02/2019
            - Added 'MX (Lowest Preference)' property
            - Added more MX Provider name resolutions. eg. Barracuda ESS, FirstWave
            - Added checks for O365/Azure AD federation, and 4 new related properties

        2.2 18/04/2019
            - Now checking commonly-used federation hostnames and returning federation metadata URL if found
            - Added more MX Provider name resolutions. eg. Sophos and some smaller Aussie mobs
			
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

    # Try resolving the domain name. If it fails, throw an error
    if ((Get-Command 'Resolve-DnsName' -ErrorAction SilentlyContinue) -eq $false) {
        throw "Couldn't locate the Resolve-DnsName PowerShell cmdlet, could not proceed"
    }

    # Check for the version of PowerShell, error if it's not 3.0 or above
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        throw "PowerShell 3.0 is required due to this script's use of ordered psobjects"
    }

    # Check if an SPF record exists
    function Check-SpfRecordExists ([psobject]$DomainData) {
        $record = $domainData.TXT | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue
        
        if (($record | Measure-Object).Count -gt 1) {
            return "ERROR: MULTIPLE SPF RECORDS"
        } else {
            ($record -ne $null)
        }
    }

    # Get the actual SPF record data
    function Get-SpfRecordText ([psobject]$DomainData) {
        $record = $domainData.TXT | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue

        if ($record -eq $null) { return }

        if (($record[0].Strings | Measure).Count -gt 1) {
            $record[0].Strings -join ''
        } else {
            $record[0].Strings[0]
        }
    }

    # Check if the domain is configured in O365, and whether it's
    # Managed = O365/Azure AD is handling authentication
    # Federated = ADFS or a third-party cloud IDP is handling authentication
    function Get-DomainFederationDataFromO365 ([string]$DomainName) {
        try {
            $uri = "https://login.microsoftonline.com/common/userrealm/?user=testuser@$DomainName&api-version=2.1&checkForMicrosoftAccount=true"

            Invoke-RestMethod -Uri $uri -ErrorAction Stop

        }
        catch {
            Write-Verbose "Couldn't retrieve federation data for domain: $DomainName"
        }
    }

    # Check which mode the SPF record advises remote email servers to use
    function Determine-SpfRecordMode ([psobject]$DomainData) {
        $record = Get-SpfRecordText $DomainData

        if ($record) {
            switch -Wildcard ($record) {
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

    # Check if the DMARC record exists
    function Check-DmarcRecordExists ([psobject]$DomainData) {
        $record = $DomainData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue

        ($record -ne $null)
    }

    # Get the DMARC record if it exists
    function Get-DmarcRecordText ([psobject]$DomainData) {
        $record = $DomainData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue

        if ($record -ne $null) {
            return $record
        } else {
                return "N/A"
        }
    }

    # Determine what the DMARC policy is for the domain
    function Determine-DmarcPolicy ([psobject]$DomainData) {
        $record = $DomainData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue

        if ($record -eq $null) { return "N/A" }

        $domainPolicy = $record.Split(';') | Where-Object {$_ -like "* p=*"}

        if ($domainPolicy) {
            $domainPolicy = $domainPolicy.Replace(' ','')
            $domainPolicy = $domainPolicy.Replace('p=','')
            $domainPolicy.ToUpper()
        }
    }

    # Determine what the DMARC policy is for subdomains
    function Determine-DmarcSubdomainPolicy ([psobject]$DomainData) {
        $record = $DomainData.DMARC | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue

        if ($record -eq $null) { return "N/A" }

        $subDomainPolicy = $record.Split(';') | Where-Object {$_ -like "*sp=*"}

        if ($subDomainPolicy) {
            $subDomainPolicy = $subDomainPolicy.Replace(' ','')
            $subDomainPolicy = $subDomainPolicy.Replace('sp=','')
            $subDomainPolicy.ToUpper()
        }
    }

    # Try and determine if this domain is using Exchange Online
    function Determine-ExchangeOnline ([psobject]$DomainData) {
        $isOffice365Tenant = "No"
    
        $msoidRecord = $DomainData.MSOID | Where-Object {$_.NameHost -like '*clientconfig.microsoftonline*'} -ErrorAction SilentlyContinue
        if ($msoidRecord) {$isOffice365Tenant = 'Possibly'}

        $txtVerificationRecord = $DomainData.TXT | Where-Object {$_.Strings -like 'MS=ms*'} -ErrorAction SilentlyContinue
        if ($txtVerificationRecord) {$isOffice365Tenant = 'Possibly'}

        $mdmRecord = $DomainData.ENTERPRISEREGISTRATION | Where-Object {$_.NameHost -eq 'enterpriseregistration.windows.net '} -ErrorAction SilentlyContinue
        if ($mdmRecord) {$isOffice365Tenant = 'Likely'}

        $autoDiscoverRecord = $DomainData.AUTODISCOVER | Where-Object {$_.NameHost -eq 'autodiscover.outlook.com'} -ErrorAction SilentlyContinue
        if ($autoDiscoverRecord) {$isOffice365Tenant = 'Yes'}

        $spfRecord = $DomainData.TXT | Where-Object {$_.Strings -like '*spf.protection.outlook.com*'} -ErrorAction SilentlyContinue
        if ($spfRecord) {$isOffice365Tenant = 'Yes'}

        $mxRecords = $DomainData.MX | Where-Object {$_.NameExchange -like '*mail.protection.outlook.com*'} -ErrorAction SilentlyContinue
        if ($mxRecords) {$isOffice365Tenant = 'Yes'}

        $isOffice365Tenant
    }

    # Determine who's handling inbound emails, based on the hostname in the lowest preference MX record
    function Determine-MXHandler ([psobject]$DomainData) {
        if ($DomainData.MX -eq $null) { return }

        $lowestPreferenceMX = $DomainData.MX | Sort-Object -Property Preference | Select-Object -First 1 -ExpandProperty NameExchange -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        switch -Wildcard ($lowestPreferenceMX) {
            'aspmx*google.com' { $determination = "Google" }
            'au*mimecast*' { $determination = "Mimecast (AU)" }
            '*barracudanetworks.com' { $determination = "Barracuda ESS" }
            '*fireeyecloud.com' { $determination = "FireEye Email Security Cloud" }
            '*eu-central*.sophos.com' { $determination = "Sophos (Germany)" }
            'eu*mimecast*' { $determination = "Mimecast (EU)" }
            '*eu-west*.sophos.com' { $determination = "Sophos (Ireland)" }
            '*.firstcloudsecurity.net' { $determination = "FirstWave (AU)" }
            '*firstwave.com.au' { $determination = "FirstWave (AU)"}
            '*in.mailcontrol.com' { $determination = "Forcepoint (Formerly Websense)" }
            '*iphmx*' { $determination = "Cisco Email Security (Formerly IronPort Cloud)" }
			'*.itoncloud.com' { $determination = "ITonCloud (AU)" }
            '*mail.protection.outlook.com*' { $determination = "Microsoft Exchange Online" }
            '*messagelabs*' { $determination = "Symantec.Cloud" }
            '*mailguard*' { $determination = "Mailguard (AU)" }
            '*mxthunder*' { $determination = "SpamHero" }
            '*mpmailmx*' { $determination = "Manage Protect (AU/NZ)" }
            '*nexon.com.au*' { $determination = "Nexon (AU MSP)" }
            '*trendmicro*' { $determination = "Trend Micro" }
	        'seg.trustwave.com' { $determination = "Trustwave Secure Email Gateway Cloud" }
            '*pphosted*' { $determination = "Proofpoint" }
            '*ppe-hosted*' { $determination = "Proofpoint" }
            '*.emailsrvr.com' { $determination = "RackSpace" }
            '*securence*' { $determination = "Securence" }
            '*us-west*.sophos.com' { $determination = "Sophos (US West)" }
            '*us-east*.sophos.com' { $determination = "Sophos (US East)" }
            "*$($domainData.SOA.Name)" { $determination = "Self-Hosted"}
            "" { $determination = "NO MX RECORD FOUND"}

            $null { $determination = "NO MX RECORD FOUND"}
            Default { $determination = "Other/Undetermined" }
        }

        return $determination
    }

    # Get the lowest preference MX record, the one most likely to be used
    function Get-LowestPreferenceMX ([psobject]$DomainData) {
        if ($DomainData.MX -eq $null) { return 'N/A' }

        $DomainData.MX | Sort-Object -Property Preference | Select-Object -First 1 -ExpandProperty NameExchange -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }

    # Check the Start of Authority (SOA) record for the domain
    function Check-DnsNameAdministrator ([psobject]$DomainData) {
        $DomainData.SOA | Select-Object -First 1 -ExpandProperty NameAdministrator -ErrorAction SilentlyContinue
    }

    # Check who's hosting DNS for the domain
    function Check-DnsHostingProvider ([psobject]$DomainData) {
        if ($DomainData.NS) {
            $nameServerRecords = ($DomainData.NS | Where-Object {$_.NameHost -ne $null} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue)

            if ($nameServerRecords) { $nameServerRecords -join ',' }
        }
    }

    function Determine-O365DomainGuid ([psobject]$DomainData) {
        $isOffice365Tenant = Determine-ExchangeOnline $DomainData
   
        if ($isOffice365Tenant -eq 'No') { return "N/A" }

        $lowestPreferenceMX = $DomainData.MX | Where-Object {$_.NameExchange -ne $null} -ErrorAction SilentlyContinue | Sort-Object -Property Preference | Select-Object -First 1 -ErrorAction SilentlyContinue
        $nameExchange = $lowestPreferenceMX | Select-Object -ExpandProperty NameExchange -ErrorAction SilentlyContinue
            
        if ($nameExchange -eq $null) { return "Undetermined" }

        if ($nameExchange.Contains('mail.protection.outlook.com')) {
            $record = $nameExchange | Where-Object {$_ -like '*.mail.protection.outlook.com'} | Select -First 1
            if ($record) { $record.Replace('.mail.protection.outlook.com','') }
        } else { return "Undetermined" }
    }

    # Determine if O365's DKIM setup is in place
    function Determine-O365Dkim ([psobject]$DomainData) {
        $isOffice365Tenant = Determine-ExchangeOnline $DomainData
   
        if ($isOffice365Tenant -eq 'No') { return "N/A" } 

        if (($DomainData.O365DKIM.SELECTOR1 -ne $null) -and ($DomainData.O365DKIM.SELECTOR2 -ne $null)) {
            $True
        } else {
            $false
        }
    }

    # Figure out which federation prodiver is in use for a domain
    function Determine-O365FederationProvider ([psobject]$DomainData) {
        # https://docs.microsoft.com/en-au/power-platform/admin/powerapps-gdpr-dsr-guide-systemlogs#determining-tenant-type

        # Check if we have any federation data for this domain
        if ($DomainData.FEDERATION -eq $null) { return }

        # Only federated domains return the AuthURL property
        if ($DomainData.FEDERATION.AuthURL -eq $null) { return "N/A" }

        Write-Verbose "Domain $($DomainData.SOA.Name) federation auth URL: $($DomainData.FEDERATION.AuthURL)"

        # Determine the auth URL hostname component. Not as elegant as a regex, but it works
        $authUrlHost = $DomainData.FEDERATION.AuthURL
        $authUrlHost = $authUrlHost.Replace('https://','') # Remove HTTPS:// from the URL
        $authUrlHost = $authUrlHost.Replace('http://','') # Remove HTTP:// from the URL, almmost 0% chance of this ever existing
        $authUrlHost = $authUrlHost.Split('/')[0] # Split the auth URL, and grab the first component, the hostname

        # Check URL hostnames and return a determination if they match
        switch -Wildcard ($authUrlHost) {
            '*.okta.com' { $determination = "Okta" }
            "*$($DomainData.SOA.Name)" { $determination = "Self-Hosted"}

            $null { $determination = "N/A"}
            Default { $determination = "Other/Undetermined" }
        }

        return $determination
    }

    # Check if the domain in question has federation enabled
    function Determine-O365IsFederated ([psobject]$DomainData) {

        # Check if we have any federation data for this domain
        if ($DomainData.FEDERATION -eq $null) { return "N/A" }

        if ($DomainData.FEDERATION.NameSpaceType -eq 'Federated') { 
            return $true 
        } else {
            return $false
        }
    }

    # Get the hostname of the federation server
    function Get-O365FederationHostname ([psobject]$DomainData) {
        if ((Determine-O365IsFederated $DomainData) -eq $false) {
            return 'N/A'
        } else {
            # Determine the auth URL hostname component. Not as elegant as a regex, but it works
            $authUrlHost = $DomainData.FEDERATION.AuthURL
            $authUrlHost = $authUrlHost.Replace('https://','') # Remove HTTPS:// from the URL
            $authUrlHost = $authUrlHost.Replace('http://','') # Remove HTTP:// from the URL, almmost 0% chance of this ever existing
            $authUrlHost = $authUrlHost.Split('/')[0] # Split the auth URL, and grab the first component, the hostname

            return $authUrlHost
        }
    }

    # Check if the Azure AD domain is un-managed. Eg. "Shadow IT" where a user has an identity automatically created for them in Azure AD based on their email domain.
    # An unmanaged directory is a directory that has no global administrator.
    # https://docs.microsoft.com/en-au/power-platform/admin/powerapps-gdpr-dsr-guide-systemlogs#determining-tenant-type
    # https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-self-service-signup#terms-and-definitions
    function Determine-AADIsUnmanaged ([psobject]$DomainData) {
        if ($DomainData.FEDERATION -eq $null) { return "N/A" }

        if ($DomainData.FEDERATION.IsViral -eq $null) { return $false }

        $DomainData.FEDERATION.IsViral
    }

    # Check for an MTA-STS record
    function Check-MtaStsRecordExists ([psobject]$DomainData) {
        $mtaRecord = $DomainData.MTASTS | Where-Object {$_.Strings -like "v=STSv1*"} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue

        ($mtaRecord -ne $null)
    }

    # Try and determine the federation hostname, and check that it responds with federation metadata
    function Determine-AdfsFederationMetadataUrl ([string]$DomainName) {
        $federationPrefixes = 'adfs','sso','sts','fs','auth','idf','fed'
        $fedHost = $null

        foreach ($prefix in $federationPrefixes) {
    
            # Build up our attempted federation hostname
            $tempURL = "{0}.{1}" -f $prefix,$DomainName

            # Try and resolve the hostname
            $resolved = Resolve-DnsName -Name $tempURL -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
            # If the hostname doesn't resolve, skip to the next one
            if ($resolved -eq $null) { continue }

            # Assuming the federation service is ADFS, build up a path to the metadata file
            $fedURL = "https://$tempURL/federationmetadata/2007-06/federationmetadata.xml" 
    
            # Try and retrieve the federation metadata XML file
            $xmlData = $null
            try {
                $xmlData = Invoke-RestMethod -Method Get -Uri $fedURL -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            catch {}

            # If we managed to retrieve the XML metadata file, return the FQDN of the ADFS server
            if (($xmlData -ne $null) -and ($xmlData.EntityDescriptor.entityID -ne $null)) {
                return $tempURL
            }
        }
    }
}

process {
    foreach ($domain in $EmailDomain) {
        if ([string]::IsNullOrEmpty($domain)) { continue }

        # Collect DNS Records
        $ErrorActionPreference = 'SilentlyContinue'

        $dataCollection = [psobject]@{
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
            FEDERATION = Get-DomainFederationDataFromO365 -DomainName $domain
        }

        $ErrorActionPreference = 'Continue'
        # Finish collecting DNS records
        
        New-Object psobject -Property ([ordered]@{
                                        'Domain' = $domain;
                                        'MX Provider' = (Determine-MXHandler $dataCollection);
                                        'MX (Lowest Preference)' = (Get-LowestPreferenceMX $dataCollection);
                                        'SPF Record Exists?' = (Check-SpfRecordExists $dataCollection);
                                        'SPF Record' = (Get-SpfRecordText $dataCollection);
                                        'SPF Mechanism (Mode)' = (Determine-SpfRecordMode $dataCollection);
                                        'DMARC Record Exists?'= (Check-DmarcRecordExists $dataCollection);
                                        'DMARC Record' = (Get-DmarcRecordText $dataCollection);
                                        'DMARC Domain Policy' = (Determine-DmarcPolicy $dataCollection);
                                        'DMARC Subdomain Policy' = (Determine-DmarcSubdomainPolicy $dataCollection);
                                        'O365 Exchange Online?'= (Determine-ExchangeOnline $dataCollection);
                                        'O365 Tenant GUID' = (Determine-O365DomainGuid $dataCollection);
                                        'O365 DKIM Enabled?' = (Determine-O365Dkim $dataCollection);
                                        'O365 Federated?' = (Determine-O365IsFederated $dataCollection);
                                        'O365 Federation Provider' = (Determine-O365FederationProvider $dataCollection);
                                        'O365 Federation Hostname' = (Get-O365FederationHostname $dataCollection);
                                        'O365/AzureAD is Unmanaged?' = (Determine-AADIsUnmanaged $dataCollection);
                                        'MTA-STS Record Exists?' = (Check-MtaStsRecordExists $dataCollection);
                                        'DNS Registrar' = (Check-DnsNameAdministrator $dataCollection);
                                        'DNS Host' = (Check-DnsHostingProvider $dataCollection);
                                        #'ADFS Host' = (Determine-AdfsFederationMetadataUrl $domain)
                                        })
    }
}

end {}
