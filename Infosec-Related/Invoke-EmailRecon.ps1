<#
.DESCRIPTION
	A quick and dirty script to be used to automate the collection of 
    publicly-available email-related records

    For example; MX, SPF, DMARC, MTA-STS records.

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

	REQUIREMENTS:
		- PowerShell 3.0, because we're using ordered PSObjects and the Resolve-DNSName cmdlet

	VERSION HISTORY:
		See https://github.com/dstreefkerk/PowerShell/commits/master/Infosec-Related/Invoke-EmailRecon.ps1

	TODO:
		- TBA
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

    # Check if a wildcard SPF record exists (one should)
    function Check-WildcardSpfRecordExists ([psobject]$DomainData) {
        $record = $domainData.WILDCARDTXT | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue
        
        if (($record | Measure-Object).Count -gt 1) {
            return "MULTIPLE SPF RECORDS"
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

    # Get the actual SPF record data out of the wildcard SPF record
    function Get-WildcardSpfRecordText ([psobject]$DomainData) {
        $record = $domainData.WILDCARDTXT | Where-Object {$_.Strings -like '*v=spf1*'} -ErrorAction SilentlyContinue

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

    # Check if the domain has an MTA-STS DNS record
    # and matching policy
    # If it does, capture the policy details into an object
    function Get-MTASTSDetails ([string]$DomainName) {
        $mtasts_dnsrecord = Resolve-DnsName -Name "_mta-sts.$DomainName" -Type TXT -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $mtasts_policy = $null

        # If we don't detect an MTA-STS DNS record, return
        if ($mtasts_dnsrecord -eq $null) { return }

        # Try and retrieve the MTA-STS policy for the domain
        try {
            $uri = "https://mta-sts.$DomainName/.well-known/mta-sts.txt"

            $mtasts_policy = Invoke-WebRequest -Uri $uri -ErrorAction Stop | Select-Object -ExpandProperty Content

        }
        catch {
            Write-Verbose "Couldn't retrieve MTA-STS policy for domain: $DomainName"
        }

        # If we retrieved an MTA-STS policy, extract details from the plain-text file
        # into an object
        if ($mtasts_policy -ne $null) {

            New-Object psobject -Property ([ordered]@{
                                        'DNSRecord' = $mtasts_dnsrecord | Select-Object -ExpandProperty Strings
                                        'Version' = "$(($mtasts_policy | Select-String -Pattern "version:(.*)").Matches.Groups[1])" -replace ' ' # only STSv1 is valid, so this property isn't used elsewhere in the script yet
                                        'Mode' = ($mtasts_policy | Select-String -Pattern "mode:.*(enforce|testing|none)").Matches[0].Captures[0].Groups[1].Value.ToUpper()
                                        'AllowedMX' = (($mtasts_policy | Select-String -Pattern 'mx:(.*)' -AllMatches).Matches.Groups | ? {$_.Value -notlike "mx:*"} | select -ExpandProperty value) -replace " " -join ','
                                        })
        }
    }

    # Retrieve basic DNSSEC details. More advanced checks to come.
    function Get-DNSSECDetails ([string]$DomainName) {
        $dnskey_dnsrecord = Resolve-DnsName -Name $DomainName -Type DNSKEY -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object {$_.Type -eq 'DNSKEY'}
        $dnskey_exists = (($dnskey_dnsrecord | Measure-Object | Select-Object -ExpandProperty Count) -gt 0)

        # If we don't detect an MTA-STS DNS record, return
        if ($dnskey_dnsrecord -eq $null) { 
            Write-Verbose "Couldn't locate a DNSKEY record for domain: $DomainName"
            $dnskey_dnsrecord = "N/A"
        }
        
        New-Object psobject -Property ([ordered]@{
                                        'DNSKeyExists' = $dnskey_exists
                                        'DNSKEYRecord' = $dnskey_dnsrecord
                                        })
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

        $mdmRecord = $DomainData.ENTERPRISEREGISTRATION | Where-Object {$_.NameHost -eq 'enterpriseregistration.windows.net'} -ErrorAction SilentlyContinue
        if ($mdmRecord) {$isOffice365Tenant = 'Likely'}

        $autoDiscoverRecord = $DomainData.AUTODISCOVER | Where-Object {$_.NameHost -eq 'autodiscover.outlook.com'} -ErrorAction SilentlyContinue
        if ($autoDiscoverRecord) {$isOffice365Tenant = 'Yes'}

        $spfRecord = $DomainData.TXT | Where-Object {$_.Strings -like '*spf.protection.outlook.com*'} -ErrorAction SilentlyContinue
        if ($spfRecord) {$isOffice365Tenant = 'Yes'}

        $mxRecords = $DomainData.MX | Where-Object {($_.NameExchange -like '*mail.protection.outlook.com*') -or ($_.NameExchange -like '*eo.outlook.com')} -ErrorAction SilentlyContinue
        if ($mxRecords) {$isOffice365Tenant = 'Yes'}

        $isOffice365Tenant
    }

    # Try and figure out the Microsoft Online Email Routing Address (MOERA) domain (e.g. contoso.onmicrosoft.com)
    function Determine-M365MOERAName ([psobject]$DomainData) {

        # Get all *.onmicrosoft.com domains, excluding *.mail.onmicrosoft.com
        $onMicrosoftDomains = $DomainData.M365DOMAINS | Where-Object {
            ($_ -like "*.onmicrosoft.com") -and ($_ -notlike "*.mail.onmicrosoft.com")
        }

        # Initialize a list to store domains with their associated data
        $domainInfoList = @()

        foreach ($domain in $onMicrosoftDomains) {
            # Initialise a hashtable to store domain information
            $domainInfo = @{
                Domain = $domain
                HasMX = $false
                HasSPF = $false
                HasDMARC = $false
            }

            # Check for MX records
            $mxRecords = Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue
            if ($mxRecords) {
                $domainInfo.HasMX = $true
            }

            # Check for SPF records
            $txtRecords = Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue
            if ($txtRecords) {
                foreach ($record in $txtRecords) {
                    if ($record.Strings -match "v=spf1") {
                        $domainInfo.HasSPF = $true
                        break
                    }
                }
            }

            # Check for DMARC records
            $dmarcRecords = Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction SilentlyContinue
            if ($dmarcRecords) {
                foreach ($record in $dmarcRecords) {
                    if ($record.Strings -match "v=DMARC1") {
                        $domainInfo.HasDMARC = $true
                        break
                    }
                }
            }

            # Add the domain information to the list
            $domainInfoList += New-Object PSObject -Property $domainInfo
        }

        # Determine the MOERA domain based on the collected data
        # Prioritise domains with MX records, then SPF, then DMARC

        # Filter domains with MX records
        $domainsWithMX = $domainInfoList | Where-Object { $_.HasMX -eq $true }
        if ($domainsWithMX.Count -eq 1) {
            return $domainsWithMX[0].Domain
        } elseif ($domainsWithMX.Count -gt 1) {
            # If multiple domains have MX records, further filter based on SPF
            $domainsWithSPF = $domainsWithMX | Where-Object { $_.HasSPF -eq $true }
            if ($domainsWithSPF.Count -eq 1) {
                return $domainsWithSPF[0].Domain
            } elseif ($domainsWithSPF.Count -gt 1) {
                # If still multiple, check for DMARC
                $domainsWithDMARC = $domainsWithSPF | Where-Object { $_.HasDMARC -eq $true }
                if ($domainsWithDMARC.Count -ge 1) {
                    # Return all domains that match all criteria
                    return ($domainsWithDMARC | Select-Object -ExpandProperty Domain) -join ','
                } else {
                    # Return domains with MX and SPF
                    return ($domainsWithSPF | Select-Object -ExpandProperty Domain) -join ','
                }
            } else {
                # Return domains with MX only
                return ($domainsWithMX | Select-Object -ExpandProperty Domain) -join ','
            }
        } else {
            # If no domains have MX records, prioritise SPF records
            $domainsWithSPF = $domainInfoList | Where-Object { $_.HasSPF -eq $true }
            if ($domainsWithSPF.Count -eq 1) {
                return $domainsWithSPF[0].Domain
            } elseif ($domainsWithSPF.Count -gt 1) {
                # If multiple domains have SPF, check for DMARC
                $domainsWithDMARC = $domainsWithSPF | Where-Object { $_.HasDMARC -eq $true }
                if ($domainsWithDMARC.Count -ge 1) {
                    # Return domains with SPF and DMARC
                    return ($domainsWithDMARC | Select-Object -ExpandProperty Domain) -join ','
                } else {
                    # Return domains with SPF only
                    return ($domainsWithSPF | Select-Object -ExpandProperty Domain) -join ','
                }
            } else {
                # If no domains have MX or SPF, check for DMARC
                $domainsWithDMARC = $domainInfoList | Where-Object { $_.HasDMARC -eq $true }
                if ($domainsWithDMARC.Count -ge 1) {
                    return ($domainsWithDMARC | Select-Object -ExpandProperty Domain) -join ','
                } else {
                    # As a last resort, return all *.onmicrosoft.com domains
                    return $onMicrosoftDomains -join ','
                }
            }
        }
    }


    # Determine if DMARC is enabled for the MOERA domain
    function Determine-M365MOERADMARC ([psobject]$DomainData) {
        $MOERA = $DomainData.M365DOMAINS | Where-Object {$_ -like "*.onmicrosoft.com"}

        $MOERADomain = $MOERA | Select-Object -First 1

        if ($null -eq $MOERADomain) { return }

        $MOERATXTRecords = Resolve-DnsName -Name "_dmarc.$($MOERADomain)" -Type TXT -ErrorAction SilentlyContinue

        if ($null -eq $MOERATXTRecords) {
            return ""
        }

        $MOERATXTRecords | Where-Object {$_.Strings -like '*v=DMARC1*'} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings
    }

    # Determine who's handling inbound emails, based on the hostname in the lowest preference MX record
    function Determine-MXHandler ([psobject]$DomainData) {
        if ($DomainData.MX -eq $null) { return }

        $lowestPreferenceMX = $DomainData.MX | Sort-Object -Property Preference | Select-Object -First 1 -ExpandProperty NameExchange -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        switch -Wildcard ($lowestPreferenceMX) {
            'inbound-smtp.*.amazonaws.com' { $determination = "Amazon SES" }
            'aspmx*google.com' { $determination = "Google" }
            'au*mimecast*' { $determination = "Mimecast (AU)" }
            '*barracudanetworks.com' { $determination = "Barracuda ESS" }
            '*fireeyecloud.com' { $determination = "FireEye Email Security Cloud" }
            'de*mimecast*' { $determination = "Mimecast (DE)" }
            '*.eo.outlook.com' { $determination = "Microsoft Exchange Online" }
            '*eu-central*.sophos.com' { $determination = "Sophos (Germany)" }
            'eu*mimecast*' { $determination = "Mimecast (EU)" }
            '*eu-west*.sophos.com' { $determination = "Sophos (Ireland)" }
            '*.firstcloudsecurity.net' { $determination = "FirstWave (AU)" }
            '*firstwave.com.au' { $determination = "FirstWave (AU)"}
            '*in.mailcontrol.com' { $determination = "Forcepoint (Formerly Websense)" }
            '*iphmx*' { $determination = "Cisco Email Security (Formerly IronPort Cloud)" }
	    '*.itoncloud.com' { $determination = "ITonCloud (AU)" }
            'mx*.mailcluster.com.au' { $determination = "Digital Pacific (AU)" } # https://support.digitalpacific.com.au/en/knowledgebase/article/what-are-digital-pacifics-mx-records
            'mx.us.mailmarshal.cloud' { $determination = "Trustwave MailMarshal Cloud (US)" } # https://support.trustwave.com/MailMarshalCloud/kb/item.asp?id=21095&Keywords=#mx
            'mx.au.mailmarshal.cloud' { $determination = "Trustwave MailMarshal Cloud (AU)" } # https://support.trustwave.com/SEGCloud/kb/item.asp?id=21149#mx
            'mx.eu.mailmarshal.cloud' { $determination = "Trustwave MailMarshal Cloud (EU)" } # https://support.trustwave.com/SEGCloud/kb/item.asp?id=21148#mx
            '*mailguard*' { $determination = "Mailguard (AU)" }
            '*.mailgun.org' { $determination = "Mailgun" }
            '*.server-mail.com' { $determination = "Melbourne IT" }
            '*mail.protection.outlook.com*' { $determination = "Microsoft Exchange Online" }
            '*messagelabs*' { $determination = "Symantec.Cloud" }
            '*.msng.telstra.com.au' { $determination = "Telstra (AU)" }
            '*mxthunder*' { $determination = "SpamHero" }
            '*mpmailmx*' { $determination = "Manage Protect (AU/NZ)" }
            '*nexon.com.au*' { $determination = "Nexon (AU MSP)" }
            '*trendmicro*' { $determination = "Trend Micro" }
            '*.secureintellicentre.net.au' { $determination = "Macquarie Government (AU)" }
	    'seg.trustwave.com' { $determination = "Trustwave Secure Email Gateway Cloud" }
            '*.sendgrid.net' { $determination = "SendGrid" }
            '*.mtaroutes.com' { $determination = "Solarwinds Mail Assure" }
            '*.sge.net' { $determination = "Verizon Business (ex CyberTrust)" }
            '*.spamh.com' { $determination = "Greenview Data SpamStopsHere" }
            '*pphosted*' { $determination = "Proofpoint" }
            '*ppe-hosted*' { $determination = "Proofpoint" }
            '*.emailsrvr.com' { $determination = "RackSpace" }
            '*securence*' { $determination = "Securence" }
            'us*mimecast*' { $determination = "Mimecast (US)" }
            '*us-west*.sophos.com' { $determination = "Sophos (US West)" }
            '*us-east*.sophos.com' { $determination = "Sophos (US East)" }
	    '*.mx.microsoft' { $determination = "Microsoft Exchange Online" }
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

    function Determine-O365DomainTenantName ([psobject]$DomainData) {
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

    # Inspired by AADInternals
    function Get-M365Domains ([string]$DomainName){
        Process {
            # Autodiscover URL for Commercial/GCC environments
            $uri = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

            # Simplified SOAP request body
            $body = @"
<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/' 
                xmlns:a='http://www.w3.org/2005/08/addressing' 
                xmlns:autodiscover='http://schemas.microsoft.com/exchange/2010/Autodiscover'>
    <soap:Header>
    <a:Action soap:mustUnderstand='1'>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand='1'>$uri</a:To>
    <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    </soap:Header>
    <soap:Body>
    <autodiscover:GetFederationInformationRequestMessage>
        <autodiscover:Request>
        <autodiscover:Domain>$DomainName</autodiscover:Domain>
        </autodiscover:Request>
    </autodiscover:GetFederationInformationRequestMessage>
    </soap:Body>
</soap:Envelope>
"@

            # Headers for the SOAP request
            $headers = @{
                "Content-Type" = "text/xml; charset=utf-8"
                "SOAPAction"   = '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"'
            }

            # Send the request
            try {
                $response = Invoke-RestMethod -Method Post -Uri $uri -Body $body -Headers $headers -UseBasicParsing

                # Extract domain information
                $domains = $response.Envelope.Body.GetFederationInformationResponseMessage.Response.Domains.Domain
            
                # Ensure the original domain is included
                if ($Domain -notin $domains) {
                    $domains += $Domain
                }

                # Return sorted, comma-separated list of domains
                $domains | Sort-Object
            }
            catch {
                Write-Error "Failed to retrieve tenant domains: $_"
            }
        }
    }

    # Retrieve the Azure AD Directory ID from the Microsoft Identity Platform via OpenID Connect
    # Credit to these blog posts
        # https://blog.tyang.org/2018/01/07/getting-azure-ad-tenant-common-configuration-such-as-tenant-id-using-powershell/
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
    function Determine-O365DirectoryID ([string]$DomainName) {
        try {
            $uri = "https://login.windows.net/$DomainName/.well-known/openid-configuration"

            $openIDResponse = Invoke-RestMethod -Uri $uri -ErrorAction Stop

        }
        catch {
            Write-Verbose "Couldn't retrieve federation data for domain: $DomainName"
        }

        if ($openIDResponse.token_endpoint) {
            $openIDResponse.token_endpoint.split('/')[3]  
        }
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

        # Attempt to find the SOA domain record, skip the domain if we can't locate one DNS
        try {
            Resolve-DnsName -Name $domain -Type SOA -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Verbose "Failed to locate SOA record for $domain"
            continue
        }

        # Collect data
        $ErrorActionPreference = 'SilentlyContinue'

        $dataCollection = [psobject]@{
            DMARC = Resolve-DnsName -Name "_dmarc.$($domain)" -Type TXT
            MX = Resolve-DnsName -Name $domain -Type MX
            MTASTS = Get-MTASTSDetails -DomainName $domain
            MSOID = Resolve-DnsName "msoid.$($domain)"
            TXT = Resolve-DnsName $domain -Type TXT
            WILDCARDTXT = Resolve-DnsName "$([guid]::NewGuid().Guid.Replace('-','')).$domain" -Type TXT
            ENTERPRISEREGISTRATION = Resolve-DnsName -Name "enterpriseregistration.$domain" -Type CNAME
            AUTODISCOVER = Resolve-DnsName -Name "autodiscover.$domain" -Type CNAME
            SOA = Resolve-DnsName -Type SOA -Name $domain
            NS = Resolve-DnsName $domain -Type NS
            O365DKIM = [psobject]@{
                    SELECTOR1 = Resolve-DnsName "selector1._domainkey.$domain" -Type CNAME
                    SELECTOR2 = Resolve-DnsName "selector2._domainkey.$domain" -Type CNAME
                }
            FEDERATION = Get-DomainFederationDataFromO365 -DomainName $domain
            DNSSEC = Get-DNSSECDetails -DomainName $domain
            M365DOMAINS = Get-M365Domains -DomainName $domain
            #M365MOERADOMAIN = Determine-M365MOERAName
        }

        $ErrorActionPreference = 'Continue'
        # Finish collecting data

        # Analyse the collected data
        New-Object psobject -Property ([ordered]@{
                                        'Domain' = $domain;
                                        'MX Records Exist?' = $dataCollection.mx.NameExchange.Count -gt 0;
                                        'MX Provider' = (Determine-MXHandler $dataCollection);
                                        'MX (Lowest Preference)' = (Get-LowestPreferenceMX $dataCollection);
                                        'SPF Record Exists?' = (Check-SpfRecordExists $dataCollection);
                                        'SPF Record' = (Get-SpfRecordText $dataCollection);
                                        'SPF Mechanism (Mode)' = (Determine-SpfRecordMode $dataCollection);
                                        'Wildcard SPF Record Exists?' = (Check-WildcardSpfRecordExists $dataCollection);
                                        'Wildcard SPF Record' = (Get-WildcardSpfRecordText $dataCollection);
                                        'DMARC Record Exists?'= (Check-DmarcRecordExists $dataCollection);
                                        'DMARC Record' = (Get-DmarcRecordText $dataCollection);
                                        'DMARC Domain Policy (Mode)' = (Determine-DmarcPolicy $dataCollection);
                                        'DMARC Subdomain Policy (Mode)' = (Determine-DmarcSubdomainPolicy $dataCollection);
                                        'M365 Exchange Online?'= (Determine-ExchangeOnline $dataCollection);
                                        'M365 Tenant Name' = (Determine-O365DomainTenantName $dataCollection);
                                        'M365 MOERA Domain' = (Determine-M365MOERAName $dataCollection);
                                        'M365 MOERA Domain DMARC Record' = (Determine-M365MOERADMARC $dataCollection);
                                        'M365 Domains' = $dataCollection.M365DOMAINS -join ',';
                                        'M365 DKIM Enabled?' = (Determine-O365Dkim $dataCollection);
                                        'M365 Federated?' = (Determine-O365IsFederated $dataCollection);
                                        'M365 Federation Provider' = (Determine-O365FederationProvider $dataCollection);
                                        'M365 Federation Hostname' = (Get-O365FederationHostname $dataCollection);
                                        'M365 Federation Brand Name' = $dataCollection.FEDERATION.FederationBrandName;
                                        'M365/EntraID Directory ID' = (Determine-O365DirectoryID $domain);
                                        'M365/EntraID is Unmanaged?' = (Determine-AADIsUnmanaged $dataCollection);
                                        'MTA-STS Record Exists?' = $dataCollection.MTASTS.DNSRecord -like "v=STSv1*";
                                        'MTA-STS Policy Mode' = $dataCollection.MTASTS.Mode;
                                        'MTA-STS Allowed MX Hosts' = $dataCollection.MTASTS.AllowedMX;
                                        'DNS Registrar' = (Check-DnsNameAdministrator $dataCollection);
                                        'DNS Host' = (Check-DnsHostingProvider $dataCollection);
                                        'DNSSEC DNSKEY Record Exists?' = $dataCollection.DNSSEC.DNSKeyExists;
                                        })
    }
}

end {}
