<#
.SYNOPSIS
    Fingerprints email services authorised through Proofpoint Hosted SPF by querying their macro-based DNS infrastructure.

.DESCRIPTION
    This script identifies which third-party email services an organisation has authorised through their
    Proofpoint Hosted SPF implementation. It examines the macro-based SPF implementation that Proofpoint
    uses to bypass the traditional 10-lookup DNS limitation.

    The script supports two detection methods:

    1. SPF-Based Detection (Primary Method):
       Proofpoint Hosted SPF uses dynamic macro expansion with the format:
       v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all

       Where:
       - %{ir} = Reversed IP octets (1.2.3.4 becomes 4.3.2.1)
       - %{v} = IP version identifier ("in-addr" for IPv4, "ip6" for IPv6)
       - %{d} = Target domain

    2. Static IP-Based Detection:
       For services with documented IP ranges (e.g., Microsoft Dynamics 365 for Marketing Email),
       the script tests known IP addresses directly. Multiple IPs can be tested per service, with
       optimisation to skip additional IPs once authorisation is confirmed.

    The script queries Proofpoint's DNS infrastructure with these IP addresses to determine
    authorisation status based on response patterns:

    - Authorised: v=spf1 ip4:x.x.x.x -all (confirms specific IP is authorised)
    - Known but unauthorised: v=spf1 -all (Proofpoint recognises IP but not authorised)
    - Not configured: NXDOMAIN (IP range not in Proofpoint's configuration)

.PARAMETER Domain
    The domain name to fingerprint for authorised email services. Must be using Proofpoint Hosted SPF.

.PARAMETER IncludeUnauthorised
    Include unauthorised and not configured services in the output. By default, only authorised services are shown.

.EXAMPLE
    .\Invoke-ProofpointSPFFingerprint.ps1 -Domain "example.com"

    Fingerprints the email services authorised for example.com through Proofpoint Hosted SPF.
    Shows only authorised services.

.EXAMPLE
    .\Invoke-ProofpointSPFFingerprint.ps1 -Domain "contoso.com" -IncludeUnauthorised

    Returns all tested services including unauthorised and not configured ones.

.EXAMPLE
    .\Invoke-ProofpointSPFFingerprint.ps1 -Domain "contoso.com" | Where-Object {$_.IsAuthorised -eq $true}

    Returns only the authorised email services for contoso.com.

.EXAMPLE
    .\Invoke-ProofpointSPFFingerprint.ps1 -Domain "fabrikam.com" | Export-Csv -Path "C:\temp\spf-results.csv" -NoTypeInformation

    Exports the fingerprinting results to a CSV file.

.EXAMPLE
    $results = .\Invoke-ProofpointSPFFingerprint.ps1 -Domain "contoso.com"
    $results | Format-List *

    Stores results in a variable and displays all properties for each authorised service.
    By default, the script displays only Domain, ServiceName, TestIP, and IsAuthorised in table format.
    Use Format-List * (or fl *) to see all properties including QueryName, ResponseType, ResponseData, and AdditionalServices.

.INPUTS
    System.String

.OUTPUTS
    PSCustomObject

    Returns custom objects with the following properties:
    - Domain: The queried domain
    - ServiceName: Name of the email service provider
    - TestIP: IP address used for testing
    - QueryName: Full DNS query name used
    - IsAuthorised: Boolean indicating if service is authorised
    - ResponseType: Type of response (Authorised/NotAuthorised/NotConfigured/Error)
    - ResponseData: Raw DNS response data
    - AdditionalServices: Any additional services detected via exists mechanisms

.NOTES
    NAME:    Invoke-ProofpointSPFFingerprint.ps1
    AUTHOR:  Daniel Streefkerk
    VERSION: 1.0

    REQUIREMENTS:
        - PowerShell 5.1 or later
        - Network access to query DNS
        - Domain must be using Proofpoint Hosted SPF

    SECURITY IMPLICATIONS:
        Organisations using Proofpoint Hosted SPF should understand that authorised email
        services are enumerable through DNS queries. This is a functional trade-off of the
        macro-based implementation.

    USE CASES:
        - Security assessments during authorised engagements
        - Incident response investigations
        - Compliance auditing
        - OSINT reconnaissance

.LINK
    https://www.proofpoint.com/

.LINK
    https://www.rfc-editor.org/rfc/rfc7208.html
#>

#Requires -Version 5.1

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Domain name to fingerprint for Proofpoint Hosted SPF services")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')]
    [string]$Domain,

    [Parameter(Mandatory = $false,
        HelpMessage = "Include unauthorised and not configured services in output")]
    [switch]$IncludeUnauthorised
)

begin {
    Set-StrictMode -Version Latest

    #region Helper Functions

    <#
    .SYNOPSIS
        Reverses the octets of an IPv4 address for DNS PTR-style queries.
    #>
    function ConvertTo-ReversedIP {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
            [string]$IPAddress
        )

        $octets = $IPAddress.Split('.')
        [array]::Reverse($octets)
        return $octets -join '.'
    }

    <#
    .SYNOPSIS
        Resolves an SPF record and extracts the first IPv4 address.
        Recursively follows include: and redirect= directives until an IP or CIDR is found.
        Only follows includes/redirects that match the original service domain to avoid false positives.
    #>
    function Get-FirstIPFromSPF {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$SPFDomain,

            [Parameter(Mandatory = $false)]
            [int]$MaxDepth = 5,

            [Parameter(Mandatory = $false)]
            [int]$CurrentDepth = 0,

            [Parameter(Mandatory = $false)]
            [string]$OriginalDomain = $null
        )

        # On first call, store the original domain for comparison
        if ([string]::IsNullOrEmpty($OriginalDomain)) {
            $OriginalDomain = $SPFDomain
        }

        # Extract base domain (e.g., mailgun.org from _spf.mailgun.org)
        function Get-BaseDomain {
            param([string]$Domain)

            # Remove common SPF prefixes and get the last two parts (domain.tld)
            $parts = $Domain -replace '^(_spf\d*\.|_netblocks\.|spf\.|mail\.)' -split '\.'

            if ($parts.Count -ge 2) {
                return ($parts[-2..-1] -join '.')
            }
            return $Domain
        }

        # Prevent infinite recursion
        if ($CurrentDepth -ge $MaxDepth) {
            Write-Verbose "Maximum recursion depth ($MaxDepth) reached for: $SPFDomain"
            return $null
        }

        try {
            $spfRecord = Resolve-DnsName -Name $SPFDomain -Type TXT -ErrorAction Stop |
                Where-Object { $_.Strings -like 'v=spf1*' } |
                Select-Object -First 1

            if ($null -eq $spfRecord) {
                Write-Verbose "No SPF record found for: $SPFDomain"
                return $null
            }

            # Handle Strings property which can be a single string or array
            $spfText = if ($spfRecord.Strings -is [System.Array]) {
                $spfRecord.Strings -join ''
            }
            elseif ($spfRecord.Strings -is [string]) {
                $spfRecord.Strings
            }
            else {
                $spfRecord.Strings.ToString()
            }

            # Ensure we have a valid string
            if ([string]::IsNullOrWhiteSpace($spfText)) {
                Write-Verbose "Empty SPF record for: $SPFDomain"
                return $null
            }

            # Extract first IP4 address from SPF record (not CIDR)
            if ($spfText -match 'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!/\d)') {
                $extractedIP = $Matches[1]
                # Validate it's a proper IP
                if ($extractedIP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                    Write-Verbose "Extracted IP $extractedIP from SPF record: $SPFDomain"
                    return $extractedIP
                }
            }

            # If no direct IP, try to extract from first CIDR range
            if ($spfText -match 'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+') {
                # Return .1 address from the CIDR range
                $baseIP = $Matches[1]
                try {
                    $octets = $baseIP.Split('.')
                    if ($octets.Count -eq 4) {
                        # Use .1 address from the range
                        $octets[3] = '1'
                        $generatedIP = $octets -join '.'
                        # Validate the generated IP
                        if ($generatedIP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                            Write-Verbose "Generated IP $generatedIP from CIDR in SPF record: $SPFDomain"
                            return $generatedIP
                        }
                    }
                }
                catch {
                    Write-Verbose "Failed to generate IP from CIDR for ${SPFDomain}: $($_.Exception.Message)"
                }
            }

            # No direct IP or CIDR found, try to follow include: directives
            if ($spfText -match 'include:([^\s]+)') {
                $includeDomain = $Matches[1]

                # Only follow includes that belong to the same service domain
                $includeBaseDomain = Get-BaseDomain -Domain $includeDomain
                $originalBaseDomain = Get-BaseDomain -Domain $OriginalDomain

                if ($includeBaseDomain -eq $originalBaseDomain) {
                    Write-Verbose "No direct IP in $SPFDomain, following include: $includeDomain (matches $originalBaseDomain, depth: $($CurrentDepth + 1))"
                    return Get-FirstIPFromSPF -SPFDomain $includeDomain -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -OriginalDomain $OriginalDomain
                }
                else {
                    Write-Verbose "Skipping include to different service: $includeDomain (base: $includeBaseDomain) does not match original service $OriginalDomain (base: $originalBaseDomain)"
                    return $null
                }
            }

            # Try redirect= modifier
            if ($spfText -match 'redirect=([^\s]+)') {
                $redirectDomain = $Matches[1]

                # Only follow redirects that belong to the same service domain
                $redirectBaseDomain = Get-BaseDomain -Domain $redirectDomain
                $originalBaseDomain = Get-BaseDomain -Domain $OriginalDomain

                if ($redirectBaseDomain -eq $originalBaseDomain) {
                    Write-Verbose "No direct IP in $SPFDomain, following redirect: $redirectDomain (matches $originalBaseDomain, depth: $($CurrentDepth + 1))"
                    return Get-FirstIPFromSPF -SPFDomain $redirectDomain -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -OriginalDomain $OriginalDomain
                }
                else {
                    Write-Verbose "Skipping redirect to different service: $redirectDomain (base: $redirectBaseDomain) does not match original service $OriginalDomain (base: $originalBaseDomain)"
                    return $null
                }
            }

            Write-Verbose "No IPv4 address found in SPF record for: $SPFDomain"
            return $null
        }
        catch {
            Write-Verbose "Failed to resolve SPF record for ${SPFDomain}: $($_.Exception.Message)"
            return $null
        }
    }

    <#
    .SYNOPSIS
        Tests if a domain is using Proofpoint Hosted SPF.
    #>
    function Test-ProofpointHostedSPF {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$DomainName
        )

        try {
            $spfRecord = Resolve-DnsName -Name $DomainName -Type TXT -ErrorAction Stop |
                Where-Object { $_.Strings -like '*v=spf1*' } |
                Select-Object -First 1

            if ($null -eq $spfRecord) {
                Write-Warning "No SPF record found for domain: $DomainName"
                return $false
            }

            $spfText = if ($spfRecord.Strings.Count -gt 1) {
                $spfRecord.Strings -join ''
            } else {
                $spfRecord.Strings[0]
            }

            if ($spfText -like '*spf.has.pphosted.com*') {
                Write-Verbose "Confirmed Proofpoint Hosted SPF for domain: $DomainName"
                return $true
            } else {
                Write-Warning "Domain $DomainName does not appear to be using Proofpoint Hosted SPF"
                return $false
            }
        }
        catch {
            Write-Error "Failed to query SPF record for domain ${DomainName}: $($_.Exception.Message)"
            return $false
        }
    }

    <#
    .SYNOPSIS
        Queries Proofpoint Hosted SPF DNS for a specific service IP.
    #>
    function Test-ProofpointServiceAuthorisation {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$DomainName,

            [Parameter(Mandatory = $true)]
            [string]$ServiceName,

            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [string]$TestIP
        )

        if ([string]::IsNullOrEmpty($TestIP)) {
            Write-Verbose "$ServiceName : NO IP ADDRESS AVAILABLE"
            return [PSCustomObject]@{
                PSTypeName         = 'ProofpointSPF.Result'
                Domain             = $DomainName
                ServiceName        = $ServiceName
                TestIP             = 'N/A'
                QueryName          = 'N/A'
                IsAuthorised       = $false
                ResponseType       = 'NoIPAvailable'
                ResponseData       = 'Could not resolve SPF record to get test IP'
                AdditionalServices = $null
            }
        }

        # Validate IP format before attempting to reverse it
        if ($TestIP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            Write-Verbose "$ServiceName : INVALID IP FORMAT ($TestIP)"
            return [PSCustomObject]@{
                PSTypeName         = 'ProofpointSPF.Result'
                Domain             = $DomainName
                ServiceName        = $ServiceName
                TestIP             = $TestIP
                QueryName          = 'N/A'
                IsAuthorised       = $false
                ResponseType       = 'InvalidIPFormat'
                ResponseData       = "Invalid IP address format: $TestIP"
                AdditionalServices = $null
            }
        }

        try {
            $reversedIP = ConvertTo-ReversedIP -IPAddress $TestIP
            $queryName = "${reversedIP}.in-addr.${DomainName}.spf.has.pphosted.com"
        }
        catch {
            Write-Verbose "$ServiceName : ERROR REVERSING IP ($TestIP): $($_.Exception.Message)"
            return [PSCustomObject]@{
                PSTypeName         = 'ProofpointSPF.Result'
                Domain             = $DomainName
                ServiceName        = $ServiceName
                TestIP             = $TestIP
                QueryName          = 'N/A'
                IsAuthorised       = $false
                ResponseType       = 'Error'
                ResponseData       = "Failed to reverse IP: $($_.Exception.Message)"
                AdditionalServices = $null
            }
        }

        Write-Verbose "Testing $ServiceName with IP $TestIP (Query: $queryName)"

        try {
            $result = Resolve-DnsName -Name $queryName -Type TXT -ErrorAction Stop

            # Properly handle Strings property which can be a single string or array
            $responseText = if ($result.Strings -is [System.Array]) {
                $result.Strings -join ''
            }
            elseif ($result.Strings -is [string]) {
                $result.Strings
            }
            else {
                $result.Strings.ToString()
            }

            if ($responseText -match "ip4:|ip6:") {
                Write-Verbose "$ServiceName : AUTHORISED"

                # Check for additional service integrations via exists mechanisms
                $additionalServices = @()
                if ($responseText -match 'exists:') {
                    $existsMatches = [regex]::Matches($responseText, 'exists:%\{i\}\.([^\s]+)')
                    foreach ($match in $existsMatches) {
                        $additionalServices += $match.Groups[1].Value
                    }
                }

                return [PSCustomObject]@{
                    PSTypeName         = 'ProofpointSPF.Result'
                    Domain             = $DomainName
                    ServiceName        = $ServiceName
                    TestIP             = $TestIP
                    QueryName          = $queryName
                    IsAuthorised       = $true
                    ResponseType       = 'Authorised'
                    ResponseData       = $responseText
                    AdditionalServices = if ($additionalServices.Count -gt 0) { $additionalServices -join ', ' } else { $null }
                }
            }
            elseif ($responseText -match "v=spf1 -all") {
                Write-Verbose "$ServiceName : NOT AUTHORISED (Known service)"

                return [PSCustomObject]@{
                    PSTypeName         = 'ProofpointSPF.Result'
                    Domain             = $DomainName
                    ServiceName        = $ServiceName
                    TestIP             = $TestIP
                    QueryName          = $queryName
                    IsAuthorised       = $false
                    ResponseType       = 'NotAuthorised'
                    ResponseData       = $responseText
                    AdditionalServices = $null
                }
            }
            else {
                Write-Verbose "$ServiceName : UNKNOWN RESPONSE - Received: '$responseText'"

                return [PSCustomObject]@{
                    PSTypeName         = 'ProofpointSPF.Result'
                    Domain             = $DomainName
                    ServiceName        = $ServiceName
                    TestIP             = $TestIP
                    QueryName          = $queryName
                    IsAuthorised       = $false
                    ResponseType       = 'Unknown'
                    ResponseData       = $responseText
                    AdditionalServices = $null
                }
            }
        }
        catch {
            if ($_.Exception.Message -like '*NXDOMAIN*') {
                Write-Verbose "$ServiceName : NOT CONFIGURED"

                return [PSCustomObject]@{
                    PSTypeName         = 'ProofpointSPF.Result'
                    Domain             = $DomainName
                    ServiceName        = $ServiceName
                    TestIP             = $TestIP
                    QueryName          = $queryName
                    IsAuthorised       = $false
                    ResponseType       = 'NotConfigured'
                    ResponseData       = 'NXDOMAIN'
                    AdditionalServices = $null
                }
            }
            else {
                Write-Error "Error querying $ServiceName : $($_.Exception.Message)"

                return [PSCustomObject]@{
                    PSTypeName         = 'ProofpointSPF.Result'
                    Domain             = $DomainName
                    ServiceName        = $ServiceName
                    TestIP             = $TestIP
                    QueryName          = $queryName
                    IsAuthorised       = $false
                    ResponseType       = 'Error'
                    ResponseData       = $_.Exception.Message
                    AdditionalServices = $null
                }
            }
        }
    }

    #endregion

    #region Service Provider SPF Domain Mappings

    # Comprehensive mapping of email service providers to their SPF domains
    # This list includes 400+ services from various categories
    # SPF records will be resolved dynamically at runtime to get test IPs
    $script:serviceProviders = @(
        @{ Name = 'Amazon SES'; SPFDomain = 'amazonses.com' }
        @{ Name = 'Twilio SendGrid'; SPFDomain = 'sendgrid.net' }
        @{ Name = 'MailChimp Campaigns'; SPFDomain = 'servers.mcsv.net' }
        @{ Name = 'MailChimp Mandrill'; SPFDomain = 'spf.mandrillapp.com' }
        @{ Name = 'Postmark'; SPFDomain = 'spf.mtasv.net' }
        @{ Name = 'Mailgun'; SPFDomain = 'mailgun.org' }
        @{ Name = 'SparkPost'; SPFDomain = '_netblocks.sparkpostmail.com' }
        @{ Name = 'Brevo (Sendinblue)'; SPFDomain = 'spf.brevo.com' }
        @{ Name = 'Campaign Monitor'; SPFDomain = '_spf.createsend.com' }
        @{ Name = 'Constant Contact'; SPFDomain = 'spf.constantcontact.com' }
        @{ Name = 'Adobe Marketo'; SPFDomain = 'mktomail.com' }
        @{ Name = 'Salesforce Marketing Cloud'; SPFDomain = 'cust-spf.exacttarget.com' }
        @{ Name = 'Salesforce Pardot'; SPFDomain = '_spf.salesforce.com' }
        @{ Name = 'Mailjet'; SPFDomain = 'spf.mailjet.com' }
        @{ Name = 'MailerLite'; SPFDomain = '_spf.mlsend.com' }
        @{ Name = 'HubSpot'; SPFDomain = 'hubspotemail.net' }
        @{ Name = 'Klaviyo'; SPFDomain = 'klaviyo.com' }
        @{ Name = 'Zoho Campaigns'; SPFDomain = 'zcsend.net' }
        @{ Name = 'MailChannels'; SPFDomain = 'relay.mailchannels.net' }
        @{ Name = 'MailerSend'; SPFDomain = '_spf.mailersend.net' }
        @{ Name = 'SMTP2GO'; SPFDomain = 'spf.smtp2go.com' }
        @{ Name = 'SendPulse'; SPFDomain = 'mxsspf.sendpulse.com' }
        @{ Name = 'Elastic Email'; SPFDomain = '_spf.elasticemail.com' }
        @{ Name = 'AWeber'; SPFDomain = 'send.aweber.com' }
        @{ Name = 'Customer.io'; SPFDomain = 'customeriomail.com' }
        @{ Name = 'Microsoft 365'; SPFDomain = 'spf.protection.outlook.com' }
        @{ Name = 'Google Workspace'; SPFDomain = '_spf.google.com' }
        @{ Name = 'Zendesk'; SPFDomain = 'mail.zendesk.com' }
        @{ Name = 'Mimecast'; SPFDomain = '_netblocks.mimecast.com' }
        @{ Name = 'Proofpoint Essentials'; SPFDomain = 'pphosted.com' }
        @{ Name = 'Barracuda ESS'; SPFDomain = 'barracudanetworks.com' }
        @{ Name = 'Cisco Email Security'; SPFDomain = 'iphmx.com' }
        @{ Name = 'Trend Micro Email Security'; SPFDomain = 'trendmicro.com' }
        @{ Name = 'Sophos Email'; SPFDomain = 'sophos.com' }
        @{ Name = 'Symantec MessageLabs'; SPFDomain = 'messagelabs.com' }
        @{ Name = 'FireEye Email Security Cloud'; SPFDomain = '_spf.fireeyecloud.com' }
        @{ Name = 'Forcepoint Email Security'; SPFDomain = 'mailcontrol.com' }
        @{ Name = 'Trustwave MailMarshal Cloud (US)'; SPFDomain = 'spf.us.mailmarshal.cloud' }
        @{ Name = 'Trustwave MailMarshal Cloud (EU)'; SPFDomain = 'spf.eu.mailmarshal.cloud' }
        @{ Name = 'Trustwave MailMarshal Cloud (AU)'; SPFDomain = 'spf.au.mailmarshal.cloud' }
        @{ Name = 'FirstWave Cloud Security (AU)'; SPFDomain = 'spf.firstwave.com.au' }
        @{ Name = 'SpamHero'; SPFDomain = 'spf.spamhero.com' }
        @{ Name = 'Securence'; SPFDomain = 'spf.securence.com' }
        @{ Name = 'SolarWinds Mail Assure'; SPFDomain = 'spf.mtaroutes.com' }
        @{ Name = 'SpamExperts'; SPFDomain = 'spamexperts.com' }
        @{ Name = 'SpamTitan'; SPFDomain = 'spamtitan.com' }
        @{ Name = 'MailGuard'; SPFDomain = 'mailguard.com.au' }
        @{ Name = 'GFI MailEssentials'; SPFDomain = 'gfi.com' }
        @{ Name = 'Freshdesk'; SPFDomain = 'freshdesk.com' }
        @{ Name = 'Intercom'; SPFDomain = 'intercom.io' }
        @{ Name = 'Help Scout'; SPFDomain = 'helpscoutemail.com' }
        @{ Name = 'Salesforce'; SPFDomain = '_spf.salesforce.com' }
        @{ Name = 'Shopify'; SPFDomain = 'shops.shopify.com' }
        @{ Name = 'WooCommerce'; SPFDomain = 'woocommerce.com' }
        @{ Name = 'BigCommerce'; SPFDomain = 'bigcommerce.com' }
        @{ Name = 'Zoho Mail'; SPFDomain = 'zoho.com' }
        @{ Name = 'Yahoo Mail'; SPFDomain = 'yahoo.com' }
        @{ Name = 'AOL Mail'; SPFDomain = 'aol.com' }
        @{ Name = 'Rackspace Email'; SPFDomain = 'emailsrvr.com' }
        @{ Name = 'Fastmail'; SPFDomain = 'spf.messagingengine.com' }
        @{ Name = 'ProtonMail'; SPFDomain = 'protonmail.ch' }
        @{ Name = 'Yandex Mail'; SPFDomain = 'yandex.ru' }
        @{ Name = 'ActiveCampaign'; SPFDomain = 'activecampaign.com' }
        @{ Name = 'GetResponse'; SPFDomain = 'getresponse.com' }
        @{ Name = 'Drip'; SPFDomain = 'spf.getdrip.com' }
        @{ Name = 'ConvertKit'; SPFDomain = 'spf.sparkpostmail.com' }
        @{ Name = 'Moosend'; SPFDomain = 'moosend.com' }
        @{ Name = 'Oracle Eloqua'; SPFDomain = 'eloqua.com' }
        @{ Name = 'Adobe Campaign'; SPFDomain = 'neolane.net' }
        @{ Name = 'SocketLabs'; SPFDomain = 'socketlabs.com' }
        @{ Name = 'Pepipost'; SPFDomain = 'pepipost.com' }
        @{ Name = 'iContact'; SPFDomain = 'icontact.com' }
        @{ Name = 'Emma'; SPFDomain = 'e2ma.net' }
        @{ Name = 'Mailstream'; SPFDomain = 'mailstream.io' }
        @{ Name = 'Act-On'; SPFDomain = 'actonsoftware.com' }
        @{ Name = 'Pardot by Salesforce'; SPFDomain = 'pardot.com' }
        @{ Name = 'Dotdigital'; SPFDomain = 'dotdigital.com' }
        @{ Name = 'Emarsys'; SPFDomain = 'emarsys.net' }
        @{ Name = 'Sailthru'; SPFDomain = 'sailthru.com' }
        @{ Name = 'Iterable'; SPFDomain = 'iterable.com' }
        @{ Name = 'Blueshift'; SPFDomain = 'blueshift.com' }
        @{ Name = 'Acoustic Campaign'; SPFDomain = 'acoustic.com' }
        @{ Name = 'Listrak'; SPFDomain = 'listrak.com' }
        @{ Name = 'Bloomreach'; SPFDomain = 'exponea.com' }
        @{ Name = 'MessageGears'; SPFDomain = 'messagegears.com' }
        @{ Name = 'Validity'; SPFDomain = 'validity.com' }
        @{ Name = 'Return Path'; SPFDomain = 'returnpath.net' }
        @{ Name = '250ok'; SPFDomain = '250ok.com' }
        @{ Name = 'Litmus'; SPFDomain = 'litmus.com' }
        @{ Name = 'Email on Acid'; SPFDomain = 'emailonacid.com' }
        @{ Name = 'Sinch Mailjet'; SPFDomain = 'spf.mailjet.com' }
        @{ Name = 'Sinch MessageMedia'; SPFDomain = 'messagemedia.com' }
        @{ Name = 'Vonage'; SPFDomain = 'nexmo.com' }
        @{ Name = 'Plivo'; SPFDomain = 'plivo.com' }
        @{ Name = 'Bandwidth'; SPFDomain = 'bandwidth.com' }
        @{ Name = 'Agile CRM'; SPFDomain = 'agilecrm.com' }
        @{ Name = 'Pipedrive'; SPFDomain = 'pipedrive.com' }
        @{ Name = 'Close CRM'; SPFDomain = 'close.com' }
        @{ Name = 'Copper CRM'; SPFDomain = 'coppercrm.com' }
        @{ Name = 'Nutshell CRM'; SPFDomain = 'nutshell.com' }
        @{ Name = 'Insightly'; SPFDomain = 'insightly.com' }
        @{ Name = 'Zoho CRM'; SPFDomain = 'zohocrm.com' }
        @{ Name = 'SAP CRM'; SPFDomain = 'sap.com' }
        @{ Name = 'SAP SuccessFactors'; SPFDomain = 'spf1.successfactors.com' }
        @{ Name = 'SwiftDigital'; SPFDomain = 'spf.swiftdigital.com.au' }
        @{ Name = 'Whispir'; SPFDomain = 'spf.whispir.com' }
        @{ Name = 'SugarCRM'; SPFDomain = 'sugarcrm.com' }
        @{ Name = 'Vtiger'; SPFDomain = 'vtiger.com' }
        @{ Name = 'Freshsales'; SPFDomain = 'freshsales.io' }
        @{ Name = 'Freshservice'; SPFDomain = 'freshservice.com' }
        @{ Name = 'Jira Service Desk'; SPFDomain = 'atlassian.net' }
        @{ Name = 'ServiceNow'; SPFDomain = 'service-now.com' }
        @{ Name = 'BMC Remedy'; SPFDomain = 'bmc.com' }
        @{ Name = 'Cherwell'; SPFDomain = 'cherwell.com' }
        @{ Name = 'Kayako'; SPFDomain = 'kayako.com' }
        @{ Name = 'LiveAgent'; SPFDomain = 'ladesk.com' }
        @{ Name = 'Gorgias'; SPFDomain = 'gorgias.com' }
        @{ Name = 'Kustomer'; SPFDomain = 'kustomer.com' }
        @{ Name = 'Front'; SPFDomain = 'frontapp.com' }
        @{ Name = 'Groove'; SPFDomain = 'groovehq.com' }
        @{ Name = 'HappyFox'; SPFDomain = 'happyfox.com' }
        @{ Name = 'Helprace'; SPFDomain = 'helprace.com' }
        @{ Name = 'Zoho Desk'; SPFDomain = 'zohodesk.com' }
        @{ Name = 'UserVoice'; SPFDomain = 'uservoice.com' }
        @{ Name = 'Canny'; SPFDomain = 'canny.io' }
        @{ Name = 'Productboard'; SPFDomain = 'productboard.com' }
        @{ Name = 'Aha!'; SPFDomain = 'aha.io' }
        @{ Name = 'Pendo'; SPFDomain = 'pendo.io' }
        @{ Name = 'Gainsight'; SPFDomain = 'gainsight.com' }
        @{ Name = 'ChurnZero'; SPFDomain = 'churnzero.net' }
        @{ Name = 'Totango'; SPFDomain = 'totango.com' }
        @{ Name = 'Planhat'; SPFDomain = 'planhat.com' }
        @{ Name = 'ClientSuccess'; SPFDomain = 'clientsuccess.com' }
        @{ Name = 'Vitally'; SPFDomain = 'vitally.io' }
        @{ Name = 'Calendly'; SPFDomain = 'calendly.com' }
        @{ Name = 'Acuity Scheduling'; SPFDomain = 'acuityscheduling.com' }
        @{ Name = 'Appointy'; SPFDomain = 'appointy.com' }
        @{ Name = 'SimplyBook.me'; SPFDomain = 'simplybook.me' }
        @{ Name = 'Setmore'; SPFDomain = 'setmore.com' }
        @{ Name = 'BookedIN'; SPFDomain = 'bookedin.com' }
        @{ Name = 'Typeform'; SPFDomain = 'typeform.com' }
        @{ Name = 'SurveyMonkey'; SPFDomain = 'surveymonkey.com' }
        @{ Name = 'Qualtrics'; SPFDomain = 'qualtrics.com' }
        @{ Name = 'JotForm'; SPFDomain = 'jotform.com' }
        @{ Name = 'Wufoo'; SPFDomain = 'wufoo.com' }
        @{ Name = 'Formstack'; SPFDomain = 'formstack.com' }
        @{ Name = 'FormAssembly'; SPFDomain = 'formassembly.com' }
        @{ Name = 'Cognito Forms'; SPFDomain = 'cognitoforms.com' }
        @{ Name = 'Gravity Forms'; SPFDomain = 'gravityforms.com' }
        @{ Name = 'WPForms'; SPFDomain = 'wpforms.com' }
        @{ Name = 'Ninja Forms'; SPFDomain = 'ninjaforms.com' }
        @{ Name = 'Formidable Forms'; SPFDomain = 'formidableforms.com' }
        @{ Name = 'Elementor Forms'; SPFDomain = 'elementor.com' }
        @{ Name = 'Contact Form 7'; SPFDomain = 'contactform7.com' }
        @{ Name = 'Unbounce'; SPFDomain = 'unbounce.com' }
        @{ Name = 'Instapage'; SPFDomain = 'instapage.com' }
        @{ Name = 'Leadpages'; SPFDomain = 'leadpages.net' }
        @{ Name = 'ClickFunnels'; SPFDomain = 'clickfunnels.com' }
        @{ Name = 'Kartra'; SPFDomain = 'kartra.com' }
        @{ Name = 'Kajabi'; SPFDomain = 'kajabi.com' }
        @{ Name = 'Thinkific'; SPFDomain = 'thinkific.com' }
        @{ Name = 'Teachable'; SPFDomain = 'teachable.com' }
        @{ Name = 'Podia'; SPFDomain = 'podia.com' }
        @{ Name = 'LearnWorlds'; SPFDomain = 'learnworlds.com' }
        @{ Name = 'Mighty Networks'; SPFDomain = 'mightynetworks.com' }
        @{ Name = 'Circle.so'; SPFDomain = 'circle.so' }
        @{ Name = 'Discourse'; SPFDomain = 'discourse.org' }
        @{ Name = 'Vanilla Forums'; SPFDomain = 'vanillaforums.com' }
        @{ Name = 'phpBB'; SPFDomain = 'phpbb.com' }
        @{ Name = 'vBulletin'; SPFDomain = 'vbulletin.com' }
        @{ Name = 'Xenforo'; SPFDomain = 'xenforo.com' }
        @{ Name = 'Invision Community'; SPFDomain = 'invisioncommunity.com' }
        @{ Name = 'bbPress'; SPFDomain = 'bbpress.org' }
        @{ Name = 'BuddyPress'; SPFDomain = 'buddypress.org' }
        @{ Name = 'Mailman'; SPFDomain = 'list.org' }
        @{ Name = 'Listserv'; SPFDomain = 'lsoft.com' }
        @{ Name = 'Yahoo Groups'; SPFDomain = 'yahoo.com' }
        @{ Name = 'Meetup'; SPFDomain = 'meetup.com' }
        @{ Name = 'Eventbrite'; SPFDomain = 'eventbrite.com' }
        @{ Name = 'Cvent'; SPFDomain = 'cvent.com' }
        @{ Name = 'Bizzabo'; SPFDomain = 'bizzabo.com' }
        @{ Name = 'Splash'; SPFDomain = 'splashthat.com' }
        @{ Name = 'Hopin'; SPFDomain = 'hopin.com' }
        @{ Name = 'Airmeet'; SPFDomain = 'airmeet.com' }
        @{ Name = 'Zoom'; SPFDomain = 'zoom.us' }
        @{ Name = 'Webex'; SPFDomain = 'webex.com' }
        @{ Name = 'GoToWebinar'; SPFDomain = 'goto.com' }
        @{ Name = 'GoToMeeting'; SPFDomain = 'goto.com' }
        @{ Name = 'Demio'; SPFDomain = 'demio.com' }
        @{ Name = 'Livestorm'; SPFDomain = 'livestorm.co' }
        @{ Name = 'Crowdcast'; SPFDomain = 'crowdcast.io' }
        @{ Name = 'StreamYard'; SPFDomain = 'streamyard.com' }
        @{ Name = 'Restream'; SPFDomain = 'restream.io' }
        @{ Name = 'Vimeo'; SPFDomain = 'vimeo.com' }
        @{ Name = 'YouTube'; SPFDomain = 'google.com' }
        @{ Name = 'Wistia'; SPFDomain = 'wistia.com' }
        @{ Name = 'Vidyard'; SPFDomain = 'vidyard.com' }
        @{ Name = 'Loom'; SPFDomain = 'loom.com' }
        @{ Name = 'Soapbox'; SPFDomain = 'soapboxhq.com' }
        @{ Name = 'Drift'; SPFDomain = 'drift.com' }
        @{ Name = 'LiveChat'; SPFDomain = 'livechatinc.com' }
        @{ Name = 'Olark'; SPFDomain = 'olark.com' }
        @{ Name = 'Crisp'; SPFDomain = 'crisp.chat' }
        @{ Name = 'Tawk.to'; SPFDomain = 'tawk.to' }
        @{ Name = 'Tidio'; SPFDomain = 'tidio.co' }
        @{ Name = 'Smartsupp'; SPFDomain = 'smartsupp.com' }
        @{ Name = 'Pure Chat'; SPFDomain = 'purechat.com' }
        @{ Name = 'Acquire'; SPFDomain = 'acquire.io' }
        @{ Name = 'Comm100'; SPFDomain = 'comm100.com' }
        @{ Name = 'Freshchat'; SPFDomain = 'freshchat.com' }
        @{ Name = 'Salesforce Live Agent'; SPFDomain = '_spf.salesforce.com' }
        @{ Name = 'Oracle Service Cloud'; SPFDomain = 'rightnow.com' }
        @{ Name = 'Genesys Cloud'; SPFDomain = 'genesys.com' }
        @{ Name = 'Five9'; SPFDomain = 'five9.com' }
        @{ Name = 'Talkdesk'; SPFDomain = 'talkdesk.com' }
        @{ Name = 'RingCentral'; SPFDomain = 'ringcentral.com' }
        @{ Name = '8x8'; SPFDomain = '8x8.com' }
        @{ Name = 'Nextiva'; SPFDomain = 'nextiva.com' }
        @{ Name = 'Vonage Business'; SPFDomain = 'vonage.com' }
        @{ Name = 'Grasshopper'; SPFDomain = 'grasshopper.com' }
        @{ Name = 'Ooma'; SPFDomain = 'ooma.com' }
        @{ Name = 'Phone.com'; SPFDomain = 'phone.com' }
        @{ Name = 'Dialpad'; SPFDomain = 'dialpad.com' }
        @{ Name = 'CloudTalk'; SPFDomain = 'cloudtalk.io' }
        @{ Name = 'Air Call'; SPFDomain = 'aircall.io' }
        @{ Name = 'JustCall'; SPFDomain = 'justcall.io' }
        @{ Name = 'Kixie'; SPFDomain = 'kixie.com' }
        @{ Name = 'CallRail'; SPFDomain = 'callrail.com' }
        @{ Name = 'CallTrackingMetrics'; SPFDomain = 'calltrackingmetrics.com' }
        @{ Name = 'ResponseTap'; SPFDomain = 'responsetap.com' }
        @{ Name = 'Invoca'; SPFDomain = 'invoca.net' }
        @{ Name = 'DialogTech'; SPFDomain = 'dialogtech.com' }
        @{ Name = 'Marchex'; SPFDomain = 'marchex.com' }
        @{ Name = 'Convirza'; SPFDomain = 'convirza.com' }
        @{ Name = 'CallSource'; SPFDomain = 'callsource.com' }
        @{ Name = 'CallFire'; SPFDomain = 'callfire.com' }
        @{ Name = 'Stripo'; SPFDomain = 'stripo.email' }
        @{ Name = 'Bee Free'; SPFDomain = 'beefree.io' }
        @{ Name = 'Unlayer'; SPFDomain = 'unlayer.com' }
        @{ Name = 'Topol.io'; SPFDomain = 'topol.io' }
        @{ Name = 'Mail Designer 365'; SPFDomain = 'maildesigner365.com' }
        @{ Name = 'Postcards'; SPFDomain = 'designmodo.com' }
        @{ Name = 'MJML'; SPFDomain = 'mjml.io' }
        @{ Name = 'Foundation for Emails'; SPFDomain = 'get.foundation' }
        @{ Name = 'Cerberus'; SPFDomain = 'tedgoas.github.io' }
        @{ Name = 'Really Good Emails'; SPFDomain = 'reallygoodemails.com' }
        @{ Name = 'Email Monks'; SPFDomain = 'emailmonks.com' }
        @{ Name = 'Email Uplers'; SPFDomain = 'emailuplers.com' }
        @{ Name = 'PSD2HTML'; SPFDomain = 'psd2html.com' }
        @{ Name = 'Chamaileon'; SPFDomain = 'chamaileon.io' }
        @{ Name = 'Dyspatch'; SPFDomain = 'dyspatch.io' }
        @{ Name = 'Stensul'; SPFDomain = 'stensul.com' }
        @{ Name = 'Knak'; SPFDomain = 'knak.com' }
        @{ Name = 'BEE Pro'; SPFDomain = 'beefree.io' }
        @{ Name = 'EDMdesigner'; SPFDomain = 'edmdesigner.com' }
        @{ Name = 'Taxi for Email'; SPFDomain = 'taxiforemail.com' }
        @{ Name = 'Maizzle'; SPFDomain = 'maizzle.com' }
        @{ Name = 'Parcel'; SPFDomain = 'parcel.io' }
        @{ Name = 'Pine'; SPFDomain = 'thememountain.com' }
        @{ Name = 'Acorn'; SPFDomain = 'thememountain.com' }
        @{ Name = 'Retro'; SPFDomain = 'thememountain.com' }
        @{ Name = 'Oxygen'; SPFDomain = 'thememountain.com' }
        @{ Name = 'Sendy'; SPFDomain = 'sendy.co' }
        @{ Name = 'phpList'; SPFDomain = 'phplist.org' }
        @{ Name = 'Mautic'; SPFDomain = 'mautic.org' }
        @{ Name = 'ListMonk'; SPFDomain = 'listmonk.app' }
        @{ Name = 'Mailtrain'; SPFDomain = 'mailtrain.org' }
        @{ Name = 'Postal'; SPFDomain = 'postal.atech.media' }
        @{ Name = 'Mautic Cloud'; SPFDomain = 'mautic.net' }
        @{ Name = 'Acumbamail'; SPFDomain = 'acumbamail.com' }
        @{ Name = 'Newsletter2Go'; SPFDomain = 'newsletter2go.com' }
        @{ Name = 'rapidmail'; SPFDomain = 'rapidmail.de' }
        @{ Name = 'CleverReach'; SPFDomain = 'cleverreach.com' }
        @{ Name = 'Mailify'; SPFDomain = 'mailify.com' }
        @{ Name = 'SendinBlue SMTP'; SPFDomain = 'spf.brevo.com' }
        @{ Name = 'Pepipost SMTP'; SPFDomain = 'pepipost.com' }
        @{ Name = 'SocketLabs SMTP'; SPFDomain = 'socketlabs.com' }
        @{ Name = 'Sendinblue SMTP'; SPFDomain = 'spf.brevo.com' }
        @{ Name = 'Turbo SMTP'; SPFDomain = 'turbosmtp.com' }
        @{ Name = 'SMTP.com'; SPFDomain = 'smtp.com' }
        @{ Name = 'AuthSMTP'; SPFDomain = 'authsmtp.com' }
        @{ Name = 'JangoSMTP'; SPFDomain = 'jangosmtp.com' }
        @{ Name = 'Dyn Email'; SPFDomain = 'emailsrvr.com' }
        @{ Name = 'SendLayer'; SPFDomain = 'sendlayer.com' }
        @{ Name = 'SMTP Bucket'; SPFDomain = 'smtpbucket.com' }
        @{ Name = 'Mailtrap'; SPFDomain = 'mailtrap.io' }
        @{ Name = 'MailSlurp'; SPFDomain = 'mailslurp.com' }
    )

    #endregion

    #region Static IP Provider Mappings

    # Services with known static IP ranges (not relying on SPF resolution)
    # These providers have documented IP ranges that we test directly
    # Multiple IPs can be provided - the first authorised IP will skip testing the rest
    $script:staticIPProviders = @(
        @{
            Name    = 'Microsoft Dynamics 365 for Marketing Email'
            TestIPs = @(
                '13.66.138.129'   # Primary test IP from 13.66.138.128/25 (US West)
                '40.78.242.1'     # Fallback test IP from 40.78.242.0/25 (US East)
            )
            # Full IP ranges from Azure Dynamics365ForMarketingEmail service tag:
            # 13.66.138.128/25, 13.69.226.128/25, 13.71.171.0/24, 13.74.106.128/25,
            # 13.75.35.0/24, 13.77.51.0/24, 13.78.107.0/24, 40.78.242.0/25,
            # 40.79.138.192/26, 40.120.64.224/27, 48.211.37.0/26, 51.107.129.64/27,
            # 51.140.147.0/24, 65.52.252.128/27, 102.133.251.96/27, 104.211.80.0/24,
            # 191.233.202.0/24
        }
    )

    #endregion
}

process {
    Write-Verbose "Starting fingerprint scan for domain: $Domain"

    # Validate domain is using Proofpoint Hosted SPF FIRST (before resolving 316+ SPF records)
    if (-not (Test-ProofpointHostedSPF -DomainName $Domain)) {
        $errorMessage = "Domain $Domain does not use Proofpoint Hosted SPF. Cannot perform fingerprinting."
        Write-Error -Message $errorMessage -Category InvalidArgument -ErrorAction Stop
        return
    }

    # Domain is valid - now resolve SPF records for all service providers
    Write-Verbose "Initialising fingerprint scan with $($script:serviceProviders.Count) SPF-based email service providers"
    Write-Verbose "Loaded $($script:staticIPProviders.Count) static IP-based email service providers"
    Write-Verbose "Resolving SPF records to obtain test IP addresses"

    # Resolve SPF records and get test IPs
    $script:emailServices = @()
    $resolvedCount = 0
    $totalServices = $script:serviceProviders.Count

    foreach ($provider in $script:serviceProviders) {
        $resolvedCount++
        Write-Progress -Activity "Resolving SPF Records" -Status "Processing $($provider.Name) ($resolvedCount of $totalServices)" -PercentComplete (($resolvedCount / $totalServices) * 100)

        $testIP = Get-FirstIPFromSPF -SPFDomain $provider.SPFDomain

        $script:emailServices += [PSCustomObject]@{
            Name      = $provider.Name
            SPFDomain = $provider.SPFDomain
            TestIP    = $testIP
            TestIPs   = $null  # SPF-based providers use single TestIP, not TestIPs array
        }
    }

    Write-Progress -Activity "Resolving SPF Records" -Completed
    $successfullyResolved = @($script:emailServices | Where-Object { $null -ne $_.TestIP }).Count
    Write-Verbose "Successfully resolved $successfullyResolved of $totalServices SPF records"

    # Process static IP providers
    Write-Verbose "Processing static IP-based providers"
    $staticIPCount = 0
    $totalStaticIP = $script:staticIPProviders.Count

    foreach ($provider in $script:staticIPProviders) {
        $staticIPCount++
        Write-Progress -Activity "Processing Static IP Providers" -Status "Processing $($provider.Name) ($staticIPCount of $totalStaticIP)" -PercentComplete (($staticIPCount / $totalStaticIP) * 100)

        $script:emailServices += [PSCustomObject]@{
            Name      = $provider.Name
            SPFDomain = $null
            TestIP    = $null
            TestIPs   = $provider.TestIPs  # Multiple IPs to test
        }
    }

    Write-Progress -Activity "Processing Static IP Providers" -Completed
    Write-Verbose "Loaded $($script:emailServices.Count) total email service providers for testing ($successfullyResolved SPF-based, $totalStaticIP static IP-based)"

    Write-Verbose "Fingerprinting $Domain for authorised email services"
    Write-Verbose "Testing $($script:emailServices.Count) services"

    $testedCount = 0
    $totalToTest = $script:emailServices.Count

    # Test each service
    foreach ($service in $script:emailServices) {
        $testedCount++
        Write-Progress -Activity "Testing Services" -Status "Testing $($service.Name) ($testedCount of $totalToTest)" -PercentComplete (($testedCount / $totalToTest) * 100)

        try {
            # Check if this is a static IP provider with multiple IPs to test
            if ($null -ne $service.TestIPs -and $service.TestIPs.Count -gt 0) {
                # Static IP provider - test multiple IPs with optimization
                $serviceAuthorised = $false
                $finalResult = $null

                foreach ($testIP in $service.TestIPs) {
                    Write-Verbose "Testing static IP provider $($service.Name) with IP: $testIP"

                    $result = Test-ProofpointServiceAuthorisation -DomainName $Domain -ServiceName $service.Name -TestIP $testIP -ErrorAction Stop

                    if ($result.IsAuthorised) {
                        # First IP is authorised - skip testing remaining IPs (optimization)
                        Write-Verbose "$($service.Name): Authorised with IP $testIP - skipping remaining IPs"
                        $finalResult = $result
                        $serviceAuthorised = $true
                        break
                    }
                    else {
                        # Store the last result in case none are authorised
                        $finalResult = $result
                    }
                }

                # Output based on IncludeUnauthorised switch
                if ($IncludeUnauthorised) {
                    Write-Output $finalResult
                }
                elseif ($serviceAuthorised) {
                    Write-Output $finalResult
                }
            }
            else {
                # SPF-based provider with single TestIP
                $testIPParam = $null
                if ($null -ne $service.TestIP) {
                    if ($service.TestIP -is [System.Array]) {
                        # If it's an array, take the first element
                        $testIPParam = $service.TestIP[0]
                        Write-Verbose "Service $($service.Name) had array TestIP, using first element: $testIPParam"
                    }
                    elseif ($service.TestIP -is [string]) {
                        $testIPParam = $service.TestIP
                    }
                    else {
                        $testIPParam = $service.TestIP.ToString()
                    }
                }

                $result = Test-ProofpointServiceAuthorisation -DomainName $Domain -ServiceName $service.Name -TestIP $testIPParam -ErrorAction Stop

                # Filter output based on IncludeUnauthorised switch
                if ($IncludeUnauthorised) {
                    Write-Output $result
                }
                elseif ($result.IsAuthorised) {
                    Write-Output $result
                }
            }
        }
        catch {
            Write-Verbose "Failed to test service $($service.Name): $($_.Exception.Message)"

            # Output error result if IncludeUnauthorised is specified
            if ($IncludeUnauthorised) {
                Write-Output ([PSCustomObject]@{
                    PSTypeName         = 'ProofpointSPF.Result'
                    Domain             = $Domain
                    ServiceName        = $service.Name
                    TestIP             = if ($service.TestIP) { $service.TestIP.ToString() } else { 'N/A' }
                    QueryName          = 'N/A'
                    IsAuthorised       = $false
                    ResponseType       = 'Error'
                    ResponseData       = $_.Exception.Message
                    AdditionalServices = $null
                })
            }
        }
    }

    Write-Progress -Activity "Testing Services" -Completed
    Write-Verbose "Fingerprint scan completed for domain: $Domain"
}

end {
    Write-Verbose "Proofpoint SPF fingerprinting complete"
}
