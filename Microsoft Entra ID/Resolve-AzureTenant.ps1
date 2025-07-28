#Requires -Version 5.1

<#
.SYNOPSIS
    Resolves comprehensive Azure AD tenant information using multiple unauthenticated endpoints.

.DESCRIPTION
    This script queries Azure AD OIDC metadata endpoints and GetUserRealm to resolve 
    comprehensive tenant information for one or more domains. It extracts organisation 
    names, tenant IDs, authentication configurations, and security-relevant metadata.
    
    The script implements intelligent rate limiting, retry logic, and proper error 
    handling to avoid triggering Azure AD throttling mechanisms.
    
    Endpoints queried (all unauthenticated):
    - GetUserRealm: Organisation name, namespace type, federation status
    - OIDC metadata: Tenant configuration, authentication endpoints, security capabilities
    - JWKS: Public key certificates and cryptographic algorithms
    
    Output includes:
    - Organisation name and tenant identification
    - MOERA domain discovery (organisational onmicrosoft.com domain)
    - Authentication endpoints and supported protocols
    - Security configuration (scopes, response types, signing algorithms)
    - Cloud environment and regional information
    - Federation and logout capabilities

.PARAMETER Domain
    The domain name(s) to resolve. Can be a single domain string or an array of domains.
    Supports both custom domains (contoso.com) and onmicrosoft.com domains.

.PARAMETER Environment
    The Azure cloud environment to query. Valid values are Global, USGov, China, Germany.
    Default is Global (login.microsoftonline.com).

.PARAMETER DelayBetweenRequests
    Base delay in seconds between requests to avoid rate limiting. Default is 0.5 seconds.
    Additional random jitter is automatically applied.

.PARAMETER MaxRetries
    Maximum number of retry attempts for failed requests. Default is 3.

.PARAMETER TimeoutSeconds
    HTTP request timeout in seconds. Default is 30 seconds.

.PARAMETER OutputFormat
    Output format for results. Valid values are Object (default), CSV, JSON.

.PARAMETER LogPath
    Optional path to write detailed logs. If not specified, only verbose messages are shown.

.EXAMPLE
    .\Resolve-AzureTenant.ps1 -Domain "contoso.com" -Verbose
    
    Resolves comprehensive tenant information for contoso.com with verbose logging.
    Returns organisation name, tenant ID, and complete OIDC configuration.

.EXAMPLE
    .\Resolve-AzureTenant.ps1 -Domain @("contoso.com", "fabrikam.onmicrosoft.com") -OutputFormat JSON
    
    Resolves multiple domains and outputs results in JSON format for further processing.

.EXAMPLE
    Get-Content domains.txt | .\Resolve-AzureTenant.ps1 -DelayBetweenRequests 1.0 -LogPath ".\tenant_scan.log"
    
    Processes domains from a file with 1-second delays and detailed logging.
    Useful for bulk tenant enumeration with comprehensive audit trails.

.NOTES
    Author: Daniel Streefkerk
    Version: 1.2
    Last Modified: 2025-07-28
    
    This script is designed for legitimate security research and tenant enumeration.
    Always respect rate limits and terms of service when using this tool.
    
    All endpoints used are publicly accessible and do not require authentication.
    The script includes intelligent delays and retry logic to avoid triggering restrictions.
    
    Useful for:
    - Security assessments and reconnaissance
    - Tenant discovery and mapping
    - Authentication configuration analysis
    - Organisation identification

.LINK
    https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
.LINK
    https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-federation-metadata
#>

[CmdletBinding(SupportsShouldProcess=$false)]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [Alias('DomainName', 'Tenant')]
    [string[]]$Domain,

    [Parameter()]
    [ValidateSet('Global', 'USGov', 'China', 'Germany')]
    [string]$Environment = 'Global',

    [Parameter()]
    [ValidateRange(0.1, 10.0)]
    [double]$DelayBetweenRequests = 0.5,

    [Parameter()]
    [ValidateRange(0, 10)]
    [int]$MaxRetries = 3,

    [Parameter()]
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 30,

    [Parameter()]
    [ValidateSet('Object', 'CSV', 'JSON')]
    [string]$OutputFormat = 'Object',

    [Parameter()]
    [ValidateScript({
        $parentPath = Split-Path $_ -Parent
        if ($parentPath -and -not (Test-Path $parentPath)) {
            throw "Parent directory does not exist: $parentPath"
        }
        $true
    })]
    [string]$LogPath
)

#region Helper Functions

function Resolve-TenantDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )

    $result = [PSCustomObject]@{
        Domain = $DomainName.ToLower().Trim()
        TenantId = $null
        OrganisationName = $null
        MOERADomain = $null
        ResponseTime = 0
        ErrorMessage = $null
        Timestamp = Get-Date
        Environment = $Environment
        NameSpaceType = $null
        IsFederated = $false
        Issuer = $null
        AuthorizationEndpoint = $null
        TokenEndpoint = $null
        UserInfoEndpoint = $null
        JwksUri = $null
        EndSessionEndpoint = $null
        DeviceAuthorizationEndpoint = $null
        CloudInstanceName = $null
        CloudGraphHostName = $null
        MsGraphHost = $null
        RbacUrl = $null
        TenantRegionScope = $null
        TenantRegionSubScope = $null
        ScopesSupported = $null
        ResponseTypesSupported = $null
        TokenEndpointAuthMethodsSupported = $null
        IdTokenSigningAlgValuesSupported = $null
        CodeChallengeMethodsSupported = $null
        ClaimsSupported = $null
        GrantTypesSupported = $null
        FrontchannelLogoutSupported = $null
        HttpLogoutSupported = $null
        ResponseModesSupported = $null
        SubjectTypesSupported = $null
        KerberosEndpoint = $null
    }

    try {
        Write-Verbose "Resolving tenant for domain: $($result.Domain)"
        
        # First, try to get organisation name via GetUserRealm
        $userRealmInfo = Get-UserRealmInfo -DomainName $result.Domain
        if ($userRealmInfo.OrganisationName) {
            $result.OrganisationName = $userRealmInfo.OrganisationName
            $result.NameSpaceType = $userRealmInfo.NameSpaceType
            $result.IsFederated = $userRealmInfo.IsFederated
        }
        
        # Discover MOERA domain
        $moeraResult = Get-MOERADomain -OrganizationName $result.OrganisationName -DomainName $result.Domain
        if ($moeraResult) {
            $result.MOERADomain = $moeraResult
            Write-Verbose "Discovered MOERA domain: $moeraResult"
        }
        
        # Try multiple domain formats for OIDC metadata
        $domainVariants = Get-DomainVariants -Domain $result.Domain
        
        foreach ($variant in $domainVariants) {
            Write-Verbose "Trying domain variant: $variant"
            
            $tenantInfo = Invoke-OidcMetadataRequest -TenantValue $variant
            
            if ($tenantInfo.Success) {
                $result.TenantId = $tenantInfo.TenantId
                $result.ResponseTime = $tenantInfo.ResponseTime
                $result.Issuer = $tenantInfo.Issuer
                $result.AuthorizationEndpoint = $tenantInfo.AuthorizationEndpoint
                $result.TokenEndpoint = $tenantInfo.TokenEndpoint
                $result.UserInfoEndpoint = $tenantInfo.UserInfoEndpoint
                $result.JwksUri = $tenantInfo.JwksUri
                $result.EndSessionEndpoint = $tenantInfo.EndSessionEndpoint
                $result.DeviceAuthorizationEndpoint = $tenantInfo.DeviceAuthorizationEndpoint
                $result.CloudInstanceName = $tenantInfo.CloudInstanceName
                $result.CloudGraphHostName = $tenantInfo.CloudGraphHostName
                $result.MsGraphHost = $tenantInfo.MsGraphHost
                $result.RbacUrl = $tenantInfo.RbacUrl
                $result.TenantRegionScope = $tenantInfo.TenantRegionScope
                $result.TenantRegionSubScope = $tenantInfo.TenantRegionSubScope
                $result.ScopesSupported = $tenantInfo.ScopesSupported
                $result.ResponseTypesSupported = $tenantInfo.ResponseTypesSupported
                $result.TokenEndpointAuthMethodsSupported = $tenantInfo.TokenEndpointAuthMethodsSupported
                $result.IdTokenSigningAlgValuesSupported = $tenantInfo.IdTokenSigningAlgValuesSupported
                $result.CodeChallengeMethodsSupported = $tenantInfo.CodeChallengeMethodsSupported
                $result.ClaimsSupported = $tenantInfo.ClaimsSupported
                $result.GrantTypesSupported = $tenantInfo.GrantTypesSupported
                $result.FrontchannelLogoutSupported = $tenantInfo.FrontchannelLogoutSupported
                $result.HttpLogoutSupported = $tenantInfo.HttpLogoutSupported
                $result.ResponseModesSupported = $tenantInfo.ResponseModesSupported
                $result.SubjectTypesSupported = $tenantInfo.SubjectTypesSupported
                $result.KerberosEndpoint = $tenantInfo.KerberosEndpoint
                
                $script:SuccessfulRequests++
                Write-Verbose "Found tenant: $($result.Domain) -> $($result.TenantId)"
                break
            }
            elseif ($tenantInfo.RateLimited) {
                $result.ErrorMessage = $tenantInfo.ErrorMessage
                $script:RateLimitedRequests++
                Write-Warning "Rate limited while resolving $($result.Domain)"
                break
            }
        }

        if (-not $result.TenantId) {
            $script:FailedRequests++
            Write-Verbose "No tenant found for: $($result.Domain)"
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        $script:FailedRequests++
        Write-Error "Error resolving $($result.Domain): $_"
    }

    return $result
}

function Get-DomainVariants {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    $variants = @($Domain)
    
    # If not already an onmicrosoft.com domain, try adding it
    if (-not $Domain.EndsWith('.onmicrosoft.com')) {
        $baseName = $Domain -replace '\..*$', ''  # Get first part before first dot
        $variants += "$baseName.onmicrosoft.com"
    }
    
    # Also try without dots (some tenants use concatenated names)
    $noDots = $Domain -replace '\.', ''
    if ($noDots -ne $Domain) {
        $variants += $noDots
        $variants += "$noDots.onmicrosoft.com"
    }

    return $variants | Select-Object -Unique
}

function Invoke-OidcMetadataRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TenantValue
    )

    $baseUrl = $script:EnvironmentEndpoints[$Environment]
    $url = "$baseUrl/$TenantValue/v2.0/.well-known/openid-configuration"
    
    $result = @{
        Success = $false
        TenantId = $null
        ResponseTime = 0
        RateLimited = $false
        ErrorMessage = $null
        Issuer = $null
        AuthorizationEndpoint = $null
        TokenEndpoint = $null
        UserInfoEndpoint = $null
        JwksUri = $null
        EndSessionEndpoint = $null
        DeviceAuthorizationEndpoint = $null
        CloudInstanceName = $null
        CloudGraphHostName = $null
        MsGraphHost = $null
        RbacUrl = $null
        TenantRegionScope = $null
        TenantRegionSubScope = $null
        ScopesSupported = $null
        ResponseTypesSupported = $null
        TokenEndpointAuthMethodsSupported = $null
        IdTokenSigningAlgValuesSupported = $null
        CodeChallengeMethodsSupported = $null
        ClaimsSupported = $null
        GrantTypesSupported = $null
        FrontchannelLogoutSupported = $null
        HttpLogoutSupported = $null
        ResponseModesSupported = $null
        SubjectTypesSupported = $null
        KerberosEndpoint = $null
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            $script:TotalRequests++
            
            # Create web request with proper headers
            $headers = @{
                'User-Agent' = 'Azure-Tenant-Resolver/1.0 PowerShell'
                'Accept' = 'application/json'
                'Accept-Encoding' = 'gzip, deflate'
            }

            Write-Verbose "Attempting request $attempt to: $url"
            
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            
            $stopwatch.Stop()
            $result.ResponseTime = $stopwatch.ElapsedMilliseconds
            
            if ($response.issuer) {
                $result.Success = $true
                
                # Core endpoints
                $result.Issuer = $response.issuer
                $result.AuthorizationEndpoint = $response.authorization_endpoint
                $result.TokenEndpoint = $response.token_endpoint
                $result.UserInfoEndpoint = $response.userinfo_endpoint
                $result.JwksUri = $response.jwks_uri
                
                # Additional endpoints useful for IT admins
                $result.EndSessionEndpoint = $response.end_session_endpoint
                $result.DeviceAuthorizationEndpoint = $response.device_authorization_endpoint
                
                # Cloud and tenant information
                $result.CloudInstanceName = $response.cloud_instance_name
                $result.CloudGraphHostName = $response.cloud_graph_host_name
                $result.MsGraphHost = $response.msgraph_host
                $result.RbacUrl = $response.rbac_url
                $result.TenantRegionScope = $response.tenant_region_scope
                $result.TenantRegionSubScope = if ($response.PSObject.Properties['tenant_region_sub_scope']) { $response.tenant_region_sub_scope } else { $null }
                
                # Security-relevant configuration for analysts
                $result.ScopesSupported = if ($response.scopes_supported) { $response.scopes_supported -join ', ' } else { $null }
                $result.ResponseTypesSupported = if ($response.response_types_supported) { $response.response_types_supported -join ', ' } else { $null }
                $result.TokenEndpointAuthMethodsSupported = if ($response.token_endpoint_auth_methods_supported) { $response.token_endpoint_auth_methods_supported -join ', ' } else { $null }
                $result.IdTokenSigningAlgValuesSupported = if ($response.id_token_signing_alg_values_supported) { $response.id_token_signing_alg_values_supported -join ', ' } else { $null }
                $result.CodeChallengeMethodsSupported = if ($response.PSObject.Properties['code_challenge_methods_supported']) { $response.code_challenge_methods_supported -join ', ' } else { $null }
                $result.ClaimsSupported = if ($response.claims_supported) { $response.claims_supported -join ', ' } else { $null }
                $result.GrantTypesSupported = if ($response.PSObject.Properties['grant_types_supported'] -and $response.grant_types_supported) { $response.grant_types_supported -join ', ' } else { $null }
                $result.FrontchannelLogoutSupported = $response.frontchannel_logout_supported
                $result.HttpLogoutSupported = $response.http_logout_supported
                $result.ResponseModesSupported = if ($response.response_modes_supported) { $response.response_modes_supported -join ', ' } else { $null }
                $result.SubjectTypesSupported = if ($response.subject_types_supported) { $response.subject_types_supported -join ', ' } else { $null }
                $result.KerberosEndpoint = $response.kerberos_endpoint
                
                # Extract tenant ID from issuer URL
                if ($response.issuer -match '/([a-f0-9\-]{36})/') {
                    $result.TenantId = $matches[1]
                }
                
                Write-Verbose "OIDC metadata retrieved successfully"
                break
            }
        }
        catch {
            $stopwatch.Stop()
            $statusCode = $null
            
            # Check if it's an HTTP error - simplified for cross-version compatibility
            try {
                if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                elseif ($_.Exception.Response.StatusCode) {
                    $statusCode = [int]$_.Exception.Response.StatusCode.value__
                }
                elseif ($_.ErrorDetails.Message) {
                    # Try to extract status from error details
                    if ($_.ErrorDetails.Message -match 'HTTP (\d{3})') {
                        $statusCode = [int]$Matches[1]
                    } else {
                        $statusCode = 400  # Default for client errors
                    }
                }
            }
            catch {
                # If we can't determine status code, assume 400
                $statusCode = 400
            }

            Write-Verbose "Request failed (attempt $attempt): StatusCode=$statusCode, Error=$($_.Exception.Message)"

            switch ($statusCode) {
                400 {
                    # Bad Request - tenant doesn't exist, don't retry
                    $result.ErrorMessage = "Tenant not found"
                    break
                }
                404 {
                    # Not Found - tenant doesn't exist, don't retry
                    $result.ErrorMessage = "Tenant not found"
                    break
                }
                429 {
                    # Too Many Requests - rate limited
                    $result.RateLimited = $true
                    $result.ErrorMessage = "Rate limited"
                    
                    if ($attempt -le $MaxRetries) {
                        $backoffDelay = [Math]::Min(60, [Math]::Pow(2, $attempt) + (Get-Random -Minimum 1 -Maximum 5))
                        Write-Warning "Rate limited. Backing off for $backoffDelay seconds..."
                        Start-Sleep -Seconds $backoffDelay
                        continue
                    }
                    break
                }
                {$_ -in @(500, 502, 503, 504)} {
                    # Server errors - retry with backoff
                    if ($attempt -le $MaxRetries) {
                        $backoffDelay = [Math]::Pow(2, $attempt) + (Get-Random -Minimum 1 -Maximum 3)
                        Write-Verbose "Server error. Retrying in $backoffDelay seconds..."
                        Start-Sleep -Seconds $backoffDelay
                        continue
                    }
                    $result.ErrorMessage = "Server error: $statusCode"
                }
                default {
                    # Other HTTP errors or network issues
                    if ($attempt -le $MaxRetries -and $statusCode -eq $null) {
                        # Network error, might be transient
                        $backoffDelay = [Math]::Pow(2, $attempt)
                        Write-Verbose "Network error. Retrying in $backoffDelay seconds..."
                        Start-Sleep -Seconds $backoffDelay
                        continue
                    }
                    $result.ErrorMessage = $_.Exception.Message
                }
            }
            
            # If we reach here, either we shouldn't retry or we've exhausted retries
            break
        }
    }

    return $result
}

function Invoke-RateLimit {
    [CmdletBinding()]
    param()

    $currentTime = Get-Date
    
    # Clean up old request times (keep only last 60 seconds)
    $cutoffTime = $currentTime.AddSeconds(-60)
    $script:RequestTimes = @($script:RequestTimes | Where-Object { $_ -gt $cutoffTime })
    
    # Check if we're approaching rate limits (conservative limit of 60 requests per minute)
    $requestsInLastMinute = $script:RequestTimes.Count
    if ($requestsInLastMinute -ge 50) {
        $oldestRequest = $script:RequestTimes | Sort-Object | Select-Object -First 1
        $waitTime = 60 - ($currentTime - $oldestRequest).TotalSeconds + (Get-Random -Minimum 1 -Maximum 5)
        
        Write-Warning "Approaching rate limit. Pausing for $([Math]::Round($waitTime, 1)) seconds..."
        Start-Sleep -Seconds $waitTime
    }
    
    # Apply base delay with jitter
    $timeSinceLastRequest = ($currentTime - $script:LastRequestTime).TotalSeconds
    $jitteredDelay = $DelayBetweenRequests + (Get-Random -Minimum 0 -Maximum ($DelayBetweenRequests * 0.5))
    
    if ($timeSinceLastRequest -lt $jitteredDelay) {
        $sleepTime = $jitteredDelay - $timeSinceLastRequest
        Write-Verbose "Rate limiting: sleeping for $([Math]::Round($sleepTime, 2)) seconds"
        Start-Sleep -Seconds $sleepTime
    }
    
    # Record this request time
    $script:RequestTimes += $currentTime
    $script:LastRequestTime = $currentTime
}

function Get-UserRealmInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    $result = @{
        OrganisationName = $null
        NameSpaceType = $null
        IsFederated = $false
        CloudInstanceName = $null
        ResponseTime = 0
        Error = $null
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        Write-Verbose "Querying GetUserRealm for organisation name: $DomainName"
        
        # Apply rate limiting
        Invoke-RateLimit
        
        # Use a common admin username format
        $testUser = "admin@$DomainName"
        $url = "https://login.microsoftonline.com/getuserrealm.srf?login=$testUser&xml=1"
        
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        
        $stopwatch.Stop()
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
        
        if ($response -and $response.RealmInfo) {
            $realm = $response.RealmInfo
            $result.NameSpaceType = $realm.NameSpaceType
            $result.IsFederated = ($realm.IsFederatedNS -eq 'true')
            $result.CloudInstanceName = $realm.CloudInstanceName
            
            # Extract organisation name from FederationBrandName
            if ($realm.FederationBrandName) {
                $result.OrganisationName = $realm.FederationBrandName
                Write-Verbose "Found organisation name: $($realm.FederationBrandName)"
            }
            
            Write-Verbose "GetUserRealm result: NameSpaceType=$($realm.NameSpaceType), Federated=$($result.IsFederated), Org=$($result.OrganisationName)"
        }
    }
    catch {
        $stopwatch.Stop()
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
        $result.Error = $_.Exception.Message
        Write-Verbose "GetUserRealm error for $DomainName : $_"
    }
    
    return $result
}

function Get-MOERADomain {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OrganizationName,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    try {
        # Generate up to 10 MOERA domain candidates
        $candidates = Get-MOERADomainCandidates -OrganizationName $OrganizationName -DomainName $DomainName
        
        Write-Verbose "Generated $($candidates.Count) MOERA domain candidates for $DomainName"
        
        # Test candidates via DNS validation
        foreach ($candidate in $candidates) {
            Write-Verbose "Testing MOERA candidate: $($candidate.Domain) ($($candidate.Type))"
            
            $dnsResult = Test-MOERADomainDNS -DomainCandidate $candidate.Domain
            if ($dnsResult.IsValid) {
                # Apply confidence-based suffix
                $moeraResult = "$($candidate.Domain).onmicrosoft.com"
                if ($candidate.Confidence -eq 'High') {
                    Write-Verbose "SUCCESS: High confidence MOERA domain: $moeraResult"
                    return $moeraResult
                }
                else {
                    Write-Verbose "SUCCESS: Medium confidence MOERA domain: $moeraResult"
                    return "$moeraResult (Inferred)"
                }
            }
            else {
                Write-Verbose "FAILED: $($candidate.Domain) - $($dnsResult.Error)"
            }
        }
        
        Write-Verbose "No valid MOERA domain found after testing $($candidates.Count) candidates"
        return $null
    }
    catch {
        Write-Verbose "Error discovering MOERA domain: $_"
        return $null
    }
}

function Get-MOERADomainCandidates {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OrganizationName,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    $candidates = @()
    
    # Normalize inputs
    $domainBase = ($DomainName -replace '\..*$', '').ToLower()  # Remove TLD
    
    # Organisation name candidates (if available) - highest priority
    if ($OrganizationName) {
        $orgNormalized = $OrganizationName.ToLower() -replace '[^a-z0-9]', ''  # Remove spaces/punctuation
        
        # 1. Full organisation name compressed (HIGHEST PRIORITY - HIGH CONFIDENCE)
        if ($orgNormalized -and $orgNormalized.Length -ge 3) {
            $candidates += @{
                Domain = $orgNormalized
                Confidence = 'High'
                Type = 'FullOrgName'
            }
        }
        
        # 2. Organisation acronym (first letters of words) - MEDIUM CONFIDENCE
        $words = @($OrganizationName.Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
        if ($words.Count -ge 2) {
            $acronym = ($words | ForEach-Object { $_[0] }) -join ''
            if ($acronym.Length -ge 2 -and $acronym.Length -le 6) {
                $candidates += @{
                    Domain = $acronym.ToLower()
                    Confidence = 'Medium'
                    Type = 'Acronym'
                }
            }
        }
        
        # 3. Organisation without common suffixes - MEDIUM CONFIDENCE
        $suffixRemoved = $orgNormalized -replace '(ltd|inc|corp|group|company|corporation|limited|llc)$', ''
        if ($suffixRemoved -and $suffixRemoved.Length -ge 3 -and $suffixRemoved -ne $orgNormalized) {
            $candidates += @{
                Domain = $suffixRemoved
                Confidence = 'Medium'
                Type = 'SuffixRemoved'
            }
        }
    }
    
    # Domain name candidates - MEDIUM CONFIDENCE
    # 4. Domain base name (remove TLD)
    if ($domainBase -and $domainBase.Length -ge 3) {
        $candidates += @{
            Domain = $domainBase
            Confidence = 'Medium'
            Type = 'DomainBase'
        }
    }
    
    # 5. Domain base without common prefixes (www, mail, etc.) - MEDIUM CONFIDENCE
    $domainCleaned = $domainBase -replace '^(www|mail|email|mx|smtp)', ''
    if ($domainCleaned -and $domainCleaned.Length -ge 3 -and $domainCleaned -ne $domainBase) {
        $candidates += @{
            Domain = $domainCleaned
            Confidence = 'Medium'
            Type = 'DomainCleaned'
        }
    }
    
    # 6-10. Additional conservative variations
    # Remove risky individual word matching to avoid false positives
    # Focus on more reliable patterns only
    
    # Deduplicate and limit to 10, prioritizing earlier entries
    $uniqueCandidates = @()
    if ($candidates) {
        foreach ($candidate in $candidates) {
            if ($candidate -and $candidate.Domain -and $candidate.Domain.Length -ge 3 -and $candidate.Domain.Length -le 64) {
                # Check if domain already exists
                $existingDomain = $uniqueCandidates | Where-Object { $_.Domain -eq $candidate.Domain }
                if (-not $existingDomain) {
                    $uniqueCandidates += $candidate
                    if ($uniqueCandidates.Count -ge 10) { break }
                }
            }
        }
    }
    
    return $uniqueCandidates
}

function Test-MOERADomainDNS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainCandidate
    )
    
    $result = @{
        IsValid = $false
        Error = $null
        MXRecord = $null
    }
    
    try {
        # Rate limiting for DNS queries
        Start-Sleep -Milliseconds 100
        
        $fullDomain = "$DomainCandidate.onmicrosoft.com"
        
        # Test DNS MX record with shorter timeout for performance
        $mxRecords = Resolve-DnsName -Name $fullDomain -Type MX -ErrorAction Stop
        
        if ($mxRecords) {
            # Filter to actual MX records (not SOA)
            $actualMX = $mxRecords | Where-Object { $_.Type -eq 'MX' }
            
            if ($actualMX) {
                # Accept any MX record as valid MOERA domain
                $result.IsValid = $true
                $result.MXRecord = $actualMX[0].NameExchange
            }
            else {
                $result.Error = "No MX records found in response"
            }
        }
        else {
            $result.Error = "No DNS records found"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

#endregion Helper Functions

# Initialize script
Set-StrictMode -Version Latest

# Start transcript if logging is enabled
if ($LogPath) {
    try {
        Start-Transcript -Path $LogPath -Append | Out-Null
        Write-Verbose "Logging enabled to: $LogPath"
    }
    catch {
        Write-Warning "Failed to start transcript: $_"
    }
}

# Environment-specific endpoints
$script:EnvironmentEndpoints = @{
    'Global'  = 'https://login.microsoftonline.com'
    'USGov'   = 'https://login.microsoftonline.us'
    'China'   = 'https://login.partner.microsoftonline.cn'
    'Germany' = 'https://login.microsoftonline.de'
}

# Rate limiting variables
$script:RequestTimes = @()
$script:LastRequestTime = [DateTime]::MinValue
$script:TotalRequests = 0
$script:SuccessfulRequests = 0
$script:FailedRequests = 0
$script:RateLimitedRequests = 0

# Results collection
$script:Results = @()

Write-Verbose "Starting Azure AD tenant resolution at $(Get-Date)"
Write-Verbose "Environment: $Environment ($($script:EnvironmentEndpoints[$Environment]))"
Write-Verbose "Rate limiting: $DelayBetweenRequests seconds base delay with jitter"
Write-Verbose "Max retries: $MaxRetries, Timeout: $TimeoutSeconds seconds"

# Process each domain
foreach ($DomainName in $Domain) {
    $result = Resolve-TenantDomain -DomainName $DomainName
    $script:Results += $result
    
    # Output result immediately for pipeline processing
    switch ($OutputFormat) {
        'Object' { Write-Output $result }
        'CSV' { 
            # For CSV, we'll collect and output at end to include headers
            # But still process for immediate feedback
            Write-Verbose "Processed: $($result.Domain) - $($result.Status)"
        }
        'JSON' {
            # For JSON, output each result as a separate JSON object
            Write-Output ($result | ConvertTo-Json -Compress)
        }
    }
}

# Final statistics
$successRate = if ($script:TotalRequests -gt 0) { 
    [Math]::Round(($script:SuccessfulRequests / $script:TotalRequests) * 100, 2) 
} else { 0 }

Write-Verbose "Scan completed at $(Get-Date)"
Write-Verbose "Statistics:"
Write-Verbose "  Total requests: $($script:TotalRequests)"
Write-Verbose "  Successful: $($script:SuccessfulRequests)"
Write-Verbose "  Failed: $($script:FailedRequests)"
Write-Verbose "  Rate limited: $($script:RateLimitedRequests)"
Write-Verbose "  Success rate: $successRate%"

# Output CSV format if requested
if ($OutputFormat -eq 'CSV' -and $script:Results.Count -gt 0) {
    $script:Results | ConvertTo-Csv -NoTypeInformation | Write-Output
}

# Stop transcript if it was started
if ($LogPath) {
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        # Transcript may not have been started successfully
    }
}