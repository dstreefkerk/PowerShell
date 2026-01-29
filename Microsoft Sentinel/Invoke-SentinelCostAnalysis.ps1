#requires -Modules Az.Accounts, Az.OperationalInsights

<#
.SYNOPSIS
    Analyses Microsoft Sentinel costs and provides pricing tier optimisation recommendations.

.DESCRIPTION
    This script started out as a proof of concept for analysing Microsoft Sentinel costs,
    for integration into my New-SentinelAssessmentReport.ps1 script, however the functionality
    is too useful to confine to just that report.

    It evolved out of a frustration with the Sentinel Costs workbooks and the requirement
    to always enter E5 seat counts, prices, etc, as well as their inability to easily
    support other currencies. 

    NOTE: There may be bugs or inaccuracies in the calculations. Always verify pricing
    details with official Microsoft documentation and your Azure billing data. Also feel free to
    fix the bug and submit a PR if you find any issues!

    This script performs comprehensive cost analysis for Microsoft Sentinel workspaces,
    comparing current spending against available pricing tiers and commitment levels.

    Capabilities:
    - Retrieves current Sentinel pricing from Azure Retail Prices API
    - Analyses ingestion trends via Log Analytics KQL queries
    - Detects Microsoft 365 E5/A5/F5/G5 licenses for data grant eligibility
    - Compares Pay-As-You-Go vs Commitment Tier pricing
    - Calculates potential savings across all commitment levels
    - Provides actionable tier recommendations based on actual usage

    Key APIs used:
    - Azure Retail Prices: https://prices.azure.com/api/retail/prices
    - Microsoft Graph: https://graph.microsoft.com/v1.0/subscribedSkus

    Microsoft 365 E5 Data Grant:
    - Eligible licenses: E5, A5, F5, G5 (and Security variants)
    - Grant: 5 MB per user per day for qualifying Microsoft data sources
    - Reference: https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer/

.PARAMETER SubscriptionId
    The Azure Subscription ID containing the Sentinel workspace.

.PARAMETER ResourceGroupName
    The Resource Group name containing the Log Analytics workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name with Sentinel enabled.

.PARAMETER SkipKqlQueries
    Skip KQL queries and use sample data for testing pricing calculations.

.EXAMPLE
    .\Invoke-SentinelCostAnalysis.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroupName "MyRG" -WorkspaceName "MyWorkspace"

    Performs full cost analysis including ingestion trend queries.

.EXAMPLE
    .\Invoke-SentinelCostAnalysis.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroupName "MyRG" -WorkspaceName "MyWorkspace" -SkipKqlQueries -Verbose

    Runs pricing calculations with sample data (useful for testing or when KQL access is unavailable).

.NOTES
    Author: Daniel Streefkerk
    GitHub: https://github.com/dstreefkerk
    Version: 1.0.0
    Date: 29 January 2026
    Requires: Az.Accounts, Az.OperationalInsights modules
    Permissions: Reader access to the Log Analytics workspace, Microsoft Graph User.Read.All for license detection
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Azure Subscription ID (GUID format)")]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true, HelpMessage = "Resource Group containing the Sentinel workspace")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = "Log Analytics workspace name")]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $false)]
    [switch]$SkipKqlQueries
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# FREE DATA SOURCES
# =============================================================================
# Tables that are ALWAYS free for ingestion in Microsoft Sentinel, regardless of license.
# See: https://learn.microsoft.com/en-us/azure/sentinel/billing#free-data-sources
#
# IMPORTANT DISTINCTIONS:
# 1. ALWAYS FREE (this list):
#    - AzureActivity, SentinelHealth, SecurityAlert, SecurityIncident, OfficeActivity
#    - These tables incur NO ingestion charges under any circumstances
#
# 2. LICENSE-DEPENDENT BENEFITS (NOT in this list):
#    - E5/A5/F5/G5 Data Grant: 5 MB/user/day for specific Microsoft data sources
#      (see $e5EligibleTables in Invoke-CostOptimizationAnalysis)
#    - Defender for Servers P2: 500 MB/VM/day for security tables
#      (see $script:DefenderP2EligibleTables below)
#
# 3. COMMON CONFUSION - SentinelAudit:
#    - SentinelAudit is BILLABLE (tracks user actions in Sentinel)
#    - SentinelHealth is FREE (tracks Sentinel system health)
#    - Only SentinelHealth is included in this free list
# =============================================================================
$script:FreeDataTables = @(
    'AzureActivity',      # Azure subscription activity logs
    'SentinelHealth',     # Sentinel health diagnostics (NOT SentinelAudit which is billable)
    'SecurityAlert',      # Alerts from all Microsoft security products
    'SecurityIncident',   # Sentinel incidents
    'OfficeActivity'      # SharePoint, Exchange, Teams activity (M365 connector)
)

# =============================================================================
# SENTINEL SOLUTION TABLES (90-day free retention)
# =============================================================================
# Tables that are part of the Microsoft Sentinel solution and receive 90 days
# free retention (vs 31 days for standard Log Analytics tables).
# See: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure
# =============================================================================
$script:SentinelSolutionTables = @(
    # Security tables from Sentinel connectors
    'SecurityEvent', 'SecurityAlert', 'SecurityIncident',
    'CommonSecurityLog', 'Syslog', 'WindowsFirewall',
    'AzureActivity', 'OfficeActivity',
    # Threat Intelligence tables (multiple name variations exist)
    'ThreatIntelligenceIndicator', 'ThreatIntelIndicators',
    # Sentinel operational tables
    'SentinelHealth', 'SentinelAudit', 'SentinelAudit_CL',
    # Microsoft Entra ID / Azure AD
    'SigninLogs', 'AuditLogs', 'AADNonInteractiveUserSignInLogs',
    'AADServicePrincipalSignInLogs', 'AADManagedIdentitySignInLogs',
    'AADProvisioningLogs', 'ADFSSignInLogs', 'IdentityInfo',
    'AADRiskyUsers', 'AADUserRiskEvents', 'AADRiskyServicePrincipals',
    # Microsoft 365 Defender (XDR) tables
    'DeviceEvents', 'DeviceFileEvents', 'DeviceImageLoadEvents',
    'DeviceInfo', 'DeviceLogonEvents', 'DeviceNetworkEvents',
    'DeviceNetworkInfo', 'DeviceProcessEvents', 'DeviceRegistryEvents',
    'DeviceFileCertificateInfo', 'DynamicEventCollection',
    'CloudAppEvents', 'EmailAttachmentInfo', 'EmailEvents',
    'EmailPostDeliveryEvents', 'EmailUrlInfo', 'UrlClickEvents',
    'IdentityLogonEvents', 'IdentityQueryEvents', 'IdentityDirectoryEvents',
    'AlertEvidence', 'AlertInfo', 'BehaviorAnalytics', 'BehaviorEntities',
    # Defender for Cloud Apps
    'McasShadowItReporting',
    # UEBA tables
    'UserAccessAnalytics', 'UserPeerAnalytics', 'EntityAnalytics',
    'Anomalies', 'AnomalyDetection',
    # Watchlists
    'Watchlist', 'WatchlistItem', '_GetWatchlist',
    # Hunting bookmarks
    'HuntingBookmark',
    # Additional Sentinel tables
    'SecurityRecommendation', 'SecurityNestedRecommendation',
    'SecurityRegulatoryCompliance', 'SecurityBaseline',
    'AzureDiagnostics', 'AzureNetworkAnalytics_CL',
    # Defender for Endpoint
    'DeviceTvmSecureConfigurationAssessment', 'DeviceTvmSoftwareInventory',
    'DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSoftwareVulnerabilitiesKB',
    # Windows events
    'WindowsEvent'
)

# =============================================================================
# TABLES WITH FIXED RETENTION
# =============================================================================
# These tables have fixed retention periods that cannot be changed.
# =============================================================================
$script:FixedRetentionTables = @{
    'Usage'         = 90   # Always 90 days, free
    'AzureActivity' = 90   # Always 90 days, free
}

# =============================================================================
# DEFENDER FOR SERVERS P2 ELIGIBLE TABLES
# =============================================================================
# Tables eligible for the Defender for Servers P2 benefit (500 MB/VM/day).
# The benefit only applies to security-related data types ingested from protected VMs.
# See: https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-servers
#
# NOTE: The current implementation applies P2 benefit as a flat deduction from total
# billable ingestion. For more precise calculation, this list should be used to
# determine which specific tables the benefit can offset.
# =============================================================================
$script:DefenderP2EligibleTables = @(
    'SecurityAlert',                    # Security alerts from Defender
    'SecurityEvent',                    # Windows Security Events
    'WindowsFirewall',                  # Windows Firewall logs
    'SecurityBaseline',                 # Security baseline assessments
    'SecurityBaselineSummary',          # Security baseline summary
    'SecurityDetection',                # Security detections
    'ProtectionStatus',                 # Endpoint protection status
    'Update',                           # Windows Update status (when Update Management not running)
    'UpdateSummary',                    # Windows Update summary (when Update Management not running)
    'MDCFileIntegrityMonitoringEvents', # Microsoft Defender for Cloud FIM events
    'WindowsEvent',                     # Windows Event logs (newer schema)
    'LinuxAuditLog'                     # Linux audit logs
)

#region Helper Functions

function Get-SafeProperty {
    <#
    .SYNOPSIS
    Safely gets a property value from an object, returning $null if it doesn't exist.
    #>
    [CmdletBinding()]
    param(
        [PSObject]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties[$PropertyName]) {
        return $Object.$PropertyName
    }
    return $null
}

function Invoke-RestMethodWithRetry {
    <#
    .SYNOPSIS
    Invokes a REST method with retry logic for transient failures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $false)]
        [object]$Body = $null,
        [int]$MaxRetries = 3,
        [int]$InitialDelaySeconds = 2
    )

    $attempt = 0
    $delay = $InitialDelaySeconds

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $params = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                ErrorAction = 'Stop'
            }
            if ($Body) {
                $params['Body'] = ($Body | ConvertTo-Json -Depth 20)
                $params['ContentType'] = 'application/json'
            }
            return Invoke-RestMethod @params
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            # Retry on transient errors: 429 (throttling), 500, 502, 503, 504
            if ($statusCode -in @(429, 500, 502, 503, 504) -and $attempt -lt $MaxRetries) {
                Write-Verbose "API call failed with status $statusCode. Retry $attempt of $MaxRetries in $delay seconds..."
                Start-Sleep -Seconds $delay
                $delay = $delay * 2  # Exponential backoff
            }
            else {
                throw
            }
        }
    }
}

function Format-Plural {
    [CmdletBinding()]
    param(
        [int]$Count,
        [string]$Singular,
        [string]$Plural = $null
    )
    if (-not $Plural) { $Plural = "${Singular}s" }
    $noun = if ($Count -eq 1) { $Singular } else { $Plural }
    return "$Count $noun"
}

function Format-DataSize {
    <#
    .SYNOPSIS
    Formats a data size in GB to the most appropriate unit (MB, GB, or TB).
    #>
    [CmdletBinding()]
    param(
        [double]$SizeInGB,
        [int]$DecimalPlaces = 2
    )

    if ($SizeInGB -eq 0) {
        return "0 MB"
    }
    elseif ($SizeInGB -lt 1) {
        # Show in MB
        $sizeInMB = $SizeInGB * 1024
        return "$([math]::Round($sizeInMB, $DecimalPlaces)) MB"
    }
    elseif ($SizeInGB -ge 1000) {
        # Show in TB
        $sizeInTB = $SizeInGB / 1024
        return "$([math]::Round($sizeInTB, $DecimalPlaces)) TB"
    }
    else {
        # Show in GB
        return "$([math]::Round($SizeInGB, $DecimalPlaces)) GB"
    }
}

#endregion Helper Functions

#region Authentication Functions

function Get-AzureAccessToken {
    <#
    .SYNOPSIS
    Gets an Azure access token for the management API.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    try {
        $tokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $Context.Account,
            $Context.Environment,
            $Context.Tenant.Id,
            $null,
            "Never",
            $null,
            "https://management.azure.com/"
        )

        if (-not $tokenRequest -or -not $tokenRequest.AccessToken) {
            throw "Failed to obtain access token."
        }

        return @{
            Token      = $tokenRequest.AccessToken
            ExpiresOn  = $tokenRequest.ExpiresOn
            ObtainedAt = Get-Date
        }
    }
    catch {
        throw "Failed to acquire access token: $_"
    }
}

function Update-TokenIfNeeded {
    <#
    .SYNOPSIS
    Refreshes the access token if it's close to expiration (45 minutes).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$TokenInfo,
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    $tokenAge = (Get-Date) - $TokenInfo.ObtainedAt
    if ($tokenAge.TotalMinutes -ge 45) {
        Write-Verbose "Token is $([math]::Round($tokenAge.TotalMinutes)) minutes old, refreshing..."
        return Get-AzureAccessToken -Context $Context
    }
    return $TokenInfo
}

function Test-LogAnalyticsAuth {
    <#
    .SYNOPSIS
    Tests Log Analytics authentication and triggers re-auth if needed.
    Returns $true if authentication is valid, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [string]$SubscriptionId
    )

    # Simple test query
    $testQuery = "Usage | take 1"

    try {
        $null = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $testQuery -ErrorAction Stop
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message

        # Check if it's an authentication error requiring Log Analytics scope
        if ($errorMsg -match "Authentication failed" -or $errorMsg -match "OperationalInsightsEndpointResourceId" -or $errorMsg -match "credentials have not been set up") {
            Write-Host "    Log Analytics requires additional authentication scope." -ForegroundColor Yellow
            Write-Host "    Re-authenticating (browser window may open)..." -ForegroundColor Yellow

            try {
                # Disconnect and reconnect with the Log Analytics scope
                Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
                Connect-AzAccount -SubscriptionId $SubscriptionId -AuthScope "https://api.loganalytics.io" -ErrorAction Stop | Out-Null
                Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

                # Test again
                $null = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $testQuery -ErrorAction Stop
                Write-Host "    Authentication successful." -ForegroundColor Green
                return $true
            }
            catch {
                Write-Warning "    Re-authentication failed: $_"
                return $false
            }
        }
        else {
            Write-Verbose "Log Analytics auth test failed with non-auth error: $_"
            return $false
        }
    }
}

function Get-GraphAccessToken {
    <#
    .SYNOPSIS
    Gets a Microsoft Graph access token using the current Azure session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    try {
        $tokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $Context.Account,
            $Context.Environment,
            $Context.Tenant.Id,
            $null,
            "Never",
            $null,
            "https://graph.microsoft.com/"
        )

        if (-not $tokenRequest -or -not $tokenRequest.AccessToken) {
            throw "Failed to obtain Graph access token."
        }

        return $tokenRequest.AccessToken
    }
    catch {
        Write-Verbose "Failed to acquire Graph access token: $_"
        return $null
    }
}

#endregion Authentication Functions

#region Defender for Servers P2 Functions

function Get-DefenderServersP2Benefit {
    <#
    .SYNOPSIS
    Checks if Defender for Servers P2 is enabled and calculates the daily data benefit.

    .DESCRIPTION
    Defender for Servers P2 includes 500 MB/day per protected VM for:
    - Security data types in Log Analytics
    - See: https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-servers

    .PARAMETER SubscriptionId
    The Azure subscription ID to check.

    .PARAMETER AuthHeader
    The authorization header with Bearer token for ARM API calls.

    .PARAMETER WorkspaceId
    The Log Analytics workspace ID for querying protected VM count.

    .PARAMETER SkipKqlQueries
    If true, skip the KQL query and return null for protected VM count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [hashtable]$AuthHeader,
        [Parameter(Mandatory = $false)]
        [string]$WorkspaceId,
        [Parameter(Mandatory = $false)]
        [switch]$SkipKqlQueries
    )

    $result = @{
        Enabled           = $false
        PricingTier       = 'Free'
        ProtectedVMCount  = 0
        DailyBenefitGB    = 0
        VMCountMethod     = 'None'  # Track how VM count was determined
        CheckedAt         = Get-Date
    }

    try {
        # Query Defender for Cloud pricing configuration for VirtualMachines
        $pricingUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2024-01-01"
        $pricingResponse = Invoke-RestMethodWithRetry -Uri $pricingUri -Method 'GET' -Headers $AuthHeader

        if ($pricingResponse -and $pricingResponse.properties) {
            $pricingTier = $pricingResponse.properties.pricingTier
            $result.PricingTier = $pricingTier

            # P2 is indicated by pricingTier = 'Standard' and subPlan = 'P2'
            $subPlan = Get-SafeProperty $pricingResponse.properties 'subPlan'
            if ($pricingTier -eq 'Standard' -and $subPlan -eq 'P2') {
                $result.Enabled = $true
                Write-Verbose "Defender for Servers P2 is enabled (subPlan: $subPlan)"
            } elseif ($pricingTier -eq 'Standard') {
                # P1 or standard without subPlan specified
                Write-Verbose "Defender for Servers is enabled but not P2 (subPlan: $subPlan)"
            } else {
                Write-Verbose "Defender for Servers is not enabled (tier: $pricingTier)"
            }
        }

        # If P2 is enabled and we have a workspace, count protected VMs
        # Use multiple methods and pick the most reliable result
        if ($result.Enabled -and $WorkspaceId -and -not $SkipKqlQueries) {
            # Method 1 (Primary): Count VMs from Heartbeat with proper resource type filtering
            # This is a reasonable proxy for VMs reporting to the workspace
            $vmCountQuery = @"
Heartbeat
| where TimeGenerated > ago(1d)
| where ResourceType =~ 'virtualMachines' or ResourceType =~ 'servers' or isempty(ResourceType)
| distinct Computer
| count
"@
            $vmCountResult = Invoke-SentinelKqlQuery -WorkspaceId $WorkspaceId -Query $vmCountQuery
            if ($vmCountResult -and $vmCountResult.Count -gt 0 -and [int]$vmCountResult[0].Count -gt 0) {
                $result.ProtectedVMCount = [int]$vmCountResult[0].Count
                $result.VMCountMethod = 'Heartbeat'
                Write-Verbose "VM count from Heartbeat: $($result.ProtectedVMCount)"
            }

            # Method 2 (Fallback): Count unique computers from P2-eligible security tables
            # More accurate for actual security data producers if Heartbeat doesn't work
            if ($result.ProtectedVMCount -eq 0) {
                $p2ActiveVMsQuery = @"
union withsource=TableName SecurityEvent, WindowsEvent, LinuxAuditLog
| where TimeGenerated > ago(1d)
| distinct Computer
| count
"@
                $p2VMCountResult = Invoke-SentinelKqlQuery -WorkspaceId $WorkspaceId -Query $p2ActiveVMsQuery
                if ($p2VMCountResult -and $p2VMCountResult.Count -gt 0 -and [int]$p2VMCountResult[0].Count -gt 0) {
                    $result.ProtectedVMCount = [int]$p2VMCountResult[0].Count
                    $result.VMCountMethod = 'P2Tables'
                    Write-Verbose "VM count from P2-eligible tables: $($result.ProtectedVMCount)"
                }
            }

            # Calculate benefit if we have a VM count
            if ($result.ProtectedVMCount -gt 0) {
                # 500 MB per VM per day = 0.5 GB
                $result.DailyBenefitGB = $result.ProtectedVMCount * 0.5
                Write-Verbose "Protected VM count: $($result.ProtectedVMCount) (method: $($result.VMCountMethod)), Daily benefit: $($result.DailyBenefitGB) GB"
            }
        }
    }
    catch {
        Write-Verbose "Failed to check Defender for Servers P2 status: $_"
    }

    return $result
}

#endregion Defender for Servers P2 Functions

#region Dedicated Cluster Functions

function Get-DedicatedClusterInfo {
    <#
    .SYNOPSIS
    Checks if the workspace is linked to a Log Analytics dedicated cluster and retrieves cluster details.

    .DESCRIPTION
    Log Analytics dedicated clusters can reduce costs when ingesting at least 100 GB/day.
    Benefits include:
    - Aggregated data volume across multiple workspaces sharing a commitment tier
    - Faster cross-workspace queries when all workspaces are in the same cluster
    - Customer-managed keys for data encryption
    - Reduced effective cost per GB at higher commitment tiers

    See: https://learn.microsoft.com/en-us/azure/sentinel/billing-reduce-costs#optimize-log-analytics-costs-with-dedicated-clusters
    See: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-dedicated-clusters

    Technical constraints:
    - Maximum 2 clusters per region per subscription
    - All linked workspaces must be in the same region as the cluster
    - Maximum 1,000 workspaces per cluster
    - Workspace linking operations limited to 2 per 30-day period
    - Minimum commitment tier is 100 GB/day (previously 500 GB, reduced in 2023)

    .PARAMETER WorkspaceConfig
    The workspace configuration object containing the workspace properties.

    .PARAMETER SubscriptionId
    The Azure subscription ID.

    .PARAMETER AuthHeader
    The authorization header with Bearer token for ARM API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$WorkspaceConfig,
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [hashtable]$AuthHeader
    )

    $result = @{
        IsLinkedToCluster     = $false
        ClusterResourceId     = $null
        ClusterName           = $null
        ClusterCapacityTier   = $null
        ClusterBillingType    = $null
        ClusterSku            = $null
        LinkedWorkspaceCount  = $null
        ErrorMessage          = $null
        CheckedAt             = Get-Date
    }

    try {
        # Check if workspace is linked to a cluster via the features.clusterResourceId property
        $wsProps = Get-SafeProperty $WorkspaceConfig 'properties'
        $wsFeatures = Get-SafeProperty $wsProps 'features'
        $clusterResourceId = Get-SafeProperty $wsFeatures 'clusterResourceId'

        if ($clusterResourceId) {
            $result.IsLinkedToCluster = $true
            $result.ClusterResourceId = $clusterResourceId
            Write-Verbose "Workspace is linked to cluster: $clusterResourceId"

            # Extract cluster name from resource ID
            if ($clusterResourceId -match '/clusters/([^/]+)$') {
                $result.ClusterName = $matches[1]
            }

            # Try to get cluster details
            try {
                $clusterUri = "https://management.azure.com$clusterResourceId`?api-version=2023-09-01"
                $clusterResponse = Invoke-RestMethodWithRetry -Uri $clusterUri -Method 'GET' -Headers $AuthHeader

                if ($clusterResponse -and $clusterResponse.properties) {
                    $clusterProps = $clusterResponse.properties
                    $clusterSku = Get-SafeProperty $clusterResponse 'sku'

                    $result.ClusterSku = Get-SafeProperty $clusterSku 'name'
                    $result.ClusterCapacityTier = Get-SafeProperty $clusterSku 'capacity'
                    $result.ClusterBillingType = Get-SafeProperty $clusterProps 'billingType'

                    Write-Verbose "Cluster capacity: $($result.ClusterCapacityTier) GB/day, Billing: $($result.ClusterBillingType)"
                }
            }
            catch {
                Write-Verbose "Could not retrieve cluster details: $_"
                # Not critical - we still know the workspace is linked
            }
        }
        else {
            Write-Verbose "Workspace is not linked to a dedicated cluster"
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Verbose "Failed to check dedicated cluster status: $_"
    }

    return $result
}

#endregion Dedicated Cluster Functions

#region Sentinel Pricing Model Detection

function Get-SentinelPricingModel {
    <#
    .SYNOPSIS
    Detects whether the workspace is using Simplified or Classic pricing.

    .DESCRIPTION
    Queries the Microsoft Sentinel solution resource to determine the pricing model.
    See: https://learn.microsoft.com/en-us/azure/sentinel/enroll-simplified-pricing-tier

    Pricing Models:
    - Simplified (Unified): Single combined meter for Log Analytics + Sentinel
    - Classic: Two separate meters (Log Analytics ingestion + Sentinel analysis)

    The pricing model is indicated by the solution's sku.name property:
    - "Unified" = Simplified pricing
    - "PerGB" or "capacityreservation" = Classic pricing

    .PARAMETER SubscriptionId
    The Azure subscription ID.

    .PARAMETER ResourceGroupName
    The resource group containing the workspace.

    .PARAMETER WorkspaceName
    The Log Analytics workspace name.

    .PARAMETER AuthHeader
    The authorization header with Bearer token for ARM API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceName,
        [Parameter(Mandatory = $true)]
        [hashtable]$AuthHeader
    )

    $result = @{
        PricingModel    = 'Unknown'
        SkuName         = $null
        CapacityTier    = $null
        DetectionMethod = 'None'
        ErrorMessage    = $null
    }

    try {
        # Query the Sentinel solution resource
        # The solution name follows the pattern "SecurityInsights(<workspaceName>)"
        $solutionName = "SecurityInsights($WorkspaceName)"
        $solutionUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationsManagement/solutions/$solutionName`?api-version=2015-11-01-preview"

        Write-Verbose "Querying Sentinel solution: $solutionUri"
        $solutionResponse = Invoke-RestMethodWithRetry -Uri $solutionUri -Method 'GET' -Headers $AuthHeader

        if ($solutionResponse -and $solutionResponse.properties -and $solutionResponse.properties.sku) {
            $skuName = $solutionResponse.properties.sku.name
            $result.SkuName = $skuName
            $result.DetectionMethod = 'SentinelSolution'

            # Check for capacity reservation level
            $capacityLevel = Get-SafeProperty $solutionResponse.properties.sku 'capacityReservationLevel'
            if ($capacityLevel) {
                $result.CapacityTier = $capacityLevel
            }

            # Determine pricing model based on SKU name
            # See: https://learn.microsoft.com/en-us/azure/sentinel/enroll-simplified-pricing-tier
            switch -Regex ($skuName) {
                '^Unified$' {
                    $result.PricingModel = 'Simplified'
                    Write-Verbose "Detected Simplified pricing (SKU: Unified)"
                }
                '^PerGB$' {
                    $result.PricingModel = 'Classic'
                    Write-Verbose "Detected Classic pricing (SKU: PerGB)"
                }
                '^capacityreservation$' {
                    $result.PricingModel = 'Classic'
                    Write-Verbose "Detected Classic pricing (SKU: capacityreservation)"
                }
                default {
                    # Unknown SKU - might be a new pricing model
                    $result.PricingModel = 'Unknown'
                    Write-Verbose "Unknown SKU name: $skuName"
                }
            }
        }
        else {
            Write-Verbose "Sentinel solution response did not contain expected sku property"
            $result.ErrorMessage = "Solution SKU property not found"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Verbose "Failed to query Sentinel solution: $errorMsg"
        $result.ErrorMessage = $errorMsg

        # If the solution query fails (e.g., permissions), try to infer from workspace
        # This is a fallback and less reliable
        $result.DetectionMethod = 'Failed'
    }

    return $result
}

#endregion Sentinel Pricing Model Detection

#region Data Collection Functions

function Get-E5LicenseCount {
    <#
    .SYNOPSIS
    Retrieves E5/A5/F5/G5 license counts from Microsoft Graph API.
    Returns the total enabled seats across all qualifying SKUs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GraphToken
    )

    # E5-tier SKU part numbers that include the 5MB/user/day Sentinel data grant
    # See: https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer/
    # NOTE: E3 licenses do NOT qualify for the Sentinel data grant
    $e5SkuPartNumbers = @(
        'SPE_E5',                    # Microsoft 365 E5
        'ENTERPRISEPREMIUM',         # Office 365 E5
        'M365_E5',                   # Microsoft 365 E5 (alternate)
        'Microsoft_365_E5_(no_Teams)', # Microsoft 365 E5 without Teams (separate Teams licensing)
        'IDENTITY_THREAT_PROTECTION', # Microsoft 365 E5 Security
        'M365_E5_SUITE_COMPONENTS',  # Microsoft 365 E5 Suite features
        'SPE_E5_NOPSTNCONF',         # Microsoft 365 E5 without Audio Conferencing
        'M365_SECURITY_COMPLIANCE_FOR_FLW', # Microsoft 365 F5 Security + Compliance
        'SPE_F5_SEC',                # Microsoft 365 F5 Security Add-on
        'SPE_F5_SECCOMP',            # Microsoft 365 F5 Security + Compliance Add-on
        'M365_G5_GCC',               # Microsoft 365 G5 GCC
        'SPE_E5_GCC',                # Microsoft 365 E5 GCC (Government)
        'SPE_E5_GOV',                # Microsoft 365 E5 Government
        'MICROSOFT_365_E5_DEVELOPER', # Microsoft 365 E5 Developer
        'M365EDU_A5_STUDENT',        # Microsoft 365 A5 for students
        'M365EDU_A5_FACULTY',        # Microsoft 365 A5 for faculty
        'M365EDU_A5_STUUSEBNFT',     # Microsoft 365 A5 student use benefit
        'SPE_E5_CALLINGMINUTES',     # Microsoft 365 E5 with calling minutes
        'INFORMATION_PROTECTION_COMPLIANCE' # Microsoft 365 E5 Compliance
    )

    try {
        $headers = @{
            'Authorization' = "Bearer $GraphToken"
            'Content-Type'  = 'application/json'
        }

        $uri = "https://graph.microsoft.com/v1.0/subscribedSkus"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop

        # Check if we got any SKUs at all - if empty, likely a permissions issue
        $allSkus = $response.value
        if (-not $allSkus -or $allSkus.Count -eq 0) {
            Write-Verbose "Graph API returned no SKUs - this typically indicates insufficient permissions (Organization.Read.All required)"
            return @{
                TotalSeats       = 0
                SkuDetails       = @()
                PermissionIssue  = $true
                TotalSkusFound   = 0
            }
        }

        $totalSeats = 0
        $skuDetails = @()
        $allSkuDetails = @()

        foreach ($sku in $allSkus) {
            $skuPartNumber = $sku.skuPartNumber
            $enabledUnits = $sku.prepaidUnits.enabled
            $consumedUnits = $sku.consumedUnits
            $isE5Eligible = $e5SkuPartNumbers -contains $skuPartNumber

            $allSkuDetails += [PSCustomObject]@{
                SkuPartNumber = $skuPartNumber
                EnabledUnits  = $enabledUnits
                ConsumedUnits = $consumedUnits
                IsE5Eligible  = $isE5Eligible
            }

            if ($isE5Eligible) {
                $totalSeats += $enabledUnits

                $skuDetails += [PSCustomObject]@{
                    SkuPartNumber = $skuPartNumber
                    DisplayName   = $sku.skuPartNumber
                    EnabledUnits  = $enabledUnits
                    ConsumedUnits = $consumedUnits
                }
            }
        }

        return @{
            TotalSeats         = $totalSeats
            SkuDetails         = $skuDetails
            PermissionIssue    = $false
            TotalSkusFound     = $allSkus.Count
            AllSkuDetails      = $allSkuDetails
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match '403|Forbidden|Authorization_RequestDenied|Insufficient privileges') {
            Write-Verbose "Graph API permission denied for subscribedSkus. Organization.Read.All permission required."
            return @{
                TotalSeats       = 0
                SkuDetails       = @()
                PermissionIssue  = $true
                ErrorMessage     = "Organization.Read.All permission required"
            }
        } else {
            Write-Verbose "Failed to retrieve E5 license information: $_"
            return @{
                TotalSeats       = 0
                SkuDetails       = @()
                PermissionIssue  = $true
                ErrorMessage     = $errorMsg
            }
        }
    }
}

function Get-RegionCurrencyMapping {
    <#
    .SYNOPSIS
    Maps Azure regions to their likely billing currencies.
    #>
    [CmdletBinding()]
    param(
        [string]$Region
    )

    $regionCurrencyMap = @{
        # Australia
        'australiaeast'      = 'AUD'
        'australiasoutheast' = 'AUD'
        'australiacentral'   = 'AUD'
        'australiacentral2'  = 'AUD'
        # Europe
        'westeurope'         = 'EUR'
        'northeurope'        = 'EUR'
        'francecentral'      = 'EUR'
        'francesouth'        = 'EUR'
        'germanywestcentral' = 'EUR'
        'germanynorth'       = 'EUR'
        'italynorth'         = 'EUR'
        'swedencentral'      = 'EUR'
        'switzerlandnorth'   = 'CHF'
        'switzerlandwest'    = 'CHF'
        'norwayeast'         = 'NOK'
        'norwaywest'         = 'NOK'
        # UK
        'uksouth'            = 'GBP'
        'ukwest'             = 'GBP'
        # Canada
        'canadacentral'      = 'CAD'
        'canadaeast'         = 'CAD'
        # Brazil
        'brazilsouth'        = 'BRL'
        'brazilsoutheast'    = 'BRL'
        # Japan
        'japaneast'          = 'JPY'
        'japanwest'          = 'JPY'
        # Korea
        'koreacentral'       = 'KRW'
        'koreasouth'         = 'KRW'
        # India
        'centralindia'       = 'INR'
        'southindia'         = 'INR'
        'westindia'          = 'INR'
        # South Africa
        'southafricanorth'   = 'ZAR'
        'southafricawest'    = 'ZAR'
        # UAE
        'uaenorth'           = 'AED'
        'uaecentral'         = 'AED'
        # Default US regions and all others
    }

    if ($regionCurrencyMap.ContainsKey($Region)) {
        return $regionCurrencyMap[$Region]
    }
    return 'USD'
}

function Get-SentinelPricingInfo {
    <#
    .SYNOPSIS
    Retrieves Microsoft Sentinel pricing information from the Azure Retail Prices API.

    .NOTES
    Uses the Azure Retail Prices REST API (unauthenticated).
    See: https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices

    Filter values are case-sensitive in API v2023-01-01-preview and later.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $false)]
        [string]$Currency = 'USD'
    )

    try {
        # Build the API filter for Sentinel pricing
        # Note: serviceName is case-sensitive in preview API
        $baseUri = "https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview"
        $filter = "armRegionName eq '$Region' and serviceName eq 'Sentinel'"
        $uri = "$baseUri&currencyCode='$Currency'&`$filter=$filter"

        $allPrices = @()
        do {
            $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
            if ($response.Items) {
                $allPrices += $response.Items
            }
            $uri = $response.NextPageLink
        } while ($uri)

        # Parse pricing tiers
        $payAsYouGo = 0
        $commitmentTiers = @()
        $basicLogsRate = 0
        $auxiliaryLogsRate = 0

        Write-Verbose "Parsing $($allPrices.Count) pricing records from API..."

        foreach ($price in $allPrices) {
            $meterName = $price.meterName
            $unitPrice = $price.unitPrice
            $skuName = $price.skuName
            $productName = $price.productName

            Write-Verbose "  Meter: '$meterName' | SKU: '$skuName' | Product: '$productName' | Price: $unitPrice"

            # Skip reserved/spot pricing and free meters
            if ($price.type -eq 'Reservation' -or $price.type -eq 'DevTestConsumption') {
                Write-Verbose "    -> Skipped (type: $($price.type))"
                continue
            }

            # Pay-As-You-Go (Analysis) - meter name is "Pay-as-you-go Analysis" or just "Analysis"
            if ($meterName -match '(^Analysis$|Pay-as-you-go Analysis)' -and $unitPrice -gt 0) {
                $payAsYouGo = $unitPrice
                Write-Verbose "    -> Matched as Pay-As-You-Go: $unitPrice"
            }
            # Commitment tiers - match with or without "Capacity Reservation" suffix
            elseif ($meterName -match '^(\d+) GB Commitment Tier') {
                $tierGB = [int]$matches[1]
                $effectivePerGB = if ($tierGB -gt 0) { [math]::Round($unitPrice / $tierGB, 4) } else { 0 }
                $commitmentTiers += [PSCustomObject]@{
                    TierGB        = $tierGB
                    DailyRate     = $unitPrice
                    EffectivePerGB = $effectivePerGB
                }
                Write-Verbose "    -> Matched as Commitment Tier: $tierGB GB/day @ $unitPrice"
            }
            # Basic Logs
            elseif ($meterName -match 'Basic Logs') {
                $basicLogsRate = $unitPrice
                Write-Verbose "    -> Matched as Basic Logs: $unitPrice"
            }
            # Auxiliary Logs
            elseif ($meterName -match 'Auxiliary Logs') {
                $auxiliaryLogsRate = $unitPrice
                Write-Verbose "    -> Matched as Auxiliary Logs: $unitPrice"
            }
            else {
                Write-Verbose "    -> Not matched"
            }
        }

        # Sort commitment tiers by GB
        if ($commitmentTiers.Count -gt 0) {
            $commitmentTiers = @($commitmentTiers | Sort-Object TierGB)
        } else {
            $commitmentTiers = @()
        }

        # If PAYG wasn't found directly, estimate from the 100GB tier
        # (PAYG is typically ~15-20% more expensive than the lowest commitment tier)
        if ($payAsYouGo -eq 0 -and $commitmentTiers.Count -gt 0) {
            $lowestTier = $commitmentTiers[0]
            # Estimate PAYG as ~18% higher than the 100GB tier effective rate
            $payAsYouGo = [math]::Round($lowestTier.EffectivePerGB * 1.18, 4)
            Write-Verbose "PAYG rate not found directly - estimated from 100GB tier: $payAsYouGo"
        }

        Write-Verbose "Parsed pricing: PAYG=$payAsYouGo, CommitmentTiers=$($commitmentTiers.Count), BasicLogs=$basicLogsRate"

        # Note: Pricing model (Simplified vs Classic) is NOT determined here.
        # It must be queried from the Sentinel solution resource using Get-SentinelPricingModel.

        # Fetch retention pricing
        # Retention pricing - two different models:
        # 1. Log Analytics Archive (older model) - uses "Data Archive" from Azure Monitor
        # 2. Sentinel Data Lake (newer preview) - uses separate Sentinel meters
        $analyticsRetentionRate = 0   # Log Analytics interactive retention beyond free period
        $archiveRetentionRate = 0     # Log Analytics Archive (long-term retention) - ~$0.02/GB/month
        $dataLakeStorageRate = 0      # Sentinel Data Lake monthly storage cost
        $dataLakeIngestionRate = 0    # Sentinel Data Lake one-time ingestion cost
        $dataLakeQueryRate = 0        # Sentinel Data Lake per-query cost
        $dataLakeProcessingRate = 0   # Sentinel Data Lake data processing cost (transformations)

        try {
            # Analytics tier retention is under "Log Analytics" service
            # Meter name: "Analytics Logs Data Retention"
            $retentionFilter = "armRegionName eq '$Region' and serviceName eq 'Log Analytics'"
            $retentionUri = "$baseUri&currencyCode='$Currency'&`$filter=$retentionFilter"

            $retentionPrices = @()
            do {
                $retentionResponse = Invoke-RestMethod -Uri $retentionUri -Method Get -ErrorAction Stop
                if ($retentionResponse.Items) {
                    $retentionPrices += $retentionResponse.Items
                }
                $retentionUri = $retentionResponse.NextPageLink
            } while ($retentionUri)

            Write-Verbose "Parsing $($retentionPrices.Count) Log Analytics pricing records for retention..."

            foreach ($price in $retentionPrices) {
                $meterName = $price.meterName
                $unitPrice = $price.unitPrice

                # Skip reserved/spot pricing
                if ($price.type -eq 'Reservation' -or $price.type -eq 'DevTestConsumption') {
                    continue
                }

                # Analytics tier retention (Interactive Retention)
                # Meter: "Analytics Logs Data Retention" or "Data Retention"
                if ($meterName -match '(Analytics Logs )?Data Retention$' -and $unitPrice -gt 0) {
                    $analyticsRetentionRate = $unitPrice
                    Write-Verbose "    -> Analytics tier retention: $unitPrice/GB/month"
                }
            }

            # Log Analytics Archive pricing (from Azure Monitor - the older long-term retention model)
            # Meter: "Data Archive" - monthly storage cost
            $archiveFilter = "armRegionName eq '$Region' and serviceName eq 'Azure Monitor'"
            $archiveUri = "$baseUri&currencyCode='$Currency'&`$filter=$archiveFilter"

            $archivePrices = @()
            do {
                $archiveResponse = Invoke-RestMethod -Uri $archiveUri -Method Get -ErrorAction Stop
                if ($archiveResponse.Items) {
                    $archivePrices += $archiveResponse.Items
                }
                $archiveUri = $archiveResponse.NextPageLink
            } while ($archiveUri)

            Write-Verbose "Parsing $($archivePrices.Count) Azure Monitor pricing records for Archive retention..."

            foreach ($price in $archivePrices) {
                $meterName = $price.meterName
                $unitPrice = $price.unitPrice

                # Skip reserved/spot pricing
                if ($price.type -eq 'Reservation' -or $price.type -eq 'DevTestConsumption') {
                    continue
                }

                # Log Analytics Archive (long-term retention) - "Data Archive"
                if ($meterName -match '^Data Archive$' -and $unitPrice -gt 0) {
                    $archiveRetentionRate = $unitPrice
                    Write-Verbose "    -> Log Analytics Archive: $unitPrice/GB/month"
                }
            }

            # Sentinel Data Lake tier pricing (from Sentinel meters already fetched)
            # This is the newer preview feature, separate from Log Analytics Archive
            # Meters:
            # - "Data lake storage Data Stored" - monthly storage cost
            # - "Data lake ingestion Data Processed" - one-time ingestion cost
            # - "Data lake query Data Analyzed" - per-query cost
            foreach ($price in $allPrices) {
                $meterName = $price.meterName
                $unitPrice = $price.unitPrice

                if ($meterName -match '^Data lake storage' -and $unitPrice -gt 0) {
                    $dataLakeStorageRate = $unitPrice
                    Write-Verbose "    -> Sentinel Data Lake storage: $unitPrice/GB/month"
                }
                elseif ($meterName -match '^Data lake ingestion' -and $unitPrice -gt 0) {
                    $dataLakeIngestionRate = $unitPrice
                    Write-Verbose "    -> Sentinel Data Lake ingestion: $unitPrice/GB (one-time)"
                }
                elseif ($meterName -match '^Data lake query' -and $unitPrice -gt 0) {
                    $dataLakeQueryRate = $unitPrice
                    Write-Verbose "    -> Sentinel Data Lake query: $unitPrice/GB analyzed"
                }
                elseif ($meterName -match '^Data lake processing|^Data Processed' -and $unitPrice -gt 0) {
                    $dataLakeProcessingRate = $unitPrice
                    Write-Verbose "    -> Sentinel Data Lake processing: $unitPrice/GB (transformations)"
                }
            }
        }
        catch {
            Write-Verbose "Failed to retrieve retention pricing: $_"
        }

        return @{
            Region                   = $Region
            Currency                 = $Currency
            PayAsYouGo               = $payAsYouGo
            CommitmentTiers          = $commitmentTiers
            BasicLogsRate            = $basicLogsRate
            AuxiliaryLogsRate        = $auxiliaryLogsRate
            AnalyticsRetentionRate   = $analyticsRetentionRate   # ~$0.10/GB/month beyond free period
            # Log Analytics Archive (older long-term retention model)
            ArchiveRetentionRate     = $archiveRetentionRate     # ~$0.02/GB/month for archived data
            # Sentinel Data Lake tier pricing (newer preview - separate from Log Analytics Archive)
            DataLakeStorageRate      = $dataLakeStorageRate      # Monthly storage: ~$0.026/GB/month
            DataLakeIngestionRate    = $dataLakeIngestionRate    # One-time ingestion: ~$0.05/GB
            DataLakeQueryRate        = $dataLakeQueryRate        # Per-query: ~$0.005/GB analyzed
            DataLakeProcessingRate   = $dataLakeProcessingRate   # Per GB for transformations
            CurrentRetailPrices      = $allPrices
        }
    }
    catch {
        Write-Verbose "Failed to retrieve Sentinel pricing information: $_"
        return $null
    }
}

function Invoke-SentinelKqlQuery {
    <#
    .SYNOPSIS
    Executes a KQL query against the Log Analytics workspace using Az.OperationalInsights.
    #>
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [string]$Query
    )

    try {
        $queryResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -ErrorAction Stop

        if ($queryResult.Results) {
            return ,@($queryResult.Results)
        }
        return $null
    }
    catch {
        Write-Verbose "KQL query failed: $_"
        return $null
    }
}

function Get-TableRetentionSettings {
    <#
    .SYNOPSIS
    Retrieves retention settings for all tables in the workspace.

    .DESCRIPTION
    Queries the Log Analytics workspace to get retention settings for each table.
    Returns workspace default retention and per-table overrides.

    .PARAMETER SubscriptionId
    The Azure subscription ID.

    .PARAMETER ResourceGroupName
    The resource group containing the workspace.

    .PARAMETER WorkspaceName
    The Log Analytics workspace name.

    .PARAMETER AuthHeader
    The authorization header with Bearer token for ARM API calls.

    .NOTES
    Per-table retention settings:
    - RetentionInDays: Analytics tier retention (interactive, max 730 days)
    - TotalRetentionInDays: Total retention including Data Lake tier (max 4,383 days / 12 years)
    - Value of -1 means "inherit workspace default"

    Free retention periods:
    - Sentinel solution tables: 90 days
    - Standard Log Analytics tables: 31 days
    - Usage, AzureActivity: Fixed at 90 days (cannot be changed)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceName,
        [Parameter(Mandatory = $true)]
        [hashtable]$AuthHeader
    )

    $result = @{
        WorkspaceDefaultRetentionDays = 90  # Default fallback
        Tables                        = @{}
        TablesWithCustomRetention     = @()
        TablesUsingDataLake           = @()
        ErrorMessage                  = $null
    }

    try {
        # Get workspace default retention
        $workspaceUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName`?api-version=2023-09-01"
        $workspaceResponse = Invoke-RestMethodWithRetry -Uri $workspaceUri -Method 'GET' -Headers $AuthHeader

        if ($workspaceResponse -and $workspaceResponse.properties) {
            $result.WorkspaceDefaultRetentionDays = $workspaceResponse.properties.retentionInDays
            Write-Verbose "Workspace default retention: $($result.WorkspaceDefaultRetentionDays) days"
        }

        # Get all tables with their retention settings
        $tablesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables?api-version=2022-10-01"
        $tablesResponse = Invoke-RestMethodWithRetry -Uri $tablesUri -Method 'GET' -Headers $AuthHeader

        if ($tablesResponse -and $tablesResponse.value) {
            foreach ($table in $tablesResponse.value) {
                $tableName = $table.name
                $props = $table.properties

                # Get retention values (-1 or null means inherit workspace default)
                $retentionInDays = Get-SafeProperty $props 'retentionInDays'
                $totalRetentionInDays = Get-SafeProperty $props 'totalRetentionInDays'
                $plan = Get-SafeProperty $props 'plan'

                # Resolve effective retention (use workspace default if -1 or null)
                $effectiveRetention = if ($null -eq $retentionInDays -or $retentionInDays -eq -1) {
                    $result.WorkspaceDefaultRetentionDays
                } else {
                    $retentionInDays
                }

                $effectiveTotalRetention = if ($null -eq $totalRetentionInDays -or $totalRetentionInDays -eq -1) {
                    $effectiveRetention  # No archive by default
                } else {
                    $totalRetentionInDays
                }

                # Get archive retention days (Log Analytics long-term retention - the old model)
                # This is different from the new Sentinel Data Lake tier
                $archiveRetentionInDays = Get-SafeProperty $props 'archiveRetentionInDays'
                $effectiveArchiveRetention = if ($null -eq $archiveRetentionInDays -or $archiveRetentionInDays -le 0) {
                    0
                } else {
                    $archiveRetentionInDays
                }

                # Determine if this is a Sentinel solution table (90-day free) or standard table (31-day free)
                $isSentinelTable = $script:SentinelSolutionTables -contains $tableName

                # Check if table has fixed retention
                $isFixedRetention = $script:FixedRetentionTables.ContainsKey($tableName)

                # Determine retention model:
                # - Log Analytics Archive: plan=Analytics and archiveRetentionInDays > 0
                # - Sentinel Data Lake: Different plan type (not yet commonly used)
                $usesArchive = ($plan -eq 'Analytics' -and $effectiveArchiveRetention -gt 0)

                $result.Tables[$tableName] = @{
                    RetentionInDays          = $retentionInDays
                    TotalRetentionInDays     = $totalRetentionInDays
                    ArchiveRetentionInDays   = $archiveRetentionInDays
                    EffectiveRetention       = $effectiveRetention
                    EffectiveTotalRetention  = $effectiveTotalRetention
                    EffectiveArchiveRetention = $effectiveArchiveRetention
                    Plan                     = $plan
                    IsSentinelTable          = $isSentinelTable
                    IsFixedRetention         = $isFixedRetention
                    FreePeriodDays           = if ($isFixedRetention) { $script:FixedRetentionTables[$tableName] } elseif ($isSentinelTable) { 90 } else { 31 }
                    UsesArchive              = $usesArchive  # Log Analytics Archive (old model)
                }

                # Track tables with custom retention (different from workspace default)
                if ($null -ne $retentionInDays -and $retentionInDays -ne -1 -and $retentionInDays -ne $result.WorkspaceDefaultRetentionDays) {
                    $result.TablesWithCustomRetention += $tableName
                }

                # Track tables using Log Analytics Archive (long-term retention)
                if ($usesArchive) {
                    $result.TablesUsingDataLake += $tableName  # Keep property name for compatibility
                }
            }

            Write-Verbose "Retrieved retention settings for $($result.Tables.Count) tables"
            Write-Verbose "Tables with custom retention: $($result.TablesWithCustomRetention.Count)"
            Write-Verbose "Tables using Data Lake: $($result.TablesUsingDataLake.Count)"
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Verbose "Failed to retrieve table retention settings: $_"
    }

    return $result
}

function Get-RetentionCostAnalysis {
    <#
    .SYNOPSIS
    Calculates retention costs for the workspace based on table ingestion and retention settings.

    .DESCRIPTION
    For each table, calculates:
    - Analytics tier retention cost (beyond free period, up to RetentionInDays)
    - Data Lake tier retention cost (beyond RetentionInDays, up to TotalRetentionInDays)

    Free retention periods:
    - Sentinel solution tables: 90 days
    - Standard Log Analytics tables: 31 days

    Retention rates (approximate):
    - Analytics tier: ~$0.10/GB/month beyond free period
    - Data Lake tier: ~$0.026/GB/month (with 6:1 compression = ~$0.004/GB effective)

    .NOTES
    The calculation uses the steady-state model:
    - Daily ingestion accumulates in storage
    - At any point, you have (dailyGB * retentionDays) worth of data stored
    - Monthly cost = (dailyGB * billableDays) * rate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$TableRetention,
        [Parameter(Mandatory = $true)]
        [array]$TopTables,
        [Parameter(Mandatory = $true)]
        [hashtable]$PricingInfo
    )

    $result = @{
        TotalAnalyticsRetentionCost = 0
        TotalDataLakeRetentionCost  = 0
        TotalRetentionCost          = 0
        TableRetentionCosts         = @()
        RetentionOptimizationTips   = @()
    }

    $analyticsRate = $PricingInfo.AnalyticsRetentionRate
    # Log Analytics Archive (older long-term retention model)
    $archiveRate = $PricingInfo.ArchiveRetentionRate
    # Sentinel Data Lake tier (newer preview - separate pricing components)
    $dataLakeStorageRate = $PricingInfo.DataLakeStorageRate
    $dataLakeIngestionRate = $PricingInfo.DataLakeIngestionRate

    # Skip if we don't have any retention pricing
    if ($analyticsRate -eq 0 -and $archiveRate -eq 0 -and $dataLakeStorageRate -eq 0) {
        Write-Verbose "Retention pricing not available - skipping retention cost calculation"
        return $result
    }

    $daysPerMonth = 30.44  # Average days per month

    foreach ($table in $TopTables) {
        $tableName = $table.DataType
        $monthlyGB = [double]$table.TotalGB
        $dailyGB = $monthlyGB / 30  # 30-day period from query

        # Get retention settings for this table
        $retention = $null
        if ($TableRetention.Tables.ContainsKey($tableName)) {
            $retention = $TableRetention.Tables[$tableName]
        } else {
            # Use workspace defaults if table not found
            $isSentinelTable = $script:SentinelSolutionTables -contains $tableName
            $retention = @{
                EffectiveRetention      = $TableRetention.WorkspaceDefaultRetentionDays
                EffectiveTotalRetention = $TableRetention.WorkspaceDefaultRetentionDays
                IsSentinelTable         = $isSentinelTable
                IsFixedRetention        = $script:FixedRetentionTables.ContainsKey($tableName)
                FreePeriodDays          = if ($isSentinelTable) { 90 } else { 31 }
            }
        }

        # Skip tables with fixed retention (they're always free)
        if ($retention.IsFixedRetention) {
            continue
        }

        $freePeriod = $retention.FreePeriodDays
        $analyticsRetention = $retention.EffectiveRetention
        $totalRetention = $retention.EffectiveTotalRetention

        # Calculate billable analytics retention (beyond free period)
        $analyticsCost = 0
        $analyticsStoredGB = 0
        if ($analyticsRetention -gt $freePeriod) {
            # Days of data stored in Analytics tier beyond free period
            $billableAnalyticsDays = $analyticsRetention - $freePeriod
            # Total GB stored in the billable analytics period (steady state)
            $analyticsStoredGB = $dailyGB * $billableAnalyticsDays
            # Monthly cost for storing this data
            $analyticsCost = $analyticsStoredGB * $analyticsRate
        }

        # Calculate long-term retention cost (beyond Analytics tier)
        # There are two models:
        # 1. Log Analytics Archive (older) - simple monthly storage cost
        # 2. Sentinel Data Lake (newer preview) - storage + ingestion costs
        $archiveCost = 0
        $archiveStoredGB = 0

        # Check if table uses Log Analytics Archive (the older model)
        $usesArchive = $retention.UsesArchive
        $archiveRetentionDays = if ($retention.EffectiveArchiveRetention) { $retention.EffectiveArchiveRetention } else { 0 }

        if ($usesArchive -and $archiveRetentionDays -gt 0 -and $archiveRate -gt 0) {
            # Log Analytics Archive - simple monthly cost per GB stored
            $archiveStoredGB = $dailyGB * $archiveRetentionDays
            $archiveCost = $archiveStoredGB * $archiveRate
        }
        elseif ($totalRetention -gt $analyticsRetention -and $dataLakeStorageRate -gt 0) {
            # Sentinel Data Lake (fallback if not using Archive but has extended retention)
            # Data Lake tier has 6:1 compression ratio: 600 GB raw = 100 GB billed
            # See: https://learn.microsoft.com/en-us/azure/sentinel/billing?tabs=simplified%2Ccommitment-tiers#data-lake-tier
            $dataLakeDays = $totalRetention - $analyticsRetention
            $rawStoredGB = $dailyGB * $dataLakeDays
            # Apply 6:1 compression for storage billing
            $compressedStorageGB = $rawStoredGB / 6
            $archiveStoredGB = $rawStoredGB  # Keep raw for display purposes
            # Monthly storage (compressed) + amortized ingestion cost (uncompressed)
            $archiveCost = ($compressedStorageGB * $dataLakeStorageRate) + (($dailyGB * $daysPerMonth) * $dataLakeIngestionRate)
        }

        $totalTableCost = $analyticsCost + $archiveCost

        if ($totalTableCost -gt 0 -or $analyticsRetention -gt $freePeriod -or $totalRetention -gt $analyticsRetention) {
            $result.TableRetentionCosts += [PSCustomObject]@{
                TableName               = $tableName
                DailyGB                 = [math]::Round($dailyGB, 2)
                FreePeriodDays          = $freePeriod
                AnalyticsRetentionDays  = $analyticsRetention
                ArchiveRetentionDays    = $archiveRetentionDays
                TotalRetentionDays      = $totalRetention
                AnalyticsStoredGB       = [math]::Round($analyticsStoredGB, 2)
                ArchiveStoredGB         = [math]::Round($archiveStoredGB, 2)
                AnalyticsCost           = [math]::Round($analyticsCost, 2)
                ArchiveCost             = [math]::Round($archiveCost, 2)
                TotalCost               = [math]::Round($totalTableCost, 2)
                IsSentinelTable         = $retention.IsSentinelTable
                UsesArchive             = $usesArchive
            }
        }

        $result.TotalAnalyticsRetentionCost += $analyticsCost
        $result.TotalDataLakeRetentionCost += $archiveCost  # Keep property name for compatibility

        # Generate optimization tips for high-cost tables
        # If Analytics retention is expensive and table doesn't use Archive, suggest moving to Archive
        if ($analyticsCost -gt 50 -and -not $usesArchive -and $archiveRate -gt 0) {
            # Calculate potential savings from using Log Analytics Archive instead of Analytics retention
            $potentialArchiveCost = $analyticsStoredGB * $archiveRate
            $potentialSavings = $analyticsCost - $potentialArchiveCost
            if ($potentialSavings -gt 20) {
                $result.RetentionOptimizationTips += [PSCustomObject]@{
                    TableName        = $tableName
                    CurrentCost      = [math]::Round($analyticsCost, 2)
                    OptimizedCost    = [math]::Round($potentialArchiveCost, 2)
                    PotentialSavings = [math]::Round($potentialSavings, 2)
                    Recommendation   = "Move data beyond free period to Archive tier"
                }
            }
        }
    }

    $result.TotalAnalyticsRetentionCost = [math]::Round($result.TotalAnalyticsRetentionCost, 2)
    $result.TotalDataLakeRetentionCost = [math]::Round($result.TotalDataLakeRetentionCost, 2)
    $result.TotalRetentionCost = [math]::Round($result.TotalAnalyticsRetentionCost + $result.TotalDataLakeRetentionCost, 2)

    return $result
}

function Invoke-CostOptimizationAnalysis {
    <#
    .SYNOPSIS
    Analyzes ingestion patterns and recommends optimal pricing tier.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CollectedData
    )

    $result = @{
        CurrentTier               = 'Unknown'
        CurrentMonthlyCost        = 0
        OptimalTier               = 'Unknown'
        OptimalMonthlyCost        = 0
        PotentialSavings          = 0
        PotentialSavingsPercent   = 0
        E5GrantUtilization        = 0
        E5DailyGrantGB            = 0
        E5EligibleIngestionGB     = 0
        E5GrantUsedGB             = 0
        E5DailyOverageGB          = 0      # Average daily overage (accurate calculation)
        E5DaysWithOverage         = 0      # Number of days where E5 grant was exceeded
        E5MaxOverageGB            = 0      # Highest single-day overage
        E5TotalOverageGB          = 0      # Total overage across all days
        FreeIngestionGB           = 0
        DefenderP2BenefitGB       = 0
        BillableIngestionGB       = 0
        EffectiveDailyIngestionGB = 0
        PricingModel              = 'Unknown'
        TierComparison            = @()
        TopTablesAnalysis         = @()
        BasicLogsCandidates       = @()
        AuxiliaryLogsCandidates   = @()
        DataLakeCandidates        = @()
        DedicatedClusterRecommendation = $null  # Recommendation for dedicated cluster
        AnalysisNotes             = @()
    }

    # Get pricing info
    $pricing = $CollectedData.PricingInfo
    if (-not $pricing -or -not $pricing.PayAsYouGo) {
        $result.AnalysisNotes += "Pricing data not available for analysis."
        return $result
    }

    # Store pricing model (from Sentinel solution, not retail prices API)
    $pricingModelInfo = $CollectedData.SentinelPricingModel
    $result.PricingModel = if ($pricingModelInfo -and $pricingModelInfo.PricingModel) { $pricingModelInfo.PricingModel } else { 'Unknown' }

    # Calculate average daily ingestion from trend data
    $avgDailyIngestion = 0
    if ($CollectedData.IngestionTrend -and $CollectedData.IngestionTrend.Count -gt 0) {
        $avgDailyIngestion = ($CollectedData.IngestionTrend | Measure-Object -Property TotalGB -Average).Average
    }

    if ($avgDailyIngestion -eq 0) {
        $result.AnalysisNotes += "No ingestion data available for analysis."
        return $result
    }

    # Calculate free data ingestion (tables that are free in Sentinel)
    $freeIngestionDaily = 0.0
    if ($CollectedData.TopTables) {
        foreach ($table in $CollectedData.TopTables) {
            if ($script:FreeDataTables -contains $table.DataType) {
                # Convert 30-day total to daily average
                # Note: KQL returns strings, so cast to double
                $freeIngestionDaily += ([double]$table.TotalGB / 30)
            }
        }
    }
    $result.FreeIngestionGB = [math]::Round($freeIngestionDaily, 2)

    # Get Defender for Servers P2 benefit (available benefit based on VM count)
    $defenderP2BenefitGB = 0
    if ($CollectedData.DefenderServersP2 -and $CollectedData.DefenderServersP2.Enabled) {
        $defenderP2BenefitGB = $CollectedData.DefenderServersP2.DailyBenefitGB
    }
    $result.DefenderP2BenefitGB = [math]::Round($defenderP2BenefitGB, 2)

    # Calculate P2-eligible ingestion from top tables
    # The P2 benefit can only offset P2-eligible table ingestion, not total ingestion
    $p2EligibleIngestion = 0.0
    if ($CollectedData.TopTables) {
        foreach ($table in $CollectedData.TopTables) {
            if ($script:DefenderP2EligibleTables -contains $table.DataType) {
                $p2EligibleIngestion += [double]$table.TotalGB
            }
        }
        # Convert from 30-day total to daily average
        $p2EligibleIngestion = $p2EligibleIngestion / 30
    }
    $result.P2EligibleIngestionGB = [math]::Round($p2EligibleIngestion, 2)

    # Calculate billable ingestion (total minus free)
    $billableIngestion = [math]::Max(0.0, $avgDailyIngestion - $freeIngestionDaily)
    $result.BillableIngestionGB = [math]::Round($billableIngestion, 2)

    # Determine current tier
    $wsProps = Get-SafeProperty $CollectedData.WorkspaceConfig 'properties'
    $skuProps = Get-SafeProperty $wsProps 'sku'
    $currentCapacity = Get-SafeProperty $skuProps 'capacityReservationLevel'
    $skuName = Get-SafeProperty $skuProps 'name'

    if ($currentCapacity -and $currentCapacity -gt 0) {
        $result.CurrentTier = "$currentCapacity GB/day"
    } else {
        $result.CurrentTier = 'Pay-As-You-Go'
    }

    # E5 grant applies to specific Microsoft data sources (5 MB/user/day).
    # Official documentation:
    #   - https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer/
    #   - https://learn.microsoft.com/en-us/azure/sentinel/billing?tabs=simplified%2Ccommitment-tiers#microsoft-365-e5-a5-f5-and-g5-benefit
    #
    # Eligible data types per official documentation:
    # https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer/
    # - Microsoft Entra ID: Sign-in and audit logs
    # - Microsoft Defender for Cloud Apps: Shadow IT discovery
    # - Azure Information Protection: Classification events
    # - Microsoft 365 Defender Suite: Advanced hunting data
    $e5EligibleTables = @(
        # Microsoft Entra ID
        'SigninLogs', 'AuditLogs', 'AADNonInteractiveUserSignInLogs',
        'AADServicePrincipalSignInLogs', 'AADManagedIdentitySignInLogs',
        'AADProvisioningLogs', 'ADFSSignInLogs',
        # Microsoft Defender for Cloud Apps
        'McasShadowItReporting',
        # Azure Information Protection
        'InformationProtectionLogs_CL',
        # Microsoft 365 Defender Suite
        'DeviceEvents', 'DeviceFileEvents', 'DeviceImageLoadEvents',
        'DeviceInfo', 'DeviceLogonEvents', 'DeviceNetworkEvents',
        'DeviceNetworkInfo', 'DeviceProcessEvents', 'DeviceRegistryEvents',
        'DeviceFileCertificateInfo', 'DynamicEventCollection',
        'CloudAppEvents', 'EmailAttachmentInfo', 'EmailEvents',
        'EmailPostDeliveryEvents', 'EmailUrlInfo',
        'IdentityLogonEvents', 'IdentityQueryEvents', 'IdentityDirectoryEvents',
        'AlertEvidence', 'UrlClickEvents'
    )

    # Calculate E5 grant if available
    $e5Info = $CollectedData.E5LicenseInfo
    $e5DailyGrantGB = 0
    $e5EligibleIngestionRaw = 0  # Unrounded value for accurate calculation

    # Calculate eligible ingestion from top tables (needed for both E5 and top tables analysis)
    # Note: KQL returns strings, so we must cast to double to avoid string concatenation
    $eligibleIngestion = 0.0
    if ($CollectedData.TopTables) {
        foreach ($table in $CollectedData.TopTables) {
            if ($e5EligibleTables -contains $table.DataType) {
                $eligibleIngestion += [double]$table.TotalGB
            }
        }
        # Convert from 30-day total to daily average
        $eligibleIngestion = $eligibleIngestion / 30
    }
    $result.E5EligibleIngestionGB = [math]::Round($eligibleIngestion, 2)
    $e5EligibleIngestionRaw = $eligibleIngestion

    # Calculate accurate daily E5 overage using per-day data
    # The E5 benefit resets daily - unused grant cannot carry over to the next day
    # This means we must calculate overage per day, not from monthly averages
    $e5TotalOverageGB = 0.0
    $e5DaysWithOverage = 0
    $e5MaxOverageGB = 0.0
    $e5GrantUsed = 0.0

    if ($e5Info -and $e5Info.TotalSeats -gt 0) {
        # 5 MB per user per day = 0.005 GB per user per day
        $e5DailyGrantGB = $e5Info.TotalSeats * 0.005
        $result.E5DailyGrantGB = [math]::Round($e5DailyGrantGB, 2)

        # Use daily E5 ingestion data if available for accurate overage calculation
        if ($CollectedData.E5DailyIngestion -and $CollectedData.E5DailyIngestion.Count -gt 0) {
            foreach ($day in $CollectedData.E5DailyIngestion) {
                $dayEligible = [double]$day.DailyEligibleGB
                $dayOverage = [math]::Max(0.0, $dayEligible - $e5DailyGrantGB)
                $dayGrantUsed = [math]::Min($dayEligible, $e5DailyGrantGB)

                $e5TotalOverageGB += $dayOverage
                $e5GrantUsed += $dayGrantUsed
                if ($dayOverage -gt 0) { $e5DaysWithOverage++ }
                if ($dayOverage -gt $e5MaxOverageGB) { $e5MaxOverageGB = $dayOverage }
            }

            # Calculate averages based on actual days of data
            $daysCount = $CollectedData.E5DailyIngestion.Count
            $e5AvgDailyOverageGB = $e5TotalOverageGB / $daysCount
            $e5GrantUsed = $e5GrantUsed / $daysCount  # Average daily grant used

            $result.E5DailyOverageGB = [math]::Round($e5AvgDailyOverageGB, 2)
            $result.E5DaysWithOverage = $e5DaysWithOverage
            $result.E5MaxOverageGB = [math]::Round($e5MaxOverageGB, 2)
            $result.E5TotalOverageGB = [math]::Round($e5TotalOverageGB, 2)

            Write-Verbose "E5 Daily Calculation ($daysCount days):"
            Write-Verbose "  Days with overage    = $e5DaysWithOverage"
            Write-Verbose "  Total overage        = $e5TotalOverageGB GB"
            Write-Verbose "  Avg daily overage    = $e5AvgDailyOverageGB GB"
            Write-Verbose "  Max single-day       = $e5MaxOverageGB GB"
        } else {
            # Fallback to average-based calculation if daily data not available
            $e5GrantUsed = [math]::Min($e5EligibleIngestionRaw, $e5DailyGrantGB)
            Write-Verbose "E5 calculation: Using average-based fallback (daily data not available)"
        }

        # Calculate utilization (how much of the grant is being used)
        # The grant can only offset E5-eligible ingestion, not total ingestion
        if ($e5DailyGrantGB -gt 0) {
            $utilization = [math]::Min(100, [math]::Round(($e5GrantUsed / $e5DailyGrantGB) * 100, 1))
            $result.E5GrantUtilization = $utilization
        }
    }

    # Calculate effective billable ingestion after all deductions:
    # 1. Free data tables (always free in Sentinel)
    # 2. E5 grant (only applies to E5-eligible tables)
    # 3. Defender for Servers P2 benefit (500 MB/day per protected VM, capped by P2-eligible ingestion)
    #
    # IMPORTANT: P2 benefit is LIMITED to actual P2-eligible table ingestion
    # If P2 benefit (500 MB/VM/day * VM count) exceeds P2-eligible ingestion, the excess is unused
    $p2BenefitApplied = [math]::Min($defenderP2BenefitGB, $p2EligibleIngestion)
    $result.P2BenefitAppliedGB = [math]::Round($p2BenefitApplied, 2)

    # Calculate P2 benefit utilization
    if ($defenderP2BenefitGB -gt 0) {
        $p2Utilization = [math]::Min(100, [math]::Round(($p2BenefitApplied / $defenderP2BenefitGB) * 100, 1))
        $result.P2BenefitUtilization = $p2Utilization
    } else {
        $result.P2BenefitUtilization = 0
    }

    # Start with billable ingestion (total minus free), then apply deductions
    # Note: Must use 0.0 (double) not 0 (int) to avoid [math]::Max truncating the result
    $effectiveDailyIngestion = [math]::Max(0.0, $billableIngestion - $e5GrantUsed - $p2BenefitApplied)

    Write-Verbose "Cost Calculation Breakdown:"
    Write-Verbose "  Total Daily Ingestion      = $avgDailyIngestion GB"
    Write-Verbose "  Free Data Tables           = -$freeIngestionDaily GB"
    Write-Verbose "  Billable Ingestion         = $billableIngestion GB"
    Write-Verbose "  E5 Grant Available         = $e5DailyGrantGB GB"
    Write-Verbose "  E5-Eligible Ingestion      = $e5EligibleIngestionRaw GB"
    Write-Verbose "  E5 Grant Used (avg/day)    = -$e5GrantUsed GB"
    Write-Verbose "  P2 Benefit Available       = $defenderP2BenefitGB GB"
    Write-Verbose "  P2-Eligible Ingestion      = $p2EligibleIngestion GB"
    Write-Verbose "  P2 Benefit Applied         = -$p2BenefitApplied GB ($($result.P2BenefitUtilization)% utilized)"
    Write-Verbose "  Effective Billable         = $effectiveDailyIngestion GB"

    # Store for reporting
    $result.E5GrantUsedGB = [math]::Round($e5GrantUsed, 2)
    $result.EffectiveDailyIngestionGB = [math]::Round($effectiveDailyIngestion, 2)

    # Build top 10 tables analysis with per-table cost breakdown
    $topTablesAnalysis = @()
    if ($CollectedData.TopTables) {
        $daysInPeriod = 30  # Data is 30-day total

        # Calculate E5 grant allocation ratio (how much of the grant applies to each table)
        # Grant is allocated proportionally across E5-eligible tables
        $e5GrantRatio = if ($e5EligibleIngestionRaw -gt 0 -and $e5DailyGrantGB -gt 0) {
            [math]::Min(1.0, $e5DailyGrantGB / $e5EligibleIngestionRaw)
        } else { 0 }

        foreach ($table in ($CollectedData.TopTables | Select-Object -First 10)) {
            $tableName = $table.DataType
            $monthlyGB = [double]$table.TotalGB
            $dailyGB = $monthlyGB / $daysInPeriod

            # Determine table characteristics
            $isFree = $script:FreeDataTables -contains $tableName
            $isE5Eligible = $e5EligibleTables -contains $tableName

            # Calculate costs
            $rawMonthlyCost = $monthlyGB * $pricing.PayAsYouGo

            # Calculate E5 grant offset for this table
            $e5GrantAppliedGB = 0
            $e5GrantAppliedCost = 0
            if ($isE5Eligible -and $e5DailyGrantGB -gt 0) {
                # Proportional allocation: this table gets its share of the grant
                $e5GrantAppliedGB = $dailyGB * $e5GrantRatio * $daysInPeriod  # Monthly GB covered by grant
                $e5GrantAppliedCost = $e5GrantAppliedGB * $pricing.PayAsYouGo
            }

            # Effective cost after E5 grant (free tables are always $0)
            $effectiveMonthlyCost = if ($isFree) {
                0
            } else {
                [math]::Max(0, $rawMonthlyCost - $e5GrantAppliedCost)
            }

            $topTablesAnalysis += [PSCustomObject]@{
                TableName           = $tableName
                MonthlyGB           = [math]::Round($monthlyGB, 2)
                DailyGB             = [math]::Round($dailyGB, 2)
                IsFree              = $isFree
                IsE5Eligible        = $isE5Eligible
                RawMonthlyCost      = [math]::Round($rawMonthlyCost, 2)
                E5GrantAppliedGB    = [math]::Round($e5GrantAppliedGB, 2)
                E5GrantAppliedCost  = [math]::Round($e5GrantAppliedCost, 2)
                EffectiveMonthlyCost = [math]::Round($effectiveMonthlyCost, 2)
            }
        }
    }
    $result.TopTablesAnalysis = $topTablesAnalysis

    # Calculate monthly costs for each tier
    $daysPerMonth = 30.44  # Average days per month
    $tierComparison = @()

    # Pay-As-You-Go
    $paygMonthlyCost = $effectiveDailyIngestion * $pricing.PayAsYouGo * $daysPerMonth
    $tierComparison += [PSCustomObject]@{
        Tier            = 'Pay-As-You-Go'
        TierGB          = 0
        DailyRate       = $pricing.PayAsYouGo
        EffectivePerGB  = $pricing.PayAsYouGo
        MonthlyEstimate = [math]::Round($paygMonthlyCost, 2)
        OverageEstimate = 0
        TotalEstimate   = [math]::Round($paygMonthlyCost, 2)
        VsCurrent       = 0
        VsCurrentPercent = 0
        IsOptimal       = $false
        IsCurrent       = ($result.CurrentTier -eq 'Pay-As-You-Go')
    }

    # Commitment tiers
    foreach ($tier in $pricing.CommitmentTiers) {
        $tierDailyCost = $tier.DailyRate
        $tierMonthlyBase = $tierDailyCost * $daysPerMonth

        # Calculate overage (billed at commitment rate, not PAYG)
        $overageGB = [math]::Max(0.0, $effectiveDailyIngestion - $tier.TierGB)
        $overageMonthlyCost = $overageGB * $tier.EffectivePerGB * $daysPerMonth

        $totalMonthlyCost = $tierMonthlyBase + $overageMonthlyCost

        $isCurrent = ($result.CurrentTier -eq "$($tier.TierGB) GB/day")

        $tierComparison += [PSCustomObject]@{
            Tier            = "$($tier.TierGB) GB/day"
            TierGB          = $tier.TierGB
            DailyRate       = $tier.DailyRate
            EffectivePerGB  = $tier.EffectivePerGB
            MonthlyEstimate = [math]::Round($tierMonthlyBase, 2)
            OverageEstimate = [math]::Round($overageMonthlyCost, 2)
            TotalEstimate   = [math]::Round($totalMonthlyCost, 2)
            VsCurrent       = 0
            VsCurrentPercent = 0
            IsOptimal       = $false
            IsCurrent       = $isCurrent
        }
    }

    # Find current tier cost
    $currentTierEntry = $tierComparison | Where-Object { $_.IsCurrent }
    $currentMonthlyCost = if ($currentTierEntry) { $currentTierEntry.TotalEstimate } else { $paygMonthlyCost }
    $result.CurrentMonthlyCost = $currentMonthlyCost

    # Calculate vs current for each tier
    foreach ($tier in $tierComparison) {
        $tier.VsCurrent = [math]::Round($tier.TotalEstimate - $currentMonthlyCost, 2)
        $tier.VsCurrentPercent = if ($currentMonthlyCost -gt 0) {
            [math]::Round((($tier.TotalEstimate - $currentMonthlyCost) / $currentMonthlyCost) * 100, 1)
        } else { 0 }
    }

    # Find optimal tier (lowest total cost)
    $optimalTier = $tierComparison | Sort-Object TotalEstimate | Select-Object -First 1
    $optimalTier.IsOptimal = $true
    $result.OptimalTier = $optimalTier.Tier
    $result.OptimalMonthlyCost = $optimalTier.TotalEstimate
    $result.PotentialSavings = [math]::Round($currentMonthlyCost - $optimalTier.TotalEstimate, 2)
    $result.PotentialSavingsPercent = if ($currentMonthlyCost -gt 0) {
        [math]::Round((($currentMonthlyCost - $optimalTier.TotalEstimate) / $currentMonthlyCost) * 100, 1)
    } else { 0 }

    $result.TierComparison = $tierComparison

    # Identify Basic Logs candidates (high-volume, low-value tables)
    # Basic Logs offer ~60-70% cost savings with 8-day interactive retention and limited KQL
    # See: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/basic-logs-configure
    #
    # IMPORTANT: Tables covered by E5 grant are EXCLUDED from Basic Logs candidates because:
    # 1. E5 grant already makes them effectively free
    # 2. Converting to Basic Logs may remove E5 benefit eligibility
    # 3. Basic Logs have reduced query capabilities (8-day interactive, limited KQL)
    $basicLogsCandidates = @()
    $basicLogsEligibleTables = @(
        # Application Insights tables
        'ContainerLogV2', 'AppTraces', 'AppDependencies', 'AppRequests',
        # Azure platform logs
        'AzureDiagnostics', 'AzureMetrics',
        # Storage logs
        'StorageBlobLogs', 'StorageFileLogs', 'StorageQueueLogs', 'StorageTableLogs',
        # Cloud provider logs
        'AWSCloudTrail', 'AWSVPCFlow', 'AWSGuardDuty', 'GCPAuditLogs',
        # Security tables (when not needed for real-time alerting)
        # NOTE: Consider carefully before converting these - may impact detection rules
        'SecurityEvent', 'CommonSecurityLog', 'Syslog'
        # NOTE: E5-eligible Entra ID tables (AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs)
        # are intentionally EXCLUDED - they're covered by E5 grant when available
    )

    if ($CollectedData.TopTables) {
        foreach ($table in $CollectedData.TopTables) {
            $tableName = $table.DataType
            $tableGB = [double]$table.TotalGB

            # Skip tables that are already free or covered by E5 grant
            $isFree = $script:FreeDataTables -contains $tableName
            $isE5Covered = ($e5EligibleTables -contains $tableName) -and ($e5DailyGrantGB -gt 0)

            if ($isFree -or $isE5Covered) {
                continue
            }

            # Check if eligible for Basic Logs
            if ($basicLogsEligibleTables -contains $tableName -or $tableName -match '_CL$') {
                $monthlyGB = $tableGB  # Already 30-day total
                $currentCost = $monthlyGB * $pricing.PayAsYouGo
                $basicCost = $monthlyGB * $pricing.BasicLogsRate
                $savings = $currentCost - $basicCost

                if ($savings -gt 10) {  # Only suggest if savings > $10/month
                    $basicLogsCandidates += [PSCustomObject]@{
                        TableName       = $tableName
                        MonthlyGB       = [math]::Round($monthlyGB, 2)
                        CurrentCost     = [math]::Round($currentCost, 2)
                        BasicCost       = [math]::Round($basicCost, 2)
                        PotentialSavings = [math]::Round($savings, 2)
                    }
                }
            }
        }
    }

    $result.BasicLogsCandidates = $basicLogsCandidates | Sort-Object PotentialSavings -Descending

    # Identify Auxiliary Logs candidates (high-volume, retention-only tables)
    # Auxiliary logs are even cheaper than Basic logs but have more query limitations
    # Best for: High-volume compliance/audit logs accessed rarely
    # See: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/auxiliary-logs
    #
    # Microsoft recommends Auxiliary Logs for:
    # - Network flow logs and firewall verbose logs
    # - Proxy and web gateway logs
    # - IoT sensor data
    # - TLS/SSL certificate logs
    # - High-volume debug/trace logs
    $auxiliaryLogsCandidates = @()
    $auxiliaryLogsEligibleTables = @(
        # Azure platform high-volume logs
        'AzureDiagnostics', 'AzureMetrics', 'ContainerLogV2',
        # Storage logs (typically very high volume)
        'StorageBlobLogs', 'StorageFileLogs', 'StorageQueueLogs', 'StorageTableLogs',
        # Cloud provider audit/flow logs
        'AWSCloudTrail', 'AWSVPCFlow', 'GCPAuditLogs',
        # Application traces (debug/verbose)
        'AppTraces', 'AppDependencies',
        # Network flow and firewall logs
        'AzureNetworkAnalytics_CL', 'NSGFlowLogs', 'VMConnection',
        # Firewall verbose/diagnostic logs
        'AZFWApplicationRule', 'AZFWNetworkRule', 'AZFWDnsQuery', 'AZFWThreatIntel',
        # Proxy and web gateway logs
        'WebProxy_CL', 'ZscalerNSSLogs', 'SquidProxy_CL',
        # IoT and device telemetry
        'IoTHubDistributedTracing', 'ADTDigitalTwinsOperation',
        # TLS/SSL certificate logs
        'TLSCertificateLogs_CL'
    )

    if ($CollectedData.TopTables -and $pricing.AuxiliaryLogsRate -gt 0) {
        foreach ($table in $CollectedData.TopTables) {
            $tableName = $table.DataType
            $tableGB = [double]$table.TotalGB

            # Skip tables that are already free or covered by E5 grant
            $isFree = $script:FreeDataTables -contains $tableName
            $isE5Covered = ($e5EligibleTables -contains $tableName) -and ($e5DailyGrantGB -gt 0)

            if ($isFree -or $isE5Covered) {
                continue
            }

            # Check if eligible for Auxiliary Logs
            if ($auxiliaryLogsEligibleTables -contains $tableName) {
                $monthlyGB = $tableGB  # Already 30-day total
                $currentCost = $monthlyGB * $pricing.PayAsYouGo
                $auxiliaryCost = $monthlyGB * $pricing.AuxiliaryLogsRate
                $savings = $currentCost - $auxiliaryCost

                # Higher threshold for Auxiliary since query capabilities are more limited
                if ($savings -gt 50) {  # Only suggest if savings > $50/month
                    $auxiliaryLogsCandidates += [PSCustomObject]@{
                        TableName         = $tableName
                        MonthlyGB         = [math]::Round($monthlyGB, 2)
                        CurrentCost       = [math]::Round($currentCost, 2)
                        AuxiliaryCost     = [math]::Round($auxiliaryCost, 2)
                        PotentialSavings  = [math]::Round($savings, 2)
                    }
                }
            }
        }
    }

    $result.AuxiliaryLogsCandidates = $auxiliaryLogsCandidates | Sort-Object PotentialSavings -Descending

    # Identify Data Lake tier candidates (tables with extended retention that could benefit from compression)
    # Data Lake tier provides 6:1 compression for storage, significantly reducing costs for long-term retention
    # See: https://learn.microsoft.com/en-us/azure/sentinel/billing?tabs=simplified%2Ccommitment-tiers#data-lake-tier
    #
    # Best candidates for Data Lake tier:
    # - Tables with retention >90 days beyond the free period
    # - High-volume tables where storage costs are significant
    # - Data that doesn't require frequent real-time queries
    $dataLakeCandidates = @()

    # Only analyze if we have Data Lake pricing and retention data
    if ($pricing.DataLakeStorageRate -gt 0 -and $CollectedData.TableRetention -and $CollectedData.TableRetention.Tables.Count -gt 0) {
        $analyticsRetentionRate = $pricing.AnalyticsRetentionRate

        foreach ($table in $CollectedData.TopTables) {
            $tableName = $table.DataType
            $monthlyGB = [double]$table.TotalGB
            $dailyGB = $monthlyGB / 30

            # Skip free tables
            if ($script:FreeDataTables -contains $tableName) {
                continue
            }

            # Get retention settings for this table
            $tableRetention = $null
            if ($CollectedData.TableRetention.Tables.ContainsKey($tableName)) {
                $tableRetention = $CollectedData.TableRetention.Tables[$tableName]
            }

            if (-not $tableRetention) {
                continue
            }

            $freePeriod = $tableRetention.FreePeriodDays
            $analyticsRetention = $tableRetention.EffectiveRetention
            $totalRetention = $tableRetention.EffectiveTotalRetention

            # Only consider tables with extended Analytics tier retention (>90 days beyond free)
            # These are prime candidates for moving to Data Lake tier
            $billableAnalyticsDays = [math]::Max(0, $analyticsRetention - $freePeriod)

            if ($billableAnalyticsDays -gt 90 -and $analyticsRetentionRate -gt 0) {
                # Current cost: Analytics tier retention
                $analyticsStoredGB = $dailyGB * $billableAnalyticsDays
                $currentAnalyticsCost = $analyticsStoredGB * $analyticsRetentionRate

                # Projected cost: Keep 90 days in Analytics, move rest to Data Lake
                # Data Lake storage is billed at 6:1 compression
                $dataLakeDays = $billableAnalyticsDays - 90
                $rawDataLakeGB = $dailyGB * $dataLakeDays
                $compressedDataLakeGB = $rawDataLakeGB / 6  # 6:1 compression
                $daysPerMonth = 30.44

                # Cost breakdown:
                # - 90 days in Analytics tier
                # - Remaining days in Data Lake (with compression)
                # - One-time ingestion cost for Data Lake (amortized monthly)
                $newAnalyticsCost = ($dailyGB * 90) * $analyticsRetentionRate
                $dataLakeStorageCost = $compressedDataLakeGB * $pricing.DataLakeStorageRate
                $dataLakeIngestionCost = ($dailyGB * $daysPerMonth) * $pricing.DataLakeIngestionRate

                $projectedTotalCost = $newAnalyticsCost + $dataLakeStorageCost + $dataLakeIngestionCost
                $savings = $currentAnalyticsCost - $projectedTotalCost

                # Only recommend if savings are significant (>$25/month)
                if ($savings -gt 25) {
                    $dataLakeCandidates += [PSCustomObject]@{
                        TableName            = $tableName
                        MonthlyGB            = [math]::Round($monthlyGB, 2)
                        DailyGB              = [math]::Round($dailyGB, 2)
                        CurrentRetentionDays = $analyticsRetention
                        FreePeriodDays       = $freePeriod
                        BillableAnalyticsDays = $billableAnalyticsDays
                        RecommendedAnalyticsDays = $freePeriod + 90
                        DataLakeDays         = $dataLakeDays
                        RawDataLakeGB        = [math]::Round($rawDataLakeGB, 2)
                        CompressedGB         = [math]::Round($compressedDataLakeGB, 2)
                        CompressionRatio     = '6:1'
                        CurrentCost          = [math]::Round($currentAnalyticsCost, 2)
                        ProjectedCost        = [math]::Round($projectedTotalCost, 2)
                        PotentialSavings     = [math]::Round($savings, 2)
                    }
                }
            }
        }
    }

    $result.DataLakeCandidates = $dataLakeCandidates | Sort-Object PotentialSavings -Descending

    # Dedicated Cluster Recommendation
    # Organizations ingesting at least 100 GB/day should consider a dedicated cluster for cost aggregation
    # See: https://learn.microsoft.com/en-us/azure/sentinel/billing-reduce-costs#optimize-log-analytics-costs-with-dedicated-clusters
    $clusterInfo = $CollectedData.DedicatedCluster
    $totalDailyIngestion = $avgDailyIngestion  # Use total ingestion (not effective) for cluster sizing

    if ($clusterInfo -and -not $clusterInfo.IsLinkedToCluster -and $totalDailyIngestion -ge 100) {
        # Workspace is not linked to a cluster but ingests >= 100 GB/day
        # Calculate potential benefit from cluster commitment tiers
        $clusterRecommendation = @{
            Recommended           = $true
            Reason                = 'High ingestion volume'
            CurrentDailyIngestion = [math]::Round($totalDailyIngestion, 2)
            MinimumClusterTier    = 100  # Minimum cluster commitment is 100 GB/day
            Benefits              = @(
                'Aggregate data volume across multiple workspaces in the same region'
                'Share a single commitment tier across all linked workspaces'
                'Faster cross-workspace queries when all workspaces are in the cluster'
                'Customer-managed keys for data encryption'
            )
            Constraints           = @(
                'Maximum 2 clusters per region per subscription'
                'All linked workspaces must be in the same region'
                'Maximum 1,000 workspaces per cluster'
                'Workspace linking limited to 2 operations per 30-day period'
            )
            DocumentationUrl      = 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-dedicated-clusters'
        }
        $result.DedicatedClusterRecommendation = $clusterRecommendation
    }
    elseif ($clusterInfo -and $clusterInfo.IsLinkedToCluster) {
        # Workspace is already linked to a cluster
        $result.DedicatedClusterRecommendation = @{
            Recommended           = $false
            Reason                = 'Already linked to cluster'
            ClusterName           = $clusterInfo.ClusterName
            ClusterCapacityTier   = $clusterInfo.ClusterCapacityTier
            CurrentDailyIngestion = [math]::Round($totalDailyIngestion, 2)
        }
    }
    elseif ($totalDailyIngestion -lt 100) {
        # Ingestion below threshold
        $result.DedicatedClusterRecommendation = @{
            Recommended           = $false
            Reason                = 'Ingestion below 100 GB/day threshold'
            CurrentDailyIngestion = [math]::Round($totalDailyIngestion, 2)
            MinimumRequired       = 100
            Note                  = 'Consider a dedicated cluster when ingestion reaches 100 GB/day or when aggregating multiple workspaces'
        }
    }

    # Add analysis notes
    if ($result.PotentialSavings -gt 0) {
        $result.AnalysisNotes += "Switching to $($result.OptimalTier) could save approximately $($pricing.Currency) $($result.PotentialSavings)/month."
    }

    if ($freeIngestionDaily -gt 0) {
        $result.AnalysisNotes += "Free data sources detected: $(Format-DataSize $result.FreeIngestionGB)/day not counted toward billable ingestion."
    }

    if ($defenderP2BenefitGB -gt 0) {
        $result.AnalysisNotes += "Defender for Servers P2 benefit applied: $(Format-DataSize $result.DefenderP2BenefitGB)/day included free."
    }

    if ($e5DailyGrantGB -gt 0 -and $result.E5GrantUtilization -lt 50) {
        $result.AnalysisNotes += "E5 data grant is underutilized. Ensure E5-eligible data sources (Entra ID, M365) are connected."
    }

    if ($basicLogsCandidates.Count -gt 0) {
        $totalBasicSavings = ($basicLogsCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        $result.AnalysisNotes += "Converting $($basicLogsCandidates.Count) table(s) to Basic Logs could save approximately $($pricing.Currency) $([math]::Round($totalBasicSavings, 2))/month."
    }

    if ($auxiliaryLogsCandidates.Count -gt 0) {
        $totalAuxSavings = ($auxiliaryLogsCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        $result.AnalysisNotes += "Converting $($auxiliaryLogsCandidates.Count) table(s) to Auxiliary Logs could save approximately $($pricing.Currency) $([math]::Round($totalAuxSavings, 2))/month (note: limited query capabilities)."
    }

    if ($dataLakeCandidates.Count -gt 0) {
        $totalDataLakeSavings = ($dataLakeCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        $result.AnalysisNotes += "Moving $($dataLakeCandidates.Count) table(s) to Data Lake tier could save approximately $($pricing.Currency) $([math]::Round($totalDataLakeSavings, 2))/month (6:1 compression for extended retention)."
    }

    if ($result.PricingModel -eq 'Classic') {
        $result.AnalysisNotes += "Classic pricing detected: Log Analytics ingestion costs are billed separately from Sentinel."
    }

    if ($result.DedicatedClusterRecommendation -and $result.DedicatedClusterRecommendation.Recommended) {
        $result.AnalysisNotes += "DEDICATED CLUSTER RECOMMENDED: Ingesting $(Format-DataSize $totalDailyIngestion)/day exceeds 100 GB threshold. A dedicated cluster can aggregate commitment tiers across workspaces and improve cross-workspace query performance."
    }

    return $result
}

#endregion Data Collection Functions

#region Output Formatting

function Write-SectionHeader {
    [CmdletBinding()]
    param(
        [string]$Title,
        [ConsoleColor]$Color = 'Cyan'
    )
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Color
    Write-Host " $Title" -ForegroundColor $Color
    Write-Host ("=" * 70) -ForegroundColor $Color
}

function Write-ResultLine {
    [CmdletBinding()]
    param(
        [string]$Label,
        [string]$Value,
        [ConsoleColor]$ValueColor = 'White'
    )
    Write-Host "  $($Label.PadRight(30)): " -NoNewline
    Write-Host $Value -ForegroundColor $ValueColor
}

#endregion Output Formatting

#region Main Execution

Write-SectionHeader "Microsoft Sentinel Cost Optimization POC" -Color Magenta
Write-Host ""
Write-Host "  Subscription:     $SubscriptionId"
Write-Host "  Resource Group:   $ResourceGroupName"
Write-Host "  Workspace:        $WorkspaceName"
Write-Host ""

# Initialize collected data structure
$collectedData = @{
    WorkspaceConfig      = $null
    SentinelPricingModel = $null  # Simplified vs Classic pricing
    E5LicenseInfo        = $null
    PricingInfo          = $null
    DefenderServersP2    = $null
    DedicatedCluster     = $null  # Log Analytics dedicated cluster info
    IngestionTrend       = $null
    TopTables            = $null
    E5DailyIngestion     = $null  # Daily E5-eligible ingestion for accurate overage calculation
    P2DailyIngestion     = $null  # Daily P2-eligible ingestion for accurate benefit calculation
    SolutionBreakdown    = $null  # Ingestion grouped by Solution (connector)
    TableRetention       = $null  # Per-table and workspace retention settings
    RetentionAnalysis    = $null  # Retention cost analysis
    Tables               = @()
    CostAnalysis         = $null
}

#-----------------------------------------------------------------------------
# Step 1: Azure Authentication
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 1: Azure Authentication"

try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "  Not logged in to Azure. Connecting..." -ForegroundColor Yellow
        Connect-AzAccount -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        $context = Get-AzContext
    }

    if ($context.Subscription.Id -ne $SubscriptionId) {
        Write-Host "  Switching to subscription $SubscriptionId..." -ForegroundColor Yellow
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        $context = Get-AzContext
    }

    Write-ResultLine "Account" $context.Account.Id -ValueColor Green
    Write-ResultLine "Subscription" $context.Subscription.Name -ValueColor Green
    Write-ResultLine "Tenant" $context.Tenant.Id -ValueColor Green
}
catch {
    Write-Host "  Failed to authenticate to Azure: $_" -ForegroundColor Red
    exit 1
}

#-----------------------------------------------------------------------------
# Step 2: Get ARM API Token
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 2: ARM API Token"

try {
    $tokenInfo = Get-AzureAccessToken -Context $context
    $authHeader = @{ 'Authorization' = "Bearer $($tokenInfo.Token)" }
    Write-ResultLine "Token Obtained" "Yes" -ValueColor Green
    Write-ResultLine "Expires On" $tokenInfo.ExpiresOn.ToString() -ValueColor Cyan
}
catch {
    Write-Host "  Failed to get ARM token: $_" -ForegroundColor Red
    exit 1
}

#-----------------------------------------------------------------------------
# Step 3: Get Workspace Configuration
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 3: Workspace Configuration"

try {
    $workspaceUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName`?api-version=2023-09-01"
    $collectedData.WorkspaceConfig = Invoke-RestMethodWithRetry -Uri $workspaceUri -Method 'GET' -Headers $authHeader

    $wsProps = $collectedData.WorkspaceConfig.properties
    $wsLocation = $collectedData.WorkspaceConfig.location
    $wsSku = Get-SafeProperty $wsProps.sku 'name'
    $wsCapacity = Get-SafeProperty $wsProps.sku 'capacityReservationLevel'
    $workspaceId = $wsProps.customerId

    Write-ResultLine "Workspace ID" $workspaceId -ValueColor Cyan
    Write-ResultLine "Location" $wsLocation -ValueColor Cyan
    Write-ResultLine "SKU" $wsSku -ValueColor Cyan
    if ($wsCapacity) {
        Write-ResultLine "Commitment Tier" "$wsCapacity GB/day" -ValueColor Yellow
    } else {
        Write-ResultLine "Commitment Tier" "None (Pay-As-You-Go)" -ValueColor Yellow
    }
}
catch {
    Write-Host "  Failed to get workspace config: $_" -ForegroundColor Red
    exit 1
}

#-----------------------------------------------------------------------------
# Step 3b: Detect Sentinel Pricing Model
#-----------------------------------------------------------------------------
Write-Host ""
Write-Host "  Detecting Sentinel pricing model..." -ForegroundColor DarkGray

try {
    $pricingModelInfo = Get-SentinelPricingModel -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -AuthHeader $authHeader
    $collectedData.SentinelPricingModel = $pricingModelInfo

    if ($pricingModelInfo.PricingModel -ne 'Unknown') {
        Write-ResultLine "Pricing Model" $pricingModelInfo.PricingModel -ValueColor $(if ($pricingModelInfo.PricingModel -eq 'Simplified') { 'Green' } else { 'Yellow' })
        Write-ResultLine "Solution SKU" $pricingModelInfo.SkuName -ValueColor Cyan
    } else {
        Write-ResultLine "Pricing Model" "Could not detect (error: $($pricingModelInfo.ErrorMessage))" -ValueColor Yellow
    }
}
catch {
    Write-ResultLine "Pricing Model" "Detection failed: $_" -ValueColor Yellow
}

#-----------------------------------------------------------------------------
# Step 3c: Get Table Retention Settings
#-----------------------------------------------------------------------------
Write-Host ""
Write-Host "  Retrieving table retention settings..." -ForegroundColor DarkGray

try {
    $tableRetention = Get-TableRetentionSettings -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -AuthHeader $authHeader
    $collectedData.TableRetention = $tableRetention

    if ($tableRetention.ErrorMessage) {
        Write-ResultLine "Retention Settings" "Error: $($tableRetention.ErrorMessage)" -ValueColor Yellow
    } else {
        Write-ResultLine "Workspace Default" "$($tableRetention.WorkspaceDefaultRetentionDays) days" -ValueColor Cyan
        Write-ResultLine "Tables Retrieved" (Format-Plural $tableRetention.Tables.Count 'table') -ValueColor Green
        if ($tableRetention.TablesWithCustomRetention.Count -gt 0) {
            Write-ResultLine "Custom Retention" (Format-Plural $tableRetention.TablesWithCustomRetention.Count 'table') -ValueColor Yellow
        }
        if ($tableRetention.TablesUsingDataLake.Count -gt 0) {
            Write-ResultLine "Using Data Lake" (Format-Plural $tableRetention.TablesUsingDataLake.Count 'table') -ValueColor Cyan
        }
    }
}
catch {
    Write-ResultLine "Retention Settings" "Failed: $_" -ValueColor Yellow
}

#-----------------------------------------------------------------------------
# Step 3d: Check Dedicated Cluster Status
#-----------------------------------------------------------------------------
Write-Host ""
Write-Host "  Checking dedicated cluster status..." -ForegroundColor DarkGray

try {
    $clusterInfo = Get-DedicatedClusterInfo -WorkspaceConfig $collectedData.WorkspaceConfig -SubscriptionId $SubscriptionId -AuthHeader $authHeader
    $collectedData.DedicatedCluster = $clusterInfo

    if ($clusterInfo.IsLinkedToCluster) {
        Write-ResultLine "Dedicated Cluster" "Linked" -ValueColor Green
        Write-ResultLine "Cluster Name" $clusterInfo.ClusterName -ValueColor Cyan
        if ($clusterInfo.ClusterCapacityTier) {
            Write-ResultLine "Cluster Tier" "$($clusterInfo.ClusterCapacityTier) GB/day" -ValueColor Cyan
        }
    } else {
        Write-ResultLine "Dedicated Cluster" "Not linked" -ValueColor Yellow
    }
}
catch {
    Write-ResultLine "Dedicated Cluster" "Check failed: $_" -ValueColor Yellow
}

#-----------------------------------------------------------------------------
# Step 4: Microsoft Graph Token (for E5 licenses)
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 4: Microsoft Graph Authentication"

try {
    $graphToken = Get-GraphAccessToken -Context $context
    if ($graphToken) {
        Write-ResultLine "Graph Token" "Obtained" -ValueColor Green

        # Get E5 license count
        $e5Info = Get-E5LicenseCount -GraphToken $graphToken
        if ($e5Info) {
            $collectedData.E5LicenseInfo = $e5Info

            # Check for permission issues first
            if ($e5Info.PermissionIssue) {
                if ($e5Info.ErrorMessage) {
                    Write-ResultLine "E5/A5/F5/G5 Licenses" "Unable to query ($($e5Info.ErrorMessage))" -ValueColor Yellow
                } else {
                    Write-ResultLine "E5/A5/F5/G5 Licenses" "Unable to query (Organization.Read.All permission required)" -ValueColor Yellow
                }
                Write-Host "    Note: Grant Organization.Read.All in Azure AD to detect E5 license data grants." -ForegroundColor DarkGray
            } elseif ($e5Info.TotalSeats -gt 0) {
                Write-ResultLine "E5/A5/F5/G5 Licenses" (Format-Plural $e5Info.TotalSeats 'seat') -ValueColor Green
                $e5DailyGrant = $e5Info.TotalSeats * 0.005
                Write-ResultLine "Daily Data Grant" "$(Format-DataSize $e5DailyGrant)/day" -ValueColor Green

                if ($e5Info.SkuDetails.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  E5-tier SKUs found:" -ForegroundColor DarkGray
                    foreach ($sku in $e5Info.SkuDetails) {
                        Write-Host "    - $($sku.SkuPartNumber): $($sku.EnabledUnits) enabled, $($sku.ConsumedUnits) consumed" -ForegroundColor DarkGray
                    }
                }
            } else {
                # We got a response with SKUs but none matched E5/A5/F5/G5
                Write-ResultLine "E5/A5/F5/G5 Licenses" "None found ($($e5Info.TotalSkusFound) SKUs checked)" -ValueColor Yellow
                if ($e5Info.AllSkuDetails -and $e5Info.AllSkuDetails.Count -gt 0) {
                    # Check if any E5-eligible SKUs exist but have 0 seats
                    $e5SkusWithZeroSeats = $e5Info.AllSkuDetails | Where-Object { $_.IsE5Eligible -and $_.EnabledUnits -eq 0 }
                    if ($e5SkusWithZeroSeats) {
                        Write-Host ""
                        Write-Host "  E5-eligible SKUs found but with 0 enabled seats:" -ForegroundColor Yellow
                        foreach ($sku in $e5SkusWithZeroSeats) {
                            Write-Host "    - $($sku.SkuPartNumber): $($sku.EnabledUnits) enabled, $($sku.ConsumedUnits) consumed" -ForegroundColor Yellow
                        }
                    }
                    Write-Host ""
                    Write-Host "  Tenant SKUs:" -ForegroundColor DarkGray
                    foreach ($sku in ($e5Info.AllSkuDetails | Sort-Object SkuPartNumber)) {
                        $marker = if ($sku.IsE5Eligible) { " [E5-ELIGIBLE]" } else { "" }
                        Write-Host "    - $($sku.SkuPartNumber): $($sku.EnabledUnits) enabled$marker" -ForegroundColor $(if ($sku.IsE5Eligible) { 'Yellow' } else { 'DarkGray' })
                    }
                }
            }
        } else {
            Write-ResultLine "E5 License Query" "Failed to query Graph API" -ValueColor Yellow
        }
    } else {
        Write-ResultLine "Graph Token" "Failed to obtain" -ValueColor Yellow
    }
}
catch {
    Write-ResultLine "Graph Auth" "Failed: $_" -ValueColor Yellow
}

#-----------------------------------------------------------------------------
# Step 5: Get Sentinel Pricing
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 5: Sentinel Pricing (Azure Retail Prices API)"

$billingCurrency = Get-RegionCurrencyMapping -Region $wsLocation
Write-ResultLine "Workspace Region" $wsLocation -ValueColor Cyan
Write-ResultLine "Billing Currency" $billingCurrency -ValueColor Cyan

try {
    $pricingInfo = Get-SentinelPricingInfo -Region $wsLocation -Currency $billingCurrency
    if ($pricingInfo) {
        $collectedData.PricingInfo = $pricingInfo

        if ($pricingInfo.PayAsYouGo -eq 0) {
            Write-ResultLine "Pricing Data" "Retrieved but PAYG rate is 0 - check region name" -ValueColor Yellow
            Write-Host "    Raw prices returned: $($pricingInfo.CurrentRetailPrices.Count)" -ForegroundColor DarkGray
            if ($pricingInfo.CurrentRetailPrices.Count -gt 0) {
                Write-Host "    Sample meter names:" -ForegroundColor DarkGray
                $pricingInfo.CurrentRetailPrices | Select-Object -First 5 | ForEach-Object {
                    Write-Host "      - $($_.meterName): $($_.unitPrice)" -ForegroundColor DarkGray
                }
            }
        } else {
            Write-ResultLine "Pay-As-You-Go Rate" "$billingCurrency $($pricingInfo.PayAsYouGo)/GB" -ValueColor Green
            Write-ResultLine "Basic Logs Rate" "$billingCurrency $($pricingInfo.BasicLogsRate)/GB" -ValueColor Green
            Write-ResultLine "Auxiliary Logs Rate" "$billingCurrency $($pricingInfo.AuxiliaryLogsRate)/GB" -ValueColor Green
            Write-ResultLine "Commitment Tiers" (Format-Plural $pricingInfo.CommitmentTiers.Count 'tier') -ValueColor Green
            # Retention rates
            if ($pricingInfo.AnalyticsRetentionRate -gt 0) {
                Write-ResultLine "Analytics Retention" "$billingCurrency $($pricingInfo.AnalyticsRetentionRate)/GB/month" -ValueColor Green
            }
            # Log Analytics Archive (long-term retention - the commonly used model)
            if ($pricingInfo.ArchiveRetentionRate -gt 0) {
                Write-ResultLine "Archive Retention" "$billingCurrency $($pricingInfo.ArchiveRetentionRate)/GB/month" -ValueColor Green
            }
            # Sentinel Data Lake tier pricing (newer preview - separate components)
            # Note: Data Lake tier has 6:1 compression for storage billing
            if ($pricingInfo.DataLakeStorageRate -gt 0) {
                $effectiveRate = [math]::Round($pricingInfo.DataLakeStorageRate / 6, 4)
                Write-ResultLine "Data Lake Storage" "$billingCurrency $($pricingInfo.DataLakeStorageRate)/GB/month (6:1 compression = ~$billingCurrency $effectiveRate effective)" -ValueColor DarkGray
            }
            if ($pricingInfo.DataLakeIngestionRate -gt 0) {
                Write-ResultLine "Data Lake Ingestion" "$billingCurrency $($pricingInfo.DataLakeIngestionRate)/GB (preview)" -ValueColor DarkGray
            }
            if ($pricingInfo.DataLakeProcessingRate -gt 0) {
                Write-ResultLine "Data Lake Processing" "$billingCurrency $($pricingInfo.DataLakeProcessingRate)/GB (transformations)" -ValueColor DarkGray
            }
            if ($pricingInfo.DataLakeQueryRate -gt 0) {
                Write-ResultLine "Data Lake Query" "$billingCurrency $($pricingInfo.DataLakeQueryRate)/GB analyzed" -ValueColor DarkGray
            }
            # Note: Pricing model is displayed in Step 3b from Sentinel solution query
        }

        if ($pricingInfo.CommitmentTiers -and $pricingInfo.CommitmentTiers.Count -gt 0) {
            Write-Host ""
            Write-Host "  Commitment Tier Pricing:" -ForegroundColor DarkGray
            foreach ($tier in $pricingInfo.CommitmentTiers) {
                Write-Host "    - $($tier.TierGB) GB/day: $billingCurrency $($tier.DailyRate)/day (effective: $billingCurrency $($tier.EffectivePerGB)/GB)" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-ResultLine "Pricing Data" "Not available for region $wsLocation" -ValueColor Yellow
    }
}
catch {
    Write-ResultLine "Pricing Query" "Failed: $_" -ValueColor Red
}

#-----------------------------------------------------------------------------
# Step 5b: Defender for Servers P2 Check
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 5b: Defender for Servers P2 Benefit"

try {
    Write-Host "  Checking Defender for Servers P2 status..." -ForegroundColor DarkGray
    $defenderP2Info = Get-DefenderServersP2Benefit -SubscriptionId $SubscriptionId -AuthHeader $authHeader -WorkspaceId $workspaceId -SkipKqlQueries:$SkipKqlQueries
    $collectedData.DefenderServersP2 = $defenderP2Info

    if ($defenderP2Info.Enabled) {
        Write-ResultLine "Defender for Servers P2" "Enabled" -ValueColor Green
        if (-not $SkipKqlQueries -and $defenderP2Info.ProtectedVMCount -gt 0) {
            Write-ResultLine "Protected VMs" (Format-Plural $defenderP2Info.ProtectedVMCount 'VM') -ValueColor Green
            Write-ResultLine "Daily Benefit" "$(Format-DataSize $defenderP2Info.DailyBenefitGB)/day (500 MB/VM)" -ValueColor Green
        } elseif ($SkipKqlQueries) {
            Write-ResultLine "Protected VMs" "Skipped (KQL queries disabled)" -ValueColor Yellow
        }
    } else {
        Write-ResultLine "Defender for Servers P2" "Not enabled (tier: $($defenderP2Info.PricingTier))" -ValueColor Yellow
        Write-Host "    Note: Defender for Servers P2 includes 500 MB/day per VM." -ForegroundColor DarkGray
    }
}
catch {
    Write-ResultLine "Defender P2 Check" "Failed: $_" -ValueColor Yellow
}

#-----------------------------------------------------------------------------
# Step 6: KQL Queries (Ingestion Data)
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 6: Ingestion Data (KQL Queries)"

if ($SkipKqlQueries) {
    Write-Host "  KQL queries skipped (-SkipKqlQueries specified)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Using mock data for demonstration..." -ForegroundColor DarkGray

    # Mock data for testing the cost analysis logic
    $collectedData.IngestionTrend = @(
        [PSCustomObject]@{ TimeGenerated = (Get-Date).AddDays(-30); TotalGB = 45.2 }
        [PSCustomObject]@{ TimeGenerated = (Get-Date).AddDays(-29); TotalGB = 48.1 }
        [PSCustomObject]@{ TimeGenerated = (Get-Date).AddDays(-28); TotalGB = 52.3 }
        [PSCustomObject]@{ TimeGenerated = (Get-Date).AddDays(-27); TotalGB = 47.8 }
        [PSCustomObject]@{ TimeGenerated = (Get-Date).AddDays(-26); TotalGB = 50.1 }
    )
    $avgDaily = ($collectedData.IngestionTrend | Measure-Object -Property TotalGB -Average).Average
    Write-ResultLine "Mock Avg Daily Ingestion" "$(Format-DataSize $avgDaily)/day" -ValueColor Cyan
} else {
    # Test Log Analytics authentication
    Write-Host "  Testing Log Analytics authentication..." -ForegroundColor DarkGray
    $kqlAuthValid = Test-LogAnalyticsAuth -WorkspaceId $workspaceId -SubscriptionId $SubscriptionId

    if ($kqlAuthValid) {
        Write-ResultLine "Log Analytics Auth" "Valid" -ValueColor Green

        # 30-day billable ingestion trend (using IsBillable for accuracy)
        # Note: Quantity is in MB, divide by 1000 for decimal GB (matches Azure billing)
        Write-Host "  Querying 30-day ingestion trend..." -ForegroundColor DarkGray
        $ingestionQuery = @"
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize TotalGB = sum(Quantity) / 1000 by bin_at(TimeGenerated, 1d, startofday(now()))
| order by TimeGenerated asc
"@
        $collectedData.IngestionTrend = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $ingestionQuery
        if ($collectedData.IngestionTrend) {
            $avgDaily = ($collectedData.IngestionTrend | Measure-Object -Property TotalGB -Average).Average
            Write-ResultLine "Ingestion Days" $collectedData.IngestionTrend.Count -ValueColor Green
            Write-ResultLine "Avg Daily Ingestion" "$(Format-DataSize $avgDaily)/day" -ValueColor Green
        } else {
            Write-ResultLine "Ingestion Trend" "No data returned" -ValueColor Yellow
        }

        # Top 15 tables by volume (includes all data for visibility into free vs billable)
        Write-Host "  Querying top tables by volume..." -ForegroundColor DarkGray
        $topTablesQuery = @"
Usage
| where TimeGenerated > ago(30d)
| summarize TotalGB = sum(Quantity) / 1000, IsBillable = take_any(IsBillable) by DataType
| top 15 by TotalGB desc
"@
        $collectedData.TopTables = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $topTablesQuery
        if ($collectedData.TopTables) {
            Write-ResultLine "Top Tables" (Format-Plural $collectedData.TopTables.Count 'table') -ValueColor Green
        }

        # Daily E5-eligible ingestion for accurate overage calculation
        # The E5 benefit resets daily - unused grant cannot carry over
        Write-Host "  Querying daily E5-eligible ingestion..." -ForegroundColor DarkGray
        $e5DailyQuery = @"
let e5Tables = dynamic([
    "SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs",
    "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
    "AADProvisioningLogs", "ADFSSignInLogs",
    "McasShadowItReporting", "InformationProtectionLogs_CL",
    "DeviceEvents", "DeviceFileEvents", "DeviceImageLoadEvents",
    "DeviceInfo", "DeviceLogonEvents", "DeviceNetworkEvents",
    "DeviceNetworkInfo", "DeviceProcessEvents", "DeviceRegistryEvents",
    "DeviceFileCertificateInfo", "DynamicEventCollection",
    "CloudAppEvents", "EmailAttachmentInfo", "EmailEvents",
    "EmailPostDeliveryEvents", "EmailUrlInfo", "UrlClickEvents",
    "IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents",
    "AlertEvidence"
]);
Usage
| where TimeGenerated > ago(30d)
| where DataType in (e5Tables)
| summarize DailyEligibleGB = sum(Quantity) / 1000 by Day = bin(TimeGenerated, 1d)
| order by Day asc
"@
        $collectedData.E5DailyIngestion = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $e5DailyQuery
        if ($collectedData.E5DailyIngestion) {
            Write-ResultLine "E5 Daily Data" (Format-Plural $collectedData.E5DailyIngestion.Count 'day') -ValueColor Green
        }

        # Daily P2-eligible ingestion for accurate benefit calculation
        # The P2 benefit (500 MB/VM/day) can only offset P2-eligible table ingestion
        Write-Host "  Querying daily P2-eligible ingestion..." -ForegroundColor DarkGray
        $p2DailyQuery = @"
let p2Tables = dynamic([
    "SecurityAlert", "SecurityEvent", "WindowsFirewall",
    "SecurityBaseline", "SecurityBaselineSummary", "SecurityDetection",
    "ProtectionStatus", "Update", "UpdateSummary",
    "MDCFileIntegrityMonitoringEvents", "WindowsEvent", "LinuxAuditLog"
]);
Usage
| where TimeGenerated > ago(30d)
| where DataType in (p2Tables)
| summarize DailyP2EligibleGB = sum(Quantity) / 1000 by Day = bin(TimeGenerated, 1d)
| order by Day asc
"@
        $collectedData.P2DailyIngestion = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $p2DailyQuery
        if ($collectedData.P2DailyIngestion) {
            Write-ResultLine "P2 Daily Data" (Format-Plural $collectedData.P2DailyIngestion.Count 'day') -ValueColor Green
        }

        # Solution breakdown (ingestion by connector/solution)
        Write-Host "  Querying ingestion by solution..." -ForegroundColor DarkGray
        $solutionQuery = @"
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize IngestedGB = sum(Quantity) / 1000 by Solution
| order by IngestedGB desc
"@
        $collectedData.SolutionBreakdown = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $solutionQuery
        if ($collectedData.SolutionBreakdown) {
            Write-ResultLine "Solutions" (Format-Plural $collectedData.SolutionBreakdown.Count 'solution') -ValueColor Green
        }
    } else {
        Write-ResultLine "Log Analytics Auth" "Failed - skipping KQL queries" -ValueColor Red
    }
}

#-----------------------------------------------------------------------------
# Step 7: Cost Optimization Analysis
#-----------------------------------------------------------------------------
Write-SectionHeader "Step 7: Cost Optimization Analysis"

if ($collectedData.PricingInfo -and $collectedData.IngestionTrend) {
    $collectedData.CostAnalysis = Invoke-CostOptimizationAnalysis -CollectedData $collectedData

    # Calculate retention costs if we have table retention settings and top tables data
    if ($collectedData.TableRetention -and $collectedData.TopTables -and $collectedData.PricingInfo.AnalyticsRetentionRate -gt 0) {
        $collectedData.RetentionAnalysis = Get-RetentionCostAnalysis `
            -TableRetention $collectedData.TableRetention `
            -TopTables $collectedData.TopTables `
            -PricingInfo $collectedData.PricingInfo
    }

    $cost = $collectedData.CostAnalysis
    $currency = $collectedData.PricingInfo.Currency

    Write-Host ""
    Write-Host "  CURRENT STATE" -ForegroundColor White
    Write-ResultLine "Current Tier" $cost.CurrentTier -ValueColor $(if ($cost.CurrentTier -eq 'Pay-As-You-Go') { 'Yellow' } else { 'Cyan' })
    Write-ResultLine "Pricing Model" $cost.PricingModel -ValueColor $(if ($cost.PricingModel -eq 'Simplified') { 'Green' } else { 'Yellow' })
    Write-ResultLine "Est. Monthly Cost" "$currency $($cost.CurrentMonthlyCost)" -ValueColor Yellow

    Write-Host ""
    Write-Host "  OPTIMAL RECOMMENDATION" -ForegroundColor White
    Write-ResultLine "Optimal Tier" $cost.OptimalTier -ValueColor $(if ($cost.OptimalTier -eq $cost.CurrentTier) { 'Green' } else { 'Cyan' })
    Write-ResultLine "Est. Monthly Cost" "$currency $($cost.OptimalMonthlyCost)" -ValueColor Green

    if ($cost.PotentialSavings -gt 0) {
        Write-ResultLine "Potential Savings" "$currency $($cost.PotentialSavings)/month ($($cost.PotentialSavingsPercent)%)" -ValueColor Green
    } else {
        Write-ResultLine "Potential Savings" "Current tier is optimal" -ValueColor Green
    }

    # Show ingestion breakdown
    $avgIngestion = if ($collectedData.IngestionTrend) {
        [math]::Round(($collectedData.IngestionTrend | Measure-Object -Property TotalGB -Average).Average, 2)
    } else { 0 }

    Write-Host ""
    Write-Host "  INGESTION BREAKDOWN" -ForegroundColor White
    Write-ResultLine "Total Daily Ingestion" "$(Format-DataSize $avgIngestion)/day" -ValueColor Cyan

    # Show free data (not billed)
    if ($cost.FreeIngestionGB -gt 0) {
        Write-ResultLine "Free Data (excluded)" "$(Format-DataSize $cost.FreeIngestionGB)/day" -ValueColor Green
    }

    Write-ResultLine "Billable Ingestion" "$(Format-DataSize $cost.BillableIngestionGB)/day" -ValueColor Cyan

    # Show E5 grant details
    if ($collectedData.E5LicenseInfo -and $collectedData.E5LicenseInfo.TotalSeats -gt 0) {
        Write-ResultLine "E5 Daily Grant" "$(Format-DataSize $cost.E5DailyGrantGB)/day" -ValueColor Cyan
        Write-ResultLine "E5-Eligible Tables" "$(Format-DataSize $cost.E5EligibleIngestionGB)/day (avg)" -ValueColor Cyan
        Write-ResultLine "E5 Grant Applied" "$(Format-DataSize $cost.E5GrantUsedGB)/day (avg)" -ValueColor Green
        Write-ResultLine "Grant Utilization" "$($cost.E5GrantUtilization)%" -ValueColor $(if ($cost.E5GrantUtilization -ge 50) { 'Green' } elseif ($cost.E5GrantUtilization -gt 0) { 'Yellow' } else { 'Red' })

        # Show daily overage details if we have daily data
        if ($cost.E5DaysWithOverage -gt 0) {
            $daysCount = if ($collectedData.E5DailyIngestion) { $collectedData.E5DailyIngestion.Count } else { 30 }
            Write-ResultLine "Days Over Grant" "$($cost.E5DaysWithOverage) of $daysCount days" -ValueColor Yellow
            Write-ResultLine "Total E5 Overage" "$(Format-DataSize $cost.E5TotalOverageGB) over $daysCount days" -ValueColor Yellow
            Write-ResultLine "Max Single-Day" "$(Format-DataSize $cost.E5MaxOverageGB) overage" -ValueColor Yellow
        } elseif ($collectedData.E5DailyIngestion -and $collectedData.E5DailyIngestion.Count -gt 0) {
            Write-ResultLine "Days Over Grant" "0 of $($collectedData.E5DailyIngestion.Count) days" -ValueColor Green
        }
    }

    # Show Defender P2 benefit details
    if ($cost.DefenderP2BenefitGB -gt 0) {
        Write-ResultLine "P2 Benefit Available" "$(Format-DataSize $cost.DefenderP2BenefitGB)/day (500 MB/VM)" -ValueColor Cyan
        Write-ResultLine "P2-Eligible Ingestion" "$(Format-DataSize $cost.P2EligibleIngestionGB)/day" -ValueColor $(if ($cost.P2EligibleIngestionGB -ge $cost.DefenderP2BenefitGB) { 'Green' } else { 'Yellow' })
        Write-ResultLine "P2 Benefit Applied" "$(Format-DataSize $cost.P2BenefitAppliedGB)/day ($($cost.P2BenefitUtilization)% utilized)" -ValueColor Green

        if ($cost.P2BenefitUtilization -lt 100) {
            Write-Host "    Note: P2 benefit exceeds P2-eligible ingestion. Some benefit unused." -ForegroundColor DarkGray
        }
    }

    Write-ResultLine "Effective Billable" "$(Format-DataSize $cost.EffectiveDailyIngestionGB)/day" -ValueColor $(if ($cost.EffectiveDailyIngestionGB -le 0.1) { 'Green' } else { 'Yellow' })

    # Tier comparison table
    Write-Host ""
    Write-Host "  TIER COMPARISON" -ForegroundColor White
    Write-Host ""
    Write-Host "  Tier                    Base/month   Overage/mo   Total/month   vs Current" -ForegroundColor DarkGray
    Write-Host "  " + ("-" * 78) -ForegroundColor DarkGray

    foreach ($tier in $cost.TierComparison) {
        $tierName = $tier.Tier.PadRight(20)
        $baseStr = "$currency $($tier.MonthlyEstimate)".PadLeft(12)
        $overageStr = "$currency $($tier.OverageEstimate)".PadLeft(12)
        $totalStr = "$currency $($tier.TotalEstimate)".PadLeft(13)
        $vsCurrentStr = if ($tier.VsCurrent -ge 0) { "+$currency $($tier.VsCurrent)" } else { "-$currency $([math]::Abs($tier.VsCurrent))" }
        $vsCurrentStr = $vsCurrentStr.PadLeft(12)

        $marker = ""
        $color = 'White'
        if ($tier.IsCurrent -and $tier.IsOptimal) {
            $marker = " [CURRENT/OPTIMAL]"
            $color = 'Green'
        } elseif ($tier.IsCurrent) {
            $marker = " [CURRENT]"
            $color = 'Yellow'
        } elseif ($tier.IsOptimal) {
            $marker = " [OPTIMAL]"
            $color = 'Cyan'
        }

        Write-Host "  $tierName $baseStr $overageStr $totalStr $vsCurrentStr" -ForegroundColor $color -NoNewline
        Write-Host $marker -ForegroundColor $color
    }

    # Top 10 tables by ingestion volume with E5 cost analysis
    if ($cost.TopTablesAnalysis -and @($cost.TopTablesAnalysis).Count -gt 0) {
        Write-Host ""
        Write-Host "  TOP 10 TABLES BY INGESTION" -ForegroundColor White
        Write-Host ""
        Write-Host "  Table                          Monthly     Daily    Raw Cost   E5 Offset   Eff. Cost  Flags" -ForegroundColor DarkGray
        Write-Host "  " + ("-" * 95) -ForegroundColor DarkGray

        foreach ($tableInfo in $cost.TopTablesAnalysis) {
            $tableName = $tableInfo.TableName
            if ($tableName.Length -gt 28) {
                $tableName = $tableName.Substring(0, 25) + "..."
            }
            $tableName = $tableName.PadRight(28)

            $monthlySize = (Format-DataSize $tableInfo.MonthlyGB).PadLeft(10)
            $dailySize = (Format-DataSize $tableInfo.DailyGB).PadLeft(8)
            $rawCost = "$currency $($tableInfo.RawMonthlyCost)".PadLeft(10)
            $e5Offset = if ($tableInfo.E5GrantAppliedCost -gt 0) {
                "-$currency $($tableInfo.E5GrantAppliedCost)".PadLeft(10)
            } else {
                "-".PadLeft(10)
            }
            $effCost = "$currency $($tableInfo.EffectiveMonthlyCost)".PadLeft(10)

            # Build flags
            $flags = @()
            if ($tableInfo.IsFree) { $flags += "FREE" }
            if ($tableInfo.IsE5Eligible) { $flags += "E5" }
            $flagStr = if ($flags.Count -gt 0) { ($flags -join ",") } else { "" }

            # Color coding
            $color = 'White'
            if ($tableInfo.IsFree) {
                $color = 'Green'
            } elseif ($tableInfo.E5GrantAppliedCost -gt 0) {
                $color = 'Cyan'
            }

            Write-Host "  $tableName $monthlySize $dailySize $rawCost $e5Offset $effCost  $flagStr" -ForegroundColor $color
        }

        # Summary row
        $totalMonthlyGB = ($cost.TopTablesAnalysis | Measure-Object -Property MonthlyGB -Sum).Sum
        $totalRawCost = ($cost.TopTablesAnalysis | Measure-Object -Property RawMonthlyCost -Sum).Sum
        $totalE5Offset = ($cost.TopTablesAnalysis | Measure-Object -Property E5GrantAppliedCost -Sum).Sum
        $totalEffCost = ($cost.TopTablesAnalysis | Measure-Object -Property EffectiveMonthlyCost -Sum).Sum

        Write-Host "  " + ("-" * 95) -ForegroundColor DarkGray
        $summaryName = "TOTAL (Top 10)".PadRight(28)
        $summaryMonthly = (Format-DataSize $totalMonthlyGB).PadLeft(10)
        $summaryDaily = (Format-DataSize ($totalMonthlyGB / 30)).PadLeft(8)
        $summaryRaw = "$currency $([math]::Round($totalRawCost, 2))".PadLeft(10)
        $summaryE5 = if ($totalE5Offset -gt 0) {
            "-$currency $([math]::Round($totalE5Offset, 2))".PadLeft(10)
        } else {
            "-".PadLeft(10)
        }
        $summaryEff = "$currency $([math]::Round($totalEffCost, 2))".PadLeft(10)
        Write-Host "  $summaryName $summaryMonthly $summaryDaily $summaryRaw $summaryE5 $summaryEff" -ForegroundColor Yellow

        # Show E5 savings note if applicable
        if ($totalE5Offset -gt 0) {
            Write-Host ""
            Write-Host "  E5 Grant Savings: $currency $([math]::Round($totalE5Offset, 2))/month across E5-eligible tables" -ForegroundColor Cyan
        }
    }

    # Solution breakdown (ingestion by connector)
    if ($collectedData.SolutionBreakdown -and @($collectedData.SolutionBreakdown).Count -gt 0) {
        Write-Host ""
        Write-Host "  INGESTION BY SOLUTION (Connector)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Solution                                    Monthly GB    Daily GB    Est. Cost" -ForegroundColor DarkGray
        Write-Host "  " + ("-" * 78) -ForegroundColor DarkGray

        $totalSolutionGB = 0
        foreach ($solution in ($collectedData.SolutionBreakdown | Select-Object -First 10)) {
            $solutionName = $solution.Solution
            if ($solutionName.Length -gt 40) {
                $solutionName = $solutionName.Substring(0, 37) + "..."
            }
            $solutionName = $solutionName.PadRight(40)

            $monthlyGB = [double]$solution.IngestedGB
            $totalSolutionGB += $monthlyGB
            $dailyGB = $monthlyGB / 30
            $estCost = $monthlyGB * $collectedData.PricingInfo.PayAsYouGo

            $monthlyStr = (Format-DataSize $monthlyGB).PadLeft(12)
            $dailyStr = (Format-DataSize $dailyGB).PadLeft(11)
            $costStr = "$currency $([math]::Round($estCost, 2))".PadLeft(12)

            Write-Host "  $solutionName $monthlyStr $dailyStr $costStr" -ForegroundColor White
        }

        if (@($collectedData.SolutionBreakdown).Count -gt 10) {
            Write-Host "  ... and $(@($collectedData.SolutionBreakdown).Count - 10) more solutions" -ForegroundColor DarkGray
        }

        Write-Host "  " + ("-" * 78) -ForegroundColor DarkGray
        $totalCost = $totalSolutionGB * $collectedData.PricingInfo.PayAsYouGo
        $totalMonthlyStr = (Format-DataSize $totalSolutionGB).PadLeft(12)
        $totalDailyStr = (Format-DataSize ($totalSolutionGB / 30)).PadLeft(11)
        $totalCostStr = "$currency $([math]::Round($totalCost, 2))".PadLeft(12)
        Write-Host "  $("TOTAL (Billable)".PadRight(40)) $totalMonthlyStr $totalDailyStr $totalCostStr" -ForegroundColor Yellow
    }

    # Basic logs candidates
    if ($cost.BasicLogsCandidates -and @($cost.BasicLogsCandidates).Count -gt 0) {
        Write-Host ""
        Write-Host "  BASIC LOGS CANDIDATES" -ForegroundColor White
        Write-Host ""
        Write-Host "  Table                             Monthly   Current     Basic       Savings" -ForegroundColor DarkGray
        Write-Host "  " + ("-" * 78) -ForegroundColor DarkGray

        foreach ($candidate in $cost.BasicLogsCandidates | Select-Object -First 5) {
            $tableName = $candidate.TableName.PadRight(30)
            $monthlySize = (Format-DataSize $candidate.MonthlyGB).PadLeft(10)
            $currentCost = "$currency $($candidate.CurrentCost)".PadLeft(10)
            $basicCost = "$currency $($candidate.BasicCost)".PadLeft(10)
            $savings = "$currency $($candidate.PotentialSavings)".PadLeft(10)
            Write-Host "  $tableName $monthlySize $currentCost $basicCost $savings" -ForegroundColor White
        }

        if (@($cost.BasicLogsCandidates).Count -gt 5) {
            Write-Host "  ... and $(@($cost.BasicLogsCandidates).Count - 5) more candidates" -ForegroundColor DarkGray
        }

        $totalBasicSavings = ($cost.BasicLogsCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        Write-Host ""
        Write-ResultLine "Total Basic Logs Savings" "$currency $([math]::Round($totalBasicSavings, 2))/month" -ValueColor Green
    }

    # Auxiliary logs candidates
    if ($cost.AuxiliaryLogsCandidates -and @($cost.AuxiliaryLogsCandidates).Count -gt 0) {
        Write-Host ""
        Write-Host "  AUXILIARY LOGS CANDIDATES" -ForegroundColor White
        Write-Host "  (For high-volume, rarely-queried data. More cost savings but limited query capabilities)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Table                             Monthly   Current     Auxiliary   Savings" -ForegroundColor DarkGray
        Write-Host "  " + ("-" * 78) -ForegroundColor DarkGray

        foreach ($candidate in $cost.AuxiliaryLogsCandidates | Select-Object -First 5) {
            $tableName = $candidate.TableName.PadRight(30)
            $monthlySize = (Format-DataSize $candidate.MonthlyGB).PadLeft(10)
            $currentCost = "$currency $($candidate.CurrentCost)".PadLeft(10)
            $auxiliaryCost = "$currency $($candidate.AuxiliaryCost)".PadLeft(10)
            $savings = "$currency $($candidate.PotentialSavings)".PadLeft(10)
            Write-Host "  $tableName $monthlySize $currentCost $auxiliaryCost $savings" -ForegroundColor White
        }

        if (@($cost.AuxiliaryLogsCandidates).Count -gt 5) {
            Write-Host "  ... and $(@($cost.AuxiliaryLogsCandidates).Count - 5) more candidates" -ForegroundColor DarkGray
        }

        $totalAuxSavings = ($cost.AuxiliaryLogsCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        Write-Host ""
        Write-ResultLine "Total Auxiliary Logs Savings" "$currency $([math]::Round($totalAuxSavings, 2))/month" -ValueColor Green
    }

    # Data Lake tier candidates (for extended retention with 6:1 compression)
    if ($cost.DataLakeCandidates -and @($cost.DataLakeCandidates).Count -gt 0) {
        Write-Host ""
        Write-Host "  DATA LAKE TIER CANDIDATES (extended retention)" -ForegroundColor White
        Write-Host "  (6:1 compression for long-term storage. Move data beyond 90 days to Data Lake tier)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Table                          Retention   Raw GB   Compressed   Current    Projected   Savings" -ForegroundColor DarkGray
        Write-Host "  " + ("-" * 95) -ForegroundColor DarkGray

        foreach ($candidate in $cost.DataLakeCandidates | Select-Object -First 5) {
            $tableName = $candidate.TableName
            if ($tableName.Length -gt 28) {
                $tableName = $tableName.Substring(0, 25) + "..."
            }
            $tableName = $tableName.PadRight(28)
            $retentionInfo = "$($candidate.CurrentRetentionDays)d".PadLeft(9)
            $rawGB = (Format-DataSize $candidate.RawDataLakeGB).PadLeft(9)
            $compressedGB = (Format-DataSize $candidate.CompressedGB).PadLeft(10)
            $currentCost = "$currency $($candidate.CurrentCost)".PadLeft(10)
            $projectedCost = "$currency $($candidate.ProjectedCost)".PadLeft(10)
            $savings = "$currency $($candidate.PotentialSavings)".PadLeft(10)
            Write-Host "  $tableName $retentionInfo $rawGB $compressedGB $currentCost $projectedCost $savings" -ForegroundColor White
        }

        if (@($cost.DataLakeCandidates).Count -gt 5) {
            Write-Host "  ... and $(@($cost.DataLakeCandidates).Count - 5) more candidates" -ForegroundColor DarkGray
        }

        $totalDataLakeSavings = ($cost.DataLakeCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        Write-Host ""
        Write-ResultLine "Total Data Lake Savings" "$currency $([math]::Round($totalDataLakeSavings, 2))/month" -ValueColor Green
        Write-Host "  Note: Data Lake tier billed at 6:1 compression (600 GB raw = 100 GB billed)" -ForegroundColor DarkGray
    }

    # Retention cost analysis
    if ($collectedData.RetentionAnalysis -and $collectedData.RetentionAnalysis.TotalRetentionCost -gt 0) {
        $retention = $collectedData.RetentionAnalysis

        Write-Host ""
        Write-Host "  RETENTION COSTS" -ForegroundColor White
        Write-Host "  (Monthly cost of storing data beyond the free retention period)" -ForegroundColor DarkGray
        Write-Host ""

        # Summary
        Write-ResultLine "Analytics Tier Retention" "$currency $($retention.TotalAnalyticsRetentionCost)/month" -ValueColor $(if ($retention.TotalAnalyticsRetentionCost -gt 100) { 'Yellow' } else { 'Cyan' })
        Write-ResultLine "Archive Tier Retention" "$currency $($retention.TotalDataLakeRetentionCost)/month" -ValueColor $(if ($retention.TotalDataLakeRetentionCost -gt 0) { 'Cyan' } else { 'DarkGray' })
        Write-ResultLine "Total Retention Cost" "$currency $($retention.TotalRetentionCost)/month" -ValueColor $(if ($retention.TotalRetentionCost -gt 200) { 'Yellow' } else { 'Green' })

        # Top tables by retention cost
        if ($retention.TableRetentionCosts -and @($retention.TableRetentionCosts).Count -gt 0) {
            $topRetentionTables = $retention.TableRetentionCosts | Sort-Object TotalCost -Descending | Select-Object -First 10 | Where-Object { $_.TotalCost -gt 1 }

            if (@($topRetentionTables).Count -gt 0) {
                Write-Host ""
                Write-Host "  TOP TABLES BY RETENTION COST" -ForegroundColor White
                Write-Host ""
                Write-Host "  Table                          Daily GB   Free  Analytics  Archive   Analytics$   Archive$    Total$" -ForegroundColor DarkGray
                Write-Host "  " + ("-" * 100) -ForegroundColor DarkGray

                foreach ($tableRet in $topRetentionTables) {
                    $tableName = $tableRet.TableName
                    if ($tableName.Length -gt 28) {
                        $tableName = $tableName.Substring(0, 25) + "..."
                    }
                    $tableName = $tableName.PadRight(28)

                    $dailyGB = (Format-DataSize $tableRet.DailyGB).PadLeft(9)
                    $freeDays = "$($tableRet.FreePeriodDays)d".PadLeft(5)
                    $analyticsDays = "$($tableRet.AnalyticsRetentionDays)d".PadLeft(9)
                    $archiveDays = if ($tableRet.ArchiveRetentionDays -gt 0) {
                        "$($tableRet.ArchiveRetentionDays)d".PadLeft(8)
                    } else { "-".PadLeft(8) }
                    $analyticsCost = "$currency $($tableRet.AnalyticsCost)".PadLeft(11)
                    $archiveCost = if ($tableRet.ArchiveCost -gt 0) { "$currency $($tableRet.ArchiveCost)".PadLeft(11) } else { "-".PadLeft(11) }
                    $totalCost = "$currency $($tableRet.TotalCost)".PadLeft(8)

                    $color = if ($tableRet.TotalCost -gt 50) { 'Yellow' } else { 'White' }
                    Write-Host "  $tableName $dailyGB $freeDays $analyticsDays $archiveDays $analyticsCost $archiveCost $totalCost" -ForegroundColor $color
                }

                Write-Host "  " + ("-" * 100) -ForegroundColor DarkGray

                # Summary row
                $summaryName = "TOTAL (Top Tables)".PadRight(28)
                $totalDailyGB = ($topRetentionTables | Measure-Object -Property DailyGB -Sum).Sum
                $totalAnalyticsCost = ($topRetentionTables | Measure-Object -Property AnalyticsCost -Sum).Sum
                $totalArchiveCost = ($topRetentionTables | Measure-Object -Property ArchiveCost -Sum).Sum
                $totalTableCost = ($topRetentionTables | Measure-Object -Property TotalCost -Sum).Sum

                $dailyGBStr = (Format-DataSize $totalDailyGB).PadLeft(9)
                $analyticsCostStr = "$currency $([math]::Round($totalAnalyticsCost, 2))".PadLeft(11)
                $archiveCostStr = if ($totalArchiveCost -gt 0) { "$currency $([math]::Round($totalArchiveCost, 2))".PadLeft(11) } else { "-".PadLeft(11) }
                $totalCostStr = "$currency $([math]::Round($totalTableCost, 2))".PadLeft(8)

                Write-Host "  $summaryName $dailyGBStr       $(" " * 18) $analyticsCostStr $archiveCostStr $totalCostStr" -ForegroundColor Yellow
            }
        }

        # Retention optimization tips
        if ($retention.RetentionOptimizationTips -and @($retention.RetentionOptimizationTips).Count -gt 0) {
            Write-Host ""
            Write-Host "  RETENTION OPTIMIZATION OPPORTUNITIES" -ForegroundColor White
            Write-Host ""

            foreach ($tip in ($retention.RetentionOptimizationTips | Select-Object -First 5)) {
                Write-Host "  - $($tip.TableName): $($tip.Recommendation)" -ForegroundColor Cyan
                Write-Host "    Current: $currency $($tip.CurrentCost)/mo -> Optimized: $currency $($tip.OptimizedCost)/mo (Save $currency $($tip.PotentialSavings)/mo)" -ForegroundColor DarkGray
            }

            $totalRetentionSavings = ($retention.RetentionOptimizationTips | Measure-Object -Property PotentialSavings -Sum).Sum
            Write-Host ""
            Write-ResultLine "Total Potential Savings" "$currency $([math]::Round($totalRetentionSavings, 2))/month" -ValueColor Green
        }
    }

    # Dedicated Cluster Recommendation
    if ($cost.DedicatedClusterRecommendation) {
        $clusterRec = $cost.DedicatedClusterRecommendation

        Write-Host ""
        Write-Host "  DEDICATED CLUSTER ANALYSIS" -ForegroundColor White
        Write-Host ""

        if ($clusterRec.Recommended) {
            Write-ResultLine "Status" "RECOMMENDED" -ValueColor Green
            Write-ResultLine "Current Ingestion" "$(Format-DataSize $clusterRec.CurrentDailyIngestion)/day" -ValueColor Cyan
            Write-ResultLine "Minimum Tier" "$($clusterRec.MinimumClusterTier) GB/day" -ValueColor Cyan

            Write-Host ""
            Write-Host "  Benefits:" -ForegroundColor White
            foreach ($benefit in $clusterRec.Benefits) {
                Write-Host "    - $benefit" -ForegroundColor Cyan
            }

            Write-Host ""
            Write-Host "  Constraints to consider:" -ForegroundColor White
            foreach ($constraint in $clusterRec.Constraints) {
                Write-Host "    - $constraint" -ForegroundColor DarkGray
            }

            Write-Host ""
            Write-Host "  Documentation: $($clusterRec.DocumentationUrl)" -ForegroundColor DarkGray
        }
        elseif ($clusterRec.Reason -eq 'Already linked to cluster') {
            Write-ResultLine "Status" "Already using dedicated cluster" -ValueColor Green
            Write-ResultLine "Cluster Name" $clusterRec.ClusterName -ValueColor Cyan
            if ($clusterRec.ClusterCapacityTier) {
                Write-ResultLine "Cluster Tier" "$($clusterRec.ClusterCapacityTier) GB/day" -ValueColor Cyan
            }
            Write-ResultLine "Current Ingestion" "$(Format-DataSize $clusterRec.CurrentDailyIngestion)/day" -ValueColor Cyan
        }
        else {
            Write-ResultLine "Status" "Not recommended at current volume" -ValueColor Yellow
            Write-ResultLine "Current Ingestion" "$(Format-DataSize $clusterRec.CurrentDailyIngestion)/day" -ValueColor Cyan
            Write-ResultLine "Minimum Required" "100 GB/day" -ValueColor DarkGray
            if ($clusterRec.Note) {
                Write-Host ""
                Write-Host "  Note: $($clusterRec.Note)" -ForegroundColor DarkGray
            }
        }
    }

    # Analysis notes
    if ($cost.AnalysisNotes -and @($cost.AnalysisNotes).Count -gt 0) {
        Write-Host ""
        Write-Host "  ANALYSIS NOTES" -ForegroundColor White
        foreach ($note in $cost.AnalysisNotes) {
            Write-Host "  - $note" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "  Cost optimization analysis skipped (missing pricing or ingestion data)" -ForegroundColor Yellow
}

#-----------------------------------------------------------------------------
# Summary
#-----------------------------------------------------------------------------
Write-SectionHeader "Summary" -Color Green

Write-Host ""
Write-Host "  Authentication:" -ForegroundColor White
Write-Host "    - ARM API:         OK" -ForegroundColor Green
Write-Host "    - Graph API:       $(if ($collectedData.E5LicenseInfo -and -not $collectedData.E5LicenseInfo.PermissionIssue) { 'OK' } elseif ($collectedData.E5LicenseInfo -and $collectedData.E5LicenseInfo.PermissionIssue) { 'Limited (need Organization.Read.All)' } else { 'Failed' })" -ForegroundColor $(if ($collectedData.E5LicenseInfo -and -not $collectedData.E5LicenseInfo.PermissionIssue) { 'Green' } else { 'Yellow' })
Write-Host "    - Log Analytics:   $(if ($collectedData.IngestionTrend -and -not $SkipKqlQueries) { 'OK' } elseif ($SkipKqlQueries) { 'Skipped' } else { 'Failed' })" -ForegroundColor $(if ($collectedData.IngestionTrend -and -not $SkipKqlQueries) { 'Green' } elseif ($SkipKqlQueries) { 'Yellow' } else { 'Red' })
Write-Host ""
Write-Host "  Data Collection:" -ForegroundColor White
Write-Host "    - Workspace Config: OK" -ForegroundColor Green
Write-Host "    - Pricing Model:    $(if ($collectedData.SentinelPricingModel -and $collectedData.SentinelPricingModel.PricingModel -ne 'Unknown') { $collectedData.SentinelPricingModel.PricingModel } else { 'Unknown' })" -ForegroundColor $(if ($collectedData.SentinelPricingModel -and $collectedData.SentinelPricingModel.PricingModel -eq 'Simplified') { 'Green' } elseif ($collectedData.SentinelPricingModel -and $collectedData.SentinelPricingModel.PricingModel -eq 'Classic') { 'Yellow' } else { 'Red' })
Write-Host "    - Retail Prices:    $(if ($collectedData.PricingInfo) { 'OK' } else { 'Failed' })" -ForegroundColor $(if ($collectedData.PricingInfo) { 'Green' } else { 'Red' })
Write-Host "    - E5 Licenses:      $(if ($collectedData.E5LicenseInfo) { if ($collectedData.E5LicenseInfo.PermissionIssue) { 'Unable to query (permissions)' } elseif ($collectedData.E5LicenseInfo.TotalSeats -gt 0) { "$($collectedData.E5LicenseInfo.TotalSeats) seats" } else { "None found ($($collectedData.E5LicenseInfo.TotalSkusFound) SKUs checked)" } } else { 'Not available' })" -ForegroundColor $(if ($collectedData.E5LicenseInfo -and -not $collectedData.E5LicenseInfo.PermissionIssue -and $collectedData.E5LicenseInfo.TotalSeats -gt 0) { 'Green' } else { 'Yellow' })
Write-Host "    - Defender P2:      $(if ($collectedData.DefenderServersP2) { if ($collectedData.DefenderServersP2.Enabled) { "Enabled ($($collectedData.DefenderServersP2.ProtectedVMCount) VMs via $($collectedData.DefenderServersP2.VMCountMethod))" } else { 'Not enabled' } } else { 'Not checked' })" -ForegroundColor $(if ($collectedData.DefenderServersP2 -and $collectedData.DefenderServersP2.Enabled) { 'Green' } else { 'Yellow' })
Write-Host "    - Ingestion Data:   $(if ($collectedData.IngestionTrend) { "$($collectedData.IngestionTrend.Count) days" } else { 'Not available' })" -ForegroundColor $(if ($collectedData.IngestionTrend) { 'Green' } else { 'Yellow' })
Write-Host "    - E5 Daily Data:    $(if ($collectedData.E5DailyIngestion) { "$($collectedData.E5DailyIngestion.Count) days (accurate overage)" } else { 'Using averages' })" -ForegroundColor $(if ($collectedData.E5DailyIngestion) { 'Green' } else { 'Yellow' })
Write-Host "    - P2 Daily Data:    $(if ($collectedData.P2DailyIngestion) { "$($collectedData.P2DailyIngestion.Count) days (accurate benefit)" } else { 'Using averages' })" -ForegroundColor $(if ($collectedData.P2DailyIngestion) { 'Green' } else { 'Yellow' })
Write-Host "    - Retention Data:   $(if ($collectedData.TableRetention -and $collectedData.TableRetention.Tables.Count -gt 0) { "$($collectedData.TableRetention.Tables.Count) tables" } else { 'Not available' })" -ForegroundColor $(if ($collectedData.TableRetention -and $collectedData.TableRetention.Tables.Count -gt 0) { 'Green' } else { 'Yellow' })
Write-Host "    - Dedicated Cluster: $(if ($collectedData.DedicatedCluster) { if ($collectedData.DedicatedCluster.IsLinkedToCluster) { "Linked ($($collectedData.DedicatedCluster.ClusterName))" } else { 'Not linked' } } else { 'Not checked' })" -ForegroundColor $(if ($collectedData.DedicatedCluster -and $collectedData.DedicatedCluster.IsLinkedToCluster) { 'Green' } else { 'Yellow' })
Write-Host ""

# Show key findings
if ($collectedData.CostAnalysis) {
    $findings = @()

    if ($collectedData.CostAnalysis.PotentialSavings -gt 0) {
        $findings += "Switching to $($collectedData.CostAnalysis.OptimalTier) could save $currency $($collectedData.CostAnalysis.PotentialSavings)/month"
    }

    if ($collectedData.CostAnalysis.FreeIngestionGB -gt 0) {
        $findings += "Free data sources: $(Format-DataSize $collectedData.CostAnalysis.FreeIngestionGB)/day excluded from billing"
    }

    if ($collectedData.CostAnalysis.P2BenefitAppliedGB -gt 0) {
        $p2Finding = "Defender P2 benefit: $(Format-DataSize $collectedData.CostAnalysis.P2BenefitAppliedGB)/day applied"
        if ($collectedData.CostAnalysis.P2BenefitUtilization -lt 100) {
            $p2Finding += " ($($collectedData.CostAnalysis.P2BenefitUtilization)% of available benefit utilized)"
        }
        $findings += $p2Finding
    }

    if ($collectedData.CostAnalysis.BasicLogsCandidates -and @($collectedData.CostAnalysis.BasicLogsCandidates).Count -gt 0) {
        $basicSavings = ($collectedData.CostAnalysis.BasicLogsCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        $findings += "Basic Logs conversion could save $currency $([math]::Round($basicSavings, 2))/month"
    }

    if ($collectedData.CostAnalysis.AuxiliaryLogsCandidates -and @($collectedData.CostAnalysis.AuxiliaryLogsCandidates).Count -gt 0) {
        $auxSavings = ($collectedData.CostAnalysis.AuxiliaryLogsCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        $findings += "Auxiliary Logs conversion could save $currency $([math]::Round($auxSavings, 2))/month"
    }

    if ($collectedData.CostAnalysis.DataLakeCandidates -and @($collectedData.CostAnalysis.DataLakeCandidates).Count -gt 0) {
        $dataLakeSavings = ($collectedData.CostAnalysis.DataLakeCandidates | Measure-Object -Property PotentialSavings -Sum).Sum
        $findings += "Data Lake tier (6:1 compression) could save $currency $([math]::Round($dataLakeSavings, 2))/month on extended retention"
    }

    # Add retention findings
    if ($collectedData.RetentionAnalysis) {
        if ($collectedData.RetentionAnalysis.TotalRetentionCost -gt 0) {
            $findings += "Retention costs: $currency $($collectedData.RetentionAnalysis.TotalRetentionCost)/month"
        }
        if ($collectedData.RetentionAnalysis.RetentionOptimizationTips -and @($collectedData.RetentionAnalysis.RetentionOptimizationTips).Count -gt 0) {
            $retentionSavings = ($collectedData.RetentionAnalysis.RetentionOptimizationTips | Measure-Object -Property PotentialSavings -Sum).Sum
            $findings += "Data Lake tier migration could save $currency $([math]::Round($retentionSavings, 2))/month on retention"
        }
    }

    # Add dedicated cluster finding
    if ($collectedData.CostAnalysis.DedicatedClusterRecommendation -and $collectedData.CostAnalysis.DedicatedClusterRecommendation.Recommended) {
        $findings += "DEDICATED CLUSTER recommended: Ingesting $(Format-DataSize $collectedData.CostAnalysis.DedicatedClusterRecommendation.CurrentDailyIngestion)/day - can aggregate commitment tiers across workspaces"
    }

    if ($findings.Count -gt 0) {
        Write-Host "  KEY FINDINGS:" -ForegroundColor Green
        foreach ($finding in $findings) {
            Write-Host "    - $finding" -ForegroundColor Green
        }
    } else {
        Write-Host "  KEY FINDING: Current configuration appears optimal." -ForegroundColor Green
    }
}

Write-Host ""

#endregion Main Execution
