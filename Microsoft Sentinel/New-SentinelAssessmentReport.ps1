#Requires -Version 7.0
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Generates a comprehensive Microsoft Sentinel Assessment Report with health checks and MITRE ATT&CK coverage analysis.

.DESCRIPTION
    This script performs a comprehensive assessment of a Microsoft Sentinel workspace, providing
    security teams and consultants with actionable insights into detection coverage, configuration
    health, and operational status.

    The script connects to Azure REST APIs and Log Analytics to collect workspace data, runs 30+
    modular health checks for best-practice compliance, calculates MITRE ATT&CK coverage metrics,
    and generates professional deliverables including an interactive HTML report and MITRE Navigator
    visualization files.

    DATA COLLECTION:
    - Analytics rules (scheduled, NRT, Fusion, ML-based) with MITRE mappings
    - Data connectors and their health/ingestion status
    - Content Hub packages and templates
    - Automation rules and playbook integrations
    - Watchlists, workbooks, and hunting queries
    - Workspace configuration (retention, SKU, daily cap)
    - Table-level retention and Basic Logs configuration
    - Data Collection Endpoints (DCEs) and Data Collection Rules (DCRs)
    - Ingestion trends and volume analysis (via KQL queries)
    - Agent health and heartbeat status
    - SentinelHealth diagnostic data (if enabled)

    HEALTH CHECKS:
    - Workspace Configuration: UEBA, Anomalies, Fusion, retention, daily cap, commitment tier
    - Data Connectors: Core connector presence, update availability, health status, staleness
    - Analytics Rules: Template updates, visibility gaps, disabled rules, NRT status
    - Analytics Health: Execution failures, delays, skipped windows, auto-disabled rules, query errors
    - MITRE Coverage: Parent/sub-technique coverage, uncovered tactics
    - Automation: Rule presence, playbook integration
    - Ingestion: Volume anomalies, dominant tables
    - Data Retention: Table-level settings, archive tier, Basic Logs usage
    - Agent Health: Heartbeat status, operation errors

    OUTPUT FILES:
    - Interactive HTML report with Bootstrap 5 styling, DataTables, and Chart.js visualizations
    - MITRE ATT&CK Navigator JSON layer file (v4.5 format, ATT&CK v18)
    - MITRE ATT&CK Navigator SVG visualization (requires Python)
    - Optional JSON export of raw collected data

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Microsoft Sentinel workspace.

.PARAMETER ResourceGroupName
    The resource group name where the Log Analytics workspace is deployed.

.PARAMETER WorkspaceName
    The Log Analytics workspace name with Microsoft Sentinel enabled.

.PARAMETER ClientName
    Optional client/organization name for the report header. Defaults to "Microsoft Sentinel Assessment".

.PARAMETER OutputPath
    Optional directory path for output files. Defaults to current directory.

.PARAMETER SkipKqlQueries
    Skip KQL queries for ingestion/health data (faster execution, less data).
    When enabled, the following data will not be collected:
    - Ingestion trends and volume analysis
    - Connector health from SentinelHealth table
    - Agent heartbeat status
    - Analytics rule execution health
    This is useful for quick assessments or when Log Analytics query permissions are limited.

.PARAMETER ExportJson
    Export raw collected data to a JSON file for further analysis or archival.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo[]
    Returns paths to the generated HTML report, MITRE Navigator JSON, and SVG files.

.NOTES
    File Name      : New-SentinelAssessmentReport.ps1
    Author         : Daniel Streefkerk
    Copyright      : MIT License

    PREREQUISITES:
    ==============

    PowerShell:
    - PowerShell 7.0 or later (cross-platform compatible)
    - Az.Accounts module (Install-Module Az.Accounts)
    - Az.OperationalInsights module (for KQL queries, Install-Module Az.OperationalInsights)

    Azure Authentication:
    - Must be authenticated to Azure (Connect-AzAccount)
    - The script will automatically handle token acquisition for both ARM and Log Analytics APIs

    REQUIRED AZURE RBAC ROLES:
    ==========================
    The following roles (or equivalent permissions) are required at the specified scopes:

    On the Log Analytics Workspace (resource group or workspace scope):
    ┌─────────────────────────────────────┬────────────────────────────────────────────────────┐
    │ Role                                │ Purpose                                            │
    ├─────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ Microsoft Sentinel Reader           │ Read Sentinel resources: analytics rules,         │
    │ (minimum required)                  │ data connectors, automation rules, watchlists,    │
    │                                     │ content packages, templates, settings, incidents  │
    ├─────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ Log Analytics Reader                │ Execute KQL queries for ingestion analysis,       │
    │ (required for KQL queries)          │ connector health, agent status, SentinelHealth    │
    │                                     │ table queries. Use -SkipKqlQueries if unavailable │
    ├─────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ Reader                              │ Read workspace configuration (retention, SKU,     │
    │ (on workspace resource)             │ daily cap), table schemas and retention settings  │
    └─────────────────────────────────────┴────────────────────────────────────────────────────┘

    On the Subscription (subscription scope):
    ┌─────────────────────────────────────┬────────────────────────────────────────────────────┐
    │ Role                                │ Purpose                                            │
    ├─────────────────────────────────────┼────────────────────────────────────────────────────┤
    │ Reader                              │ Enumerate Data Collection Endpoints (DCEs) and    │
    │ or Monitoring Reader                │ Data Collection Rules (DCRs) across subscription  │
    └─────────────────────────────────────┴────────────────────────────────────────────────────┘

    Recommended Role Assignments:
    - For full assessment: Assign "Microsoft Sentinel Reader" + "Log Analytics Reader" at the
      resource group level containing the Sentinel workspace, plus "Reader" at subscription level
    - For quick assessment (no KQL): "Microsoft Sentinel Reader" + "Reader" at resource group level
    - Alternative: "Contributor" or "Owner" roles include all required permissions but grant
      more access than necessary (not recommended for least-privilege)

    Built-in Role Hierarchy (any of these includes Sentinel read access):
    - Microsoft Sentinel Reader < Microsoft Sentinel Responder < Microsoft Sentinel Contributor
    - Reader < Contributor < Owner (Azure roles - broader scope)

    Note: If using a service principal, ensure it has the same role assignments.
    The script uses the authenticated context from Connect-AzAccount or existing Az session.

    Python (Optional - for SVG generation):
    - Python 3.7 or later
    - mitreattack-python package: pip install mitreattack-python
    - If Python is not available, the script will still generate the HTML report and Navigator JSON,
      but will skip SVG generation with a warning.

    INTERNET CONNECTIVITY:
    ======================
    This script requires internet access to the following endpoints:

    Azure APIs:
    - https://management.azure.com/ - Azure Resource Manager API for Sentinel/Log Analytics REST calls
    - https://api.loganalytics.io/ - Log Analytics query API for KQL queries

    MITRE ATT&CK Data:
    - https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
      Downloads the MITRE ATT&CK Enterprise framework data (approx. 40MB)
      Cached locally in %APPDATA%\SentinelAnalyticsTools\ for 7 days

    CDN Resources (for HTML report):
    - https://cdn.jsdelivr.net/ - Bootstrap CSS/JS, Chart.js, DataTables
    - https://code.jquery.com/ - jQuery
    - https://unpkg.com/ - Lucide icons
    Note: The generated HTML report requires internet access to load these resources when viewed.

    CACHING:
    ========
    - MITRE ATT&CK data is cached in %APPDATA%\SentinelAnalyticsTools\mitre-attack-enterprise.json
    - Cache is refreshed after 7 days or if corrupted
    - Stale cache is used as fallback if download fails

.EXAMPLE
    .\New-SentinelAssessmentReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -ClientName "Contoso Inc"

    Full assessment with client name. Generates HTML report, Navigator JSON, and SVG files.

.EXAMPLE
    .\New-SentinelAssessmentReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -SkipKqlQueries

    Quick assessment without KQL queries. Faster execution but excludes ingestion analysis,
    connector health details, and agent status.

.EXAMPLE
    .\New-SentinelAssessmentReport.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -ExportJson

    Full assessment with raw data exported to JSON for further analysis or automation.

.LINK
    https://learn.microsoft.com/en-us/azure/sentinel/roles - Microsoft Sentinel roles and permissions
    https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access - Log Analytics workspace access
    https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/monitor - Azure Monitor built-in roles
    https://learn.microsoft.com/en-us/azure/sentinel/ - Microsoft Sentinel documentation
    https://github.com/mitre/cti - MITRE ATT&CK CTI repository
    https://mitre-attack.github.io/attack-navigator/ - MITRE ATT&CK Navigator
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $false, HelpMessage = 'Client/Organization name for report header')]
    [string]$ClientName = "Microsoft Sentinel Assessment",

    [Parameter(Mandatory = $false, HelpMessage = 'Output directory for report files (defaults to current directory)')]
    [string]$OutputPath = ".",

    [Parameter(Mandatory = $false, HelpMessage = 'Skip KQL queries for faster execution')]
    [switch]$SkipKqlQueries,

    [Parameter(Mandatory = $false, HelpMessage = 'Export raw data to JSON file')]
    [switch]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helper Functions

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

function Get-SafeProperty {
    <#
    .SYNOPSIS
    Safely gets a property value from an object, returning $null if it doesn't exist.
    #>
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

function Write-SectionHeader {
    <#
    .SYNOPSIS
    Writes a formatted section header for progress output.
    #>
    param(
        [string]$Title,
        [ConsoleColor]$Color = 'Cyan'
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor $Color
    Write-Host " $Title" -ForegroundColor $Color
    Write-Host ("=" * 70) -ForegroundColor $Color
}

function Get-MitreAttackTechniques {
    <#
    .SYNOPSIS
    Retrieves the full list of MITRE ATT&CK Enterprise techniques, with local caching.
    #>
    [CmdletBinding()]
    param(
        [int]$CacheMaxAgeDays = 7
    )

    $attackUrl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    $cacheDir = Join-Path $env:APPDATA "SentinelAnalyticsTools"
    $cacheFile = Join-Path $cacheDir "mitre-attack-enterprise.json"

    # Ensure cache directory exists
    if (-not (Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }

    # Check if cache exists and is fresh
    $useCache = $false
    if (Test-Path $cacheFile) {
        $cacheAge = (Get-Date) - (Get-Item $cacheFile).LastWriteTime
        if ($cacheAge.TotalDays -lt $CacheMaxAgeDays) {
            $useCache = $true
            Write-Verbose "Using cached MITRE ATT&CK data (age: $([math]::Round($cacheAge.TotalDays, 1)) days)"
        }
    }

    try {
        if ($useCache) {
            $attackData = Get-Content -Path $cacheFile -Raw | ConvertFrom-Json
        }
        else {
            Write-Host "  Downloading MITRE ATT&CK framework data..." -ForegroundColor DarkGray
            $attackData = Invoke-RestMethod -Uri $attackUrl -ErrorAction Stop
            $attackData | ConvertTo-Json -Depth 20 -Compress | Out-File -FilePath $cacheFile -Encoding utf8 -Force
        }

        # Parse techniques
        $techniques = @{}

        foreach ($obj in $attackData.objects) {
            $revoked = $obj.PSObject.Properties.Match('revoked').Count -gt 0 -and $obj.revoked
            $deprecated = $obj.PSObject.Properties.Match('x_mitre_deprecated').Count -gt 0 -and $obj.x_mitre_deprecated

            if ($obj.type -eq 'attack-pattern' -and -not $revoked -and -not $deprecated) {
                $techRef = $obj.external_references |
                    Where-Object { $_.source_name -eq 'mitre-attack' -and $_.external_id -match '^T\d+(\.\d+)?$' }

                if ($techRef) {
                    $techID = $techRef.external_id
                    $techName = $obj.name

                    $tactics = @()
                    if ($obj.kill_chain_phases) {
                        $tactics = $obj.kill_chain_phases |
                            Where-Object { $_.kill_chain_name -eq 'mitre-attack' } |
                            ForEach-Object { $_.phase_name }
                    }

                    $isSubtechnique = $techID -match '\.\d+$'

                    $techniques[$techID] = @{
                        ID             = $techID
                        Name           = $techName
                        Tactics        = $tactics
                        IsSubtechnique = $isSubtechnique
                    }
                }
            }
        }

        Write-Verbose "Loaded $($techniques.Count) active techniques from MITRE ATT&CK framework"
        return $techniques
    }
    catch {
        Write-Warning "Failed to retrieve MITRE ATT&CK data: $_"
        if ((Test-Path $cacheFile) -and -not $useCache) {
            Write-Host "  Attempting to use stale cache as fallback..." -ForegroundColor Yellow
            return Get-MitreAttackTechniques -CacheMaxAgeDays 9999
        }
        return $null
    }
}

#endregion Helper Functions

#region Authentication Functions

function Get-AzureAccessToken {
    <#
    .SYNOPSIS
    Gets an Azure access token for the management API.
    #>
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

#endregion Authentication Functions

#region Data Collection Functions

function Get-SentinelAnalyticsRules {
    <#
    .SYNOPSIS
    Retrieves all analytics rules from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/alertRules?api-version=$ApiVersion"
    $allRules = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allRules += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allRules
}

function Get-SentinelAlertRuleTemplates {
    <#
    .SYNOPSIS
    Retrieves all alert rule templates from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/alertRuleTemplates?api-version=$ApiVersion"
    $allTemplates = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allTemplates += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allTemplates
}

function Get-SentinelDataConnectors {
    <#
    .SYNOPSIS
    Retrieves all data connectors from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/dataConnectors?api-version=$ApiVersion"
    $allConnectors = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allConnectors += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allConnectors
}

function Get-SentinelContentTemplates {
    <#
    .SYNOPSIS
    Retrieves all content templates with expanded mainTemplate from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/contentTemplates?api-version=$ApiVersion&`$expand=properties/mainTemplate"
    $allTemplates = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allTemplates += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allTemplates
}

function Get-SentinelContentPackages {
    <#
    .SYNOPSIS
    Retrieves all installed content packages (Content Hub solutions) from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/contentPackages?api-version=$ApiVersion"
    $allPackages = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allPackages += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allPackages
}

function Get-SentinelSourceControls {
    <#
    .SYNOPSIS
    Retrieves all source control (repository) connections from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers
    )

    $uri = "$BaseUri/sourcecontrols?api-version=2023-06-01-preview"
    $allSourceControls = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allSourceControls += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allSourceControls
}

function Get-SentinelWorkspaceManagerConfig {
    <#
    .SYNOPSIS
    Retrieves workspace manager configuration to determine if this is a central workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers
    )

    $uri = "$BaseUri/workspaceManagerConfigurations?api-version=2024-01-01-preview"
    try {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value -and @($response.value).Count -gt 0) {
            return $response.value[0]  # Return the default configuration
        }
        return $null
    }
    catch {
        return $null
    }
}

function Get-SentinelWorkspaceManagerMembers {
    <#
    .SYNOPSIS
    Retrieves workspace manager members (workspaces managed by this central workspace).
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers
    )

    $uri = "$BaseUri/workspaceManagerMembers?api-version=2024-01-01-preview"
    $allMembers = @()

    try {
        do {
            $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
            if ($response.value) {
                $allMembers += $response.value
            }
            $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
        } while ($uri)
    }
    catch {
        # Silently handle - workspace manager may not be enabled
    }

    return ,$allMembers
}

function Get-SentinelAutomationRules {
    <#
    .SYNOPSIS
    Retrieves all automation rules from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/automationRules?api-version=$ApiVersion"
    $allRules = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allRules += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allRules
}

function Get-SentinelWatchlists {
    <#
    .SYNOPSIS
    Retrieves all watchlists from the Sentinel workspace.
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/watchlists?api-version=$ApiVersion"
    $allWatchlists = @()

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        if ($response.value) {
            $allWatchlists += $response.value
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    return ,$allWatchlists
}

function Get-SentinelWorkbooks {
    <#
    .SYNOPSIS
    Retrieves all workbooks from the resource group that are tagged for Sentinel.
    #>
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [hashtable]$Headers
    )

    # Workbooks are Azure resources under Microsoft.Insights/workbooks
    # We filter by category 'sentinel' to get Sentinel-related workbooks
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/workbooks?api-version=2022-04-01&category=sentinel"
    $allWorkbooks = @()

    try {
        do {
            $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
            if ($response.value) {
                $allWorkbooks += $response.value
            }
            $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
        } while ($uri)
    }
    catch {
        Write-Verbose "Could not retrieve workbooks: $_"
    }

    return ,$allWorkbooks
}

function Get-SentinelSettings {
    <#
    .SYNOPSIS
    Retrieves Sentinel settings (UEBA, Anomalies, EntityAnalytics).
    #>
    param(
        [string]$BaseUri,
        [hashtable]$Headers,
        [string]$ApiVersion
    )

    $uri = "$BaseUri/settings?api-version=$ApiVersion"

    try {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
        return ,@($response.value)
    }
    catch {
        Write-Warning "Could not retrieve Sentinel settings: $_"
        return ,@()
    }
}

function Get-WorkspaceConfig {
    <#
    .SYNOPSIS
    Retrieves Log Analytics workspace configuration.
    #>
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName,
        [hashtable]$Headers
    )

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName`?api-version=2023-09-01"

    try {
        return Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
    }
    catch {
        Write-Warning "Could not retrieve workspace configuration: $_"
        return $null
    }
}

function Get-TableRetention {
    <#
    .SYNOPSIS
    Retrieves table-level retention settings from the workspace.
    #>
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName,
        [hashtable]$Headers
    )

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables?api-version=2023-09-01"
    $allTables = @()

    try {
        do {
            $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
            if ($response.value) {
                $allTables += $response.value
            }
            $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
        } while ($uri)
    }
    catch {
        Write-Warning "Could not retrieve table retention settings: $_"
    }

    return ,$allTables
}

function Format-Plural {
    <#
    .SYNOPSIS
    Returns a properly pluralized string like "1 rule" or "5 rules".
    #>
    param(
        [int]$Count,
        [string]$Singular,
        [string]$Plural = $null
    )
    if (-not $Plural) { $Plural = "${Singular}s" }
    $noun = if ($Count -eq 1) { $Singular } else { $Plural }
    return "$Count $noun"
}

function Test-LogAnalyticsAuth {
    <#
    .SYNOPSIS
    Tests Log Analytics authentication and triggers re-auth if needed.
    Returns $true if authentication is valid, $false otherwise.
    #>
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

function Invoke-SentinelKqlQuery {
    <#
    .SYNOPSIS
    Executes a KQL query against the Log Analytics workspace using Az.OperationalInsights.
    #>
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

function Get-DataCollectionEndpoints {
    <#
    .SYNOPSIS
    Retrieves Data Collection Endpoints (DCEs) from the subscription.
    #>
    param(
        [string]$SubscriptionId,
        [hashtable]$Headers
    )

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Insights/dataCollectionEndpoints?api-version=2022-06-01"
    $allDces = @()

    try {
        do {
            $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
            if ($response.value) {
                $allDces += $response.value
            }
            $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
        } while ($uri)
    }
    catch {
        Write-Verbose "Could not retrieve Data Collection Endpoints: $_"
    }

    return ,$allDces
}

function Get-DataCollectionRules {
    <#
    .SYNOPSIS
    Retrieves Data Collection Rules (DCRs) from the subscription.
    #>
    param(
        [string]$SubscriptionId,
        [hashtable]$Headers
    )

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Insights/dataCollectionRules?api-version=2022-06-01"
    $allDcrs = @()

    try {
        do {
            $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $Headers
            if ($response.value) {
                $allDcrs += $response.value
            }
            $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
        } while ($uri)
    }
    catch {
        Write-Verbose "Could not retrieve Data Collection Rules: $_"
    }

    return ,$allDcrs
}

#endregion Data Collection Functions

#region Health Check Functions

function Invoke-AllHealthChecks {
    <#
    .SYNOPSIS
    Runs all health checks and returns consolidated results.
    #>
    param(
        [hashtable]$CollectedData
    )

    $checks = @()

    # CFG-001: UEBA Enabled
    # UEBA uses kind='Ueba' with dataSources array, EntityAnalytics is for entity provider sync (AD/AAD)
    $uebaSetting = $CollectedData.Settings | Where-Object { $_.kind -eq 'Ueba' }
    $uebaDataSources = if ($uebaSetting) { Get-SafeProperty $uebaSetting.properties 'dataSources' } else { $null }
    $uebaEnabled = $uebaDataSources -and @($uebaDataSources).Count -gt 0

    $entityAnalyticsSetting = $CollectedData.Settings | Where-Object { $_.kind -eq 'EntityAnalytics' }
    $entityProviders = if ($entityAnalyticsSetting) { Get-SafeProperty $entityAnalyticsSetting.properties 'entityProviders' } else { $null }
    $entityAnalyticsEnabled = $entityProviders -and @($entityProviders).Count -gt 0

    $checks += [PSCustomObject]@{
        CheckId     = 'CFG-001'
        CheckName   = 'UEBA Enabled'
        Category    = 'Workspace Configuration'
        Status      = if ($uebaEnabled) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($uebaEnabled) {
            "User and Entity Behavior Analytics is enabled with $(Format-Plural @($uebaDataSources).Count 'data source'): $($uebaDataSources -join ', ')."
        } else {
            'UEBA is not enabled. Consider enabling for advanced threat detection.'
        }
        Details     = if (-not $uebaEnabled) {
            [ordered]@{
                Recommendation   = 'Enable UEBA to gain advanced threat detection through behavioral profiling of users and entities across your environment.'
                Benefits         = 'Identifies anomalous behaviors such as impossible travel, unusual resource access, and credential anomalies. Detects compromised accounts and surfaces insider threats using ML-based analytics. Enriches incidents with user and entity context for faster triage.'
                'Learn more'     = 'https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics'
                'How to enable'  = 'https://learn.microsoft.com/en-us/azure/sentinel/enable-entity-behavior-analytics'
            }
        } else { $null }
    }

    # CFG-002: Anomalies Enabled
    $anomaliesEnabled = $CollectedData.Settings | Where-Object {
        $_.kind -eq 'Anomalies' -and (Get-SafeProperty $_.properties 'isEnabled') -eq $true
    }
    $checks += [PSCustomObject]@{
        CheckId     = 'CFG-002'
        CheckName   = 'Anomalies Enabled'
        Category    = 'Workspace Configuration'
        Status      = if ($anomaliesEnabled) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($anomaliesEnabled) { 'Anomalies detection is enabled.' } else { 'Anomalies detection is not enabled. Consider enabling for ML-based threat detection.' }
        Details     = $null
    }

    # CFG-003: Retention >= 90 days
    $retention = Get-SafeProperty (Get-SafeProperty $CollectedData.WorkspaceConfig 'properties') 'retentionInDays'
    $checks += [PSCustomObject]@{
        CheckId     = 'CFG-003'
        CheckName   = 'Retention >= 90 Days'
        Category    = 'Workspace Configuration'
        Status      = if ($retention -ge 90) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = "Workspace retention is set to $(Format-Plural $retention 'day')." + $(if ($retention -lt 90) { ' Consider increasing to at least 90 days for compliance.' } else { '' })
        Details     = @{ RetentionDays = $retention }
    }

    # CFG-004: Fusion Enabled
    $fusionRule = $CollectedData.AnalyticsRules | Where-Object {
        $_.kind -eq 'Fusion' -and (Get-SafeProperty $_.properties 'enabled') -eq $true
    }
    $checks += [PSCustomObject]@{
        CheckId     = 'CFG-004'
        CheckName   = 'Fusion Enabled'
        Category    = 'Workspace Configuration'
        Status      = if ($fusionRule) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($fusionRule) { 'Fusion advanced multistage attack detection is enabled.' } else { 'Fusion rule is not enabled. Consider enabling for advanced attack correlation.' }
        Details     = $null
    }

    # CFG-005: Daily Cap Status
    $dailyCap = Get-SafeProperty (Get-SafeProperty (Get-SafeProperty $CollectedData.WorkspaceConfig 'properties') 'workspaceCapping') 'dailyQuotaGb'
    $hasDailyCap = $dailyCap -and $dailyCap -gt 0
    $checks += [PSCustomObject]@{
        CheckId     = 'CFG-005'
        CheckName   = 'Daily Cap Status'
        Category    = 'Workspace Configuration'
        Status      = if ($hasDailyCap) { 'Warning' } else { 'Pass' }
        Severity    = 'Warning'
        Description = if ($hasDailyCap) { "Daily ingestion cap is set to $dailyCap GB. Risk of log loss if exceeded." } else { 'No daily ingestion cap configured - no risk of log loss from capping.' }
        Details     = @{ DailyCapGb = $dailyCap }
    }

    # CFG-006: Commitment Tier
    $sku = Get-SafeProperty (Get-SafeProperty (Get-SafeProperty $CollectedData.WorkspaceConfig 'properties') 'sku') 'name'
    $capacityReservation = Get-SafeProperty (Get-SafeProperty (Get-SafeProperty $CollectedData.WorkspaceConfig 'properties') 'sku') 'capacityReservationLevel'
    $checks += [PSCustomObject]@{
        CheckId     = 'CFG-006'
        CheckName   = 'Commitment Tier'
        Category    = 'Workspace Configuration'
        Status      = 'Info'
        Severity    = 'Info'
        Description = if ($capacityReservation) { "Using commitment tier: $capacityReservation GB/day." } else { "Pricing tier: $sku (Pay-as-you-go)." }
        Details     = @{ Sku = $sku; CapacityReservation = $capacityReservation }
    }

    # CFG-007: Sentinel Free Data
    $sentinelDefaults = $CollectedData.Settings | Where-Object {
        $_.kind -eq 'EyesOn' -or $_.kind -eq 'SecurityInsightsDefaultSettings'
    }
    $freeDataEnabled = $sentinelDefaults | Where-Object {
        (Get-SafeProperty $_.properties 'isEnabled') -eq $true
    }
    $checks += [PSCustomObject]@{
        CheckId     = 'CFG-007'
        CheckName   = 'Sentinel Free Data'
        Category    = 'Workspace Configuration'
        Status      = 'Info'
        Severity    = 'Info'
        Description = if ($freeDataEnabled) { 'Sentinel free data tier is enabled for eligible data types.' } else { 'Sentinel free data tier settings not detected or disabled.' }
        Details     = @{ Settings = $sentinelDefaults | ForEach-Object { $_.kind } }
    }

    # CON-001: Connectors with Updates
    $connectorsWithUpdates = @(Get-ConnectorsWithUpdates -Connectors $CollectedData.DataConnectors -ContentTemplates $CollectedData.ContentTemplates)
    $checks += [PSCustomObject]@{
        CheckId     = 'CON-001'
        CheckName   = 'Connectors with Updates'
        Category    = 'Data Connectors'
        Status      = if ($connectorsWithUpdates.Count -eq 0) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($connectorsWithUpdates.Count -eq 0) { 'All data connectors are up to date.' } else { "$(Format-Plural $connectorsWithUpdates.Count 'connector') have pending updates available." }
        Details     = $connectorsWithUpdates
    }

    # CON-002: Unhealthy Connectors (from KQL if available)
    if ($CollectedData.ConnectorHealth) {
        $unhealthyConnectors = @($CollectedData.ConnectorHealth | Where-Object { $_.Status -ne 'Success' })
        $checks += [PSCustomObject]@{
            CheckId     = 'CON-002'
            CheckName   = 'Unhealthy Connectors'
            Category    = 'Data Connectors'
            Status      = if ($unhealthyConnectors.Count -eq 0) { 'Pass' } else { 'Critical' }
            Severity    = 'Critical'
            Description = if ($unhealthyConnectors.Count -eq 0) { 'All monitored connectors are healthy.' } else { "$(Format-Plural $unhealthyConnectors.Count 'connector') reporting unhealthy status." }
            Details     = $unhealthyConnectors
        }
    }

    # CON-003: Core Connectors Missing
    # Core connectors with their API identifiers and friendly names
    $coreConnectors = @(
        @{ Id = 'AzureActiveDirectory'; DisplayName = 'Microsoft Entra ID' }
        @{ Id = 'Office365'; DisplayName = 'Microsoft 365' }
        @{ Id = 'MicrosoftThreatProtection'; DisplayName = 'Microsoft Defender XDR' }
        @{ Id = 'MicrosoftDefenderAdvancedThreatProtection'; DisplayName = 'Microsoft Defender for Endpoint' }
    )
    # Check both kind and name fields (connectors can appear as direct kind or as StaticUI/GenericUI with name)
    $allConnectorIdentifiers = @($CollectedData.DataConnectors | ForEach-Object { $_.kind; $_.name }) | Where-Object { $_ }
    $presentCore = @($coreConnectors | Where-Object { $_.Id -in $allConnectorIdentifiers })
    $missingCore = @($coreConnectors | Where-Object { $_.Id -notin $allConnectorIdentifiers })
    $missingCoreNames = @($missingCore | ForEach-Object { $_.DisplayName })
    $presentCoreNames = @($presentCore | ForEach-Object { $_.DisplayName })
    $checks += [PSCustomObject]@{
        CheckId     = 'CON-003'
        CheckName   = 'Core Connectors'
        Category    = 'Data Connectors'
        Status      = if ($missingCore.Count -eq 0) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($missingCore.Count -eq 0) { 'All core Microsoft connectors are configured.' } else { "Missing core connectors: $($missingCoreNames -join ', ')" }
        Details     = @{ MissingConnectors = $missingCoreNames; PresentConnectors = $presentCoreNames }
    }

    # CON-004: Stale Connectors (from KQL if available)
    if ($null -ne $CollectedData.StaleConnectors) {
        $staleConnectors = @($CollectedData.StaleConnectors)
        $checks += [PSCustomObject]@{
            CheckId     = 'CON-004'
            CheckName   = 'Stale Connectors'
            Category    = 'Data Connectors'
            Status      = if ($staleConnectors.Count -eq 0) { 'Pass' } else { 'Warning' }
            Severity    = 'Warning'
            Description = if ($staleConnectors.Count -eq 0) { 'All connectors have received data in the last 24 hours.' } else { "$(Format-Plural $staleConnectors.Count 'connector') have not received data in 24+ hours." }
            Details     = $staleConnectors
        }
    }

    # ANA-001: Rules with Updates
    $rulesWithUpdates = @(Get-RulesWithUpdates -Rules $CollectedData.AnalyticsRules -AlertRuleTemplates $CollectedData.AlertRuleTemplates -ContentTemplates $CollectedData.ContentTemplates)
    $checks += [PSCustomObject]@{
        CheckId     = 'ANA-001'
        CheckName   = 'Rules with Updates'
        Category    = 'Analytics Rules'
        Status      = if ($rulesWithUpdates.Count -eq 0) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($rulesWithUpdates.Count -eq 0) { 'All analytics rules are up to date.' } else { "$(Format-Plural $rulesWithUpdates.Count 'rule') have newer template versions available." }
        Details     = $rulesWithUpdates
    }

    # ANA-002: Visibility Gaps (High/Medium severity without incidents)
    $visibilityGaps = @(Get-VisibilityGaps -Rules $CollectedData.AnalyticsRules -AlertRuleTemplates $CollectedData.AlertRuleTemplates -ContentTemplates $CollectedData.ContentTemplates -AlertVolumeByRuleName $CollectedData.AlertVolumeByRuleName)
    $checks += [PSCustomObject]@{
        CheckId     = 'ANA-002'
        CheckName   = 'Visibility Gaps'
        Category    = 'Analytics Rules'
        Status      = if ($visibilityGaps.Count -eq 0) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($visibilityGaps.Count -eq 0) { 'No visibility gaps detected.' } else { "$(Format-Plural $visibilityGaps.Count 'rule') may have visibility gaps (disabled or not creating incidents)." }
        Details     = $visibilityGaps
    }

    # ANA-003: Rules Without MITRE
    $rulesWithoutMitre = @($CollectedData.AnalyticsRules | Where-Object {
        $props = Get-SafeProperty $_ 'properties'
        $tactics = Get-SafeProperty $props 'tactics'
        $techniques = Get-SafeProperty $props 'techniques'
        $hasTactics = $tactics -and @($tactics).Count -gt 0
        $hasTechniques = $techniques -and @($techniques).Count -gt 0
        -not $hasTactics -and -not $hasTechniques
    })
    $checks += [PSCustomObject]@{
        CheckId     = 'ANA-003'
        CheckName   = 'Rules Without MITRE'
        Category    = 'Analytics Rules'
        Status      = 'Info'
        Severity    = 'Info'
        Description = "$(Format-Plural $rulesWithoutMitre.Count 'rule') have no MITRE ATT&CK mappings."
        Details     = $rulesWithoutMitre | ForEach-Object { Get-SafeProperty $_.properties 'displayName' }
    }

    # ANA-004: Custom Rules
    $customRules = @($CollectedData.AnalyticsRules | Where-Object {
        $null -eq (Get-SafeProperty $_.properties 'alertRuleTemplateName')
    })
    $checks += [PSCustomObject]@{
        CheckId     = 'ANA-004'
        CheckName   = 'Custom Rules'
        Category    = 'Analytics Rules'
        Status      = 'Info'
        Severity    = 'Info'
        Description = "$(Format-Plural $customRules.Count 'custom rule') created for environment-specific detections."
        Details     = $customRules | ForEach-Object { Get-SafeProperty $_.properties 'displayName' }
    }

    # ANA-005: Disabled Rules
    $disabledRules = @($CollectedData.AnalyticsRules | Where-Object {
        (Get-SafeProperty $_.properties 'enabled') -eq $false
    })
    $checks += [PSCustomObject]@{
        CheckId     = 'ANA-005'
        CheckName   = 'Disabled Rules'
        Category    = 'Analytics Rules'
        Status      = 'Info'
        Severity    = 'Info'
        Description = "$(Format-Plural $disabledRules.Count 'rule') currently disabled."
        Details     = $disabledRules | ForEach-Object { Get-SafeProperty $_.properties 'displayName' }
    }

    # ANA-006: NRT Rules Disabled
    $disabledNrt = @($CollectedData.AnalyticsRules | Where-Object {
        $_.kind -eq 'NRT' -and (Get-SafeProperty $_.properties 'enabled') -eq $false
    })
    $checks += [PSCustomObject]@{
        CheckId     = 'ANA-006'
        CheckName   = 'NRT Rules Disabled'
        Category    = 'Analytics Rules'
        Status      = if ($disabledNrt.Count -eq 0) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($disabledNrt.Count -eq 0) { 'All NRT rules are enabled.' } else { "$(Format-Plural $disabledNrt.Count 'Near-Real-Time rule') disabled." }
        Details     = $disabledNrt | ForEach-Object { Get-SafeProperty $_.properties 'displayName' }
    }

    # ANA-007: High Incident Volume
    if ($CollectedData.IncidentVolumeByRule) {
        $highVolumeThreshold = 10
        $highVolumeRules = @($CollectedData.IncidentVolumeByRule | Where-Object { $_.DailyAverage -gt $highVolumeThreshold })
        $checks += [PSCustomObject]@{
            CheckId     = 'ANA-007'
            CheckName   = 'High Incident Volume'
            Category    = 'Analytics Rules'
            Status      = if ($highVolumeRules.Count -eq 0) { 'Pass' } else { 'Warning' }
            Severity    = 'Warning'
            Description = if ($highVolumeRules.Count -eq 0) { "No rules averaging more than $highVolumeThreshold incidents/day over 30 days." } else { "$(Format-Plural $highVolumeRules.Count 'rule') averaging more than $highVolumeThreshold incidents/day. Review for tuning opportunities." }
            Details     = $highVolumeRules | ForEach-Object { "$($_.RuleName) ($($_.DailyAverage)/day)" }
        }
    }

    # Analytics Health checks (from _SentinelHealth table, if available)
    if ($CollectedData.AnalyticsHealthSummary) {
        $healthSummary = @($CollectedData.AnalyticsHealthSummary)
        $rulesWithFailures = @($healthSummary | Where-Object { $_.FailureCount -gt 0 })
        $highFailureRateRules = @($healthSummary | Where-Object { $_.FailureRate -gt 50 })
        $totalExecutions = ($healthSummary | Measure-Object -Property TotalExecutions -Sum).Sum
        $totalFailures = ($healthSummary | Measure-Object -Property FailureCount -Sum).Sum
        $overallSuccessRate = if ($totalExecutions -gt 0) { [math]::Round((($totalExecutions - $totalFailures) / $totalExecutions) * 100, 1) } else { 100 }

        # ANAH-001: Rule Execution Failures
        $checks += [PSCustomObject]@{
            CheckId     = 'ANAH-001'
            CheckName   = 'Rule Execution Failures'
            Category    = 'Analytics Health'
            Status      = if ($rulesWithFailures.Count -eq 0) { 'Pass' } elseif ($highFailureRateRules.Count -gt 0) { 'Critical' } else { 'Warning' }
            Severity    = if ($highFailureRateRules.Count -gt 0) { 'Critical' } else { 'Warning' }
            Description = if ($rulesWithFailures.Count -eq 0) {
                "All analytics rules executed successfully in the last 7 days ($totalExecutions total executions)."
            } else {
                "$(Format-Plural $rulesWithFailures.Count 'rule') experienced execution failures in the last 7 days. Overall success rate: $overallSuccessRate%."
            }
            Details     = @{
                TotalExecutions = $totalExecutions
                TotalFailures = $totalFailures
                SuccessRate = $overallSuccessRate
                RulesWithFailures = $rulesWithFailures | ForEach-Object {
                    @{ RuleName = $_.SentinelResourceName; Failures = $_.FailureCount; FailureRate = $_.FailureRate }
                }
            }
        }

        # ANAH-002: High Failure Rate Rules
        $checks += [PSCustomObject]@{
            CheckId     = 'ANAH-002'
            CheckName   = 'High Failure Rate Rules'
            Category    = 'Analytics Health'
            Status      = if ($highFailureRateRules.Count -eq 0) { 'Pass' } else { 'Critical' }
            Severity    = 'Critical'
            Description = if ($highFailureRateRules.Count -eq 0) {
                'No rules have failure rates exceeding 50%.'
            } else {
                "$(Format-Plural $highFailureRateRules.Count 'rule') have failure rates exceeding 50% - immediate attention required."
            }
            Details     = $highFailureRateRules | ForEach-Object {
                @{ RuleName = $_.SentinelResourceName; FailureRate = $_.FailureRate; Failures = $_.FailureCount; Total = $_.TotalExecutions }
            }
        }
    }

    # ANAH-003: Execution Delays
    if ($CollectedData.AnalyticsExecutionDelays) {
        $delayedRules = @($CollectedData.AnalyticsExecutionDelays)
        $checks += [PSCustomObject]@{
            CheckId     = 'ANAH-003'
            CheckName   = 'Execution Delays'
            Category    = 'Analytics Health'
            Status      = if ($delayedRules.Count -eq 0) { 'Pass' } else { 'Warning' }
            Severity    = 'Warning'
            Description = if ($delayedRules.Count -eq 0) {
                'All scheduled rules are executing within acceptable time windows.'
            } else {
                "$(Format-Plural $delayedRules.Count 'scheduled rule') have average execution delays exceeding 5 minutes."
            }
            Details     = $delayedRules | ForEach-Object {
                @{ RuleName = $_.SentinelResourceName; AvgDelay = $_.AvgDelay; MaxDelay = $_.MaxDelay; DelayedExecutions = $_.DelayedExecutions }
            }
        }
    }

    # ANAH-004: Skipped Query Windows
    if ($CollectedData.AnalyticsSkippedWindows) {
        $skippedRules = @($CollectedData.AnalyticsSkippedWindows)
        $checks += [PSCustomObject]@{
            CheckId     = 'ANAH-004'
            CheckName   = 'Skipped Query Windows'
            Category    = 'Analytics Health'
            Status      = if ($skippedRules.Count -eq 0) { 'Pass' } else { 'Critical' }
            Severity    = 'Critical'
            Description = if ($skippedRules.Count -eq 0) {
                'No scheduled rules have completely skipped query windows (all 6 retries failed).'
            } else {
                "$(Format-Plural $skippedRules.Count 'scheduled rule') have skipped query windows where all 6 retry attempts failed - detection gaps exist."
            }
            Details     = $skippedRules | ForEach-Object {
                @{ RuleName = $_.SentinelResourceName; SkippedWindows = $_.SkippedWindows }
            }
        }
    }

    # ANAH-005: Auto-Disabled Rules (from health events)
    if ($CollectedData.AnalyticsAutoDisabled) {
        $autoDisabledRules = @($CollectedData.AnalyticsAutoDisabled)
        $checks += [PSCustomObject]@{
            CheckId     = 'ANAH-005'
            CheckName   = 'Auto-Disabled Rules'
            Category    = 'Analytics Health'
            Status      = if ($autoDisabledRules.Count -eq 0) { 'Pass' } else { 'Critical' }
            Severity    = 'Critical'
            Description = if ($autoDisabledRules.Count -eq 0) {
                'No rules have been auto-disabled due to persistent failures.'
            } else {
                "$(Format-Plural $autoDisabledRules.Count 'rule') have been auto-disabled - rules were disabled due to repeated execution failures."
            }
            Details     = $autoDisabledRules | ForEach-Object {
                @{ RuleName = $_.SentinelResourceName; LastSeen = $_.LastSeen }
            }
        }
    }

    # ANAH-006: Semantic/Syntax Errors
    if ($CollectedData.AnalyticsFailureReasons) {
        $queryErrors = @($CollectedData.AnalyticsFailureReasons | Where-Object {
            $_.Reason -match 'semantic|syntax|error in query|query.*error'
        })
        $checks += [PSCustomObject]@{
            CheckId     = 'ANAH-006'
            CheckName   = 'Query Errors'
            Category    = 'Analytics Health'
            Status      = if ($queryErrors.Count -eq 0) { 'Pass' } else { 'Critical' }
            Severity    = 'Critical'
            Description = if ($queryErrors.Count -eq 0) {
                'No analytics rules are failing due to KQL query errors.'
            } else {
                "$(Format-Plural ($queryErrors | Measure-Object -Property AffectedRules -Sum).Sum 'rule') failing due to KQL query errors (semantic or syntax issues)."
            }
            Details     = $queryErrors | ForEach-Object {
                @{ Reason = $_.Reason; FailureCount = $_.FailureCount; AffectedRules = $_.AffectedRules }
            }
        }
    }

    # ANAH-007: Health Data Availability
    $checks += [PSCustomObject]@{
        CheckId     = 'ANAH-007'
        CheckName   = 'Analytics Health Data'
        Category    = 'Analytics Health'
        Status      = if ($CollectedData.AnalyticsHealthSummary) { 'Pass' } else { 'Info' }
        Severity    = 'Info'
        Description = if ($CollectedData.AnalyticsHealthSummary) {
            "Analytics rule health monitoring is enabled. Monitoring $(@($CollectedData.AnalyticsHealthSummary).Count) rules."
        } else {
            'Analytics rule health data not available. Enable Microsoft Sentinel health monitoring diagnostic setting to track rule execution health.'
        }
        Details     = $null
    }

    # MIT-001, MIT-002, MIT-003: MITRE Coverage (calculated separately)
    if ($CollectedData.MitreCoverage) {
        $coverage = $CollectedData.MitreCoverage

        # MIT-001: Parent Technique Coverage
        $coverageStatus = if ($coverage.ParentCoveragePercent -ge 50) { 'Pass' } elseif ($coverage.ParentCoveragePercent -ge 25) { 'Warning' } else { 'Critical' }
        $activeRuleNote = if ($coverage.ActiveRuleCount) { " (based on $($coverage.ActiveRuleCount) active rules)" } else { '' }
        $checks += [PSCustomObject]@{
            CheckId     = 'MIT-001'
            CheckName   = 'Parent Technique Coverage'
            Category    = 'MITRE Coverage'
            Status      = $coverageStatus
            Severity    = if ($coverageStatus -eq 'Critical') { 'Critical' } else { 'Warning' }
            Description = "MITRE ATT&CK parent technique coverage: $($coverage.ParentCoveragePercent)% ($($coverage.CoveredParentCount)/$($coverage.TotalParentCount))$activeRuleNote"
            Details     = [ordered]@{
                ParentCoverage = "$($coverage.CoveredParentCount)/$($coverage.TotalParentCount) ($($coverage.ParentCoveragePercent)%)"
                SubTechniqueCoverage = "$($coverage.CoveredSubCount)/$($coverage.TotalSubCount) ($($coverage.SubCoveragePercent)%)"
                UniqueTechniquesDetected = $coverage.TechniqueRuleMapping.Count
                TacticCoverage = $coverage.TacticCoverage.GetEnumerator() | Sort-Object { $coverage.TacticOrder.IndexOf($_.Key) } | ForEach-Object {
                    @{ Tactic = $_.Key; Covered = $_.Value.Covered; Total = $_.Value.Total; Rules = $_.Value.RuleCount }
                }
            }
        }

        # MIT-002: Uncovered Tactics
        $uncoveredTactics = @($coverage.TacticCoverage.GetEnumerator() | Where-Object { $_.Value.Covered -eq 0 })
        $checks += [PSCustomObject]@{
            CheckId     = 'MIT-002'
            CheckName   = 'Uncovered Tactics'
            Category    = 'MITRE Coverage'
            Status      = if ($uncoveredTactics.Count -eq 0) { 'Pass' } else { 'Warning' }
            Severity    = 'Warning'
            Description = if ($uncoveredTactics.Count -eq 0) { "All tactics have at least one technique covered$activeRuleNote." } else { "$(Format-Plural $uncoveredTactics.Count 'tactic') have zero technique coverage$activeRuleNote." }
            Details     = $uncoveredTactics | ForEach-Object { $_.Key }
        }

        # MIT-003: Sub-Technique Coverage
        $checks += [PSCustomObject]@{
            CheckId     = 'MIT-003'
            CheckName   = 'Sub-Technique Coverage'
            Category    = 'MITRE Coverage'
            Status      = 'Info'
            Severity    = 'Info'
            Description = "Sub-technique coverage: $($coverage.SubCoveragePercent)% ($($coverage.CoveredSubCount)/$($coverage.TotalSubCount))$activeRuleNote"
            Details     = $null
        }
    }

    # AUT-001: No Automation Rules
    $automationRules = @($CollectedData.AutomationRules)
    $checks += [PSCustomObject]@{
        CheckId     = 'AUT-001'
        CheckName   = 'Automation Rules'
        Category    = 'Automation'
        Status      = if ($automationRules.Count -gt 0) { 'Pass' } else { 'Warning' }
        Severity    = 'Warning'
        Description = if ($automationRules.Count -gt 0) { "$(Format-Plural $automationRules.Count 'automation rule') configured." } else { 'No automation rules configured. Consider adding automation for incident response.' }
        Details     = $null
    }

    # AUT-002: No Playbooks
    $playbookActions = @($CollectedData.AutomationRules | ForEach-Object {
        $props = Get-SafeProperty $_ 'properties'
        $actions = Get-SafeProperty $props 'actions'
        if ($actions) { $actions | Where-Object { $_.actionType -eq 'RunPlaybook' } }
    })
    $checks += [PSCustomObject]@{
        CheckId     = 'AUT-002'
        CheckName   = 'Playbook Integration'
        Category    = 'Automation'
        Status      = if ($playbookActions.Count -gt 0) { 'Pass' } else { 'Info' }
        Severity    = 'Info'
        Description = if ($playbookActions.Count -gt 0) { "$(Format-Plural $playbookActions.Count 'automation rule') trigger Logic App playbooks." } else { 'No automation rules trigger playbooks.' }
        Details     = $null
    }

    # ING-004: Ingestion Anomaly (if data available)
    $ingestionTrend = @($CollectedData.IngestionTrend)
    if ($ingestionTrend.Count -ge 2) {
        $trend = $ingestionTrend | Sort-Object TimeGenerated
        $latest = $trend[-1].TotalGB
        $previous = $trend[-2].TotalGB
        $change = if ($previous -gt 0) { (($latest - $previous) / $previous) * 100 } else { 0 }

        $checks += [PSCustomObject]@{
            CheckId     = 'ING-004'
            CheckName   = 'Ingestion Anomaly'
            Category    = 'Ingestion'
            Status      = if ([math]::Abs($change) -gt 50) { 'Warning' } else { 'Pass' }
            Severity    = 'Warning'
            Description = if ([math]::Abs($change) -gt 50) { "Significant ingestion change detected: $([math]::Round($change, 1))% from previous day." } else { "Ingestion change from previous day: $([math]::Round($change, 1))%" }
            Details     = @{ LatestGB = $latest; PreviousGB = $previous; ChangePercent = [math]::Round($change, 1) }
        }
    }

    # ING-005: Dominant Table
    $topTables = @($CollectedData.TopTables | Where-Object { $null -ne $_ })
    if ($topTables.Count -gt 0 -and $topTables[0].PSObject.Properties['TotalGB']) {
        $measureResult = $topTables | Measure-Object -Property TotalGB -Sum
        $totalGB = if ($measureResult -and $measureResult.Sum) { $measureResult.Sum } else { 0 }
        $topTable = $topTables | Sort-Object TotalGB -Descending | Select-Object -First 1
        $topTablePercent = if ($totalGB -gt 0) { ($topTable.TotalGB / $totalGB) * 100 } else { 0 }

        $checks += [PSCustomObject]@{
            CheckId     = 'ING-005'
            CheckName   = 'Dominant Table'
            Category    = 'Ingestion'
            Status      = if ($topTablePercent -gt 50) { 'Info' } else { 'Pass' }
            Severity    = 'Info'
            Description = if ($topTablePercent -gt 50) { "Table '$($topTable.DataType)' accounts for $([math]::Round($topTablePercent, 1))% of ingestion." } else { "No single table dominates ingestion (top: $($topTable.DataType) at $([math]::Round($topTablePercent, 1))%)." }
            Details     = @{ TopTable = $topTable.DataType; Percent = [math]::Round($topTablePercent, 1) }
        }
    }

    # RET-001: Workspace Default Retention
    $checks += [PSCustomObject]@{
        CheckId     = 'RET-001'
        CheckName   = 'Workspace Retention'
        Category    = 'Data Retention'
        Status      = 'Info'
        Severity    = 'Info'
        Description = "Default workspace retention: $(Format-Plural $retention 'day')"
        Details     = @{ RetentionDays = $retention }
    }

    # RET-002: Tables Below Default
    if ($CollectedData.Tables) {
        $tablesBelowDefault = @($CollectedData.Tables | Where-Object {
            $tableRetention = Get-SafeProperty $_.properties 'retentionInDays'
            $tableRetention -and $tableRetention -lt $retention
        })
        $checks += [PSCustomObject]@{
            CheckId     = 'RET-002'
            CheckName   = 'Tables Below Default'
            Category    = 'Data Retention'
            Status      = if ($tablesBelowDefault.Count -eq 0) { 'Pass' } else { 'Warning' }
            Severity    = 'Warning'
            Description = if ($tablesBelowDefault.Count -eq 0) { 'No tables have retention below workspace default.' } else { "$(Format-Plural $tablesBelowDefault.Count 'table') have retention below workspace default." }
            Details     = $tablesBelowDefault | ForEach-Object { $_.name }
        }
    }

    # RET-003: Archive Tier Usage
    if ($CollectedData.Tables) {
        $archivedTables = @($CollectedData.Tables | Where-Object {
            $archiveRetention = Get-SafeProperty $_.properties 'totalRetentionInDays'
            $interactiveRetention = Get-SafeProperty $_.properties 'retentionInDays'
            $archiveRetention -and $interactiveRetention -and ($archiveRetention -gt $interactiveRetention)
        })
        $checks += [PSCustomObject]@{
            CheckId     = 'RET-003'
            CheckName   = 'Archive Tier Usage'
            Category    = 'Data Retention'
            Status      = 'Info'
            Severity    = 'Info'
            Description = "$(Format-Plural $archivedTables.Count 'table') using archive tier for extended retention."
            Details     = $archivedTables | ForEach-Object { $_.name }
        }
    }

    # RET-004: Basic Logs Tables
    if ($CollectedData.Tables) {
        $basicLogsTables = @($CollectedData.Tables | Where-Object {
            (Get-SafeProperty $_.properties 'plan') -eq 'Basic'
        })
        $checks += [PSCustomObject]@{
            CheckId     = 'RET-004'
            CheckName   = 'Basic Logs Tables'
            Category    = 'Data Retention'
            Status      = 'Info'
            Severity    = 'Info'
            Description = "$(Format-Plural $basicLogsTables.Count 'table') configured as Basic logs (reduced query capabilities, lower cost)."
            Details     = $basicLogsTables | ForEach-Object { $_.name }
        }
    }

    # RET-005: Tables Above Default
    if ($CollectedData.Tables) {
        $tablesAboveDefault = @($CollectedData.Tables | Where-Object {
            $tableRetention = Get-SafeProperty $_.properties 'retentionInDays'
            $tableRetention -and $tableRetention -gt $retention
        })
        $checks += [PSCustomObject]@{
            CheckId     = 'RET-005'
            CheckName   = 'Tables Above Default'
            Category    = 'Data Retention'
            Status      = 'Info'
            Severity    = 'Info'
            Description = "$(Format-Plural $tablesAboveDefault.Count 'table') have interactive retention above workspace default ($retention days)."
            Details     = $tablesAboveDefault | ForEach-Object {
                @{
                    TableName = $_.name
                    RetentionDays = Get-SafeProperty $_.properties 'retentionInDays'
                }
            }
        }
    }

    # AGT-001: Agent Health Status
    if ($CollectedData.AgentHealthSummary) {
        $unhealthyAgents = @($CollectedData.AgentHealthSummary | Where-Object { $_.State -eq 'Unhealthy' })
        $totalAgents = @($CollectedData.AgentHealthSummary).Count
        $unhealthyPercent = if ($totalAgents -gt 0) { ($unhealthyAgents.Count / $totalAgents) * 100 } else { 0 }
        $checks += [PSCustomObject]@{
            CheckId     = 'AGT-001'
            CheckName   = 'Agent Health'
            Category    = 'Agent Health'
            Status      = if ($unhealthyAgents.Count -eq 0) { 'Pass' }
                          elseif ($unhealthyPercent -gt 20) { 'Critical' }
                          else { 'Warning' }
            Severity    = if ($unhealthyPercent -gt 20) { 'Critical' } else { 'Warning' }
            Description = if ($unhealthyAgents.Count -eq 0) {
                "All $(Format-Plural $totalAgents 'agent') are healthy (heartbeat within 24 hours)."
            } else {
                "$(Format-Plural $unhealthyAgents.Count 'agent') unhealthy (no heartbeat in 24+ hours) out of $totalAgents total."
            }
            Details     = $unhealthyAgents | Select-Object Computer, LastHeartbeat, HoursSinceHeartbeat
        }
    }

    # AGT-002: Agent Operation Errors
    if ($CollectedData.AgentOperationErrors) {
        $agentsWithErrors = @($CollectedData.AgentOperationErrors)
        $checks += [PSCustomObject]@{
            CheckId     = 'AGT-002'
            CheckName   = 'Agent Operation Errors'
            Category    = 'Agent Health'
            Status      = if ($agentsWithErrors.Count -eq 0) { 'Pass' } else { 'Warning' }
            Severity    = 'Warning'
            Description = if ($agentsWithErrors.Count -eq 0) {
                'No agent operation errors in the last 7 days.'
            } else {
                "$(Format-Plural $agentsWithErrors.Count 'agent') reporting operation errors in the last 7 days."
            }
            Details     = $agentsWithErrors | Select-Object Computer, Failures, Errors, Warnings
        }
    }

    return ,$checks
}

function Get-ConnectorsWithUpdates {
    <#
    .SYNOPSIS
    Identifies data connectors that have newer versions available in Content Hub.
    #>
    param(
        [array]$Connectors,
        [array]$ContentTemplates
    )

    $connectorsWithUpdates = @()

    # Build template version lookup from Content Hub templates
    $templateVersions = @{}
    foreach ($template in $ContentTemplates) {
        if ($template.properties.contentKind -eq 'DataConnector') {
            $templateName = $template.name
            $templateVersion = Get-SafeProperty $template.properties 'version'
            if ($templateName -and $templateVersion) {
                $templateVersions[$templateName] = $templateVersion
            }
        }
    }

    foreach ($connector in $Connectors) {
        $connectorName = $connector.name
        $connectorKind = $connector.kind

        # Try to find matching template by name or kind
        $templateVersion = $null
        if ($templateVersions.ContainsKey($connectorName)) {
            $templateVersion = $templateVersions[$connectorName]
        }
        elseif ($templateVersions.ContainsKey($connectorKind)) {
            $templateVersion = $templateVersions[$connectorKind]
        }

        if (-not $templateVersion) { continue }

        # Get connector's current version from properties
        $connectorVersion = Get-SafeProperty $connector.properties 'connectorDefinitionName'
        if (-not $connectorVersion) {
            # Try alternative version properties
            $uiConfig = Get-SafeProperty $connector.properties 'connectorUiConfig'
            if ($uiConfig) {
                $connectorVersion = Get-SafeProperty $uiConfig 'dataTypes'
            }
        }

        # If we can't determine connector version, check if it has any version info
        # Some connectors don't have version tracking - just report if template exists
        $currentVersion = Get-SafeProperty $connector.properties 'templateVersion'

        if ($currentVersion -and $templateVersion) {
            try {
                $currentVer = [version]$currentVersion
                $templateVer = [version]$templateVersion

                if ($templateVer -gt $currentVer) {
                    $connectorsWithUpdates += [PSCustomObject]@{
                        ConnectorName    = $connectorName
                        ConnectorKind    = $connectorKind
                        CurrentVersion   = $currentVersion
                        TemplateVersion  = $templateVersion
                    }
                }
            }
            catch {
                # Version parsing failed, skip comparison
            }
        }
    }

    return ,$connectorsWithUpdates
}

function Get-RulesWithUpdates {
    <#
    .SYNOPSIS
    Identifies analytics rules that have newer template versions available.
    #>
    param(
        [array]$Rules,
        [array]$AlertRuleTemplates,
        [array]$ContentTemplates
    )

    $rulesWithUpdates = @()

    # Build template version lookup
    $templateVersions = @{}

    # From Content Hub templates
    foreach ($template in $ContentTemplates) {
        if ($template.properties.contentKind -eq 'AnalyticsRule') {
            $templateVersions[$template.name] = Get-SafeProperty $template.properties 'version'
        }
    }

    # From built-in alert rule templates
    foreach ($template in $AlertRuleTemplates) {
        if (-not $templateVersions.ContainsKey($template.name)) {
            $templateVersions[$template.name] = Get-SafeProperty $template.properties 'version'
        }
    }

    # Compare rule versions
    foreach ($rule in $Rules) {
        $templateName = Get-SafeProperty $rule.properties 'alertRuleTemplateName'
        $ruleVersion = Get-SafeProperty $rule.properties 'templateVersion'

        if ($templateName -and $ruleVersion -and $templateVersions.ContainsKey($templateName)) {
            $templateVersion = $templateVersions[$templateName]

            if ($templateVersion) {
                try {
                    $ruleVer = [version]$ruleVersion
                    $templateVer = [version]$templateVersion

                    if ($templateVer -gt $ruleVer) {
                        $rulesWithUpdates += [PSCustomObject]@{
                            RuleName        = Get-SafeProperty $rule.properties 'displayName'
                            CurrentVersion  = $ruleVersion
                            TemplateVersion = $templateVersion
                            TemplateName    = $templateName
                        }
                    }
                }
                catch {
                    # Version parsing failed, skip comparison
                }
            }
        }
    }

    # Output items individually to avoid array-wrapping issues with @() caller
    foreach ($item in $rulesWithUpdates) { $item }
}

function Get-VisibilityGaps {
    <#
    .SYNOPSIS
    Identifies rules where template expects incidents but rule is disabled or not creating incidents.
    Enriches results with alert volume data from SecurityAlert table when available.
    #>
    param(
        [array]$Rules,
        [array]$AlertRuleTemplates,
        [array]$ContentTemplates,
        [array]$AlertVolumeByRuleName
    )

    $visibilityGaps = @()

    # Build alert volume lookup by rule name
    $alertVolumeLookup = @{}
    if ($AlertVolumeByRuleName -and @($AlertVolumeByRuleName).Count -gt 0) {
        foreach ($entry in $AlertVolumeByRuleName) {
            $entryName = if ($entry) { $entry.RuleName } else { $null }
            if ($entryName) {
                $alertVolumeLookup[$entryName] = $entry
            }
        }
    }

    # Build template createIncident lookup
    $templateCreateIncident = @{}

    # From Content Hub templates
    foreach ($template in $ContentTemplates) {
        if ($template.properties.contentKind -eq 'AnalyticsRule') {
            $mainTemplate = Get-SafeProperty $template.properties 'mainTemplate'
            if ($mainTemplate -and $mainTemplate.resources) {
                $alertResource = $mainTemplate.resources | Where-Object { $_.type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates' } | Select-Object -First 1
                if ($alertResource) {
                    $incidentConfig = Get-SafeProperty $alertResource.properties 'incidentConfiguration'
                    $createIncident = if ($incidentConfig) { Get-SafeProperty $incidentConfig 'createIncident' } else { $true }
                    $templateCreateIncident[$template.name] = $createIncident
                }
            }
        }
    }

    # From built-in templates
    foreach ($template in $AlertRuleTemplates) {
        if (-not $templateCreateIncident.ContainsKey($template.name)) {
            $incidentConfig = Get-SafeProperty $template.properties 'incidentConfiguration'
            $createIncident = if ($incidentConfig) { Get-SafeProperty $incidentConfig 'createIncident' } else { $true }
            $templateCreateIncident[$template.name] = $createIncident
        }
    }

    # Find gaps
    foreach ($rule in $Rules) {
        $severity = Get-SafeProperty $rule.properties 'severity'
        if ($severity -notin @('High', 'Medium', 'Low')) { continue }

        $templateName = Get-SafeProperty $rule.properties 'alertRuleTemplateName'
        if (-not $templateName) { continue }

        $templateExpectsIncident = $templateCreateIncident[$templateName]
        if ($templateExpectsIncident -ne $true) { continue }

        $enabled = Get-SafeProperty $rule.properties 'enabled'
        $incidentConfig = Get-SafeProperty $rule.properties 'incidentConfiguration'
        $createIncident = if ($incidentConfig) { Get-SafeProperty $incidentConfig 'createIncident' } else { $true }

        if (-not $enabled -or -not $createIncident) {
            $ruleName = Get-SafeProperty $rule.properties 'displayName'
            $issue = if (-not $enabled) { 'Disabled' } else { 'Not Creating Incidents' }

            # Enrich with alert volume data (only meaningful for enabled rules not creating incidents)
            $alertCount90d = 0
            $alertHigh = 0
            $alertMedium = 0
            $alertLow = 0
            $alertInfo = 0
            $firstAlert = $null
            $lastAlert = $null
            if ($enabled -and -not $createIncident -and $ruleName -and $alertVolumeLookup.Count -gt 0 -and $alertVolumeLookup.ContainsKey($ruleName)) {
                $vol = $alertVolumeLookup[$ruleName]
                if ($vol) {
                    $alertCount90d = if ($vol.AlertCount) { [int]$vol.AlertCount } else { 0 }
                    $alertHigh = if ($vol.HighCount) { [int]$vol.HighCount } else { 0 }
                    $alertMedium = if ($vol.MediumCount) { [int]$vol.MediumCount } else { 0 }
                    $alertLow = if ($vol.LowCount) { [int]$vol.LowCount } else { 0 }
                    $alertInfo = if ($vol.InfoCount) { [int]$vol.InfoCount } else { 0 }
                    $firstAlert = if ($vol.FirstAlert) { "$($vol.FirstAlert)" } else { $null }
                    $lastAlert = if ($vol.LastAlert) { "$($vol.LastAlert)" } else { $null }
                }
            }

            $visibilityGaps += [PSCustomObject]@{
                RuleName       = $ruleName
                Severity       = $severity
                Enabled        = $enabled
                CreateIncident = $createIncident
                Issue          = $issue
                AlertCount90d  = $alertCount90d
                AlertHigh      = $alertHigh
                AlertMedium    = $alertMedium
                AlertLow       = $alertLow
                AlertInfo      = $alertInfo
                FirstAlert     = $firstAlert
                LastAlert      = $lastAlert
            }
        }
    }

    # Output items individually to avoid array-wrapping issues with @() caller
    foreach ($gap in $visibilityGaps) { $gap }
}

#endregion Health Check Functions

#region Analysis Functions

function Get-ActiveAnalyticsRules {
    <#
    .SYNOPSIS
    Filters analytics rules to only those that are enabled AND configured to create incidents.
    Used to calculate MITRE ATT&CK coverage based on operationally active detection rules only.
    #>
    param(
        [array]$Rules
    )

    return ,@($Rules | Where-Object {
        $props = Get-SafeProperty $_ 'properties'
        if (-not $props) { return $false }

        # Must be enabled
        $enabled = Get-SafeProperty $props 'enabled'
        if ($enabled -ne $true) { return $false }

        # Must create incidents (default is true if not specified)
        $incidentConfig = Get-SafeProperty $props 'incidentConfiguration'
        $createIncident = if ($incidentConfig) {
            Get-SafeProperty $incidentConfig 'createIncident'
        } else {
            $true  # Default behavior is to create incidents
        }

        return $createIncident -eq $true
    })
}

function Get-MitreCoverageAnalysis {
    <#
    .SYNOPSIS
    Analyzes MITRE ATT&CK coverage from analytics rules.
    #>
    param(
        [array]$Rules,
        [hashtable]$MitreData
    )

    if (-not $MitreData) { return $null }

    # Extract covered techniques from rules
    $coveredTechniques = @{}
    $techniqueRuleMapping = @{}

    foreach ($rule in $Rules) {
        $props = Get-SafeProperty $rule 'properties'
        if (-not $props) { continue }

        $ruleName = Get-SafeProperty $props 'displayName'
        $techniques = Get-SafeProperty $props 'techniques'
        $subTechniques = Get-SafeProperty $props 'subTechniques'

        if ($techniques) {
            foreach ($tech in $techniques) {
                $coveredTechniques[$tech] = $true
                if (-not $techniqueRuleMapping.ContainsKey($tech)) {
                    $techniqueRuleMapping[$tech] = @()
                }
                $techniqueRuleMapping[$tech] += $ruleName
            }
        }

        if ($subTechniques) {
            foreach ($tech in $subTechniques) {
                $coveredTechniques[$tech] = $true
                if (-not $techniqueRuleMapping.ContainsKey($tech)) {
                    $techniqueRuleMapping[$tech] = @()
                }
                $techniqueRuleMapping[$tech] += $ruleName
            }
        }
    }

    # Calculate coverage
    $parentTechniques = $MitreData.Values | Where-Object { -not $_.IsSubtechnique }
    $subTechniques = $MitreData.Values | Where-Object { $_.IsSubtechnique }

    $totalParent = @($parentTechniques).Count
    $totalSub = @($subTechniques).Count

    $coveredParent = @($parentTechniques | Where-Object { $coveredTechniques.ContainsKey($_.ID) }).Count
    $coveredSub = @($subTechniques | Where-Object { $coveredTechniques.ContainsKey($_.ID) }).Count

    # Tactic coverage
    $tacticOrder = @(
        'reconnaissance', 'resource-development', 'initial-access', 'execution',
        'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
        'discovery', 'lateral-movement', 'collection', 'command-and-control',
        'exfiltration', 'impact'
    )

    $tacticCoverage = @{}
    foreach ($tactic in $tacticOrder) {
        $tacticCoverage[$tactic] = @{
            Total     = 0
            Covered   = 0
            Uncovered = @()
            RuleCount = 0
            Rules     = @()
        }
    }

    foreach ($tech in $parentTechniques) {
        foreach ($tactic in $tech.Tactics) {
            if ($tacticCoverage.ContainsKey($tactic)) {
                $tacticCoverage[$tactic].Total++
                if ($coveredTechniques.ContainsKey($tech.ID)) {
                    $tacticCoverage[$tactic].Covered++
                }
                else {
                    $tacticCoverage[$tactic].Uncovered += [PSCustomObject]@{
                        ID   = $tech.ID
                        Name = $tech.Name
                    }
                }
            }
        }
    }

    # Count unique rules per tactic
    foreach ($rule in $Rules) {
        $props = Get-SafeProperty $rule 'properties'
        if (-not $props) { continue }

        $ruleName = Get-SafeProperty $props 'displayName'
        $tactics = Get-SafeProperty $props 'tactics'

        if ($tactics) {
            foreach ($tactic in $tactics) {
                # Normalize tactic name to match our keys (lowercase, hyphenated)
                $tacticKey = $tactic.ToLower() -replace ' ', '-'
                if ($tacticCoverage.ContainsKey($tacticKey) -and $ruleName -notin $tacticCoverage[$tacticKey].Rules) {
                    $tacticCoverage[$tacticKey].Rules += $ruleName
                    $tacticCoverage[$tacticKey].RuleCount++
                }
            }
        }
    }

    return @{
        CoveredTechniques      = $coveredTechniques
        TechniqueRuleMapping   = $techniqueRuleMapping
        TotalParentCount       = $totalParent
        CoveredParentCount     = $coveredParent
        TotalSubCount          = $totalSub
        CoveredSubCount        = $coveredSub
        ParentCoveragePercent  = if ($totalParent -gt 0) { [math]::Round(($coveredParent / $totalParent) * 100, 1) } else { 0 }
        SubCoveragePercent     = if ($totalSub -gt 0) { [math]::Round(($coveredSub / $totalSub) * 100, 1) } else { 0 }
        TacticCoverage         = $tacticCoverage
        TacticOrder            = $tacticOrder
    }
}

#endregion Analysis Functions

#region Report Generation Functions

function New-MitreNavigatorJson {
    <#
    .SYNOPSIS
    Generates a MITRE ATT&CK Navigator JSON layer file (v18 format).
    #>
    param(
        [string]$WorkspaceName,
        [string]$ClientName,
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [hashtable]$MitreCoverage
    )

    $techniques = @()

    foreach ($techId in $MitreCoverage.TechniqueRuleMapping.Keys) {
        $rules = $MitreCoverage.TechniqueRuleMapping[$techId]
        $ruleCount = $rules.Count

        # Build comment with rule names (newline separated for Navigator display)
        $ruleList = $rules -join "`n`n"

        $techniques += [ordered]@{
            techniqueID = $techId
            score       = $ruleCount
            comment     = $ruleList
            enabled     = $true
        }
    }

    # Build layer structure for MITRE ATT&CK v18.0
    $layer = [ordered]@{
        name        = "$ClientName - Sentinel Coverage"
        versions    = [ordered]@{
            attack    = "18"
            navigator = "5.2.0"
            layer     = "4.5"
        }
        domain      = "enterprise-attack"
        description = "Workspace: $WorkspaceName | Subscription: $SubscriptionId | Resource Group: $ResourceGroupName | Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

        filters     = [ordered]@{
            platforms = @(
                "Windows",
                "Linux",
                "macOS",
                "Network Devices",
                "ESXi",
                "PRE",
                "Containers",
                "IaaS",
                "Office Suite",
                "SaaS",
                "Identity Provider"
            )
        }

        sorting     = 0

        layout      = [ordered]@{
            layout                 = "side"
            aggregateFunction      = "average"
            showID                 = $true
            showName               = $true
            showAggregateScores    = $false
            countUnscored          = $false
            expandedSubtechniques  = "none"
        }

        hideDisabled = $false
        techniques  = $techniques

        gradient    = [ordered]@{
            colors   = @("#ff6666ff", "#ffe766ff", "#8ec843ff")
            minValue = 0
            maxValue = 21
        }

        legendItems = @()
        metadata    = @()
        links       = @()
        showTacticRowBackground    = $false
        tacticRowBackground        = "#dddddd"
        selectTechniquesAcrossTactics = $true
        selectSubtechniquesWithParent = $false
        selectVisibleTechniques    = $false
    }

    return $layer | ConvertTo-Json -Depth 10
}

function Invoke-NavigatorSvgGeneration {
    <#
    .SYNOPSIS
    Generates MITRE ATT&CK Navigator SVG from the JSON layer file using Python.

    .DESCRIPTION
    Uses an embedded Python script to convert a Navigator layer JSON file to an
    SVG visualization. Requires Python 3.7+ and the mitreattack-python package.

    .PARAMETER JsonPath
    Path to the Navigator layer JSON file.

    .PARAMETER SvgPath
    Path where the SVG file should be saved.

    .OUTPUTS
    Returns the SVG file path if successful, $null otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonPath,

        [Parameter(Mandatory = $true)]
        [string]$SvgPath
    )

    # Embedded Python script for SVG generation
    $pythonCode = @'
#!/usr/bin/env python3
"""
Converts a MITRE ATT&CK Navigator layer JSON to SVG format.
Embedded in New-SentinelAssessmentReport.ps1
"""
import sys
import os

def main():
    if len(sys.argv) < 3:
        print("Usage: python script.py <input.json> <output.svg> [stix_bundle.json]", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    stix_bundle = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        from mitreattack.navlayers import Layer, ToSvg, SVGConfig
    except ImportError:
        print("Error: mitreattack-python package not installed.", file=sys.stderr)
        print("Install with: pip install mitreattack-python", file=sys.stderr)
        sys.exit(2)

    try:
        layer = Layer()
        layer.from_file(input_file)

        config = SVGConfig(
            width=17,
            height=8.5,
            showSubtechniques="none",
            font="sans-serif",
            showHeader=True,
            showLegend=True,
            legendDocked=True,
            showFilters=False,
            showAbout=True,
            showDomain=True
        )

        if stix_bundle and os.path.exists(stix_bundle):
            print(f"Loading ATT&CK framework data from local bundle...", file=sys.stderr)
            exporter = ToSvg(domain="enterprise-attack", source='local', resource=stix_bundle, config=config)
        else:
            print(f"Downloading ATT&CK framework data (this may take a moment)...", file=sys.stderr)
            try:
                import urllib.request
                import tempfile
                stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                temp_stix = os.path.join(tempfile.gettempdir(), "enterprise-attack.json")
                urllib.request.urlretrieve(stix_url, temp_stix)
                exporter = ToSvg(domain="enterprise-attack", source='local', resource=temp_stix, config=config)
            except Exception as download_error:
                print(f"Error downloading STIX bundle: {download_error}", file=sys.stderr)
                sys.exit(5)

        print(f"Generating SVG...", file=sys.stderr)
        exporter.to_svg(layerInit=layer, filepath=output_file)

        print(f"SVG generated: {output_file}")
        sys.exit(0)

    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"Error generating SVG: {e}", file=sys.stderr)
        sys.exit(4)

if __name__ == "__main__":
    main()
'@

    # Check if Python is available (try python first, then python3)
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $pythonCmd) {
        Write-Warning "Python not found in PATH. SVG visualization will not be generated."
        Write-Warning "To enable SVG generation, install Python 3.7+ and run: pip install mitreattack-python"
        Write-Host "    Skipping SVG generation (Navigator JSON still available)." -ForegroundColor Yellow
        return $null
    }

    # Write Python script to temp file
    $tempPythonScript = Join-Path ([System.IO.Path]::GetTempPath()) "Convert-NavigatorToSvg_$([guid]::NewGuid().ToString('N')).py"

    try {
        Write-Host "  Generating MITRE Navigator SVG (this may take a moment)..." -ForegroundColor DarkGray

        # Write embedded script to temp file
        $pythonCode | Out-File -FilePath $tempPythonScript -Encoding utf8 -Force

        # Check for cached STIX bundle (used by Get-MitreAttackTechniques)
        $stixBundlePath = Join-Path $env:APPDATA "SentinelAnalyticsTools\mitre-attack-enterprise.json"

        # Build command arguments
        $pythonArgs = @($tempPythonScript, $JsonPath, $SvgPath)
        if (Test-Path $stixBundlePath) {
            $pythonArgs += $stixBundlePath
        }

        $result = & $pythonCmd.Path @pythonArgs 2>&1

        if ($LASTEXITCODE -eq 0 -and (Test-Path $SvgPath)) {
            Write-Host "  SVG generated successfully." -ForegroundColor Green
            return $SvgPath
        }
        elseif ($LASTEXITCODE -eq 2) {
            Write-Warning "Python is installed, but the 'mitreattack-python' package is missing."
            Write-Warning "To enable SVG generation, run: pip install mitreattack-python"
            Write-Host "    Skipping SVG generation (Navigator JSON still available)." -ForegroundColor Yellow
            return $null
        }
        else {
            Write-Warning "SVG generation failed (exit code $LASTEXITCODE): $result"
            return $null
        }
    }
    catch {
        Write-Warning "SVG generation error: $_"
        return $null
    }
    finally {
        # Clean up temp Python script
        if (Test-Path $tempPythonScript) {
            Remove-Item -Path $tempPythonScript -Force -ErrorAction SilentlyContinue
        }
    }
}

function ConvertTo-ReportHtml {
    <#
    .SYNOPSIS
    Generates the complete HTML report from collected data.
    #>
    param(
        [hashtable]$Data,
        [string]$ClientName,
        [string]$WorkspaceName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Calculate KPI values
    $totalRules = $Data.AnalyticsRules.Count
    $enabledRules = @($Data.AnalyticsRules | Where-Object { (Get-SafeProperty $_.properties 'enabled') -eq $true }).Count
    $disabledRules = $totalRules - $enabledRules
    $connectorCount = $Data.DataConnectors.Count
    $mitreCoverage = if ($Data.MitreCoverage) { $Data.MitreCoverage.ParentCoveragePercent } else { 'N/A' }
    $mitreActiveRuleCount = if ($Data.MitreCoverage -and $Data.MitreCoverage.ActiveRuleCount) { $Data.MitreCoverage.ActiveRuleCount } else { 0 }

    # Health check summary
    $passCount = @($Data.HealthChecks | Where-Object { $_.Status -eq 'Pass' }).Count
    $warnCount = @($Data.HealthChecks | Where-Object { $_.Status -eq 'Warning' }).Count
    $critCount = @($Data.HealthChecks | Where-Object { $_.Status -eq 'Critical' }).Count
    $infoCount = @($Data.HealthChecks | Where-Object { $_.Status -eq 'Info' }).Count

    # Calculate average daily ingestion if available
    $avgDailyIngestion = 'N/A'
    if ($Data.IngestionTrend -and $Data.IngestionTrend.Count -gt 0) {
        $avgDailyIngestion = [math]::Round(($Data.IngestionTrend | Measure-Object -Property TotalGB -Average).Average, 1)
    }

    # Build KPI cards HTML
    $kpiHtml = @"
    <div class="col-md-4 col-lg">
      <div class="card shadow-sm border-0 border-top border-4 border-primary h-100">
        <div class="card-body d-flex align-items-center justify-content-between">
          <div>
            <div class="text-muted small fw-bold text-uppercase">Analytics Rules</div>
            <h2 class="mb-0 fw-bold">$totalRules</h2>
            <small class="text-muted">$enabledRules enabled / $disabledRules disabled</small>
          </div>
          <i data-lucide="shield-check" class="text-primary opacity-75" style="width: 32px; height: 32px;"></i>
        </div>
      </div>
    </div>
    <div class="col-md-4 col-lg">
      <div class="card shadow-sm border-0 border-top border-4 border-info h-100">
        <div class="card-body d-flex align-items-center justify-content-between">
          <div>
            <div class="text-muted small fw-bold text-uppercase">Data Connectors</div>
            <h2 class="mb-0 fw-bold">$connectorCount</h2>
          </div>
          <i data-lucide="database" class="text-info opacity-75" style="width: 32px; height: 32px;"></i>
        </div>
      </div>
    </div>
    <div class="col-md-4 col-lg">
      <div class="card shadow-sm border-0 border-top border-4 border-success h-100">
        <div class="card-body d-flex align-items-center justify-content-between">
          <div>
            <div class="text-muted small fw-bold text-uppercase">MITRE Coverage</div>
            <h2 class="mb-0 fw-bold">$mitreCoverage%</h2>
            <small class="text-muted">Parent techniques ($mitreActiveRuleCount active $(if ($mitreActiveRuleCount -eq 1) { 'rule' } else { 'rules' }))</small>
          </div>
          <i data-lucide="target" class="text-success opacity-75" style="width: 32px; height: 32px;"></i>
        </div>
      </div>
    </div>
    <div class="col-md-4 col-lg">
      <div class="card shadow-sm border-0 border-top border-4 border-warning h-100">
        <div class="card-body d-flex align-items-center justify-content-between">
          <div>
            <div class="text-muted small fw-bold text-uppercase">Avg Daily Ingestion (30d)</div>
            <h2 class="mb-0 fw-bold">$avgDailyIngestion GB</h2>
          </div>
          <i data-lucide="activity" class="text-warning opacity-75" style="width: 32px; height: 32px;"></i>
        </div>
      </div>
    </div>
    <div class="col-md-4 col-lg">
      <div class="card shadow-sm border-0 border-top border-4 $(if ($critCount -gt 0) { 'border-danger' } elseif ($warnCount -gt 0) { 'border-warning' } else { 'border-success' }) h-100">
        <div class="card-body d-flex align-items-center justify-content-between">
          <div>
            <div class="text-muted small fw-bold text-uppercase">Health Checks</div>
            <h2 class="mb-0 fw-bold">$passCount Pass</h2>
            <small class="text-muted">$warnCount warn / $critCount critical</small>
          </div>
          <i data-lucide="heart-pulse" class="$(if ($critCount -gt 0) { 'text-danger' } elseif ($warnCount -gt 0) { 'text-warning' } else { 'text-success' }) opacity-75" style="width: 32px; height: 32px;"></i>
        </div>
      </div>
    </div>
"@

    # Build environment overview
    $wsConfig = $Data.WorkspaceConfig
    $wsProps = Get-SafeProperty $wsConfig 'properties'
    $wsLocation = Get-SafeProperty $wsConfig 'location'
    $retention = Get-SafeProperty $wsProps 'retentionInDays'
    $sku = Get-SafeProperty (Get-SafeProperty $wsProps 'sku') 'name'
    $dailyCap = Get-SafeProperty (Get-SafeProperty $wsProps 'workspaceCapping') 'dailyQuotaGb'

    # UEBA uses kind='Ueba' with dataSources array
    $uebaSetting = $Data.Settings | Where-Object { $_.kind -eq 'Ueba' }
    $uebaDataSources = if ($uebaSetting) { Get-SafeProperty $uebaSetting.properties 'dataSources' } else { $null }
    $uebaEnabled = $uebaDataSources -and $uebaDataSources.Count -gt 0
    $anomaliesEnabled = $Data.Settings | Where-Object { $_.kind -eq 'Anomalies' -and (Get-SafeProperty $_.properties 'isEnabled') -eq $true }
    $fusionEnabled = $Data.AnalyticsRules | Where-Object { $_.kind -eq 'Fusion' -and (Get-SafeProperty $_.properties 'enabled') -eq $true }

    $tenantName = $Data.TenantName
    $resourceGroup = $Data.ResourceGroupName

    $envOverviewHtml = @"
<div class="row">
    <div class="col-md-6">
        <h5 class="fw-bold text-muted text-uppercase mb-3">Workspace Details</h5>
        <table class="table table-sm mb-0">
            <tr><td class="text-muted" style="width:140px">Tenant</td><td class="fw-bold">$tenantName</td></tr>
            <tr><td class="text-muted">Subscription</td><td><code>$($Data.SubscriptionId)</code></td></tr>
            <tr><td class="text-muted">Resource Group</td><td>$resourceGroup</td></tr>
            <tr><td class="text-muted">Workspace</td><td>$WorkspaceName</td></tr>
            <tr><td class="text-muted">Region</td><td>$wsLocation</td></tr>
        </table>
    </div>
    <div class="col-md-6">
        <h5 class="fw-bold text-muted text-uppercase mb-3">Configuration</h5>
        <table class="table table-sm">
            <tr><td class="text-muted" style="width:140px">SKU</td><td>$sku</td></tr>
            <tr><td class="text-muted">Retention</td><td>$(Format-Plural $retention 'day')</td></tr>
            <tr><td class="text-muted">Daily Cap</td><td>$(if ($dailyCap -and $dailyCap -gt 0) { "$dailyCap GB" } else { 'Not configured' })</td></tr>
        </table>
        <h6 class="fw-bold text-muted text-uppercase mb-2 mt-3">Sentinel Features</h6>
        <div class="d-flex flex-wrap gap-2">
            <span class="badge $(if ($uebaEnabled) { 'bg-success' } else { 'bg-secondary' })">UEBA $(if ($uebaEnabled) { 'Enabled' } else { 'Disabled' })</span>
            <span class="badge $(if ($anomaliesEnabled) { 'bg-success' } else { 'bg-secondary' })">Anomalies $(if ($anomaliesEnabled) { 'Enabled' } else { 'Disabled' })</span>
            <span class="badge $(if ($fusionEnabled) { 'bg-success' } else { 'bg-secondary' })">Fusion $(if ($fusionEnabled) { 'Enabled' } else { 'Disabled' })</span>
            <span class="badge $(if ($Data.HealthAuditEnabled) { 'bg-success' } else { 'bg-secondary' })">Health &amp; Audit $(if ($Data.HealthAuditEnabled) { 'Enabled' } else { 'Disabled' })</span>
        </div>
    </div>
</div>
"@

    # Build health checks table
    $healthChecksHtml = @"
<table class="table table-hover report-table flyout-enabled" id="healthChecksTable">
<thead>
<tr>
    <th>Check ID</th>
    <th>Category</th>
    <th>Check Name</th>
    <th>Status</th>
    <th>Description</th>
    <th class="col-flyout-icon"></th>
</tr>
</thead>
<tbody>
"@

    foreach ($check in $Data.HealthChecks) {
        $statusBadge = switch ($check.Status) {
            'Pass'     { '<span class="badge bg-success">Pass</span>' }
            'Warning'  { '<span class="badge bg-warning text-dark">Warning</span>' }
            'Critical' { '<span class="badge bg-danger">Critical</span>' }
            'Info'     { '<span class="badge bg-info">Info</span>' }
            default    { '<span class="badge bg-secondary">Unknown</span>' }
        }
        $hasDetails = $null -ne $check.Details -and (
            ($check.Details -is [hashtable] -and $check.Details.Count -gt 0) -or
            ($check.Details -is [System.Collections.IDictionary] -and $check.Details.Count -gt 0) -or
            ($check.Details -is [array] -and $check.Details.Count -gt 0) -or
            ($check.Details -is [string] -and $check.Details.Length -gt 0) -or
            ($check.Details -is [psobject] -and $check.Details -isnot [string] -and $check.Details -isnot [array] -and $check.Details -isnot [hashtable])
        )
        $flyoutAttr = if ($hasDetails) { " data-flyout-id=`"$($check.CheckId)`"" } else { "" }
        $chevronTd = if ($hasDetails) { '<td class="col-flyout-icon"><i data-lucide="chevron-right" style="width:16px;height:16px;color:#94a3b8"></i></td>' } else { '<td></td>' }
        $healthChecksHtml += @"
<tr$flyoutAttr>
    <td><code>$($check.CheckId)</code></td>
    <td>$($check.Category)</td>
    <td>$($check.CheckName)</td>
    <td>$statusBadge</td>
    <td>$($check.Description)</td>
    $chevronTd
</tr>
"@
    }
    $healthChecksHtml += "</tbody></table>"

    # Build flyout data for health checks
    $flyoutData = @{}
    foreach ($check in $Data.HealthChecks) {
        $d = $check.Details
        if ($null -eq $d) { continue }

        $detailsHtml = ""

        if ($d -is [hashtable] -or $d -is [System.Collections.IDictionary]) {
            # Hashtable -> definition list, with sub-rendering for complex values
            $detailsHtml = '<dl class="row mb-0">'
            foreach ($key in $d.Keys) {
                $v = $d[$key]
                $val = ''
                if ($null -eq $v) {
                    $val = '<span class="text-muted">-</span>'
                } elseif ($v -is [array] -and $v.Count -gt 0 -and ($v[0] -is [hashtable] -or $v[0] -is [System.Collections.IDictionary])) {
                    # Nested array of hashtables -> inline table
                    $cols = @($v[0].Keys)
                    $val = "<div class=`"table-responsive mt-1`"><table class=`"table table-sm table-bordered flyout-detail-table mb-0`"><thead><tr>"
                    foreach ($c in $cols) { $val += "<th>$([System.Web.HttpUtility]::HtmlEncode($c))</th>" }
                    $val += '</tr></thead><tbody>'
                    foreach ($row in $v) {
                        $val += '<tr>'
                        foreach ($c in $cols) {
                            $cellVal = if ($null -ne $row[$c]) { [System.Web.HttpUtility]::HtmlEncode("$($row[$c])") } else { '-' }
                            $val += "<td>$cellVal</td>"
                        }
                        $val += '</tr>'
                    }
                    $val += '</tbody></table></div>'
                } elseif ($v -is [array] -and $v.Count -gt 0 -and ($v[0] -is [psobject]) -and ($v[0] -isnot [string])) {
                    # Nested array of PSObjects -> inline table
                    $cols = @($v[0].PSObject.Properties | ForEach-Object { $_.Name })
                    $val = "<div class=`"table-responsive mt-1`"><table class=`"table table-sm table-bordered flyout-detail-table mb-0`"><thead><tr>"
                    foreach ($c in $cols) { $val += "<th>$([System.Web.HttpUtility]::HtmlEncode($c))</th>" }
                    $val += '</tr></thead><tbody>'
                    foreach ($row in $v) {
                        $val += '<tr>'
                        foreach ($c in $cols) {
                            $cellVal = if ($null -ne $row.$c) { [System.Web.HttpUtility]::HtmlEncode("$($row.$c)") } else { '-' }
                            $val += "<td>$cellVal</td>"
                        }
                        $val += '</tr>'
                    }
                    $val += '</tbody></table></div>'
                } elseif ($v -is [array]) {
                    # Nested array of scalars -> inline list
                    $val = '<ul class="list-group list-group-flush">'
                    foreach ($item in $v) { $val += "<li class=`"list-group-item px-0 py-1`">$([System.Web.HttpUtility]::HtmlEncode("$item"))</li>" }
                    $val += '</ul>'
                } else {
                    $rawVal = "$v"
                    $val = if ($rawVal -match '^https?://') {
                        $encoded = [System.Web.HttpUtility]::HtmlEncode($rawVal)
                        "<a href=`"$encoded`" target=`"_blank`" rel=`"noopener`">$encoded</a>"
                    } else {
                        [System.Web.HttpUtility]::HtmlEncode($rawVal)
                    }
                }
                $detailsHtml += "<dt class=`"col-sm-5`">$([System.Web.HttpUtility]::HtmlEncode($key))</dt><dd class=`"col-sm-7`">$val</dd>"
            }
            $detailsHtml += '</dl>'
        }
        elseif ($d -is [array] -and $d.Count -gt 0) {
            $first = $d[0]
            if ($first -is [string]) {
                # Array of strings -> list group with count badge
                $detailsHtml = "<div class=`"mb-2`"><span class=`"badge bg-secondary`">$($d.Count) items</span></div>"
                $detailsHtml += '<ul class="list-group list-group-flush">'
                foreach ($item in $d) {
                    $detailsHtml += "<li class=`"list-group-item px-0 py-1`">$([System.Web.HttpUtility]::HtmlEncode("$item"))</li>"
                }
                $detailsHtml += '</ul>'
            }
            elseif ($first -is [hashtable] -or $first -is [System.Collections.IDictionary]) {
                # Array of hashtables -> table
                $keys = @($first.Keys)
                $detailsHtml = "<div class=`"mb-2`"><span class=`"badge bg-secondary`">$($d.Count) items</span></div>"
                $detailsHtml += '<div class="table-responsive"><table class="table table-sm table-bordered flyout-detail-table mb-0"><thead><tr>'
                foreach ($k in $keys) {
                    $detailsHtml += "<th>$([System.Web.HttpUtility]::HtmlEncode($k))</th>"
                }
                $detailsHtml += '</tr></thead><tbody>'
                foreach ($row in $d) {
                    $detailsHtml += '<tr>'
                    foreach ($k in $keys) {
                        $cellVal = if ($null -ne $row[$k]) { [System.Web.HttpUtility]::HtmlEncode("$($row[$k])") } else { '-' }
                        $detailsHtml += "<td>$cellVal</td>"
                    }
                    $detailsHtml += '</tr>'
                }
                $detailsHtml += '</tbody></table></div>'
            }
            elseif ($first -is [psobject]) {
                # Array of PSObjects -> table
                $props = @($first.PSObject.Properties | ForEach-Object { $_.Name })
                if ($props.Count -gt 0) {
                    $detailsHtml = "<div class=`"mb-2`"><span class=`"badge bg-secondary`">$($d.Count) items</span></div>"
                    $detailsHtml += '<div class="table-responsive"><table class="table table-sm table-bordered flyout-detail-table mb-0"><thead><tr>'
                    foreach ($p in $props) {
                        $detailsHtml += "<th>$([System.Web.HttpUtility]::HtmlEncode($p))</th>"
                    }
                    $detailsHtml += '</tr></thead><tbody>'
                    foreach ($row in $d) {
                        $detailsHtml += '<tr>'
                        foreach ($p in $props) {
                            $cellVal = if ($null -ne $row.$p) { [System.Web.HttpUtility]::HtmlEncode("$($row.$p)") } else { '-' }
                            $detailsHtml += "<td>$cellVal</td>"
                        }
                        $detailsHtml += '</tr>'
                    }
                    $detailsHtml += '</tbody></table></div>'
                }
            }
        }
        elseif ($d -is [psobject] -and $d -isnot [string]) {
            # Single PSObject -> definition list
            $props = @($d.PSObject.Properties | ForEach-Object { $_.Name })
            if ($props.Count -gt 0) {
                $detailsHtml = '<dl class="row mb-0">'
                foreach ($p in $props) {
                    $rawVal = "$($d.$p)"
                    $val = if ($null -eq $d.$p) {
                        '<span class="text-muted">-</span>'
                    } elseif ($rawVal -match '^https?://') {
                        $encoded = [System.Web.HttpUtility]::HtmlEncode($rawVal)
                        "<a href=`"$encoded`" target=`"_blank`" rel=`"noopener`">$encoded</a>"
                    } else {
                        [System.Web.HttpUtility]::HtmlEncode($rawVal)
                    }
                    $detailsHtml += "<dt class=`"col-sm-5`">$([System.Web.HttpUtility]::HtmlEncode($p))</dt><dd class=`"col-sm-7`">$val</dd>"
                }
                $detailsHtml += '</dl>'
            }
        }
        elseif ($d -is [string] -and $d.Length -gt 0) {
            $detailsHtml = "<p>$([System.Web.HttpUtility]::HtmlEncode($d))</p>"
        }

        if ($detailsHtml.Length -gt 0) {
            $flyoutData[$check.CheckId] = @{
                checkId     = $check.CheckId
                checkName   = $check.CheckName
                category    = $check.Category
                status      = $check.Status
                description = $check.Description
                detailsHtml = $detailsHtml
            }
        }
    }
    $flyoutJson = ($flyoutData | ConvertTo-Json -Depth 10 -Compress) -replace '</', '<\/'
    $healthChecksHtml += "`n<script type=`"application/json`" id=`"healthChecksTableFlyoutData`">$flyoutJson</script>"

    # Build analytics rules table
    $analyticsHtml = @"
<table class="table table-hover report-table" id="analyticsTable">
<thead>
<tr>
    <th>Display Name</th>
    <th>Severity</th>
    <th>Kind</th>
    <th>Enabled</th>
    <th>Tactics</th>
</tr>
</thead>
<tbody>
"@

    foreach ($rule in $Data.AnalyticsRules) {
        $props = Get-SafeProperty $rule 'properties'
        $displayName = Get-SafeProperty $props 'displayName'
        $severity = Get-SafeProperty $props 'severity'
        $enabled = Get-SafeProperty $props 'enabled'
        $tactics = Get-SafeProperty $props 'tactics'

        $severityBadge = switch ($severity) {
            'High'          { '<span class="badge bg-danger">High</span>' }
            'Medium'        { '<span class="badge bg-warning text-dark">Medium</span>' }
            'Low'           { '<span class="badge bg-info">Low</span>' }
            'Informational' { '<span class="badge bg-secondary">Info</span>' }
            default         { '<span class="badge bg-secondary">-</span>' }
        }
        $enabledBadge = if ($enabled) { '<span class="badge bg-success">Yes</span>' } else { '<span class="badge bg-danger">No</span>' }
        $tacticsStr = if ($tactics) { $tactics -join ', ' } else { '-' }

        $analyticsHtml += @"
<tr>
    <td>$([System.Web.HttpUtility]::HtmlEncode($displayName))</td>
    <td>$severityBadge</td>
    <td>$($rule.kind)</td>
    <td>$enabledBadge</td>
    <td><small>$tacticsStr</small></td>
</tr>
"@
    }
    $analyticsHtml += "</tbody></table>"

    # Build rules by kind chart data
    $rulesByKind = $Data.AnalyticsRules | Group-Object -Property kind
    $kindLabels = ($rulesByKind | ForEach-Object { "'$($_.Name)'" }) -join ', '
    $kindData = ($rulesByKind | ForEach-Object { $_.Count }) -join ', '

    # Build rules by severity chart data (with fixed order and appropriate colors)
    $severityOrder = @('High', 'Medium', 'Low', 'Informational')
    $severityColors = @{
        'High'          = '#dc3545'  # Red
        'Medium'        = '#ffc107'  # Yellow/Amber
        'Low'           = '#28a745'  # Green
        'Informational' = '#6f42c1'  # Purple
    }
    $rulesBySeverity = $Data.AnalyticsRules | Group-Object -Property { Get-SafeProperty $_.properties 'severity' }
    $severityLookup = @{}
    foreach ($group in $rulesBySeverity) {
        if ($group.Name -and $group.Name -in $severityOrder) {
            $severityLookup[$group.Name] = $group.Count
        }
    }
    # Build arrays in fixed order, only including severities with data
    $severityLabelsArray = @()
    $severityDataArray = @()
    $severityColorsArray = @()
    foreach ($sev in $severityOrder) {
        if ($severityLookup.ContainsKey($sev) -and $severityLookup[$sev] -gt 0) {
            $severityLabelsArray += "'$sev'"
            $severityDataArray += $severityLookup[$sev]
            $severityColorsArray += "'$($severityColors[$sev])'"
        }
    }
    $severityLabels = $severityLabelsArray -join ', '
    $severityData = $severityDataArray -join ', '
    $severityChartColors = $severityColorsArray -join ', '

    # Build Visibility Gaps table (from health check ANA-002)
    $visibilityGapsCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'ANA-002' }
    $visibilityGapsHtml = ""
    if ($visibilityGapsCheck -and $visibilityGapsCheck.Details -and @($visibilityGapsCheck.Details).Count -gt 0) {
        $visibilityGapsHtml = @"
<h5 class="mt-4 mb-3" id="visibility-gaps"><span class="badge bg-warning text-dark me-2">$(@($visibilityGapsCheck.Details).Count)</span> Visibility Gaps</h5>
<p class="text-muted small">Rules where the template expects incident creation, but the rule is disabled or not creating incidents.</p>
<table class="table table-hover table-sm report-table flyout-enabled" id="visibilityGapsTable">
<thead><tr><th>Rule Name</th><th>Severity</th><th>Enabled</th><th>Issue</th><th>Alerts (90d)</th><th class="col-flyout-icon"></th></tr></thead>
<tbody>
"@
        $visibilityGapsFlyoutData = @{}
        $gapIndex = 0
        foreach ($gap in $visibilityGapsCheck.Details) {
            $gapKey = "gap-$gapIndex"
            $gapIndex++
            $sevBadge = switch ($gap.Severity) {
                'High'   { '<span class="badge bg-danger">High</span>' }
                'Medium' { '<span class="badge bg-warning text-dark">Medium</span>' }
                'Low'    { '<span class="badge bg-info">Low</span>' }
                default  { '<span class="badge bg-secondary">-</span>' }
            }
            $enabledBadge = if ($gap.Enabled) { '<span class="badge bg-success">Yes</span>' } else { '<span class="badge bg-danger">No</span>' }

            # Alert count badge (only for enabled rules not creating incidents)
            $alertCount = if ($gap.AlertCount90d) { [int]$gap.AlertCount90d } else { 0 }
            $alertCountBadge = if ($gap.Issue -eq 'Not Creating Incidents' -and $alertCount -gt 0) {
                '<span class="badge bg-danger">' + $alertCount + '</span>'
            } elseif ($gap.Issue -eq 'Not Creating Incidents') {
                '<span class="badge bg-secondary">0</span>'
            } else {
                '<span class="text-muted small">N/A</span>'
            }

            $chevronTd = '<td class="col-flyout-icon"><i data-lucide="chevron-right" style="width:16px;height:16px;color:#94a3b8"></i></td>'
            $ruleNameEncoded = if ($gap.RuleName) { [System.Web.HttpUtility]::HtmlEncode($gap.RuleName) } else { '(unknown)' }
            $alertSortOrder = if ($gap.Issue -eq 'Not Creating Incidents') { $alertCount } else { -1 }
            $visibilityGapsHtml += "<tr data-flyout-id=`"$gapKey`"><td>$ruleNameEncoded</td><td>$sevBadge</td><td>$enabledBadge</td><td>$($gap.Issue)</td><td data-order=`"$alertSortOrder`">$alertCountBadge</td>$chevronTd</tr>"

            # Build flyout detail HTML for this gap
            $flyoutHtml = '<dl class="row mb-0">'
            $flyoutHtml += "<dt class=`"col-sm-5`">Rule Name</dt><dd class=`"col-sm-7`">$ruleNameEncoded</dd>"
            $flyoutHtml += "<dt class=`"col-sm-5`">Severity</dt><dd class=`"col-sm-7`">$sevBadge</dd>"
            $flyoutHtml += "<dt class=`"col-sm-5`">Enabled</dt><dd class=`"col-sm-7`">$enabledBadge</dd>"
            $flyoutHtml += "<dt class=`"col-sm-5`">Issue</dt><dd class=`"col-sm-7`">$($gap.Issue)</dd>"
            $flyoutHtml += '</dl>'

            if ($gap.Issue -eq 'Not Creating Incidents') {
                $flyoutHtml += '<hr><span class="text-muted small text-uppercase fw-bold">Alert Activity (Past 90 Days)</span>'
                if ($alertCount -gt 0) {
                    $flyoutHtml += "<div class=`"mt-2 mb-2`"><span class=`"badge bg-danger fs-6`">$alertCount</span> <span class=`"text-muted`">orphaned alerts generated</span></div>"
                    $flyoutHtml += '<p class="text-muted small">This rule is actively generating alerts that are not being promoted to incidents. These alerts are only visible in the SecurityAlert table and may represent unreviewed security detections.</p>'
                    $flyoutHtml += '<div class="table-responsive mt-2"><table class="table table-sm table-bordered flyout-detail-table mb-0">'
                    $flyoutHtml += '<thead><tr><th>Alert Severity</th><th>Count</th></tr></thead><tbody>'
                    $aHigh = if ($gap.AlertHigh) { [int]$gap.AlertHigh } else { 0 }
                    $aMedium = if ($gap.AlertMedium) { [int]$gap.AlertMedium } else { 0 }
                    $aLow = if ($gap.AlertLow) { [int]$gap.AlertLow } else { 0 }
                    $aInfo = if ($gap.AlertInfo) { [int]$gap.AlertInfo } else { 0 }
                    if ($aHigh -gt 0) { $flyoutHtml += "<tr><td><span class=`"badge bg-danger`">High</span></td><td>$aHigh</td></tr>" }
                    if ($aMedium -gt 0) { $flyoutHtml += "<tr><td><span class=`"badge bg-warning text-dark`">Medium</span></td><td>$aMedium</td></tr>" }
                    if ($aLow -gt 0) { $flyoutHtml += "<tr><td><span class=`"badge bg-info`">Low</span></td><td>$aLow</td></tr>" }
                    if ($aInfo -gt 0) { $flyoutHtml += "<tr><td><span class=`"badge bg-secondary`">Informational</span></td><td>$aInfo</td></tr>" }
                    $flyoutHtml += '</tbody></table></div>'
                    if ($gap.FirstAlert) {
                        $flyoutHtml += '<dl class="row mb-0 mt-2">'
                        $flyoutHtml += "<dt class=`"col-sm-5`">First Alert</dt><dd class=`"col-sm-7`">$([System.Web.HttpUtility]::HtmlEncode("$($gap.FirstAlert)"))</dd>"
                        $flyoutHtml += "<dt class=`"col-sm-5`">Last Alert</dt><dd class=`"col-sm-7`">$([System.Web.HttpUtility]::HtmlEncode("$($gap.LastAlert)"))</dd>"
                        $flyoutHtml += '</dl>'
                    }
                } else {
                    $flyoutHtml += '<div class="mt-2"><span class="badge bg-secondary">0</span> <span class="text-muted">alerts in the past 90 days</span></div>'
                    $flyoutHtml += '<p class="text-muted small mt-1">This rule has incident creation disabled but has not generated any alerts recently.</p>'
                }
            } else {
                $flyoutHtml += '<hr><span class="text-muted small text-uppercase fw-bold">Alert Activity</span>'
                $flyoutHtml += '<p class="text-muted small mt-2">This rule is disabled and cannot generate alerts. Enable the rule to begin detecting threats.</p>'
            }

            $gapRuleNameEncoded = if ($gap.RuleName) { [System.Web.HttpUtility]::HtmlEncode($gap.RuleName) } else { '(unknown)' }
            $visibilityGapsFlyoutData[$gapKey] = @{
                checkId     = 'ANA-002'
                checkName   = $gapRuleNameEncoded
                category    = 'Visibility Gap'
                status      = if ($gap.Issue -eq 'Not Creating Incidents' -and $alertCount -gt 0) { 'Critical' } else { 'Warning' }
                description = if ($gap.Issue) { $gap.Issue } else { 'Unknown' }
                detailsHtml = $flyoutHtml
            }
        }
        $visibilityGapsHtml += "</tbody></table>"
        $visibilityGapsFlyoutJson = ($visibilityGapsFlyoutData | ConvertTo-Json -Depth 10 -Compress) -replace '</', '<\/'
        $visibilityGapsHtml += "`n<script type=`"application/json`" id=`"visibilityGapsTableFlyoutData`">$visibilityGapsFlyoutJson</script>"
    }

    # Build Disabled Rules table (from health check ANA-005)
    $disabledRulesCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'ANA-005' }
    $disabledRulesHtml = ""
    if ($disabledRulesCheck -and $disabledRulesCheck.Details -and @($disabledRulesCheck.Details).Count -gt 0) {
        $disabledRulesList = @($Data.AnalyticsRules | Where-Object { (Get-SafeProperty $_.properties 'enabled') -eq $false })
        $disabledRulesHtml = @"
<h5 class="mt-4 mb-3" id="disabled-rules"><span class="badge bg-secondary me-2">$($disabledRulesList.Count)</span> Disabled Rules</h5>
<p class="text-muted small">Rules that are currently disabled. Review for rules that should be re-enabled.</p>
<table class="table table-hover table-sm report-table" id="disabledRulesTable">
<thead><tr><th>Rule Name</th><th>Severity</th><th>Kind</th></tr></thead>
<tbody>
"@
        foreach ($rule in ($disabledRulesList | Sort-Object { Get-SafeProperty $_.properties 'severity' }, { Get-SafeProperty $_.properties 'displayName' })) {
            $props = Get-SafeProperty $rule 'properties'
            $displayName = Get-SafeProperty $props 'displayName'
            $severity = Get-SafeProperty $props 'severity'
            $sevBadge = switch ($severity) {
                'High'          { '<span class="badge bg-danger">High</span>' }
                'Medium'        { '<span class="badge bg-warning text-dark">Medium</span>' }
                'Low'           { '<span class="badge bg-info">Low</span>' }
                'Informational' { '<span class="badge bg-secondary">Info</span>' }
                default         { '<span class="badge bg-secondary">-</span>' }
            }
            $disabledRulesHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($displayName))</td><td>$sevBadge</td><td>$($rule.kind)</td></tr>"
        }
        $disabledRulesHtml += "</tbody></table>"
    }

    # Build Custom Rules table (from health check ANA-004)
    $customRulesCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'ANA-004' }
    $customRulesHtml = ""
    if ($customRulesCheck -and $customRulesCheck.Details -and @($customRulesCheck.Details).Count -gt 0) {
        $customRulesList = @($Data.AnalyticsRules | Where-Object { $null -eq (Get-SafeProperty $_.properties 'alertRuleTemplateName') })
        $customRulesHtml = @"
<h5 class="mt-4 mb-3" id="custom-rules"><span class="badge bg-primary me-2">$($customRulesList.Count)</span> Custom Rules</h5>
<p class="text-muted small">Environment-specific detection rules created for this workspace. These are not based on Content Hub templates.</p>
<table class="table table-hover table-sm report-table" id="customRulesTable">
<thead><tr><th>Rule Name</th><th>Severity</th><th>Kind</th><th>Enabled</th></tr></thead>
<tbody>
"@
        foreach ($rule in ($customRulesList | Sort-Object { Get-SafeProperty $_.properties 'severity' }, { Get-SafeProperty $_.properties 'displayName' })) {
            $props = Get-SafeProperty $rule 'properties'
            $displayName = Get-SafeProperty $props 'displayName'
            $severity = Get-SafeProperty $props 'severity'
            $enabled = Get-SafeProperty $props 'enabled'
            $sevBadge = switch ($severity) {
                'High'          { '<span class="badge bg-danger">High</span>' }
                'Medium'        { '<span class="badge bg-warning text-dark">Medium</span>' }
                'Low'           { '<span class="badge bg-info">Low</span>' }
                'Informational' { '<span class="badge bg-secondary">Info</span>' }
                default         { '<span class="badge bg-secondary">-</span>' }
            }
            $enabledBadge = if ($enabled) { '<span class="badge bg-success">Yes</span>' } else { '<span class="badge bg-danger">No</span>' }
            $customRulesHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($displayName))</td><td>$sevBadge</td><td>$($rule.kind)</td><td>$enabledBadge</td></tr>"
        }
        $customRulesHtml += "</tbody></table>"
    }

    # Build Incident Volume by Rule table (from KQL query data)
    $incidentVolumeHtml = ""
    if ($Data.IncidentVolumeByRule -and @($Data.IncidentVolumeByRule).Count -gt 0) {
        $incidentVolumeRules = @($Data.IncidentVolumeByRule)
        $incidentVolumeHtml = @"
<hr class="my-4">
<h5 class="mt-4 mb-3" id="incident-volume"><span class="badge bg-warning text-dark me-2">$($incidentVolumeRules.Count)</span> Incident Volume by Rule (30 Days)</h5>
<p class="text-muted small">Rules generating the most incidents over the last 30 days. High-volume rules may indicate tuning opportunities for false positive reduction.</p>
<table class="table table-hover table-sm report-table" id="incidentVolumeTable">
<thead><tr><th>Rule Name</th><th>Status</th><th>Severity</th><th>Incidents (30d)</th><th>Daily Avg</th><th>Weekly Avg</th></tr></thead>
<tbody>
"@
        foreach ($rule in ($incidentVolumeRules | Sort-Object { -[double]$_.DailyAverage })) {
            $ruleName = if ($rule.RuleName) { [System.Web.HttpUtility]::HtmlEncode($rule.RuleName) } else { '-' }
            $statusBadge = switch ($rule.RuleStatus) {
                'Active'   { '<span class="badge bg-success">Active</span>' }
                'Disabled' { '<span class="badge bg-danger">Disabled</span>' }
                'Deleted'  { '<span class="badge bg-secondary">Deleted</span>' }
                default    { '<span class="badge bg-secondary">Unknown</span>' }
            }
            $sevBadge = switch ($rule.Severity) {
                'High'          { '<span class="badge bg-danger">High</span>' }
                'Medium'        { '<span class="badge bg-warning text-dark">Medium</span>' }
                'Low'           { '<span class="badge bg-info">Low</span>' }
                'Informational' { '<span class="badge bg-secondary">Info</span>' }
                default         { '<span class="badge bg-secondary">-</span>' }
            }
            $incidentVolumeHtml += "<tr><td>$ruleName</td><td>$statusBadge</td><td>$sevBadge</td><td>$($rule.IncidentCount)</td><td>$($rule.DailyAverage)</td><td>$($rule.WeeklyAverage)</td></tr>"
        }
        $incidentVolumeHtml += "</tbody></table>"
    }

    # Build Rules with Updates table (from health check ANA-001)
    $rulesWithUpdatesCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'ANA-001' }
    $rulesWithUpdatesHtml = ""
    if ($rulesWithUpdatesCheck -and $rulesWithUpdatesCheck.Details -and @($rulesWithUpdatesCheck.Details).Count -gt 0) {
        $rulesWithUpdatesHtml = @"
<h5 class="mt-4 mb-3" id="rules-updates"><span class="badge bg-info me-2">$(@($rulesWithUpdatesCheck.Details).Count)</span> Rules with Pending Updates</h5>
<p class="text-muted small">Rules that have newer template versions available in Content Hub.</p>
<table class="table table-hover table-sm report-table" id="rulesUpdatesTable">
<thead><tr><th>Rule Name</th><th>Current Version</th><th>Available Version</th></tr></thead>
<tbody>
"@
        foreach ($rule in $rulesWithUpdatesCheck.Details) {
            $rulesWithUpdatesHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($rule.RuleName))</td><td><code>$($rule.CurrentVersion)</code></td><td><code>$($rule.TemplateVersion)</code></td></tr>"
        }
        $rulesWithUpdatesHtml += "</tbody></table>"
    }

    # Build Analytics Health section (from ANAH health checks)
    $analyticsHealthHtml = ""
    if ($Data.AnalyticsHealthSummary -and @($Data.AnalyticsHealthSummary).Count -gt 0) {
        $healthSummary = @($Data.AnalyticsHealthSummary)
        $totalExecutions = ($healthSummary | Measure-Object -Property TotalExecutions -Sum).Sum
        $totalFailures = ($healthSummary | Measure-Object -Property FailureCount -Sum).Sum
        $totalSuccesses = $totalExecutions - $totalFailures
        $successRate = if ($totalExecutions -gt 0) { [math]::Round(($totalSuccesses / $totalExecutions) * 100, 1) } else { 100 }
        $rulesWithFailures = @($healthSummary | Where-Object { $_.FailureCount -gt 0 })
        $skippedWindows = if ($Data.AnalyticsSkippedWindows) { @($Data.AnalyticsSkippedWindows).Count } else { 0 }

        # Summary cards
        $analyticsHealthHtml = @"
<hr class="my-4">
<h5 class="mt-4 mb-3" id="analytics-health"><i data-lucide="activity" class="me-2" style="width:16px;height:16px"></i>Analytics Health (7 Days)</h5>
<p class="text-muted small">Rule execution health based on the _SentinelHealth table. Shows rule execution success/failure rates and common issues.</p>

<div class="row mb-4">
  <div class="col-md-3">
    <div class="card bg-light h-100">
      <div class="card-body text-center py-3">
        <h3 class="mb-1">$($totalExecutions.ToString('N0'))</h3>
        <small class="text-muted">Total Executions</small>
      </div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card $(if ($successRate -ge 95) { 'bg-success text-white' } elseif ($successRate -ge 80) { 'bg-warning' } else { 'bg-danger text-white' }) h-100">
      <div class="card-body text-center py-3">
        <h3 class="mb-1">$successRate%</h3>
        <small>Success Rate</small>
      </div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card $(if ($rulesWithFailures.Count -eq 0) { 'bg-success text-white' } elseif ($rulesWithFailures.Count -le 5) { 'bg-warning' } else { 'bg-danger text-white' }) h-100">
      <div class="card-body text-center py-3">
        <h3 class="mb-1">$($rulesWithFailures.Count)</h3>
        <small>Rules with Failures</small>
      </div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card $(if ($skippedWindows -eq 0) { 'bg-success text-white' } else { 'bg-danger text-white' }) h-100">
      <div class="card-body text-center py-3">
        <h3 class="mb-1">$skippedWindows</h3>
        <small>Skipped Windows</small>
      </div>
    </div>
  </div>
</div>
"@

        # Failure Reasons table
        if ($Data.AnalyticsFailureReasons -and @($Data.AnalyticsFailureReasons).Count -gt 0) {
            # Remediation mapping
            $remediationMap = @{
                'Query execution timed out' = 'Optimize query, reduce time range'
                'Table.*not found' = 'Verify data connector is enabled'
                'Semantic error' = 'Edit and re-save the rule to reset'
                'Syntax error' = 'Fix KQL syntax and re-save'
                'too many.*resources' = 'Optimize KQL query, add filters'
                'Function.*not found' = 'Verify workspace functions exist'
                'No access' = 'Check permissions and re-save rule'
                'Ingestion delay' = 'Monitor data pipeline health'
                'disabled and was not executed' = 'Re-enable the rule if needed'
            }

            $analyticsHealthHtml += @"
<h6 class="mt-4 mb-2">Failure Reasons</h6>
<table class="table table-hover table-sm report-table" id="failureReasonsTable">
<thead><tr><th>Reason</th><th>Failures</th><th>Affected Rules</th><th>Remediation</th></tr></thead>
<tbody>
"@
            foreach ($reason in $Data.AnalyticsFailureReasons) {
                $reasonText = $reason.Reason
                # Find matching remediation
                $remediation = 'Review rule configuration'
                foreach ($pattern in $remediationMap.Keys) {
                    if ($reasonText -match $pattern) {
                        $remediation = $remediationMap[$pattern]
                        break
                    }
                }
                $analyticsHealthHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($reasonText))</td><td><span class='badge bg-danger'>$($reason.FailureCount)</span></td><td>$($reason.AffectedRules)</td><td><small class='text-muted'>$remediation</small></td></tr>"
            }
            $analyticsHealthHtml += "</tbody></table>"
        }

        # Problematic Rules table (rules with failures)
        if ($rulesWithFailures.Count -gt 0) {
            $analyticsHealthHtml += @"
<h6 class="mt-4 mb-2">Rules with Failures</h6>
<table class="table table-hover table-sm report-table" id="problematicRulesTable">
<thead><tr><th>Rule Name</th><th>Type</th><th>Total Executions</th><th>Failures</th><th>Failure Rate</th></tr></thead>
<tbody>
"@
            foreach ($rule in ($rulesWithFailures | Sort-Object FailureRate -Descending)) {
                $rateBadge = if ($rule.FailureRate -gt 50) {
                    '<span class="badge bg-danger">' + $rule.FailureRate + '%</span>'
                } elseif ($rule.FailureRate -gt 20) {
                    '<span class="badge bg-warning text-dark">' + $rule.FailureRate + '%</span>'
                } else {
                    '<span class="badge bg-secondary">' + $rule.FailureRate + '%</span>'
                }
                $typeBadge = if ($rule.SentinelResourceKind -eq 'NRT') {
                    '<span class="badge bg-info">NRT</span>'
                } else {
                    '<span class="badge bg-secondary">Scheduled</span>'
                }
                $analyticsHealthHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($rule.SentinelResourceName))</td><td>$typeBadge</td><td>$($rule.TotalExecutions)</td><td><span class='badge bg-danger'>$($rule.FailureCount)</span></td><td>$rateBadge</td></tr>"
            }
            $analyticsHealthHtml += "</tbody></table>"
        }

        # Skipped Windows table
        if ($Data.AnalyticsSkippedWindows -and @($Data.AnalyticsSkippedWindows).Count -gt 0) {
            $analyticsHealthHtml += @"
<h6 class="mt-4 mb-2"><span class="badge bg-danger me-2">Critical</span> Skipped Query Windows</h6>
<p class="text-muted small">Rules where all 6 retry attempts failed, resulting in detection gaps.</p>
<table class="table table-hover table-sm report-table" id="skippedWindowsTable">
<thead><tr><th>Rule Name</th><th>Skipped Windows</th></tr></thead>
<tbody>
"@
            foreach ($rule in $Data.AnalyticsSkippedWindows) {
                $analyticsHealthHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($rule.SentinelResourceName))</td><td><span class='badge bg-danger'>$($rule.SkippedWindows)</span></td></tr>"
            }
            $analyticsHealthHtml += "</tbody></table>"
        }

        # Execution Delays table
        if ($Data.AnalyticsExecutionDelays -and @($Data.AnalyticsExecutionDelays).Count -gt 0) {
            $analyticsHealthHtml += @"
<h6 class="mt-4 mb-2">Execution Delays</h6>
<p class="text-muted small">Scheduled rules with average execution delays exceeding 5 minutes.</p>
<table class="table table-hover table-sm report-table" id="executionDelaysTable">
<thead><tr><th>Rule Name</th><th>Avg Delay (min)</th><th>Max Delay (min)</th><th>Delayed Executions</th></tr></thead>
<tbody>
"@
            foreach ($rule in ($Data.AnalyticsExecutionDelays | Sort-Object AvgDelay -Descending)) {
                $analyticsHealthHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($rule.SentinelResourceName))</td><td>$($rule.AvgDelay)</td><td>$($rule.MaxDelay)</td><td>$($rule.DelayedExecutions)</td></tr>"
            }
            $analyticsHealthHtml += "</tbody></table>"
        }
    } else {
        # No health data available - show info message
        $analyticsHealthHtml = @"
<hr class="my-4">
<h5 class="mt-4 mb-3" id="analytics-health"><i data-lucide="activity" class="me-2" style="width:16px;height:16px"></i>Analytics Health</h5>
<div class="alert alert-info">
  <i data-lucide="info" class="me-2" style="width:16px;height:16px"></i>
  <strong>Health data not available.</strong> Enable Microsoft Sentinel health monitoring diagnostic setting to track analytics rule execution health.
  <a href="https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity" target="_blank" class="alert-link">Learn more</a>
</div>
"@
    }

    # Build connector health lookup - index by connector name prefix (before dash)
    # SentinelResourceName format: "Office365-Sharepoint", "MicrosoftThreatProtection-MTPAlerts", etc.
    $connectorHealthLookup = @{}
    if ($Data.ConnectorHealth) {
        foreach ($health in $Data.ConnectorHealth) {
            # Extract connector name prefix (before first dash)
            $resourceName = $health.SentinelResourceName
            $connectorPrefix = if ($resourceName -match '^([^-]+)') { $matches[1] } else { $resourceName }
            # Only store if we don't have one yet, or update if this one is more recent
            if (-not $connectorHealthLookup.ContainsKey($connectorPrefix) -or
                ($health.TimeGenerated -gt $connectorHealthLookup[$connectorPrefix].TimeGenerated)) {
                $connectorHealthLookup[$connectorPrefix] = $health
            }
        }
    }

    # Mapping of connector names/kinds to their primary log table(s) for fallback last seen
    # Extracted from Azure Sentinel Solutions repo data connector definitions
    $connectorTableMap = @{
        # Azure Activity
        'AzureActivity' = 'AzureActivity'
        # Entra ID (Azure AD)
        'AzureActiveDirectory' = 'SigninLogs'
        'AzureActiveDirectoryIdentityProtection' = 'SecurityAlert'
        # Security Events
        'SecurityEvents' = 'SecurityEvent'
        'WindowsSecurityEvents' = 'SecurityEvent'
        'WindowsForwardedEvents' = 'WindowsEvent'
        # Syslog
        'Syslog' = 'Syslog'
        'SyslogAma' = 'Syslog'
        # Microsoft Defender XDR (M365D / MTP)
        'MicrosoftThreatProtection' = 'DeviceEvents'
        'Microsoft365Defender' = 'DeviceEvents'
        'MicrosoftDefenderAdvancedThreatProtection' = 'SecurityAlert'
        # Microsoft Defender for Cloud
        'AzureSecurityCenter' = 'SecurityAlert'
        'MicrosoftDefenderForCloud' = 'SecurityAlert'
        'MicrosoftDefenderForCloudTenantBased' = 'SecurityAlert'
        # Microsoft Defender for Cloud Apps
        'MicrosoftCloudAppSecurity' = 'CloudAppEvents'
        # Office 365
        'Office365' = 'OfficeActivity'
        'OfficeATP' = 'EmailEvents'
        'OfficeIRM' = 'OfficeActivity'
        'Office365Project' = 'ProjectActivity'
        'OfficePowerBI' = 'PowerBIActivity'
        # DNS
        'DNS' = 'DnsEvents'
        # Threat Intelligence - try both table names (ThreatIntelIndicators is newer)
        'ThreatIntelligence' = 'ThreatIntelIndicators'
        'ThreatIntelligenceTaxii' = 'ThreatIntelIndicators'
        'ThreatIntelligenceUploadIndicatorsAPI' = 'ThreatIntelIndicators'
        'MicrosoftDefenderThreatIntelligence' = 'ThreatIntelIndicators'
        'PremiumMicrosoftDefenderForThreatIntelligence' = 'ThreatIntelIndicators'
        'MicrosoftThreatIntelligence' = 'ThreatIntelIndicators'
        # CEF/Syslog
        'CEF' = 'CommonSecurityLog'
        'CefAma' = 'CommonSecurityLog'
        'CommonSecurityLog' = 'CommonSecurityLog'
        # Azure Resources
        'AzureFirewall' = 'AzureDiagnostics'
        'WAF' = 'AzureDiagnostics'
        'AzureKeyVault' = 'AzureDiagnostics'
        'AzureNSG' = 'AzureDiagnostics'
        'AzureSql' = 'AzureDiagnostics'
        'AzureKubernetes' = 'AzureDiagnostics'
        # Microsoft Defender for Identity
        'MicrosoftDefenderForIdentity' = 'SecurityAlert'
        'AzureAdvancedThreatProtection' = 'SecurityAlert'
        # Microsoft Defender for IoT
        'MicrosoftDefenderForIoT' = 'SecurityAlert'
        'IoT' = 'SecurityAlert'
        # Microsoft Purview
        'MicrosoftPurviewInformationProtection' = 'MicrosoftPurviewInformationProtection'
        'MicrosoftAzurePurview' = 'PurviewDataSensitivityLogs'
        # Exchange Security Insights
        'ESI-ExchangeOnlineCollector' = 'ESIExchangeOnlineConfig_CL'
        # AWS
        'AWS' = 'AWSCloudTrail'
        'AmazonWebServicesCloudTrail' = 'AWSCloudTrail'
        'AwsS3' = 'AWSGuardDuty'
        # GCP
        'GCP' = 'GCPAuditLogs'
        # Dynamics 365
        'Dynamics365' = 'Dynamics365Activity'
        # WatchGuard
        'WatchguardFirebox' = 'WatchGuardFirebox'
    }

    # Build table last seen lookup from LastEventByTable data
    $tableLastSeenLookup = @{}
    if ($Data.LastEventByTable) {
        foreach ($table in $Data.LastEventByTable) {
            $tableLastSeenLookup[$table._TableName] = $table.LastEvent
        }
    }

    # Build connector-specific last seen lookup (for shared tables like SecurityAlert)
    $connectorLastSeenLookup = @{}
    if ($Data.ConnectorLastSeen) {
        foreach ($conn in $Data.ConnectorLastSeen) {
            $connectorLastSeenLookup[$conn.ConnectorKey] = $conn.LastEvent
        }
    }

    # Build data connectors table
    $connectorsHtml = @"
<p class="text-muted small mb-3">
    <strong>Health Status</strong> indicates whether a connector is actively ingesting data.
    <span class="badge bg-success">Healthy</span> connectors have status reported via SentinelHealth.
    <span class="badge bg-success">Active</span> connectors have received data within the last 24 hours (determined by querying the connector's target tables).
    <span class="badge bg-warning text-dark">Stale</span> indicates no data received in 1-7 days.
    <span class="badge bg-danger">Inactive</span> indicates no data received in over 7 days.
    <span class="badge bg-secondary">Unknown</span> indicates no health data or table activity was found.
</p>
<table class="table table-hover report-table" id="connectorsTable">
<thead>
<tr>
    <th>Name</th>
    <th>Kind</th>
    <th>Health Status</th>
    <th>Last Seen</th>
</tr>
</thead>
<tbody>
"@

    foreach ($connector in $Data.DataConnectors) {
        $connectorName = $connector.name
        $connectorKind = $connector.kind

        # Get health status - try name first (matches SentinelResourceName prefix), then kind as fallback
        $health = $connectorHealthLookup[$connectorName]
        if (-not $health) { $health = $connectorHealthLookup[$connectorKind] }
        $healthStatus = if ($health) { $health.Status } else { 'Unknown' }
        $lastSeenSource = 'none'

        # Get last seen - try SentinelHealth first, then fallback to table last event
        $lastSeen = '-'
        $lastSeenDateTime = $null
        if ($health -and $health.TimeGenerated) {
            try {
                $lastSeenDateTime = [datetime]$health.TimeGenerated
                $lastSeen = $lastSeenDateTime.ToString('yyyy-MM-dd HH:mm')
                $lastSeenSource = 'health'
            } catch { }
        }

        # Fallback 1: Try connector-specific last seen (for shared tables like SecurityAlert)
        if ($lastSeen -eq '-') {
            # Try connector name first, then kind
            $connectorLastEvent = $connectorLastSeenLookup[$connectorName]
            if (-not $connectorLastEvent) { $connectorLastEvent = $connectorLastSeenLookup[$connectorKind] }
            if ($connectorLastEvent) {
                try {
                    $lastSeenDateTime = [datetime]$connectorLastEvent
                    $lastSeen = $lastSeenDateTime.ToString('yyyy-MM-dd HH:mm')
                    $lastSeenSource = 'connector'
                } catch { }
            }
        }

        # Fallback 2: Try to get last seen from the connector's primary table
        if ($lastSeen -eq '-') {
            $tableName = $connectorTableMap[$connectorName]
            if (-not $tableName) { $tableName = $connectorTableMap[$connectorKind] }
            if ($tableName -and $tableLastSeenLookup.ContainsKey($tableName)) {
                $tableLastEvent = $tableLastSeenLookup[$tableName]
                if ($tableLastEvent) {
                    try {
                        $lastSeenDateTime = [datetime]$tableLastEvent
                        $lastSeen = $lastSeenDateTime.ToString('yyyy-MM-dd HH:mm')
                        $lastSeenSource = 'table'
                    } catch { }
                }
            }
        }

        # If we got last seen from connector or table data (not SentinelHealth), determine health based on recency
        if (($lastSeenSource -eq 'table' -or $lastSeenSource -eq 'connector') -and $lastSeenDateTime) {
            $daysSinceLastSeen = ((Get-Date) - $lastSeenDateTime).TotalDays
            if ($daysSinceLastSeen -le 1) {
                $healthStatus = 'Active'
            } elseif ($daysSinceLastSeen -le 7) {
                $healthStatus = 'Stale'
            } else {
                $healthStatus = 'Inactive'
            }
        }

        $healthBadge = switch ($healthStatus) {
            'Success' { '<span class="badge bg-success">Healthy</span>' }
            'Active'  { '<span class="badge bg-success">Active</span>' }
            'Failure' { '<span class="badge bg-danger">Unhealthy</span>' }
            'Inactive' { '<span class="badge bg-danger">Inactive</span>' }
            'Warning' { '<span class="badge bg-warning text-dark">Warning</span>' }
            'Stale'   { '<span class="badge bg-warning text-dark">Stale</span>' }
            default   { '<span class="badge bg-secondary">Unknown</span>' }
        }

        $connectorsHtml += @"
<tr>
    <td>$([System.Web.HttpUtility]::HtmlEncode($connectorName))</td>
    <td><code>$connectorKind</code></td>
    <td>$healthBadge</td>
    <td><small class="text-muted">$lastSeen</small></td>
</tr>
"@
    }
    $connectorsHtml += "</tbody></table>"

    # Build Connectors with Updates sub-table (from CON-001)
    $connectorsUpdatesCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'CON-001' }
    if ($connectorsUpdatesCheck -and $connectorsUpdatesCheck.Details -and @($connectorsUpdatesCheck.Details).Count -gt 0) {
        $connectorsHtml += @"
<h5 class="mt-4 mb-3" id="connectors-updates"><span class="badge bg-info me-2">$(@($connectorsUpdatesCheck.Details).Count)</span> Connectors with Pending Updates</h5>
<p class="text-muted small">Connectors that have newer versions available in Content Hub.</p>
<table class="table table-hover table-sm report-table" id="connectorsUpdatesTable">
<thead><tr><th>Connector Name</th><th>Kind</th><th>Current Version</th><th>Available Version</th></tr></thead>
<tbody>
"@
        foreach ($update in $connectorsUpdatesCheck.Details) {
            $connectorsHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($update.ConnectorName))</td><td><code>$($update.ConnectorKind)</code></td><td><code>$($update.CurrentVersion)</code></td><td><code>$($update.TemplateVersion)</code></td></tr>"
        }
        $connectorsHtml += "</tbody></table>"
    }

    # Build DCE and DCR section
    $dceDcrHtml = ""

    # Data Collection Endpoints (DCEs)
    if ($Data.DataCollectionEndpoints -and $Data.DataCollectionEndpoints.Count -gt 0) {
        $dceDcrHtml += @"
<h5 class="mb-3">Data Collection Endpoints (DCEs)</h5>
<p class="text-muted small mb-3">DCEs define the ingestion endpoint for custom log collection. They provide a regional endpoint for data to be sent to Azure Monitor.</p>
<table class="table table-hover table-sm report-table" id="dceTable">
<thead>
<tr>
    <th>Name</th>
    <th>Location</th>
    <th>Public Network Access</th>
    <th>Provisioning State</th>
</tr>
</thead>
<tbody>
"@
        foreach ($dce in $Data.DataCollectionEndpoints) {
            $dceName = $dce.name
            $dceLocation = Get-SafeProperty $dce 'location'
            $dceProps = Get-SafeProperty $dce 'properties'
            $publicAccess = Get-SafeProperty $dceProps 'networkAcls'
            $publicAccessEnabled = if ($publicAccess) {
                $accessMode = Get-SafeProperty $publicAccess 'publicNetworkAccess'
                if ($accessMode -eq 'Enabled') { '<span class="badge bg-warning text-dark">Enabled</span>' }
                elseif ($accessMode -eq 'Disabled') { '<span class="badge bg-success">Disabled</span>' }
                else { '<span class="badge bg-secondary">Unknown</span>' }
            } else {
                '<span class="badge bg-warning text-dark">Enabled</span>'
            }
            $provisioningState = Get-SafeProperty $dceProps 'provisioningState'
            $provisioningBadge = if ($provisioningState -eq 'Succeeded') {
                '<span class="badge bg-success">Succeeded</span>'
            } elseif ($provisioningState -eq 'Failed') {
                '<span class="badge bg-danger">Failed</span>'
            } else {
                "<span class='badge bg-secondary'>$provisioningState</span>"
            }

            $dceDcrHtml += @"
<tr>
    <td>$([System.Web.HttpUtility]::HtmlEncode($dceName))</td>
    <td>$dceLocation</td>
    <td>$publicAccessEnabled</td>
    <td>$provisioningBadge</td>
</tr>
"@
        }
        $dceDcrHtml += "</tbody></table>"
    } else {
        $dceDcrHtml += "<p class='text-muted'>No Data Collection Endpoints found in this subscription, or insufficient permissions to read them.</p>"
    }

    # Data Collection Rules (DCRs)
    if ($Data.DataCollectionRules -and $Data.DataCollectionRules.Count -gt 0) {
        $dceDcrHtml += @"
<h5 class="mt-4 mb-3">Data Collection Rules (DCRs)</h5>
<p class="text-muted small mb-3">DCRs define what data to collect, how to transform it, and where to send it. They are used for custom log ingestion via the Logs Ingestion API and Azure Monitor Agent.</p>
<table class="table table-hover table-sm report-table" id="dcrTable">
<thead>
<tr>
    <th>Name</th>
    <th>Location</th>
    <th>Kind</th>
    <th>Data Flows</th>
    <th>Provisioning State</th>
</tr>
</thead>
<tbody>
"@
        foreach ($dcr in $Data.DataCollectionRules) {
            $dcrName = $dcr.name
            $dcrLocation = Get-SafeProperty $dcr 'location'
            $dcrKind = Get-SafeProperty $dcr 'kind'
            if (-not $dcrKind) { $dcrKind = 'Standard' }
            $dcrProps = Get-SafeProperty $dcr 'properties'
            $dataFlows = Get-SafeProperty $dcrProps 'dataFlows'
            $dataFlowCount = if ($dataFlows) { @($dataFlows).Count } else { 0 }

            # Get destination tables from data flows
            $destTables = @()
            if ($dataFlows) {
                foreach ($flow in $dataFlows) {
                    $destinations = Get-SafeProperty $flow 'destinations'
                    $outputStream = Get-SafeProperty $flow 'outputStream'
                    if ($outputStream) {
                        $destTables += $outputStream -replace '^Custom-', '' -replace '^Microsoft-', ''
                    }
                }
            }
            $destTablesDisplay = if ($destTables.Count -gt 0) {
                ($destTables | Select-Object -Unique | Select-Object -First 3) -join ', '
                if ($destTables.Count -gt 3) { " (+$($destTables.Count - 3) more)" }
            } else { '-' }

            $provisioningState = Get-SafeProperty $dcrProps 'provisioningState'
            $provisioningBadge = if ($provisioningState -eq 'Succeeded') {
                '<span class="badge bg-success">Succeeded</span>'
            } elseif ($provisioningState -eq 'Failed') {
                '<span class="badge bg-danger">Failed</span>'
            } else {
                "<span class='badge bg-secondary'>$provisioningState</span>"
            }

            $dceDcrHtml += @"
<tr>
    <td>$([System.Web.HttpUtility]::HtmlEncode($dcrName))</td>
    <td>$dcrLocation</td>
    <td><code>$dcrKind</code></td>
    <td><small>$destTablesDisplay</small></td>
    <td>$provisioningBadge</td>
</tr>
"@
        }
        $dceDcrHtml += "</tbody></table>"
    } else {
        $dceDcrHtml += "<p class='text-muted mt-4'>No Data Collection Rules found in this subscription, or insufficient permissions to read them.</p>"
    }

    # Build Data Collection Health section
    $dataCollectionHealthHtml = ""

    # Helper function to format time ago
    function Format-TimeAgo {
        param([int]$Seconds)
        if ($Seconds -lt 60) { return "$(Format-Plural $Seconds 'second') ago" }
        elseif ($Seconds -lt 3600) { $m = [math]::Floor($Seconds / 60); return "$(Format-Plural $m 'minute') ago" }
        elseif ($Seconds -lt 86400) { $h = [math]::Floor($Seconds / 3600); return "$(Format-Plural $h 'hour') ago" }
        else { $d = [math]::Floor($Seconds / 86400); return "$(Format-Plural $d 'day') ago" }
    }

    # Stale Tables (staleness check) - Events by Table removed as Top 15 Tables by Volume in Ingestion Analysis provides better data
    if ($Data.LastEventByTable -and $Data.LastEventByTable.Count -gt 0) {
        $staleTables = @($Data.LastEventByTable | Where-Object { [int]$_.SecondsSinceLastEvent -gt 86400 })
        if ($staleTables.Count -gt 0) {
            $dataCollectionHealthHtml += @"
<h5 class="mt-4 mb-3">Stale Tables (No Data in 24+ Hours)</h5>
<table class="table table-hover table-sm report-table" id="staleTablesTable">
<thead>
<tr>
    <th>Table Name</th>
    <th>Last Event</th>
    <th>Time Since Last Event</th>
</tr>
</thead>
<tbody>
"@
            foreach ($table in ($staleTables | Sort-Object { [int]$_.SecondsSinceLastEvent } -Descending | Select-Object -First 20)) {
                $lastEvent = if ($table.LastEvent) { ([datetime]$table.LastEvent).ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                $timeAgo = Format-TimeAgo -Seconds ([int]$table.SecondsSinceLastEvent)
                $dataCollectionHealthHtml += "<tr><td><code>$($table._TableName)</code></td><td>$lastEvent</td><td data-order=`"$($table.SecondsSinceLastEvent)`">$timeAgo</td></tr>"
            }
            $dataCollectionHealthHtml += "</tbody></table>"
        }
    }

    # Syslog by Computer
    if ($Data.SyslogByComputer -and $Data.SyslogByComputer.Count -gt 0) {
        $dataCollectionHealthHtml += @"
<h5 class="mt-4 mb-3">Syslog - Last Data by Computer (Oldest First)</h5>
<table class="table table-hover table-sm report-table" id="syslogByComputerTable">
<thead>
<tr>
    <th>Computer</th>
    <th>Events (7d)</th>
    <th>Last Event</th>
    <th>Time Since Last Event</th>
</tr>
</thead>
<tbody>
"@
        foreach ($row in ($Data.SyslogByComputer | Sort-Object { [int]$_.SecondsSinceLastEvent } -Descending)) {
            $lastEvent = if ($row.LastEvent) { ([datetime]$row.LastEvent).ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
            $timeAgo = Format-TimeAgo -Seconds ([int]$row.SecondsSinceLastEvent)
            $events = [long]$row.Events
            $dataCollectionHealthHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($row.Computer))</code></td><td data-order=`"$events`">$($events.ToString('N0'))</td><td>$lastEvent</td><td data-order=`"$($row.SecondsSinceLastEvent)`">$timeAgo</td></tr>"
        }
        $dataCollectionHealthHtml += "</tbody></table>"
    }

    # CEF by Computer/Device
    if ($Data.CefByComputer -and $Data.CefByComputer.Count -gt 0) {
        $dataCollectionHealthHtml += @"
<h5 class="mt-4 mb-3">CEF (CommonSecurityLog) - Last Data by Device (Oldest First)</h5>
<table class="table table-hover table-sm report-table" id="cefByComputerTable">
<thead>
<tr>
    <th>Device Vendor</th>
    <th>Device Product</th>
    <th>Computer</th>
    <th>Events (7d)</th>
    <th>Last Event</th>
    <th>Time Since Last Event</th>
</tr>
</thead>
<tbody>
"@
        foreach ($row in ($Data.CefByComputer | Sort-Object { [int]$_.SecondsSinceLastEvent } -Descending)) {
            $lastEvent = if ($row.LastEvent) { ([datetime]$row.LastEvent).ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
            $timeAgo = Format-TimeAgo -Seconds ([int]$row.SecondsSinceLastEvent)
            $events = [long]$row.Events
            $dataCollectionHealthHtml += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($row.DeviceVendor))</td><td>$([System.Web.HttpUtility]::HtmlEncode($row.DeviceProduct))</td><td><code>$([System.Web.HttpUtility]::HtmlEncode($row.Computer))</code></td><td data-order=`"$events`">$($events.ToString('N0'))</td><td>$lastEvent</td><td data-order=`"$($row.SecondsSinceLastEvent)`">$timeAgo</td></tr>"
        }
        $dataCollectionHealthHtml += "</tbody></table>"
    }

    # SecurityEvent by Computer
    if ($Data.SecurityEventByComputer -and $Data.SecurityEventByComputer.Count -gt 0) {
        $dataCollectionHealthHtml += @"
<h5 class="mt-4 mb-3">SecurityEvent - Last Data by Computer (Oldest First)</h5>
<table class="table table-hover table-sm report-table" id="securityEventByComputerTable">
<thead>
<tr>
    <th>Computer</th>
    <th>Events (7d)</th>
    <th>Last Event</th>
    <th>Time Since Last Event</th>
</tr>
</thead>
<tbody>
"@
        foreach ($row in ($Data.SecurityEventByComputer | Sort-Object { [int]$_.SecondsSinceLastEvent } -Descending)) {
            $lastEvent = if ($row.LastEvent) { ([datetime]$row.LastEvent).ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
            $timeAgo = Format-TimeAgo -Seconds ([int]$row.SecondsSinceLastEvent)
            $events = [long]$row.Events
            $dataCollectionHealthHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($row.Computer))</code></td><td data-order=`"$events`">$($events.ToString('N0'))</td><td>$lastEvent</td><td data-order=`"$($row.SecondsSinceLastEvent)`">$timeAgo</td></tr>"
        }
        $dataCollectionHealthHtml += "</tbody></table>"
    }

    if (-not $dataCollectionHealthHtml) {
        $dataCollectionHealthHtml = "<p class='text-muted'>No data collection health information available. This may be because KQL queries were skipped or the relevant tables have no data.</p>"
    }

    # Build Agent Health section
    $agentHealthHtml = ""
    if ($Data.AgentHealthSummary -and $Data.AgentHealthSummary.Count -gt 0) {
        $healthyCount = @($Data.AgentHealthSummary | Where-Object { $_.State -eq 'Healthy' }).Count
        $unhealthyCount = @($Data.AgentHealthSummary | Where-Object { $_.State -eq 'Unhealthy' }).Count

        $unhealthyCardClass = if ($unhealthyCount -gt 0) { 'danger' } else { 'secondary' }
        $unhealthyTextClass = if ($unhealthyCount -gt 0) { 'text-danger' } else { 'text-muted' }

        $agentHealthHtml = @"
<div class="row mb-3">
    <div class="col-md-6">
        <div class="card border-success">
            <div class="card-body text-center">
                <h3 class="text-success mb-0">$healthyCount</h3>
                <small class="text-muted">Healthy Agents</small>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card border-$unhealthyCardClass">
            <div class="card-body text-center">
                <h3 class="$unhealthyTextClass mb-0">$unhealthyCount</h3>
                <small class="text-muted">Unhealthy Agents</small>
            </div>
        </div>
    </div>
</div>
<table class="table table-hover table-sm report-table" id="agentHealthTable">
<thead>
<tr>
    <th>Computer</th>
    <th>Status</th>
    <th>OS Type</th>
    <th>Environment</th>
    <th>Agent Type</th>
    <th>Last Heartbeat</th>
    <th>Hours Since</th>
</tr>
</thead>
<tbody>
"@
        foreach ($agent in ($Data.AgentHealthSummary | Sort-Object @{Expression={$_.State}; Descending=$true}, @{Expression={[int]$_.HoursSinceHeartbeat}; Descending=$true})) {
            $statusBadge = if ($agent.State -eq 'Healthy') {
                '<span class="badge bg-success">Healthy</span>'
            } else {
                '<span class="badge bg-danger">Unhealthy</span>'
            }
            $lastHb = if ($agent.LastHeartbeat) { ([datetime]$agent.LastHeartbeat).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
            $hours = [int]$agent.HoursSinceHeartbeat
            $agentHealthHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($agent.Computer))</code></td><td>$statusBadge</td><td>$($agent.OSType)</td><td>$($agent.ComputerEnvironment)</td><td>$($agent.SourceSystem)</td><td>$lastHb</td><td data-order=`"$hours`">$(Format-Plural $hours 'hour')</td></tr>"
        }
        $agentHealthHtml += "</tbody></table>"
    }

    # Agent Operation Errors table
    $agentErrorsHtml = ""
    if ($Data.AgentOperationErrors -and $Data.AgentOperationErrors.Count -gt 0) {
        $agentErrorsHtml = @"
<h6 class="mt-4 mb-2">Agent Operation Errors (Last 7 Days)</h6>
<table class="table table-hover table-sm report-table" id="agentErrorsTable">
<thead>
<tr>
    <th>Computer</th>
    <th>Failures</th>
    <th>Errors</th>
    <th>Warnings</th>
</tr>
</thead>
<tbody>
"@
        foreach ($err in ($Data.AgentOperationErrors | Sort-Object { [int]$_.Failures } -Descending)) {
            $failureClass = if ([int]$err.Failures -gt 0) { "class='text-danger fw-bold'" } else { '' }
            $errorClass = if ([int]$err.Errors -gt 0) { "class='text-warning fw-bold'" } else { '' }
            $agentErrorsHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($err.Computer))</code></td><td $failureClass>$($err.Failures)</td><td $errorClass>$($err.Errors)</td><td>$($err.Warnings)</td></tr>"
        }
        $agentErrorsHtml += "</tbody></table>"
    }

    if (-not $agentHealthHtml -and -not $agentErrorsHtml) {
        $agentHealthHtml = "<p class='text-muted'>No agent health data available. This may be because KQL queries were skipped or the Heartbeat table has no data.</p>"
    }

    # Build Content Hub solutions table
    $contentHubHtml = @"
<table class="table table-hover report-table" id="contentHubTable">
<thead>
<tr>
    <th>Solution Name</th>
    <th>Version</th>
    <th>Content Kind</th>
</tr>
</thead>
<tbody>
"@

    foreach ($package in $Data.ContentPackages) {
        $pkgProps = Get-SafeProperty $package 'properties'
        $displayName = Get-SafeProperty $pkgProps 'displayName'
        $version = Get-SafeProperty $pkgProps 'version'
        $contentKind = Get-SafeProperty $pkgProps 'contentKind'

        $contentHubHtml += @"
<tr>
    <td>$([System.Web.HttpUtility]::HtmlEncode($displayName))</td>
    <td>$version</td>
    <td>$contentKind</td>
</tr>
"@
    }
    $contentHubHtml += "</tbody></table>"

    # Build Workbooks section
    $workbooksHtml = ""
    if ($Data.Workbooks -and $Data.Workbooks.Count -gt 0) {
        # Build lookup of workbook templates from ContentTemplates to detect updates
        $workbookTemplateVersions = @{}
        foreach ($template in $Data.ContentTemplates) {
            $contentKind = Get-SafeProperty $template.properties 'contentKind'
            if ($contentKind -eq 'Workbook') {
                $templateId = Get-SafeProperty $template.properties 'contentId'
                $templateVersion = Get-SafeProperty $template.properties 'version'
                $templateDisplayName = Get-SafeProperty $template.properties 'displayName'
                if ($templateId -and $templateVersion) {
                    $workbookTemplateVersions[$templateId] = @{
                        Version = $templateVersion
                        DisplayName = $templateDisplayName
                    }
                }
            }
        }

        $workbooksHtml = @"
<table class="table table-hover table-sm report-table" id="workbooksTable">
<thead>
<tr>
    <th>Workbook Name</th>
    <th>Version</th>
    <th>Source</th>
    <th>Status</th>
</tr>
</thead>
<tbody>
"@
        foreach ($workbook in $Data.Workbooks) {
            $wbProps = Get-SafeProperty $workbook 'properties'
            $displayName = Get-SafeProperty $wbProps 'displayName'
            if (-not $displayName) { $displayName = $workbook.name }
            $version = Get-SafeProperty $wbProps 'version'
            $sourceId = Get-SafeProperty $wbProps 'sourceId'

            # Determine source type
            $sourceType = if ($sourceId -match 'Microsoft.OperationalInsights/workspaces') {
                'Sentinel Workspace'
            } elseif ($sourceId -match 'Microsoft.SecurityInsights') {
                'Content Hub'
            } else {
                'Custom'
            }

            # Check for updates by matching against template
            $statusBadge = '<span class="badge bg-success">Up to date</span>'
            $templateId = Get-SafeProperty $wbProps 'templateId'
            if (-not $templateId) {
                # Try to match by name
                $templateId = Get-SafeProperty $wbProps 'contentId'
            }

            if ($templateId -and $workbookTemplateVersions.ContainsKey($templateId)) {
                $templateInfo = $workbookTemplateVersions[$templateId]
                $templateVersion = $templateInfo.Version
                if ($version -and $templateVersion) {
                    try {
                        $currentVer = [version]$version
                        $templateVer = [version]$templateVersion
                        if ($templateVer -gt $currentVer) {
                            $statusBadge = "<span class='badge bg-warning text-dark' title='Template version: $templateVersion'>Update Available</span>"
                        }
                    }
                    catch {
                        # Version comparison failed
                    }
                }
            } elseif (-not $templateId) {
                $statusBadge = '<span class="badge bg-secondary">Custom</span>'
            }

            $workbooksHtml += @"
<tr>
    <td>$([System.Web.HttpUtility]::HtmlEncode($displayName))</td>
    <td>$(if ($version) { $version } else { '-' })</td>
    <td>$sourceType</td>
    <td>$statusBadge</td>
</tr>
"@
        }
        $workbooksHtml += "</tbody></table>"
    } else {
        $workbooksHtml = "<p class='text-muted'>No workbooks found in this resource group.</p>"
    }

    # Build Repository Connections section
    $repositoryHtml = ""
    if ($Data.SourceControls -and $Data.SourceControls.Count -gt 0) {
        $repositoryHtml = @"
<table class="table table-hover table-sm report-table" id="repositoryTable">
<thead>
<tr>
    <th>Name</th>
    <th>Type</th>
    <th>Repository</th>
    <th>Branch</th>
    <th>Content Types</th>
    <th>Last Deployment</th>
    <th>Status</th>
</tr>
</thead>
<tbody>
"@
        foreach ($sc in $Data.SourceControls) {
            $scProps = Get-SafeProperty $sc 'properties'
            $displayName = Get-SafeProperty $scProps 'displayName'
            $repoType = Get-SafeProperty $scProps 'repoType'
            $repository = Get-SafeProperty $scProps 'repository'
            $repoUrl = Get-SafeProperty $repository 'url'
            $repoBranch = Get-SafeProperty $repository 'branch'
            $repoDisplayUrl = Get-SafeProperty $repository 'displayUrl'
            if (-not $repoDisplayUrl) { $repoDisplayUrl = $repoUrl }
            $contentTypes = Get-SafeProperty $scProps 'contentTypes'
            $contentTypesStr = if ($contentTypes) { ($contentTypes -join ', ') } else { 'N/A' }

            $lastDeployInfo = Get-SafeProperty $scProps 'lastDeploymentInfo'
            $deployment = Get-SafeProperty $lastDeployInfo 'deployment'
            $deployTime = Get-SafeProperty $deployment 'deploymentTime'
            $deployResult = Get-SafeProperty $deployment 'deploymentResult'

            $deployTimeStr = if ($deployTime) {
                try { ([datetime]$deployTime).ToString('yyyy-MM-dd HH:mm') } catch { 'Unknown' }
            } else { 'Never' }

            $statusBadge = switch ($deployResult) {
                'Success'  { '<span class="badge bg-success">Success</span>' }
                'Failed'   { '<span class="badge bg-danger">Failed</span>' }
                'Canceled' { '<span class="badge bg-warning text-dark">Canceled</span>' }
                default    { '<span class="badge bg-secondary">Unknown</span>' }
            }

            $typeIcon = if ($repoType -eq 'Github') { 'github' } else { 'git-branch' }

            $repositoryHtml += @"
<tr>
    <td>$([System.Web.HttpUtility]::HtmlEncode($displayName))</td>
    <td><i data-lucide="$typeIcon" style="width:14px;height:14px"></i> $repoType</td>
    <td><a href="$repoUrl" target="_blank">$([System.Web.HttpUtility]::HtmlEncode($repoDisplayUrl))</a></td>
    <td><code>$repoBranch</code></td>
    <td><small>$contentTypesStr</small></td>
    <td>$deployTimeStr</td>
    <td>$statusBadge</td>
</tr>
"@
        }
        $repositoryHtml += "</tbody></table>"
    } else {
        $repositoryHtml = "<p class='text-muted'>No repository connections configured. Repository connections enable CI/CD deployments from GitHub or Azure DevOps.</p>"
    }

    # Build Workspace Manager section
    $workspaceManagerHtml = ""
    $wmConfig = $Data.WorkspaceManagerConfig
    $wmMembers = $Data.WorkspaceManagerMembers
    $wmMode = if ($wmConfig) { Get-SafeProperty (Get-SafeProperty $wmConfig 'properties') 'mode' } else { $null }

    if ($wmMode -eq 'Enabled') {
        $memberCount = if ($wmMembers) { @($wmMembers).Count } else { 0 }
        $workspaceManagerHtml = @"
<div class="alert alert-info mb-3">
    <i data-lucide="network" class="me-2" style="width:18px;height:18px"></i>
    <strong>Central Workspace</strong> - This workspace is configured as a Workspace Manager
    <span class="badge bg-primary ms-2">$(Format-Plural $memberCount 'member workspace')</span>
</div>
"@
        if ($wmMembers -and $memberCount -gt 0) {
            $workspaceManagerHtml += @"
<table class="table table-hover table-sm report-table" id="workspaceManagerTable">
<thead>
<tr>
    <th>Member Workspace</th>
    <th>Tenant</th>
</tr>
</thead>
<tbody>
"@
            foreach ($member in $wmMembers) {
                $memberProps = Get-SafeProperty $member 'properties'
                $targetWorkspace = Get-SafeProperty $memberProps 'targetWorkspaceResourceId'
                $targetTenant = Get-SafeProperty $memberProps 'targetWorkspaceTenantId'
                # Extract workspace name from resource ID
                $wsName = if ($targetWorkspace -match '/workspaces/([^/]+)$') { $matches[1] } else { $targetWorkspace }
                $workspaceManagerHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($wsName))</code></td><td><small>$targetTenant</small></td></tr>"
            }
            $workspaceManagerHtml += "</tbody></table>"
        } else {
            $workspaceManagerHtml += "<p class='text-muted'>No member workspaces have been added yet.</p>"
        }
    } else {
        $workspaceManagerHtml = "<p class='text-muted'>Workspace Manager is not enabled. Enable it to centrally manage multiple Sentinel workspaces.</p>"
    }

    # Build MITRE section
    $mitreHtml = ""
    if ($Data.MitreCoverage) {
        $mc = $Data.MitreCoverage

        # Build top 10 techniques data for bar chart
        $top10Techniques = $mc.TechniqueRuleMapping.GetEnumerator() |
            Sort-Object { $_.Value.Count } -Descending |
            Select-Object -First 10

        $top10Labels = @()
        $top10Data = @()
        foreach ($tech in $top10Techniques) {
            $techId = $tech.Key
            $ruleCount = $tech.Value.Count
            # Try to get technique name from MitreData if available
            $techName = if ($Data.MitreData -and $Data.MitreData[$techId]) {
                $Data.MitreData[$techId].Name
            } else {
                $techId
            }
            $cleanName = $techName -replace "[']", ""
            $top10Labels += "`"${techId}: $cleanName`""
            $top10Data += $ruleCount
        }
        $top10LabelsJs = $top10Labels -join ', '
        $top10DataJs = $top10Data -join ', '

        $mitreHtml = @"
<div class="alert alert-info d-flex align-items-start mb-4" role="alert">
    <i data-lucide="info" class="me-2 flex-shrink-0 mt-1" style="width: 18px; height: 18px;"></i>
    <div>
        <strong>Coverage Methodology:</strong> MITRE ATT&CK coverage is calculated from
        <strong>$($mc.ActiveRuleCount) active $(if ($mc.ActiveRuleCount -eq 1) { 'rule' } else { 'rules' })</strong>
        (enabled and configured to create incidents) out of $($mc.TotalRuleCount) total analytics rules.
        Disabled rules and rules not creating incidents are excluded to reflect actual detection capability.
    </div>
</div>
<div class="row mb-4">
    <div class="col-md-6">
        <div class="card border-0 shadow-sm h-100">
            <div class="card-body">
                <h5 class="card-title">Top 10 Techniques by Rule Count</h5>
                <div style="height: 300px;">
                    <canvas id="top10TechniquesChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card border-0 shadow-sm h-100">
            <div class="card-body">
                <h5 class="card-title">Active Rules by Tactic</h5>
                <div style="height: 300px;">
                    <canvas id="tacticRadarChart"></canvas>
                </div>
            </div>
        </div>
    </div>
</div>
"@

        # Add SVG visualization card if available (before the uncovered techniques accordion)
        if ($Data.ContainsKey('NavigatorSvgContent') -and $Data['NavigatorSvgContent']) {
            $mitreHtml += @"
<div class="row mb-4 mt-4">
    <div class="col-12">
        <div class="card border-0 shadow-sm">
            <div class="card-body">
                <h5 class="card-title">MITRE ATT&CK Coverage Matrix</h5>
                <div class="mitre-svg-container" data-bs-toggle="modal" data-bs-target="#mitreSvgModal" title="Click to enlarge">
                    $($Data.NavigatorSvgContent)
                </div>
                <p class="text-muted small mt-3 mb-0">
                    <i data-lucide="info" style="width:14px;height:14px" class="me-1"></i>
                    <strong>Note:</strong> The gradient scale shows coverage depth. Per ATT&CK Navigator Layer Controls,
                    anything more than 20 rules covering a technique should be considered "High value" coverage
                    (shown in the darkest green on the scale).
                </p>
            </div>
        </div>
    </div>
</div>

<!-- MITRE SVG Modal with Zoom/Pan -->
<div class="modal fade mitre-modal" id="mitreSvgModal" tabindex="-1" aria-labelledby="mitreSvgModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="mitreSvgModalLabel"><i data-lucide="target" style="width:18px;height:18px" class="me-2"></i>MITRE ATT&CK Coverage Matrix</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div class="mitre-svg-viewer" id="mitreSvgViewer">
                    $($Data.NavigatorSvgContent)
                </div>
            </div>
            <div class="modal-footer justify-content-between">
                <div class="zoom-controls">
                    <button type="button" class="btn btn-outline-secondary btn-sm" id="zoomOut" title="Zoom Out"><i data-lucide="zoom-out" style="width:16px;height:16px"></i></button>
                    <span class="zoom-level" id="zoomLevel">100%</span>
                    <button type="button" class="btn btn-outline-secondary btn-sm" id="zoomIn" title="Zoom In"><i data-lucide="zoom-in" style="width:16px;height:16px"></i></button>
                    <button type="button" class="btn btn-outline-secondary btn-sm ms-2" id="zoomReset" title="Reset View"><i data-lucide="maximize" style="width:16px;height:16px"></i></button>
                </div>
                <div class="text-muted small">Scroll to zoom &bull; Drag to pan</div>
            </div>
        </div>
    </div>
</div>
"@
        }

        # Add Coverage Statistics section (full width, below matrix)
        $mitreHtml += @"
<div class="row mb-4">
    <div class="col-12">
        <div class="card border-0 shadow-sm">
            <div class="card-body">
                <h5 class="card-title mb-4">Coverage Statistics</h5>
                <div class="row">
                    <div class="col-md-3 text-center border-end">
                        <h3 class="mb-0 text-primary">$($mc.ParentCoveragePercent)%</h3>
                        <small class="text-muted">Parent Techniques</small>
                        <p class="mb-0"><small class="text-muted">$($mc.CoveredParentCount) / $($mc.TotalParentCount) covered</small></p>
                    </div>
                    <div class="col-md-3 text-center border-end">
                        <h3 class="mb-0 text-info">$($mc.SubCoveragePercent)%</h3>
                        <small class="text-muted">Sub-Techniques</small>
                        <p class="mb-0"><small class="text-muted">$($mc.CoveredSubCount) / $($mc.TotalSubCount) covered</small></p>
                    </div>
                    <div class="col-md-3 text-center border-end">
                        <h3 class="mb-0 text-success">$($mc.TechniqueRuleMapping.Count)</h3>
                        <small class="text-muted">Unique Techniques</small>
                        <p class="mb-0"><small class="text-muted">with detection rules</small></p>
                    </div>
                    <div class="col-md-3 text-center d-flex flex-column align-items-center justify-content-center">
                        <div class="d-flex gap-2 justify-content-center">
                            <button id="downloadNavigator" class="btn btn-outline-primary btn-sm">
                                <i data-lucide="download" style="width:14px;height:14px" class="me-1"></i> Download JSON
                            </button>
                            $(if ($Data.ContainsKey('NavigatorSvgContent') -and $Data['NavigatorSvgContent']) { '<button id="downloadSvg" class="btn btn-outline-success btn-sm"><i data-lucide="image" style="width:14px;height:14px" class="me-1"></i> Download SVG</button>' })
                        </div>
                        <p class="text-muted small mt-2 mb-0">Import JSON into <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank">ATT&CK Navigator</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"@

        # Build uncovered techniques accordion
        $mitreHtml += '<div class="accordion" id="uncoveredAccordion">'
        $accordionIndex = 0

        foreach ($tactic in $mc.TacticOrder) {
            $tacticData = $mc.TacticCoverage[$tactic]
            if ($tacticData.Uncovered.Count -eq 0) { continue }

            $tacticWithSpaces = ($tactic -replace '-', ' ')
            $tacticDisplay = (Get-Culture).TextInfo.ToTitleCase($tacticWithSpaces)
            $coveragePercent = if ($tacticData.Total -gt 0) { [math]::Round(($tacticData.Covered / $tacticData.Total) * 100) } else { 0 }

            $mitreHtml += @"
<div class="accordion-item">
    <h2 class="accordion-header">
        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse$accordionIndex">
            <span class="badge bg-secondary me-2">$($tacticData.Uncovered.Count)</span>
            $tacticDisplay <span class="text-muted ms-2">($coveragePercent% covered)</span>
        </button>
    </h2>
    <div id="collapse$accordionIndex" class="accordion-collapse collapse" data-bs-parent="#uncoveredAccordion">
        <div class="accordion-body">
            <ul class="list-unstyled mb-0">
"@
            foreach ($tech in ($tacticData.Uncovered | Sort-Object { $_.ID })) {
                $mitreHtml += "<li><code>$($tech.ID)</code> - $([System.Web.HttpUtility]::HtmlEncode($tech.Name))</li>"
            }
            $mitreHtml += "</ul></div></div></div>"
            $accordionIndex++
        }
        $mitreHtml += '</div>'

        # Radar chart data - rule counts per tactic (active rules only)
        $radarLabels = ($mc.TacticOrder | ForEach-Object {
            $tacticWithSpaces = ($_ -replace '-', ' ')
            $display = (Get-Culture).TextInfo.ToTitleCase($tacticWithSpaces)
            "'$display'"
        }) -join ', '
        $radarData = ($mc.TacticOrder | ForEach-Object {
            $tacticData = $mc.TacticCoverage[$_]
            $tacticData.RuleCount
        }) -join ', '
        $radarMaxValue = ($mc.TacticOrder | ForEach-Object { $mc.TacticCoverage[$_].RuleCount } | Measure-Object -Maximum).Maximum
        # Round up to nearest 10 for cleaner axis, minimum of 10
        $radarMaxValue = [math]::Max(10, [math]::Ceiling($radarMaxValue / 10) * 10)
    }

    # Build ingestion section
    $ingestionHtml = ""

    # Events by Table over Time (7 days) - Full width stacked area chart
    $eventsByTableChartHtml = ""
    if ($Data.EventsByTableTimeSeries -and $Data.EventsByTableTimeSeries.Count -gt 0) {
        # Get unique timestamps and table categories
        $timestamps = $Data.EventsByTableTimeSeries | Select-Object -ExpandProperty TimeGenerated -Unique | Sort-Object
        $categories = $Data.EventsByTableTimeSeries | Select-Object -ExpandProperty TableCategory -Unique | Sort-Object

        # Ensure "Other" is last in the list
        $sortedCategories = @($categories | Where-Object { $_ -ne "Other" }) + @($categories | Where-Object { $_ -eq "Other" })

        # Build labels (timestamps) - daily format since we use 1d buckets
        $chartLabels = ($timestamps | ForEach-Object { "'$(([datetime]$_).ToString('MM/dd'))'" }) -join ', '

        # Define color palette for 10 categories (9 tables + Other)
        $colorPalette = @(
            "rgba(54, 162, 235, 0.7)",   # Blue
            "rgba(255, 99, 132, 0.7)",   # Red
            "rgba(75, 192, 192, 0.7)",   # Teal
            "rgba(255, 206, 86, 0.7)",   # Yellow
            "rgba(153, 102, 255, 0.7)",  # Purple
            "rgba(255, 159, 64, 0.7)",   # Orange
            "rgba(46, 204, 113, 0.7)",   # Green
            "rgba(52, 73, 94, 0.7)",     # Dark Gray
            "rgba(241, 196, 15, 0.7)",   # Gold
            "rgba(149, 165, 166, 0.7)"   # Light Gray (Other)
        )

        # Build datasets for each category
        $datasets = @()
        $colorIndex = 0
        foreach ($category in $sortedCategories) {
            $dataPoints = @()
            foreach ($ts in $timestamps) {
                $record = $Data.EventsByTableTimeSeries | Where-Object { $_.TimeGenerated -eq $ts -and $_.TableCategory -eq $category }
                $value = if ($record) { [math]::Round($record.EventCount, 0) } else { 0 }
                $dataPoints += $value
            }
            $dataStr = $dataPoints -join ', '
            $color = $colorPalette[$colorIndex % $colorPalette.Count]
            $borderColor = $color -replace '0\.7\)', '1)'

            $datasets += @"
        {
          label: '$category',
          data: [$dataStr],
          backgroundColor: '$color',
          borderColor: '$borderColor',
          borderWidth: 1,
          fill: true
        }
"@
            $colorIndex++
        }
        $datasetsJs = $datasets -join ",`n"

        $eventsByTableChartHtml = @"
<div class="row mb-4">
    <div class="col-12">
        <div class="card border-0 shadow-sm">
            <div class="card-body">
                <h5 class="card-title">Events by Table (Last 7 Days)</h5>
                <canvas id="eventsByTableChart" height="100"></canvas>
            </div>
        </div>
    </div>
</div>
"@
    }

    # Billable breakdown section
    $billableHtml = ""
    if ($Data.BillableBreakdown -and $Data.BillableBreakdown.Count -gt 0) {
        $billableTotal = ($Data.BillableBreakdown | Measure-Object -Property TotalGB -Sum).Sum
        $billableData = $Data.BillableBreakdown | Where-Object { $_.Type -eq 'Billable' }
        $freeData = $Data.BillableBreakdown | Where-Object { $_.Type -eq 'Free' }
        $billableGB = if ($billableData) { [math]::Round($billableData.TotalGB, 2) } else { 0 }
        $freeGB = if ($freeData) { [math]::Round($freeData.TotalGB, 2) } else { 0 }
        $billablePercent = if ($billableTotal -gt 0) { [math]::Round(($billableGB / $billableTotal) * 100, 1) } else { 0 }
        $freePercent = if ($billableTotal -gt 0) { [math]::Round(($freeGB / $billableTotal) * 100, 1) } else { 0 }

        $billableHtml = @"
<div class="col-md-4">
    <div class="card border-0 shadow-sm h-100">
        <div class="card-body">
            <h5 class="card-title">Billable vs Free (30d)</h5>
            <div class="d-flex justify-content-between mb-2">
                <span class="badge bg-primary">Billable</span>
                <strong>$billableGB GB ($billablePercent%)</strong>
            </div>
            <div class="progress mb-3" style="height: 10px;">
                <div class="progress-bar bg-primary" style="width: $billablePercent%"></div>
            </div>
            <div class="d-flex justify-content-between mb-2">
                <span class="badge bg-success">Free</span>
                <strong>$freeGB GB ($freePercent%)</strong>
            </div>
            <div class="progress" style="height: 10px;">
                <div class="progress-bar bg-success" style="width: $freePercent%"></div>
            </div>
            <canvas id="billableChart" height="150" class="mt-3"></canvas>
        </div>
    </div>
</div>
"@
    }

    # Start with 30-day ingestion trend
    $ingestionHtml = ""

    if ($Data.IngestionTrend -and $Data.IngestionTrend.Count -gt 0) {
        $trendLabels = ($Data.IngestionTrend | ForEach-Object { "'$(([datetime]$_.TimeGenerated).ToString('MM/dd'))'" }) -join ', '
        $trendData = ($Data.IngestionTrend | ForEach-Object { [math]::Round($_.TotalGB, 2) }) -join ', '

        # Get daily cap for chart annotation
        $chartDailyCap = Get-SafeProperty (Get-SafeProperty (Get-SafeProperty $Data.WorkspaceConfig 'properties') 'workspaceCapping') 'dailyQuotaGb'
        $capLineNote = if ($chartDailyCap -and $chartDailyCap -gt 0) { " <span class='badge bg-warning text-dark'>Daily Cap: $chartDailyCap GB</span>" } else { "" }

        $ingestionHtml = @"
<div class="row mb-4">
    <div class="$(if ($billableHtml) { 'col-md-8' } else { 'col-12' })">
        <div class="card border-0 shadow-sm h-100">
            <div class="card-body">
                <h5 class="card-title">30-Day Ingestion Trend$capLineNote</h5>
                <canvas id="ingestionChart" height="$(if ($billableHtml) { '150' } else { '100' })"></canvas>
            </div>
        </div>
    </div>
    $billableHtml
</div>
"@
    }
    elseif ($billableHtml) {
        $ingestionHtml = @"
<div class="row mb-4">
    $billableHtml
</div>
"@
    }

    # Add events by table chart after ingestion trend
    $ingestionHtml += $eventsByTableChartHtml

    if ($Data.TopTables -and $Data.TopTables.Count -gt 0) {
        $totalIngestion = ($Data.TopTables | Measure-Object -Property TotalGB -Sum).Sum

        $ingestionHtml += @"
<h5 class="mt-4 mb-3">Top 15 Tables by Volume (Last 30 Days)</h5>
<table class="table table-hover report-table" id="topTablesTable">
<thead>
<tr>
    <th>Table Name</th>
    <th>Volume (GB)</th>
    <th>% of Total</th>
</tr>
</thead>
<tbody>
"@
        foreach ($table in ($Data.TopTables | Sort-Object { [double]$_.TotalGB } -Descending | Select-Object -First 15)) {
            $volumeGb = [math]::Round([double]$table.TotalGB, 2)
            $percent = if ($totalIngestion -gt 0) { [math]::Round(($table.TotalGB / $totalIngestion) * 100, 1) } else { 0 }
            $ingestionHtml += @"
<tr>
    <td><code>$($table.DataType)</code></td>
    <td data-order="$volumeGb">$volumeGb</td>
    <td data-order="$percent">
        <div class="progress" style="height: 20px;">
            <div class="progress-bar" style="width: $percent%">$percent%</div>
        </div>
    </td>
</tr>
"@
        }
        $ingestionHtml += "</tbody></table>"
    }

    # Build Data Retention section
    $retentionHtml = ""
    $wsRetention = Get-SafeProperty (Get-SafeProperty $Data.WorkspaceConfig 'properties') 'retentionInDays'

    # Get retention-related health check details
    $tablesBelowDefaultCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'RET-002' }
    $archiveTablesCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'RET-003' }
    $basicLogsTablesCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'RET-004' }
    $tablesAboveDefaultCheck = $Data.HealthChecks | Where-Object { $_.CheckId -eq 'RET-005' }

    # Count tables with non-default retention
    $belowCount = @($tablesBelowDefaultCheck.Details | Where-Object { $_ }).Count
    $aboveCount = @($tablesAboveDefaultCheck.Details | Where-Object { $_ }).Count
    $archiveCount = @($archiveTablesCheck.Details | Where-Object { $_ }).Count
    $basicCount = @($basicLogsTablesCheck.Details | Where-Object { $_ }).Count

    $retentionHtml = @"
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card border-0 shadow-sm h-100">
            <div class="card-body text-center">
                <h3 class="mb-0 text-primary">$wsRetention</h3>
                <small class="text-muted">Workspace Default (Days)</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-0 shadow-sm h-100 $(if ($belowCount -gt 0) { 'border-warning border-2' })">
            <div class="card-body text-center">
                <h3 class="mb-0 $(if ($belowCount -gt 0) { 'text-warning' } else { 'text-success' })">$belowCount</h3>
                <small class="text-muted">Tables Below Default</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-0 shadow-sm h-100">
            <div class="card-body text-center">
                <h3 class="mb-0 text-info">$aboveCount</h3>
                <small class="text-muted">Tables Above Default</small>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card border-0 shadow-sm h-100">
            <div class="card-body text-center">
                <h3 class="mb-0 text-secondary">$archiveCount</h3>
                <small class="text-muted">Using Archive Tier</small>
            </div>
        </div>
    </div>
</div>
"@

    # Tables with non-default retention
    if ($Data.Tables -and $Data.Tables.Count -gt 0) {
        # Tables BELOW workspace default (warning - potential data loss)
        $tablesBelowDefault = @($Data.Tables | Where-Object {
            $tableRet = Get-SafeProperty $_.properties 'retentionInDays'
            $tableRet -and $tableRet -lt $wsRetention
        })

        if ($tablesBelowDefault.Count -gt 0) {
            $retentionHtml += @"
<h5 class="mt-4 mb-3"><span class="badge bg-warning text-dark me-2">$($tablesBelowDefault.Count)</span> Tables Below Workspace Default ($wsRetention days)</h5>
<p class="text-muted small">These tables have shorter retention than the workspace default. Data may be deleted sooner than expected.</p>
<table class="table table-hover table-sm report-table" id="tablesBelowDefaultTable">
<thead><tr><th>Table Name</th><th>Interactive Retention</th><th>Difference</th><th>Plan</th></tr></thead>
<tbody>
"@
            foreach ($table in ($tablesBelowDefault | Sort-Object { Get-SafeProperty $_.properties 'retentionInDays' })) {
                $tableName = $table.name
                $tableRet = Get-SafeProperty $table.properties 'retentionInDays'
                $plan = Get-SafeProperty $table.properties 'plan'
                $diff = $wsRetention - $tableRet

                $planBadge = if ($plan -eq 'Basic') { '<span class="badge bg-info">Basic</span>' } elseif ($plan -eq 'Analytics') { '<span class="badge bg-primary">Analytics</span>' } else { $plan }

                $retentionHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($tableName))</code></td><td><span class='badge bg-warning text-dark'>$tableRet days</span></td><td class='text-danger'>-$diff days</td><td>$planBadge</td></tr>"
            }
            $retentionHtml += "</tbody></table>"
        }

        # Tables ABOVE workspace default
        $tablesAboveDefault = @($Data.Tables | Where-Object {
            $tableRet = Get-SafeProperty $_.properties 'retentionInDays'
            $tableRet -and $tableRet -gt $wsRetention
        })

        if ($tablesAboveDefault.Count -gt 0) {
            $retentionHtml += @"
<h5 class="mt-4 mb-3"><span class="badge bg-info me-2">$($tablesAboveDefault.Count)</span> Tables Above Workspace Default ($wsRetention days)</h5>
<p class="text-muted small">These tables have longer interactive retention than the workspace default.</p>
<table class="table table-hover table-sm report-table" id="tablesAboveDefaultTable">
<thead><tr><th>Table Name</th><th>Interactive Retention</th><th>Difference</th><th>Total Retention</th></tr></thead>
<tbody>
"@
            foreach ($table in ($tablesAboveDefault | Sort-Object { Get-SafeProperty $_.properties 'retentionInDays' } -Descending)) {
                $tableName = $table.name
                $tableRet = Get-SafeProperty $table.properties 'retentionInDays'
                $totalRet = Get-SafeProperty $table.properties 'totalRetentionInDays'
                $diff = $tableRet - $wsRetention

                $archiveBadge = if ($totalRet -and $totalRet -gt $tableRet) { "$totalRet days <span class='badge bg-secondary'>Archive</span>" } elseif ($totalRet) { "$totalRet days" } else { '-' }

                $retentionHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($tableName))</code></td><td><span class='badge bg-info'>$tableRet days</span></td><td class='text-success'>+$diff days</td><td>$archiveBadge</td></tr>"
            }
            $retentionHtml += "</tbody></table>"
        }

        # Tables with Archive tier (showing archive details)
        $tablesWithArchive = @($Data.Tables | Where-Object {
            $tableRet = Get-SafeProperty $_.properties 'retentionInDays'
            $totalRet = Get-SafeProperty $_.properties 'totalRetentionInDays'
            $totalRet -and $tableRet -and $totalRet -gt $tableRet
        })

        if ($tablesWithArchive.Count -gt 0) {
            $retentionHtml += @"
<h5 class="mt-4 mb-3"><span class="badge bg-secondary me-2">$($tablesWithArchive.Count)</span> Tables Using Archive Tier</h5>
<p class="text-muted small">These tables have data archived beyond interactive retention for long-term storage.</p>
<table class="table table-hover table-sm report-table" id="tablesArchiveTable">
<thead><tr><th>Table Name</th><th>Interactive Retention</th><th>Total Retention</th><th>Archive Period</th></tr></thead>
<tbody>
"@
            foreach ($table in ($tablesWithArchive | Sort-Object { Get-SafeProperty $_.properties 'totalRetentionInDays' } -Descending)) {
                $tableName = $table.name
                $tableRet = Get-SafeProperty $table.properties 'retentionInDays'
                $totalRet = Get-SafeProperty $table.properties 'totalRetentionInDays'
                $archivePeriod = $totalRet - $tableRet

                $retentionHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($tableName))</code></td><td>$tableRet days</td><td>$totalRet days</td><td><span class='badge bg-secondary'>$archivePeriod days</span></td></tr>"
            }
            $retentionHtml += "</tbody></table>"
        }

        # Basic Logs tables
        $basicLogsTables = @($Data.Tables | Where-Object {
            (Get-SafeProperty $_.properties 'plan') -eq 'Basic'
        })

        if ($basicLogsTables.Count -gt 0) {
            $retentionHtml += @"
<h5 class="mt-4 mb-3"><span class="badge bg-primary me-2">$($basicLogsTables.Count)</span> Basic Logs Tables</h5>
<p class="text-muted small">Tables configured as Basic logs have reduced query capabilities but lower ingestion costs.</p>
<table class="table table-hover table-sm report-table" id="basicLogsTable">
<thead><tr><th>Table Name</th><th>Interactive Retention</th><th>Total Retention</th></tr></thead>
<tbody>
"@
            foreach ($table in ($basicLogsTables | Sort-Object { $_.name })) {
                $tableName = $table.name
                $tableRet = Get-SafeProperty $table.properties 'retentionInDays'
                $totalRet = Get-SafeProperty $table.properties 'totalRetentionInDays'

                $retentionHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($tableName))</code></td><td>$tableRet days</td><td>$(if ($totalRet) { "$totalRet days" } else { '-' })</td></tr>"
            }
            $retentionHtml += "</tbody></table>"
        }
    }

    # Build TOC
    $tocHtml = @"
<li><a class='nav-link py-1' href='#health-checks'>Health Checks</a></li>
<li><a class='nav-link py-1' href='#analytics-rules'>Analytics Rules</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#visibility-gaps'>Visibility Gaps</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#rules-updates'>Pending Updates</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#disabled-rules'>Disabled Rules</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#custom-rules'>Custom Rules</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#incident-volume'>Incident Volume</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#analytics-health'>Analytics Health</a></li>
<li><a class='nav-link py-1' href='#data-collection'>Data Collection</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#data-connectors'>Data Connectors</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#dce-dcr'>DCEs & DCRs</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#ingestion-analysis'>Ingestion Analysis</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#data-collection-health'>Collection Health</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#agent-health'>Agent Health</a></li>
<li><a class='nav-link py-1' href='#content-management'>Content Management</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#content-hub'>Content Hub</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#workbooks'>Workbooks</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#repository-connections'>Repository Connections</a></li>
<li class='ms-3'><a class='nav-link py-1 small' href='#workspace-manager'>Workspace Manager</a></li>
<li><a class='nav-link py-1' href='#mitre-coverage'>MITRE Coverage</a></li>
<li><a class='nav-link py-1' href='#data-retention'>Data Retention</a></li>
"@

    # Master HTML template
    $html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$ClientName - Sentinel Assessment</title>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">

  <style>
    body { font-family: 'Inter', sans-serif; background-color: #f8fafc; color: #1e293b; scroll-behavior: smooth; }
    .top-bar { background: #0f172a; border-bottom: 4px solid #3b82f6; }
    .card { border-radius: 12px; border: none; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .toc-container { position: sticky; top: 2rem; }
    .toc-container a { color: #64748b; font-size: 0.9rem; border-left: 2px solid #e2e8f0; padding-left: 15px; text-decoration: none; transition: 0.2s; }
    .toc-container a:hover { color: #3b82f6; border-left-color: #3b82f6; }
    .table-controls { display: flex; justify-content: flex-end; align-items: center; gap: 12px; margin-bottom: 1.5rem; }
    .dataTables_filter { margin: 0 !important; }
    .dataTables_filter label { margin: 0; font-weight: 600; font-size: 0.85rem; color: #64748b; display: flex; align-items: center; gap: 8px; }
    .dataTables_filter input { border-radius: 6px; border: 1px solid #e2e8f0; padding: 0.4rem 0.75rem; font-size: 0.85rem; width: 220px; }
    .dt-buttons.btn-group { margin: 0 !important; }
    .dt-buttons .btn { border-radius: 6px !important; font-size: 0.8rem; font-weight: 600; border: 1px solid #e2e8f0; background: white; color: #475569; padding: 0.45rem 1rem; }
    .dt-buttons .btn:hover { background: #f8fafc; color: #2563eb; border-color: #3b82f6; }
    table.dataTable thead th { background-color: #f8fafc; font-size: 0.75rem; text-transform: uppercase; color: #64748b; padding: 12px; border-bottom: 2px solid #e2e8f0; }
    h2 { margin-top: 2.5rem; font-weight: 700; color: #334155; scroll-margin-top: 30px; }
    h5[id] { scroll-margin-top: 30px; }
    .section-card { margin-bottom: 2rem; }
    /* MITRE Navigator SVG container */
    .mitre-svg-container { overflow-x: auto; max-width: 100%; background: #f8f9fa; border-radius: 8px; padding: 1rem; cursor: pointer; position: relative; transition: box-shadow 0.2s; }
    .mitre-svg-container:hover { box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.3); }
    .mitre-svg-container::after { content: 'Click to enlarge'; position: absolute; bottom: 0.5rem; right: 0.5rem; background: rgba(0,0,0,0.7); color: white; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; opacity: 0; transition: opacity 0.2s; pointer-events: none; }
    .mitre-svg-container:hover::after { opacity: 1; }
    .mitre-svg-container svg { max-width: 100%; height: auto; display: block; }
    /* MITRE SVG Modal */
    .mitre-modal .modal-dialog { max-width: 95vw; margin: 1rem auto; }
    .mitre-modal .modal-content { background: #fff; border: none; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25); }
    .mitre-modal .modal-header { border-bottom: 1px solid #e2e8f0; padding: 0.75rem 1rem; background: #f8fafc; }
    .mitre-modal .modal-title { color: #334155; font-size: 1rem; }
    .mitre-modal .modal-body { padding: 0; overflow: hidden; height: calc(95vh - 120px); }
    .mitre-svg-viewer { width: 100%; height: 100%; overflow: hidden; cursor: grab; background: #f8fafc; }
    .mitre-svg-viewer:active { cursor: grabbing; }
    .mitre-svg-viewer svg { transform-origin: 0 0; transition: none; }
    .mitre-modal .modal-footer { border-top: 1px solid #e2e8f0; padding: 0.5rem 1rem; background: #f8fafc; }
    .mitre-modal .zoom-controls { display: flex; align-items: center; gap: 0.5rem; }
    .mitre-modal .zoom-controls .btn { padding: 0.25rem 0.5rem; font-size: 0.875rem; }
    .mitre-modal .zoom-level { color: #334155; font-size: 0.875rem; min-width: 50px; text-align: center; }
    /* Details Flyout */
    .offcanvas-end#detailsFlyout { width: 33vw; min-width: 360px; }
    .flyout-enabled tbody tr[data-flyout-id] { cursor: pointer; }
    .flyout-enabled tbody tr[data-flyout-id]:hover { background-color: #f1f5f9 !important; }
    .flyout-enabled .col-flyout-icon { width: 32px; text-align: center; }
    .flyout-detail-table { font-size: 0.85rem; }
    .flyout-detail-table th { background-color: #f8fafc; font-size: 0.75rem; text-transform: uppercase; color: #64748b; }
    @media print {
      .toc-container, .dt-buttons, .dataTables_filter, .dataTables_paginate { display: none !important; }
      .card { break-inside: avoid; }
      .mitre-svg-container { overflow: visible; }
      .mitre-svg-container::after { display: none; }
      .offcanvas, .offcanvas-backdrop, .col-flyout-icon { display: none !important; }
    }
    @media (max-width: 576px) { .offcanvas-end#detailsFlyout { width: 100%; } }
  </style>
</head>
<body>
  <nav class="top-bar py-3 shadow-lg mb-5">
    <div class="container d-flex justify-content-between align-items-center">
      <span class="navbar-brand text-white fw-bold"><i data-lucide="shield" class="me-2"></i> Microsoft Sentinel Assessment</span>
      <span class="text-white-50 small">Client: <strong>$ClientName</strong></span>
    </div>
  </nav>

  <div class="container">
    <div class="row g-3 mb-4">$kpiHtml</div>

    <div class="row g-4 mb-5">
      <div class="col-12">
        <div class="card h-100 shadow-sm">
          <div class="card-body p-4">
            $envOverviewHtml
          </div>
        </div>
      </div>
    </div>

    <div class="row g-4">
      <div class="col-lg-2 d-none d-lg-block">
        <div class="toc-container">
          <h6 class="fw-bold text-uppercase small text-muted mb-3">Sections</h6>
          <ul class="nav flex-column">$tocHtml</ul>
        </div>
      </div>
      <div class="col-lg-10">

        <div class="card shadow-sm section-card" id="health-checks">
          <div class="card-header bg-white py-3 fw-bold">
            <i data-lucide="heart-pulse" class="me-2" style="width:18px;height:18px"></i> Health Checks
          </div>
          <div class="card-body p-4">
            $healthChecksHtml
          </div>
        </div>

        <div class="card shadow-sm section-card" id="analytics-rules">
          <div class="card-header bg-white py-3 fw-bold">
            <i data-lucide="shield-check" class="me-2" style="width:18px;height:18px"></i> Analytics Rules
          </div>
          <div class="card-body p-4">
            <div class="row mb-4">
              <div class="col-md-6">
                <canvas id="kindChart" height="200"></canvas>
              </div>
              <div class="col-md-6">
                <canvas id="severityChart" height="200"></canvas>
              </div>
            </div>
            $analyticsHtml
            $visibilityGapsHtml
            $rulesWithUpdatesHtml
            $disabledRulesHtml
            $customRulesHtml
            $incidentVolumeHtml
            $analyticsHealthHtml
          </div>
        </div>

        <div class="card shadow-sm section-card" id="data-collection">
          <div class="card-header bg-white py-3 fw-bold">
            <i data-lucide="database" class="me-2" style="width:18px;height:18px"></i> Data Collection
          </div>
          <div class="card-body p-4">

            <div id="data-connectors" class="mb-4">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="plug" class="me-2" style="width:16px;height:16px"></i>Data Connectors</h5>
              $connectorsHtml
            </div>

            <hr class="my-4">

            <div id="dce-dcr" class="mb-4">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="route" class="me-2" style="width:16px;height:16px"></i>Data Collection Endpoints & Rules</h5>
              $dceDcrHtml
            </div>

            <hr class="my-4">

            <div id="ingestion-analysis" class="mb-4">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="bar-chart-3" class="me-2" style="width:16px;height:16px"></i>Ingestion Analysis</h5>
              $ingestionHtml
            </div>

            <hr class="my-4">

            <div id="data-collection-health">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="activity" class="me-2" style="width:16px;height:16px"></i>Data Collection Health</h5>
              $dataCollectionHealthHtml
            </div>

            <hr class="my-4">

            <div id="agent-health">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="heart-pulse" class="me-2" style="width:16px;height:16px"></i>Agent Health</h5>
              $agentHealthHtml
              $agentErrorsHtml
            </div>

          </div>
        </div>

        <div class="card shadow-sm section-card" id="content-management">
          <div class="card-header bg-white py-3 fw-bold">
            <i data-lucide="boxes" class="me-2" style="width:18px;height:18px"></i> Content Management
          </div>
          <div class="card-body p-4">

            <div id="content-hub" class="mb-4">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="package" class="me-2" style="width:16px;height:16px"></i>Content Hub Solutions</h5>
              $contentHubHtml
            </div>

            <hr class="my-4">

            <div id="workbooks" class="mb-4">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="book-open" class="me-2" style="width:16px;height:16px"></i>Workbooks</h5>
              $workbooksHtml
            </div>

            <hr class="my-4">

            <div id="repository-connections">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="git-branch" class="me-2" style="width:16px;height:16px"></i>Repository Connections</h5>
              $repositoryHtml
            </div>

            <hr class="my-4">

            <div id="workspace-manager">
              <h5 class="fw-bold text-muted text-uppercase mb-3"><i data-lucide="network" class="me-2" style="width:16px;height:16px"></i>Workspace Manager</h5>
              $workspaceManagerHtml
            </div>

          </div>
        </div>

        <div class="card shadow-sm section-card" id="mitre-coverage">
          <div class="card-header bg-white py-3 fw-bold">
            <i data-lucide="target" class="me-2" style="width:18px;height:18px"></i> MITRE ATT&CK Coverage
          </div>
          <div class="card-body p-4">
            $mitreHtml
          </div>
        </div>

        <div class="card shadow-sm section-card" id="data-retention">
          <div class="card-header bg-white py-3 fw-bold">
            <i data-lucide="database" class="me-2" style="width:18px;height:18px"></i> Data Retention
          </div>
          <div class="card-body p-4">
            $retentionHtml
          </div>
        </div>

      </div>
    </div>
  </div>

  <footer class="bg-light py-4 mt-5 border-top">
    <div class="container text-center text-muted small">
      Generated by New-SentinelAssessmentReport.ps1 | $timestamp
    </div>
  </footer>

  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
  <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
  <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://unpkg.com/lucide@latest"></script>

  <script>
    lucide.createIcons();

    // Rules by Kind chart (using colors distinct from severity chart)
    new Chart(document.getElementById('kindChart'), {
      type: 'doughnut',
      data: {
        labels: [$kindLabels],
        datasets: [{
          data: [$kindData],
          backgroundColor: ['#0d6efd', '#0dcaf0', '#fd7e14', '#d63384', '#20c997', '#6c757d', '#adb5bd']
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom' },
          title: { display: true, text: 'Rules by Kind' }
        }
      }
    });

    // Rules by Severity chart
    new Chart(document.getElementById('severityChart'), {
      type: 'doughnut',
      data: {
        labels: [$severityLabels],
        datasets: [{
          data: [$severityData],
          backgroundColor: [$severityChartColors]
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom' },
          title: { display: true, text: 'Rules by Severity' }
        }
      }
    });

    $(if ($Data.MitreCoverage) {
        # Generate Navigator JSON for embedding
        $navigatorJsonEscaped = (New-MitreNavigatorJson -WorkspaceName $WorkspaceName -ClientName $ClientName -SubscriptionId $Data.SubscriptionId -ResourceGroupName $Data.ResourceGroupName -MitreCoverage $Data.MitreCoverage) -replace '\\', '\\\\' -replace "'", "\'" -replace "`r`n", '\n' -replace "`n", '\n'

        # Build top 10 techniques data for bar chart (recalculate for JS scope)
        $mcJs = $Data.MitreCoverage
        $top10TechniquesJs = $mcJs.TechniqueRuleMapping.GetEnumerator() |
            Sort-Object { $_.Value.Count } -Descending |
            Select-Object -First 10

        $top10LabelsJs = @()
        $top10DataJs = @()
        foreach ($tech in $top10TechniquesJs) {
            $techId = $tech.Key
            $ruleCount = $tech.Value.Count
            $techName = if ($Data.MitreData -and $Data.MitreData[$techId]) {
                $Data.MitreData[$techId].Name
            } else {
                $techId
            }
            $cleanName = $techName -replace "[']", ""
            $top10LabelsJs += "`"${techId}: $cleanName`""
            $top10DataJs += $ruleCount
        }
        $top10LabelsJsStr = $top10LabelsJs -join ', '
        $top10DataJsStr = $top10DataJs -join ', '

        @"
    // Top 10 Techniques bar chart
    new Chart(document.getElementById('top10TechniquesChart'), {
      type: 'bar',
      data: {
        labels: [$top10LabelsJsStr],
        datasets: [{
          label: 'Rule Count',
          data: [$top10DataJsStr],
          backgroundColor: 'rgba(34, 197, 94, 0.7)',
          borderColor: 'rgb(34, 197, 94)',
          borderWidth: 1,
          barThickness: 14
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: function(ctx) { return ctx[0].label; }
            }
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { stepSize: 5 },
            grid: { display: false }
          },
          y: {
            ticks: {
              font: { size: 9 },
              callback: function(value, index, ticks) {
                var label = this.getLabelForValue(value);
                return label.length > 35 ? label.substring(0, 35) + '...' : label;
              }
            },
            grid: { display: false }
          }
        }
      }
    });

    // MITRE Tactic Radar chart - Active Rule Counts
    new Chart(document.getElementById('tacticRadarChart'), {
      type: 'radar',
      data: {
        labels: [$radarLabels],
        datasets: [{
          label: 'Active Rules',
          data: [$radarData],
          backgroundColor: 'rgba(59, 130, 246, 0.2)',
          borderColor: '#3b82f6',
          pointBackgroundColor: '#3b82f6'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            beginAtZero: true,
            max: $radarMaxValue,
            ticks: {
              stepSize: Math.ceil($radarMaxValue / 5)
            }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function(context) {
                return context.parsed.r + ' active rules';
              }
            }
          }
        }
      }
    });

    // MITRE Navigator download functionality
    var navigatorJson = '$navigatorJsonEscaped';
    document.getElementById('downloadNavigator').addEventListener('click', function() {
      var blob = new Blob([navigatorJson], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = '${WorkspaceName}_MITRE_Navigator.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });

    // SVG download functionality (if SVG button exists)
    var svgBtn = document.getElementById('downloadSvg');
    if (svgBtn) {
      svgBtn.addEventListener('click', function() {
        var svgElement = document.querySelector('.mitre-svg-container svg');
        if (svgElement) {
          var svgContent = new XMLSerializer().serializeToString(svgElement);
          var blob = new Blob([svgContent], { type: 'image/svg+xml' });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = '${WorkspaceName}_MITRE_Navigator.svg';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        }
      });
    }

    // MITRE SVG Modal Zoom/Pan functionality
    (function() {
      var viewer = document.getElementById('mitreSvgViewer');
      var modal = document.getElementById('mitreSvgModal');
      if (!viewer || !modal) return;

      var svg = viewer.querySelector('svg');
      if (!svg) return;

      var scale = 1;
      var panX = 0;
      var panY = 0;
      var isPanning = false;
      var startX = 0;
      var startY = 0;

      var minScale = 0.5;
      var maxScale = 5;
      var scaleStep = 0.25;

      function updateTransform() {
        svg.style.transform = 'translate(' + panX + 'px, ' + panY + 'px) scale(' + scale + ')';
        document.getElementById('zoomLevel').textContent = Math.round(scale * 100) + '%';
      }

      function resetView() {
        scale = 1;
        panX = 0;
        panY = 0;
        updateTransform();
      }

      // Reset view when modal opens
      modal.addEventListener('shown.bs.modal', function() {
        resetView();
        lucide.createIcons();
      });

      // Zoom controls
      document.getElementById('zoomIn').addEventListener('click', function() {
        scale = Math.min(maxScale, scale + scaleStep);
        updateTransform();
      });

      document.getElementById('zoomOut').addEventListener('click', function() {
        scale = Math.max(minScale, scale - scaleStep);
        updateTransform();
      });

      document.getElementById('zoomReset').addEventListener('click', resetView);

      // Mouse wheel zoom
      viewer.addEventListener('wheel', function(e) {
        e.preventDefault();
        var rect = viewer.getBoundingClientRect();
        var mouseX = e.clientX - rect.left;
        var mouseY = e.clientY - rect.top;

        var prevScale = scale;
        if (e.deltaY < 0) {
          scale = Math.min(maxScale, scale + scaleStep);
        } else {
          scale = Math.max(minScale, scale - scaleStep);
        }

        // Adjust pan to zoom toward mouse position
        var scaleChange = scale / prevScale;
        panX = mouseX - (mouseX - panX) * scaleChange;
        panY = mouseY - (mouseY - panY) * scaleChange;

        updateTransform();
      }, { passive: false });

      // Pan with mouse drag
      viewer.addEventListener('mousedown', function(e) {
        isPanning = true;
        startX = e.clientX - panX;
        startY = e.clientY - panY;
        viewer.style.cursor = 'grabbing';
      });

      document.addEventListener('mousemove', function(e) {
        if (!isPanning) return;
        panX = e.clientX - startX;
        panY = e.clientY - startY;
        updateTransform();
      });

      document.addEventListener('mouseup', function() {
        isPanning = false;
        viewer.style.cursor = 'grab';
      });

      // Touch support for mobile
      var touchStartX = 0;
      var touchStartY = 0;
      var touchStartDist = 0;
      var touchStartScale = 1;

      viewer.addEventListener('touchstart', function(e) {
        if (e.touches.length === 1) {
          isPanning = true;
          touchStartX = e.touches[0].clientX - panX;
          touchStartY = e.touches[0].clientY - panY;
        } else if (e.touches.length === 2) {
          isPanning = false;
          touchStartDist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
          );
          touchStartScale = scale;
        }
      }, { passive: true });

      viewer.addEventListener('touchmove', function(e) {
        if (e.touches.length === 1 && isPanning) {
          panX = e.touches[0].clientX - touchStartX;
          panY = e.touches[0].clientY - touchStartY;
          updateTransform();
        } else if (e.touches.length === 2) {
          var dist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
          );
          scale = Math.min(maxScale, Math.max(minScale, touchStartScale * (dist / touchStartDist)));
          updateTransform();
        }
      }, { passive: true });

      viewer.addEventListener('touchend', function() {
        isPanning = false;
      });
    })();
"@})

    $(if ($Data.EventsByTableTimeSeries -and $Data.EventsByTableTimeSeries.Count -gt 0) {
        # Get unique timestamps and table categories (reusing logic from HTML generation)
        $timestamps = $Data.EventsByTableTimeSeries | Select-Object -ExpandProperty TimeGenerated -Unique | Sort-Object
        $categories = $Data.EventsByTableTimeSeries | Select-Object -ExpandProperty TableCategory -Unique | Sort-Object
        $sortedCategories = @($categories | Where-Object { $_ -ne "Other" }) + @($categories | Where-Object { $_ -eq "Other" })

        $chartLabelsJs = ($timestamps | ForEach-Object { "'$(([datetime]$_).ToString('MM/dd'))'" }) -join ', '

        # Solid colors for line chart
        $colorPalette = @(
            "rgb(54, 162, 235)",    # Blue
            "rgb(255, 99, 132)",    # Red
            "rgb(75, 192, 192)",    # Teal
            "rgb(255, 206, 86)",    # Yellow
            "rgb(153, 102, 255)",   # Purple
            "rgb(255, 159, 64)",    # Orange
            "rgb(46, 204, 113)",    # Green
            "rgb(52, 73, 94)",      # Dark Gray
            "rgb(241, 196, 15)",    # Gold
            "rgb(149, 165, 166)"    # Light Gray (Other)
        )

        # Calculate total events per category and sort by descending (largest first in legend)
        $categoryTotals = @{}
        foreach ($category in $sortedCategories) {
            $total = ($Data.EventsByTableTimeSeries | Where-Object { $_.TableCategory -eq $category } | Measure-Object -Property EventCount -Sum).Sum
            $categoryTotals[$category] = $total
        }
        $orderedCategories = $sortedCategories | Sort-Object { $categoryTotals[$_] } -Descending

        $datasetsArray = @()
        $colorIndex = 0
        foreach ($category in $orderedCategories) {
            $dataPoints = @()
            foreach ($ts in $timestamps) {
                $record = $Data.EventsByTableTimeSeries | Where-Object { $_.TimeGenerated -eq $ts -and $_.TableCategory -eq $category }
                $value = if ($record) { [math]::Round($record.EventCount, 0) } else { 0 }
                $dataPoints += $value
            }
            $dataStr = $dataPoints -join ', '
            $color = $colorPalette[$colorIndex % $colorPalette.Count]

            $datasetsArray += @"
        {
          label: '$category',
          data: [$dataStr],
          borderColor: '$color',
          backgroundColor: '$color',
          borderWidth: 2,
          fill: false,
          tension: 0.1,
          pointRadius: 3,
          pointHoverRadius: 5
        }
"@
            $colorIndex++
        }
        $datasetsJsStr = $datasetsArray -join ",`n"
        @"
    // Events by Table line chart
    if (document.getElementById('eventsByTableChart')) {
      new Chart(document.getElementById('eventsByTableChart'), {
        type: 'line',
        data: {
          labels: [$chartLabelsJs],
          datasets: [
$datasetsJsStr
          ]
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { boxWidth: 12, padding: 15 }
            },
            tooltip: {
              mode: 'nearest',
              intersect: true,
              callbacks: {
                label: function(context) {
                  return context.dataset.label + ': ' + context.parsed.y.toLocaleString() + ' events';
                }
              }
            }
          },
          interaction: { mode: 'nearest', intersect: true },
          scales: {
            x: {
              display: true,
              title: { display: false }
            },
            y: {
              stacked: false,
              display: true,
              title: { display: true, text: 'Event Count' },
              ticks: {
                callback: function(value) {
                  if (value >= 1000000) return (value/1000000).toFixed(1) + 'M';
                  if (value >= 1000) return (value/1000).toFixed(0) + 'K';
                  return value;
                }
              }
            }
          }
        }
      });
    }
"@})

    $(if ($Data.IngestionTrend -and $Data.IngestionTrend.Count -gt 0) {
        # Build cap line dataset if daily cap is configured
        $capDataset = ""
        if ($chartDailyCap -and $chartDailyCap -gt 0) {
            $capDataPoints = ($Data.IngestionTrend | ForEach-Object { $chartDailyCap }) -join ', '
            $capDataset = @"
, {
          label: 'Daily Cap ($chartDailyCap GB)',
          data: [$capDataPoints],
          borderColor: '#ef4444',
          borderWidth: 2,
          borderDash: [5, 5],
          fill: false,
          pointRadius: 0,
          tension: 0
        }
"@
        }
        @"
    // Ingestion trend chart
    new Chart(document.getElementById('ingestionChart'), {
      type: 'line',
      data: {
        labels: [$trendLabels],
        datasets: [{
          label: 'Ingestion (GB)',
          data: [$trendData],
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          fill: true,
          tension: 0.4
        }$capDataset]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: $(if ($chartDailyCap -and $chartDailyCap -gt 0) { 'true' } else { 'false' }) } },
        scales: { y: { beginAtZero: false } }
      }
    });
"@})

    $(if ($Data.BillableBreakdown -and $Data.BillableBreakdown.Count -gt 0) {
        $billableChartData = ($Data.BillableBreakdown | ForEach-Object { [math]::Round($_.TotalGB, 2) }) -join ', '
        $billableChartLabels = ($Data.BillableBreakdown | ForEach-Object { "'$($_.Type)'" }) -join ', '
        @"
    // Billable vs Free chart
    if (document.getElementById('billableChart')) {
      new Chart(document.getElementById('billableChart'), {
        type: 'doughnut',
        data: {
          labels: [$billableChartLabels],
          datasets: [{
            data: [$billableChartData],
            backgroundColor: ['#3b82f6', '#22c55e']
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: 'bottom' }
          }
        }
      });
    }
"@})

    // Initialize DataTables
    `$(document).ready(function() {
      `$('.report-table').each(function() {
        var sectionTitle = `$(this).closest('.card').find('.card-header').text().trim() || 'Export';
        var fileName = sectionTitle.replace(/\s+/g, '_');
        var tableId = `$(this).attr('id');

        // Custom options for specific tables
        var options = {
          dom: '<"table-controls"fB>rtp',
          buttons: [
            {
              extend: 'copy',
              text: '<i data-lucide="copy" class="me-1" style="width:14px;height:14px"></i> Copy',
              className: 'btn'
            },
            {
              extend: 'excel',
              text: '<i data-lucide="file-spreadsheet" class="me-1" style="width:14px;height:14px"></i> Excel',
              className: 'btn',
              filename: '${ClientName}_' + fileName
            }
          ],
          language: { search: "Filter:" },
          pageLength: 25
        };

        // Sort topTablesTable by Volume (column 1) descending by default
        if (tableId === 'topTablesTable') {
          options.order = [[1, 'desc']];
        }

        // Sort incident volume table by Daily Avg (column 4) descending
        if (tableId === 'incidentVolumeTable') {
          options.order = [[4, 'desc']];
        }

        // Sort visibility gaps table by Alerts 90d (column 4) descending
        if (tableId === 'visibilityGapsTable') {
          options.order = [[4, 'desc']];
          options.columnDefs = [{ targets: -1, orderable: false, searchable: false }];
        }

        // Data Collection Health tables: 10 items per page, sorted by Time Since Last Event (oldest first)
        var dataCollectionHealthTables = ['staleTablesTable', 'syslogByComputerTable', 'cefByComputerTable', 'securityEventByComputerTable'];
        if (dataCollectionHealthTables.includes(tableId)) {
          options.pageLength = 10;
        }
        // Sort syslog and securityEvent tables by Time Since Last Event (column 3) descending
        if (tableId === 'syslogByComputerTable' || tableId === 'securityEventByComputerTable') {
          options.order = [[3, 'desc']];
        }
        // Sort CEF table by Time Since Last Event (column 5) descending
        if (tableId === 'cefByComputerTable') {
          options.order = [[5, 'desc']];
        }

        // Agent Health tables
        if (tableId === 'agentHealthTable') {
          options.pageLength = 10;
          options.order = [[1, 'asc'], [6, 'desc']];  // Sort by Status (Unhealthy first), then Hours Since desc
        }
        if (tableId === 'agentErrorsTable') {
          options.pageLength = 10;
          options.order = [[1, 'desc']];  // Sort by Failures desc
        }

        // Workbooks table
        if (tableId === 'workbooksTable') {
          options.pageLength = 10;
        }

        // Health checks flyout icon column: non-sortable, non-searchable
        if (tableId === 'healthChecksTable') {
          options.columnDefs = [{ targets: -1, orderable: false, searchable: false }];
        }

        `$(this).DataTable(options);
        `$(this).on('draw.dt', function() { lucide.createIcons(); });
        lucide.createIcons();
      });

      // Generic flyout handler - auto-discovers all flyout-enabled tables
      (function() {
        var flyout = document.getElementById('detailsFlyout');
        if (!flyout) return;
        var bsOffcanvas = new bootstrap.Offcanvas(flyout);

        var statusBadges = {
          'Pass':     '<span class="badge bg-success">Pass</span>',
          'Warning':  '<span class="badge bg-warning text-dark">Warning</span>',
          'Critical': '<span class="badge bg-danger">Critical</span>',
          'Info':     '<span class="badge bg-info">Info</span>'
        };

        function openFlyout(data) {
          document.getElementById('flyoutCheckId').textContent = data.checkId || '';
          document.getElementById('flyoutStatusBadge').innerHTML = statusBadges[data.status] || '';
          document.getElementById('detailsFlyoutLabel').textContent = data.checkName || '';
          document.getElementById('flyoutCategory').textContent = data.category || '';
          document.getElementById('flyoutDescription').textContent = data.description || '';
          var section = document.getElementById('flyoutDetailsSection');
          var content = document.getElementById('flyoutDetailsContent');
          if (data.detailsHtml) {
            section.style.display = '';
            content.innerHTML = data.detailsHtml;
          } else {
            section.style.display = 'none';
          }
          bsOffcanvas.show();
        }

        `$('.flyout-enabled').each(function() {
          var tableId = `$(this).attr('id');
          var dataEl = document.getElementById(tableId + 'FlyoutData');
          if (!dataEl) return;
          var data = JSON.parse(dataEl.textContent);
          `$('#' + tableId + ' tbody').on('click', 'tr[data-flyout-id]', function() {
            var key = `$(this).attr('data-flyout-id');
            if (data[key]) openFlyout(data[key]);
          });
        });
      })();
    });
  </script>
<div class="offcanvas offcanvas-end" tabindex="-1" id="detailsFlyout" aria-labelledby="detailsFlyoutLabel">
  <div class="offcanvas-header border-bottom">
    <div>
      <div class="d-flex align-items-center gap-2 mb-1">
        <span id="flyoutStatusBadge"></span>
        <code id="flyoutCheckId"></code>
      </div>
      <h5 class="offcanvas-title mb-0" id="detailsFlyoutLabel"></h5>
    </div>
    <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
  </div>
  <div class="offcanvas-body">
    <div class="mb-3">
      <span class="text-muted small text-uppercase fw-bold">Category</span>
      <div id="flyoutCategory"></div>
    </div>
    <div class="mb-3">
      <span class="text-muted small text-uppercase fw-bold">Description</span>
      <div id="flyoutDescription"></div>
    </div>
    <hr>
    <div id="flyoutDetailsSection">
      <span class="text-muted small text-uppercase fw-bold">Details</span>
      <div id="flyoutDetailsContent" class="mt-2"></div>
    </div>
  </div>
</div>
</body>
</html>
"@

    return $html
}

#endregion Report Generation Functions

#region Main

# Validate output path
if (-not (Test-Path -Path $OutputPath -PathType Container)) {
    Write-Error "Output path does not exist: $OutputPath"
    return
}

Write-SectionHeader "MICROSOFT SENTINEL ASSESSMENT" -Color Cyan
Write-Host "Workspace: $WorkspaceName"
Write-Host "Subscription: $SubscriptionId"
Write-Host "Resource Group: $ResourceGroupName"
Write-Host ""

# Check for existing Azure context
$context = Get-AzContext
if (-not $context) {
    Write-Host "No Azure context found. Connecting to Azure..." -ForegroundColor Yellow
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Failed to connect to Azure: $_"
        return
    }
}

# Set subscription context
Write-Host "Setting subscription context..." -ForegroundColor DarkGray
try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}
catch {
    Write-Error "Failed to set subscription context: $_"
    return
}

# Get access token
Write-Host "Acquiring access token..." -ForegroundColor DarkGray
$context = Get-AzContext
$tokenInfo = Get-AzureAccessToken -Context $context

$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = "Bearer $($tokenInfo.Token)"
}

# API versions
$sentinelApiVersion = "2025-01-01-preview"
$workspaceApiVersion = "2023-09-01"

# Base URI for Sentinel
$sentinelBaseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# Get tenant display name
$tenantInfo = Get-AzTenant -TenantId $context.Tenant.Id -ErrorAction SilentlyContinue
$tenantName = if ($tenantInfo) { $tenantInfo.Name } else { $context.Tenant.Id }

# Initialize collected data
$collectedData = @{
    TenantName         = $tenantName
    TenantId           = $context.Tenant.Id
    SubscriptionId     = $SubscriptionId
    ResourceGroupName  = $ResourceGroupName
    AnalyticsRules     = @()
    AlertRuleTemplates = @()
    DataConnectors     = @()
    ContentTemplates   = @()
    ContentPackages    = @()
    SourceControls     = @()
    WorkspaceManagerConfig = $null
    WorkspaceManagerMembers = @()
    AutomationRules    = @()
    Watchlists         = @()
    Workbooks          = @()
    Settings           = @()
    WorkspaceConfig    = $null
    Tables             = @()
    IngestionTrend     = $null
    TopTables          = $null
    BillableBreakdown  = $null
    AlertTrend         = $null
    ConnectorHealth    = $null
    StaleConnectors    = $null
    HealthAuditEnabled = $false
    EventsByTableTimeSeries = $null
    LastEventByTable   = $null
    ConnectorLastSeen  = $null
    SyslogByComputer   = $null
    CefByComputer      = $null
    SecurityEventByComputer = $null
    MitreCoverage      = $null
    HealthChecks       = @()
    # Analytics Health (from _SentinelHealth table)
    AnalyticsHealthSummary   = $null
    AnalyticsFailureReasons  = $null
    AnalyticsSkippedWindows  = $null
    AnalyticsExecutionDelays = $null
    AnalyticsAutoDisabled    = $null
    IncidentVolumeByRule     = $null
    AlertVolumeByRuleName    = $null
    # Agent Health (from Heartbeat and Operation tables)
    AgentHealthSummary       = $null
    AgentOperationErrors     = $null
}

# Collect data with progress
Write-SectionHeader "DATA COLLECTION" -Color Yellow

Write-Host "  Fetching analytics rules..." -ForegroundColor DarkGray
try {
    $collectedData.AnalyticsRules = Get-SentinelAnalyticsRules -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion
    Write-Host "    Retrieved $($collectedData.AnalyticsRules.Count) analytics rules" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch analytics rules: $_" }

Write-Host "  Fetching alert rule templates..." -ForegroundColor DarkGray
try {
    $collectedData.AlertRuleTemplates = Get-SentinelAlertRuleTemplates -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion
    Write-Host "    Retrieved $($collectedData.AlertRuleTemplates.Count) alert rule templates" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch alert rule templates: $_" }

Write-Host "  Fetching data connectors..." -ForegroundColor DarkGray
try {
    $collectedData.DataConnectors = Get-SentinelDataConnectors -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion
    Write-Host "    Retrieved $($collectedData.DataConnectors.Count) data connectors" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch data connectors: $_" }

Write-Host "  Fetching content templates..." -ForegroundColor DarkGray
try {
    $collectedData.ContentTemplates = Get-SentinelContentTemplates -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion
    Write-Host "    Retrieved $($collectedData.ContentTemplates.Count) content templates" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch content templates: $_" }

Write-Host "  Fetching content packages..." -ForegroundColor DarkGray
try {
    $collectedData.ContentPackages = Get-SentinelContentPackages -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion
    Write-Host "    Retrieved $($collectedData.ContentPackages.Count) content packages" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch content packages: $_" }

Write-Host "  Fetching source control connections..." -ForegroundColor DarkGray
try {
    $collectedData.SourceControls = Get-SentinelSourceControls -BaseUri $sentinelBaseUri -Headers $authHeader
    $scCount = if ($collectedData.SourceControls) { @($collectedData.SourceControls).Count } else { 0 }
    Write-Host "    Retrieved $scCount repository connections" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch source controls: $_" }

Write-Host "  Fetching workspace manager configuration..." -ForegroundColor DarkGray
try {
    $collectedData.WorkspaceManagerConfig = Get-SentinelWorkspaceManagerConfig -BaseUri $sentinelBaseUri -Headers $authHeader
    $collectedData.WorkspaceManagerMembers = Get-SentinelWorkspaceManagerMembers -BaseUri $sentinelBaseUri -Headers $authHeader
    $wmMode = if ($collectedData.WorkspaceManagerConfig) {
        Get-SafeProperty (Get-SafeProperty $collectedData.WorkspaceManagerConfig 'properties') 'mode'
    } else { 'Not configured' }
    $wmMemberCount = if ($collectedData.WorkspaceManagerMembers) { @($collectedData.WorkspaceManagerMembers).Count } else { 0 }
    Write-Host "    Workspace Manager: $wmMode ($wmMemberCount members)" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch workspace manager config: $_" }

Write-Host "  Fetching automation rules..." -ForegroundColor DarkGray
try {
    $collectedData.AutomationRules = @(Get-SentinelAutomationRules -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion)
    Write-Host "    Retrieved $($collectedData.AutomationRules.Count) automation rules" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch automation rules: $_" }

Write-Host "  Fetching watchlists..." -ForegroundColor DarkGray
try {
    $collectedData.Watchlists = @(Get-SentinelWatchlists -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion)
    Write-Host "    Retrieved $($collectedData.Watchlists.Count) watchlists" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch watchlists: $_" }

Write-Host "  Fetching workbooks..." -ForegroundColor DarkGray
try {
    $collectedData.Workbooks = Get-SentinelWorkbooks -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -Headers $authHeader
    Write-Host "    Retrieved $(Format-Plural $collectedData.Workbooks.Count 'workbook')" -ForegroundColor Green
}
catch { Write-Warning "    Failed to fetch workbooks: $_" }

Write-Host "  Fetching Sentinel settings..." -ForegroundColor DarkGray
$collectedData.Settings = Get-SentinelSettings -BaseUri $sentinelBaseUri -Headers $authHeader -ApiVersion $sentinelApiVersion
Write-Host "    Retrieved $($collectedData.Settings.Count) settings" -ForegroundColor Green

Write-Host "  Fetching workspace configuration..." -ForegroundColor DarkGray
$collectedData.WorkspaceConfig = Get-WorkspaceConfig -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Headers $authHeader
if ($collectedData.WorkspaceConfig) {
    Write-Host "    Workspace config retrieved" -ForegroundColor Green
}

Write-Host "  Fetching table retention settings..." -ForegroundColor DarkGray
$collectedData.Tables = Get-TableRetention -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Headers $authHeader
Write-Host "    Retrieved $($collectedData.Tables.Count) tables" -ForegroundColor Green

Write-Host "  Fetching Data Collection Endpoints..." -ForegroundColor DarkGray
$collectedData.DataCollectionEndpoints = Get-DataCollectionEndpoints -SubscriptionId $SubscriptionId -Headers $authHeader
if ($collectedData.DataCollectionEndpoints) {
    Write-Host "    Retrieved $(Format-Plural $collectedData.DataCollectionEndpoints.Count 'DCE')" -ForegroundColor Green
} else {
    Write-Host "    No DCEs found or insufficient permissions" -ForegroundColor Yellow
    $collectedData.DataCollectionEndpoints = @()
}

Write-Host "  Fetching Data Collection Rules..." -ForegroundColor DarkGray
$collectedData.DataCollectionRules = Get-DataCollectionRules -SubscriptionId $SubscriptionId -Headers $authHeader
if ($collectedData.DataCollectionRules) {
    Write-Host "    Retrieved $(Format-Plural $collectedData.DataCollectionRules.Count 'DCR')" -ForegroundColor Green
} else {
    Write-Host "    No DCRs found or insufficient permissions" -ForegroundColor Yellow
    $collectedData.DataCollectionRules = @()
}

# KQL queries (if not skipped)
if (-not $SkipKqlQueries) {
    Write-Host "  Running KQL queries..." -ForegroundColor DarkGray

    # Get workspace ID for queries
    $workspaceId = Get-SafeProperty (Get-SafeProperty $collectedData.WorkspaceConfig 'properties') 'customerId'

    if ($workspaceId) {
        # Test and refresh Log Analytics authentication if needed
        Write-Host "    Testing Log Analytics authentication..." -ForegroundColor DarkGray
        $kqlAuthValid = Test-LogAnalyticsAuth -WorkspaceId $workspaceId -SubscriptionId $SubscriptionId

        if (-not $kqlAuthValid) {
            Write-Warning "    KQL queries will be skipped due to authentication issues."
            $workspaceId = $null
        }
    }

    if ($workspaceId) {
        # 30-day ingestion trend
        $ingestionQuery = @"
Usage
| where TimeGenerated > ago(30d)
| summarize TotalGB = sum(Quantity) / 1024 by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
"@
        $collectedData.IngestionTrend = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $ingestionQuery
        if ($collectedData.IngestionTrend) {
            Write-Host "    Ingestion trend (30d): $($collectedData.IngestionTrend.Count) days" -ForegroundColor Green
        }

        # Top 15 tables by volume (30-day)
        $topTablesQuery = @"
Usage
| where TimeGenerated > ago(30d)
| summarize TotalGB = sum(Quantity) / 1024 by DataType
| top 15 by TotalGB desc
"@
        $collectedData.TopTables = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $topTablesQuery
        if ($collectedData.TopTables) {
            Write-Host "    Top tables (30d): $($collectedData.TopTables.Count) tables" -ForegroundColor Green
        }

        # Connector health
        $connectorHealthQuery = @"
SentinelHealth
| where TimeGenerated > ago(24h)
| where SentinelResourceType == "Data connector"
| summarize arg_max(TimeGenerated, *) by SentinelResourceName
| project SentinelResourceName, Status, Description, TimeGenerated
"@
        $collectedData.ConnectorHealth = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $connectorHealthQuery
        if ($collectedData.ConnectorHealth) {
            Write-Host "    Connector health: $($collectedData.ConnectorHealth.Count) connectors" -ForegroundColor Green
        }

        # Stale connectors
        $staleConnectorsQuery = @"
SentinelHealth
| where TimeGenerated > ago(7d)
| where SentinelResourceType == "Data connector"
| summarize LastSeen = max(TimeGenerated) by SentinelResourceName
| where LastSeen < ago(24h)
"@
        $collectedData.StaleConnectors = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $staleConnectorsQuery
        if ($collectedData.StaleConnectors) {
            Write-Host "    Stale connectors: $($collectedData.StaleConnectors.Count) found" -ForegroundColor Yellow
        }

        # Billable vs Free breakdown
        $billableQuery = @"
Usage
| where TimeGenerated > ago(30d)
| summarize TotalGB = sum(Quantity) / 1024 by IsBillable
| extend Type = iff(IsBillable, "Billable", "Free")
| project Type, TotalGB
"@
        $collectedData.BillableBreakdown = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $billableQuery
        if ($collectedData.BillableBreakdown) {
            Write-Host "    Billable breakdown: $($collectedData.BillableBreakdown.Count) categories" -ForegroundColor Green
        }

        # Alert volume trend (30d)
        $alertTrendQuery = @"
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize AlertCount = count() by bin(TimeGenerated, 1d), AlertSeverity
| order by TimeGenerated asc
"@
        $collectedData.AlertTrend = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $alertTrendQuery
        if ($collectedData.AlertTrend) {
            Write-Host "    Alert trend: $($collectedData.AlertTrend.Count) data points" -ForegroundColor Green
        }

        # Alert volume by rule name (90d) - used for visibility gaps enrichment
        $alertVolumeByRuleQuery = @"
SecurityAlert
| where TimeGenerated > ago(90d)
| where ProviderName in ("ASI Scheduled Alerts", "ASI NRT Alerts")
| extend RuleName = extract(@'"Analytic Rule Name":"([^"]+)"', 1, tostring(ExtendedProperties))
| where isnotempty(RuleName)
| summarize
    AlertCount = count(),
    HighCount = countif(AlertSeverity == "High"),
    MediumCount = countif(AlertSeverity == "Medium"),
    LowCount = countif(AlertSeverity == "Low"),
    InfoCount = countif(AlertSeverity == "Informational"),
    FirstAlert = min(TimeGenerated),
    LastAlert = max(TimeGenerated)
    by RuleName
| order by AlertCount desc
"@
        $collectedData.AlertVolumeByRuleName = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $alertVolumeByRuleQuery
        if ($collectedData.AlertVolumeByRuleName -and @($collectedData.AlertVolumeByRuleName).Count -gt 0) {
            Write-Host "    Alert volume by rule: $(@($collectedData.AlertVolumeByRuleName).Count) rules with alerts" -ForegroundColor Green
        }

        # Events by table over time (7 days, top 9 + Other) - using daily buckets for performance
        $eventsByTableQuery = @"
let Top9Tables = Usage
| where TimeGenerated > ago(7d)
| summarize TotalQuantity = sum(Quantity) by DataType
| top 9 by TotalQuantity desc
| project DataType;
union withsource=_TableName *
| where TimeGenerated > ago(7d)
| extend TableCategory = iff(_TableName in (Top9Tables), _TableName, "Other")
| summarize EventCount = count() by bin(TimeGenerated, 1d), TableCategory
| order by TimeGenerated asc, TableCategory asc
"@
        try {
            $collectedData.EventsByTableTimeSeries = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $eventsByTableQuery
            if ($collectedData.EventsByTableTimeSeries -and $collectedData.EventsByTableTimeSeries.Count -gt 0) {
                $tableCategories = $collectedData.EventsByTableTimeSeries | Select-Object -ExpandProperty TableCategory -Unique
                Write-Host "    Events by table (7d): $($tableCategories.Count) table categories" -ForegroundColor Green
            }
            else {
                Write-Host "    Events by table (7d): No data returned" -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Warning "    Events by table query failed: $_"
        }

        # Check if SentinelHealth or SentinelAudit tables have data (Health & Audit diagnostic setting)
        # Use 90-day lookback to reliably detect if feature is enabled (not just if there's recent data)
        $healthAuditCheckQuery = @"
union isfuzzy=true
    (SentinelHealth | where TimeGenerated > ago(90d) | take 1),
    (SentinelAudit | where TimeGenerated > ago(90d) | take 1)
| take 1
"@
        $healthAuditResult = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $healthAuditCheckQuery
        $collectedData.HealthAuditEnabled = ($null -ne $healthAuditResult -and @($healthAuditResult).Count -gt 0)
        Write-Host "    Health & Audit (SentinelHealth/SentinelAudit): $(if ($collectedData.HealthAuditEnabled) { 'Enabled' } else { 'Not detected' })" -ForegroundColor $(if ($collectedData.HealthAuditEnabled) { 'Green' } else { 'DarkGray' })

        # Analytics Rule Health queries (requires _SentinelHealth table)
        if ($collectedData.HealthAuditEnabled) {
            Write-Host "    Running analytics rule health queries..." -ForegroundColor DarkGray

            # Query 1: Analytics Rule Health Summary (last 7 days)
            $analyticsHealthSummaryQuery = @"
_SentinelHealth()
| where TimeGenerated > ago(7d)
| where SentinelResourceType == "Analytics Rule"
| summarize
    TotalExecutions = count(),
    SuccessCount = countif(Status == "Success"),
    FailureCount = countif(Status != "Success")
    by SentinelResourceId, SentinelResourceName, SentinelResourceKind
| extend FailureRate = round(todouble(FailureCount) / TotalExecutions * 100, 1)
| project SentinelResourceId, SentinelResourceName, SentinelResourceKind,
    TotalExecutions, SuccessCount, FailureCount, FailureRate
"@
            $collectedData.AnalyticsHealthSummary = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $analyticsHealthSummaryQuery
            if ($collectedData.AnalyticsHealthSummary) {
                $rulesWithFailures = @($collectedData.AnalyticsHealthSummary | Where-Object { $_.FailureCount -gt 0 }).Count
                Write-Host "      Analytics health summary: $($collectedData.AnalyticsHealthSummary.Count) rules ($rulesWithFailures with failures)" -ForegroundColor $(if ($rulesWithFailures -gt 0) { 'Yellow' } else { 'Green' })
            }

            # Query 2: Failure Reasons Summary
            $analyticsFailureReasonsQuery = @"
_SentinelHealth()
| where TimeGenerated > ago(7d)
| where SentinelResourceType == "Analytics Rule"
| where Status != "Success"
| summarize FailureCount = count(), AffectedRules = dcount(SentinelResourceId) by Reason
| order by FailureCount desc
"@
            $collectedData.AnalyticsFailureReasons = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $analyticsFailureReasonsQuery
            if ($collectedData.AnalyticsFailureReasons) {
                Write-Host "      Failure reasons: $($collectedData.AnalyticsFailureReasons.Count) distinct reasons" -ForegroundColor $(if ($collectedData.AnalyticsFailureReasons.Count -gt 0) { 'Yellow' } else { 'Green' })
            }

            # Query 3: Skipped Windows (All 6 retries failed for scheduled rules)
            $analyticsSkippedWindowsQuery = @"
_SentinelHealth()
| where TimeGenerated > ago(7d)
| where SentinelResourceType == "Analytics Rule"
| where SentinelResourceKind == "Scheduled"
| where Status != "Success"
| extend QueryStartTime = tostring(ExtendedProperties["QueryStartTimeUTC"])
| summarize RetryCount = count() by QueryStartTime, SentinelResourceId, SentinelResourceName
| where RetryCount == 6
| summarize SkippedWindows = count() by SentinelResourceId, SentinelResourceName
| order by SkippedWindows desc
"@
            $collectedData.AnalyticsSkippedWindows = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $analyticsSkippedWindowsQuery
            if ($collectedData.AnalyticsSkippedWindows -and @($collectedData.AnalyticsSkippedWindows).Count -gt 0) {
                Write-Host "      Skipped query windows: $(@($collectedData.AnalyticsSkippedWindows).Count) rules with complete failures" -ForegroundColor Red
            }

            # Query 4: Execution Delays (Scheduled Rules with >5 min delay)
            $analyticsExecutionDelaysQuery = @"
_SentinelHealth()
| where TimeGenerated > ago(7d)
| where SentinelResourceType == "Analytics Rule"
| where SentinelResourceKind == "Scheduled"
| where Status == "Success"
| extend
    QueryStart = todatetime(ExtendedProperties["QueryStartTimeUTC"]),
    ExecutionStart = todatetime(ExtendedProperties["executionStart"])
| extend DelayMinutes = datetime_diff('minute', ExecutionStart, QueryStart)
| where DelayMinutes > 5
| summarize AvgDelay = round(avg(DelayMinutes), 1), MaxDelay = max(DelayMinutes), DelayedExecutions = count()
    by SentinelResourceId, SentinelResourceName
| order by AvgDelay desc
"@
            $collectedData.AnalyticsExecutionDelays = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $analyticsExecutionDelaysQuery
            if ($collectedData.AnalyticsExecutionDelays -and @($collectedData.AnalyticsExecutionDelays).Count -gt 0) {
                Write-Host "      Execution delays: $(@($collectedData.AnalyticsExecutionDelays).Count) rules with >5 min avg delay" -ForegroundColor Yellow
            }

            # Query 5: Auto-Disabled Rules
            $analyticsAutoDisabledQuery = @"
_SentinelHealth()
| where TimeGenerated > ago(7d)
| where SentinelResourceType == "Analytics Rule"
| where Reason == "The analytics rule is disabled and was not executed."
| summarize LastSeen = max(TimeGenerated) by SentinelResourceId, SentinelResourceName
| order by LastSeen desc
"@
            $collectedData.AnalyticsAutoDisabled = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $analyticsAutoDisabledQuery
            if ($collectedData.AnalyticsAutoDisabled -and @($collectedData.AnalyticsAutoDisabled).Count -gt 0) {
                Write-Host "      Auto-disabled rules: $(@($collectedData.AnalyticsAutoDisabled).Count) rules" -ForegroundColor Yellow
            }

            # Query 6: Incident Volume by Rule (from SecurityIncident + SecurityAlert + _SentinelAudit)
            $incidentVolumeQuery = @"
let LookbackDays = 30;
let LookbackPeriod = ago(LookbackDays * 1d);
let RuleAuditStatus = _SentinelAudit()
    | where SentinelResourceType == "Analytic Rule"
    | extend Props = todynamic(ExtendedProperties)
    | extend UpdatedState = parse_json(tostring(Props.UpdatedResourceState))
    | extend Enabled = tobool(UpdatedState.properties.enabled)
    | extend IsDelete = OperationName has "Delete"
    | summarize arg_max(TimeGenerated, OperationName, Enabled, IsDelete) by SentinelResourceName
    | extend RuleStatus = case(
        IsDelete, "Deleted",
        Enabled == false, "Disabled",
        Enabled == true, "Active",
        "Unknown")
    | project RuleName = SentinelResourceName, RuleStatus;
let rules = SecurityAlert
    | where TimeGenerated > ago(365d)
    | where ProviderName in ("ASI Scheduled Alerts", "ASI NRT Alerts")
    | where AlertSeverity in ("Medium", "High")
    | extend ExtendedProperties = todynamic(ExtendedProperties)
    | extend RuleName = tostring(ExtendedProperties["Analytic Rule Name"])
    | mv-expand ExtendedProperties["Analytic Rule Ids"] to typeof(string)
    | extend RelatedAnalyticRuleIds = tostring(todynamic(['ExtendedProperties_Analytic Rule Ids'])[0])
    | summarize LastAlert = arg_max(TimeGenerated, RuleName, AlertSeverity) by RelatedAnalyticRuleIds;
SecurityIncident
| where TimeGenerated > LookbackPeriod
| where Severity in ("Medium", "High")
| where AdditionalData.alertProductNames has "Azure Sentinel"
| where isnotempty(RelatedAnalyticRuleIds)
| mv-expand RelatedAnalyticRuleIds to typeof(string)
| where isnotempty(RelatedAnalyticRuleIds)
| summarize IncidentCount = dcount(IncidentNumber) by RelatedAnalyticRuleIds
| extend DailyAverage = round(todouble(IncidentCount) / todouble(LookbackDays), 2)
| extend WeeklyAverage = round(DailyAverage * 7, 2)
| join kind=inner rules on RelatedAnalyticRuleIds
| join kind=leftouter RuleAuditStatus on RuleName
| extend RuleStatus = coalesce(RuleStatus, "Active")
| project RuleName, RuleStatus, IncidentCount, DailyAverage, WeeklyAverage, Severity = AlertSeverity
| order by DailyAverage desc
"@
            $collectedData.IncidentVolumeByRule = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $incidentVolumeQuery
            if ($collectedData.IncidentVolumeByRule -and @($collectedData.IncidentVolumeByRule).Count -gt 0) {
                Write-Host "      Incident volume: $(@($collectedData.IncidentVolumeByRule).Count) rules with incidents" -ForegroundColor Yellow
            }
        }

        # Data Collection Health queries
        Write-Host "    Running data collection health queries..." -ForegroundColor DarkGray

        # Last event received by table (for staleness detection)
        $lastEventByTableQuery = @"
union withsource=_TableName *
| where TimeGenerated > ago(7d)
| summarize LastEvent = max(TimeGenerated) by _TableName
| extend SecondsSinceLastEvent = datetime_diff('second', now(), LastEvent)
| order by SecondsSinceLastEvent desc
"@
        $collectedData.LastEventByTable = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $lastEventByTableQuery
        if ($collectedData.LastEventByTable) {
            Write-Host "      Last event by table: $($collectedData.LastEventByTable.Count) tables" -ForegroundColor Green
        }

        # Connector-specific last seen (for shared tables like SecurityAlert)
        # Uses the same logic as Sentinel data connector definitions
        $connectorLastSeenQuery = @"
union isfuzzy=true
    // SecurityAlert by ProviderName - maps to multiple Defender connectors
    (SecurityAlert
    | where TimeGenerated > ago(30d)
    | summarize LastEvent = max(TimeGenerated) by ProviderName
    | extend ConnectorKey = case(
        ProviderName == "Azure Active Directory Identity Protection", "AzureActiveDirectoryIdentityProtection",
        ProviderName == "Microsoft Defender Advanced Threat Protection" or ProviderName == "MDATP", "MicrosoftDefenderAdvancedThreatProtection",
        ProviderName == "Azure Advanced Threat Protection" or ProviderName == "Azure ATP", "AzureAdvancedThreatProtection",
        ProviderName == "Azure Security Center" or ProviderName == "Microsoft Defender for Cloud", "AzureSecurityCenter",
        ProviderName == "Microsoft Cloud App Security" or ProviderName == "MCAS", "MicrosoftCloudAppSecurity",
        ProviderName == "Office 365 Advanced Threat Protection" or ProviderName == "OATP", "OfficeATP",
        ProviderName == "IPC", "AzureActiveDirectoryIdentityProtection",
        ProviderName
    )
    | project ConnectorKey, LastEvent),
    // CloudAppEvents for MCAS
    (CloudAppEvents
    | where TimeGenerated > ago(30d)
    | summarize LastEvent = max(TimeGenerated)
    | extend ConnectorKey = "MicrosoftCloudAppSecurity"
    | project ConnectorKey, LastEvent),
    // EmailEvents for Office ATP
    (EmailEvents
    | where TimeGenerated > ago(30d)
    | summarize LastEvent = max(TimeGenerated)
    | extend ConnectorKey = "OfficeATP"
    | project ConnectorKey, LastEvent),
    // ThreatIntelIndicators for TI connectors
    (ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize LastEvent = max(TimeGenerated) by SourceSystem
    | extend ConnectorKey = case(
        SourceSystem has "Microsoft Defender", "MicrosoftDefenderThreatIntelligence",
        SourceSystem has "TAXII", "ThreatIntelligenceTaxii",
        "ThreatIntelligence"
    )
    | project ConnectorKey, LastEvent),
    // AzureDiagnostics by ResourceProvider for Azure resource connectors
    (AzureDiagnostics
    | where TimeGenerated > ago(30d)
    | summarize LastEvent = max(TimeGenerated) by ResourceProvider
    | extend ConnectorKey = case(
        ResourceProvider == "MICROSOFT.KEYVAULT", "AzureKeyVault",
        ResourceProvider == "MICROSOFT.NETWORK" and Category == "AzureFirewallApplicationRule", "AzureFirewall",
        ResourceProvider == "MICROSOFT.SQL", "AzureSql",
        ResourceProvider
    )
    | project ConnectorKey, LastEvent)
| summarize LastEvent = max(LastEvent) by ConnectorKey
"@
        $collectedData.ConnectorLastSeen = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $connectorLastSeenQuery
        if ($collectedData.ConnectorLastSeen) {
            Write-Host "      Connector last seen: $($collectedData.ConnectorLastSeen.Count) connectors" -ForegroundColor Green
        }

        # Syslog: Last data by computer
        $syslogByComputerQuery = @"
Syslog
| where TimeGenerated > ago(7d)
| summarize LastEvent = max(TimeGenerated), Events = count() by Computer
| extend SecondsSinceLastEvent = datetime_diff('second', now(), LastEvent)
| order by SecondsSinceLastEvent desc
"@
        $collectedData.SyslogByComputer = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $syslogByComputerQuery
        if ($collectedData.SyslogByComputer) {
            Write-Host "      Syslog by computer: $($collectedData.SyslogByComputer.Count) computers" -ForegroundColor Green
        }

        # CEF (CommonSecurityLog): Last data by computer
        $cefByComputerQuery = @"
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize LastEvent = max(TimeGenerated), Events = count() by DeviceVendor, DeviceProduct, Computer
| extend SecondsSinceLastEvent = datetime_diff('second', now(), LastEvent)
| order by SecondsSinceLastEvent desc
"@
        $collectedData.CefByComputer = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $cefByComputerQuery
        if ($collectedData.CefByComputer) {
            Write-Host "      CEF by device: $($collectedData.CefByComputer.Count) devices" -ForegroundColor Green
        }

        # SecurityEvent: Last data by computer
        $securityEventByComputerQuery = @"
SecurityEvent
| where TimeGenerated > ago(7d)
| summarize LastEvent = max(TimeGenerated), Events = count() by Computer
| extend SecondsSinceLastEvent = datetime_diff('second', now(), LastEvent)
| order by SecondsSinceLastEvent desc
"@
        $collectedData.SecurityEventByComputer = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $securityEventByComputerQuery
        if ($collectedData.SecurityEventByComputer) {
            Write-Host "      SecurityEvent by computer: $($collectedData.SecurityEventByComputer.Count) computers" -ForegroundColor Green
        }

        # Agent Health queries
        Write-Host "    Running agent health queries..." -ForegroundColor DarkGray

        # Agent Health Summary (from Heartbeat table)
        $agentHealthQuery = @"
Heartbeat
| where TimeGenerated > ago(7d)
| summarize LastHeartbeat = max(TimeGenerated), HeartbeatCount = count()
    by Computer, OSType, Category, ComputerEnvironment, Version, SourceSystem
| extend State = iff(LastHeartbeat < ago(24h), 'Unhealthy', 'Healthy')
| extend HoursSinceHeartbeat = datetime_diff('hour', now(), LastHeartbeat)
| order by State desc, HoursSinceHeartbeat desc
"@
        $collectedData.AgentHealthSummary = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $agentHealthQuery
        if ($collectedData.AgentHealthSummary) {
            $unhealthyCount = @($collectedData.AgentHealthSummary | Where-Object { $_.State -eq 'Unhealthy' }).Count
            Write-Host "      Agent health: $(Format-Plural $collectedData.AgentHealthSummary.Count 'agent') ($unhealthyCount unhealthy)" -ForegroundColor $(if ($unhealthyCount -gt 0) { 'Yellow' } else { 'Green' })
        }

        # Agent Operation Errors (from Operation table)
        $agentOpsQuery = @"
Operation
| where TimeGenerated > ago(7d)
| where Computer != ""
| summarize Failures = countif(OperationStatus in ("Failed", "Failure")),
            Errors = countif(OperationStatus == "Error"),
            Warnings = countif(OperationStatus == "Warning")
    by Computer
| where Failures > 0 or Errors > 0
| order by Failures desc, Errors desc
"@
        $collectedData.AgentOperationErrors = Invoke-SentinelKqlQuery -WorkspaceId $workspaceId -Query $agentOpsQuery
        if ($collectedData.AgentOperationErrors) {
            Write-Host "      Agent operation errors: $(Format-Plural $collectedData.AgentOperationErrors.Count 'agent') with errors" -ForegroundColor $(if ($collectedData.AgentOperationErrors.Count -gt 0) { 'Yellow' } else { 'Green' })
        }
    }
    else {
        Write-Warning "    Could not determine workspace ID for KQL queries"
    }
}
else {
    Write-Host "  Skipping KQL queries (use -SkipKqlQueries:$false to enable)" -ForegroundColor DarkGray
}

# MITRE analysis
Write-SectionHeader "MITRE ANALYSIS" -Color Yellow
Write-Host "  Loading MITRE ATT&CK framework..." -ForegroundColor DarkGray
$mitreData = Get-MitreAttackTechniques
if ($mitreData) {
    Write-Host "    Loaded $($mitreData.Count) techniques" -ForegroundColor Green
    $collectedData.MitreData = $mitreData

    # Filter to active rules only (enabled AND creating incidents) for accurate coverage
    $activeRulesForMitre = Get-ActiveAnalyticsRules -Rules $collectedData.AnalyticsRules
    Write-Host "    Calculating coverage from $(Format-Plural $activeRulesForMitre.Count 'active rule') (enabled + creating incidents)" -ForegroundColor DarkGray

    $collectedData.MitreCoverage = Get-MitreCoverageAnalysis -Rules $activeRulesForMitre -MitreData $mitreData

    # Store counts for report display
    if ($collectedData.MitreCoverage) {
        $collectedData.MitreCoverage.ActiveRuleCount = $activeRulesForMitre.Count
        $collectedData.MitreCoverage.TotalRuleCount = $collectedData.AnalyticsRules.Count
        Write-Host "    Coverage: $($collectedData.MitreCoverage.ParentCoveragePercent)% parent techniques" -ForegroundColor $(if ($collectedData.MitreCoverage.ParentCoveragePercent -ge 50) { 'Green' } elseif ($collectedData.MitreCoverage.ParentCoveragePercent -ge 25) { 'Yellow' } else { 'Red' })
    }
}

# Run health checks
Write-SectionHeader "HEALTH CHECKS" -Color Yellow
Write-Host "  Running health checks..." -ForegroundColor DarkGray
$collectedData.HealthChecks = Invoke-AllHealthChecks -CollectedData $collectedData
$passCount = @($collectedData.HealthChecks | Where-Object { $_.Status -eq 'Pass' }).Count
$warnCount = @($collectedData.HealthChecks | Where-Object { $_.Status -eq 'Warning' }).Count
$critCount = @($collectedData.HealthChecks | Where-Object { $_.Status -eq 'Critical' }).Count
Write-Host "    Completed: $passCount pass, $warnCount warnings, $critCount critical" -ForegroundColor $(if ($critCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' })

# Generate reports
Write-SectionHeader "REPORT GENERATION" -Color Yellow

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$baseFileName = "${WorkspaceName}_Assessment_${timestamp}"

# Generate MITRE Navigator JSON and SVG (before HTML so SVG can be embedded)
$navigatorSvgPath = $null
if ($collectedData.MitreCoverage) {
    Write-Host "  Generating MITRE Navigator layer..." -ForegroundColor DarkGray
    $navigatorJson = New-MitreNavigatorJson -WorkspaceName $WorkspaceName -ClientName $ClientName -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -MitreCoverage $collectedData.MitreCoverage
    $navigatorPath = Join-Path -Path $OutputPath -ChildPath "${baseFileName}_MitreNavigator.json"
    $navigatorJson | Out-File -FilePath $navigatorPath -Encoding utf8
    Write-Host "    Navigator layer: $navigatorPath" -ForegroundColor Green

    # Generate SVG from the Navigator JSON
    $navigatorSvgPath = Join-Path -Path $OutputPath -ChildPath "${baseFileName}_MitreNavigator.svg"
    $svgResult = Invoke-NavigatorSvgGeneration -JsonPath $navigatorPath -SvgPath $navigatorSvgPath

    if ($svgResult -and (Test-Path $navigatorSvgPath)) {
        # Read SVG content for embedding in HTML
        $svgContent = Get-Content -Path $navigatorSvgPath -Raw
        $collectedData['NavigatorSvgContent'] = $svgContent
        $collectedData['NavigatorSvgPath'] = $navigatorSvgPath
        Write-Host "    Navigator SVG: $navigatorSvgPath" -ForegroundColor Green
    }
    else {
        $navigatorSvgPath = $null
    }
}

# Generate HTML report (after Navigator so SVG can be embedded)
Write-Host "  Generating HTML report..." -ForegroundColor DarkGray
$htmlContent = ConvertTo-ReportHtml -Data $collectedData -ClientName $ClientName -WorkspaceName $WorkspaceName
$htmlPath = Join-Path -Path $OutputPath -ChildPath "${baseFileName}.html"
$htmlContent | Out-File -FilePath $htmlPath -Encoding utf8
Write-Host "    HTML report: $htmlPath" -ForegroundColor Green

# Export raw JSON if requested
if ($ExportJson) {
    Write-Host "  Exporting raw data JSON..." -ForegroundColor DarkGray
    $jsonPath = Join-Path -Path $OutputPath -ChildPath "${baseFileName}_Data.json"
    $collectedData | ConvertTo-Json -Depth 20 | Out-File -FilePath $jsonPath -Encoding utf8
    Write-Host "    Raw data: $jsonPath" -ForegroundColor Green
}

Write-SectionHeader "ASSESSMENT COMPLETE" -Color Green
Write-Host "Output files generated in: $OutputPath" -ForegroundColor Cyan

# Return output file paths
$outputFiles = @($htmlPath)
if ($collectedData.MitreCoverage) { $outputFiles += $navigatorPath }
if ($navigatorSvgPath) { $outputFiles += $navigatorSvgPath }
if ($ExportJson) { $outputFiles += $jsonPath }

return $outputFiles

#endregion Main
