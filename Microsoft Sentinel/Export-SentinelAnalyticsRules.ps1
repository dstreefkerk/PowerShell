#Requires -Version 5.1
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Exports all Microsoft Sentinel Analytics Rules from a workspace to a flattened JSON file.

.DESCRIPTION
    This script exports all Analytics Rules from a Microsoft Sentinel workspace using the Azure
    REST API. The output is flattened for easy CSV conversion - nested properties are promoted
    to top-level fields and arrays are joined as comma-separated strings.

    Features:
    - Exports all rule types (Scheduled, Fusion, MLBehaviorAnalytics, MicrosoftSecurityIncidentCreation, NRT)
    - Includes MITRE ATT&CK tactics, techniques, and subtechniques
    - Captures incident creation settings (createIncident, grouping configuration)
    - Handles pagination for large rule sets
    - Retry logic with exponential backoff for transient API failures
    - Auto-generates output filename based on workspace details

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Microsoft Sentinel workspace.

.PARAMETER ResourceGroupName
    The resource group name where the Log Analytics workspace is deployed.

.PARAMETER WorkspaceName
    The Log Analytics workspace name with Microsoft Sentinel enabled.

.PARAMETER OutputPath
    Optional directory path for the output JSON file. Defaults to current directory.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
    Returns the path to the exported JSON file.

.NOTES
    File Name      : Export-SentinelAnalyticsRules.ps1
    Author         : Daniel Streefkerk
    Prerequisite   : PowerShell 5.1+, Az.Accounts module, Azure authentication
    Copyright      : MIT License

.EXAMPLE
    .\Export-SentinelAnalyticsRules.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace"

    Exports all analytics rules to a JSON file in the current directory.

.EXAMPLE
    .\Export-SentinelAnalyticsRules.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -OutputPath "C:\Exports"

    Exports all analytics rules to a JSON file in the specified directory.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $false, HelpMessage = 'Output directory for the JSON file (defaults to current directory)')]
    [string]$OutputPath = "."
)

Set-StrictMode -Version Latest

#region Functions

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
        [int]$MaxRetries = 3,
        [int]$InitialDelaySeconds = 2
    )

    $attempt = 0
    $delay = $InitialDelaySeconds

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -ErrorAction Stop
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

function ConvertTo-FlattenedRule {
    <#
    .SYNOPSIS
    Flattens a Sentinel analytics rule object for CSV-friendly output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Rule,

        [Parameter(Mandatory = $false)]
        [hashtable]$TemplateLookup = @{}
    )

    # Start with top-level properties
    $flatRule = [ordered]@{
        id   = Get-SafeProperty $Rule 'id'
        name = Get-SafeProperty $Rule 'name'
        type = Get-SafeProperty $Rule 'type'
        kind = Get-SafeProperty $Rule 'kind'
    }

    # Flatten all properties from the properties object
    $props = Get-SafeProperty $Rule 'properties'
    if ($props) {
        # Core properties
        $flatRule['displayName'] = Get-SafeProperty $props 'displayName'
        $flatRule['description'] = Get-SafeProperty $props 'description'
        $flatRule['severity'] = Get-SafeProperty $props 'severity'
        $flatRule['enabled'] = Get-SafeProperty $props 'enabled'

        # MITRE ATT&CK - join arrays as comma-separated strings
        # Note: API uses camelCase 'subTechniques' not 'subtechniques'
        $tactics = Get-SafeProperty $props 'tactics'
        $techniques = Get-SafeProperty $props 'techniques'
        $subTechniques = Get-SafeProperty $props 'subTechniques'
        $flatRule['tactics'] = if ($tactics) { ($tactics -join ',') } else { $null }
        $flatRule['techniques'] = if ($techniques) { ($techniques -join ',') } else { $null }
        $flatRule['subTechniques'] = if ($subTechniques) { ($subTechniques -join ',') } else { $null }

        # Incident Configuration - flatten nested object
        $incidentConfig = Get-SafeProperty $props 'incidentConfiguration'
        $flatRule['createIncident'] = Get-SafeProperty $incidentConfig 'createIncident'

        $grouping = Get-SafeProperty $incidentConfig 'groupingConfiguration'
        $flatRule['groupingEnabled'] = Get-SafeProperty $grouping 'enabled'
        $flatRule['groupingReopenClosedIncident'] = Get-SafeProperty $grouping 'reopenClosedIncident'
        $flatRule['groupingLookbackDuration'] = Get-SafeProperty $grouping 'lookbackDuration'
        $flatRule['groupingMatchingMethod'] = Get-SafeProperty $grouping 'matchingMethod'

        $groupByEntities = Get-SafeProperty $grouping 'groupByEntities'
        $groupByAlertDetails = Get-SafeProperty $grouping 'groupByAlertDetails'
        $groupByCustomDetails = Get-SafeProperty $grouping 'groupByCustomDetails'
        $flatRule['groupByEntities'] = if ($groupByEntities) { ($groupByEntities -join ',') } else { $null }
        $flatRule['groupByAlertDetails'] = if ($groupByAlertDetails) { ($groupByAlertDetails -join ',') } else { $null }
        $flatRule['groupByCustomDetails'] = if ($groupByCustomDetails) { ($groupByCustomDetails -join ',') } else { $null }

        # Query properties (for Scheduled rules)
        $flatRule['query'] = Get-SafeProperty $props 'query'
        $flatRule['queryFrequency'] = Get-SafeProperty $props 'queryFrequency'
        $flatRule['queryPeriod'] = Get-SafeProperty $props 'queryPeriod'
        $flatRule['triggerOperator'] = Get-SafeProperty $props 'triggerOperator'
        $flatRule['triggerThreshold'] = Get-SafeProperty $props 'triggerThreshold'

        # Suppression
        $flatRule['suppressionEnabled'] = Get-SafeProperty $props 'suppressionEnabled'
        $flatRule['suppressionDuration'] = Get-SafeProperty $props 'suppressionDuration'

        # Template info
        $flatRule['alertRuleTemplateName'] = Get-SafeProperty $props 'alertRuleTemplateName'
        $flatRule['templateVersion'] = Get-SafeProperty $props 'templateVersion'

        # Entity mappings - convert to JSON string for CSV compatibility
        $entityMappings = Get-SafeProperty $props 'entityMappings'
        $flatRule['entityMappings'] = if ($entityMappings) {
            ($entityMappings | ConvertTo-Json -Compress -Depth 10)
        } else { $null }

        # Custom details - convert to JSON string
        $customDetails = Get-SafeProperty $props 'customDetails'
        $flatRule['customDetails'] = if ($customDetails) {
            ($customDetails | ConvertTo-Json -Compress -Depth 10)
        } else { $null }

        # Alert details override
        $alertOverride = Get-SafeProperty $props 'alertDetailsOverride'
        $flatRule['alertDisplayNameFormat'] = Get-SafeProperty $alertOverride 'alertDisplayNameFormat'
        $flatRule['alertDescriptionFormat'] = Get-SafeProperty $alertOverride 'alertDescriptionFormat'
        $flatRule['alertSeverityColumnName'] = Get-SafeProperty $alertOverride 'alertSeverityColumnName'
        $flatRule['alertTacticsColumnName'] = Get-SafeProperty $alertOverride 'alertTacticsColumnName'

        # Event grouping
        $eventGrouping = Get-SafeProperty $props 'eventGroupingSettings'
        $flatRule['eventGroupingAggregationKind'] = Get-SafeProperty $eventGrouping 'aggregationKind'

        # Timestamps
        $flatRule['lastModifiedUtc'] = Get-SafeProperty $props 'lastModifiedUtc'

        # For Microsoft Security Incident Creation rules
        $flatRule['productFilter'] = Get-SafeProperty $props 'productFilter'

        $displayNamesFilter = Get-SafeProperty $props 'displayNamesFilter'
        $displayNamesExcludeFilter = Get-SafeProperty $props 'displayNamesExcludeFilter'
        $severitiesFilter = Get-SafeProperty $props 'severitiesFilter'
        $flatRule['displayNamesFilter'] = if ($displayNamesFilter) { ($displayNamesFilter -join ',') } else { $null }
        $flatRule['displayNamesExcludeFilter'] = if ($displayNamesExcludeFilter) { ($displayNamesExcludeFilter -join ',') } else { $null }
        $flatRule['severitiesFilter'] = if ($severitiesFilter) { ($severitiesFilter -join ',') } else { $null }

        # For Fusion rules
        $flatRule['alertRulesCreatedByTemplateCount'] = Get-SafeProperty $props 'alertRulesCreatedByTemplateCount'

        # Template comparison - get the template's original createIncident setting
        $alertRuleTemplateName = Get-SafeProperty $props 'alertRuleTemplateName'
        if ($alertRuleTemplateName -and $TemplateLookup.ContainsKey($alertRuleTemplateName)) {
            $flatRule['templateCreateIncident'] = $TemplateLookup[$alertRuleTemplateName]
        }
        else {
            $flatRule['templateCreateIncident'] = $null
        }
    }

    return [PSCustomObject]$flatRule
}

#endregion Functions

#region Main

# Validate output path
if (-not (Test-Path -Path $OutputPath -PathType Container)) {
    Write-Error "Output path does not exist: $OutputPath"
    return
}

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
Write-Verbose "Setting subscription context to: $SubscriptionId"
try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}
catch {
    Write-Error "Failed to set subscription context: $_"
    return
}

# Get access token using the authentication factory (more reliable across Az module versions)
Write-Verbose "Acquiring access token..."
$context = Get-AzContext
try {
    $tokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
        $context.Account,
        $context.Environment,
        $context.Tenant.Id,
        $null,
        "Never",
        $null,
        "https://management.azure.com/"
    )

    if (-not $tokenRequest -or -not $tokenRequest.AccessToken) {
        throw "Failed to obtain access token."
    }

    $accessToken = $tokenRequest.AccessToken
}
catch {
    Write-Error "Failed to acquire access token: $_"
    return
}

$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = "Bearer $accessToken"
}

# Define API version (2025-01-01-preview required for MITRE subtechniques)
$apiVersion = "2025-01-01-preview"

# Build the base URI for analytics rules
$baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"

Write-Host "Fetching analytics rules from workspace: $WorkspaceName" -ForegroundColor Cyan

# Fetch all rules with pagination
$allRules = @()
$uri = $baseUri
$pageCount = 0

do {
    $pageCount++
    Write-Verbose "Fetching page $pageCount..."

    try {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $authHeader
    }
    catch {
        Write-Error "Failed to fetch analytics rules: $_"
        return
    }

    if ($response.value) {
        $allRules += $response.value
        Write-Verbose "Retrieved $($response.value.Count) rules (total: $($allRules.Count))"
    }

    # Check for next page (property may not exist if no more pages)
    $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
} while ($uri)

Write-Host "Retrieved $($allRules.Count) analytics rules" -ForegroundColor Green

if ($allRules.Count -eq 0) {
    Write-Warning "No analytics rules found in the workspace."
    return
}

# Build template lookup for createIncident comparison using batch API with $expand
Write-Host "Fetching template details for incident creation comparison..." -ForegroundColor Cyan
$templateLookup = @{}

# Use $expand to get mainTemplate in a single batch call (much faster than individual calls)
$templatesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$apiVersion&`$expand=properties/mainTemplate"

$allTemplates = @()
$uri = $templatesUri

try {
    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $authHeader
        if ($response.value) {
            $allTemplates += $response.value
            Write-Verbose "Retrieved $($response.value.Count) templates (total: $($allTemplates.Count))"
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    Write-Host "Retrieved $($allTemplates.Count) content templates" -ForegroundColor Green

    # Build lookup from batch results - only process AnalyticsRule templates
    $analyticsTemplateCount = 0
    $templatesWithMainTemplate = 0
    $templatesWithIncidentConfig = 0

    foreach ($template in $allTemplates) {
        if ($template.properties.contentKind -ne 'AnalyticsRule') {
            continue
        }
        $analyticsTemplateCount++

        $templateName = $template.name

        # Check if mainTemplate was expanded
        if (-not $template.properties.PSObject.Properties['mainTemplate'] -or -not $template.properties.mainTemplate) {
            Write-Verbose "Template $templateName has no mainTemplate (not expanded) - assuming default (createIncident=true)"
            $templateLookup[$templateName] = $true
            continue
        }
        $templatesWithMainTemplate++

        # Navigate to the AlertRuleTemplates resource to get incidentConfiguration
        $resource = $null
        if ($template.properties.mainTemplate.resources) {
            $resource = $template.properties.mainTemplate.resources |
                Where-Object { $_.type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates' } |
                Select-Object -First 1
        }

        if ($resource -and $resource.properties) {
            if ($resource.properties.PSObject.Properties['incidentConfiguration']) {
                $templateCreateIncident = $resource.properties.incidentConfiguration.createIncident
                $templatesWithIncidentConfig++
            }
            else {
                # No incidentConfiguration means default behavior = create incidents
                $templateCreateIncident = $true
            }
            $templateLookup[$templateName] = $templateCreateIncident
        }
        else {
            # No resource properties - assume default (create incidents)
            $templateLookup[$templateName] = $true
        }
    }

    Write-Host "Processed $analyticsTemplateCount Content Hub templates ($templatesWithMainTemplate with mainTemplate, $templatesWithIncidentConfig with incidentConfiguration)" -ForegroundColor Green
}
catch {
    Write-Warning "Could not fetch content templates: $_"
}

# Also fetch built-in alertRuleTemplates (classic templates not from Content Hub)
Write-Host "Fetching built-in alert rule templates..." -ForegroundColor Cyan
$alertRuleTemplatesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=$apiVersion"

try {
    $builtInTemplates = @()
    $uri = $alertRuleTemplatesUri

    do {
        $response = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -Headers $authHeader
        if ($response.value) {
            $builtInTemplates += $response.value
            Write-Verbose "Retrieved $($response.value.Count) built-in templates (total: $($builtInTemplates.Count))"
        }
        $uri = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
    } while ($uri)

    Write-Host "Retrieved $($builtInTemplates.Count) built-in alert rule templates" -ForegroundColor Green

    # Process built-in templates - these have a different structure
    $builtInProcessed = 0
    $builtInWithIncidentConfig = 0

    foreach ($template in $builtInTemplates) {
        $templateName = $template.name

        # Skip if already in lookup from Content Hub templates
        if ($templateLookup.ContainsKey($templateName)) {
            continue
        }

        $builtInProcessed++

        # Built-in templates have properties directly on the object
        if ($template.properties) {
            if ($template.properties.PSObject.Properties['incidentConfiguration']) {
                $templateCreateIncident = $template.properties.incidentConfiguration.createIncident
                $builtInWithIncidentConfig++
            }
            else {
                # No incidentConfiguration = default behavior (create incidents)
                $templateCreateIncident = $true
            }
            $templateLookup[$templateName] = $templateCreateIncident
        }
        else {
            $templateLookup[$templateName] = $true
        }
    }

    Write-Host "Processed $builtInProcessed built-in templates ($builtInWithIncidentConfig with incidentConfiguration)" -ForegroundColor Green
}
catch {
    Write-Warning "Could not fetch built-in alert rule templates: $_"
}

Write-Host "Total templates in lookup: $($templateLookup.Count)" -ForegroundColor Cyan

# Flatten all rules
Write-Verbose "Flattening rule objects for CSV compatibility..."
$flattenedRules = $allRules | ForEach-Object { ConvertTo-FlattenedRule -Rule $_ -TemplateLookup $templateLookup }

# Generate output filename
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFileName = "${SubscriptionId}_${ResourceGroupName}_${WorkspaceName}_AnalyticsRules_${timestamp}.json"
$outputFilePath = Join-Path -Path $OutputPath -ChildPath $outputFileName

# Export to JSON
Write-Verbose "Exporting to: $outputFilePath"
$flattenedRules | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFilePath -Encoding utf8

Write-Host "`nExport complete!" -ForegroundColor Green
Write-Host "Output file: $outputFilePath" -ForegroundColor Cyan
Write-Host "Total rules exported: $($flattenedRules.Count)" -ForegroundColor Cyan

# Return the file path
return $outputFilePath

#endregion Main
