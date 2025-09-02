#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Websites, Az.Resources

<#
.SYNOPSIS
    Retrieves comprehensive configuration and workflow details from Azure Logic App Standard instances.

.DESCRIPTION
    This script fetches all development-relevant information from Logic App Standard including:
    - Complete workflow definitions with full JSON depth
    - Logic App properties and configuration
    - API connections and their status
    - App Service Plan details
    - Managed Identity configuration
    - Application settings (non-sensitive)
    - Network configuration
    - Deployment slots information
    
    Designed for developers needing complete Logic App information for:
    - Development and debugging
    - Documentation generation
    - Configuration backup
    - Migration planning
    - Troubleshooting

.PARAMETER ResourceGroupName
    The name of the Azure resource group containing the Logic App Standard.

.PARAMETER LogicAppStandardName
    The name of the Logic App Standard instance.

.PARAMETER SubscriptionId
    The Azure subscription ID. If not specified, uses current context.

.PARAMETER WorkflowName
    Specific workflow name. If not specified, retrieves all workflows.

.PARAMETER DetailLevel
    Level of detail to retrieve:
    - Basic: Essential properties only
    - Detailed: Includes workflow definitions and connections (default)
    - Full: Everything including diagnostic settings and metrics

.PARAMETER IncludeSensitive
    Include sensitive configuration values (requires additional permissions).
    WARNING: Use with caution, masks values by default.

.PARAMETER IncludeConnections
    Retrieve detailed API connection information including status.

.PARAMETER IncludeAppServicePlan
    Include App Service Plan details (SKU, scaling, limits).

.PARAMETER IncludeManagedIdentity
    Include Managed Identity configuration and role assignments.

.PARAMETER IncludeNetworking
    Include network configuration (VNet integration, private endpoints).

.PARAMETER IncludeSlots
    Include deployment slot information.

.PARAMETER ExportPath
    Path to export results. Format determined by extension (.json, .yaml, .yml).

.PARAMETER GenerateMarkdown
    Generate a markdown report alongside data export.

.PARAMETER ValidateWorkflows
    Perform validation checks on workflow definitions.

.PARAMETER CompareWithProduction
    Compare current configuration with production slot (if applicable).

.PARAMETER NonInteractive
    Run without prompts (fails if choices required).

.EXAMPLE
    .\Get-LogicAppStandardDetails.ps1 -ResourceGroupName "MyResourceGroup" -LogicAppStandardName "MyLogicAppStandard"
    Retrieves basic Logic App information with default detail level.

.EXAMPLE
    .\Get-LogicAppStandardDetails.ps1 -ResourceGroupName "MyResourceGroup" -LogicAppStandardName "MyLogicAppStandard" -DetailLevel "Full" -IncludeConnections -ExportPath "logicapp-config.json" -GenerateMarkdown
    Performs full export with all details and generates markdown documentation.

.NOTES
    Version:        1.0.0
    Author:         Daniel Streefkerk
    Creation Date:  September 2025
    Purpose:        Azure Logic App Standard configuration extraction
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogicAppStandardName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter()]
    [string]$WorkflowName,

    [Parameter()]
    [ValidateSet('Basic', 'Detailed', 'Full', IgnoreCase = $true)]
    [string]$DetailLevel = 'Detailed',

    [Parameter()]
    [switch]$IncludeSensitive,

    [Parameter()]
    [switch]$IncludeConnections,

    [Parameter()]
    [switch]$IncludeAppServicePlan,

    [Parameter()]
    [switch]$IncludeManagedIdentity,

    [Parameter()]
    [switch]$IncludeNetworking,

    [Parameter()]
    [switch]$IncludeSlots,

    [Parameter()]
    [ValidateScript({
        $extension = [System.IO.Path]::GetExtension($_).ToLower()
        if ($extension -notin @('.json', '.yaml', '.yml')) {
            throw "Export file must have .json, .yaml, or .yml extension"
        }
        return $true
    })]
    [string]$ExportPath,

    [Parameter()]
    [switch]$GenerateMarkdown,

    [Parameter()]
    [switch]$ValidateWorkflows,

    [Parameter()]
    [switch]$CompareWithProduction,

    [Parameter()]
    [switch]$NonInteractive
)

#region Script Configuration
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Script metadata
$script:Version = '1.0.0'
$script:StartTime = Get-Date
$script:RequestCounter = 0
$script:RequestTimes = @()
$script:RateLimitPerMinute = 120
#endregion

#region Helper Functions

function Write-ActionLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Verbose')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formattedMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'Error' { Write-Error $formattedMessage }
        'Warning' { Write-Warning $formattedMessage }
        'Verbose' { Write-Verbose $formattedMessage }
        'Success' { Write-Host $formattedMessage -ForegroundColor Green }
        default { Write-Information $formattedMessage -InformationAction Continue }
    }
}

function Test-AzureConnection {
    [CmdletBinding()]
    param()

    try {
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context) {
            throw "No Azure context found. Please run Connect-AzAccount first."
        }
        
        if ($SubscriptionId -and $context.Subscription.Id -ne $SubscriptionId) {
            Write-ActionLog "Switching to subscription: $SubscriptionId" -Level Verbose
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        }
        
        Write-ActionLog "Connected to Azure subscription: $($context.Subscription.Name)" -Level Verbose
        return $true
    }
    catch {
        Write-ActionLog "Azure connection failed: $_" -Level Error
        throw
    }
}

function Invoke-AzureRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter()]
        [string]$Method = 'GET',
        
        [Parameter()]
        [hashtable]$Body,
        
        [Parameter()]
        [uint32]$MaxRetries = 3
    )

    # Rate limiting
    $script:RequestCounter++
    $script:RequestTimes += Get-Date
    
    $cutoffTime = (Get-Date).AddMinutes(-1)
    $script:RequestTimes = @($script:RequestTimes | Where-Object { $_ -gt $cutoffTime })
    
    if ($script:RequestTimes.Count -ge $script:RateLimitPerMinute) {
        $waitTime = 60 - ((Get-Date) - $script:RequestTimes[0]).TotalSeconds
        if ($waitTime -gt 0) {
            Write-ActionLog "Rate limit approaching, waiting $([Math]::Round($waitTime, 2)) seconds" -Level Warning
            Start-Sleep -Seconds $waitTime
        }
    }

    $attempt = 0
    $baseDelay = 2

    while ($attempt -lt $MaxRetries) {
        $attempt++
        
        try {
            $params = @{
                Uri = $Uri
                Method = $Method
                ErrorAction = 'Stop'
            }
            
            if ($Body) {
                $params['Body'] = $Body | ConvertTo-Json -Depth 100
                $params['ContentType'] = 'application/json'
            }

            $token = (Get-AzAccessToken).Token
            $params['Headers'] = @{
                'Authorization' = "Bearer $token"
            }

            Write-ActionLog "Making Azure API request (Attempt $attempt): $Method $Uri" -Level Verbose
            $response = Invoke-RestMethod @params
            return $response
        }
        catch {
            $errorMessage = $_.Exception.Message
            
            if ($attempt -eq $MaxRetries) {
                Write-ActionLog "All retry attempts exhausted. Final error: $errorMessage" -Level Error
                throw
            }
            
            # Check if error is retryable
            if ($_.Exception.Response.StatusCode -in @(429, 500, 502, 503, 504)) {
                $delay = [Math]::Pow($baseDelay, $attempt)
                Write-ActionLog "Transient error on attempt $attempt. Retrying in $delay seconds..." -Level Warning
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
}

function Get-LogicAppBasicInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$LogicAppName
    )

    Write-ActionLog "Retrieving basic Logic App information" -Level Verbose

    try {
        $logicApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $LogicAppName -ErrorAction Stop
        
        $basicInfo = [PSCustomObject]@{
            Name = $logicApp.Name
            ResourceGroup = $logicApp.ResourceGroup
            Location = $logicApp.Location
            State = $logicApp.State
            Kind = $logicApp.Kind
            DefaultHostName = $logicApp.DefaultHostName
            ResourceId = $logicApp.Id
            Tags = if ($logicApp.Tags) { $logicApp.Tags } else { @{} }
            LastModifiedTime = if ($logicApp.LastModifiedTimeUtc) { $logicApp.LastModifiedTimeUtc } else { $null }
            RuntimeVersion = if ($logicApp.SiteConfig.FunctionAppScaleLimit) { $logicApp.SiteConfig.FunctionAppScaleLimit } else { $null }
        }

        Write-ActionLog "Successfully retrieved basic information for $LogicAppName" -Level Success
        return $basicInfo
    }
    catch {
        Write-ActionLog "Failed to retrieve basic Logic App info: $_" -Level Error
        throw
    }
}

function Get-WorkflowDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$LogicAppName,
        
        [Parameter()]
        [string]$SpecificWorkflow
    )

    Write-ActionLog "Retrieving workflow definitions" -Level Verbose
    
    $workflows = @()
    
    try {
        $subscription = (Get-AzContext).Subscription.Id
        
        # Get access token (same as working script)
        $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
        if ($token -is [System.Security.SecureString]) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
            $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        
        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }
        
        # Build base URI (same approach as working script)
        $baseUri = "https://management.azure.com/subscriptions/$subscription/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$LogicAppName"
        
        if ($SpecificWorkflow) {
            $workflowUri = "$baseUri/workflows/$($SpecificWorkflow)?api-version=2018-11-01"
            
            try {
                Write-ActionLog "Fetching specific workflow: $SpecificWorkflow" -Level Verbose
                $workflow = Invoke-RestMethod -Uri $workflowUri -Headers $headers -Method Get -ErrorAction Stop
                $workflowList = @($workflow)
            }
            catch {
                Write-ActionLog "Failed to retrieve specific workflow '$SpecificWorkflow': $_" -Level Warning
                return @()
            }
        } else {
            $workflowsUri = "$baseUri/workflows?api-version=2018-11-01"
            
            try {
                Write-ActionLog "Fetching workflows from: $workflowsUri" -Level Verbose
                $response = Invoke-RestMethod -Uri $workflowsUri -Headers $headers -Method Get -ErrorAction Stop
                $workflowList = if ($response.value) { $response.value } else { @() }
                Write-ActionLog "Found $($workflowList.Count) workflow(s) in Logic App" -Level Verbose
            }
            catch {
                Write-ActionLog "Failed to retrieve workflows: $_" -Level Warning
                return @()
            }
        }
        
        # Process workflows using the same helper function approach as the working script
        foreach ($workflow in $workflowList) {
            $workflowDetail = [PSCustomObject]@{
                Name = if ($workflow.name) { $workflow.name -replace "^$LogicAppName/", "" } else { 'Unknown' }
                State = Get-SafeProperty -Object $workflow -PropertyPath 'properties.flowState' -Default 'Unknown'
                Definition = Get-SafeProperty -Object $workflow -PropertyPath 'properties.definition' -Default @{}
                Version = Get-SafeProperty -Object $workflow -PropertyPath 'properties.version'
                CreatedTime = Get-SafeProperty -Object $workflow -PropertyPath 'properties.createdTime'
                ChangedTime = Get-SafeProperty -Object $workflow -PropertyPath 'properties.changedTime'
                Parameters = Get-SafeProperty -Object $workflow -PropertyPath 'properties.parameters' -Default @{}
                AccessEndpoint = Get-SafeProperty -Object $workflow -PropertyPath 'properties.accessEndpoint'
                ConnectionReferences = @()
            }
            
            # Extract connection references from definition if available
            $definition = $workflowDetail.Definition
            if ($definition -and $definition.PSObject.Properties['triggers']) {
                foreach ($trigger in $definition.triggers.PSObject.Properties) {
                    if ($trigger.Value.inputs -and $trigger.Value.inputs.host -and $trigger.Value.inputs.host.connection) {
                        $workflowDetail.ConnectionReferences += $trigger.Value.inputs.host.connection.name
                    }
                }
            }
            
            if ($definition -and $definition.PSObject.Properties['actions']) {
                foreach ($action in $definition.actions.PSObject.Properties) {
                    if ($action.Value.inputs -and $action.Value.inputs.host -and $action.Value.inputs.host.connection) {
                        $workflowDetail.ConnectionReferences += $action.Value.inputs.host.connection.name
                    }
                }
            }
            
            $workflowDetail.ConnectionReferences = @($workflowDetail.ConnectionReferences | Select-Object -Unique)
            $workflows += $workflowDetail
        }
        
        Write-ActionLog "Successfully retrieved $($workflows.Count) workflow(s)" -Level Success
        return $workflows
    }
    catch {
        Write-ActionLog "Failed to retrieve workflow definitions: $_" -Level Error
        Write-ActionLog "This may be due to insufficient permissions or the Logic App not having any workflows deployed" -Level Warning
        return @()
    }
}

function Get-SafeProperty {
    param(
        $Object,
        [string]$PropertyPath,
        $Default = $null
    )
    
    try {
        $result = $Object
        foreach ($prop in $PropertyPath.Split('.')) {
            $result = $result.$prop
            if ($null -eq $result) { return $Default }
        }
        return $result
    }
    catch {
        return $Default
    }
}

function Get-LogicAppConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$LogicAppName,
        
        [Parameter()]
        [switch]$IncludeSensitive
    )

    Write-ActionLog "Retrieving Logic App configuration" -Level Verbose
    
    try {
        $config = [PSCustomObject]@{
            AppSettings = @{}
            ConnectionStrings = @{}
            HostConfiguration = $null
            RuntimeSettings = @{}
        }
        
        # Get app settings
        $appSettings = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $LogicAppName -ErrorAction Stop
        
        foreach ($setting in $appSettings.SiteConfig.AppSettings) {
            $value = $setting.Value
            
            if (-not $IncludeSensitive -and $setting.Name -match 'Key|Secret|Password|ConnectionString') {
                $value = '***MASKED***'
            }
            
            $config.AppSettings[$setting.Name] = $value
        }
        
        # Get connection strings
        $connectionStrings = $appSettings.SiteConfig.ConnectionStrings
        
        foreach ($connStr in $connectionStrings) {
            $value = $connStr.ConnectionString
            
            if (-not $IncludeSensitive) {
                # Mask sensitive parts
                $value = $value -replace '(Password|AccountKey)=([^;]+)', '$1=***MASKED***'
            }
            
            $config.ConnectionStrings[$connStr.Name] = @{
                Type = $connStr.Type
                Value = $value
            }
        }
        
        # Get host configuration
        $hostConfigUri = "https://management.azure.com/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$LogicAppName/hostruntime/admin/host/_master/properties?api-version=2022-03-01"
        
        try {
            $hostConfig = Invoke-AzureRequest -Uri $hostConfigUri
            $config.HostConfiguration = $hostConfig
        }
        catch {
            Write-ActionLog "Could not retrieve host configuration: $_" -Level Warning
        }
        
        Write-ActionLog "Successfully retrieved configuration" -Level Success
        return $config
    }
    catch {
        Write-ActionLog "Failed to retrieve Logic App configuration: $_" -Level Error
        throw
    }
}

function Get-ApiConnections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$LogicAppName
    )

    Write-ActionLog "Retrieving API connections" -Level Verbose
    
    try {
        $connections = @()
        $subscription = (Get-AzContext).Subscription.Id
        
        # Get all API connections in the resource group
        $apiConnections = Get-AzResource -ResourceGroupName $ResourceGroupName `
            -ResourceType "Microsoft.Web/connections" -ErrorAction SilentlyContinue
        
        if ($apiConnections -and $apiConnections.Count -gt 0) {
            foreach ($conn in $apiConnections) {
                $connectionDetails = Get-AzResource -ResourceId $conn.ResourceId -ExpandProperties -ErrorAction Stop
                
                $connectionInfo = [PSCustomObject]@{
                    Name = if ($connectionDetails.Name) { $connectionDetails.Name } else { 'Unknown' }
                    Type = Get-SafeProperty -Object $connectionDetails -PropertyPath 'Properties.api.name' -Default 'Unknown'
                    Status = Get-SafeProperty -Object $connectionDetails -PropertyPath 'Properties.statuses[0].status' -Default 'Unknown'
                    AuthType = Get-SafeProperty -Object $connectionDetails -PropertyPath 'Properties.authenticatedUser.name' -Default 'Unknown'
                    TestResult = 'Not Tested'
                    Parameters = @{}
                    CreatedTime = Get-SafeProperty -Object $connectionDetails -PropertyPath 'Properties.createdTime'
                    ChangedTime = Get-SafeProperty -Object $connectionDetails -PropertyPath 'Properties.changedTime'
                }
                
                # Extract non-sensitive parameters
                $parameterValues = Get-SafeProperty -Object $connectionDetails -PropertyPath 'Properties.parameterValues'
                if ($parameterValues) {
                    foreach ($param in $parameterValues.PSObject.Properties) {
                        if ($param.Name -notmatch 'secret|key|password|token') {
                            $connectionInfo.Parameters[$param.Name] = $param.Value
                        } else {
                            $connectionInfo.Parameters[$param.Name] = '***MASKED***'
                        }
                    }
                }
                
                # Test connection if possible
                $testUri = "https://management.azure.com$($conn.ResourceId)/testconnection?api-version=2016-06-01"
                
                try {
                    $testResult = Invoke-AzureRequest -Uri $testUri -Method POST
                    $connectionInfo.TestResult = if ($testResult.status -eq 'Succeeded') { 'Connected' } else { 'Failed' }
                }
                catch {
                    $connectionInfo.TestResult = 'Test Failed'
                }
                
                $connections += $connectionInfo
            }
        } else {
            Write-ActionLog "No API connections found in resource group" -Level Verbose
        }
        
        Write-ActionLog "Successfully retrieved $($connections.Count) API connection(s)" -Level Success
        return $connections
    }
    catch {
        Write-ActionLog "Failed to retrieve API connections: $_" -Level Error
        throw
    }
}

function Get-AppServicePlanDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$LogicAppName
    )

    Write-ActionLog "Retrieving App Service Plan details" -Level Verbose
    
    try {
        $logicApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $LogicAppName -ErrorAction Stop
        $planId = $logicApp.ServerFarmId
        
        $plan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName `
            -Name ($planId -split '/')[-1] -ErrorAction Stop
        
        $planDetails = [PSCustomObject]@{
            Name = $plan.Name
            Tier = $plan.Sku.Tier
            Size = $plan.Sku.Name
            Capacity = $plan.Sku.Capacity
            Family = $plan.Sku.Family
            NumberOfSites = $plan.NumberOfSites
            MaximumNumberOfWorkers = $plan.MaximumNumberOfWorkers
            Status = $plan.Status
            ResourceGroup = $plan.ResourceGroup
            Location = $plan.Location
            PerSiteScaling = $plan.PerSiteScaling
            MaximumElasticWorkerCount = $plan.MaximumElasticWorkerCount
            IsElasticScaleEnabled = $plan.ElasticScaleEnabled
            Tags = $plan.Tags
        }
        
        Write-ActionLog "Successfully retrieved App Service Plan details" -Level Success
        return $planDetails
    }
    catch {
        Write-ActionLog "Failed to retrieve App Service Plan details: $_" -Level Error
        throw
    }
}

function Get-ManagedIdentityInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$LogicAppName
    )

    Write-ActionLog "Retrieving Managed Identity information" -Level Verbose
    
    try {
        $logicApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $LogicAppName -ErrorAction Stop
        
        $identityInfo = [PSCustomObject]@{
            SystemAssigned = $null
            UserAssigned = @()
            RoleAssignments = @()
        }
        
        # System-assigned identity
        if ($logicApp.Identity.Type -in @('SystemAssigned', 'SystemAssigned,UserAssigned')) {
            $identityInfo.SystemAssigned = [PSCustomObject]@{
                PrincipalId = $logicApp.Identity.PrincipalId
                TenantId = $logicApp.Identity.TenantId
                Enabled = $true
            }
            
            # Get role assignments for system-assigned identity
            if ($logicApp.Identity.PrincipalId) {
                $roleAssignments = Get-AzRoleAssignment -ObjectId $logicApp.Identity.PrincipalId -ErrorAction SilentlyContinue
                
                foreach ($assignment in $roleAssignments) {
                    $identityInfo.RoleAssignments += [PSCustomObject]@{
                        IdentityType = 'SystemAssigned'
                        Role = $assignment.RoleDefinitionName
                        Scope = $assignment.Scope
                        AssignmentId = $assignment.RoleAssignmentId
                    }
                }
            }
        }
        
        # User-assigned identities
        if ($logicApp.Identity.UserAssignedIdentities) {
            foreach ($identity in $logicApp.Identity.UserAssignedIdentities.PSObject.Properties) {
                $userIdentity = [PSCustomObject]@{
                    ResourceId = $identity.Name
                    PrincipalId = $identity.Value.PrincipalId
                    ClientId = $identity.Value.ClientId
                }
                
                $identityInfo.UserAssigned += $userIdentity
                
                # Get role assignments for user-assigned identity
                if ($identity.Value.PrincipalId) {
                    $roleAssignments = Get-AzRoleAssignment -ObjectId $identity.Value.PrincipalId -ErrorAction SilentlyContinue
                    
                    foreach ($assignment in $roleAssignments) {
                        $identityInfo.RoleAssignments += [PSCustomObject]@{
                            IdentityType = 'UserAssigned'
                            IdentityResourceId = $identity.Name
                            Role = $assignment.RoleDefinitionName
                            Scope = $assignment.Scope
                            AssignmentId = $assignment.RoleAssignmentId
                        }
                    }
                }
            }
        }
        
        Write-ActionLog "Successfully retrieved Managed Identity information" -Level Success
        return $identityInfo
    }
    catch {
        Write-ActionLog "Failed to retrieve Managed Identity info: $_" -Level Error
        throw
    }
}

function Get-NetworkConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$LogicAppName
    )

    Write-ActionLog "Retrieving network configuration" -Level Verbose
    
    try {
        $logicApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $LogicAppName -ErrorAction Stop
        
        $networkConfig = [PSCustomObject]@{
            VNetIntegration = $null
            PrivateEndpoints = @()
            IpRestrictions = @()
            ScmIpRestrictions = @()
            CorsSettings = $null
            HybridConnections = @()
        }
        
        # VNet Integration
        if ($logicApp.VirtualNetworkSubnetId) {
            $networkConfig.VNetIntegration = [PSCustomObject]@{
                SubnetId = $logicApp.VirtualNetworkSubnetId
                SwiftSupported = $logicApp.SiteConfig.VnetRouteAllEnabled
                RouteAllTraffic = $logicApp.SiteConfig.VnetRouteAllEnabled
            }
        }
        
        # IP Restrictions
        foreach ($restriction in $logicApp.SiteConfig.IpSecurityRestrictions) {
            $networkConfig.IpRestrictions += [PSCustomObject]@{
                Name = $restriction.Name
                IpAddress = $restriction.IpAddress
                Action = $restriction.Action
                Priority = $restriction.Priority
                Description = $restriction.Description
            }
        }
        
        # SCM IP Restrictions
        foreach ($restriction in $logicApp.SiteConfig.ScmIpSecurityRestrictions) {
            $networkConfig.ScmIpRestrictions += [PSCustomObject]@{
                Name = $restriction.Name
                IpAddress = $restriction.IpAddress
                Action = $restriction.Action
                Priority = $restriction.Priority
                Description = $restriction.Description
            }
        }
        
        # CORS Settings
        if ($logicApp.SiteConfig.Cors) {
            $networkConfig.CorsSettings = [PSCustomObject]@{
                AllowedOrigins = $logicApp.SiteConfig.Cors.AllowedOrigins
                SupportCredentials = $logicApp.SiteConfig.Cors.SupportCredentials
            }
        }
        
        # Private Endpoints
        $privateEndpointConnections = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $logicApp.Id -ErrorAction SilentlyContinue
        
        foreach ($peConnection in $privateEndpointConnections) {
            $networkConfig.PrivateEndpoints += [PSCustomObject]@{
                Name = $peConnection.Name
                State = $peConnection.PrivateLinkServiceConnectionState.Status
                Description = $peConnection.PrivateLinkServiceConnectionState.Description
            }
        }
        
        Write-ActionLog "Successfully retrieved network configuration" -Level Success
        return $networkConfig
    }
    catch {
        Write-ActionLog "Failed to retrieve network configuration: $_" -Level Error
        throw
    }
}

function Test-WorkflowConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Workflows,
        
        [Parameter()]
        [PSCustomObject[]]$Connections
    )

    Write-ActionLog "Validating workflow configurations" -Level Verbose
    
    $validationResults = @()
    
    foreach ($workflow in $Workflows) {
        $validationErrors = @()
        $validationWarnings = @()
        
        # Check workflow state
        if ($workflow.State -ne 'Enabled') {
            $validationWarnings += "Workflow is not enabled (current state: $($workflow.State))"
        }
        
        # Validate triggers
        $triggers = Get-SafeProperty -Object $workflow -PropertyPath 'Definition.triggers'
        if (-not $triggers -or ($triggers.PSObject.Properties.Count -eq 0)) {
            $validationWarnings += "Workflow has no triggers defined"
        }
        
        # Validate actions
        $actions = Get-SafeProperty -Object $workflow -PropertyPath 'Definition.actions'
        if (-not $actions -or ($actions.PSObject.Properties.Count -eq 0)) {
            $validationErrors += "Workflow has no actions defined"
        }
        
        # Check connection references
        foreach ($connRef in $workflow.ConnectionReferences) {
            $connectionExists = $Connections | Where-Object { $_.Name -eq $connRef }
            
            if (-not $connectionExists) {
                $validationErrors += "Referenced connection '$connRef' not found"
            }
            elseif ($connectionExists.Status -ne 'Connected') {
                $validationWarnings += "Referenced connection '$connRef' is not in Connected state"
            }
        }
        
        # Check for deprecated actions
        if ($actions) {
            foreach ($action in $actions.PSObject.Properties) {
                if ($action.Value.type -eq 'Http' -and -not $action.Value.inputs.authentication) {
                    $validationWarnings += "Action '$($action.Name)' uses HTTP without authentication"
                }
            }
        }
        
        $validationResults += [PSCustomObject]@{
            WorkflowName = $workflow.Name
            IsValid = $validationErrors.Count -eq 0
            Errors = $validationErrors
            Warnings = $validationWarnings
            ValidationTime = Get-Date
        }
    }
    
    Write-ActionLog "Validation completed for $($validationResults.Count) workflow(s)" -Level Success
    return $validationResults
}

function Export-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter()]
        [switch]$GenerateMarkdown
    )

    Write-ActionLog "Exporting results to: $Path" -Level Verbose
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            '.json' {
                $Data | ConvertTo-Json -Depth 100 | Out-File -FilePath $Path -Encoding UTF8
                Write-ActionLog "Exported to JSON: $Path" -Level Success
            }
            
            {$_ -in '.yaml', '.yml'} {
                # For YAML export, we'll use a simplified conversion
                # In production, you might want to use a proper YAML module
                $yamlContent = ConvertTo-Yaml -Data $Data
                $yamlContent | Out-File -FilePath $Path -Encoding UTF8
                Write-ActionLog "Exported to YAML: $Path" -Level Success
            }
            
            default {
                throw "Unsupported export format: $extension"
            }
        }
        
        if ($GenerateMarkdown) {
            $markdownPath = [System.IO.Path]::ChangeExtension($Path, '.md')
            $markdownContent = Generate-MarkdownReport -Data $Data
            $markdownContent | Out-File -FilePath $markdownPath -Encoding UTF8
            Write-ActionLog "Generated markdown report: $markdownPath" -Level Success
        }
    }
    catch {
        Write-ActionLog "Failed to export results: $_" -Level Error
        throw
    }
}

function ConvertTo-Yaml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Data,
        
        [Parameter()]
        [int]$Indent = 0
    )

    $yaml = @()
    $indentString = '  ' * $Indent

    foreach ($property in $Data.PSObject.Properties) {
        $key = $property.Name
        $value = $property.Value

        if ($null -eq $value) {
            $yaml += "${indentString}${key}: null"
        }
        elseif ($value -is [string]) {
            $escapedValue = $value -replace '"', '\"'
            $yaml += "${indentString}${key}: `"$escapedValue`""
        }
        elseif ($value -is [bool]) {
            $yaml += "${indentString}${key}: $($value.ToString().ToLower())"
        }
        elseif ($value -is [int] -or $value -is [decimal] -or $value -is [double]) {
            $yaml += "${indentString}${key}: $value"
        }
        elseif ($value -is [datetime]) {
            $yaml += "${indentString}${key}: $($value.ToString('yyyy-MM-ddTHH:mm:ss'))"
        }
        elseif ($value -is [array]) {
            $yaml += "${indentString}${key}:"
            foreach ($item in $value) {
                if ($item -is [PSCustomObject]) {
                    $yaml += "${indentString}- "
                    $yaml += ConvertTo-Yaml -Data $item -Indent ($Indent + 2)
                }
                else {
                    $yaml += "${indentString}  - $item"
                }
            }
        }
        elseif ($value -is [PSCustomObject] -or $value -is [hashtable]) {
            $yaml += "${indentString}${key}:"
            if ($value -is [hashtable]) {
                $value = [PSCustomObject]$value
            }
            $yaml += ConvertTo-Yaml -Data $value -Indent ($Indent + 1)
        }
        else {
            $yaml += "${indentString}${key}: $($value.ToString())"
        }
    }

    return $yaml -join "`n"
}

function Generate-MarkdownReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Data
    )

    $md = @()
    $md += "# Logic App Standard Configuration Report"
    $md += ""
    $md += "Generated: $($Data.Metadata.RetrievedAt)"
    $md += ""
    
    # Executive Summary
    $md += "## Executive Summary"
    $md += ""
    $md += "- **Logic App Name:** $($Data.LogicApp.Name)"
    $md += "- **Resource Group:** $($Data.LogicApp.ResourceGroup)"
    $md += "- **Location:** $($Data.LogicApp.Location)"
    $md += "- **State:** $($Data.LogicApp.State)"
    $md += "- **Workflows Count:** $($Data.Workflows.Count)"
    $md += "- **Connections Count:** $($Data.Connections.Count)"
    $md += ""
    
    # Workflows
    if ($Data.Workflows) {
        $md += "## Workflows"
        $md += ""
        $md += "| Name | State | Created | Modified | Connections |"
        $md += "|------|-------|---------|----------|-------------|"
        
        foreach ($workflow in $Data.Workflows) {
            $connections = if ($workflow.ConnectionReferences) { $workflow.ConnectionReferences -join ', ' } else { 'None' }
            $md += "| $($workflow.Name) | $($workflow.State) | $($workflow.CreatedTime) | $($workflow.ChangedTime) | $connections |"
        }
        $md += ""
    }
    
    # API Connections
    if ($Data.Connections) {
        $md += "## API Connections"
        $md += ""
        $md += "| Name | Type | Status | Test Result |"
        $md += "|------|------|--------|-------------|"
        
        foreach ($conn in $Data.Connections) {
            $md += "| $($conn.Name) | $($conn.Type) | $($conn.Status) | $($conn.TestResult) |"
        }
        $md += ""
    }
    
    # Infrastructure
    if ($Data.Infrastructure) {
        $md += "## Infrastructure"
        $md += ""
        
        if ($Data.Infrastructure.AppServicePlan) {
            $plan = $Data.Infrastructure.AppServicePlan
            $md += "### App Service Plan"
            $md += ""
            $md += "- **Name:** $($plan.Name)"
            $md += "- **Tier:** $($plan.Tier)"
            $md += "- **Size:** $($plan.Size)"
            $md += "- **Capacity:** $($plan.Capacity)"
            $md += ""
        }
        
        if ($Data.Infrastructure.ManagedIdentity) {
            $identity = $Data.Infrastructure.ManagedIdentity
            $md += "### Managed Identity"
            $md += ""
            
            if ($identity.SystemAssigned) {
                $md += "**System Assigned:** Enabled"
                $md += ""
            }
            
            if ($identity.UserAssigned.Count -gt 0) {
                $md += "**User Assigned Identities:** $($identity.UserAssigned.Count)"
                $md += ""
            }
            
            if ($identity.RoleAssignments.Count -gt 0) {
                $md += "**Role Assignments:**"
                $md += ""
                foreach ($role in $identity.RoleAssignments) {
                    $md += "- $($role.Role) at scope: $($role.Scope)"
                }
                $md += ""
            }
        }
    }
    
    # Validation Results
    if ($Data.Validation -and $Data.Validation.Performed) {
        $md += "## Validation Results"
        $md += ""
        
        if ($Data.Validation.Errors.Count -gt 0) {
            $md += "### Errors"
            foreach ($error in $Data.Validation.Errors) {
                $md += "- $error"
            }
            $md += ""
        }
        
        if ($Data.Validation.Warnings.Count -gt 0) {
            $md += "### Warnings"
            foreach ($warning in $Data.Validation.Warnings) {
                $md += "- $warning"
            }
            $md += ""
        }
        
        if ($Data.Validation.Errors.Count -eq 0 -and $Data.Validation.Warnings.Count -eq 0) {
            $md += "✅ All validations passed successfully"
            $md += ""
        }
    }
    
    return $md -join "`n"
}

#endregion

#region Main Script Execution

try {
    # Initialize
    Write-ActionLog "Logic App Standard Details Retrieval Script v$($script:Version)" -Level Info
    Write-ActionLog "Starting retrieval for: $LogicAppStandardName in $ResourceGroupName" -Level Info
    
    # Test Azure connection
    Test-AzureConnection
    
    # Initialize result object
    $result = [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            RetrievedAt = Get-Date
            ScriptVersion = $script:Version
            DetailLevel = $DetailLevel
        }
        LogicApp = $null
        Workflows = @()
        Configuration = $null
        Connections = @()
        Infrastructure = [PSCustomObject]@{
            AppServicePlan = $null
            ManagedIdentity = $null
            Networking = $null
            Slots = @()
        }
        Validation = [PSCustomObject]@{
            Performed = $false
            Results = @()
            Errors = @()
            Warnings = @()
        }
    }
    
    # Get basic Logic App information
    Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting basic information" -PercentComplete 10
    $result.LogicApp = Get-LogicAppBasicInfo -ResourceGroupName $ResourceGroupName -LogicAppName $LogicAppStandardName
    
    # Get workflows based on detail level
    if ($DetailLevel -in @('Detailed', 'Full')) {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting workflow definitions" -PercentComplete 25
        $result.Workflows = Get-WorkflowDefinitions -ResourceGroupName $ResourceGroupName `
            -LogicAppName $LogicAppStandardName -SpecificWorkflow $WorkflowName
    }
    
    # Get configuration
    if ($DetailLevel -in @('Detailed', 'Full')) {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting configuration" -PercentComplete 40
        $result.Configuration = Get-LogicAppConfiguration -ResourceGroupName $ResourceGroupName `
            -LogicAppName $LogicAppStandardName -IncludeSensitive:$IncludeSensitive
    }
    
    # Get API connections if requested
    if ($IncludeConnections -or $DetailLevel -eq 'Full') {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting API connections" -PercentComplete 55
        $result.Connections = Get-ApiConnections -ResourceGroupName $ResourceGroupName `
            -LogicAppName $LogicAppStandardName
    }
    
    # Get App Service Plan details if requested
    if ($IncludeAppServicePlan -or $DetailLevel -eq 'Full') {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting App Service Plan" -PercentComplete 65
        $result.Infrastructure.AppServicePlan = Get-AppServicePlanDetails -ResourceGroupName $ResourceGroupName `
            -LogicAppName $LogicAppStandardName
    }
    
    # Get Managed Identity information if requested
    if ($IncludeManagedIdentity -or $DetailLevel -eq 'Full') {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting Managed Identity" -PercentComplete 75
        $result.Infrastructure.ManagedIdentity = Get-ManagedIdentityInfo -ResourceGroupName $ResourceGroupName `
            -LogicAppName $LogicAppStandardName
    }
    
    # Get Network configuration if requested
    if ($IncludeNetworking -or $DetailLevel -eq 'Full') {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting network configuration" -PercentComplete 85
        $result.Infrastructure.Networking = Get-NetworkConfiguration -ResourceGroupName $ResourceGroupName `
            -LogicAppName $LogicAppStandardName
    }
    
    # Get deployment slots if requested
    if ($IncludeSlots) {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Getting deployment slots" -PercentComplete 90
        
        try {
            $slots = Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $LogicAppStandardName -ErrorAction Stop
            
            foreach ($slot in $slots) {
                $result.Infrastructure.Slots += [PSCustomObject]@{
                    Name = $slot.Name
                    State = $slot.State
                    DefaultHostName = $slot.DefaultHostName
                    LastModifiedTime = $slot.LastModifiedTimeUtc
                }
            }
            
            Write-ActionLog "Found $($slots.Count) deployment slot(s)" -Level Success
        }
        catch {
            Write-ActionLog "Could not retrieve deployment slots: $_" -Level Warning
        }
    }
    
    # Validate workflows if requested
    if ($ValidateWorkflows -and $result.Workflows.Count -gt 0) {
        Write-Progress -Activity "Retrieving Logic App Details" -Status "Validating workflows" -PercentComplete 95
        
        $validationResults = Test-WorkflowConfiguration -Workflows $result.Workflows -Connections $result.Connections
        $result.Validation.Performed = $true
        $result.Validation.Results = $validationResults
        
        # Aggregate errors and warnings
        foreach ($validation in $validationResults) {
            foreach ($validationError in $validation.Errors) {
                $result.Validation.Errors += "$($validation.WorkflowName): $validationError"
            }
            foreach ($validationWarning in $validation.Warnings) {
                $result.Validation.Warnings += "$($validation.WorkflowName): $validationWarning"
            }
        }
    }
    
    Write-Progress -Activity "Retrieving Logic App Details" -Completed
    
    # Export results if path provided
    if ($ExportPath) {
        if ($PSCmdlet.ShouldProcess($ExportPath, "Export Logic App configuration")) {
            Export-Results -Data $result -Path $ExportPath -GenerateMarkdown:$GenerateMarkdown
        }
    }
    
    # Display summary
    Write-Host ""
    Write-Host "================== Retrieval Summary ==================" -ForegroundColor Cyan
    Write-Host "Logic App:          $($result.LogicApp.Name)" -ForegroundColor Green
    Write-Host "Resource Group:     $($result.LogicApp.ResourceGroup)" -ForegroundColor Green
    Write-Host "Workflows:          $(if ($result.Workflows) { $result.Workflows.Count } else { 0 })" -ForegroundColor Green
    Write-Host "Connections:        $(if ($result.Connections) { $result.Connections.Count } else { 0 })" -ForegroundColor Green
    Write-Host "Detail Level:       $DetailLevel" -ForegroundColor Green
    
    if ($result.Validation.Performed) {
        Write-Host "Validation Errors:  $($result.Validation.Errors.Count)" -ForegroundColor $(if ($result.Validation.Errors.Count -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Validation Warnings: $($result.Validation.Warnings.Count)" -ForegroundColor $(if ($result.Validation.Warnings.Count -gt 0) { 'Yellow' } else { 'Green' })
    }
    
    Write-Host "Execution Time:     $([Math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)) seconds" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Cyan
    
    # Output result object for pipeline consumption
    Write-Output $result
}
catch {
    $errorDetails = $_
    Write-ActionLog "Script execution failed: $($errorDetails.Exception.Message)" -Level Error
    Write-Error $errorDetails
    throw
}
finally {
    # Cleanup
    Write-ActionLog "Script execution completed" -Level Verbose
}

#endregion