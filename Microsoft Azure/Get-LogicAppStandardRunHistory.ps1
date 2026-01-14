#Requires -Version 7.0
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Retrieves Azure Logic App Standard workflow run history with filtering and export capabilities.

.DESCRIPTION
    This script fetches Logic App Standard workflow run history from Azure using the Management REST API.
    It supports filtering by status and date range, handles pagination automatically,
    and provides options for exporting results to CSV or JSON formats.
    
    Key capabilities include:
    - List all workflows in a Standard Logic App
    - Basic run information (status, timing, correlation data)
    - Detailed action information with inputs/outputs for specific or all actions
    - Complete trigger output data from trigger history API
    - Flexible filtering by status, date range, and specific action names
    - Automatic handling of large payloads via content links
    - Export functionality to CSV or JSON formats

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Logic App Standard.
    If not specified, uses the current Azure context.

.PARAMETER ResourceGroupName
    The name of the Azure resource group containing the Logic App Standard. (Mandatory)

.PARAMETER LogicAppStandardName
    The name of the Logic App Standard instance. (Mandatory)

.PARAMETER WorkflowName
    The name of the specific workflow within the Logic App Standard.
    If not specified, lists all workflows and prompts for selection.

.PARAMETER Status
    Filter runs by status. Valid values: 'Succeeded', 'Failed', 'Running', 
    'Cancelled', 'Skipped', 'Suspended', 'Aborted', 'TimedOut', 'Faulted'.
    If not specified, returns runs of all statuses.

.PARAMETER StartTime
    Filter runs that started after this date/time.
    Defaults to 7 days ago.

.PARAMETER EndTime
    Filter runs that started before this date/time.
    Defaults to current time.

.PARAMETER MaxResults
    Maximum number of results to return. Default is 1000.
    Set to 0 for unlimited.

.PARAMETER MostRecent
    Retrieve only the most recent run. Overrides MaxResults.

.PARAMETER ExportPath
    Optional path to export results. Extension determines format:
    .csv for CSV export, .json for JSON export.

.PARAMETER IncludeActionDetails
    Include detailed action information for each run (steps executed, status, timing).
    This increases execution time as it requires additional API calls per run.

.PARAMETER IncludeInputsOutputs
    Include the input and output data for each action and trigger inputs.
    When used with -IncludeActionDetails, includes action inputs/outputs.
    Always includes trigger inputs regardless of other parameters.
    Warning: This can result in very large data sets.

.PARAMETER IncludeTriggerOutputs
    Include the complete trigger output data (headers and body) from the trigger history API.
    This provides the same rich trigger data visible in Azure portal's "Show raw outputs".
    Warning: Requires additional API calls per run and can result in large data sets.

.PARAMETER ActionNames
    Filter to only retrieve specific action names. Accepts an array of action names.
    When specified, only these actions will be included in the results.
    Automatically enables -IncludeActionDetails.
    Names can be specified with spaces (as shown in the Azure Portal GUI) or with
    underscores (as used in the backend). Spaces are automatically converted to underscores.

.PARAMETER RequireSucceededActions
    Only include runs where the specified action(s) exist AND succeeded.
    Accepts an array of action names. Runs where any of these actions are missing
    or did not succeed will be excluded from the output.
    Names can be specified with spaces (as shown in the Azure Portal GUI) or with
    underscores (as used in the backend). Spaces are automatically converted to underscores.
    Automatically enables -IncludeActionDetails.

.PARAMETER ListWorkflows
    Lists all workflows in the Logic App Standard without retrieving run history.

.PARAMETER NonInteractive
    Run in non-interactive mode. When multiple workflows are available and no WorkflowName 
    is specified, the script will fail instead of prompting for selection.

.EXAMPLE
    .\Get-LogicAppStandardRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppStandardName "MyLogicAppStandard" -ListWorkflows
    
    Lists all workflows in the Logic App Standard instance.

.EXAMPLE
    .\Get-LogicAppStandardRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppStandardName "MyLogicAppStandard" -WorkflowName "MyWorkflow"
    
    Retrieves the last 7 days of run history for the specified workflow.

.EXAMPLE
    .\Get-LogicAppStandardRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppStandardName "MyLogicAppStandard" -WorkflowName "MyWorkflow" -MostRecent -IncludeActionDetails -IncludeInputsOutputs
    
    Retrieves the most recent run with full details including all action inputs and outputs.

.EXAMPLE
    .\Get-LogicAppStandardRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppStandardName "MyLogicAppStandard" -WorkflowName "MyWorkflow" -Status "Failed" -StartTime "2025-08-01"
    
    Retrieves only failed runs since August 1st, 2025.

.OUTPUTS
    System.Object[]
    Returns an array of custom objects with run history details.

.NOTES
    Version:        2.0.1
    Author:         Daniel Streefkerk
    Creation Date:  06 August 2025
    Last Modified:  14 January 2026
    Purpose:        Azure Logic App Standard workflow run history extraction
    
    Prerequisites:
    - PowerShell 7.0 or higher
    - Az.Accounts module installed and imported
    - Authenticated to Azure using Connect-AzAccount
    - Contributor or Logic App Contributor role on the Logic App Standard resource
    
    Performance Considerations:
    - Basic run retrieval is fast and lightweight
    - -IncludeActionDetails requires additional API calls (one per run)
    - -IncludeTriggerOutputs requires additional API calls (one per run)
    - -IncludeInputsOutputs can result in very large data sets
    - Use -ActionNames to filter and improve performance when possible
    - Large trigger outputs are automatically handled via content links
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogicAppStandardName,

    [Parameter()]
    [string]$WorkflowName,

    [Parameter()]
    [ValidateSet('Succeeded', 'Failed', 'Running', 'Cancelled', 'Skipped', 'Suspended', 'Aborted', 'TimedOut', 'Faulted', IgnoreCase = $true)]
    [string]$Status,

    [Parameter()]
    [ValidateScript({
        if ($_ -is [DateTime]) { return $true }
        try { [DateTime]::Parse($_); return $true }
        catch { throw "Invalid date format" }
    })]
    $StartTime = (Get-Date).AddDays(-7),

    [Parameter()]
    [ValidateScript({
        if ($_ -is [DateTime]) { return $true }
        try { [DateTime]::Parse($_); return $true }
        catch { throw "Invalid date format" }
    })]
    $EndTime = (Get-Date),

    [Parameter()]
    [ValidateRange(0, [uint32]::MaxValue)]
    [uint32]$MaxResults = 1000,

    [Parameter()]
    [switch]$MostRecent,

    [Parameter()]
    [ValidateScript({
        $extension = [System.IO.Path]::GetExtension($_).ToLower()
        if ($extension -notin @('.csv', '.json')) {
            throw "Export file must have .csv or .json extension"
        }
        $parent = Split-Path $_ -Parent
        if ($parent -and !(Test-Path $parent)) {
            throw "Parent directory does not exist: $parent"
        }
        return $true
    })]
    [string]$ExportPath,

    [Parameter()]
    [switch]$IncludeActionDetails,

    [Parameter()]
    [switch]$IncludeInputsOutputs,

    [Parameter()]
    [switch]$IncludeTriggerOutputs,

    [Parameter()]
    [string[]]$ActionNames,

    [Parameter()]
    [string[]]$RequireSucceededActions,

    [Parameter()]
    [switch]$ListWorkflows,

    [Parameter()]
    [switch]$NonInteractive
)

#region Functions

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

function Get-AzureAccessToken {
    [CmdletBinding()]
    param()
    
    try {
        $context = Get-AzContext
        if (-not $context) {
            throw "No Azure context found. Please run Connect-AzAccount first."
        }
        
        Write-Verbose "Using context: $($context.Account.Id)"
        
        # Get token - handle both Az module versions
        $tokenInfo = Get-AzAccessToken -ResourceUrl "https://management.azure.com" -ErrorAction Stop
        
        if ($tokenInfo.Token -is [System.Security.SecureString]) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenInfo.Token)
            $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        else {
            $token = $tokenInfo.Token
        }
        
        Write-Verbose "Access token obtained (expires: $($tokenInfo.ExpiresOn))"
        return $token
    }
    catch {
        throw "Failed to obtain Azure access token: $_"
    }
}

function Get-LogicAppStandardWorkflows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseUri
    )
    
    try {
        # List workflows endpoint for Standard Logic Apps
        $workflowsUri = "$BaseUri/workflows?api-version=2018-11-01"
        Write-Verbose "Fetching workflows from: $workflowsUri"
        
        $response = Invoke-RestMethod -Uri $workflowsUri -Headers $Headers -Method Get -ErrorAction Stop
        
        if (-not $response.value) {
            Write-Warning "No workflows found in Logic App Standard"
            return @()
        }
        
        # Use efficient foreach output capture pattern
        $workflows = foreach ($workflow in $response.value) {
            # Extract just the workflow name (remove the Logic App prefix if present)
            $workflowName = if ($workflow.name -match '/([^/]+)$') {
                $matches[1]
            } else {
                $workflow.name
            }

            [PSCustomObject]@{
                Name         = $workflowName
                Id           = $workflow.id
                Type         = $workflow.type
                State        = Get-SafeProperty -Object $workflow -PropertyPath 'properties.flowState'
                Version      = Get-SafeProperty -Object $workflow -PropertyPath 'properties.version'
                CreatedTime  = Get-SafeProperty -Object $workflow -PropertyPath 'properties.createdTime'
                ChangedTime  = Get-SafeProperty -Object $workflow -PropertyPath 'properties.changedTime'
                AccessEndpoint = Get-SafeProperty -Object $workflow -PropertyPath 'properties.accessEndpoint'
            }
        }
        
        return $workflows
    }
    catch {
        throw "Failed to retrieve workflows: $_"
    }
}

function Get-WorkflowRuns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseUri,
        
        [Parameter()]
        [string]$Status,
        
        [Parameter()]
        [DateTime]$StartTime,
        
        [Parameter()]
        [uint32]$MaxResults = 1000
    )
    
    try {
        # Build the runs endpoint for Standard Logic Apps
        # Using the hostruntime API endpoint
        $runsUri = "$BaseUri/hostruntime/runtime/webhooks/workflow/api/management/workflows/$WorkflowName/runs?api-version=2018-11-01&`$top=50"
        
        # Add filter for status if specified
        if ($Status) {
            $runsUri += "&`$filter=status eq '$Status'"
        }
        
        # Add date filter
        if ($StartTime) {
            $startTimeUtc = $StartTime.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            if ($Status) {
                $runsUri += " and startTime ge $startTimeUtc"
            }
            else {
                $runsUri += "&`$filter=startTime ge $startTimeUtc"
            }
        }
        
        Write-Verbose "Fetching runs from: $runsUri"
        
        $allRuns = @()
        $runCount = 0
        $pageCount = 0
        $nextLink = $runsUri
        
        while ($nextLink -and ($MaxResults -eq 0 -or $runCount -lt $MaxResults)) {
            $pageCount++
            Write-Verbose "Fetching page $pageCount"
            
            $response = Invoke-RestMethod -Uri $nextLink -Headers $Headers -Method Get -ErrorAction Stop
            
            if ($response.value) {
                $runsToAdd = $response.value
                
                # Limit results if MaxResults specified
                if ($MaxResults -gt 0) {
                    $remaining = $MaxResults - $runCount
                    if ($runsToAdd.Count -gt $remaining) {
                        $runsToAdd = $runsToAdd[0..($remaining - 1)]
                    }
                }
                
                $allRuns = $allRuns + $runsToAdd  # More efficient than += for arrays
                $runCount += $runsToAdd.Count
                
                Write-Verbose "Retrieved $($runsToAdd.Count) runs (total: $runCount)"
            }
            
            # Check if there's a next page
            $nextLink = if ($response.PSObject.Properties['nextLink']) {
                $response.nextLink
            } else {
                $null
            }
        }
        
        return $allRuns
    }
    catch {
        throw "Failed to retrieve runs: $_"
    }
}

function Get-RunActions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowName,

        [Parameter(Mandatory = $true)]
        [string]$RunId,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$BaseUri,

        [Parameter()]
        [switch]$IncludeInputsOutputs,

        [Parameter()]
        [string[]]$ActionNames
    )
    
    try {
        # Actions endpoint for Standard Logic Apps
        $actionsUri = "$BaseUri/hostruntime/runtime/webhooks/workflow/api/management/workflows/$WorkflowName/runs/$RunId/actions?api-version=2018-11-01"
        Write-Verbose "Fetching actions for run: $RunId"

        # Fetch all pages of actions (API paginates at ~30 actions)
        $allActionData = @()
        $nextLink = $actionsUri
        $pageCount = 0

        while ($nextLink) {
            $pageCount++
            $response = Invoke-RestMethod -Uri $nextLink -Headers $Headers -Method Get -ErrorAction Stop

            if ($response.value) {
                $allActionData += $response.value
            }

            # Check for next page
            $nextLink = if ($response.PSObject.Properties['nextLink']) { $response.nextLink } else { $null }
            if ($nextLink) {
                Write-Verbose "Fetching actions page $($pageCount + 1) for run: $RunId"
            }
        }

        if ($allActionData.Count -eq 0) {
            return @()
        }

        Write-Verbose "Retrieved $($allActionData.Count) total actions across $pageCount page(s)"

        # Use efficient foreach output capture pattern, wrapped in @() to ensure array even when empty
        $actions = @(foreach ($action in $allActionData) {
            # Filter by action name if specified
            if ($ActionNames -and $action.name -notin $ActionNames) {
                Write-Verbose "Skipping action '$($action.name)' - not in filter list"
                continue
            }
            
            Write-Verbose "Processing action: $($action.name)"
            
            $actionObject = [PSCustomObject]@{
                Name         = $action.name
                Type         = Get-SafeProperty -Object $action -PropertyPath 'properties.type'
                Status       = Get-SafeProperty -Object $action -PropertyPath 'properties.status'
                Code         = Get-SafeProperty -Object $action -PropertyPath 'properties.code'
                StartTime    = Get-SafeProperty -Object $action -PropertyPath 'properties.startTime'
                EndTime      = Get-SafeProperty -Object $action -PropertyPath 'properties.endTime'
                Duration     = if ($action.properties.startTime -and $action.properties.endTime) {
                    try {
                        ([DateTime]$action.properties.endTime - [DateTime]$action.properties.startTime).TotalSeconds
                    }
                    catch { $null }
                } else { $null }
                Error        = Get-SafeProperty -Object $action -PropertyPath 'properties.error'
            }
            
            # Include inputs/outputs if requested
            if ($IncludeInputsOutputs) {
                # Get the direct inputs/outputs first
                $inputs = Get-SafeProperty -Object $action -PropertyPath 'properties.inputs'
                $outputs = Get-SafeProperty -Object $action -PropertyPath 'properties.outputs'

                # Check for content links and override if they exist
                $inputsLinkUri = Get-SafeProperty -Object $action -PropertyPath 'properties.inputsLink.uri'
                if ($inputsLinkUri) {
                    try {
                        Write-Verbose "Fetching input content for action: $($action.name)"
                        # Content links have their own SAS auth, don't pass headers
                        $inputs = Invoke-RestMethod -Uri $inputsLinkUri -Method Get -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Could not fetch input content: $_"
                    }
                }

                $outputsLinkUri = Get-SafeProperty -Object $action -PropertyPath 'properties.outputsLink.uri'
                if ($outputsLinkUri) {
                    try {
                        Write-Verbose "Fetching output content for action: $($action.name)"
                        # Content links have their own SAS auth, don't pass headers
                        $outputs = Invoke-RestMethod -Uri $outputsLinkUri -Method Get -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Could not fetch output content: $_"
                    }
                }

                # Add the inputs/outputs to the action object
                $actionObject | Add-Member -NotePropertyName Inputs -NotePropertyValue $inputs
                $actionObject | Add-Member -NotePropertyName Outputs -NotePropertyValue $outputs
            }
            
            # Output the action object
            $actionObject
        })

        if ($ActionNames) {
            Write-Verbose "Found $($actions.Count) of $($ActionNames.Count) requested actions: $($ActionNames -join ', ')"
        }
        
        return $actions
    }
    catch {
        Write-Warning "Failed to retrieve actions for run $RunId : $_"
        return @()
    }
}

function Get-TriggerHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowName,
        
        [Parameter(Mandatory = $true)]
        [string]$TriggerName,
        
        [Parameter(Mandatory = $true)]
        [string]$RunId,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseUri
    )
    
    try {
        # Trigger history endpoint for Standard Logic Apps
        $triggerHistoryUri = "$BaseUri/hostruntime/runtime/webhooks/workflow/api/management/workflows/$WorkflowName/triggers/$TriggerName/histories/${RunId}?api-version=2018-11-01"
        Write-Verbose "Fetching trigger history for run: $RunId"
        
        $response = Invoke-RestMethod -Uri $triggerHistoryUri -Headers $Headers -Method Get -ErrorAction Stop
        
        if (-not $response.properties) {
            Write-Verbose "No trigger history properties found"
            return $null
        }
        
        # Extract trigger outputs (this should contain headers and body)
        $triggerOutputs = Get-SafeProperty -Object $response -PropertyPath 'properties.outputs'
        
        # Check for content links for large trigger outputs
        $triggerOutputsLinkUri = Get-SafeProperty -Object $response -PropertyPath 'properties.outputsLink.uri'
        if ($triggerOutputsLinkUri) {
            try {
                Write-Verbose "Fetching trigger output content from content link"
                # Content links have their own SAS auth, don't pass headers
                $triggerOutputs = Invoke-RestMethod -Uri $triggerOutputsLinkUri -Method Get -ErrorAction Stop
            }
            catch {
                Write-Verbose "Could not fetch trigger output content: $_"
            }
        }
        
        return $triggerOutputs
    }
    catch {
        Write-Warning "Failed to retrieve trigger history for run $RunId : $_"
        return $null
    }
}

function Export-RunData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$RunData,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    $extension = [System.IO.Path]::GetExtension($Path).ToLower()
    
    try {
        switch ($extension) {
            '.csv' {
                $RunData | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Information "Exported $($RunData.Count) runs to CSV: $Path" -InformationAction Continue
            }
            '.json' {
                $RunData | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -ErrorAction Stop
                Write-Information "Exported $($RunData.Count) runs to JSON: $Path" -InformationAction Continue
            }
        }
    }
    catch {
        throw "Failed to export data: $_"
    }
}

#endregion

#region Main Script

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Information "Starting Logic App Standard run history retrieval" -InformationAction Continue

try {
    # Get access token
    Write-Verbose "Obtaining Azure access token"
    $token = Get-AzureAccessToken
    
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    
    # Get subscription ID if not provided
    if (-not $SubscriptionId) {
        $context = Get-AzContext
        $SubscriptionId = $context.Subscription.Id
        Write-Verbose "Using subscription: $($context.Subscription.Name)"
    }
    
    # Build base API URI for Logic App Standard (Microsoft.Web/sites)
    $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId"
    $baseUri += "/resourceGroups/$ResourceGroupName"
    $baseUri += "/providers/Microsoft.Web/sites/$LogicAppStandardName"
    
    # If ListWorkflows flag is set, just list workflows and exit
    if ($ListWorkflows) {
        Write-Information "Listing workflows in Logic App Standard: $LogicAppStandardName" -InformationAction Continue
        $workflows = Get-LogicAppStandardWorkflows -Headers $headers -BaseUri $baseUri
        
        if ($workflows.Count -eq 0) {
            Write-Information "No workflows found in Logic App Standard" -InformationAction Continue
        }
        else {
            Write-Information "Found $($workflows.Count) workflow(s):" -InformationAction Continue
        }
        
        return $workflows
    }
    
    # If no workflow name specified, get list and prompt
    if (-not $WorkflowName) {
        Write-Information "No workflow specified. Fetching available workflows..." -InformationAction Continue
        $workflows = Get-LogicAppStandardWorkflows -Headers $headers -BaseUri $baseUri
        
        if ($workflows.Count -eq 0) {
            throw "No workflows found in Logic App Standard: $LogicAppStandardName"
        }
        elseif ($workflows.Count -eq 1) {
            $WorkflowName = $workflows[0].Name
            Write-Information "Using the only available workflow: $WorkflowName" -InformationAction Continue
        }
        else {
            if ($NonInteractive) {
                $workflowNames = $workflows | ForEach-Object { $_.Name }
                throw "Multiple workflows found but no WorkflowName specified in non-interactive mode. Available workflows: $($workflowNames -join ', '). Please specify -WorkflowName parameter."
            }
            
            Write-Information "Available workflows:" -InformationAction Continue
            for ($i = 0; $i -lt $workflows.Count; $i++) {
                Write-Information "$($i + 1). $($workflows[$i].Name) (State: $($workflows[$i].State))" -InformationAction Continue
            }
            
            do {
                $selection = Read-Host "Select workflow number (1-$($workflows.Count))"
                $selectedIndex = [int]$selection - 1
            } while ($selectedIndex -lt 0 -or $selectedIndex -ge $workflows.Count)
            
            $WorkflowName = $workflows[$selectedIndex].Name
            Write-Information "Selected workflow: $WorkflowName" -InformationAction Continue
        }
    }
    
    # Validate dates
    if ($StartTime -ge $EndTime) {
        throw "StartTime must be earlier than EndTime"
    }
    
    # Convert to DateTime if needed
    if ($StartTime -is [string]) {
        $StartTime = [DateTime]::Parse($StartTime)
    }
    if ($EndTime -is [string]) {
        $EndTime = [DateTime]::Parse($EndTime)
    }
    
    # Override MaxResults if MostRecent is specified
    if ($MostRecent) {
        $MaxResults = 1
        Write-Verbose "MostRecent specified - limiting to 1 result"
    }

    # Normalize action names: convert spaces to underscores (GUI format to backend format)
    if ($ActionNames) {
        $ActionNames = $ActionNames | ForEach-Object { $_ -replace ' ', '_' }
        Write-Verbose "Normalized ActionNames filter: $($ActionNames -join ', ')"
    }
    if ($RequireSucceededActions) {
        $RequireSucceededActions = $RequireSucceededActions | ForEach-Object { $_ -replace ' ', '_' }
        Write-Verbose "Normalized RequireSucceededActions filter: $($RequireSucceededActions -join ', ')"
    }
    
    # Retrieve runs
    Write-Information "Retrieving runs for workflow: $WorkflowName" -InformationAction Continue
    
    if ($PSCmdlet.ShouldProcess("Azure Management API", "Query Logic App Standard workflow runs")) {
        $allRuns = Get-WorkflowRuns -WorkflowName $WorkflowName -Headers $headers -BaseUri $baseUri -Status $Status -StartTime $StartTime -MaxResults $MaxResults
        
        Write-Information "Retrieved $($allRuns.Count) runs" -InformationAction Continue
        
        if ($allRuns.Count -eq 0) {
            Write-Information "No runs found matching the criteria" -InformationAction Continue
            
            if ($ExportPath) {
                Export-RunData -RunData @() -Path $ExportPath
            }
            return @()
        }
        
        # Process runs into objects using efficient foreach pattern, wrapped in @() to ensure array even when empty
        Write-Verbose "Processing run data"
        $processedRuns = @(foreach ($run in $allRuns) {
            # Filter by EndTime if specified (API doesn't support this)
            # Note: API returns UTC times, but EndTime parameter is in local time
            if ($EndTime) {
                $runStartTime = if ($run.properties.startTime) {
                    try { ([DateTime]$run.properties.startTime).ToLocalTime() } catch { $null }
                } else { $null }

                if ($runStartTime -and $runStartTime -gt $EndTime) {
                    continue
                }
            }
            
            # Create output object
            $runStartTimeRaw = Get-SafeProperty -Object $run -PropertyPath 'properties.startTime'
            $runEndTimeRaw = Get-SafeProperty -Object $run -PropertyPath 'properties.endTime'

            # Calculate duration if both times exist
            $duration = if ($runStartTimeRaw -and $runEndTimeRaw) {
                try { ([DateTime]$runEndTimeRaw - [DateTime]$runStartTimeRaw).TotalSeconds } catch { $null }
            } else { $null }

            $runObject = [PSCustomObject]@{
                RunId        = $run.name
                WorkflowName = $WorkflowName
                Status       = Get-SafeProperty -Object $run -PropertyPath 'properties.status'
                StartTime    = $runStartTimeRaw ? ([DateTime]$runStartTimeRaw).ToLocalTime() : $null
                EndTime      = $runEndTimeRaw ? ([DateTime]$runEndTimeRaw).ToLocalTime() : $null
                Duration     = $duration
                TriggerName  = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.name'
                TriggerTime  = if ($triggerTime = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.startTime') {
                    try { ([DateTime]$triggerTime).ToLocalTime() } catch { $null }
                } else { $null }
                ErrorCode    = Get-SafeProperty -Object $run -PropertyPath 'properties.error.code'
                ErrorMessage = Get-SafeProperty -Object $run -PropertyPath 'properties.error.message'
                Correlation  = Get-SafeProperty -Object $run -PropertyPath 'properties.correlation'
            }
            
            # Get action details if requested, specific actions requested, or need to check required succeeded actions
            if ($IncludeActionDetails -or $ActionNames -or $RequireSucceededActions) {
                Write-Verbose "Fetching action details for run: $($run.name)"

                # Calculate which actions to fetch - union of ActionNames and RequireSucceededActions (only fetch what we need)
                $actionNamesToFetch = if ($ActionNames -or $RequireSucceededActions) {
                    @(($ActionNames + $RequireSucceededActions) | Where-Object { $_ } | Select-Object -Unique)
                } else {
                    $null  # Fetch all if just -IncludeActionDetails
                }

                $allActions = Get-RunActions -WorkflowName $WorkflowName -RunId $run.name -Headers $headers -BaseUri $baseUri -IncludeInputsOutputs:$IncludeInputsOutputs -ActionNames $actionNamesToFetch

                # Check RequireSucceededActions filter - skip run if required actions don't exist or didn't succeed
                if ($RequireSucceededActions) {
                    $missingOrFailed = @()
                    foreach ($requiredAction in $RequireSucceededActions) {
                        $matchedAction = $allActions | Where-Object { $_.Name -eq $requiredAction }
                        if (-not $matchedAction) {
                            $missingOrFailed += "$requiredAction (missing)"
                        }
                        elseif ($matchedAction.Status -ne 'Succeeded') {
                            $missingOrFailed += "$requiredAction (status: $($matchedAction.Status))"
                        }
                    }

                    if ($missingOrFailed.Count -gt 0) {
                        Write-Verbose "Skipping run $($run.name) - required actions not succeeded: $($missingOrFailed -join ', ')"
                        continue
                    }
                }

                # Apply ActionNames filter for display if specified
                $actions = if ($ActionNames) {
                    @($allActions | Where-Object { $_.Name -in $ActionNames })
                } else {
                    $allActions
                }

                if ($actions) {
                    $runObject | Add-Member -NotePropertyName Actions -NotePropertyValue $actions
                    $runObject | Add-Member -NotePropertyName ActionCount -NotePropertyValue $actions.Count
                    $runObject | Add-Member -NotePropertyName FailedActions -NotePropertyValue (
                        @($actions | Where-Object { $_.Status -eq 'Failed' }).Count
                    )
                }
            }
            
            # Get trigger inputs if requested
            if ($IncludeInputsOutputs -and $run.properties.trigger) {
                $triggerInputs = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.inputs'
                
                # Check for content links (large payloads are stored separately)
                $triggerInputsLinkUri = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.inputsLink.uri'
                if ($triggerInputsLinkUri) {
                    try {
                        Write-Verbose "Fetching trigger input content"
                        # Content links have their own SAS auth, don't pass headers
                        $triggerInputs = Invoke-RestMethod -Uri $triggerInputsLinkUri -Method Get -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Could not fetch trigger input content: $_"
                    }
                }
                
                $runObject | Add-Member -NotePropertyName TriggerInputs -NotePropertyValue $triggerInputs
            }
            
            # Get rich trigger outputs (headers and body) if requested
            if ($IncludeTriggerOutputs -and $run.properties.trigger) {
                $triggerName = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.name'
                if ($triggerName) {
                    Write-Verbose "Fetching trigger history for run: $($run.name)"
                    $triggerHistoryOutputs = Get-TriggerHistory -WorkflowName $WorkflowName -TriggerName $triggerName -RunId $run.name -Headers $headers -BaseUri $baseUri
                    
                    if ($triggerHistoryOutputs) {
                        $runObject | Add-Member -NotePropertyName TriggerOutputs -NotePropertyValue $triggerHistoryOutputs
                    }
                }
            }
            
            # Output the run object
            $runObject
        })

        Write-Information "Processed $($processedRuns.Count) runs" -InformationAction Continue
        
        # Generate summary
        $statusGroups = $processedRuns | Group-Object Status | Select-Object Name, Count
        foreach ($group in $statusGroups) {
            Write-Information "$($group.Name): $($group.Count) runs" -InformationAction Continue
        }
        
        # Export if requested
        if ($ExportPath -and $PSCmdlet.ShouldProcess($ExportPath, "Export run data")) {
            Export-RunData -RunData $processedRuns -Path $ExportPath
        }
        
        # Output results
        Write-Output $processedRuns
    }
}
catch {
    Write-Error "Script failed: $_"
    throw
}
finally {
    Write-Information "Script completed" -InformationAction Continue
}

#endregion