#Requires -Version 7.0
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Retrieves Azure Logic App run history with filtering and export capabilities.

.DESCRIPTION
    This script fetches Logic App run history from Azure using the Management REST API.
    It supports filtering by status and date range, handles pagination automatically,
    and provides options for exporting results to CSV or JSON formats.
    
    Key capabilities include:
    - Basic run information (status, timing, correlation data)
    - Detailed action information with inputs/outputs for specific or all actions
    - Complete trigger output data (headers and body) from trigger history API
    - Flexible filtering by status, date range, and specific action names
    - Automatic handling of large payloads via content links
    - Export functionality to CSV or JSON formats

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Logic App.
    If not specified, uses the current Azure context.

.PARAMETER ResourceGroupName
    The name of the Azure resource group containing the Logic App. (Mandatory)

.PARAMETER LogicAppName
    The name of the Logic App to query. (Mandatory)

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
    Use this parameter to reduce data volume and improve performance when you only need specific actions.

.EXAMPLE
    .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -ActionNames "Check_if_hostname_exists"
    
    Retrieves runs and only includes the "Check_if_hostname_exists" action in the results.

.EXAMPLE
    .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -ActionNames @("Action1", "Action2") -IncludeInputsOutputs
    
    Retrieves runs with only specific actions and their inputs/outputs.

.EXAMPLE
    .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -MostRecent
    
    Retrieves only the most recent run.

.EXAMPLE
    .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -MostRecent -IncludeActionDetails -IncludeInputsOutputs
    
    Retrieves the most recent run with full details including all action inputs and outputs.

.EXAMPLE
    .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp"
    
    Retrieves the last 7 days of run history for the specified Logic App.

.EXAMPLE
    $runs = .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -IncludeActionDetails -IncludeInputsOutputs
    $runs[0] | ConvertTo-Json -Depth 10
    
    Retrieves run history with full action details including inputs and outputs for each step.

.EXAMPLE
    $runs = .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -IncludeTriggerOutputs
    $runs[0].TriggerOutputs.headers
    $runs[0].TriggerOutputs.body
    
    Retrieves run history with complete trigger output data (headers and body) and accesses the trigger request details.

.EXAMPLE
    .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -Status "Failed" -StartTime "2025-08-01" -EndTime "2025-08-06"
    
    Retrieves only failed runs between specific dates.

.EXAMPLE
    .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -ExportPath "C:\temp\runs.json" -MaxResults 500
    
    Retrieves up to 500 runs and exports them to JSON format.

.EXAMPLE
    $runs = .\Get-LogicAppRunHistory.ps1 -ResourceGroupName "MyRG" -LogicAppName "MyLogicApp" -IncludeTriggerOutputs -IncludeActionDetails -IncludeInputsOutputs
    $runs | Where-Object { $_.Status -eq 'Failed' } | Select-Object RunId, StartTime, TriggerName, FailedActions
    
    Comprehensive data retrieval with filtering for failed runs and custom output formatting.

.OUTPUTS
    System.Object[]
    Returns an array of custom objects with the following properties:
    
    Basic Properties (always included):
    - RunId: Unique identifier for the run
    - Status: Run status (Succeeded, Failed, Running, etc.)
    - StartTime: When the run started (DateTime)
    - EndTime: When the run completed (DateTime)
    - Duration: Run duration in seconds
    - TriggerName: Name of the trigger that started the run
    - TriggerTime: When the trigger fired (DateTime)
    - ErrorCode: Error code if the run failed
    - ErrorMessage: Error message if the run failed
    - Correlation: Correlation information for tracking
    
    Optional Properties (included when respective parameters are used):
    - Actions: Array of action objects (when -IncludeActionDetails or -ActionNames specified)
    - ActionCount: Number of actions in the run (when actions included)
    - FailedActions: Number of failed actions (when actions included)
    - TriggerInputs: Trigger input data (when -IncludeInputsOutputs specified)
    - TriggerOutputs: Complete trigger output with headers and body (when -IncludeTriggerOutputs specified)

.NOTES
    Version:        1.1.0
    Author:         Daniel Streefkerk
    Creation Date:  06 August 2025
    Purpose:        Azure Logic App run history extraction
    
    Prerequisites:
    - PowerShell 7.0 or higher
    - Az.Accounts module installed and imported
    - Authenticated to Azure using Connect-AzAccount
    - Contributor or Logic App Contributor role on the Logic App resource
    
    Performance Considerations:
    - Basic run retrieval is fast and lightweight
    - -IncludeActionDetails requires additional API calls (one per run)
    - -IncludeTriggerOutputs requires additional API calls (one per run)
    - -IncludeInputsOutputs can result in very large data sets
    - Use -ActionNames to filter and improve performance when possible
    - Large trigger outputs are automatically handled via content links
    
    Best Practices:
    - Use date filters to limit the scope of data retrieval
    - Specify -MaxResults to prevent excessive data retrieval
    - Use -MostRecent for quick troubleshooting of recent issues
    - Export large datasets to files rather than displaying in console
    - Consider using -ActionNames to focus on specific actions of interest
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
    [string]$LogicAppName,

    [Parameter()]
    [ValidateSet('Succeeded', 'Failed', 'Running', 'Cancelled', 'Skipped', 'Suspended', 'Aborted', 'TimedOut', 'Faulted')]
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
    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaxResults = 1000,

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
    [string[]]$ActionNames
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

function Get-RunActions {
    [CmdletBinding()]
    param(
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
        $actionsUri = "$BaseUri/runs/$RunId/actions?api-version=2019-05-01"
        Write-Verbose "Fetching actions for run: $RunId"
        
        $response = Invoke-RestMethod -Uri $actionsUri -Headers $Headers -Method Get -ErrorAction Stop
        
        if (-not $response.value) {
            return @()
        }
        
        $actions = @()
        foreach ($action in $response.value) {
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
            
            $actions += $actionObject
        }
        
        if ($ActionNames) {
            Write-Verbose "Filtered to $($actions.Count) actions matching: $($ActionNames -join ', ')"
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
        [string]$TriggerName,
        
        [Parameter(Mandatory = $true)]
        [string]$RunId,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseUri
    )
    
    try {
        $triggerHistoryUri = "$BaseUri/triggers/$TriggerName/histories/$RunId" + "?api-version=2016-06-01"
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

Write-Information "Starting Logic App run history retrieval" -InformationAction Continue

try {
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
    
    # Build API URI
    $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId"
    $baseUri += "/resourceGroups/$ResourceGroupName"
    $baseUri += "/providers/Microsoft.Logic/workflows/$LogicAppName"
    
    # Build filter
    $uri = "$baseUri/runs?api-version=2019-05-01&`$top=50"
    if ($Status) {
        $uri += "&`$filter=status eq '$Status'"
    }
    
    # Add date filter (API only supports startTime)
    $startTimeUtc = $StartTime.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    if ($Status) {
        $uri += " and startTime ge $startTimeUtc"
    }
    else {
        $uri += "&`$filter=startTime ge $startTimeUtc"
    }
    
    Write-Verbose "Filter: Status=$Status, StartTime=$startTimeUtc"
    
    # Override MaxResults if MostRecent is specified
    if ($MostRecent) {
        $MaxResults = 1
        Write-Verbose "MostRecent specified - limiting to 1 result"
    }
    
    # Retrieve runs with pagination
    $allRuns = @()
    $runCount = 0
    $pageCount = 0
    $nextLink = $uri
    
    Write-Information "Retrieving Logic App runs..." -InformationAction Continue
    
    while ($nextLink -and ($MaxResults -eq 0 -or $runCount -lt $MaxResults)) {
        $pageCount++
        Write-Verbose "Fetching page $pageCount"
        
        try {
            if ($PSCmdlet.ShouldProcess("Azure Management API", "Query Logic App runs (page $pageCount)")) {
                $response = Invoke-RestMethod -Uri $nextLink -Headers $headers -Method Get -ErrorAction Stop
                
                if ($response.value) {
                    $runsToAdd = $response.value
                    
                    # Limit results if MaxResults specified
                    if ($MaxResults -gt 0) {
                        $remaining = $MaxResults - $runCount
                        if ($runsToAdd.Count -gt $remaining) {
                            $runsToAdd = $runsToAdd[0..($remaining - 1)]
                        }
                    }
                    
                    $allRuns += $runsToAdd
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
            else {
                break  # WhatIf mode
            }
        }
        catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            
            if ($errorMessage -like "*401*" -or $errorMessage -like "*Unauthorized*") {
                throw "Authentication failed. Please re-authenticate with Connect-AzAccount"
            }
            elseif ($pageCount -eq 1) {
                throw "Failed to retrieve runs: $errorMessage"
            }
            else {
                Write-Warning "Failed to retrieve page $pageCount : $errorMessage"
                Write-Warning "Continuing with $runCount runs retrieved so far"
                break
            }
        }
    }
    
    Write-Information "Retrieved $runCount runs" -InformationAction Continue
    
    if ($runCount -eq 0) {
        Write-Information "No runs found matching the criteria" -InformationAction Continue
        
        if ($ExportPath) {
            Export-RunData -RunData @() -Path $ExportPath
        }
        return @()
    }
    
    # Process runs into objects
    Write-Verbose "Processing run data"
    $processedRuns = @()
    
    foreach ($run in $allRuns) {
        # Filter by EndTime if specified (API doesn't support this)
        if ($EndTime) {
            $runStartTime = if ($run.properties.startTime) { 
                try { [DateTime]$run.properties.startTime } catch { $null }
            } else { $null }
            
            if ($runStartTime -and $runStartTime -gt $EndTime) {
                continue
            }
        }
        
        # Create output object using helper function for clean property access
        $startTime = Get-SafeProperty -Object $run -PropertyPath 'properties.startTime'
        $endTime = Get-SafeProperty -Object $run -PropertyPath 'properties.endTime'
        
        # Calculate duration if both times exist
        $duration = if ($startTime -and $endTime) {
            try { ([DateTime]$endTime - [DateTime]$startTime).TotalSeconds } catch { $null }
        } else { $null }
        
        $runObject = [PSCustomObject]@{
            RunId        = $run.name
            Status       = Get-SafeProperty -Object $run -PropertyPath 'properties.status'
            StartTime    = $startTime ? [DateTime]$startTime : $null
            EndTime      = $endTime ? [DateTime]$endTime : $null
            Duration     = $duration
            TriggerName  = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.name'
            TriggerTime  = ($triggerTime = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.startTime') ? [DateTime]$triggerTime : $null
            ErrorCode    = Get-SafeProperty -Object $run -PropertyPath 'properties.error.code'
            ErrorMessage = Get-SafeProperty -Object $run -PropertyPath 'properties.error.message'
            Correlation  = Get-SafeProperty -Object $run -PropertyPath 'properties.correlation'
        }
        
        # Get action details if requested or if specific actions are requested
        if ($IncludeActionDetails -or $ActionNames) {
            Write-Verbose "Fetching action details for run: $($run.name)"
            $actions = Get-RunActions -RunId $run.name -Headers $headers -BaseUri $baseUri -IncludeInputsOutputs:$IncludeInputsOutputs -ActionNames $ActionNames
            
            if ($actions) {
                $runObject | Add-Member -NotePropertyName Actions -NotePropertyValue $actions
                $runObject | Add-Member -NotePropertyName ActionCount -NotePropertyValue $actions.Count
                $runObject | Add-Member -NotePropertyName FailedActions -NotePropertyValue (
                    @($actions | Where-Object { $_.Status -eq 'Failed' }).Count
                )
            }
        }
        
        # Also get the trigger's full inputs/outputs if requested
        if ($IncludeInputsOutputs -and $run.properties.trigger) {
            $triggerInputs = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.inputs'
            $triggerOutputs = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.outputs'
            
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
            
            $triggerOutputsLinkUri = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.outputsLink.uri'
            if ($triggerOutputsLinkUri) {
                try {
                    Write-Verbose "Fetching trigger output content"
                    # Content links have their own SAS auth, don't pass headers
                    $triggerOutputs = Invoke-RestMethod -Uri $triggerOutputsLinkUri -Method Get -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Could not fetch trigger output content: $_"
                }
            }
            
            $runObject | Add-Member -NotePropertyName TriggerInputs -NotePropertyValue $triggerInputs
        }
        
        # Get rich trigger outputs (headers and body) if requested
        if ($IncludeTriggerOutputs -and $run.properties.trigger) {
            $triggerName = Get-SafeProperty -Object $run -PropertyPath 'properties.trigger.name'
            if ($triggerName) {
                Write-Verbose "Fetching trigger history for run: $($run.name)"
                $triggerHistoryOutputs = Get-TriggerHistory -TriggerName $triggerName -RunId $run.name -Headers $headers -BaseUri $baseUri
                
                if ($triggerHistoryOutputs) {
                    $runObject | Add-Member -NotePropertyName TriggerOutputs -NotePropertyValue $triggerHistoryOutputs
                }
            }
        }
        
        $processedRuns += $runObject
    }
    
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
catch {
    Write-Error "Script failed: $_"
    throw
}
finally {
    Write-Information "Script completed" -InformationAction Continue
}

#endregion