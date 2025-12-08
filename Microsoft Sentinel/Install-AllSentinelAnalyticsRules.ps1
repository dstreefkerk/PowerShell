#Requires -Version 7.4
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Bulk creates Microsoft Sentinel Analytics Rules from all installed Content Hub solutions.

.DESCRIPTION
    This script automates the deployment of Microsoft Sentinel Analytics Rules at scale by:

    - Enumerating all installed Content Hub solutions in the specified workspace
    - Extracting Analytics Rule templates from each solution
    - Creating enabled alert rules with proper MITRE ATT&CK mappings
    - Linking rules to their source solutions with full metadata (source, author, support)
    - Skipping rules that already exist to prevent duplicates
    - Optionally excluding Preview and Deprecated rules
    - Supporting -WhatIf for dry-run validation
    - Automatically refreshing authentication tokens during long-running deployments
    - Graceful CTRL+C handling that completes the current rule before stopping
    - Retry logic with exponential backoff for transient API failures

    The script uses the Azure REST API with the 2025-01-01-preview version to ensure
    MITRE ATT&CK sub-techniques are properly included in created rules.

.PARAMETER subscriptionId
    The Azure subscription ID containing the Microsoft Sentinel workspace.

.PARAMETER resourceGroupName
    The resource group name where the Log Analytics workspace is deployed.

.PARAMETER workspaceName
    The Log Analytics workspace name with Microsoft Sentinel enabled.

.PARAMETER excludeRuleTemplates
    Optional array of rule template display names to exclude from creation.
    Example: @("Rule Name 1", "Rule Name 2")

.PARAMETER excludePreviewDeprecated
    Whether to exclude rules marked as [Preview] or [Deprecated]. Default: Yes.
    Valid values: Yes, No

.PARAMETER enableRules
    Whether to enable rules upon creation. Default: Yes.
    Valid values: Yes, No

.PARAMETER LogFile
    Optional file path for audit logging. When specified, all operations are logged
    with timestamps for compliance and troubleshooting.

.PARAMETER Limit
    Optional maximum number of rules to create. Useful for testing with a small batch
    before running a full deployment. Skipped rules do not count toward the limit.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Returns structured result objects with Solution, RuleName, Status, Tactics, and Techniques
    properties for each processed rule template.

.NOTES
    File Name      : Install-AllSentinelAnalyticsRules.ps1
    Author         : Daniel Streefkerk
    Prerequisite   : PowerShell 7.4+, Az.Accounts module, Azure authentication
    Copyright      : MIT License

    Based on original work by Charbel Nemnom (Microsoft MVP/MCT)
    https://charbelnemnom.com/set-microsoft-sentinel-analytics-rules-at-scale

    Change Log:
    v1.0 - 2025-12-08 - Initial release (forked from Set-AnalyticsRules.ps1 by Charbel Nemnom)
        Core Features:
        - Process ALL installed Content Hub solutions (vs single -SolutionName parameter)
        - Automatic duplicate detection to prevent API errors
        - Graceful CTRL+C handling with confirmation prompt
        - Token auto-refresh for long-running deployments (45-min interval)
        - Generates new GUIDs for rule IDs to avoid 409 conflicts
        - Proper solution metadata linkage (Content Source shown correctly in portal)
        - Concise error messages for missing tables
        - Exponential backoff retry for transient API failures (429, 5xx)
        - -Limit parameter for controlled test batches
        - -LogFile parameter for audit trail
        - -WhatIf support for dry-run validation
        - Structured PSCustomObject output for pipeline/CSV export

.EXAMPLE
    .\Install-AllSentinelAnalyticsRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -Verbose

    Connects to Azure (if needed) and creates all analytics rules from installed Content Hub
    solutions. Existing rules are skipped. Verbose output shows progress details.

.EXAMPLE
    .\Install-AllSentinelAnalyticsRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -WhatIf

    Performs a dry run showing which rules would be created without making any changes.
    Useful for planning and validation before actual deployment.

.EXAMPLE
    .\Install-AllSentinelAnalyticsRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -LogFile "C:\logs\sentinel-rules.log"

    Creates rules and writes a timestamped audit log for compliance tracking.

.EXAMPLE
    .\Install-AllSentinelAnalyticsRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -excludePreviewDeprecated "No" -enableRules "No"

    Creates all rules including Preview and Deprecated ones, but leaves them disabled
    for manual review before activation.

.EXAMPLE
    .\Install-AllSentinelAnalyticsRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -excludeRuleTemplates @("Brute force attack against a Cloud PC", "Anomalous sign-in location")

    Creates all rules except for the specified rule templates by display name.

.EXAMPLE
    $results = .\Install-AllSentinelAnalyticsRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace"
    $results | Where-Object Status -eq "Created" | Export-Csv -Path "created-rules.csv"

    Captures the structured output and exports created rules to CSV for reporting.

.EXAMPLE
    .\Install-AllSentinelAnalyticsRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -Limit 5

    Creates only the first 5 rules (that don't already exist) as a test batch.
    Useful for validating the deployment process before running at full scale.

.LINK
    TBC
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$subscriptionId,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$resourceGroupName,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$workspaceName,
    [Parameter(Position = 3, Mandatory = $false, HelpMessage = 'Exclude Rule Templates Names i.e: @("ABC","DEF")')]
    [ValidateNotNullOrEmpty()]
    [array]$excludeRuleTemplates,
    [Parameter(Position = 4, Mandatory = $false, HelpMessage = 'Exclude [Preview] and [Deprecated] Rule Templates [Yes/No]')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Yes", "No")]
    [String]$excludePreviewDeprecated = 'Yes',
    [Parameter(Position = 5, Mandatory = $false, HelpMessage = 'Enable Rules at Creation Time [Yes/No]')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Yes", "No")]
    [String]$enableRules = 'Yes',
    [Parameter(Position = 6, Mandatory = $false, HelpMessage = 'Optional log file path for audit trail')]
    [string]$LogFile,
    [Parameter(Position = 7, Mandatory = $false, HelpMessage = 'Maximum number of rules to create (for testing)')]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Limit
)

Set-StrictMode -Version Latest

#region Functions

function Install-RequiredModule {
    <#
    .SYNOPSIS
    Installs a PowerShell module if not already present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Verbose "Module '$ModuleName' already exists, continue..."
    }
    else {
        Write-Verbose "Module '$ModuleName' does not exist, installing..."
        Install-Module $ModuleName -Force -AllowClobber -ErrorAction Stop
        Write-Verbose "Module '$ModuleName' installed."
    }
}

function Write-Log {
    <#
    .SYNOPSIS
    Writes a timestamped log entry to a file if LogFile is specified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$LogFile,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    if ($LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp [$Level] $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
    }
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
            $statusCode = $_.Exception.Response.StatusCode.value__
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

function Get-AzureAccessToken {
    <#
    .SYNOPSIS
    Gets or refreshes the Azure access token for ARM API calls.
    #>
    [CmdletBinding()]
    param()

    $context = Get-AzContext
    if (-not $context) {
        throw "No Azure context found. Please re-authenticate."
    }

    $tokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
        $context.Account,
        $context.Environment,
        $context.Tenant.Id,
        $null,
        "Never",
        $null,
        "https://management.azure.com/"
    )

    if (-not $tokenRequest) {
        throw "Failed to obtain access token."
    }

    return $tokenRequest.AccessToken
}

function Update-TokenIfNeeded {
    <#
    .SYNOPSIS
    Refreshes the access token if it's approaching expiration (45 min threshold).
    #>
    [CmdletBinding()]
    param()

    $elapsed = (Get-Date) - $script:TokenAcquiredTime
    if ($elapsed.TotalMinutes -ge $script:TokenRefreshInterval) {
        Write-Verbose "Refreshing access token (elapsed: $([int]$elapsed.TotalMinutes) minutes)..."
        $script:AzureAccessToken = Get-AzureAccessToken
        $script:authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = "Bearer $script:AzureAccessToken"
        }
        $script:TokenAcquiredTime = Get-Date
        Write-Host "  [Token refreshed]" -ForegroundColor DarkCyan
    }
}

function Test-CancellationRequested {
    <#
    .SYNOPSIS
    Checks if CTRL+C was pressed (when TreatControlCAsInput is enabled).
    #>
    [CmdletBinding()]
    param()

    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true)
        if (($key.Modifiers -band [ConsoleModifiers]::Control) -and ($key.Key -eq 'C')) {
            return $true
        }
    }
    return $false
}

#endregion Functions

#region Main

# Install Az Accounts Module If Needed
Install-RequiredModule -ModuleName Az.Accounts

#! Check Azure Connection - Only connect if not already connected
$context = Get-AzContext
if (-not $context) {
    Try {
        Write-Verbose "Connecting to Azure Cloud..."
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
    Catch {
        Write-Warning "Cannot connect to Azure Cloud. Please check your credentials. Exiting!"
        Break
    }
}
else {
    Write-Verbose "Already connected to Azure as $($context.Account.Id)"
}

# Set subscription context
Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null
Write-Verbose "Using subscription: $subscriptionId"

# Initialize log file if specified
if ($LogFile) {
    $logHeader = @"
=== Microsoft Sentinel Analytics Rules Deployment ===
Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Subscription: $subscriptionId
Resource Group: $resourceGroupName
Workspace: $workspaceName
Enable Rules: $enableRules
Exclude Preview/Deprecated: $excludePreviewDeprecated
Limit: $(if ($Limit) { $Limit } else { 'None' })
==================================================

"@
    $logHeader | Out-File -FilePath $LogFile -Encoding utf8
    Write-Verbose "Logging to: $LogFile"
}

# Define the Preview API Version to use for Microsoft Sentinel
# The Preview API Version is needed to include the MITRE ATT&CK "Sub techniques"
$apiVersion = "?api-version=2025-01-01-preview"

# Create the authentication access token with refresh tracking
# Token refresh every 45 minutes to stay ahead of 60-90 min expiry
Write-Verbose "Creating authentication access token..."
$script:TokenRefreshInterval = 45
$script:TokenAcquiredTime = Get-Date
$script:AzureAccessToken = Get-AzureAccessToken
$script:authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = "Bearer $script:AzureAccessToken"
}

# Enable graceful CTRL+C handling (allows completing current rule before stopping)
$script:CancellationRequested = $false
$script:OriginalTreatCtrlC = [Console]::TreatControlCAsInput
[Console]::TreatControlCAsInput = $true
$Host.UI.RawUI.FlushInputBuffer()

# Get Content Packages (INSTALLED solutions only)
# Note: contentPackages returns installed solutions, contentProductPackages returns ALL available solutions
$contentURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentPackages$($apiVersion)"
$contentResponse = (Invoke-RestMethodWithRetry -Uri $contentURI -Method 'GET' -Headers $script:authHeader).value
$allSolutions = @($contentResponse | Where-Object { $_.properties.contentKind -eq 'Solution' })

Write-Host "`nFound $($allSolutions.Count) installed Content Hub solutions" -ForegroundColor Cyan
Write-Log -Message "Found $($allSolutions.Count) installed Content Hub solutions" -LogFile $LogFile

# Get ALL Content Templates
$contentURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates$($apiVersion)"
$allContentTemplates = (Invoke-RestMethodWithRetry -Uri $contentURI -Method 'GET' -Headers $script:authHeader).value

# Get ALL existing alert rules to check for duplicates
Write-Verbose "Fetching existing alert rules to prevent duplicates..."
$existingRulesURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules$($apiVersion)"
$existingRulesResponse = (Invoke-RestMethodWithRetry -Uri $existingRulesURI -Method 'GET' -Headers $script:authHeader).value
$existingRuleIds = @{}
foreach ($existingRule in $existingRulesResponse) {
    # Track by rule name (GUID) and template name if available
    $existingRuleIds[$existingRule.name] = $true
    if ($existingRule.properties.alertRuleTemplateName) {
        $existingRuleIds[$existingRule.properties.alertRuleTemplateName] = $true
    }
}
Write-Verbose "Found $($existingRulesResponse.Count) existing alert rules"
Write-Log -Message "Found $($existingRulesResponse.Count) existing alert rules" -LogFile $LogFile

# Results tracking
$results = @()
$totalCreated = 0
$totalWouldCreate = 0
$totalSkipped = 0
$totalFailed = 0

# Process each solution
try {
:solutionLoop foreach ($solution in $allSolutions) {
    $solutionName = $solution.properties.displayName
    $solutionContentId = $solution.properties.contentId

    # Get templates for this solution (wrap in @() to ensure array even for single items or $null)
    $contentTemplates = @($allContentTemplates | Where-Object {
        $_.properties.packageId -eq $solutionContentId -and $_.properties.contentKind -eq "AnalyticsRule"
    })

    if ($contentTemplates.Count -eq 0) {
        Write-Verbose "No Analytics Rules found for solution: [$solutionName]"
        continue
    }

    Write-Host "`nProcessing solution: $solutionName ($($contentTemplates.Count) rules)" -ForegroundColor Yellow

    if ($excludePreviewDeprecated -eq 'Yes') {
        $contentTemplatesExcluded = @($contentTemplates | Where-Object {
            $_.properties.displayName -notmatch '^(Preview|Deprecated)' -and
            $_.properties.displayName -notmatch '\[Preview\]' -and
            $_.properties.displayName -notmatch '\[Deprecated\]'
        })

        if ($contentTemplatesExcluded.Count -ne $contentTemplates.Count) {
            Write-Verbose "$($contentTemplates.Count - $contentTemplatesExcluded.Count) Preview/Deprecated rule(s) excluded for: [$solutionName]"
            $contentTemplates = $contentTemplatesExcluded
        }
    }

    if ($excludeRuleTemplates) {
        foreach ($ruleTemplate in $excludeRuleTemplates) {
            $contentTemplates = @($contentTemplates | Where-Object { $_.properties.displayname -ne "$ruleTemplate" })
        }
    }

    foreach ($contentTemplate in $contentTemplates) {
        # Check for CTRL+C BEFORE starting a new rule (with confirmation prompt)
        if (-not $script:CancellationRequested -and (Test-CancellationRequested)) {
            Write-Host "`n[CTRL+C detected] Stop after current rule completes? (Y/N): " -ForegroundColor Yellow -NoNewline
            $confirmation = Read-Host
            if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
                $script:CancellationRequested = $true
                Write-Host "Cancellation confirmed. Stopping..." -ForegroundColor Yellow
                Write-Log -Message "User requested cancellation via CTRL+C" -LogFile $LogFile -Level 'Warning'
                break solutionLoop
            } else {
                Write-Host "Continuing execution..." -ForegroundColor Green
                $Host.UI.RawUI.FlushInputBuffer()
            }
        }

        # Refresh token if approaching expiration (every 45 min)
        Update-TokenIfNeeded

        $ruleName = $contentTemplate.name

        # Check if rule already exists - skip to prevent duplicates
        if ($existingRuleIds.ContainsKey($ruleName)) {
            Write-Host "  - Skipped (exists): $($contentTemplate.properties.displayName)" -ForegroundColor DarkGray
            Write-Log -Message "SKIPPED (exists): [$solutionName] $($contentTemplate.properties.displayName)" -LogFile $LogFile
            $totalSkipped++
            $results += [PSCustomObject]@{
                Solution   = $solutionName
                RuleName   = $contentTemplate.properties.displayName
                Status     = "Skipped (already exists)"
                Tactics    = ""
                Techniques = ""
            }
            continue
        }

        $ruleTemplateURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$($ruleName)$($apiVersion)"

        try {
            $ruleResponse = Invoke-RestMethodWithRetry -Uri $ruleTemplateURI -Method 'GET' -Headers $script:authHeader

            $rule = $ruleResponse.properties.mainTemplate.resources | Where-Object type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates'

            # Check again by template rule name
            if ($existingRuleIds.ContainsKey($rule.name)) {
                Write-Host "  - Skipped (exists): $($rule.properties.displayName)" -ForegroundColor DarkGray
                Write-Log -Message "SKIPPED (exists): [$solutionName] $($rule.properties.displayName)" -LogFile $LogFile
                $totalSkipped++
                $results += [PSCustomObject]@{
                    Solution   = $solutionName
                    RuleName   = $rule.properties.displayName
                    Status     = "Skipped (already exists)"
                    Tactics    = ""
                    Techniques = ""
                }
                continue
            }

            # Store the template name before generating a new rule ID
            $templateName = $rule.name

            # Generate a new GUID for the rule ID (avoids conflicts with recently deleted rules)
            $newRuleId = (New-Guid).Guid

            # Update the rule's name property to match the new ID (API requires name in payload to match URI)
            $rule.name = $newRuleId

            $rule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $templateName
            $rule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $ruleResponse.properties.version

            # Fix Grouping Configuration
            if ($rule.properties.PSObject.Properties.Name -contains "incidentConfiguration") {
                if ($rule.properties.incidentConfiguration.PSObject.Properties.Name -contains "groupingConfiguration") {
                    if (-not $rule.properties.incidentConfiguration.groupingConfiguration) {
                        $rule.properties.incidentConfiguration | Add-Member -NotePropertyName "groupingConfiguration" -NotePropertyValue @{
                            matchingMethod   = "AllEntities"
                            lookbackDuration = "PT1H"
                        }
                    }
                    else {
                        # Ensure `matchingMethod` exists
                        if (-not ($rule.properties.incidentConfiguration.groupingConfiguration.PSObject.Properties.Name -contains "matchingMethod")) {
                            $rule.properties.incidentConfiguration.groupingConfiguration | Add-Member -NotePropertyName "matchingMethod" -NotePropertyValue "AllEntities"
                        }

                        # Ensure `lookbackDuration` is in ISO 8601 format
                        if ($rule.properties.incidentConfiguration.groupingConfiguration.PSObject.Properties.Name -contains "lookbackDuration") {
                            $lookbackDuration = $rule.properties.incidentConfiguration.groupingConfiguration.lookbackDuration
                            if ($lookbackDuration -match "^(\d+)(h|d|m)$") {
                                $timeValue = $matches[1]
                                $timeUnit = $matches[2]
                                switch ($timeUnit) {
                                    "h" { $isoDuration = "PT${timeValue}H" }
                                    "d" { $isoDuration = "P${timeValue}D" }
                                    "m" { $isoDuration = "PT${timeValue}M" }
                                }
                                $rule.properties.incidentConfiguration.groupingConfiguration.lookbackDuration = $isoDuration
                            }
                        }
                    }
                }
            }

            If ($enableRules -eq "Yes") {
                $rule.properties.enabled = $true
            }

            $rulePayload = $rule | ConvertTo-Json -EnumsAsStrings -Depth 50
            $ruleURI = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($newRuleId)$($apiVersion)"

            # Prepare tactics and techniques strings for results
            $tacticsStr = if ($rule.properties.tactics) { $rule.properties.tactics -join ',' } else { "" }
            $techniquesStr = if ($rule.properties.techniques) { $rule.properties.techniques -join ',' } else { "" }

            # Check ShouldProcess before making changes
            if ($PSCmdlet.ShouldProcess($rule.properties.displayName, "Create Analytics Rule")) {
                $ruleResult = Invoke-AzRestMethod -Method PUT -path $ruleURI -Payload $rulePayload -Verbose:$false

                If (!($ruleResult.StatusCode -in 200, 201)) {
                    # Parse API error to extract a concise message
                    $apiError = "Unknown error"
                    try {
                        $errorJson = $ruleResult.Content | ConvertFrom-Json
                        $apiError = $errorJson.error.message
                        # Extract table name from common "table does not exist" errors
                        if ($apiError -match "Failed to resolve (table|scalar) expression named '([^']+)'") {
                            $apiError = "Missing table: $($Matches[2])"
                        }
                        elseif ($apiError -match "'([^']+)' is not found") {
                            $apiError = "Missing table: $($Matches[1])"
                        }
                    }
                    catch {
                        $apiError = $ruleResult.Content.Substring(0, [Math]::Min(150, $ruleResult.Content.Length))
                    }
                    throw $apiError
                }

                # Track the newly created rule to prevent duplicates within this run
                $existingRuleIds[$newRuleId] = $true
                $existingRuleIds[$templateName] = $true

                $totalCreated++
                $results += [PSCustomObject]@{
                    Solution   = $solutionName
                    RuleName   = $rule.properties.displayName
                    Status     = "Created"
                    Tactics    = $tacticsStr
                    Techniques = $techniquesStr
                }

                Write-Host "  + Created: $($rule.properties.displayName)" -ForegroundColor Green
                Write-Log -Message "CREATED: [$solutionName] $($rule.properties.displayName)" -LogFile $LogFile -Level 'Success'

                # Update metadata to link rule to solution (sets Content Source in UI)
                If ($ruleResult.StatusCode -in 200, 201) {
                    $ruleResultContent = $ruleResult.Content | ConvertFrom-Json

                    # Build metadata body from scratch to link rule to solution
                    $metadataBody = @{
                        "properties" = @{
                            "contentId" = $templateName
                            "parentId"  = $ruleResultContent.id
                            "kind"      = "AnalyticsRule"
                            "version"   = $ruleResponse.properties.version
                            "source"    = $solution.properties.source
                            "author"    = $solution.properties.author
                            "support"   = $solution.properties.support
                        }
                    }

                    $metadataURI = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/metadata/analyticsrule-$($newRuleId)$($apiVersion)"
                    $metadataPayload = $metadataBody | ConvertTo-Json -EnumsAsStrings -Depth 50
                    Write-Verbose "Metadata payload: $metadataPayload"
                    $resultMetadata = Invoke-AzRestMethod -Method PUT -path $metadataURI -Payload $metadataPayload -Verbose:$false
                    if (!($resultMetadata.StatusCode -in 200, 201)) {
                        Write-Warning "Failed to update metadata for: $($rule.properties.displayName) - Status: $($resultMetadata.StatusCode) - $($resultMetadata.Content)"
                    }
                    else {
                        Write-Verbose "Metadata updated successfully for: $($rule.properties.displayName)"
                    }
                }

                # Check if limit reached (after metadata update)
                if ($Limit -and $totalCreated -ge $Limit) {
                    Write-Host "`nLimit of $Limit rules reached. Stopping." -ForegroundColor Yellow
                    Write-Log -Message "Limit of $Limit rules reached. Stopping." -LogFile $LogFile -Level 'Info'
                    break solutionLoop
                }

                # Check if cancellation was requested during rule creation (delayed check)
                if ($script:CancellationRequested) {
                    Write-Host "`nStopping after completing rule: $($rule.properties.displayName)" -ForegroundColor Yellow
                    break solutionLoop
                }
            }
            elseif ($WhatIfPreference) {
                # WhatIf mode - track what would be created
                $totalWouldCreate++
                $results += [PSCustomObject]@{
                    Solution   = $solutionName
                    RuleName   = $rule.properties.displayName
                    Status     = "Would Create"
                    Tactics    = $tacticsStr
                    Techniques = $techniquesStr
                }

                # Check if limit reached in WhatIf mode
                if ($Limit -and $totalWouldCreate -ge $Limit) {
                    Write-Host "`nLimit of $Limit rules would be reached. Stopping." -ForegroundColor Yellow
                    Write-Log -Message "Limit of $Limit rules would be reached. Stopping." -LogFile $LogFile -Level 'Info'
                    break solutionLoop
                }
            }
        }
        catch {
            $totalFailed++
            $results += [PSCustomObject]@{
                Solution   = $solutionName
                RuleName   = $contentTemplate.properties.displayName
                Status     = "Failed: $($_.Exception.Message)"
                Tactics    = ""
                Techniques = ""
            }
            Write-Host "  x Failed: $($contentTemplate.properties.displayName) - $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Message "FAILED: [$solutionName] $($contentTemplate.properties.displayName) - $($_.Exception.Message)" -LogFile $LogFile -Level 'Error'
        }
    }
}
}
finally {
    # Restore original CTRL+C behavior
    [Console]::TreatControlCAsInput = $script:OriginalTreatCtrlC
    if ($script:CancellationRequested) {
        Write-Host "`nScript cancelled by user. All rules created before cancellation have complete metadata." -ForegroundColor Yellow
        Write-Log -Message "Script cancelled by user after creating $totalCreated rules" -LogFile $LogFile -Level 'Warning'
    }
}

# Summary
Write-Host "`n=== EXECUTION SUMMARY ===" -ForegroundColor Cyan
if ($Limit) {
    Write-Host "Limit: $Limit" -ForegroundColor Cyan
}
if ($WhatIfPreference) {
    Write-Host "Total Would Create: $totalWouldCreate" -ForegroundColor Yellow
}
else {
    Write-Host "Total Created: $totalCreated" -ForegroundColor Green
}
Write-Host "Total Skipped (already exist): $totalSkipped" -ForegroundColor DarkGray
Write-Host "Total Failed: $totalFailed" -ForegroundColor $(if ($totalFailed -gt 0) { "Red" } else { "Green" })
Write-Host ""

# Write summary to log file
if ($LogFile) {
    $logSummary = @"

==================================================
=== EXECUTION SUMMARY ===
Completed: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Limit: $(if ($Limit) { $Limit } else { 'None' })
Total Created: $totalCreated
Total Would Create: $totalWouldCreate
Total Skipped (already exist): $totalSkipped
Total Failed: $totalFailed
==================================================
"@
    $logSummary | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Verbose "Log file written to: $LogFile"
}

#endregion Main

# Output structured results object for pipeline consumption
$results | Format-Table -AutoSize