<#
.SYNOPSIS
Update all default Microsoft Sentinel active Analytics Rules at once. Tuned or modified analytic rules are untouched.

.DESCRIPTION
How to update built-in Microsoft Sentinel active Analytics Rules at once using PowerShell and REST API.

.NOTES
File Name : Update-AnalyticsRules.ps1
Author    : Microsoft MVP/MCT - Charbel Nemnom and Willem-Jan van Esschoten
Version   : 1.8
Date      : 04-April-2024
Updated   : 18-April-2024
Requires  : PowerShell 6.2 or PowerShell 7.x.x (Core)
Module    : Az Module
Service   : Automation Accounts

.LINK
To provide feedback or for further assistance please visit:
https://charbelnemnom.com

.EXAMPLE
.\Update-AnalyticsRules.ps1 -SubscriptionId <SUB-ID> -ResourceGroup <RG-Name> `
    -WorkspaceName <Log-Analytics-Name> -skipTunedRulesTextInput <Skip-Tuned-Analytics-Rules> -Verbose
This example will connect to your Azure account using the subscription Id specified, and then update all active analytics rules from templates.
By default, only  the rules with the state Enabled will be updated.
#>

param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$subscriptionId,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$resourceGroupName,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$workspaceName,
    [Parameter(Position = 3, Mandatory = $false, HelpMessage = 'Enter a keyword that exists in the KQL query to prevent the rule from being updated')]
    [string]$skipTunedRulesTextInput
)

# Ensures you do not inherit an AzContext in your runbook 
Disable-AzContextAutosave -Scope Process 

#! Check Azure Connection
Try {
    Write-Output "Connecting to Azure Cloud..."
    # Connect to Azure with system-assigned managed identity (automation account)
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
}
Catch {
    Write-Warning "Cannot connect to Azure Cloud. Please check your managed identity Azure RBAC access. Exiting!"
    Break
}

# Set Azure Subscription context
Set-AzContext -Subscription $subscriptionId

# Define the latest API Version to use for Sentinel
$apiVersion = "?api-version=2024-03-01"

# Add Wildcards to Skip Tuned/Modified Analytics Rules Text Input
$skipTunedRulesText = "*$($skipTunedRulesTextInput)*"

function Update-AnalyticRule {
    param ( 
        $rulePayload,
        $apiVersion,
        $ruleName,
        $ruleDisplayName        
    )    
    # Define analytic rule URI
    $ruleURI = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($ruleName)$($apiVersion)"
    try {
        $ruleResult = Invoke-AzRestMethod -Method PUT -path $ruleURI -Payload $rulePayload -Verbose:$false

        if (!($ruleResult.StatusCode -in 200, 201)) {
            Write-Host $ruleResult.StatusCode
            Write-Host $ruleResult.Content
            throw "Error when updating Analytic rule: $($ruleDisplayName)"
        }        
    }
    catch {
        Write-Error $_ -ErrorAction Continue
    }
    return $ruleResult    
}

function Update-Metadata {
    param ( 
        $metadataPayload,
        $apiVersion,
        $ruleName,
        $ruleDisplayName        
    )
    # Define metadata URI for the Analytic rule
    $metadataURI = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/metadata/analyticsrule-$($ruleName)$($apiVersion)"
    try {
        $resultMetadata = Invoke-AzRestMethod -Method PUT -path $metadataURI -Payload $metadataPayload -Verbose:$false

        if (!($resultMetadata.StatusCode -in 200, 201)) {
            Write-Host $resultMetadata.StatusCode
            Write-Host $resultMetadata.Content
            throw "Error when updating Metadata for Analytic rule: $($ruleDisplayName)"
        }
        else {
            Write-Output "Updating Metadata for Analytic rule: $($ruleDisplayName)"
        }        
    }
    catch {
        Write-Error $_ -ErrorAction Continue
    }    
}

#! Get Az Access Token
$token = Get-AzAccessToken #This will default to Azure Resource Manager endpoint
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}

# Get all installed content Rule Templates
Write-Output "Get all installed content Rule Templates..."
$contentURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates$($apiVersion)"
$contentResponse = (Invoke-RestMethod $contentURI -Method 'GET' -Headers $authHeader).value

try {    
    $contentTemplates = $contentResponse | Where-Object { $_.properties.contentKind -eq "AnalyticsRule" }
    if ($contentTemplates.Count -eq 0) {
        throw "No content Rule templates can be found. Please check and install Analytics Rule from the Content Hub blade"
    }
}
catch {
    Write-Error $_ -ErrorAction Stop
}

# Get all active Analytics Rules
Write-Output "Get all active Analytics Rules..."
$activeRulesURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertrules$($apiVersion)"
$ruleResponse = (Invoke-RestMethod $activeRulesURI -Method 'GET' -Headers $authHeader).value
# Filter only enabled Analytics rules
Write-Output "Filter only enabled Analytics rules..."
$ruleEnabled = $ruleResponse.properties | Where-Object enabled -eq True
 
# Filter out tuned and modified KQL rules (Optional)
if ($skipTunedRulesText -ne "**") {
    Write-Output "Filter out tuned and modified KQL rules..."
    $ruleSkipTuned = $ruleEnabled | Where-Object { $_.query -notlike $skipTunedRulesText }
    $activeRules = $ruleSkipTuned | Where-Object alertRuleTemplateName -ne $null | Select-Object alertRuleTemplateName
}
else {
    $ruleSkipTuned = $ruleEnabled | Where-Object { $_.query -like $skipTunedRulesText }
    $activeRules = $ruleEnabled | Where-Object alertRuleTemplateName -ne $null | Select-Object alertRuleTemplateName
}

# Filter out Content Rule Templates to match active, enabled, and skipped tuned/modified Analytics rules
Write-Output "Filter out Content Rule Templates to match active and enabled Analytics rules..."
$matchedTemplates = $contentTemplates | Where-Object { 
    $template = $_
    $activeRules.alertRuleTemplateName -eq $template.properties.contentId }

Write-Output "$($matchedTemplates.count) matched Active Analytics Rules were found!"

$updatedActiveRules = @()

foreach ($contentTemplate in $matchedTemplates) { 
   
    # Get the latest Template of the active Analytic Rule    
    $ruleTemplateURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$($contentTemplate.name)$($apiVersion)"
    $ruleResponse = Invoke-RestMethod $ruleTemplateURI -Method 'GET' -Headers $authHeader -Verbose:$false
    $ruleContentId = $ruleResponse.properties.contentId
    $ruleProperties = $ruleResponse.properties.mainTemplate.resources | Where-Object type -eq 'Microsoft.OperationalInsights/workspaces/providers/metadata' | Select-Object properties
    $ruleProperties.properties = $ruleProperties.properties | Select-Object * -ExcludeProperty description, parentId
    Write-Output "Getting the latest Template of the Active Analytic Rule => $($ruleResponse.properties.mainTemplate.resources.properties.displayName)"
           
    # Comparing the latest rule template version to active Analytics Rule version
    $templateVersion = $ruleResponse.properties | Select-Object version
    $ruleTemplateVersion = $ruleSkipTuned | Where-Object alertRuleTemplateName -eq $ruleContentId | Select-Object templateversion    
    Write-Output "Comparing the latest rule template version $($templateVersion.version) to Active Analytic Rule version $($ruleTemplateVersion.templateVersion)"

    # If the version is not in (the objects aren't the same), update the analytic rule
    if ($templateVersion.version -notin $ruleTemplateVersion.templateVersion) {
        Write-Output "KQL query requires an update, updating the analytic rule..."       
        
        # 'Microsoft.SecurityInsights/AlertRuleTemplates' for analytic rules installed from a Content hub solution
        # 'Microsoft.OperationalInsights/workspaces/providers/alertRules' for standalone analytic rules
        $rule = $ruleResponse.properties.mainTemplate.resources | Where-Object { $_.type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates' -or $_.type -eq 'Microsoft.OperationalInsights/workspaces/providers/alertRules' }
       
        # Load the latest Analytic rule properties to JSON
        if (!$rule.properties.alertRuleTemplateName) {
            $rule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $rule.name
        }
        if (!$rule.properties.templateVersion) {
            $rule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $ruleResponse.properties.version
        }
        $rule.properties.enabled = $true 
        $rulePayload = $rule | ConvertTo-Json -Depth 100

        # Update Active Analytic Rule
        Write-Output "Updating Analytic rule: $($rule.properties.displayName)"   
        $ruleResult = Update-AnalyticRule -rulePayload $rulePayload -apiVersion $apiVersion -ruleName $rule.name -ruleDisplayName $rule.properties.displayName
        
        # Load the Metadata properties to JSON
        $ruleResult = $ruleResult.Content | ConvertFrom-Json -Depth 100
        if (!$ruleProperties.properties.parentId) {
            $ruleProperties.properties | Add-Member -NotePropertyName parentId -NotePropertyValue $ruleResult.id
        }
        $metadataPayload = $ruleProperties | ConvertTo-Json -Depth 100
        # Update Metadata for Active Analytic Rule
        Update-Metadata -metadataPayload $metadataPayload -apiVersion $apiVersion -ruleName $rule.name -ruleDisplayName $rule.properties.displayName       

        $updatedActiveRules += $rule
    }      
}

if ($updatedActiveRules.count -eq 0) {
    Write-Output "All the active Analytics Rules are currently up to date. No update is required."
}
else {
    Write-Output "$($updatedActiveRules.count) Active Analytics Rules were found and updated!"
}