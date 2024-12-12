#requires -Version 5.1
#requires -Module Az.Resources

<#
.SYNOPSIS
Connects Azure Active Directory logs to Microsoft Sentinel.

.DESCRIPTION
This script links specified Azure Active Directory log types to a Microsoft Sentinel workspace.
It ensures that the user is authenticated to Azure, retrieves necessary tenant and subscription details,
and deploys the Sentinel data connectors via an ARM template.

.PARAMETER ResourceGroupName
The name of the resource group where the Sentinel workspace resides.

.PARAMETER WorkspaceName
The name of the Log Analytics workspace associated with Sentinel.

.EXAMPLE
Connect-EntraLogsToSentinel.ps1 -ResourceGroupName "MyResourceGroup" -WorkspaceName "MyWorkspace" -Location "Australia East"

.NOTES
Version: 1.0.0
Author: Daniel Streefkerk
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName
)

$context = Get-AzContext

# Check for existing AzContext
if (-not ($context)) {
    Write-Host "No Azure context detected. Logging in..."
    Connect-AzAccount -ErrorAction Stop
}

$TenantId = $context.Tenant.Id
Write-Host "Using Tenant $($context.Tenant.Name) (ID: $TenantId)"

$SubscriptionId = $context.Subscription.Id
Write-Host "Using Subscription $($context.Subscription.Name) (ID: $SubscriptionId)"

# Check if the user has appropriate privileges
$roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue
if (-not $roleAssignments) {
    throw "Unable to retrieve role assignments. Ensure you have the necessary permissions to query roles."
}

$hasRequiredRole = $roleAssignments | Where-Object {
    $_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor"
}

if (-not $hasRequiredRole) {
    throw "Current user does not have sufficient privileges. Required roles: Owner or Contributor."
}

# Define the parameters as a hashtable
$parameters = @{
    dataConnectorsKind = @("AzureActiveDirectory")
    aadStreams         = @(
        "SignInLogs",
        "AuditLogs",
        "NonInteractiveUserSignInLogs",
        "ServicePrincipalSignInLogs",
        "ManagedIdentitySignInLogs",
        "ProvisioningLogs",
        "ADFSSignInLogs",
        "UserRiskEvents",
        "RiskyUsers",
        "RiskyServicePrincipals",
        "ServicePrincipalRiskEvents"
    )
    workspaceName      = $WorkspaceName
    tenantId           = $TenantId
    subscriptionId     = $SubscriptionId
}

# Confirm with the user before deployment
$confirmation = Read-Host "Are you sure that you want to apply the Entra ID data connectors ARM template to tenant '$($context.Tenant.Name) - $TenantId' and connect the analytics logs to Log Analytics Workspace '$WorkspaceName'? (y/n)"
if ($confirmation -ne 'y') {
    Write-Host "Deployment cancelled by user."
    return
}

# Deploy the template
$templateUri = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/refs/heads/master/Tools/Sentinel-All-In-One/v2/LinkedTemplates/dataConnectors.json"

New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri $templateUri -TemplateParameterObject $parameters -Verbose
