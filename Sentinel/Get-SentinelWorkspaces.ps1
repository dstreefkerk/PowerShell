#requires -Modules Az.Accounts, Az.Resources, Az.OperationalInsights

<#
.SYNOPSIS
Retrieves Microsoft Sentinel-enabled Log Analytics workspaces. Useful for Lighthouse scenarios where multiple tenants are managed.

.DESCRIPTION
This script retrieves all subscriptions available in the current context, enumerates the Log Analytics workspaces for each subscription, and checks whether Microsoft Sentinel (SecurityInsights) is enabled on each workspace by matching the ResourceId field. If Sentinel is detected, the script outputs a custom object with workspace details.

.EXAMPLE
.\Get-SentinelWorkspaces.ps1 -Verbose

Displays all Sentinel-enabled workspaces with verbose logging enabled.

.EXAMPLE
.\Get-SentinelWorkspaces.ps1 -Verbose | Export-Csv -Path SentinelWorkspaces.csv -NoTypeInformation

Exports the list of Sentinel-enabled workspaces to a CSV file.

.NOTES
By: Daniel Streefkerk
Date: 07 February 2025

#>

[CmdletBinding()]
param()

# Retrieve all subscriptions available in the current context.
Write-Verbose "Retrieving subscriptions available in the current context"
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Write-Verbose "Processing subscription '$($sub.Name)' (ID: $($sub.Id))"

    # Set the context to the current subscription to ensure correct resource retrieval.
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
    Write-Verbose "Context set to subscription ID: $($sub.Id)"

    # Retrieve tenant details associated with the current subscription.
    Write-Verbose "Retrieving tenant details for subscription: $($sub.Name)"
    $tenant = Get-AzTenant -TenantId $sub.TenantId

    # Retrieve all Log Analytics workspaces for the current subscription.
    Write-Verbose "Retrieving Log Analytics workspaces for subscription ID: $($sub.Id)"
    $workspaces = Get-AzOperationalInsightsWorkspace

    foreach ($workspace in $workspaces) {
        Write-Verbose "Examining workspace '$($workspace.Name)' in resource group '$($workspace.ResourceGroupName)'"

        # Check if Microsoft Sentinel is enabled on the workspace by matching the ResourceId field.
        # This regex searches for the pattern SecurityInsights(<WorkspaceName>) in the ResourceId.
        $sentinelSolution = Get-AzResource -ResourceType 'Microsoft.OperationsManagement/solutions' `
            | Where-Object { $_.ResourceId -match "SecurityInsights\($($workspace.Name)\)" }

        if ($sentinelSolution) {
            Write-Verbose "Sentinel detected on workspace '$($workspace.Name)'. Adding to results."

            # Process tags into a formatted string, ensuring keys and values are uppercase for consistency.
            $tagString = if ($workspace.Tags) { 
                ($workspace.Tags.GetEnumerator() | 
                    Sort-Object Key | 
                    ForEach-Object { "$($_.Key.ToUpper())=$($_.Value.ToString().ToUpper())" }) -join "; "
            } else { 
                "NO TAGS" 
            }

            # Output Sentinel-enabled workspace details as a custom object.
            [PSCustomObject]@{
                ID               = $workspace.CustomerId
                Name             = $workspace.Name.ToUpper()
                ResourceGroup    = $workspace.ResourceGroupName.ToUpper()
                Location         = $workspace.Location
                SKU              = $workspace.Sku
                Retention        = $workspace.retentionInDays
                Created          = $workspace.CreatedDate
                TenantID         = $sub.TenantId
                TenantName       = $tenant.Name
                SubscriptionID   = $sub.Id
                SubscriptionName = $sub.Name.ToUpper()
                Tags             = $tagString
            }
        }
        else {
            Write-Verbose "Sentinel not found for workspace '$($workspace.Name)'"
        }
    }
}
