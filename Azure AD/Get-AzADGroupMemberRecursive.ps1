<#
.SYNOPSIS
Get-AzADGroupMemberRecursive - Retrieve Azure AD group memberships recursively using the Az PowerShell module

.DESCRIPTION 
Given that there's no native recursive group membership retrieval functionality
in Az PowerShell, this module can be used to recursively list Azure AD group memberships

.PARAMETER GroupDisplayName
The display name of the Azure AD group

.INPUTS
System.String.

.OUTPUTS Microsoft.Azure.Commands.ActiveDirectory.PSADUser, Microsoft.Azure.Commands.ActiveDirectory.PSADGroup, Microsoft.Azure.Commands.ActiveDirectory.PSADServicePrincipal

.LINK
https://github.com/dstreefkerk/PowerShell/blob/master/Azure%20AD/Get-AzADGroupMemberRecursive.ps1

.NOTES
Written By: Daniel Streefkerk
Change Log
v1.0, 16/02/2021 - Initial version
#>
Function Get-AzADGroupMemberRecursive {

[cmdletbinding()]
param(
   [parameter(Mandatory=$True,ValueFromPipeline=$true)]
   $GroupDisplayName)

    begin{
        try {
            if ((Get-AzAccessToken) -eq $null) {
                Write-Host "Log in with Connect-AzAccount first"
                Connect-AzAccount
            }
        }
        catch {
            throw "An error occurred while accessing Azure via PowerShell"
        }

    }
    
    process {
        $members = Get-AzADGroupMember -groupDisplayName $GroupDisplayName

        # If group contains no members, return null
        if ($null -eq $members) {
            return
        }

        # Return all members that aren't groups
        $members | Where-Object {$_.ObjectType -ne 'Group'}

        # Get sub-groups, and fetch their memberships recursively
        $groupMembers = $members | Where-Object{$_.ObjectType -eq 'Group'}
        If ($groupMembers) {
            $groupMembers | ForEach-Object {Get-AzADGroupMemberRecursive -GroupDisplayName $_.DisplayName}
        }
    }

}
