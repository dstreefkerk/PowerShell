$lowRiskPermissions = @('User.Read','offline_access','openid','profile')
$csvContent = Import-Csv $env:USERPROFILE\Desktop\aad_delegated_permissions.csv
 
$consentsByApp = ($csvContent | Group-Object -Property ClientDisplayName) | Sort-Object -Property Count -Descending
 
$output = @()
 
foreach ($app in $consentsByApp) {
    $lowRiskPermissionsSufficient = $false
    $appPermissions = $app.group.Permission | Sort-Object -Unique
    $disabledUserAccounts = $app.group | Where-Object {$_.PrincipalAccountEnabled -eq $false} | Sort-Object -Unique -Property PrincipalUserPrincipalName
    $enabledUserAccounts = $app.group | Where-Object {$_.PrincipalAccountEnabled -eq $true} | Sort-Object -Unique -Property PrincipalUserPrincipalName
    $extraPermissions = ($appPermissions | Compare-Object -ReferenceObject $lowRiskPermissions | Where-Object {$_.SideIndicator -eq '=>'} | Select-Object -ExpandProperty InputObject) -join ','
    if ([string]::IsNullOrEmpty($extraPermissions)) { $lowRiskPermissionsSufficient = $true }
    $appHasAdminConsent = ($app.Group.ConsentType | Sort-Object -Unique)  -contains 'AllPrincipals'
    $appHasUserConsent = ($app.Group.ConsentType | Sort-Object -Unique)  -contains 'Principal'
 
    $tempOutput = [pscustomobject][ordered]@{
        ApplicationName = $app.Group.ClientDisplayName | Sort-Object -Unique
        ApplicationPublisherName = ($app.Group.ClientPublisherName | Sort-Object -Unique) -join ','
        DisabledAccounts = $disabledUserAccounts | Measure-Object | Select-Object -ExpandProperty Count
        EnabledAccounts = $enabledUserAccounts | Measure-Object | Select-Object -ExpandProperty Count
        LowRiskPermissionsSufficient = $lowRiskPermissionsSufficient
        ExtraPermissionsRequired = $extraPermissions
        AppHasAdminConsents = $appHasAdminConsent
        AppHasUserConsents = $appHasUserConsent
        AppPermissionsGranted = $appPermissions -join ','
    }
 
    $output += $tempOutput
}
 
$output | Export-Csv -Path $env:USERPROFILE\desktop\analyse-apps.csv -NoTypeInformation -force
