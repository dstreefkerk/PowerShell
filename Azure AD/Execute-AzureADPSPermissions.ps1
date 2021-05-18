Connect-AzureAD
 
# Grab the permission assignments from Azure AD
$delegatedPermissions = Get-AzureADPSPermissions.ps1 -ShowProgress -DelegatedPermissions -UserProperties @('DisplayName','UserPrincipalName','AccountEnabled','PhysicalDeliveryOfficeName') -ServicePrincipalProperties @('DisplayName','ReplyUrls','ServicePrincipalType','AppRoleAssignmentRequired','PublisherName','Oauth2Permissions','HomePage') -PrecacheSize 1500
 
# Export the properties we're after to a CSV file
$delegatedPermissions | Select-Object -Property 'PrincipalDisplayName','PrincipalUserPrincipalName','PrincipalAccountEnabled','PrincipalPhysicalDeliveryOfficeName','ClientDisplayName','ClientPublisherName','ResourceAppRoleAssignmentRequired','Permission','PermissionType','ConsentType' | Export-Csv $env:USERPROFILE\Desktop\aad_delegated_permissions.csv -NoTypeInformation -Force
