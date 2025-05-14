# Get all enabled accounts in AD
$allEnabledAccounts = Get-ADUser -Filter {enabled -eq $true} -Properties Manager

# Extract the manager information from the above accounts
$allManagers = $allEnabledAccounts | Group-Object -Property Manager | Sort-Object -Property Count -Descending

foreach ($manager in $allManagers) {
    # If the manager name is empty, skip
    if ([string]::IsNullOrEmpty($manager.Name)) { continue }

    # Find the matching AD user details for the manager
    $matchingADUser = $null; $matchingADUser = ($manager.Name | Get-ADUser -Properties mail)

    # If a matching AD user cannot be found, skip
    if ($null -eq $matchingADUser) { continue }

    # If the matching manager's AD account is disabled, skip
    if ($matchingADUser.Enabled -eq $false) { continue }

    # Output our formatted object - Name|GivenName|Surname|Mail|DirectReportCount|DirectReports
    $matchingADUser | Select-Object Name,GivenName,Surname,Mail,@{n='DirectReportCount';e={$manager.Count}},@{n='DirectReports';e={($manager.Group | Select-Object -ExpandProperty Name | Sort-Object) -join ','}}
}
