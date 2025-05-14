<#
.DESCRIPTION
	Extracts information from AD about members of the default privileged groups.

    Saves this information into CSV format on the desktop.

    RUN THIS AS A REGULAR AD USER, it does NOT need to be run as a Domain Admin.

.SYNOPSIS
	Generates a CSV extract, listing members of the built-in AD privileged groups like "Schema Admins", "Domain Admins", and so on.

.EXAMPLE
	.\Invoke-GetPrivilegedUsers.ps1

	Retrieve privileged group membership details for the AD domain in which the script is being executed

.INPUTS
	None

.OUTPUTS
	CSV File on executing user's desktop

.NOTES
	NAME:	 Invoke-GetPrivilegedUsers.ps1
	AUTHOR:	 Daniel Streefkerk
	WWW:	 https://daniel.streefkerkonline.com
	Twitter: @dstreefkerk

	REQUIREMENTS:
		- ActiveDirectory PowerShell module

	VERSION HISTORY:
		1.0 05/02/2019
			- Initial Version
		
	TODO:
		- None. This is the basic version of the script. An expanded version already exists, I just need to clean it up before publishing it.
#>

Write-Host "Loading ActiveDirectory PowerShell module"
Import-Module ActiveDirectory -ErrorAction Stop

Function Invoke-GetPrivilegedUser {
	# List of AD groups to audit
	$groupNames = 'Domain Admins','Schema Admins','Enterprise Admins','Group Policy Creator Owners','Protected Users','Administrators','DNSAdmins','Account Operators','Server Operators','Print Operators','Backup Operators','Remote Management Users'

	# Some other property names we'll use later
	$organisationalProperties = 'Name','Account Owner','Purpose','Last Review Date'
	$adProperties = 'Name','DistinguishedName','Enabled','LastLogonDate','Created','Modified','PasswordLastSet','PasswordNeverExpires','PasswordNotRequired','PrimaryGroup','TrustedForDelegation','TrustedToAuthForDelegation','AdminCount'
	$orderOfProperties = $organisationalProperties + $groupNames + $adProperties
	
	# Array to hold our AD groups
	$groups = @()

	# Retrieve all of the groups from AD
	foreach ($groupName in $groupNames) {
		Write-Host "Reading AD Groups"
		$groups += Get-ADGroup $groupName -Properties Members
	}

	# Sort our list of groups for display purposes later
	Write-Host "Sorting Group list"
	$groups = $groups | Sort-Object -Property Name

	# Retrieve a unique list of all members of the privileged groups
	Write-Host "Retrieving members of privileged groups"
	$allUsers = $groups | Select-Object -ExpandProperty Members
	
	# Add to the existing list of all users every account that has an AdminCount of 1
	Write-Host "Retrieving all users with AdminCount of 1"
	$allUsers += Get-ADUser -Filter {AdminCount -eq 1} | Select-Object -ExpandProperty DistinguishedName
	
	# Sort the list of all users, and ensure that only unique values remain
	Write-Host "Sorting user list"
	$allUsers = $allUsers | Sort-Object -Unique
	
	#Testing
	#$allUsers = $allUsers | select-object -first 5

	# Loop through all of the users we've identified, and build up a custom PSObject to hold our report data
	foreach ($user in $allUsers) {
		Write-Host "Processing user: $user" -ForegroundColor Yellow
		
		$thisUser = $user | Get-ADUser -Properties MemberOf,AdminCount,Name,DistinguishedName,LastLogonDate,Created,Modified,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,PrimaryGroup,TrustedForDelegation,TrustedToAuthForDelegation -ErrorAction SilentlyContinue

		if ($thisUser -eq $null) { continue }
		
		Write-Host " $($thisUser.name): Successfully read AD properties"
		
		Write-Host " $($thisUser.name): Generating custom object for reporting"
		
		# New custom object
		$thisObject = New-Object PSObject -Property @{
				Name = $thisUser.Name
				'Account Owner' = ''
				Purpose = ''
				'Last Review Date' = ''
				DistinguishedName = $user
				AdminCount = $thisUser.AdminCount
				LastLogonDate = $thisUser.LastLogonDate
				Created = $thisUser.Created
				Modified = $thisUser.Modified
				PasswordLastSet = $thisUser.PasswordLastSet
				PasswordNeverExpires = $thisUser.PasswordNeverExpires
				PasswordNotRequired = $thisUser.PasswordNotRequired
				PrimaryGroup = $thisUser.PrimaryGroup
				TrustedForDelegation = $thisUser.TrustedForDelegation
				TrustedToAuthForDelegation = $thisUser.TrustedToAuthForDelegation
		}
		
		# Check if this user is in any of the groups we're investigating
		foreach ($group in $groups) {
			Write-Host " $($thisUser.name): Checking group membership of group: $group"
		
			# Check if user is in each group, and whether membership is direct or nested
			if (($group.Members).Contains($user)) {
				# User is directly a member of this group
				$thisObject | Add-Member -MemberType NoteProperty -Name $group.Name -Value "Direct"
				Write-Host " $($thisUser.name): IS a DIRECT member of group: $group" -ForegroundColor Green
			} else {
				if (($group.DistinguishedName | Get-ADGroupMember -Recursive -ErrorAction SilentlyContinue) | Select-Object -ExpandProperty distinguishedName | Where-Object {$_ -eq $user}) {
					# User is a nested member of this group
					$thisObject | Add-Member -MemberType NoteProperty -Name $group.Name -Value "Nested"	
					Write-Host " $($thisUser.name): IS a NESTED member of group: $group" -ForegroundColor Green
				} else {
					# User is not a member of this group
					$thisObject | Add-Member -MemberType NoteProperty -Name $group.Name -Value "No"
					Write-Host " $($thisUser.name): Is NOT a member of group: $group"
				}
			}
		}

		Write-Host " $($thisUser.name): Adding data to our output collection" -ForegroundColor Cyan
		$thisObject | Select-Object -Property $orderOfProperties -ErrorAction SilentlyContinue
	}
}

Invoke-GetPrivilegedUser | Export-Csv -Path (Join-Path $env:userprofile "desktop\$($env:USERDNSDOMAIN)-PrivilegedUsers.csv") -NoTypeInformation -Force
