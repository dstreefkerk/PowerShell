# Helper script for Monitor-ADGroupMemberShip.ps1
# from https://github.com/lazywinadmin/Monitor-ADGroupMembership/blob/master/Monitor-ADGroupMemberShip.ps1
#
# Dynamically builds up the list of AD groups to monitor, ensuring that we're catching
# all of the relevant groups, and that no new ones slip through the cracks.
#
# This script, Monitor-ADGroupMembership.ps1, and the resulting text file should be stored in C:\Scripts\Monitor-ADGroupMemberShip
#
# You can use https://github.com/dstreefkerk/PowerShell/blob/master/New-ScheduledScriptByMSA.ps1 to run this
# on a schedule using a gMSA
#
# This script first updates the groups text file, and then runs the Monitor-ADGroupMemberShip.ps1 script
$emailFrom = 'AD Group Monitor <groupmonitor@contoso.local>'
$emailTo = 'IT Team <itcontoso.com>'
$smtpServer = 'smtp.contoso.local'

# Our output path. This file will be used by Monitor-ADGroupMembership.ps1
$groupFile = "C:\Scripts\Monitor-ADGroupMemberShip\groups_to_monitor.txt"

# Remove the existing groups text file
Remove-Item $groupFile -Force -ErrorAction SilentlyContinue

# Empty array to hold our groups
$groups = @()

# Add Groups with *admins* in their name
$groups += Get-ADGroup -Filter {name -like "*admins*"} | Where-Object {$_.GroupCategory -eq 'Security'}

# Add Groups with *operators* in their name
$groups += Get-ADGroup -Filter {name -like "*operators*"} | Where-Object {$_.GroupCategory -eq 'Security'}

# Add the built-in Administrators group
$groups += Get-ADGroup -Filter {SID -eq 'S-1-5-32-544'}

# Add any groups in the Contoso-specific 'Administrative Access Groups' OU
#$groups += Get-ADGroup -SearchBase "OU=Administrative Access Groups,DC=contoso,DC=local" -Filter *

# Remove duplicates, sort, and output the group listing to file
$groups | Select-Object -ExpandProperty DistinguishedName -Unique | Sort-Object | Out-File $groupFile -Force

# Invoke the Monitor-ADGroupMemberShip.ps1 script, passing in our groups text file
."C:\Scripts\Monitor-ADGroupMemberShip\Monitor-ADGroupMemberShip.ps1" -File .\groups_to_monitor.txt -Emailfrom $emailFrom -Emailto $emailTo -EmailServer $smtpServer -ExtendedProperty
