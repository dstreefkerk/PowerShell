<#
.SYNOPSIS
Invoke-SetScanFolderPermissions.ps1 - Lock down user scan-to-SMB folders

.DESCRIPTION
Toshiba multi-function devices can automatically create a new "SCAN-<samaccountname>" folder when
a new user scans to a configured SMB share. Problem is, these folders aren't locked down to that specific user.

This script will run through a share with existing user scan folders and lock down the permissions

This script uses ADSI to query AD, so no ActiveDirectory PowerShell module required, however you will need
the 'File System Security PowerShell Module' from the Script Center:
https://gallery.technet.microsoft.com/scriptcenter/1abd77a5-9c0b-4a2b-acef-90dbb2b84e85

You could repurpose this script to automatically set up user-specific folders and lock them down.

Set the $scanRoot, $domainName, and $scanAccount variables to match your own environment

.LINK
TBA

.NOTES
Written By: Daniel Streefkerk
Website:    http://daniel.streefkerkonline.com
Twitter:    http://twitter.com/dstreefkerk
Todo:       Nothing at the moment

Change Log
v1.0, 07/06/2018 - Initial version
#>

Import-Module NTFSSecurity -ErrorAction Stop

$scanRoot = 'D:\Scanned Documents'
$domainName = 'CONTOSO'
$scanAccount = 'CONTOSO\CopierServiceAccount' # account/group that the copiers use. Will be added to NTFS permissions

# Simple logging function. Log file path is hard-coded into the function parameters
function Write-LogEntry($Message,$Level = "Information", $LogFile = 'C:\Scripts\Logs\Invoke-SetScanFolderPermissions.log') {
    if ((Test-Path $LogFile) -eq $false) {
        "$(Get-Date) - Log File Created" | Out-File $LogFile -Force
    }
    
    "$(Get-Date) - $Level - $Message" | Out-File $LogFile -Append
}

# Get all of our users' scan folders
$folders = Get-ChildItem $scanRoot

# Some numbers for logging purposes
$folderCount = ($folders | Measure-Object) | Select-Object -ExpandProperty Count
$changedCount = 0

foreach ($folder in $folders) {
    # Pull the username out of the scan folder name
    $username = $folder.Name.replace('SCAN-','')
    
   if ($username -eq $null) {
        Write-LogEntry "Couldn't extract a username from $($folder.fullname)" -Level Error
        continue
    }
  
    # Find a matching user object in AD
    $matchingUser = ([ADSISEARCHER]"samaccountname=$($username)").Findone()
    
    # If the username in the folder doesn't match an AD user, skip over this folder
    if ($matchingUser -eq $null) {
        Write-LogEntry "Couldn't find a matching AD user for $username" -Level Error
        continue
    }
       
    # Check existing inheritance, skip folder if it's already disabled
    $existingInheritance = $folder | Get-NTFSInheritance
    if ($existingInheritance.AccessInheritanceEnabled -eq $false) {
        continue
    }
    
    # Form up a CONTOSO\<samaccountname> variable for use later
    $matchingUserNTAccountName = "$domainName\$($matchingUser.Properties.samaccountname)"
    
    # Get the existing NTFS Security Descriptor for this folder
    $descriptor = $folder | Get-NTFSSecurityDescriptor
    
    Write-LogEntry "Folder $($folder.FullName): Disabling inheritance"
    $descriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
    
    Write-LogEntry "Folder $($folder.FullName): Clearing existing NTFS permissions"
    $descriptor | Clear-NTFSAccess

    Write-LogEntry "Folder $($folder.FullName): Granting NT AUTHORITY\SYSTEM FullControl"
    $descriptor | Add-NTFSAccess -Account 'NT AUTHORITY\SYSTEM' -AccessRights 'FullControl' -AppliesTo ThisFolderSubfoldersAndFiles
    
    Write-LogEntry "Folder $($folder.FullName): Granting BUILTIN\Administrators FullControl"
    $descriptor | Add-NTFSAccess -Account 'BUILTIN\Administrators' -AccessRights 'FullControl' -AppliesTo ThisFolderSubfoldersAndFiles
    
    Write-LogEntry "Folder $($folder.FullName): Granting $scanAccount FullControl"
    $descriptor | Add-NTFSAccess -Account $scanAccount -AccessRights 'FullControl' -AppliesTo ThisFolderSubfoldersAndFiles
    
    Write-LogEntry "Folder $($folder.FullName): Granting $matchingUserNTAccountName FullControl"
    $descriptor | Add-NTFSAccess -Account $matchingUserNTAccountName -AccessRights 'FullControl' -AppliesTo ThisFolderSubfoldersAndFiles
    
    try {
        Write-LogEntry "Folder $($folder.FullName): Writing Security Descriptor"
        $descriptor | Set-NTFSSecurityDescriptor -ErrorAction Stop
        }
    catch {
        Write-LogEntry -Message "An error occurred when attempting to write the security descriptor for $($folder.fullname)" -Level Error
    }

    # increment our change tracking counter
    $changedCount++
    
    $folder = $null
    $descriptor = $null
}

Write-LogEntry "Script completed at $(Get-Date). Folders checked: $folderCount, Folders modified: $changedCount"
