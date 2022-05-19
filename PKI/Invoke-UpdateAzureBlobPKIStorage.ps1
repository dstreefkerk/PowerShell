<#
.SYNOPSIS
Copies CRL files from a Windows Enterprise PKI up to Azure AD Blob Storage using AzCopy

.DESCRIPTION 
This script was written to facilitate a highly-available Azure-based CDP and AIA
location instead of the traditional technique of hosting CRLs and AIAs on
internal web servers and/or opening them up to the Internet through
a DMZ or via a reverse proxy like Azure AD App Proxy.

Requirements:
  1. AzCopy installed on the CA server - http://aka.ms/azcopy
  2. Outbound HTTPS from the CA server to Azure Blob Storage
  3. An Azure Storage Account with blob storage configured for HTTP access
  4. A folder in the blob storage named 'pki' (https://<storageaccountname>.blob.core.windows.net/pki/)
  5. A SAS key with read/write/change access to blob storage only (don't assign more access than necessary)
  6. A scheduled task running hourly as NETWORK SERVICE to call this PowerShell script
  7. Create a folder in %PROGRAMDATA% called ScriptLogs, and give NETWORK SERVICE [Modify] rights

Ensure that you update the first two variables below with valid details pointing to your
Azure blob storage.

The benefit of using AzCopy is that we can have it copy files up to Azure only if
they've changed, thereby avoiding the need to do any complex file/date comparisons or
incur additional data transfer costs.

Note that if you change your storage account key, you'll need to regenerate your SAS key.

This script will copy the verbose AzCopy log for successful or failed transfers to %appdata%\ScriptLogs
(It won't log anything when 0 files were copied)

If your CA server uses Windows in a language other than English you'll need to adjust the logging code to look
for the correct text strings in the AzCopy output.

.LINK
https://github.com/dstreefkerk/PowerShell/blob/master/PKI/Invoke-UpdateAzureBlobPKIStorage.ps1

.NOTES
Written By: Daniel Streefkerk
Website:    http://daniel.streefkerkonline.com
Twitter:    http://twitter.com/dstreefkerk
Todo:       Nothing at the moment

Change Log
v1.0, 05/10/2018 - Initial version
#>

# Blob storage location to upload files to
$azCopyDestination = "https://<storageaccountname>.blob.core.windows.net/pki/?"

# SAS key for the above destination
$azCopyDestinationSASKey = "<YOUR SAS KEY HERE>"

# Log location for AzCopy
$azCopyLogLocation = Join-Path $env:SystemRoot 'Temp\AzCopy-PKI.log'

# Long-term log for successful copy actions
$azCopyLogArchiveLocation = Join-Path $env:ProgramData 'ScriptLogs\Invoke-UpdateAzureBlobPKIStorage.log'

# If the archive log file doesn't exist
if ((Test-Path $azCopyLogArchiveLocation) -eq $false) {
    $archiveLogFolder = Split-Path $azCopyLogArchiveLocation -Parent

    # If the ScriptLogs folder doesn't exist in %ProgramData%, create it
    if ((Test-Path $archiveLogFolder) -eq $false) {
        New-Item $archiveLogFolder -ItemType Directory -Force
    }
}

# Determine if AzCopy is installed
$azCopyBinaryPath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft SDKs\Azure\AzCopy\AzCopy.exe'
if ((Test-Path $azCopyBinaryPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) -eq $false) {
    throw "Missing AzCopy.exe"
}

# Check for the defaul CertEnroll folder
$cdpLocalLocation = Join-Path $env:SystemRoot 'System32\CertSrv\CertEnroll'
if ((Test-Path $cdpLocalLocation -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) -eq $false) {
    throw "It doesn't appear that the default local CDP and AIA location is being used"
}

# Grab the existing ErrorActionPreference and save it for later
$existingErrorActionPreference = $ErrorActionPreference

# Force PowerShell to stop on errors for the Call Operator below
$ErrorActionPreference = 'Stop'

try {
    # Run AzCopy to copy only .crl files that are newer than already exist at the destination
    &$azCopyBinaryPath cp $cdpLocalLocation $azCopyDestination$azCopyDestinationSASKey --include-pattern="*.crl" --log-level="error" --check-length=false
    }
catch {
    $error | Out-File $azCopyLogArchiveLocation -Append
    Remove-Item $azCopyLogLocation -Force
    exit 9999
}

# Set the ErrorActionPreference back to what it was prior to running AzCopy
$ErrorActionPreference = $existingErrorActionPreference

# Read in the contents of the latest AzCopy Log and archive it if there have been successful or failed transfers
if (Test-Path $azCopyLogLocation) {
    $transferSummaryText = Get-Content $azCopyLogLocation -Tail 5

    # Extract the Total Files Transferred count
    $totalFilesTransferred = (($transferSummaryText | Where-Object {$_ -like "Total files transferred*"}) | Select-String -Pattern "\d+").Matches[0].Value

    # Extract the Transfer Failed count
    $transferFailed = (($transferSummaryText | Where-Object {$_ -like "Transfer failed*"}) | Select-String -Pattern "\d+").Matches[0].Value

    # If a transfer failed or some files were actually transferred, archive the log
    if (($transferFailed -gt 0) -or ($totalFilesTransferred -gt 0)) {
        (Get-Content $azCopyLogLocation) | Out-File $azCopyLogArchiveLocation -Append
    }

    # Remove the log for this run
    Remove-Item $azCopyLogLocation -Force

    # Throw an error code if transfers failed. This will bubble up to the scheduled task status
    if ($transferFailed -gt 0) {
        exit 9999
    }
}
