<#
.DESCRIPTION
	This script can be used to quickly set up a new scheduled PowerShell script to be run by a gMSA

 	Note that the gMSA needs to be installed on the system in question first.

.SYNOPSIS
	Set up a new Scheduled Task to run a PowerShell script as a gMSA (Group Managed Service Account)

.PARAMETER TaskName
	Specify a name for the scheduled task

.PARAMETER ManagedServiceAccount
	Specify the Managed Service Account to use. Note that it should be in format "DOMAIN\gMSAName$" or "gMSAName$"

.PARAMETER PathToPS1File
	The full path to the PowerShell script that is to be run on a schedule

.PARAMETER StartDateTime
	A DateTime object that denotes when the task will start running. Defaults to the time of task creation

.PARAMETER RepetitionInterval
	A TimeSpan object that denotes how often the task will repeat. Defaults to 60 minutes

.PARAMETER TaskDescription
	A description for the scheduled task. Will appear in the UI

.PARAMETER ExecutionPolicy
	The PowerShell Execution Policy to run the scheduled script under. Defaults to "Bypass"
	
.EXAMPLE
	.\New-ScheduledScriptByMSA.ps1 -TaskName "Test MSA Task" -ManagedServiceAccount 'DOMAIN\gMSA-Blah$' -PathToPS1File "C:\Scripts\RunThisScript.ps1" -TaskDescription "This is a test task"

	Create a scheduled task that runs "C:\Scripts\RunThisScript.ps1" every 60 minutes using the security principal DOMAIN\gMSA-Blah$

.EXAMPLE
	.\New-ScheduledScriptByMSA.ps1 -TaskName "Test MSA Task - 30 days" -ManagedServiceAccount 'DOMAIN\gMSA-Blah$' -PathToPS1File "C:\Scripts\RunThisScript.ps1" -RepetitionInterval (New-TimeSpan -Days 30)

	Create a scheduled task that runs "C:\Scripts\RunThisScript.ps1" every 30 days using the security principal DOMAIN\gMSA-Blah$

.EXAMPLE
	.\New-ScheduledScriptByMSA.ps1 -TaskName "Test MSA Task" -ManagedServiceAccount 'DOMAIN\gMSA-Blah$' -PathToPS1File "C:\Scripts\RunThisScript.ps1" -TaskDescription "This is a test task"

	Create a scheduled task that runs "C:\Scripts\RunThisScript.ps1" every 60 minutes using the security principal DOMAIN\gMSA-Blah$, but under the AllSigned PowerShell Execution Policy -ExecutionPolicy AllSigned

.INPUTS
	System.String

.OUTPUTS
	Nothing

.NOTES
	NAME:	 New-ScheduledScriptByMSA.ps1
	AUTHOR:	 Daniel Streefkerk
	WWW:	 https://daniel.streefkerkonline.com
	Twitter: @dstreefkerk

	REQUIREMENTS:
		-gMSA must be already configured appropriately in AD
		-gMSA must have "Log on as a Service" and "Log on as a Batch Job" rights on the machine in question
		-gMSA must have permissions to read the PowerShell script, and to make changes as required by the script
		-gMSA must be installed (by a local admin) on the system that's having the task installed

	VERSION HISTORY:
		1.0 	14/06/2018
			Initial Version

	TODO:
		- Perhaps include a test to see if the gMSA is installed, however that will add a dependency on the ActiveDirectory module
		- Error handling and logging
#>

PARAM (
	[Parameter(Mandatory = $true, HelpMessage = "You must specify a name for the scheduled task")]
	[ValidateNotNull()]
	[string]$TaskName,

	[Parameter(Mandatory = $true, HelpMessage = "You must specify a managed service account to run the task. Specify as domain.local\gMSAName$")]
	[ValidateNotNull()]
	[string]$ManagedServiceAccount,
	
	[Parameter(Mandatory = $true, HelpMessage = "Specify the full path to the PowerShell Script")]
	[ValidateScript({Test-Path $_})]	
	[String]$PathToPS1File,

	[Parameter(Mandatory = $false, HelpMessage = "Specify when the task should begin running. Default is now()")]
	[datetime]$StartDateTime = (Get-Date),

	[Parameter(Mandatory = $false, HelpMessage = "Specify a repetition interval for the task, as a timespan object. Default is 60 minutes.")]
	[timespan]$RepetitionInterval = (New-TimeSpan -Minutes 60),

	[Parameter(Mandatory = $false, HelpMessage = "Specify an optional description for the task")]
	[String]$TaskDescription,

	[Parameter(Mandatory = $false, HelpMessage = "Run the scheduled script under this execution policy")]
	[ValidateSet("AllSigned", "Bypass", "Default", "RemoteSigned", "Restricted", "Undefined", "Unrestricted")]	
	[String]$ExecutionPolicy = "Bypass"
)

# Determine the OS version this is running on
$osVersion = [version]::Parse((Get-WmiObject Win32_OperatingSystem).Version)

# Check if a task already exists with that name
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue ) { throw "A task with that name already exists."}

# Some scripts need the working directory set, so we'll figure out what that should be
$workingDirectory = Split-Path $PathToPS1File -Parent

# Set up the scheduled task action to run powershell.exe with our desired parameters
$taskAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-ExecutionPolicy $ExecutionPolicy -File ""$PathToPS1File""" -WorkingDirectory $workingDirectory

# Set up the scheduled task trigger, to run as desired
if ($osVersion.Major -lt 10) {
    # Server 2012 R2 seems to need the -RepetitionDuration parameter
    $taskTrigger = New-ScheduledTaskTrigger -Once -At $StartDateTime -RepetitionInterval $RepetitionInterval -RepetitionDuration ([System.TimeSpan]::MaxValue)
} else {
    # Server 2016 doesn't like the RepetitionDuration being set to [System.TimeSpan]::MaxValue
    $taskTrigger = New-ScheduledTaskTrigger -Once -At $StartDateTime -RepetitionInterval $RepetitionInterval
}

# Set up a scheduled task principal to run the task
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $ManagedServiceAccount -RunLevel Highest -LogonType Password

# If no description has been specified, at least include a rudimentary one
if ($TaskDescription -eq "") {
    $TaskDescription = "Runs $PathToPS1File as the MSA $ManagedServiceAccount"
}

# Create the scheduled task
Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal
