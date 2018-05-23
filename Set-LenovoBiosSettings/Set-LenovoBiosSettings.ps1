<#
.SYNOPSIS
Sets BIOS settings from a config file.

.DESCRIPTION 
This script was designed to be used within a ConfigMgr task sequence, however it can also be used stand-alone.

Sets BIOS settings from a .txt config file in a specific folder, and automatically selects the correct
file for the current model PC based on a file naming convention of <MANUFACTURER>_<MODEL>.txt

The script was built with the following requirements in mind:
    
    1. It must be able to handle different model PCs
    2. Configs can't be hard-coded into the script
    3. BIOS Supervisor Passwords must be supported
    4. It needs to support running multiple "passes" with different settings
       at different stages of the task sequence.

Per-model BIOS settings are stored in plain text files in a sub-folder next to the script. The default
folder is 'Settings'.

For example, a Lenovo Yoga BIOS setting file would be stored in .\Settings\LENOVO_20FQ002JAU.txt

Each setting must be on a new line, however # comments are allowed on their own line, or even inline

This has only been tested on Lenovo laptops. The design of the script depends on the way that
Lenovo passes in parameters to the BIOS WMI methods, so I'm unsure if it could be adapted to
be used with a different manufacturer.

.PARAMETER SettingsFolder
The SettingsFolder parameter tells the script where to search for settings files. 

You must specify the folder name as a plain string, not a filesystem path. It needs to be relative to the location from which the script is run.

The default value for this parameter is 'Settings', and the script will search for config
files in <ScriptLocation>\Settings\

You could, for example, store pre-OS deployment settings files in a folder called 'PreOSD',
and post-deployment settings in a folder called 'PostOSD'.

.PARAMETER BiosPassword
Specifies a "Supervisor Password" (BIOS password) to use when saving settings

.EXAMPLE
Apply BIOS settings for this model PC from the Settings folder, without specifying a BIOS password

Set-LenovoBiosSettings

.EXAMPLE
Apply BIOS settings for this model PC from the "PreOSD" folder, without specifying a BIOS password

Set-LenovoBiosSettings -SettingsFolder PreOSD

.EXAMPLE
Apply BIOS settings for this model PC from the "PostOSD" folder, specifying a BIOS password of 'correcthorsestaple'

Set-LenovoBiosSettings -SettingsFolder PreOSD -BiosPassword correcthorsestaple

.LINK
TBA

.NOTES
Written By: Daniel Streefkerk
Website:	http://daniel.streefkerkonline.com
Twitter:	http://twitter.com/dstreefkerk
Todo:       Nothing at the moment

Change Log
v1.0, 23/05/2018 - Initial version
#>

#Requires -RunAsAdministrator
#Requires -Version 4

param(
    [parameter(Mandatory=$false)]
    [string]$SettingsFolder = 'Settings',

    [parameter(Mandatory=$false)]
    [string]$BiosPassword
)

# Set up the TSEnvironment object. Will be used to check if we're running within a ConfigMgr task sequence
$TSEnvironment = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

# This function was borrowed+adapted from https://github.com/NickolajA/PowerShell/blob/master/ConfigMgr/OS%20Deployment/Invoke-CMDownloadBIOSPackage.ps1
function Write-CMLogEntry {
	param(
		[parameter(Mandatory=$true, HelpMessage="Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,

		[parameter(Mandatory=$true, HelpMessage="Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
        [ValidateSet("1", "2", "3")]
		[string]$Severity,

		[parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]$FileName = "LenovoBiosSettings.log"
	)
    
    # If we're not running from within a Task Sequence, log to console in the appropriate colour
    if ($TSEnvironment -eq $null) {
        switch ($Severity) {
            2 {$foregroundColour = [System.ConsoleColor]::Yellow}
            3 {$foregroundColour = [System.ConsoleColor]::Red}
            default {$foregroundColour = [System.ConsoleColor]::White}
        }
        Write-Host $Value -ForegroundColor $foregroundColour
        return
    }

	# Determine log file location
    $LogFilePath = Join-Path -Path $Script:TSEnvironment.Value("_SMSTSLogPath") -ChildPath $FileName

    # Construct time stamp for log entry
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))

    # Construct date for log entry
    $Date = (Get-Date -Format "MM-dd-yyyy")

    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

    # Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""LenovoBIOSSettings"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	
	# Add value to log file
    try {
	    Add-Content -Value $LogText -LiteralPath $LogFilePath -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to $($FileName) file. Error message: $($_.Exception.Message)"
    }
}

# Function to read the contents of a BIOS config file, but remove all comments
# Works on inline comments, as well as comments on their own line
function Read-FileAndRemoveComments([string]$FilePath) {
    
    # Boolean to indicate whether or not the file exists
    $fileFound = Test-Path $FilePath

    # Throw an error if it doesn't exist
    if ($fileFound -eq $null) {
        throw "Could not find a file to read at $FilePath"
    }

    # Read in the file content, stripping out any comments along the way
    $fileContent = Select-String -Path $FilePath -Pattern '([#]+)(.*)' -NotMatch

    # Test if the config line is a 2-column comma-delimited value
    foreach ($line in $fileContent.line) {
        $splitline = $line.split(',')

        # If it is, add it to the $config variable to be returned
        if ($splitline.Count -eq 2) {
            $line
        }
    }   
}

if ($BiosPassword) {
    Write-CMLogEntry -Value "A BIOS password has been passed into the script. It will be used for all Set and Save operations." -Severity 1
}

$thisPC = $null
$thisProduct = $null

try {
    # Get the WMI information about this system
    $thisPC = Get-WmiObject Win32_ComputerSystem
    $thisProduct = Get-WmiObject Win32_ComputerSystemProduct
    Write-CMLogEntry -Value "WMI Query for manufacturer: $($thisPC.Manufacturer)" -Severity 1
    Write-CMLogEntry -Value "WMI Query for product: $($thisPC.Model)" -Severity 1
}
catch {
    Write-Warning -Message "Unable to retrieve WMI data" ; exit 1
}

# Set up some WMI Objects for later
$lenovoSetBios = (gwmi -class Lenovo_SetBiosSetting –namespace root\wmi)
$lenovoSaveBios = (gwmi -class Lenovo_SaveBiosSettings –namespace root\wmi)

# Get the path from which this script is currently running
$scriptPath = $MyInvocation.MyCommand.Source | Split-Path -Parent

# Determine the full path to the 'Settings' folder that lives alongside the script
$settingsFolderPath = Join-Path $scriptPath $SettingsFolder

# Build the file name we're going to look for, based on the manufacturer and model of this system
# For example, an Aussie-delivered X1 Yoga would be LENOVO_20FQ002JAU.txt
$settingsFileName = "{0}_{1}.txt" -f $thisPC.Manufacturer,$thisPC.Model

# Check if the matching settings file exists
$settingsFileExists = Test-Path -Path (Join-Path $settingsFolderPath $settingsFileName)

# If the settings file exists for this system, read the contents
if ($settingsFileExists) {
    $settingsFilePath = Join-Path $settingsFolderPath $settingsFileName
    $settings = Read-FileAndRemoveComments -FilePath $settingsFilePath
    Write-CMLogEntry -Value "Found settings file for '$($thisProduct.Version)' ($($thisProduct.Name)): $settingsFilePath" -Severity 1
} else {
    Write-CMLogEntry -Value "Could not find a matching settings file for '$($thisProduct.Version)' ($($thisProduct.Name)) in $settingsFolderPath" -Severity 3
    exit 1
}

# If we found the settings, log some details about how many items we found in the file
if ($settings) {
    $settingsCount = $settings.Count

    Write-CMLogEntry -Value "Read $settingsCount settings from $settingsFilePath" -Severity 1
    foreach ($setting in $settings) {
        Write-CMLogEntry -Value "Read setting from file: $setting" -Severity 1
    }
} else {
    Write-CMLogEntry -Value "Read file, but no settings found for '$($thisProduct.Version)' ($($thisProduct.Name)) in $settingsFolderPath" -Severity 3
    exit 1
}

$failureCount = 0
$successCount = 0

# Apply each setting
foreach ($setting in $settings) {
    $plainSetting = $setting # store the setting in a variable without the BIOS password, for logging
    Write-CMLogEntry -Value "Applying Setting: $plainSetting" -Severity 1

    # If a BIOS password has been passed in, add that to the setting
    if ($BiosPassword -ne "") {
        $setting = "$setting,$BiosPassword,ascii,us"
    }

    # Set the bios setting
    $status = $lenovoSetBios.SetBiosSetting("$setting")
    
    switch ($status.return.ToUpper()) {
        "SUCCESS" {
            $successCount++
            Write-CMLogEntry "Successfully wrote the setting '$plainSetting'" -Severity 1
        }
        "ACCESS DENIED" {
            $failureCount++
            Write-CMLogEntry "Access was denied. Could not write the setting '$plainSetting'" -Severity 3
        }
        default {
            $failureCount++
            Write-CMLogEntry "An unexpected status message was returned when attempting to write the setting '$plainSetting' - $($status.return)" -Severity 2
        }
    }
}

# Log a message about success or otherwise
if ($successCount -ne $settingsCount) {
    Write-CMLogEntry $("Failed to save {0} of {1} BIOS Settings" -f $failureCount,$settingsCount) -Severity 2
} else {
    Write-CMLogEntry $("Successfully saved {0} of {1} BIOS Settings" -f $successCount,$settingsCount) -Severity 1
}

if ($successCount -lt 1) {
    Write-CMLogEntry "No settings were changed, so no attempt will be made to save the overall BIOS changes" -Severity 3
    exit 1
}

# Save the BIOS settings
try {
    if ($BiosPassword) {
        $overallStatus = $lenovoSaveBios.SaveBiosSettings("$BiosPassword,ascii,us")
    } else {
        $overallStatus = $lenovoSaveBios.SaveBiosSettings()
    }
}
catch {
    Write-CMLogEntry "Error saving changes to BIOS: $($overallStatus.return)" -Severity 3
}

if ($overallStatus.return -eq "Success") {
    Write-CMLogEntry "Changes successfully written to BIOS" -Severity 1
} else {
    Write-CMLogEntry "Failed to write changes to BIOS: $($overallStatus.return)" -Severity 3
    exit 1
}
