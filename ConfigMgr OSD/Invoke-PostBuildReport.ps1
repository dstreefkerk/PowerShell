# Generate a basic HTML report containing some settings we're interested in 
# post-build and place it in c:\windows\build.html
#
# Daniel Streefkerk, 28/05/2018

function Get-CSDeviceGuardStatus {
# from https://github.com/PowerShellMafia/CimSweep/blob/master/CimSweep/Auditing/DeviceGuard.ps1

    [CmdletBinding()]
    [OutputType('CimSweep.DeviceGuardStatus')]
    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $CIMSessionCount = 1
        } else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0

        # Also applies to RequiredSecurityProperties
        $AvailableSecurityPropertiesTable = @{
            1 = 'BaseVirtualizationSupport'
            2 = 'SecureBoot'
            3 = 'DMAProtection'
            4 = 'SecureMemoryOverwrite'
            5 = 'UEFICodeReadOnly'
            6 = 'SMMSecurityMitigations1.0'
        }

        # Also applies to UsermodeCodeIntegrityPolicyEnforcementStatus
        $CodeIntegrityPolicyEnforcementStatusTable = @{
            0 = 'Off'
            1 = 'AuditMode'
            2 = 'EnforcementMode'
        }

        # Also applies to SecurityServicesRunning
        $SecurityServicesConfiguredTable = @{
            1 = 'CredentialGuard'
            2 = 'HypervisorEnforcedCodeIntegrity'
        }

        $VirtualizationBasedSecurityStatusTable = @{
            0 = 'Off'
            1 = 'Configured'
            2 = 'Running'
        }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Device Guard configuration sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }
            
            $DeviceGuardStatus = Get-CimInstance -Namespace ROOT\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard @CommonArgs

            # An object will not be returned if the namespace/class do not exist
            # e.g. <= Win8 and Server 2012
            if ($DeviceGuardStatus) {
                # Map numeric settings values to human readable strings.

                # All of these properties are UInt32 values.
                # The currently defined values are safe to cast to Int32
                $AvailableSecurityProperties = $DeviceGuardStatus.AvailableSecurityProperties |
                    ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }

                $CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.CodeIntegrityPolicyEnforcementStatus]

                $RequiredSecurityProperties = $DeviceGuardStatus.RequiredSecurityProperties |
                    ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }

                $SecurityServicesConfigured = $DeviceGuardStatus.SecurityServicesConfigured |
                    ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }

                $SecurityServicesRunning = $DeviceGuardStatus.SecurityServicesRunning |
                    ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }

                $UsermodeCodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.UsermodeCodeIntegrityPolicyEnforcementStatus]

                $VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatusTable[[Int32] $DeviceGuardStatus.VirtualizationBasedSecurityStatus]
            
                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.DeviceGuardStatus'
                    AvailableSecurityProperties = $AvailableSecurityProperties
                    CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatus
                    InstanceIdentifier = $DeviceGuardStatus.InstanceIdentifier
                    RequiredSecurityProperties = $RequiredSecurityProperties
                    SecurityServicesConfigured = $SecurityServicesConfigured
                    SecurityServicesRunning = $SecurityServicesRunning
                    UsermodeCodeIntegrityPolicyEnforcementStatus = $UsermodeCodeIntegrityPolicyEnforcementStatus
                    Version = $DeviceGuardStatus.Version
                    VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatus
                }

                if ($DeviceGuardStatus.PSComputerName) {
                    $ObjectProperties['PSComputerName'] = $DeviceGuardStatus.PSComputerName
                }

                [PSCustomObject] $ObjectProperties
            }
        }
    }
}

# Wrap whatever's passed into this function in HTML and HEAD tags with some CSS included
function WrapInHtmlPage($html) {
    # Set up some CSS
    $style = "<style>BODY{font-family: Arial; font-size: 10pt;}"
    $style += "TABLE{border: 1px solid black; border-collapse: collapse;}"
    $style += "TH{border: 1px solid black; background: #dddddd; padding: 5px; }"
    $style += "TD{border: 1px solid black; padding: 5px; }"
    $style += "td.grey {background-color: #bbbbbb; color: #ffffff; font-weight: bold;}"
    $style += "h2 {margin-bottom: 5px;}"
    $style += "</style>"

    $newHTML = "<html>"
    $newHTML += $style

    $newHTML += $html

    $newHTML += "</html>"

    return $newHTML
}

# Wrap whatever's passed into this function in HTML and HEAD tags with some CSS included
function WrapInVerticalTable($object) {

    $html = '<table>'  

    foreach ($row in $object.Keys) {
        $html += "<tr><td class=""grey"">$($row | Out-String)</td><td>$($object[$row] | Out-String)</td></tr>"
    }

    $html += '</table>'

    $html
}

# Collection info via CIM
$computerSystemProduct = Get-CimInstance Win32_ComputerSystemProduct
$operatingSystem = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive

# Get Basic Information
$basicDetails = [ordered]@{  'Computer Name' = $operatingSystem.CSName;
                    'Operating System' = ($operatingSystem.Name).Split('|')[0];
                    'OS Version' = $operatingSystem.Version;
                    'Install Date' = $operatingSystem.InstallDate;
                    'Computer Model' = $computerSystemProduct.Version;
                    'Computer Model Number' = $computerSystemProduct.Name;
                    'Serial Number' = $computerSystemProduct.IdentifyingNumber;
                    'UUID' = $computerSystemProduct.UUID
                }

# Get BIOS Information
$biosDetails = [ordered]@{ 'BIOS Version' = $bios.SMBIOSBIOSVersion;
                    'BIOS Date' = $bios.ReleaseDate
                }

# Get BitLocker information
$bitlockerDetails = [ordered]@{ 'Protection Status' = $bitlocker.ProtectionStatus;
                                'Volume Status' = $bitlocker.VolumeStatus;
                                #'Key Protector' = $bitlocker.KeyProtector | Out-String
                              }

# Secure Boot information
$secureBootDetails = [ordered]@{'Secure Boot Enabled?'=(Confirm-SecureBootUEFI)}

# Device Guard information
$deviceGuard = Get-CSDeviceGuardStatus
$deviceGuardDetails = [ordered]@{ 'Security Services Configured' = $deviceGuard.SecurityServicesConfigured;
                                  'Security Services Running' = $deviceGuard.SecurityServicesRunning;
                                  'Available Security Properties' = $deviceGuard.AvailableSecurityProperties
                              }

# Display/Output
$innerHTML = "<h1>Post-OSD Report for $($operatingSystem.CSName)</h1>"
$innerHTML += "<h2>System Information</h2>"
$innerHTML += WrapInVerticalTable($basicDetails)

$innerHTML += "<h2>BIOS</h2>"
$innerHTML += WrapInVerticalTable($biosDetails)

$innerHTML += "<h2>BitLocker</h2>"
$innerHTML += WrapInVerticalTable($bitlockerDetails)

$innerHTML += "<h2>Secure Boot</h2>"
$innerHTML += WrapInVerticalTable($secureBootDetails)

$innerHTML += "<h2>Device Guard/Credential Guard</h2>"
$innerHTML += WrapInVerticalTable($deviceGuardDetails)

$innerHTML += "<p><em>Report generated at conclusion of OSD process: $((Get-Date -Format 'dd/MM/yyyy HH:mm:ss'))</em></p>"

$innerHTML = WrapInHtmlPage($innerHTML)

$innerHTML | Out-File (Join-Path $env:windir 'build.html') -Force -Verbose
