#Requires -Version 5
<#
.SYNOPSIS
Invoke-EndpointCleanup - Deregister sensors from the Carbon Black console via the Devices API
https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/devices-api/

.DESCRIPTION
This script takes a CSV file listing Carbon Black (Cb) endpoints and deregisters those endpoints via the Cb API.

Required API permissions:
1. Create an Access Level with the following permissions:
    a. device.uninstall - Execute
    b. device - Read

2. Create an API key that uses the 'Custom' Access Level Type, and select the Access Level created earlier.
3. Copy and paste the API ID and API Key into the script below.
4. Ensure that you delete the API key when you're done with it.

Input CSV Format:
The input CSV file must contain the following columns (case-sensitive):
- name: The name of the device.
- sensorVersion: The version of the Cb sensor installed.
- lastContactTime: The last time the endpoint connected, in the format 'YYYY-MM-DDTHH:MM:SSZ'.
- policyName: The name of the policy applied to the device.
- deviceId: The unique device ID in the Cb console.
- status: The status of the device, expected to be 'inactive' for processing.

Example of input CSV:
name,sensorVersion,lastContactTime,policyName,deviceId,status
DeviceA,7.2.1,2019-05-10T12:34:56Z,Policy1,12345,inactive
DeviceB,7.2.1,2018-11-15T08:22:13Z,Policy2,67890,inactive

Use at your own risk. This script is provided as-is and is not supported by Carbon Black (or by the author).

.OUTPUTS
Writes a log in CSV format to $env:TEMP\cb_agent_cleanup.csv and appends if it already exists.

.EXAMPLE
Invoke-EndpointCleanup.ps1

.NOTES
Written By: Daniel Streefkerk
Todo:       Nothing at the moment
Change Log
v1.0, 17 May 2023 - Initial version
#>

$apiID = "##########"
$apiKey = "########################"
$cbcHostname = "defense-######.conferdeploy.net" # https://developer.carbonblack.com/reference/carbon-black-cloud/authentication/#hostname
$orgKey = "########" # found in your product console under Settings > API Access > API Keys
$endpointCSVPath = "c:\temp\inactive_endpoints.csv"

# Agents with last contact in these years will be deregistered. All other years will be ignored
$yearsToProcess = @("2017","2018","2019")

# Set up the path to the log file (%temp%\cb_agent_cleanup.csv)
$logFile = Join-Path $env:TEMP -ChildPath "cb_agent_cleanup.csv"

# Object grouping related stuff
$processingGroupSize = 250
$index = [pscustomobject] @{ Value = 0 }

# Device Action API response codes, used when
$apiCodes = @{
    200 = "Successful request"; # Cb API response code
    204 = "Successful device action creation"; # Cb API response code
    400 = "Invalid request"; # Cb API response code
    500 = "Internal server error" # Cb API response code
    999 = "Dev/Test Code" # Custom response code used by this script
    998 = "Script Error" # Custom response code used by this script
}

# Function takes an 'endpoint' in CSV format, selects some data, adds log info, and writes it to our log CSV
function Write-ResultsLog([object]$Endpoints,[string]$Result,[int]$ResultCode,[string]$Notes) {
    foreach ($endpoint in $Endpoints) {
        $tempObject = $endpoint | Select-Object -Property name,sensorVersion,lastContactTime,policyName,deviceId

        $tempObject | Add-Member -MemberType NoteProperty -Name "deregisterResult" -Value $Result
        $tempObject | Add-Member -MemberType NoteProperty -Name "resultCode" -Value $ResultCode
        $tempObject | Add-Member -MemberType NoteProperty -Name "resultDescription" -Value $apiCodes[$ResultCode]
        $tempObject | Add-Member -MemberType NoteProperty -Name "notes" -Value $Notes

        $tempObject | Export-Csv -Path $logFile -Append -Force -NoTypeInformation
    }
}

# Import our list of inactive endpoints from CSV
Write-Host "Importing endpoint list from CSV"
$inactiveEndpointCSVExtract = Import-Csv $endpointCSVPath
Write-Host "Loaded $($inactiveEndpointCSVExtract | Measure-Object | Select-Object -ExpandProperty Count) endpoints from CSV"

# Narrow down the scope of inactive endpoints, just for paranoia's sake
Write-Host "Filtering CSV endpoint data to inactive endpoints from in-scope years only"
$inactiveEndpoints = $inactiveEndpointCSVExtract | Where-Object {($_.lastcontacttime.substring(0,4)) -in $yearsToProcess}

# Filter to ensure that only inactive endpoints are included
$inactiveEndpoints = $inactiveEndpoints | Where-Object {$_.status -eq "inactive"}
Write-Host "After filtering, $($inactiveEndpoints | Measure-Object | Select-Object -ExpandProperty Count) endpoints selected for deregistration"

# Group our endpoints into groups of $processingGroupSize
Write-Host "Grouping endpoint list into groups of $processingGroupSize"
$groupedInactiveEndpoints = $inactiveEndpoints | Group-Object -Property { [math]::Floor($index.value++ / $processingGroupSize) }

# Set up our request headers for the API call
$requestHeaders = @{
    "X-Auth-Token" = "$apiKey/$apiID"
    "Content-Type" = "application/json"
}

# Iterate through each group of endpoints and make the API call to deregister them
foreach ($group in $groupedInactiveEndpoints) {
    $groupStartTime = [datetime]::Now # Used to time how long the API call took
    Write-Host "Processing group $([int]::Parse(($group.name)) + 1) of $($groupedInactiveEndpoints.Count) ($($group.Count) endpoints)"
    
    # Grab some info for logging to screen, to help us keep track of where we're at
    $firstDevice = $null; $firstDevice = $group.group | Select-Object -First 1
    $lastDevice = $null; $lastDevice = $group.group | Select-Object -Last 1
    Write-Host ("From {0}:{1} ({2}) to {3}:{4} ({5})" -f $firstDevice.deviceId,$firstDevice.name,$firstDevice.lastContactTime,$lastDevice.deviceId,$lastDevice.name,$lastDevice.lastContactTime )

    # Set up our device actions URL
    $deviceActionsURL = "https://$cbcHostname/appservices/v6/orgs/$orgKey/device_actions"

    # Set up the request body
    $requestBody = [ordered]@{
        "action_type" = "UNINSTALL_SENSOR"
        "device_id" = $group.group.deviceid
    } | ConvertTo-Json -Compress # We had to use the -Compress parameter as the Cb API didn't like nicely-formatted JSON containing newlines

    try {
        $apiResponse = Invoke-WebRequest -Method Post -Uri $deviceActionsURL -Headers $requestHeaders -Body $requestBody -UseBasicParsing

        Write-ResultsLog -Endpoints $group.Group -Result "Success" -Notes "API call performed at $((Get-Date).ToString())" -ResultCode $apiResponse.statuscode
        #$apiResponse = [pscustomobject]@{ "statuscode" = "999" } # mock object for testing

        $groupEndTime = [datetime]::Now # Used to time how long the API call took
        Write-Host "Last API call completed in $(($groupEndTime - $groupStartTime).TotalMilliseconds)ms with status: $($apiCodes[$apiResponse.statuscode]) ($($apiResponse.statuscode))" -ForegroundColor Green
        }
    catch {
        Write-ResultsLog -Endpoints $group.Group -Result "Error" -Notes "API Error: $($error[0].ToString())" -ResultCode 998
        Write-Host "Last API call ran into an error: $($error[0].ToString())" -ForegroundColor Red
        }


    Write-Host "Sleeping for 5 seconds to give the poor Cb API a chance to keep up" # also gives the operator a chance to stop the script if they wish. 
    # If you stop the script during the 5 second sleep, remove the already-processed endpoints from the source CSV by referring to the last deviceID in the group as shown on-screen
    Start-Sleep -Seconds 5
}