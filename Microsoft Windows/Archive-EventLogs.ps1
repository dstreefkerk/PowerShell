 # Path to archive the logs to
$rootShare = "\\server1\log$"

# Which logs to archive. Find out the names with "wevtutil.exe enum-logs"
$logs = @(
    "Application",
    "System",
    "Security",
    "Microsoft-Windows-Sysmon/Operational"
)

# XPath Query to grab the last 24 hours (plus 5 minutes) from the log
$eventLogQuery = "*[System[TimeCreated[timediff(@SystemTime) <= 86700000]]]" # 24 hours + 5 minutes

# Function to remove invalid characters from a Windows file name
function Clean-FileName ([string]$FileName,[string]$Replacement = '.') {
    [System.IO.Path]::GetInvalidFileNameChars() | ForEach-Object {$FileName = $FileName.Replace($_,$Replacement)}

    return $FileName
}

# Get today's date as a DateTime object
$dateNow = Get-Date

# Set up the base folder path in the following format
# {year}\{nn - Month}\{day} 
# eg. "2018\04 - april\24" for the 24th of April 2018
$baseFolders = "{0}\{1} - {2}\{3}" -f $dateNow.Year,$dateNow.ToString('MM'),$dateNow.ToString('MMMM'),$dateNow.Day
$fullBasePath = Join-Path $rootShare $baseFolders

# Create today's folder on the share
New-Item $fullBasePath -ItemType Directory -Force

# Iterate through each log we're exporting, and use wevtutil.exe export-log to archive it to the share
foreach ($log in $logs) {
    # Set up the log filename in the format {COMPUTERNAME}-{LOGNAME}-{DATE}
    $logFileName = "{0}-{1}-{2}.evtx" -f ($env:COMPUTERNAME).ToUpper(),$dateNow.ToString("yyyyMMdd"),$log

    # Remove any invalid characters from the file name. These usually come from the log name
    $logFileName = Clean-FileName $logFileName

    # Set up the full path
    $fullLogPath = Join-Path $fullBasePath $logFileName

    # Set up the command we're going to run
    $command = "wevtutil.exe export-log `"$log`" `"$fullLogPath`" /query:`"$eventLogQuery`""

    # Execute the command using cmd.exe /c
    cmd.exe /c $command
} 
