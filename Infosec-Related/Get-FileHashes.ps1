# Create a CSV file on the desktop containing SHA256 hashes for scripting files hosted across several folder locations

$fileTypesToHash = "vbs","bat","ps1"

# Locations to scan for the filetypes above
$scriptLocations = @(
    "\\server1\tools",
    "\\company.internal\SysVol\company.internal\" # Sysvol share 
    )

# Temp array to hold our listing of hashes, file paths, and log messages for CSV output
$hashes = @()

# Temp array to hold our listing of files
$files = @()

# Get a listing of the files we're after, just with file extensions listed in $fileTypesToHash
foreach ($type in $fileTypesToHash) {
    $files += Get-ChildItem -Path $scriptLocations -Filter "*.$type" -File
}

# Get a listing of SHA256 hashes and file path/names
$hashes = $files | Get-FileHash -Algorithm SHA256 | Select-Object Path,@{name="FileName";expression={$_ | Split-Path -Leaf}},Hash

# Export the list of hashes to CSV on the desktop if possible, otherwise to %temp%
# This is for compatibility for the folks who have their Desktops redirected to OneDrive
if (Test-Path -Path $env:USERPROFILE\Desktop) {
    $hashes | Export-Csv $env:USERPROFILE\Desktop\script-hashes.csv -NoTypeInformation -Force
    Write-Output "Hash CSV written to $($env:USERPROFILE)\Desktop\script-hashes.csv"
} else {
    $hashes | Export-Csv $env:TEMP\script-hashes.csv -NoTypeInformation -Force
    Write-Output "Hash CSV written to $($env:TEMP)\script-hashes.csv"
}