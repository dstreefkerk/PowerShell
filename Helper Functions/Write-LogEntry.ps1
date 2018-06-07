# A very basic helper function to write to a plain-text log file, intended
# to be dropped into short scripts for simple text-based logging
#
# Usage: Write-LogEntry "This is a test message"
#        Write-LogEntry "This is a test error message" -Level Error
#
function Write-LogEntry($Message,$Level = "Information", $LogFile = 'C:\Scripts\Logs\ThisLogName.log') {
    if ((Test-Path $LogFile) -eq $false) {
        "$(Get-Date) - Log File Created" | Out-File $LogFile -Force
    }
    
    "$(Get-Date) - $Level - $Message" | Out-File $LogFile -Append
}
