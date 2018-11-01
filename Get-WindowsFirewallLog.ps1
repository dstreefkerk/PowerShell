#requires -version 3
<#
.SYNOPSIS
Get-WindowsFirewallLog - A quick and dirty Windows Firewall log parser

.DESCRIPTION 
Not designed to do anything fancy.

Just parses the Windows Firewall log and displays it in a PowerShell GridView

.LINK
TODO

.NOTES
Written By: Daniel Streefkerk
Website:    http://daniel.streefkerkonline.com
Twitter:    http://twitter.com/dstreefkerk
Todo:       Nothing at the moment

Change Log
v1.0, 01/11/2018 - Initial version
#>
function Get-WindowsFirewallLog {
    param(
        [parameter(Position=0,Mandatory=$false)]
        [ValidateScript({Test-Path $_})]
        [string]$LogFilePath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    )

    # CSV header fields, to be used later when converting each line of the tailed log from CSV
    $headerFields = @("date","time","action","protocol","src-ip","dst-ip","src-port","dst-port","size","tcpflags","tcpsyn","tcpack","tcpwin","icmptype","icmpcode","info","path")
 
    # Read in the firewall log
    $firewallLogs = Get-Content $LogFilePath | ConvertFrom-Csv -Header $headerFields -Delimiter ' '

    # Output logs into a gridview
    $firewallLogs | Out-GridView
}

Get-WindowsFirewallLog
