#Requires -Version 5 -RunAsAdministrator
<#
.SYNOPSIS
Create-EventViewerCustomViews - Creates local event viewer custom view files based on Palantir's WEF Github repo
.DESCRIPTION
Palantir have a great Github repo that contains WEF (Windows Event Forwarding) subscriptions to be created on
a WEC (Windows Event Collector) server. They've done the hard work of setting up event log filters
to capture various events. https://github.com/palantir/windows-event-forwarding

I'd recently been wondering if it was possible to push out custom Event Viewer views, and at the same time
decided I'd like to leverage the work Palantir had done with WEF/WEC to create custom view files
that allow you to filter local or remote event logs using Event Viewer.

Rather than create these views manually, this script does the following:
    1. Downloads the Palantir 'windows-event-forwarding' repo in ZIP format
    2. Extracts the Event Log query out of each file in the 'wef-subscriptions' folder, and
       turns it into a custom Event Viewer view (XML) file in %PROGRAMDATA%\Microsoft\Event Viewer\Views

YMMV with this, as I couldn't test the actual outbound connectivity and download functionality on my work
laptop. My Windows Firewall policies don't allow PowerShell to communicate out to the Internet. I have, however,
tested the script from line #63 onwards.

Needs to be run as an admin in order to create the view files in %PROGRAMDATA%, unless you change the 
output path in the $templateStoragePath variable

.OUTPUTS
Places custom view files into %PROGRAMDATA%\Microsoft\Event Viewer\Views
.EXAMPLE
Create-EventViewerCustomViews.ps1
.LINK
TBA
.NOTES
Written By: Daniel Streefkerk
Website:	http://daniel.streefkerkonline.com
Twitter:	http://twitter.com/dstreefkerk
Todo:       Nothing at the moment
Change Log
v1.0, 07/11/2017 - Initial version
#>

# Download URL for the Palantir windows-event-forwarding Repo on Github
$repoZipURL = 'https://codeload.github.com/palantir/windows-event-forwarding/zip/master'

# Location in which to create the custom Event Viewer views
$templateStoragePath = Join-Path $env:ProgramData 'Microsoft\Event Viewer\Views'

$xmlTemplate = @"
<ViewerConfig>
  <QueryConfig>
    <QueryParams>
      <UserQuery />
    </QueryParams>
    <QueryNode>
      <Name>{NAMEHERE}</Name>
      <Description>{DESCRIPTIONHERE}</Description>
      {QUERYLISTHERE}
    </QueryNode>
  </QueryConfig>
</ViewerConfig>
"@

# Temporary storage location for the downloaded Palantir WEF
$tempFile = (Join-Path $env:temp 'wef-repo.zip')
Remove-Item $tempFile -Force

# Download the Repo
Invoke-WebRequest -Uri $repoZipURL -OutFile $tempFile

if (!Test-Path $tempFile) {
    throw "Couldn't locate the downloaded Repo ZIP file. You could manually download it at $repoZipURL and save it as $tempFile"
}

# Expand the ZIP file to a temporary folder
$tempFolder = (Join-Path $env:temp 'wef-repo')
Expand-Archive $tempFile -DestinationPath $tempFolder

# Get our list of WEF Subscription files
$subscriptionFiles = Get-ChildItem (Join-Path $tempFolder 'windows-event-forwarding-master\wef-subscriptions') -File

foreach ($file in $subscriptionFiles) {
    # Grab a copy of our custom Event Log view template XML
    $eventXml = $xmlTemplate

    # Convert the repo subscription file to XML
    $fileXml = [xml](Get-Content $file)

    # Insert the info from the repo subscription file into our template
    $eventXml = $eventXml.Replace('{NAMEHERE}',$filexml.Subscription.SubscriptionId)
    $eventXml = $eventXml.Replace('{DESCRIPTIONHERE}',$filexml.Subscription.Description)
    $eventXml = $eventXml.Replace('{QUERYLISTHERE}',$filexml.Subscription.Query.InnerText)

    # Write our populated template variable out to a custom view XML file
    $outputPath = Join-Path $templateStoragePath "CUSTOMVIEW - $($filexml.Subscription.SubscriptionId).xml"
    $eventXml | Out-File -FilePath $outputPath -Force
}