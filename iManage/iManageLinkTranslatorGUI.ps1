<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    iManageLinkTranslator
.SYNOPSIS
    GUI to rewrite IWL into HTTPS links
.DESCRIPTION
    Extract data from legacy iManage iwl: protocol links, and form a modern iManage 10 HTTPS document link

    This code is extremely rudimentary, with no error checking.

    https://twitter.com/dstreefkerk
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

#region begin GUI{ 

$iManageLinkTranslatorForm       = New-Object system.Windows.Forms.Form
$iManageLinkTranslatorForm.ClientSize  = '624,265'
$iManageLinkTranslatorForm.text  = "iManage Link Translater"
$iManageLinkTranslatorForm.TopMost  = $false

$existingLinkTextBox             = New-Object system.Windows.Forms.TextBox
$existingLinkTextBox.multiline   = $false
$existingLinkTextBox.width       = 579
$existingLinkTextBox.height      = 20
$existingLinkTextBox.location    = New-Object System.Drawing.Point(16,50)
$existingLinkTextBox.Font        = 'Microsoft Sans Serif,10'

$existingLinkLabel               = New-Object system.Windows.Forms.Label
$existingLinkLabel.text          = "IWL Protocol Link:"
$existingLinkLabel.AutoSize      = $true
$existingLinkLabel.width         = 25
$existingLinkLabel.height        = 10
$existingLinkLabel.location      = New-Object System.Drawing.Point(16,27)
$existingLinkLabel.Font          = 'Microsoft Sans Serif,10'

$goButton                        = New-Object system.Windows.Forms.Button
$goButton.text                   = "Translate Link"
$goButton.width                  = 108
$goButton.height                 = 30
$goButton.location               = New-Object System.Drawing.Point(243,138)
$goButton.Font                   = 'Microsoft Sans Serif,10'

$iManageServerURLLabel           = New-Object system.Windows.Forms.Label
$iManageServerURLLabel.text      = "iManage Web Hostname:"
$iManageServerURLLabel.AutoSize  = $true
$iManageServerURLLabel.width     = 25
$iManageServerURLLabel.height    = 10
$iManageServerURLLabel.location  = New-Object System.Drawing.Point(17,85)
$iManageServerURLLabel.Font      = 'Microsoft Sans Serif,10'

$serverNameTextBox               = New-Object system.Windows.Forms.TextBox
$serverNameTextBox.multiline     = $false
$serverNameTextBox.text          = "dms.contoso.com"
$serverNameTextBox.width         = 579
$serverNameTextBox.height        = 20
$serverNameTextBox.location      = New-Object System.Drawing.Point(17,108)
$serverNameTextBox.Font          = 'Microsoft Sans Serif,10'

$rewrittenURLTextBox             = New-Object system.Windows.Forms.TextBox
$rewrittenURLTextBox.multiline   = $false
$rewrittenURLTextBox.width       = 494
$rewrittenURLTextBox.height      = 20
$rewrittenURLTextBox.location    = New-Object System.Drawing.Point(19,208)
$rewrittenURLTextBox.Font        = 'Microsoft Sans Serif,10'

$rewrittenURLLabel               = New-Object system.Windows.Forms.Label
$rewrittenURLLabel.text          = "iManage 10 URL:"
$rewrittenURLLabel.AutoSize      = $true
$rewrittenURLLabel.width         = 25
$rewrittenURLLabel.height        = 10
$rewrittenURLLabel.location      = New-Object System.Drawing.Point(19,187)
$rewrittenURLLabel.Font          = 'Microsoft Sans Serif,10'

$copyButton                      = New-Object system.Windows.Forms.Button
$copyButton.text                 = "Copy"
$copyButton.width                = 60
$copyButton.height               = 30
$copyButton.location             = New-Object System.Drawing.Point(535,201)
$copyButton.Font                 = 'Microsoft Sans Serif,10'

$iManageLinkTranslatorForm.controls.AddRange(@($existingLinkTextBox,$existingLinkLabel,$goButton,$iManageServerURLLabel,$serverNameTextBox,$rewrittenURLTextBox,$rewrittenURLLabel,$copyButton))

#region gui events {
$goButton.Add_Click({ TranslateButtonClick })
$copyButton.Add_Click({ CopyButtonClick })
#endregion events }

#endregion GUI }

function Parse-iManageLink ([string]$link, [string]$urlHostName, [string]$protocol = "HTTPS") {
    $linkParts = $link.Split('&&')

    $databaseName = ($linkParts | ? {$_ -like "lib=*"}).Replace('lib=','')
    $docNumber = ($linkParts | ? {$_ -like "num=*"}).Replace('num=','')
    $docVersion = ($linkParts | ? {$_ -like "ver=*"}).Replace('ver=','')

    $newLink = "{0}://{1}/link/d/{2}!{3}.{4}" -f $protocol,$urlHostName,$databaseName,$docNumber,$docVersion

    return $newLink.ToLower()
}

#Write your logic code here
function TranslateButtonClick() {
    if ($existingLinkTextBox.Text -notlike 'iwl:*') {
        $rewrittenURLTextBox.Text = "INVALID LINK ENTERED"
        return
    }

    $rewrittenURLTextBox.Text = Parse-iManageLink -link $existingLinkTextBox.Text -urlHostName $serverNameTextBox.Text -protocol 'HTTPS'
}

function CopyButtonClick() {
    if ($rewrittenURLTextBox.Text -ne $null) {
        Set-Clipboard -Value $rewrittenURLTextBox.Text
    }
}

[void]$iManageLinkTranslatorForm.ShowDialog()
