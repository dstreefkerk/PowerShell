<#
.SYNOPSIS
A simple utility to convert Markdown to Word documents using Pandoc.

.DESCRIPTION
This script provides a user-friendly GUI application that converts Markdown content to Microsoft Word
documents (.docx) using Pandoc. The interface allows users to enter Markdown directly, select template
files for styling, and choose where to save the output document.

.PARAMETER None
This script does not accept parameters as it runs as an interactive GUI application.

.NOTES
Version:        1.0
Author:         Daniel Streefkerk
Creation Date:  09 April 2025
Requirements:   
  - PowerShell 5.1 or higher
  - Pandoc must be installed and available in the system PATH (https://pandoc.org/)
  - Windows environment with WPF and Windows Forms support

.EXAMPLE
.\MarkdownToWord.ps1

Launches the Markdown to Word Converter GUI application.

.FUNCTIONALITY
The script provides the following features:
  - A text editor for entering or pasting Markdown content
  - Option to apply styles from an existing Word template
  - Custom output location selection
  - Persistent settings between sessions
  - Error handling for common issues (file permissions, missing dependencies)

.LINK
https://pandoc.org/
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# Define the XAML for the WPF UI
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Markdown to Word Converter" Height="600" Width="550"
    WindowStartupLocation="CenterScreen" Background="#F0F0F0">
    <Border BorderBrush="Gray" BorderThickness="1" Margin="10">
        <Grid Margin="10">
            <Grid.RowDefinitions>
                <RowDefinition Height="30"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <!-- Title -->
            <TextBlock Grid.Row="0" Text="Markdown to Word Converter" FontWeight="Bold" 
                       VerticalAlignment="Center" HorizontalAlignment="Left" Margin="5,0,0,0"/>
            
            <!-- Markdown Content Textbox -->
            <Border Grid.Row="1" BorderBrush="Gray" BorderThickness="1" Margin="0,10,0,10">
                <TextBox Name="txtMarkdownContent" 
                         TextWrapping="Wrap" 
                         AcceptsReturn="True" 
                         VerticalScrollBarVisibility="Auto"
                         HorizontalScrollBarVisibility="Auto"
                         FontFamily="Consolas"
                         BorderThickness="0"/>
            </Border>
            
            <!-- Use Styles Checkbox -->
            <CheckBox Grid.Row="2" Name="chkUseStyles" Content="Use Styles from Template" Margin="5,0,0,10"/>
            
            <!-- Template File -->
            <Grid Grid.Row="3" Margin="0,0,0,10">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="100"/>
                </Grid.ColumnDefinitions>
                <TextBox Grid.Column="0" Name="txtTemplateDocument" Padding="5" Margin="0,0,10,0"/>
                <Button Grid.Column="1" Name="btnBrowseTemplate" Content="Browse" Padding="10,5"/>
            </Grid>
            
            <!-- Output Filename -->
            <Grid Grid.Row="4" Margin="0,0,0,20">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="100"/>
                </Grid.ColumnDefinitions>
                <TextBox Grid.Column="0" Name="txtOutputFilename" Padding="5" Margin="0,0,10,0"/>
                <Button Grid.Column="1" Name="btnBrowseOutput" Content="Browse" Padding="10,5"/>
            </Grid>
            
            <!-- Buttons -->
            <Grid Grid.Row="5">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="100"/>
                    <ColumnDefinition Width="100"/>
                </Grid.ColumnDefinitions>
                
                <Button Grid.Column="1" Name="btnExit" Content="Exit" Padding="10,5" Margin="0,0,10,0"/>
                <Button Grid.Column="2" Name="btnGenerate" Content="Convert" Padding="10,5" 
                        Background="#CCCCCC"/>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

# Create a reader for the XAML
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Get UI elements by name
$outputFilename = $window.FindName("txtOutputFilename")
$templateDocument = $window.FindName("txtTemplateDocument")
$markdownContent = $window.FindName("txtMarkdownContent")
$browseOutputBtn = $window.FindName("btnBrowseOutput")
$browseTemplateBtn = $window.FindName("btnBrowseTemplate")
$generateBtn = $window.FindName("btnGenerate")
$exitBtn = $window.FindName("btnExit")
$useStylesChk = $window.FindName("chkUseStyles")

# Config file path
$configPath = Join-Path -Path $env:APPDATA -ChildPath "markdown2doc_converter_settings.json"
$pandocBinary = ""

# Functions
# Function to get the desktop path (works with OneDrive redirection)
function Get-DesktopPath {
    try {
        # Try to get the desktop folder path using the shell method (handles redirections)
        $shell = New-Object -ComObject "Shell.Application"
        $folder = $shell.NameSpace(0) # 0 = Desktop
        $desktopPath = $folder.Self.Path
        return $desktopPath
    }
    catch {
        # Fallback to environment variable if shell method fails
        $fallbackPath = [Environment]::GetFolderPath("Desktop")
        if ([string]::IsNullOrEmpty($fallbackPath)) {
            # Further fallback if environment method fails
            $fallbackPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop"
        }
        return $fallbackPath
    }
}

# Function to set placeholder text for textbox controls
function Set-PlaceholderText {
    param (
        [System.Windows.Controls.TextBox]$TextBox,
        [string]$PlaceholderText
    )

    # Tag the TextBox with its placeholder text for reference
    $TextBox.Tag = $PlaceholderText
    
    # Set initial placeholder text
    $TextBox.Text = $PlaceholderText
    $TextBox.Foreground = [System.Windows.Media.Brushes]::Gray

    # Clear placeholder when focused
    $TextBox.Add_GotFocus({
        if ($this.Foreground -eq [System.Windows.Media.Brushes]::Gray) {
            $this.Clear()
            $this.Foreground = [System.Windows.Media.Brushes]::Black
        }
    })

    # Restore placeholder when losing focus if empty
    $TextBox.Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($this.Text)) {
            $this.Text = $this.Tag  # Use the stored placeholder text
            $this.Foreground = [System.Windows.Media.Brushes]::Gray
        }
    })
}

# Function to update UI state based on current inputs
function Update-UIState {
    # Handle template checkbox - disable if template file is empty or is placeholder
    $isTemplatePlaceholder = $templateDocument.Foreground -eq [System.Windows.Media.Brushes]::Gray
    
    if ([string]::IsNullOrWhiteSpace($templateDocument.Text) -or $isTemplatePlaceholder) {
        $useStylesChk.IsEnabled = $false
        $useStylesChk.IsChecked = $false
    } else {
        $useStylesChk.IsEnabled = $true
    }
    
    # Handle convert button - disable if markdown content is empty or is placeholder
    $isMarkdownPlaceholder = $markdownContent.Foreground -eq [System.Windows.Media.Brushes]::Gray
    
    if ([string]::IsNullOrWhiteSpace($markdownContent.Text) -or $isMarkdownPlaceholder) {
        $generateBtn.IsEnabled = $false
    } else {
        $generateBtn.IsEnabled = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($templateDocument.Text) -and ($templateDocument.Text.Length -gt 60)) {
        $templateDocument.ScrollToHorizontalOffset($templateDocument.ExtentWidth)
    }

    if (-not [string]::IsNullOrWhiteSpace($outputFilename.Text) -and ($outputFilename.Text.Length -gt 60)) {
        $outputFilename.ScrollToHorizontalOffset($outputFilename.ExtentWidth)
    }
}

# Function to load configuration
function Load-Configuration {
    if (Test-Path $configPath) {
        try {
            $config = Get-Content -Path $configPath | ConvertFrom-Json
            
            # Only set actual values from config, not placeholders
            if (-not [string]::IsNullOrWhiteSpace($config.OutputFilename)) {
                $outputFilename.Text = $config.OutputFilename
                $outputFilename.Foreground = [System.Windows.Media.Brushes]::Black
            }
            
            if (-not [string]::IsNullOrWhiteSpace($config.TemplateDocument)) {
                $templateDocument.Text = $config.TemplateDocument
                $templateDocument.Foreground = [System.Windows.Media.Brushes]::Black
            }
            
            # Set checkbox state if available
            if ($null -ne $config.UseStyles) {
                $useStylesChk.IsChecked = $config.UseStyles
            }
        }
        catch {
            [System.Windows.MessageBox]::Show("Failed to load configuration. Using defaults.", "Configuration Error", "OK", "Error")
        }
    }
}

# Function to save configuration
function Save-Configuration {
    # Don't save placeholder text to config
    $outputText = $outputFilename.Text
    $templateText = $templateDocument.Text
    
    if ($outputFilename.Foreground -eq [System.Windows.Media.Brushes]::Gray) {
        $outputText = ""
    }
    
    if ($templateDocument.Foreground -eq [System.Windows.Media.Brushes]::Gray) {
        $templateText = ""
    }
    
    $config = @{
        OutputFilename = $outputText
        TemplateDocument = $templateText
        UseStyles = $useStylesChk.IsChecked
    }
    
    try {
        $config | ConvertTo-Json | Set-Content -Path $configPath
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to save configuration.", "Configuration Error", "OK", "Error")
    }
}

# Function to check if Pandoc is installed
function Check-PandocInstallation {
    try {
        $pandocBinary = Get-Command pandoc -ErrorAction Stop
        return $true
    }
    catch {
        [System.Windows.MessageBox]::Show(
            "Pandoc is not installed or not found in your PATH. Please install Pandoc from https://pandoc.org/installing.html",
            "Pandoc Not Found", 
            "OK", 
            "Error"
        )
        return $false
    }
}

# Function to test file access permissions and throw an exception if access is denied
function Test-FileAccessPermission {
    param (
        [string]$FilePath,
        [switch]$ThrowOnError
    )
    
    try {
        # Get the directory from the file path
        $directory = [System.IO.Path]::GetDirectoryName($FilePath)
        
        # Create a temporary file to test write access
        $testFilePath = Join-Path -Path $directory -ChildPath "write_test_$([Guid]::NewGuid()).tmp"
        
        # Try to create the test file
        [System.IO.File]::Create($testFilePath).Close()
        
        # Clean up the test file
        if (Test-Path -Path $testFilePath) {
            Remove-Item -Path $testFilePath -Force
        }
        
        return $true
    }
    catch [System.UnauthorizedAccessException] {
        $errorMsg = "You don't have permission to save files in this location. Please choose a different location."
        [System.Windows.MessageBox]::Show(
            $errorMsg,
            "Permission Denied",
            "OK",
            "Warning"
        )
        
        if ($ThrowOnError) {
            throw [System.UnauthorizedAccessException]::new($errorMsg)
        }
        
        return $false
    }
    catch [System.IO.DirectoryNotFoundException] {
        $errorMsg = "The specified directory does not exist. Please choose a valid location."
        [System.Windows.MessageBox]::Show(
            $errorMsg,
            "Directory Not Found",
            "OK",
            "Warning"
        )
        
        if ($ThrowOnError) {
            throw [System.IO.DirectoryNotFoundException]::new($errorMsg)
        }
        
        return $false
    }
    catch {
        $errorMsg = "An error occurred testing file access: $_"
        [System.Windows.MessageBox]::Show(
            $errorMsg,
            "Access Error",
            "OK",
            "Warning"
        )
        
        if ($ThrowOnError) {
            throw $_
        }
        
        return $false
    }
}

# Add event handlers for text changes to update UI state
$templateDocument.Add_TextChanged({ Update-UIState })
$outputFilename.Add_TextChanged({ Update-UIState })
$templateDocument.Add_Loaded({ Update-UIState })
$outputFilename.Add_Loaded({ Update-UIState })
$markdownContent.Add_TextChanged({ Update-UIState })

# Set placeholder text for both text fields
Set-PlaceholderText -TextBox $templateDocument -PlaceholderText "Browse for template document..."
Set-PlaceholderText -TextBox $outputFilename -PlaceholderText "Choose output file location..."
Set-PlaceholderText -TextBox $markdownContent -PlaceholderText "Enter your markdown content here..."

# Force update the UI state to reflect placeholder status properly
$window.Focus()  # This moves focus away from textboxes to ensure placeholders appear
Update-UIState

# Browse for output file
$browseOutputBtn.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    
    # Set initial directory to desktop (handles OneDrive redirection)
    $desktopPath = Get-DesktopPath
    if (Test-Path -Path $desktopPath) {
        $saveFileDialog.InitialDirectory = $desktopPath
    }

    $saveFileDialog.Filter = "Word Document (*.docx)|*.docx"
    $saveFileDialog.Title = "Save Word Document"
    $saveFileDialog.DefaultExt = "docx"
    if ($saveFileDialog.ShowDialog() -eq "OK") {
        # Get the directory from the selected file path
        $selectedDirectory = [System.IO.Path]::GetDirectoryName($saveFileDialog.FileName)
        
        # Test if we have permission to write to this directory
        if (Test-FileAccessPermission -FilePath $selectedDirectory) {
            $outputFilename.Text = $saveFileDialog.FileName
            $outputFilename.Foreground = [System.Windows.Media.Brushes]::Black
        }
    } else {
        # If the dialog was canceled and no text was entered before, restore placeholder
        if ([string]::IsNullOrWhiteSpace($outputFilename.Text) -or 
            ($outputFilename.Text -eq $outputFilename.Tag -and $outputFilename.Foreground -eq [System.Windows.Media.Brushes]::Gray)) {
            $outputFilename.Text = $outputFilename.Tag
            $outputFilename.Foreground = [System.Windows.Media.Brushes]::Gray
        }
    }
})

# Browse for template file
$browseTemplateBtn.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    
    # Set initial directory to the Templates folder if it exists
    $templatesFolder = Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Templates"
    if (Test-Path -Path $templatesFolder) {
        $openFileDialog.InitialDirectory = $templatesFolder
    }
    
    $openFileDialog.Filter = "Word Templates (*.dotx;*.docx)|*.dotx;*.docx"
    $openFileDialog.Title = "Select Template Document"
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $templateDocument.Text = $openFileDialog.FileName
        $templateDocument.Foreground = [System.Windows.Media.Brushes]::Black
        Update-UIState
        
        # Test if we have permission to read this file
        try {
            [System.IO.File]::OpenRead($openFileDialog.FileName).Close()
        }
        catch [System.UnauthorizedAccessException] {
            [System.Windows.MessageBox]::Show(
                "You don't have permission to access this template file.",
                "Permission Denied",
                "OK",
                "Warning"
            )
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "An error occurred accessing the template file: $_",
                "Access Error",
                "OK",
                "Warning"
            )
        }
    } else {
        # If the dialog was canceled and no text was entered before, restore placeholder
        if ([string]::IsNullOrWhiteSpace($templateDocument.Text) -or 
            ($templateDocument.Text -eq $templateDocument.Tag -and $templateDocument.Foreground -eq [System.Windows.Media.Brushes]::Gray)) {
            $templateDocument.Text = $templateDocument.Tag
            $templateDocument.Foreground = [System.Windows.Media.Brushes]::Gray
        }
        Update-UIState
    }
})

# Generate Word document
$generateBtn.Add_Click({
    # First check if Pandoc is installed
    if (-not (Check-PandocInstallation)) {
        return
    }

    # Check if markdown content is provided and not a placeholder
    if ([string]::IsNullOrWhiteSpace($markdownContent.Text) -or 
        ($markdownContent.Text -eq $markdownContent.Tag -and $markdownContent.Foreground -eq [System.Windows.Media.Brushes]::Gray)) {
        [System.Windows.MessageBox]::Show("Please enter some markdown content.", "No Content", "OK", "Warning")
        return
    }

    # Check if output filename is provided and not a placeholder
    if ([string]::IsNullOrWhiteSpace($outputFilename.Text) -or $outputFilename.Foreground -eq [System.Windows.Media.Brushes]::Gray) {
        [System.Windows.MessageBox]::Show("Please specify an output filename.", "No Output File", "OK", "Warning")
        return
    }
    
    # Test if we have permission to write to the output file location
    # This will throw an exception and halt execution if access is denied
    try {
        Test-FileAccessPermission -FilePath $outputFilename.Text -ThrowOnError
    }
    catch {
        # The error has already been displayed to the user by the Test-FileAccessPermission function
        return
    }
    
    # Variable to store the temporary file path so it can be cleaned up in finally block
    $tempMarkdownFile = $null
    
    try {
        # Create a temporary file for the markdown content
        $tempMarkdownFile = [System.IO.Path]::GetTempFileName() + ".md"
        Set-Content -Path $tempMarkdownFile -Value $markdownContent.Text -Encoding UTF8

        # Prepare the Pandoc command arguments
        $pandocArgs = "-f markdown -t docx -o ""{0}"" ""{1}""" -f $outputFilename.Text, $tempMarkdownFile

        # Add template if checkbox is checked and template is specified (and not a placeholder)
        if ($useStylesChk.IsChecked -and -not [string]::IsNullOrWhiteSpace($templateDocument.Text) -and 
            $templateDocument.Foreground -ne [System.Windows.Media.Brushes]::Gray) {
            
            # Verify template file exists and is accessible
            if (-not (Test-Path -Path $templateDocument.Text)) {
                [System.Windows.MessageBox]::Show(
                    "The specified template file does not exist.",
                    "Template Not Found",
                    "OK",
                    "Warning"
                )
                return
            }
            
            $pandocArgs += " --reference-doc=""{0}""" -f $templateDocument.Text
        }

        # Execute Pandoc
        $pandocBinary = Get-Command pandoc -ErrorAction Stop
        $process = Start-Process -FilePath $pandocBinary.Path -ArgumentList $pandocArgs -NoNewWindow -Wait -PassThru

        # Check the process exit code
        if ($process.ExitCode -eq 0) {
            # Verify the file was actually created
            if (Test-Path -Path $outputFilename.Text) {
                [System.Windows.MessageBox]::Show(
                    "Word document successfully generated at $($outputFilename.Text)",
                    "Success",
                    "OK",
                    "Information"
                )
                
                # Save configuration and close
                Save-Configuration
                $window.Close()
            }
            else {
                [System.Windows.MessageBox]::Show(
                    "Pandoc reported success but the output file was not created. This might be due to permission issues.",
                    "File Creation Failed",
                    "OK",
                    "Error"
                )
            }
        }
        else {
            [System.Windows.MessageBox]::Show(
                "Pandoc conversion failed with exit code $($process.ExitCode).",
                "Conversion Error",
                "OK",
                "Error"
            )
        }
    }
    catch [System.UnauthorizedAccessException] {
        [System.Windows.MessageBox]::Show(
            "Access denied while trying to save the file. Please choose a different location or run as administrator.",
            "Permission Denied",
            "OK",
            "Error"
        )
    }
    catch [System.IO.IOException] {
        [System.Windows.MessageBox]::Show(
            "I/O error occurred. The file might be in use by another process or the disk might be full.",
            "I/O Error",
            "OK",
            "Error"
        )
    }
    catch {
        [System.Windows.MessageBox]::Show(
            "An error occurred during conversion: $_",
            "Error",
            "OK",
            "Error"
        )
    }
    finally {
        # Clean up temp file if it exists
        if ($tempMarkdownFile -and (Test-Path $tempMarkdownFile)) {
            try {
                Remove-Item -Path $tempMarkdownFile -Force -ErrorAction SilentlyContinue
            }
            catch {
                # Just log that cleanup failed; no need to alert the user
                Write-Warning "Failed to clean up temporary file: $tempMarkdownFile"
            }
        }
    }
})

# Add Exit button functionality
$exitBtn.Add_Click({
    # Save configuration before exiting
    Save-Configuration
    $window.Close()
})

# Load configuration when starting
Load-Configuration

# Check Pandoc at startup
Check-PandocInstallation | Out-Null

# Initialize UI state
Update-UIState

# Show the window
$window.ShowDialog() | Out-Null