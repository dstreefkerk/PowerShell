<#
.SYNOPSIS
    Extracts Microsoft Secure Score control profiles and saves them to disk in a structured format.

.DESCRIPTION
    This script connects to Microsoft Graph, retrieves all secure score control profiles,
    removes tenant-specific information, and saves them in a structured directory format.

.PARAMETER OutputPath
    Specifies the output directory where control profiles will be saved.
    Default is a 'ControlProfiles' folder in the temp directory.

.EXAMPLE
    .\Export-SecureScoreControls.ps1 -OutputPath "C:\ControlProfiles"

.NOTES
    Requires Microsoft.Graph PowerShell module.
    Requires authentication to Microsoft Graph with SecurityEvents.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = (Join-Path -Path $env:TEMP -ChildPath "ControlProfiles")
)

#Requires -Modules Microsoft.Graph

# Function to convert a string to slug format
function ConvertTo-Slug {
    param([string]$Text)
    
    if ([string]::IsNullOrEmpty($Text)) {
        return "unknown"
    }
    
    $Text = $Text.ToLower()
    $Text = $Text -replace '[^a-zA-Z0-9\s-]', ''
    $Text = $Text -replace '\s+', '-'
    return $Text
}

# Function to process control profiles and remove tenant-specific information
function Remove-TenantSpecificInfo {
    param($profiles)
    
    $cleanedProfiles = @()
    
    foreach ($profile in $profiles) {
        # Create a deep clone of the profile to avoid modifying the original
        $cleanProfile = $profile | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        
        # Remove tenant-specific properties
        $propertiesToRemove = @(
            'azureTenantId',
            'controlStateUpdates',
            'lastModifiedDateTime'
        )
        
        foreach ($prop in $propertiesToRemove) {
            if ($cleanProfile.PSObject.Properties[$prop]) {
                $cleanProfile.PSObject.Properties.Remove($prop)
            }
        }
        
        $cleanedProfiles += $cleanProfile
    }
    
    return $cleanedProfiles
}

# Function to get local path for a control profile
function Get-ControlPath {
    param($control, $baseDir)
    
    $tier = $control.tier ?? "Unknown"
    $vendor = $control.vendorInformation.vendor ?? "Unknown"
    $provider = $control.vendorInformation.provider ?? "Unknown"
    $service = $control.service ?? "Unknown"
    $category = $control.controlCategory ?? "Unknown"
    $titleSlug = ConvertTo-Slug -Text $control.title
    
    # Simplified path structure - removing redundant "SecureScore" part
    $dirPath = Join-Path -Path $baseDir -ChildPath "$tier/$vendor/$provider/$service/$category"
    $filePath = Join-Path -Path $dirPath -ChildPath "$titleSlug.json"
    
    return @{
        DirPath = $dirPath
        FilePath = $filePath
    }
}

# Main script execution
try {
    # Ensure output directory exists
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Verbose "Created output directory: $OutputPath"
    }

    # Check if already connected to Graph with required scope
    $needToConnect = $true
    try {
        $graphContext = Get-MgContext -ErrorAction Stop
        if ($graphContext -and $graphContext.Scopes -contains "SecurityEvents.Read.All") {
            Write-Verbose "Already connected to Microsoft Graph as $($graphContext.Account) with required scope"
            $needToConnect = $false
        } else {
            Write-Verbose "Connected as $($graphContext.Account) but missing required scope SecurityEvents.Read.All"
        }
    } 
    catch {
        Write-Verbose "Not connected to Microsoft Graph"
    }

    # Connect only if needed
    if ($needToConnect) {
        Write-Host "Connecting to Microsoft Graph with SecurityEvents.Read.All scope..."
        Connect-MgGraph -Scopes "SecurityEvents.Read.All"
    }

    # Get secure score control profiles
    Write-Host "Retrieving secure score control profiles..."
    $secureScoreControlProfiles = @()
    $nextLink = "https://graph.microsoft.com/beta/security/secureScoreControlProfiles"

    do {
        Write-Verbose "Requesting: $nextLink"
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink
        $secureScoreControlProfiles += $response.value
        $nextLink = $response.'@odata.nextLink'
        Write-Verbose "Retrieved $($secureScoreControlProfiles.Count) profiles so far"
    } while ($nextLink)

    Write-Host "Retrieved $($secureScoreControlProfiles.Count) control profiles."

    # Process profiles to remove tenant-specific information
    Write-Host "Removing tenant-specific information..."
    $processedProfiles = Remove-TenantSpecificInfo -profiles $secureScoreControlProfiles

    # Process each control profile
    Write-Host "Processing control profiles..."
    foreach ($control in $processedProfiles) {
        # Get path information for this control
        $pathInfo = Get-ControlPath -control $control -baseDir $OutputPath
        
        # Create directory if it doesn't exist
        if (-not (Test-Path -Path $pathInfo.DirPath)) {
            New-Item -Path $pathInfo.DirPath -ItemType Directory -Force | Out-Null
        }
        
        # Save control to file
        $control | ConvertTo-Json -Depth 10 | Out-File -FilePath $pathInfo.FilePath -Force
        
        Write-Verbose "Saved control: $($control.id) to $($pathInfo.FilePath)"
    }

    # Generate control index file for all controls
    $allControlIds = @($processedProfiles | ForEach-Object { $_.id })
    $indexPath = Join-Path -Path $OutputPath -ChildPath "control-index.json"
    
    @{
        totalControls = $allControlIds.Count
        controlIds = $allControlIds
        lastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    } | ConvertTo-Json | Out-File -FilePath $indexPath -Force
    
    Write-Host "Generated control index with $($allControlIds.Count) controls at: $indexPath"

    # Open explorer to the output directory
    explorer $OutputPath
    
    Write-Host "Successfully processed secure score control profiles."
    Write-Host "Output directory: $OutputPath"
} 
catch {
    Write-Error "An error occurred: $_"
}