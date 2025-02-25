#Requires -Version 5.1
#Requires -Modules PowerShell-Yaml
<#
.SYNOPSIS
Converts Azure Sentinel analytic rule YAML files into structured output.

.DESCRIPTION
This script automates the process of retrieving and parsing analytic rule definitions from the Azure Sentinel GitHub repository. It either clones or updates the repository at a specified path, then recursively searches for YAML files in each solution's "Analytic Rules" folder. Key details (such as rule name, description, severity, status, data connectors, data types, tactics, and techniques) are extracted and output as a PSCustomObject. This output can be further processed—such as piping to Export-Csv for CSV output or to Export-Excel (a third-party module) for Excel spreadsheets.

.PARAMETER RepositoryPath
Optional. Specifies a custom local path to the Azure Sentinel repository. Defaults to "$env:TEMP\Azure-Sentinel" if not provided.

.EXAMPLE
.\SentinelARConverterScript.ps1
Runs the script, and outputs the results to the console.

.EXAMPLE
.\SentinelARConverterScript.ps1 -RepositoryPath "C:\Custom\Azure-Sentinel"
Runs the script using a custom repository path.

.EXAMPLE
.\SentinelARConverterScript.ps1 | Export-Csv -Path "C:\output.csv" -NoTypeInformation
Executes the script and pipes the output directly to a CSV file.

.EXAMPLE
.\SentinelARConverterScript.ps1 | Export-Excel -Path "C:\output.xlsx"
Executes the script and exports the output directly to an Excel file using the third-party Export-Excel module (which you would need to install).

.NOTES
Author: Daniel Streefkerk
Date: 25 February 2025
Version: 1.0

REQUIREMENTS
- PowerShell-Yaml module must be installed.
- Git must be installed and available in the system PATH.

.LINK
TBA
#>

[CmdletBinding()]
param (
    [string]$RepositoryPath = (Join-Path $env:TEMP "Azure-Sentinel")
)

# Store the original location to restore later
$originalLocation = Get-Location
try {
    # Check if Git is installed
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error "Git is not installed or not available in the system PATH. Please install Git before running this script: https://git-scm.com/downloads"
        return
    }

    # Define the repository path
    $repoPath = $RepositoryPath

    # Check if the repository exists locally
    if (-not (Test-Path -Path $repoPath)) {
        Write-Verbose "Cloning the Azure Sentinel repository to $repoPath..."
        # Clone the repository directly to the specified path, suppressing output
        # We're using sparse-checkout to only fetch the "Solutions" folder to save time and disk space
        Set-Location -Path (Split-Path -Path $repoPath -Parent)
        git clone --depth 1 --filter=blob:none --sparse https://github.com/Azure/Azure-Sentinel.git $repoPath | Out-Null
        Set-Location -Path $repoPath
        git sparse-checkout set Solutions | Out-Null
    } else {
        # Update the repository if it already exists
        Write-Verbose "Repository exists. Updating to mirror the latest changes..."
        Set-Location -Path $repoPath
        git fetch | Out-Null
        git checkout master | Out-Null
        git reset --hard origin/master | Out-Null
        git clean -xfd | Out-Null
    }

    # Set the Solutions folder path
    $solutionsPath = Join-Path $repoPath "Solutions"

    # Check if the Solutions folder exists
    if (-not (Test-Path -Path $solutionsPath)) {
        Write-Error "Solutions folder not found in the repository."
        return
    }

    # Iterate through each solution folder under Solutions
    Get-ChildItem -Path $solutionsPath -Directory | ForEach-Object {
        $solution = $_
        $analyticRulesFolder = Join-Path $solution.FullName "Analytic Rules"
        
        # Check if the Analytic Rules folder exists
        if (Test-Path -Path $analyticRulesFolder) {
            # Get all YAML files (supports both .yml and .yaml) recursively
            $yamlFiles = Get-ChildItem -Path $analyticRulesFolder -Recurse -File |
                         Where-Object { $_.Extension -in ".yml", ".yaml" }
            
            # Iterate through each YAML file
            foreach ($yamlFile in $yamlFiles) {
                try {
                    # Parse the YAML file using the PowerShell-Yaml module
                    $rule = Get-Content -Path $yamlFile.FullName | ConvertFrom-Yaml
                    
                    # Handle requiredDataConnectors as key/value structure
                    $connectors = if ($rule.requiredDataConnectors -is [array]) {
                        $rule.requiredDataConnectors | ForEach-Object { $_.connectorId }
                    } else {
                        @($rule.requiredDataConnectors.connectorId)
                    }
                    
                    # Extract DataTypes for the output object
                    $dataTypes = if ($rule.requiredDataConnectors -is [array]) {
                        $rule.requiredDataConnectors | ForEach-Object { $_.dataTypes } | Select-Object -ExpandProperty *
                    } else {
                        @($rule.requiredDataConnectors.dataTypes)
                    }

                    # Trim single quotes from the description, if present
                    $description = $rule.description -replace "^'|'$", ""

                    # Create and output a PSCustomObject with the desired properties
                    [PSCustomObject]@{
                        SolutionName = $solution.Name
                        RuleName     = $rule.name
                        Description  = $description
                        Severity     = $rule.severity
                        Status       = $rule.status
                        Connectors   = ($connectors -join ', ')
                        DataTypes    = ($dataTypes -join ', ')
                        Tactics      = ($rule.tactics -join ', ')
                        Techniques   = ($rule.relevantTechniques -join ', ')
                    }
                }
                catch {
                    Write-Warning "Failed to parse YAML file: $($yamlFile.FullName) with error: $_.Exception.Message"
                }
            }
        }
    }
} finally {
    # Restore original location
    Set-Location $originalLocation
}
