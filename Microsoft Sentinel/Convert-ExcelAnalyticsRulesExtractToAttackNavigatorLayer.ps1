<#
.SYNOPSIS
Converts Microsoft Sentinel Analytics Rules from Excel or CSV to MITRE ATT&CK Navigator layer file

.DESCRIPTION
This script processes an Excel or CSV export of Microsoft Sentinel Analytics Rules and generates
a MITRE ATT&CK Navigator layer file (v4.5 format) with technique scoring based on rule coverage.
Updated for MITRE ATT&CK v18.0 compatibility.

.PARAMETER InputExcelPath
Path to the input Excel file containing analytics rules data

.PARAMETER InputCsvPath
Path to the input CSV file containing analytics rules data

.EXAMPLE
PS> .\Convert-ExcelAnalyticsRulesExtractToAttackNavigatorLayer.ps1 -InputExcelPath .\sentinel_rules.xlsx

.EXAMPLE
PS> .\Convert-ExcelAnalyticsRulesExtractToAttackNavigatorLayer.ps1 -InputCsvPath .\sentinel_rules.csv

.NOTES
Author: Daniel Streefkerk
Version: 2.2.0
Date: 7 November 2025
Updated for MITRE ATT&CK v18.0 compatibility
TODO: Handle sub-techniques
#>

[CmdletBinding(DefaultParameterSetName = 'Excel')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Excel')]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [ValidatePattern('\.xlsx$')]
    [string]$InputExcelPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'CSV')]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [ValidatePattern('\.csv$')]
    [string]$InputCsvPath
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Check for ImportExcel module if using Excel parameter set
    if ($PSCmdlet.ParameterSetName -eq 'Excel') {
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            throw "ImportExcel module is required for Excel input. Install it with: Install-Module -Name ImportExcel"
        }
    }

    # Consolidate input path
    $InputPath = if ($PSCmdlet.ParameterSetName -eq 'Excel') { $InputExcelPath } else { $InputCsvPath }

    # Initialize MITRE technique tracking
    $techniqueMap = @{}
}

process {
    try {
        # Import data based on parameter set
        $rules = if ($PSCmdlet.ParameterSetName -eq 'Excel') {
            Import-Excel -Path $InputPath
        } else {
            Import-Csv -Path $InputPath
        }

        # Filter out disabled rules
        $rules = $rules | Where-Object {$_.status -notlike "false"}

        foreach ($rule in $rules) {
            # Skip rules without MITRE mappings
            if ([string]::IsNullOrWhiteSpace($rule.tactics) -and 
                [string]::IsNullOrWhiteSpace($rule.techniques)) {
                Write-Output "No MITRE mappings found for rule: $($rule.displayName)"
                continue
            }

            # Parse MITRE techniques
            $techniques = @()
            if (-not [string]::IsNullOrWhiteSpace($rule.techniques)) {
                $techniques = $rule.techniques | ConvertFrom-Json
            }

            # Skip rules without MITRE techniques
            if (($techniques | Measure-Object | Select-Object -ExpandProperty Count) -eq 0) {
                Write-Output "No MITRE techniques found for rule: $($rule.displayName)"
                continue
            }

            # Process each technique
            foreach ($tech in $techniques) {
                if (-not $techniqueMap.ContainsKey($tech)) {
                    $techniqueMap[$tech] = [PSCustomObject]@{
                        Score = 0
                        Rules = [System.Collections.Generic.List[string]]::new()
                    }
                }
                
                $techniqueMap[$tech].Score++
                $techniqueMap[$tech].Rules.Add($rule.displayName)
            }
        }

        # Build layer structure for MITRE ATT&CK v18.0
        $layer = [ordered]@{
            name = "Microsoft Sentinel Coverage"
            versions = [ordered]@{
                attack    = "18"
                navigator = "5.2.0"
                layer     = "4.5"
            }
            domain = "enterprise-attack"
            description = "Automatically generated from Sentinel Analytics Rules"
            
            filters = [ordered]@{
                platforms = @(
                    "Windows",
                    "Linux",
                    "macOS",
                    "Network Devices",
                    "ESXi",
                    "PRE",
                    "Containers",
                    "IaaS",
                    "Office Suite",
                    "SaaS",
                    "Identity Provider"
                )
            }
            
            sorting = 0
            
            layout = [ordered]@{
                layout = "side"
                aggregateFunction = "average"
                showID = $true
                showName = $true
                showAggregateScores = $false
                countUnscored = $false
                expandedSubtechniques = "none"
            }
            
            hideDisabled = $false
            
            techniques = foreach ($tech in $techniqueMap.GetEnumerator()) {
                [ordered]@{
                    techniqueID = $tech.Name
                    score       = $tech.Value.Score
                    comment     = $tech.Value.Rules -join "`n`n"
                    enabled     = $true
                }
            }

            gradient = [ordered]@{
                colors = @("#ff6666ff", "#ffe766ff", "#8ec843ff")
                minValue = 0
                maxValue = ($techniqueMap.Values.Score | Measure-Object -Maximum).Maximum
            }
            
            legendItems = @()
            metadata = @()
            links = @()
            showTacticRowBackground = $false
            tacticRowBackground = "#dddddd"
            selectTechniquesAcrossTactics = $true
            selectSubtechniquesWithParent = $false
            selectVisibleTechniques = $false
        }

        # Generate output file path with .json extension
        $OutputJsonPath = [System.IO.Path]::ChangeExtension($InputPath, ".json")

        # Export JSON
        $layer | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJsonPath -Encoding utf8

    }
    catch {
        Write-Error "Processing failed: $_"
        throw
    }
}

end {
    Write-Output "Layer file generated at: $OutputJsonPath"
}
