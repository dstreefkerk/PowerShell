#Requires -Modules ImportExcel

<#
.SYNOPSIS
Converts Microsoft Sentinel Analytics Rules from Excel to MITRE ATT&CK Navigator layer file

.DESCRIPTION
This script processes an Excel export of Microsoft Sentinel Analytics Rules and generates
a MITRE ATT&CK Navigator layer file (v4.5 format) with technique scoring based on rule coverage.
Updated for MITRE ATT&CK v17.1 compatibility.

.PARAMETER InputExcelPath
Path to the input Excel file containing analytics rules data

.EXAMPLE
PS> Convert-ExcelToMitreLayer -InputExcelPath .\sentinel_rules.xlsx

.NOTES
Author: Daniel Streefkerk
Version: 2.0.0
Date: 29 May 2025
Updated for MITRE ATT&CK v17.1 compatibility
TODO: Handle sub-techniques
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$InputExcelPath
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Initialize MITRE technique tracking
    $techniqueMap = @{}
}

process {
    try {
        # Import Excel data
        $rules = Import-Excel -Path $InputExcelPath

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

        # Build layer structure for MITRE ATT&CK v17.1
        $layer = [ordered]@{
            name = "Microsoft Sentinel Coverage"
            versions = [ordered]@{
                attack    = "17"
                navigator = "5.1.0"
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
                    "SaaS",
                    "Office Suite",
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
        $OutputJsonPath = [System.IO.Path]::ChangeExtension($InputExcelPath, ".json")

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
