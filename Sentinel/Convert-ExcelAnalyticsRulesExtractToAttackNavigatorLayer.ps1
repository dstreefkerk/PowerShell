#Requires -Modules ImportExcel

<#
.SYNOPSIS
Converts Microsoft Sentinel Analytics Rules from Excel to MITRE ATT&CK Navigator layer file

.DESCRIPTION
This script processes an Excel export of Microsoft Sentinel Analytics Rules and generates
a MITRE ATT&CK Navigator layer file (v4.5 format) with technique scoring based on rule coverage.

.PARAMETER InputExcelPath
Path to the input Excel file containing analytics rules data

.EXAMPLE
PS> Convert-ExcelToMitreLayer -InputExcelPath .\sentinel_rules.xlsx

.NOTES
Author: Daniel Streefkerk
Version: 1.0.0
Date: 20 Feb 2025
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

        # Build layer structure
        $layer = [ordered]@{
            versions = [ordered]@{
                attack    = "16"
                navigator = "4.9.0"
                layer     = "4.5"
            }
            name     = "Microsoft Sentinel Coverage"
            domain   = "enterprise-attack"
            description = "Automatically generated from Sentinel Analytics Rules"

            techniques = foreach ($tech in $techniqueMap.GetEnumerator()) {
                [ordered]@{
                    techniqueID = $tech.Name
                    score       = $tech.Value.Score
                    comment     = $tech.Value.Rules -join "`n`n"
                    enabled     = $true
                }
            }

            gradient = [ordered]@{
                colors   = @("#ff6666", "#ffe766", "#8ec843")
                minValue = 0
                maxValue = ($techniqueMap.Values.Score | Measure-Object -Maximum).Maximum
            }

            layout = [ordered]@{
                layout    = "side"
                showID    = $true
                showName = $true
            }
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
