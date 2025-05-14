#Requires -Modules ImportExcel

<#
.SYNOPSIS
Converts Microsoft Sentinel Analytics Rules from Excel to MITRE ATT&CK Navigator layer files

.DESCRIPTION
This script processes an Excel export of Microsoft Sentinel Analytics Rules and generates
two MITRE ATT&CK Navigator layer files (v4.5 format) with technique scoring based on rule coverage:
1. One file for enabled rules
2. One file for disabled rules

.PARAMETER InputExcelPath
Path to the input Excel file containing analytics rules data

.EXAMPLE
PS> Convert-ExcelToMitreLayer -InputExcelPath .\sentinel_rules.xlsx

.NOTES
Author: Daniel Streefkerk
Version: 1.1.0
Date: 10 March 2025
TODO: Handle sub-techniques

CHANGELOG:
- 1.1.0: Adjusted script to output two files - one containing disabled rules, and the other containing enabled rules
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

    # Initialize MITRE technique tracking for enabled and disabled rules
    $enabledTechniqueMap = @{}
    $disabledTechniqueMap = @{}
}

process {
    try {
        # Import Excel data
        $allRules = Import-Excel -Path $InputExcelPath

        # Separate enabled and disabled rules
        $enabledRules = $allRules | Where-Object {$_.status -notlike "false"}
        $disabledRules = $allRules | Where-Object {$_.status -like "false"}

        # Process enabled rules
        foreach ($rule in $enabledRules) {
            # Skip rules without MITRE mappings
            if ([string]::IsNullOrWhiteSpace($rule.tactics) -and 
                [string]::IsNullOrWhiteSpace($rule.techniques)) {
                Write-Output "No MITRE mappings found for enabled rule: $($rule.displayName)"
                continue
            }

            # Parse MITRE techniques
            $techniques = @()
            if (-not [string]::IsNullOrWhiteSpace($rule.techniques)) {
                $techniques = $rule.techniques | ConvertFrom-Json
            }

            # Skip rules without MITRE techniques
            if (($techniques | Measure-Object | Select-Object -ExpandProperty Count) -eq 0) {
                Write-Output "No MITRE techniques found for enabled rule: $($rule.displayName)"
                continue
            }

            # Process each technique
            foreach ($tech in $techniques) {
                if (-not $enabledTechniqueMap.ContainsKey($tech)) {
                    $enabledTechniqueMap[$tech] = [PSCustomObject]@{
                        Score = 0
                        Rules = [System.Collections.Generic.List[string]]::new()
                    }
                }
                
                $enabledTechniqueMap[$tech].Score++
                $enabledTechniqueMap[$tech].Rules.Add($rule.displayName)
            }
        }

        # Process disabled rules
        foreach ($rule in $disabledRules) {
            # Skip rules without MITRE mappings
            if ([string]::IsNullOrWhiteSpace($rule.tactics) -and 
                [string]::IsNullOrWhiteSpace($rule.techniques)) {
                Write-Output "No MITRE mappings found for disabled rule: $($rule.displayName)"
                continue
            }

            # Parse MITRE techniques
            $techniques = @()
            if (-not [string]::IsNullOrWhiteSpace($rule.techniques)) {
                $techniques = $rule.techniques | ConvertFrom-Json
            }

            # Skip rules without MITRE techniques
            if (($techniques | Measure-Object | Select-Object -ExpandProperty Count) -eq 0) {
                Write-Output "No MITRE techniques found for disabled rule: $($rule.displayName)"
                continue
            }

            # Process each technique
            foreach ($tech in $techniques) {
                if (-not $disabledTechniqueMap.ContainsKey($tech)) {
                    $disabledTechniqueMap[$tech] = [PSCustomObject]@{
                        Score = 0
                        Rules = [System.Collections.Generic.List[string]]::new()
                    }
                }
                
                $disabledTechniqueMap[$tech].Score++
                $disabledTechniqueMap[$tech].Rules.Add($rule.displayName)
            }
        }

        # Function to build layer structure
        function Build-LayerStructure {
            param (
                [hashtable]$TechniqueMap,
                [string]$Name
            )
            
            return [ordered]@{
                versions = [ordered]@{
                    attack    = "16"
                    navigator = "4.9.0"
                    layer     = "4.5"
                }
                name     = $Name
                domain   = "enterprise-attack"
                description = "Automatically generated from Sentinel Analytics Rules"

                techniques = foreach ($tech in $TechniqueMap.GetEnumerator()) {
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
                    maxValue = ($TechniqueMap.Values.Score | Measure-Object -Maximum).Maximum
                }

                layout = [ordered]@{
                    layout    = "side"
                    showID    = $true
                    showName = $true
                }
            }
        }

        # Build and export enabled rules layer
        $enabledLayer = Build-LayerStructure -TechniqueMap $enabledTechniqueMap -Name "Microsoft Sentinel Coverage - Enabled Rules"
        $EnabledOutputJsonPath = "{0}\{1}_enabled.json" -f ([System.IO.Path]::GetDirectoryName($InputExcelPath)), 
                                                            ([System.IO.Path]::GetFileNameWithoutExtension($InputExcelPath))
        $enabledLayer | ConvertTo-Json -Depth 10 | Out-File -FilePath $EnabledOutputJsonPath -Encoding utf8
        
        # Build and export disabled rules layer
        $disabledLayer = Build-LayerStructure -TechniqueMap $disabledTechniqueMap -Name "Microsoft Sentinel Coverage - Disabled Rules"
        $DisabledOutputJsonPath = "{0}\{1}_disabled.json" -f ([System.IO.Path]::GetDirectoryName($InputExcelPath)),
                                                             ([System.IO.Path]::GetFileNameWithoutExtension($InputExcelPath))
        $disabledLayer | ConvertTo-Json -Depth 10 | Out-File -FilePath $DisabledOutputJsonPath -Encoding utf8
    }
    catch {
        Write-Error "Processing failed: $_"
        throw
    }
}

end {
    Write-Output "Layer files generated at:"
    Write-Output "  Enabled rules: $EnabledOutputJsonPath"
    Write-Output "  Disabled rules: $DisabledOutputJsonPath"
}
