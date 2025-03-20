#Requires -Modules ImportExcel

<#
.SYNOPSIS
Converts Microsoft Sentinel Threat Hunting Queries from Excel to MITRE ATT&CK Navigator layer file

.DESCRIPTION
This script processes an Excel export of Microsoft Sentinel Threat Hunting Queries and generates
a MITRE ATT&CK Navigator layer file (v4.5 format) with technique scoring based on query coverage.

.PARAMETER InputExcelPath
Path to the input Excel file containing hunting queries data

.EXAMPLE
PS> Convert-ExcelThreatHuntingExtractToAttackNavigatorLayer.ps1 -InputExcelPath .\sentinel_hunting_queries.xlsx

.NOTES
Author: Daniel Streefkerk
Version: 1.1
Date: 20 March 2025
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$InputExcelPath
)

function Get-MitreTacticToTechniqueMapping {
    <#
    .SYNOPSIS
    Retrieves the latest MITRE ATT&CK tactics-to-techniques mapping.
    
    .DESCRIPTION
    Downloads the latest MITRE ATT&CK framework dataset from MITRE's GitHub repository,
    extracts active techniques, and maps them to their associated tactics.

    Basically a function-embedded version of this script: https://github.com/dstreefkerk/PowerShell/blob/master/Infosec-Related/Get-LatestMitreTechniquesToTacticsMapping.ps1
    
    .OUTPUTS
    A hashtable where the key is a tactic name and the value is an array of technique IDs.
    #>
    $attackUrl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try {
        $attackData = Invoke-RestMethod -Uri $attackUrl -ErrorAction Stop
        $tacticToTechniqueMap = @{}
        
        foreach ($obj in $attackData.objects) {
            # Ensure properties exist before accessing them
            $revoked = $obj.PSObject.Properties.Match('revoked').Count -gt 0 -and $obj.revoked
            $deprecated = $obj.PSObject.Properties.Match('x_mitre_deprecated').Count -gt 0 -and $obj.x_mitre_deprecated
            
            # Filter out revoked and deprecated techniques
            if ($obj.type -eq 'attack-pattern' -and -not $revoked -and -not $deprecated) {
                $techRef = $obj.external_references |
                    Where-Object { $_.source_name -eq 'mitre-attack' -and $_.external_id -match '^T\d+(\.\d+)?$' }
                
                # Extract tactic names for each technique
                if ($techRef) {
                    $techID = $techRef.external_id
                    $tactics = $obj.kill_chain_phases |
                        Where-Object { $_.kill_chain_name -eq 'mitre-attack' } |
                        ForEach-Object { $_.phase_name }
                    
                    # Map tactics to techniques
                    foreach ($tactic in $tactics) {
                        if (-not $tacticToTechniqueMap.ContainsKey($tactic)) {
                            $tacticToTechniqueMap[$tactic] = @()
                        }
                        $tacticToTechniqueMap[$tactic] += $techID
                    }
                }
            }
        }
        return $tacticToTechniqueMap
    }
    catch {
        throw "Failed to retrieve MITRE ATT&CK mappings: $_"
    }
}

# Initialize MITRE technique tracking
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$techniqueMap = @{}

# Get MITRE tactic-to-technique mappings
$MitreMapping = Get-MitreTacticToTechniqueMapping

try {
    # Import Excel data
    $queries = Import-Excel -Path $InputExcelPath

    # Process each query
    foreach ($query in $queries) {
        # Parse embedded JSON in 'tags' property
        try {
            $tags = $query.tags | ConvertFrom-Json
        } catch {
            Write-Warning "Skipping query $($query.displayName): Invalid JSON in tags."
            continue
        }

        # Extract MITRE tactics from tags, ensuring 'value' property exists
        $tactics = ($tags | Where-Object { $_.name -eq "tactics" -and $_.PSObject.Properties['value'] }) | ForEach-Object { $_.value }

        # Skip queries without MITRE tactics (handles null, empty, and whitespace-only strings)
        if ([string]::IsNullOrWhiteSpace($tactics)) {
            Write-Output "No MITRE tactics found for query: $($query.displayName)"
            continue
        }

        # Map tactics to techniques using MITRE framework
        foreach ($tactic in $tactics -split ",") {
            $techniques = $MitreMapping[$tactic]
            if (-not $techniques) {
                Write-Output "No techniques mapped for tactic: $tactic"
                continue
            }

            # Increment technique score and track query references
            foreach ($technique in $techniques) {
                if (-not $techniqueMap.ContainsKey($technique)) {
                    $techniqueMap[$technique] = @{
                        Score = 0
                        Queries = @()
                    }
                }
                
                $techniqueMap[$technique].Score++
                $techniqueMap[$technique].Queries += $query.displayName
            }
        }
    }

    # Build layer structure
    $layer = @{
        versions = @{
            attack    = "16"
            navigator = "4.9.0"
            layer     = "4.5"
        }
        name     = "Microsoft Sentinel Threat Hunting Coverage"
        domain   = "enterprise-attack"
        description = "Automatically generated from Sentinel Threat Hunting Queries"
        techniques = @()
    }

    # For each technique, generate hashtable with scores and comments
    foreach ($technique in $techniqueMap.GetEnumerator()) {
        $layer.techniques += @{
            techniqueID = $technique.Name
            score       = $technique.Value.Score
            comment     = ($technique.Value.Queries -join "`n`n")
            enabled     = $true
        }
    }

    # Generate output file path with .json extension
    $OutputJsonPath = [System.IO.Path]::ChangeExtension($InputExcelPath, ".json")

    # Export JSON
    $layer | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJsonPath -Encoding utf8

    Write-Output "Layer file generated at: $OutputJsonPath"
}
catch {
    Write-Error "Processing failed: $_"
    throw
}
