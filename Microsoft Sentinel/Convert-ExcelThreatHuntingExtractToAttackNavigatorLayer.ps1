<#
.SYNOPSIS
Converts Microsoft Sentinel Threat Hunting Queries from Excel or CSV to MITRE ATT&CK Navigator layer file

.DESCRIPTION
This script processes an Excel or CSV export of Microsoft Sentinel Threat Hunting Queries and generates
a MITRE ATT&CK Navigator layer file (v4.5 format) with technique scoring based on query coverage.
Updated for MITRE ATT&CK v18.0 compatibility.

.PARAMETER InputExcelPath
Path to the input Excel file containing hunting queries data

.PARAMETER InputCsvPath
Path to the input CSV file containing hunting queries data

.EXAMPLE
PS> .\Convert-ExcelThreatHuntingExtractToAttackNavigatorLayer.ps1 -InputExcelPath .\sentinel_hunting_queries.xlsx

.EXAMPLE
PS> .\Convert-ExcelThreatHuntingExtractToAttackNavigatorLayer.ps1 -InputCsvPath .\sentinel_hunting_queries.csv

.NOTES
Author: Daniel Streefkerk
Version: 1.5
Date: 7 November 2025
Updated for MITRE ATT&CK v18.0 framework compatibility
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

# Check for ImportExcel module if using Excel parameter set
if ($PSCmdlet.ParameterSetName -eq 'Excel') {
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        throw "ImportExcel module is required for Excel input. Install it with: Install-Module -Name ImportExcel"
    }
}

# Consolidate input path
$InputPath = if ($PSCmdlet.ParameterSetName -eq 'Excel') { $InputExcelPath } else { $InputCsvPath }

$techniqueMap = @{}

# Get MITRE tactic-to-technique mappings
$MitreMapping = Get-MitreTacticToTechniqueMapping

try {
    # Import data based on parameter set
    $queries = if ($PSCmdlet.ParameterSetName -eq 'Excel') {
        Import-Excel -Path $InputPath
    } else {
        Import-Csv -Path $InputPath
    }

    # Process each query
    foreach ($query in $queries) {
        # Parse embedded JSON in 'tags' property
        try {
            $tags = $query.tags | ConvertFrom-Json
        } catch {
            Write-Warning "Skipping query $($query.displayName): Invalid JSON in tags."
            continue
        }

        # First, check if specific techniques are defined in the tags
        $specificTechniques = ($tags | Where-Object { $_.name -eq "techniques" -and $_.PSObject.Properties['value'] }) | ForEach-Object { $_.value }
        
        # Extract MITRE tactics from tags, ensuring 'value' property exists
        $tactics = ($tags | Where-Object { $_.name -eq "tactics" -and $_.PSObject.Properties['value'] }) | ForEach-Object { $_.value }

        # Skip queries without MITRE tactics or techniques
        if ([string]::IsNullOrWhiteSpace($tactics) -and [string]::IsNullOrWhiteSpace($specificTechniques)) {
            Write-Output "No MITRE tactics or techniques found for query: $($query.displayName)"
            continue
        }

        # If specific techniques are provided, use those directly
        if (-not [string]::IsNullOrWhiteSpace($specificTechniques)) {
            foreach ($technique in $specificTechniques -split ",") {
                $techniqueID = $technique.Trim()
                
                if (-not $techniqueMap.ContainsKey($techniqueID)) {
                    $techniqueMap[$techniqueID] = @{
                        Score = 0
                        Queries = @()
                    }
                }
                
                $techniqueMap[$techniqueID].Score++
                $techniqueMap[$techniqueID].Queries += $query.displayName
            }
        }
        # Only use tactic-to-technique mapping if no specific techniques are provided
        elseif (-not [string]::IsNullOrWhiteSpace($tactics)) {
            # Map tactics to techniques using MITRE framework
            foreach ($tactic in $tactics -split ",") {
                $techniques = $MitreMapping[$tactic.Trim()]
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
    }

    # Build layer structure for MITRE ATT&CK v18.0
    $layer = @{
        versions = @{
            attack    = "18"
            navigator = "5.2.0"
            layer     = "4.5"
        }
        name        = "Microsoft Sentinel Threat Hunting Coverage"
        domain      = "enterprise-attack"
        description = "Automatically generated from Sentinel Threat Hunting Queries - MITRE ATT&CK v18.0"
        filters     = @{
            platforms = @("Windows", "Linux", "macOS", "Network Devices", "ESXi", "PRE", "Containers", "IaaS", "Office Suite", "SaaS", "Identity Provider")
        }
        sorting     = 0
        layout      = @{
            layout           = "side"
            aggregateFunction = "average"
            showID          = $false
            showName        = $true
            showAggregateScores = $false
            countUnscored   = $false
            expandedSubtechniques = "none"
        }
        hideDisabled = $false
        techniques   = @()
        gradient     = @{
            colors    = @("#ff6666ff", "#ffe766ff", "#8ec843ff")
            minValue  = 0
            maxValue  = 100
        }
        legendItems = @()
        metadata    = @()
        links       = @()
        showTacticRowBackground = $false
        tacticRowBackground    = "#dddddd"
        selectTechniquesAcrossTactics = $true
        selectSubtechniquesWithParent = $false
        selectVisibleTechniques = $false
    }

    # For each technique, generate hashtable with scores and comments
    foreach ($technique in $techniqueMap.GetEnumerator()) {
        $layer.techniques += @{
            techniqueID = $technique.Name
            score       = $technique.Value.Score
            color       = ""
            comment     = ($technique.Value.Queries -join "`n`n")
            enabled     = $true
            metadata    = @()
            links       = @()
            showSubtechniques = $false
        }
    }

    # Generate output file path with .json extension
    $OutputJsonPath = [System.IO.Path]::ChangeExtension($InputPath, ".json")

    # Export JSON
    $layer | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJsonPath -Encoding utf8

    Write-Output "MITRE ATT&CK v18.0 layer file generated at: $OutputJsonPath"
    Write-Output "Processed $($techniqueMap.Count) unique techniques from $($queries.Count) hunting queries"
}
catch {
    Write-Error "Processing failed: $_"
    throw
}
