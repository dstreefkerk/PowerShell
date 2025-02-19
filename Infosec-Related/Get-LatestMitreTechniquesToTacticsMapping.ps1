<#
.SYNOPSIS
Downloads MITRE ATT&CK framework data and generates a JSON file mapping tactics to technique IDs

.DESCRIPTION
This script retrieves the latest MITRE ATT&CK Enterprise dataset from MITRE's GitHub repository, parses the STIX/JSON format, and generates a structured JSON file containing all active techniques mapped to their associated tactics. 

The output is a JSON file as used by the Hybrid Brothers MITRE Analytics and Incidents Mapping tool and its ATT&CK layer templates: https://github.com/HybridBrothers/Hybrid-Brothers-Projects/tree/main/MITRE%20Analytics%20and%20Incidents%20Mapping/attack-layer-templates

.NOTES
Author: Daniel Streefkerk
Version: 1.0
Last Modified: 19/02/2025
#>

$attackUrl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
$outputFile = "mitre_attack_techniques.json"

try {
    # Retrieve and parse ATT&CK dataset
    $attackData = Invoke-RestMethod -Uri $attackUrl -ErrorAction Stop
    $techniques = @()

    # Process each object in the dataset
    foreach ($obj in $attackData.objects) {
        if ($obj.type -eq 'attack-pattern' -and 
            -not $obj.revoked -and 
            -not $obj.x_mitre_deprecated) {
            
            # Extract technique ID
            $techRef = $obj.external_references | 
                Where-Object { 
                    $_.source_name -eq 'mitre-attack' -and 
                    $_.external_id -match '^T\d+(\.\d+)?$' 
                }
            
            if ($techRef) {
                $techID = $techRef.external_id
                
                # Extract associated tactics
                $tactics = $obj.kill_chain_phases | 
                    Where-Object { $_.kill_chain_name -eq 'mitre-attack' } | 
                    ForEach-Object { $_.phase_name }

                # Create entries for each tactic association
                foreach ($tactic in $tactics) {
                    $techniques += [PSCustomObject]@{
                        tactic = $tactic
                        techniqueID = $techID
                    }
                }
            }
        }
    }

    # Generate output structure and save to file
    @{ techniques = $techniques } | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputFile -Encoding utf8

    Write-Host "Successfully generated $outputFile with $($techniques.Count) technique-tactic mappings"
}
catch {
    Write-Error "Failed to process ATT&CK data: $_"
    exit 1
}
