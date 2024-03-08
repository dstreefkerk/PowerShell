function Get-MitreTechniqueInformation {
    [CmdletBinding()]
    param (
        [ValidatePattern('^[T][0-9]+$')]
        [string]$TechniqueID
    )

    # Static variable for caching
    if (-not (Test-Path variable:global:mitreAttackDataCache)) {
        $global:mitreAttackDataCache = $null
    }

    $filePath = Join-Path $env:TEMP "enterprise-attack.json"
    $shouldDownload = $false

    # Check if the file exists and determine if it needs to be downloaded
    if (Test-Path $filePath) {
        $fileInfo = Get-Item $filePath
        $timeSpan = New-TimeSpan -Start $fileInfo.LastWriteTime -End (Get-Date)
        if ($timeSpan.Days -ge 1) {
            $shouldDownload = $true
        }
    } else {
        $shouldDownload = $true
    }

    # Download the file if needed
    if ($shouldDownload) {
        Write-Output "Downloading MITRE ATT&CK data..."
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" -OutFile $filePath
        $global:mitreAttackDataCache = $null # Clear cache if new data is downloaded
    }

    # Load from cache if available, otherwise read from disk and cache it
    if ($null -eq $global:mitreAttackDataCache) {
        $global:mitreAttackDataCache = Get-Content $filePath | ConvertFrom-Json
    }

    # See if we can find a match
    $technique = $global:mitreAttackDataCache.objects | Where-Object {$_.type -eq "attack-pattern"} | Where-Object {$_.external_references.external_id -eq $TechniqueID}

    if ($technique) {
        return $technique
    } else {
        Write-Output "Technique ID '$TechniqueID' not found."
    }
}

# Example usage:
Get-MitreTechniqueInformation -TechniqueID "T1189"
