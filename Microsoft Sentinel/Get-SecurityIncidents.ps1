<#
.SYNOPSIS
    Retrieves high-severity security incidents from Microsoft Sentinel and Microsoft Defender via Microsoft Graph Security API.

.DESCRIPTION
    This script connects to Microsoft Graph Security API to retrieve security incidents with high severity.
    It supports filtering by date range, pagination for large result sets, and optional CSV export.
    The script uses delegated permissions with the current user's credentials.

.PARAMETER StartDate
    The start date for filtering incidents. Only incidents created after this date will be retrieved.
    If not specified, no start date filter is applied.

.PARAMETER EndDate
    The end date for filtering incidents. Only incidents created before this date will be retrieved.
    Must be after StartDate if both are specified.

.PARAMETER IncludeAlerts
    Switch to include expanded alert information with each incident.
    This provides additional detail but may increase query time.

.PARAMETER AdditionalProperties
    Array of additional properties to retrieve for each incident.
    These properties will be included in the query's $select parameter.

.PARAMETER ExportToCsv
    Switch to export the results to a CSV file.
    The file will be saved in the location specified by ExportPath.

.PARAMETER ExportPath
    The directory path where the CSV file will be saved.
    Defaults to the current directory. Must be a valid existing directory.

.PARAMETER GroupBySource
    Switch to group the results by their source (product) before returning.
    Useful for understanding incident distribution across security products.

.PARAMETER MaxRetries
    Maximum number of retry attempts for failed API calls.
    Defaults to 3. Used for handling transient errors and rate limiting.

.PARAMETER RetryDelaySeconds
    Number of seconds to wait between retry attempts.
    Defaults to 2. Increases exponentially with each retry.

.EXAMPLE
    .\Get-SecurityIncidents.ps1
    Retrieves all high-severity incidents without date filtering.

.EXAMPLE
    .\Get-SecurityIncidents.ps1 -StartDate (Get-Date).AddDays(-30) -IncludeAlerts
    Retrieves high-severity incidents from the last 30 days with alert details.

.EXAMPLE
    .\Get-SecurityIncidents.ps1 -StartDate "2024-01-01" -EndDate "2024-01-31" -ExportToCsv
    Retrieves high-severity incidents for January 2024 and exports to CSV.

.EXAMPLE
    .\Get-SecurityIncidents.ps1 -GroupBySource -Verbose
    Retrieves all high-severity incidents grouped by source with verbose output.

.NOTES
    Author: Security Operations Team
    Version: 1.0.0
    Date: 2024-01-30
    Requires: Microsoft.Graph.Security module
    
    Required Permissions: SecurityIncident.Read.All (delegated)

.LINK
    https://learn.microsoft.com/en-us/graph/api/security-list-incidents

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/security-incident
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Security

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Start date for incident filter")]
    [ValidateNotNullOrEmpty()]
    [DateTime]$StartDate,

    [Parameter(Mandatory = $false, HelpMessage = "End date for incident filter")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ 
        $_ -gt $StartDate -or -not $StartDate 
    }, ErrorMessage = "EndDate must be after StartDate")]
    [DateTime]$EndDate,

    [Parameter(Mandatory = $false, HelpMessage = "Include expanded alert information")]
    [switch]$IncludeAlerts,

    [Parameter(Mandatory = $false, HelpMessage = "Additional properties to retrieve")]
    [ValidateNotNullOrEmpty()]
    [string[]]$AdditionalProperties,

    [Parameter(Mandatory = $false, HelpMessage = "Export results to CSV")]
    [switch]$ExportToCsv,

    [Parameter(Mandatory = $false, HelpMessage = "Path for CSV export")]
    [ValidateScript({ 
        Test-Path $_ -PathType Container 
    }, ErrorMessage = "Path must exist and be a directory")]
    [string]$ExportPath = $PWD,

    [Parameter(Mandatory = $false, HelpMessage = "Group results by source product")]
    [switch]$GroupBySource,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum retry attempts for API calls")]
    [ValidateRange(0, 10)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false, HelpMessage = "Delay in seconds between retries")]
    [ValidateRange(1, 60)]
    [int]$RetryDelaySeconds = 2
)

begin {
    #region Initialization
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    
    Write-Verbose "Starting Get-SecurityIncidents script execution"
    Write-Verbose "PowerShell Version: $($PSVersionTable.PSVersion)"
    
    #region Functions
    function Test-GraphConnection {
        [CmdletBinding()]
        param()
        
        try {
            $context = Get-MgContext
            if (-not $context) {
                return $false
            }
            
            $requiredScope = "SecurityIncident.Read.All"
            $hasScope = $context.Scopes -contains $requiredScope
            
            if (-not $hasScope) {
                Write-Warning "Current connection does not have required scope: $requiredScope"
                return $false
            }
            
            return $true
        }
        catch {
            Write-Verbose "Error checking Graph connection: $_"
            return $false
        }
    }
    
    function Invoke-GraphRequestWithRetry {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            
            [Parameter(Mandatory = $false)]
            [int]$MaxRetries = 3,
            
            [Parameter(Mandatory = $false)]
            [int]$RetryDelay = 2
        )
        
        $attempt = 0
        $success = $false
        $result = $null
        
        while (-not $success -and $attempt -le $MaxRetries) {
            try {
                $attempt++
                Write-Verbose "Executing Graph API request (Attempt $attempt of $($MaxRetries + 1))"
                
                $result = & $ScriptBlock
                $success = $true
            }
            catch {
                $errorMessage = $_.Exception.Message
                
                if ($attempt -gt $MaxRetries) {
                    Write-Error "Graph API request failed after $MaxRetries retries: $errorMessage"
                    throw
                }
                
                if ($errorMessage -match "429|TooManyRequests") {
                    $waitTime = $RetryDelay * [Math]::Pow(2, $attempt - 1)
                    Write-Warning "Rate limit encountered. Waiting $waitTime seconds before retry..."
                }
                elseif ($errorMessage -match "503|ServiceUnavailable|504|GatewayTimeout") {
                    $waitTime = $RetryDelay * [Math]::Pow(2, $attempt - 1)
                    Write-Warning "Service temporarily unavailable. Waiting $waitTime seconds before retry..."
                }
                else {
                    Write-Error "Graph API request failed: $errorMessage"
                    throw
                }
                
                Start-Sleep -Seconds $waitTime
            }
        }
        
        return $result
    }
    
    function ConvertTo-FlatObject {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $InputObject,
            
            [Parameter(Mandatory = $false)]
            [string]$Prefix = ''
        )
        
        process {
            $flatObject = [ordered]@{}
            
            foreach ($property in $InputObject.PSObject.Properties) {
                $propertyName = if ($Prefix) { "$Prefix.$($property.Name)" } else { $property.Name }
                
                if ($null -eq $property.Value) {
                    $flatObject[$propertyName] = $null
                }
                elseif ($property.Value -is [System.Collections.IEnumerable] -and $property.Value -isnot [string]) {
                    $flatObject[$propertyName] = ($property.Value | ForEach-Object { $_.ToString() }) -join '; '
                }
                elseif ($property.Value.PSObject.Properties.Count -gt 0 -and 
                         $property.Value -isnot [string] -and 
                         $property.Value -isnot [datetime] -and 
                         $property.Value -isnot [int] -and 
                         $property.Value -isnot [long] -and 
                         $property.Value -isnot [double] -and 
                         $property.Value -isnot [bool]) {
                    $nestedFlat = ConvertTo-FlatObject -InputObject $property.Value -Prefix $propertyName
                    foreach ($nestedProperty in $nestedFlat.GetEnumerator()) {
                        $flatObject[$nestedProperty.Key] = $nestedProperty.Value
                    }
                }
                else {
                    $flatObject[$propertyName] = $property.Value
                }
            }
            
            [PSCustomObject]$flatObject
        }
    }
    #endregion Functions
    
    #region Connection Validation
    Write-Verbose "Checking Microsoft Graph connection..."
    
    if (-not (Test-GraphConnection)) {
        Write-Warning "Not connected to Microsoft Graph or missing required permissions"
        
        if ($PSCmdlet.ShouldProcess("Microsoft Graph", "Connect with SecurityIncident.Read.All scope")) {
            try {
                Write-Verbose "Attempting to connect to Microsoft Graph..."
                Connect-MgGraph -Scopes "SecurityIncident.Read.All" -NoWelcome
                Write-Verbose "Successfully connected to Microsoft Graph"
            }
            catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new("Failed to connect to Microsoft Graph: $_"),
                    "GraphConnectionFailed",
                    [System.Management.Automation.ErrorCategory]::ConnectionError,
                    $null
                )
                $PSCmdlet.WriteError($errorRecord)
                return
            }
        }
        else {
            Write-Verbose "Connection cancelled by user"
            return
        }
    }
    else {
        Write-Verbose "Already connected to Microsoft Graph with required permissions"
    }
    #endregion Connection Validation
    
    #region Build Query Parameters
    $queryParams = @{
        All = $true
        Property = @('*')
    }
    
    $filterParts = @("severity eq 'high'")
    
    if ($StartDate) {
        $startDateString = $StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $filterParts += "createdDateTime ge $startDateString"
        Write-Verbose "Filtering incidents created after: $startDateString"
    }
    
    if ($EndDate) {
        $endDateString = $EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $filterParts += "createdDateTime le $endDateString"
        Write-Verbose "Filtering incidents created before: $endDateString"
    }
    
    $queryParams['Filter'] = $filterParts -join ' and '
    Write-Verbose "Using filter: $($queryParams['Filter'])"
    
    if ($IncludeAlerts) {
        $queryParams['ExpandProperty'] = 'alerts'
        Write-Verbose "Including expanded alert information"
    }
    
    if ($AdditionalProperties) {
        $allProperties = @('*') + $AdditionalProperties | Select-Object -Unique
        $queryParams['Property'] = $allProperties
        Write-Verbose "Retrieving properties: $($allProperties -join ', ')"
    }
    #endregion Build Query Parameters
    
    $incidents = @()
    $incidentCount = 0
    $progressParams = @{
        Activity = "Retrieving Security Incidents"
        Status = "Initializing..."
        PercentComplete = 0
    }
    #endregion Initialization
}

process {
    #region Retrieve Incidents
    try {
        Write-Progress @progressParams
        
        $scriptBlock = {
            Get-MgSecurityIncident @queryParams
        }
        
        Write-Verbose "Executing security incident query..."
        $results = Invoke-GraphRequestWithRetry -ScriptBlock $scriptBlock -MaxRetries $MaxRetries -RetryDelay $RetryDelaySeconds
        
        if ($results) {
            $totalCount = @($results).Count
            Write-Verbose "Retrieved $totalCount incidents from Graph API"
            
            foreach ($incident in $results) {
                $incidentCount++
                
                $progressParams['Status'] = "Processing incident $incidentCount of $totalCount"
                $progressParams['PercentComplete'] = ($incidentCount / $totalCount) * 100
                Write-Progress @progressParams
                
                $incidents += $incident
            }
        }
        else {
            Write-Warning "No incidents retrieved from Graph API"
        }
    }
    catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new("Failed to retrieve security incidents: $_"),
            "IncidentRetrievalFailed",
            [System.Management.Automation.ErrorCategory]::ReadError,
            $null
        )
        $PSCmdlet.WriteError($errorRecord)
        return
    }
    finally {
        Write-Progress @progressParams -Completed
    }
    #endregion Retrieve Incidents
}

end {
    #region Process Results
    if ($incidents.Count -eq 0) {
        Write-Warning "No high-severity incidents found for the specified criteria"
        return
    }
    
    Write-Verbose "Total incidents retrieved: $($incidents.Count)"
    
    #region Statistics
    if ($VerbosePreference -eq 'Continue') {
        $stats = $incidents | Group-Object -Property status | 
            Select-Object @{N='Status';E={$_.Name}}, @{N='Count';E={$_.Count}}
        
        Write-Verbose "Incident breakdown by status:"
        foreach ($stat in $stats) {
            Write-Verbose "  $($stat.Status): $($stat.Count)"
        }
        
        $sources = $incidents | Group-Object -Property { $_.AdditionalProperties.productName } |
            Select-Object @{N='Source';E={$_.Name}}, @{N='Count';E={$_.Count}}
        
        Write-Verbose "Incident breakdown by source:"
        foreach ($source in $sources) {
            Write-Verbose "  $($source.Source): $($source.Count)"
        }
        
        if ($incidents.createdDateTime) {
            $dateRange = $incidents.createdDateTime | Measure-Object -Minimum -Maximum
            Write-Verbose "Date range of incidents: $($dateRange.Minimum) to $($dateRange.Maximum)"
        }
    }
    #endregion Statistics
    
    #region Export to CSV
    if ($ExportToCsv) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvFileName = "SecurityIncidents_High_$timestamp.csv"
        $csvPath = Join-Path -Path $ExportPath -ChildPath $csvFileName
        
        if ($PSCmdlet.ShouldProcess($csvPath, "Export incidents to CSV")) {
            try {
                Write-Verbose "Flattening incident objects for CSV export..."
                $flatIncidents = $incidents | ForEach-Object { ConvertTo-FlatObject -InputObject $_ }
                
                $flatIncidents | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Verbose "Exported $($incidents.Count) incidents to: $csvPath"
                
                [PSCustomObject]@{
                    ExportPath = $csvPath
                    IncidentCount = $incidents.Count
                    FileSize = (Get-Item $csvPath).Length
                }
            }
            catch {
                Write-Warning "Failed to export incidents to CSV: $_"
            }
        }
    }
    #endregion Export to CSV
    
    #region Group by Source
    if ($GroupBySource) {
        Write-Verbose "Grouping incidents by source..."
        $groupedIncidents = $incidents | Group-Object -Property { $_.AdditionalProperties.productName }
        
        foreach ($group in $groupedIncidents) {
            $groupObject = [PSCustomObject]@{
                Source = $group.Name
                Count = $group.Count
                Incidents = $group.Group
            }
            
            Write-Output $groupObject
        }
    }
    else {
        Write-Output $incidents
    }
    #endregion Group by Source
    
    Write-Verbose "Script execution completed"
    #endregion Process Results
}