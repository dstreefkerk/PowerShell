<#
.SYNOPSIS
    Processes Prowler findings from an OCSF JSON file, groups findings by event code and status, 
    and exports the results to a CSV file, organized by severity level and with a column per compliance framework.

.DESCRIPTION
    This script reads a JSON file containing Prowler findings in OCSF format, processes and groups findings 
    by event code and status, and generates a CSV report for easier analysis and reporting.
    Findings are organized by severity levels in descending order (Critical, High, Medium, Low, 
    Informational), with options to specify compliance frameworks relevant to each finding.
    
    If no output path is specified, the CSV is saved in the same directory as the input file.

    More info about OCSF: https://www.observo.ai/post/observability-101-understanding-ocsf

.PARAMETER InputOCSFFile
    Specifies the path to the input JSON file containing Prowler findings in OCSF format.
    The script validates that the file exists and has a '.json' extension.

.PARAMETER OutputCSVFile
    (Optional) Specifies the path where the CSV report should be saved.
    If not provided, the output file will be saved with the same path and filename as the input file, 
    with a '.csv' extension.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    A CSV file containing processed findings, organized by event code, status, and severity.

.EXAMPLE
    .\Invoke-AnalyseProwlerOCSF.ps1 -InputOCSFFile "C:\path\to\prowler-output.json" -OutputCSVFile "C:\path\to\report.csv"
    Processes the specified JSON file and saves the CSV report to the specified path.

.EXAMPLE
    .\Invoke-AnalyseProwlerOCSF.ps1 -InputOCSFFile "C:\path\to\prowler-output.json"
    Processes the specified JSON file and saves the CSV report in the same directory with a ".csv" extension.

.NOTES
    - This script expects JSON data structured according to the OCSF standard for Prowler findings.
    - Ensure the executing user has permissions to write to the specified output path.
#>

param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        Test-Path $_; 
        (Get-Item $_).Extension -eq '.json'
    })]
    [string]$InputOCSFFile,

    [ValidateScript({
        ($_ -eq "") -or (Test-Path -PathType Container $_)
    })]
    [string]$OutputCSVFile = ""
)

# Set default output file path if not provided
if (-not $OutputCSVFile) {
    $OutputCSVFile = "$($InputOCSFFile).csv"
}

# Read and group findings by event code
$findings = Get-Content -Path $InputOCSFFile | ConvertFrom-Json
$findings = $findings | Group-Object { $_.metadata.event_code }

# Extract unique compliance frameworks across all objects
$complianceFrameworks = $findings.group.unmapped.compliance | 
    ForEach-Object { $_ | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name } | 
    Sort-Object -Unique

# Set up a new generic list to contain our processed findings
$output = [System.Collections.Generic.List[PSObject]]::new()

# Loop through each group of findings, grouped by the check name
foreach ($finding in $findings) {

    # Within each group, we want to further group by the status code. e.g. Extract each failing or passing group of the same check as their own line item
    foreach ($findingStatus in ($finding.Group | Group-Object -Property status_code)) {

        # Set up a temporary placeholder representation of each CSV row
        $tempObject = [pscustomobject][ordered]@{
            "Check ID"            = $finding.Name
            "Count"               = $findingStatus.Count
            "Severity"            = $findingStatus.Group.severity | Select-Object -First 1
            "Check"               = $findingStatus.Group.finding_info.title | Select-Object -First 1
            "Status"              = $findingStatus.Name
            "Risk"                = $finding.Group.risk_details | Select-Object -First 1
            "Affected Resources"  = $findingStatus.Group.resources.uid -join "`n"
            "Extended Status"     = $findingStatus.Group.status_detail -join "`n"
            "Recommendation"      = $findingStatus.Group.remediation.desc | Select-Object -First 1
            "References"          = ($findingStatus.Group.remediation.references | Sort-Object -Unique | Where-Object { $_ -like "http*" }) -join "`n"
            "Include in Report?"  = ""
            "Review Notes"        = ""
        }

        # Add compliance framework property columns for each row
        foreach ($framework in $complianceFrameworks) {
            $frameworkValue = if (($finding.Group.unmapped.compliance | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name) -contains $framework) {
                ($finding.Group.unmapped.compliance.$framework | Sort-Object -Unique) -join "`n"
            } else {
                ""
            }
            $tempObject | Add-Member -MemberType NoteProperty -Name $framework -Value $frameworkValue
        }

        # Add our temporary object to the output collection
        $output.Add($tempObject)
    }
}

# Sort the output by severity and count
$sortOrder = @("Critical","High","Medium","Low","Informational")
$sortedOutput = @()

# Reorganise the output in proper descending severity order (Critical->High->Medium->Low->Informational)
foreach ($order in $sortOrder) {
    $sortedOutput += ($output | Where-Object { $_.Severity -eq $order } | Sort-Object -Property Count -Descending)
}

# Export sorted output to CSV
$sortedOutput | Export-Csv -Path $OutputCSVFile -NoTypeInformation -Force

Write-Host "CSV file generated at: $OutputCSVFile"
