#Requires -Version 5.1

<#
.SYNOPSIS
    Detects Microsoft Sentinel feature availability by Azure region using the public
    Azure Retail Prices API.

.DESCRIPTION
    Not all Sentinel features are available in every Azure region. This script detects
    availability by checking which pricing meters exist per region — if a meter for a
    feature (e.g., "Data lake ingestion Data Processed") appears in a region's pricing
    data, that feature is available there.

    The script queries the unauthenticated Azure Retail Prices REST API
    (https://prices.azure.com/api/retail/prices) filtering for serviceName='Sentinel'
    per region, then matches returned meter names against regex patterns for each
    feature group.

    Features detected:
      - Pay-as-you-go           standard PAYG analysis ingestion
      - Commitment Tiers        50 GB to 50,000 GB/day capacity reservations
      - Basic Logs              low-cost ingestion tier for verbose logs
      - Auxiliary Logs          ultra-low-cost tier (Classic Auxiliary)
      - Data Lake Ingestion     ingestion into Sentinel Data Lake
      - Data Lake Storage       long-term Data Lake retention
      - Data Lake Query         querying Data Lake data
      - Data Processing         data processing charges
      - Advanced Data Insights  hourly compute for advanced analytics

    No authentication or Azure subscription is required. The Retail Prices API is
    public and free to call.

    This script is a proof-of-concept. The two internal functions
    (Get-SentinelRegionPricing, Test-SentinelFeatureAvailability) follow a reusable
    pattern and can be copied into a module or integrated into assessment scripts.

.PARAMETER Region
    One or more Azure region names to compare. Must be lowercase alphanumeric ARM
    region names as used by Azure (e.g., 'australiaeast', 'uksouth', 'eastus2').

    Accepts an array for multi-region comparison. The comparison table will have one
    column per region.

    Default: @('australiaeast', 'australiasoutheast', 'australiacentral')

    To find valid region names, run: Get-AzLocation | Select DisplayName, Location
    or: az account list-locations --query "[].name" -o tsv

.PARAMETER Detailed
    When specified, appends two additional sections after the comparison table:

    1. Meter Match Details - for each region, lists which specific meter names matched
       each feature pattern (prefixed [+]) or notes absence (prefixed [-]).

    2. All Meters by Region - dumps every Sentinel meter in each region with
       meterName, unitOfMeasure, retailPrice, and unitPrice columns.

    Useful for understanding exactly which meters drive each feature detection and
    for spotting new or unexpected meters.

.EXAMPLE
    .\Get-SentinelRegionFeatures.ps1

    Checks the three default Australian regions. Sample output:

      Microsoft Sentinel - Region Feature Availability (PoC)
      API: https://prices.azure.com/api/retail/prices

        Querying region: australiaeast ... 23 meters
        Querying region: australiasoutheast ... 18 meters
        Querying region: australiacentral ... 18 meters

        Feature Availability Comparison
        --------------------------------------------------

        Feature                australiaeast australiasoutheast australiacentral
        -------                ------------- ------------------ ----------------
        Pay-as-you-go          Yes           Yes                Yes
        Commitment Tiers       Yes           Yes                Yes
        Basic Logs             Yes           Yes                Yes
        Auxiliary Logs         Yes           Yes                Yes
        Data Lake Ingestion    Yes           -                  -
        Data Lake Storage      Yes           -                  -
        Data Lake Query        Yes           -                  -
        Data Processing        Yes           -                  -
        Advanced Data Insights Yes           -                  -

    This shows that Data Lake, Data Processing, and Advanced Data Insights meters
    only exist in australiaeast, not in australiasoutheast or australiacentral.
    'Yes' means at least one matching meter was found; '-' means none.

.EXAMPLE
    .\Get-SentinelRegionFeatures.ps1 -Region 'eastus','westeurope','southeastasia'

    Compares three major regions across different geographies. Each region becomes
    a column in the output table. Pass as many regions as needed — the table adapts.

.EXAMPLE
    .\Get-SentinelRegionFeatures.ps1 -Detailed

    Shows the comparison table followed by per-region detail. Excerpt of the two
    additional sections:

      Meter Match Details
      --------------------------------------------------

      Region: australiaeast
        [+] Pay-as-you-go - Free Benefit - M365 Defender Analysis; Pay-as-you-go Analysis; ...
        [+] Commitment Tiers - 100 GB Commitment Tier Capacity Reservation; ...
        [+] Data Lake Ingestion - Data lake ingestion Data Processed
        [+] Data Lake Storage - Data lake storage Data Stored
        [+] Data Lake Query - Data lake query Data Analyzed

      Region: australiasoutheast
        [+] Pay-as-you-go - Free Benefit - M365 Defender Analysis; Pay-as-you-go Analysis; ...
        [+] Commitment Tiers - 100 GB Commitment Tier Capacity Reservation; ...
        [-] Data Lake Ingestion - not available
        [-] Data Lake Storage - not available
        [-] Data Lake Query - not available

      All Meters by Region
      --------------------------------------------------

      Region: australiaeast (23 meters)
      meterName                                     unitOfMeasure retailPrice unitPrice
      ---------                                     ------------- ----------- ---------
      100 GB Commitment Tier Capacity Reservation   1/Day         419.4000    419.4000
      Data lake ingestion Data Processed            1 GB          0.0725      0.0725
      Data lake storage Data Stored                 1 GB/Month    0.0250      0.0250
      Pay-as-you-go Analysis                        1 GB          6.2400      6.2400
      ...

.EXAMPLE
    .\Get-SentinelRegionFeatures.ps1 -Region 'uksouth' -Verbose

    Checks a single region with verbose API logging. The -Verbose flag shows each
    HTTP request and pagination detail as it happens:

      VERBOSE:   Page 1: GET https://prices.azure.com/api/retail/prices?$filter=...
      VERBOSE:   Total: 23 meters for 'uksouth' (1 pages)

      Feature Availability Comparison
      --------------------------------------------------

      Feature                uksouth
      -------                -------
      Pay-as-you-go          Yes
      ...

.NOTES
    API Reference : https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices
    API Endpoint  : https://prices.azure.com/api/retail/prices
    Auth Required : None (public, unauthenticated)
    Rate Limits   : Undocumented; the API is generally permissive for moderate use.
    Pagination    : The API returns up to 100 items per page with a NextPageLink for
                    subsequent pages. This script follows all pages automatically.

    HOW DETECTION WORKS
    The script filters the API with:
        $filter=serviceName eq 'Sentinel' and armRegionName eq '<region>'
    Each returned item has a meterName property (e.g., "Data lake ingestion Data
    Processed", "Pay-as-you-go Analysis", "100 GB Commitment Tier Capacity
    Reservation"). The script matches meterName values against regex patterns defined
    in $FeatureDefinitions. If at least one meter matches any of a feature's patterns,
    that feature is marked 'Yes' for that region.

    REUSABLE FUNCTIONS
    This script defines two functions intended for reuse in larger tooling:

    Get-SentinelRegionPricing -RegionName <string>
        Returns all Sentinel meter objects for a region as PSObject[]. Each object
        has properties including: meterName, unitOfMeasure, retailPrice, unitPrice,
        armRegionName, skuName, productName, and others from the API.

    Test-SentinelFeatureAvailability -RegionName <string> -Meters <PSObject[]> -Features <OrderedDictionary>
        Takes meter objects and a feature-to-pattern dictionary. Returns one
        PSCustomObject per feature with properties: Region (string), Feature (string),
        Available (bool), MatchingMeters (string[]).

    To reuse these functions, copy them into your own script or module. Do not
    dot-source this file, as that will also execute the main body (querying the
    default regions).

    OUTPUT BEHAVIOUR
    All display output uses Write-Host (information stream). The script does not
    emit objects to the success output stream. To work with meter data
    programmatically, copy the functions and call them directly.

    LIMITATIONS
    - Meter names may change over time as Microsoft updates pricing SKUs. If
      detection stops working for a feature, run with -Detailed to inspect current
      meter names and update the regex patterns in $FeatureDefinitions.
    - The API returns retail (list) prices. These may differ from negotiated,
      EA, or CSP pricing — but the presence/absence of meters still indicates
      feature availability regardless of price.
    - Region names must exactly match Azure ARM region identifiers (lowercase,
      no spaces or hyphens). Invalid names return zero meters rather than an error.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-z0-9]+$')]
    [string[]]$Region = @('australiaeast', 'australiasoutheast', 'australiacentral'),

    [Parameter()]
    [switch]$Detailed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure TLS 1.2 for HTTPS (required on some older Windows systems)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

#region Feature Definitions

# Each feature maps to one or more regex patterns matched against Sentinel meter names.
# A feature is "available" in a region if at least one meter matches any of its patterns.
$FeatureDefinitions = [ordered]@{
    'Pay-as-you-go'          = @('Pay-as-you-go Analysis', 'Analysis')
    'Commitment Tiers'       = @('\d+ GB Commitment Tier')
    'Basic Logs'             = @('Basic Logs')
    'Auxiliary Logs'         = @('Auxiliary Logs', 'Classic Auxiliary')
    'Data Lake Ingestion'    = @('Data [Ll]ake [Ii]ngestion')
    'Data Lake Storage'      = @('Data [Ll]ake [Ss]torage')
    'Data Lake Query'        = @('Data [Ll]ake [Qq]uery')
    'Data Processing'        = @('Data [Pp]rocessing')
    'Advanced Data Insights' = @('Advanced Data Insights')
}

#endregion

#region Functions

function Get-SentinelRegionPricing {
    <#
    .SYNOPSIS
        Retrieves all Sentinel pricing meters for a given Azure region from the Retail Prices API.
    .PARAMETER RegionName
        Azure region name (lowercase, e.g. 'australiaeast').
    .OUTPUTS
        PSObject[] - Array of pricing meter objects from the API.
    #>
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z0-9]+$')]
        [string]$RegionName
    )

    $baseUri = 'https://prices.azure.com/api/retail/prices'
    $filter = "serviceName eq 'Sentinel' and armRegionName eq '$RegionName'"
    $uri = "$baseUri`?`$filter=$filter"

    $allItems = [System.Collections.Generic.List[PSObject]]::new()
    $pageCount = 0

    while ($uri) {
        $pageCount++
        Write-Verbose "  Page ${pageCount}: GET $uri"

        try {
            $response = Invoke-RestMethod -Uri $uri -ErrorAction Stop
        }
        catch {
            throw "API request failed for region '$RegionName' (page $pageCount): $_"
        }

        if ($response.Items) {
            $allItems.AddRange([PSObject[]]$response.Items)
        }
        $uri = $response.NextPageLink
    }

    Write-Verbose "  Total: $($allItems.Count) meters for '$RegionName' ($pageCount pages)"
    return $allItems.ToArray()
}

function Test-SentinelFeatureAvailability {
    <#
    .SYNOPSIS
        Tests which Sentinel features are present based on pricing meter data.
    .PARAMETER RegionName
        Azure region name for labelling results.
    .PARAMETER Meters
        Array of pricing meter objects (from Get-SentinelRegionPricing).
    .PARAMETER Features
        Ordered dictionary mapping feature names to arrays of regex patterns.
    .OUTPUTS
        PSObject[] - One object per feature with Region, Feature, Available, and MatchingMeters properties.
    #>
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    param(
        [Parameter(Mandatory)]
        [string]$RegionName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [PSObject[]]$Meters,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Features
    )

    $meterNames = @()
    if ($null -ne $Meters -and $Meters.Count -gt 0) {
        $meterNames = @($Meters | ForEach-Object { $_.meterName } | Select-Object -Unique)
    }

    foreach ($featureName in $Features.Keys) {
        $patterns = $Features[$featureName]
        $matchingMeters = [System.Collections.Generic.List[string]]::new()

        foreach ($name in $meterNames) {
            foreach ($pattern in $patterns) {
                if ($name -match $pattern) {
                    if (-not $matchingMeters.Contains($name)) {
                        $matchingMeters.Add($name)
                    }
                    break
                }
            }
        }

        [PSCustomObject]@{
            Region         = $RegionName
            Feature        = $featureName
            Available      = ($matchingMeters.Count -gt 0)
            MatchingMeters = $matchingMeters.ToArray()
        }
    }
}

#endregion

#region Main

Write-Host ''
Write-Host 'Microsoft Sentinel - Region Feature Availability (PoC)' -ForegroundColor Cyan
Write-Host 'API: https://prices.azure.com/api/retail/prices' -ForegroundColor DarkGray
Write-Host ''

# Query pricing data per region
$regionData = @{}
foreach ($r in $Region) {
    Write-Host "  Querying region: $r ..." -ForegroundColor Yellow -NoNewline
    try {
        $regionData[$r] = @(Get-SentinelRegionPricing -RegionName $r)
        Write-Host " $($regionData[$r].Count) meters" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to query region '$r': $_"
        $regionData[$r] = @()
    }
}

# Test feature availability per region
$allResults = foreach ($r in $Region) {
    Test-SentinelFeatureAvailability -RegionName $r -Meters $regionData[$r] -Features $FeatureDefinitions
}

# Build comparison rows — one per feature, with a column per region
$comparisonRows = foreach ($featureName in $FeatureDefinitions.Keys) {
    $row = [ordered]@{ Feature = $featureName }
    foreach ($r in $Region) {
        $result = $allResults | Where-Object { $_.Region -eq $r -and $_.Feature -eq $featureName }
        $row[$r] = if ($result.Available) { 'Yes' } else { '-' }
    }
    [PSCustomObject]$row
}

# Display comparison table
Write-Host ''
Write-Host '  Feature Availability Comparison' -ForegroundColor Cyan
Write-Host "  $('-' * 50)"
$comparisonRows | Format-Table -AutoSize | Out-String -Stream | ForEach-Object { Write-Host "  $_" }

# Detailed output (interactive only, via Write-Host)
if ($Detailed) {
    Write-Host '  Meter Match Details' -ForegroundColor Cyan
    Write-Host "  $('-' * 50)"

    foreach ($r in $Region) {
        Write-Host ''
        Write-Host "  Region: $r" -ForegroundColor Yellow

        foreach ($featureName in $FeatureDefinitions.Keys) {
            $result = $allResults | Where-Object { $_.Region -eq $r -and $_.Feature -eq $featureName }
            if ($result.Available) {
                Write-Host "    [+] $featureName" -ForegroundColor Green -NoNewline
                Write-Host " - $($result.MatchingMeters -join '; ')"
            }
            else {
                Write-Host "    [-] $featureName - not available" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ''
    Write-Host '  All Meters by Region' -ForegroundColor Cyan
    Write-Host "  $('-' * 50)"

    foreach ($r in $Region) {
        Write-Host ''
        Write-Host "  Region: $r ($($regionData[$r].Count) meters)" -ForegroundColor Yellow
        if ($regionData[$r].Count -gt 0) {
            $regionData[$r] |
                Sort-Object meterName |
                Select-Object meterName, unitOfMeasure,
                    @{ Name = 'retailPrice'; Expression = { '{0:N4}' -f $_.retailPrice } },
                    @{ Name = 'unitPrice';   Expression = { '{0:N4}' -f $_.unitPrice } } |
                Format-Table -AutoSize |
                Out-String -Stream |
                ForEach-Object { Write-Host "  $_" }
        }
    }
}

#endregion
