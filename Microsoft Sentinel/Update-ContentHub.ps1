<#
.SYNOPSIS
Update Microsoft Sentinel Content Hub Solutions at Scale.

.DESCRIPTION
How to update Microsoft Sentinel Content Hub Solutions at Scale using PowerShell and REST API.

.NOTES
File Name : Update-ContentHub.ps1
Author    : Microsoft MVP/MCT - Charbel Nemnom
Version   : 2.2
Date      : 29-November-2023
Updated   : 18-March-2024
Requires  : PowerShell 6.2 or PowerShell 7.x.x (Core)
Module    : Az Module

.LINK
To provide feedback or for further assistance please visit:
 https://charbelnemnom.com 

.EXAMPLE
.\Update-ContentHub.ps1 -SubscriptionId <SUB-ID> -ResourceGroup <RG-Name> -WorkspaceName <Log-Analytics-Name> -Verbose
This example will connect to your Azure account using the subscription ID specified, and then check for the installed solutions in the Content Hub and filter the ones that require an update.
#>

param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$subscriptionId,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$resourceGroupName,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$workspaceName,
    [Parameter(Mandatory)]
    [ValidateSet("Yes", "No")]
    [String]$preview = 'No'
)

#! Install Az Module If Needed
function Install-Module-If-Needed {
    param([string]$ModuleName)
 
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "Module '$($ModuleName)' already exists, continue..." -ForegroundColor Green
    } 
    else {
        Write-Host "Module '$($ModuleName)' does not exist, installing..." -ForegroundColor Yellow
        Install-Module $ModuleName -Force  -AllowClobber -ErrorAction Stop
        Write-Host "Module '$($ModuleName)' installed." -ForegroundColor Green
    }
}

#! Install Az Accounts Module If Needed
Install-Module-If-Needed Az.Accounts

#! Check Azure Connection
Try { 
    Write-Verbose "Connecting to Azure Cloud..." 
    Connect-AzAccount -ErrorAction Stop | Out-Null 
}
Catch { 
    Write-Warning "Cannot connect to Azure Cloud. Please check your credentials. Exiting!" 
    Break 
}

# Define the latest API Version to use for Sentinel
$apiVersion = "?api-version=2023-11-01"

# Get Content Hub Solutions Function
Function Get-ContentHub {
    param (
        [string]$contentURI            
    )    
    #! Get Az Access Token
    $token = Get-AzAccessToken #This will default to Azure Resource Manager endpoint
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.Token
    }
    return Invoke-RestMethod $contentURI -Method 'GET' -Headers $authHeader
}

# Install Content Hub Solutions Function
Function Install-ContentHub {
    param (
        [string]$installURL,
        [string]$installBody            
    )    
    return Invoke-AzRestMethod $installURL -Method 'PUT' -Payload $installBody -Verbose:$false
}

# Define the base Rest API URI Call
$restAPIUri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/"

# Get [Installed] All Content Hub Solutions
$installedContentHub = (Get-ContentHub -contentURI ($restAPIUri + "contentPackages$($apiVersion)")).value

# Get All Content Hub Solutions
$ContentHub = (Get-ContentHub -contentURI ($restAPIUri + "contentProductPackages$($apiVersion)")).value

if ($preview -eq "Yes") {
    # Filter Installed Content Hub Solutions, which requires update including [Preview] content from getting updated
    $solutions = @()
    foreach ($item in $installedContentHub) {
        $ref = $ContentHub | Where-Object { $_.properties.displayName -eq $item.properties.displayName } 
        if ($ref.properties.version -gt $item.properties.version) {
            $solutions += $ref
        }
    }    
}
else {
    # Filter Installed Content Hub Solutions, which requires update excluding [Preview] content from getting updated
    $solutions = @()
    foreach ($item in $installedContentHub) {
        $ref = $ContentHub | Where-Object { $_.properties.displayName -eq $item.properties.displayName -and $_.properties.isPreview -eq $false } 
        if ($ref.properties.version -gt $item.properties.version) {
            $solutions += $ref
        }
    }    
}
  
if ($solutions.count -eq 0) {
    Write-Output "All the installed Content Hub solutions are currently up to date. No update is required."
}
Else {
    Write-Output "$($solutions.count) Content Hub solutions were found installed and require an update."
    
    foreach ($solution in $solutions) {        
        $singleSolution = Get-ContentHub -contentURI ($restAPIUri + "contentProductPackages/$($solution.name)$($apiVersion)")
        $packagedContent = $singleSolution.properties.packagedContent

        foreach ($resource in $packagedContent.resources) {
            if ($null -ne $resource.properties.mainTemplate.metadata.postDeployment ) {                
                $resource.properties.mainTemplate.metadata.postDeployment = $null 
            } 
        }
        $solutionDisplayName = $solution.properties.displayName -replace " ",""
        $installBody = @{"properties" = @{ 
                "parameters" = @{ 
                    "workspace"          = @{"Value" = $workspaceName }
                    "workspace-location" = @{"Value" = "" } 
                } 
                "template"   = $packagedContent
                "mode"       = "Incremental" 
            } 
        } 
        $deploymentName = ("ContenthubBulkInstall-" + $solutionDisplayName)
        if ($deploymentName.Length -gt 62) {
            $deploymentName = $deploymentName.Substring(0, 62)
        }

        $installURL = "https://management.azure.com/subscriptions/$subscriptionid/resourcegroups/$resourceGroupName/providers/Microsoft.Resources/deployments/" + $deploymentName + "?api-version=2021-04-01"
        $installContentHub = Install-ContentHub -installURL $installURL -installBody ($installBody | ConvertTo-Json -EnumsAsStrings -Depth 50 -EscapeHandling EscapeNonAscii)
                        
        try {        
            if (!($installContentHub.StatusCode -in 200, 201)) {
                Write-Host $installContentHub.StatusCode
                Write-Host $installContentHub.Content
                throw "Error when updating Content Hub Solution [$($solution.properties.displayName)]"
            }
            Write-Output "Content Hub Solution [$($solution.properties.displayName)] updated successfully!"
        }
        catch {
            Write-Error $_ -ErrorAction Continue
        }        
    }   
}
