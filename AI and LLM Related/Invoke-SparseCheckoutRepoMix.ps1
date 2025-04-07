#Requires -Version 5.1
<#
.SYNOPSIS
Performs a sparse checkout from a Git repository and runs Repomix on the checked-out content.

.DESCRIPTION
This script uses Git sparse checkout to clone only specific folders from a remote Git repository,
then runs `npx repomix` over the checked-out content to generate a summarised, compressed, AI-friendly
output file. It supports fine-grained control over Repomix parameters, including formatting, compression,
and header injection.

.PARAMETER RepoUrl
The Git repository URL (e.g., https://github.com/user/repo.git).

.PARAMETER SparsePath
One or more folder paths (relative to the repo root) to include via sparse checkout.

.PARAMETER Include
Optional. One or more fast-glob patterns (e.g., "**/*.yaml") to include in the repomix output.
Defaults to "**/*".

.PARAMETER Exclude
Optional. One or more fast-glob patterns to exclude.

.PARAMETER OutputFile
Path to the file where Repomix will write the output.

.PARAMETER Style
Output format for Repomix: xml, markdown, or plain. Defaults to "markdown".

.PARAMETER Compress
Switch. Enables Repomix compression to reduce token count.

.PARAMETER NoFileSummary
Switch. Disables the file summary section in the output.

.PARAMETER NoDirectoryStructure
Switch. Disables the directory structure section in the output.

.PARAMETER RemoveComments
Switch. Removes comments from source files before processing.

.PARAMETER RemoveEmptyLines
Switch. Removes empty lines from source files before processing.

.PARAMETER HeaderText
Optional. Adds custom header text to the top of the output file.

.EXAMPLE
Invoke-SparseCheckoutRepoMix.ps1 `
    -RepoUrl https://github.com/Azure/Azure-Sentinel.git `
    -SparsePath "Hunting Queries" `
    -Include "**/*.yaml" `
    -OutputFile C:\Temp\test.md `
    -Style markdown `
    -HeaderText "Hunting Queries Test"

.NOTES
Author: Daniel Streefkerk
Date: 07 April 2025
Requires:
  - Git in system PATH
  - Node.js (for npx)
  - Internet access for cloning remote repo

.LINK
https://github.com/modelcontextprotocol/repomix
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$RepoUrl,

    [Parameter(Mandatory)]
    [string[]]$SparsePath,

    [string[]]$Include = @("**/*"),

    [string[]]$Exclude = @(),

    [Parameter(Mandatory)]
    [string]$OutputFile,

    [ValidateSet("xml", "markdown", "plain")]
    [string]$Style = "markdown",

    [switch]$Compress,
    [switch]$NoFileSummary,
    [switch]$NoDirectoryStructure,
    [switch]$RemoveComments,
    [switch]$RemoveEmptyLines,

    [string]$HeaderText
)

function Ensure-ToolAvailable {
    param (
        [string]$ToolName,
        [string]$ErrorMessage
    )
    if (-not (Get-Command $ToolName -ErrorAction SilentlyContinue)) {
        throw $ErrorMessage
    }
}

function Ensure-NpxRepomixAvailable {
    Write-Host "Verifying 'npx repomix' is available..."
    $null = npx --yes repomix --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "'repomix' is not available via 'npx'. Ensure it can be resolved properly."
    }
}

function Get-TempPath {
    $tempDir = Join-Path $env:TEMP "repomix-sparse-$([System.Guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    return $tempDir
}

function Sparse-CheckoutRepo {
    param (
        [string]$RepoUrl,
        [string]$TargetPath,
        [string[]]$SparseFolders
    )

    git clone --filter=blob:none --no-checkout $RepoUrl $TargetPath
    Push-Location $TargetPath
    git sparse-checkout init --cone
    git sparse-checkout set $SparseFolders
    git checkout
    Pop-Location
}

function Run-Repomix {
    param (
        [string]$RepoPath,
        [string[]]$Include,
        [string[]]$Exclude,
        [string]$OutputFile,
        [string]$Style,
        [switch]$Compress,
        [switch]$NoFileSummary,
        [switch]$NoDirectoryStructure,
        [switch]$RemoveComments,
        [switch]$RemoveEmptyLines,
        [string]$HeaderText
    )

    $includeArgs = ($Include | ForEach-Object { "--include `"$($_)`"" }) -join ' '
    $excludeArgs = ($Exclude | ForEach-Object { "--ignore `"$($_)`"" }) -join ' '

    $options = @(
        "--style $Style"
        if ($Compress) { "--compress" }
        if ($NoFileSummary) { "--no-file-summary" }
        if ($NoDirectoryStructure) { "--no-directory-structure" }
        if ($RemoveComments) { "--remove-comments" }
        if ($RemoveEmptyLines) { "--remove-empty-lines" }
        if ($HeaderText) { "--header-text `"$HeaderText`"" }
    ) -join ' '

    $cmd = "npx --yes repomix `"$RepoPath`" $includeArgs $excludeArgs $options -o `"$OutputFile`""
    Write-Host "Running: $cmd"
    Invoke-Expression $cmd
}

# Main logic
$originalLocation = Get-Location
$tempRepo = $null

try {
    Ensure-ToolAvailable -ToolName "git" -ErrorMessage "'git' is not installed or not in PATH. Install Git from https://git-scm.com/downloads"
    Ensure-ToolAvailable -ToolName "npx" -ErrorMessage "'npx' is not installed or not in PATH. Install Node.js from https://nodejs.org"
    Ensure-NpxRepomixAvailable

    $tempRepo = Get-TempPath
    Write-Host "Using temporary repo path: $tempRepo"
    Sparse-CheckoutRepo -RepoUrl $RepoUrl -TargetPath $tempRepo -SparseFolders $SparsePath

    Run-Repomix -RepoPath $tempRepo `
                -Include $Include `
                -Exclude $Exclude `
                -OutputFile $OutputFile `
                -Style $Style `
                -Compress:$Compress `
                -NoFileSummary:$NoFileSummary `
                -NoDirectoryStructure:$NoDirectoryStructure `
                -RemoveComments:$RemoveComments `
                -RemoveEmptyLines:$RemoveEmptyLines `
                -HeaderText $HeaderText
}
finally {
    if ($tempRepo -and (Test-Path $tempRepo)) {
        Remove-Item -Path $tempRepo -Recurse -Force
        Write-Host "Cleaned up temp repo at: $tempRepo"
    }
    Set-Location $originalLocation
}
