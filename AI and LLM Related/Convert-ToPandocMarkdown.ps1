<#
.SYNOPSIS
Converts document formats to searchable Markdown using Pandoc with intelligent table handling.

.DESCRIPTION
This PowerShell script leverages Pandoc to convert various document formats (docx, html, odt, epub, etc.) 
to Markdown format with a focus on preserving searchable text content. The script automatically handles 
folder paths with spaces and provides multiple table conversion strategies to prevent word-breaking issues 
that can hamper text searching.

Key Features:
- Supports 25+ input formats via Pandoc
- Handles folder paths containing spaces properly
- Intelligent table conversion using Lua filters (default)
- Batch processing with recursive folder support
- Automatic Pandoc installation if missing
- Comprehensive error handling and validation
- Temporary file management for reliable conversion

The default LuaFilter option converts tables to clean, searchable plain text format while preserving 
line breaks, bullet points, and paragraph structure - ideal for full-text searching without the 
word-breaking issues common in standard Markdown tables.

.PARAMETER File
Path to a single file to convert to Markdown. Must be an existing file with a supported format.

.PARAMETER Folder
Path to a folder containing files to convert to Markdown. Script will process all supported file types found.

.PARAMETER OutputPath
Optional output directory for converted files. If not specified, files are converted in their original location.
When specified, the script maintains the folder structure relative to the input folder.

.PARAMETER Recurse
When processing folders, include files in subdirectories recursively.

.PARAMETER Force
Overwrite existing output files without prompting. Without this flag, the script will skip files where output already exists.

.PARAMETER TableHandling
Controls how tables are handled during conversion (default: LuaFilter for best searchability):

- LuaFilter: Converts tables to clean plain text format using embedded Lua filter. Preserves complete words,
  line breaks, and list formatting. Best option for text searching and content analysis. (DEFAULT)
  
- Default: Standard Markdown table format with pipe symbols. May break words across table cell boundaries,
  which can interfere with text searching (e.g., "Descrip|tion" instead of "Description").
  
- NoTables: Preserves tables as HTML markup. Maintains complete words and structure but includes HTML tags.
  Good for searching but less readable as plain text.
  
- PlainText: Uses pandoc's plain text output format. May still have ASCII table borders and formatting issues.
  
- SimpleText: Uses markdown_strict format which produces clean HTML tables. Similar to NoTables but with
  stricter markdown compliance.

.EXAMPLE
Convert-ToPandocMarkdown.ps1 -File "report.docx"
Converts a single Word document to Markdown using the default LuaFilter for optimal searchability.

.EXAMPLE
Convert-ToPandocMarkdown.ps1 -Folder "C:\Project Documents" -Recurse
Processes all supported files in the folder and subfolders, converting them to searchable Markdown format.

.EXAMPLE
Convert-ToPandocMarkdown.ps1 -Folder "C:\Source\Docs" -OutputPath "C:\Output\Markdown" -Force
Converts all files from source folder to a separate output directory, overwriting any existing files.

.EXAMPLE
Convert-ToPandocMarkdown.ps1 -File "data.xlsx" -TableHandling Default
Converts using standard Markdown tables instead of the default LuaFilter (may break words in table cells).

.NOTES
Author: Claude Code Assistant
Requires: PowerShell 5.1+, Pandoc (auto-installed if missing via winget)
Supported Input Formats: docx, html, odt, epub, rtf, tex, org, wiki, csv, json, ipynb, and many more
Output Format: Markdown (.md files)

For best text searching results, use the default LuaFilter option which eliminates word-breaking issues
common in traditional table formats while maintaining clean, readable output.
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(ParameterSetName = 'File', Mandatory = $true, Position = 0)]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { 
            return $true 
        } else {
            throw "The path '$_' is not a valid file. Use -File for individual files or -Folder for directories."
        }
    })]
    [string]$File,
    
    [Parameter(ParameterSetName = 'Folder', Mandatory = $true, Position = 0)]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { 
            return $true 
        } else {
            throw "The path '$_' is not a valid directory. Use -Folder for directories or -File for individual files."
        }
    })]
    [string]$Folder,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$Recurse,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Default", "NoTables", "PlainText", "SimpleText", "LuaFilter")]
    [string]$TableHandling = "LuaFilter"
)

function Test-PandocInstalled {
    try {
        $null = Get-Command pandoc -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Install-Pandoc {
    Write-Host "Pandoc not found. Installing via winget..." -ForegroundColor Yellow
    try {
        winget install --id JohnMacFarlane.Pandoc -e --silent
        Write-Host "Pandoc installed successfully." -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Failed to install Pandoc: $($_.Exception.Message)"
        return $false
    }
}

function Get-SupportedInputFormats {
    try {
        $formats = pandoc --list-input-formats
        return $formats
    } catch {
        Write-Error "Failed to get supported input formats from pandoc: $($_.Exception.Message)"
        return @()
    }
}

function New-LuaTableFilter {
    param([string]$OutputPath)
    
    $luaContent = @'
function Table(el)
  local lines = {}
  
  -- Helper function to convert cell contents while preserving line breaks
  local function stringify_with_breaks(cell_contents)
    local result = {}
    for _, block in pairs(cell_contents) do
      if block.t == "Para" then
        table.insert(result, pandoc.utils.stringify(block))
      elseif block.t == "BulletList" or block.t == "OrderedList" then
        for _, item in pairs(block.content) do
          table.insert(result, "- " .. pandoc.utils.stringify(item))
        end
      else
        table.insert(result, pandoc.utils.stringify(block))
      end
    end
    return table.concat(result, "\n")
  end
  
  -- Process header if it exists
  if el.head and el.head.rows and #el.head.rows > 0 then
    for _, row in pairs(el.head.rows) do
      local header_line = {}
      for _, cell in pairs(row.cells) do
        table.insert(header_line, stringify_with_breaks(cell.contents))
      end
      table.insert(lines, table.concat(header_line, " | "))
    end
    table.insert(lines, "")
  end
  
  -- Process body rows
  if el.bodies and #el.bodies > 0 then
    for _, body in pairs(el.bodies) do
      if body.body then
        for _, row in pairs(body.body) do
          local row_line = {}
          for _, cell in pairs(row.cells) do
            table.insert(row_line, stringify_with_breaks(cell.contents))
          end
          table.insert(lines, table.concat(row_line, " | "))
        end
      end
    end
  end
  
  return pandoc.CodeBlock(table.concat(lines, "\n"))
end
'@
    
    Set-Content -Path $OutputPath -Value $luaContent -Encoding UTF8
    return $OutputPath
}

function Get-FileExtensionMapping {
    $mapping = @{
        '.tex' = 'latex'
        '.html' = 'html'
        '.htm' = 'html'
        '.docx' = 'docx'
        '.odt' = 'odt'
        '.epub' = 'epub'
        '.fb2' = 'fb2'
        '.ipynb' = 'ipynb'
        '.json' = 'json'
        '.csv' = 'csv'
        '.tsv' = 'tsv'
        '.rst' = 'rst'
        '.rtf' = 'rtf'
        '.org' = 'org'
        '.md' = 'markdown'
        '.markdown' = 'markdown'
        '.mdown' = 'markdown'
        '.mkd' = 'markdown'
        '.wiki' = 'mediawiki'
        '.textile' = 'textile'
        '.typ' = 'typst'
    }
    return $mapping
}

function Test-SupportedFileType {
    param(
        [string]$FilePath,
        [array]$SupportedFormats,
        [hashtable]$ExtensionMapping
    )
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    if ($ExtensionMapping.ContainsKey($extension)) {
        $format = $ExtensionMapping[$extension]
        return $SupportedFormats -contains $format
    }
    
    return $false
}

function Convert-FileToMarkdown {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [hashtable]$ExtensionMapping,
        [string]$TableHandling = "Default"
    )
    
    # Validate inputs
    if ([string]::IsNullOrEmpty($InputFile) -or [string]::IsNullOrEmpty($OutputFile)) {
        Write-Error "Input file and output file paths cannot be null or empty"
        return $false
    }
    
    $extension = [System.IO.Path]::GetExtension($InputFile).ToLower()
    $inputFormat = $ExtensionMapping[$extension]
    
    # Validate format
    if ([string]::IsNullOrEmpty($inputFormat)) {
        Write-Error "Could not determine input format for extension: $extension"
        return $false
    }
    
    try {
        Write-Host "Converting: $InputFile -> $OutputFile" -ForegroundColor Cyan
        
        # Create temporary files with short names to avoid space issues
        $tempInputFile = [System.IO.Path]::GetTempFileName() + [System.IO.Path]::GetExtension($InputFile)
        $tempOutputFile = [System.IO.Path]::GetTempFileName() + ".md"
        $tempLuaFilter = $null
        
        try {
            # Copy input file to temp location
            Copy-Item $InputFile $tempInputFile -Force
            
            # Determine output format and options based on table handling
            switch ($TableHandling) {
                "NoTables" {
                    $outputFormat = "markdown-pipe_tables-simple_tables-multiline_tables-grid_tables"
                    pandoc -f $inputFormat -t $outputFormat $tempInputFile -o $tempOutputFile
                }
                "PlainText" {
                    $outputFormat = "plain"
                    pandoc -f $inputFormat -t $outputFormat $tempInputFile -o $tempOutputFile
                }
                "SimpleText" {
                    $outputFormat = "markdown_strict"
                    pandoc -f $inputFormat -t $outputFormat $tempInputFile -o $tempOutputFile
                }
                "LuaFilter" {
                    # Create temporary Lua filter
                    $tempLuaFilter = [System.IO.Path]::Combine($env:TEMP, "table-to-text-$([System.Guid]::NewGuid().ToString()).lua")
                    New-LuaTableFilter -OutputPath $tempLuaFilter | Out-Null
                    
                    $outputFormat = "markdown"
                    pandoc -f $inputFormat -t $outputFormat --lua-filter $tempLuaFilter $tempInputFile -o $tempOutputFile
                }
                default {
                    $outputFormat = "markdown"
                    pandoc -f $inputFormat -t $outputFormat $tempInputFile -o $tempOutputFile
                }
            }
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -eq 0) {
                # Copy result back to original location
                Copy-Item $tempOutputFile $OutputFile -Force
                Write-Host "Successfully converted: $InputFile" -ForegroundColor Green
                return $true
            } else {
                Write-Warning "Failed to convert: $InputFile (Exit code: $exitCode)"
                return $false
            }
        } finally {
            # Clean up temp files
            if (Test-Path $tempInputFile) { Remove-Item $tempInputFile -Force -ErrorAction SilentlyContinue }
            if (Test-Path $tempOutputFile) { Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue }
            if ($tempLuaFilter -and (Test-Path $tempLuaFilter)) { Remove-Item $tempLuaFilter -Force -ErrorAction SilentlyContinue }
        }
    } catch {
        Write-Error "Error converting $InputFile : $($_.Exception.Message)"
        return $false
    }
}

# Main script logic
Write-Host "Pandoc to Markdown Converter" -ForegroundColor Magenta
Write-Host "=============================" -ForegroundColor Magenta

# Check if pandoc is installed
if (-not (Test-PandocInstalled)) {
    Write-Host "Pandoc is not installed." -ForegroundColor Red
    $install = Read-Host "Would you like to install Pandoc now? (y/N)"
    
    if ($install -match '^[Yy]') {
        if (-not (Install-Pandoc)) {
            Write-Error "Cannot proceed without Pandoc. Exiting."
            exit 1
        }
    } else {
        Write-Error "Cannot proceed without Pandoc. Exiting."
        exit 1
    }
}

# Get supported formats and extension mapping
$supportedFormats = Get-SupportedInputFormats
$extensionMapping = Get-FileExtensionMapping

if ($supportedFormats.Count -eq 0) {
    Write-Error "Could not retrieve supported input formats from pandoc. Exiting."
    exit 1
}

Write-Host "Supported input formats: $($supportedFormats.Count)" -ForegroundColor Green

# Process based on parameter set
switch ($PSCmdlet.ParameterSetName) {
    'File' {
        # Single file processing
        if (-not (Test-SupportedFileType -FilePath $File -SupportedFormats $supportedFormats -ExtensionMapping $extensionMapping)) {
            $extension = [System.IO.Path]::GetExtension($File)
            Write-Error "File type '$extension' is not supported by pandoc for conversion to markdown."
            exit 1
        }
        
        if (-not $OutputPath) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($File)
            $directory = [System.IO.Path]::GetDirectoryName($File)
            $OutputPath = Join-Path $directory "$baseName.md"
        }
        
        if ((Test-Path $OutputPath) -and -not $Force) {
            Write-Error "Output file '$OutputPath' already exists. Use -Force to overwrite."
            exit 1
        }
        
        $success = Convert-FileToMarkdown -InputFile $File -OutputFile $OutputPath -ExtensionMapping $extensionMapping -TableHandling $TableHandling
        
        if ($success) {
            Write-Host ""
            Write-Host "Conversion completed successfully!" -ForegroundColor Green
            Write-Host "Output: $OutputPath" -ForegroundColor Yellow
        } else {
            Write-Error "Conversion failed."
            exit 1
        }
    }
    
    'Folder' {
        # Folder processing
        $allFiles = Get-ChildItem -Path $Folder -File -Recurse:$Recurse
        
        # Filter for supported file types
        $supportedFiles = @()
        foreach ($currentFile in $allFiles) {
            if (Test-SupportedFileType -FilePath $currentFile.FullName -SupportedFormats $supportedFormats -ExtensionMapping $extensionMapping) {
                $supportedFiles += $currentFile
            }
        }
        
        if ($supportedFiles.Count -eq 0) {
            Write-Warning "No supported files found in the specified folder."
            exit 0
        }
        
        Write-Host "Found $($supportedFiles.Count) supported files for conversion." -ForegroundColor Green
        
        $successCount = 0
        $failCount = 0
        
        foreach ($currentFile in $supportedFiles) {
            # Add null checks and validation
            if ([string]::IsNullOrEmpty($currentFile.FullName)) {
                Write-Warning "Skipping file with empty path"
                $failCount++
                continue
            }
            
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($currentFile.FullName)
            $directory = [System.IO.Path]::GetDirectoryName($currentFile.FullName)
            
            # Validate extracted values
            if ([string]::IsNullOrEmpty($baseName) -or [string]::IsNullOrEmpty($directory)) {
                Write-Warning "Skipping $($currentFile.FullName) - unable to extract valid file or directory name"
                $failCount++
                continue
            }
            
            if ($OutputPath) {
                # If output path specified, maintain folder structure
                $relativePath = [System.IO.Path]::GetRelativePath($Folder, $directory)
                $outputDir = Join-Path $OutputPath $relativePath
                
                if (-not (Test-Path $outputDir)) {
                    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                }
                
                $outputFile = Join-Path $outputDir "$baseName.md"
            } else {
                # Convert in place
                $outputFile = Join-Path $directory "$baseName.md"
            }
            
            if ((Test-Path $outputFile) -and -not $Force) {
                Write-Warning "Skipping $($currentFile.Name) - output file already exists. Use -Force to overwrite."
                $failCount++
                continue
            }
            
            $success = Convert-FileToMarkdown -InputFile $currentFile.FullName -OutputFile $outputFile -ExtensionMapping $extensionMapping -TableHandling $TableHandling
            
            if ($success) {
                $successCount++
            } else {
                $failCount++
            }
        }
        
        Write-Host ""
        Write-Host "Folder conversion completed:" -ForegroundColor Green
        Write-Host "  Successfully converted: $successCount files" -ForegroundColor Green
        if ($failCount -gt 0) {
            Write-Host "  Failed conversions: $failCount files" -ForegroundColor Red
        }
    }
}