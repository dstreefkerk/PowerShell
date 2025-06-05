param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

# Check if pandoc is installed
try {
    $null = Get-Command pandoc -ErrorAction Stop
}
catch {
    Write-Error "Pandoc is not installed or not in PATH. Please install pandoc first."
    exit 1
}

# Validate the path exists
if (-not (Test-Path $Path)) {
    Write-Error "The specified path '$Path' does not exist."
    exit 1
}

# Get all .docx files recursively
$docxFiles = Get-ChildItem -Path $Path -Filter "*.docx" -Recurse -File

if ($docxFiles.Count -eq 0) {
    Write-Warning "No .docx files found in '$Path'"
    exit 0
}

Write-Host "Found $($docxFiles.Count) .docx files to convert" -ForegroundColor Green

# Convert each file
foreach ($file in $docxFiles) {
    # Create the output filename with .md extension
    $mdFile = Join-Path $file.DirectoryName ($file.BaseName + ".md")
    
    Write-Host "Converting: $($file.FullName)" -ForegroundColor Cyan
    Write-Host "       To: $mdFile" -ForegroundColor Gray
    
    try {
        # Run pandoc conversion
        & pandoc -f docx -t markdown -o $mdFile $file.FullName
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Success!" -ForegroundColor Green
        }
        else {
            Write-Warning "  Pandoc returned exit code $LASTEXITCODE for file: $($file.Name)"
        }
    }
    catch {
        Write-Error "  Failed to convert $($file.Name): $_"
    }
}

Write-Host "`nConversion complete!" -ForegroundColor Green