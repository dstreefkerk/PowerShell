# Convert dates from US format to AU, or any specified source/target culture
function Convert-DateTimeFormat([string]$DateTime,$SourceCulture='en-US',$TargetCulture='en-AU') {
    if ([string]::IsNullOrEmpty($DateTime)) { return }

    $sourceDate = [DateTime]::Now
    $success = [DateTime]::TryParse($DateTime,[System.Globalization.CultureInfo]::new($SourceCulture),0,[ref]$sourceDate)

    if ($success) {
        $sourceDate.ToString([System.Globalization.CultureInfo]::new($TargetCulture)) | Get-Date
    } else {
        "Parse Error: $DateTime"
    }
}
