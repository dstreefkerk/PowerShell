#Requires -Version 5.1

<#
.SYNOPSIS
    Parses Microsoft Stream transcript JSON files and outputs structured data.

.DESCRIPTION
    Invoke-ProcessStreamContentParser reads and parses Microsoft Stream/Teams transcript JSON files,
    extracting transcript entries and events into structured PowerShell objects for further processing.

    The script validates the JSON schema and provides detailed error handling for malformed files.

    OBTAINING TRANSCRIPT JSON:
    When viewing Teams meeting recordings where transcript download is not available, the JSON
    transcript can be obtained using browser developer tools (F12). Navigate to the Network tab,
    filter for 'streamContent', and locate the API call with format=json parameter. The response
    contains the raw transcript JSON that can be saved and processed with this script.

.PARAMETER Path
    Specifies the path to the transcript JSON file to parse. Accepts pipeline input.

.PARAMETER IncludeMetadata
    When specified, includes schema version and transcript type metadata in the output.

.PARAMETER EntriesOnly
    Returns only transcript entries, excluding event data.

.PARAMETER EventsOnly
    Returns only event data, excluding transcript entries.

.EXAMPLE
    Invoke-ProcessStreamContentParser -Path "C:\Transcripts\meeting.json"

    Parses the transcript file and outputs each entry and event as individual objects to the pipeline.

.EXAMPLE
    Invoke-ProcessStreamContentParser -Path "transcript.json" | Format-Table SpeakerDisplayName, StartOffset, Text -Wrap

    Displays the transcript in a formatted table with speaker names, timestamps, and text.

.EXAMPLE
    Get-ChildItem "C:\Transcripts\*.json" | Invoke-ProcessStreamContentParser -EntriesOnly

    Processes multiple transcript files and returns only the transcript entries.

.EXAMPLE
    Invoke-ProcessStreamContentParser -Path "transcript.json" -EventsOnly | Where-Object EventType -eq 'CallStarted'

    Filters events to show only when calls started.

.EXAMPLE
    Invoke-ProcessStreamContentParser -Path "transcript.json" | Out-GridView

    Displays the transcript in an interactive, searchable grid view window.

.EXAMPLE
    Invoke-ProcessStreamContentParser -Path "transcript.json" | Export-Csv -NoTypeInformation "C:\temp\transcript.csv"

    Exports the transcript entries to a CSV file for analysis in Excel or other tools.

.OUTPUTS
    StreamTranscript.Entry
    Returns transcript entry objects with properties:
    - SpeakerDisplayName: Name of the speaker
    - StartOffset: Timestamp when speech started
    - EndOffset: Timestamp when speech ended
    - Text: Transcribed text content
    - Confidence: Speech recognition confidence score
    - Language: Spoken language tag
    - SpeakerId: Unique identifier for the speaker
    - Id: Entry identifier
    - SpeechServiceId: Speech service result identifier
    - HasBeenEdited: Whether the entry was manually edited
    - RoomId: Associated room identifier

    StreamTranscript.Event
    Returns event objects with properties:
    - EventType: Type of event (CallStarted, TranscriptStarted, etc.)
    - UserDisplayName: Name of the user associated with the event
    - StartOffset: Timestamp when the event occurred
    - UserId: Unique identifier for the user
    - Id: Event identifier

.NOTES
    Version:        1.0.0
    Author:         Daniel Streefkerk
    Creation Date:  20 October 2025

    This script requires PowerShell 5.1 or later.
#>

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(
        Mandatory = $true,
        Position = 0,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Path to the transcript JSON file'
    )]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Leaf)) {
            throw "File not found: $_"
        }
        if ($_ -notmatch '\.json$') {
            throw "File must have .json extension: $_"
        }
        $true
    })]
    [Alias('FilePath', 'FullName')]
    [string]$Path,

    [Parameter(HelpMessage = 'Include schema metadata in output')]
    [switch]$IncludeMetadata,

    [Parameter(
        ParameterSetName = 'EntriesOnly',
        HelpMessage = 'Return only transcript entries'
    )]
    [switch]$EntriesOnly,

    [Parameter(
        ParameterSetName = 'EventsOnly',
        HelpMessage = 'Return only events'
    )]
    [switch]$EventsOnly
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    Write-Verbose "Starting transcript parser with parameter set: $($PSCmdlet.ParameterSetName)"
}

process {
    try {
        # Resolve full path
        $resolvedPath = Resolve-Path -Path $Path -ErrorAction Stop
        Write-Verbose "Processing file: $resolvedPath"

        # Read and parse JSON
        Write-Debug "Reading JSON content from file"
        $jsonContent = Get-Content -Path $resolvedPath -Raw -Encoding UTF8 -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($jsonContent)) {
            Write-Error "File is empty or contains only whitespace: $resolvedPath"
            return
        }

        Write-Debug "Parsing JSON content"
        $transcript = $jsonContent | ConvertFrom-Json -ErrorAction Stop

        # Validate required schema properties
        if (-not $transcript.PSObject.Properties['$schema']) {
            Write-Warning "Missing schema property in file: $resolvedPath"
        }

        if (-not $transcript.version) {
            Write-Warning "Missing version property in file: $resolvedPath"
        }

        # Process and output entries directly
        if ($PSCmdlet.ParameterSetName -eq 'All' -or $PSCmdlet.ParameterSetName -eq 'EntriesOnly') {
            if ($transcript.entries) {
                Write-Verbose "Processing $($transcript.entries.Count) transcript entries from: $resolvedPath"

                foreach ($entry in $transcript.entries) {
                    $outputEntry = [PSCustomObject]@{
                        PSTypeName          = 'StreamTranscript.Entry'
                        SpeakerDisplayName  = if ($entry.PSObject.Properties['speakerDisplayName']) { $entry.speakerDisplayName } else { $null }
                        StartOffset         = if ($entry.PSObject.Properties['startOffset']) { $entry.startOffset } else { $null }
                        EndOffset           = if ($entry.PSObject.Properties['endOffset']) { $entry.endOffset } else { $null }
                        Text                = if ($entry.PSObject.Properties['text']) { $entry.text } else { $null }
                        Confidence          = if ($entry.PSObject.Properties['confidence']) { $entry.confidence } else { $null }
                        Language            = if ($entry.PSObject.Properties['spokenLanguageTag']) { $entry.spokenLanguageTag } else { $null }
                        SpeakerId           = if ($entry.PSObject.Properties['speakerId']) { $entry.speakerId } else { $null }
                        Id                  = if ($entry.PSObject.Properties['id']) { $entry.id } else { $null }
                        SpeechServiceId     = if ($entry.PSObject.Properties['speechServiceResultId']) { $entry.speechServiceResultId } else { $null }
                        HasBeenEdited       = if ($entry.PSObject.Properties['hasBeenEdited']) { $entry.hasBeenEdited } else { $null }
                        RoomId              = if ($entry.PSObject.Properties['roomId']) { $entry.roomId } else { $null }
                    }

                    # Add metadata if requested
                    if ($IncludeMetadata) {
                        $outputEntry | Add-Member -NotePropertyName 'SourceFile' -NotePropertyValue $resolvedPath.Path
                        $outputEntry | Add-Member -NotePropertyName 'Schema' -NotePropertyValue $transcript.'$schema'
                        $outputEntry | Add-Member -NotePropertyName 'Version' -NotePropertyValue $transcript.version
                    }

                    Write-Output $outputEntry
                }
            }
            else {
                Write-Verbose "No entries found in transcript"
            }
        }

        # Process and output events directly
        if ($PSCmdlet.ParameterSetName -eq 'All' -or $PSCmdlet.ParameterSetName -eq 'EventsOnly') {
            if ($transcript.events) {
                Write-Verbose "Processing $($transcript.events.Count) events from: $resolvedPath"

                foreach ($event in $transcript.events) {
                    $outputEvent = [PSCustomObject]@{
                        PSTypeName      = 'StreamTranscript.Event'
                        EventType       = if ($event.PSObject.Properties['eventType']) { $event.eventType } else { $null }
                        UserDisplayName = if ($event.PSObject.Properties['userDisplayName']) { $event.userDisplayName } else { $null }
                        StartOffset     = if ($event.PSObject.Properties['startOffset']) { $event.startOffset } else { $null }
                        UserId          = if ($event.PSObject.Properties['userId']) { $event.userId } else { $null }
                        Id              = if ($event.PSObject.Properties['id']) { $event.id } else { $null }
                    }

                    # Add metadata if requested
                    if ($IncludeMetadata) {
                        $outputEvent | Add-Member -NotePropertyName 'SourceFile' -NotePropertyValue $resolvedPath.Path
                    }

                    Write-Output $outputEvent
                }
            }
            else {
                Write-Verbose "No events found in transcript"
            }
        }

        Write-Verbose "Successfully processed transcript from: $resolvedPath"
    }
    catch [System.IO.IOException] {
        Write-Error "I/O error reading file '$Path': $($_.Exception.Message)"
    }
    catch [System.ArgumentException] {
        Write-Error "Invalid JSON format in file '$Path': $($_.Exception.Message)"
    }
    catch {
        Write-Error "Failed to process transcript file '$Path': $($_.Exception.Message)"
    }
}

end {
    Write-Verbose "Transcript parser completed"
}
