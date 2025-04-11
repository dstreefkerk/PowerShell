# Guidelines for Generating WPF-Based GUIs in PowerShell

This document provides structured guidelines for creating robust, user-friendly WPF-based graphical user interfaces for PowerShell scripts. 

## XAML Structure and UI Layout

### Basic Structure
- Define the XAML as a PowerShell here-string for clarity and syntax highlighting
- Use appropriate XML namespaces (Windows Presentation Framework, XAML)
- Set window properties at the top level (Title, Height, Width, StartupLocation)
- Use a consistent and professional background colour (#F0F0F0 is a good neutral choice)

### Layout Best Practices
- Use Grid as the primary layout container with defined RowDefinitions and ColumnDefinitions
- Apply Border elements to visually frame content areas and create visual hierarchy
- Maintain consistent margins (8-10px) and padding (5-10px) throughout the interface
- Create proportional layouts with "*" for flexible space and "Auto" for content-sized rows/columns
- Group related controls using nested Grid or StackPanel containers
- Avoid fixed control sizes - use MinWidth, MaxWidth, and other adaptive sizing techniques instead
- Use UniformGrid where consistent sizing and alignment of sibling controls is required (e.g., action buttons)

### Control Naming Conventions
- Use a consistent naming convention with prefixes indicating control type (txt, btn, chk)
- Ensure every interactive control has a unique Name attribute for PowerShell reference
- Include descriptive suffixes that indicate the control's purpose (txtOutputFilename)
- Avoid unnecessarily long names while maintaining clarity

### Advanced Layout Components
- Consider tabbed interfaces for complex applications with multiple functional areas:
  ```powershell
  <TabControl Grid.Row="1" Margin="10">
      <TabItem Header="General">
          <!-- General settings content -->
      </TabItem>
      <TabItem Header="Advanced">
          <!-- Advanced settings content -->
      </TabItem>
  </TabControl>
  ```
- Enable or disable tabs based on user input or application state to control workflow

## PowerShell Integration with WPF

### Loading XAML
- Use `System.Xml.XmlNodeReader` with `Windows.Markup.XamlReader::Load` to parse XAML
- Wrap parsing in `try/catch`. On error, provide a meaningful message
- Explicitly validate XAML string before loading to catch malformed or incomplete XML:
  ```powershell
  # Quick validation check before attempting to load XAML
  if (-not ($xamlString -match '<Window[\s\S]*</Window>')) {
      Write-Error "XAML appears to be malformed or incomplete."
      exit
  }
  ```

### Accessing UI Elements
- Create variables for UI elements using the FindName method on the window object
- Store references to frequently accessed elements in script-level variables
- Group related element references together for clarity
- Verify element references are valid before attempting to manipulate them
- Wrap UI logic in a Show-MainWindow or similar function to avoid polluting the global scope

### Managing Window Lifecycle
- Set appropriate WindowStartupLocation (CenterScreen is generally preferred)
- Use ShowDialog() for modal windows and Show() for non-modal windows
- Implement proper cleanup in window closing events
- Save user preferences before closing the window

## Event Handling and User Interaction

### Event Registration
- Register event handlers after UI elements are defined and referenced
- Use Add_EventName or add_EventName syntax for attaching PowerShell event handlers (both are valid)
- Group related event handlers together in the code
- Consider performance implications for high-frequency events (like TextChanged)
- Access sender and event arguments within handlers for more flexible implementation:
  ```powershell
  $btnSubmit.Add_Click({
      param($sender, $e)
      # $sender is the button that was clicked
      # $e contains event-specific data
      Write-Host "Button '$($sender.Name)' was clicked"
  })
  ```
- Debounce high-frequency events like TextChanged using timers or logic checks to prevent excessive processing

### Common Events to Handle
- Essential events to implement:
  - Add_Click for buttons
  - Add_TextChanged for input validation and dynamic UI updates
  - Add_Closing for cleanup operations
  - Add_Loaded for initialization when a control is fully loaded
- Recommended where relevant:
  - Add_GotFocus and Add_LostFocus for field-level interactions
  - Add_SelectionChanged for dropdowns and list controls

### Handling User Input
- Use appropriate dialog boxes (SaveFileDialog, OpenFileDialog) for file operations
- Persist last used directories when possible
- Provide sensible defaults based on system information (e.g., desktop location)
- Remember user preferences between sessions
- Handle cancellation gracefully without error messages

## Input Validation and Error Handling

### Field Validation
- Validate input as it's entered using TextChanged events
- Provide immediate visual feedback for invalid input
- Disable submission controls when inputs are invalid
- Implement and centralize complex validation logic into a single function (e.g., Validate-Inputs)
- Display subtle feedback using ToolTip or visual cues instead of disruptive message boxes
- Check permissions before attempting operations that might fail

### Error Handling
- Use structured try/catch blocks for operations that might fail
- Create specific catch blocks for anticipated exceptions
- Provide user-friendly error messages with clear next steps
- Log detailed errors for troubleshooting
- Implement finally blocks to ensure cleanup regardless of success or failure

### External Dependencies
- Check for required dependencies at startup
- Provide clear guidance if dependencies are missing
- Handle version compatibility issues gracefully
- Test for required permissions before performing restricted operations

## User Experience Enhancements

### Placeholder Text
- Implement custom placeholder mechanism for TextBox controls
- Use distinguishable formatting (grey text) for placeholders
- Clear placeholders on focus and restore when appropriate
- Store placeholder text in Tag property for reference

### Dynamic UI
- Update UI state based on current input values and application state
- Enable/disable controls based on related input values
- Scroll text fields to show most relevant content (e.g., end of file paths)
- Provide visual feedback when processing long operations

### Context-Aware Defaults
- Open file dialogs in contextually appropriate locations
- Set default values based on system information
- Remember user preferences between sessions
- Handle special cases like OneDrive redirection

### Informative Feedback
- Provide success confirmations for completed operations
- Include specific details in error messages
- Suggest next steps when errors occur
- Verify operations completed successfully even when no exceptions occurred

## Code Organization and Maintainability

### Function Structure
- Create discrete functions for specific functionality
- Use verb-noun naming convention for functions (e.g., Update-UIState)
- Keep functions focused on a single responsibility
- Use parameters with appropriate types and validation
- Place functions at the beginning of the script, before the UI code for better readability
- Validate parameters explicitly using [Parameter()] declarations where applicable
- Avoid global variables - use script: scope only where justified

### Modular Approach
- For larger applications, consider separating components into modules:
  - UI definition in one file
  - Event handlers in another
  - Business logic in a separate module
- Use dot-sourcing to incorporate modules into the main script:
  ```powershell
  # Main.ps1
  . .\UI-Definition.ps1
  . .\Business-Logic.ps1
  
  $Window = Get-MainWindow
  # Set up event handlers
  $Window.ShowDialog()
  ```

### Documentation
- Include comment-based help for scripts and functions
- Document parameters, examples, and expected behaviour
- Use region tags for organizing large scripts
- Include version information and dependencies

### Configuration Management
- Store configuration in standard locations (e.g., %APPDATA%)
- Use structured formats like JSON for configuration
- Implement functions for loading and saving configuration
- Handle missing or corrupt configuration gracefully

### Resource Cleanup
- Use try/finally blocks to ensure cleanup
- Close file handles explicitly
- Remove temporary files even when operations fail
- Dispose of COM objects properly using [System.Runtime.InteropServices.Marshal]::ReleaseComObject() and Remove-Variable
- Call .Dispose() on disposable .NET objects when finished:
  ```powershell
  $timer = New-Object System.Windows.Threading.DispatcherTimer
  # Use the timer...
  
  # When done, dispose of it properly
  if ($timer -ne $null) {
      $timer.Stop()
      # For objects that implement IDisposable
      if ($timer -is [System.IDisposable]) {
          $timer.Dispose()
      }
      Remove-Variable -Name timer
  }
  ```

## Asynchronous Operations and Multi-threading

### Background Jobs
- Use Start-Job for long-running operations to prevent UI freezing:
  ```powershell
  $btnProcess.Add_Click({
      # Start a background job
      $job = Start-Job -ScriptBlock {
          param($parameter)
          # Perform long-running operation
          Start-Sleep -Seconds 5
          return "Completed processing $parameter"
      } -ArgumentList $txtInput.Text
      
      # Set up a timer to check job status
      $timer = New-Object System.Windows.Threading.DispatcherTimer
      $timer.Interval = [TimeSpan]::FromSeconds(0.5)
      $timer.Add_Tick({
          if ($job.State -eq "Completed") {
              $result = Receive-Job -Job $job
              $txtResult.Text = $result
              $timer.Stop()
              Remove-Job -Job $job -Force
          }
      })
      $timer.Start()
  })
  ```
- Use a DispatcherTimer to periodically check job status and update the UI
- Always clean up jobs explicitly with Remove-Job -Force
- Consider using BackgroundWorker when UI thread access is required

### Utility Functions for Async Operations
- Encapsulate common async patterns in reusable functions:
  ```powershell
  function Start-JobWithPolling {
      param(
          [ScriptBlock]$ScriptBlock,
          [object[]]$ArgumentList,
          [ScriptBlock]$OnComplete,
          [double]$PollIntervalSeconds = 0.5
      )
      
      $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
      
      $timer = New-Object System.Windows.Threading.DispatcherTimer
      $timer.Interval = [TimeSpan]::FromSeconds($PollIntervalSeconds)
      $timer.Add_Tick({
          if ($job.State -eq "Completed") {
              $result = Receive-Job -Job $job
              & $OnComplete $result
              $timer.Stop()
              Remove-Job -Job $job -Force
          }
      })
      $timer.Start()
      
      return $timer
  }
  
  # Usage example
  $btnProcess.Add_Click({
      Start-JobWithPolling -ScriptBlock {
          param($input)
          # Process data
          return "Result: $input"
      } -ArgumentList $txtInput.Text -OnComplete {
          param($result)
          $txtOutput.Text = $result
      }
  })
  ```

### Thread Safety
- Never update UI elements directly from background threads
- Use synchronized hashtables and the Dispatcher to safely update UI from background threads:
  ```powershell
  # Create a synchronized hashtable to share data between threads
  $syncHash = [hashtable]::Synchronized(@{})
  $syncHash.Window = $Window
  $syncHash.TextBox = $txtOutput

  Start-Job -ScriptBlock {
      # This works correctly
      $syncHash.Window.Dispatcher.Invoke([action]{
          $syncHash.TextBox.Text = "Updated from background thread"
      })
  }
  ```
- Always use the UI thread's Dispatcher to make UI updates from background operations
- Avoid capturing UI controls directly inside jobs - pass only minimal data into jobs and refer back via the dispatcher:
  ```powershell
  # AVOID THIS - capturing UI controls directly in closure
  $txtResult = $Window.FindName("txtResult")
  Start-Job -ScriptBlock {
      # BAD: Direct reference to UI control from background thread
      $txtResult.Text = "Results"  # Will fail or cause thread issues
  }
  
  # BETTER APPROACH - minimize captured state
  Start-Job -ScriptBlock {
      # Process and return only the data
      return "Results"
  } | Register-ObjectEvent -EventName StateChanged -Action {
      # Handle data in UI thread when job completes
      if ($sender.State -eq "Completed") {
          $Window.Dispatcher.Invoke([action]{
              $txtResult.Text = (Receive-Job -Job $sender)
          })
      }
  }
  ```

## Testing and Debugging

### Debugging Techniques
- Use Write-Verbose for diagnostic information, especially within event handlers:
  ```powershell
  $btnSubmit.Add_Click({
      Write-Verbose "Button clicked with current state: $($txtInput.Text)" -Verbose
      # Handle button click
  })
  ```
- Implement logging for complex operations
- Test script as non-administrator to catch permission issues
- Verify operations in various Windows environments (versions, languages)
- Log system information at startup, including $PSVersionTable, OS version, and execution context
- Log performance data for expensive operations using [Diagnostics.Stopwatch]
- Capture detailed error information in catch blocks:
  ```powershell
  try {
      # Operation that might fail
  }
  catch {
      # Capture full error details
      $errorDetails = $_ | Out-String
      Write-Verbose "Error details: $errorDetails"
      
      # Also consider logging the entire $Error variable
      Write-Verbose "Error collection: $($Error[0] | Out-String)"
  }
  ```
- Add support for toggling debug/verbose mode dynamically:
  ```powershell
  $chkDebugMode = $Window.FindName("chkDebugMode")
  $chkDebugMode.Add_Click({
      if ($chkDebugMode.IsChecked) {
          $script:VerbosePreference = 'Continue'
          Write-Verbose "Debug mode enabled"
      } else {
          $script:VerbosePreference = 'SilentlyContinue'
          Write-Verbose "Debug mode disabled" 
      }
  })
  ```

### Common Pitfalls to Avoid
- Hardcoding system paths instead of using environment variables
- Assuming administrative privileges
- Not handling file-in-use scenarios
- Forgetting to dispose COM objects
- Using synchronous operations for long-running tasks
- Updating UI elements directly from background threads (causing cross-thread exceptions)

### Testing Checklist
- Verify all UI elements are accessible via keyboard navigation
- Test with various screen resolutions and DPI settings
- Confirm error handling works as expected
- Validate behaviour with unusual input values
- Test with and without required dependencies
- Test under restricted environments (e.g., non-admin, Constrained Language Mode)
- Test on multiple Windows versions and language packs
