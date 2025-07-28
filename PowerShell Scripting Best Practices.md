This guide outlines essential PowerShell scripting best practices for enterprise environments. Whether you're writing automation scripts, building reusable modules, or developing security tools, following these guidelines will help ensure your PowerShell code is robust, maintainable, and secure.

The practices are organised by topic area and prioritised into Critical, Recommended, and Good to Have categories. Each section includes both patterns to follow and anti-patterns to avoid, helping you write PowerShell that meets enterprise standards.

Feed this to your LLM of choice, to ensure that it generates quality code.

## Script Structure and Style

* **Standard Script Layout:** Begin scripts with a clear header section. Include **comment-based help** (using `<# ... #>` at top) for Synopsis, Description, Parameter definitions, and Examples. This ensures maintainers and tools (like `Get-Help`) can understand usage and purpose. Follow with a `param()` block for inputs, then your code. A typical structure is: **Help → Param → Functions → Main code → Cleanup**. Using this consistent layout makes scripts easier to navigate and maintain (Critical).

* **Script vs Function Structure:** Understand the difference between **script files** (.ps1) and **advanced functions**. Script files execute linearly and cannot use `begin/process/end` blocks at the top level - these blocks only work inside functions that support pipeline input. For script files, structure your code linearly after the param block. For advanced functions (used in modules or defined within scripts), you can use `begin/process/end` blocks to handle pipeline input effectively. **Script file structure:** `#Requires → Help → param() → Functions → Linear execution`. **Advanced function structure:** `function Name { [CmdletBinding()] param() → begin{} → process{} → end{} }`. Mixing these patterns causes parsing errors (Critical).

* **Use `#Requires` and Strict Mode:** Include `#Requires` statements at the top to enforce prerequisites (PowerShell version, required modules, or run as admin) so that the script fails fast if the environment is not suitable. For example, `#Requires -Version 7.0` or `#Requires -Modules ActiveDirectory`. This prevents runtime errors on unsupported systems. Enable strict mode with `Set-StrictMode -Version Latest` at the start of execution (Critical). Strict Mode forces good practices by making undefined variables or out-of-scope references throw errors, similar to "Option Explicit". This helps catch bugs early by disallowing undeclared variables and other unsafe coding practices.

* **Regions and Layout:** Use **#region**/**#endregion** in your script or module to group related code blocks (e.g. parameters, variable setup, function definitions, main logic). This has no effect at runtime but improves readability in editors. Maintain consistent **indentation and whitespace** style across the team. For example, prefer 4 spaces per indent level and avoid trailing spaces. Consistent formatting makes code review and collaboration easier (Recommended). Keep line lengths reasonable (e.g. <120 chars) and use line breaks to avoid horizontal scrolling.

* **Variable Initialisation and Scope:** Initialise variables explicitly rather than assuming defaults, and use proper scoping. Avoid using global scope unless absolutely necessary – prefer local (`$local:`), script (`$script:`), or function-private variables. This **scope hygiene** prevents unexpected side-effects between scripts or interactive sessions. For example, set `$ErrorActionPreference = 'Stop'` (with local scope) at start if you want all errors to be terminating by default. Clear or reset critical variables in cleanup sections to free resources or prepare for re-use (Good to Have).

* **Source Control Integration:** Organise scripts in source control with logical naming and structure. Use **descriptive file names** (e.g. `Backup-UserHomeDirs.ps1` instead of `script1.ps1`) that reflect their purpose. Group related scripts into folders or PowerShell modules for easier versioning. Include metadata like version, author, last modified date either in a `.NOTES` section of comment-based help or in a module manifest. This helps track changes and ensure the right script versions are deployed (Good to Have).

**Anti-Patterns to Avoid:** 

- Writing one monolithic script without structure or help (hard to reuse or debug), using inconsistent naming/indentation (reduces readability), or relying on implicit behaviour (like uninitialised variables) instead of explicit `Set-StrictMode` and clear code (these can lead to subtle bugs). 
- Also avoid leaving behind state (e.g. not cleaning up temporary files or credentials) – always include a cleanup step if needed.

## Cmdlet and Function Design

* **Use Advanced Functions (`[CmdletBinding()]`):** Always turn your script functions into *advanced functions* by adding `[CmdletBinding()]` at the top. This implicitly gives your function cmdlet-like behaviour (common parameters such as `-Verbose`, `-ErrorAction`, etc.). It also allows using `$PSCmdlet` inside for more advanced features. This is critical for enterprise scripts – it standardises how your functions behave in pipelines and automation (Critical).

* **Approved Verb-Noun Naming:** Name functions and scripts using the PowerShell **Verb-Noun** convention with approved verbs and singular nouns. Use `Get-Verb` to see allowed verbs – e.g. "Get", "Set", "New", "Remove", etc. – and avoid unapproved verbs to prevent warnings. For example, prefer `Get-UserReport` instead of `GenerateUserReport`. Singular nouns (e.g. *User* not *Users*) are recommended even if multiple items are returned. Good naming improves discoverability and consistency (Critical).

* **SupportsShouldProcess (WhatIf/Confirm):** If your script or function makes changes (files, AD objects, systems), implement `ShouldProcess`. Mark the function with `[CmdletBinding(SupportsShouldProcess=$true)]` and use `if ($PSCmdlet.ShouldProcess(<target>, <action>)) { ... }` around the destructive action. This enables `-WhatIf` (simulate actions without executing) and `-Confirm` support, which is crucial for safe operation in production. For high-impact actions, set `ConfirmImpact='High'` so that PowerShell will prompt by default (Recommended). **Rationale:** In enterprise automation, being able to preview or confirm changes prevents mistakes and aligns with user expectations.

* **Output Objects, Not Text:** Functions should **output rich objects** (e.g. PSCustomObject or strongly-typed objects) rather than formatted strings or using `Write-Host` for results. This allows downstream automation to parse and reuse your output (through the pipeline or by converting to JSON, CSV, etc.). Use `Write-Output` (or simply output an object) to emit data. **Avoid** using `Write-Host` unless purely for interactive messages (Write-Host writes only to the console host, not the output stream). This is a common bad practice to avoid – in non-interactive scenarios, `Write-Host` output can't be captured or piped, making your script less useful in automation (Critical). Instead, use `Write-Verbose` or `Write-Information` for informational console messages that aren't part of data output.

* **Designing Output Objects:** Ensure objects your script returns have a consistent structure (same properties for each item) and meaningful property names. Consider using custom classes or `[PSCustomObject]` with `Add-Member` / hashtables for complex data, so properties are easily accessible. For example, return an object with properties like `UserName`, `LastLogin`, `Status` instead of a raw string. You can declare `[OutputType()]` attribute to document output types for users and tooling (Good to Have). If you create custom object types, you can also provide a formatting file (`.format.ps1xml`) in modules to define default views, rather than formatting in the script.

* **Parameter Splatting for Readability:** When calling cmdlets with many parameters or when passing along parameters, use **splatting** (i.e. store parameters in a hashtable and use `@params`) to keep code tidy. For example:
  
  ```powershell
  $params = @{ Path = $FilePath; Recurse = $true; Filter = '*.log' }
  Get-ChildItem @params
  ```
  
  This avoids very long command lines and makes maintenance easier (Recommended). It also simplifies forwarding parameters from one function to another.

* **Consistent Usage of Objects:** Wherever possible, follow common cmdlet patterns. For instance, if your function has to output different object types based on a parameter, consider splitting into separate functions or use parameter sets (with distinct OutputType) to keep output predictable. Also, avoid mixing multiple object types in one output stream, as that can confuse formatting and consumers. If truly necessary (e.g. an internal helper returns two related types), document it clearly or output them as a single combined object.

**Anti-Patterns:** 

- Avoid using unapproved verbs or abbreviations (e.g. "Do-Something" or "Get-ADInfo" where verb or noun is not clear) – it's confusing and may trigger warnings. 
- Don't hardcode output to text with format commands or string concatenation – this reduces reusability. 
- Never use `Write-Host` to produce output data (only for user prompts or progress). 
- Not implementing `-WhatIf` on a destructive function is a missed safeguard; it's better to include it (the PSScriptAnalyzer rule **UseShouldProcessForStateChangingFunctions** flags this). 
- Also, avoid making functions that both perform an action and also prompt for input within – separate the data retrieval from action so they can be automated without interactive prompts (e.g. provide parameters for all inputs).

## Parameter Handling

* **Use Advanced Parameter Attributes:** Define parameters with proper attributes for validation and clarity. Key examples: **`[ValidateNotNullOrEmpty]`** to ensure a required string isn't empty, **`[ValidateSet('A','B',...)]`** to restrict input to allowed values, **`[ValidateRange(min,max)]`** for numeric bounds, and **`[ValidateScript({ ... })]`** for custom logic. Using these attributes shifts validation to PowerShell (it throws errors before running your code if inputs are invalid), which is more robust than manual checks (Critical). For instance, instead of coding `if($value -notin @('A','B')){ throw "Invalid" }`, just do `[ValidateSet('A','B')]` on the parameter – it's clearer and less error-prone.

* **Mandatory and Default Values:** Mark important parameters as **Mandatory** in the param block `[Parameter(Mandatory=$true)]` rather than prompting inside the script. PowerShell will handle prompting for missing mandatory params when the script is run interactively, and it makes it obvious to others which inputs are required. Provide sensible default values for optional parameters when appropriate (but avoid defaulting to something that could be dangerous – e.g. a `-Path` defaulting to `C:\` might be risky). Use **Parameter sets** when you have multiple exclusive sets of parameters. Each parameter set should have a unique combination of mandatory params, and use `DefaultParameterSetName` in `[CmdletBinding()]` to specify which set to use if PowerShell can't tell from arguments. This improves UX and prevents mutually exclusive parameters from being used together.

* **Secure Credentials and Secrets:** For any secret or credential input, avoid plain strings. Use the `[PSCredential]` type for accounts (so the user can pass output of `Get-Credential`), or `[SecureString]` if only a password is needed. This ensures passwords are handled securely in memory and not exposed in command history or logs. **Never** hard-code credentials or accept raw passwords via parameters named "Password" (PSScriptAnalyzer flags this as a risk). In PowerShell 7+, consider using SecretManagement module/vaults for retrieval of secrets by name, rather than passing sensitive data in plain text (Recommended). For example, use a param like `[string]$ApiKeySecretName` and retrieve the actual secret with `Get-Secret` inside the script, or allow a `PSCredential` for authentication.

* **Dynamic Parameters (Use Caution):** Dynamic parameters (defined in a `DynamicParam` block) can adapt to context, but they add complexity and can confuse users (as they don't show in standard help until runtime). Use them sparingly and only for advanced scenarios (Good to Have). If used, ensure you also provide proper help metadata. In many cases, it's clearer to just validate within the script or use simpler approaches. **Trade-off:** While dynamic parameters can provide context-sensitive choices (e.g. available Azure regions dynamically), they make testing and maintenance harder. Many community scripts avoid them, whereas some Microsoft modules use them heavily – weigh necessity versus complexity.

* **Help Messages and Aliases:** Use the `HelpMessage` attribute to provide a brief tip for parameters (this appears when PowerShell prompts for mandatory param in CLI). For example: `[Parameter(Mandatory)][string]$UserName = $(throw "Username is required")` or using `HelpMessage` to hint acceptable input. You can also define **aliases** for parameters using the `[Alias('ShortName')]` attribute to accept alternate names, especially if integrating with existing scripts or to offer a shorter name. But avoid overusing aliases – the primary name should be clear and preferred in documentation.

* **Parameter Sets for Clarity:** Use parameter sets to make the script interface intuitive. For example, a script might have `-FilePath` and `-Directory` as two ways to specify input; you can separate these into two parameter sets so only one is required at a time. Always set a `DefaultParameterSetName` in CmdletBinding when using sets to avoid ambiguity. This prevents confusion and runtime errors about parameter combinations (Recommended).

* **Treat Parameters as Read-Only:** Once inside the script, avoid reusing parameter variable names for other purposes and do not modify them. If you need to transform input, assign to a new local variable. This protects the original input and makes the code easier to follow. For example, if you have `$Path` parameter, don't later assign `$Path = Join-Path $Path 'subdir'`; instead use a new variable `$ResolvedPath`. This is more of a coding style, but helps maintain clarity (Good to Have).

**Anti-Patterns:** Avoid manual prompting like `Read-Host` to get input mid-script – instead design all needed input as parameters so the script can run unattended (except perhaps in very interactive scripts). Do not accept insecure input types for sensitive data (e.g. `[string]$Password`) – always prefer secure types. Do not leave parameters undocumented (every parameter in a public script should have a `.PARAMETER` description in comment-based help). Also, **do not ignore parameter validation** – catching bad input early saves a lot of trouble (e.g., letting a function proceed with a `$null` parameter that later causes a cryptic error is poor practice when ValidateNotNull could have caught it).

## Error Handling and Resilience

* **Use Try/Catch/Finally for Robustness:** Enclose risky operations in `try { ... } catch { ... }` blocks to gracefully handle exceptions (Critical). A **try/catch** ensures that if something fails (e.g. an AD lookup, file operation), you can log the error or take corrective action instead of the script crashing. Use `finally { ... }` for any cleanup that must run regardless of success or error (e.g. closing a file handle, reverting settings). This pattern is essential for long-running automation where transient errors are expected. For example:
  
  ```powershell
  try {
      Invoke-RESTMethod -Uri $api -ErrorAction Stop 
  } catch {
      Write-Error "API call failed: $_"
      return  # or handle accordingly
  } finally {
      Stop-Transcript
  }
  ```
  
  Always include `-ErrorAction Stop` when calling cmdlets inside try blocks to convert non-terminating errors into terminating exceptions that can be caught. This is important because many cmdlets by default only emit non-terminating errors (warnings) which would skip the catch.

* **Distinguish Error Types:** Recognise the difference between **terminating** and **non-terminating** errors. Non-terminating errors (the default for many cmdlets) do **not** stop the script nor trigger catch blocks. That's why setting `-ErrorAction Stop` is needed to treat them as terminating (Recommended). Within catch, you can use multiple `catch [ExceptionType] { ... }` to handle specific exceptions differently (e.g., catch `System.Net.WebException` vs other exceptions). This allows resilience strategies: you might retry on a network timeout exception but not on a parameter binding exception.

* **ErrorActionPreference and Throwing:** It's often useful in script automation to set `$ErrorActionPreference = 'Stop'` at top (or in critical sections) so that any error halts execution. Just remember to reset it if you change it temporarily. For non-cmdlet code (like calling a .NET method), adjusting `$ErrorActionPreference` is how you enforce terminating behaviour. Alternatively, explicitly check results and throw if needed. Inside advanced functions, you can also call `$PSCmdlet.ThrowTerminatingError($errRecord)` to throw a terminating error that cannot be suppressed by `-ErrorAction` (for truly critical failures). Use this for serious issues where continuing could cause corruption or incorrect outcomes – it **always** terminates the function regardless of caller's preferences (Recommended for critical failures). For example, if a parameter validation inside the function fails in a way that shouldn't be caught by the caller, use `ThrowTerminatingError`. Otherwise, a simple `throw "message"` is sufficient for most cases (and can be caught by parent if needed).

* **Use Write-Error for Non-Terminating Issues:** If an error is not fatal to the entire script's operation, you can use `Write-Error` to record it without throwing. `Write-Error` writes to the error stream but doesn't stop execution (unless `$ErrorActionPreference` is Stop). For example, in a loop processing 100 files, if one file is locked, you might do `Write-Error "Could not access $file"` and continue to the next. This logs the issue but continues the pipeline (Good to Have). Make sure to include enough context in the error message. However, avoid blindly continuing after errors unless it's truly non-critical – in many cases, if one step fails, subsequent steps might not make sense.

* **Implement Retry Logic for Transient Failures:** In enterprise scenarios (especially cloud or network operations), temporary glitches happen (e.g., network timeouts, API rate limits). Plan for this by implementing **retry with backoff**. For example, if an API call fails with a 429 (too many requests) or a network error, you might catch it and retry after a delay (increasing the delay each attempt). This can be a loop in the catch:
  
  ```powershell
  for($i=1; $i -le 3; $i++) {
      try {
          Invoke-RESTMethod ... -ErrorAction Stop
          break  # success, exit loop
      } catch {
          Write-Warning "Attempt $i failed: $($_.Exception.Message)"
          Start-Sleep -Seconds (2 * $i)  # exponential backoff
      }
  }
  ```
  
  This pattern improves resilience (Recommended). Use judiciously – don't retry on permanent errors like "access denied." Distinguish **transient** vs. **permanent** errors either by error type or message. Logging warnings for retries is helpful for later analysis.

* **Avoid Silencing or Ignoring Errors:** It's an anti-pattern to use `try {} catch {}` with an empty catch or merely `$null` – this hides exceptions and makes troubleshooting impossible. At minimum, log something in the catch (`Write-Error` or `Write-Warning`) so the failure isn't silent. Similarly, avoid using `$ErrorActionPreference = 'SilentlyContinue'` (or `-ErrorAction SilentlyContinue`) unless you absolutely know what you're doing – suppressed errors can lead to incorrect script results. A better approach is to catch and handle or explicitly decide to ignore specific, known non-critical errors with a comment explaining why.

* **Capture Error Details Immediately:** In a catch block, the error details are available in `$_` (the current error) and also in `$Error[0]`. If you perform additional commands inside catch, note that `$_` might change if those commands error. Best practice is to **save the error** to a variable at the start of catch: e.g. `$err = $_; Write-Error "Failed: $($err.Exception.Message)"`. This preserves the original error record for later use (like including it in a report or rethrowing). It's usually *not* necessary to clear `$Error` manually; PowerShell manages it as a stack.

* **Use Flags/Return Codes Judiciously:** Rather than setting flags like `$success = $false` in catch and checking after, prefer structuring logic so that you do all necessary steps in the `try` and handle failures in one place (the catch). The **ERR-03** guideline suggests avoiding "flag variables" for error handling, and instead wrapping the entire transactional sequence in one try/catch. This makes code more linear and clear. For example, do not do: `try { $ok=$true; Step1 -EA Stop } catch { $ok=$false } if($ok){ Step2; Step3 }`. Instead, do `try { Step1; Step2; Step3; } catch { ... handle ... }`.

**Anti-Patterns:** 

- Relying on `$?` to detect errors – `$?` only tells if the last command considered itself successful, which might be misleading and it carries no error details. It's better to use try/catch or check `$Error[0]`. 
- Avoid catching generic `Exception` and then doing nothing or just writing a general message – you lose the specific error context. 
- Never ignore errors by piping to `Out-Null` or `>$null` without justification; if a command's output is not needed, that's fine, but if you're doing it just to avoid an error, handle the error instead. 
- Finally, don't overuse `Write-Host` for error reporting – use `Write-Error` or `throw` so that errors are properly captured in logs/streams and can be handled by callers.

## Security and Compliance

* **Avoid Unsafe Code Practices:** **Never use** `Invoke-Expression` (or similar techniques) on untrusted or user-provided input. Constructing commands from strings can lead to injection vulnerabilities. For example, building a string `"Get-User $user"` and calling `Invoke-Expression` is dangerous if `$user` contains malicious content. Instead, use parameterised cmdlets or splatting. PSScriptAnalyzer explicitly flags `Invoke-Expression` usage as a warning. If you must execute dynamic code, ensure the content is fully under your control or whitelisted. Also avoid using `Add-Type` or `New-Object` with user input without validation, as they could be leveraged for malicious actions (Critical).

* **Secure Handling of Secrets:** Treat credentials, passwords, API keys with utmost care. **Do not embed plaintext passwords or keys** in scripts (even in comments). Use PowerShell's built-in **PSCredential** (username + SecureString password) for any authentication parameters. If a script needs to use a password, prefer to retrieve it from a secure location: e.g., Windows Credential Manager, Azure Key Vault, or the PowerShell SecretManagement module (which can use SecretStore or other vault backends). For instance, you might store a secret with `Set-Secret -Name MyAPI -Secret $secureString` and retrieve it in script via `Get-Secret -Name MyAPI`. This avoids hardcoding and keeps secrets encrypted at rest (Critical). If using SecureString conversion (e.g. `ConvertTo-SecureString -AsPlainText`), be aware that plaintext may reside briefly in memory – use it only with `-AsPlainText -Force` when absolutely needed, and prefer more secure patterns where possible. PSScriptAnalyzer rules **AvoidUsingPlainTextForPassword** and **UsePSCredentialType** emphasise using secure types and not raw strings.

* **Script Signing and Execution Policy:** In enterprise environments, **script signing** is a recommended practice (Recommended). By signing your PowerShell scripts or modules with a trusted code-signing certificate, you ensure the script's integrity and origin. This works with Execution Policy set to *AllSigned* (requiring all scripts to be signed) or *RemoteSigned* (requiring signature for scripts from UNC/internet). While in practice some organisations use the laxer *RemoteSigned* (where internal scripts don't need signing), having a signing process for production scripts is more secure. It prevents tampering – a user cannot run a script that has been altered since signing (the signature check will fail). The trade-off is operational overhead of managing certificates and signing each update. Nonetheless, given PowerShell's role in system administration, signing is **Critical** for high-security contexts (like incident response tooling or scripts run on many servers).
  
  > **Note that Microsoft doesn't view the Execution Policy as a security boundary, nor should you.** It is easily bypassed. You should be using App Control of some description to restrict which scripts execute in your environment, not something as easily-bypassed as the PowerShell Execution Policy.

* **Least Privilege Principle:** Ensure your scripts run with the minimal privileges required. If a script doesn't need admin rights, avoid running it as admin. Conversely, if it **does** need elevation (e.g. modifying system state), make that explicit – use `#Requires -RunAsAdministrator` at the top so that it will refuse to run if not elevated. This prevents partial execution with insufficient rights (Critical). If a script performs actions on remote systems or sensitive data, consider using a dedicated service account with limited permissions for those tasks, rather than a domain admin account. This way, even if the script or credentials are compromised, the blast radius is limited.

* **Audit Logging:** Incorporate logging of key actions, especially those that change state or access sensitive info. Use `Write-Verbose` for detailed operational logs that can be enabled when needed, and `Write-Information` or custom logging to record critical events (Recommended). For example, if a script creates users or changes ACLs, log an entry with details (who/what was changed). In security automation (blue team scripts, IR tools), logs might be needed as evidence, so include timestamps and unique identifiers. Avoid logging sensitive data (like full passwords or secret material) – sanitise logs to include contextual info but not secrets. You might log to a file (ensure proper access permissions on it), to the Windows Event Log (via `Write-EventLog` for persistent, centralised logs), or to a SIEM/central system if available. Also consider using **Start-Transcript** at the beginning of critical operations to capture all output (the transcript will include all console output, which is useful for review). Be mindful to stop the transcript and secure the file if it contains sensitive outputs.

* **Compliance and Ethics:** Adhere to any organisational policies for data handling in your scripts. For example, if dealing with personal data, ensure your script only collects what is needed and possibly anonymises or encrypts it when storing. In incident response (IR) scripts, ensure actions like forensic data collection are done in a way that doesn't modify the evidence (e.g. copying files in read-only mode, using checksums). Maintain an **audit trail** of what the script did – who ran it and what it did (this can often be achieved by event log entries or naming the transcript file with date/user). Ethically, avoid writing scripts that bypass security controls unless explicitly authorised (and even then, log that you did so). For instance, if your script needs to disable a security tool for troubleshooting, make sure it's documented and requires explicit confirmation, and re-enable it after.

* **PowerShell Constrained Language Mode (CLM):** Be aware of CLM if operating in locked-down environments (like WDAC enforcement). In CLM, some .NET methods, COM objects, and Add-Type are blocked. Best practice is to avoid relying on those in critical scripts or detect CLM via `$ExecutionContext.SessionState.LanguageMode` and warn the user. Prefer using approved cmdlets or .NET classes that are allowed. This ensures your script runs even under constrained settings (Good to Have for highly secure contexts).

**Anti-Patterns:** 

- Hardcoding credentials or other secrets in plain text (one of the worst security sins) – not only can they be extracted from the script, but they might end up in version control or backups. 
- Avoid using outdated or vulnerable protocols in scripts (e.g. forcing TLS 1.0, or using basic auth over HTTP) – instead update to use TLS 1.2/1.3 and secure APIs. 
- Don't disable PowerShell security features for convenience: for example, setting `Set-ExecutionPolicy Unrestricted` or bypassing CLM without approval can expose the enterprise to risk. 
- Another anti-pattern is not validating inputs that are used in sensitive operations (e.g., taking a user input and directly using it in a file path or SQL query) – always validate or sanitise inputs to prevent injection or abuse. 
- Lastly, **do not log sensitive info** like passwords or private keys – logs often go to systems that many can read.

## Module and Dependency Management

* **Leverage Modules for Reusability:** If you have a collection of related functions or scripts, package them into a PowerShell module rather than loose scripts. A **module** (`.psm1` with a manifest `.psd1`) allows you to encapsulate functions, export only the public ones, and define dependencies and metadata. This makes code reuse across the team easier and promotes consistent usage. Place common helper functions in a module so that multiple scripts can import it instead of duplicating code (Recommended). For one-off scripts, modules might not be necessary, but anything that grows or could be reused should be modularised. Microsoft's guidance: "Write functions whenever possible... add them to a script module... call the functions without needing to locate where you saved them". Modules also integrate with the PowerShell Gallery or private repositories for distribution.

* **Specify Required Modules and Versions:** Use `#Requires -Modules ModuleName` at the top of scripts to ensure required modules are loaded (and correct version if needed). This prevents the script from running if a dependency is missing, providing a clear message. In a module manifest (psd1), list required modules and their versions in `RequiredModules`. In scripts, you can also do an explicit `Import-Module ModuleName -MinimumVersion 2.1` and handle the error if not found (perhaps instructing the user how to install it). Pinning versions is important in enterprise to avoid surprises – if a newer module version could break your script, specify the exact version (Critical when dependencies are critical). Balance this with keeping modules up-to-date: track updates and update your scripts accordingly rather than staying indefinitely on old versions.

* **Use Module Manifests:** For any internal module, create a module manifest (with `New-ModuleManifest`). Populate key fields like **Version**, **Author**, **Description**, **CompanyName**, **RequiredModules**, **Files**, etc. This is both documentation and allows tools to parse module info. PSScriptAnalyzer highlights missing important manifest fields (Version, Author, Description, LicenseUri) as a best practice. Even if not publishing outside, it's good to include these for internal clarity. The manifest also allows you to specify which functions to export (via `FunctionsToExport` or using `Export-ModuleMember` inside the psm1) so internal helper functions aren't exposed (Good to Have).

* **Versioning and Naming:** Follow semantic versioning for your modules/scripts if possible (Major.Minor.Patch). Update the version in the script header or module manifest when changes are made, especially breaking changes. Use source control tags or release notes to track these changes. In scripts, you can include a `Version` number in the .NOTES or in a custom comment. This helps when an incident arises – you can quickly identify which version of the script is in use (Recommended).

* **Handle Module Conflicts:** In an enterprise environment with many modules (some possibly with overlapping commands), use fully qualified module import or command names to avoid ambiguity. For example, `Import-Module ActiveDirectory -RequiredVersion 1.0.1` to be sure of the version, and call `ActiveDirectory\Get-ADUser` if there's a naming conflict with another module. You can also use `-Prefix` parameter on Import-Module to give a module's cmdlets a unique prefix, though this changes usage and is often a last resort. Strive to keep your module names unique and do not alias built-in commands with your own. If a conflict occurs (two modules have `Get-User`), you might need to fully qualify or rename your function to avoid confusion.

* **Publishing and Deployment:** For internal modules, set up a private PowerShell repository (e.g. using a file share with `Register-PSRepository` or an artifact repository like Nexus/Artifactory/Azure DevOps). This way, team members can do `Install-Module YourModule -Repository InternalRepo`. This encourages using the latest approved version. If that's not available, at least use a source control (git) to host modules and have a documented process for installation (even if it's "pull from git and copy to PSModulePath"). Ensure that installation of your scripts/modules doesn't require manual hacks – provide instructions or scripts for deployment (Good to Have).

* **Manage Dependencies in Code:** Within scripts or modules, if you rely on an external program or specific files, check for their presence and version. For example, if your script calls an external EXE or a specific .dll, verify it exists and perhaps the version, before proceeding, giving a friendly error if not. This proactive approach is similar to `#Requires` but for non-PS components. It avoids weird runtime failures and makes the script more robust to environment differences.

**Anti-Patterns:** 

- Avoid duplicating code across multiple scripts – this often leads to inconsistencies and harder maintenance. If you find yourself copy-pasting functions, it's a sign to move them to a common module. 
- Don't assume a module is loaded (except for core modules); always explicitly import or use #Requires. 
- Also, don't leave module imports scattered in the middle of script logic – import at the top for clarity (and minimal performance impact) so dependency handling is centralised. 
- Another anti-pattern is failing to specify versions and later a module update breaks your script – mitigate this by testing and locking versions as appropriate. 
- Finally, refrain from using deprecated features like *PSSnapins* (e.g. `Add-PSSnapin`) in new scripts – almost everything is available as modules now, and snap-ins are legacy (if you must use one, document it clearly and expect additional setup on new machines).

## Cross-Version and Platform Compatibility

* **Target the Right PowerShell Versions:** Be explicit about whether your script is meant for Windows PowerShell 5.1, PowerShell 7+, or both. There are significant differences (PS7 is cross-platform, uses .NET Core, new cmdlets, etc.). Use `#Requires -Version 5.1` (for example) if you use features only in that version, or require 7.0 if you rely on PS7-only features. If supporting multiple versions, test on both. Note differences like PS7's *automatic* `$PSStyle` for console text colouring (not in 5.1), new operators (`??`, `|>` pipeline chain operators, etc.), default encoding (PS7 uses UTF-8 without BOM by default for Out-File/Set-Content, whereas 5.1 uses UTF-16LE) – these can affect behaviour. Use `$PSVersionTable.PSVersion` or `$PSVersionTable.Platform` to adjust logic if needed (Good to Have). For example, if your script outputs to a file and it must be in UTF-16 for compatibility with an old system, explicitly set `-Encoding Unicode` in PS7 (which is UTF-8 by default).

* **Cross-Platform Considerations:** If your script is intended to run on Linux/macOS under PowerShell 7, avoid Windows-only features. **Do not use COM objects or WMI (Get-WmiObject)** which are Windows-specific (Get-CimInstance is the cross-platform way to query CIM/WMI, as it works on PS7 with WSMan or DCOM on Windows). Avoid registry access (`Get-Item HKLM:\...`) unless you guard it with `$IsWindows`. Use environment-agnostic methods: e.g., `[System.IO.Path]::Combine()` or `Join-Path` for file paths instead of hardcoding "C:\". Leverage `$Env:HOME` or `$HOME` instead of `C:\Users\Name`. You can check `$IsWindows`, `$IsLinux`, `$IsMacOS` automatic variables to branch OS-specific code. For example, if running on Linux, maybe skip a section that uses ActiveDirectory module. **Test** your script on all intended platforms – don't assume it "should work" because it's PS; line endings, case-sensitive file systems, presence of certain utilities (like `whoami` exists on Windows but on Linux you might call `id`) all differ (Recommended).

* **Conditional Code for Compatibility:** Use conditional logic to handle version or platform differences. Example:
  
  ```powershell
  if ($PSVersionTable.PSVersion -ge [Version]"7.0") {
      # Use new parameter or cmdlet available in PS7
      Some-Command -NewParam ...
  } else {
      # Alternative for Windows PowerShell 5.1
      Some-Command -LegacyParam ...
  }
  ```
  
  Or platform example:
  
  ```powershell
  if ($IsWindows) {
      $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  } else {
      $user = $(whoami)  # use native whoami on Linux
  }
  ```
  
  This ensures the script runs in both environments without error (Good to Have).

* **Use Compatible APIs:** Prefer .NET and PowerShell APIs that are available in Core. For instance, instead of using older .NET classes that might be Windows-only, use newer cross-platform classes or PowerShell cmdlets. Many .NET Framework APIs are present in .NET Core, but some (like certain Microsoft.Office COM interops, etc.) are not. If you need to, use `Import-Module Microsoft.PowerShell.Management` and other modules which exist on all platforms for standard tasks (they often abstract differences). If targeting PS7, you can utilise `ForEach-Object -Parallel` etc., but make sure to either guard them or ensure PS7 usage. Conversely, avoid deprecated stuff like `Write-Host` in scripts as earlier – but note that in PS7, `Write-Host` now writes to the Information stream (still not pipeline output, but can be captured via redirection), a subtle difference from 5.1. These kinds of changes are minor but could impact how output is captured.

* **Console and Logging Differences:** When running scripts on Linux, the concept of event logs doesn't apply the same way. If your script logs to Windows Event Log via `Write-EventLog`, that won't work on Linux. Instead, consider logging to a file or syslog (perhaps via `logger` command). Similarly, `Start-Transcript` works on PowerShell 7 in a cross-platform way (it will create a text file transcript), but verify the behaviour. If your script uses GUI elements (WinForms/WPF) or Out-GridView, those won't function on non-Windows or headless environments. Document such requirements or have checks (`if ($IsWindows) { use Out-GridView } else { output plain text/table }`). In summary, decide if cross-platform is a goal; if yes, stick to core functionality and test accordingly (Recommended for any automation that might be used in cloud or by diverse teams).

* **Module Availability:** Be aware that some Microsoft modules are only for Windows PowerShell (e.g., AzureAD module is 5.1 only, whereas Az module works on 7+). If your script must use AzureAD (no PS7 version as of now), then it won't run on PS7 – you might mention that in documentation or automatically fall back to using the MS Graph API via REST as an alternative. Likewise, older Exchange, SharePoint modules may not run on Core. The **trade-off** for compatibility might be using platform-neutral REST APIs or PowerShell 7 compatible modules where possible. This is more work upfront but pays off in flexibility.

**Anti-Patterns:** 

- Writing scripts that unknowingly assume Windows – e.g. using backslashes in paths, or `ipconfig` command – and then finding they fail in a Linux PowerShell container. 
- Always examine whether each external call or method is portable. Don't use `$PSScriptRoot` for something and assume path separator; use `Join-Path $PSScriptRoot 'subfolder'`. 
- Another anti-pattern is ignoring encoding issues: if your script produces a file that will be consumed by Windows and Linux, ensure the encoding is acceptable in both (UTF-8 is a good universal choice). 
- Avoid using features from a newer PS version without guarding for older ones if you claim to support them – e.g., using the `Ternary operator ?:` introduced in PS7 will cause syntax errors in PS5. If backward compatibility is needed, either refrain or handle via separate script versions.

## Maintainability and Readability

* **Clear, Self-Documenting Code:** Prioritise code readability – **use meaningful names** for variables and functions (e.g., `$processList` instead of `$x`), and follow a naming convention (PascalCase for function names and parameters, camelCase or PascalCase for internal variables as long as it's consistent). Write short, focused functions – if a script exceeds a few hundred lines, consider splitting it into functions or modules for clarity. **Comment wisely:** Explain *why* something is done if it's not obvious, rather than what the code plainly does. For example, a comment like `# Convert to UTC to match DB timezone` is helpful, whereas `# loop through servers` above a `foreach($server in $servers)` is redundant. Use comment-based help for public functions (so usage is documented). A well-documented script with clear code is easier for others (or future you) to maintain (Critical).

* **Use PSScriptAnalyzer and Linting:** Incorporate [**PSScriptAnalyzer**](https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview?view=ps-modules) into your development workflow. This tool checks your script against a set of best practice rules (style, performance, etc.). Many IDEs (VS Code with the PowerShell extension) will run PSScriptAnalyzer in the background and highlight issues as you code. You can also customise the rules by using a settings file to enforce your team's style. For enterprise, it's wise to adopt an agreed-upon ruleset (maybe start with PSScriptAnalyzer's default, then adjust). Key rules include flagging unused variables, use of aliases, missing help, use of deprecated cmdlets, etc.. For example, it will warn if you used an alias like `gwmi` instead of `Get-WmiObject`, or if you used `Write-Host` in a script (which is discouraged). Treat these warnings as hints to improve. Making your code pass a static analysis not only catches potential bugs but also keeps style consistent (Recommended). Integrating this into CI (Continuous Integration) is even better – e.g. fail a build if the script doesn't meet certain criteria (like no Severity "Error" rules triggered).

* **Consistent Style and Formatting:** Establish a coding style guide and stick to it. This includes indentation (typically 4 spaces, no tabs), bracket placement, pipeline placement (many style guides put `|` at the start of the next line when line-breaking pipelines), capitalisation (cmdlets and parameters can be written in any case, but consistency improves readability; e.g. always capitalise cmdlet names as they appear). The community "PowerShell Practice and Style" guide recommends K\&R style bracing and PascalCase for names, for example. Choose a convention for where to place curly braces (PowerShell generally puts the opening brace on the same line as the function/if/etc.). Ensure blank lines are used to separate logical sections of code, but avoid excessive blank lines. Remove any trailing whitespace. These might sound trivial, but a clean and uniform code style reduces cognitive load when reading scripts (Recommended).

* **Scripting vs. Toolmaking Mindset:** Write scripts as if you're writing a tool for someone else – because in enterprises, often others will run or maintain your script. That means handle edge cases, produce clear error messages, and avoid interactive prompts unless absolutely necessary. Provide examples in your help so others know how to use it. Also, **avoid using aliases and positional parameters** in the script itself (use full cmdlet/parameter names). Aliases are fine for one-time CLI usage, but in scripts they hurt clarity (PSScriptAnalyzer's *AvoidUsingCmdletAliases* rule will catch many). For instance, use `Where-Object` not `%`, `ForEach-Object` not `%{}`, `Select-Object` not `select`, etc., and always use `-ParameterName value` instead of relying on positional order (Recommended). This makes the script self-explanatory.

* **Logging and Verbose Output:** Adopt a standard way of logging what your script is doing. We discussed using `Write-Verbose` for routine status messages – ensure to use it at key points (start/end of major functions, before/after significant actions). This way, running the script with `-Verbose` gives a play-by-play without you writing custom logging code. Use `Write-Debug` for even more granular internal state info useful during development or troubleshooting (like intermediate values). Marking such output with debug vs verbose levels allows you to leave them in the code without spamming normal output. For persistent logging, consider adding an optional `-LogPath` parameter to your script: if provided, the script could write verbose messages to that log file (or you can simply instruct users to start a transcript). Consistency in logging format (e.g., always prefix log lines with a timestamp or with the function name) will help in parsing logs later (Good to Have).

* **Splitting Code into Functions:** Even within a single script file, it's often beneficial to define helper functions for repetitive tasks or logically separate operations. For example, if your script does A, B, C in sequence, consider making `function Do-A { ... }`, `function Do-B { ... }`, etc., and then in the main body call those functions. This avoids long, deeply nested script code and improves readability by giving descriptive names to sections of logic. It also naturally makes your code testable (each function can be tested individually) and potentially reusable. Just ensure those helper functions are defined before they are used (in script files, define all functions at top or in a dedicated region). This approach is endorsed by the idea of writing "toolmaking" style functions even if they are only used in this script – it's cleaner and if needed, easy to export to a module later (Recommended).

* **String Formatting and Interpolation:** Use PowerShell's native string formatting capabilities properly to avoid parsing errors and improve readability (Critical). **Preferred approaches:**
  
  - **Subexpression syntax:** `"Processing $($user.Name) at $(Get-Date)"` for complex expressions
  - **Format operator:** `"Found {0} items in {1} seconds" -f $count, $elapsed` for structured formatting
  - **Simple variable expansion:** `"Hello $Name"` for basic variable insertion
  
  **Avoid string concatenation** with the `+` operator in PowerShell as it's not idiomatic and can be error-prone: `$message = "User " + $name + " processed"` should be `$message = "User $name processed"`. Be particularly careful with string interpolation in verbose messages - expressions like `"Response time ($($stopwatch.ElapsedMilliseconds)ms)"` can cause parsing issues because PowerShell may interpret the closing `)ms` as a method call. Use spaces or format operators instead: `"Response time ($($stopwatch.ElapsedMilliseconds) ms)"` or `"Response time ({0}ms)" -f $stopwatch.ElapsedMilliseconds`. The format operator is especially useful when the same template is reused multiple times or when precision is needed (like formatting numbers or dates).

* **Transcripts and Debugging Aids:** In a production scenario, you might not run with `-Verbose` normally. But having a **transcript** (Start-Transcript) can capture what happened if things go wrong. For maintainability, you could build in a debug mode to your script (e.g., a `-DebugMode` switch that maybe sets `$DebugPreference='Continue'` to break on Write-Debug, or triggers more detailed logging). This way, when a user reports "the script didn't work", you can ask them to run in debug/verbose mode or send the transcript. It's much easier to troubleshoot with that information. Additionally, ensure your script returns proper exit codes if used in scheduled tasks or CI pipelines (e.g., if a critical error happens, you might end with `exit 1` so the calling system knows it failed). Without this, a failed script might still appear successful to automation orchestrators.

**Anti-Patterns:** 

- Massive scripts with no modularisation, no comments, and cryptic variable names – they become "write-only" (only the author can understand them, and even that for a short time). 
- Not documenting parameters and expected input/output makes a script much less useful for others. 
- **Using string concatenation with `+` operator** instead of PowerShell's native string interpolation – this is not idiomatic and can be error-prone.
- **String interpolation parsing errors** from expressions like `"Time: ($($var)ms)"` where PowerShell misinterprets the closing parenthesis – always use spaces or format operators.
- **Using begin/process/end blocks in script files** instead of functions – these blocks only work inside functions, not at the script file top level.
- Letting stylistic inconsistencies creep in (like half the file using 4 spaces, another part using 2 or tabs, random capitalisation) – it signals lack of attention to detail, and in worst cases can even cause errors (e.g. misaligned backticks or indentation might hide a continuation).
- Another anti-pattern is leaving old or dead code commented out in the script indefinitely – use source control for history, and remove unused code to avoid confusion. 
- Also, avoid writing interactive prompts (`Read-Host`) for things like passwords or confirmations in scripts that are meant for automation – these block non-interactive use; instead use parameters and `ShouldProcess` for confirmations. 
- **Saving files with UTF-8 BOM** which can cause parsing errors in PowerShell – always save as UTF-8 without BOM.
- Lastly, ignoring PSScriptAnalyzer warnings without good reason can lead to technical debt – if a rule isn't applicable, consider disabling that rule via comment for that instance (with explanation) or in your settings, but don't just ignore all output of analysis.

## Output and Interoperability

* **Emit Structured Data, Not Formatted Text:** Design your scripts to output **objects** or structured data, rather than human-formatted text, to maximise interoperability (Critical). For instance, if your script gathers user data, output a list of objects with properties like Name, Department, LastLogin, rather than spacing them in columns with `Format-Table` inside the script. Leave formatting to the end user (they can pipe to `Format-Table` or `Out-File` as needed). This way, the output can be consumed by other scripts or converted easily to JSON/XML/CSV. The principle is: **separate data generation from presentation**. The only time you'd format inside is when writing a tool explicitly for display (e.g. a script whose sole purpose is to show a UI or report). Even then, consider offering a `-Raw` or `-AsObject` switch to output raw data. Remember that any use of `Format-*` cmdlets or `Out-Host` in the middle of a pipeline will stop the pipeline from carrying objects forward, so avoid those in library-type scripts.

* **Ensure Output Is Serialisable:** In enterprise scenarios, it's common to pass data between systems (maybe your PowerShell outputs JSON to send to a web service, etc.). Test that the objects you output can cleanly convert to JSON or CSV if needed. Some objects (especially highly complex .NET objects or objects with methods) may not serialise well. If you have such data, transform it to a simpler hashtable or PSCustomObject with just the necessary properties before output. For example, a `[System.IO.FileInfo]` object has many properties including methods and might not fully convert to JSON as expected. If you only need Name, Length, LastWriteTime, select those into a new PSCustomObject. This keeps your output lean and portable (Recommended). Also be mindful of **circular references** (objects referencing each other) as they break serialisation – typically not an issue with basic objects.

* **Avoid Mixing Different Output Types:** As mentioned earlier, don't output heterogeneous object types from the same function unless absolutely necessary. If one element is a string (e.g. an error message) and others are objects, the pipeline will end up outputting them as separate things which can confuse formatting (PowerShell might switch to list format when types differ). Instead, if you need to convey an error or special status among data, consider using the error stream (Write-Error) or include a property in the object (e.g. a Status property). The PSSA guidance is to output only one kind of object per command. This leads to predictability. **Exception:** Internal helper functions can return multiple types if used internally (e.g., a function returns two objects which the caller assigns to two different variables in one call), but external commands should present a clean output type.

* **Provide Output Options if Needed:** If your script's output might be consumed by non-PowerShell systems, consider offering an option to output in standardised formats. For example, a `-AsJson` switch that does `ConvertTo-Json` on the output object, or a `-OutCsv <path>` parameter that directly writes CSV. This is not always necessary (since the user can pipe to these cmdlets), but in some enterprise contexts, providing a direct parameter makes integration easier (Good to Have). If implementing, ensure these switches don't break standard usage (use parameter sets, e.g. `ParameterSetName="JSON"` for `-AsJson` that conflicts with sending objects down pipeline).

* **Handling Large Outputs:** For scripts that may deal with thousands of objects or lines of output, be mindful of memory and responsiveness. **Stream output** when possible (process items one by one and output incrementally). For example, if querying a large database, output each record object as you fetch it rather than accumulating in a huge array and outputting at end. This allows the pipeline to start consuming results earlier and uses constant memory. It also means if the pipeline is being further processed or exported, it can do so in a streaming fashion. Use the `process{}` block in advanced functions to naturally emit one object at a time for pipeline input scenarios. If you must collect all data (e.g., to compute a summary), document that behaviour and ensure the script can handle the scale (maybe test with sample large input). For extremely large data, consider implementing paging or prompting the user if they really want to output 10 million records (perhaps that should be written to file instead of console).

* **Default Display Considerations:** When you output custom objects, PowerShell will try to display them in a table or list based on their properties (up to a certain width). If the default display is messy or shows too much/little, you can control this via a format.ps1xml file in a module or by adjusting the `PSCustomObject` type name and using `Update-TypeData`. This is advanced, but for enterprise tools it can be nice to have a clean default view. For instance, if your object has 10 properties but only 3 are important, you might create a format xml to show only those 3 by default. However, **do not embed formatting** in the script itself (like calling `Format-Table` internally), as that prevents downstream processing. Provide formatting definitions externally or instruct users to pipe to formatting as needed. This approach follows the PowerShell paradigm (separating data from presentation).

* **Interoperability with other tools:** Sometimes your script might need to call external utilities or accept input from other systems (like a JSON file from another app). Use standard data formats for interchange: PowerShell's `ConvertFrom-Json` and `ConvertTo-Json` are handy for reading/writing JSON, and `Import-CSV`/`Export-CSV` for CSV data. If writing to a file that will be read by something else, make sure to use appropriate encoding and include a header if needed (for CSV). If your script produces output meant for, say, a monitoring system that expects a certain text format, provide a distinct mode or a separate helper that formats specifically for that system, rather than complicating the primary output path. Essentially, keep the core output clean and then adapt/format for external targets as an optional step.

**Anti-Patterns:** 

- Using `Write-Host` or `Write-Output` to emit coloured or formatted text like an ASCII table – this output cannot be parsed or reused by other scripts. It might look nice for a report, but it's not automation-friendly. If pretty reports are needed, separate that concern: produce data, then in a different context, format it (e.g., perhaps generate an HTML report using `ConvertTo-Html` or use PSWriteHTML module). 
- Another anti-pattern is writing verbose messages to the output stream inadvertently – e.g. forgetting to use `Write-Verbose` and instead using `Write-Output` for status messages will pollute the data output. Make sure any non-data messages go to the appropriate stream (Warning, Verbose, Debug, etc.) so as not to confuse consumers. Also, be cautious with `Out-File` or `Set-Content` inside your script – if the purpose is to provide output to the pipeline, you usually don't want to redirect it to a file internally (unless explicitly requested via a parameter). Let the user decide to pipe your output to a file or not.

## Testing and Debugging

* **Embrace Pester for Unit Testing:** [Pester](https://pester.dev/) is the de facto testing framework for PowerShell. Write **unit tests** for your functions, especially those that perform critical logic (Critical). This might involve creating a separate tests file/module where you import your script/module and use `Describe/It` blocks to specify expected behaviour. Test normal cases (given valid inputs, does output match expected), edge cases (empty input, invalid input should throw or handle gracefully), and error cases (simulate an error and see if it's handled). For example, if you have a function `Get-UserData`, a Pester test might call it with a sample input and `Should -Not -Throw` and check that properties are present. This not only gives confidence but also serves as documentation for usage. Pester allows **mocking** of commands, which is crucial for tests – e.g., if your script calls `Send-MailMessage`, you can Mock it in tests so no real email is sent, and instead assert it was called with correct parameters. In an enterprise, having automated tests can catch regressions when you modify scripts or when environment changes occur (Recommended). Incorporate test runs in a CI pipeline if possible.

* **Simulate and Force Error Paths:** It's important to test how your script behaves on failure paths. Use Pester to simulate exceptions (e.g., use `Mock Some-Command { throw "fail" }` to see if your try/catch catches it properly). You can also design your functions with a **fault injection** mechanism for testing; for instance, a hidden parameter like `-SimulateError` that, when set (and perhaps only enabled in a non-prod context), will deliberately trigger an error at a certain point. This is not always needed, but can be useful to verify your error handling logic (Good to Have). At minimum, do manual tests by providing bad input or causing a known error (like pointing to a non-existent server) and observe if your script handles it gracefully (does it throw a meaningful message or just traceback? Ideally the former).

* **Use `$DebugPreference` and Breakpoints:** During development or troubleshooting, leverage PowerShell's debugging tools. Setting `$DebugPreference = "Break"` will cause `Write-Debug` statements to break into the debugger, allowing you to examine variables at that point. You can also use `Set-PSBreakpoint` to break at a certain line or when a variable changes. In VS Code, you can set breakpoints and step through the script visually. Make sure to remove or disable breakpoints in production code. If you include any `Write-Debug` or even `Write-Verbose` with sensitive info, consider wrapping them to only output in dev scenarios (for example, behind a `if($env:ENV -eq 'Dev')` check, or instruct users to only use -Debug in non-production). Another handy trick: use `Start-Transcript` at the beginning of a debug session to capture the sequence of events leading up to an issue.

* **Test in Environments Similar to Production:** It's common that a script works on the developer's machine but fails in production due to subtle differences (different module versions, lack of permissions, etc.). Try to test in an isolated environment or a staging server that mimics production (Recommended). For example, if your script will run as a scheduled task under a service account, test it under that context (use `RunAs` or a scheduled task to simulate). If it will run on PowerShell 5.1 on Windows Server 2016, don't only test on 7.5 on Windows 11. This catches environmental issues early. Use Pester integration tests for this if possible (Pester 5 supports running tests remotely or in PowerShell 5.1 via invoking pester with `-PowerShellVersion` in some setups).

* **Edge Case Testing:** Identify edge cases and ensure the script handles them. For example, if input could be an empty array, does the script handle it (maybe just outputs nothing or a warning instead of throwing)? If an API call returns 500 error, does your retry logic kick in? If a user lacks certain permissions, does the script fail gracefully with a clear message? Consider also testing performance with larger inputs (if script will normally handle 10 items, what if someone accidentally gives it 10,000 items? Does it slow to a crawl or break?). These scenarios can be tested manually or with Pester (though performance tests often manual). Document any known limitations so they are clear to others.

* **Continuous Improvement via Testing:** When a bug is found in your script, write a test that would have caught it, then fix the bug. This way, the test will prevent that bug from reoccurring in the future. Over time, you build a robust test suite. In an enterprise, this is very valuable especially if multiple people collaborate on scripts – tests catch issues early and reduce risk of deploying a faulty script that could cause downtime or bad data.

* **Using Transcripts and Logging in Debug:** As noted in maintainability, enabling transcripts (`Start-Transcript`) can help capture elusive issues that only occur in production (for example, an environment-specific error). If a script is run via automation (like orchestrator or cron), consider building in that it starts a transcript to a known location (with maybe timestamp in name) at start and stops at end. This way, if something goes wrong, you have a full log of all output and errors. Just be careful with sensitive info (transcript captures everything including secrets in output). Alternatively, implement your own logging inside the script to capture key steps (which might be safer if you omit sensitive data).

**Anti-Patterns:**

- Not testing at all and using production as "test" – this can be disastrous if the script has a destructive bug. 
- Relying solely on manual testing is okay for very small changes, but as scripts get complex, manual testing might miss scenarios. 
- Another anti-pattern is writing tests after long delays or not updating tests when the script changes – tests should evolve with the code. 
- Avoid writing tests that are too brittle (e.g., expecting an exact error message string, which might change) – test for outcomes or error types rather than exact wording where possible. 
- Also, avoid tests that have external dependencies (like actually calling a live system) – use mocking to simulate external interactions; this makes tests reliable and not dependent on environment or network. 
- Finally, don't ignore failed test results; if Pester or analysis flags something, address it or if it's a false positive, update the test or rule accordingly. The whole point is to trust your tests so you can confidently deploy scripts.

---

## ✅ Prioritised Best Practices Checklist

Below is a concise checklist of key best practices, categorised by priority:

* **Critical:**
  
  1. **Comment-Based Help & Metadata:** Include Synopsis, Description, Parameter info, and Examples in every script/function for clarity.
  2. **Param Block with Validation:** Use a `param()` block with `[CmdletBinding()]` and appropriate validation attributes (e.g. ValidateSet, Mandatory) instead of relying on prompts or defaults.
  3. **Approved Verb-Noun Naming:** Name scripts/functions with approved verbs and singular nouns (e.g. `Get-Item`, `New-Report`), to align with PowerShell standards and avoid import warnings.
  4. **Output Objects Not Text:** Always output structured objects to the pipeline, not formatted text or host-only output, enabling downstream processing and reuse.
  5. **Error Handling with Try/Catch:** Wrap risky operations in try/catch blocks and handle errors gracefully; use `-ErrorAction Stop` on cmdlets to catch non-terminating errors.
  6. **No Plaintext Secrets:** Never hardcode passwords or secrets; use `PSCredential` objects or vault/secure store solutions to handle sensitive data.
  7. **Avoid Invoke-Expression & Injection:** Do not use `Invoke-Expression` with untrusted input or construct commands from strings – this is a major security risk.
  8. **SupportsShouldProcess for Changes:** Implement `SupportsShouldProcess` (WhatIf/Confirm) for any action that changes system state (files, settings, user accounts, etc.).
  9. **Scope and Strict Mode:** Use `Set-StrictMode -Latest` to catch undefined variables; avoid global state and ensure variables are properly scoped to prevent side effects.
  10. **Logging and Audit:** Log important actions and errors (via verbose, warning, or error streams) and/or use transcripts. Ensure actions in security scripts are auditable (who ran, what was changed).

* **Recommended:**
  
  11. **Use Source Control & Versioning:** Store scripts in source control (git), use semantic versioning and update version/tags on changes for traceability. Include version info in script comments or module manifest.
  12. **PSScriptAnalyzer Clean:** Run PSScriptAnalyzer and address warnings (e.g. avoid aliases, empty catches, use singular nouns, etc.) to keep code quality high.
  13. **Module-ise for Reuse:** Package related functions into modules with manifests (psd1) specifying Author, Version, etc., and import as needed. Use `#Requires -Modules X` in scripts to ensure dependencies are present.
  14. **Retry Logic for Transients:** Implement retry with exponential backoff for transient failures (like network glitches) and distinguish those from permanent errors to improve resilience.
  15. **Use Verbose/Debug for Messaging:** Utilise `Write-Verbose` for runtime messages and `Write-Debug` for internal state info, instead of `Write-Host`. This allows users to turn on/off these messages with `-Verbose` or `-Debug`.
  16. **PowerShell 7 Compatibility:** Write scripts compatible with PS7 when possible – avoid Windows-only APIs or guard them with `$IsWindows`. Use cross-platform alternatives (e.g. `Get-CimInstance` vs `Get-WmiObject`) for portability.
  17. **ConfirmImpact and Force:** For destructive actions, assign an appropriate `ConfirmImpact` level and consider adding a `-Force` switch to bypass confirmations in non-interactive scenarios.
  18. **Test Path and Inputs:** Validate files, paths, and other inputs early (e.g. use `Test-Path` in a ValidateScript or in code) to fail fast with clear error if something is amiss (like missing file or lack of access).
  19. **Comments for Intent:** Include brief comments explaining complex logic or important decisions/trade-offs in code. Avoid obvious comments; focus on intent and rationale behind code segments.
  20. **Use Proper Types:** Strongly type parameters and variables when possible (e.g., `[int]$Count`, `[DateTime]$Start`) to catch type conversion issues early. Use `[switch]` for boolean flags instead of `[bool]` for more idiomatic usage.

* **Good to Have:**
  
  21. **Region Tags for Organisation:** Use `#region` to collapse sections in editors (e.g. "#region Functions", "#region Main") – helps navigate larger scripts without affecting execution.
  22. **Splatting for Long Parameters:** Use splatting (`@params`) to pass parameters for better readability especially when calling commands with many parameters or forwarding parameters.
  23. **Default Parameter Sets:** When using parameter sets, define `DefaultParameterSetName` in `CmdletBinding` to avoid ambiguity. This enhances user experience and prevents confusing errors.
  24. **Format Output (Advanced):** If creating custom object types, provide a format.ps1xml in modules for pretty default formatting rather than formatting in the script. Also consider a Types.ps1xml for custom type accelerators or methods (for advanced tooling scenarios).
  25. **Pipeline Efficiency:** Where appropriate, make functions pipeline-aware (process input objects one at a time using `process{}`) so they can be part of larger pipelines efficiently.
  26. **Transcripts in Scheduled Runs:** If running as a scheduled task or CI job, consider auto-starting a transcript to capture output for troubleshooting.
  27. **Graceful Stop/Exit:** Handle user cancellations or stop requests (`CTRL+C` or `$host.UI.RawUI.ReadKey()`) if applicable, and cleanup (e.g., remove temp files) if script is interrupted. Honour `$Stopping` in loops (for long-running scripts, check `$PSCmdlet.ShouldExitCurrentIteration` or simply `$Stopping` to break out if PowerShell is trying to stop the script).
  28. **Documentation for Dependencies:** In script/module documentation, list any external requirements (modules, software, permissions). E.g., "Requires Azure Az module v5+" or "User running must have local admin rights".
  29. **No Empty Catch or Finally:** Every `catch` should handle or log the error; every `finally` should be for cleanup, not logic. Empty catches make debugging hard.
  30. **Editor and Environment:** Use Visual Studio Code with the PowerShell extension (and PowerShell Preview extension for latest features) for script development. This provides IntelliSense, inline PSScriptAnalyzer feedback, and an integrated debugger. (Good practice to mention, though not code-specific.)

## 📋 PowerShell Scripting Best Practices Cheat Sheet

**Structure & Style:**

* **Template:** Always start with `#requires` (version, modules) and `<# .SYNOPSIS/.DESCRIPTION #>` help. Then `param(...)` with `[CmdletBinding()]`. **Script files:** Use linear execution after param block. **Functions:** Use `Begin/Process/End` blocks for pipeline functions. Keep functions short and focused.
* **String Formatting:** Use `"Variable is $var"` for simple cases. Use `"Complex: $($obj.Property)"` for expressions. Use `"Template {0} with {1}" -f $val1, $val2` for structured formatting. **Avoid** `+` concatenation and parsing-error patterns like `"($($var)ms)"`.
* **Consistency:** Use 4 spaces for indent. Use PascalCase for Names (Cmdlets, Params), lowercase for keywords (`if`, `foreach`), UPPERCASE for help tags in comments. Consistent naming and layout across scripts.
* **Strict Mode:** Enable strict mode (`Set-StrictMode -Version Latest`) to catch undefined vars and subtle bugs early.
* **Source Control:** Keep scripts in a repo, track versions. Document changes in .NOTES or changelog. Name files clearly (Get-Report.ps1, not script1.ps1). Save as UTF-8 without BOM.

**Cmdlet Design:**

* **Naming:** `Verb-Noun` (Approved verbs only, singular noun). E.g. `Start-DataExport`. Use prefixes if needed to avoid name collisions (e.g., `Get-ACMEUser` for company ACME).
* **CmdletBinding:** Always include `[CmdletBinding()]` for functions – gives common parameters (`-Verbose`, `-ErrorAction`, etc.).
* **ShouldProcess:** Use `SupportsShouldProcess=$true` for actions (Modify, Remove, etc.). Call `if($PSCmdlet.ShouldProcess(...)){ ... }` around changes. Implement `-Confirm` and honour `-WhatIf`.
* **Output:** Emit objects (prefer `[PSCustomObject]` or standard .NET objects). **No** `Write-Host` for data. Let users format or export as needed.
* **OutputType:** Optionally use `[OutputType()]` to declare return object type(s) for documentation.
* **No Return for Pipeline:** In advanced functions, output in `Process` block and let the function return implicitly (avoid using the `return` keyword for output).

**Parameters:**

* **Validation:** Use `[ValidateNotNullOrEmpty]`, `[ValidateSet()]`, `[ValidateRange()]`, etc., to catch bad inputs.
* **Mandatory:** Mark required params as Mandatory=\$true so PowerShell prompts if missing (or throws in non-interactive). Don't prompt with Read-Host inside scripts.
* **Secure Input:** Use `[PSCredential]` for credentials (instead of string username/password). Use SecureString for secrets or integrate with SecretManagement for pulling secrets securely.
* **Parameter Sets:** Organise parameters into sets if they are mutually exclusive. Set `DefaultParameterSetName` to a sensible default.
* **Common Param Names:** Use standard names (e.g. `Path`, `LiteralPath`, `Credential`, `Force`) where applicable, to meet user expectations.
* **Aliases:** Provide `[Alias()]` for backward compatibility or convenience (e.g. Alias "CN" for a param named ComputerName), but primary name should be clear.

**Error Handling:**

* **Try/Catch:** Wrap operations in try/catch. Use `-ErrorAction Stop` to make non-terminating errors catchable.
* **Informative Errors:** Throw or write errors with clear messages. Include identifying info (e.g. `"Failed to remove user $User: $_"`).
* **Non-Terminating vs Terminating:** Use `Write-Error` for recoverable issues (allows continuing) and `throw`/`ThrowTerminatingError` for critical ones to stop processing.
* **No Empty Catch:** Always handle or log in catch blocks – don't swallow exceptions silently.
* **\$ErrorActionPreference:** Optionally set `$ErrorActionPreference = 'Stop'` at start of script (and revert if needed) to ensure any error stops execution for global scripts.
* **Finally/Cleanup:** Use `finally` to clean up resources (close files, dispose objects) regardless of errors.

**Security:**

* **No Plain Text Creds:** Never store passwords in script. Use `Get-Credential` or vault. **Avoid** `ConvertTo-SecureString -AsPlainText` except for automation with secure external storage.
* **Sign Scripts:** Sign production scripts with a code-signing certificate if possible. Use `AllSigned` or `RemoteSigned` execution policy enterprise-wide.
* **Least Privilege:** Run scripts with least privileges needed. If admin rights required, enforce via `#Requires -RunAsAdministrator`.
* **Input Sanitisation:** If your script uses input in commands (like building a file path or SQL query), validate or sanitise to prevent injection. Avoid `Invoke-Expression` on any user input.
* **Logging/Audit:** Log actions and results to a secure log (file or event log). Include timestamps and who ran the script (e.g. capture `$env:USERNAME` or context). For IR scripts, log to an immutable store if needed for evidentiary reasons.
* **Constrained Language:** Be aware if CLM is enabled (no Add-Type, limited .NET). Stick to approved cmdlets in locked-down environments.

**Modules & Dependencies:**

* **Module Use:** Prefer modules (.psm1) for sets of functions – easier to maintain and reuse. Single-use script functions can live in the script, but anything shareable -> module.
* **#Requires -Modules:** At top of script, list required modules and minimum versions. E.g. `#Requires -Modules AzureAD` (so script fails early if not available).
* **Import-Module in Code:** If not using #Requires, do `Import-Module` explicitly and handle load errors gracefully (inform user to install module).
* **Version Pinning:** Import specific versions if needed: `Import-Module SQLServer -RequiredVersion 21.1`.
* **Manifest Metadata:** Fill module manifest fields (Author, Company, Description, Version). Export only necessary commands via `Export-ModuleMember` or manifest entries.
* **Dependency Documentation:** Document any external dependencies (EXEs, network resources, etc.) in the script help or readme.

**Cross-Version/Platform:**

* **Windows PS vs PS Core:** Test on both Windows PowerShell 5.1 and PowerShell 7+ if supporting both. Note differences (PS7 has newer features, different defaults).
* **Platform Checks:** Use `$IsWindows/$IsLinux` to branch OS-specific code when necessary. E.g. if using `Send-MailMessage` (Windows only), consider `Send-MailKitMessage` on Core, or use `MailKit` library.
* **Avoid WMI/COM for X-plat:** Use REST APIs, .NET Core compatible libraries or cross-platform cmdlets (like `Get-CimInstance` instead of old WMI cmdlets) for anything that might run on Linux/macOS.
* **Paths:** Use `Join-Path` or `[IO.Path]::Combine` for file paths; avoid hardcoded `"C:\..."` in code. For Linux, paths start at `/`.
* **Encoding:** Remember `Out-File` default encoding differs (PS7 = UTF8, PS5 = UTF16). Specify `-Encoding` if consumers require a specific format.
* **Testing:** If claiming cross-platform support, test key functionality on each platform (file operations, credential usage, etc. can differ per OS).

**Maintainability:**

* **Readable Code:** Use whitespace and line breaks to make code readable. For long pipelines, consider one segment per line (with pipeline `|` at line starts or ends uniformly).
* **No Aliases in Scripts:** Write full cmdlet names (e.g. `Where-Object` not `?`), full parameter names (no positional use for readability).
* **DRY (Don't Repeat Yourself):** Factor out repetitive code into functions rather than copy-paste. Makes future changes easier and reduces mistakes.
* **Comments & Help:** Keep comment-based help updated when code changes. Use `.PARAMETER` to explain each param's purpose, `.EXAMPLE` to show usage.
* **Tool Output vs Host Output:** Use `Write-Verbose`/`Write-Progress` for updates to user (progress, status), not echoing to output. Reserve output stream for actual results.
* **Pester Tests:** Write Pester tests for functions if possible. At least, test critical paths and edge cases. This ensures reliability when refactoring.
* **CI Integration:** If feasible, integrate script testing and style check in CI pipelines (e.g., run PSScriptAnalyzer and Pester on PRs).

**Debugging & Testing:**

* **Verbose/Debug Switches:** Encourage using `-Verbose` for debug info. Provide ample `Write-Verbose` messages in your script (they don't show unless `-Verbose` is used).
* **Breakpoints:** Use the debugger in VSCode or `Set-PSBreakpoint` for complex debugging. Use `$DebugPreference="Break"` with `Write-Debug` strategically to inspect state.
* **Transient Fail Testing:** Simulate failures (e.g. via Pester mocks or by toggling network) to ensure your error handling and retry logic works.
* **User Feedback:** If a script might run long, use `Write-Progress` to show activity. That improves perceived reliability (script isn't hanging).
* **Clean Exit:** If script completes (or is interrupted), ensure open files or connections are closed. Set exit codes appropriately (`exit 0` for success, non-zero for errors) if the script is used in automated jobs.

This cheat sheet can be used as a quick-reference for script development and code reviews, ensuring adherence to enterprise PowerShell standards.

## ⚠️ Common Pitfalls and How to Avoid Them

Based on real-world debugging experience, here are specific mistakes that cause script failures and how to prevent them:

### String Formatting Pitfalls

**Problem:** String interpolation parsing errors

```powershell
# ❌ WRONG - Causes "Unexpected token 'ms'" error
Write-Verbose "Response time ($($stopwatch.ElapsedMilliseconds)ms)"

# ✅ CORRECT - Add space or use format operator
Write-Verbose "Response time ($($stopwatch.ElapsedMilliseconds) ms)"
Write-Verbose ("Response time ({0}ms)" -f $stopwatch.ElapsedMilliseconds)
```

**Problem:** String concatenation in PowerShell

```powershell
# ❌ WRONG - Not idiomatic PowerShell
$message = "User " + $name + " processed at " + $timestamp

# ✅ CORRECT - Use string interpolation
$message = "User $name processed at $timestamp"
```

### Script Structure Pitfalls

**Problem:** Using begin/process/end blocks in script files

```powershell
# ❌ WRONG - Causes "The term 'begin' is not recognized" error
param($Domain)

begin {
    # This fails in .ps1 files
}

# ✅ CORRECT - Linear execution in scripts
param($Domain)

# Initialisation code here
Set-StrictMode -Version Latest

# Main logic here
foreach ($DomainName in $Domain) {
    # Process each domain
}
```

**Problem:** Incorrect array handling in rate limiting

```powershell
# ❌ WRONG - Can cause "Count property not found" error
$script:RequestTimes = $script:RequestTimes | Where-Object { $_ -gt $cutoffTime }

# ✅ CORRECT - Ensure result is always an array
$script:RequestTimes = @($script:RequestTimes | Where-Object { $_ -gt $cutoffTime })
```

### File Encoding Pitfalls

**Problem:** Byte Order Mark (BOM) issues

```powershell
# ❌ WRONG - Files saved with UTF-8 BOM can cause parsing errors
# The BOM character at start of file: ﻿#Requires -Version 5.1

# ✅ CORRECT - Save files as UTF-8 without BOM
#Requires -Version 5.1
```

### Error Handling Pitfalls

**Problem:** Not capturing error details immediately

```powershell
# ❌ WRONG - Error details may be lost
catch {
    Write-Log "Some other operation"  # This might change $_
    Write-Error "Failed: $($_.Exception.Message)"  # May be wrong error
}

# ✅ CORRECT - Capture error immediately
catch {
    $currentError = $_  # Capture immediately
    Write-Log "Some other operation"
    Write-Error "Failed: $($currentError.Exception.Message)"
}
```

These examples represent actual failures encountered during script development and demonstrate the importance of following PowerShell best practices consistently.

## 🧪 Example: Script Template with Best Practices

Below is a simplified PowerShell script template incorporating many best practices discussed. It demonstrates structure, parameter validation, error handling, logging, and secure patterns:

```powershell
#Requires -Version 7.0
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Example script that performs a user account action (template).
.DESCRIPTION
    This script template shows how to structure a PowerShell script with best practices:
    param block with validations, CmdletBinding, logging, error handling, and output.
.PARAMETER UserName
    The samAccountName of the user to process. (Mandatory)
.PARAMETER Action
    The action to perform on the user account. E.g. 'Disable' or 'Enable'.
.PARAMETER Credential
    A PSCredential for domain authentication (if not run as a user with permissions).
.EXAMPLE
    .\UserTool.ps1 -UserName jdoe -Action Disable -Verbose
    Disables the account 'jdoe' in Active Directory, with verbose logging.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [Parameter(Mandatory=$true)]
    [ValidateSet('Enable','Disable')]
    [string]$Action,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential
)

#region Helper Functions (if needed)
function Write-ActionLog {
    param($Message, $UserName, $Action)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Verbose "$timestamp - $Action action: $Message (User: $UserName)"
}
#endregion

# Script initialisation
Set-StrictMode -Version Latest

# Start transcript for logging if verbose is enabled
if ($PSBoundParameters.ContainsKey('Verbose')) {
    $logPath = "./Logs/UserTool_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
    Start-Transcript -Path $logPath -Append | Out-Null
    Write-Verbose "Transcript started: $logPath"
}

Write-Verbose "Starting script at $(Get-Date) for user: $UserName, Action: $Action"

# Main script logic
try {
    # Construct a message for ShouldProcess
    $target = "user account '$UserName'"
    $what = if ($Action -eq 'Disable') { 'Disable Account' } else { 'Enable Account' }

    if ($PSCmdlet.ShouldProcess($target, $what)) {
        # Connect to AD (if needed, using Credential)
        if ($Credential) {
            Write-Verbose "Connecting to AD with provided credentials"
            Import-Module ActiveDirectory -ErrorAction Stop
        }

        Write-ActionLog "Starting $Action operation" $UserName $Action

        if ($Action -eq 'Disable') {
            $params = @{
                Identity = $UserName
                ErrorAction = 'Stop'
            }
            if ($Credential) { $params.Credential = $Credential }
            Disable-ADAccount @params
        } else {
            $params = @{
                Identity = $UserName
                ErrorAction = 'Stop'
            }
            if ($Credential) { $params.Credential = $Credential }
            Enable-ADAccount @params
        }

        Write-ActionLog "Successfully completed $Action operation" $UserName $Action

        # Output structured result object
        $result = [PSCustomObject]@{
            UserName = $UserName
            Action   = $Action
            Status   = 'Success'
            Timestamp = Get-Date
            Message  = "$Action operation completed successfully"
        }
        Write-Output $result

    } else {
        Write-Verbose "ShouldProcess declined action. No changes made to $UserName."

        # Output result for WhatIf scenarios
        $result = [PSCustomObject]@{
            UserName = $UserName
            Action   = $Action
            Status   = 'Skipped'
            Timestamp = Get-Date
            Message  = "Operation skipped (WhatIf or user declined confirmation)"
        }
        Write-Output $result
    }
}
catch {
    # Capture error details immediately
    $errorDetails = $_
    $errorMessage = "Failed to {0} user {1}: {2}" -f $Action, $UserName, $errorDetails.Exception.Message

    Write-Error $errorMessage
    Write-ActionLog "Error occurred: $($errorDetails.Exception.Message)" $UserName $Action

    # Output failure object
    $result = [PSCustomObject]@{
        UserName = $UserName
        Action   = $Action
        Status   = 'Failed'
        Timestamp = Get-Date
        Error    = $errorDetails.Exception.Message
        Message  = $errorMessage
    }
    Write-Output $result
}
finally {
    # Cleanup - always runs regardless of success/failure
    Write-Verbose "Script completed at $(Get-Date)"

    if ($PSBoundParameters.ContainsKey('Verbose')) {
        Stop-Transcript | Out-Null
    }
}
```

**Key features of the above template:**

* Uses `#Requires` to ensure minimum PS version and module availability.
* Comment-based help provides Synopsis, Description, Parameters, Examples.
* `[CmdletBinding()]` with `SupportsShouldProcess` enables `-WhatIf`/`-Confirm` usage.
* Parameters have validation (`ValidateNotNullOrEmpty`, `ValidateSet`) and support secure credential input.
* **Linear script structure** - no begin/process/end blocks at top level, which would cause parsing errors in .ps1 files.
* Helper functions defined in a region for organisation and reusability.
* `Set-StrictMode -Latest` is called for robust variable usage.
* `Start-Transcript` is conditionally used when `-Verbose` is enabled to log the session.
* **Proper string formatting** using the `-f` format operator to avoid interpolation issues.
* Verbose messages (`Write-Verbose`) provide insight into script flow.
* Uses `ShouldProcess` to confirm the action on the target, wrapping the core operation.
* **Parameter splatting** (`@params`) for cleaner cmdlet calls with conditional parameters.
* Try/Catch/Finally pattern with immediate error capture and proper cleanup.
* On both success and failure, outputs structured PSCustomObject results for pipeline compatibility.
* Avoids `Write-Host` entirely – all user-facing info is via appropriate streams (Verbose, Error).
* **Finally block** ensures cleanup always occurs, even if errors happen (stopping transcript).
