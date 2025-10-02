# PowerShell Scripting - Patterns and Antipatterns

## Script structure & style

* **MUST** start with `#Requires`, then comment-based help, then `param()`. Keep flow: Help → Param → Functions → Main → Cleanup.
* **MUST** enable `Set-StrictMode -Version Latest`.
* **MUST** distinguish script vs advanced function patterns (no `begin/process/end` at script top level).
* **SHOULD** use `#region` blocks, 4-space indents, ≤120-char lines, explicit variable initialisation.
* **SHOULD** keep scripts in source control with clear names and version metadata.
* **AVOID** monolithic/no-help scripts, implicit globals, and leftover state.

## Cmdlet & function design

* **MUST** use `[CmdletBinding()]` for advanced functions and approved **Verb-Noun** names (singular nouns).
* **MUST** output structured **objects** (not formatted text); reserve `Write-Host` for purely interactive messages.
* **MUST** implement `SupportsShouldProcess` for any state-changing action; honour `-WhatIf/-Confirm`.
* **SHOULD** use splatting for long parameter lists; keep outputs consistent in type/shape.
* **AVOID** unapproved verbs, mixed output types, formatting (`Format-*`) inside producing commands, or interactive prompts inside action functions.

## Parameters

* **MUST** validate inputs with attributes (`ValidateSet`, `ValidateRange`, etc.) and mark required params `Mandatory=$true`.
* **MUST** treat secrets securely: use `[PSCredential]`/`[SecureString]` or a secret vault; never plain strings.
* **SHOULD** use parameter sets with `DefaultParameterSetName`; add helpful `HelpMessage`/`Alias` sparingly.
* **AVOID** `Read-Host` for required inputs (design for unattended use), and modifying parameter variables in-place.

## Error handling & resilience

* **MUST** wrap risky ops in `try/catch/finally`; use `-ErrorAction Stop` (or `$ErrorActionPreference='Stop'`) to catch non-terminating errors.
* **MUST** provide informative error messages; log or rethrow as appropriate; never swallow exceptions.
* **SHOULD** differentiate transient vs permanent errors; implement bounded retries with backoff for transients.
* **AVOID** empty `catch`, relying on `$?`, or silencing errors without justification.

## Security & compliance

* **NEVER** use `Invoke-Expression` on untrusted input; avoid string-built commands—use parameters/splatting.
* **MUST** keep secrets out of code and logs; prefer vaults/PSCredential.
* **MUST** enforce least privilege and declare elevation needs with `#Requires -RunAsAdministrator`.
* **SHOULD** sign production scripts; log key actions (without sensitive data); consider transcripts when appropriate.
* **AVOID** weakening platform safeguards (e.g. bypassing policy) without explicit, documented justification.

## Modules & dependencies

* **MUST** declare required modules/versions (`#Requires -Modules`, manifest `RequiredModules`).
* **SHOULD** package reusable functions into modules with manifests, semantic versions, and clear exports.
* **SHOULD** handle command conflicts via fully-qualified names or `-Prefix` when necessary.
* **AVOID** duplicated code, scattered imports, legacy snap-ins unless unavoidable and documented.

## Cross-version/platform

* **MUST** state and/or guard for targeted PS versions; branch for platform specifics (`$IsWindows/$IsLinux/$IsMacOS`).
* **SHOULD** prefer cross-platform APIs (`Get-CimInstance`, `Join-Path`, UTF-8 encoding) and test on all target runtimes.
* **AVOID** Windows-only features in cross-platform scripts without guards; brittle path/encoding assumptions.

## Maintainability & readability

* **MUST** write clear, self-documenting code; comment **why**, not the obvious.
* **SHOULD** run PSScriptAnalyzer and fix findings (or document justified suppressions); avoid aliases/positional params in code.
* **SHOULD** split logic into small functions; provide examples in help; use `Write-Verbose/Write-Debug` for diagnostics.
* **AVOID** dead code, inconsistent style, string concatenation where interpolation/formatting is clearer.

## Output & interoperability

* **MUST** emit data objects; separate data generation from presentation.
* **SHOULD** ensure output serialises cleanly (JSON/CSV); stream large outputs; offer optional `-AsJson`/`-OutCsv` modes if helpful.
* **AVOID** mixing data with status text on the output stream; don’t break pipelines with `Format-*` mid-stream.

## Testing & debugging

* **MUST** cover critical functions with Pester tests (normal, edge, and error paths); mock external calls.
* **SHOULD** add retry/fault-injection tests; capture transcripts/logs for supportability; test under production-like conditions.
* **AVOID** untested destructive changes; brittle tests that depend on exact wording rather than outcomes.
