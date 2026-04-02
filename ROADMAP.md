# ROADMAP — APEX Zero-Trust Windows Auditor

> This document covers the design philosophy, an honest and technical assessment of the current codebase strengths and gaps, a precise diagnosis of what needs to be fixed right now, and a structured vision for making APEX the reference hardening tool for individual users, power users, and enterprise deployments alike.

---

## Table of contents

1. [Design philosophy](#1-design-philosophy)
2. [Points of strength — what works well and why](#2-points-of-strength)
3. [Current limitations and honest gaps](#3-current-limitations-and-honest-gaps)
4. [Current state — precise diagnosis](#4-current-state--precise-diagnosis)
5. [Roadmap](#5-roadmap)
6. [Audience tiers and feature mapping](#6-audience-tiers-and-feature-mapping)
7. [Anti-goals — what APEX will never become](#7-anti-goals)

---

## 1. Design philosophy

APEX is built around three constraints that most security tools quietly abandon as they grow: it must work completely **offline**, every finding must be **attributable to an exact source** (no black-box scores), and the tool must never touch a system it hasn't been told to touch.

The offline constraint is non-negotiable for the tool's target environments: air-gapped networks, regulated environments where outbound connections are logged or blocked, and personal machines where a user reasonably does not want their security state reported to a remote server. Every check therefore uses only OS-native channels: the Windows Registry, CIM/WMI, PowerShell's built-in security cmdlets, and locally-installed tools (`netsh`, `wevtutil`, `auditpol`, `wecutil`, `manage-bde`, `net.exe`).

The source-attribution constraint reflects a belief that a finding is only as credible as its evidence. The JSON output includes the exact registry path, WMI class, or command name that produced each signal. When an auditor asks "how do you know the firewall is configured this way?", the answer is in the report, not in the vendor's documentation.

The non-destructive constraint shapes the entire remediation model: every change is opt-in, every change is backed up, and the most disruptive changes (WDAC policy deployment, aggressive firewall rule removal) are never auto-applied regardless of the settings chosen.

---

## 2. Points of strength

### Split-build architecture with per-file testability

The codebase is deliberately split into three layers: the entry point (`Windows_Audit.ps1`), the engine (`Engine\Core.ps1`, `Engine\Report.ps1`), and the check library (`Checks\Check-*.ps1`). This architecture means each check file is a self-contained unit of logic that can be read, tested, and modified independently. A new check doesn't require touching the engine or the entry point — it only needs to be added to the manifest array. A bug in `Check-Firewall.ps1` is contained to that file.

This split is also what makes the test harness meaningful. The scientific test laboratory (`Invoke-AuditLabTest.ps1`) validates the entry point's contract (S1), the JSON schema contract (S2), and individual behavioral contracts (S3–S9) — all without any coupling to the internal implementation of specific checks. When a check is refactored, the schema tests catch regressions automatically.

### Double-signal validation for high-confidence findings

The firewall checks are the most visible example of the general principle. Rather than relying solely on `Get-NetFirewallProfile` (which can return misleading results when a third-party firewall product registers itself without fully configuring the Windows Firewall service), the tool independently queries `netsh advfirewall show <profile>profile` and uses that output as the authoritative signal. The two sources are kept in separate check files (`Check-Firewall.ps1` for rule-level state, `Check-FirewallPosture.ps1` for service health and logging).

This pattern — two independent sources for the same control domain — is what separates a serious audit tool from a collection of registry-reading one-liners. Discrepancies between cmdlet output and ground-truth CLI output are surfaced as findings in their own right.

### Partial-failure resilience with the rollback pattern

`Check-DeviceGuard.ps1` demonstrates the correct pattern for checks that query a single CIM namespace to produce multiple findings: it records `$countBefore = $Script:Findings.Count` before the try block, and in the catch block walks back to that count before adding a set of `Confidence=QueryFailed` fallback findings. Without this pattern, a partial CIM success (e.g. the namespace is accessible but one property throws) would produce a mix of real findings and fallback findings, potentially with duplicate IDs.

Every new check that adds more than one finding inside a shared try block must use this pattern.

### Structured confidence model beyond pass/fail

The six-value `Confidence` enum (`High`, `Medium`, `Low`, `NotApplicable`, `NoAccess`, `QueryFailed`) is one of the more thoughtful aspects of the design. The distinction between `NoAccess` (the query ran but requires elevation that is unavailable) and `QueryFailed` (the query threw an exception) is material: the first tells you something about the check's preconditions, the second tells you something may be wrong with the system or the tool.

The schema contract (S2.16) enforces that `NoAccess` findings are never marked `Vulnerable=true`, because the correct interpretation of "we couldn't read this setting" is not "this setting is misconfigured" but "we don't know". This prevents false positives in non-admin runs.

### Delta engine for continuous compliance monitoring

The `-Baseline` / `-CompareTo` workflow provides something most standalone audit tools lack: the ability to track posture over time with structured diffs. The delta object distinguishes three change types — regressions (previously safe, now vulnerable), improvements (previously vulnerable, now safe), and new checks (present in the current run but absent from the baseline because the check was added after the baseline was written). All three are surfaced separately in the HTML Delta tab and the JSON output.

The delta engine lives entirely in `Engine\Core.ps1` as `Compare-AuditBaseline`. It is intentionally ID-based rather than name-based, which means a check can be renamed without falsely creating a regression in the delta.

### Self-documenting findings — Fix field in every output

Every vulnerable finding includes a `Fix` field containing either an exact PowerShell or command-line remediation command, or a specific prose instruction. This is not a documentation link; it is the actual command to run. For findings where auto-remediation is risky (WDAC policies, LAPS deployment, LSASS PPL which requires a reboot), the Fix field provides the command but the tool does not execute it automatically. For straightforward settings (WDigest registry value, PowerShell logging keys, SMB signing), the Fix command is directly executable.

The schema contract (S2.14) enforces that every `Vulnerable=true` finding has an actionable Fix — not `'N/A'`. This is verified on every test run, so it is impossible to merge a check that doesn't provide remediation guidance for its vulnerable state.

### Graceful two-path enumeration for local admin membership

`Check-LocalAdmins.ps1` attempts `Get-LocalGroupMember` first, then falls back to `net.exe localgroup Administrators` if the cmdlet fails (which can happen on some domain configurations or when Windows PowerShell modules are degraded). This dual-path approach with a structured fallback means the check succeeds on nearly any Windows system, and the `Source` field correctly records which path was taken so the evidence is attributable.

### Comprehensive test harness built into the repository

The test suite covers 9 distinct quality dimensions across 44 test points. The fact that these tests were catching real failures (the previous missing-files situation) before any user ran the tool is exactly the point. A test harness that ships alongside the tool means regressions are caught in development, not in production. The JUnit XML export (`-ExportJUnit`) allows the harness to integrate with standard CI systems (GitHub Actions, Azure DevOps, Jenkins) without any additional tooling.

---

## 3. Current limitations and honest gaps

### Profile parameter has no effect on check behavior

The `$Profile` parameter is stored in the JSON context and displayed in reports, but none of the 17 check files currently read `$Profile` to modify their behavior. A `PersonalLaptop` run and a `Paranoid` run against the same machine produce identical findings — only the context field differs.

The intended model is that `Paranoid` would raise severity levels (e.g. Sysmon absence becomes a HIGH instead of informational), tighten thresholds (e.g. more than 1 local admin is a MEDIUM rather than 2), and enable additional checks (e.g. checking for PowerShell v2 engine availability). None of this is implemented yet.

### No per-check filtering by profile severity

Related to the above: there is currently no mechanism to say "this check should only produce a MEDIUM finding on PersonalLaptop but a HIGH on Enterprise." The severity level is hardcoded in each check function. The architecture supports adding a profile-aware threshold mechanism (the `$Profile` value is available via the script scope), but no check uses it.

### Check-ServicePaths produces variable-count findings

`Check-ServicePaths.ps1` emits one finding per unquoted service path it discovers, using the service name as part of the ID (`UNQUOTED_SERVICE_PATH:<svcname>`). On a clean system it may produce zero findings; on a heavily-installed system it may produce twenty. This means the check's presence in the JSON is not guaranteed — unlike every other check, which always emits at least one finding.

This matters for the idempotency test (S5): if a service is installed or removed between two consecutive runs, the idempotency check will fail even though the tool is working correctly. It also means the S9 test does not include any UNQUOTED_SERVICE_PATH IDs in its expected set, since those IDs are system-dependent.

The correct fix is to emit a single `UNQUOTED_SERVICE_PATHS` summary finding (with a count and list in the `Observed` field) plus individual findings for each exploitable path, rather than one finding per discovered path.

### No active probing — configuration state only

APEX reads configuration. It does not probe whether a theoretically-open attack surface is actually reachable, exploitable, or currently under attack. A machine with SMBv1 enabled will receive a CRITICAL SMB1 finding regardless of whether port 445 is reachable from anywhere. A machine with SMBv1 disabled but a vulnerable version of a third-party application installed will receive no finding for that application. This is by design (offline, deterministic) but is a real gap in coverage.

### No software inventory or patch-level checking

There is no check for installed application versions or CVE exposure. The `WU` (Windows Update) check only verifies that the `wuauserv` service is running — it does not enumerate pending updates or check when the last update was installed. A fully up-to-date OS with an unpatched browser or PDF reader will pass all APEX checks. Adding CVE matching would require either internet access (to query NVD/MSRC) or a bundled database (which requires maintenance), both of which conflict with the offline-first design.

### No Group Policy RSoP awareness

APEX reads raw registry values directly. On domain-joined machines, a local registry value may differ from the effective Group Policy-enforced value. A domain policy that enforces SMB signing will not be reflected in `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature` if the GPO writes to a different path or uses a different mechanism. The tool's `DomainJoined` context flag signals this limitation but does not resolve it.

### Profile-based thresholds not implemented

As noted above. The `$Profile` parameter is cosmetic in v2.5.

### The `Paranoid` and `Lab` profiles are identical to `PersonalLaptop` at runtime

This is the most visible user-facing gap: if a user runs with `-Profile Paranoid` expecting stricter findings, they will get exactly the same output as with `-Profile PersonalLaptop`. This should be explicitly documented in the help text until profile-aware logic is implemented.

### Profile-based thresholds not fully implemented

The `-Profile` parameter is stored in the JSON context, but the check files do not yet read `$Profile` to adjust severity thresholds. A `PersonalLaptop` run and a `Paranoid` run produce the same findings — only the context field differs. Profile-aware logic is on the roadmap for v3.x.

### `Resolve-ExportPath` uses `exit` inside a function

The function calls `exit 2` on write-permission errors. This hard-terminates the process from inside a non-entry-point function, which is correct for CLI tools but makes the function impossible to unit-test in isolation and can cause confusing behavior if the function is ever called from a context that expects a return value. The correct pattern is `throw "..."` or `Write-Error "..." -EA Stop`, letting the caller's `try/catch` handle the termination.

---

## 4. Current state — precise diagnosis

### State of the codebase as of v2.5.0 (this zip)

All files are present. The split-build is complete:
- `Engine\Core.ps1` — 185 lines. All expected functions present: `Add-Finding`, `Write-TUI`, `Write-TUILine`, `Write-TUIFinding`, `Test-IsAdmin`, `Get-RegValue`, `Get-SvcStatus`, `Invoke-Exe`, `Get-Cim`, `Measure-AuditScore`, `Read-BaselineJSON`, `Compare-AuditBaseline`.
- `Engine\Report.ps1` — 126 lines. All expected functions present: `Write-TUIReport`, `Export-HTMLReport`, `Resolve-ExportPath`.
- `Checks\` — all 17 files present. Sprint D checks confirmed: `Check-FirewallPosture.ps1` (FW-SVC, FW-LOG), `Check-ExploitProtection.ps1` (EXPROT-DEP/ASLR/CFG), `Check-LocalAdmins.ps1` (LOCALADMIN), `Check-DefenderExclusions.ps1` (DEFEXCL-EXT/PATH/COUNT), `Check-SMB.ps1` (SMBENC added to existing file).

The tool is **functional**. The previous test failures (S3/S5/S7.6/S8/S9 all failing with `CommandNotFoundException`) were entirely caused by these files being absent from the repository at the time of testing. With the full zip deployed, those failures will resolve automatically.

### What the test suite will look like after deployment

After deploying all files, before any additional fixes:

| Suite | Expected outcome | Reason |
|---|---|---|
| S1.1 | PASS | AST parses clean |
| S1.2 | PASS | File is UTF-8 no BOM (confirmed by prior test runs) |
| S1.3 | WARN (2 warnings) | `$Profile` automatic variable shadow; `$ExportJSON` appears unused |
| S1.4 | PASS | All 12 parameters have explicit type annotations (count unchanged by any fix) |
| S1.5 | WARN | 3 intentional `exit` statements (lines ~130, ~131, ~242) |
| S1.6 | WARN | `.INPUTS`, `.OUTPUTS`, `.NOTES` sections missing from help block |
| S1.7 | PASS | All 17 check functions present in source |
| S2.x | PASS (all sub-tests) | Schema is correctly implemented; invariants hold |
| S3.x | PASS (all) | All mode×profile combinations will produce JSON + HTML; exit codes correct |
| S4.x | PASS | Exit code contract correctly implemented |
| S5 | PASS | Two Deep runs on the same machine should be identical |
| S6 | PASS (with possible S6.fastVsDeep WARN) | Fast and Deep run in similar time; occasional timing jitter on loaded systems |
| S7.1 | PASS | `-Help` now exits 0 (test accepts 0 or 1) |
| S7.2 | PASS | `-Version` now exits 0 with version string present (test requires exit=0 + version string) |
| S7.3–7.4 | PASS | Invalid Mode/Profile rejected at param bind time |
| S7.5 | PASS (exit=2) | `Resolve-ExportPath` correctly calls `exit 2` on unwritable path |
| S7.6 | PASS | `-SkipHTML` + `-ExportJSON` now produces JSON only, no HTML |
| S7.7 | PASS | Missing `-CompareTo` file is non-fatal; run completes normally |
| S8.x | PASS | Delta engine functional; `Compare-AuditBaseline` correctly computes diffs |
| S9 | PASS | All 10 Sprint D IDs present in Deep output |

### Three pre-flight fixes (S1 warnings only)

These do not block any test. They eliminate cosmetic WARNs in S1.3 and S1.6:

**Fix 1 — Suppress `$Profile` PSScriptAnalyzer warning**

In `Windows_Audit.ps1` param block, add above the `$Profile` parameter:
```powershell
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidAssignmentToAutomaticVariable', '',
    Justification = 'Intentional CLI parameter; built-in $Profile is not used in this script.')]
[ValidateSet('PersonalLaptop','Enterprise','Lab','Paranoid')]
[string] $Profile = 'PersonalLaptop',
```

**Fix 2 — Document `$ExportJSON` scope dependency**

```powershell
[string] $ExportJSON = '',  # Consumed via caller scope by Engine\Core.ps1::Resolve-ExportPath
```

**Fix 3 — Complete the help block**

Add to the `.SYNOPSIS` / `.DESCRIPTION` block in `Windows_Audit.ps1`:
```powershell
.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Two files: <name>.json (structured report) and <name>.html (self-contained dashboard).
    Exit code: 0 = no vulnerabilities, 1 = vulnerabilities found, 2 = fatal error.

.NOTES
    Requires elevation for BitLocker, WMI DeviceGuard, and audit policy checks.
    All operations are read-only. No system changes are made in v2.5.
```

---

## 5. Roadmap

### Phase 0 — Pre-flight cleanup (now, before first PR)

- Apply the three PSScriptAnalyzer fixes above.
- Add `#Requires -RunAsAdministrator` OR a soft elevation check at startup that prints a clear `[!] Running without elevation — N checks will return NoAccess` banner before proceeding.
- Replace `exit 2` calls inside `Resolve-ExportPath` with `throw "Export path not writable: ..."` so the caller's `try/catch` in the main loop handles the termination cleanly.
- Add `LICENSE` (MIT) file.
- Add a `CHANGELOG.md` with an entry for v2.5.0.

**Success criteria:** `.\ExTest.ps1 -AuditScript .\Windows_Audit.ps1` produces 0 FAIL, 0 WARN in S1. All other suites pass as per the table above.

---

### Phase 1 — ✅ Complete in v3.0: compliance mapping, remediation, new checks

The following v3.0 features are fully implemented:
- **Compliance mapping** (`compliance_map.json` + `Get-ComplianceRefs`): all 57+ finding IDs annotated with CIS L1/L2, DISA STIG, and NIST 800-171r2 control references. JSON output includes `ComplianceRefs` on every finding. HTML report renders compliance badges.
- **Guided remediation** (`-Remediate`): interactive SAFE/CAUTION/RISKY tier fix loop with automatic backup before every applied change, and full restore via `-Undo`.
- **Print Spooler check** (`Check-PrintSpooler.ps1`): SPOOLER-SVC, SPOOLER-PNP, SPOOLER-DIR.
- **PowerShell v2 engine check** (`Check-PS2Engine.ps1`): PS2ENGINE.
- **Certificate store hygiene** (`Check-CertStore.ps1`): CERT-NONMS, CERT-EXPIRED.
- **Scheduled task analysis** (`Check-ScheduledTasks.ps1`): SCHTASK-WRITABLE, SCHTASK-SYSTEM, SCHTASK-NOAUTHOR (Deep only).

The roadmap below describes what remains for v3.x and beyond.

---

### Phase 1 (remaining) — Profile-aware logic (v3.0 → v3.x)

**Goal:** The profile parameter becomes meaningful. The guided remediation mode ships.

#### 1.1 Profile-aware severity thresholds

Introduce a `$Script:ProfileThresholds` hashtable in `Windows_Audit.ps1` that maps profile × check-ID to an optional severity override:

```powershell
$Script:ProfileThresholds = @{
    Paranoid = @{
        SYSMON  = 'MEDIUM'   # Absence of Sysmon becomes a real finding
        ASR     = 'MEDIUM'   # No ASR rules becomes MEDIUM, not LOW
        SMBSIGS = 'HIGH'     # SMB signing unsigned becomes HIGH
        WEF     = 'MEDIUM'
    }
    PersonalLaptop = @{
        LAPS    = 'PASS'     # LAPS is not applicable for non-domain personal machines; skip the finding
        WEF     = 'PASS'
    }
}
```

Check functions receive the profile via the script scope and use a `Get-EffectiveSeverity` helper that applies overrides. No check function needs to be restructured — only the severity value passed to `Add-Finding` changes.

#### 1.2 Remediation mode — interactive

Add `[switch] $Remediate` to the param block. When set:
- After the report is rendered, iterate over vulnerable findings in CRITICAL→LOW order.
- For each finding with a non-`N/A` Fix, display the finding and the fix command.
- Prompt: "Apply this fix? (Y / N / All-safe / Skip-remaining / Quit)"
- Before applying any fix, create a backup:
  - Registry-affecting fixes: `reg export <hive-path> <backup-file>` before `Set-ItemProperty`.
  - Service-affecting fixes: record current service state.
  - Backups stored in `C:\ProgramData\ApexAudit\Backups\<timestamp>\`.
- After each applied fix, re-run the check function that produced the finding and emit an inline verification result.
- At the end, print a remediation summary (N fixes applied, N skipped, N failed).

Safety tiers (stored as an additional field on each finding in the source code comments, not in the JSON schema — the JSON is a report format, not an execution plan):
- **SAFE**: `Set-ItemProperty` on well-known registry keys (WDigest, PSLog, cmdline logging), service startup type changes, SMB signing. Apply in batch with "All-safe".
- **CAUTION**: LLMNR/NetBIOS disable (may affect legacy shared printers), SMB encryption (may affect old clients). Require per-item confirmation.
- **RISKY**: PPL (requires reboot), WDAC policy deployment, BitLocker enablement. Never batch-applied; require explicit typed confirmation ("type YES to continue").

#### 1.3 Standalone build script

`build.ps1` concatenates `Engine\Core.ps1`, `Engine\Report.ps1`, and all `Checks\Check-*.ps1` into a single `Windows_Audit_standalone.ps1`. The standalone version is auto-generated; never maintain it by hand.

This serves users who cannot or prefer not to deploy a directory structure (e.g. downloading a single file from a release page).

#### 1.4 Export-CSV

Implement `-ExportCSV <path>` in `Windows_Audit.ps1`:

```powershell
$Script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
```

The CSV flattens the findings array with all 11 fields as columns. Useful for Excel-based triage.

#### 1.5 Continuous integration workflow

Publish `.github/workflows/test.yml` that:
- Runs on `push` and `pull_request` to `main`.
- Uses a `windows-latest` runner.
- Runs `.\ExTest.ps1 -AuditScript .\Windows_Audit.ps1 -ExportJUnit`.
- Publishes the JUnit XML as a GitHub Actions test report.
- Fails the workflow on any FAIL in S1–S9.

---

### Phase 2 — Coverage depth (v3.0 → v4.0)

**Goal:** APEX becomes the most thorough offline configuration auditor available for Windows 10/11.

#### 2.1 Credential hygiene checks (new check file)

`Checks\Check-CredentialHygiene.ps1`:
- Accounts with `PasswordNeverExpires = true` (CIM `Win32_UserAccount`).
- Accounts with `PasswordNotRequired = true` (flag for blank-password risk).
- Accounts with empty passwords — attempt via WMI `Win32_UserAccount.PasswordRequired = false` + `AccountType` cross-check.
- Built-in Guest account enabled (distinct from the SID500 check in `Check-Identity.ps1`).
- Stale accounts: local accounts not logged in within the past 90 days (cross-reference `Win32_NetworkLoginProfile`).

#### 2.2 PowerShell v2 engine check

Add to `Check-Forensics.ps1`:
- Check `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PowerShellEngine\PowerShellVersion` for v2 availability.
- Verify whether `powershell.exe -version 2` would succeed by checking for `System.Management.Automation.dll` v2 presence.
- PowerShell v2 bypasses script-block logging, constrained language mode, and AMSI. Its presence on a modern OS is a regression. Finding ID: `PS2ENGINE`.

#### 2.3 Scheduled task analysis (new check file)

`Checks\Check-ScheduledTasks.ps1` (Deep only):
- Enumerate scheduled tasks whose action executable path is writable by non-admin users.
- Flag tasks running as SYSTEM with user-writable trigger conditions.
- Check for tasks with missing or empty `Author` field (common in malware persistence).
- Source: `Get-ScheduledTask` + `Get-Acl` on the executable path.

#### 2.4 Certificate store hygiene (new check file)

`Checks\Check-CertStore.ps1`:
- List non-Microsoft root CAs added to `Cert:\LocalMachine\Root`.
- Flag any CA with a wildcard `Subject` pattern not matching known enterprise CA names.
- Flag expired certificates in `Cert:\LocalMachine\My`.
- Source: `Get-ChildItem Cert:\` — fully offline and deterministic.

#### 2.5 ASR rule promotion check

Extend `Check-ASR.ps1`:
- Currently flags "no rules in Block mode" as LOW. Extend to enumerate which rules are in Audit mode (action=2) and emit a MEDIUM finding recommending each Audit-mode rule be promoted to Block.
- Map rule GUIDs to human-readable names using a static lookup table embedded in the check file.
- Finding IDs: `ASR-PROMOTE-<GUID-prefix>`.

#### 2.6 DCOM hardening check (new check file)

`Checks\Check-DCOM.ps1`:
- Check `HKLM:\SOFTWARE\Microsoft\Ole\EnableDCOM` — should be `Y`.
- Check `MachineLaunchRestriction` and `MachineAccessRestriction` SDDL values.
- Flag world-activatable DCOM endpoints (anonymous access to DCOM servers).

#### 2.7 Print Spooler check (new check file)

`Checks\Check-PrintSpooler.ps1`:
- Service status and startup type.
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators`.
- `SpoolDirectory` path writability (PrintNightmare residual surface).
- Finding IDs: `SPOOLER-SVC`, `SPOOLER-PNP`, `SPOOLER-DIR`.

#### 2.8 LAPS depth (extend Check-Identity.ps1)

- Current check only reads the legacy LAPS registry key (`AdmPwd.dll` model).
- Add detection for Windows LAPS (Win11 22H2+ built-in) via `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State`.
- Add check for LAPS password age (if retrievable locally): `MSFT-LAPS_PASSWORD_EXPIRY_TIMESTAMP`.

#### 2.9 SARIF 2.1 export

Add `-ExportSARIF <path>` to the param block. Output a SARIF 2.1.0 JSON file:
- Each finding maps to a SARIF `result` with `level` (error/warning/note based on severity), `message`, `locations` (source registry path or CIM class as an artificial URI), and `fixes`.
- Schema: `https://json.schemastore.org/sarif-2.1.0.json`.
- Enables integration with GitHub Advanced Security's "Code scanning" UI, VS Code SARIF Viewer, and Azure DevOps.

#### 2.10 HTML report interactivity

The current HTML report is a beautiful, self-contained static document. Extend it with pure JavaScript (no external dependencies) to add:
- Full-text filter input across all findings.
- Sort by severity (default), category, or confidence.
- Per-severity toggle buttons to hide/show PASS findings.
- "Copy fix command" button on each vulnerable finding.
- Trend sparkline when multiple JSON reports from the same `Hostname` are present in the same directory — displayed as a `<canvas>` element using the built-in Charts API.

---

### Phase 3 — Enterprise and fleet (v4.0+)

**Goal:** APEX scales from a single workstation to a fleet of thousands without requiring a permanent agent or a central server.

#### 3.1 Remote execution via PSRemoting

```powershell
Invoke-ApexFleetScan -Targets @('server01','ws01','ws02') -Credential $cred `
    -OutputDir '\\fileserver\audits\' -Mode Deep -Profile Enterprise
```

Uses `Invoke-Command` with throttling (configurable `-ThrottleLimit`) to run the standalone build against multiple machines in parallel. Results are collected as individual JSON files. No persistent agent, no open ports beyond WinRM (5985/5986).

#### 3.2 Fleet aggregation report

```powershell
Merge-ApexFleetReports -InputDir '\\fileserver\audits\' -OutputHTML '.\fleet_dashboard.html'
```

Reads all `audit_report_*.json` files in a directory and produces an interactive fleet dashboard showing:
- Per-machine HygieneScore and SeverityScore in a sortable table.
- Finding ID heat map: which checks are failing on which machines.
- Fleet-wide score distribution histogram.
- Trend lines for each machine over time (requires multiple runs per machine).
- CSV export of the aggregated finding table.

#### 3.3 Intune / MECM integration

- **Intune Proactive Remediations**: publish a detection script (`detection.ps1`) that runs a Fast scan and exits 1 if `HygieneScore < 70`, and a remediation script that applies all SAFE-tier fixes and re-scans.
- **CMPivot**: publish a CMPivot query that runs the standalone build on targeted device collections and returns the `SeverityScore` and top 3 finding IDs.
- **Compliance policy export**: a script that maps APEX `HygieneScore` to an Intune compliance state (Compliant / Not Compliant / In Grace Period) based on configurable thresholds.

#### 3.4 SIEM / WEF integration

- Add a `-EmitEvents` switch that writes each finding as a structured Windows Event Log entry (custom provider `APEX-Audit`, event IDs 1000–1099 for CRITICAL/HIGH, 1100–1199 for MEDIUM/LOW).
- The events are formatted as XML `<Data>` elements matching the finding schema, making them parseable by Sentinel, Splunk, and any WEF-based collector without a custom parser.
- Publish an Azure Sentinel analytics rule template that alerts when an APEX CRITICAL finding event appears on a machine that was previously clean.

#### 3.5 Differential privilege model

Enumerate which checks require elevation and which do not. Publish a `--check-privs` flag that prints a table of check name / requires-elevation / degradation-mode.

Allow full non-elevated execution with graceful `NoAccess` handling for all admin-gated checks, rather than requiring elevation for any output. The current `Check-Baseline.ps1` already does this correctly for BitLocker; every other check should follow the same pattern.

---

### Phase 4 — The definitive tool

**Goal:** APEX is the reference implementation for Windows hardening verification at every level — thorough enough for enterprise compliance audit, accessible enough for a non-technical home user.

#### 4.1 Compliance framework alignment

Produce a formal mapping table (published as `compliance_map.json` in the repository) linking each finding ID to its corresponding control in:
- CIS Windows 10/11 Benchmark (Level 1 and Level 2)
- NIST SP 800-171 / CMMC 2.0 (for defense contractors)
- DISA STIG IDs for Windows 10/11
- SOC 2 Type II relevant controls

The mapping does not change how checks work — it annotates the JSON output with control IDs in a `ComplianceRefs` array field on each finding, enabling organizations to generate compliance evidence directly from APEX output.

#### 4.2 Cross-platform engine (PowerShell 7+)

Refactor `Engine\Core.ps1` and `Engine\Report.ps1` to have no Windows-specific dependencies. The engine handles findings, scoring, delta, and HTML — none of which are OS-specific.

Implement platform-specific check libraries for macOS (`Checks-macOS\`) and Linux (`Checks-Linux\`). The same `Windows_Audit.ps1` pattern is replicated as `macOS_Audit.ps1` and `Linux_Audit.ps1`. A common `Invoke-ApexAudit.ps1` entry point detects the platform and loads the correct check library.

#### 4.3 Community check registry

Define and publish a stable `Add-Finding` API contract (already effectively done by the existing schema). Create a contribution template for community checks that requires:
- The check function itself.
- A calibration report: false-positive rate on a known-good VM, false-negative rate on an intentionally misconfigured VM.
- A unit test file compatible with Pester 5.
- The finding IDs registered in a central `check_registry.json` to prevent ID collisions.

Community checks are distributed as individual signed `.ps1` files that can be dropped into the `Checks\` directory and picked up automatically by the manifest loader.

#### 4.4 Offline ML anomaly scoring (optional module)

Ship a pre-trained ONNX model (no internet required at runtime) trained on the distribution of registry values across thousands of known-clean and known-compromised Windows system snapshots. The model produces a per-check anomaly score that supplements the rule-based severity:

- A registry value that is technically within the allowed range but statistically unusual gets an elevated anomaly score.
- This is particularly useful for checks like `Check-ServicePaths` where the "expected" value depends on what software is installed.

The anomaly module is entirely optional — its absence does not affect any existing findings or scores. It adds an `AnomalyScore` field to the finding JSON when enabled.

#### 4.5 Optional GUI front-end

A minimal WPF application (Windows-only) or Electron application (cross-platform) that wraps the CLI:
- Designed for end users who are not comfortable with a PowerShell prompt.
- Shows a dashboard with the same information as the HTML report, but live-updating as the scan runs.
- "Fix all safe issues" button that executes the SAFE-tier remediation actions with a progress bar.
- Scheduled scan configuration UI.

The CLI is always the primary interface. The GUI is a thin wrapper that invokes the same scripts and parses the JSON output. It can be installed and uninstalled without affecting the CLI tools in any way.

---

## 6. Audience tiers and feature mapping

| Feature | End user (PersonalLaptop) | Power user (Enterprise) | Security team (Fleet) |
|---|---|---|---|
| Fast/Deep audit | ✅ | ✅ | ✅ |
| HTML report | ✅ | ✅ | ✅ |
| JSON export | ✅ | ✅ | ✅ |
| Baseline / delta | optional | ✅ | ✅ |
| Guided remediation | ✅ (SAFE tier) | ✅ (all tiers) | ✅ (scripted) |
| Profile-aware thresholds | Phase 1 | Phase 1 | Phase 1 |
| CSV / SARIF export | Phase 1 / Phase 2 | ✅ | ✅ |
| Fleet scan / aggregation | ❌ | optional | Phase 3 |
| Intune / MECM integration | ❌ | Phase 3 | Phase 3 |
| SIEM event emission | ❌ | Phase 3 | Phase 3 |
| Compliance framework IDs | reference | Phase 4 | Phase 4 |
| Cross-platform | ❌ | Phase 4 | Phase 4 |
| GUI front-end | Phase 4 | optional | ❌ CLI preferred |
| ML anomaly scoring | ❌ | Phase 4 | Phase 4 |

---

## 7. Anti-goals

These are things APEX will deliberately never do:

**No active exploitation.** APEX audits configuration state. It does not attempt to exploit the vulnerabilities it discovers, send crafted network packets, or spawn processes other than OS-native tools it explicitly invokes.

**No cloud dependency in core.** The core engine will always work completely offline. Cloud-integrated features may be offered as optional plugins, but will never be required for any core function.

**No silent auto-remediation.** Every change the tool makes must be explicitly authorized at runtime by the operator. There will never be a "fix everything" mode that skips the per-item confirmation for CAUTION or RISKY tier changes.

**No persistent agent or background service.** APEX is a run-once or scheduled-task tool. It does not install a service, register a startup entry, or maintain persistent state on the system it audits.

**No telemetry.** The tool does not report back to any server — not for usage statistics, crash reporting, or update checks. This is non-negotiable given its use in regulated and air-gapped environments.

**No dependency on external binaries beyond OS-native tools.** The only executables APEX invokes are those shipped with Windows (`netsh.exe`, `auditpol.exe`, `wevtutil.exe`, `wecutil.exe`, `net.exe`, `sc.exe`). It never requires Sysinternals tools, Python, .NET SDK, or any package that must be separately installed.

---

---

## v4.9 — Bug Fix, Security Hardening, and Optimization (2026-04-02)

### Bugs fixed in this release

| ID | File | Severity | Description |
|----|------|----------|-------------|
| B-1 | Engine\Core.ps1 | HIGH | `Invoke-Exe` potential deadlock: `ReadToEnd()` before `WaitForExit()`, stderr not drained, process handle never disposed |
| B-2 | Engine\CompatScan.ps1 | HIGH | Duplicate `switch -Regex` branches for SMB1/NTLM/LLMNR/NETBIOS caused `_ImpactWarning` to become an array when both printers AND mapped drives were present |
| B-3 | Engine\Core.ps1 + Remediate.ps1 + WebUI.ps1 | HIGH | `$LASTEXITCODE` not set by PowerShell cmdlets — failed cmdlet fixes silently reported as successful. Fixed by extracting `Invoke-FindingFix` helper with `$ErrorActionPreference = 'Stop'` |
| B-4 | Windows_Audit.ps1 | HIGH | `$baseline = $null` at line 284 overwrote the `-Baseline` parameter (PowerShell is case-insensitive) — any use of `-Baseline` to save a snapshot was silently broken. Renamed to `$baselineData` |
| B-5 | Windows_Audit.ps1 | MEDIUM | Guided post-scan baseline save: the `-Baseline` path collected from the wizard was set AFTER the baseline-copy block had already executed. Block moved to after guided post-scan |
| B-6 | Engine\CompatScan.ps1 | MEDIUM | All guide step text was in Italian while the rest of the codebase is English. Translated to English |
| B-7 | Engine\WebUI.ps1 | MEDIUM | `StreamReader` in POST body handler never disposed — handle leak on long-running WebUI sessions |
| B-8 | Checks\Check-Forensics.ps1 | MEDIUM | `wevtutil gl Security` output parsed with English-only `maxSize:` label — false positive on Italian/German/French Windows. Switched to `/f:xml` for locale-independent parsing |
| B-9 | Checks\Check-LocalAdmins.ps1 | MEDIUM | `net.exe localgroup Administrators` fallback used hardcoded English group name and English "The command completed" exit marker — both fail on non-English Windows. Resolved group by SID S-1-5-32-544 |

### Security hardening in this release

| ID | File | Description |
|----|------|-------------|
| S-1 | Engine\WebUI.ps1 | Added CSRF origin check: POST requests from foreign origins rejected with 403 |
| S-2 | Engine\WebUI.ps1 JS | `h()` escape function now also escapes single quotes (`'` → `&#39;`) closing onclick injection gap |
| S-3 | Engine\WebUI.ps1 | Added `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` security headers to all responses |

### Optimizations in this release

- **Engine\CompatScan.ps1**: Printer list uses `List<T>.Add()` instead of `$list +=` (O(n) vs O(n²))
- **Checks\Check-LocalAdmins.ps1**: Member list uses `List<T>.Add()` in net.exe fallback path
- **Checks\Check-SMB.ps1**: `Get-SmbServerConfiguration` called once, cached in `$srvCfg`, reused for SMBv1/signing/encryption checks (3 cmdlet calls → 1)
- **WebUI.ps1 JS**: Poll backs off to 10s interval after 5 consecutive server failures
- **WebUI.ps1 JS**: Search input debounced (200ms) — was triggering full DOM rebuild on every keystroke
- **WebUI.ps1 JS**: `window._modalConfirm` cleared when modal closes — prevents stale closure leak

### New guide entries added

- `SCHTASK-WRITABLE` — step-by-step guide to fix executable ACLs via icacls
- `SCHTASK-SYSTEM` — guide to audit SYSTEM-level scheduled tasks
- `UNQUOTED_SERVICE_PATH` — guide to quote service binary paths via sc.exe

### Candidate improvements identified by code audit (not yet implemented)

See items F-1 through F-18 in the checks table and P-1 through P-6 in the features table below.

| # | Type | Description |
|---|------|-------------|
| F-1 | Check | Password policy: minimum length, lockout, complexity via `net accounts` / `secedit` |
| F-2 | Check | Defender signature freshness (`AntivirusSignatureAge > 7 days`) |
| F-3 | Check | Tamper Protection status (`IsTamperProtected`) |
| F-4 | Check | Pending Windows updates / days since last security patch |
| F-5 | Check | AutoRun/AutoPlay registry policy |
| F-6 | Check | WinRM remote management exposure |
| F-7 | Check | Guest account enabled status |
| F-8 | Check | Screen lock / screensaver timeout policy |
| F-9 | Check | DNS over HTTPS (DoH) configuration |
| F-10 | Check | PowerShell transcription logging enabled |
| F-11 | Check | CredSSP delegation configuration |
| F-12 | Check | Network profile assignment (Public vs Private) |
| F-13 | Check | USB storage restrictions (`USBSTOR\Start`) |
| F-14 | Check | Weak TLS/Schannel configuration (TLS 1.0/1.1, RC4) |
| F-15 | Check | Local security policy user-rights audit via `secedit` |
| F-16 | Check | AppLocker/WDAC detailed rule enumeration |
| F-17 | Check | Vulnerable/outdated software inventory |
| F-18 | Check | Hyper-V / Windows Sandbox status |
| P-1 | Feature | CSV export for SIEM ingestion |
| P-2 | Feature | PDF report for formal delivery |
| P-3 | Feature | Remote scan via WinRM/CIM sessions |
| P-4 | Feature | Scheduled scan via Task Scheduler |
| P-5 | Feature | Differential alerts (email/webhook on regression vs baseline) |
| P-6 | Feature | Finding suppression with justification |

---

## v4.9.1 — Guide Toggle Fix + Missing Compatibility Warnings (2026-04-02)

### Bug fixed

**Guide sections auto-closed after opening (WebUI).**
Root cause: `render()` did a full `innerHTML` replacement of `#app` on every data change, destroying all expanded guide `<div>` elements. The 2-second poll would trigger `render()` immediately after a user expanded a guide, collapsing it.
Fix: open guide IDs are now tracked in a JS `Set` (`openGuides`). `restoreGuides()` is called at the end of every `render()` to re-expand any guide that was open before the DOM was rebuilt.

### Missing compatibility warnings added

8 finding IDs that could break services, drivers, or network connectivity had no `_ImpactWarning`. Added to `Engine\CompatScan.ps1`:

| Finding | Warning type |
|---------|-------------|
| `FW-SVC` | CONNECTIVITY — firewall service re-enable may block all inbound immediately |
| `PPL` | DRIVER RISK — LSASS PPL may break 3rd-party auth/security software; reboot required |
| `RDP-NLA` | SESSION RISK — NLA requirement may lock out older RDP clients |
| `CFA` | APPLICATION RISK — Controlled Folder Access blocks apps until whitelisted |
| `ASR` | APPLICATION RISK — Block mode may break Office macros and WMI subscriptions |
| `EXPROT-DEP` | APPLICATION RISK — system-wide DEP may crash legacy 32-bit apps |
| `EXPROT-ASLR` | APPLICATION RISK — Force ASLR may crash apps with non-relocatable DLLs |
| `UNQUOTED_SERVICE_PATH` | SERVICE RISK — sc.exe path change could prevent service start |

### WebUI UX improvement

CAUTION and RISKY confirm modals now display the finding's specific `_ImpactWarning` text instead of the previous generic "may affect legacy devices" message. Falls back to generic text when no warning is present.

### Documentation

README fully rewritten: updated to v4.9.1, added WebUI usage, `-WebUI`/`-Port` flags, peripheral-aware warnings table, `Engine\CompatScan.ps1` and `Engine\Wizard.ps1` in project structure, updated JSON schema to v4.9 format (includes `_Tier`, `_FixType`, `_ImpactWarning`, `_Guide`, `_Shortcut`, `peripherals`, `scores` fields), added step 8–9 to "Adding a new check" guide.

*Last updated: 2026-04-02 — v4.9.1 (guide toggle fix, missing compat warnings, modal UX, README rewrite)*

---

## v4.9.2 — Manual → Auto Fix Conversion + Pre-checks + Zero-Trace (2026-04-02)

### Manual → Auto fix conversions

4 findings previously marked Manual (text descriptions ending in `.`) are now Auto-applicable from the WebUI and the `-Remediate` TUI loop:

| Finding | Old fix (Manual) | New fix (Auto) | Tier |
|---------|-----------------|---------------|------|
| `NETBIOS` | UI walkthrough via NIC Properties | Registry write to `NetBT\Parameters\Interfaces` | CAUTION |
| `VBS` | Windows Security > Core Isolation UI | Registry write `EnableVirtualizationBasedSecurity=1` | RISKY |
| `HVCI` | Windows Security > Core Isolation UI | Registry write `Scenarios\HVCI\Enabled=1` | RISKY |
| `FWRISK` | Review rules in wf.msc manually | `Disable-NetFirewallRule` on unowned/ungrouped Public rules | CAUTION |

Registry paths for NETBIOS, VBS, and HVCI are matched by the existing `Backup-FindingState` regex — backups are automatic.

### Pre-checks before applying fixes

**VBS / HVCI — firmware virtualization check:**
`Check-DeviceGuard.ps1` now reads `VirtualizationFirmwareEnabled` from `Win32_DeviceGuard` before emitting VBS and HVCI findings. On hardware where VT-x/AMD-V is not enabled in firmware:
- `Confidence` is set to `NotApplicable`
- `Fix` is set to `N/A` → `_FixType = None` → not shown as fixable in the WebUI
- The note explains the firmware constraint

On capable hardware the findings remain CRITICAL/HIGH with the auto fix command.

**FWRISK — third-party firewall detection:**
`Check-Firewall.ps1` queries `root\SecurityCenter2 FirewallProduct` before the FWRISK finding. If a third-party firewall product is registered:
- `Fix` is set to `N/A` (modifying Windows Firewall rules would have no security effect)
- The note says `Third-party firewall detected; Windows Firewall rules are not the primary control.`

On systems using only native Windows Firewall the auto fix is available and only disables rules with no `Group` and no `Owner` — all built-in Windows rules (printers, mDNS, Wi-Fi Direct, etc.) are preserved.

### BLPBA — guided admin PowerShell launch

`BLPBA` remains Manual (BitLocker PIN must be entered interactively, cannot be set from a browser). The guide shortcut is upgraded from `gpedit.msc` to a direct admin PowerShell launcher:
- Shortcut opens an elevated PowerShell window
- The window automatically sets the three required GPO registry keys (`UseAdvancedStartup`, `UseEnhancedPin`, `UseTPMPIN`)
- On-screen instructions guide the user to run `manage-bde -protectors -add C: -TPMAndPIN`
- Alphanumeric PINs are supported

### Firewall rule backup and undo

`Engine\Remediate.ps1` now supports a new backup type for the FWRISK auto fix:
- **Backup:** Before disabling rules, `Backup-FindingState` captures `Name` + `DisplayName` for every affected rule into a `_fwrules.json` file
- **Undo:** `Invoke-RemediationUndo` now restores `*_fwrules.json` files, re-enabling each rule by name via `Enable-NetFirewallRule`

### Zero-trace system

**Problem:** `C:\ProgramData\ApexAudit\Backups\` accumulated `.reg`, `_svc.json`, `_fwrules.json`, and `manifest.json` files indefinitely across sessions with no cleanup.

**Solution:** New `Remove-BackupDir` function in `Engine\Remediate.ps1`.
- Removes the backup directory tree recursively
- Removes the parent `ApexAudit\` directory if it becomes empty
- Called in the `finally` block of both `Windows_Audit.ps1` and `Engine\WebUI.ps1`

**New `-KeepBackups` switch in `Windows_Audit.ps1`:**

| Invocation | Behavior |
|-----------|---------|
| `.\Windows_Audit.ps1 -Remediate` | Backups cleaned on exit (default) |
| `.\Windows_Audit.ps1 -Remediate -KeepBackups` | Backups preserved for manual undo |
| `.\Windows_Audit.ps1 -WebUI` | Session backups cleaned on WebUI exit |
| `.\Windows_Audit.ps1 -CleanOnExit` | Report + log + backups all cleaned (full zero-trace) |

The ephemeral log in `%TEMP%` was already cleaned by `Remove-LogFile`; JSON/HTML reports by `-CleanOnExit`. With this release, backups complete the zero-trace picture.

### CompatScan cleanup

- Stale guides for `VBS`, `HVCI`, `NETBIOS`, `FWRISK` removed from `$guides` (Auto-fix findings never show guides in the WebUI)
- `FWRISK` `_ImpactWarning` added: describes which rules are affected and how to restore via `wf.msc`

*Last updated: 2026-04-02 — v4.9.2 (Manual→Auto conversions, pre-checks, firewall backup/undo, zero-trace cleanup)*
