# APEX Zero-Trust Windows Auditor

> **Offline, standalone Windows security auditor and guided hardening tool — written in PowerShell. No internet connection, no cloud, no external agents.**

**v3.0** — 21 check domains · 57+ finding IDs · CIS / DISA STIG / NIST 800-171r2 compliance mapping · interactive remediation with backup and undo

---

## Features

- **Read-only by default** — collects configuration signals only; never changes anything without explicit `-Remediate`
- **Fully offline** — uses only OS-native channels (Registry, CIM/WMI, built-in cmdlets, `netsh`, `auditpol`, `wevtutil`)
- **Dual scoring** — SeverityScore (CRITICAL/HIGH exposure) and HygieneScore (MEDIUM/LOW hygiene), both 0–100
- **Delta engine** — baseline a known-good state, re-run after changes; the HTML report gains a Δ tab showing regressions, improvements, and new checks
- **Compliance mapping** — every finding annotated with CIS L1/L2, DISA STIG, and NIST 800-171r2 control IDs
- **Guided remediation** — interactive fix loop with safety tiers (SAFE / CAUTION / RISKY), automatic backup before every change, and full undo
- **Self-contained HTML report** — single file, no internet required, dark-themed with compliance badge rendering
- **Structured JSON output** — machine-readable, schema-stable, suitable for CI pipelines and SIEM ingestion

---

## Project structure

```
apex-auditor/
├── Windows_Audit.ps1              ← entry point (param block, manifest, main loop)
├── Engine/
│   ├── Core.ps1                   ← findings accumulator, helpers, scoring, delta, compliance
│   ├── Report.ps1                 ← TUI console report, HTML exporter, path resolver
│   └── Remediate.ps1              ← backup, interactive fix loop, undo
├── Checks/
│   ├── Check-ASR.ps1              ← Attack Surface Reduction rules
│   ├── Check-AuditPol.ps1         ← Advanced audit subcategories (6 sub-checks)
│   ├── Check-Baseline.ps1         ← TPM, Secure Boot, BitLocker, Defender, Windows Update
│   ├── Check-CertStore.ps1        ← Root CA hygiene, expired personal certificates
│   ├── Check-DefenderExclusions.ps1  ← Dangerous exclusion extensions and paths
│   ├── Check-DeviceGuard.ps1      ← VBS, HVCI, WDAC/UMCI, Credential Guard
│   ├── Check-ExploitProtection.ps1   ← DEP, ASLR, CFG system-wide
│   ├── Check-Firewall.ps1         ← Per-profile firewall state, risky inbound rules
│   ├── Check-FirewallPosture.ps1  ← MpsSvc health, drop logging
│   ├── Check-Forensics.ps1        ← PS script-block logging, cmdline logging, Security log
│   ├── Check-Identity.ps1         ← WDigest, LSASS PPL, RID-500, LAPS, UAC
│   ├── Check-LocalAdmins.ps1      ← Local Administrators group membership
│   ├── Check-Network.ps1          ← LLMNR, NetBIOS, NTLM auth level
│   ├── Check-PrintSpooler.ps1     ← Print Spooler service + PointAndPrint + spool dir ACL
│   ├── Check-PS2Engine.ps1        ← PowerShell v2 engine availability
│   ├── Check-RDP.ps1              ← RDP enabled state, NLA enforcement
│   ├── Check-ScheduledTasks.ps1   ← Writable task executables, SYSTEM tasks, orphaned authors
│   ├── Check-ServicePaths.ps1     ← Unquoted service executable paths (Deep only)
│   ├── Check-SMB.ps1              ← SMBv1, signing server+client, encryption
│   ├── Check-Telemetry.ps1        ← Sysmon presence (informational)
│   └── Check-WEF.ps1              ← Windows Event Forwarding subscriptions (Deep only)
├── compliance_map.json            ← CIS / DISA STIG / NIST 800-171r2 control mapping
├── Invoke-AuditLabTest.ps1        ← Full scientific test harness (Suites S1–S9)
└── ExTest.ps1                     ← Convenience wrapper for the test harness
```

All layers must be present side-by-side. `Windows_Audit.ps1` dot-sources `Engine\Core.ps1`, `Engine\Report.ps1`, and `Engine\Remediate.ps1` outside the main `try/catch`, then dot-sources every `Checks\Check-*.ps1` via a glob. Missing files cause immediate `CommandNotFoundException`.

---

## Requirements

- Windows 10 / 11 (x64)
- PowerShell 5.1 (Windows PowerShell) or PowerShell 7+
- **Run as Administrator** — required for full WMI/CIM coverage, BitLocker status, and audit policy reads
- All `Engine\` and `Checks\` files present in the directory structure above

---

## Quick start

```powershell
# From an elevated PowerShell prompt in the script directory:
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Windows_Audit.ps1
```

Default: Deep mode, PersonalLaptop profile, auto-named JSON + HTML in the current directory.

---

## Usage

### Core audit

```powershell
.\Windows_Audit.ps1                                    # Deep scan, PersonalLaptop profile
.\Windows_Audit.ps1 -Mode Fast -Profile Enterprise     # Fast scan, Enterprise profile
.\Windows_Audit.ps1 -Mode Deep -SkipHTML               # JSON only — CI-friendly
.\Windows_Audit.ps1 -Mode Deep -ExportJSON "C:\Audits\audit.json"
```

**Modes:**

| Mode | Checks | Notes |
|------|--------|-------|
| `Fast` | 18 | All checks except `Check-WEF` and `Check-ServicePaths` (deep analysis only) and `Check-ScheduledTasks` (deep only) |
| `Deep` | 21 | Full posture — all checks including WEF subscription enumeration, unquoted service path analysis, and scheduled task ACL inspection |

**Profiles** — stored in the JSON context field:

| Profile | Intended threat model |
|---------|----------------------|
| `PersonalLaptop` | Personal device, consumer posture (default) |
| `Enterprise` | Domain-joined workstation, corporate baseline |
| `Lab` | Test/dev environment |
| `Paranoid` | High-value targets, strictest interpretation |

### Baseline and delta tracking

```powershell
# Capture baseline at a known-good state
.\Windows_Audit.ps1 -Baseline "C:\Baselines\before_patch.json"

# Compare after changes (patches, config drift, new software)
.\Windows_Audit.ps1 -CompareTo "C:\Baselines\before_patch.json" -ExportJSON "C:\Audits\after.json"
```

The HTML report gains a **Δ Delta** tab showing regressions, improvements, and new checks side-by-side.

### Remediation mode

```powershell
# Interactive fix loop after the audit report
.\Windows_Audit.ps1 -Remediate
```

For each vulnerable finding the tool displays the finding, its safety tier, and the exact fix command, then prompts:

```
[Y]es  [N]o  [A]ll-safe  [S]kip-remaining  [Q]uit
```

**Safety tiers:**

| Tier | Behaviour | Examples |
|------|-----------|---------|
| `SAFE` | Can be batch-applied with `[A]` | WDigest disable, PS logging keys, SMB signing flags |
| `CAUTION` | Requires per-item confirmation | LLMNR/NetBIOS, SMB encryption, Spooler service |
| `RISKY` | Requires typing `YES` explicitly — never batch-applied | BitLocker, PPL, VBS, UAC, SMB1 removal |

Before every applied fix, the tool exports the affected registry hive (`.reg`) or service state (`.json`) to `C:\ProgramData\ApexAudit\Backups\<timestamp>\`.

### Undo

```powershell
# Restore all registry exports and service states from a previous remediation run
.\Windows_Audit.ps1 -Undo "C:\ProgramData\ApexAudit\Backups\20260330_120000"
```

### Other options

```powershell
.\Windows_Audit.ps1 -ShowSignals   # Append raw ASR rule GUIDs + actions to JSON
.\Windows_Audit.ps1 -NoTUI         # Suppress console output
.\Windows_Audit.ps1 -Help          # Full help
.\Windows_Audit.ps1 -Version       # Version string
```

---

## Check domains

| Category | Check file | Finding IDs | Mode |
|----------|-----------|-------------|------|
| Baseline | Check-Baseline.ps1 | TPM, SBOOT, BLENC, BLPBA, RTP, PUA, CFA, WU | Fast+Deep |
| DeviceGuard | Check-DeviceGuard.ps1 | VBS, HVCI, UMCI, CG | Fast+Deep |
| Firewall | Check-Firewall.ps1 | FW-Domain, FW-Private, FW-Public, FWRISK | Fast+Deep |
| FirewallPosture | Check-FirewallPosture.ps1 | FW-SVC, FW-LOG | Fast+Deep |
| SMB | Check-SMB.ps1 | SMB1, SMBSIGS, SMBSIGC, SMBENC | Fast+Deep |
| RDP | Check-RDP.ps1 | RDP, RDP-NLA | Fast+Deep |
| Network | Check-Network.ps1 | LLMNR, NETBIOS, NTLM | Fast+Deep |
| Identity | Check-Identity.ps1 | WDIG, PPL, SID500, LAPS, UAC, UAC-SD | Fast+Deep |
| LocalAdmins | Check-LocalAdmins.ps1 | LOCALADMIN | Fast+Deep |
| Defender | Check-DefenderExclusions.ps1 | DEFEXCL-EXT, DEFEXCL-PATH, DEFEXCL-COUNT | Fast+Deep |
| ExploitProt | Check-ExploitProtection.ps1 | EXPROT-DEP, EXPROT-ASLR, EXPROT-CFG | Fast+Deep |
| Forensics | Check-Forensics.ps1 | PSLOG, CMDLINE, SECLOG | Fast+Deep |
| Telemetry | Check-Telemetry.ps1 | SYSMON | Fast+Deep |
| ASR | Check-ASR.ps1 | ASR | Fast+Deep |
| AuditPolicy | Check-AuditPol.ps1 | AUDITPOL_PROCESS_CREATION, _CREDENTIAL_VALID, _LOGON, _LOCKOUT, _SPECIAL_LOGON, _GROUP_MGMT | Fast+Deep |
| PrintSpooler | Check-PrintSpooler.ps1 | SPOOLER-SVC, SPOOLER-PNP, SPOOLER-DIR | Fast+Deep |
| PS2Engine | Check-PS2Engine.ps1 | PS2ENGINE | Fast+Deep |
| CertStore | Check-CertStore.ps1 | CERT-NONMS, CERT-EXPIRED | Fast+Deep |
| EventFwd | Check-WEF.ps1 | WEF | **Deep only** |
| Services | Check-ServicePaths.ps1 | UNQUOTED_SERVICE_PATH:\<svcname\> | **Deep only** |
| SchedTasks | Check-ScheduledTasks.ps1 | SCHTASK-WRITABLE, SCHTASK-SYSTEM, SCHTASK-NOAUTHOR | **Deep only** |

---

## JSON output schema (v3.0)

```json
{
  "Context": {
    "Hostname":     "string",
    "OSCaption":    "string",
    "OSBuild":      "string",
    "DomainJoined": "bool",
    "IsPortable":   "bool",
    "TimestampUTC": "yyyy-MM-ddTHH:mm:ssZ",
    "Mode":         "Fast|Deep",
    "Profile":      "PersonalLaptop|Enterprise|Lab|Paranoid",
    "PSVersion":    "string"
  },
  "ScoreBefore":  "int (0–100; Critical/High exposure — lower = more exposed)",
  "HygieneScore": "int (0–100; Medium/Low hygiene — lower = worse hygiene)",
  "ScoreAfter":   "-1 (reserved for post-remediation delta)",
  "Delta":        "null | { BaselineTimestamp, BaselineMode, SeverityScoreDelta, HygieneScoreDelta, Regressions[], Improvements[], NewChecks[] }",
  "Findings": [
    {
      "Id":             "string — unique per run",
      "Category":       "string",
      "CheckName":      "string",
      "Severity":       "CRITICAL | HIGH | MEDIUM | LOW | PASS",
      "Vulnerable":     "bool",
      "Confidence":     "High | Medium | Low | NotApplicable | NoAccess | QueryFailed",
      "Observed":       "string — what was found",
      "Expected":       "string — what the baseline requires",
      "Source":         "string — registry path, CIM class, cmdlet, or exe",
      "Fix":            "string — exact remediation command or guidance",
      "Note":           "string",
      "ComplianceRefs": {
        "CIS":       ["string"],
        "CIS_Level": "int (1 or 2)",
        "STIG":      ["string"],
        "NIST":      ["string"]
      }
    }
  ]
}
```

**Scoring:**
```
SeverityScore = 100 − Σ(CRITICAL×15 + HIGH×8)   [floor 0]
HygieneScore  = 100 − Σ(MEDIUM×5   + LOW×2)     [floor 0]
```

**Exit codes:** `0` = no vulnerabilities · `1` = vulnerabilities found · `2` = fatal error

**Schema invariants:**
- `Vulnerable=true` never co-exists with `Severity=PASS`
- `Confidence=NoAccess` never has `Vulnerable=true`
- Every `Vulnerable=true` finding has a non-`N/A` Fix field
- All finding IDs are unique within a single run
- `ComplianceRefs` present on all findings when `compliance_map.json` is found

---

## Running the test suite

```powershell
.\ExTest.ps1 -AuditScript .\Windows_Audit.ps1                         # All suites
.\ExTest.ps1 -AuditScript .\Windows_Audit.ps1 -ExportJUnit            # + JUnit XML for CI
.\Invoke-AuditLabTest.ps1 -AuditScript .\Windows_Audit.ps1 -Suites S1,S2,S9
.\Invoke-AuditLabTest.ps1 -AuditScript .\Windows_Audit.ps1 -SkipMatrix  # Faster on slow machines
```

| Suite | Validates |
|-------|-----------|
| S1 | Static analysis: AST parse, UTF-8 no BOM, PSScriptAnalyzer, typed params, help block, 21 check functions present |
| S2 | JSON schema: top-level fields, Context values, score ranges, Findings array, Severity/Confidence enums, unique IDs, schema invariants, Fix coverage |
| S3 | Smoke matrix: 5 mode×profile combinations — exit code + JSON + HTML produced |
| S4 | Exit code contract: 0 when clean, 1 when findings exist |
| S5 | Idempotency: two consecutive Deep runs produce identical JSON |
| S6 | Performance: Fast and Deep complete within bounds; Fast ≤ Deep elapsed |
| S7 | Boundary cases: `-Help`, `-Version`, invalid Mode/Profile, unwritable path, `-SkipHTML`, `-CompareTo` missing file |
| S8 | Delta engine: baseline write, compare, Delta object structure, score polarity |
| S9 | Check coverage: verifies all expected finding IDs present in Deep output |

---

## Adding a new check

1. Create `Checks\Check-<Domain>.ps1` with a single exported function `Invoke-Check<Domain>`.
2. Add an entry to `$Script:CheckManifest` in `Windows_Audit.ps1`: `Fn`, `Modes` array, `NeedsAdmin`, `Phase`.
3. Every signal must call `Add-Finding` with all mandatory fields. Use `Fix = 'N/A'` only when a control is genuinely non-remediable.
4. Wrap every external query in its own `try/catch` returning `Confidence='QueryFailed'` — never let exceptions propagate.
5. If multiple findings share a single `try` block, use the rollback pattern (`$countBefore = $Script:Findings.Count`) to prevent partial finding sets on failure.
6. Add the new finding IDs to `compliance_map.json`.
7. Add the IDs to S9's expected-ID list in `Invoke-AuditLabTest.ps1`.
8. Run `.\ExTest.ps1 -AuditScript .\Windows_Audit.ps1 -Suites S1,S2,S9` before opening a PR.

---

## License

MIT — see `LICENSE`.
