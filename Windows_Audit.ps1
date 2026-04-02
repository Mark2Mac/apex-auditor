#Requires -Version 5.1
<#
.SYNOPSIS
    APEX Zero-Trust Enterprise Audit v3.0 -- standalone Windows security posture scanner.

.DESCRIPTION
    Collects security signals from a live Windows system, evaluates posture against a
    Zero-Trust baseline, and produces a JSON report, a self-contained HTML report, and an
    optional console TUI.

    Architecture (split build):
      Windows_Audit.ps1     -- entry point (this file); param block, manifest, main loop
      Engine\Core.ps1       -- Add-Finding, helpers, scoring, delta engine, compliance refs
      Engine\Report.ps1     -- Write-TUIReport, Export-HTMLReport, Resolve-ExportPath
      Engine\Remediate.ps1  -- Backup, interactive fix loop, undo
      Checks\Check-*.ps1    -- one file per check domain (21 functions)
      compliance_map.json   -- CIS / DISA STIG / NIST 800-171r2 finding-to-control mapping

    v3.0 changes (v2.5 -> v3.0):
      Compliance mapping: all findings annotated with CIS L1/L2, DISA STIG, NIST 800-171r2.
      Remediation mode (-Remediate): interactive fix loop with SAFE/CAUTION/RISKY tiers and
        automatic backup before every applied fix.
      Undo mode (-Undo): restore system state from a backup directory.
      Four new check domains: PrintSpooler, PS2Engine, ScheduledTasks (Deep), CertStore.

.PARAMETER Mode
    Scan depth. Fast = critical checks only. Deep = full posture. Default: Deep.

.PARAMETER Profile
    Risk profile. PersonalLaptop | Enterprise | Lab | Paranoid. Default: PersonalLaptop.

.PARAMETER ExportJSON
    Full path for the JSON report. Auto-generated in current directory if omitted.

.PARAMETER ExportHTML
    Full path for the HTML report. Defaults to ExportJSON with .html extension.

.PARAMETER SkipHTML
    Suppress HTML report generation (CI pipelines that only need JSON).

.PARAMETER CompareTo
    Path to a previous audit_report JSON. Enables delta computation and the HTML Delta tab.

.PARAMETER Baseline
    Path where the current output will ALSO be written after the run completes.

.PARAMETER NoTUI
    Suppress console output.

.PARAMETER ShowSignals
    Append raw ASR signal data to the exported JSON.

.PARAMETER Version
    Print version string and exit 0.

.PARAMETER Remediate
    After the audit report, enter interactive remediation mode. For each vulnerable finding,
    prompt to apply the pre-built fix command. Backups are created automatically before each
    applied fix in C:\ProgramData\ApexAudit\Backups\<timestamp>\. Requires elevation for
    some fixes (RISKY tier). RISKY-tier fixes require typing YES explicitly.

.PARAMETER Undo
    Path to a backup directory created by a previous -Remediate run. Restores all registry
    exports and service states found in the backup. Run without any checks.

.PARAMETER Help
    Print this help block and exit 0.

.EXAMPLE
    .\Windows_Audit.ps1
    .\Windows_Audit.ps1 -Mode Fast -Profile Enterprise
    .\Windows_Audit.ps1 -Baseline C:\Baselines\jan.json
    .\Windows_Audit.ps1 -CompareTo C:\Baselines\jan.json
    .\Windows_Audit.ps1 -NoTUI -SkipHTML -CompareTo .\baseline.json -ExportJSON .\current.json
    .\Windows_Audit.ps1 -Remediate
    .\Windows_Audit.ps1 -Undo 'C:\ProgramData\ApexAudit\Backups\20260330_120000'
#>
[CmdletBinding()]
param(
    [ValidateSet('Fast','Deep')]
    [string] $Mode       = 'Deep',

    [ValidateSet('PersonalLaptop','Enterprise','Lab','Paranoid')]
    [string] $Profile    = 'PersonalLaptop',

    [string] $ExportJSON = '',
    [string] $ExportHTML = '',
    [string] $CompareTo  = '',
    [string] $Baseline   = '',
    [switch] $SkipHTML,
    [switch] $NoTUI,
    [switch] $ShowSignals,
    [switch] $Remediate,
    [string] $Undo       = '',
    [string] $Portable   = '',   # All output to this dir; defaults to $PSScriptRoot if passed without value
    [switch] $CleanOnExit,       # Delete JSON+HTML on exit (backups are always kept)
    [switch] $Guided,            # Interactive wizard mode
    [switch] $WebUI,             # Launch interactive localhost web dashboard
    [switch] $Version,
    [switch] $Help
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# Portable flag without an explicit path -> default to script's own directory
if ($PSBoundParameters.ContainsKey('Portable') -and ($Portable -eq '')) {
    $Portable = $PSScriptRoot
}
$Script:GeneratedFiles = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
#  DOT-SOURCE ENGINE AND CHECKS
# ---------------------------------------------------------------------------
$Script:RootDir = $PSScriptRoot

. (Join-Path $Script:RootDir 'Engine\Core.ps1')
. (Join-Path $Script:RootDir 'Engine\Report.ps1')
. (Join-Path $Script:RootDir 'Engine\Remediate.ps1')
. (Join-Path $Script:RootDir 'Engine\CompatScan.ps1')
if ($WebUI) { . (Join-Path $Script:RootDir 'Engine\WebUI.ps1') }

$checkFiles = Get-ChildItem -Path (Join-Path $Script:RootDir 'Checks') -Filter 'Check-*.ps1' |
              Sort-Object Name
foreach ($f in $checkFiles) { . $f.FullName }

# ---------------------------------------------------------------------------
#  CONSTANTS
# ---------------------------------------------------------------------------
$Script:TOOL_VERSION  = '4.9.1'
$Script:BUILD_DATE    = '2026-04-01'
$Script:SCORE_WEIGHTS = @{ CRITICAL=15; HIGH=8; MEDIUM=5; LOW=2 }
$Script:CimSession    = $null

# Initialize ephemeral log in TEMP -- auto-deleted on clean exit via Remove-LogFile
try {
    $Script:LogFile = Join-Path $env:TEMP "apex_audit_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
    Write-Log "APEX v$Script:TOOL_VERSION started. Admin=$Script:IsAdmin Host=$env:COMPUTERNAME"
} catch { $Script:LogFile = $null }

# ---------------------------------------------------------------------------
#  CHECK MANIFEST
# ---------------------------------------------------------------------------
$Script:CheckManifest = @(
    @{ Fn='Invoke-CheckBaseline';           Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='Baseline'      }
    @{ Fn='Invoke-CheckDeviceGuard';        Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='DeviceGuard'   }
    @{ Fn='Invoke-CheckFirewall';           Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='Firewall'      }
    @{ Fn='Invoke-CheckFirewallPosture';    Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='FWPosture'     }
    @{ Fn='Invoke-CheckSMB';               Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='SMB'           }
    @{ Fn='Invoke-CheckRDP';               Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='RDP'           }
    @{ Fn='Invoke-CheckNetwork';           Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='Network'       }
    @{ Fn='Invoke-CheckIdentity';          Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='Identity'      }
    @{ Fn='Invoke-CheckLocalAdmins';       Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='LocalAdmins'   }
    @{ Fn='Invoke-CheckDefenderExclusions';Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='DefenderExcl'  }
    @{ Fn='Invoke-CheckExploitProtection'; Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='ExploitProt'   }
    @{ Fn='Invoke-CheckForensics';         Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='Forensics'     }
    @{ Fn='Invoke-CheckTelemetry';         Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='Telemetry'     }
    @{ Fn='Invoke-CheckASR';               Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='ASR'           }
    @{ Fn='Invoke-CheckAuditPol';          Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='AuditPolicy'   }
    @{ Fn='Invoke-CheckWEF';               Modes=@('Deep');        NeedsAdmin=$false; Phase='EventFwd'      }
    @{ Fn='Invoke-CheckServicePaths';      Modes=@('Deep');        NeedsAdmin=$false; Phase='Services'      }
    @{ Fn='Invoke-CheckPrintSpooler';      Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='PrintSpooler'  }
    @{ Fn='Invoke-CheckPS2Engine';         Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='PS2Engine'     }
    @{ Fn='Invoke-CheckCertStore';         Modes=@('Fast','Deep'); NeedsAdmin=$false; Phase='CertStore'     }
    @{ Fn='Invoke-CheckScheduledTasks';    Modes=@('Deep');        NeedsAdmin=$false; Phase='SchedTasks'    }
)

# ---------------------------------------------------------------------------
#  COLORED HELP
# ---------------------------------------------------------------------------
function Show-ColoredHelp {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','')]
    param()
    $c  = 'Cyan'; $w = 'White'; $g = 'DarkGray'; $dc = 'DarkCyan'; $y = 'Yellow'
    Write-Host ''
    Write-Host "  APEX Zero-Trust Windows Auditor v$($Script:TOOL_VERSION)  ($($Script:BUILD_DATE))" -ForegroundColor $c
    Write-Host ('  ' + '-' * 60) -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host '  QUICK START' -ForegroundColor $c
    Write-Host '    .\Windows_Audit.ps1                     ' -NoNewline -ForegroundColor $w
    Write-Host '# Guided wizard (auto-detect everything)'    -ForegroundColor $g
    Write-Host '    .\Windows_Audit.ps1 -Mode Deep           ' -NoNewline -ForegroundColor $w
    Write-Host '# Full scan, default profile'                -ForegroundColor $g
    Write-Host '    .\Windows_Audit.ps1 -Remediate           ' -NoNewline -ForegroundColor $w
    Write-Host '# Scan + guided fix loop'                    -ForegroundColor $g
    Write-Host '    .\Windows_Audit.ps1 -WebUI               ' -NoNewline -ForegroundColor $w
    Write-Host '# Launch live web dashboard'                 -ForegroundColor $g
    Write-Host ''
    Write-Host '  SCAN OPTIONS' -ForegroundColor $c
    Write-Host '    -Mode <Fast|Deep>          ' -NoNewline -ForegroundColor $w
    Write-Host 'Scan depth. Fast=18 checks, Deep=21. Default: Deep'      -ForegroundColor $g
    Write-Host '    -Profile <PersonalLaptop|Enterprise|Lab|Paranoid>'    -ForegroundColor $w
    Write-Host '                               ' -NoNewline -ForegroundColor $w
    Write-Host 'Risk profile label. Default: PersonalLaptop'              -ForegroundColor $g
    Write-Host '    -Guided                    ' -NoNewline -ForegroundColor $w
    Write-Host 'Step-by-step setup wizard (auto-activates on bare run)'   -ForegroundColor $g
    Write-Host ''
    Write-Host '  OUTPUT OPTIONS' -ForegroundColor $c
    Write-Host '    -ExportJSON <path>         ' -NoNewline -ForegroundColor $w
    Write-Host 'JSON report path (auto-generated if omitted)'             -ForegroundColor $g
    Write-Host '    -ExportHTML <path>         ' -NoNewline -ForegroundColor $w
    Write-Host 'HTML report path (derived from JSON path if omitted)'     -ForegroundColor $g
    Write-Host '    -SkipHTML                  ' -NoNewline -ForegroundColor $w
    Write-Host 'Suppress HTML generation (CI pipelines)'                  -ForegroundColor $g
    Write-Host '    -NoTUI                     ' -NoNewline -ForegroundColor $w
    Write-Host 'Suppress all console output'                              -ForegroundColor $g
    Write-Host '    -ShowSignals               ' -NoNewline -ForegroundColor $w
    Write-Host 'Append raw ASR GUIDs to JSON output'                      -ForegroundColor $g
    Write-Host '    -Portable [path]           ' -NoNewline -ForegroundColor $w
    Write-Host 'All output to specified dir (USB-safe). Omit path = script dir'  -ForegroundColor $g
    Write-Host '    -CleanOnExit               ' -NoNewline -ForegroundColor $w
    Write-Host 'Delete JSON+HTML on exit (backups are always kept)'       -ForegroundColor $g
    Write-Host ''
    Write-Host '  COMPARISON & BASELINE' -ForegroundColor $c
    Write-Host '    -CompareTo <path>          ' -NoNewline -ForegroundColor $w
    Write-Host 'Compare against a previous report (shows Delta Delta tab)'   -ForegroundColor $g
    Write-Host '    -Baseline <path>           ' -NoNewline -ForegroundColor $w
    Write-Host 'Save this report as baseline for future comparisons'      -ForegroundColor $g
    Write-Host ''
    Write-Host '  REMEDIATION' -ForegroundColor $c
    Write-Host '    -Remediate                 ' -NoNewline -ForegroundColor $w
    Write-Host 'Interactive fix loop after scan (SAFE/CAUTION/RISKY tiers)'      -ForegroundColor $g
    Write-Host '    -Undo <backup-path>        ' -NoNewline -ForegroundColor $w
    Write-Host 'Restore system state from a previous remediation backup'  -ForegroundColor $g
    Write-Host ''
    Write-Host '  WEB DASHBOARD' -ForegroundColor $c
    Write-Host '    -WebUI                     ' -NoNewline -ForegroundColor $w
    Write-Host 'Launch live dashboard at http://localhost:86xx/ in browser'      -ForegroundColor $g
    Write-Host ''
    Write-Host '  EXAMPLES' -ForegroundColor $c
    Write-Host '    # Enterprise server, JSON only, no browser:'                  -ForegroundColor $dc
    Write-Host '    .\Windows_Audit.ps1 -Mode Deep -Profile Enterprise -NoTUI -SkipHTML' -ForegroundColor $y
    Write-Host ''
    Write-Host '    # USB portable scan -- all files on the stick, clean exit:'    -ForegroundColor $dc
    Write-Host '    .\Windows_Audit.ps1 -Portable E:\AuditResults -CleanOnExit'   -ForegroundColor $y
    Write-Host ''
    Write-Host '    # Compare against last month''s baseline:'                     -ForegroundColor $dc
    Write-Host '    .\Windows_Audit.ps1 -CompareTo .\jan_baseline.json'           -ForegroundColor $y
    Write-Host ''
    Write-Host '    # Full interactive session with web dashboard:'                -ForegroundColor $dc
    Write-Host '    .\Windows_Audit.ps1 -WebUI'                                   -ForegroundColor $y
    Write-Host ''
    Write-Host '  Exit codes: 0 = clean  1 = vulnerabilities found  2 = fatal error' -ForegroundColor DarkGray
    Write-Host ''
}

# ---------------------------------------------------------------------------
#  EARLY EXITS
# ---------------------------------------------------------------------------
if ($Help)    { Show-ColoredHelp; exit 0 }
if ($Version) { Write-Output "APEX Zero-Trust Enterprise Audit v$($Script:TOOL_VERSION) ($($Script:BUILD_DATE))"; exit 0 }
if ($Undo -ne '') {
    try   { Invoke-RemediationUndo -BackupPath $Undo }
    catch { Write-Warning "APEX Undo fatal error: $($_.Exception.Message)"; exit 2 }
    exit 0
}

# ---------------------------------------------------------------------------
#  GUIDED MODE TRIGGER
#  Activates on bare invocation (no params) or explicit -Guided.
#  Never activates when any explicit scan param is given (CI-safe).
# ---------------------------------------------------------------------------
$Script:InGuidedMode = $false
$isBareLaunch = ($PSBoundParameters.Count -eq 0)
if ($Guided -or $isBareLaunch) {
    . (Join-Path $Script:RootDir 'Engine\Wizard.ps1')
    $wizResult = Invoke-GuidedMode
    if ($wizResult) {
        $Mode    = $wizResult.Mode
        $Profile = $wizResult.Profile
        if ($wizResult.CompareTo -ne '') { $CompareTo = $wizResult.CompareTo }
        if ($wizResult.Baseline  -ne '') { $Baseline  = $wizResult.Baseline  }
    }
}

# ===========================================================================
#  MAIN
# ===========================================================================
$exitCode = 1
try {
    try   { $Script:CimSession = New-CimSession -ErrorAction Stop }
    catch { $Script:CimSession = $null; Write-TUI '[!] CIM session unavailable -- direct WMI fallback active' -Color Yellow }

    $baselineData = $null
    if ($CompareTo -ne '') {
        Write-TUI "[*] Loading baseline: $CompareTo"
        $baselineData = Read-BaselineJSON -Path $CompareTo
    }

    if (-not $Script:IsAdmin -and -not $Script:InGuidedMode) {
        Write-TUI ''
        Write-TUI '  [!] Running without administrator elevation.' -Color Yellow
        Write-TUI '      Limited checks: AuditPol, SMB Config, Firewall Policy,' -Color DarkYellow
        Write-TUI '      Firewall Logging, Security Log Size, Exploit Protection, WEF' -Color DarkYellow
        Write-TUI '      All remediation fixes require elevation.' -Color Yellow
        Write-TUI '      Re-run as Administrator for a complete assessment.' -Color Yellow
        Write-TUI ''
    }

    Write-TUI '[*] Phase 1/4  Context  -- collecting system metadata'
    $osInfo  = try { Get-Cim 'Win32_OperatingSystem' } catch { $null }
    $csInfo  = try { Get-Cim 'Win32_ComputerSystem'  } catch { $null }
    $encInfo = try { Get-Cim 'Win32_SystemEnclosure' } catch { $null }

    $context = [PSCustomObject]@{
        Hostname        = $env:COMPUTERNAME
        OSCaption       = if ($osInfo)  { $osInfo.Caption.Trim()  } else { 'Unknown' }
        OSBuild         = if ($osInfo)  { $osInfo.BuildNumber     } else { 'Unknown' }
        OSVersionName   = Get-OSVersionName
        DomainJoined    = if ($csInfo)  { [bool]$csInfo.PartOfDomain } else { $false }
        IsPortable      = if ($encInfo) { [bool]($encInfo.ChassisTypes | Where-Object { $_ -in @(8,9,10,11,12,14,18,21) }) } else { $false }
        IsAdmin         = $Script:IsAdmin
        ChassisType     = Get-ChassisTypeName -EnclosureInfo $encInfo -CSInfo $csInfo
        DetectedProfile = Get-DetectedProfile -DomainJoined ([bool]($csInfo -and $csInfo.PartOfDomain)) -ChassisType (Get-ChassisTypeName -EnclosureInfo $encInfo -CSInfo $csInfo)
        TimestampUTC    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Mode            = $Mode
        Profile         = $Profile
        PSVersion       = $PSVersionTable.PSVersion.ToString()
    }

    # Peripheral and network dependency detection (no admin required)
    $Script:Peripherals = Get-SystemPeripherals
    if ($Script:Peripherals.Printers.Count -gt 0) {
        $pSummary = "$($Script:Peripherals.LocalPrinters) local, $($Script:Peripherals.NetworkPrinters) network"
        if ($Script:Peripherals.SharedPrinters -gt 0) { $pSummary += ", $($Script:Peripherals.SharedPrinters) shared" }
        Write-TUI "  Printers         : $($Script:Peripherals.Printers.Count) ($pSummary)" -Color DarkCyan
    }
    if ($Script:Peripherals.SharedFolders.Count -gt 0) {
        Write-TUI "  Shared folders   : $($Script:Peripherals.SharedFolders.Count)" -Color DarkCyan
    }

    $jsonPath = Resolve-ExportPath
    $htmlPath = if ($ExportHTML -ne '') { $ExportHTML } else { [System.IO.Path]::ChangeExtension($jsonPath, '.html') }

    $activeChecks = @($Script:CheckManifest | Where-Object { $Mode -in $_.Modes })
    Write-TUI "[*] Phase 2/4  Checks   -- running $($activeChecks.Count) checks ($Mode mode, $Profile profile)"
    $idx = 0
    foreach ($chk in $activeChecks) {
        if ($chk.NeedsAdmin -and -not $Script:IsAdmin) { continue }
        $idx++
        Write-TUI "    [$idx/$($activeChecks.Count)] $($chk.Phase) ..."
        try { & $chk.Fn } catch { Write-TUI "    [!] $($chk.Fn): $($_.Exception.Message)" -Color Yellow }
    }

    $mapFile = Join-Path $Script:RootDir 'compliance_map.json'
    Get-ComplianceRefs -MapPath $mapFile
    Set-FindingRecommendations -Findings $Script:Findings -Profile $Profile
    Set-FindingImpactFlags     -Findings $Script:Findings -Peripherals $Script:Peripherals
    Set-FindingGuides          -Findings $Script:Findings

    Write-TUI '[*] Phase 3/4  Score    -- computing Severity + Hygiene + Delta'
    $scores    = Measure-AuditScore    -Findings $Script:Findings
    $delta     = Compare-AuditBaseline -Baseline $baselineData -CurrentFindings $Script:Findings -CurrentScores $scores
    $vulnCount = @($Script:Findings | Where-Object { $_.Vulnerable }).Count

    if ($delta -and -not $NoTUI) {
        $signFn = { param([double]$v); if ($v -ge 0) { "+$v" } else { "$v" } }
        $sc2    = if ($delta.SeverityScoreDelta -ge 0) { 'Green' } else { 'Red' }
        Write-TUI "    Delta: Severity $(& $signFn $delta.SeverityScoreDelta)  Hygiene $(& $signFn $delta.HygieneScoreDelta)  Regressions=$(@($delta.Regressions).Count) Improvements=$(@($delta.Improvements).Count)" -Color $sc2
        if (@($delta.Regressions).Count -gt 0) {
            Write-TUI '    [!!] Regressions:' -Color Red
            foreach ($r in $delta.Regressions) { Write-TUI "         [$($r.Severity)] $($r.CheckName)" -Color Red }
        }
    }

    Write-TUI '[*] Phase 4/4  Report   -- rendering output'
    if (-not $NoTUI) { Write-TUIReport -Ctx $context -Scores $scores -Findings $Script:Findings -Delta $delta }

    $payload = [ordered]@{
        Context      = $context
        ScoreBefore  = $scores.SeverityScore
        HygieneScore = $scores.HygieneScore
        ScoreAfter   = -1
        Delta        = $delta
        Findings     = @($Script:Findings)
        Peripherals  = $Script:Peripherals
    }
    if ($ShowSignals) {
        try {
            $mp = Get-MpPreference -ErrorAction SilentlyContinue
            $payload['Signals'] = @{ ASR_Rules=$mp.AttackSurfaceReductionRules_Ids; ASR_Actions=$mp.AttackSurfaceReductionRules_Actions }
        } catch { Write-Warning "Suppressed: $_" }
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($jsonPath, ([PSCustomObject]$payload | ConvertTo-Json -Depth 8), $utf8NoBom)
    if (-not $NoTUI) { Write-TUILine; Write-TUI "JSON : $jsonPath" }

    if (-not $SkipHTML) {
        $ok      = Export-HTMLReport -Path $htmlPath -Ctx $context -Scores $scores -Findings $Script:Findings -Delta $delta
        $htmlMsg = if ($ok) { "HTML : $htmlPath" } else { '[!] HTML export failed' }
        if (-not $NoTUI) { Write-TUI $htmlMsg }
        # Auto-open report in default browser (skip in headless/CI and when WebUI replaces it)
        if ($ok -and -not $NoTUI -and -not $WebUI) {
            try { Start-Process $htmlPath } catch { }
        }
    }

    # ---------------------------------------------------------------------------
    #  WEB DASHBOARD MODE: interactive localhost dashboard (supersedes remediation)
    # ---------------------------------------------------------------------------
    if ($WebUI) {
        $backupBase = if ($Portable -and $Portable -ne '') { Join-Path $Portable 'Backups' } else { 'C:\ProgramData\ApexAudit\Backups' }
        Start-AuditWebUI -Context $context -Scores $scores -Findings $Script:Findings `
            -Delta $delta -SafetyTiers $Script:SafetyTiers -BackupBaseDir $backupBase
    }

    # ---------------------------------------------------------------------------
    #  GUIDED POST-SCAN: offer remediation + baseline save
    # ---------------------------------------------------------------------------
    if ($Script:InGuidedMode -and -not $Remediate -and -not $WebUI) {
        $postResult = Invoke-GuidedPostScan -VulnCount $vulnCount
        if ($postResult.Remediate) { $Remediate = $true }
        if ($postResult.Baseline -ne '') { $Baseline = $postResult.Baseline }
    }

    # ---------------------------------------------------------------------------
    #  BASELINE SAVE: after guided post-scan so $Baseline from wizard is honored
    # ---------------------------------------------------------------------------
    if ($Baseline -ne '') {
        try {
            $bDir = Split-Path $Baseline -Parent
            if ($bDir -and -not (Test-Path $bDir)) { New-Item -ItemType Directory -Path $bDir -Force | Out-Null }
            # Copy the already-written JSON rather than re-serializing ($payload hashtable
            # cannot be safely serialized twice in PS 5.1 when it contains List<T> members)
            Copy-Item -Path $jsonPath -Destination $Baseline -Force -ErrorAction Stop
            Write-TUI "  [*] Baseline saved: $Baseline" -Color Cyan
        } catch { Write-Warning "[!] Could not save baseline to '$Baseline': $($_.Exception.Message)" }
    }

    # ---------------------------------------------------------------------------
    #  REMEDIATION MODE: interactive fix loop after report
    # ---------------------------------------------------------------------------
    if ($Remediate -and -not $WebUI) {
        $backupBase = if ($Portable -and $Portable -ne '') { Join-Path $Portable 'Backups' } else { '' }
        $backupDir  = New-RemediationBackup -FindingCount $vulnCount -ToolVersion $Script:TOOL_VERSION -BaseDir $backupBase
        if ($backupDir) {
            Invoke-RemediationLoop -Findings $Script:Findings -BackupDir $backupDir -SafetyTiers $Script:SafetyTiers
        } else {
            Write-Warning 'APEX: Could not create backup directory. Remediation aborted for safety.'
        }
    }
    $exitCode = if ($vulnCount -eq 0) { 0 } else { 1 }

} catch {
    Write-Log "APEX Audit fatal error: $($_.Exception.Message)" -Level ERROR
    Write-Warning "APEX Audit fatal error: $($_.Exception.Message)"
    $exitCode = 2
} finally {
    if ($Script:CimSession) {
        try { Remove-CimSession $Script:CimSession -ErrorAction SilentlyContinue } catch { Write-Warning "Suppressed: $_" }
    }
    if ($CleanOnExit -and $Script:GeneratedFiles) {
        foreach ($gf in $Script:GeneratedFiles) {
            if ($gf -notlike '*Backups*' -and (Test-Path $gf -ErrorAction SilentlyContinue)) {
                Remove-Item $gf -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Remove-LogFile   # ephemeral log -- deleted on clean exit
}

exit $exitCode
