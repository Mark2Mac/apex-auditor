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
    [switch] $Version,
    [switch] $Help
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
#  DOT-SOURCE ENGINE AND CHECKS
# ---------------------------------------------------------------------------
$Script:RootDir = $PSScriptRoot

. (Join-Path $Script:RootDir 'Engine\Core.ps1')
. (Join-Path $Script:RootDir 'Engine\Report.ps1')
. (Join-Path $Script:RootDir 'Engine\Remediate.ps1')

$checkFiles = Get-ChildItem -Path (Join-Path $Script:RootDir 'Checks') -Filter 'Check-*.ps1' |
              Sort-Object Name
foreach ($f in $checkFiles) { . $f.FullName }

# ---------------------------------------------------------------------------
#  CONSTANTS
# ---------------------------------------------------------------------------
$Script:TOOL_VERSION  = '3.0.0'
$Script:BUILD_DATE    = '2026-03-30'
$Script:SCORE_WEIGHTS = @{ CRITICAL=15; HIGH=8; MEDIUM=5; LOW=2 }
$Script:CimSession    = $null

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
#  EARLY EXITS
# ---------------------------------------------------------------------------
if ($Help)    { Get-Help $MyInvocation.MyCommand.Path -Full; exit 0 }
if ($Version) { Write-Output "APEX Zero-Trust Enterprise Audit v$($Script:TOOL_VERSION) ($($Script:BUILD_DATE))"; exit 0 }
if ($Undo -ne '') {
    try   { Invoke-RemediationUndo -BackupPath $Undo }
    catch { Write-Warning "APEX Undo fatal error: $($_.Exception.Message)"; exit 2 }
    exit 0
}

# ===========================================================================
#  MAIN
# ===========================================================================
$exitCode = 1
try {
    try   { $Script:CimSession = New-CimSession -ErrorAction Stop }
    catch { $Script:CimSession = $null; Write-TUI '[!] CIM session unavailable -- direct WMI fallback active' -Color Yellow }

    $baseline = $null
    if ($CompareTo -ne '') {
        Write-TUI "[*] Loading baseline: $CompareTo"
        $baseline = Read-BaselineJSON -Path $CompareTo
    }

    Write-TUI '[*] Phase 1/4  Context  -- collecting system metadata'
    $osInfo  = try { Get-Cim 'Win32_OperatingSystem' } catch { $null }
    $csInfo  = try { Get-Cim 'Win32_ComputerSystem'  } catch { $null }
    $encInfo = try { Get-Cim 'Win32_SystemEnclosure' } catch { $null }

    $context = [PSCustomObject]@{
        Hostname     = $env:COMPUTERNAME
        OSCaption    = if ($osInfo)  { $osInfo.Caption.Trim()  } else { 'Unknown' }
        OSBuild      = if ($osInfo)  { $osInfo.BuildNumber     } else { 'Unknown' }
        DomainJoined = if ($csInfo)  { [bool]$csInfo.PartOfDomain } else { $false }
        IsPortable   = if ($encInfo) { [bool]($encInfo.ChassisTypes | Where-Object { $_ -in @(8,9,10,11,12,14,18,21) }) } else { $false }
        TimestampUTC = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Mode         = $Mode
        Profile      = $Profile
        PSVersion    = $PSVersionTable.PSVersion.ToString()
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

    Write-TUI '[*] Phase 3/4  Score    -- computing Severity + Hygiene + Delta'
    $scores    = Measure-AuditScore    -Findings $Script:Findings
    $delta     = Compare-AuditBaseline -Baseline $baseline -CurrentFindings $Script:Findings -CurrentScores $scores
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
    }

    if ($Baseline -ne '') {
        try {
            $bDir = Split-Path $Baseline -Parent
            if ($bDir -and -not (Test-Path $bDir)) { New-Item -ItemType Directory -Path $bDir -Force | Out-Null }
            # Copy the already-written JSON rather than re-serializing ($payload hashtable
            # cannot be safely serialized twice in PS 5.1 when it contains List<T> members)
            Copy-Item -Path $jsonPath -Destination $Baseline -Force -ErrorAction Stop
            Write-Warning "Baseline saved: $Baseline"
        } catch { Write-Warning "[!] Could not save baseline to '$Baseline': $($_.Exception.Message)" }
    }

    # ---------------------------------------------------------------------------
    #  REMEDIATION MODE: interactive fix loop after report
    # ---------------------------------------------------------------------------
    if ($Remediate) {
        $backupDir = New-RemediationBackup -FindingCount $vulnCount -ToolVersion $Script:TOOL_VERSION
        if ($backupDir) {
            Invoke-RemediationLoop -Findings $Script:Findings -BackupDir $backupDir -SafetyTiers $Script:SafetyTiers
        } else {
            Write-Warning 'APEX: Could not create backup directory. Remediation aborted for safety.'
        }
    }
    $exitCode = if ($vulnCount -eq 0) { 0 } else { 1 }

} catch {
    Write-Warning "APEX Audit fatal error: $($_.Exception.Message)"
    $exitCode = 2
} finally {
    if ($Script:CimSession) {
        try { Remove-CimSession $Script:CimSession -ErrorAction SilentlyContinue } catch { Write-Warning "Suppressed: $_" }
    }
}

exit $exitCode
