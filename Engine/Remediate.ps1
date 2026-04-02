#Requires -Version 5.1
# =============================================================================
#  APEX Audit Engine -- Remediate.ps1
#  Interactive remediation loop with backup and undo capabilities.
#  Dot-sourced by Windows_Audit.ps1 when -Remediate or -Undo is used.
# =============================================================================

# ---------------------------------------------------------------------------
#  SAFETY TIER MAP
#  SAFE    : low-risk registry sets; can batch-apply with [A]ll-safe
#  CAUTION : may affect legacy apps or devices; requires per-finding confirm
#  RISKY   : reboot required, encryption, or major system change; requires typed "YES"
#  Findings not in this map default to CAUTION.
# ---------------------------------------------------------------------------
$Script:SafetyTiers = @{
    # SAFE -- simple registry value writes
    WDIG                       = 'SAFE'
    PSLOG                      = 'SAFE'
    CMDLINE                    = 'SAFE'
    SMBSIGS                    = 'SAFE'
    SMBSIGC                    = 'SAFE'
    'UAC-SD'                   = 'SAFE'
    PS2ENGINE                  = 'SAFE'
    'SPOOLER-PNP'              = 'SAFE'
    'FW-LOG'                   = 'SAFE'
    SID500                     = 'SAFE'
    AUDITPOL_PROCESS_CREATION  = 'SAFE'
    AUDITPOL_CREDENTIAL_VALID  = 'SAFE'
    AUDITPOL_LOGON             = 'SAFE'
    AUDITPOL_LOCKOUT           = 'SAFE'
    AUDITPOL_SPECIAL_LOGON     = 'SAFE'
    AUDITPOL_GROUP_MGMT        = 'SAFE'
    SECLOG                     = 'SAFE'
    ASR                        = 'SAFE'
    PUA                        = 'SAFE'
    CFA                        = 'SAFE'
    # CAUTION -- may affect connectivity or legacy apps
    LLMNR                      = 'CAUTION'
    NETBIOS                    = 'CAUTION'
    SMBENC                     = 'CAUTION'
    NTLM                       = 'CAUTION'
    'SPOOLER-SVC'              = 'CAUTION'
    FWRISK                     = 'CAUTION'
    'FW-Domain'                = 'CAUTION'
    'FW-Private'               = 'CAUTION'
    'FW-Public'                = 'CAUTION'
    'FW-SVC'                   = 'CAUTION'
    LAPS                       = 'CAUTION'
    # RISKY -- reboot, encryption, or irreversible
    PPL                        = 'RISKY'
    BLENC                      = 'RISKY'
    BLPBA                      = 'RISKY'
    UAC                        = 'RISKY'
    SMB1                       = 'RISKY'
    RDP                        = 'RISKY'
    'RDP-NLA'                  = 'RISKY'
    VBS                        = 'RISKY'
    HVCI                       = 'RISKY'
    CG                         = 'RISKY'
}

# ---------------------------------------------------------------------------
#  NEW-REMEDIATIONBACKUP
# ---------------------------------------------------------------------------
function New-RemediationBackup {
    <#
    .SYNOPSIS
        Creates a timestamped backup directory and writes a run manifest.
    .OUTPUTS
        [string] Path to the created backup directory.
    #>
    param(
        [int]    $FindingCount = 0,
        [string] $ToolVersion  = '3.0.0',
        [string] $BaseDir      = ''   # If set, backups go here instead of C:\ProgramData\...
    )
    $ts      = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $root    = if ($BaseDir -and $BaseDir -ne '') { $BaseDir } else { 'C:\ProgramData\ApexAudit\Backups' }
    $backDir = Join-Path $root $ts
    try {
        New-Item -ItemType Directory -Path $backDir -Force | Out-Null
    } catch {
        Write-Warning "APEX Remediate: Cannot create backup dir $backDir -- $_"
        return $null
    }
    $manifest = [PSCustomObject]@{
        Created      = (Get-Date).ToUniversalTime().ToString('o')
        Hostname     = $env:COMPUTERNAME
        ToolVersion  = $ToolVersion
        FindingCount = $FindingCount
        BackupDir    = $backDir
    }
    $manifest | ConvertTo-Json -Depth 3 |
        Set-Content -Path (Join-Path $backDir 'manifest.json') -Encoding UTF8
    return $backDir
}

# ---------------------------------------------------------------------------
#  BACKUP-FINDINGSTATE
# ---------------------------------------------------------------------------
function Backup-FindingState {
    <#
    .SYNOPSIS
        Backs up the registry hive or service state relevant to a finding's fix.
    .OUTPUTS
        [string] Path to the backup file, or $null if backup not applicable.
    #>
    param(
        [PSCustomObject] $Finding,
        [string]         $BackupDir
    )
    if (-not $BackupDir -or -not (Test-Path $BackupDir)) { return $null }

    $id  = $Finding.Id
    $fix = $Finding.Fix

    # Registry-based fix: extract hive path from Fix string and export via reg.exe
    if ($fix -match "(HK[LC][MU][^'`";\s]+)") {
        $regPath  = $Matches[1]
        $hiveName = ($regPath -split '\\')[0]
        # Map short names to reg.exe format
        $regExeHive = switch ($hiveName) {
            'HKLM:' { 'HKLM' }
            'HKCU:' { 'HKCU' }
            default { $hiveName.TrimEnd(':') }
        }
        $regKey     = $regPath.Substring($hiveName.Length).TrimStart('\')
        $backFile   = Join-Path $BackupDir "$($id -replace '[:\\]','_').reg"
        try {
            $result = Invoke-Exe 'reg.exe' @('export', "$regExeHive\$regKey", $backFile, '/y')
            if (Test-Path $backFile) { return $backFile }
        } catch { <# silently skip backup failure #> }
    }

    # Service-based fix: save current state to JSON
    if ($fix -match 'Stop-Service|Set-Service|sc\.exe') {
        $svcName = switch ($id) {
            'SPOOLER-SVC' { 'Spooler' }
            'FW-SVC'      { 'MpsSvc' }
            'WU'          { 'wuauserv' }
            default       { $null }
        }
        if ($svcName) {
            try {
                $svc      = Get-Service $svcName -ErrorAction Stop
                $svcState = [PSCustomObject]@{ Name=$svc.Name; Status=$svc.Status.ToString(); StartType=$svc.StartType.ToString() }
                $backFile = Join-Path $BackupDir "$($id -replace '[:\\]','_')_svc.json"
                $svcState | ConvertTo-Json | Set-Content $backFile -Encoding UTF8
                return $backFile
            } catch { <# silently skip #> }
        }
    }

    # Firewall rule-based fix: save affected rules before disabling
    if ($fix -match 'Disable-NetFirewallRule') {
        try {
            $affectedRules = @(
                Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
                Where-Object { $_.Profile -match 'Public' -and -not $_.Owner -and (-not $_.Group) } |
                Select-Object Name, DisplayName
            )
            if ($affectedRules.Count -gt 0) {
                $backFile = Join-Path $BackupDir "$($id -replace '[:\\]','_')_fwrules.json"
                $affectedRules | ConvertTo-Json -Depth 3 | Set-Content $backFile -Encoding UTF8
                return $backFile
            }
        } catch { <# silently skip #> }
    }

    return $null
}

# ---------------------------------------------------------------------------
#  INVOKE-REMEDIATIONLOOP
# ---------------------------------------------------------------------------
function Invoke-RemediationLoop {
    <#
    .SYNOPSIS
        Interactive loop: iterates vulnerable findings CRITICAL->LOW, prompts for each fix.
    .OUTPUTS
        [PSCustomObject] Summary with Applied, Skipped, Failed counts and BackupDir.
    #>
    param(
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [string]   $BackupDir,
        [hashtable] $SafetyTiers
    )

    if (-not $Script:IsAdmin) {
        Write-TUI ''
        Write-TUI '  [!] REMEDIATION REQUIRES ADMINISTRATOR ELEVATION' -Color Red
        Write-TUI '      All fixes modify system-level settings (registry, services, audit policy).' -Color Yellow
        Write-TUI '      Re-run the script as Administrator to apply fixes.' -Color Yellow
        Write-TUI ''
        return [PSCustomObject]@{ Applied=0; Skipped=0; Failed=0; BackupDir=$BackupDir }
    }

    $applied  = 0
    $skipped  = 0
    $failed   = 0
    $autoSafe = $false   # set when user presses [A]

    $vulnFindings = @($Findings | Where-Object { $_.Vulnerable } |
        Sort-Object @{E={switch($_.Severity){'CRITICAL'{0}'HIGH'{1}'MEDIUM'{2}'LOW'{3}default{4}}}})

    if (-not $vulnFindings) {
        Write-TUI "`n  [REMEDIATE] No vulnerable findings to remediate." -Color Green
        return [PSCustomObject]@{ Applied=0; Skipped=0; Failed=0; BackupDir=$BackupDir }
    }

    Write-TUI ''
    Write-TUI '  >> REMEDIATION MODE' -Color Cyan
    Write-TUI "     Backup directory : $BackupDir" -Color DarkCyan
    Write-TUI "     Vulnerable findings : $($vulnFindings.Count)" -Color DarkCyan
    Write-TUI '     Prompts: [Y]es  [N]o  [A]ll-safe  [S]kip-remaining  [Q]uit' -Color DarkCyan
    Write-TUI '     RISKY tier always requires typing YES (ignores [A])' -Color DarkYellow
    Write-TUILine

    foreach ($f in $vulnFindings) {
        $tier = if ($SafetyTiers.ContainsKey($f.Id)) { $SafetyTiers[$f.Id] } else { 'CAUTION' }

        # Skip findings whose Fix is a text description, not an executable command
        $isManual = $f.Fix -and (($f.Fix.TrimEnd() -match '\.$') -or ($f.Fix -match '<[A-Za-z_][^>]+>'))
        if ($isManual) {
            Write-TUI "  [MANUAL]    $($f.Id) -- fix requires manual action: $($f.Fix)" -Color DarkYellow
            $skipped++
            continue
        }

        # Show compatibility/impact warning if peripherals were affected
        if ($f.PSObject.Properties['_ImpactWarning'] -and $f._ImpactWarning) {
            Write-TUI "  [!] $($f._ImpactWarning)" -Color Yellow
        }

        # Auto-apply SAFE tier when [A] was pressed
        if ($autoSafe -and $tier -eq 'SAFE') {
            $backFile = Backup-FindingState -Finding $f -BackupDir $BackupDir
            try {
                $null = Invoke-FindingFix -Expression $f.Fix -FindingId $f.Id
                Write-TUI "  [AUTO-SAFE] $($f.Id) applied." -Color Green
                $applied++
            } catch {
                Write-TUI "  [FAILED]    $($f.Id) : $_" -Color Red
                $failed++
            }
            continue
        }

        # Display finding
        Write-TUIFinding -F $f

        # Tier badge
        $tierColor = switch ($tier) {
            'SAFE'    { 'Green' }
            'CAUTION' { 'Yellow' }
            'RISKY'   { 'Red' }
            default   { 'Yellow' }
        }
        Write-TUI "  Safety tier : [$tier]" -Color $tierColor
        Write-TUI "  Fix command : $($f.Fix)" -Color DarkCyan

        # Prompt
        $prompt = if ($tier -eq 'RISKY') {
            "  Apply this RISKY fix? (type YES to confirm, N to skip) : "
        } else {
            "  Apply? [Y]es / [N]o / [A]ll-safe / [S]kip-remaining / [Q]uit : "
        }
        Write-Host $prompt -NoNewline -ForegroundColor White
        $ans = (Read-Host).Trim()

        # RISKY requires exact "YES"
        if ($tier -eq 'RISKY') {
            if ($ans -eq 'YES') {
                $backFile = Backup-FindingState -Finding $f -BackupDir $BackupDir
                try {
                    $null = Invoke-FindingFix -Expression $f.Fix -FindingId $f.Id
                    Write-TUI "  [APPLIED]   $($f.Id)" -Color Green
                    $applied++
                } catch {
                    Write-TUI "  [FAILED]    $($f.Id) : $_" -Color Red
                    $failed++
                }
            } else {
                Write-TUI "  [SKIPPED]   $($f.Id)" -Color DarkGray
                $skipped++
            }
            Write-TUI ''
            continue
        }

        switch ($ans.ToUpper()) {
            'Y' {
                $backFile = Backup-FindingState -Finding $f -BackupDir $BackupDir
                try {
                    $null = Invoke-FindingFix -Expression $f.Fix -FindingId $f.Id
                    Write-TUI "  [APPLIED]   $($f.Id)" -Color Green
                    $applied++
                } catch {
                    Write-TUI "  [FAILED]    $($f.Id) : $_" -Color Red
                    $failed++
                }
            }
            'A' {
                if ($tier -eq 'SAFE') {
                    $autoSafe = $true
                    $backFile = Backup-FindingState -Finding $f -BackupDir $BackupDir
                    try {
                        $null = Invoke-FindingFix -Expression $f.Fix -FindingId $f.Id
                        Write-TUI "  [APPLIED]   $($f.Id) (auto-safe enabled for remaining SAFE fixes)" -Color Green
                        $applied++
                    } catch {
                        Write-TUI "  [FAILED]    $($f.Id) : $_" -Color Red
                        $failed++
                    }
                } else {
                    Write-TUI "  [NOTE] [A]ll-safe only auto-applies SAFE tier. This finding is [$tier]. Skipping." -Color Yellow
                    $skipped++
                }
            }
            'S' {
                Write-TUI "  [SKIPPED]   Remaining findings skipped." -Color DarkGray
                $skipped += ($vulnFindings.Count - $applied - $failed - $skipped - 1)
                break
            }
            'Q' {
                Write-TUI "  [QUIT]      Remediation stopped by user." -Color DarkGray
                break
            }
            default {
                Write-TUI "  [SKIPPED]   $($f.Id)" -Color DarkGray
                $skipped++
            }
        }
        Write-TUI ''

        if ($ans.ToUpper() -in @('S','Q')) { break }
    }

    Write-Log "REMEDIATION SUMMARY applied=$applied skipped=$skipped failed=$failed"
    Write-TUILine
    Write-TUI "  REMEDIATION SUMMARY" -Color Cyan
    Write-TUI "    Applied  : $applied" -Color Green
    Write-TUI "    Skipped  : $skipped" -Color DarkGray
    Write-TUI "    Failed   : $failed"  -Color $(if ($failed -gt 0) { 'Red' } else { 'DarkGray' })
    Write-TUI "    Backups  : $BackupDir" -Color DarkCyan
    Write-TUI '  Re-run audit to verify applied fixes.' -Color DarkCyan
    if ($failed -gt 0 -and $Script:LogFile -and (Test-Path $Script:LogFile -ErrorAction SilentlyContinue)) {
        Write-TUI "    Log file : $Script:LogFile  (temporary -- deleted on clean exit)" -Color Yellow
    }
    Write-TUILine

    return [PSCustomObject]@{
        Applied   = $applied
        Skipped   = $skipped
        Failed    = $failed
        BackupDir = $BackupDir
    }
}

# ---------------------------------------------------------------------------
#  INVOKE-REMEDIATIONUNDO
# ---------------------------------------------------------------------------
function Invoke-RemediationUndo {
    <#
    .SYNOPSIS
        Restores system state from a backup directory created by a previous remediation run.
    #>
    param([string]$BackupPath)

    if (-not $BackupPath -or -not (Test-Path $BackupPath)) {
        Write-Warning "APEX Undo: Backup path not found: $BackupPath"
        return
    }

    $manifestFile = Join-Path $BackupPath 'manifest.json'
    if (Test-Path $manifestFile) {
        $manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json
        Write-TUI ''
        Write-TUI '  >> UNDO MODE' -Color Cyan
        Write-TUI "     Backup created : $($manifest.Created)" -Color DarkCyan
        Write-TUI "     Hostname       : $($manifest.Hostname)" -Color DarkCyan
        Write-TUI "     Tool version   : $($manifest.ToolVersion)" -Color DarkCyan
        Write-TUILine
    }

    $restored = 0
    $failed   = 0

    # Restore registry exports (.reg files)
    $regFiles = Get-ChildItem -Path $BackupPath -Filter '*.reg' -ErrorAction SilentlyContinue
    foreach ($regFile in $regFiles) {
        Write-TUI "  Restoring registry: $($regFile.Name) ..." -Color DarkCyan
        try {
            $result = Invoke-Exe 'reg.exe' @('import', $regFile.FullName)
            Write-TUI "  [OK] $($regFile.Name)" -Color Green
            $restored++
        } catch {
            Write-TUI "  [FAILED] $($regFile.Name) : $_" -Color Red
            $failed++
        }
    }

    # Restore service states (_svc.json files)
    $svcFiles = Get-ChildItem -Path $BackupPath -Filter '*_svc.json' -ErrorAction SilentlyContinue
    foreach ($svcFile in $svcFiles) {
        try {
            $svcState = Get-Content $svcFile.FullName -Raw | ConvertFrom-Json
            Write-TUI "  Restoring service: $($svcState.Name) -> StartType=$($svcState.StartType) Status=$($svcState.Status) ..." -Color DarkCyan
            Set-Service -Name $svcState.Name -StartupType $svcState.StartType -ErrorAction SilentlyContinue
            if ($svcState.Status -eq 'Running') {
                Start-Service -Name $svcState.Name -ErrorAction SilentlyContinue
            } elseif ($svcState.Status -eq 'Stopped') {
                Stop-Service -Name $svcState.Name -Force -ErrorAction SilentlyContinue
            }
            Write-TUI "  [OK] $($svcState.Name)" -Color Green
            $restored++
        } catch {
            Write-TUI "  [FAILED] $($svcFile.Name) : $_" -Color Red
            $failed++
        }
    }

    # Restore firewall rules (_fwrules.json files)
    $fwFiles = Get-ChildItem -Path $BackupPath -Filter '*_fwrules.json' -ErrorAction SilentlyContinue
    foreach ($fwFile in $fwFiles) {
        try {
            $rules = Get-Content $fwFile.FullName -Raw | ConvertFrom-Json
            foreach ($rule in $rules) {
                Write-TUI "  Re-enabling firewall rule: $($rule.DisplayName) ..." -Color DarkCyan
                Enable-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
            }
            Write-TUI "  [OK] $($fwFile.Name) -- $(@($rules).Count) rule(s) re-enabled" -Color Green
            $restored++
        } catch {
            Write-TUI "  [FAILED] $($fwFile.Name) : $_" -Color Red
            $failed++
        }
    }

    Write-TUILine
    Write-TUI "  UNDO SUMMARY" -Color Cyan
    Write-TUI "    Restored : $restored" -Color Green
    Write-TUI "    Failed   : $failed"   -Color $(if ($failed -gt 0) { 'Red' } else { 'DarkGray' })
    if ($failed -gt 0) {
        Write-TUI '  Some items could not be restored automatically. Check backup files manually.' -Color Yellow
    }
    Write-TUILine
}

# ---------------------------------------------------------------------------
#  REMOVE-BACKUPDIR
# ---------------------------------------------------------------------------
function Remove-BackupDir {
    <#
    .SYNOPSIS
        Removes the session's backup directory tree. Called on clean exit
        to leave no trace. Skipped if -KeepBackups was specified.
    #>
    param([string]$BackupPath)
    if (-not $BackupPath -or -not (Test-Path $BackupPath)) { return }
    try {
        Remove-Item $BackupPath -Recurse -Force -ErrorAction Stop
        Write-Log "Backup directory removed: $BackupPath"
        # Remove parent ApexAudit dir if now empty
        $parent = Split-Path $BackupPath
        if ((Test-Path $parent) -and @(Get-ChildItem $parent -ErrorAction SilentlyContinue).Count -eq 0) {
            Remove-Item $parent -Force -ErrorAction SilentlyContinue
        }
    } catch { Write-Log "Failed to remove backup dir: $_" -Level WARN }
}
