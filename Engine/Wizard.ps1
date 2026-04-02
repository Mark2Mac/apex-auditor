#Requires -Version 5.1
# =============================================================================
#  APEX Audit Engine -- Wizard.ps1
#  Guided terminal wizard: environment detection, profile/mode selection,
#  baseline discovery, post-scan remediation and baseline-save offers.
#  Dot-sourced lazily by Windows_Audit.ps1 when -Guided or bare invocation.
# =============================================================================

function Invoke-GuidedMode {
    <#
    .SYNOPSIS
        Interactive setup wizard. Detects environment, prompts for scan options.
    .OUTPUTS
        [hashtable] Keys: Mode, Profile, CompareTo, Baseline — apply to param overrides.
                    Returns $null if user aborts.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','')]
    param()

    # --- Banner ---
    Write-Host ''
    Write-Host '  +==============================================================+' -ForegroundColor Cyan
    Write-Host "  |   APEX Zero-Trust Windows Auditor v$($Script:TOOL_VERSION)  ($($Script:BUILD_DATE))   |" -ForegroundColor Cyan
    Write-Host '  |   Guided Setup                                               |' -ForegroundColor Cyan
    Write-Host '  +==============================================================+' -ForegroundColor Cyan
    Write-Host ''

    # --- Environment detection ---
    Write-Host '  [*] Detecting environment ...' -ForegroundColor DarkCyan

    $osName  = if (Get-Command Get-OSVersionName -EA SilentlyContinue) { Get-OSVersionName } else { 'Unknown' }
    $build   = try { ([System.Environment]::OSVersion.Version.Build).ToString() } catch { '?' }
    $isAdmin = $Script:IsAdmin

    # CIM already queried in caller; use script-scope if available, else query fresh
    $encInfo = try { Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue } catch { $null }
    $csInfo  = try { Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue } catch { $null }

    $chassis  = if (Get-Command Get-ChassisTypeName -EA SilentlyContinue) {
                    Get-ChassisTypeName -EnclosureInfo $encInfo -CSInfo $csInfo
                } else { 'Unknown' }
    $domain   = if ($csInfo) { [bool]$csInfo.PartOfDomain } else { $false }
    $sugProf  = if (Get-Command Get-DetectedProfile -EA SilentlyContinue) {
                    Get-DetectedProfile -DomainJoined $domain -ChassisType $chassis
                } else { 'PersonalLaptop' }

    Write-Host ''
    Write-Host '  Environment detected:' -ForegroundColor White
    Write-Host "    OS         : $osName (Build $build)" -ForegroundColor DarkGray
    Write-Host "    Admin      : $(if ($isAdmin) { 'Yes (elevated)' } else { 'No - limited mode (see below)' })" `
               -ForegroundColor (if ($isAdmin) { 'Green' } else { 'Yellow' })
    Write-Host "    Domain     : $(if ($domain) { 'Joined' } else { 'Not joined' })" -ForegroundColor DarkGray
    Write-Host "    Chassis    : $chassis" -ForegroundColor DarkGray
    Write-Host "    Suggested  : $sugProf profile, Deep scan" -ForegroundColor Cyan
    Write-Host ''

    # --- Self-elevation offer (non-admin only) ---
    if (-not $isAdmin) {
        Write-Host '  [!] Limited without elevation:' -ForegroundColor Yellow
        Write-Host '        AuditPol, SMB Config, Firewall Policy, Firewall Logging,' -ForegroundColor DarkYellow
        Write-Host '        Security Log Size, Exploit Protection, Event Forwarding' -ForegroundColor DarkYellow
        Write-Host '      All remediation fixes also require elevation.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  [?] Restart as Administrator?  [Y / n]  ' -NoNewline -ForegroundColor White
        $elevAns = (Read-Host).Trim().ToUpper()
        if ($elevAns -ne 'N') {
            try {
                $scriptPath = Join-Path $Script:RootDir 'Windows_Audit.ps1'
                Start-Process powershell -Verb RunAs `
                    -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`" -Guided"
                Write-Host '  Elevated session launched. This window will close.' -ForegroundColor DarkCyan
                exit 0
            } catch {
                Write-Host '  [!] Elevation cancelled. Continuing without elevation.' -ForegroundColor Yellow
            }
        }
        Write-Host ''
    }

    # --- Profile selection ---
    Write-Host "  [?] Use suggested profile `"$sugProf`"?  [Y / n / change]  " -NoNewline -ForegroundColor White
    $ans = (Read-Host).Trim().ToUpper()
    $chosenProfile = $sugProf
    if ($ans -eq 'N') {
        Write-Host '  Profiles:  [1] PersonalLaptop  [2] Enterprise  [3] Lab  [4] Paranoid' -ForegroundColor DarkGray
        Write-Host '  Choice [1]: ' -NoNewline -ForegroundColor White
        $pc = (Read-Host).Trim()
        $chosenProfile = switch ($pc) {
            '2' { 'Enterprise' }; '3' { 'Lab' }; '4' { 'Paranoid' }; default { 'PersonalLaptop' }
        }
    } elseif ($ans -eq 'CHANGE') {
        Write-Host '  Profiles:  [1] PersonalLaptop  [2] Enterprise  [3] Lab  [4] Paranoid' -ForegroundColor DarkGray
        Write-Host '  Choice [1]: ' -NoNewline -ForegroundColor White
        $pc = (Read-Host).Trim()
        $chosenProfile = switch ($pc) {
            '2' { 'Enterprise' }; '3' { 'Lab' }; '4' { 'Paranoid' }; default { 'PersonalLaptop' }
        }
    }
    Write-Host "  Profile: $chosenProfile" -ForegroundColor Cyan

    # --- Mode selection ---
    Write-Host ''
    Write-Host '  [?] Scan mode:' -ForegroundColor White
    Write-Host '      [1] Fast  -- critical checks only, ~10s'  -ForegroundColor DarkGray
    Write-Host '      [2] Deep  -- full posture analysis, ~30s (recommended)' -ForegroundColor DarkGray
    Write-Host '  Choice [2]: ' -NoNewline -ForegroundColor White
    $mc = (Read-Host).Trim()
    $chosenMode = if ($mc -eq '1') { 'Fast' } else { 'Deep' }
    Write-Host "  Mode: $chosenMode" -ForegroundColor Cyan

    # --- Baseline discovery ---
    $compareTarget = ''
    $searchDirs = @($Script:RootDir, (Get-Location).Path) | Select-Object -Unique
    $recentBaselines = foreach ($sd in $searchDirs) {
        Get-ChildItem -Path $sd -Filter 'audit_report_*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 3
    }
    $recentBaselines = @($recentBaselines | Sort-Object LastWriteTime -Descending | Select-Object -First 1)

    if ($recentBaselines.Count -gt 0) {
        $bl  = $recentBaselines[0]
        $age = [math]::Round(((Get-Date) - $bl.LastWriteTime).TotalHours, 1)
        Write-Host ''
        Write-Host "  [*] Found recent scan: $($bl.Name) ($age hours ago)" -ForegroundColor DarkCyan
        Write-Host '  [?] Compare against it for delta tracking?  [Y / n]  ' -NoNewline -ForegroundColor White
        $da = (Read-Host).Trim().ToUpper()
        if ($da -ne 'N') { $compareTarget = $bl.FullName }
    }

    Write-Host ''
    Write-Host '  Starting scan ...' -ForegroundColor DarkCyan
    Write-Host ''
    $Script:InGuidedMode = $true

    return @{
        Mode       = $chosenMode
        Profile    = $chosenProfile
        CompareTo  = $compareTarget
        Baseline   = ''
    }
}

function Invoke-GuidedPostScan {
    <#
    .SYNOPSIS
        Post-scan interactive prompts: offer remediation and baseline save.
    .OUTPUTS
        [hashtable] Keys: Remediate [bool], Baseline [string] (path or '')
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','')]
    param(
        [int] $VulnCount
    )

    $result = @{ Remediate = $false; Baseline = '' }

    # --- Offer remediation ---
    if ($VulnCount -gt 0) {
        Write-Host ''
        Write-Host "  [?] $VulnCount vulnerable finding(s) detected.  Enter remediation mode now?  [Y / n]  " `
                   -NoNewline -ForegroundColor Yellow
        $ra = (Read-Host).Trim().ToUpper()
        if ($ra -ne 'N') { $result.Remediate = $true }
    } else {
        Write-Host ''
        Write-Host '  [*] No vulnerabilities detected. System is clean.' -ForegroundColor Green
    }

    # --- Offer baseline save ---
    Write-Host ''
    Write-Host '  [?] Save this scan as a baseline for future comparison?  [Y / n]  ' `
               -NoNewline -ForegroundColor White
    $ba = (Read-Host).Trim().ToUpper()
    if ($ba -ne 'N') {
        $defaultPath = Join-Path $Script:RootDir 'baseline.json'
        Write-Host "  Baseline path [$defaultPath]: " -NoNewline -ForegroundColor White
        $bPath = (Read-Host).Trim()
        $result.Baseline = if ($bPath -ne '') { $bPath } else { $defaultPath }
    }

    return $result
}
