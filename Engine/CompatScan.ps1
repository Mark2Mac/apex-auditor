#Requires -Version 5.1
# =============================================================================
#  APEX Audit Engine -- CompatScan.ps1
#  Peripheral and network dependency detection.
#  Stamps _FixType and _ImpactWarning on findings before remediation.
#  Dot-sourced by Windows_Audit.ps1.
# =============================================================================

function Get-SystemPeripherals {
    <#
    .SYNOPSIS
        Detects installed printers, shared folders, and mapped drives.
    .OUTPUTS
        [PSCustomObject] with Printers, NetworkPrinters, SharedPrinters,
        LocalPrinters, SharedFolders, MappedDrives.
    #>
    $ctx = [PSCustomObject]@{
        Printers         = @()
        NetworkPrinters  = 0
        SharedPrinters   = 0
        LocalPrinters    = 0
        PhysicalPrinters = 0   # non-virtual: USB, WSD, IP, network-mapped
        SharedFolders    = @()
        MappedDrives     = @()
    }

    # --- Printers via CIM (works without admin) ---
    # Note: WiFi/IP printers (WSD, EP_, IP_ ports) always show Type=Local in WMI
    # even though they're physically on the network.
    try {
        $raw = Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue
        $list = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($p in $raw) {
            $type = if ($p.Network)    { 'Network' }
                    elseif ($p.Shared) { 'Shared' }
                    else               { 'Local' }
            # Classify as virtual if port/driver indicates software-only printer
            $port = [string]$p.PortName
            $drv  = [string]$p.DriverName
            $isVirtual = ($port -eq 'nul:') -or
                         ($port -eq 'PORTPROMPT:') -or
                         ($port -like 'Documents\*') -or
                         ($port -like 'Microsoft.Office.*') -or
                         ($drv  -match '(?i)(OneNote|PDF|Fax|XPS|Virtual|Microsoft Print)')
            $list.Add([PSCustomObject]@{
                Name       = [string]$p.Name
                PortName   = $port
                Type       = $type
                DriverName = $drv
                Virtual    = $isVirtual
            })
        }
        $ctx.Printers         = $list
        $ctx.NetworkPrinters  = @($list | Where-Object Type -eq 'Network').Count
        $ctx.SharedPrinters   = @($list | Where-Object Type -eq 'Shared').Count
        $ctx.LocalPrinters    = @($list | Where-Object Type -eq 'Local').Count
        $ctx.PhysicalPrinters = @($list | Where-Object { -not $_.Virtual }).Count
    } catch { }

    # --- Non-default SMB shares ---
    try {
        $defaults = @('ADMIN$', 'C$', 'IPC$', 'print$')
        $ctx.SharedFolders = @(
            Get-SmbShare -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin $defaults } |
            Select-Object -ExpandProperty Name
        )
    } catch { }

    # --- Mapped network drives ---
    try {
        $ctx.MappedDrives = @(
            Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayRoot -like '\\*' } |
            ForEach-Object { $_.DisplayRoot }
        )
    } catch { }

    return $ctx
}

function Set-FindingImpactFlags {
    <#
    .SYNOPSIS
        Stamps _FixType (Auto/Manual/None) and _ImpactWarning on each finding
        based on the fix string heuristic and detected peripherals.
    #>
    param(
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [PSCustomObject] $Peripherals
    )

    $physP  = $Peripherals.PhysicalPrinters
    $pNames = (@($Peripherals.Printers | Where-Object { -not $_.Virtual } | ForEach-Object { $_.Name }) -join ', ')
    $netP   = $Peripherals.NetworkPrinters
    $shrP   = $Peripherals.SharedPrinters
    $shares = $Peripherals.SharedFolders.Count

    foreach ($f in $Findings) {

        # --- _FixType ---
        $ft = if (-not $f.Fix -or $f.Fix -eq 'N/A') {
                  'None'
              } elseif ($f.Fix.TrimEnd() -match '\.$' -or $f.Fix -match '<[A-Za-z_][^>]+>') {
                  'Manual'
              } else {
                  'Auto'
              }
        $f | Add-Member -NotePropertyName '_FixType' -NotePropertyValue $ft -Force

        # --- _ImpactWarning (only for vulnerable findings) ---
        if (-not $f.Vulnerable) { continue }

        $warn = switch -Regex ($f.Id) {
            '^SPOOLER-SVC$' {
                if ($physP -gt 0) {
                    "PRINTER IMPACT: Disabling Print Spooler stops ALL printing. $physP printer(s) found: $pNames"
                }
            }
            '^SPOOLER-PNP$' {
                if ($physP -gt 0) {
                    "PRINTER IMPACT: Non-admin users cannot add new printer drivers. $physP physical printer(s) detected."
                }
            }
            '^SMBENC$' {
                if ($shrP -gt 0 -or $shares -gt 0 -or $netP -gt 0) {
                    "COMPATIBILITY: SMB encryption may disconnect older clients from shared printers/folders."
                }
            }
            '^SMB1$' {
                $parts = @()
                if ($netP -gt 0) { $parts += "Pre-2015 network printers using SMBv1-only will lose connectivity." }
                if ($Peripherals.MappedDrives.Count -gt 0) { $parts += "Mapped network drives to legacy servers using SMBv1-only will lose connectivity." }
                if ($parts.Count -gt 0) { "COMPATIBILITY: " + ($parts -join ' ') }
            }
            '^NTLM$' {
                $parts = @()
                if ($netP -gt 0) { $parts += "Network printers using NTLMv1 auth will fail to authenticate." }
                if ($Peripherals.MappedDrives.Count -gt 0) { $parts += "Mapped network drives using NTLMv1 auth will fail. Ensure servers support NTLMv2." }
                if ($parts.Count -gt 0) { "COMPATIBILITY: " + ($parts -join ' ') }
            }
            '^LLMNR$' {
                $parts = @()
                if ($netP -gt 0) { $parts += "Printers discovered by hostname (not IP) may become unreachable without DNS." }
                if ($Peripherals.MappedDrives.Count -gt 0 -or $shrP -gt 0) { $parts += "Hostname-based mapped drives or shares may become unreachable without DNS." }
                if ($parts.Count -gt 0) { "COMPATIBILITY: " + ($parts -join ' ') }
            }
            '^NETBIOS$' {
                $parts = @()
                if ($netP -gt 0) { $parts += "Older name resolution for printers will stop. Ensure printers use IP or DNS." }
                if ($Peripherals.MappedDrives.Count -gt 0) { $parts += "Mapped drives using NetBIOS name resolution will stop working. Ensure servers are in DNS." }
                if ($parts.Count -gt 0) { "COMPATIBILITY: " + ($parts -join ' ') }
            }
            '^FW-(Domain|Private|Public)$' {
                if ($shrP -gt 0 -or $shares -gt 0) {
                    "COMPATIBILITY: Block-inbound will prevent other machines from reaching shared printers/folders on this PC."
                }
            }
        '^(VBS|HVCI)$' {
            "DRIVER RISK: Enabling Memory Integrity may prevent booting if incompatible kernel drivers are installed. Check Windows Security > Core Isolation for driver compatibility warnings before enabling."
        }
        '^CG$' {
            "COMPATIBILITY: Credential Guard breaks NTLM delegation and RDP with saved credentials in some configurations. Verify before enabling on domain-joined machines."
        }
        '^RDP$' {
            "SESSION RISK: Disabling RDP will immediately terminate any active remote desktop sessions."
        }
        '^(SMBSIGS|SMBSIGC)$' {
            if ($Peripherals.MappedDrives.Count -gt 0 -or $shares -gt 0) {
                "COMPATIBILITY: Requiring SMB signing may disconnect older NAS devices or Linux Samba shares that do not support signing."
            }
        }
        '^FW-SVC$' {
            "CONNECTIVITY: Re-enabling the Firewall service will immediately enforce all firewall profiles. Inbound connections (RDP, shared folders, printers) may be blocked until rules are reviewed."
        }
        '^PPL$' {
            "DRIVER RISK: Enabling LSASS PPL may break third-party authentication providers, smartcard middleware, or security software that hooks LSASS. Requires reboot."
        }
        '^RDP-NLA$' {
            "SESSION RISK: Requiring NLA may prevent older RDP clients (pre-Vista, some thin clients) from connecting. Verify all remote desktop clients support NLA before enabling."
        }
        '^CFA$' {
            "APPLICATION RISK: Controlled Folder Access blocks unauthorized apps from writing to Documents/Desktop/etc. Many legitimate apps (installers, dev tools, backup software) will be blocked until whitelisted."
        }
        '^ASR$' {
            "APPLICATION RISK: ASR rules in Block mode may prevent Office macros, WMI event subscriptions, and script execution from Office/email. Test in Audit mode first."
        }
        '^EXPROT-DEP$' {
            "APPLICATION RISK: System-wide DEP may crash legacy 32-bit applications that execute code from data pages."
        }
        '^EXPROT-ASLR$' {
            "APPLICATION RISK: Force ASLR may crash applications with DLLs not compiled for relocation (/DYNAMICBASE)."
        }
        '^UNQUOTED_SERVICE_PATH' {
            "SERVICE RISK: Modifying the service binary path could prevent the service from starting if the quoted path or arguments are incorrect. Verify the fix command before applying."
        }
        default { $null }
        }

        if ($warn) {
            $f | Add-Member -NotePropertyName '_ImpactWarning' -NotePropertyValue $warn -Force
        }
    }
}

function Set-FindingGuides {
    <#
    .SYNOPSIS
        Stamps _Guide (step-by-step instructions) and _Shortcut (PowerShell launch command)
        on findings that require manual remediation.
    #>
    param(
        [System.Collections.Generic.List[PSCustomObject]] $Findings
    )

    # Map: FindingId -> @{ Steps=[]; Shortcut=@{Cmd='...'; Label='...'} }
    $guides = @{
        'VBS'        = @{
            Steps   = @(
                'Open Windows Security',
                'Go to Device Security > Core Isolation Details',
                'Enable "Memory Integrity"',
                'Restart the PC when prompted'
            )
            Shortcut = @{ Cmd='Start-Process "windowsdefender://coreisolation"'; Label='Open Core Isolation' }
        }
        'HVCI'       = @{
            Steps   = @(
                'Open Windows Security',
                'Go to Device Security > Core Isolation Details',
                'Enable "Memory Integrity"',
                'Restart the PC when prompted'
            )
            Shortcut = @{ Cmd='Start-Process "windowsdefender://coreisolation"'; Label='Open Core Isolation' }
        }
        'CG'         = @{
            Steps   = @(
                'Open gpedit.msc',
                'Go to Computer Configuration > Administrative Templates > System > Device Guard',
                'Enable "Turn On Virtualization Based Security"',
                'Under "Credential Guard Configuration" select "Enabled with UEFI lock"',
                'Restart the PC'
            )
            Shortcut = @{ Cmd='Start-Process gpedit.msc'; Label='Open Group Policy Editor' }
        }
        'BLPBA'      = @{
            Steps   = @(
                'Open gpedit.msc',
                'Go to Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Operating System Drives',
                'Enable "Allow enhanced PINs for startup"',
                'Then run: manage-bde -protectors -add C: -TPMAndPIN',
                'Enter your PIN when prompted'
            )
            Shortcut = @{ Cmd='Start-Process gpedit.msc'; Label='Open Group Policy Editor' }
        }
        'TPM'        = @{
            Steps   = @(
                'Restart the PC',
                'Enter BIOS/UEFI firmware (Del/F2/F10 key at boot)',
                'Find the Security or Trusted Computing section',
                'Enable "TPM Device" or "PTT" (Intel) / "fTPM" (AMD)',
                'Save and restart'
            )
            Shortcut = @{ Cmd='Start-Process ms-settings:recovery'; Label='Advanced Startup (UEFI)' }
        }
        'SBOOT'      = @{
            Steps   = @(
                'Restart the PC',
                'Enter BIOS/UEFI firmware (Del/F2/F10 key at boot)',
                'Find the Boot or Security section',
                'Enable "Secure Boot"',
                'Save and restart'
            )
            Shortcut = @{ Cmd='Start-Process ms-settings:recovery'; Label='Advanced Startup (UEFI)' }
        }
        'NETBIOS'    = @{
            Steps   = @(
                'Open Network Connections (ncpa.cpl)',
                'For each network adapter: right-click > Properties',
                'Select "Internet Protocol Version 4 (TCP/IPv4)" > Advanced',
                'WINS tab > select "Disable NetBIOS over TCP/IP"',
                'Repeat for each active adapter',
                'Or use the PowerShell fix command shown above (faster)'
            )
            Shortcut = @{ Cmd='Start-Process ncpa.cpl'; Label='Open Network Connections' }
        }
        'FWRISK'     = @{
            Steps   = @(
                'Open Windows Firewall with Advanced Security (wf.msc)',
                'Go to Inbound Rules',
                'Filter by Profile = Public and Action = Allow',
                'Disable or delete rules that are not needed',
                'Keep only rules tied to specific software you actively use'
            )
            Shortcut = @{ Cmd='Start-Process wf.msc'; Label='Open Advanced Firewall' }
        }
        'ASR'        = @{
            Steps   = @(
                'Open Windows Security',
                'Go to Virus & threat protection > Exploit protection settings',
                'Or configure ASR rules via PowerShell (see fix command above)',
                'Enable at least the Microsoft-recommended rules for Office and browser'
            )
            Shortcut = @{ Cmd='Start-Process "windowsdefender://threatsettings"'; Label='Open Threat Settings' }
        }
        'DEFEXCL-EXT'  = @{
            Steps   = @(
                'Open Windows Security > Virus & threat protection > Manage settings',
                'Go to Exclusions > Add or remove exclusions',
                'Remove the risky extensions listed in the Observed field',
                'Or run: Remove-MpPreference -ExclusionExtension ".ext" for each one'
            )
            Shortcut = @{ Cmd='Start-Process "windowsdefender://threatsettings"'; Label='Open Defender Settings' }
        }
        'DEFEXCL-PATH' = @{
            Steps   = @(
                'Open Windows Security > Virus & threat protection > Manage settings',
                'Go to Exclusions > Add or remove exclusions',
                'Remove the user-writable paths listed in the Observed field',
                'Or run: Remove-MpPreference -ExclusionPath "C:\path" for each one'
            )
            Shortcut = @{ Cmd='Start-Process "windowsdefender://threatsettings"'; Label='Open Defender Settings' }
        }
        'DEFEXCL-COUNT' = @{
            Steps   = @(
                'List all exclusions with:',
                'Get-MpPreference | Select ExclusionPath,ExclusionExtension,ExclusionProcess',
                'Remove exclusions that have no operational justification',
                'Run: Remove-MpPreference -ExclusionPath "..." to remove each one'
            )
            Shortcut = @{ Cmd='Start-Process "windowsdefender://threatsettings"'; Label='Open Defender Settings' }
        }
        'CERT-NONMS' = @{
            Steps   = @(
                'Open certlm.msc (Local Computer Certificates)',
                'Go to Trusted Root Certification Authorities > Certificates',
                'Review each certificate listed in the Observed field',
                'Remove only those you do not recognize as legitimate enterprise CAs',
                'WARNING: removing certificates used by the system can break applications'
            )
            Shortcut = @{ Cmd='Start-Process certlm.msc'; Label='Open Certificate Manager' }
        }
        'CERT-EXPIRED' = @{
            Steps   = @(
                'Open certlm.msc (Local Computer Certificates)',
                'Go to Personal > Certificates',
                'Sort by "Expiration Date"',
                'Delete expired certificates that are no longer in use',
                'Verify first that they are not used by any active applications'
            )
            Shortcut = @{ Cmd='Start-Process certlm.msc'; Label='Open Certificate Manager' }
        }
        'WEF'        = @{
            Steps   = @(
                'This is an advanced feature, optional for home environments',
                'Requires a WEC (Windows Event Collector) server on the network',
                'For a single PC, consider centralizing logs locally instead',
                'Open Event Viewer to access local security logs'
            )
            Shortcut = @{ Cmd='Start-Process eventvwr.msc'; Label='Open Event Viewer' }
        }
        'LOCALADMIN' = @{
            Steps   = @(
                'Open Local Users and Groups (lusrmgr.msc)',
                'Go to Groups > Administrators',
                'Review members: remove accounts that should not be there',
                'Keep only your primary account and the built-in Administrator (if needed)',
                'Or run: Remove-LocalGroupMember -Group Administrators -Member "name"'
            )
            Shortcut = @{ Cmd='Start-Process lusrmgr.msc'; Label='Open User Management' }
        }
        'LAPS'       = @{
            Steps   = @(
                'For non-domain PCs: this feature is not applicable',
                'For domain-joined PCs: configure Windows LAPS via Group Policy',
                'Go to gpedit.msc > Computer Configuration > Administrative Templates > System > LAPS',
                'Enable LAPS and configure password backup to Active Directory'
            )
            Shortcut = @{ Cmd='Start-Process gpedit.msc'; Label='Open Group Policy Editor' }
        }
        'SCHTASK-NOAUTHOR' = @{
            Steps   = @(
                'Open Task Scheduler (taskschd.msc)',
                'Browse to the tasks listed in the Observed field',
                'For each task without a recognized author: inspect the executable it runs',
                'Disable or delete tasks you do not recognize'
            )
            Shortcut = @{ Cmd='Start-Process taskschd.msc'; Label='Open Task Scheduler' }
        }
        'SCHTASK-WRITABLE' = @{
            Steps   = @(
                'Open Task Scheduler (taskschd.msc) and locate the affected task',
                'Note the executable path shown in the Observed field',
                'Open an elevated Command Prompt or PowerShell',
                'Run: icacls "<exe_path>" /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"',
                'Replace <exe_path> with the actual path from the Observed field',
                'Verify the task executable is from a trusted source'
            )
            Shortcut = @{ Cmd='Start-Process taskschd.msc'; Label='Open Task Scheduler' }
        }
        'SCHTASK-SYSTEM'   = @{
            Steps   = @(
                'Open Task Scheduler (taskschd.msc)',
                'Review each task running as SYSTEM listed in the Observed field',
                'For each task: check the Actions tab to see what executable is run',
                'Verify the executable path is signed and from a trusted vendor',
                'Disable tasks you do not recognize and cannot attribute to installed software'
            )
            Shortcut = @{ Cmd='Start-Process taskschd.msc'; Label='Open Task Scheduler' }
        }
        'UNQUOTED_SERVICE_PATH' = @{
            Steps   = @(
                'Open an elevated Command Prompt',
                'Run: sc qc "<ServiceName>" to view the current binary path',
                'Note the unquoted path shown in the Observed field',
                'Run: sc config "<ServiceName>" binPath= "\"<full quoted path>\""',
                'Replace <ServiceName> and <full quoted path> with the actual values',
                'Restart the service: sc stop "<ServiceName>" && sc start "<ServiceName>"'
            )
            Shortcut = @{ Cmd='Start-Process services.msc'; Label='Open Services' }
        }
    }

    foreach ($f in $Findings) {
        if (-not $f.PSObject.Properties['_FixType']) { continue }
        if ($f._FixType -ne 'Manual') { continue }

        $g = $guides[$f.Id]
        if (-not $g) {
            # Try prefix match for dynamic IDs like UNQUOTED_SERVICE_PATH:*
            foreach ($key in $guides.Keys) {
                if ($f.Id -like "$key*") { $g = $guides[$key]; break }
            }
        }
        if (-not $g) { continue }

        $f | Add-Member -NotePropertyName '_Guide'    -NotePropertyValue $g.Steps   -Force
        $f | Add-Member -NotePropertyName '_Shortcut' -NotePropertyValue $g.Shortcut -Force
    }
}
