#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckBaseline
#  TPM, Secure Boot, BitLocker, Defender, Windows Update.
# =============================================================================
function Invoke-CheckBaseline {
    # TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmPresent -and $tpm.TpmReady) {
            Add-Finding -Id 'TPM' -Category 'Baseline' -CheckName 'TPM 2.0 Ready' `
                -Severity 'PASS' -Vulnerable $false -Confidence 'High' `
                -Observed 'Ready' -Expected 'Ready' -Source 'Get-Tpm'
        } else {
            Add-Finding -Id 'TPM' -Category 'Baseline' -CheckName 'TPM 2.0 Ready' `
                -Severity 'HIGH' -Vulnerable $true -Confidence 'High' `
                -Observed "Present=$($tpm.TpmPresent) Ready=$($tpm.TpmReady)" `
                -Expected 'Ready' -Source 'Get-Tpm' `
                -Fix 'Enable and provision TPM 2.0 in BIOS/UEFI.' `
                -Note 'Required for BitLocker, Secure Boot attestation, and Windows Hello.'
        }
    } catch {
        Add-Finding -Id 'TPM' -Category 'Baseline' -CheckName 'TPM 2.0 Ready' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'NotApplicable' `
            -Observed 'ServiceUnavailable' -Expected 'Ready' -Source 'Get-Tpm' `
            -Note 'TPM service not present or module unavailable.'
    }

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            Add-Finding -Id 'SBOOT' -Category 'Baseline' -CheckName 'Secure Boot' `
                -Severity 'PASS' -Vulnerable $false -Confidence 'High' `
                -Observed 'True' -Expected 'True' -Source 'Confirm-SecureBootUEFI'
        } else {
            Add-Finding -Id 'SBOOT' -Category 'Baseline' -CheckName 'Secure Boot' `
                -Severity 'HIGH' -Vulnerable $true -Confidence 'High' `
                -Observed 'False' -Expected 'True' -Source 'Confirm-SecureBootUEFI' `
                -Fix 'Enable Secure Boot in UEFI firmware settings.' `
                -Note 'Prevents unsigned bootloaders and rootkits.'
        }
    } catch {
        Add-Finding -Id 'SBOOT' -Category 'Baseline' -CheckName 'Secure Boot' `
            -Severity 'HIGH' -Vulnerable $false -Confidence 'NotApplicable' `
            -Observed 'CmdletUnavailable' -Expected 'True' -Source 'Confirm-SecureBootUEFI' `
            -Note 'Likely legacy BIOS or virtual machine.'
    }

    # BitLocker
    if (-not $Script:IsAdmin) {
        Add-Finding -Id 'BLENC' -Category 'Baseline' -CheckName 'BitLocker Encryption' `
            -Severity 'CRITICAL' -Vulnerable $false -Confidence 'NoAccess' `
            -Observed 'RequiresElevation' -Expected 'FullyEncrypted' `
            -Source 'Get-BitLockerVolume' -Note 'Run as Administrator for BitLocker status.'
        Add-Finding -Id 'BLPBA' -Category 'Baseline' -CheckName 'BitLocker Pre-Boot Auth (PBA)' `
            -Severity 'HIGH' -Vulnerable $false -Confidence 'NoAccess' `
            -Observed 'RequiresElevation' -Expected 'Includes TpmAndPin' `
            -Source 'Get-BitLockerVolume'
    } else {
        try {
            $vols   = Get-BitLockerVolume -ErrorAction Stop
            $sysVol = $vols | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
            if (-not $sysVol) { $sysVol = $vols | Select-Object -First 1 }
            if ($sysVol) {
                $enc = $sysVol.VolumeStatus -in @('FullyEncrypted','EncryptionInProgress')
                Add-Finding -Id 'BLENC' -Category 'Baseline' -CheckName 'BitLocker Encryption' `
                    -Severity 'CRITICAL' -Vulnerable (-not $enc) -Confidence 'High' `
                    -Observed $sysVol.VolumeStatus -Expected 'FullyEncrypted' `
                    -Source 'Get-BitLockerVolume' `
                    -Fix 'Enable-BitLocker -MountPoint C: -EncryptionMethod Aes256 -UsedSpaceOnly' `
                    -Note 'Full-disk encryption prevents data exposure on lost/stolen devices.'
                $protTypes = $sysVol.KeyProtector.KeyProtectorType -join ', '
                $pbaVuln   = $sysVol.KeyProtector.KeyProtectorType -notcontains 'TpmPin'
                Add-Finding -Id 'BLPBA' -Category 'Baseline' -CheckName 'BitLocker Pre-Boot Auth (PBA)' `
                    -Severity 'HIGH' -Vulnerable $pbaVuln -Confidence 'High' `
                    -Observed "Protectors=$protTypes" -Expected 'Includes TpmAndPin' `
                    -Source 'Get-BitLockerVolume' `
                    -Fix 'Consider enabling TPM+PIN if theft/physical access is a concern.' `
                    -Note 'TPM+PIN improves resistance to offline/physical attacks.'
            } else {
                Add-Finding -Id 'BLENC' -Category 'Baseline' -CheckName 'BitLocker Encryption' `
                    -Severity 'CRITICAL' -Vulnerable $true -Confidence 'High' `
                    -Observed 'NoVolumeFound' -Expected 'FullyEncrypted' `
                    -Source 'Get-BitLockerVolume' -Fix 'Enable BitLocker on the OS drive.'
            }
        } catch {
            Add-Finding -Id 'BLENC' -Category 'Baseline' -CheckName 'BitLocker Encryption' `
                -Severity 'CRITICAL' -Vulnerable $false -Confidence 'QueryFailed' `
                -Observed "QueryFailed: $($_.Exception.Message)" -Expected 'FullyEncrypted' `
                -Source 'Get-BitLockerVolume'
        }
    }

    # Defender RTP
    try {
        $rtp = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
        Add-Finding -Id 'RTP' -Category 'Baseline' -CheckName 'Defender Real-Time Protection' `
            -Severity 'HIGH' -Vulnerable (-not $rtp) -Confidence 'High' `
            -Observed "$rtp" -Expected 'True' -Source 'Get-MpComputerStatus' `
            -Fix 'Set-MpPreference -DisableRealtimeMonitoring 0' `
            -Note 'Primary defence against malware.'
    } catch {
        Add-Finding -Id 'RTP' -Category 'Baseline' -CheckName 'Defender Real-Time Protection' `
            -Severity 'HIGH' -Vulnerable $false -Confidence 'NotApplicable' `
            -Observed 'DefenderUnavailable' -Expected 'True' -Source 'Get-MpComputerStatus' `
            -Note 'Defender not installed or third-party AV active.'
    }

    # PUA
    try {
        $pua = (Get-MpPreference -ErrorAction Stop).PUAProtection
        Add-Finding -Id 'PUA' -Category 'Baseline' -CheckName 'Defender PUA Protection' `
            -Severity 'LOW' -Vulnerable ($pua -ne 1) -Confidence 'High' `
            -Observed "PUAProtection=$pua" -Expected '1 (Enabled)' -Source 'Get-MpPreference' `
            -Fix 'Set-MpPreference -PUAProtection Enabled'
    } catch {
        Add-Finding -Id 'PUA' -Category 'Baseline' -CheckName 'Defender PUA Protection' `
            -Severity 'LOW' -Vulnerable $false -Confidence 'NotApplicable' `
            -Observed 'DefenderUnavailable' -Expected '1 (Enabled)' -Source 'Get-MpPreference'
    }

    # Controlled Folder Access
    try {
        $cfa = (Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess
        Add-Finding -Id 'CFA' -Category 'Baseline' -CheckName 'Controlled Folder Access' `
            -Severity 'LOW' -Vulnerable ($cfa -ne 1) -Confidence 'High' `
            -Observed "CFA=$cfa" -Expected '1 (Enabled)' -Source 'Get-MpPreference' `
            -Fix 'Set-MpPreference -EnableControlledFolderAccess Enabled' `
            -Note 'CFA blocks ransomware from encrypting protected folders.'
    } catch {
        Add-Finding -Id 'CFA' -Category 'Baseline' -CheckName 'Controlled Folder Access' `
            -Severity 'LOW' -Vulnerable $false -Confidence 'NotApplicable' `
            -Observed 'DefenderUnavailable' -Expected '1 (Enabled)' -Source 'Get-MpPreference'
    }

    # Windows Update — 4 sub-checks: service health, source trust, binary integrity, freshness

    # WU — Service not disabled (demand-start Manual is the correct Windows default)
    $wuSvc     = $null
    try { $wuSvc = Get-Service 'wuauserv' -ErrorAction SilentlyContinue } catch {}
    $wuStart   = if ($wuSvc) { $wuSvc.StartType.ToString() } else { 'Unknown' }
    $wuStatus  = if ($wuSvc) { $wuSvc.Status.ToString() }    else { 'Unknown' }
    $wuDisabled = $wuStart -eq 'Disabled'
    Add-Finding -Id 'WU' -Category 'Baseline' -CheckName 'Windows Update Service' `
        -Severity 'MEDIUM' -Vulnerable $wuDisabled -Confidence 'High' `
        -Observed "wuauserv StartType=$wuStart Status=$wuStatus" -Expected 'StartType!=Disabled' `
        -Source 'Service' `
        -Fix 'Set-Service wuauserv -StartupType Manual' `
        -Note 'wuauserv is demand-start by design; Stopped+Manual is healthy. Disabled blocks all updates.'

    # WU-SRC — Update source trust (WSUS hijack detection)
    $wuKey      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auKey      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $useWU      = Get-RegValue -Path $auKey  -Name 'UseWUServer'  -Default 0
    $wuServer   = Get-RegValue -Path $wuKey  -Name 'WUServer'     -Default ''
    if ($useWU -eq 1 -and $wuServer) {
        $isHttps   = $wuServer -match '^https://'
        $wuSrcVuln = -not $isHttps
        $wuSrcSev  = if ($wuSrcVuln) { 'HIGH' } else { 'PASS' }
        $wuSrcNote = if ($wuSrcVuln) {
            'HTTP WSUS is susceptible to WSUS poisoning (CVE-2020-1013). Attackers on the network can inject malicious updates.'
        } else {
            'WSUS configured with HTTPS — source is encrypted in transit.'
        }
        Add-Finding -Id 'WU-SRC' -Category 'Baseline' -CheckName 'Windows Update Source Trust' `
            -Severity $wuSrcSev -Vulnerable $wuSrcVuln -Confidence 'High' `
            -Observed "UseWUServer=1 WUServer=$wuServer" -Expected 'HTTPS WSUS endpoint' `
            -Source 'Registry' `
            -Fix 'Enforce HTTPS on WSUS: configure SSL on the WSUS server and update WUServer/WUStatusServer policies to https://.' `
            -Note $wuSrcNote
    } else {
        Add-Finding -Id 'WU-SRC' -Category 'Baseline' -CheckName 'Windows Update Source Trust' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'High' `
            -Observed 'UseWUServer=0 (direct Microsoft Update)' -Expected 'Direct or HTTPS WSUS' `
            -Source 'Registry' `
            -Note 'Updates sourced directly from Microsoft Update — no WSUS redirection.'
    }

    # WU-SIGN — Authenticode integrity of core WU binaries
    $wuBinaries   = @(
        [IO.Path]::Combine($env:SystemRoot, 'System32', 'wuaueng.dll'),
        [IO.Path]::Combine($env:SystemRoot, 'System32', 'wuapi.dll'),
        [IO.Path]::Combine($env:SystemRoot, 'System32', 'wuauclt.exe')
    )
    $wuSignFailed = [System.Collections.Generic.List[string]]::new()
    $wuSignObs    = [System.Collections.Generic.List[string]]::new()
    foreach ($bin in $wuBinaries) {
        $leaf = [IO.Path]::GetFileName($bin)
        if (-not (Test-Path $bin)) {
            $wuSignFailed.Add($leaf)
            $wuSignObs.Add("$leaf=NotFound")
            continue
        }
        try {
            $sig = Get-AuthenticodeSignature -FilePath $bin -ErrorAction Stop
            $ok  = ($sig.Status -eq 'Valid') -and ($sig.SignerCertificate.Subject -match 'Microsoft')
            $wuSignObs.Add("$leaf=$($sig.Status)")
            if (-not $ok) { $wuSignFailed.Add("$leaf(Status=$($sig.Status))") }
        } catch {
            $wuSignFailed.Add("$leaf(QueryFailed)")
            $wuSignObs.Add("$leaf=QueryFailed")
        }
    }
    $wuSignVuln = $wuSignFailed.Count -gt 0
    $wuSignSev  = if ($wuSignVuln) { 'CRITICAL' } else { 'PASS' }
    Add-Finding -Id 'WU-SIGN' -Category 'Baseline' -CheckName 'Windows Update Binary Integrity' `
        -Severity $wuSignSev -Vulnerable $wuSignVuln -Confidence 'High' `
        -Observed ($wuSignObs -join ' ') `
        -Expected 'All Valid + Microsoft signer' -Source 'Authenticode' `
        -Fix 'Run: sfc /scannow  then  DISM /Online /Cleanup-Image /RestoreHealth  to restore tampered system binaries.' `
        -Note 'Verifies Authenticode signature of wuaueng.dll, wuapi.dll, wuauclt.exe against Microsoft root CA.'

    # WU-STALE — Update freshness (>90 days without an installed hotfix = flag)
    $wuStaleVuln = $false
    $wuStaleObs  = 'Unknown'
    $wuStaleConf = 'Medium'
    try {
        $lastHf = Get-HotFix -ErrorAction Stop |
                  Where-Object { $_.InstalledOn } |
                  Sort-Object InstalledOn -Descending |
                  Select-Object -First 1
        if ($lastHf -and $lastHf.InstalledOn) {
            $daysSince   = ([datetime]::Today - [datetime]$lastHf.InstalledOn).Days
            $wuStaleVuln = $daysSince -gt 90
            $wuStaleObs  = "LastHotfix=$($lastHf.HotFixID) InstalledOn=$($lastHf.InstalledOn.ToString('yyyy-MM-dd')) DaysAgo=$daysSince"
        } else {
            $wuStaleObs  = 'NoHotfixFound'
            $wuStaleVuln = $true
            $wuStaleConf = 'Low'
        }
    } catch {
        $wuStaleObs  = "QueryFailed: $($_.Exception.Message)"
        $wuStaleConf = 'QueryFailed'
    }
    Add-Finding -Id 'WU-STALE' -Category 'Baseline' -CheckName 'Windows Update Freshness' `
        -Severity 'MEDIUM' -Vulnerable $wuStaleVuln -Confidence $wuStaleConf `
        -Observed $wuStaleObs -Expected 'Hotfix installed within 90 days' -Source 'Get-HotFix' `
        -Fix 'Run Windows Update to install pending patches, or investigate blocking Group Policy.' `
        -Note 'Get-HotFix covers cumulative/security updates. Gap >90 days may indicate WU is blocked or broken.'
}
