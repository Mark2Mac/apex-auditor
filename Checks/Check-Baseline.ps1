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

    # Windows Update
    $wuStat = Get-SvcStatus 'wuauserv'
    Add-Finding -Id 'WU' -Category 'Baseline' -CheckName 'Windows Update Mechanism' `
        -Severity 'LOW' -Vulnerable ($wuStat -ne 'Running') -Confidence 'Medium' `
        -Observed "wuauserv=$wuStat" -Expected 'Running' -Source 'Service' `
        -Fix 'Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv' `
        -Note 'Offline check only.'
}
