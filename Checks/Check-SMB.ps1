#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckSMB
#  SMBv1, signing (server + client), encryption.
# =============================================================================
function Invoke-CheckSMB {
    if (-not $Script:IsAdmin) {
        foreach ($chk in @(
            @{Id='SMB1';   Name='SMBv1 Protocol';               Sev='CRITICAL';Src='Get-SmbServerConfiguration'}
            @{Id='SMBSIGS';Name='SMB Signing (Server Required)'; Sev='MEDIUM'; Src='Get-SmbServerConfiguration'}
            @{Id='SMBSIGC';Name='SMB Signing (Client Required)'; Sev='MEDIUM'; Src='Get-SmbClientConfiguration'}
            @{Id='SMBENC'; Name='SMB Encryption (Server)';       Sev='LOW';    Src='Get-SmbServerConfiguration'}
        )) {
            Add-Finding -Id $chk.Id -Category 'SMB' -CheckName $chk.Name `
                -Severity $chk.Sev -Vulnerable $false -Confidence 'NoAccess' `
                -Observed 'RequiresElevation' -Expected 'Configured' -Source $chk.Src `
                -Note 'SMB configuration query requires administrator elevation.'
        }
        return
    }
    # SMBv1
    try {
        $srv  = Get-SmbServerConfiguration -ErrorAction Stop
        $feat = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
        $featState = if ($feat) { $feat.State } else { 'Unknown' }
        Add-Finding -Id 'SMB1' -Category 'SMB' -CheckName 'SMBv1 Protocol' `
            -Severity 'CRITICAL' -Vulnerable $srv.EnableSMB1Protocol -Confidence 'High' `
            -Observed "ServerSMBv1=$($srv.EnableSMB1Protocol) ClientFeature=$featState" `
            -Expected 'Disabled' -Source 'Get-SmbServerConfiguration' `
            -Fix 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' `
            -Note 'SMBv1 is the EternalBlue/WannaCry attack vector. Disable unconditionally.'
    } catch {
        Add-Finding -Id 'SMB1' -Category 'SMB' -CheckName 'SMBv1 Protocol' `
            -Severity 'CRITICAL' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'Disabled' -Source 'Get-SmbServerConfiguration'
    }

    # SMB signing - server
    try {
        $sig = (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature
        Add-Finding -Id 'SMBSIGS' -Category 'SMB' -CheckName 'SMB Signing (Server Required)' `
            -Severity 'MEDIUM' -Vulnerable (-not $sig) -Confidence 'High' `
            -Observed "RequireSecuritySignature=$sig" -Expected 'True' `
            -Source 'Get-SmbServerConfiguration' `
            -Fix 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force' `
            -Note 'Without required signing, NTLM relay attacks are feasible.'
    } catch {
        Add-Finding -Id 'SMBSIGS' -Category 'SMB' -CheckName 'SMB Signing (Server Required)' `
            -Severity 'MEDIUM' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'True' -Source 'Get-SmbServerConfiguration'
    }

    # SMB signing - client
    try {
        $sig = (Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature
        Add-Finding -Id 'SMBSIGC' -Category 'SMB' -CheckName 'SMB Signing (Client Required)' `
            -Severity 'MEDIUM' -Vulnerable (-not $sig) -Confidence 'High' `
            -Observed "RequireSecuritySignature=$sig" -Expected 'True' `
            -Source 'Get-SmbClientConfiguration' `
            -Fix 'Set-SmbClientConfiguration -RequireSecuritySignature $true -Force'
    } catch {
        Add-Finding -Id 'SMBSIGC' -Category 'SMB' -CheckName 'SMB Signing (Client Required)' `
            -Severity 'MEDIUM' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'True' -Source 'Get-SmbClientConfiguration'
    }

    # SMB encryption (server-side) [Sprint D]
    try {
        $enc = (Get-SmbServerConfiguration -ErrorAction Stop).EncryptData
        Add-Finding -Id 'SMBENC' -Category 'SMB' -CheckName 'SMB Encryption (Server)' `
            -Severity 'LOW' -Vulnerable (-not $enc) -Confidence 'High' `
            -Observed "EncryptData=$enc" -Expected 'True' `
            -Source 'Get-SmbServerConfiguration' `
            -Fix 'Set-SmbServerConfiguration -EncryptData $true -Force' `
            -Note 'SMB encryption protects file-transfer confidentiality on the local network. May impact throughput on older clients -- test before enforcing.'
    } catch {
        Add-Finding -Id 'SMBENC' -Category 'SMB' -CheckName 'SMB Encryption (Server)' `
            -Severity 'LOW' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'True' -Source 'Get-SmbServerConfiguration'
    }
}
