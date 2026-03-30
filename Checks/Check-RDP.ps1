#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckRDP
#  RDP enabled state + Network Level Authentication.
# =============================================================================
function Invoke-CheckRDP {
    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpOn = (Get-RegValue -Path $tsKey -Name 'fDenyTSConnections' -Default 1) -eq 0
    if (-not $rdpOn) {
        Add-Finding -Id 'RDP' -Category 'RDP' -CheckName 'RDP Enabled' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'High' `
            -Observed 'Disabled' -Expected 'Disabled' -Source 'Registry'
        Add-Finding -Id 'RDP-NLA' -Category 'RDP' -CheckName 'RDP Network Level Auth' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'High' `
            -Observed 'N/A' -Expected 'N/A' -Source 'Registry' `
            -Note 'RDP is disabled; NLA check not applicable.'
        return
    }
    Add-Finding -Id 'RDP' -Category 'RDP' -CheckName 'RDP Enabled' `
        -Severity 'HIGH' -Vulnerable $true -Confidence 'High' `
        -Observed 'Enabled' -Expected 'Disabled (or restricted)' -Source 'Registry' `
        -Fix "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1" `
        -Note 'Disable RDP if not required, or restrict via firewall and VPN gating.'
    $nlaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $nla    = Get-RegValue -Path $nlaKey -Name 'UserAuthenticationRequired' -Default 0
    Add-Finding -Id 'RDP-NLA' -Category 'RDP' -CheckName 'RDP Network Level Auth' `
        -Severity 'HIGH' -Vulnerable ($nla -ne 1) -Confidence 'High' `
        -Observed "NLA=$nla" -Expected '1 (Required)' -Source 'Registry' `
        -Fix "Set-ItemProperty '$nlaKey' UserAuthenticationRequired 1" `
        -Note 'NLA forces authentication before the RDP session is established.'
}
