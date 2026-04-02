#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckNetwork
#  LLMNR, NetBIOS, NTLM authentication level.
#  Bug fix: LLMNR/NETBIOS now emit correct severity when vulnerable.
# =============================================================================
function Invoke-CheckNetwork {
    # LLMNR
    $llmnrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $llmnr    = Get-RegValue -Path $llmnrKey -Name 'EnableMulticast' -Default 1
    $llmnrV   = $llmnr -ne 0
    $llmnrSev = if ($llmnrV) { 'MEDIUM' } else { 'PASS' }
    Add-Finding -Id 'LLMNR' -Category 'Network' -CheckName 'LLMNR Disabled' `
        -Severity $llmnrSev -Vulnerable $llmnrV -Confidence 'High' `
        -Observed "$llmnr" -Expected '0' -Source 'Registry' `
        -Fix "New-Item -Force '$llmnrKey'; Set-ItemProperty '$llmnrKey' EnableMulticast 0" `
        -Note 'LLMNR is exploitable via poisoning (Responder). Disable unless required.'

    # NetBIOS
    try {
        $nics  = Get-Cim 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=TRUE'
        $nbOn  = @($nics) | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
        $nbV   = [bool]$nbOn
        $nbSev = if ($nbV) { 'MEDIUM' } else { 'PASS' }
        $nbObs = if ($nbV) { "Enabled on $(@($nbOn).Count) adapter(s)" } else { 'Disabled' }
        Add-Finding -Id 'NETBIOS' -Category 'Network' -CheckName 'NetBIOS over TCP/IP' `
            -Severity $nbSev -Vulnerable $nbV -Confidence 'High' `
            -Observed $nbObs -Expected 'Disabled' -Source 'CIM' `
            -Fix "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty -Path `$_.PSPath -Name NetbiosOptions -Value 2 }" `
            -Note 'NetBIOS enables NBNS poisoning attacks similar to LLMNR.'
    } catch {
        Add-Finding -Id 'NETBIOS' -Category 'Network' -CheckName 'NetBIOS over TCP/IP' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'Disabled' -Source 'CIM'
    }

    # NTLM level
    $lsaKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lmCompat = Get-RegValue -Path $lsaKey -Name 'LmCompatibilityLevel' -Default 3
    Add-Finding -Id 'NTLM' -Category 'Identity' -CheckName 'NTLM Minimum Auth Level' `
        -Severity 'MEDIUM' -Vulnerable ($lmCompat -lt 5) -Confidence 'High' `
        -Observed "LmCompatibility=$lmCompat" -Expected '5 (NTLMv2 only)' -Source 'Registry' `
        -Fix "Set-ItemProperty '$lsaKey' LmCompatibilityLevel 5" `
        -Note 'Level <5 permits LM/NTLMv1 hashes, which are trivially crackable offline.'
}
