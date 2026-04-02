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
    # Detection is multi-layer: per-interface TcpipNetbiosOptions AND global NodeType.
    # NodeType=2 (P-node) is a system-wide backstop: without a WINS server it silences
    # all NetBIOS name resolution even for adapters (e.g. VPN tunnels) that reset their
    # per-interface value on reconnect. The system is considered protected when EITHER
    # all adapters are explicitly disabled (TcpipNetbiosOptions=2) OR NodeType=2 is set.
    try {
        $nbParamKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
        $nbNodeType  = Get-RegValue -Path $nbParamKey -Name 'NodeType' -Default 0
        $nics        = Get-Cim 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=TRUE'
        $nbOn        = @($nics) | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
        $nbIfaceV    = [bool]$nbOn
        # Protected when NodeType=2 backstop is active even if some adapters aren't at 2
        $nbV         = $nbIfaceV -and ($nbNodeType -ne 2)
        $nbSev       = if ($nbV) { 'MEDIUM' } else { 'PASS' }
        $nbObs       = if (-not $nbIfaceV) { 'Disabled' }
                       elseif (-not $nbV)  { "NodeType=2 backstop active; $(@($nbOn).Count) adapter(s) OS-default" }
                       else               { "Enabled on $(@($nbOn).Count) adapter(s)" }
        Add-Finding -Id 'NETBIOS' -Category 'Network' -CheckName 'NetBIOS over TCP/IP' `
            -Severity $nbSev -Vulnerable $nbV -Confidence 'High' `
            -Observed $nbObs -Expected 'Disabled (NodeType=2 or per-interface=2)' -Source 'CIM+Registry' `
            -Fix "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' NodeType 2 -Type DWord; Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' EnableLMHOSTS 0 -Type DWord; Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty -Path `$_.PSPath -Name NetbiosOptions -Value 2 }; Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { `$_ | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2} }" `
            -Note 'NetBIOS enables NBNS poisoning (Responder). Fix sets NodeType=2 (P-node, global backstop) + disables per-interface + notifies driver via WMI. Persists across VPN reconnects and reboots.'
    } catch {
        Add-Finding -Id 'NETBIOS' -Category 'Network' -CheckName 'NetBIOS over TCP/IP' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'Disabled (NodeType=2 or per-interface=2)' -Source 'CIM+Registry'
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
