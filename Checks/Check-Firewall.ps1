#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckFirewall
#  Per-profile firewall state + risky inbound allow rules.
#  Uses Get-NetFirewallProfile for locale-independent state detection.
# =============================================================================
function Invoke-CheckFirewall {
    if (-not $Script:IsAdmin) {
        foreach ($prof in @('Domain','Private','Public')) {
            Add-Finding -Id "FW-$prof" -Category 'Firewall' -CheckName "$prof Firewall Policy" `
                -Severity 'HIGH' -Vulnerable $false -Confidence 'NoAccess' `
                -Observed 'RequiresElevation' -Expected 'State=ON,BlockInbound,AllowOutbound' `
                -Source 'Get-NetFirewallProfile' `
                -Note 'Firewall policy query requires administrator elevation.'
        }
    } else {
        foreach ($prof in @('Domain','Private','Public')) {
            try {
                $fp       = Get-NetFirewallProfile -Name $prof -ErrorAction Stop
                $stateOn  = [bool]$fp.Enabled
                $blockIn  = ($fp.DefaultInboundAction  -eq 'Block')
                $allowOut = ($fp.DefaultOutboundAction -eq 'Allow')
                $vuln     = (-not $stateOn) -or (-not $blockIn)
                $sev      = if ($vuln) { 'HIGH' } else { 'PASS' }
                $stateStr = if ($stateOn) { 'ON' } else { 'OFF' }
                $obsOut   = "State=$stateStr,"
                $obsOut  += if ($blockIn)  { 'BlockInbound'  } else { 'AllowInbound'  }
                $obsOut  += if ($allowOut) { ',AllowOutbound' } else { ',BlockOutbound' }
                Add-Finding -Id "FW-$prof" -Category 'Firewall' -CheckName "$prof Firewall Policy" `
                    -Severity $sev -Vulnerable $vuln -Confidence 'High' `
                    -Observed $obsOut -Expected 'State=ON,BlockInbound,AllowOutbound' `
                    -Source 'Get-NetFirewallProfile' `
                    -Fix "netsh advfirewall set ${prof}profile state on; netsh advfirewall set ${prof}profile firewallpolicy blockinbound,allowoutbound"
            } catch {
                Add-Finding -Id "FW-$prof" -Category 'Firewall' -CheckName "$prof Firewall Policy" `
                    -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
                    -Observed 'QueryFailed' -Expected 'State=ON,BlockInbound,AllowOutbound' `
                    -Source 'Get-NetFirewallProfile'
            }
        }
    }
    try {
        # Pre-check: detect third-party firewall.
        # root\SecurityCenter2 only exists on Windows client SKUs (ProductType=1).
        # On Windows Server the namespace is absent; default to $true (safe: skip auto-fix).
        $thirdPartyFW = $false
        try {
            $isServer = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -ne 1
            if ($isServer) {
                $thirdPartyFW = $true  # Can't query SecurityCenter2 on Server; conservative default
            } else {
                $fwProducts = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'FirewallProduct' -ErrorAction SilentlyContinue)
                $thirdPartyFW = $fwProducts.Count -gt 0
            }
        } catch { }

        $cnt  = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow `
                    -ErrorAction SilentlyContinue |
                  Where-Object { $_.Profile -match 'Public' -and -not $_.Owner -and (-not $_.Group) }).Count
        $vuln = $cnt -gt 5
        $sev  = if ($vuln) { 'MEDIUM' } else { 'PASS' }
        $obs  = if ($cnt -eq 0) { 'None' } else { "Count=$cnt" }
        Add-Finding -Id 'FWRISK' -Category 'Firewall' -CheckName 'Risky Inbound Allow Rules (Public)' `
            -Severity $sev -Vulnerable $vuln -Confidence 'Medium' `
            -Observed $obs -Expected 'None or minimal' -Source 'Get-NetFirewallRule' `
            -Fix $(if(-not $thirdPartyFW){'Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { $_.Profile -match ''Public'' -and -not $_.Owner -and (-not $_.Group) } | Disable-NetFirewallRule'}else{'N/A'}) `
            -Note $(if($thirdPartyFW){'Third-party firewall detected; Windows Firewall rules are not the primary control.'}else{'Disables third-party app rules on Public profile. Built-in Windows rules (printers, mDNS, Wi-Fi Direct) are preserved.'})
    } catch {
        Add-Finding -Id 'FWRISK' -Category 'Firewall' -CheckName 'Risky Inbound Allow Rules (Public)' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'None' -Source 'Get-NetFirewallRule'
    }
}
