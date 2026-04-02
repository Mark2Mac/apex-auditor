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
        $cnt  = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow `
                    -ErrorAction SilentlyContinue |
                  Where-Object { $_.Profile -match 'Public' -and -not $_.Owner }).Count
        $vuln = $cnt -gt 5
        $sev  = if ($vuln) { 'MEDIUM' } else { 'PASS' }
        $obs  = if ($cnt -eq 0) { 'None' } else { "Count=$cnt" }
        Add-Finding -Id 'FWRISK' -Category 'Firewall' -CheckName 'Risky Inbound Allow Rules (Public)' `
            -Severity $sev -Vulnerable $vuln -Confidence 'Medium' `
            -Observed $obs -Expected 'None or minimal' -Source 'Get-NetFirewallRule' `
            -Fix 'Review and tighten inbound firewall rules on the Public profile.' `
            -Note 'High rule count on Public profile increases attack surface.'
    } catch {
        Add-Finding -Id 'FWRISK' -Category 'Firewall' -CheckName 'Risky Inbound Allow Rules (Public)' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'None' -Source 'Get-NetFirewallRule'
    }
}
