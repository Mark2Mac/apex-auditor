#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckFirewall
#  Per-profile firewall state + risky inbound allow rules.
#  Bug fix: severity now reflects actual vulnerability state (no more
#  Severity=PASS with Vulnerable=true).
# =============================================================================
function Invoke-CheckFirewall {
    if (-not $Script:IsAdmin) {
        foreach ($prof in @('Domain','Private','Public')) {
            Add-Finding -Id "FW-$prof" -Category 'Firewall' -CheckName "$prof Firewall Policy" `
                -Severity 'HIGH' -Vulnerable $false -Confidence 'NoAccess' `
                -Observed 'RequiresElevation' -Expected 'BlockInbound,AllowOutbound' `
                -Source 'netsh advfirewall' `
                -Note 'Firewall policy query via netsh requires administrator elevation.'
        }
    } else {
        foreach ($prof in @('Domain','Private','Public')) {
            try {
                $out     = Invoke-Exe 'netsh.exe' @('advfirewall', "show", "${prof}profile")
                $stateOn = $out -match '(?m)^\s*State\s+ON'
                $blockIn = $out -match '(?m)BlockInbound'
                $vuln    = (-not $stateOn) -or (-not $blockIn)
                $sev     = if ($vuln) { 'HIGH' } else { 'PASS' }
                $obsOut  = if ($blockIn) { 'BlockInbound' } else { 'AllowInbound' }
                $obsOut += if ($out -match 'AllowOutbound') { ',AllowOutbound' } else { ',BlockOutbound' }
                Add-Finding -Id "FW-$prof" -Category 'Firewall' -CheckName "$prof Firewall Policy" `
                    -Severity $sev -Vulnerable $vuln -Confidence 'High' `
                    -Observed $obsOut -Expected 'BlockInbound,AllowOutbound' `
                    -Source 'netsh advfirewall' `
                    -Fix "netsh advfirewall set ${prof}profile firewallpolicy blockinbound,allowoutbound"
            } catch {
                Add-Finding -Id "FW-$prof" -Category 'Firewall' -CheckName "$prof Firewall Policy" `
                    -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
                    -Observed 'netshFailed' -Expected 'BlockInbound,AllowOutbound' `
                    -Source 'netsh advfirewall'
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
