#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckFirewallPosture  [Sprint D]
#  MpsSvc service health + dropped-packet logging on the Public profile.
# =============================================================================
function Invoke-CheckFirewallPosture {
    # FW-SVC: Windows Firewall service
    $mpsStat     = Get-SvcStatus 'MpsSvc'
    $mpsSI       = $null
    try { $mpsSI = Get-Service 'MpsSvc' -ErrorAction SilentlyContinue } catch { Write-Warning "Suppressed: $_" }
    $mpsDisabled = $mpsSI -and $mpsSI.StartType -eq 'Disabled'
    $fwSvcVuln   = ($mpsStat -ne 'Running') -or $mpsDisabled
    $startType   = if ($mpsSI) { $mpsSI.StartType } else { 'Unknown' }
    Add-Finding -Id 'FW-SVC' -Category 'Firewall' -CheckName 'Windows Firewall Service (MpsSvc)' `
        -Severity 'CRITICAL' -Vulnerable $fwSvcVuln -Confidence 'High' `
        -Observed "Status=$mpsStat StartType=$startType" `
        -Expected 'Running, StartType=Automatic' -Source 'Service' `
        -Fix 'Set-Service MpsSvc -StartupType Automatic; Start-Service MpsSvc' `
        -Note 'A stopped/disabled Windows Firewall service disables all host-based packet filtering.'

    # FW-LOG: Dropped-packet logging on Public profile
    if (-not $Script:IsAdmin) {
        Add-Finding -Id 'FW-LOG' -Category 'Firewall' -CheckName 'Firewall Drop Logging (Public Profile)' `
            -Severity 'LOW' -Vulnerable $false -Confidence 'NoAccess' `
            -Observed 'RequiresElevation' -Expected 'LogDroppedPackets=Yes' -Source 'Get-NetFirewallProfile' `
            -Note 'Firewall logging query requires administrator elevation.'
    } else {
        try {
            $pub         = Get-NetFirewallProfile -Name Public -ErrorAction Stop
            $logDropped  = ($pub.LogBlocked -eq 'True') -or ($pub.LogBlocked -eq $true)
            $logFilePath = [string]$pub.LogFileName
            $logVuln     = -not $logDropped
            $logObs      = if ($logDropped) { "Enabled LogFile=$logFilePath" } else { 'Disabled' }
            Add-Finding -Id 'FW-LOG' -Category 'Firewall' -CheckName 'Firewall Drop Logging (Public Profile)' `
                -Severity 'LOW' -Vulnerable $logVuln -Confidence 'High' `
                -Observed $logObs -Expected 'LogDroppedPackets=Yes' -Source 'Get-NetFirewallProfile' `
                -Fix 'netsh advfirewall set publicprofile logging droppedconnections enable' `
                -Note 'Logging dropped packets on the Public profile exposes port scans and inbound connection attempts for forensic review.'
        } catch {
            Add-Finding -Id 'FW-LOG' -Category 'Firewall' -CheckName 'Firewall Drop Logging (Public Profile)' `
                -Severity 'LOW' -Vulnerable $false -Confidence 'QueryFailed' `
                -Observed 'QueryFailed' -Expected 'LogDroppedPackets=Yes' -Source 'Get-NetFirewallProfile'
        }
    }
}
