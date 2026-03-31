#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckWEF
#  Windows Event Forwarding (Deep mode only).
# =============================================================================
function Invoke-CheckWEF {
    $wecStat = Get-SvcStatus 'Wecsvc'
    if (-not $Script:IsAdmin) {
        Add-Finding -Id 'WEF' -Category 'EventFwd' -CheckName 'Windows Event Collector / WEF' `
            -Severity 'LOW' -Vulnerable $false -Confidence 'NoAccess' `
            -Observed "Wecsvc=$wecStat Subscriptions=RequiresElevation" `
            -Expected 'Subscriptions configured (enterprise/SOC)' -Source 'Service + wecutil' `
            -Note 'WEF subscription enumeration (wecutil) requires administrator elevation.'
        return
    }
    $subOut  = Invoke-Exe 'wecutil.exe' @('es')
    $subCnt  = @(($subOut.Trim() -split "`n") | Where-Object { $_ -ne '' }).Count
    $wefV    = $subCnt -eq 0
    $wefSev  = if ($wefV) { 'LOW' } else { 'PASS' }
    Add-Finding -Id 'WEF' -Category 'EventFwd' -CheckName 'Windows Event Collector / WEF' `
        -Severity $wefSev -Vulnerable $wefV -Confidence 'Medium' `
        -Observed "Wecsvc=$wecStat Subscriptions=$subCnt" `
        -Expected 'Subscriptions configured (enterprise/SOC)' -Source 'Service + wecutil' `
        -Fix 'Optional: configure WEF subscriptions for centralised log collection.' `
        -Note 'Standalone endpoints can skip this; relevant for enterprise SOC deployments.'
}
