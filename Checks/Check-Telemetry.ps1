#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckTelemetry
#  Sysmon telemetry readiness (informational).
# =============================================================================
function Invoke-CheckTelemetry {
    $svcName = if ((Get-SvcStatus 'Sysmon64') -ne 'NotFound') { 'Sysmon64' } else { 'Sysmon' }
    $svcStat = Get-SvcStatus $svcName
    $sysObs  = if ($svcStat -ne 'NotFound') { "Installed Running=$($svcStat -eq 'Running')" } else { 'NotInstalled' }
    Add-Finding -Id 'SYSMON' -Category 'Telemetry' -CheckName 'Sysmon Telemetry Readiness' `
        -Severity 'PASS' -Vulnerable $false -Confidence 'High' `
        -Observed $sysObs -Expected 'Installed + Running' -Source 'Service' `
        -Note 'Sysmon is not a built-in component. Absence is informational, not a vulnerability.'
}
