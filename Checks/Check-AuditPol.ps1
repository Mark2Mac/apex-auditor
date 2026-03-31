#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckAuditPol
#  Windows Advanced Audit Policy -- 6 subcategories.
# =============================================================================
function Invoke-CheckAuditPol {
    if (-not $Script:IsAdmin) {
        foreach ($chk in @(
            @{Id='AUDITPOL_PROCESS_CREATION';Name='Audit: Process Creation (4688)';   Sev='MEDIUM'}
            @{Id='AUDITPOL_CREDENTIAL_VALID';Name='Audit: Credential Validation';     Sev='MEDIUM'}
            @{Id='AUDITPOL_LOGON';           Name='Audit: Logon/Logoff';              Sev='MEDIUM'}
            @{Id='AUDITPOL_LOCKOUT';         Name='Audit: Account Lockout';           Sev='LOW'}
            @{Id='AUDITPOL_SPECIAL_LOGON';   Name='Audit: Special Logon';             Sev='LOW'}
            @{Id='AUDITPOL_GROUP_MGMT';      Name='Audit: Security Group Management'; Sev='LOW'}
        )) {
            Add-Finding -Id $chk.Id -Category 'AuditPolicy' -CheckName $chk.Name `
                -Severity $chk.Sev -Vulnerable $false -Confidence 'NoAccess' `
                -Observed 'RequiresElevation' -Expected 'Success' -Source 'auditpol.exe' `
                -Note 'Audit policy query requires administrator elevation.'
        }
        return
    }
    $apOut  = Invoke-Exe 'auditpol.exe' @('/get','/category:*')
    $checks = @(
        @{Id='AUDITPOL_PROCESS_CREATION';Name='Audit: Process Creation (4688)';   Pattern='Process Creation';          Severity='MEDIUM';Fix='auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable'}
        @{Id='AUDITPOL_CREDENTIAL_VALID';Name='Audit: Credential Validation';     Pattern='Credential Validation';     Severity='MEDIUM';Fix='auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable'}
        @{Id='AUDITPOL_LOGON';           Name='Audit: Logon/Logoff';              Pattern='Logon';                     Severity='MEDIUM';Fix='auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable'}
        @{Id='AUDITPOL_LOCKOUT';         Name='Audit: Account Lockout';           Pattern='Account Lockout';           Severity='LOW';   Fix='auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /success:enable'}
        @{Id='AUDITPOL_SPECIAL_LOGON';   Name='Audit: Special Logon';             Pattern='Special Logon';             Severity='LOW';   Fix='auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable'}
        @{Id='AUDITPOL_GROUP_MGMT';      Name='Audit: Security Group Management'; Pattern='Security Group Management'; Severity='LOW';   Fix='auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable'}
    )
    foreach ($chk in $checks) {
        $line       = ($apOut -split "`n") | Where-Object { $_ -match [regex]::Escape($chk.Pattern) } | Select-Object -First 1
        $hasSuccess = $line -match 'Success'
        $vuln       = -not $hasSuccess
        $sev        = if ($vuln) { $chk.Severity } else { 'PASS' }
        $obs        = if ($hasSuccess) { 'Success' } else { 'NoAuditing' }
        Add-Finding -Id $chk.Id -Category 'AuditPolicy' -CheckName $chk.Name `
            -Severity $sev -Vulnerable $vuln -Confidence 'High' `
            -Observed $obs -Expected 'Success' -Source 'auditpol.exe' -Fix $chk.Fix
    }
}
