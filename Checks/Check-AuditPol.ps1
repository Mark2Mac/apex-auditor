#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckAuditPol
#  Windows Advanced Audit Policy -- 6 subcategories.
#  Queries per-GUID to avoid locale-dependent text parsing.
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

    # ---------------------------------------------------------------------------
    #  Self-calibrate: learn what "No Auditing" looks like in the current locale.
    #  We query "Filtering Platform Packet Drop" -- rarely enabled on home/office PCs.
    #  If the calibration subcategory happens to be enabled we fall back to a
    #  known-locale list, which covers EN/IT/DE/FR/ES/PT/NL.
    # ---------------------------------------------------------------------------
    $calRaw  = Invoke-Exe 'auditpol.exe' @('/get', '/subcategory:{0CCE9225-69AE-11D9-BED3-505054503030}')
    $calLine = ($calRaw -split "`n") | Where-Object { $_.Trim() -and $_ -match '^\s+\S' } | Select-Object -Last 1
    $calToken = ''
    if ($calLine -match '\s{2,}(\S.+)$') { $calToken = $Matches[1].Trim() }

    # Fallback patterns for common Windows locales (No Auditing equivalents)
    $fallbackNoAudit = 'No Auditing|Nessun controllo|Keine .berwachung|Aucun audit|Sin auditor|Sem Auditoria|Geen controle'

    $checks = @(
        @{Id='AUDITPOL_PROCESS_CREATION';Name='Audit: Process Creation (4688)';   Guid='{0CCE922B-69AE-11D9-BED3-505054503030}';Severity='MEDIUM';Fix='auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable'}
        @{Id='AUDITPOL_CREDENTIAL_VALID';Name='Audit: Credential Validation';     Guid='{0CCE923F-69AE-11D9-BED3-505054503030}';Severity='MEDIUM';Fix='auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable'}
        @{Id='AUDITPOL_LOGON';           Name='Audit: Logon/Logoff';              Guid='{0CCE9215-69AE-11D9-BED3-505054503030}';Severity='MEDIUM';Fix='auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable'}
        @{Id='AUDITPOL_LOCKOUT';         Name='Audit: Account Lockout';           Guid='{0CCE9217-69AE-11D9-BED3-505054503030}';Severity='LOW';   Fix='auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /success:enable'}
        @{Id='AUDITPOL_SPECIAL_LOGON';   Name='Audit: Special Logon';             Guid='{0CCE921B-69AE-11D9-BED3-505054503030}';Severity='LOW';   Fix='auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable'}
        @{Id='AUDITPOL_GROUP_MGMT';      Name='Audit: Security Group Management'; Guid='{0CCE9237-69AE-11D9-BED3-505054503030}';Severity='LOW';   Fix='auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable'}
    )

    foreach ($chk in $checks) {
        # Query this specific subcategory by GUID -- works in any locale
        $raw     = Invoke-Exe 'auditpol.exe' @('/get', "/subcategory:$($chk.Guid)")
        $dataLine = ($raw -split "`n") | Where-Object { $_.Trim() -and $_ -match '^\s+\S' } | Select-Object -Last 1
        $setting  = ''
        if ($dataLine -match '\s{2,}(\S.+)$') { $setting = $Matches[1].Trim() }

        # Vulnerable = setting is "No Auditing" (calibrated token, known locale list, or empty)
        $vuln = ($setting -eq '') -or
                ($calToken -and $setting -eq $calToken) -or
                ($setting -match $fallbackNoAudit)

        $sev = if ($vuln) { $chk.Severity } else { 'PASS' }
        $obs = if ($setting) { $setting } else { 'Unknown' }
        Add-Finding -Id $chk.Id -Category 'AuditPolicy' -CheckName $chk.Name `
            -Severity $sev -Vulnerable $vuln -Confidence 'High' `
            -Observed $obs -Expected 'Success' -Source 'auditpol.exe' -Fix $chk.Fix
    }
}
