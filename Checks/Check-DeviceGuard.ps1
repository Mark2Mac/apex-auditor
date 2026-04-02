#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckDeviceGuard
#  VBS, HVCI, UMCI, Credential Guard.
#  Bug fix: rollback partial findings before emitting fallback set,
#  preventing duplicate IDs when a partial CIM success occurs.
# =============================================================================
function Invoke-CheckDeviceGuard {
    $countBefore = $Script:Findings.Count
    try {
        $dg = Get-Cim 'Win32_DeviceGuard' -Namespace 'root\Microsoft\Windows\DeviceGuard'

        # Pre-check: firmware must support VT-x for VBS/HVCI to work.
        # Use VirtualizationFirmwareEnabled when available; fall back to VBS already running
        # (if VBS status=2 it proved hardware capability even if the property is $null).
        $vbsCapable = ($dg.VirtualizationFirmwareEnabled -eq $true) -or
                      ($dg.VirtualizationBasedSecurityStatus -eq 2)

        $vbsObs  = if ($null -ne $dg.VirtualizationBasedSecurityStatus)        { "$($dg.VirtualizationBasedSecurityStatus)" }  else { 'Unknown' }
        $hvciRunning = 2 -in @($dg.SecurityServicesRunning)
        $hvciObs = if ($hvciRunning) { '2 (Enforced)' } elseif (2 -in @($dg.SecurityServicesConfigured)) { 'Configured but not running' } else { 'Not running' }
        $umciObs = if ($null -ne $dg.CodeIntegrityPolicyEnforcementStatus)      { "$($dg.CodeIntegrityPolicyEnforcementStatus)" } else { 'Unknown' }
        $cgObs   = if ($null -ne $dg.SecurityServicesRunning -and @($dg.SecurityServicesRunning).Count -gt 0) { ($dg.SecurityServicesRunning -join ',') } else { 'Unknown' }

        Add-Finding -Id 'VBS' -Category 'DeviceGuard' -CheckName 'VBS' `
            -Severity 'CRITICAL' `
            -Vulnerable ($dg.VirtualizationBasedSecurityStatus -ne 2) `
            -Confidence $(if($vbsCapable){'High'}else{'NotApplicable'}) `
            -Observed $vbsObs -Expected '2 (Running)' `
            -Source 'CIM Win32_DeviceGuard' `
            -Fix $(if($vbsCapable){'$p=''HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard''; if(-not(Test-Path $p)){New-Item $p -Force|Out-Null}; Set-ItemProperty $p EnableVirtualizationBasedSecurity 1 -Type DWord'}else{'N/A'}) `
            -Note $(if($vbsCapable){'VBS is the foundation of Credential Guard and HVCI.'}else{'VBS requires firmware virtualization (VT-x/AMD-V) which is not enabled in this system firmware.'})

        Add-Finding -Id 'HVCI' -Category 'DeviceGuard' -CheckName 'HVCI / Memory Integrity' `
            -Severity 'HIGH' `
            -Vulnerable (-not $hvciRunning) `
            -Confidence $(if($vbsCapable){'High'}else{'NotApplicable'}) `
            -Observed $hvciObs -Expected '2 (Enforced)' `
            -Source 'CIM Win32_DeviceGuard' `
            -Fix $(if($vbsCapable){'$p=''HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity''; if(-not(Test-Path $p)){New-Item $p -Force|Out-Null}; Set-ItemProperty $p Enabled 1 -Type DWord'}else{'N/A'}) `
            -Note $(if($vbsCapable){'HVCI blocks kernel-mode code injection attacks.'}else{'HVCI requires firmware virtualization (VT-x/AMD-V) which is not enabled in this system firmware.'})

        Add-Finding -Id 'UMCI' -Category 'Execution' -CheckName 'WDAC/UMCI Posture' `
            -Severity 'LOW' `
            -Vulnerable ($dg.CodeIntegrityPolicyEnforcementStatus -ne 2) `
            -Confidence 'High' `
            -Observed "UMCI=$umciObs" -Expected '2 (Enforced)' `
            -Source 'CIM Win32_DeviceGuard' `
            -Fix 'Deploy WDAC policy if you want strict app control.' `
            -Note 'Not auto-applied; needs policy design.'

        Add-Finding -Id 'CG' -Category 'Identity' -CheckName 'Credential Guard' `
            -Severity 'MEDIUM' `
            -Vulnerable ($dg.SecurityServicesRunning -notcontains 1) `
            -Confidence 'High' `
            -Observed "Running=$cgObs" -Expected 'Includes 1' `
            -Source 'CIM Win32_DeviceGuard' `
            -Fix 'Enable Credential Guard (requires reboot).' `
            -Note 'Hardens credential theft resistance.'

    } catch {
        # Rollback any partial findings added in the try block above
        while ($Script:Findings.Count -gt $countBefore) {
            $Script:Findings.RemoveAt($Script:Findings.Count - 1)
        }
        $note = "CIM query failed: $($_.Exception.Message)"
        foreach ($id in @('VBS','HVCI','UMCI','CG')) {
            Add-Finding -Id $id -Category 'DeviceGuard' -CheckName $id `
                -Severity 'MEDIUM' -Vulnerable $false -Confidence 'QueryFailed' `
                -Observed 'WMIQueryFailed' -Expected 'N/A' `
                -Source 'CIM Win32_DeviceGuard' -Note $note
        }
    }
}
