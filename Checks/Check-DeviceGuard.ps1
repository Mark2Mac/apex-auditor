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

        Add-Finding -Id 'VBS' -Category 'DeviceGuard' -CheckName 'VBS' `
            -Severity 'CRITICAL' `
            -Vulnerable ($dg.VirtualizationBasedSecurityStatus -ne 2) `
            -Confidence 'High' `
            -Observed "$($dg.VirtualizationBasedSecurityStatus)" -Expected '2 (Running)' `
            -Source 'CIM Win32_DeviceGuard' `
            -Fix 'Enable VBS in Windows Security > Core Isolation > Memory Integrity.' `
            -Note 'VBS is the foundation of Credential Guard and HVCI.'

        Add-Finding -Id 'HVCI' -Category 'DeviceGuard' -CheckName 'HVCI / Memory Integrity' `
            -Severity 'HIGH' `
            -Vulnerable ($dg.HypervisorEnforcedCodeIntegrityStatus -ne 2) `
            -Confidence 'High' `
            -Observed "$($dg.HypervisorEnforcedCodeIntegrityStatus)" -Expected '2 (Enforced)' `
            -Source 'CIM Win32_DeviceGuard' `
            -Fix 'Enable Memory Integrity in Windows Security > Core Isolation.' `
            -Note 'HVCI blocks kernel-mode code injection attacks.'

        Add-Finding -Id 'UMCI' -Category 'Execution' -CheckName 'WDAC/UMCI Posture' `
            -Severity 'LOW' `
            -Vulnerable ($dg.CodeIntegrityPolicyEnforcementStatus -ne 2) `
            -Confidence 'High' `
            -Observed "UMCI=$($dg.CodeIntegrityPolicyEnforcementStatus)" -Expected '2 (Enforced)' `
            -Source 'CIM Win32_DeviceGuard' `
            -Fix 'Deploy WDAC policy if you want strict app control.' `
            -Note 'Not auto-applied; needs policy design.'

        Add-Finding -Id 'CG' -Category 'Identity' -CheckName 'Credential Guard' `
            -Severity 'MEDIUM' `
            -Vulnerable ($dg.SecurityServicesRunning -notcontains 1) `
            -Confidence 'High' `
            -Observed "Running=$($dg.SecurityServicesRunning -join ',')" -Expected 'Includes 1' `
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
