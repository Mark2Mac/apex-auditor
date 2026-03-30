#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckPS2Engine
#  PowerShell v2 engine availability.
#  PS2ENGINE : PS v2 engine enabled (bypasses SBL, CLM, AMSI)
# =============================================================================
function Invoke-CheckPS2Engine {
    param()
    try {
        $enabled  = $false
        $source   = 'Get-WindowsOptionalFeature'
        $observed = 'Unknown'

        # Primary: Get-WindowsOptionalFeature (requires admin or works non-admin on Win10/11)
        try {
            $feat    = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' `
                           -ErrorAction Stop
            $enabled = ($feat.State -eq 'Enabled')
            $observed = "State=$($feat.State)"
        } catch {
            # Fallback: registry key presence under PSv1/v2 engine path
            $source  = 'Registry'
            $regPath = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
            if (Test-Path $regPath -ErrorAction SilentlyContinue) {
                $ver = Get-RegValue -Path $regPath -Name 'PowerShellVersion' -Default ''
                # If the key exists and version starts with 2, the engine is present
                $enabled  = ($ver -like '2.*')
                $observed = if ($ver) { "PSv1EngineKey Present Version=$ver" } else { 'PSv1EngineKey Present VersionUnknown' }
            } else {
                $observed = 'PSv1EngineKey Absent (likely disabled)'
                $enabled  = $false
            }
        }

        $sev = if ($enabled) { 'MEDIUM' } else { 'PASS' }
        Add-Finding -Id 'PS2ENGINE' -Category 'Forensics' -CheckName 'PowerShell v2 Engine' `
            -Severity $sev -Vulnerable $enabled -Confidence 'High' `
            -Observed $observed -Expected 'Disabled' -Source $source `
            -Fix 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart' `
            -Note 'PS v2 lacks script-block logging, Constrained Language Mode, and AMSI -- an attacker can downgrade to it to bypass all three.'
    } catch {
        Add-Finding -Id 'PS2ENGINE' -Category 'Forensics' -CheckName 'PowerShell v2 Engine' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'Disabled' -Source 'Get-WindowsOptionalFeature / Registry'
    }
}
