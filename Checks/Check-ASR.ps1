#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckASR
#  Attack Surface Reduction rules posture.
# =============================================================================
function Invoke-CheckASR {
    try {
        $mp    = Get-MpPreference -ErrorAction Stop
        $ids   = $mp.AttackSurfaceReductionRules_Ids
        $acts  = $mp.AttackSurfaceReductionRules_Actions
        $total = if ($ids)   { @($ids).Count }  else { 0 }
        $block = 0; $off = 0
        if ($ids -and $acts) {
            for ($i = 0; $i -lt [Math]::Min(@($ids).Count, @($acts).Count); $i++) {
                switch ($acts[$i]) { 1 { $block++ }; 0 { $off++ } }
            }
        }
        $asrV   = $block -eq 0
        $asrSev = if ($asrV) { 'LOW' } else { 'PASS' }
        Add-Finding -Id 'ASR' -Category 'ASR' -CheckName 'ASR Rules Posture' `
            -Severity $asrSev -Vulnerable $asrV -Confidence 'High' `
            -Observed "Rules=$total Block=$block Off=$off" -Expected 'Several key rules in Block/Audit' `
            -Source 'Get-MpPreference' `
            -Fix 'Increase ASR coverage (Audit or Block) for common attack vectors.' `
            -Note 'Use -ShowSignals to export the raw ASR rule list to JSON.'
    } catch {
        Add-Finding -Id 'ASR' -Category 'ASR' -CheckName 'ASR Rules Posture' `
            -Severity 'LOW' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'Several key rules in Block/Audit' `
            -Source 'Get-MpPreference'
    }
}
