#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckDefenderExclusions  [Sprint D]
#  DEFEXCL-EXT, DEFEXCL-PATH, DEFEXCL-COUNT.
# =============================================================================
function Invoke-CheckDefenderExclusions {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param()
    try {
        $mp        = Get-MpPreference -ErrorAction Stop
        $exclPaths = @($mp.ExclusionPath)      | Where-Object { $_ }
        $exclExts  = @($mp.ExclusionExtension) | Where-Object { $_ }
        $exclProcs = @($mp.ExclusionProcess)   | Where-Object { $_ }
        $totalExcl = $exclPaths.Count + $exclExts.Count + $exclProcs.Count

        $dangerousExts = @('.exe','.dll','.sys','.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.js','.hta','.scr','.cpl')
        $badExts = $exclExts | Where-Object { $_ -in $dangerousExts }
        $vulnExt = [bool]$badExts
        $extObs  = if ($vulnExt) { "DangerousExts=$($badExts -join ',')" } else { "None (total ExclExts=$($exclExts.Count))" }
        Add-Finding -Id 'DEFEXCL-EXT' -Category 'Defender' -CheckName 'Defender: Dangerous Extension Exclusions' `
            -Severity 'HIGH' -Vulnerable $vulnExt -Confidence 'High' `
            -Observed $extObs -Expected 'No executable/script extensions excluded' `
            -Source 'Get-MpPreference.ExclusionExtension' `
            -Fix "Remove-MpPreference -ExclusionExtension '<ext>' for each dangerous extension found." `
            -Note 'Excluding .exe/.dll/.ps1 extensions allows malware in any directory to bypass real-time scanning.'

        $writablePaths = $exclPaths | Where-Object { $_ -match '(?i)\\Temp\\?$|\\AppData\\|\\Users\\|\\Public\\|\\Downloads\\|\\Desktop\\' }
        $vulnPath      = [bool]$writablePaths
        $pathObs       = if ($vulnPath) { "SuspiciousPaths=$($writablePaths -join ' | ')" } else { "None (total ExclPaths=$($exclPaths.Count))" }
        Add-Finding -Id 'DEFEXCL-PATH' -Category 'Defender' -CheckName 'Defender: User-Writable Path Exclusions' `
            -Severity 'HIGH' -Vulnerable $vulnPath -Confidence 'High' `
            -Observed $pathObs -Expected 'No exclusions under user-writable directories' `
            -Source 'Get-MpPreference.ExclusionPath' `
            -Fix "Remove-MpPreference -ExclusionPath '<path>' for each user-writable exclusion." `
            -Note 'Exclusions under Temp/AppData/Users/Downloads give attackers a reliable staging area invisible to Defender.'

        $vulnCount = $totalExcl -gt 10
        Add-Finding -Id 'DEFEXCL-COUNT' -Category 'Defender' -CheckName 'Defender: Excessive Exclusion Volume' `
            -Severity 'MEDIUM' -Vulnerable $vulnCount -Confidence 'Medium' `
            -Observed "Total=$totalExcl (Paths=$($exclPaths.Count) Exts=$($exclExts.Count) Procs=$($exclProcs.Count))" `
            -Expected '<=10 total exclusions' -Source 'Get-MpPreference' `
            -Fix 'Audit all Defender exclusions and remove those not operationally justified.' `
            -Note 'A large exclusion set significantly degrades Defender coverage even when individual entries appear benign.'
    } catch {
        foreach ($id in @('DEFEXCL-EXT','DEFEXCL-PATH','DEFEXCL-COUNT')) {
            Add-Finding -Id $id -Category 'Defender' -CheckName "Defender: Exclusions ($id)" `
                -Severity 'HIGH' -Vulnerable $false -Confidence 'NotApplicable' `
                -Observed 'DefenderUnavailable' -Expected 'No dangerous exclusions' -Source 'Get-MpPreference' `
                -Note "Defender not installed or Get-MpPreference failed: $($_.Exception.Message)"
        }
    }
}
