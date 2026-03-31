#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckForensics
#  PowerShell script block logging, cmdline logging, Security log size.
# =============================================================================
function Invoke-CheckForensics {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param()
    $pslKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $pslOn  = (Test-Path $pslKey) -and ((Get-RegValue $pslKey 'EnableScriptBlockLogging' 0) -eq 1)
    $outDir = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' ''
    $pslObs = if ($pslOn) { "Enabled$(if($outDir){' OutDir='+$outDir})" } else { 'Disabled' }
    $pslV   = -not $pslOn
    $pslSev = if ($pslV) { 'MEDIUM' } else { 'PASS' }
    Add-Finding -Id 'PSLOG' -Category 'Forensics' -CheckName 'PowerShell Script Block Logging' `
        -Severity $pslSev -Vulnerable $pslV -Confidence 'High' `
        -Observed $pslObs -Expected 'Enabled' -Source 'Registry' `
        -Fix "New-Item -Force '$pslKey'; Set-ItemProperty '$pslKey' EnableScriptBlockLogging 1" `
        -Note 'Script block logging captures all executed PS code -- critical for DFIR.'

    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $cmdline  = Get-RegValue -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Default 0
    Add-Finding -Id 'CMDLINE' -Category 'Forensics' -CheckName 'Process Creation CommandLine Logging' `
        -Severity 'LOW' -Vulnerable ($cmdline -ne 1) -Confidence 'High' `
        -Observed "$cmdline" -Expected '1' -Source 'Registry' `
        -Fix "Set-ItemProperty '$auditKey' ProcessCreationIncludeCmdLine_Enabled 1" `
        -Note 'Required to capture full command lines in Event 4688.'

    if (-not $Script:IsAdmin) {
        Add-Finding -Id 'SECLOG' -Category 'Forensics' -CheckName 'Security Log Max Size' `
            -Severity 'LOW' -Vulnerable $false -Confidence 'NoAccess' `
            -Observed 'RequiresElevation' -Expected '>=256MB' -Source 'wevtutil' `
            -Note 'Security event log query requires administrator elevation.'
    } else {
        try {
            $logOut  = Invoke-Exe 'wevtutil.exe' @('gl','Security')
            $maxSize = 0
            if ($logOut -match 'maxSize:\s*(\d+)') { $maxSize = [long]$Matches[1] }
            $logV   = $maxSize -lt 268435456
            $logSev = if ($logV) { 'LOW' } else { 'PASS' }
            Add-Finding -Id 'SECLOG' -Category 'Forensics' -CheckName 'Security Log Max Size' `
                -Severity $logSev -Vulnerable $logV -Confidence 'High' `
                -Observed "maxSize=$maxSize" -Expected '>=256MB' -Source 'wevtutil' `
                -Fix 'wevtutil sl Security /ms:268435456' `
                -Note 'Small log sizes cause event overwrite during sustained incidents.'
        } catch {
            Add-Finding -Id 'SECLOG' -Category 'Forensics' -CheckName 'Security Log Max Size' `
                -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
                -Observed 'QueryFailed' -Expected '>=256MB' -Source 'wevtutil'
        }
    }
}
