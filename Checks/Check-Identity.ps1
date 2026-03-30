#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckIdentity
#  WDigest, PPL, Built-in Administrator, LAPS, UAC.
#  Bug fix: SID500 now emits correct severity when enabled (Vulnerable=true).
# =============================================================================
function Invoke-CheckIdentity {
    # WDigest
    $wdKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $wdVal = Get-RegValue -Path $wdKey -Name 'UseLogonCredential' -Default $null
    $wdV   = ($null -ne $wdVal -and $wdVal -ne 0)
    $wdObs = if ($null -eq $wdVal) { 'Null(DefaultSafe)' } else { "$wdVal" }
    Add-Finding -Id 'WDIG' -Category 'Identity' -CheckName 'WDigest Plaintext Caching' `
        -Severity 'CRITICAL' -Vulnerable $wdV -Confidence 'High' `
        -Observed $wdObs -Expected '0 or Null' -Source 'Registry' `
        -Fix "Set-ItemProperty '$wdKey' UseLogonCredential 0" `
        -Note 'UseLogonCredential=1 caches plaintext creds in LSASS, harvestable by Mimikatz.'

    # LSASS PPL
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ppl    = Get-RegValue -Path $lsaKey -Name 'RunAsPPL' -Default 0
    Add-Finding -Id 'PPL' -Category 'Identity' -CheckName 'LSASS Protected Process Light' `
        -Severity 'HIGH' -Vulnerable ($ppl -ne 1) -Confidence 'High' `
        -Observed "$ppl" -Expected '1' -Source 'Registry' `
        -Fix "Set-ItemProperty '$lsaKey' RunAsPPL 1 -Type DWord  # Requires reboot" `
        -Note 'PPL prevents user-mode tools from directly reading LSASS process memory.'

    # Built-in Administrator (RID 500)
    try {
        $adm = Get-Cim 'Win32_UserAccount' -Filter "SID LIKE '%-500'" | Select-Object -First 1
        if ($adm) {
            $enabled  = -not $adm.Disabled
            $sid500V  = $enabled
            $sid500S  = if ($enabled) { 'LOW' } else { 'PASS' }
            $sid500Ob = if ($enabled) { 'Enabled' } else { 'Disabled' }
            $sid500Ob += " Name='$($adm.Name)' SID='$($adm.SID)'"
            Add-Finding -Id 'SID500' -Category 'Identity' -CheckName 'Built-in Administrator (RID 500)' `
                -Severity $sid500S -Vulnerable $sid500V -Confidence 'High' `
                -Observed $sid500Ob -Expected 'Disabled' -Source 'CIM Win32_UserAccount' `
                -Fix "Disable-LocalUser -Name '$($adm.Name)'" `
                -Note 'The built-in Administrator is a well-known target.'
        }
    } catch {
        Add-Finding -Id 'SID500' -Category 'Identity' -CheckName 'Built-in Administrator (RID 500)' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected 'Disabled' -Source 'CIM Win32_UserAccount'
    }

    # LAPS
    $domJoined = $false
    try { $domJoined = [bool](Get-Cim 'Win32_ComputerSystem').PartOfDomain } catch { Write-Warning "Suppressed: $_" }
    if (-not $domJoined) {
        Add-Finding -Id 'LAPS' -Category 'Identity' -CheckName 'LAPS Posture' `
            -Severity 'PASS' -Vulnerable $false -Confidence 'NotApplicable' `
            -Observed 'WorkgroupMachine' -Expected 'N/A' -Source 'Registry + JoinState' `
            -Note 'LAPS is a domain feature. Not applicable to workgroup machines.'
    } else {
        $lapsPath = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
        $lapsOn   = (Test-Path $lapsPath) -and ((Get-RegValue -Path $lapsPath -Name 'AdmPwdEnabled' -Default 0) -eq 1)
        $lapsV    = -not $lapsOn
        $lapsSev  = if ($lapsV) { 'MEDIUM' } else { 'PASS' }
        $lapsObs  = if ($lapsOn) { 'Configured' } else { 'NotConfigured' }
        Add-Finding -Id 'LAPS' -Category 'Identity' -CheckName 'LAPS Posture' `
            -Severity $lapsSev -Vulnerable $lapsV -Confidence 'Medium' `
            -Observed $lapsObs -Expected 'Configured' -Source 'Registry + JoinState' `
            -Fix 'Deploy Microsoft LAPS or Windows LAPS (built-in Win11 22H2+) via Group Policy.' `
            -Note 'LAPS rotates local admin passwords, preventing lateral movement.'
    }

    # UAC
    $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua    = Get-RegValue -Path $uacKey -Name 'EnableLUA' -Default 0
    $consent= Get-RegValue -Path $uacKey -Name 'ConsentPromptBehaviorAdmin' -Default 5
    Add-Finding -Id 'UAC' -Category 'UAC' -CheckName 'UAC Enabled' `
        -Severity 'CRITICAL' -Vulnerable (($lua -ne 1) -or ($consent -lt 2)) -Confidence 'High' `
        -Observed "EnableLUA=$lua ConsentPromptBehaviorAdmin=$consent" `
        -Expected 'EnableLUA=1; ConsentPromptBehaviorAdmin>=2' -Source 'Registry' `
        -Fix "Set-ItemProperty '$uacKey' EnableLUA 1" `
        -Note 'Disabling UAC removes the consent boundary between user and admin context.'

    $sdOn = Get-RegValue -Path $uacKey -Name 'PromptOnSecureDesktop' -Default 0
    Add-Finding -Id 'UAC-SD' -Category 'UAC' -CheckName 'UAC Secure Desktop Prompt' `
        -Severity 'LOW' -Vulnerable ($sdOn -ne 1) -Confidence 'High' `
        -Observed "PromptOnSecureDesktop=$sdOn" -Expected '1' -Source 'Registry' `
        -Fix "Set-ItemProperty '$uacKey' PromptOnSecureDesktop 1" `
        -Note 'Without Secure Desktop, malware can spoof the UAC prompt via UI automation.'
}
