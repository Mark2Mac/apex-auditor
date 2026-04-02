#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckLocalAdmins  [Sprint D]
#  Enumerates local Administrators group. Flags Guest, excessive count.
# =============================================================================
function Invoke-CheckLocalAdmins {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param()
    $memberNames = [System.Collections.Generic.List[string]]::new(); $memberCount = 0; $sourceUsed = ''; $parseOk = $false

    try {
        $members     = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $memberNames = $members | ForEach-Object { $_.Name }
        $memberCount = $members.Count
        $sourceUsed  = 'Get-LocalGroupMember'
        $parseOk     = $true
    } catch { Write-Warning "Suppressed: $_" }

    if (-not $parseOk) {
        try {
            # Resolve the Administrators group by well-known SID (S-1-5-32-544) so this
            # works on non-English Windows where the group name is localized.
            $adminSid   = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $adminGroup = $adminSid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
            $netOut = Invoke-Exe 'net.exe' @('localgroup', $adminGroup)
            if ($netOut) {
                $inMembers = $false
                foreach ($line in ($netOut -split "`r?`n")) {
                    if ($line -match '^-{5,}')   { $inMembers = $true; continue }
                    if ($inMembers -and $line -match '^\s*$') { break }   # blank line before footer
                    if ($inMembers -and $line.Trim()) { $memberNames.Add($line.Trim()) }
                }
                $memberCount = $memberNames.Count
                $sourceUsed  = 'net.exe localgroup'
                $parseOk     = $true
            }
        } catch { Write-Warning "Suppressed: $_" }
    }

    if (-not $parseOk) {
        Add-Finding -Id 'LOCALADMIN' -Category 'Identity' -CheckName 'Local Administrators Group Membership' `
            -Severity 'MEDIUM' -Vulnerable $false -Confidence 'QueryFailed' `
            -Observed 'QueryFailed' -Expected '<=3 designated accounts; no Guest' `
            -Source 'Get-LocalGroupMember / net.exe' `
            -Note 'Both Get-LocalGroupMember and net.exe failed to enumerate the group.'
        return
    }

    $guestMembers   = $memberNames | Where-Object { $_ -match '\\Guest$|^Guest$' }
    $domJoined      = $false
    try { $domJoined = [bool](Get-Cim 'Win32_ComputerSystem').PartOfDomain } catch { Write-Warning "Suppressed: $_" }
    $excessiveCount = (-not $domJoined) -and ($memberCount -gt 3)
    $vulnGuest      = [bool]$guestMembers
    $vuln           = $vulnGuest -or $excessiveCount
    $sev            = if ($vulnGuest) { 'HIGH' } elseif ($excessiveCount) { 'MEDIUM' } else { 'PASS' }
    $noteLines      = @()
    if ($vulnGuest)      { $noteLines += 'Guest account in Administrators group -- disable or remove immediately.' }
    if ($excessiveCount) { $noteLines += "Count=$memberCount exceeds recommended maximum of 3 for a non-domain machine." }

    Add-Finding -Id 'LOCALADMIN' -Category 'Identity' -CheckName 'Local Administrators Group Membership' `
        -Severity $sev -Vulnerable $vuln -Confidence 'High' `
        -Observed "Count=$memberCount Members=$($memberNames -join ' | ')" `
        -Expected '<=3 designated accounts; no Guest' -Source $sourceUsed `
        -Fix "Remove unnecessary accounts: Remove-LocalGroupMember -Group Administrators -Member '<n>'" `
        -Note ($noteLines -join ' ')
}
