#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckPrintSpooler
#  Print Spooler service exposure (PrintNightmare surface).
#  SPOOLER-SVC : Spooler running + auto-start on non-print-server
#  SPOOLER-PNP : Point-and-Print not restricted to admins
#  SPOOLER-DIR : Spool directory writable by non-admins (only if svc running)
# =============================================================================
function Invoke-CheckPrintSpooler {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param()

    $countBefore = $Script:Findings.Count
    try {
        # --- SPOOLER-SVC ---
        $svcStatus = Get-SvcStatus 'Spooler'
        $svcObj    = $null
        try { $svcObj = Get-Service 'Spooler' -ErrorAction SilentlyContinue } catch { <# silently skip #> }
        $svcStart  = if ($svcObj) { $svcObj.StartType.ToString() } else { 'Unknown' }
        $running   = ($svcStatus -eq 'Running')
        $svcV      = $running -and ($svcStart -in @('Automatic','AutomaticDelayedStart'))
        $svcSev    = if ($svcV) { 'HIGH' } else { 'PASS' }
        Add-Finding -Id 'SPOOLER-SVC' -Category 'Services' -CheckName 'Print Spooler Service' `
            -Severity $svcSev -Vulnerable $svcV -Confidence 'High' `
            -Observed "Status=$svcStatus StartType=$svcStart" -Expected 'Stopped+Disabled' `
            -Source 'Get-Service Spooler' `
            -Fix 'Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled' `
            -Note 'Running Spooler exposes PrintNightmare (CVE-2021-34527) and related RCE/LPE vectors.'

        # --- SPOOLER-PNP ---
        $pnpKey  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        $pnpVal  = Get-RegValue -Path $pnpKey -Name 'RestrictDriverInstallationToAdministrators' -Default 0
        $pnpV    = ($pnpVal -ne 1)
        $pnpSev  = if ($pnpV) { 'MEDIUM' } else { 'PASS' }
        Add-Finding -Id 'SPOOLER-PNP' -Category 'Services' -CheckName 'Print Spooler Point-and-Print Restriction' `
            -Severity $pnpSev -Vulnerable $pnpV -Confidence 'High' `
            -Observed "RestrictDriverInstallationToAdministrators=$pnpVal" -Expected '1' `
            -Source 'Registry HKLM:\SOFTWARE\Policies\...\PointAndPrint' `
            -Fix "New-Item -Force '$pnpKey' | Out-Null; Set-ItemProperty '$pnpKey' RestrictDriverInstallationToAdministrators 1 -Type DWord" `
            -Note 'Without this restriction non-admins can install arbitrary printer drivers via Point-and-Print.'

        # --- SPOOLER-DIR (only if spooler is running) ---
        if ($running) {
            $spoolDirDefault = "$env:SystemRoot\System32\spool\PRINTERS"
            $spoolDirReg     = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers' `
                                            -Name 'DefaultSpoolDirectory' -Default $spoolDirDefault
            $spoolDir = if ($spoolDirReg) { $spoolDirReg } else { $spoolDirDefault }
            $dirV     = $false
            $dirObs   = "Dir=$spoolDir NotFound"
            if (Test-Path $spoolDir -ErrorAction SilentlyContinue) {
                try {
                    $acl     = Get-Acl $spoolDir -ErrorAction Stop
                    $writable = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl' -and
                        $_.IdentityReference -match 'Users|Everyone|Authenticated Users'
                    }
                    $dirV   = [bool]$writable
                    $dirObs = "Dir=$spoolDir Writable=$dirV"
                } catch {
                    $dirObs = "Dir=$spoolDir AclQueryFailed"
                }
            }
            $dirSev = if ($dirV) { 'LOW' } else { 'PASS' }
            Add-Finding -Id 'SPOOLER-DIR' -Category 'Services' -CheckName 'Print Spooler Directory ACL' `
                -Severity $dirSev -Vulnerable $dirV -Confidence (if ($dirV) { 'High' } else { 'Medium' }) `
                -Observed $dirObs -Expected 'Non-writable by Users/Everyone' `
                -Source 'Get-Acl SpoolDirectory' `
                -Fix "icacls `"$spoolDir`" /remove:g `"Authenticated Users`" /remove:g Users /remove:g Everyone" `
                -Note 'A writable spool directory enables DLL planting attacks against the Spooler process.'
        }
    } catch {
        # Rollback partial findings before emitting consistent QueryFailed fallbacks
        while ($Script:Findings.Count -gt $countBefore) {
            $Script:Findings.RemoveAt($Script:Findings.Count - 1)
        }
        foreach ($id in @('SPOOLER-SVC','SPOOLER-PNP','SPOOLER-DIR')) {
            Add-Finding -Id $id -Category 'Services' -CheckName "Print Spooler ($id)" `
                -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
                -Observed 'QueryFailed' -Expected 'N/A' -Source 'Get-Service / Registry / Get-Acl'
        }
    }
}
