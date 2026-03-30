#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckServicePaths
#  Unquoted service executable paths with writable drop-parent directories.
# =============================================================================
function Invoke-CheckServicePaths {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param()
    try {
        $svcs = Get-Cim 'Win32_Service' |
            Where-Object { $_.PathName -and
                           $_.PathName -notmatch '^"' -and
                           $_.PathName -match ' ' -and
                           $_.PathName -notmatch '^[A-Z]:\\Windows\\' }
        if (-not $svcs) { return }
        foreach ($svc in $svcs) {
            $exe     = ($svc.PathName -split ' -' | Select-Object -First 1).Trim()
            $parts   = $exe.Split(' ')
            $targets = @()
            for ($i = 1; $i -lt $parts.Count; $i++) {
                $candidate = ($parts[0..$i] -join ' ') + '.exe'
                $parentDir = Split-Path $candidate -Parent
                if (Test-Path $parentDir -ErrorAction SilentlyContinue) {
                    try {
                        $acl = Get-Acl $parentDir -ErrorAction Stop
                        if ($acl.Access | Where-Object {
                            $_.FileSystemRights -match 'Write|FullControl' -and
                            $_.IdentityReference -match 'Users|Everyone|BUILTIN\\Users'
                        }) { $targets += $candidate }
                    } catch { Write-Warning "Suppressed: $_" }
                }
            }
            $exploitable = [bool]$targets
            $conf = if ($exploitable) { 'High' } else { 'Medium' }
            $note = if ($exploitable) {
                "Exploitability confirmed: writable drop parent at $(Split-Path $targets[0] -Parent)"
            } else {
                'Unquoted path but no writable drop parent found. Low exploitability.'
            }
            Add-Finding -Id "UNQUOTED_SERVICE_PATH:$($svc.Name)" `
                -Category 'Services' -CheckName "Unquoted Service Path: $($svc.Name)" `
                -Severity 'CRITICAL' -Vulnerable $exploitable -Confidence $conf `
                -Observed "Svc=$($svc.Name) StartAs=$($svc.StartMode) Exe=$exe DropTargets=$(if($targets){'['+($targets -join '], [')+']'}else{'None'})" `
                -Expected 'Quoted executable path' -Source 'CIM Win32_Service' `
                -Fix "sc.exe config `"$($svc.Name)`" binPath= `"`"$exe`"  <args>`"" `
                -Note $note
        }
    } catch { Write-Warning "Suppressed: $_" }
}
