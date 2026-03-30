#Requires -Version 5.1
# =============================================================================
#  Invoke-CheckScheduledTasks  (Deep only)
#  Scheduled task security hygiene.
#  SCHTASK-WRITABLE  : Non-MS task with user-writable action executable (CRITICAL)
#  SCHTASK-SYSTEM    : SYSTEM-principal task whose task XML file is user-writable (HIGH)
#  SCHTASK-NOAUTHOR  : Non-MS enabled tasks with missing Author field (MEDIUM)
# =============================================================================
function Invoke-CheckScheduledTasks {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param()

    $countBefore = $Script:Findings.Count
    try {
        # Fetch all non-disabled tasks outside \Microsoft\ path
        $allTasks  = Get-ScheduledTask -ErrorAction Stop
        $userTasks = $allTasks | Where-Object {
            $_.State -ne 'Disabled' -and
            $_.TaskPath -notlike '\Microsoft\*'
        }

        # --- SCHTASK-WRITABLE ---
        $writableNames = [System.Collections.Generic.List[string]]::new()
        foreach ($task in $userTasks) {
            foreach ($action in $task.Actions) {
                $exe = $action.Execute
                if (-not $exe) { continue }
                # Expand environment variables
                $exeExpanded = [System.Environment]::ExpandEnvironmentVariables($exe)
                if (-not (Test-Path $exeExpanded -ErrorAction SilentlyContinue)) { continue }
                try {
                    $acl = Get-Acl $exeExpanded -ErrorAction Stop
                    $writable = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|FullControl' -and
                        $_.IdentityReference -match 'Users|Everyone|Authenticated Users|BUILTIN\\Users'
                    }
                    if ($writable) { $writableNames.Add("$($task.TaskPath)$($task.TaskName)") }
                } catch { <# silently skip ACL errors #> }
            }
        }
        $writV   = $writableNames.Count -gt 0
        $writSev = if ($writV) { 'CRITICAL' } else { 'PASS' }
        $writObs = if ($writV) {
            "Count=$($writableNames.Count) Tasks=[$($writableNames -join '; ')]"
        } else { 'NoWritableTaskExeFound' }
        Add-Finding -Id 'SCHTASK-WRITABLE' -Category 'Services' -CheckName 'Scheduled Task Writable Executable' `
            -Severity $writSev -Vulnerable $writV -Confidence (if ($writV) { 'High' } else { 'Medium' }) `
            -Observed $writObs -Expected 'No user-writable action executables' `
            -Source 'Get-ScheduledTask + Get-Acl' `
            -Fix 'icacls "<exe_path>" /remove:g "Authenticated Users" /remove:g Users /remove:g Everyone' `
            -Note 'A user-writable scheduled task executable allows privilege escalation by replacing the binary before it runs as SYSTEM.'

        # --- SCHTASK-SYSTEM ---
        $sysTasksWritable = [System.Collections.Generic.List[string]]::new()
        $systemPrincipals = @('System','LocalSystem','NT AUTHORITY\SYSTEM','S-1-5-18')
        $systemTasks = $userTasks | Where-Object {
            $_.Principal.UserId -in $systemPrincipals -or
            $_.Principal.UserId -match 'S-1-5-18'
        }
        $taskFolder = "$env:SystemRoot\System32\Tasks"
        foreach ($task in $systemTasks) {
            $xmlPath = Join-Path $taskFolder ($task.TaskPath.TrimStart('\')) | Join-Path -ChildPath $task.TaskName
            if (-not (Test-Path $xmlPath -ErrorAction SilentlyContinue)) { continue }
            try {
                $acl = Get-Acl $xmlPath -ErrorAction Stop
                $writable = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl' -and
                    $_.IdentityReference -match 'Users|Everyone|Authenticated Users|BUILTIN\\Users'
                }
                if ($writable) { $sysTasksWritable.Add("$($task.TaskPath)$($task.TaskName)") }
            } catch { <# silently skip #> }
        }
        $sysV   = $sysTasksWritable.Count -gt 0
        $sysSev = if ($sysV) { 'HIGH' } else { 'PASS' }
        $sysObs = if ($sysV) {
            "Count=$($sysTasksWritable.Count) Tasks=[$($sysTasksWritable -join '; ')]"
        } else { 'NoWritableSystemTaskXmlFound' }
        Add-Finding -Id 'SCHTASK-SYSTEM' -Category 'Services' -CheckName 'SYSTEM Scheduled Task XML ACL' `
            -Severity $sysSev -Vulnerable $sysV -Confidence (if ($sysV) { 'High' } else { 'Medium' }) `
            -Observed $sysObs -Expected 'No user-writable SYSTEM task XML files' `
            -Source 'Get-ScheduledTask + Get-Acl on task XML' `
            -Fix 'icacls "<task_xml_path>" /remove:g "Authenticated Users" /remove:g Users' `
            -Note 'A writable task XML file allows replacing task actions; when the SYSTEM task next runs the attacker code executes as SYSTEM.'

        # --- SCHTASK-NOAUTHOR ---
        $noAuthorTasks = $userTasks | Where-Object { -not $_.Author }
        $noAuthV   = $noAuthorTasks.Count -gt 0
        $noAuthSev = if ($noAuthV) { 'MEDIUM' } else { 'PASS' }
        $noAuthObs = if ($noAuthV) {
            $names = ($noAuthorTasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }) -join '; '
            "Count=$($noAuthorTasks.Count) Tasks=[$names]"
        } else { 'AllNonMsTasksHaveAuthor' }
        Add-Finding -Id 'SCHTASK-NOAUTHOR' -Category 'Services' -CheckName 'Scheduled Task Missing Author' `
            -Severity $noAuthSev -Vulnerable $noAuthV -Confidence (if ($noAuthV) { 'Medium' } else { 'High' }) `
            -Observed $noAuthObs -Expected 'All tasks have Author field populated' `
            -Source 'Get-ScheduledTask' `
            -Fix 'Investigate each listed task manually; remove if unexplained.' `
            -Note 'Empty Author is a common characteristic of malware persistence via scheduled tasks. Requires manual verification.'
    } catch {
        # Rollback any partial findings
        while ($Script:Findings.Count -gt $countBefore) {
            $Script:Findings.RemoveAt($Script:Findings.Count - 1)
        }
        foreach ($id in @('SCHTASK-WRITABLE','SCHTASK-SYSTEM','SCHTASK-NOAUTHOR')) {
            Add-Finding -Id $id -Category 'Services' -CheckName "Scheduled Tasks ($id)" `
                -Severity 'PASS' -Vulnerable $false -Confidence 'QueryFailed' `
                -Observed 'QueryFailed' -Expected 'N/A' -Source 'Get-ScheduledTask'
        }
    }
}
