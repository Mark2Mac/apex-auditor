#Requires -Version 5.1
# =============================================================================
#  APEX Audit Engine -- Core.ps1
#  Finding accumulator, console helpers, system helpers, scoring, delta engine.
#  Dot-sourced by Windows_Audit.ps1 before Checks/ and Engine/Report.ps1.
# =============================================================================

# ---------------------------------------------------------------------------
#  FINDING ACCUMULATOR
# ---------------------------------------------------------------------------
$Script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns','')]
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Category,
        [Parameter(Mandatory)][string] $CheckName,
        [Parameter(Mandatory)][ValidateSet('PASS','CRITICAL','HIGH','MEDIUM','LOW')] [string] $Severity,
        [Parameter(Mandatory)][bool]   $Vulnerable,
        [Parameter(Mandatory)][ValidateSet('High','Medium','Low','NotApplicable','NoAccess','QueryFailed')] [string] $Confidence,
        [Parameter(Mandatory)][string] $Observed,
        [Parameter(Mandatory)][string] $Expected,
        [Parameter(Mandatory)][string] $Source,
        [string] $Fix  = 'N/A',
        [string] $Note = ''
    )
    $Script:Findings.Add([PSCustomObject]@{
        Id=$Id; Category=$Category; CheckName=$CheckName; Severity=$Severity
        Vulnerable=$Vulnerable; Confidence=$Confidence; Observed=$Observed
        Expected=$Expected; Source=$Source; Fix=$Fix; Note=$Note
    })
}

# ---------------------------------------------------------------------------
#  CONSOLE HELPERS
# ---------------------------------------------------------------------------
function Write-TUI {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','')]
    param([string]$Text, [string]$Color = 'White')
    if (-not $NoTUI) { Write-Host $Text -ForegroundColor $Color }
}
function Write-TUILine {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','')]
    param()
    if (-not $NoTUI) { Write-Host ('-' * 110) -ForegroundColor DarkCyan }
}
function Write-TUIFinding {
    param([PSCustomObject]$F)
    if ($NoTUI -or $F.Severity -eq 'PASS') { return }
    $col = switch ($F.Severity) {
        'CRITICAL' { 'Red' }; 'HIGH' { 'DarkYellow' }
        'MEDIUM'   { 'Yellow' }; 'LOW'  { 'Cyan' }; default { 'White' }
    }
    Write-TUI ''
    Write-TUI "  [$($F.Severity)] $($F.CheckName)" -Color $col
    Write-TUI "    Obs  : $($F.Observed)"
    Write-TUI "    Exp  : $($F.Expected)"
    Write-TUI "    Src  : $($F.Source)  [Conf: $($F.Confidence)]"
    if ($F.Note)                    { Write-TUI "    Note : $($F.Note)" }
    if ($F.Fix -and $F.Fix -ne 'N/A') { Write-TUI "    Fix  : $($F.Fix)" }
}

# ---------------------------------------------------------------------------
#  SYSTEM HELPERS
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    try {
        $pr = New-Object System.Security.Principal.WindowsPrincipal(
            [System.Security.Principal.WindowsIdentity]::GetCurrent())
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
$Script:IsAdmin = Test-IsAdmin

function Get-RegValue {
    param([string]$Path, [string]$Name, [object]$Default = $null)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $v -and $null -ne $v.$Name) { return $v.$Name }
    } catch { Write-Warning "Suppressed: $_" }
    return $Default
}

function Get-SvcStatus {
    param([string]$Name)
    try {
        $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($s) { return $s.Status.ToString() }
    } catch { Write-Warning "Suppressed: $_" }
    return 'NotFound'
}

function Invoke-Exe {
    param([string]$Exe, [string[]]$ExeArgs)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe; $psi.Arguments = $ExeArgs -join ' '
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi; $p.Start() | Out-Null
        $out = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit(8000) | Out-Null
        return $out
    } catch { return '' }
}

function Get-Cim {
    param(
        [Parameter(Mandatory)][string]$ClassName,
        [string]$Namespace = 'root\cimv2',
        [string]$Filter    = ''
    )
    $p = @{ ClassName=$ClassName; Namespace=$Namespace; ErrorAction='Stop' }
    if ($Filter)              { $p.Filter     = $Filter }
    if ($Script:CimSession)   { $p.CimSession = $Script:CimSession }
    return Get-CimInstance @p
}

# ---------------------------------------------------------------------------
#  SCORING
# ---------------------------------------------------------------------------
function Measure-AuditScore {
    param([System.Collections.Generic.List[PSCustomObject]]$Findings)
    $sevDed = 0; $hygDed = 0
    foreach ($f in ($Findings | Where-Object { $_.Vulnerable })) {
        $w = $Script:SCORE_WEIGHTS[$f.Severity]
        if ($null -eq $w) { continue }
        if ($f.Severity -in @('CRITICAL','HIGH')) { $sevDed += $w } else { $hygDed += $w }
    }
    return [PSCustomObject]@{
        SeverityScore = [math]::Max(0, 100 - $sevDed)
        HygieneScore  = [math]::Max(0, 100 - $hygDed)
    }
}

# ---------------------------------------------------------------------------
#  DELTA ENGINE
# ---------------------------------------------------------------------------
function Read-BaselineJSON {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-TUI "[!] -CompareTo path not found: $Path -- delta skipped" -Color Yellow
        return $null
    }
    try {
        $raw = Get-Content $Path -Raw -ErrorAction Stop
        if (-not $raw.Trim()) { return $null }
        return $raw | ConvertFrom-Json
    } catch {
        Write-TUI "[!] -CompareTo parse failed: $($_.Exception.Message) -- delta skipped" -Color Yellow
        return $null
    }
}

function Compare-AuditBaseline {
    param(
        [PSCustomObject]  $Baseline,
        [System.Collections.Generic.List[PSCustomObject]] $CurrentFindings,
        [PSCustomObject]  $CurrentScores
    )
    if ($null -eq $Baseline) { return $null }

    $prevMap = @{}
    $baseFindings = try { @($Baseline.Findings) } catch { @() }
    foreach ($f in $baseFindings) { if ($f.Id) { $prevMap[$f.Id] = $f.Vulnerable } }

    $prevSevScore = try { [double]$Baseline.ScoreBefore } catch { 100.0 }
    $prevHygScore = try { [double]$Baseline.HygieneScore } catch { 100.0 }

    $regressions  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $improvements = [System.Collections.Generic.List[PSCustomObject]]::new()
    $newChecks    = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($f in $CurrentFindings) {
        if (-not $prevMap.ContainsKey($f.Id)) {
            if ($f.Vulnerable) { $newChecks.Add($f) }
            continue
        }
        $wasVuln = $prevMap[$f.Id]
        if ($f.Vulnerable -and -not $wasVuln)  { $regressions.Add($f) }
        elseif (-not $f.Vulnerable -and $wasVuln) { $improvements.Add($f) }
    }

    $bts = try { [string]$Baseline.Context.TimestampUTC } catch { 'Unknown' }
    $bmd = try { [string]$Baseline.Context.Mode         } catch { 'Unknown' }

    return [PSCustomObject]@{
        BaselineTimestamp  = $bts
        BaselineMode       = $bmd
        SeverityScoreDelta = [math]::Round($CurrentScores.SeverityScore - $prevSevScore, 1)
        HygieneScoreDelta  = [math]::Round($CurrentScores.HygieneScore  - $prevHygScore, 1)
        Regressions        = @($regressions)
        Improvements       = @($improvements)
        NewChecks          = @($newChecks)
    }
}

# ---------------------------------------------------------------------------
#  COMPLIANCE MAPPING
# ---------------------------------------------------------------------------
function Get-ComplianceRefs {
    <#
    .SYNOPSIS
        Annotates findings with compliance framework references from compliance_map.json.
    .DESCRIPTION
        Loads compliance_map.json and adds a ComplianceRefs NoteProperty to each finding
        in $Script:Findings. If the map file is missing or malformed, silently returns.
    #>
    param([string]$MapPath)
    if (-not (Test-Path $MapPath -ErrorAction SilentlyContinue)) { return }
    try {
        $raw = Get-Content $MapPath -Raw -Encoding UTF8 -ErrorAction Stop
        $map = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "APEX: Could not load compliance_map.json -- $_"
        return
    }
    foreach ($f in $Script:Findings) {
        $ref = $map.($f.Id)
        if ($null -ne $ref) {
            $crefs = [PSCustomObject]@{
                CIS       = @($ref.cis)
                CIS_Level = $ref.cis_level
                STIG      = @($ref.stig)
                NIST      = @($ref.nist)
            }
            $f | Add-Member -NotePropertyName 'ComplianceRefs' -NotePropertyValue $crefs -Force
        }
    }
}
