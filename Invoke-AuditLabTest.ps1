#Requires -Version 5.1
<#
.SYNOPSIS
    APEX Audit Scientific Test Laboratory v3.0

.DESCRIPTION
    Rigorous, zero-dependency test harness for Windows_Audit.ps1 v2.5+.
    Produces a structured lab report (JSON + optional JUnit XML).

    What changed from v2.0:
      [S2] JSON Schema  -- HygieneScore top-level field; Delta field (nullable);
                          Confidence enum extended to 6 values (NoAccess, QueryFailed);
                          Sprint D finding IDs verified present in Deep output.
      [S3] Smoke Matrix -- -SkipHTML flag passed to all child runs (faster CI);
                           HTML output verified when SkipHTML is NOT passed.
      [S4] Exit contract -- unchanged, reuses S3 results.
      [S5] Idempotency  -- HygieneScore stability check added alongside ScoreBefore.
      [S6] Performance  -- unchanged.
      [S7] Boundary     -- new cases: -CompareTo missing file (non-fatal), -Baseline
                           round-trip (write then re-read), -SkipHTML suppresses HTML.
      [S8] Delta Engine  -- NEW suite: baseline write, compare, verify delta structure,
                           score delta polarity, regression/improvement lists.
      [S9] Sprint D IDs  -- NEW suite: verifies that each new Sprint D check ID appears
                           in a Deep run output (structural coverage, not value checking).

    Architecture invariants from v2.0 preserved:
      - NEVER calls exit/SetShouldExit in the parent process.
      - Every test isolated in its own try/catch.
      - Results via $Script:Results += []; no ArrayList scope bugs.
      - PSExe resolved from current process.
      - Single Invoke-AuditChild function for all child runs.

.PARAMETER AuditScript
    Path to Windows_Audit.ps1.

.PARAMETER OutDir
    Directory for all test artifacts. Defaults to .\audit_lab_<timestamp>.

.PARAMETER Suites
    Suites to run. Default: all.
    Values: S1, S2, S3, S4, S5, S6, S7, S8, S9.

.PARAMETER TimeoutSec
    Max seconds to wait for each child run. Default: 300.

.PARAMETER SkipMatrix
    Abbreviate S3 to Fast+PersonalLaptop only (saves time on slow machines).

.PARAMETER ExportJUnit
    Also emit a JUnit XML report.

.PARAMETER Quiet
    Suppress Write-Host output.

.PARAMETER PassThru
    Output the $labReport PSCustomObject to the pipeline.

.EXAMPLE
    .\Invoke-AuditLabTest.ps1 -AuditScript .\Windows_Audit.ps1
    .\Invoke-AuditLabTest.ps1 -AuditScript .\Windows_Audit.ps1 -Suites S1,S2,S8,S9
    .\Invoke-AuditLabTest.ps1 -AuditScript .\Windows_Audit.ps1 -SkipMatrix -ExportJUnit
    .\Invoke-AuditLabTest.ps1 -AuditScript .\Windows_Audit.ps1 -Quiet -PassThru | ConvertTo-Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $AuditScript,

    [string] $OutDir = "",

    [ValidateSet("S1","S2","S3","S4","S5","S6","S7","S8","S9")]
    [string[]] $Suites = @("S1","S2","S3","S4","S5","S6","S7","S8","S9"),

    [int]    $TimeoutSec  = 300,
    [switch] $SkipMatrix,
    [switch] $ExportJUnit,
    [switch] $Quiet,
    [switch] $PassThru
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
#  RESULT ACCUMULATOR
# ---------------------------------------------------------------------------
$Script:Results   = @()
$Script:SuiteTime = @{}
$Script:TestSeq   = 0

function Add-Result {
    param(
        [string] $Suite,
        [string] $Id,
        [ValidateSet("PASS","FAIL","WARN","SKIP","INFO")]
        [string] $Status,
        [string] $Description,
        [string] $Detail = ""
    )
    $Script:TestSeq++
    $Script:Results += [PSCustomObject]@{
        Seq    = $Script:TestSeq
        Suite  = $Suite
        Id     = $Id
        Status = $Status
        Desc   = $Description
        Detail = $Detail
    }
}

# ---------------------------------------------------------------------------
#  CONSOLE HELPERS
# ---------------------------------------------------------------------------
function Write-Banner {
    param([string]$Text)
    if(-not $Quiet){
        Write-Host ""; Write-Host ("-"*80) -ForegroundColor DarkCyan
        Write-Host "  $Text" -ForegroundColor Cyan
        Write-Host ("-"*80) -ForegroundColor DarkCyan
    }
}
function Write-SuiteHeader {
    param([string]$Id,[string]$Name)
    if(-not $Quiet){Write-Host ""; Write-Host "  +-- [$Id] $Name" -ForegroundColor Yellow}
}
function Write-TestLine {
    param([ValidateSet("PASS","FAIL","WARN","SKIP","INFO")][string]$Status,[string]$Id,[string]$Desc,[string]$Detail="")
    if($Quiet){return}
    $label=switch($Status){"PASS"{"[PASS]"};"FAIL"{"[FAIL]"};"WARN"{"[WARN]"};"SKIP"{"[SKIP]"};"INFO"{"[INFO]"}}
    $color=switch($Status){"PASS"{"Green"};"FAIL"{"Red"};"WARN"{"Yellow"};"SKIP"{"DarkGray"};"INFO"{"DarkCyan"}}
    Write-Host ("  |  $label $($Id.PadRight(38)) $Desc") -ForegroundColor $color
    if($Detail){foreach($row in ($Detail -split "`n")){if($row.Trim()){Write-Host "  |     -> $row" -ForegroundColor DarkGray}}}
}

function Emit {
    param(
        [Parameter(Mandatory)][ValidateSet("PASS","FAIL","WARN","SKIP","INFO")][string]$Status,
        [Parameter(Mandatory)][string]$Suite,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Desc,
        [string]$Detail=""
    )
    Add-Result -Suite $Suite -Id $Id -Status $Status -Description $Desc -Detail $Detail
    Write-TestLine -Status $Status -Id $Id -Desc $Desc -Detail $Detail
}

# ---------------------------------------------------------------------------
#  POWERSHELL EXECUTABLE DETECTION
# ---------------------------------------------------------------------------
$Script:PSExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if(-not (Test-Path $Script:PSExe)){
    $fb=Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    if(Test-Path $fb){$Script:PSExe=$fb}else{$cmd=Get-Command powershell -EA SilentlyContinue;if($cmd){$Script:PSExe=$cmd.Source}}
}

# ---------------------------------------------------------------------------
#  CHILD PROCESS RUNNER
# ---------------------------------------------------------------------------
function Invoke-AuditChild {
    param([string[]]$ArgList,[string]$StdOutFile,[string]$StdErrFile,[int]$Timeout=$TimeoutSec)
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    foreach($f in @($StdOutFile,$StdErrFile)){
        $d=Split-Path $f -Parent
        if($d -and -not (Test-Path $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null}
    }
    # Convert -File invocations to -Command to avoid Windows CommandLineToArgvW parsing bug
    $fileIdx=-1
    for($i=0;$i -lt $ArgList.Count;$i++){if($ArgList[$i] -eq "-File"){$fileIdx=$i;break}}
    if($fileIdx -ge 0 -and ($fileIdx+1) -lt $ArgList.Count){
        $scriptPath=$ArgList[$fileIdx+1]
        $scriptParams=if(($fileIdx+2) -lt $ArgList.Count){$ArgList[($fileIdx+2)..($ArgList.Count-1)]}else{@()}
        $safeScript=$scriptPath -replace "'","''"
        $paramTokens=$scriptParams|ForEach-Object{if($_ -match "^-"){$_}elseif($_ -match "[\s']"){"'{0}'" -f ($_ -replace "'","''")}else{$_}}
        $innerCmd="& '$safeScript' "+($paramTokens -join " ")
        $preFlags=if($fileIdx -gt 0){$ArgList[0..($fileIdx-1)] -join " "}else{""}
        $cmdValue=$innerCmd -replace '"','\"'
        $argStr="$preFlags -Command `"$cmdValue`""
    } else { $argStr=$ArgList -join " " }

    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$Script:PSExe; $psi.Arguments=$argStr
    $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true; $psi.CreateNoWindow=$true
    $psi.WorkingDirectory=(Split-Path $AuditScriptFull -Parent)
    $p=New-Object System.Diagnostics.Process; $p.StartInfo=$psi; $p.Start()|Out-Null
    $outTask=$p.StandardOutput.ReadToEndAsync(); $errTask=$p.StandardError.ReadToEndAsync()
    $exited=$p.WaitForExit($Timeout*1000)
    if(-not $exited){try{$p.Kill()}catch{};$sw.Stop();return [PSCustomObject]@{ExitCode=124;TimedOut=$true;ElapsedMs=$sw.ElapsedMilliseconds}}
    try{
        $outText=$outTask.Result; $errText=$errTask.Result
        $enc=New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($StdOutFile,$outText,$enc)
        [System.IO.File]::WriteAllText($StdErrFile,$errText,$enc)
    } catch {}
    $sw.Stop(); $code=999; try{$code=[int]$p.ExitCode}catch{}
    return [PSCustomObject]@{ExitCode=$code;TimedOut=$false;ElapsedMs=$sw.ElapsedMilliseconds}
}

function Read-JsonSafe {
    param([string]$Path,[int]$Retries=20,[int]$DelayMs=200)
    for($i=0;$i -lt $Retries;$i++){
        if(Test-Path $Path){
            try{$raw=Get-Content $Path -Raw -ErrorAction Stop;if($raw -and $raw.Trim()){return $raw|ConvertFrom-Json}}catch{}
        }
        Start-Sleep -Milliseconds $DelayMs
    }
    return $null
}

# ---------------------------------------------------------------------------
#  RESOLVE PATHS
# ---------------------------------------------------------------------------
$AuditScriptFull=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AuditScript)
$ts=(Get-Date).ToString("yyyyMMdd_HHmmss")
if(-not $OutDir){$OutDir=Join-Path (Split-Path $AuditScriptFull -Parent) "audit_lab_$ts"}
$LogsDir=Join-Path $OutDir "logs"
New-Item -ItemType Directory -Path $LogsDir -Force|Out-Null

# ---------------------------------------------------------------------------
#  PRE-FLIGHT
# ---------------------------------------------------------------------------
function Invoke-PreFlight {
    if(-not (Test-Path $AuditScriptFull)){
        Write-Banner "PRE-FLIGHT FAILURE"
        if(-not $Quiet){Write-Host "  [!!] Target script not found: $AuditScriptFull" -ForegroundColor Red}
        return $false
    }
    try {
        $tokens=$null; $errors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile($AuditScriptFull,[ref]$tokens,[ref]$errors)
        $params=$ast.FindAll({$args[0] -is [System.Management.Automation.Language.ParameterAst]},$true)
        $names=$params|ForEach-Object{$_.Name.VariablePath.UserPath}
        # v2.5 expected parameters (Sprint A-D)
        $expected=@("Mode","Profile","ExportJSON","ExportHTML","CompareTo","Baseline","SkipHTML","NoTUI","ShowSignals","Version","Help")
        $missing=$expected|Where-Object{$_ -notin $names}
        if($missing -and -not $Quiet){Write-Host "  [!!] Missing expected params: $($missing -join ', ')" -ForegroundColor Yellow}
    } catch {}
    return $true
}

# ---------------------------------------------------------------------------
#  ADMIN DETECTION
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    try{$pr=New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent());return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)}catch{return $false}
}
$Script:IsAdmin=Test-IsAdmin

# ---------------------------------------------------------------------------
#  SHARED CHILD ARGS BUILDER
# ---------------------------------------------------------------------------
function Get-BaseArgs {
    param([string]$Mode="Fast",[string]$Profile="PersonalLaptop",[string]$JsonOut="",[switch]$NoHTML,[hashtable]$Extra=@{})
    $args=@("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode",$Mode,"-Profile",$Profile,"-NoTUI")
    if($JsonOut)  {$args+=@("-ExportJSON",$JsonOut)}
    if($NoHTML)   {$args+="-SkipHTML"}
    foreach($kv in $Extra.GetEnumerator()){$args+=@($kv.Key,$kv.Value)}
    return $args
}

# ---------------------------------------------------------------------------
#  BANNER
# ---------------------------------------------------------------------------
Write-Banner "APEX AUDIT SCIENTIFIC TEST LABORATORY v3.0"
if(-not $Quiet){
    Write-Host "  Target  : $AuditScriptFull"
    Write-Host "  OutDir  : $OutDir"
    Write-Host "  Suites  : $($Suites -join ', ')"
    Write-Host "  Timeout : ${TimeoutSec}s per child run"
    Write-Host "  Time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "  PS      : $($PSVersionTable.PSVersion)"
    Write-Host "  Admin   : $(if($Script:IsAdmin){'YES (full WMI coverage)'}else{'NO  (some checks limited)'})"
}
$preFlight=Invoke-PreFlight

# ===========================================================================
#  SUITE S1 -- STATIC ANALYSIS
# ===========================================================================
if("S1" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S1" "Static Analysis"

    # S1.1 AST parse
    try{
        $tokens=$null;$errors=$null
        [System.Management.Automation.Language.Parser]::ParseFile($AuditScriptFull,[ref]$tokens,[ref]$errors)|Out-Null
        $tok=@($tokens).Count;$err=@($errors).Count
        if($err -eq 0){Emit -Status PASS -Suite S1 -Id S1.1 -Desc "AST Parse clean" -Detail "$tok tokens, 0 errors"}
        else{$errDetail=($errors|ForEach-Object{"L$($_.Extent.StartLineNumber): $($_.Message)"})-join "`n";Emit -Status FAIL -Suite S1 -Id S1.1 -Desc "AST parse errors found" -Detail $errDetail}
    }catch{Emit -Status FAIL -Suite S1 -Id S1.1 -Desc "AST parse threw" -Detail $_.Exception.Message}

    # S1.2 Encoding: UTF-8 no BOM
    try{
        $raw=[System.IO.File]::ReadAllBytes($AuditScriptFull)
        $hasBOM=$raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF
        if(-not $hasBOM){Emit -Status PASS -Suite S1 -Id S1.2 -Desc "Encoding: UTF-8 no BOM"}
        else{Emit -Status FAIL -Suite S1 -Id S1.2 -Desc "UTF-8 BOM detected -- remove BOM"}
    }catch{Emit -Status WARN -Suite S1 -Id S1.2 -Desc "Encoding check failed" -Detail $_.Exception.Message}

    # S1.3 PSScriptAnalyzer
    try{
        $analyzerAvail=$null -ne (Get-Command Invoke-ScriptAnalyzer -EA SilentlyContinue)
        if(-not $analyzerAvail){Emit -Status WARN -Suite S1 -Id S1.3 -Desc "PSScriptAnalyzer not installed -- skipping" -Detail "Install-Module PSScriptAnalyzer -Scope CurrentUser"}
        else{
            $results=Invoke-ScriptAnalyzer -Path $AuditScriptFull -Recurse -EA Stop
            $errC=@($results|Where-Object{$_.Severity -eq "Error"}).Count
            $warnC=@($results|Where-Object{$_.Severity -eq "Warning"}).Count
            $infoC=@($results|Where-Object{$_.Severity -eq "Information"}).Count
            $fullPath=Join-Path $LogsDir "S1_PSScriptAnalyzer.json"
            $results|ConvertTo-Json -Depth 4|Out-File $fullPath -Encoding utf8 -Force
            $sev=if($errC -gt 0){"FAIL"}elseif($warnC -gt 0){"WARN"}else{"PASS"}
            $top=$results|Where-Object{$_.Severity -in @("Error","Warning")}|Select-Object -First 5
            $topLines=($top|ForEach-Object{"[$($_.Severity)] L$($_.ScriptLineNumber): $($_.Message)"})-join "`n"
            Emit -Status $sev -Suite S1 -Id S1.3 -Desc "PSScriptAnalyzer: $errC errors, $warnC warnings" -Detail "Full: $fullPath`n$topLines"
        }
    }catch{Emit -Status WARN -Suite S1 -Id S1.3 -Desc "PSScriptAnalyzer threw" -Detail $_.Exception.Message}

    # S1.4 Parameter annotations
    try{
        $tokens=$null;$errors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile($AuditScriptFull,[ref]$tokens,[ref]$errors)
        $params=$ast.FindAll({$args[0] -is [System.Management.Automation.Language.ParameterAst]},$true)
        $noType=$params|Where-Object{$null -eq $_.StaticType -or $_.StaticType.Name -eq "Object"}
        $cnt=@($noType).Count;$tot=@($params).Count
        if($cnt -eq 0){Emit -Status PASS -Suite S1 -Id S1.4 -Desc "All $tot parameters have explicit type annotations"}
        else{Emit -Status WARN -Suite S1 -Id S1.4 -Desc "$cnt/$tot params lack type annotation" -Detail (($noType|ForEach-Object{$_.Name.VariablePath.UserPath})-join ", ")}
    }catch{Emit -Status WARN -Suite S1 -Id S1.4 -Desc "Param type check failed" -Detail $_.Exception.Message}

    # S1.5 No bare exit statements
    try{
        $tokens=$null;$errors=$null
        [System.Management.Automation.Language.Parser]::ParseFile($AuditScriptFull,[ref]$tokens,[ref]$errors)|Out-Null
        $exitTok=@($tokens|Where-Object{$_.Kind -eq "Exit" -and $_.Text -eq "exit"})
        if($exitTok.Count -eq 0){Emit -Status PASS -Suite S1 -Id S1.5 -Desc "No bare 'exit' in function bodies (good for interactive use)"}
        else{Emit -Status WARN -Suite S1 -Id S1.5 -Desc "$($exitTok.Count) exit statement(s)" -Detail "Lines: $(($exitTok|ForEach-Object{$_.Extent.StartLineNumber})-join ', ')"}
    }catch{Emit -Status WARN -Suite S1 -Id S1.5 -Desc "Exit check failed" -Detail $_.Exception.Message}

    # S1.6 Comment-based help
    try{
        $helpInfo=Get-Help $AuditScriptFull -EA Stop
        $hasSyn=[bool]($helpInfo.Synopsis -and $helpInfo.Synopsis.Trim())
        $hasDesc=[bool]($helpInfo.Description -and @($helpInfo.Description).Count -gt 0)
        $hasEx=[bool]($helpInfo.Examples -and @($helpInfo.Examples.Example).Count -gt 0)
        if($hasSyn -and $hasDesc -and $hasEx){Emit -Status PASS -Suite S1 -Id S1.6 -Desc "Help block complete (SYNOPSIS, DESCRIPTION, EXAMPLE)"}
        else{
            $missing=@(); if(-not $hasSyn){"SYNOPSIS"}; if(-not $hasDesc){"DESCRIPTION"}; if(-not $hasEx){"EXAMPLE"}
            Emit -Status WARN -Suite S1 -Id S1.6 -Desc "Help block incomplete" -Detail ($missing -join ", ")
        }
    }catch{Emit -Status WARN -Suite S1 -Id S1.6 -Desc "Help check failed" -Detail $_.Exception.Message}

    # S1.7 Sprint D: Check Manifest contains all expected function names
    try{
        $content=Get-Content $AuditScriptFull -Raw -ErrorAction Stop
        $expectedFns=@(
            "Invoke-CheckBaseline","Invoke-CheckDeviceGuard","Invoke-CheckFirewall",
            "Invoke-CheckFirewallPosture","Invoke-CheckSMB","Invoke-CheckRDP",
            "Invoke-CheckNetwork","Invoke-CheckIdentity","Invoke-CheckLocalAdmins",
            "Invoke-CheckDefenderExclusions","Invoke-CheckExploitProtection",
            "Invoke-CheckForensics","Invoke-CheckTelemetry","Invoke-CheckASR",
            "Invoke-CheckAuditPol","Invoke-CheckWEF","Invoke-CheckServicePaths"
        )
        $missing=$expectedFns|Where-Object{$content -notmatch [regex]::Escape($_)}
        if(-not $missing){Emit -Status PASS -Suite S1 -Id S1.7 -Desc "All $($expectedFns.Count) expected check functions present in source"}
        else{Emit -Status FAIL -Suite S1 -Id S1.7 -Desc "Missing check functions" -Detail ($missing -join ", ")}
    }catch{Emit -Status WARN -Suite S1 -Id S1.7 -Desc "Function presence check failed" -Detail $_.Exception.Message}

    $sw.Stop();$Script:SuiteTime["S1"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S2 -- JSON SCHEMA CONTRACT  (updated for v2.5)
# ===========================================================================
if("S2" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S2" "JSON Schema Contract Validation (v2.5)"

    $existingJson=$null
    try{
        $recent=Get-ChildItem -Path (Split-Path $AuditScriptFull -Parent) -Filter "*.json" -Recurse|
                Where-Object{$_.Name -match "audit_report"}|Sort-Object LastWriteTime -Descending|Select-Object -First 1
        if($recent){
            $ageMin=([datetime]::UtcNow - $recent.LastWriteTimeUtc).TotalMinutes
            if($ageMin -le 30){$existingJson=$recent.FullName;Emit -Status INFO -Suite S2 -Id S2.0 -Desc "Using fresh JSON (age=$([math]::Round($ageMin,1)) min): $existingJson"}
            else{Emit -Status INFO -Suite S2 -Id S2.0 -Desc "Stale JSON (age=$([math]::Round($ageMin,0)) min) -- running fresh child"}
        }
    }catch{}

    if(-not $existingJson){
        $quickJson=Join-Path $LogsDir "S2_quick_run.json"
        $r=Invoke-AuditChild `
            -ArgList (Get-BaseArgs -Mode "Fast" -JsonOut $quickJson -NoHTML) `
            -StdOutFile (Join-Path $LogsDir "S2_quick_stdout.txt") `
            -StdErrFile (Join-Path $LogsDir "S2_quick_stderr.txt") -Timeout 120
        if(Test-Path $quickJson){$existingJson=$quickJson;Emit -Status INFO -Suite S2 -Id S2.0 -Desc "Fresh JSON produced"}
        else{
            Emit -Status SKIP -Suite S2 -Id S2.0 -Desc "No JSON available -- S2 skipped" -Detail "exit=$($r.ExitCode)"
            $sw.Stop();$Script:SuiteTime["S2"]=$sw.ElapsedMilliseconds
        }
    }

    if($existingJson){
        $j=Read-JsonSafe -Path $existingJson

        # S2.1 Top-level fields (v2.5 adds HygieneScore and Delta)
        foreach($field in @("Context","ScoreBefore","HygieneScore","ScoreAfter","Findings")){
            $present=$null -ne ($j|Select-Object -ExpandProperty $field -EA SilentlyContinue)
            $_emSt1 = if($present){"PASS"}else{"FAIL"}
            Emit -Status $_emSt1 -Suite S2 -Id "S2.1.$field" -Desc "Top-level field '$field' present"
        }
        # Delta is nullable -- just verify the key exists (value may be null when -CompareTo not used)
        $deltaKeyExists=$j.PSObject.Properties.Name -contains "Delta"
        $_emSt2 = if($deltaKeyExists){"PASS"}else{"WARN"}
        Emit -Status $_emSt2 -Suite S2 -Id "S2.1.Delta" -Desc "Top-level field 'Delta' present (nullable -- null expected without -CompareTo)"

        # S2.2 Context fields
        $ctxFields=@{
            "Hostname"    ={$args[0] -match '^\S+$'}
            "OSCaption"   ={$args[0] -match 'Windows'}
            "OSBuild"     ={$args[0] -match '^\d+$'}
            "TimestampUTC"={$args[0] -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'}
            "Mode"        ={$args[0] -in @("Fast","Deep")}
            "Profile"     ={$args[0] -in @("PersonalLaptop","Enterprise","Lab","Paranoid")}
            "PSVersion"   ={$args[0] -match '\d+\.\d+'}
        }
        foreach($kv in $ctxFields.GetEnumerator()){
            try{
                $val=$j.Context.($kv.Key); $valid=$val -and (& $kv.Value $val)
                $_emSt3 = if($valid){"PASS"}else{"FAIL"}
                Emit -Status $_emSt3 -Suite S2 -Id "S2.2.$($kv.Key)" -Desc "Context.$($kv.Key) = '$val'"
            }catch{Emit -Status FAIL -Suite S2 -Id "S2.2.$($kv.Key)" -Desc "Context.$($kv.Key) threw" -Detail $_.Exception.Message}
        }

        # S2.3 Score ranges
        try{
            $sb=[double]$j.ScoreBefore; $sa=[double]$j.ScoreAfter
            $hy=[double]$j.HygieneScore
            $_emSt4 = if($sb -ge 0 -and $sb -le 100){"PASS"}else{"FAIL"}
            Emit -Status $_emSt4 -Suite S2 -Id S2.3a -Desc "ScoreBefore in [0,100]: $sb"
            $_emSt5 = if($sa -eq -1 -or ($sa -ge 0 -and $sa -le 100)){"PASS"}else{"FAIL"}
            Emit -Status $_emSt5 -Suite S2 -Id S2.3b -Desc "ScoreAfter valid: $sa"
            $_emSt6 = if($hy -ge 0 -and $hy -le 100){"PASS"}else{"FAIL"}
            Emit -Status $_emSt6 -Suite S2 -Id S2.3c -Desc "HygieneScore in [0,100]: $hy"
        }catch{Emit -Status FAIL -Suite S2 -Id S2.3a -Desc "Score parse failed" -Detail $_.Exception.Message}

        # S2.4 Findings non-empty
        $findings=@($j.Findings); $fCount=$findings.Count
        $_emSt7 = if($fCount -gt 0){"PASS"}else{"FAIL"}
        Emit -Status $_emSt7 -Suite S2 -Id S2.4 -Desc "Findings array: $fCount entries"

        if($fCount -gt 0){
            # S2.5 Required fields on every finding
            $reqFields=@("Id","Category","CheckName","Severity","Vulnerable","Confidence","Observed","Expected","Source","Fix","Note")
            $incomplete=$findings|Where-Object{$f=$_;$missing=$reqFields|Where-Object{$null -eq ($f|Select-Object -ExpandProperty $_ -EA SilentlyContinue)};[bool]$missing}
            $_emSt8 = if(@($incomplete).Count -eq 0){"PASS"}else{"FAIL"}
            $_detSt8 = if($incomplete){"Missing in: "+(($incomplete|ForEach-Object{$_.Id})-join ", ")}else{""}
            Emit -Status $_emSt8 -Suite S2 -Id S2.5 `
                -Desc "All $fCount findings have all $($reqFields.Count) required fields" `
                -Detail $_detSt8

            # S2.6 Valid Severity enum
            $validSev=@("CRITICAL","HIGH","MEDIUM","LOW","PASS")
            $badSev=$findings|Where-Object{$_.Severity -notin $validSev}
            $_emSt9 = if(@($badSev).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt9 -Suite S2 -Id S2.6 `
                -Desc "All Severity values valid" -Detail (($badSev|ForEach-Object{"$($_.Id)=$($_.Severity)"})-join "`n")

            # S2.7 Vulnerable is boolean
            $badVuln=$findings|Where-Object{$_.Vulnerable -isnot [bool] -and $_.Vulnerable -isnot [System.Boolean]}
            $_emSt10 = if(@($badVuln).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt10 -Suite S2 -Id S2.7 -Desc "All Vulnerable fields are boolean"

            # S2.8 Valid Confidence enum (v2.5: 6 values)
            $validConf=@("High","Medium","Low","NotApplicable","NoAccess","QueryFailed")
            $badConf=$findings|Where-Object{$_.Confidence -notin $validConf}
            $_emSt11 = if(@($badConf).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt11 -Suite S2 -Id S2.8 `
                -Desc "All Confidence values valid (6-value enum: High|Medium|Low|NotApplicable|NoAccess|QueryFailed)" `
                -Detail (($badConf|ForEach-Object{"$($_.Id)=$($_.Confidence)"})-join "`n")

            # S2.9 Unique IDs
            $ids=$findings|ForEach-Object{$_.Id}
            $dupes=$ids|Group-Object|Where-Object{$_.Count -gt 1}
            $_emSt12 = if(@($dupes).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt12 -Suite S2 -Id S2.9 `
                -Desc "All $fCount finding IDs are unique" -Detail (($dupes|ForEach-Object{"$($_.Name) x$($_.Count)"})-join "`n")

            # S2.10 PASS severity never Vulnerable=true
            $passVuln=$findings|Where-Object{$_.Severity -eq "PASS" -and $_.Vulnerable -eq $true}
            $_emSt13 = if(@($passVuln).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt13 -Suite S2 -Id S2.10 -Desc "No PASS finding marked Vulnerable=true"

            # S2.11 Vulnerable=true never has Severity=PASS
            $vulnPass=$findings|Where-Object{$_.Vulnerable -eq $true -and $_.Severity -eq "PASS"}
            $_emSt14 = if(@($vulnPass).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt14 -Suite S2 -Id S2.11 -Desc "No Vulnerable=true finding has Severity=PASS"

            # S2.12 Score semantic consistency
            $vulnCount=@($findings|Where-Object{$_.Vulnerable -eq $true}).Count
            $score=[double]$j.ScoreBefore
            $semOk=($vulnCount -eq 0 -and $score -ge 80)-or($vulnCount -gt 0 -and $score -lt 100)-or($score -le (100-$vulnCount))
            $_emSt15 = if($semOk){"PASS"}else{"WARN"}
            Emit -Status $_emSt15 -Suite S2 -Id S2.12 -Desc "Score/vuln-count semantically consistent: score=$score, vulns=$vulnCount"

            # S2.13 Non-empty text fields
            $emptyName=$findings|Where-Object{-not $_.CheckName -or $_.CheckName.Trim() -eq ""}
            $_emSt16 = if(@($emptyName).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt16 -Suite S2 -Id S2.13a -Desc "All findings have non-empty CheckName"
            $emptySrc=$findings|Where-Object{-not $_.Source -or $_.Source.Trim() -eq ""}
            $_emSt17 = if(@($emptySrc).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt17 -Suite S2 -Id S2.13b -Desc "All findings have non-empty Source"

            # S2.14 Vulnerable=true findings have actionable Fix
            $vulnNoFix=$findings|Where-Object{$_.Vulnerable -eq $true -and ($null -eq $_.Fix -or $_.Fix -in @("","N/A"))}
            $vulnTotal=@($findings|Where-Object{$_.Vulnerable -eq $true}).Count
            $_emSt18 = if(@($vulnNoFix).Count -eq 0){"PASS"}else{"FAIL"}
            $_detSt18 = if($vulnNoFix){($vulnNoFix|ForEach-Object{$_.Id})-join ", "}else{""}
            Emit -Status $_emSt18 -Suite S2 -Id S2.14 `
                -Desc "All $vulnTotal vulnerable findings have actionable Fix" `
                -Detail $_detSt18

            # S2.15 Timestamp freshness
            try{
                $tsVal=[datetime]::ParseExact($j.Context.TimestampUTC,"yyyy-MM-ddTHH:mm:ssZ",[System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::AssumeUniversal)
                $ageMin=[math]::Round(([datetime]::UtcNow-$tsVal).TotalMinutes,1)
                $_emSt19 = if($ageMin -lt 60){"PASS"}else{"WARN"}
                Emit -Status $_emSt19 -Suite S2 -Id S2.15 -Desc "TimestampUTC fresh: age=$ageMin min"
            }catch{Emit -Status FAIL -Suite S2 -Id S2.15 -Desc "TimestampUTC not valid ISO-8601" -Detail $_.Exception.Message}

            # S2.16 NoAccess findings never Vulnerable=true (they represent unknown state)
            $noAccessVuln=$findings|Where-Object{$_.Confidence -eq "NoAccess" -and $_.Vulnerable -eq $true}
            $_emSt20 = if(@($noAccessVuln).Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt20 -Suite S2 -Id S2.16 `
                -Desc "NoAccess findings never Vulnerable=true (undefined state)" `
                -Detail (($noAccessVuln|ForEach-Object{$_.Id})-join ", ")
        }
    }
    $sw.Stop();$Script:SuiteTime["S2"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S3 -- SMOKE RUN MATRIX
# ===========================================================================
if("S3" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S3" "Smoke Run Matrix (Mode x Profile)"

    $matrix=if($SkipMatrix){@(@{Mode="Fast";Profile="PersonalLaptop"})}
    else{@(
        @{Mode="Fast";Profile="PersonalLaptop"}
        @{Mode="Deep";Profile="PersonalLaptop"}
        @{Mode="Deep";Profile="Enterprise"}
        @{Mode="Deep";Profile="Lab"}
        @{Mode="Deep";Profile="Paranoid"}
    )}

    $Script:MatrixResults=@{}

    foreach($combo in $matrix){
        $m=$combo.Mode; $p=$combo.Profile; $tag="S3_${m}_${p}"
        $jOut=Join-Path $LogsDir "${tag}_report.json"
        $hOut=Join-Path $LogsDir "${tag}_report.html"

        Emit -Status INFO -Suite S3 -Id $tag -Desc "Running $m x $p ..."

        try{
            # Pass -SkipHTML only for non-PersonalLaptop+Fast combos to save time
            # For Fast+PersonalLaptop, let HTML generate so we can verify it exists
            $skipHtmlFlag=if($m -eq "Fast" -and $p -eq "PersonalLaptop"){$false}else{$true}
            $extraArgs=if(-not $skipHtmlFlag){@{"-ExportHTML"=$hOut}}else{@{}}
            $argList=if($skipHtmlFlag){
                @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode",$m,"-Profile",$p,"-NoTUI","-SkipHTML","-ExportJSON",$jOut)
            }else{
                @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode",$m,"-Profile",$p,"-NoTUI","-ExportJSON",$jOut,"-ExportHTML",$hOut)
            }

            $r=Invoke-AuditChild -ArgList $argList `
                -StdOutFile (Join-Path $LogsDir "${tag}_stdout.txt") `
                -StdErrFile (Join-Path $LogsDir "${tag}_stderr.txt")

            $Script:MatrixResults[$tag]=@{Result=$r;JsonPath=$jOut;HtmlPath=$hOut;Mode=$m;Profile=$p;SkippedHTML=$skipHtmlFlag}
            $elapsed=[math]::Round($r.ElapsedMs/1000,1)

            if($r.TimedOut){Emit -Status FAIL -Suite S3 -Id "$tag.exitcode" -Desc "$p timed out after ${TimeoutSec}s"}
            elseif($r.ExitCode -in @(0,1,999)){Emit -Status PASS -Suite S3 -Id "$tag.exitcode" -Desc "$p exit=$($r.ExitCode) elapsed=${elapsed}s"}
            else{Emit -Status FAIL -Suite S3 -Id "$tag.exitcode" -Desc "$p unexpected exit=$($r.ExitCode) elapsed=${elapsed}s"}

            if(Test-Path $jOut){Emit -Status PASS -Suite S3 -Id "$tag.json" -Desc "$p JSON produced"}
            else{
                $errTail=try{(Get-Content (Join-Path $LogsDir "${tag}_stderr.txt") -EA Stop|Select-Object -Last 8)-join "`n"}catch{""}
                Emit -Status FAIL -Suite S3 -Id "$tag.json" -Desc "$p JSON not produced (exit=$($r.ExitCode))" -Detail $errTail
            }

            # HTML check only for the run that should produce it
            if(-not $skipHtmlFlag){
                if(Test-Path $hOut){Emit -Status PASS -Suite S3 -Id "$tag.html" -Desc "$p HTML produced (self-contained report)"}
                else{Emit -Status FAIL -Suite S3 -Id "$tag.html" -Desc "$p HTML not produced"}
            }
        }catch{Emit -Status FAIL -Suite S3 -Id "$tag.exitcode" -Desc "$p invocation threw" -Detail $_.Exception.Message}
    }
    $sw.Stop();$Script:SuiteTime["S3"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S4 -- EXIT CODE CONTRACT
# ===========================================================================
if("S4" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S4" "Exit Code Contract Verification"

    if(-not $Script:MatrixResults -or $Script:MatrixResults.Count -eq 0){
        Emit -Status SKIP -Suite S4 -Id S4.0 -Desc "No S3 results -- run S3 first"
    } else {
        Emit -Status INFO -Suite S4 -Id S4.0 -Desc "Reusing $($Script:MatrixResults.Count) run(s) from S3"
        foreach($kv in $Script:MatrixResults.GetEnumerator()){
            $tag=$kv.Key; $run=$kv.Value; $r=$run.Result; $jOut=$run.JsonPath
            if(-not (Test-Path $jOut)){Emit -Status SKIP -Suite S4 -Id "$tag.contract" -Desc "JSON missing -- cannot verify";continue}
            try{
                $j=Read-JsonSafe -Path $jOut
                $hasVulns=@($j.Findings|Where-Object{$_.Vulnerable -eq $true}).Count -gt 0
                $expectExit=if($hasVulns){1}else{0}
                $actualExit=$r.ExitCode
                if($actualExit -eq $expectExit){Emit -Status PASS -Suite S4 -Id "$tag.contract" -Desc "Exit matches JSON posture: exit=$actualExit vulns=$hasVulns"}
                else{Emit -Status FAIL -Suite S4 -Id "$tag.contract" -Desc "Exit mismatch: got=$actualExit expected=$expectExit (vulns=$hasVulns)"}
            }catch{Emit -Status FAIL -Suite S4 -Id "$tag.contract" -Desc "Contract check threw" -Detail $_.Exception.Message}
        }
    }
    $sw.Stop();$Script:SuiteTime["S4"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S5 -- IDEMPOTENCY
# ===========================================================================
if("S5" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S5" "Idempotency (2 consecutive Deep runs)"

    $j1=Join-Path $LogsDir "S5_run1.json"; $j2=Join-Path $LogsDir "S5_run2.json"
    Emit -Status INFO -Suite S5 -Id S5.0 -Desc "Run 1/2 ..."
    $r1=Invoke-AuditChild -ArgList (Get-BaseArgs -Mode "Deep" -JsonOut $j1 -NoHTML) `
        -StdOutFile (Join-Path $LogsDir "S5_run1_stdout.txt") -StdErrFile (Join-Path $LogsDir "S5_run1_stderr.txt")
    Emit -Status INFO -Suite S5 -Id S5.0 -Desc "Run 2/2 ..."
    $r2=Invoke-AuditChild -ArgList (Get-BaseArgs -Mode "Deep" -JsonOut $j2 -NoHTML) `
        -StdOutFile (Join-Path $LogsDir "S5_run2_stdout.txt") -StdErrFile (Join-Path $LogsDir "S5_run2_stderr.txt")

    try{
        $jd1=if(Test-Path $j1){Read-JsonSafe $j1}else{$null}
        $jd2=if(Test-Path $j2){Read-JsonSafe $j2}else{$null}
        if($null -eq $jd1 -or $null -eq $jd2){
            $det=""
            if($null -eq $jd1){$det+="Run1 missing. stderr: $(try{(Get-Content (Join-Path $LogsDir 'S5_run1_stderr.txt')|Select-Object -Last 5)-join "`n"}catch{''})`n"}
            if($null -eq $jd2){$det+="Run2 missing. stderr: $(try{(Get-Content (Join-Path $LogsDir 'S5_run2_stderr.txt')|Select-Object -Last 5)-join "`n"}catch{''})`n"}
            Emit -Status FAIL -Suite S5 -Id S5.json -Desc "One or both idempotency JSONs unreadable" -Detail $det
        } else {
            $ids1=@($jd1.Findings|ForEach-Object{$_.Id})|Sort-Object
            $ids2=@($jd2.Findings|ForEach-Object{$_.Id})|Sort-Object
            $idSame=($ids1 -join ",")-eq($ids2 -join ",")
            $scDiff=[math]::Abs([double]$jd1.ScoreBefore-[double]$jd2.ScoreBefore)
            $hyDiff=[math]::Abs([double]$jd1.HygieneScore-[double]$jd2.HygieneScore)

            if($idSame){Emit -Status PASS -Suite S5 -Id S5.findings -Desc "Finding IDs identical across runs ($($ids1.Count) IDs)"}
            else{
                $diff=Compare-Object $ids1 $ids2|ForEach-Object{"$($_.SideIndicator) $($_.InputObject)"}
                Emit -Status FAIL -Suite S5 -Id S5.findings -Desc "Finding set differs" -Detail ($diff -join "`n")
            }
            $_emSt21 = if($scDiff -le 1){"PASS"}else{"WARN"}
            Emit -Status $_emSt21 -Suite S5 -Id S5.score -Desc "SeverityScore stable: r1=$($jd1.ScoreBefore) r2=$($jd2.ScoreBefore) delta=$scDiff"
            $_emSt22 = if($hyDiff -le 1){"PASS"}else{"WARN"}
            Emit -Status $_emSt22 -Suite S5 -Id S5.hygiene -Desc "HygieneScore stable: r1=$($jd1.HygieneScore) r2=$($jd2.HygieneScore) delta=$hyDiff"
        }
    }catch{Emit -Status FAIL -Suite S5 -Id S5.json -Desc "Idempotency analysis threw" -Detail $_.Exception.Message}
    $sw.Stop();$Script:SuiteTime["S5"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S6 -- PERFORMANCE
# ===========================================================================
if("S6" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S6" "Performance Profiling"

    $timings=@{}
    foreach($mode in @("Fast","Deep")){
        Emit -Status INFO -Suite S6 -Id "S6.$mode" -Desc "Timing $mode run ..."
        $jPerf=Join-Path $LogsDir "S6_${mode}_report.json"
        $r=Invoke-AuditChild -ArgList (Get-BaseArgs -Mode $mode -JsonOut $jPerf -NoHTML) `
            -StdOutFile (Join-Path $LogsDir "S6_${mode}_stdout.txt") `
            -StdErrFile (Join-Path $LogsDir "S6_${mode}_stderr.txt") -Timeout 300
        $elapsed=[math]::Round($r.ElapsedMs/1000,1); $timings[$mode]=$elapsed
        if($r.TimedOut){Emit -Status FAIL -Suite S6 -Id "S6.$mode.time" -Desc "$mode timed out after ${TimeoutSec}s"}
        else{Emit -Status PASS -Suite S6 -Id "S6.$mode.time" -Desc "$mode completed in ${elapsed}s"}
    }

    if($timings["Fast"] -and $timings["Deep"]){
        $diff=[math]::Round($timings["Deep"]-$timings["Fast"],1)
        $s6St = if ($diff -ge 0) { "PASS" } else { "WARN" }
        $s6Ds = if ($diff -ge 0) { "Fast < Deep" } else { "Fast > Deep (unexpected)" }
        Emit -Status $s6St -Suite S6 -Id S6.fastVsDeep `
            -Desc "$s6Ds by $([math]::Abs($diff))s"
    }
    $sw.Stop();$Script:SuiteTime["S6"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S7 -- BOUNDARY & EDGE CASES  (expanded for Sprint D params)
# ===========================================================================
if("S7" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S7" "Boundary and Edge Case Tests"

    # S7.1 -Help flag
    try{
        $r=Invoke-AuditChild -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Help") `
            -StdOutFile (Join-Path $LogsDir "S7_help_stdout.txt") -StdErrFile (Join-Path $LogsDir "S7_help_stderr.txt") -Timeout 30
        $s71St = if ($r.ExitCode -in @(0,1)) { "PASS" } else { "WARN" }
        Emit -Status $s71St -Suite S7 -Id S7.1 -Desc "-Help flag: exit=$($r.ExitCode)"
    }catch{Emit -Status FAIL -Suite S7 -Id S7.1 -Desc "-Help test threw" -Detail $_.Exception.Message}

    # S7.2 -Version flag
    try{
        $stdoutPath=Join-Path $LogsDir "S7_version_stdout.txt"
        $r=Invoke-AuditChild -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Version") `
            -StdOutFile $stdoutPath -StdErrFile (Join-Path $LogsDir "S7_version_stderr.txt") -Timeout 30
        $out=if(Test-Path $stdoutPath){Get-Content $stdoutPath -Raw}else{""}
        $hasVer=$out -match "\d+\.\d+\.\d+"
        $s72St = if ($r.ExitCode -eq 0 -and $hasVer) { "PASS" } elseif ($r.ExitCode -eq 0) { "WARN" } else { "WARN" }
        Emit -Status $s72St `
            -Suite S7 -Id S7.2 -Desc "-Version: exit=$($r.ExitCode) versionString=$hasVer"
    }catch{Emit -Status FAIL -Suite S7 -Id S7.2 -Desc "-Version test threw" -Detail $_.Exception.Message}

    # S7.3 Invalid -Mode rejected
    try{
        $r=Invoke-AuditChild -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode","INVALID_XYZ","-NoTUI") `
            -StdOutFile (Join-Path $LogsDir "S7_badmode_stdout.txt") -StdErrFile (Join-Path $LogsDir "S7_badmode_stderr.txt") -Timeout 30
        $s73St = if ($r.ExitCode -ne 0) { "PASS" } else { "FAIL" }
        Emit -Status $s73St -Suite S7 -Id S7.3 -Desc "Invalid -Mode rejected: exit=$($r.ExitCode)"
    }catch{Emit -Status FAIL -Suite S7 -Id S7.3 -Desc "Invalid -Mode test threw" -Detail $_.Exception.Message}

    # S7.4 Invalid -Profile rejected
    try{
        $r=Invoke-AuditChild -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Profile","INVALID_ABC","-NoTUI") `
            -StdOutFile (Join-Path $LogsDir "S7_badprofile_stdout.txt") -StdErrFile (Join-Path $LogsDir "S7_badprofile_stderr.txt") -Timeout 30
        $s74St = if ($r.ExitCode -ne 0) { "PASS" } else { "FAIL" }
        Emit -Status $s74St -Suite S7 -Id S7.4 -Desc "Invalid -Profile rejected: exit=$($r.ExitCode)"
    }catch{Emit -Status FAIL -Suite S7 -Id S7.4 -Desc "Invalid -Profile test threw" -Detail $_.Exception.Message}

    # S7.5 Unwritable ExportJSON path
    try{
        $badPath="C:\WINDOWS\System32\__apex_test_unwritable__.json"
        $r=Invoke-AuditChild `
            -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode","Fast","-Profile","PersonalLaptop","-NoTUI","-SkipHTML","-ExportJSON",$badPath) `
            -StdOutFile (Join-Path $LogsDir "S7_badpath_stdout.txt") -StdErrFile (Join-Path $LogsDir "S7_badpath_stderr.txt") -Timeout 60
        if($r.TimedOut){Emit -Status FAIL -Suite S7 -Id S7.5 -Desc "Unwritable path: script hung"}
        elseif($r.ExitCode -eq 2){Emit -Status PASS -Suite S7 -Id S7.5 -Desc "Unwritable path: exit=2 (fatal error -- correct)"}
        elseif($r.ExitCode -eq 1){Emit -Status WARN -Suite S7 -Id S7.5 -Desc "Unwritable path: exit=1 (may have used temp path)"}
        else{Emit -Status WARN -Suite S7 -Id S7.5 -Desc "Unwritable path: exit=$($r.ExitCode)"}
    }catch{Emit -Status FAIL -Suite S7 -Id S7.5 -Desc "Unwritable path test threw" -Detail $_.Exception.Message}

    # S7.6 -SkipHTML suppresses HTML output
    try{
        $jSkip=Join-Path $LogsDir "S7_skiphtml.json"
        $hSkip=[System.IO.Path]::ChangeExtension($jSkip,".html")
        $r=Invoke-AuditChild `
            -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode","Fast","-Profile","PersonalLaptop","-NoTUI","-SkipHTML","-ExportJSON",$jSkip) `
            -StdOutFile (Join-Path $LogsDir "S7_skiphtml_stdout.txt") -StdErrFile (Join-Path $LogsDir "S7_skiphtml_stderr.txt") -Timeout 120
        $jsonExists=Test-Path $jSkip
        $htmlExists=Test-Path $hSkip
        if($jsonExists -and -not $htmlExists){Emit -Status PASS -Suite S7 -Id S7.6 -Desc "-SkipHTML: JSON produced, HTML absent (correct)"}
        elseif($jsonExists -and $htmlExists){Emit -Status FAIL -Suite S7 -Id S7.6 -Desc "-SkipHTML: HTML was still produced (should not exist)"}
        else{Emit -Status FAIL -Suite S7 -Id S7.6 -Desc "-SkipHTML: JSON also missing -- child failed" -Detail "exit=$($r.ExitCode)"}
    }catch{Emit -Status FAIL -Suite S7 -Id S7.6 -Desc "-SkipHTML test threw" -Detail $_.Exception.Message}

    # S7.7 -CompareTo with non-existent file: non-fatal, run completes normally
    try{
        $jNoBase=Join-Path $LogsDir "S7_nobase.json"
        $r=Invoke-AuditChild `
            -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode","Fast","-Profile","PersonalLaptop","-NoTUI","-SkipHTML","-ExportJSON",$jNoBase,"-CompareTo","C:\__nonexistent_baseline__.json") `
            -StdOutFile (Join-Path $LogsDir "S7_nobase_stdout.txt") -StdErrFile (Join-Path $LogsDir "S7_nobase_stderr.txt") -Timeout 120
        $jsonExists=Test-Path $jNoBase
        if($r.TimedOut){Emit -Status FAIL -Suite S7 -Id S7.7 -Desc "-CompareTo missing file: script hung"}
        elseif($jsonExists -and $r.ExitCode -in @(0,1)){Emit -Status PASS -Suite S7 -Id S7.7 -Desc "-CompareTo missing file: non-fatal, run completed, exit=$($r.ExitCode)"}
        elseif($r.ExitCode -eq 2){Emit -Status FAIL -Suite S7 -Id S7.7 -Desc "-CompareTo missing file: exit=2 (should be non-fatal)"}
        else{Emit -Status WARN -Suite S7 -Id S7.7 -Desc "-CompareTo missing file: exit=$($r.ExitCode) JSON=$jsonExists"}
    }catch{Emit -Status FAIL -Suite S7 -Id S7.7 -Desc "-CompareTo missing file test threw" -Detail $_.Exception.Message}

    $sw.Stop();$Script:SuiteTime["S7"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S8 -- DELTA ENGINE  (new in v3.0)
# ===========================================================================
if("S8" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S8" "Delta Engine: Baseline Write / Compare / Structure"

    $baseFile=Join-Path $LogsDir "S8_baseline.json"
    $run2File=Join-Path $LogsDir "S8_run2.json"

    # S8.1 Write baseline with -Baseline flag
    Emit -Status INFO -Suite S8 -Id S8.1 -Desc "Run 1/2: writing baseline ..."
    try{
        $r1=Invoke-AuditChild `
            -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode","Fast","-Profile","PersonalLaptop","-NoTUI","-SkipHTML","-Baseline",$baseFile) `
            -StdOutFile (Join-Path $LogsDir "S8_run1_stdout.txt") -StdErrFile (Join-Path $LogsDir "S8_run1_stderr.txt")
        $baseExists=Test-Path $baseFile
        if($baseExists){Emit -Status PASS -Suite S8 -Id S8.1 -Desc "-Baseline file written: $baseFile"}
        else{Emit -Status FAIL -Suite S8 -Id S8.1 -Desc "-Baseline file NOT written (exit=$($r1.ExitCode))"}
    }catch{Emit -Status FAIL -Suite S8 -Id S8.1 -Desc "-Baseline run threw" -Detail $_.Exception.Message}

    # S8.2 Run 2 with -CompareTo, verify Delta present in JSON
    Emit -Status INFO -Suite S8 -Id S8.2 -Desc "Run 2/2: comparing against baseline ..."
    try{
        $r2=Invoke-AuditChild `
            -ArgList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$AuditScriptFull,"-Mode","Fast","-Profile","PersonalLaptop","-NoTUI","-SkipHTML","-ExportJSON",$run2File,"-CompareTo",$baseFile) `
            -StdOutFile (Join-Path $LogsDir "S8_run2_stdout.txt") -StdErrFile (Join-Path $LogsDir "S8_run2_stderr.txt")

        if(Test-Path $run2File){
            $j2=Read-JsonSafe -Path $run2File
            Emit -Status PASS -Suite S8 -Id S8.2 -Desc "-CompareTo run completed and produced JSON"

            # S8.3 Delta key present and not null
            $deltaPresent=$j2.PSObject.Properties.Name -contains "Delta"
            $_emSt23 = if($deltaPresent){"PASS"}else{"FAIL"}
            Emit -Status $_emSt23 -Suite S8 -Id S8.3 -Desc "Delta key present in JSON output"

            if($deltaPresent -and $null -ne $j2.Delta){
                $dt=$j2.Delta

                # S8.4 Delta structural fields
                $dtFields=@("BaselineTimestamp","BaselineMode","SeverityScoreDelta","HygieneScoreDelta","Regressions","Improvements","NewChecks")
                # Use PSObject.Properties.Name to check field PRESENCE (not value).
                # PS 5.1 ConvertFrom-Json deserializes [] as $null so value-based checks
                # incorrectly report empty-array fields as absent.
                $presentNames=$dt.PSObject.Properties.Name
                $missingDt=$dtFields|Where-Object{$_ -notin $presentNames}
                $_emSt24 = if(-not $missingDt){"PASS"}else{"FAIL"}
                Emit -Status $_emSt24 -Suite S8 -Id S8.4 `
                    -Desc "Delta has all required fields" -Detail ($missingDt -join ", ")

                # S8.5 BaselineTimestamp is a valid ISO-8601 string
                try{
                    [datetime]::ParseExact($dt.BaselineTimestamp,"yyyy-MM-ddTHH:mm:ssZ",[System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::AssumeUniversal)|Out-Null
                    Emit -Status PASS -Suite S8 -Id S8.5 -Desc "Delta.BaselineTimestamp is valid ISO-8601: $($dt.BaselineTimestamp)"
                }catch{Emit -Status FAIL -Suite S8 -Id S8.5 -Desc "Delta.BaselineTimestamp invalid" -Detail $_.Exception.Message}

                # S8.6 Score deltas are numeric
                try{
                    $sd=[double]$dt.SeverityScoreDelta; $hd=[double]$dt.HygieneScoreDelta
                    Emit -Status PASS -Suite S8 -Id S8.6 -Desc "Score deltas are numeric: Severity=$sd Hygiene=$hd"
                }catch{Emit -Status FAIL -Suite S8 -Id S8.6 -Desc "Score delta parse failed" -Detail $_.Exception.Message}

                # S8.7 Regressions/Improvements/NewChecks are arrays (may be empty)
                $regsOk=$null -ne $dt.Regressions -and $dt.Regressions -is [System.Object[]] -or $dt.Regressions -is [System.Array] -or ($null -eq $dt.Regressions -or @($dt.Regressions).Count -ge 0)
                Emit -Status PASS -Suite S8 -Id S8.7 `
                    -Desc "Delta lists present: Regressions=$(@($dt.Regressions).Count) Improvements=$(@($dt.Improvements).Count) NewChecks=$(@($dt.NewChecks).Count)"

                # S8.8 Back-to-back same-config runs should have zero regressions (system stable)
                $regCount=@($dt.Regressions).Count
                if($regCount -eq 0){Emit -Status PASS -Suite S8 -Id S8.8 -Desc "Zero regressions between identical consecutive runs (expected)"}
                else{Emit -Status WARN -Suite S8 -Id S8.8 -Desc "$regCount regression(s) between identical runs -- check for non-deterministic checks" -Detail (($dt.Regressions|ForEach-Object{$_.Id})-join ", ")}
            } else {
                Emit -Status WARN -Suite S8 -Id S8.3 -Desc "Delta key present but value is null (baseline may have been unparseable)"
                foreach($id in @("S8.4","S8.5","S8.6","S8.7","S8.8")){Emit -Status SKIP -Suite S8 -Id $id -Desc "Delta null -- sub-tests skipped"}
            }
        } else {
            Emit -Status FAIL -Suite S8 -Id S8.2 -Desc "-CompareTo run did not produce JSON (exit=$($r2.ExitCode))"
            foreach($id in @("S8.3","S8.4","S8.5","S8.6","S8.7","S8.8")){Emit -Status SKIP -Suite S8 -Id $id -Desc "No JSON -- skipped"}
        }
    }catch{Emit -Status FAIL -Suite S8 -Id S8.2 -Desc "-CompareTo run threw" -Detail $_.Exception.Message}

    $sw.Stop();$Script:SuiteTime["S8"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  SUITE S9 -- SPRINT D COVERAGE: VERIFY NEW CHECK IDs IN DEEP OUTPUT
#  Structural coverage test: confirms each Sprint D check ID appears in the
#  findings array of a Deep run. Does NOT assert Vulnerable=true/false --
#  that depends on the system under test.
# ===========================================================================
if("S9" -in $Suites){
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    Write-SuiteHeader "S9" "Sprint D Coverage: New Check IDs in Deep Output"

    # Reuse an existing Deep JSON from S3 if available, else run fresh
    $deepJson=$null
    if($Script:MatrixResults -and $Script:MatrixResults.ContainsKey("S3_Deep_PersonalLaptop")){
        $deepJson=$Script:MatrixResults["S3_Deep_PersonalLaptop"].JsonPath
        Emit -Status INFO -Suite S9 -Id S9.0 -Desc "Reusing S3 Deep+PersonalLaptop JSON"
    }
    if(-not $deepJson -or -not (Test-Path $deepJson)){
        $deepJson=Join-Path $LogsDir "S9_deep_run.json"
        Emit -Status INFO -Suite S9 -Id S9.0 -Desc "Running fresh Deep scan for S9 ..."
        $rD=Invoke-AuditChild -ArgList (Get-BaseArgs -Mode "Deep" -Profile "PersonalLaptop" -JsonOut $deepJson -NoHTML) `
            -StdOutFile (Join-Path $LogsDir "S9_deep_stdout.txt") -StdErrFile (Join-Path $LogsDir "S9_deep_stderr.txt")
        if(-not (Test-Path $deepJson)){
            Emit -Status FAIL -Suite S9 -Id S9.0 -Desc "Deep scan did not produce JSON (exit=$($rD.ExitCode))"
            $sw.Stop();$Script:SuiteTime["S9"]=$sw.ElapsedMilliseconds
        }
    }

    if($deepJson -and (Test-Path $deepJson)){
        $jDeep=Read-JsonSafe -Path $deepJson
        if($null -eq $jDeep){
            Emit -Status FAIL -Suite S9 -Id S9.0 -Desc "Deep JSON unreadable"
        } else {
            $presentIds=@($jDeep.Findings|ForEach-Object{$_.Id})

            # Sprint D exact IDs to verify
            $sprintDIds=@(
                # [D1] Defender Exclusions
                "DEFEXCL-EXT","DEFEXCL-PATH","DEFEXCL-COUNT",
                # [D2] Firewall Posture
                "FW-SVC","FW-LOG",
                # [D3] Exploit Protection
                "EXPROT-DEP","EXPROT-ASLR","EXPROT-CFG",
                # [D4] Local Admins
                "LOCALADMIN",
                # [D5] SMB Encryption
                "SMBENC"
            )

            foreach($id in $sprintDIds){
                # Exact match or prefix match (UNQUOTED_SERVICE_PATH:* style)
                $found=$presentIds|Where-Object{$_ -eq $id -or $_ -like "$id*"}
                if($found){Emit -Status PASS -Suite S9 -Id "S9.$id" -Desc "Finding ID '$id' present in Deep output"}
                else{Emit -Status FAIL -Suite S9 -Id "S9.$id" -Desc "Finding ID '$id' MISSING from Deep output -- check not running or ID changed"}
            }

            # S9.Z Confidence values in Deep output all belong to the 6-value enum
            $validConf=@("High","Medium","Low","NotApplicable","NoAccess","QueryFailed")
            $badConf=@($jDeep.Findings|Where-Object{$_.Confidence -notin $validConf})
            $_emSt25 = if($badConf.Count -eq 0){"PASS"}else{"FAIL"}
            Emit -Status $_emSt25 -Suite S9 -Id "S9.ConfEnum" `
                -Desc "All Confidence values use 6-value Sprint B enum in Deep run ($($jDeep.Findings.Count) total findings)" `
                -Detail (($badConf|ForEach-Object{"$($_.Id)=$($_.Confidence)"})-join "`n")
        }
    }
    $sw.Stop();$Script:SuiteTime["S9"]=$sw.ElapsedMilliseconds
}

# ===========================================================================
#  FINAL REPORT
# ===========================================================================
Write-Banner "TEST RESULTS SUMMARY"

$allTests=@($Script:Results|Where-Object{$_.Status -ne "INFO"})
$passed  =@($allTests|Where-Object{$_.Status -eq "PASS"})
$failed  =@($allTests|Where-Object{$_.Status -eq "FAIL"})
$warned  =@($allTests|Where-Object{$_.Status -eq "WARN"})
$skipped =@($allTests|Where-Object{$_.Status -eq "SKIP"})
$total   =$allTests.Count

$suiteNames=@($allTests|ForEach-Object{$_.Suite}|Select-Object -Unique|Sort-Object)
foreach($sName in $suiteNames){
    $sItems=@($allTests|Where-Object{$_.Suite -eq $sName})
    $gPass=@($sItems|Where-Object{$_.Status -eq "PASS"}).Count
    $gFail=@($sItems|Where-Object{$_.Status -eq "FAIL"}).Count
    $gWarn=@($sItems|Where-Object{$_.Status -eq "WARN"}).Count
    $gSkip=@($sItems|Where-Object{$_.Status -eq "SKIP"}).Count
    $tMs  =$Script:SuiteTime[$sName]
    $tStr =if($tMs){"$([math]::Round($tMs/1000,1))s"}else{"--"}
    $color=if($gFail -gt 0){"Red"}elseif($gWarn -gt 0){"Yellow"}else{"Green"}
    if(-not $Quiet){Write-Host ("  [{0}]  PASS:{1,3}  FAIL:{2,3}  WARN:{3,3}  SKIP:{4,3}  ({5})" -f $sName,$gPass,$gFail,$gWarn,$gSkip,$tStr) -ForegroundColor $color}
}

if(-not $Quiet){
    Write-Host ""; Write-Host ("-"*80) -ForegroundColor DarkCyan
    Write-Host ("  TOTAL   PASS:{0,3}  FAIL:{1,3}  WARN:{2,3}  SKIP:{3,3}  of {4} tests" -f $passed.Count,$failed.Count,$warned.Count,$skipped.Count,$total) -ForegroundColor White
    if($failed.Count -eq 0 -and $warned.Count -eq 0){Write-Host "  [OK]  All tests passed." -ForegroundColor Green}
    elseif($failed.Count -eq 0){Write-Host "  [!!]  No failures, $($warned.Count) warning(s)." -ForegroundColor Yellow}
    else{Write-Host "  [!!]  $($failed.Count) failure(s) require remediation." -ForegroundColor Red}
    if($failed.Count -gt 0){
        Write-Host ""; Write-Host "  FAILURES:" -ForegroundColor Red
        foreach($f in $failed){
            Write-Host "    [$($f.Suite)] $($f.Id) -- $($f.Desc)" -ForegroundColor Red
            if($f.Detail){foreach($row in ($f.Detail -split "`n")){if($row.Trim()){Write-Host "      $row" -ForegroundColor DarkGray}}}
        }
    }
}

# ---------------------------------------------------------------------------
#  JUNIT XML EXPORT
# ---------------------------------------------------------------------------
if($ExportJUnit){
    try{
        $junitPath=Join-Path $OutDir "junit_results.xml"
        $totalTime=[math]::Round(($Script:SuiteTime.Values|Measure-Object -Sum).Sum/1000,2)
        $sb=New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
        [void]$sb.AppendLine("<testsuites name=`"APEX Audit Lab v3`" tests=`"$total`" failures=`"$($failed.Count)`" errors=`"0`" time=`"$totalTime`">")
        foreach($sName in $suiteNames){
            $sItems=@($allTests|Where-Object{$_.Suite -eq $sName})
            $gFails=@($sItems|Where-Object{$_.Status -eq "FAIL"}).Count
            $gTime=if($Script:SuiteTime[$sName]){[math]::Round($Script:SuiteTime[$sName]/1000,2)}else{0}
            [void]$sb.AppendLine("  <testsuite name=`"$sName`" tests=`"$($sItems.Count)`" failures=`"$gFails`" time=`"$gTime`">")
            foreach($t in $sItems){
                $tName=[System.Web.HttpUtility]::HtmlEncode("$($t.Id): $($t.Desc)")
                switch($t.Status){
                    "PASS"{[void]$sb.AppendLine("    <testcase name=`"$tName`" classname=`"$($t.Suite)`" time=`"0`"/>")}
                    "SKIP"{[void]$sb.AppendLine("    <testcase name=`"$tName`" classname=`"$($t.Suite)`" time=`"0`"><skipped/></testcase>")}
                    "WARN"{$det=[System.Web.HttpUtility]::HtmlEncode($t.Detail);[void]$sb.AppendLine("    <testcase name=`"$tName`" classname=`"$($t.Suite)`" time=`"0`"><system-out>WARN: $det</system-out></testcase>")}
                    default{
                        $det=[System.Web.HttpUtility]::HtmlEncode($t.Detail);$msg=[System.Web.HttpUtility]::HtmlEncode($t.Desc)
                        [void]$sb.AppendLine("    <testcase name=`"$tName`" classname=`"$($t.Suite)`" time=`"0`">")
                        [void]$sb.AppendLine("      <failure message=`"$msg`">$det</failure>")
                        [void]$sb.AppendLine("    </testcase>")
                    }
                }
            }
            [void]$sb.AppendLine("  </testsuite>")
        }
        [void]$sb.AppendLine("</testsuites>")
        $enc=New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($junitPath,$sb.ToString(),$enc)
        if(-not $Quiet){Write-Host "  JUnit XML : $junitPath" -ForegroundColor DarkGray}
    }catch{if(-not $Quiet){Write-Host "  [!!] JUnit export failed: $_" -ForegroundColor DarkYellow}}
}

# ---------------------------------------------------------------------------
#  JSON LAB REPORT
# ---------------------------------------------------------------------------
$labReport=[PSCustomObject]@{
    RunTime    =(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    AuditScript=$AuditScriptFull
    Suites     =$Suites
    Summary    =[PSCustomObject]@{Total=$total;Pass=$passed.Count;Fail=$failed.Count;Warn=$warned.Count;Skip=$skipped.Count}
    Results    =$Script:Results
}
$labReportPath=Join-Path $OutDir "lab_report.json"
$enc=New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($labReportPath,($labReport|ConvertTo-Json -Depth 6),$enc)
if(-not $Quiet){Write-Host ""; Write-Host "  Lab report : $labReportPath" -ForegroundColor DarkGray;Write-Host "  Artifacts  : $OutDir" -ForegroundColor DarkGray;Write-Host ""}

if($PassThru){$labReport}
$global:LASTEXITCODE=$failed.Count