#Requires -Version 5.1
# =============================================================================
#  APEX Audit Engine -- WebUI.ps1
#  HttpListener-based local web server serving an interactive SPA dashboard.
#  Dot-sourced lazily by Windows_Audit.ps1 when -WebUI is specified.
#  Security: ONLY binds to localhost. Never binds to 0.0.0.0 or +.
# =============================================================================

function Find-AvailablePort {
    <#
    .SYNOPSIS Finds an available TCP port in the range 8600-8699. #>
    param([int]$Start = 8600, [int]$End = 8699)
    for ($p = $Start; $p -le $End; $p++) {
        try {
            $tl = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
            $tl.Start()
            $tl.Stop()
            return $p
        } catch { }
    }
    return 8600   # fallback — HttpListener will fail descriptively if taken
}

function Send-JsonResponse {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','')]
    param(
        [System.Net.HttpListenerResponse] $Response,
        [object] $Data,
        [int]    $StatusCode = 200
    )
    try {
        $json   = ($Data | ConvertTo-Json -Depth 8 -Compress)
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
        $Response.StatusCode    = $StatusCode
        $Response.ContentType   = 'application/json; charset=utf-8'
        $Response.ContentLength64 = $buffer.LongLength
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    } catch { }
    finally  { try { $Response.OutputStream.Close() } catch { } }
}

function Send-HtmlResponse {
    param(
        [System.Net.HttpListenerResponse] $Response,
        [string] $Html
    )
    try {
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($Html)
        $Response.StatusCode    = 200
        $Response.ContentType   = 'text/html; charset=utf-8'
        $Response.ContentLength64 = $buffer.LongLength
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    } catch { }
    finally  { try { $Response.OutputStream.Close() } catch { } }
}

function Get-AuditApiData {
    param(
        [PSCustomObject] $Context,
        [PSCustomObject] $Scores,
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [PSCustomObject] $Delta,
        [string]         $BackupBaseDir
    )
    # Refresh scores from current findings state
    $live = Measure-AuditScore -Findings $Findings
    $backups = @()
    if ($BackupBaseDir -and (Test-Path $BackupBaseDir -ErrorAction SilentlyContinue)) {
        $backups = @(Get-ChildItem -Path $BackupBaseDir -Directory -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 10 | ForEach-Object {
                $files = @(Get-ChildItem $_.FullName -File -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name)
                [PSCustomObject]@{
                    Path    = $_.FullName
                    Created = $_.LastWriteTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    Files   = $files
                }
            })
    }
    return [PSCustomObject]@{
        context      = $Context
        scores       = $live
        findings     = @($Findings)
        delta        = $Delta
        backups      = $backups
        vulnCount    = @($Findings | Where-Object { $_.Vulnerable }).Count
        serverTime   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        version      = $Script:TOOL_VERSION
    }
}

function Invoke-WebFix {
    param(
        [System.Net.HttpListenerResponse] $Response,
        [string] $FindingId,
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [hashtable] $SafetyTiers,
        [string] $BackupBaseDir,
        [bool]   $Confirmed
    )
    $f = $Findings | Where-Object { $_.Id -eq $FindingId } | Select-Object -First 1
    if (-not $f) {
        Send-JsonResponse $Response @{ success=$false; error="Finding '$FindingId' not found" } 404
        return
    }
    if (-not $f.Vulnerable) {
        Send-JsonResponse $Response @{ success=$false; error='Finding is already resolved' } 409
        return
    }
    $tier = if ($SafetyTiers.ContainsKey($f.Id)) { $SafetyTiers[$f.Id] } else { 'CAUTION' }
    if (($tier -eq 'CAUTION' -or $tier -eq 'RISKY') -and -not $Confirmed) {
        Send-JsonResponse $Response @{ success=$false; requiresConfirm=$true; tier=$tier } 428
        return
    }
    if (-not $f.Fix -or $f.Fix -eq 'N/A') {
        Send-JsonResponse $Response @{ success=$false; error='No fix available for this finding' } 422
        return
    }

    # Backup before fix
    $backupFile = $null
    if ($BackupBaseDir) {
        $ts = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
        $backDir = Join-Path $BackupBaseDir $ts
        try { New-Item -ItemType Directory -Path $backDir -Force | Out-Null } catch { }
        $backupFile = Backup-FindingState -Finding $f -BackupDir $backDir
    }

    # Execute fix
    try {
        Invoke-Expression $f.Fix | Out-Null
        $f.Vulnerable = $false
        $f.Severity   = 'PASS'
        $f | Add-Member -NotePropertyName '_FixedAt' -NotePropertyValue `
            (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') -Force
        Send-JsonResponse $Response @{
            success    = $true
            findingId  = $FindingId
            tier       = $tier
            backupPath = $backupFile
            message    = "Fix applied successfully"
        }
    } catch {
        Send-JsonResponse $Response @{
            success   = $false
            findingId = $FindingId
            error     = $_.Exception.Message
        } 500
    }
}

function Invoke-WebUndo {
    param(
        [System.Net.HttpListenerResponse] $Response,
        [string] $FindingId,
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [string] $BackupBaseDir
    )
    $f = $Findings | Where-Object { $_.Id -eq $FindingId } | Select-Object -First 1
    if (-not $f) {
        Send-JsonResponse $Response @{ success=$false; error="Finding '$FindingId' not found" } 404
        return
    }

    # Find most recent backup containing this finding's files
    $backupFile = $null
    if ($BackupBaseDir -and (Test-Path $BackupBaseDir -ErrorAction SilentlyContinue)) {
        $backupDirs = Get-ChildItem $BackupBaseDir -Directory -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
        foreach ($bd in $backupDirs) {
            $regFile = Join-Path $bd.FullName "$($FindingId -replace '[:\\]','_').reg"
            $svcFile = Join-Path $bd.FullName "$($FindingId -replace '[:\\]','_')_svc.json"
            if (Test-Path $regFile)  { $backupFile = $regFile;  break }
            if (Test-Path $svcFile)  { $backupFile = $svcFile;  break }
        }
    }

    if (-not $backupFile) {
        Send-JsonResponse $Response @{ success=$false; error='No backup found for this finding' } 404
        return
    }

    try {
        if ($backupFile -like '*.reg') {
            Invoke-Exe 'reg.exe' @('import', $backupFile) | Out-Null
        } elseif ($backupFile -like '*_svc.json') {
            $svcState = Get-Content $backupFile -Raw | ConvertFrom-Json
            Set-Service -Name $svcState.Name -StartupType $svcState.StartType -ErrorAction SilentlyContinue
            if ($svcState.Status -eq 'Running') { Start-Service $svcState.Name -EA SilentlyContinue }
            elseif ($svcState.Status -eq 'Stopped') { Stop-Service $svcState.Name -Force -EA SilentlyContinue }
        }
        $f.Vulnerable = $true
        if ($f.Severity -eq 'PASS') {
            # Restore the severity — look up from a fresh check would be ideal; use tag if available
            $f.Severity = if ($f.PSObject.Properties['_OrigSeverity']) { $f._OrigSeverity } else { 'MEDIUM' }
        }
        Send-JsonResponse $Response @{ success=$true; findingId=$FindingId; message='Undo applied' }
    } catch {
        Send-JsonResponse $Response @{ success=$false; error=$_.Exception.Message } 500
    }
}

function Invoke-WebRescan {
    param(
        [System.Net.HttpListenerResponse] $Response,
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [string] $MapPath,
        [string] $Profile
    )
    try {
        $Findings.Clear()
        $activeChecks = @($Script:CheckManifest | Where-Object { $Mode -in $_.Modes })
        foreach ($chk in $activeChecks) {
            if ($chk.NeedsAdmin -and -not $Script:IsAdmin) { continue }
            try { & $chk.Fn } catch { }
        }
        Get-ComplianceRefs  -MapPath $MapPath
        Set-FindingRecommendations -Findings $Findings -Profile $Profile
        Send-JsonResponse $Response @{
            success      = $true
            findingCount = $Findings.Count
            vulnCount    = @($Findings | Where-Object { $_.Vulnerable }).Count
        }
    } catch {
        Send-JsonResponse $Response @{ success=$false; error=$_.Exception.Message } 500
    }
}

function Get-WebUISPA {
    param([string]$BaseUrl)
    # Inlined SPA: extends the Report.ps1 HTML with live dashboard controls.
    # Data is fetched from /api/data; UI re-renders on state changes.
    @"
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>APEX Live Dashboard</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bd:#30363d;--tx:#e6edf3;--tx2:#8b949e;
      --red:#ff7b72;--ora:#ffa657;--yel:#e3b341;--cya:#79c0ff;--grn:#56d364;--pur:#bc8cff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.5}
.topbar{position:sticky;top:0;z-index:100;background:var(--bg2);border-bottom:1px solid var(--bd);padding:10px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.dot{width:10px;height:10px;border-radius:50%;background:var(--grn);flex-shrink:0}
.dot.err{background:var(--red)}.logo{font-weight:700;color:var(--cya);font-size:15px}
.scores-mini{display:flex;gap:14px;margin-left:auto}
.sm{text-align:center;font-size:11px;color:var(--tx2)}.sm strong{display:block;font-size:18px;font-weight:700}
.sm.ok strong{color:var(--grn)}.sm.warn strong{color:var(--yel)}.sm.bad strong{color:var(--red)}
.topbtn{background:var(--bg3);border:1px solid var(--bd);color:var(--tx);padding:5px 12px;border-radius:6px;cursor:pointer;font-size:13px}
.topbtn:hover{border-color:var(--cya);color:var(--cya)}.topbtn.stop{border-color:var(--red);color:var(--red)}
.topbtn:disabled{opacity:.4;cursor:default}
.wrap{max-width:1160px;margin:0 auto;padding:16px}
.card{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;margin-bottom:12px;overflow:hidden}
.sec-hdr{display:flex;align-items:center;gap:10px;padding:12px 18px;cursor:pointer;user-select:none}
.sec-hdr:hover{background:var(--bg3)}.chev{transition:transform .2s;font-size:11px;color:var(--tx2)}
.sec.open .chev{transform:rotate(90deg)}.sec-body{display:none;padding:0 18px 14px}
.sec.open .sec-body{display:block}
.badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;font-family:monospace;margin-right:4px}
.CRITICAL{background:#3d0a0a;color:var(--red);border:1px solid #7a1414}
.HIGH{background:#3d2200;color:var(--ora);border:1px solid #7a4400}
.MEDIUM{background:#3d3300;color:var(--yel);border:1px solid #7a6600}
.LOW{background:#003d4d;color:var(--cya);border:1px solid #006680}
.PASS{background:#0d3320;color:var(--grn);border:1px solid #1a6640}
.finding{padding:10px 0;border-bottom:1px solid var(--bg3)}
.finding:last-child{border-bottom:none}
.finding-hdr{display:flex;align-items:flex-start;gap:10px;margin-bottom:6px}
.finding-title{flex:1;font-weight:600}
.finding-meta{color:var(--tx2);font-size:12px;line-height:1.8}
.finding-meta span{color:var(--tx);font-family:monospace;font-size:11px}
.fix-cmd{background:var(--bg3);border:1px solid var(--bd);border-radius:4px;padding:6px 10px;font-family:monospace;font-size:11px;color:var(--cya);margin:6px 0;word-break:break-all}
.actions{display:flex;gap:8px;margin-top:8px}
.btn{padding:5px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;border:none}
.btn-safe{background:#0d3320;color:var(--grn);border:1px solid #1a6640}.btn-safe:hover{background:#1a4d30}
.btn-caut{background:#3d2200;color:var(--ora);border:1px solid #7a4400}.btn-caut:hover{background:#4d2d00}
.btn-risk{background:#3d0a0a;color:var(--red);border:1px solid #7a1414}.btn-risk:hover{background:#4d1010}
.btn-undo{background:var(--bg3);color:var(--tx2);border:1px solid var(--bd)}.btn-undo:hover{border-color:var(--pur);color:var(--pur)}
.btn:disabled{opacity:.4;cursor:default}
.comp{display:flex;flex-wrap:wrap;gap:3px;margin-top:5px}
.cb{padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.03em;font-family:monospace}
.cb-cis{background:#0d2233;color:var(--cya);border:1px solid #1a4060}
.cb-stig{background:#2d1a1a;color:var(--red);border:1px solid #5a2828}
.cb-nist{background:#0d2416;color:var(--grn);border:1px solid #1a4a2a}
.rec-tag{font-size:10px;padding:1px 6px;border-radius:3px;border:1px solid var(--bd);color:var(--tx2);font-family:monospace}
.rec-tag.Recommended{border-color:var(--grn);color:var(--grn)}
.toast-ctr{position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px}
.toast{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;padding:10px 16px;font-size:13px;
       max-width:320px;opacity:0;transform:translateY(20px);transition:all .3s;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}.toast.ok{border-color:var(--grn);color:var(--grn)}
.toast.err{border-color:var(--red);color:var(--red)}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;display:flex;align-items:center;justify-content:center}
.modal{background:var(--bg2);border:1px solid var(--bd);border-radius:10px;padding:24px;max-width:440px;width:90%}
.modal h3{color:var(--yel);margin-bottom:10px}.modal p{color:var(--tx2);font-size:13px;margin-bottom:14px}
.modal input{width:100%;background:var(--bg3);border:1px solid var(--bd);color:var(--tx);padding:7px 10px;border-radius:6px;margin-bottom:14px;font-size:13px}
.modal-btns{display:flex;gap:8px;justify-content:flex-end}
.tabs{display:flex;gap:0;border-bottom:1px solid var(--bd);padding:0 16px;margin-bottom:4px}
.tab{padding:10px 16px;cursor:pointer;color:var(--tx2);font-size:13px;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:var(--cya);border-bottom-color:var(--cya)}
.empty{padding:20px;text-align:center;color:var(--tx2);font-size:13px}
.summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:12px}
.scard{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;padding:10px;text-align:center}
.scard .n{font-size:24px;font-weight:700}.scard .l{font-size:11px;color:var(--tx2);margin-top:2px}
</style>
</head>
<body>
<div class="topbar">
  <div class="dot" id="dot"></div>
  <div class="logo">APEX Live Dashboard</div>
  <div id="scantime" style="color:var(--tx2);font-size:12px"></div>
  <div class="scores-mini" id="scores-mini"></div>
  <button class="topbtn" id="btn-rescan" onclick="doRescan()">&#8635; Rescan</button>
  <button class="topbtn stop" onclick="doStop()">&#9632; Stop Server</button>
</div>
<div class="toast-ctr" id="toasts"></div>
<div id="modal-bg" style="display:none" class="modal-bg"></div>
<div class="wrap">
  <div id="summary" class="summary-grid"></div>
  <div class="tabs">
    <div class="tab active" id="tab-vuln" onclick="setTab('vuln')">Vulnerabilities</div>
    <div class="tab" id="tab-all"  onclick="setTab('all')">All Findings</div>
  </div>
  <div id="app"></div>
</div>
<script>
const BASE = '$BaseUrl';
let D = null, tab = 'vuln', pollTimer = null;

function h(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function sev(s){const m={CRITICAL:'var(--red)',HIGH:'var(--ora)',MEDIUM:'var(--yel)',LOW:'var(--cya)',PASS:'var(--grn)'};return m[s]||'var(--tx)'}
function scoreClass(n){return n>=80?'ok':n>=60?'warn':'bad'}

function toast(msg,ok=true){
  const el=document.createElement('div');
  el.className='toast '+(ok?'ok':'err');
  el.textContent=msg;
  document.getElementById('toasts').appendChild(el);
  requestAnimationFrame(()=>{el.classList.add('show')});
  setTimeout(()=>{el.classList.remove('show');setTimeout(()=>el.remove(),400)},3500);
}

function setTab(t){
  tab=t;
  document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
  document.getElementById('tab-'+t).classList.add('active');
  render();
}

function renderScores(scores){
  const ss=scores.SeverityScore|0, hs=scores.HygieneScore|0;
  document.getElementById('scores-mini').innerHTML=
    '<div class="sm '+scoreClass(ss)+'"><strong>'+ss+'</strong>Severity</div>'+
    '<div class="sm '+scoreClass(hs)+'"><strong>'+hs+'</strong>Hygiene</div>';
}

function renderSummary(findings){
  const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,PASS:0};
  findings.forEach(f=>{ if(cnt[f.Severity]!==undefined) cnt[f.Severity]++; });
  const col={CRITICAL:'var(--red)',HIGH:'var(--ora)',MEDIUM:'var(--yel)',LOW:'var(--cya)',PASS:'var(--grn)'};
  document.getElementById('summary').innerHTML=
    Object.entries(cnt).map(([s,n])=>
      '<div class="scard"><div class="n" style="color:'+col[s]+'">'+n+'</div><div class="l">'+s+'</div></div>'
    ).join('');
}

function tierOf(id,safeIds){
  const safe=['WDIG','PSLOG','CMDLINE','SMBSIGS','SMBSIGC','UAC-SD','PS2ENGINE','SPOOLER-PNP','FW-LOG',
              'SID500','AUDITPOL_PROCESS_CREATION','AUDITPOL_CREDENTIAL_VALID','AUDITPOL_LOGON',
              'AUDITPOL_LOCKOUT','AUDITPOL_SPECIAL_LOGON','AUDITPOL_GROUP_MGMT','SECLOG','ASR','PUA','CFA'];
  const risky=['PPL','BLENC','BLPBA','UAC','SMB1','RDP','RDP-NLA','VBS','HVCI','CG'];
  if(risky.includes(id)) return 'RISKY';
  if(safe.includes(id)) return 'SAFE';
  return 'CAUTION';
}

function compBadges(f){
  if(!f.ComplianceRefs) return '';
  let b='<div class="comp">';
  const cr=f.ComplianceRefs;
  if(cr.CIS&&cr.CIS.length) cr.CIS.forEach(c=>{ b+='<span class="cb cb-cis">CIS '+h(c)+'</span>'; });
  if(cr.STIG&&cr.STIG.length) cr.STIG.forEach(s=>{ b+='<span class="cb cb-stig">'+h(s)+'</span>'; });
  if(cr.NIST&&cr.NIST.length) cr.NIST.forEach(n=>{ b+='<span class="cb cb-nist">NIST '+h(n)+'</span>'; });
  return b+'</div>';
}

function findingCard(f){
  const tier=tierOf(f.Id,[]);
  const fixed=!f.Vulnerable;
  const btnClass={'SAFE':'btn-safe','CAUTION':'btn-caut','RISKY':'btn-risk'}[tier]||'btn-caut';
  const recTag=f.Recommendation?'<span class="rec-tag '+h(f.Recommendation)+'">'+h(f.Recommendation)+'</span>':'';
  let actions='';
  if(f.Vulnerable){
    actions='<div class="actions"><button class="btn '+btnClass+'" onclick="doFix(\''+h(f.Id)+'\',\''+tier+'\',this)" title="Tier: '+tier+'">Fix ['+tier+']</button></div>';
  } else if(f._FixedAt){
    actions='<div class="actions"><button class="btn btn-undo" onclick="doUndo(\''+h(f.Id)+'\',this)">&#8635; Undo</button><span style="font-size:11px;color:var(--tx2);align-self:center">Fixed at '+h(f._FixedAt)+'</span></div>';
  }
  return '<div class="finding">'+
    '<div class="finding-hdr"><span class="badge '+h(f.Severity)+'">'+h(f.Severity)+'</span>'+
    '<span class="finding-title">'+h(f.CheckName)+'</span>'+recTag+'</div>'+
    '<div class="finding-meta">'+
    '<div>Observed: <span>'+h(f.Observed)+'</span></div>'+
    '<div>Expected: <span>'+h(f.Expected)+'</span></div>'+
    '<div>Source: <span>'+h(f.Source)+'</span> &nbsp; Confidence: <span>'+h(f.Confidence)+'</span></div>'+
    (f.Note?'<div>Note: <span>'+h(f.Note)+'</span></div>':'')+
    '</div>'+
    (f.Fix&&f.Fix!=='N/A'?'<div class="fix-cmd">'+h(f.Fix)+'</div>':'')+
    compBadges(f)+
    actions+
  '</div>';
}

function render(){
  if(!D){document.getElementById('app').innerHTML='<div class="empty">Connecting to APEX server...</div>';return;}
  const findings=D.findings||[];
  const show=tab==='vuln'?findings.filter(f=>f.Vulnerable||f._FixedAt):findings;
  if(!show.length){
    document.getElementById('app').innerHTML='<div class="empty">'+(tab==='vuln'?'No vulnerabilities found.':'No findings.')+'</div>';
    return;
  }
  // Group by category
  const groups={};
  show.forEach(f=>{const c=f.Category||'Other';(groups[c]=groups[c]||[]).push(f);});
  let html='';
  for(const [cat,fs] of Object.entries(groups)){
    const hasVuln=fs.some(f=>f.Vulnerable);
    html+='<div class="card sec'+(hasVuln?' open':'')+'">'+
      '<div class="sec-hdr" onclick="this.closest(\'.sec\').classList.toggle(\'open\')">'+
      '<span class="chev">&#9654;</span>'+
      '<strong>'+h(cat)+'</strong>'+
      '<span style="margin-left:auto;font-size:12px;color:var(--tx2)">'+fs.length+' finding'+(fs.length===1?'':'s')+'</span>'+
      '</div>'+
      '<div class="sec-body">'+fs.map(findingCard).join('')+'</div>'+
    '</div>';
  }
  document.getElementById('app').innerHTML=html;
}

async function poll(){
  try{
    const r=await fetch(BASE+'/api/data',{signal:AbortSignal.timeout(5000)});
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    const changed=JSON.stringify(d)!==JSON.stringify(D);
    D=d;
    document.getElementById('dot').className='dot';
    document.getElementById('scantime').textContent='Last scan: '+(D.context&&D.context.TimestampUTC||'');
    renderScores(D.scores||{SeverityScore:0,HygieneScore:0});
    renderSummary(D.findings||[]);
    if(changed) render();
  }catch(e){
    document.getElementById('dot').className='dot err';
  }
}

async function doRescan(){
  const btn=document.getElementById('btn-rescan');
  btn.disabled=true; btn.textContent='Scanning...';
  try{
    const r=await fetch(BASE+'/api/rescan',{method:'POST'});
    const d=await r.json();
    if(d.success) toast('Rescan complete: '+d.vulnCount+' vulnerabilities');
    else toast('Rescan failed: '+d.error,false);
  }catch(e){toast('Rescan error: '+e.message,false);}
  btn.disabled=false; btn.textContent='⟳ Rescan';
  await poll();
}

async function doStop(){
  try{ await fetch(BASE+'/api/shutdown',{method:'POST'}); }catch(e){}
  clearInterval(pollTimer);
  document.getElementById('dot').className='dot err';
  toast('Server stopped. You can close this tab.',true);
}

function showModal(html, onConfirm){
  const bg=document.getElementById('modal-bg');
  bg.innerHTML='<div class="modal">'+html+'</div>';
  bg.style.display='flex';
  bg.onclick=e=>{ if(e.target===bg) bg.style.display='none'; };
  window._modalConfirm=async(val)=>{ bg.style.display='none'; await onConfirm(val); };
}

async function doFix(id, tier, btn){
  if(tier==='SAFE'){
    await applyFix(id, true, btn);
  } else if(tier==='CAUTION'){
    showModal(
      '<h3>Confirm Fix</h3><p>This fix may affect legacy devices or network connectivity. Proceed?</p>'+
      '<div class="modal-btns"><button class="btn btn-undo" onclick="document.getElementById(\'modal-bg\').style.display=\'none\'">Cancel</button>'+
      '<button class="btn btn-caut" onclick="_modalConfirm(true)">Apply</button></div>',
      async()=>applyFix(id, true, btn)
    );
  } else {
    showModal(
      '<h3 style="color:var(--red)">&#9888; RISKY Fix</h3>'+
      '<p>This fix may require a reboot or make irreversible system changes. Type the finding ID to confirm:</p>'+
      '<input id="risky-confirm" placeholder="'+id+'" autocomplete="off">'+
      '<div class="modal-btns"><button class="btn btn-undo" onclick="document.getElementById(\'modal-bg\').style.display=\'none\'">Cancel</button>'+
      '<button class="btn btn-risk" onclick="_modalConfirm(document.getElementById(\'risky-confirm\').value)">Apply</button></div>',
      async(val)=>{ if(val===id) await applyFix(id,true,btn); else toast('ID mismatch — fix not applied.',false); }
    );
  }
}

async function applyFix(id, confirmed, btn){
  if(btn) btn.disabled=true;
  try{
    const r=await fetch(BASE+'/api/fix/'+encodeURIComponent(id),{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({confirm:confirmed})
    });
    const d=await r.json();
    if(d.success){ toast(id+' fixed successfully'); await poll(); }
    else toast('Fix failed: '+(d.error||'unknown error'),false);
  }catch(e){ toast('Error: '+e.message,false); if(btn) btn.disabled=false; }
}

async function doUndo(id, btn){
  if(btn) btn.disabled=true;
  try{
    const r=await fetch(BASE+'/api/undo/'+encodeURIComponent(id),{method:'POST'});
    const d=await r.json();
    if(d.success){ toast(id+' undone'); await poll(); }
    else toast('Undo failed: '+(d.error||'unknown error'),false);
  }catch(e){ toast('Error: '+e.message,false); if(btn) btn.disabled=false; }
}

poll();
pollTimer=setInterval(poll,2000);
</script>
</body></html>
"@
}

function Start-AuditWebUI {
    <#
    .SYNOPSIS
        Starts the localhost-only HttpListener web dashboard.
        Blocking call — exits when user closes the server or hits Ctrl+C.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','')]
    param(
        [PSCustomObject] $Context,
        [PSCustomObject] $Scores,
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [PSCustomObject] $Delta,
        [hashtable]      $SafetyTiers,
        [string]         $BackupBaseDir = ''
    )

    $port    = Find-AvailablePort
    $baseUrl = "http://localhost:$port"
    $mapFile = Join-Path $Script:RootDir 'compliance_map.json'

    $listener = $null
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("$baseUrl/")   # ONLY localhost — never + or *
        $listener.Start()
    } catch {
        Write-Warning "APEX WebUI: Could not start HTTP listener on port $port -- $_"
        return
    }

    Write-Host ''
    Write-Host "  [*] APEX Web Dashboard running at $baseUrl" -ForegroundColor Cyan
    Write-Host '      Opening in default browser...' -ForegroundColor DarkCyan
    Write-Host '      Press Ctrl+C or click [Stop Server] in the browser to exit.' -ForegroundColor DarkGray
    Write-Host ''

    try { Start-Process $baseUrl } catch { }

    $spa = Get-WebUISPA -BaseUrl $baseUrl

    try {
        while ($listener.IsListening) {
            $ctx = $null
            try { $ctx = $listener.GetContext() } catch { break }

            $req  = $ctx.Request
            $resp = $ctx.Response
            $path = $req.Url.LocalPath.TrimEnd('/')
            $meth = $req.HttpMethod.ToUpper()

            # Read request body for POST endpoints
            $body = $null
            if ($meth -eq 'POST' -and $req.HasEntityBody) {
                try {
                    $sr   = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                    $body = $sr.ReadToEnd() | ConvertFrom-Json
                } catch { $body = $null }
            }

            switch -Regex ($path) {
                '^$|^/app$' {
                    Send-HtmlResponse $resp $spa
                }
                '^/api/data$' {
                    $data = Get-AuditApiData -Context $Context -Scores $Scores `
                                -Findings $Findings -Delta $Delta -BackupBaseDir $BackupBaseDir
                    Send-JsonResponse $resp $data
                }
                '^/api/fix/(.+)$' {
                    $fid       = [System.Uri]::UnescapeDataString($Matches[1])
                    $confirmed = if ($body -and $null -ne $body.confirm) { [bool]$body.confirm } else { $false }
                    Invoke-WebFix -Response $resp -FindingId $fid -Findings $Findings `
                        -SafetyTiers $SafetyTiers -BackupBaseDir $BackupBaseDir -Confirmed $confirmed
                }
                '^/api/undo/(.+)$' {
                    $fid = [System.Uri]::UnescapeDataString($Matches[1])
                    Invoke-WebUndo -Response $resp -FindingId $fid `
                        -Findings $Findings -BackupBaseDir $BackupBaseDir
                }
                '^/api/rescan$' {
                    Invoke-WebRescan -Response $resp -Findings $Findings `
                        -MapPath $mapFile -Profile $Profile
                }
                '^/api/backups$' {
                    $data = Get-AuditApiData -Context $Context -Scores $Scores `
                                -Findings $Findings -Delta $Delta -BackupBaseDir $BackupBaseDir
                    Send-JsonResponse $resp @{ backups = $data.backups }
                }
                '^/api/shutdown$' {
                    Send-JsonResponse $resp @{ success=$true; message='Server stopping' }
                    $listener.Stop()
                    break
                }
                default {
                    Send-JsonResponse $resp @{ error='Not found' } 404
                }
            }
        }
    } catch [System.Net.HttpListenerException] {
        # Listener stopped (Ctrl+C or /api/shutdown) — normal exit
    } catch {
        Write-Warning "APEX WebUI error: $($_.Exception.Message)"
    } finally {
        try { $listener.Close() } catch { }
        Write-Host ''
        Write-Host '  [*] APEX Web Dashboard stopped.' -ForegroundColor DarkCyan
    }
}
