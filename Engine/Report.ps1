#Requires -Version 5.1
# =============================================================================
#  APEX Audit Engine -- Report.ps1
#  TUI console report, self-contained HTML report, export-path resolution.
#  Dot-sourced by Windows_Audit.ps1 after Engine/Core.ps1.
# =============================================================================

# ---------------------------------------------------------------------------
#  TUI REPORT
# ---------------------------------------------------------------------------
function Write-TUIReport {
    param(
        [PSCustomObject] $Ctx,
        [PSCustomObject] $Scores,
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [PSCustomObject] $Delta = $null
    )
    $W = 110
    Write-TUI ''
    Write-TUI ('+' + ('-' * ($W - 2)) + '+') -Color DarkCyan
    $title = 'APEX ZERO-TRUST ENTERPRISE AUDIT REPORT'
    $pad   = [int](($W - 2 - $title.Length) / 2)
    Write-TUI ('| ' + (' ' * $pad) + $title + (' ' * ($W - 2 - $pad - $title.Length)) + ' |') -Color Cyan
    Write-TUI ('+' + ('-' * ($W - 2)) + '+') -Color DarkCyan
    Write-TUI ''
    Write-TUI '  >> CONTEXT'
    Write-TUI "    Host   : $($Ctx.Hostname) | $($Ctx.OSCaption) (Build $($Ctx.OSBuild))"
    Write-TUI "    Mode   : $($Ctx.Mode) | Profile: $($Ctx.Profile) | $($Ctx.TimestampUTC) UTC"
    Write-TUI ''
    Write-TUI '  >> RISK METRICS'
    $sc = if ($Scores.SeverityScore -ge 80) { 'Green' } elseif ($Scores.SeverityScore -ge 60) { 'Yellow' } else { 'Red' }
    $hc = if ($Scores.HygieneScore  -ge 80) { 'Green' } elseif ($Scores.HygieneScore  -ge 60) { 'Yellow' } else { 'Red' }
    Write-TUI "    Severity Score : $($Scores.SeverityScore) / 100  (Critical/High)" -Color $sc
    Write-TUI "    Hygiene  Score : $($Scores.HygieneScore)  / 100  (Medium/Low)"    -Color $hc
    if ($Delta) {
        $signFn = { param([double]$v); if ($v -ge 0) { "+$v" } else { "$v" } }
        $sc2    = if ($Delta.SeverityScoreDelta -ge 0) { 'Green' } else { 'Red' }
        Write-TUI "    vs Baseline    : Severity $(& $signFn $Delta.SeverityScoreDelta)  Hygiene $(& $signFn $Delta.HygieneScoreDelta)  (baseline: $($Delta.BaselineTimestamp))" -Color $sc2
        Write-TUI "    Regressions    : $(@($Delta.Regressions).Count)  Improvements: $(@($Delta.Improvements).Count)  New checks: $(@($Delta.NewChecks).Count)"
    }
    Write-TUI ''
    $bySev = @{}
    foreach ($s in @('CRITICAL','HIGH','MEDIUM','LOW','PASS')) { $bySev[$s] = 0 }
    foreach ($f in $Findings) { $bySev[$f.Severity]++ }
    if ($bySev.CRITICAL -gt 0) { Write-TUI "    CRITICAL : $($bySev.CRITICAL)" -Color Red }
    if ($bySev.HIGH     -gt 0) { Write-TUI "    HIGH     : $($bySev.HIGH)"     -Color DarkYellow }
    if ($bySev.MEDIUM   -gt 0) { Write-TUI "    MEDIUM   : $($bySev.MEDIUM)"   -Color Yellow }
    if ($bySev.LOW      -gt 0) { Write-TUI "    LOW      : $($bySev.LOW)"      -Color Cyan }
    Write-TUI "    SECURE   : $(@($Findings | Where-Object { -not $_.Vulnerable }).Count) passed" -Color Green
    Write-TUILine
    Write-TUI '  >> FINDINGS'
    foreach ($sev in @('CRITICAL','HIGH','MEDIUM','LOW')) {
        foreach ($f in ($Findings | Where-Object { $_.Vulnerable -and $_.Severity -eq $sev })) {
            Write-TUIFinding -F $f
        }
    }
}

# ---------------------------------------------------------------------------
#  HTML REPORT
# ---------------------------------------------------------------------------
function Export-HTMLReport {
    param(
        [string]         $Path,
        [PSCustomObject] $Ctx,
        [PSCustomObject] $Scores,
        [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [PSCustomObject] $Delta = $null
    )
    $dataObj = [PSCustomObject]@{ context=$Ctx; scores=$Scores; findings=@($Findings); delta=$Delta }
    $json    = ($dataObj | ConvertTo-Json -Depth 8 -Compress) -replace '</script>','<\/script>'
    $tpl = @'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>APEX Audit Report</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bd:#30363d;--tx:#e6edf3;--tx2:#8b949e;--red:#ff7b72;--ora:#ffa657;--yel:#e3b341;--cya:#79c0ff;--grn:#56d364;--pur:#bc8cff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.5;padding:16px}
.wrap{max-width:1160px;margin:0 auto}.card{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;margin-bottom:12px;overflow:hidden}
.hdr{padding:18px 22px}.hdr h1{font-size:17px;font-weight:700;color:var(--cya);margin-bottom:6px}.meta{display:flex;flex-wrap:wrap;gap:14px;color:var(--tx2);font-size:12px}
.scores{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.sc{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;padding:16px 20px}
.sc .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--tx2);margin-bottom:6px}
.sc .val{font-size:38px;font-weight:700;line-height:1}.sc .bar{height:5px;background:var(--bg3);border-radius:3px;margin:10px 0 4px}
.sc .fill{height:100%;border-radius:3px;transition:width .5s}.sc .sub{font-size:11px;color:var(--tx2)}.sc .delta{font-size:12px;margin-top:4px;font-weight:600}
.tabs{display:flex;gap:8px;margin-bottom:12px}
.tab{padding:6px 15px;border-radius:6px;border:1px solid var(--bd);background:transparent;color:var(--tx2);cursor:pointer;font-size:13px;font-weight:500;transition:all .15s}
.tab.on{background:var(--cya);color:#0d1117;border-color:var(--cya)}.tab:hover:not(.on){background:var(--bg3);color:var(--tx)}.tab.hidden{display:none}
.sumgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;padding:14px}
.stat{text-align:center;padding:10px 6px;background:var(--bg3);border-radius:6px}.stat .n{font-size:26px;font-weight:700}.stat .l{font-size:10px;color:var(--tx2);margin-top:2px;text-transform:uppercase}
.n-C{color:var(--red)}.n-H{color:var(--ora)}.n-M{color:var(--yel)}.n-L{color:var(--cya)}.n-P{color:var(--grn)}
.sec{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;margin-bottom:8px;overflow:hidden}
.sh{padding:11px 16px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;user-select:none}.sh:hover{background:var(--bg3)}
.st{font-weight:600;font-size:13px;display:flex;align-items:center;gap:8px}.sc2{font-size:11px;color:var(--tx2);font-weight:400}
.cv{color:var(--tx2);font-size:9px;transition:transform .2s}.sec.open .cv{transform:rotate(90deg)}
.sb{display:none;border-top:1px solid var(--bd)}.sec.open .sb{display:block}
.fi{padding:11px 16px;border-bottom:1px solid var(--bd)}.fi:last-child{border-bottom:none}
.fih{display:flex;align-items:flex-start;gap:9px;margin-bottom:3px}
.sv{padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.04em;white-space:nowrap;flex-shrink:0}
.sv-C{background:#3d1a1a;color:var(--red);border:1px solid #6d2222}.sv-H{background:#2d1f0a;color:var(--ora);border:1px solid #5d3a0e}
.sv-M{background:#2d260a;color:var(--yel);border:1px solid #5a4a10}.sv-L{background:#0d2233;color:var(--cya);border:1px solid #1a4060}
.sv-P{background:#0d2416;color:var(--grn);border:1px solid #1a4a2a}
.fn{font-weight:500;font-size:13px}.fhum{color:var(--tx2);font-size:12px;margin-top:3px;line-height:1.45}
.ffix{margin-top:6px;font-size:11px;background:var(--bg3);border-left:3px solid var(--cya);padding:4px 9px;border-radius:0 4px 4px 0;color:var(--tx2)}
.ffix code{color:var(--cya);font-family:"SFMono-Regular",Consolas,monospace;font-size:10px}
.trow{display:grid;grid-template-columns:90px 1fr;gap:6px;font-size:11px;margin-top:4px}.trow+.trow{margin-top:2px}
.tl{color:var(--tx2);font-weight:600;font-size:10px;text-transform:uppercase;padding-top:1px}.tv{color:var(--tx);word-break:break-word}
.cf{font-size:10px;margin-left:auto;flex-shrink:0;padding:1px 5px;border-radius:3px}
.cf-High{color:var(--grn)}.cf-Medium{color:var(--yel)}.cf-Low,.cf-NotApplicable{color:var(--tx2);opacity:.6}
.cf-NoAccess{color:var(--ora)}.cf-QueryFailed{color:var(--red)}
.comp{display:flex;flex-wrap:wrap;gap:3px;margin-top:5px}
.cb{padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.03em;font-family:"SFMono-Regular",Consolas,monospace}
.cb-cis{background:#0d2233;color:#79c0ff;border:1px solid #1a4060}
.cb-stig{background:#2d1a1a;color:#ff7b72;border:1px solid #5a2828}
.cb-nist{background:#0d2416;color:#56d364;border:1px solid #1a4a2a}
.delta-banner{padding:14px 18px;background:var(--bg2);border:1px solid var(--bd);border-radius:8px;margin-bottom:12px}
.delta-banner .drow{display:flex;gap:28px;flex-wrap:wrap;margin-top:8px}
.delta-banner .dk{font-size:11px;color:var(--tx2);text-transform:uppercase;letter-spacing:.05em}
.delta-banner .dv{font-size:22px;font-weight:700}
.tag-reg{background:#3d1a1a;color:var(--red);border:1px solid #6d2222;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700}
.tag-imp{background:#0d2416;color:var(--grn);border:1px solid #1a4a2a;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700}
.tag-new{background:#1a1a3d;color:var(--pur);border:1px solid #3a3a6d;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700}
.empty{padding:22px;text-align:center;color:var(--tx2)}
@media(max-width:580px){.scores{grid-template-columns:1fr}.sumgrid{grid-template-columns:repeat(3,1fr)}}
</style></head><body><div class="wrap"><div id="app"></div></div>
<script>
const D=__APEX_DATA__;
const F=D.findings,C=D.context,S=D.scores,DT=D.delta;
const SEV_LABEL={CRITICAL:'C',HIGH:'H',MEDIUM:'M',LOW:'L',PASS:'P'};
const SEV_HUMAN={CRITICAL:'Immediate action required — critical security gap.',HIGH:'Should be addressed soon — significant risk.',MEDIUM:'Plan to address — moderate risk.',LOW:'Best-practice recommendation — low exploitability.',PASS:'Control verified and effective.'};
function h(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function sv(s){const k=SEV_LABEL[s]||'P';return`<span class="sv sv-${k}">${h(s)}</span>`}
function cf(c){return`<span class="cf cf-${h(c)}">${h(c)}</span>`}
function compBadges(f){
  const r=f.ComplianceRefs;if(!r)return'';
  const cis=(r.CIS||[]).map(v=>`<span class="cb cb-cis">CIS ${h(v)}${r.CIS_Level?' L'+r.CIS_Level:''}</span>`).join('');
  const stig=(r.STIG||[]).map(v=>`<span class="cb cb-stig">STIG ${h(v)}</span>`).join('');
  const nist=(r.NIST||[]).map(v=>`<span class="cb cb-nist">NIST ${h(v)}</span>`).join('');
  const all=cis+stig+nist;
  return all?`<div class="comp">${all}</div>`:'';
}
function scoreCol(v){return v>=80?'var(--grn)':v>=60?'var(--yel)':'var(--red)'}
function sign(v){return(v>=0?'+':'')+v}
let view='executive';
function hdr(){return`<div class="card"><div class="hdr"><h1>APEX Zero-Trust Enterprise Audit</h1><div class="meta"><span>&#128421; ${h(C.Hostname)}</span><span>&#129695; ${h(C.OSCaption)} (Build ${h(C.OSBuild)})</span><span>&#9881; ${h(C.Mode)} &middot; ${h(C.Profile)}</span><span>&#128336; ${h(C.TimestampUTC)}</span></div></div></div>`}
function scoreCards(){
  const sv2=S.SeverityScore,hv=S.HygieneScore;
  function card(lbl,sub,val,delta){
    const c=scoreCol(val);
    const dHtml=delta!==null?`<div class="delta" style="color:${delta>=0?'var(--grn)':'var(--red)'}"> ${sign(delta)} vs baseline</div>`:'';
    return`<div class="sc"><div class="lbl">${lbl}</div><div class="val" style="color:${c}">${val}</div><div class="bar"><div class="fill" style="width:${val}%;background:${c}"></div></div><div class="sub">${sub}</div>${dHtml}</div>`;
  }
  const sd=DT?DT.SeverityScoreDelta:null,hd=DT?DT.HygieneScoreDelta:null;
  return`<div class="scores">${card('Severity Score <small style="font-weight:400;text-transform:none">(Critical/High)</small>','Immediate risk',sv2,sd)}${card('Hygiene Score <small style="font-weight:400;text-transform:none">(Medium/Low)</small>','Posture &amp; best-practice',hv,hd)}</div>`
}
function tabs(){
  const dh=!DT?'hidden':'';
  return`<div class="tabs"><button class="tab ${view==='executive'?'on':''}" onclick="setView('executive')">Executive Summary</button><button class="tab ${view==='technical'?'on':''}" onclick="setView('technical')">Technical Detail</button><button class="tab ${dh} ${view==='delta'?'on':''}" onclick="setView('delta')">&#916; Delta</button></div>`
}
function summaryBar(){
  const c={C:0,H:0,M:0,L:0,P:0};
  F.forEach(f=>{if(f.Vulnerable){const k=SEV_LABEL[f.Severity];if(k&&k!=='P')c[k]++}else c.P++});
  const labels={C:'Critical',H:'High',M:'Medium',L:'Low',P:'Secure'};
  return`<div class="card"><div class="sumgrid">${Object.entries(c).map(([k,v])=>`<div class="stat"><div class="n n-${k}">${v}</div><div class="l">${labels[k]}</div></div>`).join('')}</div></div>`
}
function findingCard(f,techMode){
  const dispSev=f.Vulnerable?f.Severity:'PASS';
  const fix=f.Fix&&f.Fix!=='N/A'?`<div class="ffix">Fix: <code>${h(f.Fix)}</code></div>`:'';
  if(!techMode)return`<div class="fi"><div class="fih">${sv(dispSev)}<div class="fn">${h(f.CheckName)}</div></div><div class="fhum">${h(SEV_HUMAN[f.Severity]||'')}${f.Note?' '+h(f.Note):''}</div>${fix}</div>`;
  return`<div class="fi"><div class="fih">${sv(dispSev)}<div class="fn">${h(f.CheckName)}</div>${cf(f.Confidence)}</div><div class="trow"><span class="tl">Observed</span><span class="tv">${h(f.Observed)}</span></div><div class="trow"><span class="tl">Expected</span><span class="tv">${h(f.Expected)}</span></div><div class="trow"><span class="tl">Source</span><span class="tv">${h(f.Source)}</span></div><div class="trow"><span class="tl">ID</span><span class="tv" style="font-family:monospace;font-size:11px">${h(f.Id)}</span></div>${compBadges(f)}${fix}</div>`
}
function section(title,items,open,tech){
  const body=items.length?items.map(f=>findingCard(f,tech)).join(''):`<div class="empty">No findings in this group.</div>`;
  return`<div class="sec ${open?'open':''}"><div class="sh" onclick="tog(this)"><div class="st">${title}</div><span class="cv">&#9654;</span></div><div class="sb">${body}</div></div>`
}
function executive(){
  const vulns=F.filter(f=>f.Vulnerable);
  if(!vulns.length)return`<div class="card"><div class="empty">&#9989; All checks passed.</div></div>`;
  let out='';
  const top=vulns.filter(f=>['CRITICAL','HIGH'].includes(f.Severity));
  if(top.length)out+=section(`&#128308; Top Risks <span class="sc2">${top.length} critical/high</span>`,top,true,false);
  ['MEDIUM','LOW'].forEach(s=>{const items=vulns.filter(f=>f.Severity===s);if(items.length)out+=section(`${s==='MEDIUM'?'&#128992;':'&#128309;'} ${s} <span class="sc2">${items.length} items</span>`,items,false,false)});
  return out;
}
function technical(){
  const cats={};F.forEach(f=>{(cats[f.Category]=cats[f.Category]||[]).push(f)});
  return Object.entries(cats).map(([cat,items])=>{const vc=items.filter(i=>i.Vulnerable).length;return section(`${vc>0?'&#9888;':'&#10003;'} ${h(cat)} <span class="sc2">${vc} issue${vc!==1?'s':''} / ${items.length} checks</span>`,items,vc>0,true)}).join('')
}
function deltaView(){
  if(!DT)return`<div class="card"><div class="empty">No baseline data. Run with -CompareTo to enable delta tracking.</div></div>`;
  const regs=DT.Regressions||[],imps=DT.Improvements||[],news=DT.NewChecks||[];
  const banner=`<div class="delta-banner"><div style="font-weight:600;color:var(--tx2);font-size:12px;text-transform:uppercase;letter-spacing:.05em">Baseline: ${h(DT.BaselineTimestamp)} &middot; Mode: ${h(DT.BaselineMode)}</div><div class="drow"><div><div class="dk">Regressions</div><div class="dv" style="color:${regs.length?'var(--red)':'var(--grn)'}"> ${regs.length}</div></div><div><div class="dk">Improvements</div><div class="dv" style="color:${imps.length?'var(--grn)':'var(--tx2)'}"> ${imps.length}</div></div><div><div class="dk">New Findings</div><div class="dv" style="color:${news.length?'var(--pur)':'var(--tx2)'}"> ${news.length}</div></div><div><div class="dk">Severity &Delta;</div><div class="dv" style="color:${DT.SeverityScoreDelta>=0?'var(--grn)':'var(--red)'}"> ${sign(DT.SeverityScoreDelta)}</div></div><div><div class="dk">Hygiene &Delta;</div><div class="dv" style="color:${DT.HygieneScoreDelta>=0?'var(--grn)':'var(--red)'}"> ${sign(DT.HygieneScoreDelta)}</div></div></div></div>`;
  let body=banner;
  if(regs.length)body+=section(`<span class="tag-reg">REGRESSED</span> Newly Vulnerable <span class="sc2">${regs.length}</span>`,regs,true,true);
  if(imps.length)body+=section(`<span class="tag-imp">IMPROVED</span> No Longer Vulnerable <span class="sc2">${imps.length}</span>`,imps,false,true);
  if(news.length)body+=section(`<span class="tag-new">NEW CHECK</span> Not in Previous Run <span class="sc2">${news.length}</span>`,news,false,true);
  if(!regs.length&&!imps.length&&!news.length)body+=`<div class="card"><div class="empty">&#9989; No changes detected since baseline.</div></div>`;
  return body;
}
function render(){document.getElementById('app').innerHTML=hdr()+scoreCards()+tabs()+summaryBar()+(view==='executive'?executive():view==='technical'?technical():deltaView())}
function setView(v){view=v;render()}
function tog(el){el.closest('.sec').classList.toggle('open')}
render();
</script></body></html>
'@
    $html = $tpl.Replace('__APEX_DATA__', $json)
    try {
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Path, $html, $enc)
        return $true
    } catch { return $false }
}

# ---------------------------------------------------------------------------
#  EXPORT PATH RESOLUTION
# ---------------------------------------------------------------------------
function Resolve-ExportPath {
    # $ExportJSON is visible via script scope (set in Windows_Audit.ps1 param block)
    if ($ExportJSON -ne '') {
        $dir = Split-Path $ExportJSON -Parent
        if ($dir -and -not (Test-Path $dir)) {
            try   { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            catch { Write-Warning "Cannot create dir: $dir -- $_"; exit 2 }
        }
        try {
            $tmp = $ExportJSON + '.apextmp'
            [System.IO.File]::WriteAllText($tmp, 'x')
            Remove-Item $tmp -ErrorAction SilentlyContinue
        } catch { Write-Warning "Export path not writable: $ExportJSON"; exit 2 }
        return $ExportJSON
    }
    $ts = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    return Join-Path (Get-Location).Path "audit_report_$ts.json"
}
