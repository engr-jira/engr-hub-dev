
function getMenuToggleList(){
  const out=[], seen=new Set();
  document.querySelectorAll('.sb-btn[id^="nav-"]').forEach(b=>{
    const key=b.id.replace('nav-',''); if(!key||key==='more-mobile'||seen.has(key))return; seen.add(key);
    out.push({key,label:(b.textContent||'').replace(/\s+/g,' ').trim().replace(/\s*\d+$/,'').trim()||key});
  });
  FEATURE_SPECIAL.forEach(([key,label])=>{ if(!seen.has(key)){seen.add(key);out.push({key,label});} });
  return out;
}
async function loadFeatureFlags(){
  try{ const d=await hubApi('/features'); FEATURE_FLAGS={...FEATURE_FLAGS,...(d.flags||{})}; MONITOR_ALLOWED=!!d.monAllowed; }catch(_){}
  applyFeatureFlags(); renderFeatureFlagsAdmin(); applyMonitorVisibility();
}
function applyFeatureFlags(){
  if(!document.getElementById('feat-off-style')){const st=document.createElement('style');st.id='feat-off-style';st.textContent='.sb-btn.feat-off{display:none!important}';document.head.appendChild(st);}
  document.querySelectorAll('.sb-btn[id^="nav-"]').forEach(btn=>{
    const key=btn.id.replace('nav-','');
    if(key==='more-mobile')return;                                        // 모바일 더보기 버튼은 토글 대상 아님
    if(FEATURE_PROTECTED[key]){btn.classList.remove('feat-off');return;}  // settings/dash 등은 락아웃 방지(토글 불가)
    btn.classList.toggle('feat-off', FEATURE_FLAGS[key]===false);          // 클래스만 추가/제거 → 역할 게이트(인라인) 보존
  });
  const hb=document.getElementById('cust-history-btn'); if(hb)hb.style.display=FEATURE_FLAGS.history===false?'none':'';
  const am=document.getElementById('audit-mig-section'); if(am){am.style.display=IS_SUPER?'':'none'; if(IS_SUPER&&typeof loadAuditMigStatus==='function')loadAuditMigStatus();}
  if(typeof applyMonitorVisibility==='function')applyMonitorVisibility();
}
function renderFeatureFlagsAdmin(){
  const w=document.getElementById('feature-flags-wrap'); if(!w)return;
  w.innerHTML=getMenuToggleList().map(({key,label})=>{
    const locked=!!FEATURE_PROTECTED[key], on=FEATURE_FLAGS[key]!==false;
    const tail=locked?'<span class="u-muted-10">잠금</span>':(FEATURE_WARN[key]?`<span class="u-c-warn" title="${FEATURE_WARN[key]}">⚠</span>`:'');
    return `<label style="display:flex;align-items:center;gap:9px;padding:7px 0;font-size:13px;cursor:${locked?'not-allowed':'pointer'};border-bottom:1px solid var(--border);opacity:${locked?'.6':'1'}"><input type="checkbox" data-ff="${key}" ${(on||locked)?'checked':''} ${locked?'disabled':''} style="width:16px;height:16px"> <span>${escapeHtml(label)}</span> <code style="font-size:10px;color:var(--text3);margin-left:auto">${key}</code>${tail}</label>`;
  }).join('');
}
async function saveFeatureFlags(){
  const flags={}; document.querySelectorAll('#feature-flags-wrap input[data-ff]').forEach(c=>{flags[c.dataset.ff]=c.checked;});
  flags.settings=true;  // 락아웃 방지
  try{ const d=await hubApi('/features',{method:'POST',body:JSON.stringify({flags})}); FEATURE_FLAGS={...FEATURE_FLAGS,...(d.flags||{})}; applyFeatureFlags(); renderFeatureFlagsAdmin(); toast('기능 토글을 저장했습니다'); }
  catch(e){ toast('저장 실패: '+e.message); }
}
/* ── §2 고객사 업무 이력 (Jira /team/history) ─────────── */
let HISTORY_ITEMS=[];
function openCustomerHistory(){
  if(FEATURE_FLAGS.history===false){toast('비활성화된 기능입니다');return;}
  const m=document.getElementById('cust-history-modal'); if(!m)return;
  const cust=(typeof CUST_SEL!=='undefined'&&CUST_SEL)?CUST_SEL.name:'';
  const ci=document.getElementById('ch-customer'); if(cust&&ci&&!ci.value)ci.value=cust;
  const from=document.getElementById('ch-from'), to=document.getElementById('ch-to');
  if(from&&!from.value){ const d=new Date(); d.setFullYear(d.getFullYear()-1); from.value=d.toISOString().slice(0,10); if(to)to.value=new Date().toISOString().slice(0,10); }
  m.style.display='flex';
}
function closeCustomerHistory(){ const m=document.getElementById('cust-history-modal'); if(m)m.style.display='none'; }
async function runCustomerHistory(){
  const g=id=>document.getElementById(id)?.value?.trim()||'';
  const payload={customer:g('ch-customer'),dateField:g('ch-datefield'),from:g('ch-from'),to:g('ch-to'),product:g('ch-product'),type:g('ch-type'),assignee:g('ch-assignee'),status:g('ch-status')};
  const st=document.getElementById('ch-status-text'), res=document.getElementById('ch-results');
  if(st)st.textContent='조회 중...'; if(res)res.innerHTML='';
  try{
    const d=await hubApi('/team/history',{method:'POST',body:JSON.stringify(payload)});
    HISTORY_ITEMS=d.items||[];
    if(st)st.textContent=`${d.count}건`+(d.jql?` · ${d.jql}`:'');
    renderHistoryResults();
  }catch(e){ if(st)st.textContent=''; if(res)res.innerHTML=`<div class="u-cdanger-p16px">조회 실패: ${escapeHtml(e.message)}</div>`; }
}
function histClsBadge(cls){
  if(!cls)return '';
  if(cls.customer)return ` <span class="badge" style="background:#34d39922;color:#34d399">${escapeHtml(cls.customer)}</span>`;
  if(cls.kind==='vendorcase')return ' <span class="badge" style="background:#60a5fa22;color:#60a5fa">벤더케이스</span>';
  if(cls.kind==='unclassified')return ` <span class="badge" style="background:#fbbf2422;color:#fbbf24" title="${escapeAttr(cls.bracket||'')}">미분류 ⚑</span>`;
  if(cls.kind==='internal')return ' <span class="badge" style="background:#94a3b822;color:#94a3b8">내부</span>';
  return '';
}
function renderHistoryResults(){
  const res=document.getElementById('ch-results'); if(!res)return;
  if(!HISTORY_ITEMS.length){ res.innerHTML='<div class="muted" style="padding:16px">결과가 없습니다.</div>'; return; }
  const rows=HISTORY_ITEMS.map(i=>`<tr>
    <td><a href="https://escare-engr.atlassian.net/browse/${escapeAttr(i.key)}" target="_blank" rel="noopener" style="color:#60a5fa;white-space:nowrap">${escapeHtml(i.key)}</a></td>
    <td style="max-width:340px">${escapeHtml(i.summary||'')}${histClsBadge(i.cls)}</td>
    <td>${escapeHtml(i.status||'')}</td><td>${escapeHtml(i.assignee||'-')}</td>
    <td class="u-fs-11px">${(i.labels||[]).map(l=>escapeHtml(l)).join(', ')}</td>
    <td class="u-ws-nowrap">${i.type==='subtask'?'하위':'작업'}</td>
    <td class="u-ws-nowrap">${escapeHtml((i.created||'').slice(0,10))}</td>
    <td class="u-ws-nowrap">${escapeHtml((i.updated||'').slice(0,10))}</td>
  </tr>`).join('');
  res.innerHTML=`<table class="ch-tbl srt"><tr><th>키</th><th>제목</th><th>상태</th><th>담당</th><th>라벨</th><th>유형</th><th>생성</th><th>수정</th></tr>${rows}</table>`;
  const _st=res.querySelector('table.srt'); if(_st)applySrtState(_st);
}
function copyHistoryTable(){
  if(!HISTORY_ITEMS.length){toast('복사할 결과가 없습니다');return;}
  const head=['키','제목','상태','담당','라벨','유형','생성','수정'];
  const lines=[head.join('\t')].concat(HISTORY_ITEMS.map(i=>[i.key,(i.summary||'').replace(/\s+/g,' '),i.status,i.assignee,(i.labels||[]).join('|'),i.type==='subtask'?'하위':'작업',(i.created||'').slice(0,10),(i.updated||'').slice(0,10)].map(v=>v||'').join('\t')));
  navigator.clipboard.writeText(lines.join('\n')).then(()=>toast(`${HISTORY_ITEMS.length}건 복사`)).catch(()=>toast('복사 실패'));
}
/* ── §3 팀 업무 모니터 (mj.park 전용) ─────────────── */
let MONITOR_ALLOWED=false;
function applyMonitorVisibility(){
  const nav=document.getElementById('nav-monitor');
  if(nav)nav.style.display=(MONITOR_ALLOWED && FEATURE_FLAGS.monitor!==false)?'':'none';
}
async function loadMonitor(kind){
  const st=document.getElementById('monitor-status'), body=document.getElementById('monitor-body');
  if(st)st.textContent='조회 중...'; if(body)body.innerHTML='';
  try{
    let items, caption;
    if(kind==='snapshot'){ const d=await hubApi('/team/snapshot'); const s=d.snapshot; if(!s){ if(st)st.textContent='저장된 스냅샷이 없습니다 (매일 08:30 자동 생성).'; return; } items=s.items||[]; caption=`스냅샷 ${s.day} · 생성 ${(s.built_at||'').slice(0,16).replace('T',' ')}`; }
    else if(kind==='daily'){ const d=await hubApi('/team/daily',{method:'POST',body:JSON.stringify({})}); items=d.items||[]; caption=`오늘(${d.day}) 갱신 ${d.count}건`; }
    else { const d=await hubApi('/team/weekly',{method:'POST',body:JSON.stringify({days:7})}); items=d.items||[]; caption=`최근 ${d.days}일 갱신 ${d.count}건`; }
    if(st)st.textContent='';
    renderMonitor(items, caption);
  }catch(e){ if(st)st.textContent=''; if(body)body.innerHTML=`<div class="u-cdanger-p10px">조회 실패: ${escapeHtml(e.message)}</div>`; }
}
function renderMonitor(items, caption){
  const body=document.getElementById('monitor-body'); if(!body)return;
  const byA={}; (items||[]).forEach(i=>{const a=i.assignee||'미지정';(byA[a]=byA[a]||[]).push(i);});
  const order=Object.keys(byA).sort((a,b)=>byA[b].length-byA[a].length);
  const unclassified=(items||[]).filter(i=>i.cls&&i.cls.kind==='unclassified');
  const flag=unclassified.length?`<div style="background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.3);border-radius:8px;padding:8px 12px;margin-bottom:10px;font-size:12px;color:var(--warn)">⚑ 미분류 브래킷 ${unclassified.length}건 — 검토 필요(자동 추가 안 함): ${unclassified.slice(0,10).map(i=>escapeHtml(i.cls.bracket||'')).join(', ')}${unclassified.length>10?' …':''}</div>`:'';
  const cards=order.map(a=>`<div class="chart-card soft u-mb-8px"><div style="display:flex;justify-content:space-between;font-weight:700;font-size:13px;margin-bottom:6px"><span>${escapeHtml(a)}</span><span class="u-muted">${byA[a].length}건</span></div>${byA[a].map(i=>`<div style="font-size:11.5px;padding:3px 0;border-bottom:1px solid var(--border)"><a href="https://escare-engr.atlassian.net/browse/${escapeAttr(i.key)}" target="_blank" rel="noopener" style="color:#60a5fa">${escapeHtml(i.key)}</a> <span class="u-muted">${escapeHtml(i.status||'')}</span> ${escapeHtml(i.summary||'')}${histClsBadge(i.cls)}</div>`).join('')}</div>`).join('');
  body.innerHTML=`<div class="muted u-fs115px-mb8px">${escapeHtml(caption)} · 담당 ${order.length}명</div>${flag}${cards||'<div class="muted">결과 없음</div>'}`;
}
/* ── §4 NSIS 설치 스크립트 분석기 ───────────────────── */
let NSIS_PARSED=null, MERMAID_LOADED=false;
function nsisClear(){ ['nsis-input','nsis-summary','nsis-diagram','nsis-ai'].forEach((id,i)=>{const el=document.getElementById(id);if(el)el[i?'innerHTML':'value']='';}); NSIS_PARSED=null; }
function nsisLoadFile(ev){
  const f=ev.target.files?.[0]; if(!f)return;
  if(f.size>2*1024*1024){toast('파일이 너무 큽니다 (2MB 이하)');return;}
  const r=new FileReader(); r.onload=()=>{const el=document.getElementById('nsis-input');if(el)el.value=r.result||'';toast('파일을 불러왔습니다');}; r.readAsText(f);
  ev.target.value='';
}
function parseNsis(src){
  const lines=String(src||'').split(/\r?\n/);
  const defines=[],sections=[],functions=[],blocks=[],files=[],regs=[],execs=[],shortcuts=[],downloads=[],deletes=[];
  const urls=new Set(),ips=new Set(),hashes=new Set();
  let cur=null;
  const ensure=()=>{ if(!cur){cur={name:'(전역/초기화)',kind:'global',ops:[]};blocks.push(cur);} return cur; };
  const op=(kind,detail)=>{ ensure().ops.push({kind,detail:String(detail||'').trim()}); };
  for(const raw of lines){
    const line=raw.trim(); if(!line||line[0]===';'||line[0]==='#')continue;
    let m;
    if(m=/^!define\s+(\S+)\s*(.*)$/i.exec(line)){defines.push(m[1]+(m[2]?(' = '+m[2]):''));continue;}
    if(m=/^Section(?:Group)?\s+(?:\/o\s+)?"?([^"]*)"?/i.exec(line)){const nm=(m[1]||'(이름없음)').trim();sections.push(nm);cur={name:nm,kind:'section',ops:[]};blocks.push(cur);continue;}
    if(/^Section(?:Group)?End/i.test(line)){cur=null;continue;}
    if(m=/^Function\s+(\S+)/i.exec(line)){functions.push(m[1]);cur={name:m[1],kind:'function',ops:[]};blocks.push(cur);continue;}
    if(/^FunctionEnd/i.test(line)){cur=null;continue;}
    if(m=/^SetOutPath\s+(.+)$/i.exec(line))op('dir','SetOutPath '+m[1].replace(/"/g,'').trim());
    else if(m=/^CreateDirectory\s+(.+)$/i.exec(line))op('dir','CreateDirectory '+m[1].replace(/"/g,'').trim());
    else if(m=/^File\b\s+(.+)$/i.exec(line)){const f=m[1].replace(/^\/\S+\s+/,'').replace(/"/g,'').trim();files.push(f);op('file',f);}
    else if(m=/^(WriteRegStr|WriteRegDWORD|WriteRegExpandStr|WriteRegBin|WriteRegMultiStr)\b\s+(.+)$/i.exec(line)){const d=m[2].replace(/"/g,'').trim();regs.push(m[1]+' '+d);op('reg',d);}
    else if(m=/^(DeleteRegKey|DeleteRegValue)\b\s+(.+)$/i.exec(line)){const d=m[2].replace(/"/g,'').trim();regs.push(m[1]+' '+d);op('regdel',d);}
    else if(m=/^(ExecWait|ExecShell|Exec)\b\s+(.+)$/i.exec(line)){const d=m[2].replace(/"/g,'').trim();execs.push(d);op('exec',d);}
    else if(m=/^(nsExec::ExecToLog|nsExec::ExecToStack|nsExec::Exec)\s+(.+)$/i.exec(line)){const d=m[2].replace(/"/g,'').trim();execs.push(d);op('exec',d);}
    else if(m=/^CreateShortCut\b\s+(.+)$/i.exec(line)){const d=m[1].replace(/"/g,'').trim();shortcuts.push(d);op('shortcut',d.split(/\s{2,}|"\s/)[0].replace(/"/g,'')||d);}
    else if(m=/^(Delete|RMDir)\b\s+(.+)$/i.exec(line)){const d=(m[1]+' '+m[2].replace(/"/g,'')).trim();deletes.push(d);op('delete',d);}
    else if(m=/^(CopyFiles|Rename)\b\s+(.+)$/i.exec(line))op('file',m[1]+' '+m[2].replace(/"/g,'').trim());
    else if(/inetc::get|NSISdl::download|INetC|nsisdl/i.test(line)){const d=line.replace(/"/g,'').slice(0,140);downloads.push(d);op('download',d);}
    (line.match(/https?:\/\/[^\s"'<>)]+/gi)||[]).forEach(u=>urls.add(u));
    (line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[]).forEach(x=>ips.add(x));
    (line.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi)||[]).forEach(h=>hashes.add(h.toLowerCase()));
  }
  return {defines,sections,functions,blocks,files,regs,execs,shortcuts,downloads,deletes,indicators:{urls:[...urls],ips:[...ips],hashes:[...hashes]}};
}
function runNsisParse(){
  const src=document.getElementById('nsis-input')?.value?.trim();
  if(!src){toast('NSIS 스크립트를 입력하세요');return;}
  NSIS_PARSED=parseNsis(src); renderNsisSummary(NSIS_PARSED);
}
function renderNsisSummary(p){
  const el=document.getElementById('nsis-summary'); if(!el)return;
  const chip=(label,n,col)=>`<span style="display:inline-block;background:${col}22;color:${col};border-radius:6px;padding:3px 9px;font-size:12px;margin:2px">${label} ${n}</span>`;
  const list=(title,arr,max=60)=>arr.length?`<details class="u-mt-8px"><summary style="cursor:pointer;font-size:12px;color:var(--text2,#cbd5e1)">${title} (${arr.length})</summary><div style="font-size:11.5px;color:var(--text3);font-family:monospace;white-space:pre-wrap;margin-top:6px;max-height:220px;overflow:auto">${arr.slice(0,max).map(x=>escapeHtml(String(x))).join('\n')}${arr.length>max?'\n… +'+(arr.length-max):''}</div></details>`:'';
  const ind=p.indicators, iocs=[...ind.urls,...ind.ips,...ind.hashes];
  const risky=(p.downloads.length||p.execs.length)?`<div style="margin-top:8px;font-size:11.5px;color:var(--warn)">⚠️ 외부 다운로드/임의 실행 항목이 있습니다 — AI 보안 분석 권장</div>`:'';
  el.innerHTML=`<div style="margin-bottom:6px">${chip('📦 섹션',p.sections.length,'#60a5fa')}${chip('🔧 함수',p.functions.length,'#a78bfa')}${chip('📄 File',p.files.length,'#34d399')}${chip('▶️ Exec',p.execs.length,'#f59e0b')}${chip('🗝️ Reg',p.regs.length,'#f472b6')}${chip('⬇️ 다운로드',p.downloads.length,'#fb7185')}${chip('🔗 URL',ind.urls.length,'#22d3ee')}${chip('🌐 IP',ind.ips.length,'#22d3ee')}${chip('#️⃣ Hash',ind.hashes.length,'#22d3ee')}</div>${risky}
    ${list('섹션/함수',p.sections.concat(p.functions))}${list('▶️ 실행(Exec) — 전체',p.execs)}${list('🗝️ 레지스트리 — 전체',p.regs)}${list('🗑️ 삭제(Delete/RMDir)',p.deletes)}${list('🔗 바로가기',p.shortcuts)}${list('⬇️ 다운로드',p.downloads)}${list('📄 파일(File) — 전체',p.files)}${list('!define',p.defines)}
    ${iocs.length?`<div class="u-mt-10px"><div style="font-size:11px;color:var(--text3);margin-bottom:4px">위협 인텔(VT) 조회 — 클릭 시 VirusTotal 페이지로 전달:</div>${iocs.slice(0,24).map(v=>`<button onclick="nsisToVT(${jsAttr(v)})" style="${CMB};margin:2px">${escapeHtml(v.length>42?v.slice(0,42)+'…':v)}</button>`).join('')}</div>`:''}`;
}
function nsisToVT(v){
  showPage('vt');
  setTimeout(()=>{ const inp=document.getElementById('vt-input'); if(inp){inp.value=v; inp.focus(); inp.dispatchEvent(new Event('input',{bubbles:true})); } toast('VirusTotal로 전달했습니다 — 조회 버튼을 누르세요'); },60);
}
function ensureMermaid(){
  return new Promise((resolve,reject)=>{
    if(window.mermaid&&MERMAID_LOADED)return resolve(window.mermaid);
    const done=()=>{try{window.mermaid.initialize({startOnLoad:false,theme:'dark',securityLevel:'strict',flowchart:{useMaxWidth:true,nodeSpacing:40,rankSpacing:50,curve:'basis'}});MERMAID_LOADED=true;resolve(window.mermaid);}catch(e){reject(e);}};
    if(window.mermaid)return done();
    const s=document.createElement('script'); s.src='vendor/mermaid.min.js';
    s.onload=done; s.onerror=()=>reject(new Error('Mermaid 번들 로드 실패'));
    document.head.appendChild(s);
  });
}
function nsisFlowMermaid(src){
  const rawLines=String(src||'').split(/\r?\n/), toks=[];
  for(let raw of rawLines){
    let line=raw.trim(); if(!line||line[0]===';'||line[0]==='#')continue;
    let note=''; const ci=line.search(/\s;/);
    if(ci>=0 && (line.slice(0,ci).match(/"/g)||[]).length%2===0){ note=line.slice(ci+1).replace(/^[\s;]+/,'').trim(); line=line.slice(0,ci).trim(); }
    if(!line)continue; let m;
    if(m=/^(?:Section|SectionGroup)\b\s*(?:\/o\s+)?"?([^"]*)"?/i.exec(line)){toks.push({t:'block',kind:'section',name:(m[1]||'Section').trim()});continue;}
    if(/^(?:SectionEnd|SectionGroupEnd)\b/i.test(line))continue;
    if(m=/^Function\s+(\S+)/i.exec(line)){toks.push({t:'block',kind:'function',name:m[1]});continue;}
    if(/^FunctionEnd\b/i.test(line))continue;
    if(m=/^\$\{(IfNot|Unless|If)\}\s*(.*)$/i.exec(line)){toks.push({t:'if',cond:(/Not|Unless/i.test(m[1])?'NOT ':'')+m[2].trim(),note});continue;}
    if(/^\$\{Else\}/i.test(line)){toks.push({t:'else'});continue;}
    if(m=/^\$\{ElseIf\}\s*(.*)$/i.exec(line)){toks.push({t:'elseif',cond:m[1].trim(),note});continue;}
    if(/^\$\{(?:EndIf|EndUnless)\}/i.test(line)){toks.push({t:'endif'});continue;}
    if(m=/^\$\{(?:Switch|Select)\}\s*(.*)$/i.exec(line)){toks.push({t:'if',cond:'switch '+m[1].trim(),note});continue;}
    if(/^\$\{(?:EndSwitch|EndSelect)\}/i.test(line)){toks.push({t:'endif'});continue;}
    if(m=/^IfFileExists\s+("[^"]*"|\S+)\s+(\S+)(?:\s+(\S+))?$/i.exec(line)){toks.push({t:'cond',text:note||('File 존재? '+m[1].replace(/"/g,'')),yes:m[2],no:m[3]});continue;}
    if(m=/^IfErrors\s+(\S+)(?:\s+(\S+))?$/i.exec(line)){toks.push({t:'cond',text:note||'에러 발생?',yes:m[1],no:m[2]});continue;}
    if(m=/^IfRebootFlag\s+(\S+)(?:\s+(\S+))?$/i.exec(line)){toks.push({t:'cond',text:note||'재부팅 플래그?',yes:m[1],no:m[2]});continue;}
    if(m=/^StrCmpS?\s+(.+?)\s+(\S+)(?:\s+(\S+))?$/i.exec(line)){toks.push({t:'cond',text:note||('StrCmp '+m[1]),yes:m[2],no:m[3]});continue;}
    if(m=/^Goto\s+(\S+)/i.exec(line)){toks.push({t:'goto',label:m[1]});continue;}
    if(m=/^([A-Za-z_][\w.\-]*):$/.exec(line)){toks.push({t:'label',name:m[1]});continue;}
    if(m=/^Call\s+(\S+)/i.exec(line)){toks.push({t:'op',icon:'⮞ Call',detail:m[1],note});continue;}
    if(m=/^File\b\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'📄 File',detail:m[1].replace(/^\/\S+\s+/,'').replace(/"/g,''),note});continue;}
    if(m=/^SetOutPath\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'📁 OutPath',detail:m[1].replace(/"/g,''),note});continue;}
    if(m=/^CreateDirectory\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'📁 MkDir',detail:m[1].replace(/"/g,''),note});continue;}
    if(m=/^(?:WriteRegStr|WriteRegDWORD|WriteRegExpandStr|WriteRegBin|WriteRegMultiStr)\b\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'🗝️ WriteReg',detail:m[1].replace(/"/g,''),note});continue;}
    if(m=/^(?:DeleteRegKey|DeleteRegValue)\b\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'🗝️➖ DelReg',detail:m[1].replace(/"/g,''),warn:1,note});continue;}
    if(m=/^(?:ExecWait|ExecShell|Exec)\b\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'▶️ Exec',detail:m[1].replace(/"/g,''),warn:1,note});continue;}
    if(m=/^nsExec::\w+\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'▶️ nsExec',detail:m[1].replace(/"/g,''),warn:1,note});continue;}
    if(m=/^CreateShortCut\b\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'🔗 Shortcut',detail:m[1].replace(/"/g,'').split(/\s{2,}/)[0],note});continue;}
    if(m=/^(Delete|RMDir)\b\s+(.+)$/i.exec(line)){toks.push({t:'op',icon:'🗑️ '+m[1],detail:m[2].replace(/"/g,''),warn:1,note});continue;}
    if(/^(?:inetc::get|NSISdl::download|INetC::get)\b/i.test(line)){toks.push({t:'op',icon:'⬇️ Download',detail:line.replace(/"/g,'').slice(0,60),warn:1,note});continue;}
    if(m=/^(StrCpy|IntOp|ReadRegStr|ReadEnvStr|SetRebootFlag|Var|Push|Pop)\b\s*(.*)$/i.exec(line)){toks.push({t:'op',icon:'▫️ '+m[1],detail:(m[2]||'').replace(/"/g,'').slice(0,46),note});continue;}
  }
  return buildFlow(toks);
}
function buildFlow(toks){
  // 연속 동종 작업(같은 icon)을 한 노드로 묶어 긴 선형 체인을 축약
  const merged=[];
  for(const t of toks){
    const last=merged[merged.length-1];
    if(t.t==='op' && last && last.t==='op' && last.icon===t.icon){ last.items.push(t.detail||''); last.n++; if(t.warn)last.warn=1; }
    else if(t.t==='op'){ merged.push({...t, items:[t.detail||''], n:1}); }
    else merged.push(t);
  }
  toks=merged;
  // "label: 짧은 op; Goto X" 패턴을 한 노드로 접어 부채꼴(라벨 수렴) 노드수 축소
  const _li={}, _f=[];
  for(let i=0;i<toks.length;i++){
    const t=toks[i];
    if(t.t==='label'){ let j=i+1; const ops=[]; while(j<toks.length && toks[j].t==='op' && ops.length<3){ops.push(toks[j]);j++;} if(ops.length && j<toks.length && toks[j].t==='goto'){ _li[t.name]={ops,goto:toks[j].label}; _f.push({t:'label',name:t.name}); i=j; continue; } }
    _f.push(t);
  }
  toks=_f; const labelInfo=_li;
  // 부채꼴/switch 축약: [cond(상대점프)? op+ goto X]가 같은 X로 2회+ 반복 → 한 노드
  // StrCmp $3 0 0 +3 처럼 yes/no가 상대점프(0,+N,-N)인 cond는 라벨이 아니므로 케이스 셀렉터로 흡수(가짜 0/+3 노드 제거)
  const _isRel=s=>/^[+-]?\d+$/.test(String(s==null?'':s).trim());
  const _unit=(start)=>{ let k=start;
    while(toks[k] && toks[k].t==='cond' && _isRel(toks[k].yes) && _isRel(toks[k].no)) k++;
    const ops=[]; while(toks[k] && toks[k].t==='op'){ ops.push(toks[k]); k++; }
    if(ops.length && toks[k] && toks[k].t==='goto') return {ops, goto:toks[k].label, end:k+1};
    return null; };
  const _g=[];
  for(let i=0;i<toks.length;){
    const u0=_unit(i);
    if(u0){ const items=[...u0.ops]; const target=u0.goto; let end=u0.end, cnt=1, u;
      while((u=_unit(end)) && u.goto===target){ items.push(...u.ops); end=u.end; cnt++; }
      if(cnt>=2){ _g.push({t:'gotorun',items,goto:target}); i=end; continue; } }
    _g.push(toks[i]); i++;
  }
  toks=_g;
  let nid=0; const lines=[], edges=[], warns=[], decs=[];
  const enc=s=>{ let r=String(s||'').replace(/[\r\n]+/g,' ').replace(/\$\{(\w+)\}/g,'$1').replace(/\s+/g,' ').trim(); if(r.length>56)r=r.slice(0,56)+'…'; return r.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/[\[\](){}#|]/g,c=>'&#'+c.charCodeAt(0)+';')||'·'; };
  const node=(shape,text)=>{const i='f'+(nid++);let s;if(shape==='dec'){s=i+'{"'+enc(text)+'"}';decs.push(i);}else if(shape==='term')s=i+'(["'+enc(text)+'"])';else if(shape==='block')s=i+'[["'+enc(text)+'"]]';else if(shape==='label')s=i+'>"'+enc(text)+'"]';else s=i+'["'+enc(text)+'"]';lines.push('  '+s);return i;};
  const edge=(a,b,l)=>{edges.push(l?('  '+a+' -->|'+enc(l)+'| '+b):('  '+a+' --> '+b));};
  const opLabel=tk=>{ if(tk.n>1)return tk.icon+' ×'+tk.n+': '+tk.items.slice(0,4).filter(Boolean).join(', ')+(tk.n>4?' …':''); return tk.icon+': '+(tk.detail||'')+(tk.note?(' — '+tk.note):''); };
  const start=node('term','⚙️ START'); let pending=[{id:start}];
  const connect=to=>{ pending.forEach(p=>edge(p.id,to,p.label)); pending=[]; };
  const labelNodes={}; const ensureLabel=name=>{ if(!labelNodes[name]){ const inf=labelInfo[name]; labelNodes[name]=node('label','▸ '+name+(inf&&inf.ops.length?' → '+inf.ops.map(o=>o.icon+(o.detail?' '+o.detail:'')).join(', '):'')); } return labelNodes[name]; };
  const ifStack=[]; const MAX=200; let n=0, trunc=false;
  for(const tk of toks){
    if(n>=MAX){trunc=true;break;}
    if(tk.t==='block'){ const b=node('block',(tk.kind==='function'?'🔧 ':'📦 ')+tk.name); connect(b); pending=[{id:b}]; n++; }
    else if(tk.t==='op'){ const o=node('proc',opLabel(tk)); connect(o); if(tk.warn)warns.push(o); pending=[{id:o}]; n++; }
    else if(tk.t==='gotorun'){ const lbl='🔀 '+tk.items.length+'-분기 → '+tk.goto+': '+tk.items.map(o=>o.detail||'').filter(Boolean).slice(0,6).join(' / ')+(tk.items.length>6?' …':''); const nd=node('proc',lbl); connect(nd); pending=[{id:nd}]; n++; }
    else if(tk.t==='if'){ const d=node('dec','❓ '+(tk.note||tk.cond)); connect(d); ifStack.push({dec:d,trueEnds:[],elseStarted:false}); pending=[{id:d,label:'예'}]; n++; }
    else if(tk.t==='elseif'){ const fr=ifStack[ifStack.length-1]; if(fr){ fr.trueEnds.push(...pending); const d=node('dec','❓ '+(tk.note||tk.cond)); edge(fr.dec,d,'아니오'); fr.dec=d; pending=[{id:d,label:'예'}]; n++; } }
    else if(tk.t==='else'){ const fr=ifStack[ifStack.length-1]; if(fr){ fr.trueEnds.push(...pending); fr.elseStarted=true; pending=[{id:fr.dec,label:'아니오'}]; } }
    else if(tk.t==='endif'){ const fr=ifStack.pop(); if(fr){ const ends=[...fr.trueEnds,...pending]; if(!fr.elseStarted)ends.push({id:fr.dec,label:'아니오'}); pending=ends; } }
    else if(tk.t==='cond'){ const d=node('dec','❓ '+tk.text); connect(d); const np=[]; if(tk.yes)edge(d,ensureLabel(tk.yes),'예'); else np.push({id:d,label:'예'}); if(tk.no)edge(d,ensureLabel(tk.no),'아니오'); else np.push({id:d,label:'아니오'}); pending=np; n++; }
    else if(tk.t==='goto'){ connect(ensureLabel(tk.label)); pending=[]; }
    else if(tk.t==='label'){ const t=ensureLabel(tk.name); connect(t); const inf=labelInfo[tk.name]; if(inf&&inf.goto){ edge(t, ensureLabel(inf.goto)); pending=[]; } else pending=[{id:t}]; }
  }
  const endN=node('term','✅ END'); pending.forEach(p=>edge(p.id,endN,p.label));
  let g='flowchart TD\n'+lines.join('\n')+'\n'+edges.join('\n')+'\n';
  g+='  classDef dec fill:#172033,stroke:#60a5fa,stroke-width:2px,color:#dbeafe\n';
  if(decs.length)g+='  class '+decs.join(',')+' dec\n';
  if(warns.length)g+='  classDef warn fill:#7f1d1d,stroke:#f87171,color:#fee2e2\n  class '+warns.join(',')+' warn\n';
  if(trunc)g+='  '+endN+' -.-> trunc["… 노드 '+MAX+'개 초과 — 상세 목록 참고"]\n';
  return g;
}
async function renderNsisDiagram(){
  const wrap=document.getElementById('nsis-diagram'); if(!wrap)return;
  const src=document.getElementById('nsis-input')?.value?.trim();
  if(!src){toast('먼저 스크립트를 입력하세요');return;}
  if(!NSIS_PARSED)NSIS_PARSED=parseNsis(src);
  wrap.innerHTML='<div class="muted" style="padding:14px">다이어그램 생성 중...</div>';
  try{
    const mer=await ensureMermaid();
    const r=await mer.render('nsisFlow'+(window.__nsisN=(window.__nsisN||0)+1), nsisFlowMermaid(src));
    wrap.innerHTML=`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px;overflow:auto">${r.svg}</div>`;
  }catch(e){ wrap.innerHTML=`<div class="u-cdanger-p10px">다이어그램 실패: ${escapeHtml(e.message)}</div>`; }
}
async function analyzeNsisAI(){
  const src=document.getElementById('nsis-input')?.value?.trim();
  if(!src){toast('NSIS 스크립트를 입력하세요');return;}
  const out=document.getElementById('nsis-ai'); if(out)out.innerHTML='<div class="muted u-p-10px">AI 보안 분석 중...</div>';
  const p=NSIS_PARSED||parseNsis(src);
  const prompt=`다음은 NSIS(Nullsoft) 설치 스크립트다. 보안 엔지니어 관점에서 분석하라.\n1) 설치 동작 요약 — 무엇을 설치/실행/기록하는가\n2) 보안상 주의점 — 외부 다운로드, 임의 실행(ExecWait/nsExec), 레지스트리/권한 변경, 의심 URL·IP\n3) 위험도(낮음/보통/높음)와 근거\n한국어로 간결히. 추정과 확인된 사실을 구분하라.\n\n[추출 요약] 섹션 ${p.sections.length} · File ${p.files.length} · Exec ${p.execs.length} · Reg ${p.regs.length} · 다운로드 ${p.downloads.length} · URL ${p.indicators.urls.length} · IP ${p.indicators.ips.length} · Hash ${p.indicators.hashes.length}\n\n[스크립트]\n${src.slice(0,16000)}`;
  try{
    const txt=await callAI(prompt,'nsisx',{feature:'nsis'});
    if(out)out.innerHTML=`<div class="u-bgcard-bor1pxsol-br10px-p14px-wsprewra-f">${escapeHtml(txt)}</div><div class="muted u-fs105px-mt4px">AI 추정 — 확정 판단은 검토 필요 · ${escapeHtml(aiModelLabel(LAST_AI_MODEL))}</div>`;
  }catch(e){ if(out)out.innerHTML=`<div class="u-cdanger-p10px">AI 분석 실패: ${escapeHtml(e.message)}</div>`; }
}
async function analyzeNsisImprove(){
  const src=document.getElementById('nsis-input')?.value?.trim();
  if(!src){toast('NSIS 스크립트를 입력하세요');return;}
  const out=document.getElementById('nsis-ai'); if(out)out.innerHTML='<div class="muted u-p-10px">AI 개선안 도출 중...</div>';
  const prompt=`다음은 NSIS(Nullsoft) 설치 스크립트다. 설치 엔지니어 관점에서 이 스크립트의 개선안을 제시하라.\n1) 버그·오류 가능성 — 잔존 프로세스/파일, 64/32비트 분기, 권한, 재부팅 처리\n2) 견고성·멱등성 — 재설치/업그레이드 안전, 실패 시 롤백, IfErrors/에러 처리\n3) 보안 하드닝 — 불필요한 임의 실행 축소, 외부 다운로드 무결성 검증, 레지스트리 최소 권한\n4) 모범사례·현대화 — LogicLib 활용, 상세 로그(ShowInstDetails), 언인스톨러 정합성\n각 항목을 구체적으로(어느 부분을 어떻게 고치는지, 가능하면 코드 스니펫). 한국어. 확정과 추정을 구분.\n\n[스크립트]\n${src.slice(0,16000)}`;
  try{
    const txt=await callAI(prompt,'nsisx',{feature:'nsis_improve'});
    if(out)out.innerHTML=`<div class="u-bgcard-bor1pxsol-br10px-p14px-wsprewra-f"><div style="font-weight:700;color:var(--accent);margin-bottom:8px">💡 스크립트 개선안</div>${escapeHtml(txt)}</div><div class="muted u-fs105px-mt4px">AI 추정 — 적용 전 검토 필요 · ${escapeHtml(aiModelLabel(LAST_AI_MODEL))}</div>`;
  }catch(e){ if(out)out.innerHTML=`<div class="u-cdanger-p10px">개선안 도출 실패: ${escapeHtml(e.message)}</div>`; }
}
/* ── §H 감사로그 마이그레이션 (슈퍼) ─────────────── */
async function loadAuditMigStatus(){
  const el=document.getElementById('audit-mig-status'); if(!el)return;
  try{ const d=await hubApi('/admin/migrate/audit-status'); el.innerHTML=`D1 적재 <b>${d.d1Count}</b>건 · 읽기 소스 <b style="color:${d.readD1?'#34d399':'#fbbf24'}">${d.readD1?'D1':'KV(기존)'}</b>`; }
  catch(e){ el.textContent='상태 조회 실패: '+e.message; }
}
async function auditMigBackfill(){
  if(!confirm('기존 KV 감사로그를 D1로 백필합니다(멱등·안전). 계속할까요?'))return;
  const el=document.getElementById('audit-mig-status'); let total=0, rounds=0;
  try{
    for(const prefix of ['auditLatest:','audit:']){
      let cursor=null;
      do{
        const d=await hubApi('/admin/migrate/audit-backfill',{method:'POST',body:JSON.stringify({prefix,cursor})});
        total+=d.inserted||0; cursor=d.cursor; rounds++;
        if(el)el.textContent=`백필 중... ${total}건 적재 (${rounds}배치)`;
        if(rounds>300){toast('배치 상한 — 한 번 더 실행하세요');break;}
      }while(cursor);
    }
    toast(`백필 완료: ${total}건 적재`); loadAuditMigStatus();
  }catch(e){ toast('백필 실패: '+e.message); loadAuditMigStatus(); }
}
async function auditMigReadSource(d1){
  if(!confirm(d1?'감사로그 읽기를 D1로 전환합니다. 계속?':'감사로그 읽기를 KV(기존)로 되돌립니다. 계속?'))return;
  try{ await hubApi('/admin/migrate/audit-readsource',{method:'POST',body:JSON.stringify({d1})}); toast('전환했습니다'); loadAuditMigStatus(); }
  catch(e){ toast('전환 실패: '+e.message); }
}
/* ── 공용: 일괄 선택/삭제 ── */
function bulkSelectAll(master, itemSel){ document.querySelectorAll(itemSel).forEach(c=>{c.checked=master.checked;}); }
function bulkSelectedIds(itemSel){ return [...document.querySelectorAll(itemSel+':checked')].map(c=>c.dataset.id).filter(Boolean); }
async function bulkDeleteItems(itemSel, deleteFn, reloadFn, label){
  const ids=bulkSelectedIds(itemSel);
  if(!ids.length){toast('선택된 항목이 없습니다');return;}
  if(!confirm(`${label||''} 선택 ${ids.length}건을 삭제합니다. 계속할까요?`))return;
  let ok=0; for(const id of ids){ try{ await deleteFn(id); ok++; }catch(_){} }
  toast(`${ok}/${ids.length}건 삭제했습니다`); if(typeof reloadFn==='function')reloadFn();
}
async function bulkDeleteAll(getIds, deleteFn, reloadFn, label){
  const ids=(typeof getIds==='function'?getIds():getIds)||[];
  if(!ids.length){toast('삭제할 항목이 없습니다');return;}
  if(!confirm(`⚠ ${label||''} 전체 ${ids.length}건을 삭제합니다. 되돌릴 수 없습니다. 계속할까요?`))return;
  let ok=0; for(const id of ids){ try{ await deleteFn(id); ok++; }catch(_){} }
  toast(`${ok}/${ids.length}건 삭제했습니다`); if(typeof reloadFn==='function')reloadFn();
}
/* ── 공용: 표 컬럼 정렬 (table.srt 헤더 클릭) ── */
const SRT_STATE={};
function applySrtState(table){
  try{ const idEl=table&&table.closest('[id]'); const k=idEl&&idEl.id; const s=k&&SRT_STATE[k]; if(!s)return;
    const headRow=[...table.rows].find(r=>r.querySelector('th')); if(!headRow)return;
    const th=headRow.children[s.col]; if(!th||th.querySelector('input,select,button')||th.classList.contains('nosort'))return;
    th.setAttribute('data-srt', s.dir==='asc'?'desc':'asc'); hubSortTable(table,s.col,th);
  }catch(_){}
}
function hubSortTable(table, colIdx, th){
  const allRows=[...table.rows];
  let headIdx=allRows.findIndex(r=>r.querySelector('th')); if(headIdx<0)headIdx=0;
  const dataRows=allRows.filter((r,i)=>i>headIdx && !r.querySelector('th'));
  if(dataRows.length<2)return;
  const dir=th.getAttribute('data-srt')==='asc'?'desc':'asc';
  [...th.parentElement.children].forEach(c=>{c.removeAttribute('data-srt');const a=c.querySelector('.srt-ar');if(a)a.remove();});
  th.setAttribute('data-srt',dir);
  const cellVal=r=>{const c=r.children[colIdx];if(!c)return '';return String(c.getAttribute('data-sort')??c.textContent).trim();};
  const numericRe=/^[\s\d.,%\-+]+$/;
  const isDate=s=>/^\d{4}-\d{2}-\d{2}/.test(s);
  dataRows.sort((a,b)=>{
    const x=cellVal(a),y=cellVal(b);
    if(x===''&&y!=='')return 1; if(y===''&&x!=='')return -1; if(x===''&&y==='')return 0;
    let cmp;
    if(isDate(x)&&isDate(y))cmp=x.localeCompare(y);
    else if(numericRe.test(x)&&numericRe.test(y)){const nx=parseFloat(x.replace(/[,\s%]/g,'')),ny=parseFloat(y.replace(/[,\s%]/g,''));cmp=(isNaN(nx)?0:nx)-(isNaN(ny)?0:ny);}
    else cmp=x.localeCompare(y,'ko',{numeric:true});
    return dir==='asc'?cmp:-cmp;
  });
  const parent=dataRows[0].parentNode;
  dataRows.forEach(r=>parent.appendChild(r));
  const ar=document.createElement('span'); ar.className='srt-ar'; ar.textContent=dir==='asc'?'▲':'▼'; th.appendChild(ar);
  try{ const idEl=table.closest('[id]'); if(idEl&&idEl.id)SRT_STATE[idEl.id]={col:colIdx,dir}; }catch(_){}
}
document.addEventListener('click',function(e){
  const th=e.target.closest('th'); if(!th)return;
  const table=th.closest('table.srt'); if(!table)return;
  if(!th.parentElement.querySelector('th'))return;
  if(th.querySelector('input,select,button')||th.classList.contains('nosort'))return;
  hubSortTable(table, [...th.parentElement.children].indexOf(th), th);
});
function hubApi(path,options={}){
  return fetch(`${WORKERS}${path}`,{
    ...options,
    headers:authHeaders({'Content-Type':'application/json',...(options.headers||{})})
  }).then(async r=>{const d=await r.json().catch(()=>({ok:false,message:'응답 파싱 실패'}));if(!r.ok||d.ok===false)throw new Error(d.message||`HTTP ${r.status}`);return d;});
}
function api(path,options={}){return hubApi(path,options);}
const updateSyncMetaV154=updateSyncMeta;
updateSyncMeta=function(meta=SYNC_META){
  updateSyncMetaV154(meta);
  const el=document.getElementById('sync-meta');
  if(el){
    const range=SYNC_META?.rangeMonths||localStorage.getItem('jira_range_months')||'-';
    const count=SYNC_META?.count!=null?`${SYNC_META.count}건`:(ISSUES.length?`${ISSUES.length}건`:'-');
    const when=SYNC_META?.syncedAt?fdt(SYNC_META.syncedAt):'-';
    el.textContent=`최근 ${range}개월 · ${count} · ${when}`;
  }
};
function enterApp(){
  document.body.classList.add('app-entered');
  document.body.classList.toggle('is-admin', !!(IS_ADMIN||IS_SUPER));
  document.body.classList.toggle('is-super', !!IS_SUPER);
  document.getElementById('cfg').style.display='none';
  document.getElementById('app').style.display='flex';
  if(IS_ADMIN||IS_SUPER){const audit=document.getElementById('nav-audit');if(audit)audit.style.display='flex';}
  if(IS_SUPER){const settings=document.getElementById('nav-settings');if(settings)settings.style.display='flex';}
  {const md=document.getElementById('nav-mydesk');if(md)md.style.display='flex';}
  updateNavGroups();
  renderSidebarCompact();
  const ai=document.getElementById('ai-status');if(ai){ai.textContent='준비됨';ai.className='h-state ok';}
  startSessionTimer();
  syncJira();
  loadAIUsage({reason:'login'});
  loadSyncMeta();
  renderVTHistory();
  bindFileUpload();
  loadEOS();
  loadLinks();
  loadEosWarnDays();
  loadKnowledge();
}
injectV154Style();injectV155Style();try{renderSidebarCompact();}catch(e){console.warn('sidebar init failed',e);}



/* ── 모바일 검색 오버레이 ── */
function openMobSearch(){
  const overlay=document.getElementById('mob-search-overlay');
  if(!overlay)return;
  overlay.classList.add('show');
  const inp=document.getElementById('mob-search-input');
  if(inp){inp.value='';setTimeout(()=>inp.focus(),60);}
}
function closeMobSearch(){
  const overlay=document.getElementById('mob-search-overlay');
  if(overlay)overlay.classList.remove('show');
}
function onMobSearch(val){
  const page=document.querySelector('.page.active');
  if(!page)return;
  const id=page.id.replace('page-','');
  const map={issues:'f-q',cases:'case-q',customers:'cust-q',links:'links-q',eos:'eos-q',knowledge:'know-q',vt:'vt-input'};
  const inputId=map[id];
  if(!inputId)return;
  const el=document.getElementById(inputId);
  if(el){el.value=val;el.dispatchEvent(new Event('input',{bubbles:true}));}
}

/* ── 모바일 바텀 시트 ── */
function openMobSheet(){
  document.getElementById('mob-sheet-overlay')?.classList.add('show');
  document.getElementById('mob-sheet')?.classList.add('show');
  document.body.style.overflow='hidden';
}
function closeMobSheet(){
  document.getElementById('mob-sheet-overlay')?.classList.remove('show');
  document.getElementById('mob-sheet')?.classList.remove('show');
  document.body.style.overflow='';
}
function syncMobSheet(panelId){
  if(window.innerWidth>700)return;
  const panel=document.getElementById(panelId);
  const sheet=document.getElementById('mob-sheet-body');
  if(panel&&sheet){sheet.innerHTML=panel.innerHTML;}
}

/* ── v1.5.8: mobile app polish + admin alignment ───────────── */
/* ── v1.5.11: session revoke + comment feed ───────────── */
/* mobile primary nav + compact admin settings */
const MOBILE_PRIMARY_NAV=['nav-dash','nav-issues','nav-cases','nav-customers'];
const MOBILE_MORE_NAV=['nav-mydesk','nav-sales','nav-eos','nav-compat','nav-log','nav-vt','nav-nsis','nav-links','nav-knowledge','nav-monitor','nav-audit','nav-settings'];
const MOBILE_NAV_LABELS={sales:'영업 현황',eos:'라이선스',log:'로그 분석기',vt:'VirusTotal',links:'업무 링크',knowledge:'팀 노하우',audit:'감사 로그',settings:'관리자 설정',mydesk:'My Desk',compat:'호환성 매트릭스',nsis:'NSIS 분석기',monitor:'팀 모니터'};
function mobilePageNameFromNav(id){return String(id||'').replace(/^nav-/,'');}
function canShowMobileMoreItem(id){
  if(id==='nav-audit')return !!(IS_ADMIN||IS_SUPER);
  if(id==='nav-settings')return !!IS_SUPER;
  if(id==='nav-monitor')return !!(typeof MONITOR_ALLOWED!=='undefined'&&MONITOR_ALLOWED&&(typeof FEATURE_FLAGS==='undefined'||FEATURE_FLAGS.monitor!==false));
  const el=document.getElementById(id); if(!el)return false;
  if(el.classList.contains('feat-off'))return false;            // 기능 토글 OFF
  return el.style.display!=='none';                              // 역할/숨김 존중
}
function toggleNavGroup(head){const g=head&&head.closest('.sb-group');if(g)g.classList.toggle('collapsed');}
function updateNavGroups(){
  document.querySelectorAll('#app .sb-group').forEach(g=>{
    const hasVisible=[...g.querySelectorAll('.sb-btn')].some(b=>b.style.display!=='none');
    g.style.display=hasVisible?'':'none';
  });
}