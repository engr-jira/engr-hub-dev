
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
  try{ const d=await hubApi('/features',{method:'POST',body:JSON.stringify({flags})}); FEATURE_FLAGS={...FEATURE_FLAGS,...(d.flags||{})}; applyFeatureFlags(); renderFeatureFlagsAdmin(); if(typeof applyMonitorVisibility==='function')applyMonitorVisibility(); toast('기능 토글을 저장했습니다'); }
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
  if(cls.customer)return ` <span class="badge" style="background:#34d39922;color:var(--success)">${escapeHtml(cls.customer)}</span>`;
  if(cls.kind==='vendorcase')return ' <span class="badge" style="background:#60a5fa22;color:var(--cyan)">벤더케이스</span>';
  if(cls.kind==='unclassified')return ` <span class="badge" style="background:#fbbf2422;color:var(--warn)" title="${escapeAttr(cls.bracket||'')}">미분류 ⚑</span>`;
  if(cls.kind==='internal')return ' <span class="badge" style="background:#94a3b822;color:var(--text3)">내부</span>';
  return '';
}
// #6 월간 지원 리포트(ESCARE_DLP_Monthly) 컬럼 형식으로 출력.
// Jira에서 채울 수 있는 항목만 자동 기입, 나머지(지원시간·서비스유형·지원유형·서비스방법 등)는 공란(리포트 작성 시 보완).
const HIST_WD=['일','월','화','수','목','금','토'];
const HIST_COLS=['Year','Month','Date','지원시간','hr.','제품명(관련 항목)','지원 내역','고객담당자','담당자','서비스 유형','지원유형','서비스 방법','Remark','지원그룹'];
function histRowCells(i){
  const c=(i.created||'').slice(0,10);
  const dt=c?new Date(c+'T00:00:00'):null;
  const wd=(dt&&!isNaN(dt))?HIST_WD[dt.getDay()]:'';
  const year=c.slice(0,4)||'';
  const mon=c.slice(5,7)?String(parseInt(c.slice(5,7),10)):'';
  const dayN=c.slice(8,10)?String(parseInt(c.slice(8,10),10)):'';
  const date=dayN?`${dayN}${wd?'('+wd+')':''}`:'';
  const prod=(i.labels||[]).join(', ');
  return { year, mon, date, support:'', hr:'', prod, detail:(i.summary||''), custMgr:'', assignee:(i.assignee||''), svcType:'', supType:'', svcMethod:'', remark:(i.key||''), group:'' };
}
function renderHistoryResults(){
  const res=document.getElementById('ch-results'); if(!res)return;
  if(!HISTORY_ITEMS.length){ res.innerHTML='<div class="muted" style="padding:16px">결과가 없습니다.</div>'; return; }
  const rows=HISTORY_ITEMS.map(i=>{
    const r=histRowCells(i);
    return `<tr>
    <td class="u-ws-nowrap">${escapeHtml(r.year)}</td>
    <td class="u-ws-nowrap">${escapeHtml(r.mon)}</td>
    <td class="u-ws-nowrap">${escapeHtml(r.date)}</td>
    <td></td>
    <td></td>
    <td class="u-ws-nowrap">${escapeHtml(r.prod)}</td>
    <td style="max-width:360px"><a href="https://escare-engr.atlassian.net/browse/${escapeAttr(i.key)}" target="_blank" rel="noopener" style="color:var(--cyan)">${escapeHtml(r.detail)}</a>${histClsBadge(i.cls)}</td>
    <td></td>
    <td class="u-ws-nowrap">${escapeHtml(r.assignee)}</td>
    <td></td>
    <td></td>
    <td></td>
    <td class="u-ws-nowrap"><a href="https://escare-engr.atlassian.net/browse/${escapeAttr(i.key)}" target="_blank" rel="noopener" style="color:var(--text3)">${escapeHtml(r.remark)}</a></td>
    <td></td>
  </tr>`;}).join('');
  res.innerHTML=`<div class="u-muted-10" style="margin-bottom:6px">※ Jira에서 채울 수 있는 항목만 자동 기입 · 지원시간·서비스유형·지원유형·서비스방법·고객담당자는 공란(리포트 작성 시 보완)</div>
    <table class="ch-tbl srt"><tr>${HIST_COLS.map(h=>`<th>${escapeHtml(h)}</th>`).join('')}</tr>${rows}</table>`;
  const _st=res.querySelector('table.srt'); if(_st)applySrtState(_st);
}
function copyHistoryTable(){
  if(!HISTORY_ITEMS.length){toast('복사할 결과가 없습니다');return;}
  const lines=[HIST_COLS.join('\t')].concat(HISTORY_ITEMS.map(i=>{
    const r=histRowCells(i);
    return [r.year,r.mon,r.date,r.support,r.hr,r.prod,(r.detail||'').replace(/\s+/g,' '),r.custMgr,r.assignee,r.svcType,r.supType,r.svcMethod,r.remark,r.group].map(v=>v||'').join('\t');
  }));
  navigator.clipboard.writeText(lines.join('\n')).then(()=>toast(`${HISTORY_ITEMS.length}건 복사 (리포트 형식)`)).catch(()=>toast('복사 실패'));
}
/* ── §3 팀 업무 모니터 (mj.park 전용) ─────────────── */
let MONITOR_ALLOWED=false;
function applyMonitorVisibility(){
  const nav=document.getElementById('nav-monitor');
  if(nav)nav.style.display=(MONITOR_ALLOWED && FEATURE_FLAGS.monitor!==false)?'':'none';
  // 팀 다이제스트 버튼은 IA 서브탭(홈: 대시보드/My Desk) 줄에 인라인 렌더 → 허용/토글 변동 시 서브탭 재렌더
  if(typeof renderIASubtabs==='function'){ try{ const cur=((document.querySelector('.page.active')||{}).id||'page-dash').replace('page-',''); renderIASubtabs(cur); }catch(_){} }
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
  const cards=order.map(a=>`<div class="chart-card soft u-mb-8px"><div style="display:flex;justify-content:space-between;font-weight:700;font-size:13px;margin-bottom:6px"><span>${escapeHtml(a)}</span><span class="u-muted">${byA[a].length}건</span></div>${byA[a].map(i=>`<div style="font-size:11.5px;padding:3px 0;border-bottom:1px solid var(--border)"><a href="https://escare-engr.atlassian.net/browse/${escapeAttr(i.key)}" target="_blank" rel="noopener" style="color:var(--cyan)">${escapeHtml(i.key)}</a> <span class="u-muted">${escapeHtml(i.status||'')}</span> ${escapeHtml(i.summary||'')}${histClsBadge(i.cls)}</div>`).join('')}</div>`).join('');
  body.innerHTML=`<div class="muted u-fs115px-mb8px">${escapeHtml(caption)} · 담당 ${order.length}명</div>${flag}${cards||'<div class="muted">결과 없음</div>'}`;
}
/* ── §4 NSIS 설치 스크립트 분석기 ───────────────────── */












/* ── §H 감사로그 마이그레이션 (슈퍼) ─────────────── */
async function loadAuditMigStatus(){
  const el=document.getElementById('audit-mig-status'); if(!el)return;
  try{ const d=await hubApi('/admin/migrate/audit-status'); el.innerHTML=`D1 적재 <b>${d.d1Count}</b>건 · 읽기 소스 <b style="color:${d.readD1?'#3FBE92':'#E0A32E'}">${d.readD1?'D1':'KV(기존)'}</b>`; }
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
  const salesUI=(typeof USER_ROLE!=='undefined'&&USER_ROLE==='sales');
  if(!salesUI){
    // 초기 동기화 동안 랜딩(대시보드)이 빈 화면으로 보이지 않게 플레이스홀더
    const kw=document.getElementById('kpi-wrap');
    if(kw&&!kw.innerHTML.trim())kw.innerHTML='<div class="loading" style="grid-column:1/-1;padding:18px 4px">Jira 데이터 불러오는 중...</div>';
    const dl=document.getElementById('dash-list');
    if(dl&&!dl.innerHTML.trim())dl.innerHTML='<div class="empty">Jira 동기화 중...</div>';
    syncJira();
    renderVTHistory();
    loadLinks();
    loadKnowledge();
    if(typeof loadCustomerAliases==='function')loadCustomerAliases();
  }
  // sales 역할은 서버 화이트리스트가 /jira·/links·/knowledge·/vt를 차단 — 호출 자체를 생략(403 오탐 토스트 방지)
  loadSyncMeta();
  loadEOS();
  loadEosWarnDays();
  if(typeof loadCustomerOwners==='function')loadCustomerOwners();
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
const MOBILE_PRIMARY_NAV=['nav-dash','nav-issues','nav-customers','nav-sales'];
const MOBILE_MORE_NAV=['nav-vt','nav-links','nav-audit'];
const MOBILE_NAV_LABELS={vt:'도구 (VT)',links:'자료실',audit:'관리'};
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

/* ── A안: 팀 다이제스트 (조회+미리보기+복사만 — 외부 발송 코드 없음) ── */
// 플레인 텍스트 → Teams용 서식 HTML(인라인 스타일만, emoji·bold·색·CTA 링크)
function digestToHtml(text){
  const esc=s=>escapeHtml(String(s||''));
  const A='#D9603B';
  const rows=[];
  String(text||'').split('\n').forEach(raw=>{
    const line=raw.replace(/\s+$/,'');
    if(!line.trim())return;
    if(/^(📋|📰)/.test(line)){ rows.push(`<div style="font-size:18px;font-weight:800;color:${A};letter-spacing:-.2px">${esc(line)}</div>`); return; }
    if(/^⚡/.test(line)){ rows.push(`<div style="display:inline-block;background:#FBEFE6;color:#8A3417;font-weight:700;font-size:12.5px;padding:5px 12px;border-radius:20px;margin:7px 0 3px">${esc(line)}</div>`); return; }
    if(/^🎉/.test(line)){ rows.push(`<div style="font-size:14px;color:#1E9E6A;font-weight:700;margin:8px 0">${esc(line)}</div>`); return; }
    if(/^🔗/.test(line)){
      const m=line.match(/(https?:\/\/[^\s]+)/); const url=m?m[1]:'#';
      rows.push(`<div style="margin:15px 0 2px"><a href="${esc(url)}" style="display:inline-block;background:${A};color:#ffffff;font-weight:800;font-size:13px;text-decoration:none;padding:10px 20px;border-radius:8px">👉 HUB에서 전체 보기</a></div>`);
      return;
    }
    if(/^(🗞|🚨|🏢|📚|📌)/.test(line)){ rows.push(`<div style="font-size:14px;font-weight:800;color:#8A3417;background:linear-gradient(90deg,#FBEFE6,rgba(251,239,230,0));border-left:4px solid ${A};padding:8px 12px;border-radius:0 8px 8px 0;margin:16px 0 7px">${esc(line)}</div>`); return; }
    if(/^(⏰|🔴|📄|📝)/.test(line)){
      const col=/^🔴/.test(line)?'#C94540':(/^📄/.test(line)?'#B27E00':(/^📝/.test(line)?'#8A5CC4':'#1E9E6A'));
      rows.push(`<div style="font-size:13.5px;font-weight:800;color:${col};margin:13px 0 5px;border-bottom:1px solid #EEE4D5;padding-bottom:3px">${esc(line)}</div>`);
      return;
    }
    if(/^·/.test(line)){
      let b=esc(line.replace(/^·\s*/,''));
      b=b.replace(/(\[[^\]]+\])/,'<b style="color:#5C4E3A">$1</b>');
      b=b.replace(/(\((?:D\+\d+,\s*)?ENGR-\d+\))/g,'<span style="color:#9A8C79;font-size:12px">$1</span>');
      b=b.replace(/(\([^)]*(?:고객사|레이블|범주|기한)[^)]*\))/,'<span style="color:#9A8C79;font-size:12px">$1</span>');
      rows.push(`<div style="font-size:13px;line-height:1.55;margin:3px 0 3px 2px;color:#2A2420">• ${b}</div>`);
      return;
    }
    rows.push(`<div style="font-size:13px;color:#2A2420;margin:2px 0">${esc(line)}</div>`);
  });
  return `<div style="font-family:'Segoe UI',Roboto,system-ui,sans-serif;max-width:580px;border:1px solid #E7DFD2;border-left:4px solid ${A};border-radius:12px;padding:16px 20px;background:#FFFFFF;color:#2A2420">${rows.join('')}</div>`;
}
function digestToTeamsHtml(text){
  // Teams 입력창은 인라인 CSS(색·배경·테두리)를 벗겨내므로, 붙여넣기 때 보존되는 시맨틱 태그(h2/h3/ul/li/hr/b/a)로 조립
  const esc=s=>escapeHtml(String(s||''));
  const rows=[]; let inList=false;
  const closeList=()=>{ if(inList){ rows.push('</ul>'); inList=false; } };
  String(text||'').split('\n').forEach(raw=>{
    const line=raw.replace(/\s+$/,'');
    if(!line.trim())return;
    if(/^📢/.test(line)){ closeList(); rows.push(`<p><b>${esc(line)}</b></p>`); return; }
    if(/^(📋|📰)/.test(line)){ closeList(); rows.push(`<h2>${esc(line)}</h2>`); return; }
    if(/^⚡/.test(line)){ closeList(); rows.push(`<p><b>${esc(line)}</b></p>`); return; }
    if(/^🎉/.test(line)){ closeList(); rows.push(`<p><b>${esc(line)}</b></p>`); return; }
    if(/^🔗/.test(line)){ closeList(); const m=line.match(/(https?:\/\/[^\s]+)/); const url=m?m[1]:'#'; rows.push(`<p><a href="${esc(url)}"><b>👉 HUB에서 전체 보기</b></a></p>`); return; }
    if(/^(🗞|🚨|🏢|📚|📌)/.test(line)){ closeList(); rows.push('<hr><h3>'+esc(line)+'</h3>'); return; }
    if(/^(⏰|🔴|📄|📝)/.test(line)){ closeList(); rows.push(`<p><b>${esc(line)}</b></p>`); return; }
    if(/^·/.test(line)){ if(!inList){ rows.push('<ul>'); inList=true; } let b=esc(line.replace(/^·\s*/,'')); b=b.replace(/(\[[^\]]+\])/,'<b>$1</b>'); rows.push(`<li>${b}</li>`); return; }
    closeList(); rows.push(`<p>${esc(line)}</p>`);
  });
  closeList();
  return `<div>${rows.join('')}</div>`;
}
function digestFullText(){
  const ta=document.getElementById('digest-text'), nt=document.getElementById('digest-notice');
  const nlines=((nt&&nt.value)||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const base=(ta&&ta.value)||'';
  return (nlines.length?('📢 공지사항\n'+nlines.map(l=>'· '+l).join('\n')+'\n\n'):'')+base;
}
function renderDigestPreview(){
  const pv=document.getElementById('digest-preview');
  if(pv)pv.innerHTML=digestToTeamsHtml(digestFullText());
}
async function openDigest(){
  const modal=document.getElementById('digest-modal'); if(!modal)return;
  const ta=document.getElementById('digest-text'), st=document.getElementById('digest-status');
  modal.style.display='flex'; if(st){st.textContent='';st.style.color='';} if(ta)ta.value='생성 중...'; renderDigestPreview();
  loadDigestRecipients();
  try{
    const d=await hubApi('/team/digest');
    const text=String(d.text||'').replace('{HUB_URL}', location.origin+location.pathname);
    if(ta)ta.value=text;
    // 저장된 공지 복원(지정 날짜까지 유지 — cron 자동 게시에도 동일 적용)
    const nt=document.getElementById('digest-notice'), ns=document.getElementById('digest-notice-state');
    if(nt)nt.value=String(d.notice||'');
    if(ns)ns.innerHTML=d.noticeExpired?'<span style="color:var(--warn)">⚠️ 이전 공지 만료됨(미게시)</span>':(d.notice?`<span style="color:var(--success)">✓ 저장됨${d.noticeUntil?' · '+escapeHtml(d.noticeUntil)+'까지':' · 무기한'}</span>`:'');
    renderDigestPreview();
    if(st){const s=d.sections||{};const mi=(s.metaIncomplete||[]).reduce((a,r)=>a+(r.count||0),0);st.textContent=`마감 ${s.dueToday?.length||0} · 지연 ${s.overdue?.length||0} · 미기입 ${mi} · 라이선스 ${s.licenseSoon?.length||0}${(s.doneYesterday||[]).length?' · 어제완료 '+s.doneYesterday.length:''}${(s.headline||[]).length?' · 헤드라인 '+s.headline.length:''}`;}
  }catch(e){ if(ta)ta.value=''; renderDigestPreview(); if(st){st.textContent='생성 실패: '+e.message;st.style.color='var(--danger)';} }
}
async function copyDigest(){
  const st=document.getElementById('digest-status');
  const text=digestFullText().trim();
  if(!text){ if(st){st.textContent='내용이 없습니다';st.style.color='var(--danger)';} return; }
  const html=digestToTeamsHtml(text);
  try{
    if(navigator.clipboard&&window.ClipboardItem){
      await navigator.clipboard.write([new ClipboardItem({'text/html':new Blob([html],{type:'text/html'}),'text/plain':new Blob([text],{type:'text/plain'})})]);
    }else{ await navigator.clipboard.writeText(text); }
    if(st){st.textContent='✓ 서식 복사됨 — Teams에 붙여넣기';st.style.color='var(--success)';}
    if(typeof toast==='function')toast('다이제스트 복사됨 — Teams에 붙여넣기');
  }catch(e){
    try{ await navigator.clipboard.writeText(text); if(st){st.textContent='✓ 복사됨(텍스트)';st.style.color='var(--success)';} }
    catch(_){ if(st){st.textContent='복사 실패 — 직접 선택해 복사하세요';st.style.color='var(--danger)';} }
  }
}
async function saveDigestNotice(){
  const nt=document.getElementById('digest-notice'), ns=document.getElementById('digest-notice-state');
  const text=((nt&&nt.value)||'').trim();
  const days=parseInt((document.getElementById('digest-notice-days')||{}).value||'6');
  if(!text){ if(ns)ns.innerHTML='<span style="color:var(--danger)">공지 내용이 비어 있습니다</span>'; return; }
  try{
    const r=await hubApi('/team/digest/notice',{method:'POST',body:JSON.stringify({text,days})});
    if(ns)ns.innerHTML=`<span style="color:var(--success)">✓ 저장됨${r.until?' · '+escapeHtml(r.until)+'까지 유지':' · 무기한'}</span>`;
    if(typeof toast==='function')toast('공지 저장됨 — 자동 게시에도 포함됩니다');
  }catch(e){ if(ns)ns.innerHTML=`<span style="color:var(--danger)">저장 실패: ${escapeHtml(e.message)}</span>`; }
}
async function clearDigestNotice(){
  if(!confirm('저장된 공지를 삭제합니다. 계속할까요?'))return;
  const nt=document.getElementById('digest-notice'), ns=document.getElementById('digest-notice-state');
  try{
    await hubApi('/team/digest/notice',{method:'POST',body:JSON.stringify({text:''})});
    if(nt)nt.value=''; if(ns)ns.innerHTML='<span class="u-muted-10">공지 없음</span>';
    renderDigestPreview();
    if(typeof toast==='function')toast('공지 삭제됨');
  }catch(e){ if(ns)ns.innerHTML=`<span style="color:var(--danger)">삭제 실패: ${escapeHtml(e.message)}</span>`; }
}
// ── 개인 브리핑 수신 대상 (off/test/allow/all) — 전송 축소는 워커가 수행, 여기선 설정만 ──
var __DG_PEOPLE=[];
var DG_MODE_HINT={
  off:'⏸ 자동·수동 모두 아무에게도 발송되지 않습니다.',
  test:'🧪 모든 사람의 카드가 <b>지정한 1명</b>에게만 갑니다. 카드 상단에 원래 수신자가 표시됩니다.',
  allow:'✅ 체크한 사람에게만 <b>각자 본인 카드</b>가 갑니다. 체크 안 된 사람은 발송 제외.',
  all:'📢 대상 전원에게 각자 본인 카드가 갑니다. (챙길 것이 없는 사람은 자동 제외)'
};
function onDigestRcpMode(){
  const mode=((document.getElementById('digest-rcp-mode')||{}).value)||'test';
  const wrap=document.getElementById('digest-rcp-people'), tt=document.getElementById('digest-rcp-testto'), hint=document.getElementById('digest-rcp-hint');
  if(wrap)wrap.style.display=(mode==='allow')?'flex':'none';
  if(tt)tt.style.display=(mode==='test')?'':'none';
  if(hint)hint.innerHTML=DG_MODE_HINT[mode]||'';
}
async function loadDigestRecipients(){
  const st=document.getElementById('digest-rcp-state');
  try{
    const d=await hubApi('/team/digest/recipients');
    __DG_PEOPLE=d.people||[];
    const ms=document.getElementById('digest-rcp-mode'); if(ms)ms.value=d.mode||'test';
    const tt=document.getElementById('digest-rcp-testto');
    if(tt)tt.innerHTML=__DG_PEOPLE.map(p=>`<option value="${escapeHtml(p.id)}"${p.id===d.testTo?' selected':''}>${escapeHtml(p.name)}</option>`).join('')||`<option value="${escapeHtml(d.testTo||'')}">${escapeHtml(d.testTo||'')}</option>`;
    const allow=new Set(d.allow||[]);
    const wrap=document.getElementById('digest-rcp-people');
    if(wrap)wrap.innerHTML=__DG_PEOPLE.map(p=>`<label style="display:inline-flex;align-items:center;gap:5px;font-size:11.5px;cursor:pointer"><input type="checkbox" class="dg-rcp-chk" value="${escapeHtml(p.id)}"${allow.has(p.id)?' checked':''}> ${escapeHtml(p.name)}</label>`).join('');
    if(st)st.innerHTML=d.hasWebhook?'':'<span style="color:var(--warn)">⚠️ Teams 웹훅 미설정 — 발사는 동작하지 않습니다</span>';
    onDigestRcpMode();
  }catch(e){ if(st)st.innerHTML=`<span style="color:var(--danger)">대상 불러오기 실패: ${escapeHtml(e.message)}</span>`; }
}
async function saveDigestRecipients(){
  const st=document.getElementById('digest-rcp-state');
  const mode=((document.getElementById('digest-rcp-mode')||{}).value)||'test';
  const testTo=((document.getElementById('digest-rcp-testto')||{}).value)||'mj.park';
  const allow=[...document.querySelectorAll('.dg-rcp-chk:checked')].map(c=>c.value);
  if(mode==='allow'&&!allow.length){ if(st)st.innerHTML='<span style="color:var(--danger)">지정 인원을 1명 이상 체크하세요</span>'; return; }
  if(mode==='all'&&!confirm('수신 대상을 "전원"으로 바꿉니다.\n이후 자동 발송(매일 08:30)이 대상자 전원에게 나갑니다. 계속할까요?'))return;
  try{
    const r=await hubApi('/team/digest/recipients',{method:'POST',body:JSON.stringify({mode,testTo,allow})});
    const label={off:'중단',test:'테스트→'+testTo,allow:'지정 '+r.allow.length+'명',all:'전원'}[r.mode]||r.mode;
    if(st)st.innerHTML=`<span style="color:var(--success)">✓ 저장됨 · ${escapeHtml(label)}</span>`;
    if(typeof toast==='function')toast('수신 대상 저장됨 — 자동 발송에도 적용됩니다');
  }catch(e){ if(st)st.innerHTML=`<span style="color:var(--danger)">저장 실패: ${escapeHtml(e.message)}</span>`; }
}
async function pushPersonalDigest(){
  const st=document.getElementById('digest-status');
  const mode=((document.getElementById('digest-rcp-mode')||{}).value)||'test';
  if(mode==='off'){ if(st){st.textContent='수신 대상이 "중단"입니다 — 발송하지 않습니다';st.style.color='var(--warn)';} return; }
  if(st){st.textContent='대상 확인 중...';st.style.color='';}
  let pre; try{ pre=await hubApi('/team/digest/personal'); }catch(e){ if(st){st.textContent='대상 확인 실패: '+e.message;st.style.color='var(--danger)';} return; }
  if(!pre.willSend){ if(st){st.textContent=`발송 대상 0명 (생성 ${pre.count}명 · 정책 ${pre.mode})`;st.style.color='var(--warn)';} return; }
  const who=(pre.sendTo||[]).map(r=>r.testOf?`${r.testOf}→${r.userId}`:r.assignee).join(', ');
  const head=pre.mode==='test'?`🧪 테스트 — 아래 ${pre.willSend}건이 모두 "${(pre.sendTo[0]||{}).userId||''}" 1명에게만 갑니다.`:`📬 ${pre.willSend}명에게 각자 본인 카드를 보냅니다.`;
  if(!confirm(`${head}\n\n${who}\n\n계속할까요?`))return;
  if(st){st.textContent='📬 발사 중...';st.style.color='';}
  try{
    const r=await hubApi('/team/digest/personal',{method:'POST'});
    if(st){st.textContent=`✓ ${r.sent}건 전송${r.failed?` · 실패 ${r.failed}`:''} (모드 ${r.mode})`;st.style.color=r.failed?'var(--warn)':'var(--success)';}
    if(typeof toast==='function')toast(`개인 브리핑 ${r.sent}건 전송됨`);
  }catch(e){
    if(st){st.textContent='발사 실패: '+e.message;st.style.color='var(--danger)';}
    if(typeof toast==='function')toast('발사 실패: '+e.message,true);
  }
}
window.openDigest=openDigest; window.copyDigest=copyDigest; window.renderDigestPreview=renderDigestPreview; window.saveDigestNotice=saveDigestNotice; window.clearDigestNotice=clearDigestNotice;
window.onDigestRcpMode=onDigestRcpMode; window.saveDigestRecipients=saveDigestRecipients; window.pushPersonalDigest=pushPersonalDigest;