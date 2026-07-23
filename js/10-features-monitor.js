
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
  loadSyncMeta();
  renderVTHistory();
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