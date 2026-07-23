
async function refreshStorageStats(){
  const wrap=document.getElementById('storage-stats-wrap');
  const btn=document.getElementById('storage-stats-btn');
  if(!wrap||!btn)return;
  const old=btn.textContent;
  btn.disabled=true;btn.textContent='조회 중...';
  wrap.innerHTML='<div class="loading">저장소 현황 조회 중...</div>';
  try{
    const r=await fetch(`${WORKERS}/admin/storage/stats`,{headers:authHeaders()});
    const d=await r.json();
    if(!d.ok)throw new Error(d.message||'조회 실패');
    const summary=d.summary||{};
    const used=Number(summary.usedBytes||0);
    const quota=Number(summary.quotaBytes||0);
    const pct=quota>0?Math.min(100,(used/quota)*100):0;
    const itemCount=summary.itemCount||'-';
    const quotaLabel=summary.quotaLabel||fmtBytes(quota);
    const ops=summary.operationBudget||{};
    const limits=ops.dailyLimits||{};
    const opPct=Number(ops.estimatedNewWritePct||0);
    const opColor=opPct>=90?'var(--danger)':(opPct>=70?'var(--warn)':'var(--success)');
    const opHtml=ops.dailyLimits?`
      <div class="storage-summary u-mt-10px">
        <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:10px">
          <div>
            <div style="font-size:12px;font-weight:900;color:#eaf0ff">Cloudflare KV Operation 사용량</div>
            <div class="storage-note">Free 기준 일일 한도: read ${Number(limits.reads||0).toLocaleString()} / write ${Number(limits.writes||0).toLocaleString()} / list ${Number(limits.lists||0).toLocaleString()} / delete ${Number(limits.deletes||0).toLocaleString()} · UTC ${escapeHtml(ops.resetAtUtc||'00:00')} 리셋</div>
          </div>
          <div style="text-align:right;font-size:11px;color:var(--text3)">AI 오늘 ${ops.aiToday||0}회 · 이번달 ${ops.aiMonth||0}회</div>
        </div>
        <div class="storage-summary-top">
          <div class="storage-metric"><div class="label">AI 기준 예상 write</div><div class="value" style="color:${opColor}">${ops.estimatedNewAiWritesToday||0} / ${limits.writes||1000}</div></div>
          <div class="storage-metric"><div class="label">기존 구조였다면</div><div class="value">${ops.estimatedOldAiWritesToday||0}</div></div>
          <div class="storage-metric"><div class="label">오늘 절감 추정</div><div class="value u-c-success">${ops.estimatedSavedWritesToday||0}</div></div>
          <div class="storage-metric"><div class="label">AI 성공 / 실패</div><div class="value">${ops.aiSuccessToday||0} / ${ops.aiFailToday||0}</div></div>
        </div>
        <div class="storage-bar"><div class="storage-bar-fill" style="width:${Math.max(0.2,Math.min(100,opPct))}%;background:${opColor}"></div></div>
        <div class="storage-grid u-mt-10px">
          ${(ops.reductions||[]).map(x=>`<div class="storage-item"><div class="storage-item-title">${escapeHtml(x.item)}</div><small>이전: ${escapeHtml(x.before)}</small><small class="u-c-success">현재: ${escapeHtml(x.after)}</small></div>`).join('')}
        </div>
        <div class="storage-note">${(ops.notes||[]).map(escapeHtml).join(' · ')}</div>
      </div>`:'';
    const status=pct>=90?'위험':(pct>=70?'주의':'정상');
    const statusColor=pct>=90?'var(--danger)':(pct>=70?'var(--warn)':'var(--success)');
    const alertHtml=pct>=90
      ? '<div class="storage-alert danger">⚠ 저장소 사용률이 위험 기준(90%) 이상입니다. 백업 후 AI 캐시/오래된 감사 로그 정리를 우선 검토하세요.</div>'
      : (pct>=70?'<div class="storage-alert">⚠ 저장소 사용률이 주의 기준(70%) 이상입니다. 데이터 증가 추이를 확인하고 정리 계획을 준비하세요.</div>':'');
    wrap.innerHTML=`
      ${alertHtml}
      <div class="storage-summary">
        <div class="storage-summary-top">
          <div class="storage-metric"><div class="label">총 저장소 기준</div><div class="value">${escapeHtml(quotaLabel)}</div></div>
          <div class="storage-metric"><div class="label">현재 사용량</div><div class="value">${fmtBytes(used)}</div></div>
          <div class="storage-metric"><div class="label">사용률</div><div class="value" style="color:${statusColor}">${pct.toFixed(3)}%</div></div>
          <div class="storage-metric"><div class="label">상태 / 항목</div><div class="value" style="color:${statusColor}">${status} · ${itemCount}개</div></div>
        </div>
        <div class="storage-bar"><div class="storage-bar-fill" style="width:${Math.max(0.2,pct)}%;background:${pct>=90?'var(--danger)':(pct>=70?'var(--warn)':'linear-gradient(90deg,#2de6b8,#818cf8)')}"></div></div>
        <div class="storage-note">기준: ${escapeHtml(summary.quotaNote||'Cloudflare Workers KV 기본 저장소 1GB 기준')} · 감사 로그/AI 캐시는 표본 기반 추정치가 포함될 수 있습니다.</div>
      </div>
      ${opHtml}
      <div class="storage-grid">
        ${(d.items||[]).map(x=>`<div class="storage-item">
          <div class="storage-item-title">${escapeHtml(x.label)}</div>
          <div>항목: <strong class="u-c-accent3">${escapeHtml(String(x.count??'-'))}</strong></div>
          <div>크기: <strong class="u-c-success">${x.bytes!==undefined?fmtBytes(x.bytes):'-'}</strong>${x.estimated?' <span style="color:var(--warn);font-size:10px">추정</span>':''}</div>
          <small>${escapeHtml(x.note||'')}</small>
        </div>`).join('')}
      </div>
      <div style="margin-top:8px;font-size:10px;color:var(--text3)">갱신 ${fmtClock(d.asOf)} · 삭제/정리 작업은 수행하지 않음</div>`;
    setAdminActionStatus('저장소 / KV 사용량 조회 완료');
  }catch(e){wrap.innerHTML=`<span style="color:var(--danger)">조회 실패: ${escapeHtml(e.message)}</span>`;setAdminActionStatus('저장소 / KV 사용량 조회 실패: '+e.message,'err');}
  finally{btn.disabled=false;btn.textContent=old;}
}

// ── AI CALL ───────────────────────────────────────




// ── v1.5.1: Case 분리 / 필터 이동 / 제조사 신고 ─────────────
let ISSUE_PRESET=null;
let CASE_PRESET=null;

function jsAttr(v){return escapeHtml(JSON.stringify(String(v??'')));}
function withinRecentDays(date,days){
  if(!days)return true;
  if(!date)return false;
  const d=daysSince(date);
  return d>=0&&d<=Number(days);
}
function applyV151Dom(){
  const vtBtn=document.getElementById('vt-btn');
  if(vtBtn&&!document.getElementById('sym-submit-btn')){
    const a=document.createElement('a');
    a.id='sym-submit-btn';
    a.href='https://symsubmit.symantec.com/';
    a.target='_blank';
    a.rel='noopener noreferrer';
    a.innerHTML='<button type="button" class="btn btn-ghost" style="width:auto;padding:12px 18px">🏭 제조사 신고</button>';
    vtBtn.insertAdjacentElement('afterend',a);
  }
  const issuePg=document.getElementById('f-pg');
  if(issuePg&&!document.getElementById('f-date')){
    const sel=document.createElement('select');
    sel.id='f-date';
    sel.onchange=()=>{ISSUE_PRESET=null;PAGE=1;renderIssues();};
    sel.innerHTML='<option value="">전체 기간</option><option value="7">최근 7일</option><option value="30">최근 한달</option><option value="90">최근 3개월</option><option value="180">최근 6개월</option><option value="365">최근 1년</option>';
    issuePg.insertAdjacentElement('beforebegin',sel);
  }
  const casePg=document.getElementById('case-pg');
  if(casePg&&!document.getElementById('case-date')){
    const sel=document.createElement('select');
    sel.id='case-date';
    sel.onchange=()=>{CASE_PRESET=null;PAGE_STATE.cases=1;renderCases();};
    sel.innerHTML='<option value="">전체 기간</option><option value="7">최근 7일</option><option value="30">최근 한달</option><option value="90">최근 3개월</option><option value="180">최근 6개월</option><option value="365">최근 1년</option>';
    casePg.insertAdjacentElement('beforebegin',sel);
  }
  const caseInfo=document.querySelector('#page-cases > div');
  if(caseInfo&&caseInfo.textContent.includes('7자리 이상')){
    caseInfo.innerHTML='📦 <strong>케이스 트래커 분류 기준:</strong> Jira 제목 맨 앞이 <code style="background:rgba(255,255,255,.08);padding:2px 5px;border-radius:5px">[숫자8자리]</code> 형식인 항목만 케이스로 분류합니다. 일반 이슈에 포함된 케이스 번호는 연결 케이스로만 표시합니다.';
  }
  if(!document.getElementById('v151-style')){
    const st=document.createElement('style');
    st.id='v151-style';
    st.textContent=`
      .kpi.clickable{cursor:pointer;transition:transform .12s,border-color .12s,background .12s}.kpi.clickable:hover{transform:translateY(-1px);border-color:rgba(129,140,248,.55);background:rgba(129,140,248,.08)}
      .case-chip{display:inline-flex;align-items:center;gap:4px;border-radius:999px;padding:2px 7px;font-size:10px;font-weight:700;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.06);color:#c5cee8;margin-left:4px}
      .case-chip.done{color:#2de6b8;background:rgba(34,211,165,.12);border-color:rgba(34,211,165,.25)}.case-chip.open{color:#fcd34d;background:rgba(252,211,77,.10);border-color:rgba(252,211,77,.25)}
      .jump-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.jump-row button{width:auto;padding:7px 12px;font-size:11px}
      .case-ai-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-bottom:8px}.case-ai-grid .btn{width:100%;font-size:11px;padding:8px 10px}
    `;
    document.head.appendChild(st);
  }
}
applyV151Dom();




function resetFilters(){
  ['f-q','f-stat','f-pri','f-lab','f-ass','f-date'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  ISSUE_PRESET=null;
  const ib=document.getElementById('f-incomplete-btn');if(ib){ib.style.background='rgba(251,191,36,.12)';ib.style.color='#fbbf24';}
  PAGE=1;renderIssues();
}
function toggleIncompleteFilter(){
  const on=!!(ISSUE_PRESET&&ISSUE_PRESET.kind==='incomplete');
  ISSUE_PRESET=on?null:{kind:'incomplete',label:'메타 미완성 일반 이슈'};
  const ib=document.getElementById('f-incomplete-btn');
  if(ib){ if(!on){ib.style.background='rgba(251,191,36,.28)';ib.style.color='#fff';} else {ib.style.background='rgba(251,191,36,.12)';ib.style.color='#fbbf24';} }
  showPage('issues',document.getElementById('nav-issues'));
  PAGE=1;renderIssues();
}
// ── My Desk 서버(KV) 동기화 — 사용자별, 기기 간 동일 ──
// 데이터 손실 방지 3중 안전장치:
//  (1) 디바운스(600ms) + 최대대기(3s): 연속 입력으로 타이머가 계속 밀려도 3초마다 강제 저장
//  (2) 페이지 이탈(새로고침/탭전환/닫기) 시 keepalive로 보류분 즉시 flush
//  (3) 로드 GET 실패 시 빈 값으로 덮어쓰지 않음 — 로컬 표시 + 서버 저장 보류(서버 원본 보호)
let __mdSaveTimer=null, __mdDirty=false, __mdFirstDirtyTs=0;
function __mdPutStore(useKeepalive){
  __mdDirty=false; __mdFirstDirtyTs=0;
  clearTimeout(__mdSaveTimer); __mdSaveTimer=null;
  const opts={method:'PUT',body:JSON.stringify({store:window.__MD_STORE||{}})};
  if(useKeepalive)opts.keepalive=true;   // 이탈 중에도 전송 보장(본문 64KB 이내)
  try{ return hubApi('/mydesk',opts).catch(()=>{}); }catch(_){ }
}
window.__mdQueueServerSave=function(){
  if(!CURRENT_USER||!window.__mdLoaded)return;
  if(!__mdDirty){ __mdDirty=true; __mdFirstDirtyTs=Date.now(); }
  if(Date.now()-__mdFirstDirtyTs>=3000){ __mdPutStore(false); return; } // 최대대기 초과 → 즉시 저장
  clearTimeout(__mdSaveTimer);
  __mdSaveTimer=setTimeout(()=>__mdPutStore(false),600);
};
window.__mdServerSaveNow=function(){
  if(!CURRENT_USER||!window.__mdLoaded)return;
  __mdPutStore(false);
};
window.__mdFlushNow=function(){
  if(!CURRENT_USER||!window.__mdLoaded||!__mdDirty)return;
  __mdPutStore(true);
};
window.addEventListener('pagehide',()=>{ try{ window.__mdFlushNow&&window.__mdFlushNow(); }catch(_){ } });
document.addEventListener('visibilitychange',()=>{ if(document.visibilityState==='hidden'){ try{ window.__mdFlushNow&&window.__mdFlushNow(); }catch(_){ } } });
// 주기적 백스톱: 보류분이 2초 이상 지나면 강제 저장(keepalive 불안정 대비, 새로고침 직전까지 손실 최소화)
setInterval(()=>{ try{ if(__mdDirty&&CURRENT_USER&&window.__mdLoaded&&Date.now()-__mdFirstDirtyTs>=2000)__mdPutStore(false); }catch(_){ } },2000);
async function loadMyDeskForUser(){
  if(!CURRENT_USER)return;                                   // 로그인 전 호출 차단(빈 사용자로 로드 금지)
  if(window.__mdLoadedUser===CURRENT_USER&&window.__mdInited)return; // 이 사용자로 이미 1회 초기화됨
  if(window.__mdLoading)return;
  window.__mdLoading=true;
  let ok=false;
  try{ const d=await hubApi('/mydesk'); window.__MD_STORE=(d&&d.data)||{}; ok=true; }
  catch(_){ ok=false; }
  if(ok){ window.__mdLoaded=true; }
  else {
    // 서버 로드 실패: 빈 값 덮어쓰기 금지(파괴적 PUT 방지). 로컬값으로 표시하고 서버 저장은 보류.
    window.__mdLoaded=false;
    if(typeof toast==='function')toast('서버 연결이 불안정합니다 — 변경사항이 저장되지 않을 수 있어요. 잠시 후 새로고침 해주세요.');
  }
  window.__mdLoadedUser=CURRENT_USER;
  try{ if(!window.__mdInited){ window.__mdInited=true; if(typeof window.__mydeskInit==='function') await window.__mydeskInit(); } }catch(_){}
  window.__mdLoading=false;
}
function resetMyDesk(){
  if(!confirm('My Desk의 모든 값(루틴·할 일·메모·팀 일보고·주간 미팅·케이스·고객사·단축/원격)을 빈 값으로 초기화합니다.\n되돌릴 수 없습니다. 계속할까요?'))return;
  window.__MD_STORE={};
  try{
    const keys=[];
    for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);if(k&&k.indexOf('escare:')===0)keys.push(k);}
    keys.forEach(k=>localStorage.removeItem(k));
  }catch(_){}
  hubApi('/mydesk',{method:'DELETE'}).catch(()=>{}).finally(()=>{
    toast('My Desk를 초기화했습니다. 새로고침합니다.');
    setTimeout(()=>location.reload(),700);
  });
}
function resetCaseFilters(){
  ['case-q','case-stat','case-ass','case-sla','case-date'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  CASE_PRESET=null;PAGE_STATE.cases=1;renderCases();
}
function renderFilterTags(){
  const tags=[];
  const q=document.getElementById('f-q')?.value;
  const st=document.getElementById('f-stat')?.value;
  const pr=document.getElementById('f-pri')?.value;
  const lb=document.getElementById('f-lab')?.value;
  const ass=document.getElementById('f-ass')?.value;
  const dt=document.getElementById('f-date')?.value;
  if(ISSUE_PRESET){tags.push({label:ISSUE_PRESET.label||'대시보드 필터',clear:()=>{ISSUE_PRESET=null;PAGE=1;renderIssues();}});}
  if(q)tags.push({label:`검색: "${q}"`,clear:()=>{document.getElementById('f-q').value='';PAGE=1;renderIssues();}});
  if(st)tags.push({label:`상태: ${st}`,clear:()=>{document.getElementById('f-stat').value='';PAGE=1;renderIssues();}});
  if(pr)tags.push({label:`우선순위: ${pr}`,clear:()=>{document.getElementById('f-pri').value='';PAGE=1;renderIssues();}});
  if(lb)tags.push({label:`레이블: ${lb}`,clear:()=>{document.getElementById('f-lab').value='';PAGE=1;renderIssues();}});
  if(ass)tags.push({label:`담당자: ${ass}`,clear:()=>{document.getElementById('f-ass').value='';PAGE=1;renderIssues();}});
  if(dt)tags.push({label:`기간: ${v154LabelOfRange(dt)}`,clear:()=>{document.getElementById('f-date').value='';PAGE=1;renderIssues();}});
  const wrap=document.getElementById('active-filter-tags');
  if(!wrap)return;
  wrap.innerHTML=tags.map((t,i)=>`<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.3);color:var(--accent3);border-radius:20px;padding:3px 10px;font-size:11px;font-weight:600">${escapeHtml(t.label)}<span onclick="window._filterClears[${i}]()" style="cursor:pointer;color:var(--accent2);font-size:14px;line-height:1">×</span></span>`).join('');
  window._filterClears=tags.map(t=>t.clear);
}
function filteredIssues(){
  const q=(document.getElementById('f-q')?.value||'').toLowerCase();
  const st=document.getElementById('f-stat')?.value||'';
  const pr=document.getElementById('f-pri')?.value||'';
  const lb=document.getElementById('f-lab')?.value||'';
  const ass=document.getElementById('f-ass')?.value||'';
  const dt=parseInt(document.getElementById('f-date')?.value||'0');
  let list=getGeneralIssues().filter(i=>{
    const caseRefs=getIssueCaseRefs(i).map(c=>c.num).join(' ');
    const txt=[i.key,i.title,i.customer,i.assignee,i.reporter,(i.labels||[]).join(' '),caseRefs].join(' ').toLowerCase();
    if(q&&!txt.includes(q))return false;
    if(st&&i.status!==st)return false;
    if(pr&&i.pri!==pr)return false;
    if(lb&&!(i.labels||[]).includes(lb))return false;
    if(ass&&i.assignee!==ass)return false;
    if(dt&&!withinRecentDays(i.date,dt))return false;
    if(ISSUE_PRESET){
      if(ISSUE_PRESET.kind==='open'&&!isOpenStatus(i.status))return false;
      if(ISSUE_PRESET.kind==='done'&&!isDoneStatus(i.status))return false;
      if(ISSUE_PRESET.kind==='overdue'&&!(isOpenStatus(i.status)&&daysSince(i.date)>=7))return false;
      if(ISSUE_PRESET.kind==='high'&&!['Highest','High'].includes(i.pri))return false;
      if(ISSUE_PRESET.kind==='customer'&&i.customer!==ISSUE_PRESET.customer)return false;
    }
    return true;
  });
  return list;
}

// v1.5.2 hotfix: dashboard renderDash override removed.
// Reason: the v1.5.1 override referenced non-existing dashboard DOM IDs such as kpi-grid, cust-chart, recent-list.
// The original renderDash above uses the actual IDs: kpi-wrap, chart-section, dash-list.
function issueRow(i){
  const sc=SC[i.status]||'#94a3b8',pc=PC[i.pri]||'#94a3b8';
  const active=SEL&&SEL.key===i.key?' selected':'';
  const cases=getIssueCaseRefs(i);
  const caseHtml=cases.length?`<span class="imeta">케이스</span>${cases.map(c=>`<span class="case-chip ${c.done?'done':(c.status==='미동기화'?'':'open')}" title="${escapeHtml(c.status)}${c.key?' · '+escapeHtml(c.key):''}">${escapeHtml(c.num)} · ${escapeHtml(c.status)}</span>`).join('')}`:'';
  return `<div class="irow${active}" data-key="${escapeHtml(i.key)}" style="--lc:${sc}"><div class="irow-top"><span class="ikey">${i.key}</span><span class="badge" style="background:${sc}22;color:${sc}">${i.status}</span><span class="badge" style="background:${pc}22;color:${pc}">${i.pri}</span><span class="ititle">${escapeHtml(cleanTitle(i.title))}</span><span class="imeta">${escapeHtml(i.customer||'-')}</span></div><div class="irow-bot">${(i.labels||[]).map(l=>`<span class="badge" style="background:${labelColor(l)}22;color:${labelColor(l)}">${escapeHtml(l)}</span>`).join('')}<span class="imeta">@${escapeHtml(i.assignee)}</span><span class="imeta">${fd(i.date)}</span>${caseHtml}</div></div>`;
}
function renderIssues_legacy_v2(){
  const list=filteredIssues();
  list.sort((a,b)=>new Date(b.date)-new Date(a.date));
  const size=parseInt(document.getElementById('f-pg')?.value||'10');
  const maxPage=Math.max(1,Math.ceil(list.length/size));
  if(PAGE>maxPage)PAGE=maxPage;
  const start=(PAGE-1)*size;
  const page=list.slice(start,start+size);
  const wrap=document.getElementById('issue-list-wrap');
  document.getElementById('f-count').textContent=`총 ${list.length}건 · ${size}건씩 표시`;
  renderFilterTags();
  if(!page.length){wrap.innerHTML=`<div class="u-empty">조건에 맞는 일반 이슈가 없습니다<br><span class="u-fs-11px">케이스 항목은 케이스 트래커에서 확인하세요.</span></div>`;document.getElementById('page-nav').innerHTML='';return;}
  wrap.innerHTML=page.map(i=>issueRow(i)).join('');
  wrap.querySelectorAll('.irow').forEach((el,idx)=>el.onclick=()=>selectIssue(page[idx]));
  renderPageNav(list.length,size);
}

function getCases(){
  return getCaseIssueBase().map(i=>{
    const cn=getCasePrefixNum(i.title);
    return {...i,caseNum:cn,caseNums:[cn]};
  });
}
async function selectCase(c){
  if(!c)return;
  const base=ISSUES.find(x=>x.key===c.key)||c;
  CASE_SEL=Object.assign(c,base);
  renderCases();
  renderCaseRight(true);
  if(window.innerWidth<=700){syncMobSheet('case-right');openMobSheet();}
  await ensureIssueDetail(base);
  CASE_SEL=Object.assign(c,base);
  renderCases();
  renderCaseRight(false);
  if(window.innerWidth<=700)syncMobSheet('case-right');
}
function renderCases_legacy_v2(){
  const q=(document.getElementById('case-q')||{}).value?.toLowerCase()||'';
  const cStat=document.getElementById('case-stat')?.value||'';
  const cAss=document.getElementById('case-ass')?.value||'';
  const cSla=parseInt(document.getElementById('case-sla')?.value||'0');
  const cDate=parseInt(document.getElementById('case-date')?.value||'0');
  let cases=getCases().filter(c=>{
    const txt=[c.caseNum,c.title,c.customer,c.assignee,(c.labels||[]).join(' ')].join(' ').toLowerCase();
    if(q&&!txt.includes(q))return false;
    if(cStat&&c.status!==cStat)return false;
    if(cAss&&c.assignee!==cAss)return false;
    if(cSla&&daysSince(c.date)<cSla)return false;
    if(cDate&&!withinRecentDays(c.date,cDate))return false;
    if(CASE_PRESET){
      if(CASE_PRESET.kind==='open'&&!isOpenStatus(c.status))return false;
      if(CASE_PRESET.kind==='done'&&!isDoneStatus(c.status))return false;
      if(CASE_PRESET.kind==='overdue'&&!(isOpenStatus(c.status)&&daysSince(c.date)>=7))return false;
      if(CASE_PRESET.kind==='customer'&&c.customer!==CASE_PRESET.customer)return false;
    }
    return true;
  });
  cases.sort((a,b)=>new Date(b.date)-new Date(a.date));
  const cAssEl=document.getElementById('case-ass');
  if(cAssEl){const assignees=[...new Set(getCases().map(c=>c.assignee).filter(a=>a&&a!=='-'))].sort();const curAss=cAssEl.value;cAssEl.innerHTML='<option value="">전체 담당자</option>'+assignees.map(a=>`<option ${a===curAss?'selected':''}>${escapeHtml(a)}</option>`).join('');}
  const wrap=document.getElementById('case-list');
  const pageCases=sliceForPage(cases,'cases');
  const cnt=document.getElementById('case-count');
  if(cnt)cnt.textContent=pageCountText('cases',cases.length);
  if(!pageCases.length){wrap.innerHTML=`<div class="u-empty">제목 맨 앞이 [숫자8자리] 형식인 케이스가 없습니다</div>`;renderPager('case-pager','cases',cases.length,'renderCases');return;}
  wrap.innerHTML=pageCases.map((c,idx)=>{const days=daysSince(c.date);const slaBg=days>=7?'rgba(248,113,113,.2)':days>=5?'rgba(251,191,36,.2)':days>=3?'rgba(251,191,36,.12)':'rgba(34,211,165,.15)';const slaColor=days>=7?'#f87171':days>=5?'#fbbf24':days>=3?'#fbbf24':'#22d3a5';const sc=SC[c.status]||'#94a3b8';let t=c.title.replace(new RegExp('^\\s*\\[\\s*'+c.caseNum+'\\s*\\]'),'').replace(/\[\s*\]/g,'').replace(/\s+/g,' ').trim();return `<div class="case-card${CASE_SEL&&CASE_SEL.caseNum===c.caseNum&&CASE_SEL.key===c.key?' selected':''}" style="--lc:${sc}" data-idx="${idx}"><div class="irow-top"><span class="case-num">📦 ${c.caseNum}</span><span class="badge" style="background:${sc}22;color:${sc}">${c.status}</span><span class="sla-badge" style="background:${slaBg};color:${slaColor}">${days}일 경과</span><span class="ititle">${escapeHtml(t)}</span><span class="imeta">${escapeHtml(c.customer||'-')}</span></div><div class="irow-bot">${(c.labels||[]).map(l=>`<span class="badge" style="background:${labelColor(l)}22;color:${labelColor(l)}">${escapeHtml(l)}</span>`).join('')}<span class="imeta">@${escapeHtml(c.assignee)}</span><span class="imeta">${fd(c.date)}</span><span class="imeta">첨부 ${c.attachments?.length||0} · 댓글 ${c.comments?.length||0}</span></div></div>`;}).join('');
  wrap.querySelectorAll('.case-card').forEach((el,idx)=>{el.onclick=()=>selectCase(pageCases[idx]);});
  renderPager('case-pager','cases',cases.length,'renderCases');
}
function renderCaseRight(loading=false){
  if(!CASE_SEL)return;
  const c=CASE_SEL,sc=SC[c.status]||'#94a3b8';
  const days=daysSince(c.date);
  const refIssues=(typeof getGeneralIssues==='function'?getGeneralIssues():[]).filter(i=>typeof issueCaseMatches==='function'&&issueCaseMatches(i,c));
  document.getElementById('case-right').innerHTML=`
  <div class="rpanel">
    <div class="rp-title">${escapeHtml(cleanTitle(c.title))}</div>
    <div class="rp-meta">
      <div class="rp-row"><span>케이스</span><span style="color:var(--cyan);font-weight:700">${escapeHtml(c.caseNum)}</span></div>
      <div class="rp-row"><span>Jira 이슈키</span><span class="u-c-accent3">${escapeHtml(c.key)}</span></div>
      <div class="rp-row"><span>고객사</span><span>${escapeHtml(caseCustomerName(c)||'-')}</span></div>
      <div class="rp-row"><span>담당자</span><span>${escapeHtml(c.assignee)}</span></div>
      <div class="rp-row"><span>상태</span><span style="color:${sc}">${escapeHtml(c.status)}</span></div>
      <div class="rp-row"><span>경과일</span><span style="color:${days>=7?'#f87171':days>=3?'#fbbf24':'#22d3a5'};font-weight:700">${days}일</span></div>
    </div>
    ${loading?'<div class="loading u-mb-12px">첨부파일/댓글 상세 조회 중...</div>':''}
    ${c.desc?`<div class="rp-desc">${adfToHtml(c.desc)}</div>`:''}
    ${c.attachments&&c.attachments.length?`<div class="u-mb-12px"><div class="u-sec-label">📎 첨부파일 (${c.attachments.length})</div>${c.attachments.map(a=>`<div class="rp-attach-item">📄 ${escapeHtml(a.name)} <span class="u-ctext3-mlauto">${(a.size/1024).toFixed(1)}KB</span></div>`).join('')}</div>`:''}
    ${c.comments&&c.comments.length?`<div class="rp-comments u-mb-12px"><div class="u-sec-label">💬 코멘트 (${c.comments.length})</div>${c.comments.map(cm=>`<div class="rp-comment-item"><div class="rp-comment-author">${escapeHtml(cm.author)} · ${fdt(cm.created)}</div><div class="rp-comment-body">${adfToHtml(cm.body)}</div></div>`).join('')}</div>`:''}
    ${refIssues.length?`<div class="u-mb-12px"><div class="u-sec-label">🔗 이 케이스를 참조한 일반 이슈 (${refIssues.length})</div>${refIssues.slice(0,8).map(i=>`<div class="rp-attach-item u-cur-pointer" onclick="v154GoIssueExact('${escapeAttr(i.key)}')">${escapeHtml(i.key)} · ${escapeHtml(cleanTitle(i.title||i.summary||''))} <span class="u-ctext3-mlauto">${escapeHtml(i.status||'')}</span></div>`).join('')}</div>`:''}
    <div class="u-mb-10px" id="ai-analysis-sec-case"></div>
    <div class="detail-link-row">
      <a class="u-td-none" href="https://escare-engr.atlassian.net/browse/${c.key}" target="_blank"><button class="btn btn-ghost">Jira →</button></a>
    </div>
  </div>`;
  try{ renderIssueAnalysis(c.key,'ai-analysis-sec-case'); }catch(_){}
}


function renderOverdueBanner(){
  const OVERDUE_DAYS=7;
  const overdue=getGeneralIssues().filter(i=>isOpenStatus(i.status)&&daysSince(i.date)>=OVERDUE_DAYS);
  const myOpen=getGeneralIssues().filter(i=>isMyIssue(i)&&isOpenStatus(i.status));
  const wrap=document.getElementById('overdue-banner-wrap');
  if(!wrap)return;
  if(!overdue.length&&!myOpen.length){wrap.innerHTML='';return;}
  const byAss={};overdue.forEach(i=>{byAss[i.assignee]=(byAss[i.assignee]||0)+1;});
  const topAss=Object.entries(byAss).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([n,c])=>`${escapeHtml(n)} ${c}건`).join(', ');
  const overduePart=overdue.length?`<div style="flex:1;min-width:240px;background:linear-gradient(135deg,rgba(251,191,36,.1),rgba(248,113,113,.08));border:1px solid rgba(251,191,36,.3);border-radius:12px;padding:12px 18px;display:flex;align-items:center;gap:12px"><span class="u-fs-22px">🚨</span><div class="u-flex1-minw0"><div style="font-size:13px;font-weight:700;color:var(--warn);margin-bottom:2px">${OVERDUE_DAYS}일 이상 미완료 일반 이슈 ${overdue.length}건</div><div style="font-size:11px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">필터 기준: 케이스 제외 · 미완료/진행 상태 · 접수/수정일 기준 ${OVERDUE_DAYS}일 이상 · 주요 담당자: ${topAss}</div></div><button title="7일 이상 미완료 일반 이슈 목록을 엽니다" onclick="setIssueNavigationFilter({preset:{kind:'overdue',label:'7일 이상 미완료 일반 이슈'}})" style="background:rgba(251,191,36,.2);border:1px solid rgba(251,191,36,.4);color:var(--warn);padding:6px 14px;border-radius:8px;font-size:11px;cursor:pointer;font-family:inherit;font-weight:700;white-space:nowrap">이슈 보기 →</button></div>`:'';
  const myLabel=myOpen.length?`담당자: ${escapeHtml(CURRENT_DISPLAY||CURRENT_USER)} · 미완료/진행 ${myOpen.length}건`:'현재 담당 미완료 이슈 없음';
  const myPart=`<div style="flex:1;min-width:240px;background:linear-gradient(135deg,rgba(99,102,241,.12),rgba(139,92,246,.08));border:1px solid rgba(99,102,241,.35);border-radius:12px;padding:12px 18px;display:flex;align-items:center;gap:12px;cursor:pointer" onclick="setIssueNavigationFilter({preset:{kind:'myopen',label:'내 미완료 이슈'}})"><span class="u-fs-22px">📋</span><div class="u-flex1-minw0"><div style="font-size:13px;font-weight:700;color:#a5b4fc;margin-bottom:2px">내 미완료 이슈 ${myOpen.length}건</div><div style="font-size:11px;color:var(--text2)">${myLabel}</div></div><button style="background:rgba(99,102,241,.2);border:1px solid rgba(99,102,241,.4);color:#a5b4fc;padding:6px 14px;border-radius:8px;font-size:11px;cursor:pointer;font-family:inherit;font-weight:700;white-space:nowrap" onclick="event.stopPropagation();setIssueNavigationFilter({preset:{kind:'myopen',label:'내 미완료 이슈'}})">내 이슈 보기 →</button></div>`;
  wrap.innerHTML=`<div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">${overduePart}${myPart}</div>`;
}
function renderOpsFocus(){
  const overdue=getGeneralIssues().filter(i=>isOpenStatus(i.status)&&daysSince(i.date)>=7).sort((a,b)=>daysSince(b.date)-daysSince(a.date)).slice(0,5);
  const highOpen=getGeneralIssues().filter(i=>isOpenStatus(i.status)&&['Highest','High'].includes(i.pri)).slice(0,5);
  const nearEos=EOS_ITEMS.filter(x=>x.expireDate&&daysUntil(x.expireDate)>=0&&daysUntil(x.expireDate)<=60).sort((a,b)=>daysUntil(a.expireDate)-daysUntil(b.expireDate)).slice(0,5);
  const metaInc=getGeneralIssues().filter(i=>isOpenStatus(i.status)&&isMetaIncomplete(i)).slice(0,5);
  const wrap=document.getElementById('ops-focus');
  if(!wrap)return;
  const sec=(title,items,empty,mapper)=>`<div style="background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:12px;padding:12px"><div style="font-size:12px;font-weight:800;color:#e8edff;margin-bottom:8px">${title}</div>${items.length?items.map(mapper).join(''):`<div style="font-size:11px;color:var(--text3);padding:8px">${empty}</div>`}</div>`;
  wrap.innerHTML=`<div class="chart-card"><div class="chart-title">운영 포커스</div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px">${sec('7일 이상 미완료 일반 이슈',overdue,'대상 없음',i=>`<div class="u-curpointe-fs11px-ctext2-p6px0-bor1pxsol" onclick="setIssueNavigationFilter({preset:{kind:'overdue',label:'7일 이상 미완료 일반 이슈'}})"><b class="u-c-fcd34d">${i.key}</b> ${escapeHtml(cleanTitle(i.title)).slice(0,50)} <span style="float:right;color:#f87171">${daysSince(i.date)}일</span></div>`)}${sec('High 이상 미완료 일반 이슈',highOpen,'대상 없음',i=>`<div class="u-curpointe-fs11px-ctext2-p6px0-bor1pxsol" onclick="setIssueNavigationFilter({preset:{kind:'high',label:'High 이상 미완료 일반 이슈'}})"><b class="u-c-fca5a5">${i.key}</b> ${escapeHtml(cleanTitle(i.title)).slice(0,50)} <span style="float:right;color:#fca5a5">${i.pri}</span></div>`)}${sec('메타 미완성 (고객사·레이블·범주·기한)',metaInc,'모두 입력됨 ✓',i=>`<div class="u-curpointe-fs11px-ctext2-p6px0-bor1pxsol" onclick="setIssueNavigationFilter({preset:{kind:'incomplete',label:'메타 미완성 일반 이슈'}})"><b class="u-c-fbbf24">${i.key}</b> ${escapeHtml(cleanTitle(i.title)).slice(0,38)} <span style="float:right;color:#fbbf24">${metaMissingFields(i).join('·')}</span></div>`)}${sec('60일 내 라이선스 만료',nearEos,'대상 없음',x=>`<div class="u-curpointe-fs11px-ctext2-p6px0-bor1pxsol" onclick="showPage('eos',document.getElementById('nav-eos'));document.getElementById('eos-q').value=${jsAttr(x.customer)};PAGE_STATE.eos=1;renderEosList();"><b class="u-c-fcd34d">${escapeHtml(x.customer)}</b> ${escapeHtml(x.productDesc||x.product||'')} <span style="float:right;color:#fcd34d">D-${daysUntil(x.expireDate)}</span></div>`)}</div></div>`;
}


/* ── v1.5.5: case/customer/status/dashboard/sidebar stability patch ───────────── */
function applyV153Dom(){
  try{
    if(document.getElementById('v153-style'))return;
    const s=document.createElement('style');
    s.id='v153-style';
    s.textContent=`
      .kpi-grid{display:grid;grid-template-columns:repeat(6,minmax(120px,1fr));gap:10px;margin-bottom:12px}
      .kpi{background:var(--card);border:1px solid var(--border);border-radius:13px;padding:12px;min-height:76px;cursor:pointer;transition:.15s}
      .kpi:hover{border-color:var(--accent2);transform:translateY(-1px)}
      .kpi .num{font-size:28px;font-weight:900;color:#f4f7ff;line-height:1}
      .kpi .label{font-size:11px;color:#c5cee8;margin-top:7px;font-weight:700}
      .kpi .sub{font-size:10px;color:var(--text3);margin-top:5px}
      .dash-alert{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:12px;padding:13px 16px;border-radius:14px;border:1px solid rgba(251,191,36,.35);background:linear-gradient(90deg,rgba(251,191,36,.1),rgba(124,58,237,.08))}
      .dash-section{margin-top:14px}
      .dash-section .sec-title{font-size:11px;color:#9fb3ff;font-weight:800;margin:7px 0 9px;display:flex;align-items:center;gap:8px}
      .dash-section .sec-title:after{content:'';height:1px;background:var(--border);flex:1}
      .mini-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
      .mini-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:12px;min-height:140px;overflow:hidden}
      .dash-list-row{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.06);font-size:12px;cursor:pointer}
      .dash-list-row:last-child{border-bottom:0}
      .dash-list-row:hover .title{color:#fff}
      .case-chip{display:inline-flex;align-items:center;gap:4px;border:1px solid rgba(251,191,36,.32);background:rgba(251,191,36,.1);color:#fcd34d;border-radius:999px;padding:2px 7px;font-size:10px;font-weight:800;margin-left:6px;white-space:nowrap}
      .case-chip.done{border-color:rgba(45,230,184,.32);background:rgba(45,230,184,.1);color:#2de6b8}
      .case-chip.open{border-color:rgba(129,140,248,.32);background:rgba(129,140,248,.1);color:#a5b4fc}
      .sb-bottom{gap:7px!important;padding-bottom:8px!important}
      .usage-card,.health-card{padding:9px 11px!important;border-radius:12px!important}
      .usage-card .u-head,.health-card .h-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px!important}
      .usage-card .u-title,.health-card .h-title{font-size:11px!important;font-weight:800;color:#a5b4fc}
      .usage-card .u-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:4px 10px;font-size:10px!important}
      .usage-card .u-muted,.health-card .u-muted{color:var(--text3)}
      .usage-card .u-val,.health-card .u-val{color:#f4f7ff;font-weight:800;text-align:right}
      .usage-card .u-ok{color:#2de6b8;font-weight:900}.usage-card .u-bad{color:#fc8181;font-weight:900}
      .usage-card .u-foot{font-size:9px;color:var(--text3);text-align:right;margin-top:5px}
      .health-card .h-row{display:flex;align-items:center;justify-content:space-between;font-size:10px;margin:3px 0;color:#a8b3d6}
      .health-card .h-state{font-weight:800}.health-card .ok{color:#2de6b8}.health-card .bad{color:#fc8181}.health-card .warn{color:#fcd34d}
      .health-card .sync-mini{margin-top:6px;width:100%;padding:6px 8px!important;font-size:10px!important}
      @media(max-height:880px){.usage-card .u-hide-compact,.health-card .u-hide-compact{display:none!important}.usage-card,.health-card{padding:8px 10px!important}.sb-bottom{gap:6px!important}}
      @media(max-width:1400px){.kpi-grid{grid-template-columns:repeat(3,1fr)}.mini-grid{grid-template-columns:1fr}}
    `;
    document.head.appendChild(s);
  }catch(e){console.warn('applyV153Dom failed',e);}
}


function getCasePrefixNum(title){
  const m=String(title||'').match(/^\s*\[(\d{8})\]/);
  return m?m[1]:'';
}
function extractCaseNums(text){
  const s=String(text||'');
  const out=[];
  let m;
  const bracket=/\[(\d{8})\]/g;
  while((m=bracket.exec(s)))out.push(m[1]);
  return [...new Set(out)];
}
function isCaseIssue(i){return !!getCasePrefixNum(i&&i.title);}
function getCaseIssueBase(){return (ISSUES||[]).filter(isCaseIssue);}
function getGeneralIssues(){return (ISSUES||[]).filter(i=>!isCaseIssue(i));}
function normText(s){return String(s||'').toLowerCase().replace(/\s+/g,'').trim();}
function currentUserAliases(){
  return [...new Set([CURRENT_USER,CURRENT_DISPLAY].filter(Boolean).map(normText))];
}
function isDoneStatus(status){
  const s=normText(status);
  return ['완료','done','closed','resolved','해결','종료'].some(x=>s.includes(normText(x)));
}
function isOpenStatus(status){return !isDoneStatus(status);}
function isMyIssue(i){
  const aliases=currentUserAliases();
  const ass=normText(i&&i.assignee);
  return !!ass && aliases.some(me=>me && (ass.includes(me)||me.includes(ass)));
}