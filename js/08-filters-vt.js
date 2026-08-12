
function v154ActiveCaseFilterText(){
  const xs=[]; const q=document.getElementById('case-q')?.value?.trim(); const stat=document.getElementById('case-stat')?.value; const ass=document.getElementById('case-ass')?.value; const sla=document.getElementById('case-sla')?.value; const date=document.getElementById('case-date')?.value;
  if(q)xs.push('검색: '+q); if(stat)xs.push('상태: '+stat); if(ass)xs.push('담당자: '+ass); if(sla)xs.push(`${sla}일 이상`); if(date)xs.push(v154LabelOfRange(date));
  return xs;
}
function v154FilterNoteHtml(list){return list?.length?`<div class="mini-filter-note">${list.map(x=>`<span class="tag">${escapeHtml(x)}</span>`).join('')}</div>`:'';}
function v154GetIssueByKey(key){return ISSUES.find(x=>x.key===key)||null;}
function v154GetCaseByKey(key){return getCases().find(x=>x.key===key)||ISSUES.find(x=>x.key===key)||null;}
function renderIssues_legacy_v3(){
  const wrap=document.getElementById('issue-list-wrap'); if(!wrap)return;
  const arr=getFilteredIssues(); const size=parseInt(document.getElementById('f-pg')?.value||'10');
  const max=Math.max(1,Math.ceil(arr.length/size)); if(PAGE>max)PAGE=max; if(PAGE<1)PAGE=1;
  document.getElementById('f-count').textContent=`${arr.length}건`;
  const selectedStill=SEL&&arr.some(x=>x.key===SEL.key);
  if(!selectedStill){SEL=arr.length===1?arr[0]:null;}
  const pageItems=arr.slice((PAGE-1)*size,PAGE*size);
  wrap.innerHTML=`${v154FilterNoteHtml(v154ActiveIssueFilterText())}`+pageItems.map(i=>{
    const age=daysOld(i.created); const done=isDoneStatus(i.status);
    const cases=typeof getIssueCaseRefs==='function'?getIssueCaseRefs(i):[];
    const caseHtml=cases.length?`<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">${cases.map(c=>`<span class="case-chip ${c.done?'done':'open'}" onclick="event.stopPropagation();v154GoCaseExact('${escapeAttr(c.key||i.key)}')">${escapeHtml(c.num)} · ${c.done?'완료':'진행'}</span>`).join('')}</div>`:'';
    return `<div class="issue-item ${SEL&&SEL.key===i.key?'sel':''}" onclick="selectIssue(ISSUES.find(x=>x.key==='${escapeAttr(i.key)}'))">
      <div class="issue-title"><span class="issue-key">${escapeHtml(i.key)}</span>${escapeHtml(i.summary||'')}</div>
      <div class="issue-meta"><span>${escapeHtml(i.customer||'고객사 없음')}</span><span>${escapeHtml(i.assignee||'미지정')}</span><span>${fmtDate(i.created)}</span><span>${age}일</span>${done?'<span style="color:var(--ok)">완료</span>':'<span class="u-c-warn">진행/미완료</span>'}</div>
      ${caseHtml}
    </div>`;
  }).join('') || `<div class="empty">조건에 맞는 일반 이슈가 없습니다.</div>`;
  document.getElementById('page-nav').innerHTML=Array.from({length:max},(_,idx)=>`<button class="${PAGE===idx+1?'active':''}" onclick="PAGE=${idx+1};renderIssues()">${idx+1}</button>`).join('');
  renderIssueFilterTags(); renderRightPanel(false);
  if(SEL&&!SEL._detailLoaded){ensureIssueDetail(SEL).then(()=>renderRightPanel(false));}
}
function renderCases_legacy_v3(){
  const q=(document.getElementById('case-q')||{}).value?.toLowerCase()||'';
  const cStat=document.getElementById('case-stat')?.value||''; const cAss=document.getElementById('case-ass')?.value||''; const cSla=parseInt(document.getElementById('case-sla')?.value||'0'); const cDate=parseInt(document.getElementById('case-date')?.value||'0');
  let cases=getCases().filter(c=>{
    const txt=[c.key,c.caseNum,c.title,c.customer,c.assignee,(c.labels||[]).join(' ')].join(' ').toLowerCase();
    if(!qMatch(q,txt))return false; if(cStat&&c.status!==cStat)return false; if(cAss&&c.assignee!==cAss)return false; if(cSla&&c.age<cSla)return false;
    if(cDate){const t=new Date(c.created||0).getTime(); if(!t||Date.now()-t>cDate*86400000)return false;}
    return true;
  });
  const wrap=document.getElementById('case-list'); if(!wrap)return;
  const size=PAGE_SIZES.cases||10; const max=Math.max(1,Math.ceil(cases.length/size)); if(PAGE_STATE.cases>max)PAGE_STATE.cases=max; if(PAGE_STATE.cases<1)PAGE_STATE.cases=1;
  document.getElementById('case-count').textContent=`${cases.length}건`;
  const selectedStill=CASE_SEL&&cases.some(x=>x.key===CASE_SEL.key);
  if(!selectedStill){CASE_SEL=cases.length===1?cases[0]:null;}
  const rows=cases.slice((PAGE_STATE.cases-1)*size,PAGE_STATE.cases*size);
  wrap.innerHTML=`${v154FilterNoteHtml(v154ActiveCaseFilterText())}`+rows.map(c=>`<div class="issue-item ${CASE_SEL&&CASE_SEL.key===c.key?'sel':''}" onclick="selectCase(v154GetCaseByKey('${escapeAttr(c.key)}'))">
    <div class="issue-title"><span class="issue-key">${escapeHtml(c.caseNum)}</span>${escapeHtml(c.title||'')}</div>
    <div class="issue-meta"><span>${escapeHtml(c.key)}</span><span>${escapeHtml(caseCustomerName(c)||'고객사 없음')}</span><span>${escapeHtml(c.assignee||'미지정')}</span><span>${fmtDate(c.created)}</span><span>${c.age}일</span><span>${escapeHtml(c.status)}</span></div>
  </div>`).join('') || `<div class="empty">조건에 맞는 케이스가 없습니다.</div>`;
  document.getElementById('case-pager').innerHTML=Array.from({length:max},(_,idx)=>`<button class="${PAGE_STATE.cases===idx+1?'active':''}" onclick="PAGE_STATE.cases=${idx+1};renderCases()">${idx+1}</button>`).join('');
  renderCaseRight(false);
  if(CASE_SEL&&!CASE_SEL._detailLoaded){const base=ISSUES.find(x=>x.key===CASE_SEL.key)||CASE_SEL;ensureIssueDetail(base).then(()=>{CASE_SEL=Object.assign(CASE_SEL,base);renderCaseRight(false);});}
}
function renderVTHistory(){
  const wrap=document.getElementById('vt-history-wrap'); if(!wrap)return;
  const list=Array.isArray(VT_HISTORY)?VT_HISTORY.slice(0,20):[];
  if(!list.length){wrap.innerHTML='<div class="empty">최근 조회 이력이 없습니다.</div>';return;}
  wrap.innerHTML=list.map(x=>{
    const det=(Number(x.mal||0)+Number(x.suspicious||0));
    const res=det>0?`⚠ ${det}`:'✅ 0';
    const who=x.user||'-'; const when=x.ts?new Date(x.ts).toLocaleString('ko-KR'):'-';
    return `<div class="vt-history-item"><div><div class="vt-history-hash">${escapeHtml(x.hash||'')}</div><div class="vt-history-meta">${escapeHtml(x.name||x.type||'')} ${x.size?`· ${Math.round(x.size/1024)}KB`:''}</div></div><div>${res}</div><div class="hide-narrow">${escapeHtml(who)}</div><div class="vt-history-meta">${when}</div></div>`;
  }).join('');
}
async function loadSharedVTHistory(force=false){
  if(VT_HISTORY_SHARED_LOADED&&!force)return;
  const wrap=document.getElementById('vt-history-wrap'); if(wrap)wrap.innerHTML='<div class="empty">최근 파일(해시) 조회 이력 불러오는 중...</div>';
  try{const res=await api('/vt/history'); VT_HISTORY=res.history||[]; VT_HISTORY_SHARED_LOADED=true;}catch(e){VT_HISTORY=VT_HISTORY||[];}
  renderVTHistory();
}

/* ── v1.5.5 hotfix: AI usage card polish + Jira render routing ───────────── */
let CUST_ALIAS_MAP=null;
async function loadCustomerAliases(){
  // D1 customers의 별칭을 정식명으로 접기(워커 classifyBracket과 동일 규칙) — 우리FIS→우리에프아이에스 등
  try{
    const d=await hubApi('/customers');
    const m={};
    (d.items||[]).forEach(c=>(c.aliases||[]).forEach(a=>{if(a&&a!==c.name)m[a]=c.name;}));
    CUST_ALIAS_MAP=m;
    normalizeAllIssueAliases();
    if(typeof renderCurrent==='function')renderCurrent();
  }catch(_){CUST_ALIAS_MAP={};}
}
function canonCustomer(n){return (CUST_ALIAS_MAP&&CUST_ALIAS_MAP[n])||n;}
function normalizeIssueAliases(i){
  if(!i)return i;
  i.summary=i.summary||i.title||'';
  i.title=i.title||i.summary||'';
  i.created=i.created||i.date||'';
  i.date=i.date||i.created||'';
  i.updated=i.updated||i.updatedAt||i.date||i.created||'';
  i.age=daysSince(i.date||i.created);
  if(CUST_ALIAS_MAP){
    if(i.customer)i.customer=canonCustomer(i.customer);
    if(Array.isArray(i.customers)&&i.customers.length)i.customers=i.customers.map(canonCustomer);
  }
  return i;
}
const normalizeJiraIssueV154=normalizeJiraIssue;
normalizeJiraIssue=function(i){return normalizeIssueAliases(normalizeJiraIssueV154(i));};
function normalizeAllIssueAliases(){(ISSUES||[]).forEach(normalizeIssueAliases);}
function daysOld(d){return daysSince(d);}
function fmtDate(d){return fd(d);}
function getCaseNum(text){return getCasePrefixNum(text);}
function renderSidebarCompact(){
  const box=document.querySelector('.sb-bottom');
  if(!box)return;
  box.dataset.v153='1';
  const gi=getGeneralIssues().length, ci=getCaseIssueBase().length;
  const jiraState=ISSUES&&ISSUES.length?'<span class="dot dot-green dot-live"></span>연결됨':'<span class="dot u-bg-warn"></span>대기';
  box.innerHTML=`
    <div class="health-card">
      <div class="h-head"><div class="h-title">연결/동기화</div><span class="u-muted-10" id="issue-count">${gi||ci?`일반 ${gi} / 케이스 ${ci}`:'-'}</span></div>
      <div class="h-row"><span>접속자</span><span class="h-state">${escapeHtml(CURRENT_DISPLAY||CURRENT_USER||'-')}</span></div>
      <div class="h-row"><span>Jira</span><span class="h-state ${ISSUES&&ISSUES.length?'ok':''}" id="jira-dot">${jiraState}</span></div>
      <div class="h-row"><span>AI</span><span class="h-state ok" id="ai-status">준비됨</span></div>
      <button class="btn btn-ghost sync-mini" onclick="syncJira()">Jira 새로고침</button>
      <div class="u-foot" id="sync-meta" style="font-size:10px;color:var(--text3);margin-top:5px">-</div>
      <div class="u-foot" id="session-timer" style="font-size:10px;color:var(--text3);margin-top:4px;text-align:center"></div>
      <button onclick="logout()" style="width:100%;margin-top:4px;background:none;border:0;color:var(--text3);font-size:10px;cursor:pointer;font-family:inherit">로그아웃</button>
    </div>`;
  renderTopbarStatus();
}
function renderDash(){
  applyV153Dom();normalizeAllIssueAliases();
  const g=getGeneralIssues();
  const c=getCaseIssueBase();
  const done=g.filter(i=>isDoneStatus(i.status));
  const open=g.filter(i=>isOpenStatus(i.status));
  const my=g.filter(isMyIssue);
  const myDone=my.filter(i=>isDoneStatus(i.status));
  const myOpen=my.filter(i=>isOpenStatus(i.status));
  const highOpen=g.filter(i=>isOpenStatus(i.status)&&String(i.pri||'').toLowerCase().includes('high'));
  const stale=g.filter(i=>isOpenStatus(i.status)&&daysSince(i.date)>=7);
  const cDone=c.filter(i=>isDoneStatus(i.status));
  const cOpen=c.filter(i=>isOpenStatus(i.status));
  const myRate=my.length?Math.round(myDone.length/my.length*100):0;
  const k=document.getElementById('kpi-wrap');
  if(k)k.innerHTML=`
    <div class="kpi" onclick="setIssueNavigationFilter({})"><div class="kpi-num">${g.length}</div><div class="kpi-label">일반 이슈</div><div class="kpi-sub">케이스 제외</div></div>
    <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'status',status:'done',label:'완료 일반 이슈'}})"><div class="kpi-num">${done.length}</div><div class="kpi-label">완료</div><div class="kpi-sub">${g.length?Math.round(done.length/g.length*100):0}% 완료율</div></div>
    <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'status',status:'open',label:'진행/미완료 일반 이슈'}})"><div class="kpi-num">${open.length}</div><div class="kpi-label">진행/미완료</div><div class="kpi-sub">처리 필요</div></div>
    <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'high',label:'High 이상 미완료 일반 이슈'}})"><div class="kpi-num">${highOpen.length}</div><div class="kpi-label">High+</div><div class="kpi-sub">미완료 기준</div></div>
    <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'my',label:'내 담당 일반 이슈'}})"><div class="kpi-num">${my.length}</div><div class="kpi-label">내 담당</div><div class="kpi-sub">진행 ${myOpen.length} / 완료 ${myDone.length}</div></div>
    <div class="kpi" onclick="setCaseNavigationFilter({})"><div class="kpi-num">${c.length}</div><div class="kpi-label">케이스</div><div class="kpi-sub">진행 ${cOpen.length} / 완료 ${cDone.length}</div></div>`;
  const handled=document.getElementById('rank-handled'); if(handled)handled.innerHTML=topAssigneeRows(g);
  const rate=document.getElementById('rank-rate'); if(rate)rate.innerHTML=completionRateRows(g);
  const cs=document.getElementById('rank-case-speed'); if(cs)cs.innerHTML=caseSpeedRows(c);
  const nr=document.getElementById('rank-need-reply'); if(nr)nr.innerHTML=needReplyRows();
  const chart=document.getElementById('trend-chart'); if(chart)chart.innerHTML=trendSvg(g,c);
  const dl=document.getElementById('dash-list');
  if(dl)dl.innerHTML=g.sort((a,b)=>issueDateValue(b)-issueDateValue(a)).slice(0,10).map(issueRowHTML).join('')||'<div class="empty">Jira 새로고침 후 최근 이슈가 표시됩니다.</div>';
  renderOverdueBanner();renderEosBanner();renderMetaIncomplete();
  const ic=document.getElementById('issue-count'); if(ic)ic.textContent=`일반 ${g.length} / 케이스 ${c.length}`;
  renderTopbarStatus();
}
function renderMetaIncomplete(){
  const wrap=document.getElementById('meta-incomplete-wrap');
  if(!wrap)return;
  const inc=getGeneralIssues().filter(i=>isOpenStatus(i.status)&&isMetaOrOverdue(i));
  if(!inc.length){wrap.innerHTML=`<div class="chart-card u-mb-16px"><div class="chart-title">📋 주요 항목 미기입 점검</div><div style="font-size:12px;color:var(--success);padding:8px 2px">✓ 미완료 일반 이슈의 핵심 항목(고객사·레이블·범주·기한)이 모두 입력됐고 기한 초과 건도 없습니다.</div></div>`;return;}
  // 담당자별 집계 (미기입 항목 + 기한 초과)
  const byAss={};
  inc.forEach(i=>{const a=i.assignee||'(미지정)';if(!byAss[a])byAss[a]={count:0,fields:{}};byAss[a].count++;const flags=[...metaMissingFields(i),...(isOverdueIssue(i)?['기한초과']:[])];flags.forEach(f=>{byAss[a].fields[f]=(byAss[a].fields[f]||0)+1;});});
  const rows=Object.entries(byAss).sort((a,b)=>b[1].count-a[1].count).map(([name,info])=>{
    const fieldChips=Object.entries(info.fields).sort((a,b)=>b[1]-a[1]).map(([f,n])=>{const od=f==='기한초과';return `<span style="display:inline-block;background:${od?'rgba(248,113,113,.15)':'rgba(251,191,36,.12)'};color:${od?'var(--danger)':'var(--warn)'};border-radius:8px;padding:1px 7px;font-size:10px;margin:1px">${f} ${n}</span>`;}).join(' ');
    return `<div onclick="setIssueNavigationFilter({assignee:${jsAttr(name==='(미지정)'?'':name)},preset:{kind:'incomplete',label:${jsAttr('메타 미완성 · '+name)}}})" style="display:flex;align-items:center;gap:10px;padding:9px 6px;border-bottom:1px solid var(--border);cursor:pointer">
      <span style="min-width:90px;font-size:13px;font-weight:700;color:var(--text)">${escapeHtml(name)}</span>
      <span style="background:rgba(248,113,113,.15);color:var(--danger);border-radius:8px;padding:2px 9px;font-size:12px;font-weight:700">${info.count}건</span>
      <span style="flex:1;text-align:right">${fieldChips}</span>
    </div>`;
  }).join('');
  wrap.innerHTML=`<div class="chart-card u-mb-16px">
    <div class="chart-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>📋 주요 항목 미기입 점검 — 담당자별 (${inc.length}건)</span>
      <button onclick="setIssueNavigationFilter({preset:{kind:'incomplete',label:'메타 미완성 일반 이슈'}})" class="btn btn-ghost u-btn-xxs">전체 보기 →</button>
    </div>
    <div class="u-fs11px-ctext3-mb6px">미완료 일반 이슈 중 고객사·레이블·범주·기한 미기입 또는 <b style="color:var(--danger)">기한 초과</b> 건. 담당자 클릭 시 해당 이슈로 이동합니다.</div>
    ${rows}
  </div>`;
}
function focusCardHtml(title,items,empty,mapper){
  return `<div class="chart-card"><h4>${escapeHtml(title)}</h4>${items.length?items.slice(0,6).map(mapper).join(''):`<div class="empty" style="padding:16px 0">${escapeHtml(empty)}</div>`}</div>`;
}
function completionRateRows(list){
  const grouped=Object.entries(list.reduce((m,i)=>{const a=i.assignee||'-';m[a]=m[a]||{t:0,d:0};m[a].t++;if(isDoneStatus(i.status))m[a].d++;return m;},{}))
    .filter(([,v])=>v.t>=5).sort((a,b)=>(b[1].d/b[1].t)-(a[1].d/a[1].t)).slice(0,6);
  return grouped.map(([a,v])=>`<div class="dash-list-row"><span class="title">${escapeHtml(a)}</span><b>${Math.round(v.d/v.t*100)}%</b></div>`).join('')||'<div class="u-fs12px-ctext3">데이터 없음</div>';
}
let RESP_METRICS=null;
async function loadRespMetrics(){
  try{ const d=await hubApi('/analysis/resp'); RESP_METRICS=d.items||[]; }catch(_){ RESP_METRICS=[]; }
  const active=document.querySelector('.page.active')?.id;
  if(active==='page-dash'){
    const cs=document.getElementById('rank-case-speed');
    if(cs)cs.innerHTML=caseSpeedRows(getCaseIssueBase());
    const nr=document.getElementById('rank-need-reply');
    if(nr)nr.innerHTML=needReplyRows();
  }
  if(active==='page-cases'&&typeof renderCases==='function')renderCases();
}
function respByKey(key){ return (RESP_METRICS||[]).find(r=>r.key===key)||null; }
function caseBallBadge(key){
  // 다음 회신 주체 배지 — 스케줄 엔진이 마지막 코멘트 방향(팀→벤더/벤더→팀)으로 판정
  const r=respByKey(key); if(!r||!r.ball)return '';
  const days=r.last_comm!=null?` · ${Math.round(r.last_comm)}일 전`:'';
  const tip=escapeHtml(r.ball_note||'');
  if(r.ball==='team')return `<span title="${tip}" style="background:rgba(248,113,113,.14);color:var(--danger);border-radius:8px;padding:1px 7px;font-size:10px;font-weight:700;white-space:nowrap">🔴 팀 회신 필요${days}</span>`;
  return `<span title="${tip}" style="background:rgba(63,163,196,.12);color:var(--cyan);border-radius:8px;padding:1px 7px;font-size:10px;font-weight:700;white-space:nowrap">⏳ 제조사 대기${days}</span>`;
}
function respSpeedRows(){
  // 코멘트 기반 (스케줄 분석 산출): avg_resp = 최초응답+코멘트 간격+현재까지 무응답 구간의 평균
  const by={};
  (RESP_METRICS||[]).filter(r=>r.is_case).forEach(r=>{
    const a=r.assignee||''; if(!a||a==='-')return;
    const t=by[a]=by[a]||{n:0,open:0,respSum:0,respN:0,firstSum:0,firstN:0,needReply:0};
    t.n++;
    if(r.is_open)t.open++;
    if(r.avg_resp!=null){t.respSum+=r.avg_resp;t.respN++;}
    if(r.first_resp!=null){t.firstSum+=r.first_resp;t.firstN++;}
    if(r.ball==='team')t.needReply++;
  });
  const list=Object.entries(by)
    .map(([a,v])=>({a,v,avg:v.respN?Math.round(v.respSum/v.respN*10)/10:null}))
    .sort((x,y)=>(y.avg??999)-(x.avg??999))
    .slice(0,8);
  const maxAvg=Math.max(1,...list.map(x=>x.avg||0));
  return list.map(({a,v,avg})=>{
      const first=v.firstN?Math.round(v.firstSum/v.firstN*10)/10:null;
      const col=avg===null?'var(--text3)':avg>=7?'#E06A63':avg>=4?'#E0A32E':'#3FBE92';
      const pct=avg===null?0:Math.max(4,Math.round(avg/maxAvg*100));
      const sub=[`진행 ${v.open} · 완료 ${v.n-v.open}`,v.needReply?`<span style="color:var(--danger);font-weight:700">팀 회신 필요 ${v.needReply}건</span>`:'',first!==null?`접수→첫 기록 평균 ${first}일`:''].filter(Boolean).join(' · ');
      return `<div style="padding:7px 2px;border-bottom:1px solid var(--border);cursor:pointer" onclick="setCaseNavigationFilter({assignee:${jsAttr(a)}})">
        <div style="display:grid;grid-template-columns:minmax(0,1fr) 46px 64px;gap:8px;align-items:center">
          <span style="font-weight:700;font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(a)}</span>
          <span style="background:rgba(239,131,84,.14);color:var(--accent3);border-radius:8px;padding:2px 0;font-size:11px;font-weight:700;text-align:center;white-space:nowrap">${v.n}건</span>
          <b style="color:${col};white-space:nowrap;text-align:right;font-size:12.5px">${avg===null?'-':avg+'일'}</b>
        </div>
        <div style="height:4px;background:var(--surface-tint-2);border-radius:99px;margin-top:5px"><div style="height:4px;width:${pct}%;background:${col};border-radius:99px"></div></div>
        <div style="font-size:10px;color:var(--text3);margin-top:3px">${sub}</div>
      </div>`;
    }).join('');
}
function needReplyRows(){
  const cases=getCaseIssueBase();
  const rows=(RESP_METRICS||[]).filter(r=>r.is_case&&r.ball==='team')
    .sort((a,b)=>(b.last_comm||0)-(a.last_comm||0))
    .slice(0,8)
    .map(r=>{
      const c=cases.find(x=>x.key===r.key);
      const label=c?`<b>${escapeHtml(c.caseNum||c.key)}</b> ${escapeHtml(caseCustomerName(c)||'')} @${escapeHtml(c.assignee||r.assignee)}`:`<b>${escapeHtml(r.key)}</b> @${escapeHtml(r.assignee)}`;
      const days=r.last_comm!=null?Math.round(r.last_comm):null;
      return `<div class="dash-list-row" onclick="v154GoCaseExact(${jsAttr(r.key)})" title="${escapeHtml(r.ball_note||'')}"><span class="title">${label}</span><b style="color:var(--danger);white-space:nowrap">${days===null?'-':days+'일 전'}</b></div>`;
    });
  return rows.join('')||'<div style="font-size:12px;color:var(--success);padding:8px 2px">✓ 팀 응답 대기 케이스 없음</div>';
}
function caseSpeedRows(list){
  // 1순위: 코멘트 기반 응답 지표(D1 issue_resp) / 폴백: updated(마지막 갱신) 기반
  if(RESP_METRICS===null){ RESP_METRICS=[]; try{loadRespMetrics();}catch(_){} }
  const respRows=respSpeedRows();
  if(respRows)return respRows;
  const today=new Date(); today.setHours(0,0,0,0);
  const dayDiff=(a,b)=>Math.max(0,Math.round((a-b)/86400000));
  const by={};
  (list||[]).forEach(i=>{
    const a=i.assignee||'';
    if(!a||a==='-')return;
    const t=by[a]=by[a]||{open:0,idleSum:0,idleMax:0,idleKey:'',doneN:0,doneSum:0};
    const upd=new Date((i.updated||i.date)+'T00:00:00');
    if(isNaN(upd))return;
    if(isOpenStatus(i.status)){
      const idle=dayDiff(today,upd);
      t.open++; t.idleSum+=idle;
      if(idle>t.idleMax){t.idleMax=idle;t.idleKey=i.caseNum||i.key;}
    }else{
      const cre=new Date((i.date||'')+'T00:00:00');
      if(!isNaN(cre)){t.doneN++;t.doneSum+=dayDiff(upd,cre);}
    }
  });
  const rows=Object.entries(by)
    .sort((a,b)=>(b[1].open?b[1].idleSum/b[1].open:-1)-(a[1].open?a[1].idleSum/a[1].open:-1))
    .slice(0,8)
    .map(([a,v])=>{
      const avgIdle=v.open?Math.round(v.idleSum/v.open):null;
      const avgDone=v.doneN?Math.round(v.doneSum/v.doneN):null;
      const col=avgIdle===null?'var(--text3)':avgIdle>=7?'#E06A63':avgIdle>=4?'#E0A32E':'#3FBE92';
      const sub=[v.open?`진행 ${v.open}건`:'',v.open&&v.idleMax>=7?`최장 ${v.idleMax}일(${v.idleKey})`:'',avgDone!==null?`완료평균 ${avgDone}일`:''].filter(Boolean).join(' · ');
      return `<div class="dash-list-row" onclick="setCaseNavigationFilter({assignee:${jsAttr(a)},status:'미해결'})"><span class="title">${escapeHtml(a)}<br><small style="color:var(--text3);font-size:10px">${escapeHtml(sub)}</small></span><b style="color:${col};white-space:nowrap">${avgIdle===null?'진행 없음':avgIdle+'일'}</b></div>`;
    });
  return rows.join('')||'<div class="u-fs12px-ctext3">케이스 데이터 없음</div>';
}
function trendSvg(g,c){
  // 월별 신규 등록 건수 — 일반(청록)·케이스(보라) 2선 분리
  const keys=[];
  for(let n=5;n>=0;n--){const d=new Date();d.setMonth(d.getMonth()-n);keys.push(d.toISOString().slice(0,7));}
  const vals=keys.map(k=>({k,g:g.filter(i=>String(i.date).slice(0,7)===k).length,c:c.filter(i=>String(i.date).slice(0,7)===k).length}));
  const max=Math.max(1,...vals.map(v=>Math.max(v.g,v.c)));
  const y=n=>118-n/max*90;
  const x=idx=>30+idx*68;
  const line=(sel,color)=>`<polyline points="${vals.map((v,i)=>`${x(i)},${y(sel(v))}`).join(' ')}" fill="none" stroke="${color}" stroke-width="2.5"/>`+vals.map((v,i)=>`<circle cx="${x(i)}" cy="${y(sel(v))}" r="3.5" fill="${color}"/><text x="${x(i)}" y="${y(sel(v))-7}" text-anchor="middle" fill="${color}" font-size="9">${sel(v)}</text>`).join('');
  return line(v=>v.g,'#3FA3C4')+line(v=>v.c,'#9F6BB5')+`<g>${vals.map((v,i)=>`<text x="${x(i)}" y="135" text-anchor="middle" fill="#8B7A62" font-size="9">${v.k.slice(5)}</text>`).join('')}</g>`;
}
function renderCurrent(){
  normalizeAllIssueAliases();
  const active=document.querySelector('.page.active');
  const id=(active&&active.id||'page-dash').replace('page-','');
  if(id==='dash')renderDash();
  else if(id==='issues')renderIssues();
  else if(id==='cases')renderCases();
  else if(id==='customers')renderCustomers();
  // 캐시로 즉시 그리고 서버에서 다시 읽어 갱신 — 다른 사람이 등록한 라이선스가 새로고침 전까지 안 보이던 문제
  else if(id==='eos'){renderEosList();loadEOS().then(()=>renderEosList()).catch(()=>{});}
  else if(id==='sales')renderSalesPage();
  else if(id==='links')renderLinks();
  else if(id==='knowledge')renderKnowledge();
  else if(id==='audit')loadAudit();
  else if(id==='settings')loadSettings();
  else if(id==='vt')loadSharedVTHistory();
}
function renderIssueFilterTags(){renderFilterTags();}
function renderCompactPager(elId,page,totalPages,setter){
  const el=document.getElementById(elId);if(!el)return;
  if(totalPages<=1){el.innerHTML='';return;}
  const buttons=pagerNums(page,totalPages).map(n=>`<button class="${page===n?'active':''}" onclick="${setter}(${n})">${n}</button>`).join('');
  el.innerHTML=`<button ${page<=1?'disabled':''} onclick="${setter}(${page-1})">이전</button>${buttons}<button ${page>=totalPages?'disabled':''} onclick="${setter}(${page+1})">다음</button>`;
}
function setIssuePage(n){PAGE=n;renderIssues();}
function setCasePage(n){PAGE_STATE.cases=n;renderCases();}
function renderIssues(){
  normalizeAllIssueAliases();
  const wrap=document.getElementById('issue-list-wrap'); if(!wrap)return;
  // #3 기본 정렬: 진행중 우선 + 최근 등록순
  const arr=getFilteredIssues().slice().sort((a,b)=>{const ao=isOpenStatus(a.status)?0:1,bo=isOpenStatus(b.status)?0:1;return ao!==bo?ao-bo:issueDateValue(b)-issueDateValue(a);});
  const size=parseInt(document.getElementById('f-pg')?.value||'10',10)||10;
  const pages=Math.max(1,Math.ceil(arr.length/size)); if(PAGE>pages)PAGE=pages;if(PAGE<1)PAGE=1;
  const count=document.getElementById('f-count');if(count)count.textContent=`${arr.length}건`;
  const pageItems=arr.slice((PAGE-1)*size,PAGE*size);
  wrap.innerHTML=v154FilterNoteHtml(v154ActiveIssueFilterText())+
    (pageItems.length?pageItems.map(issueRowHTML).join(''):'<div class="empty">조건에 맞는 일반 이슈가 없습니다.</div>');
  renderCompactPager('page-nav',PAGE,pages,'setIssuePage');
  renderIssueFilterTags();
  // 필터↔상세 정합: 선택된 이슈가 현재 필터 결과에 없으면 상세 초기화(리스트와 불일치 방지)
  if(SEL && !arr.some(i=>i.key===SEL.key)){ SEL=null; const rp=document.getElementById('right-panel'); if(rp)rp.innerHTML='<div class="rpanel"><div class="rp-empty"><p class="u-muted-13">이슈를 선택하세요</p></div></div>'; }
  renderRightPanel(false);
}
function renderCases_legacy_v4(){
  normalizeAllIssueAliases();
  const wrap=document.getElementById('case-list'); if(!wrap)return;
  const arr=getFilteredCases();
  const size=PAGE_SIZES.cases||10;
  const pages=Math.max(1,Math.ceil(arr.length/size)); if(PAGE_STATE.cases>pages)PAGE_STATE.cases=pages;if(PAGE_STATE.cases<1)PAGE_STATE.cases=1;
  const count=document.getElementById('case-count');if(count)count.textContent=`${arr.length}건`;
  const rows=arr.slice((PAGE_STATE.cases-1)*size,PAGE_STATE.cases*size);
  wrap.innerHTML=v154FilterNoteHtml(v154ActiveCaseFilterText())+
    (rows.length?rows.map(c=>{
      const col=SC[c.status]||'#A2917A';
      return `<div class="issue-card ${CASE_SEL&&CASE_SEL.key===c.key?'sel':''}" onclick="selectCase(v154GetCaseByKey('${escapeAttr(c.key)}'))">
        <div class="issue-main">
          <span class="key">${escapeHtml(c.caseNum||c.key)}</span>
          <span class="st" style="background:${col}22;color:${col}">${escapeHtml(c.status||'-')}</span>
          <span class="title">${escapeHtml(cleanTitle(c.title||c.summary||''))}</span>
          <span class="date">${fd(c.date||c.created)}</span>
        </div>
        <div class="issue-sub"><span>${escapeHtml(c.key)}</span><span>${escapeHtml(c.customer||'고객사 없음')}</span><span>@${escapeHtml(c.assignee||'미지정')}</span><span>${daysSince(c.date||c.created)}일</span></div>
      </div>`;
    }).join(''):'<div class="empty">조건에 맞는 케이스가 없습니다.</div>');
  renderCompactPager('case-pager',PAGE_STATE.cases,pages,'setCasePage');
  renderCaseRight(false);
}
function setIssueNavigationFilter(opts={}){
  ['f-q','f-stat','f-pri','f-lab','f-ass','f-date'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  ISSUE_PRESET=opts.preset||null;
  if(opts.exactKey){document.getElementById('f-q').value=opts.exactKey;}
  else if(opts.q){document.getElementById('f-q').value=opts.q;}
  if(opts.status)document.getElementById('f-stat').value=opts.status;
  if(opts.priority)document.getElementById('f-pri').value=opts.priority;
  if(opts.label)document.getElementById('f-lab').value=opts.label;
  if(opts.assignee)document.getElementById('f-ass').value=opts.assignee;
  if(opts.dateDays&&document.getElementById('f-date'))document.getElementById('f-date').value=String(opts.dateDays);
  PAGE=1;showPage('issues');setTimeout(renderIssues,0);
}
function setCaseNavigationFilter(opts={}){
  ['case-q','case-stat','case-ass','case-sla','case-date'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  CASE_PRESET=opts.preset||null;
  if(opts.exactKey){document.getElementById('case-q').value=opts.exactKey;}
  else if(opts.q){document.getElementById('case-q').value=opts.q;}
  if(opts.status)document.getElementById('case-stat').value=opts.status;
  if(opts.assignee)document.getElementById('case-ass').value=opts.assignee;
  if(opts.sla)document.getElementById('case-sla').value=String(opts.sla);
  if(opts.dateDays&&document.getElementById('case-date'))document.getElementById('case-date').value=String(opts.dateDays);
  PAGE_STATE.cases=1;showPage('cases');
}
function selectCustomer(idx,name){
  const all=buildCustomers();
  CUST_SEL=all.find(c=>c.name===name)||all[idx]||null;
  renderCustomers();
  renderCustomerRight();
}
function renderCustomerRight(){
  const right=document.getElementById('cust-right'); if(!right)return;
  if(!CUST_SEL){right.innerHTML='<div class="rpanel"><div class="rp-empty"><p class="u-muted-13">고객사를 선택하면<br>상세 현황이 표시됩니다</p></div></div>';return;}
  const c=CUST_SEL;
  const general=c.general||c.issues?.filter(i=>!isCaseIssue(i))||[];
  const cases=c.cases||c.issues?.filter(isCaseIssue)||[];
  const done=general.filter(i=>isDoneStatus(i.status));
  const open=general.filter(i=>isOpenStatus(i.status));
  const caseDone=cases.filter(i=>isDoneStatus(i.status));
  const caseOpen=cases.filter(i=>isOpenStatus(i.status));
  const recent=[...general].sort((a,b)=>issueDateValue(b)-issueDateValue(a)).slice(0,8);
  const recentCases=[...cases].sort((a,b)=>issueDateValue(b)-issueDateValue(a)).slice(0,8);
  const rate=general.length?Math.round(done.length/general.length*100):0;
  const eosForCust=(typeof EOS_ITEMS!=='undefined'?EOS_ITEMS:[]).filter(e=>e.customer===c.name);
  const _td=new Date(); _td.setHours(0,0,0,0); const _tdm=_td.getTime();
  const licDday=eosForCust.map(e=>e.expireDate?Math.ceil((new Date(e.expireDate+'T00:00:00').getTime()-_tdm)/86400000):null).filter(d=>d!==null).sort((a,b)=>a-b);
  const nearLic=licDday.length?licDday[0]:null;
  const row=(i,kind)=>`<div class="customer-work-row" onclick="${kind==='case'?`v154GoCaseExact('${escapeAttr(i.key)}')`:`v154GoIssueExact('${escapeAttr(i.key)}')`}"><div><div class="k">${escapeHtml(kind==='case'?(i.caseNum||getCasePrefixNum(i.title)||i.key):i.key)}</div><div class="t">${escapeHtml(cleanTitle(i.title||i.summary||''))}</div></div><div class="m">${escapeHtml(i.status||'')} · ${fd(i.date||i.created)}</div></div>`;
  right.innerHTML=`<div class="rpanel">
    <div style="font-size:16px;font-weight:800;color:var(--text-strong);margin-bottom:14px">${escapeHtml(c.name)}${(typeof isOwnerInactive==='function'&&isOwnerInactive(c.name))?` <span class="badge" style="font-size:10px;vertical-align:middle;background:color-mix(in srgb,var(--danger) 15%,transparent);color:var(--danger)">계약종료</span>`:''}</div>
    <div class="rp-meta two-col">
      <div class="rp-row rp-span2" id="cust-prod-row"><span>제품</span><span style="flex-wrap:wrap;display:flex;gap:4px">${[...(c.products||[])].map(p=>`<span class="badge" style="background:${(LC_MAP[p]||'#A2917A')}22;color:${(LC_MAP[p]||'#A2917A')}">${escapeHtml(p)}</span>`).join('')||'-'}</span></div>
      <div class="rp-row"><span>영업 담당</span><span>${(typeof salesOwnerOf==='function'&&salesOwnerOf(c.name))?escapeHtml(salesOwnerOf(c.name)):'<span class="u-muted-11">미지정</span>'}</span></div>
      <div class="rp-row"><span>정/부 담당</span><span style="display:flex;flex-wrap:wrap;gap:4px">${(typeof ownerOf==='function'&&ownerOf(c.name))?ownerMetaHtml(c.name):'<span class="u-muted-11">미지정</span>'}</span></div>
      <div class="rp-row"><span>일반 이슈</span><span>${general.length} · 완료 ${done.length}/미완 ${open.length}</span></div>
      <div class="rp-row"><span>케이스</span><span>${cases.length} · 완료 ${caseDone.length}/미완 ${caseOpen.length}</span></div>
      <div class="rp-row"><span>완료율</span><span style="color:${rate>=80?'var(--success)':rate>=50?'var(--warn)':'var(--danger)'};font-weight:700">${rate}%</span></div>
      <div class="rp-row"><span>라이선스</span><span>${eosForCust.length}건${nearLic!==null?` · <b style="color:${nearLic<0?'var(--danger)':nearLic<=30?'var(--warn)':'var(--success)'}">${nearLic<0?'만료':'D-'+nearLic}</b>`:''}</span></div>
      <div class="rp-row rp-span2"><span>솔루션</span><span id="cust-sol-val"><span class="u-muted-11">불러오는 중…</span></span></div>
      <div class="rp-row rp-span2"><span>환경 메모</span><span id="cust-env-val"><span class="u-muted-11">불러오는 중…</span></span></div>
    </div>
    <div id="cust-env-edit" style="display:none;margin:-4px 0 12px"></div>
    <div class="jump-row"><button class="btn btn-ghost" onclick="setIssueNavigationFilter({preset:{kind:'customer',customer:${jsAttr(c.name)},label:${jsAttr('고객사: '+c.name)}}})">일반 이슈 보기</button><button class="btn btn-ghost" onclick="setCaseNavigationFilter({preset:{kind:'customer',customer:${jsAttr(c.name)},label:${jsAttr('고객사 케이스: '+c.name)}}})">케이스 보기</button></div>
    <div style="font-size:10px;color:var(--text3);font-weight:700;margin:12px 0 8px;text-transform:uppercase">최근 일반 이슈</div>${recent.map(i=>row(i,'issue')).join('')||'<div class="empty">최근 일반 이슈 없음</div>'}
    <div class="u-fs10px-ctext3-fw700-m14px08-ttupperc">최근 케이스</div>${recentCases.map(i=>row(i,'case')).join('')||'<div class="empty">최근 케이스 없음</div>'}
    ${eosForCust.length?`<div class="u-fs10px-ctext3-fw700-m14px08-ttupperc">🔑 라이선스</div>${eosForCust.map(e=>`<div class="customer-work-row" onclick="showPage('eos',document.getElementById('nav-eos'))"><div><div class="k">${escapeHtml(e.productDesc||e.product||'-')}</div><div class="t">${escapeHtml(e.serial||e.siteId||'')}</div></div><div class="m">${e.expireDate?'~ '+escapeHtml(e.expireDate):'-'}</div></div>`).join('')}`:''}
  </div>`;
  if(typeof loadCustomerEnv==='function')loadCustomerEnv(c.name);
}
function issueCaseMatches(issue,caseIssue){
  if(!issue||!caseIssue||issue.key===caseIssue.key)return false;
  const issueParent=issue.parentKey||'';
  const caseParent=caseIssue.parentKey||'';
  if(caseParent&&caseParent===issue.key)return true;
  if(issueParent&&issueParent===caseIssue.key)return true;
  if(issueParent&&caseParent&&issueParent===caseParent)return true;
  const text=[issue.title,issue.summary,issue.parentTitle,issue.descPlain,(issue.comments||[]).map(c=>c.bodyPlain||c.body||'').join(' ')].join(' ');
  const nums=new Set([...(issue.caseNums||[]),...extractCaseNums(text)]);
  return !!(caseIssue.caseNum&&nums.has(caseIssue.caseNum));
}
function casesForIssue(issue){
  if(!issue)return [];
  return getCaseIssueBase().filter(c=>issueCaseMatches(issue,c));
}
function getIssueCaseRefs(issue){
  return casesForIssue(issue).map(c=>({
    key:c.key,
    num:c.caseNum||getCasePrefixNum(c.title)||c.key,
    status:c.status,
    done:isDoneStatus(c.status)
  }));
}
function caseChipsForIssue(issue){
  const cases=casesForIssue(issue);
  if(!cases.length)return '';
  return `<span class="case-chip-wrap">${cases.map(c=>{
    const done=isDoneStatus(c.status);
    const label=`${done?'완료':'진행'} ${c.caseNum||getCasePrefixNum(c.title)||c.key}`;
    return `<span class="case-chip ${done?'done':'open'}" title="${escapeAttr(c.title||c.key)}" onclick="event.stopPropagation();v154GoCaseExact(${jsAttr(c.key)})">${escapeHtml(label)}</span>`;
  }).join('')}</span>`;
}