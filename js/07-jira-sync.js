
function issueDateValue(i){return new Date((i&&i.date)||0).getTime()||0;}
function cleanTitle(t){return String(t||'').replace(/^\s*\[\d{8}\]\s*/,'').trim();}
function parentSummaryOf(fields){
  const p=fields&&fields.parent;
  return (p&&p.fields&&p.fields.summary)||p&&p.summary||'';
}
function parentStatusOf(fields){
  const p=fields&&fields.parent;
  return (p&&p.fields&&p.fields.status&&p.fields.status.name)||'';
}
function normalizeJiraIssue(i){
  const f=i.fields||{};
  const title=f.summary||'';
  const parentTitle=parentSummaryOf(f);
  const caseNum=getCasePrefixNum(title);
  const cfCustomers=(Array.isArray(f.customfield_10134)?f.customfield_10134:[]).filter(isRealCust);
  const parsedCustomer=caseNum ? (extractCustomer(parentTitle)||extractCustomer(title)||'') : (extractCustomer(title)||extractCustomer(parentTitle)||'');
  const customer=cfCustomers[0]||parsedCustomer;
  return {
    key:i.key,
    title,
    status:f.status?f.status.name:'-',
    pri:f.priority?f.priority.name:'Medium',
    assignee:f.assignee?f.assignee.displayName:'-',
    reporter:f.reporter?f.reporter.displayName:'-',
    labels:f.labels||[],
    date:f.created?f.created.slice(0,10):'',
    updated:f.updated?f.updated.slice(0,10):'',
    desc:'',descPlain:'',comments:[],attachments:[],
    type:f.issuetype?f.issuetype.name:'작업',
    customer,
    customers:cfCustomers,
    division:Array.isArray(f.customfield_10178)?f.customfield_10178:[],
    category:(f.customfield_10036&&f.customfield_10036.value)||'',
    rating:(f.customfield_10244&&f.customfield_10244.value)||'',
    startDate:f.customfield_10015||'',
    due:f.duedate||'',
    caseNum,
    caseNums:caseNum?[caseNum]:extractCaseNums(title),
    parentKey:f.parent?f.parent.key:'',
    parentTitle,
    parentStatus:parentStatusOf(f),
    _detailLoaded:false
  };
}
function normalizeCustomerFallback(){
  const byKey=new Map((ISSUES||[]).map(i=>[i.key,i]));
  (ISSUES||[]).forEach(i=>{
    if(!i.customer && i.parentKey && byKey.has(i.parentKey))i.customer=byKey.get(i.parentKey).customer||'';
    if(!i.parentTitle && i.parentKey && byKey.has(i.parentKey))i.parentTitle=byKey.get(i.parentKey).title||'';
  });
}

async function syncJira(){
  applyV153Dom();renderSidebarCompact();
  const dot=document.getElementById('jira-dot');
  if(dot)dot.innerHTML='<span class="dot u-bg-warn"></span><span class="warn">동기화중...</span>';
  try{
    const r=await fetch(`${WORKERS}/jira/search/jql`,{headers:authHeaders()});
    if(!r.ok)throw new Error('응답 오류: '+r.status);
    const d=await r.json();
    if(!d.issues)throw new Error('이슈 데이터 없음');
    ISSUES=d.issues.map(normalizeJiraIssue);
    normalizeCustomerFallback();
    const gi=getGeneralIssues().length, ci=getCaseIssueBase().length;
    if(dot)dot.innerHTML='<span class="dot dot-green"></span><span class="ok">연결됨</span>';
    const ic=document.getElementById('issue-count');
    if(ic)ic.textContent=`일반 ${gi} / 케이스 ${ci}`;
    renderTopbarStatus();
    updateSyncMeta(d.sync||{rangeMonths:d.rangeMonths,count:ISSUES.length,syncedAt:new Date().toISOString(),syncedBy:CURRENT_USER});
    try{refreshFilters();}catch(e){console.warn('refreshFilters failed',e);}
    try{renderCurrent();}catch(e){console.error('render failed',e);toast('화면 렌더링 오류: '+(e.message||e),true);}
    toast(`Jira 동기화 완료! 일반 이슈 ${gi}건 · 케이스 ${ci}건`);
  }catch(e){
    if(dot)dot.innerHTML='<span class="dot" style="background:var(--danger)"></span><span class="bad">오류</span>';
    toast('Jira 연결 실패: '+(e.message||e),true);
  }
}

async function fetchIssueDetail(key){
  const fields=['summary','status','priority','assignee','reporter','created','updated','description','labels','issuetype','attachment','comment','parent','duedate','customfield_10134','customfield_10036','customfield_10178','customfield_10015','customfield_10244'].join(',');
  const r=await fetch(`${WORKERS}/jira/issue/${encodeURIComponent(key)}?fields=${encodeURIComponent(fields)}`,{headers:authHeaders()});
  if(!r.ok)throw new Error('상세 조회 오류: '+r.status);
  const i=await r.json();
  const base=normalizeJiraIssue(i);
  const f=i.fields||{};
  const descPlain=extractADFPlain(f.description);
  const comments=extractCommentsArr(f.comment);
  const text=[base.title,base.parentTitle,descPlain,comments.map(c=>c.bodyPlain||'').join(' ')].join(' ');
  const caseNum=getCasePrefixNum(base.title);
  return Object.assign(base,{
    desc:extractADF(f.description),
    descPlain,
    comments,
    attachments:extractAttachments(f.attachment),
    customer:base.customer||extractCustomer(text)||'',
    caseNum,
    caseNums:caseNum?[caseNum]:extractCaseNums(text),
    _detailLoaded:true
  });
}



function getFilteredIssues(){
  let arr=getGeneralIssues();
  arr=filterByPreset(arr,ISSUE_PRESET);
  const q=(document.getElementById('f-q')?.value||'').toLowerCase();
  const st=document.getElementById('f-stat')?.value||'';
  const pri=document.getElementById('f-pri')?.value||'';
  const lab=document.getElementById('f-lab')?.value||'';
  const ass=document.getElementById('f-ass')?.value||'';
  const date=document.getElementById('f-date')?.value||'';
  if(q)arr=arr.filter(i=>[i.key,i.title,i.customer,i.assignee,i.reporter,...(i.labels||[]),...(i.caseNums||[]),...casesForIssue(i).map(c=>c.caseNum)].join(' ').toLowerCase().includes(q));
  if(st)arr=arr.filter(i=>st==='완료'?isDoneStatus(i.status):st==='진행 중'?isOpenStatus(i.status)&&/진행|처리|progress/i.test(i.status):st==='미해결'?isOpenStatus(i.status):i.status===st);
  if(pri)arr=arr.filter(i=>i.pri===pri);
  if(lab)arr=arr.filter(i=>(i.labels||[]).includes(lab));
  if(ass)arr=arr.filter(i=>i.assignee===ass);
  if(date)arr=arr.filter(i=>dateFilterMatches(i.date,date));
  return arr.sort((a,b)=>issueDateValue(b)-issueDateValue(a));
}

function getFilteredCases(){
  let arr=getCaseIssueBase();
  arr=filterByPreset(arr,CASE_PRESET);
  const q=(document.getElementById('case-q')?.value||'').toLowerCase();
  const st=document.getElementById('case-stat')?.value||'';
  const ass=document.getElementById('case-ass')?.value||'';
  const sla=document.getElementById('case-sla')?.value||'';
  const date=document.getElementById('case-date')?.value||'';
  if(q)arr=arr.filter(i=>[i.key,i.caseNum,i.title,caseCustomerName(i),i.customer,i.assignee,i.parentKey,i.parentTitle,...(i.labels||[])].join(' ').toLowerCase().includes(q));
  if(st)arr=arr.filter(i=>st==='완료'?isDoneStatus(i.status):st==='진행 중'?isOpenStatus(i.status)&&/진행|처리|progress/i.test(i.status):st==='미해결'?isOpenStatus(i.status):i.status===st);
  if(ass)arr=arr.filter(i=>i.assignee===ass);
  if(sla)arr=arr.filter(i=>isOpenStatus(i.status)&&age(i.date)>=parseInt(sla,10));
  if(date)arr=arr.filter(i=>dateFilterMatches(i.date,date));
  return arr.sort((a,b)=>issueDateValue(b)-issueDateValue(a));
}

function refreshFilters(){
  applyV153Dom();renderSidebarCompact();
  const labels=new Set(),assignees=new Set(),caseAssignees=new Set();
  getGeneralIssues().forEach(i=>{(i.labels||[]).forEach(l=>labels.add(l));if(i.assignee&&i.assignee!=='-')assignees.add(i.assignee);});
  getCaseIssueBase().forEach(i=>{if(i.assignee&&i.assignee!=='-')caseAssignees.add(i.assignee);});
  const labSel=document.getElementById('f-lab');
  if(labSel){const cur=labSel.value;labSel.innerHTML='<option value="">전체 레이블</option>'+[...labels].sort().map(l=>`<option ${l===cur?'selected':''}>${escapeHtml(l)}</option>`).join('');}
  const assSel=document.getElementById('f-ass');
  if(assSel){const cur=assSel.value;assSel.innerHTML='<option value="">전체 담당자</option>'+[...assignees].sort().map(a=>`<option ${a===cur?'selected':''}>${escapeHtml(a)}</option>`).join('');}
  const caseAss=document.getElementById('case-ass');
  if(caseAss){const cur=caseAss.value;caseAss.innerHTML='<option value="">전체 담당자</option>'+[...caseAssignees].sort().map(a=>`<option ${a===cur?'selected':''}>${escapeHtml(a)}</option>`).join('');}
  if(!document.getElementById('case-date')){
    const pg=document.getElementById('case-pg');
    if(pg)pg.insertAdjacentHTML('beforebegin',`<select id="case-date" onchange="PAGE_STATE.cases=1;renderCases()"><option value="">전체 기간</option><option value="7">최근 7일</option><option value="30">최근 1개월</option><option value="90">최근 3개월</option><option value="180">최근 6개월</option><option value="365">최근 1년</option></select>`);
  }
  applyV151Dom();
}

function renderDash_legacy_v2(){
  applyV153Dom();
  const g=getGeneralIssues();
  const c=getCaseIssueBase();
  const done=g.filter(i=>isDoneStatus(i.status));
  const open=g.filter(i=>isOpenStatus(i.status));
  const my=g.filter(isMyIssue);
  const myDone=my.filter(i=>isDoneStatus(i.status));
  const myOpen=my.filter(i=>isOpenStatus(i.status));
  const high=g.filter(i=>String(i.pri||'').toLowerCase().includes('high'));
  const stale=g.filter(i=>isOpenStatus(i.status)&&age(i.date)>=7);
  const cDone=c.filter(i=>isDoneStatus(i.status));
  const cOpen=c.filter(i=>isOpenStatus(i.status));
  const myRate=my.length?Math.round(myDone.length/my.length*100):0;
  const k=document.getElementById('kpis');
  if(k)k.innerHTML=`
    ${stale.length?`<div class="dash-alert" style="grid-column:1/-1"><div><b class="u-c-fcd34d">🚨 7일 이상 미완료 일반 이슈 ${stale.length}건</b><div style="font-size:11px;color:var(--text2);margin-top:4px">케이스 제외 · 주요 담당자: ${Object.entries(stale.reduce((m,i)=>(m[i.assignee]=(m[i.assignee]||0)+1,m),{})).sort((a,b)=>b[1]-a[1]).slice(0,4).map(([a,n])=>`${escapeHtml(a)} ${n}건`).join(', ')||'-'}</div></div><button class="btn btn-warn" onclick="setIssueNavigationFilter({preset:{kind:'stale',label:'7일 이상 미완료 일반 이슈'}})">이슈 보기 →</button></div>`:''}
    <div class="kpi-grid">
      <div class="kpi" onclick="setIssueNavigationFilter({})"><div class="num">${g.length}</div><div class="label">일반 이슈</div><div class="sub">케이스 제외</div></div>
      <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'status',status:'done',label:'완료 일반 이슈'}})"><div class="num">${done.length}</div><div class="label">완료</div><div class="sub">${g.length?Math.round(done.length/g.length*100):0}% 완료율</div></div>
      <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'status',status:'open',label:'진행/미완료 일반 이슈'}})"><div class="num">${open.length}</div><div class="label">진행/미완료</div><div class="sub">처리 필요</div></div>
      <div class="kpi" onclick="setCaseNavigationFilter({})"><div class="num">${c.length}</div><div class="label">케이스</div><div class="sub">진행 ${cOpen.length} / 완료 ${cDone.length}</div></div>
      <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'my',label:'내 담당 일반 이슈'}})"><div class="num">${my.length}</div><div class="label">내 담당</div><div class="sub">진행 ${myOpen.length} / 완료 ${myDone.length}</div></div>
      <div class="kpi" onclick="setIssueNavigationFilter({preset:{kind:'my',label:'내 담당 일반 이슈'}})"><div class="num">${myRate}%</div><div class="label">내 완료율</div><div class="sub">${myDone.length}/${my.length}건</div></div>
    </div>`;
  const focus=document.getElementById('focus');
  if(focus)focus.innerHTML=`<div class="dash-section"><div class="sec-title">운영 포커스</div><div class="mini-grid">
    <div class="mini-card"><div class="u-fs12px-ca5b4fc-fw800-mb8px">처리 건수 TOP</div>${topAssigneeRows(g)}</div>
    <div class="mini-card"><div class="u-fs12px-ca5b4fc-fw800-mb8px">케이스 진행 TOP</div>${topAssigneeRows(cOpen)}</div>
    <div class="mini-card"><div class="u-fs12px-ca5b4fc-fw800-mb8px">월별 추이 (최근 6개월)</div>${monthTrendRows(g,c)}</div>
  </div></div>`;
  const recent=document.getElementById('recent');
  if(recent)recent.innerHTML=`<div class="dash-section"><div class="sec-title">최근 일반 이슈 (10건)</div>${g.sort((a,b)=>issueDateValue(b)-issueDateValue(a)).slice(0,10).map(i=>`<div class="issue-card" onclick="setIssueNavigationFilter({q:${jsAttr(i.key)}})"><div class="issue-main"><span class="key">${escapeHtml(i.key)}</span><span class="st" style="background:${(SC[i.status]||'#94a3b8')}22;color:${SC[i.status]||'#94a3b8'}">${escapeHtml(i.status)}</span><span class="title">${escapeHtml(cleanTitle(i.title))}</span>${caseChipsForIssue(i)}<span class="date">${fd(i.date)}</span></div><div class="issue-sub"><span>@${escapeHtml(i.assignee||'-')}</span><span>${escapeHtml(i.customer||'-')}</span></div></div>`).join('')||'<div class="empty">최근 일반 이슈 없음</div>'}</div>`;
}
function topAssigneeRows(list){
  const rows=Object.entries(list.reduce((m,i)=>(m[i.assignee||'-']=(m[i.assignee||'-']||0)+1,m),{})).sort((a,b)=>b[1]-a[1]).slice(0,6);
  return rows.map(([a,n])=>`<div class="dash-list-row"><span class="title">${escapeHtml(a)}</span><b>${n}건</b></div>`).join('')||'<div class="u-fs12px-ctext3">데이터 없음</div>';
}
function monthTrendRows(g,c){
  const m={};
  [...g.map(x=>({...x,_kind:'이슈'})),...c.map(x=>({...x,_kind:'케이스'}))].forEach(i=>{const k=String(i.date||'').slice(0,7)||'미상';m[k]=m[k]||{g:0,c:0};if(i._kind==='이슈')m[k].g++;else m[k].c++;});
  return Object.entries(m).sort((a,b)=>a[0].localeCompare(b[0])).slice(-6).map(([mon,v])=>`<div class="dash-list-row"><span class="title">${escapeHtml(mon)}</span><span>이슈 <b>${v.g}</b> · 케이스 <b>${v.c}</b></span></div>`).join('')||'<div class="u-fs12px-ctext3">데이터 없음</div>';
}


// ── INIT ──────────────────────────────────────────
async function restoreSession(){
  const savedUser=localStorage.getItem('engr_user')||'';
  const token=localStorage.getItem('engr_session_token')||'';
  const deadline=parseInt(localStorage.getItem('engr_session_deadline')||'0',10);
  if(!savedUser||!token||!deadline||deadline<=Date.now()){clearLocalSession();return false;}
  CURRENT_USER=savedUser;
  CURRENT_DISPLAY=localStorage.getItem('engr_display')||savedUser;
  USER_ROLE=localStorage.getItem('engr_role')||'user';
  IS_ADMIN=localStorage.getItem('engr_is_admin')==='1'||USER_ROLE==='admin'||USER_ROLE==='super';
  IS_SUPER=localStorage.getItem('engr_is_super')==='1'||USER_ROLE==='super';
  SESSION_MIN=parseInt(localStorage.getItem('engr_session_min')||'120',10)||120;
  SESSION_DEADLINE=deadline;
  try{
    const r=await fetch(`${WORKERS}/auth/session`,{headers:authHeaders()});
    const d=await r.json();
    if(!d.ok)throw new Error(d.message||'invalid session');
    CURRENT_USER=d.userId||CURRENT_USER;
    CURRENT_DISPLAY=d.displayName||CURRENT_DISPLAY;
    USER_ROLE=d.role||USER_ROLE;
    IS_ADMIN=!!d.isAdmin;
    IS_SUPER=!!d.isSuperAdmin;
    SESSION_MIN=d.sessionMin||SESSION_MIN;
    MUST_CHANGE_PIN=!!d.mustChangePin;
    localStorage.setItem('engr_user',CURRENT_USER);
    localStorage.setItem('engr_display',CURRENT_DISPLAY);
    localStorage.setItem('engr_role',USER_ROLE);
    localStorage.setItem('engr_is_admin',IS_ADMIN?'1':'0');
    localStorage.setItem('engr_is_super',IS_SUPER?'1':'0');
    localStorage.setItem('engr_session_min',String(SESSION_MIN));
    enterApp();
    if(MUST_CHANGE_PIN)setTimeout(forcePinChange,200);
    return true;
  }catch(e){
    clearLocalSession();
    if(localStorage.getItem('engr_remember')!=='1')toast('세션이 만료되어 다시 로그인해주세요',true);
    return false;
  }
}

function autoLogin(){
  const name=(localStorage.getItem('engr_saved_user')||'').trim();
  let pin='';try{pin=decodeURIComponent(escape(atob(localStorage.getItem('engr_saved_pin')||'')));}catch(_){pin='';}
  if(!name||!pin)return false;
  const nameEl=document.getElementById('l-name'),pinEl=document.getElementById('l-pin'),rc=document.getElementById('l-remember');
  if(nameEl)nameEl.value=name; if(pinEl)pinEl.value=pin; if(rc)rc.checked=true;
  return login({auto:true});  // 실패 시 저장정보 자동 해제(반복 실패 방지)
}
(function init(){
  const remembered=localStorage.getItem('engr_remember')==='1';
  const savedUser=localStorage.getItem('engr_saved_user')||localStorage.getItem('engr_user')||'';
  if(savedUser){const el=document.getElementById('l-name');if(el)el.value=savedUser;}
  // PIN은 화면에 미리 채우지 않음(낡은 값이 그대로 제출돼 실패하는 혼란 방지). 자동 로그인만 내부적으로 저장 PIN 사용.
  if(remembered){
    const rc=document.getElementById('l-remember');if(rc)rc.checked=true;
  }
  localStorage.removeItem('engr_pin');
  restoreSession().then(ok=>{
    if(ok)return;
    if(remembered){autoLogin();return;}
    const el=document.getElementById('l-pin');if(el&&!el.value)el.focus();
  });
})();

// ── PWA 설치: 상단 메뉴의 '앱 설치' 항목으로 노출 (방해되는 플로팅 버튼 제거) ──
let __deferredInstall=null;
function isStandaloneApp(){try{return window.matchMedia('(display-mode:standalone)').matches||window.navigator.standalone;}catch(_){return false;}}
function isIOSDevice(){try{return /iphone|ipad|ipod/i.test(navigator.userAgent)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);}catch(_){return false;}}
function syncInstallMenuItem(){
  const el=document.getElementById('tmp-install'); if(!el)return;
  // 안드로이드/크롬=beforeinstallprompt, iOS=사파리 공유 안내. 이미 설치(standalone)면 숨김.
  el.style.display=(!isStandaloneApp() && (!!__deferredInstall || isIOSDevice()))?'flex':'none';
}
async function pwaInstall(){
  closeTopMenu();
  if(__deferredInstall){ __deferredInstall.prompt(); try{await __deferredInstall.userChoice;}catch(_){} __deferredInstall=null; syncInstallMenuItem(); return; }
  if(isIOSDevice()){
    openGenModal('📲 아이폰에 앱 설치',`<div style="font-size:13px;line-height:2;color:var(--text2)">
      <b>Safari</b> 하단의 <b>공유</b> 버튼 <span style="display:inline-block;border:1px solid var(--border2);border-radius:5px;padding:0 7px;color:var(--accent3)">⬆</span> 을 누르고,<br>
      메뉴에서 <b>"홈 화면에 추가"</b> 를 선택하세요.<br><br>
      홈 화면에 <b>ESCARE</b> 아이콘이 생기고, 주소 입력 없이 앱처럼 열립니다.<br><br>
      <span style="color:var(--text3);font-size:12px">※ 반드시 <b>Safari</b>에서 열어야 추가됩니다(다른 브라우저는 제한).</span>
    </div>`,`<button class="btn btn-indigo u-btn-inline" onclick="closeGenModal()">확인</button>`);
    return;
  }
  toast('이미 설치되었거나, 브라우저 메뉴의 "홈 화면에 추가"를 이용해 주세요.',true);
}
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();__deferredInstall=e;syncInstallMenuItem();});
window.addEventListener('appinstalled',()=>{__deferredInstall=null;syncInstallMenuItem();try{toast&&toast('앱이 설치되었습니다 ✓');}catch(_){}});

// ══════════ Web Push (알림) — 클라이언트 ══════════
let __pushState={ supported:false, permission:'default', subscribed:false, enabled:true, configured:false };
function pushSupported(){ return ('serviceWorker' in navigator) && ('PushManager' in window) && ('Notification' in window); }
function urlB64ToU8(b64){ const pad='='.repeat((4-b64.length%4)%4); const s=(b64+pad).replace(/-/g,'+').replace(/_/g,'/'); const raw=atob(s); const a=new Uint8Array(raw.length); for(let i=0;i<raw.length;i++)a[i]=raw.charCodeAt(i); return a; }
async function registerPushSW(){
  if(!('serviceWorker' in navigator))return null;
  try{ if(!window.__swReg)window.__swReg=await navigator.serviceWorker.register('sw.js'); return window.__swReg; }catch(_){ return null; }
}
async function refreshPushState(){
  __pushState.supported=pushSupported();
  if(!__pushState.supported){ if(typeof syncNotifMenuItem==='function')syncNotifMenuItem(); return __pushState; }
  try{ __pushState.permission=Notification.permission; }catch(_){}
  try{ const reg=await registerPushSW(); if(reg){ const s=await reg.pushManager.getSubscription(); __pushState.subscribed=!!s; } }catch(_){}
  try{ const d=await hubApi('/push/pref'); __pushState.enabled=d.enabled!==false; __pushState.configured=!!d.configured; }catch(_){}
  if(typeof syncNotifMenuItem==='function')syncNotifMenuItem();
  if(typeof syncPushAdminState==='function')syncPushAdminState();
  return __pushState;
}
function pushIsOn(){ try{ return __pushState.subscribed && __pushState.enabled && Notification.permission==='granted'; }catch(_){ return false; } }
function syncNotifMenuItem(){
  const el=document.getElementById('tmp-notif');
  const row=document.getElementById('top-notif-state-row');
  const st=document.getElementById('top-notif-state');
  const supported = pushSupported() && !(isIOSDevice() && !isStandaloneApp());
  if(el) el.style.display = supported ? 'flex' : 'none';
  if(row) row.style.display = supported ? 'flex' : 'none';
  if(!supported) return;
  let denied=false; try{ denied=(Notification.permission==='denied'); }catch(_){}
  const on=pushIsOn();
  if(st){ st.textContent = denied ? '권한 차단됨' : (on?'켜짐':'꺼짐'); st.className = (denied||!on) ? 'warn' : 'ok'; }
  const ic=document.getElementById('tmp-notif-ic'), lb=document.getElementById('tmp-notif-label');
  if(ic)ic.textContent=on?'🔕':'🔔';   // 전환 동작: 켜짐→끄기(🔕) / 꺼짐→켜기(🔔)
  if(lb)lb.textContent=on?'알림 끄기':'알림 켜기';
}
async function enablePush(){
  if(!pushSupported()){ toast('이 브라우저는 알림을 지원하지 않습니다.',true); return false; }
  if(isIOSDevice() && !isStandaloneApp()){ toast('아이폰은 먼저 홈 화면에 앱을 추가한 뒤 알림을 켤 수 있어요.',true); return false; }
  let perm=Notification.permission;
  if(perm!=='granted'){ try{ perm=await Notification.requestPermission(); }catch(_){} }
  if(perm!=='granted'){ toast('알림 권한이 거부되었습니다. 브라우저 사이트 설정에서 허용해주세요.',true); await refreshPushState(); return false; }
  const reg=await registerPushSW(); if(!reg){ toast('알림 등록 실패(서비스워커).',true); return false; }
  try{ await navigator.serviceWorker.ready; }catch(_){}
  let pub=''; try{ const d=await fetch(`${WORKERS}/push/public-key`).then(r=>r.json()); pub=d.publicKey||''; }catch(_){}
  if(!pub){ toast('알림 서버 설정 오류(VAPID).',true); return false; }
  let sub;
  try{ sub=await reg.pushManager.getSubscription() || await reg.pushManager.subscribe({ userVisibleOnly:true, applicationServerKey:urlB64ToU8(pub) }); }
  catch(e){ toast('구독 실패: '+e.message,true); return false; }
  try{ await hubApi('/push/subscribe',{method:'POST',body:JSON.stringify({subscription:sub.toJSON()})}); }
  catch(e){ toast('서버 등록 실패: '+e.message,true); return false; }
  await refreshPushState();
  toast('알림이 켜졌습니다 🔔');
  return true;
}
async function disablePush(){
  try{
    const reg=await registerPushSW();
    const sub=reg?await reg.pushManager.getSubscription():null;
    if(sub){ try{ await hubApi('/push/unsubscribe',{method:'POST',body:JSON.stringify({endpoint:sub.endpoint})}); }catch(_){} try{ await sub.unsubscribe(); }catch(_){} }
    else { try{ await hubApi('/push/pref',{method:'POST',body:JSON.stringify({enabled:false})}); }catch(_){} }
  }catch(_){}
  await refreshPushState();
  toast('알림을 껐습니다 🔕');
}
async function togglePushFromMenu(){ closeTopMenu(); if(pushIsOn()) await disablePush(); else await enablePush(); }
window.togglePushFromMenu=togglePushFromMenu;
async function sendPushTest(){
  if(!pushIsOn()){ const ok=await enablePush(); if(!ok)return; }
  try{ const d=await hubApi('/push/test',{method:'POST',body:JSON.stringify({})}); toast(d.sent?`테스트 알림 전송됨(${d.sent}대 기기)`:'전송 대상 없음'); }
  catch(e){ toast('테스트 실패: '+e.message,true); }
}
window.sendPushTest=sendPushTest;
async function initPushOnLogin(){
  if(!pushSupported())return;
  await registerPushSW();
  try{ navigator.serviceWorker.addEventListener('message',ev=>{ if(ev.data&&ev.data.type==='navigate'&&ev.data.page){ try{ showPage(ev.data.page); }catch(_){} } }); }catch(_){}
  try{ const go=new URLSearchParams(location.search).get('go'); if(go){ try{ showPage(go); }catch(_){} } }catch(_){}
  await refreshPushState();
  // 권한이 이미 허용 + 사용자가 끄지 않았으면 조용히 구독 갱신(자동 권한요청은 하지 않음)
  if(Notification.permission==='granted' && __pushState.enabled){
    try{
      const reg=await registerPushSW(); await navigator.serviceWorker.ready;
      let sub=await reg.pushManager.getSubscription();
      if(!sub){ const d=await fetch(`${WORKERS}/push/public-key`).then(r=>r.json()); if(d.publicKey)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlB64ToU8(d.publicKey)}); }
      if(sub){ await hubApi('/push/subscribe',{method:'POST',body:JSON.stringify({subscription:sub.toJSON()})}); await refreshPushState(); }
    }catch(_){}
  }
}
window.initPushOnLogin=initPushOnLogin;
// ── 관리자: 푸시 알림 설정 ──
async function loadPushSettings(){
  const evWrap=document.getElementById('push-events-wrap'); if(!evWrap)return;
  let data;
  try{ data=await hubApi('/push/settings'); }catch(e){ evWrap.innerHTML='<div class="u-err-12">로드 실패: '+escapeHtml(e.message)+'</div>'; return; }
  const st=document.getElementById('push-config-status');
  if(st)st.innerHTML = data.configured ? '✅ 서버 알림(VAPID) 설정 완료' : '⚠️ 서버에 VAPID 키가 없어 알림이 동작하지 않습니다.';
  const ev=(data.settings&&data.settings.events)||{};
  evWrap.innerHTML=Object.entries(ev).map(([k,e])=>`
    <div class="push-ev" data-key="${escapeHtml(k)}">
      <label class="push-ev-head"><input type="checkbox" class="push-ev-on" ${e.enabled!==false?'checked':''}><b>${escapeHtml(e.label||k)}</b></label>
      <input class="admin-input push-ev-title" value="${escapeHtml(e.title||'')}" placeholder="알림 제목">
      <input class="admin-input push-ev-body" value="${escapeHtml(e.body||'')}" placeholder="본문 — {user}님이 '{target}' 등록">
    </div>`).join('');
  const incSel=new Set((data.settings&&data.settings.include)||[]);
  const excSel=new Set((data.settings&&data.settings.exclude)||[]);
  const um=window.__userMap||{};
  const team=(window.__teamNames&&window.__teamNames.length)?window.__teamNames:Object.keys(um);
  const nameOf=id=>{ const u=um[id]||{}; return u.displayName?`${u.displayName} (${id})`:id; };
  const renderPeople=(wrapId,selSet,cls)=>{
    const w=document.getElementById(wrapId); if(!w)return;
    w.innerHTML=team.length?team.map(id=>`<label class="push-person"><input type="checkbox" class="${cls}" value="${escapeHtml(id)}" ${selSet.has(id)?'checked':''}>${escapeHtml(nameOf(id))}</label>`).join(''):'<span class="u-muted-11">팀원 목록이 없습니다.</span>';
  };
  renderPeople('push-include-wrap',incSel,'push-inc');
  renderPeople('push-exclude-wrap',excSel,'push-exc');
  renderPeople('push-send-people',new Set(),'push-send-r');
  const sub=document.getElementById('push-subscribers');
  if(sub){
    const list=data.subscribers||[];
    const dev=list.reduce((n,s)=>n+(Number(s.devices)||0),0);
    sub.innerHTML=list.length
      ?('🔔 <b>구독된 기기</b> — '+list.length+'명 / '+dev+'대: '+list.map(s=>`${escapeHtml(nameOf(s.id))} <span class="u-muted">(${s.devices}대)</span>`).join(', ')+'<div style="font-size:10.5px;color:var(--text3);margin-top:6px">※ 알림을 켠 뒤 끄지 않은 기기 목록입니다(앱에서 끈 사람은 즉시 제외). 브라우저 권한을 끄거나 만료·삭제된 기기는 다음 알림 발송 시 자동 정리됩니다.</div>')
      :'아직 알림을 켠 사용자가 없습니다.';
  }
}
async function savePushSettings(){
  const events={};
  document.querySelectorAll('#push-events-wrap .push-ev').forEach(row=>{
    events[row.dataset.key]={ enabled:row.querySelector('.push-ev-on').checked, title:row.querySelector('.push-ev-title').value, body:row.querySelector('.push-ev-body').value };
  });
  const include=[...document.querySelectorAll('.push-inc:checked')].map(x=>x.value);
  const exclude=[...document.querySelectorAll('.push-exc:checked')].map(x=>x.value);
  try{ await hubApi('/push/settings',{method:'POST',body:JSON.stringify({events,include,exclude})}); toast('알림 설정 저장됨 ✓'); }
  catch(e){ toast('저장 실패: '+e.message,true); }
}
window.loadPushSettings=loadPushSettings; window.savePushSettings=savePushSettings;
async function sendDirectPush(){
  const title=(document.getElementById('push-send-title')||{}).value?.trim()||'';
  const body=(document.getElementById('push-send-body')||{}).value?.trim()||'';
  const recipients=[...document.querySelectorAll('.push-send-r:checked')].map(x=>x.value);
  const includeMuted=!!(document.getElementById('push-send-muted')||{}).checked;
  if(!title && !body){ toast('제목 또는 내용을 입력하세요.',true); return; }
  if(!recipients.length){ toast('받을 사람을 한 명 이상 선택하세요.',true); return; }
  if(!confirm(`${recipients.length}명에게 알림을 보냅니다.${includeMuted?' (알림 끈 사람 포함)':''}\n계속할까요?`)) return;
  try{
    const d=await hubApi('/push/send',{method:'POST',body:JSON.stringify({title,body,recipients,includeMuted})});
    const skip=(d.skipped&&d.skipped.length)?` · ${d.skipped.length}명 미수신(미구독/끔)`:'';
    toast(`알림 전송 완료: ${d.sent||0}건 발송${skip}`);
    const t=document.getElementById('push-send-title'); if(t)t.value='';
    const b=document.getElementById('push-send-body'); if(b)b.value='';
    document.querySelectorAll('.push-send-r:checked').forEach(c=>c.checked=false);
    const m=document.getElementById('push-send-muted'); if(m)m.checked=false;
  }catch(e){ toast('전송 실패: '+e.message,true); }
}
window.sendDirectPush=sendDirectPush;


/* =========================================================
   v1.5.5 안정화 패치
   - 이슈 상세 자동 선택/표시 보강
   - 고객사 상세에 일반 이슈 + 케이스 동시 표시
   - 고객사 상세 항목 클릭 시 해당 건만 필터링 이동
   - VirusTotal 최근 조회 이력 팀 공유(Worker /vt/history 연동)
   ========================================================= */
let VT_HISTORY_SHARED_LOADED=false;
function injectV154Style(){
  if(document.getElementById('v154-style'))return;
  const st=document.createElement('style');
  st.id='v154-style';
  st.textContent=`
    .mini-filter-note{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px 0}
    .mini-filter-note .tag{border:1px solid rgba(129,140,248,.35);background:rgba(99,102,241,.12);color:#dfe6ff;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:700}
    .customer-work-row{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;padding:9px 10px;border:1px solid var(--border);border-radius:10px;background:rgba(255,255,255,.025);cursor:pointer;margin-bottom:7px;transition:.12s ease}
    .customer-work-row:hover{border-color:rgba(129,140,248,.55);background:rgba(129,140,248,.09);transform:translateY(-1px)}
    .customer-work-row .k{font-weight:800;color:#cfe1ff;font-size:12px}.customer-work-row .t{font-size:11px;color:var(--text2);margin-top:2px;line-height:1.35}.customer-work-row .m{font-size:10px;color:var(--text3);white-space:nowrap}
    .vt-history-item{display:grid;grid-template-columns:minmax(150px,1fr) 70px 76px 84px;gap:8px;align-items:center;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.08);font-size:11px}
    .vt-history-item:last-child{border-bottom:0}.vt-history-hash{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#cfe1ff;overflow:hidden;text-overflow:ellipsis}.vt-history-meta{color:var(--text3);font-size:10px}
    @media(max-width:1200px){.vt-history-item{grid-template-columns:1fr 62px 66px}.vt-history-item .hide-narrow{display:none}}
  `;
  document.head.appendChild(st);
}
function escapeAttr(s){return escapeHtml(s).replace(/`/g,'&#96;');}
function v154LabelOfRange(value){
  const v=String(value||'');
  if(v==='today')return '오늘';
  if(v==='yesterday')return '어제';
  const days=parseInt(v,10);
  return days?`최근 ${days===7?'7일':days===30?'1개월':days===90?'3개월':days===180?'6개월':days===365?'1년':days+'일'}`:'';
}
function kstDateKey(input){
  const d=input instanceof Date?input:new Date(input);
  if(Number.isNaN(d.getTime()))return '';
  const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(d);
  const obj=Object.fromEntries(parts.filter(p=>p.type!=='literal').map(p=>[p.type,p.value]));
  return `${obj.year}-${obj.month}-${obj.day}`;
}
function relativeDateKey(offsetDays){
  const d=new Date();
  d.setDate(d.getDate()+offsetDays);
  return kstDateKey(d);
}
function dateFilterMatches(itemDate,value){
  const v=String(value||'');
  if(!v)return true;
  if(v==='today')return kstDateKey(itemDate)===relativeDateKey(0);
  if(v==='yesterday')return kstDateKey(itemDate)===relativeDateKey(-1);
  const days=parseInt(v,10);
  return days?age(itemDate)<=days:true;
}
function ensureRelativeDateOptions(){
  ['f-date','case-date'].forEach(id=>{
    const sel=document.getElementById(id);
    if(!sel||sel.dataset.relativeDates==='1')return;
    const hadToday=[...sel.options].some(o=>o.value==='today');
    if(!hadToday){
      const today=new Option('오늘','today');
      const yesterday=new Option('어제','yesterday');
      sel.add(yesterday, sel.options[1]||null);
      sel.add(today, sel.options[1]||null);
    }
    sel.dataset.relativeDates='1';
  });
}
function v154ActiveIssueFilterText(){
  const xs=[];
  const q=document.getElementById('f-q')?.value?.trim();
  const stat=document.getElementById('f-stat')?.value; const pri=document.getElementById('f-pri')?.value; const lab=document.getElementById('f-lab')?.value; const ass=document.getElementById('f-ass')?.value; const date=document.getElementById('f-date')?.value;
  if(ISSUE_PRESET)xs.push(ISSUE_PRESET.label||'대시보드 필터');
  if(q)xs.push('검색: '+q); if(stat)xs.push('상태: '+stat); if(pri)xs.push('우선순위: '+pri); if(lab)xs.push('레이블: '+lab); if(ass)xs.push('담당자: '+ass); if(date)xs.push(v154LabelOfRange(date));
  return xs;
}