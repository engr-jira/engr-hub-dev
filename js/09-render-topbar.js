
function issueRowHTML(i){
  const col=SC[i.status]||'#94a3b8';
  const priCol=i.pri==='High'?'#fc8181':i.pri==='Medium'?'#fcd34d':'#a5b4fc';
  const labels=(i.labels||[]).slice(0,3).map(l=>`<span class="badge" style="background:${(LC_MAP[l]||'#818cf8')}22;color:${(LC_MAP[l]||'#818cf8')}">${escapeHtml(l)}</span>`).join('');
  return `<div class="issue-card ${SEL&&SEL.key===i.key?'sel':''}" onclick="selectIssue(ISSUES.find(x=>x.key===${jsAttr(i.key)}))">
    <div class="issue-main">
      <span class="key">${escapeHtml(i.key)}</span>
      <span class="st" style="background:${col}22;color:${col}">${escapeHtml(i.status)}</span>
      <span class="pri" style="background:${priCol}22;color:${priCol}">${escapeHtml(i.pri)}</span>
      <span class="title">${escapeHtml(cleanTitle(i.title||i.summary||''))}</span>
      <span class="date">${fd(i.date||i.created)}</span>
      ${caseChipsForIssue(i)}
    </div>
    <div class="issue-sub">${labels}<span>@${escapeHtml(i.assignee||'-')}</span>${i.attachments&&i.attachments.length?`<span>첨부 ${i.attachments.length}</span>`:''}${i.comments&&i.comments.length?`<span>댓글 ${i.comments.length}</span>`:''}</div>
  </div>`;
}
function v154GoIssueExact(key){
  ISSUE_PRESET=null;
  const q=document.getElementById('f-q'); if(q)q.value=key;
  ['f-stat','f-pri','f-lab','f-ass','f-date'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  PAGE=1; showPage('issues');
  setTimeout(()=>{const item=v154GetIssueByKey(key); if(item)selectIssue(item);},20);
}
function v154GoCaseExact(key){
  CASE_PRESET=null;
  const q=document.getElementById('case-q'); if(q)q.value=key;
  ['case-stat','case-ass','case-sla','case-date'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  PAGE_STATE.cases=1; showPage('cases');
  setTimeout(()=>{const item=v154GetCaseByKey(key); if(item)selectCase(item);},20);
}
function caseCustomerName(c){
  if(!c)return '미분류';
  const productNames=new Set(['SEP','DLP','PP','S1','ESA','EPP','EMS','EDR','TS','AOS','AhnLab']);
  const usable=name=>!!(name&&String(name).trim()&&!productNames.has(String(name).trim()));
  const byKey=new Map((ISSUES||[]).map(i=>[i.key,i]));
  const parent=c.parentKey?byKey.get(c.parentKey):null;
  if(parent&&usable(parent.customer))return parent.customer;
  const fromParentTitle=extractCustomer(c.parentTitle||'');
  if(usable(fromParentTitle))return fromParentTitle;
  const linked=getGeneralIssues().find(i=>issueCaseMatches(i,c)&&i.customer);
  if(linked&&usable(linked.customer))return linked.customer;
  if(usable(c.customer))return c.customer;
  return '미분류';
}
function buildCustomers(){
  const map={};
  const ensure=name=>map[name]||(map[name]={name,issues:[],general:[],cases:[],products:new Set(),assignees:new Set()});
  getGeneralIssues().forEach(i=>{
    const name=i.customer||'미분류';
    const obj=ensure(name);
    obj.issues.push(i);obj.general.push(i);
    (i.labels||[]).forEach(l=>obj.products.add(l));
    if(i.assignee&&i.assignee!=='-')obj.assignees.add(i.assignee);
  });
  getCaseIssueBase().forEach(i=>{
    const name=caseCustomerName(i);
    const obj=ensure(name);
    obj.issues.push(i);obj.cases.push(i);
    (i.labels||[]).forEach(l=>obj.products.add(l));
    if(i.assignee&&i.assignee!=='-')obj.assignees.add(i.assignee);
  });
  return Object.values(map).sort((a,b)=>(b.general.length+b.cases.length)-(a.general.length+a.cases.length));
}
function buildCustomerData(){return buildCustomers();}
function metaMissingFields(i){
  if(!i)return [];
  const miss=[];
  if(!(i.customers&&i.customers.length))miss.push('고객사');
  if(!(i.labels&&i.labels.length))miss.push('레이블');
  if(!i.category||i.category==='N/A')miss.push('범주');
  if(!i.due)miss.push('기한');
  return miss;
}
function isHandsOn(i){return /hands[\s\-]?on/i.test((i&&i.title)||'');}
function isMetaIncomplete(i){ if(isHandsOn(i))return false; return metaMissingFields(i).length>0;}
function filterByPreset(list,preset){
  if(!preset)return list;
  let out=list;
  if(preset.kind==='status')out=out.filter(i=>preset.status==='done'?isDoneStatus(i.status):preset.status==='open'?isOpenStatus(i.status):true);
  if(preset.kind==='my')out=out.filter(isMyIssue);
  if(preset.kind==='myopen')out=out.filter(i=>isMyIssue(i)&&isOpenStatus(i.status));
  if(preset.kind==='stale'||preset.kind==='overdue')out=out.filter(i=>isOpenStatus(i.status)&&age(i.date)>=7);
  if(preset.kind==='high')out=out.filter(i=>isOpenStatus(i.status)&&String(i.pri||'').toLowerCase().includes('high'));
  if(preset.kind==='customer')out=out.filter(i=>isCaseIssue(i)?caseCustomerName(i)===preset.customer:(i.customer||'')===preset.customer);
  if(preset.kind==='priority')out=out.filter(i=>String(i.pri||'').toLowerCase().includes('high'));
  if(preset.kind==='incomplete')out=out.filter(i=>isOpenStatus(i.status)&&isMetaIncomplete(i));
  return out;
}
function renderTopbarStatus(){
  const right=document.querySelector('.topbar-right'); if(!right)return;
  const gi=getGeneralIssues().length, ci=getCaseIssueBase().length;
  const connected=!!(ISSUES&&ISSUES.length);
  right.innerHTML=`<div class="top-status">
    <div class="top-status-card"><span class="label">접속자</span><span class="value" id="top-user">${escapeHtml(CURRENT_DISPLAY||CURRENT_USER||'-')}</span></div>
    <button class="top-pin" onclick="openChangePinModal()">PIN 변경</button>
    <div class="top-status-card"><span class="label">Jira</span><span class="value ${connected?'ok':'warn'}" id="top-jira">${connected?'연결됨':'대기'}</span></div>
    <div class="top-status-card"><span class="label">동기화</span><span class="value" id="top-count">${gi||ci?`일반 ${gi} / 케이스 ${ci}`:'-'}</span></div>
    <button class="top-refresh" onclick="syncJira()" title="Jira 새로고침"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg></button>
    <button class="mob-search-btn" onclick="openMobSearch()" title="검색"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></button>
    <button class="top-logout" onclick="logout()">로그아웃</button>
  </div>`;
}
function renderTopbarStatusV159(){
  const right=document.querySelector('.topbar-right'); if(!right)return;
  // body로 빠져나간 모바일 메뉴 팝오버 잔여물 정리(중복 id 방지)
  const _stale=document.getElementById('top-menu-pop'); if(_stale && _stale.parentElement===document.body) _stale.remove();
  const gi=getGeneralIssues().length, ci=getCaseIssueBase().length;
  const connected=!!(ISSUES&&ISSUES.length);
  const manualHref=(IS_ADMIN||IS_SUPER)?'manual.html':'manual-user.html';
  const role=IS_SUPER?'슈퍼관리자':(IS_ADMIN?'관리자':'팀원');
  const uname=escapeHtml(CURRENT_DISPLAY||CURRENT_USER||'-');
  right.innerHTML=`<div class="top-status">
    <div class="top-clock" id="top-clock">
      <svg class="tc-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 1.8"/></svg>
      <span class="tc-date" id="tc-date">----.--.--</span>
      <span class="tc-time" id="tc-time">--:--:--</span>
    </div>
    <div class="top-menu">
      <button class="top-menu-btn" id="top-menu-btn" type="button" onclick="toggleTopMenu(event)" aria-haspopup="true" aria-expanded="false" title="메뉴">
        <svg class="tmb-av" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        <span class="tmb-user">${uname}</span>
        <svg class="tmb-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div class="top-menu-pop" id="top-menu-pop" role="menu">
        <div class="tmp-head">
          <div class="tmp-user"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>${uname}</div>
          <div class="tmp-role">${role}</div>
        </div>
        <div class="tmp-status"><span>Jira</span><span class="${connected?'ok':'warn'}" id="top-jira">${connected?'연결됨':'대기'}</span></div>
        <div class="tmp-status"><span>동기화</span><span id="top-count">${gi||ci?`일반 ${gi} / 케이스 ${ci}`:'-'}</span></div>
        <div class="tmp-status"><span>현재 화면</span><span id="top-theme-state">-</span></div>
        <div class="tmp-status" id="top-notif-state-row" style="display:none"><span>현재 알림</span><span id="top-notif-state">-</span></div>
        <div class="tmp-sep"></div>
        <button class="tmp-item" type="button" onclick="closeTopMenu();syncJira()"><span class="tmp-ic">🔄</span> Jira 새로고침</button>
        <button class="tmp-item" type="button" onclick="closeTopMenu();window.open('${manualHref}','_blank','noopener')"><span class="tmp-ic">📖</span> 사용 매뉴얼</button>
        <button class="tmp-item" type="button" id="tmp-install" style="display:none" onclick="pwaInstall()"><span class="tmp-ic">📲</span> 앱 설치</button>
        <button class="tmp-item" type="button" id="theme-toggle" onclick="toggleTheme()"><span class="tmp-ic theme-icon" id="theme-icon">☾</span> <span id="theme-label">다크</span> 모드</button>
        <button class="tmp-item" type="button" id="tmp-notif" style="display:none" onclick="togglePushFromMenu()"><span class="tmp-ic" id="tmp-notif-ic">🔔</span> <span id="tmp-notif-label">알림 켜기</span></button>
        <button class="tmp-item" type="button" onclick="closeTopMenu();openChangePinModal()"><span class="tmp-ic">🔑</span> PIN 변경</button>
        <div class="tmp-sep"></div>
        <button class="tmp-item tmp-danger" type="button" onclick="closeTopMenu();logout()"><span class="tmp-ic">🚪</span> 로그아웃</button>
      </div>
    </div>
  </div>`;
  syncThemeToggle();
  if(typeof syncInstallMenuItem==='function')syncInstallMenuItem();
  if(typeof syncNotifMenuItem==='function')syncNotifMenuItem();
  tickTopClock();
  if(!window.__topClockTimer)window.__topClockTimer=setInterval(tickTopClock,1000);
}
function tickTopClock(){
  const t=document.getElementById('tc-time'); if(!t)return;
  const d=new Date(); const dows=['일','월','화','수','목','금','토'];
  t.textContent=String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0')+':'+String(d.getSeconds()).padStart(2,'0');
  const dd=document.getElementById('tc-date'); if(dd)dd.textContent=`${d.getFullYear()}.${String(d.getMonth()+1).padStart(2,'0')}.${String(d.getDate()).padStart(2,'0')} (${dows[d.getDay()]})`;
}
function toggleTopMenu(e){
  if(e){e.stopPropagation();}
  const p=document.getElementById('top-menu-pop'); if(!p)return;
  const b=document.getElementById('top-menu-btn');
  const willOpen=!p.classList.contains('show');
  let mob=false; try{mob=window.matchMedia('(max-width:700px)').matches;}catch(_){}
  if(willOpen){
    if(mob && b){
      // iOS Safari: 상단바 backdrop-filter가 fixed 기준이 돼 메뉴가 잘림 → body로 빼서 뷰포트 기준 고정
      if(p.parentElement!==document.body) document.body.appendChild(p);
      const r=b.getBoundingClientRect();
      p.style.position='fixed';
      p.style.top=(r.bottom+6)+'px';
      p.style.right=Math.max(8,Math.round(window.innerWidth-r.right))+'px';
      p.style.left='auto';
      p.style.zIndex='2000';
    }else{
      p.style.position='';p.style.top='';p.style.right='';p.style.left='';p.style.zIndex='';
    }
    p.classList.add('show');
    if(b)b.setAttribute('aria-expanded','true');
  }else{ closeTopMenu(); }
}
function closeTopMenu(){ const p=document.getElementById('top-menu-pop'); if(p)p.classList.remove('show'); const b=document.getElementById('top-menu-btn'); if(b)b.setAttribute('aria-expanded','false'); }
document.addEventListener('click',e=>{ const m=document.querySelector('.top-menu'); const pop=document.getElementById('top-menu-pop'); if(m && !m.contains(e.target) && !(pop&&pop.contains(e.target))) closeTopMenu(); });
document.addEventListener('keydown',e=>{ if(e.key==='Escape')closeTopMenu(); });
renderTopbarStatus=renderTopbarStatusV159;
function enhanceDateButtons(){
  document.querySelectorAll('input[type="date"]').forEach(input=>{
    if(input.dataset.dateButton==='1')return;
    input.dataset.dateButton='1';
    const btn=document.createElement('button');
    btn.type='button';
    btn.className='date-open-btn';
    btn.textContent='📅';
    btn.title='달력 열기';
    btn.onclick=()=>{
      try{input.showPicker ? input.showPicker() : input.focus();}catch(_){input.focus();}
    };
    input.insertAdjacentElement('afterend',btn);
  });
}
function renderCases(){
  normalizeAllIssueAliases();
  if(typeof RESP_METRICS!=='undefined'&&RESP_METRICS===null){RESP_METRICS=[];try{loadRespMetrics();}catch(_){}}
  const wrap=document.getElementById('case-list'); if(!wrap)return;
  const arr=getFilteredCases();
  const size=PAGE_SIZES.cases||10;
  const pages=Math.max(1,Math.ceil(arr.length/size)); if(PAGE_STATE.cases>pages)PAGE_STATE.cases=pages;if(PAGE_STATE.cases<1)PAGE_STATE.cases=1;
  const count=document.getElementById('case-count');if(count)count.textContent=`${arr.length}건`;
  const rows=arr.slice((PAGE_STATE.cases-1)*size,PAGE_STATE.cases*size);
  wrap.innerHTML=v154FilterNoteHtml(v154ActiveCaseFilterText())+
    (rows.length?rows.map(c=>{
      const col=SC[c.status]||'#94a3b8';
      return `<div class="issue-card ${CASE_SEL&&CASE_SEL.key===c.key?'sel':''}" onclick="selectCase(v154GetCaseByKey(${jsAttr(c.key)}))">
        <div class="issue-main">
          <span class="key">${escapeHtml(c.caseNum||c.key)}</span>
          <span class="st" style="background:${col}22;color:${col}">${escapeHtml(c.status||'-')}</span>
          <span class="title">${escapeHtml(cleanTitle(c.title||c.summary||''))}</span>
          <span class="date">${fd(c.date||c.created)}</span>
        </div>
        <div class="issue-sub"><span>${escapeHtml(c.key)}</span><span>${escapeHtml(caseCustomerName(c)||'고객사 없음')}</span><span>@${escapeHtml(c.assignee||'미지정')}</span><span>${daysSince(c.date||c.created)}일</span>${typeof caseBallBadge==='function'?caseBallBadge(c.key):''}</div>
      </div>`;
    }).join(''):'<div class="empty">조건에 맞는 케이스가 없습니다.</div>');
  renderCompactPager('case-pager',PAGE_STATE.cases,pages,'setCasePage');
  renderCaseRight(false);
}
// ── 페이지 방문 비콘 : 세션당 페이지 1회만 전송(열람형 기능 사용 측정용) ──
const __pvSent={};
function beaconPageView(page){
  if(!CURRENT_USER||!page)return;
  if(__pvSent[page])return;
  __pvSent[page]=1;
  try{ fetch(`${WORKERS}/usage/pageview`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({page})}).catch(()=>{}); }catch(_){}
}
// ── 스케줄 AI 분석(B안) 뷰 : 생성은 스케줄 에이전트, 팀원은 조회만 ──
let ANALYSIS_KEYS=new Set(), ANALYSIS_BUILT=null;
function fmtBuiltAt(ts){ if(!ts)return ''; const d=new Date(ts); const p=n=>String(n).padStart(2,'0'); return `${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; }
async function loadAnalysisLatest(){
  try{
    const d=await hubApi('/analysis/latest');
    ANALYSIS_BUILT=d.built_at||null;
    ANALYSIS_KEYS=new Set(d.issueKeys||[]);
    renderAIBriefing(d);
  }catch(_){/* 데이터 없음/미로그인 = 조용히 */}
}
function renderAIBriefing(d){
  const wrap=document.getElementById('ai-brief-wrap'), title=document.getElementById('ai-brief-title');
  if(!wrap||!title)return;
  if(!d||(!d.team&&!(d.issueKeys||[]).length)){wrap.style.display='none';title.style.display='none';return;}
  title.style.display=''; wrap.style.display='';
  const t=d.team||{};
  const secs=[];
  if(t.monthly)secs.push(`<div class="chart-card"><h4>월간 동향</h4><div class="u-fs125px-lh17-ctext2-wsprewra">${escapeHtml(String(t.monthly))}</div></div>`);
  if(t.patterns)secs.push(`<div class="chart-card"><h4>고객사 패턴</h4><div class="u-fs125px-lh17-ctext2-wsprewra">${escapeHtml(String(t.patterns))}</div></div>`);
  if(t.focus)secs.push(`<div class="chart-card"><h4>오늘의 포커스</h4><div class="u-fs125px-lh17-ctext2-wsprewra">${escapeHtml(String(t.focus))}</div></div>`);
  wrap.innerHTML=`<div class="u-fs11px-ctext3-mb8px">🕐 ${fmtBuiltAt(d.built_at)} 기준 · 스케줄 분석(일 2회 07:00/15:30) · 이슈 분석 ${(d.issueKeys||[]).length}건</div><div class="chart-grid u-gridtemplatecolumns-repeatautofi">${secs.join('')||'<div class="chart-card"><div class="u-fs12px-ctext3">팀 리포트가 아직 없습니다</div></div>'}</div>`;
}
async function renderIssueAnalysis(key,secId){
  const sec=document.getElementById(secId||'ai-analysis-sec'); if(!sec||!key)return;
  const isAdm=(typeof IS_ADMIN!=='undefined'&&IS_ADMIN)||(typeof IS_SUPER!=='undefined'&&IS_SUPER)||!!window.__HUB_IS_ADMIN;
  const btn=isAdm?`<button class="btn btn-ghost" style="width:auto;padding:3px 10px;font-size:10.5px" onclick="requestReanalysis('${key}')">🔄 재분석 요청</button>`:'';
  sec.innerHTML=`<div class="u-fs10px-ctext3-fw700-m4px06p">🤖 AI 분석 (스케줄)</div><div class="sync-meta">불러오는 중...</div>`;
  try{
    const d=await hubApi('/analysis/issue/'+encodeURIComponent(key));
    const a=d.analysis;
    if(!a){sec.innerHTML=`<div class="u-fs10px-ctext3-fw700-m4px06p">🤖 AI 분석 (스케줄)</div><div style="font-size:11.5px;color:var(--text3);background:rgba(255,255,255,.03);border:1px dashed var(--border);border-radius:8px;padding:10px 12px;display:flex;justify-content:space-between;align-items:center;gap:8px"><span>이 이슈는 최근 분석 대상에 포함되지 않았습니다. 다음 주기(07:00/15:30)에 변경된 이슈 위주로 분석됩니다.</span>${btn}</div>`;return;}
    const rows=[];
    if(a.summary)rows.push(`<div class="u-mb-8px"><b style="color:var(--text)">📋 내용 요약</b><div class="u-ws-prewrap">${escapeHtml(String(a.summary))}</div></div>`);
    if(a.tech_analysis)rows.push(`<div class="u-mb-8px"><b style="color:#a78bfa">🧪 기술 분석</b><div class="u-ws-prewrap">${escapeHtml(String(a.tech_analysis))}</div></div>`);
    if(a.stall_reason)rows.push(`<div class="u-mb-8px"><b class="u-c-fbbf24">⏸ 정체 사유</b><div class="u-ws-prewrap">${escapeHtml(String(a.stall_reason))}</div></div>`);
    const dirArr=Array.isArray(a.direction)?a.direction:(a.direction?[a.direction]:(Array.isArray(a.next_actions)?a.next_actions:[]));
    if(dirArr.length)rows.push(`<div class="u-mb-8px"><b class="u-c-34d399">🧭 추천 진행 방향</b><ol style="margin:4px 0 0 18px;padding:0">${dirArr.map(x=>`<li style="margin-bottom:3px">${escapeHtml(String(x))}</li>`).join('')}</ol></div>`);
    if(a.reply_draft){const rid=(secId||'ai-analysis-sec')+'-reply';rows.push(`<div class="u-mb-8px"><div style="display:flex;justify-content:space-between;align-items:center"><b style="color:#22d3ee">✉️ 고객사 회신 멘트</b><button class="btn btn-ghost" style="width:auto;padding:2px 9px;font-size:10px" onclick="copyText(document.getElementById('${rid}').innerText)">📋 복사</button></div><div id="${rid}" style="white-space:pre-wrap;background:rgba(34,211,238,.06);border:1px solid rgba(34,211,238,.2);border-radius:8px;padding:9px 11px;margin-top:5px">${escapeHtml(String(a.reply_draft))}</div></div>`);}
    if(a.log_findings)rows.push(`<div style="margin-bottom:8px"><b style="color:#22d3ee">📎 첨부 로그 분석</b><div style="white-space:pre-wrap">${escapeHtml(String(a.log_findings))}</div></div>`);
    if(a.due_risk)rows.push(`<div><b class="u-c-f87171">⏰ 기한 리스크</b><div class="u-ws-prewrap">${escapeHtml(String(a.due_risk))}</div></div>`);
    sec.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center;margin:4px 0 6px"><span style="font-size:10px;color:var(--text3);font-weight:700">🤖 AI 분석 · ${fmtBuiltAt(a.built_at)} 기준</span>${btn}</div><div style="font-size:12px;line-height:1.65;color:var(--text2);background:rgba(129,140,248,.06);border:1px solid rgba(129,140,248,.22);border-radius:10px;padding:12px 14px">${rows.join('')||'<span class="u-muted">내용 없음</span>'}</div>`;
  }catch(e){sec.innerHTML=`<div class="u-muted-11">AI 분석 조회 실패: ${escapeHtml(e.message)}</div>`;}
}
async function requestReanalysis(key){
  try{ await hubApi('/analysis/request/'+encodeURIComponent(key),{method:'POST'}); toast(`${key} 재분석 요청 등록 — 다음 실행 시 우선 분석됩니다`); }
  catch(e){ toast('요청 실패: '+e.message,true); }
}
function showPage(name,btn){
  injectV154Style();injectV155Style();renderSidebarCompact();
  renderTopbarStatus();
  if(name==='dashboard')name='dash';
  if(name==='monitor' && !(typeof MONITOR_ALLOWED!=='undefined'&&MONITOR_ALLOWED&&(typeof FEATURE_FLAGS==='undefined'||FEATURE_FLAGS.monitor!==false)))name='dash';  // 비허용자 모니터 진입 차단
  if(name==='admin')name='settings';
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const page=document.getElementById('page-'+name); if(page)page.classList.add('active');
  document.querySelectorAll('.sb-btn').forEach(b=>b.classList.remove('active'));
  const nav=btn||document.getElementById('nav-'+name); if(nav)nav.classList.add('active');
  const titleMap={dash:'대시보드',issues:'이슈 관리',cases:'케이스 트래커',customers:'고객사 프로필',sales:'영업 현황',eos:'라이선스',vt:'VirusTotal 조회',links:'업무 링크',knowledge:'팀 노하우',audit:'감사 로그',settings:'관리자 설정',mydesk:'My Desk',compat:'호환성 매트릭스',monitor:'팀 업무 모니터'};
  const descMap={dash:'이슈 기반 보안기술팀 허브',issues:'Jira 일반 이슈 조회 및 AI 요약',cases:'제조사 케이스 번호 기준 추적',customers:'고객사별 이슈/케이스 현황',sales:'고객사 계약·갱신 기회 · 규칙 기반 실시간 집계',eos:'고객사 라이선스 만료 관리',vt:'해시 조회 및 제조사 신고',links:'업무 참고 링크 모음',knowledge:'팀 내부 노하우 문서',audit:'사용자 작업 이력',settings:'초기 데이터 및 저장소 관리',compat:'제품·OS 호환성 / EOS·EOL 매트릭스',monitor:'일/주 단위 팀 업무 갱신 현황'};
  const title=document.getElementById('page-title'); if(title)title.textContent=titleMap[name]||'HUB';
  const desc=document.getElementById('page-desc'); if(desc)desc.textContent=descMap[name]||'';
  expandActiveNavGroup(name);
  if(name==='mydesk'){
    window.__HUB_DISPLAY=CURRENT_DISPLAY||CURRENT_USER||'팀원';
    window.__HUB_IS_ADMIN=!!(IS_ADMIN||IS_SUPER);
    const tp=document.getElementById('md-team-report-panel');if(tp)tp.style.display=(IS_ADMIN||IS_SUPER)?'':'none';
    if(typeof loadMyDeskForUser==='function')loadMyDeskForUser();
  }
  if(name==='compat')loadCompat();
  if(name==='monitor')loadMonitor('daily');
  renderCurrent();
  ensureRelativeDateOptions();
  setTimeout(enhanceDateButtons,0);
  try{ beaconPageView(name); }catch(_){}
}
/* ── §1 호환성·EOS 매트릭스 ─────────────────────────── */
let COMPAT_ROWS=[];
const CMB='font-size:11px;padding:3px 7px;margin:0 1px;background:var(--card2,#1e293b);border:1px solid var(--border);border-radius:6px;color:var(--text,#e2e8f0);cursor:pointer';
function compatDday(d){ if(!d)return null; const t=new Date(d+'T00:00:00'); if(isNaN(t))return null; const today=new Date(); today.setHours(0,0,0,0); return Math.round((t-today)/86400000); }
function compatDdayHtml(d){ const n=compatDday(d); if(n===null)return ''; const col=n<0?'var(--danger)':n<=90?'var(--warn)':'var(--text3)'; const lab=n<0?`D+${-n}`:`D-${n}`; return `<br><span style="color:${col};font-weight:600;font-size:11px;white-space:nowrap">${lab}</span>`; }
async function loadCompat(){
  document.querySelectorAll('.compat-admin').forEach(b=>b.style.display=(IS_ADMIN||IS_SUPER)?'':'none');
  if(typeof vendorKbVersions==='function')vendorKbVersions();
  const wrap=document.getElementById('compat-table-wrap'); if(wrap)wrap.innerHTML='<div class="muted u-p-20px">불러오는 중...</div>';
  try{ const d=await hubApi('/compat'); COMPAT_ROWS=d.items||[]; }
  catch(e){ COMPAT_ROWS=[]; if(wrap)wrap.innerHTML=`<div class="u-cdanger-p20px">조회 실패: ${escapeHtml(e.message)}</div>`; return; }
  renderCompat();
}
function renderCompat(){
  const wrap=document.getElementById('compat-table-wrap'); if(!wrap)return;
  const q=(document.getElementById('compat-q')?.value||'').trim().toLowerCase();
  const admin=!!(IS_ADMIN||IS_SUPER);
  let rows=COMPAT_ROWS;
  if(q)rows=rows.filter(r=>[r.product,r.product_version,r.os,r.os_version,r.note,r.supported].some(v=>(v||'').toLowerCase().includes(q)));
  const sum=document.getElementById('compat-summary');
  if(sum)sum.textContent=`총 ${rows.length}행 · 확정 ${rows.filter(r=>r.status==='confirmed').length} · 초안 ${rows.filter(r=>r.status!=='confirmed').length}`;
  if(!rows.length){ wrap.innerHTML='<div class="muted u-p-20px">데이터가 없습니다.'+(admin?' “+ 행 추가” 또는 “AI 후보”로 등록하세요.':'')+'</div>'; return; }
  const supBadge=s=>{ s=s||''; const c=/미지원|불가|no/i.test(s)?'var(--danger)':/조건|부분|partial/i.test(s)?'var(--warn)':/지원|ok|yes/i.test(s)?'#34d399':'var(--text3)'; return `<span style="color:${c};font-weight:600">${escapeHtml(s||'-')}</span>`; };
  const head=`<tr>${admin?`<th class="nosort u-w-26px"><input type="checkbox" onclick="bulkSelectAll(this,'.cmp-pick')" title="전체 선택"></th>`:''}<th>제품</th><th>버전</th><th>OS</th><th>OS버전</th><th>지원</th><th>EOS</th><th>EOL</th><th>비고</th><th>상태</th>${admin?'<th>작업</th>':''}</tr>`;
  const body=rows.map(r=>`<tr>
    ${admin?`<td><input type="checkbox" class="cmp-pick" data-id="${r.id}"></td>`:''}<td><strong>${escapeHtml(r.product||'-')}</strong></td><td>${escapeHtml(r.product_version||'')}</td>
    <td>${escapeHtml(r.os||'')}</td><td class="c-osv">${escapeHtml(r.os_version||'')}</td>
    <td>${supBadge(r.supported)}</td>
    <td class="u-ws-nowrap">${r.eos_date?escapeHtml(r.eos_date)+compatDdayHtml(r.eos_date):'-'}</td>
    <td>${r.eol_date?escapeHtml(r.eol_date):'-'}</td>
    <td class="c-note">${escapeHtml(r.note||'')}${r.source?`<span class="cmp-src">출처: ${/^https?:\/\//.test(r.source)?`<a href="${escapeHtml(r.source)}" target="_blank" rel="noopener">${escapeHtml(r.source)}</a>`:escapeHtml(r.source)}</span>`:''}</td>
    <td>${r.status==='confirmed'?'<span style="color:#34d399;white-space:nowrap">✓ 확정</span>':'<span style="background:rgba(251,191,36,.15);color:#fbbf24;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700;white-space:nowrap">초안</span>'}</td>
    ${admin?`<td class="u-ws-nowrap">${r.status!=='confirmed'?`<button style="${CMB}" onclick="confirmCompat(${r.id})">확정</button>`:''}<button style="${CMB}" onclick="openCompatModal(${r.id})">수정</button><button style="${CMB};color:var(--danger)" onclick="deleteCompat(${r.id})">삭제</button></td>`:''}
  </tr>`).join('');
  wrap.innerHTML=`<table class="data-tbl srt">${head}${body}</table>`;
  const _st=wrap.querySelector('table.srt'); if(_st)applySrtState(_st);
}
function openCompatModal(id){
  const m=document.getElementById('compat-modal'); if(!m)return;
  const row=id?COMPAT_ROWS.find(r=>r.id===id):null;
  document.getElementById('compat-modal-title').textContent=row?'행 수정':'행 추가';
  document.getElementById('cm-id').value=row?row.id:'';
  ['product','product_version','os','os_version','supported','eos_date','eol_date','note','source'].forEach(k=>{const el=document.getElementById('cm-'+k);if(el)el.value=row?(row[k]||''):'';});
  m.style.display='flex';
}
function closeCompatModal(){ const m=document.getElementById('compat-modal'); if(m)m.style.display='none'; }
async function saveCompat(){
  const id=document.getElementById('cm-id').value;
  const get=k=>document.getElementById('cm-'+k)?.value?.trim()||'';
  const payload={product:get('product'),product_version:get('product_version'),os:get('os'),os_version:get('os_version'),supported:get('supported'),eos_date:get('eos_date'),eol_date:get('eol_date'),note:get('note'),source:get('source')};
  if(!payload.product){toast('제품명을 입력하세요');return;}
  try{ await hubApi(id?`/compat/${id}`:'/compat',{method:id?'PUT':'POST',body:JSON.stringify(payload)}); toast(id?'수정했습니다':'추가했습니다 (초안)'); closeCompatModal(); loadCompat(); }
  catch(e){ toast('저장 실패: '+e.message); }
}
async function confirmCompat(id){ if(!confirm('이 행을 확정 처리할까요? (공식 기준으로 노출)'))return; try{ await hubApi(`/compat/${id}/confirm`,{method:'POST'}); toast('확정했습니다'); loadCompat(); }catch(e){ toast('실패: '+e.message); } }
async function deleteCompat(id){ if(!confirm('이 행을 삭제할까요?'))return; try{ await hubApi(`/compat/${id}`,{method:'DELETE'}); toast('삭제했습니다'); loadCompat(); }catch(e){ toast('실패: '+e.message); } }
async function confirmAllDrafts(){
  const drafts=(COMPAT_ROWS||[]).filter(r=>r.status!=='confirmed');
  if(!drafts.length){toast('확정할 초안이 없습니다');return;}
  if(!confirm(`초안 ${drafts.length}건을 모두 확정할까요? (공식 기준으로 노출)`))return;
  let ok=0,fail=0;
  for(const r of drafts){ try{ await hubApi(`/compat/${r.id}/confirm`,{method:'POST'}); ok++; }catch(_){ fail++; } }
  toast(`${ok}건 확정${fail?(' · '+fail+'건 실패'):''}`); loadCompat();
}
/* ── §1 벤더 KB (DLP/SEP) System Requirements 바로가기 ── */
const _SEPSYS='https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/release-notes/system-requirements-for-v53308029-d69e1453.html';
const _SEPNEW='https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/release-notes/what-s-new-for-all-releases-of-14-x-v117739871-d43e160.html';
const _SEPRN='https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/release-notes/';  // 버전별 What's New base (curl 200 검증)
const _SEPPDF='https://techdocs.broadcom.com/content/dam/broadcom/techdocs/us/en/dita/symantec-security-software/endpoint-security-and-management/endpoint-protection/generated-pdfs/';
const _DLP='https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/';
const VENDOR_KB={
  // eos: Broadcom 라이프사이클 기준 지원종료일(리서치 워크플로 다중소스 검증). 드롭다운 라벨에만 표기, 값(v)은 불변.
  DLP:[
    {v:'26.1',eos:'2028-10-31',sysreq:_DLP+'26-1/dlp-system-requirements.html',whatsnew:_DLP+'26-1/new-and-changed/what-s-new-in-data-loss-prevention.html',notes:_DLP+'26-1/new-and-changed/release-notes.html'},
    {v:'25.1',eos:'2028-01-31',sysreq:_DLP+'25-1/dlp-system-requirements.html',whatsnew:_DLP+'25-1/new-and-changed/what-s-new-in-data-loss-prevention.html',notes:_DLP+'25-1/new-and-changed/release-notes.html'},
    {v:'16.1',eos:'2027-04-30',sysreq:_DLP+'16-1/dlp-system-requirements.html',whatsnew:_DLP+'16-1/new-and-changed/what-s-new-in-data-loss-prevention.html',notes:_DLP+'16-1/new-and-changed/release-notes.html'},
    {v:'16.1 MP1',eos:'2027-04-30',sysreq:_DLP+'16-1/dlp-system-requirements.html',whatsnew:_DLP+'16-1/new-and-changed/what-s-new-in-data-loss-prevention.html',notes:_DLP+'16-1/release-notes/symantec-data-loss-prevention-16-1-mp1-release-notes.html'},
    {v:'16.0 RU2 (16.0.2)',eos:'2026-06-20',sysreq:_DLP+'16-0-2/dlp-system-requirements/system-requirements-and-recommendations.html',notes:_DLP+'16-0-2/release-notes/dlp-16-0-ru2-release-notes.html'},
    {v:'16.0 RU1 (16.0.1)',eos:'2026-06-20',sysreq:_DLP+'16-0-1/DLP-system-requirements/system-requirements-and-recommendations-v19666017-d366e1680.html'},
    {v:'16.0.1 MP1',eos:'2026-06-20',sysreq:_DLP+'16-0-1/DLP-system-requirements/system-requirements-and-recommendations-v19666017-d366e1680.html',notes:_DLP+'16-0-1/about-these-release-notes-v123654044-d333e11/symantec-data-loss-prevention-16-0-1-mp1-release-notes.html'},
    {v:'16.0 MP1',eos:'2026-06-20',sysreq:_DLP+'16-0/DLP-system-requirements.html',notes:_DLP+'16-0/Release-Notes/symantec-data-loss-prevention-16-0-mp1-release-notes.html'},
    {v:'16.0',eos:'2026-06-20',sysreq:_DLP+'16-0/DLP-system-requirements.html'},
    {v:'15.8',eos:'2025-04-30',sysreq:'https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/information-security/data-loss-prevention/generated-pdfs/Symantec_DLP_15-8_System_Requirements_Guide.pdf'}
  ],
  SEP:[
    // SEP: Broadcom 공개 KB에 EOS 미발표(=지원중) → eos 라벨 없음. 패치 서브버전은 전용 PDF가 없어 부모 RU 문서 상속.
    {v:'14.4',sysreq:_SEPSYS,whatsnew:_SEPRN+'what-s-new-for-symantec-endpoint-protection-144.html',notes:_SEPPDF+'Release-Notes-SEP14-4.pdf'},
    {v:'14.3 RU10',sysreq:_SEPSYS,whatsnew:_SEPRN+'Whats-new-for-Symantec-Endpoint-Protection-14-3-RU10.html',notes:_SEPPDF+'Release-Notes-SEP14-3RU10.pdf'},
    {v:'14.3 RU10 Patch 1',sysreq:_SEPSYS,whatsnew:_SEPRN+'Whats-new-for-Symantec-Endpoint-Protection-14-3-RU10.html',notes:_SEPPDF+'Release-Notes-SEP14-3RU10.pdf'},
    {v:'14.3 RU9',sysreq:_SEPSYS,whatsnew:_SEPRN+'Whats-new-for-Symantec-Endpoint-Protection-14-3-RU9.html',notes:_SEPPDF+'Release-Notes-SEP14-3RU9.pdf'},
    {v:'14.3 RU9 Patch 2',sysreq:_SEPSYS,whatsnew:_SEPRN+'Whats-new-for-Symantec-Endpoint-Protection-14-3-RU9.html',notes:_SEPPDF+'Release-Notes-SEP14-3RU9.pdf'},
    {v:'14.3 RU8',sysreq:_SEPSYS,whatsnew:_SEPRN+'Whats-new-for-Symantec-Endpoint-Protection-14-3-RU8.html',notes:_SEPPDF+'Release-Notes-SEP14-3RU8.pdf'},
    {v:'14.3 RU8 Patch 3',sysreq:_SEPSYS,whatsnew:_SEPRN+'Whats-new-for-Symantec-Endpoint-Protection-14-3-RU8.html',notes:_SEPPDF+'Release-Notes-SEP14-3RU8.pdf'}
  ]
};
function vendorKbVersions(){
  const prodEl=document.getElementById('vendor-kb-product'); if(!prodEl)return;
  const prod=prodEl.value, sel=document.getElementById('vendor-kb-version'), today=new Date();
  if(sel)sel.innerHTML=(VENDOR_KB[prod]||[]).map(x=>{
    let suf=''; if(x.eos){ suf=' · EOS '+x.eos+((new Date(x.eos)<today)?' ⚠만료':''); }
    return `<option value="${escapeHtml(x.v)}">${escapeHtml(x.v+suf)}</option>`;
  }).join('');
  vendorKbUpdateButtons();
}
function vendorKbEntry(){ const p=document.getElementById('vendor-kb-product')?.value, v=document.getElementById('vendor-kb-version')?.value; return (VENDOR_KB[p]||[]).find(x=>x.v===v); }
function vendorKbUpdateButtons(){
  const e=vendorKbEntry()||{};
  const set=(id,on)=>{const b=document.getElementById(id);if(b)b.style.display=on?'':'none';};
  set('vkb-sysreq',!!e.sysreq); set('vkb-new',!!e.whatsnew); set('vkb-notes',!!e.notes);
}
function openVendorKb(which){
  const e=vendorKbEntry(); if(!e){toast('버전을 선택하세요');return;}
  const url=e[which]; if(!url){toast('해당 링크가 없습니다');return;}
  window.open(url,'_blank','noopener');
}

let COMPAT_AI_CANDS=[];
const CURATED_COMPAT={
  DLP:{
    '26.1':{src:'https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/26-1/dlp-system-requirements/supported_platforms/endpoint-computer-requirements-for-the-symantec-dlp-agent.html',rows:[
      {os:'Windows (DLP Agent)',os_version:'Windows 11 23H2 / 24H2 / 25H2 (Pro·Enterprise)',supported:'지원',note:'엔드포인트 에이전트. ARM64(23H2/24H2/25H2). VC++ 2015–2022 재배포 필요'},
      {os:'Windows Server (DLP Agent)',os_version:'2019 / 2022 / 2025 (Desktop Experience, Credential Guard)',supported:'지원',note:'엔드포인트 에이전트'},
      {os:'macOS (DLP Agent)',os_version:'Sonoma 14.0–14.7.6 / Sequoia 15.0–15.6 / Tahoe 26–26.4',supported:'지원',note:'엔드포인트 에이전트. Sonoma(14.x) deprecated'},
      {os:'Linux (DLP Agent)',os_version:'RHEL 8.6–8.10 / RHEL 9.0–9.7 / Ubuntu 24.04 LTS',supported:'지원',note:'엔드포인트 에이전트'}
    ]},
    '25.1':{src:'https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/25-1/dlp-system-requirements/supported_platforms/endpoint-computer-requirements-for-the-symantec-dlp-agent.html',rows:[
      {os:'Windows (DLP Agent)',os_version:'Windows 10 20H1–22H2 / Windows 11 23H2–25H2',supported:'지원',note:'엔드포인트 에이전트. Windows 10 deprecated. ARM64(23H2/24H2). VC++ 재배포 필요'},
      {os:'Windows Server (DLP Agent)',os_version:'2019 / 2022 / 2025 (Desktop Experience, Credential Guard)',supported:'지원',note:'엔드포인트 에이전트'},
      {os:'macOS (DLP Agent)',os_version:'Ventura 13.0.1–13.6.7 / Sonoma 14.0–14.7.6 / Sequoia 15.0–15.6 / Tahoe 26–26.4',supported:'지원',note:'엔드포인트 에이전트. Ventura(13.x) deprecated'},
      {os:'Linux (DLP Agent)',os_version:'RHEL 8.4–8.8 / Ubuntu 22.04 LTS',supported:'지원',note:'엔드포인트 에이전트'}
    ]},
    '16.0 RU2 (16.0.2)':{src:'https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-0-2/dlp-system-requirements/system-requirements-and-recommendations/endpoint-computer-requirements-for-the-symantec-dlp-agent.html',rows:[
      {os:'Windows (DLP Agent)',os_version:'Windows 10 21H2/22H2 · Windows 11 21H2/22H2/23H2/24H2/25H2 (Enterprise 64-bit)',supported:'지원',note:'엔드포인트 에이전트. 25H2는 16.0.2만 지원. 마이너버전 best-effort'},
      {os:'Windows Server (DLP Agent)',os_version:'2016 / 2019 / 2022 (64-bit)',supported:'지원',note:'엔드포인트 에이전트'},
      {os:'macOS (DLP Agent)',os_version:'Monterey 12.0–12.7 / Ventura 13.0–13.6 / Sonoma 14.0–14.7 / Sequoia 15.0–15.6 / macOS 26',supported:'지원',note:'엔드포인트 에이전트. Monterey(12.x) deprecated. macOS 26은 16.0.2만. Big Sur/Catalina 미지원'},
      {os:'Linux (DLP Agent)',os_version:'RHEL 7.9, 8.4–8.8 / Ubuntu 20.04 LTS, 22.04 LTS',supported:'지원',note:'엔드포인트 에이전트. RHEL 8.8은 16.0.2만'}
    ]},
    '16.1':{src:'https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-1/dlp-system-requirements/system-requirements-and-recommendations/endpoint-computer-requirements-for-the-symantec-dlp-agent.html',rows:[
      {os:'Windows (DLP Agent)',os_version:'Windows 10 20H2/21H2/22H2 · Windows 11 21H2/22H2/23H2/24H2/25H2 (Enterprise 64-bit)',supported:'지원',note:'엔드포인트 에이전트. Server 2012 R2 미지원. 마이너버전 reasonable-effort'},
      {os:'Windows Server (DLP Agent)',os_version:'2016 / 2019 / 2022 (64-bit)',supported:'지원',note:'엔드포인트 에이전트'},
      {os:'macOS (DLP Agent)',os_version:'Ventura 13.0–13.6.7 / Sonoma 14.0–14.6.1 / Sequoia 15.0–15.6 / macOS 26–26.4',supported:'지원',note:'엔드포인트 에이전트. Ventura(13.x) deprecated'},
      {os:'Linux (DLP Agent)',os_version:'RHEL 8.4–8.8 / Ubuntu 20.04 LTS, 22.04 LTS',supported:'지원',note:'엔드포인트 에이전트. RHEL 7.9는 16.1에서 deprecated'}
    ]}
  },
  SEP:{}
};
function vendorCuratedMatrix(){
  const prod=document.getElementById('vendor-kb-product')?.value;
  const ver=(document.getElementById('vendor-kb-version')?.value||'').trim();
  const e=vendorKbEntry();
  const cur=(CURATED_COMPAT[prod]||{})[ver];
  if(!cur){ toast('이 버전의 검증 데이터가 아직 없습니다 — 관리자에게 공식 문서 검증 등록을 요청하세요.',true); return; }
  const brand='Symantec '+prod;
  COMPAT_AI_CANDS=cur.rows.map(o=>({product:brand,product_version:ver,os:o.os||'',os_version:o.os_version||'',supported:o.supported||'지원',eos_date:(e&&e.eos)||'',eol_date:'',note:o.note||'',source:cur.src}));
  showCompatAICandidates(true);
}
function showCompatAICandidates(mode){
  const m=document.getElementById('compat-ai-modal'), body=document.getElementById('compat-ai-rows'); if(!m||!body)return;
  const _tt=document.getElementById('compat-ai-title'), _wn=document.getElementById('compat-ai-warn');
  const _v=(mode===true||mode==='verified'), _off=(mode==='official');
  if(_tt)_tt.innerHTML=_v?'📋 검증 호환성 데이터 <span class="u-muted-11-400">· 공식 문서 기준 · 검토 후 저장</span>':_off?'🌐 공식 문서 기반 추출 <span class="u-muted-11-400">· Broadcom 페이지에서 추출 · 검토 후 저장</span>':'🤖 AI 호환성 후보 <span class="u-muted-11-400">· 검토 후 초안 저장</span>';
  if(_wn)_wn.innerHTML=_v?'✅ Broadcom 공식 System Requirements 기준으로 큐레이션된 데이터입니다. 저장 시 <b>초안</b>으로 들어가며 확인 후 <b>확정</b>하세요.':_off?'🌐 Broadcom 공식 페이지에서 AI가 추출한 데이터입니다(창작 아님). 저장 전 원문과 대조해 확인하세요.':'⚠ AI 추정값입니다. 저장 시 모두 <b>초안</b>으로 들어가며, 표에서 검토·수정 후 <b>확정</b>하세요.';
  body.innerHTML=COMPAT_AI_CANDS.map((r,i)=>`<tr>
    <td><input type="checkbox" class="cai-pick" data-i="${i}" checked></td>
    <td>${escapeHtml(r.product||'')}</td>
    <td>${escapeHtml(r.product_version||'')}</td>
    <td>${escapeHtml((r.os||'')+' '+(r.os_version||''))}</td>
    <td>${escapeHtml(r.supported||'-')}</td>
    <td style="max-width:220px">${escapeHtml(r.note||'')}</td>
  </tr>`).join('');
  m.style.display='flex';
}
function closeCompatAICandidates(){ const m=document.getElementById('compat-ai-modal'); if(m)m.style.display='none'; }
async function saveCompatAICandidates(){
  const picks=[...document.querySelectorAll('#compat-ai-rows .cai-pick:checked')].map(c=>COMPAT_AI_CANDS[+c.dataset.i]).filter(Boolean);
  if(!picks.length){toast('저장할 행을 선택하세요');return;}
  let ok=0;
  for(const r of picks){ try{ await hubApi('/compat',{method:'POST',body:JSON.stringify(r)}); ok++; }catch(_){} }
  closeCompatAICandidates(); toast(`${ok}/${picks.length}건 초안 저장`); loadCompat();
}
function copyCompatTable(){
  const q=(document.getElementById('compat-q')?.value||'').trim().toLowerCase();
  let rows=COMPAT_ROWS; if(q)rows=rows.filter(r=>[r.product,r.product_version,r.os,r.os_version,r.note,r.supported].some(v=>(v||'').toLowerCase().includes(q)));
  const head=['제품','버전','OS','OS버전','지원','EOS','EOL','비고','상태'];
  const lines=[head.join('\t')].concat(rows.map(r=>[r.product,r.product_version,r.os,r.os_version,r.supported,r.eos_date,r.eol_date,(r.note||'').replace(/\s+/g,' '),r.status==='confirmed'?'확정':'초안'].map(v=>v||'').join('\t')));
  navigator.clipboard.writeText(lines.join('\n')).then(()=>toast(`표 ${rows.length}행을 복사했습니다`)).catch(()=>toast('복사 실패'));
}
/* ── §5 기능 토글 ───────────────────────────────────── */
let FEATURE_FLAGS={compat:true,history:true,monitor:true};
const FEATURE_SPECIAL=[['history','고객사 업무 이력']];
const FEATURE_PROTECTED={settings:1,dash:1};
const FEATURE_WARN={audit:'끄면 감사 로그 메뉴가 숨겨집니다(역할 권한은 그대로).'};