
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
    if(q&&!txt.includes(q))return false; if(cStat&&c.status!==cStat)return false; if(cAss&&c.assignee!==cAss)return false; if(cSla&&c.age<cSla)return false;
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
async function lookupVT(){
  const input=document.getElementById('vt-hash'); const hash=input.value.trim(); const resBox=document.getElementById('vt-result');
  if(!hash){resBox.innerHTML='<div class="alert warn">해시값을 입력하세요.</div>';return;}
  resBox.innerHTML='<div class="empty">VirusTotal 조회 중...</div>';
  try{
    const data=await api('/vt/lookup?hash='+encodeURIComponent(hash));
    const attrs=data.data?.attributes||{}; const stats=attrs.last_analysis_stats||{};
    const total=(stats.harmless||0)+(stats.malicious||0)+(stats.suspicious||0)+(stats.undetected||0);
    const danger=(stats.malicious||0)+(stats.suspicious||0);
    resBox.innerHTML=`<div class="vt-card"><h3>${danger>0?'⚠️ 탐지됨':'✅ 미탐지'}</h3><div class="vt-stats"><div><span>악성</span><b>${stats.malicious||0}</b></div><div><span>의심</span><b>${stats.suspicious||0}</b></div><div><span>정상</span><b>${stats.harmless||0}</b></div><div><span>전체</span><b>${total}</b></div></div><p style="margin-top:12px;color:var(--text2);font-size:12px">${escapeHtml(attrs.meaningful_name||attrs.type_description||'파일 정보 없음')}</p><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px"><a class="btn" target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/${encodeURIComponent(hash)}">VirusTotal에서 보기</a><a class="btn" target="_blank" rel="noopener" href="https://symsubmit.symantec.com/">제조사 신고</a></div></div>`;
    await loadSharedVTHistory(true);
  }catch(e){
    resBox.innerHTML=`<div class="alert error">조회 실패: ${escapeHtml(e.message||String(e))}</div><div class="u-mt-10px"><a class="btn" target="_blank" rel="noopener" href="https://symsubmit.symantec.com/">제조사 신고</a></div>`;
  }
}
/* ── v1.5.5 hotfix: AI usage card polish + Jira render routing ───────────── */
function injectV155Style(){
  if(document.getElementById('v155-style'))return;
  const st=document.createElement('style');
  st.id='v155-style';
  st.textContent=`
    .usage-card.ai-usage-v155{border:1px solid rgba(103,232,249,.18);background:linear-gradient(180deg,rgba(103,232,249,.08),rgba(45,230,184,.045));box-shadow:0 10px 28px rgba(0,0,0,.16)}
    .ai-usage-v155 .u-head{margin-bottom:8px!important}.ai-usage-v155 .u-title{display:flex;align-items:center;gap:7px;color:#c7f9ff!important;letter-spacing:0}
    .ai-usage-v155 .u-dot{width:8px;height:8px;border-radius:50%;background:#2de6b8;box-shadow:0 0 0 4px rgba(45,230,184,.1)}
    .ai-usage-v155 .pill-btn{border-radius:8px!important;border:1px solid rgba(103,232,249,.28)!important;background:rgba(103,232,249,.1)!important;color:#dffbff!important;padding:4px 8px!important;font-size:9px!important}
    .ai-usage-v155 .usage-total{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:8px}
    .ai-usage-v155 .usage-total span{font-size:9px;color:var(--text3);font-weight:700}.ai-usage-v155 .usage-total b{font-size:18px;color:#f8faff;line-height:1}
    .ai-usage-v155 .usage-meter{height:6px;background:rgba(255,255,255,.08);border-radius:999px;overflow:hidden;margin:7px 0 9px}
    .ai-usage-v155 .usage-meter>div{height:100%;border-radius:999px;background:linear-gradient(90deg,#2de6b8,#67e8f9);transition:width .25s ease}
    .ai-usage-v155 .u-grid{grid-template-columns:1fr auto!important;gap:5px 10px!important}.ai-usage-v155 .u-muted{font-size:10px}.ai-usage-v155 .u-val{font-size:10px}
    .ai-usage-v155 .u-split{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px}
    .ai-usage-v155 .u-mini{border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.035);border-radius:8px;padding:6px}
    .ai-usage-v155 .u-mini span{display:block;font-size:9px;color:var(--text3);margin-bottom:3px}.ai-usage-v155 .u-mini b{font-size:11px;color:#f4f7ff}
    .ai-usage-v155 .u-foot{border-top:1px solid rgba(255,255,255,.08);padding-top:6px;text-align:left!important}
    .health-card .sync-mini{background:rgba(255,255,255,.08)!important;border-color:rgba(255,255,255,.18)!important;color:#e8edff!important}
    .issue-list{display:flex;flex-direction:column;gap:8px}
    .issue-card{background:rgba(255,255,255,.035);border:1px solid rgba(129,140,248,.18);border-left:3px solid rgba(103,232,249,.42);border-radius:8px;padding:11px 13px;cursor:pointer;transition:background .12s ease,border-color .12s ease,transform .12s ease}
    .issue-card:hover,.issue-card.sel{background:rgba(99,102,241,.12);border-color:rgba(129,140,248,.48);transform:translateY(-1px)}
    .issue-main{display:grid;grid-template-columns:auto auto auto minmax(0,1fr) auto;gap:7px;align-items:center;min-width:0}
    .issue-main .key{font-size:12px;font-weight:900;color:#cfe1ff;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
    .issue-main .st,.issue-main .pri{font-size:10px;font-weight:800;border-radius:6px;padding:3px 6px;white-space:nowrap}
    .issue-main .title{font-size:13px;font-weight:700;color:#f8faff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
    .issue-main .date{font-size:11px;color:var(--text3);white-space:nowrap}
    .issue-sub{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:7px;font-size:11px;color:var(--text3)}
    .issue-sub .badge{font-size:9px;border-radius:6px;padding:2px 6px;font-weight:800}
    .case-chip-wrap{grid-column:1/-1;display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-top:2px;min-width:0}
    .case-chip{display:inline-flex;align-items:center;gap:4px;max-width:100%;border-radius:999px;padding:3px 8px;font-size:10px;font-weight:900;line-height:1.2;white-space:nowrap;border:1px solid rgba(255,255,255,.1);cursor:pointer}
    .case-chip.open{background:rgba(45,212,191,.16);border-color:rgba(45,212,191,.34);color:#5eead4}
    .case-chip.done{background:rgba(99,102,241,.16);border-color:rgba(129,140,248,.36);color:#c4b5fd}
    input[type="date"]{color-scheme:dark}
    input[type="date"]::-webkit-calendar-picker-indicator{opacity:.01;cursor:pointer}
    .date-open-btn{height:36px;min-width:48px;border-radius:8px;border:1px solid rgba(103,232,249,.45);background:#dff8ff;color:#0f172a;font-size:11px;font-weight:900;font-family:inherit;cursor:pointer;box-shadow:0 0 12px rgba(103,232,249,.22);padding:0 10px}
    .date-open-btn:hover{background:#f2fdff;border-color:#a5f3fc}
    .modal-form input[type="date"]{width:calc(100% - 62px)!important;display:inline-block!important;vertical-align:middle;margin-right:8px}
    .modal-form input[type="date"]+.date-open-btn,.private-editor input[type="date"]+.date-open-btn{vertical-align:middle}
    .private-editor .filter-row{display:grid!important;grid-template-columns:1fr 1fr minmax(130px,1fr) 48px;align-items:center;gap:8px}
    .private-editor .filter-row select,.private-editor .filter-row input{height:36px!important;margin-bottom:0!important;min-width:0!important}
    .private-editor .filter-row .date-open-btn{height:36px;margin:0;padding:0 9px}
    .knowledge-card{min-height:186px;max-height:230px;overflow:hidden}
    .knowledge-excerpt{display:-webkit-box;-webkit-line-clamp:7;-webkit-box-orient:vertical;overflow:hidden}
    .detail-actions{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px!important;margin-top:8px}
    .detail-actions .btn,.case-ai-grid .btn{height:32px!important;min-height:32px;box-sizing:border-box!important;padding:0 10px!important;border-radius:8px!important;font-size:11px!important;line-height:1!important;width:100%!important;white-space:nowrap;display:flex!important;align-items:center!important;justify-content:center!important}
    .detail-actions .wide,.case-ai-grid .wide{grid-column:1/-1}
    .detail-link-row{display:flex;justify-content:flex-end;gap:6px;margin-top:7px}
    .detail-link-row .btn{width:auto!important;height:30px!important;min-height:30px;padding:0 11px!important;border-radius:8px!important;font-size:10.5px!important}
    .case-ai-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:7px!important;margin-top:8px!important;margin-bottom:7px!important}
    .topbar-right .search-box{display:none!important}
    .sb-bottom .health-card{display:none!important}
    .top-status{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
    .top-status-card{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);border-radius:10px;padding:7px 10px;min-height:34px}
    .top-status-card .label{font-size:9px;color:var(--text3);font-weight:800;letter-spacing:.2px}
    .top-status-card .value{font-size:11px;color:#f5f8ff;font-weight:900;white-space:nowrap}
    .top-status-card .ok{color:#2de6b8}.top-status-card .warn{color:#fcd34d}
    .top-refresh,.top-logout,.top-pin{height:34px;border-radius:10px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.08);color:#eaf0ff;font-family:inherit;font-size:11px;font-weight:900;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:0 10px}
    .top-pin{color:#dffbff;border-color:rgba(103,232,249,.28);background:rgba(103,232,249,.08)}
    .top-refresh{width:36px;padding:0}.top-refresh svg{width:15px;height:15px}.top-refresh:hover,.top-logout:hover,.top-pin:hover{background:rgba(129,140,248,.2);border-color:rgba(129,140,248,.42)}
    #page-nav,#case-pager{display:flex!important;justify-content:flex-end!important;align-items:center!important;gap:6px!important;background:transparent!important;border:0!important;padding:8px 0!important}
    #page-nav button,#case-pager button{background:#262d47;border:1px solid rgba(129,140,248,.25);color:#dfe6ff;border-radius:7px;padding:6px 10px;font-size:11px;font-weight:800;font-family:inherit;cursor:pointer}
    #page-nav button.active,#case-pager button.active{background:#6366f1;border-color:#818cf8;color:#fff}
    #page-nav button:disabled,#case-pager button:disabled{opacity:.38;cursor:not-allowed}
    .private-layout{display:grid;grid-template-columns:360px minmax(0,1fr);gap:16px}
    .private-editor{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;align-self:start}
    .private-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}.private-head strong{font-size:13px}.private-head span{font-size:10px;color:var(--text3)}
    .private-editor input,.private-editor textarea{width:100%;background:#1b2034;border:1px solid var(--border2);border-radius:8px;color:var(--text);padding:10px 11px;margin-bottom:8px;font-family:inherit;font-size:12px}
    .private-editor textarea{min-height:140px;resize:vertical;line-height:1.5}
    .private-actions{display:flex;gap:6px;margin-top:8px}.private-actions button{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);color:var(--text2);border-radius:7px;padding:5px 8px;font-size:10px;cursor:pointer}
    .private-done{opacity:.65}.private-done .title{text-decoration:line-through;color:var(--text3)}
    @media(max-width:1100px){.private-layout{grid-template-columns:1fr}}
    @media(max-width:1200px){.issue-main{grid-template-columns:auto auto minmax(0,1fr) auto}.issue-main .pri{display:none}}
    @media(max-width:700px){
      *{box-sizing:border-box}
      html,body{width:100%;max-width:100%;overflow-x:hidden}
      #app{min-height:100vh;background:var(--bg);max-width:100%;overflow-x:hidden}
      main{width:100%;max-width:100%;min-width:0;overflow-x:hidden;padding:10px!important}
      .content,.page,.panel,.admin-card,.card,.issue-card,.case-card,.link-card,.k-card,.storage-summary,.file-drop{max-width:100%;min-width:0;overflow-wrap:anywhere}
      .issue-main{display:grid!important;grid-template-columns:auto minmax(0,1fr)!important;gap:6px!important;align-items:center!important}
      .issue-main .title{grid-column:1/-1;white-space:normal!important;overflow:visible!important;text-overflow:clip!important;line-height:1.45}
      .issue-main .date{grid-column:1/-1}.issue-sub{flex-wrap:wrap;gap:6px}
      .link-url,.link-title,.link-desc{word-break:break-all;overflow-wrap:anywhere}
      aside{position:sticky;top:0;z-index:80;background:rgba(22,27,39,.98);box-shadow:0 8px 24px rgba(0,0,0,.28);max-width:100%;overflow:hidden}
      .sb-top{padding:10px 10px 8px}
      .sb-brand{margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid rgba(255,255,255,.08)}
      .sb-logo{width:32px;height:32px;border-radius:10px}.sb-logo svg{width:17px;height:17px}.sb-name{font-size:14px}.sb-sub{font-size:9px}
      .sb-nav{display:flex;gap:6px;overflow-x:auto;overflow-y:hidden;padding:2px 10px 10px 10px;margin:0 -10px;scroll-snap-type:x proximity;-webkit-overflow-scrolling:touch}
      .sb-nav::-webkit-scrollbar{height:0}
      .sb-btn{flex:0 0 auto;width:auto;min-width:max-content;padding:8px 10px;border-radius:999px;font-size:11px;scroll-snap-align:start;white-space:nowrap}
      .sb-btn svg{width:14px;height:14px;flex:0 0 14px}.sb-bottom{display:none!important}
      header{position:sticky;top:0;z-index:70;margin:-10px -10px 10px;padding:8px 10px;background:rgba(15,18,28,.96);border-bottom:1px solid rgba(255,255,255,.08);backdrop-filter:blur(10px)}
      .topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;width:100%;min-width:0}
      .top-left{min-width:0;flex:1}.top-title{font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.top-desc{display:none}
      .top-status{display:flex!important;gap:6px;overflow-x:auto;overflow-y:hidden;max-width:54vw;padding-bottom:2px;-webkit-overflow-scrolling:touch;flex-wrap:nowrap}
      .top-status::-webkit-scrollbar{height:0}
      .top-status-card,.top-pin,.top-refresh,.top-logout{flex:0 0 auto;height:32px;min-height:32px;border-radius:999px;padding:0 9px;white-space:nowrap}
      .top-status-card{gap:6px}.top-status-card .label{display:none}.top-status-card .value{font-size:10px}.top-status-card .dot{width:7px;height:7px}.top-pin,.top-logout{font-size:10px}.top-refresh{width:32px;padding:0}
      .sec-title{font-size:15px;margin:6px 0 10px}.alert{padding:10px 12px;font-size:11px;line-height:1.55}
      .chart-grid,.two-col,.storage-summary-top,.storage-grid{grid-template-columns:1fr!important;gap:10px!important}
      .filter-row{display:grid!important;grid-template-columns:1fr!important;gap:6px!important;align-items:stretch!important}
      .filter-row input,.filter-row select,.filter-row button,.page-size-select{width:100%!important;min-width:0!important;max-width:100%!important;height:36px;font-size:12px;margin:0!important}
      .private-editor .filter-row{display:grid!important;grid-template-columns:1fr 1fr!important}
      .private-editor .filter-row select{grid-column:1/-1}
      .private-editor .filter-row input[type="date"]{grid-column:1/2}.private-editor .filter-row .date-open-btn{grid-column:2/3;width:100%!important}
      .admin-section{border-radius:12px;margin-bottom:10px;max-width:100%}
      .admin-section>summary{padding:12px;display:grid;grid-template-columns:1fr auto;align-items:center;gap:8px;font-size:12px}
      .admin-section>summary small{grid-column:1/-1;white-space:normal;font-size:9.5px;line-height:1.4}.admin-section>summary:after{grid-row:1;grid-column:2;font-size:9px;padding:3px 7px}
      .admin-section .admin-card{margin:10px;padding:14px;border-radius:12px}.admin-card h3{font-size:12.5px}
      .admin-row{display:grid!important;grid-template-columns:1fr!important;gap:6px!important;align-items:stretch!important}.admin-row label{min-width:0!important}
      .admin-input,.admin-textarea,.admin-row input,.admin-row select,.admin-add-row input,.admin-add-row select{width:100%!important;min-width:0!important;max-width:100%!important}
      .admin-add-row,.storage-actions,.safe-actions,.danger-actions{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}.admin-add-row .btn,.storage-actions .btn{width:100%!important;min-width:0!important;max-width:100%!important}
      #kb-seed-btn,#log-btn{width:100%!important;max-width:100%!important}
      #log-product{width:100%!important;min-width:0!important}.log-textarea,.admin-textarea{font-size:11px;min-height:130px}.file-drop{padding:14px!important}
      #page-vt [style*="display:flex"]{flex-wrap:wrap!important}
      #vt-input{width:100%!important;min-width:0!important;flex:1 1 100%!important}.vt-history-item,.vt-hist-row{grid-template-columns:1fr!important;gap:4px!important}.vt-history-item .hide-narrow{display:none!important}
      .eos-table,.audit-table{display:block;width:100%;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;border-spacing:0}.eos-table thead,.eos-table tbody,.eos-table tr,.audit-table thead,.audit-table tbody,.audit-table tr{min-width:620px}.eos-table th,.eos-table td,.audit-table th,.audit-table td{white-space:nowrap}
      .audit-detail{max-width:220px;white-space:nowrap}.pager{gap:6px;flex-wrap:wrap}.pager button{min-width:64px}
      [style*="minmax(320px"],[style*="minmax(340px"],[style*="grid-template-columns:repeat(auto-fit,minmax(320px"],[style*="grid-template-columns:repeat(auto-fit,minmax(340px"]{grid-template-columns:1fr!important}
      .link-desc,.link-url,.link-meta{display:none!important}
      .link-card{gap:8px;min-height:38px;padding:6px 10px}
      .link-cat{min-width:52px!important;font-size:8px}
      .link-card .link-actions{opacity:1!important}
    }
  `;
  document.head.appendChild(st);
}
function normalizeIssueAliases(i){
  if(!i)return i;
  i.summary=i.summary||i.title||'';
  i.title=i.title||i.summary||'';
  i.created=i.created||i.date||'';
  i.date=i.date||i.created||'';
  i.updated=i.updated||i.updatedAt||i.date||i.created||'';
  i.age=daysSince(i.date||i.created);
  return i;
}
const normalizeJiraIssueV154=normalizeJiraIssue;
normalizeJiraIssue=function(i){return normalizeIssueAliases(normalizeJiraIssueV154(i));};
function normalizeAllIssueAliases(){(ISSUES||[]).forEach(normalizeIssueAliases);}
function daysOld(d){return daysSince(d);}
function fmtDate(d){return fd(d);}
function getCaseNum(text){return getCasePrefixNum(text);}
function renderSidebarCompact(){
  injectV155Style();
  const box=document.querySelector('.sb-bottom');
  if(!box)return;
  box.dataset.v153='1';
  const gi=getGeneralIssues().length, ci=getCaseIssueBase().length;
  const jiraState=ISSUES&&ISSUES.length?'<span class="dot dot-green"></span>연결됨':'<span class="dot u-bg-warn"></span>대기';
  box.innerHTML=`
    <div class="health-card">
      <div class="h-head"><div class="h-title">연결/동기화</div><span class="u-muted-10" id="issue-count">${gi||ci?`일반 ${gi} / 케이스 ${ci}`:'-'}</span></div>
      <div class="h-row"><span>접속자</span><span class="h-state">${escapeHtml(CURRENT_DISPLAY||CURRENT_USER||'-')}</span></div>
      <div class="h-row"><span>Jira</span><span class="h-state ${ISSUES&&ISSUES.length?'ok':''}" id="jira-dot">${jiraState}</span></div>
      <div class="h-row"><span>AI</span><span class="h-state ok" id="ai-status">준비됨</span></div>
      <button class="btn btn-ghost sync-mini" onclick="syncJira()">Jira 새로고침</button>
      <div class="u-foot" id="sync-meta" style="font-size:9px;color:var(--text3);margin-top:5px">-</div>
      <div class="u-foot" id="session-timer" style="font-size:9px;color:var(--text3);margin-top:4px;text-align:center"></div>
      <button onclick="logout()" style="width:100%;margin-top:4px;background:none;border:0;color:var(--text3);font-size:9px;cursor:pointer;font-family:inherit">로그아웃</button>
    </div>`;
  renderTopbarStatus();
}
function renderDash(){
  applyV153Dom();injectV155Style();normalizeAllIssueAliases();
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
  const ops=document.getElementById('ops-focus');
  if(ops)ops.innerHTML=[
    focusCardHtml('7일 이상 미완료 일반 이슈',stale,'대상 없음',i=>`<div class="dash-list-row" onclick="v154GoIssueExact(${jsAttr(i.key)})"><span class="title"><b>${escapeHtml(i.key)}</b> ${escapeHtml(cleanTitle(i.title)).slice(0,48)}</span><span>${daysSince(i.date)}일</span></div>`),
    focusCardHtml('High 이상 미완료 일반 이슈',highOpen,'대상 없음',i=>`<div class="dash-list-row" onclick="v154GoIssueExact(${jsAttr(i.key)})"><span class="title"><b>${escapeHtml(i.key)}</b> ${escapeHtml(cleanTitle(i.title)).slice(0,48)}</span><span>${escapeHtml(i.pri)}</span></div>`),
    focusCardHtml('진행 중 케이스',cOpen,'대상 없음',i=>`<div class="dash-list-row" onclick="v154GoCaseExact(${jsAttr(i.key)})"><span class="title"><b>${escapeHtml(i.caseNum||i.key)}</b> ${escapeHtml(cleanTitle(i.title)).slice(0,48)}</span><span>${daysSince(i.date)}일</span></div>`)
  ].join('');
  const handled=document.getElementById('rank-handled'); if(handled)handled.innerHTML=topAssigneeRows(g);
  const rate=document.getElementById('rank-rate'); if(rate)rate.innerHTML=completionRateRows(g);
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
  const inc=getGeneralIssues().filter(i=>isOpenStatus(i.status)&&isMetaIncomplete(i));
  if(!inc.length){wrap.innerHTML=`<div class="chart-card u-mb-16px"><div class="chart-title">📋 주요 항목 미기입 점검</div><div style="font-size:12px;color:var(--success);padding:8px 2px">✓ 미완료 일반 이슈의 핵심 항목(고객사·레이블·범주·기한)이 모두 입력되어 있습니다.</div></div>`;return;}
  // 담당자별 집계
  const byAss={};
  inc.forEach(i=>{const a=i.assignee||'(미지정)';if(!byAss[a])byAss[a]={count:0,fields:{}};byAss[a].count++;metaMissingFields(i).forEach(f=>{byAss[a].fields[f]=(byAss[a].fields[f]||0)+1;});});
  const rows=Object.entries(byAss).sort((a,b)=>b[1].count-a[1].count).map(([name,info])=>{
    const fieldChips=Object.entries(info.fields).sort((a,b)=>b[1]-a[1]).map(([f,n])=>`<span style="display:inline-block;background:rgba(251,191,36,.12);color:#fbbf24;border-radius:6px;padding:1px 7px;font-size:10px;margin:1px">${f} ${n}</span>`).join(' ');
    return `<div onclick="setIssueNavigationFilter({assignee:${jsAttr(name==='(미지정)'?'':name)},preset:{kind:'incomplete',label:${jsAttr('메타 미완성 · '+name)}}})" style="display:flex;align-items:center;gap:10px;padding:9px 6px;border-bottom:1px solid var(--border);cursor:pointer">
      <span style="min-width:90px;font-size:13px;font-weight:700;color:var(--text)">${escapeHtml(name)}</span>
      <span style="background:rgba(248,113,113,.15);color:#f87171;border-radius:7px;padding:2px 9px;font-size:12px;font-weight:700">${info.count}건</span>
      <span style="flex:1;text-align:right">${fieldChips}</span>
    </div>`;
  }).join('');
  wrap.innerHTML=`<div class="chart-card u-mb-16px">
    <div class="chart-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>📋 주요 항목 미기입 점검 — 담당자별 (${inc.length}건)</span>
      <button onclick="setIssueNavigationFilter({preset:{kind:'incomplete',label:'메타 미완성 일반 이슈'}})" class="btn btn-ghost u-btn-xxs">전체 보기 →</button>
    </div>
    <div class="u-fs11px-ctext3-mb6px">미완료 일반 이슈 중 고객사·레이블·범주·기한이 빠진 건. 담당자 클릭 시 해당 미기입 이슈로 이동합니다.</div>
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
function trendSvg(g,c){
  const keys=[];
  for(let n=5;n>=0;n--){const d=new Date();d.setMonth(d.getMonth()-n);keys.push(d.toISOString().slice(0,7));}
  const vals=keys.map(k=>({k,g:g.filter(i=>String(i.date).slice(0,7)===k).length,c:c.filter(i=>String(i.date).slice(0,7)===k).length}));
  const max=Math.max(1,...vals.map(v=>v.g+v.c));
  const pts=vals.map((v,idx)=>`${30+idx*68},${118-(v.g+v.c)/max*90}`).join(' ');
  return `<polyline points="${pts}" fill="none" stroke="#67e8f9" stroke-width="3"/><g>${vals.map((v,idx)=>`<circle cx="${30+idx*68}" cy="${118-(v.g+v.c)/max*90}" r="4" fill="#2de6b8"/><text x="${30+idx*68}" y="135" text-anchor="middle" fill="#7b89aa" font-size="9">${v.k.slice(5)}</text>`).join('')}</g>`;
}
function renderCurrent(){
  normalizeAllIssueAliases();
  const active=document.querySelector('.page.active');
  const id=(active&&active.id||'page-dash').replace('page-','');
  if(id==='dash')renderDash();
  else if(id==='issues')renderIssues();
  else if(id==='cases')renderCases();
  else if(id==='customers')renderCustomers();
  else if(id==='eos')renderEosList();
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
  const nums=new Set([1,totalPages,page-1,page,page+1]);
  const ordered=[...nums].filter(n=>n>=1&&n<=totalPages).sort((a,b)=>a-b);
  let last=0;
  const buttons=[];
  ordered.forEach(n=>{
    if(last&&n-last>1)buttons.push('<span style="color:var(--text3);padding:0 4px">…</span>');
    buttons.push(`<button class="${page===n?'active':''}" onclick="${setter}(${n})">${n}</button>`);
    last=n;
  });
  el.innerHTML=`<button ${page<=1?'disabled':''} onclick="${setter}(${page-1})">이전</button>${buttons.join('')}<button ${page>=totalPages?'disabled':''} onclick="${setter}(${page+1})">다음</button>`;
}
function setIssuePage(n){PAGE=n;renderIssues();}
function setCasePage(n){PAGE_STATE.cases=n;renderCases();}
function renderIssues(){
  normalizeAllIssueAliases();
  const wrap=document.getElementById('issue-list-wrap'); if(!wrap)return;
  const arr=getFilteredIssues();
  const size=parseInt(document.getElementById('f-pg')?.value||'10',10)||10;
  const pages=Math.max(1,Math.ceil(arr.length/size)); if(PAGE>pages)PAGE=pages;if(PAGE<1)PAGE=1;
  const count=document.getElementById('f-count');if(count)count.textContent=`${arr.length}건`;
  const pageItems=arr.slice((PAGE-1)*size,PAGE*size);
  wrap.innerHTML=v154FilterNoteHtml(v154ActiveIssueFilterText())+
    (pageItems.length?pageItems.map(issueRowHTML).join(''):'<div class="empty">조건에 맞는 일반 이슈가 없습니다.</div>');
  renderCompactPager('page-nav',PAGE,pages,'setIssuePage');
  renderIssueFilterTags();
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
      const col=SC[c.status]||'#94a3b8';
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
    <div style="font-size:16px;font-weight:800;color:#f0f4ff;margin-bottom:14px">${escapeHtml(c.name)}</div>
    <div class="rp-meta">
      <div class="rp-row"><span>제품</span><span style="flex-wrap:wrap;display:flex;gap:4px">${[...(c.products||[])].map(p=>`<span class="badge" style="background:${(LC_MAP[p]||'#94a3b8')}22;color:${(LC_MAP[p]||'#94a3b8')}">${escapeHtml(p)}</span>`).join('')||'-'}</span></div>
      <div class="rp-row"><span>담당자</span><span>${escapeHtml([...(c.assignees||[])].join(', ')||'-')}</span></div>
      <div class="rp-row"><span>일반 이슈</span><span>${general.length}건 (완료 ${done.length} / 미완료 ${open.length})</span></div>
      <div class="rp-row"><span>케이스</span><span>${cases.length}건 (완료 ${caseDone.length} / 미완료 ${caseOpen.length})</span></div>
      <div class="rp-row"><span>일반 이슈 완료율</span><span style="color:${rate>=80?'#2de6b8':rate>=50?'#fcd34d':'#fc8181'};font-weight:700">${rate}%</span></div>
      <div class="rp-row"><span>라이선스</span><span>${eosForCust.length}건${nearLic!==null?` · 최단 <b style="color:${nearLic<0?'#f87171':nearLic<=30?'#fbbf24':'#22d3a5'}">${nearLic<0?'만료':'D-'+nearLic}</b>`:''}</span></div>
    </div>
    <div class="jump-row"><button class="btn btn-ghost" onclick="setIssueNavigationFilter({preset:{kind:'customer',customer:${jsAttr(c.name)},label:${jsAttr('고객사: '+c.name)}}})">일반 이슈 보기</button><button class="btn btn-ghost" onclick="setCaseNavigationFilter({preset:{kind:'customer',customer:${jsAttr(c.name)},label:${jsAttr('고객사 케이스: '+c.name)}}})">케이스 보기</button></div>
    <div style="font-size:10px;color:var(--text3);font-weight:700;margin:12px 0 8px;text-transform:uppercase">최근 일반 이슈</div>${recent.map(i=>row(i,'issue')).join('')||'<div class="empty">최근 일반 이슈 없음</div>'}
    <div class="u-fs10px-ctext3-fw700-m14px08-ttupperc">최근 케이스</div>${recentCases.map(i=>row(i,'case')).join('')||'<div class="empty">최근 케이스 없음</div>'}
    <div class="u-fs10px-ctext3-fw700-m14px08-ttupperc">🔑 라이선스</div>${eosForCust.length?eosForCust.map(e=>`<div class="customer-work-row" onclick="showPage('eos',document.getElementById('nav-eos'))"><div><div class="k">${escapeHtml(e.productDesc||e.product||'-')}</div><div class="t">${escapeHtml(e.serial||e.siteId||'')}</div></div><div class="m">${e.expireDate?'~ '+escapeHtml(e.expireDate):'-'}</div></div>`).join(''):'<div class="empty">등록된 라이선스 없음</div>'}
  </div>`;
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