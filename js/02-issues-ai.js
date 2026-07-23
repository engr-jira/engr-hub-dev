

// ── DASHBOARD ─────────────────────────────────────


// renderDash — v1.5.5 최종 정의는 파일 하단에 있음 (중복 제거됨)
function renderDash_legacy_v1(){
  const total=ISSUES.length;
  const done=ISSUES.filter(i=>i.status==='완료').length;
  const prog=ISSUES.filter(i=>['진행 중','진행중','In Progress'].includes(i.status)).length;
  const high=ISSUES.filter(i=>['High','Highest'].includes(i.pri)).length;
  const myIssues=ISSUES.filter(i=>i.assignee===CURRENT_USER);
  const myDone=myIssues.filter(i=>i.status==='완료').length;
  const myRate=myIssues.length?Math.round(myDone/myIssues.length*100):0;
  document.getElementById('kpi-wrap').innerHTML=`
    <div class="kpi" style="--kpi-c1:#4f46e5;--kpi-c2:#818cf8"><div class="kpi-val">${total}</div><div class="kpi-label">전체 이슈</div><div class="kpi-sub">팀 전체</div></div>
    <div class="kpi" style="--kpi-c1:#059669;--kpi-c2:#22d3a5"><div class="kpi-val">${done}</div><div class="kpi-label">완료</div><div class="kpi-sub">${total?Math.round(done/total*100):0}% 완료율</div></div>
    <div class="kpi" style="--kpi-c1:#2563eb;--kpi-c2:#60a5fa"><div class="kpi-val">${prog}</div><div class="kpi-label">진행중</div><div class="kpi-sub">처리 중</div></div>
    <div class="kpi" style="--kpi-c1:#d97706;--kpi-c2:#fbbf24"><div class="kpi-val">${high}</div><div class="kpi-label">High+</div><div class="kpi-sub">우선처리</div></div>
    <div class="kpi" style="--kpi-c1:#7c3aed;--kpi-c2:#a78bfa"><div class="kpi-val">${myIssues.length}</div><div class="kpi-label">내 담당</div><div class="kpi-sub">${escapeHtml(CURRENT_USER)}</div></div>
    <div class="kpi" style="--kpi-c1:#be185d;--kpi-c2:#f472b6"><div class="kpi-val">${myRate}%</div><div class="kpi-label">내 완료율</div><div class="kpi-sub">${myDone}/${myIssues.length}건</div></div>`;

  const cusCnt={},labCnt={},priCnt={};
  ISSUES.forEach(i=>{
    if(i.customer)cusCnt[i.customer]=(cusCnt[i.customer]||0)+1;
    i.labels.forEach(l=>{labCnt[l]=(labCnt[l]||0)+1;});
    priCnt[i.pri]=(priCnt[i.pri]||0)+1;
  });
  const maxC=Math.max(1,...Object.values(cusCnt));
  const maxL=Math.max(1,...Object.values(labCnt));
  const noData='<div class="u-ctext3-fs11px">데이터 없음</div>';
  document.getElementById('chart-section').innerHTML=`
  <div class="chart-card"><h4>고객사별 분포 TOP 8</h4>
  ${Object.entries(cusCnt).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([k,v])=>`
  <div class="bar-row"><div class="bar-lbl" title="${escapeHtml(k)}">${escapeHtml(k)}</div>
  <div class="bar-track"><div class="bar-fill" style="width:${Math.round(v/maxC*100)}%;background:linear-gradient(90deg,#4f46e5,#6366f1)"><span class="bar-n">${v}</span></div></div></div>`).join('')||noData}
  </div>
  <div class="chart-card"><h4>레이블별 분포</h4>
  ${Object.entries(labCnt).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([k,v])=>`
  <div class="bar-row"><div class="bar-lbl">${escapeHtml(k)}</div>
  <div class="bar-track"><div class="bar-fill" style="width:${Math.round(v/maxL*100)}%;background:${labelColor(k)}88"><span class="bar-n">${v}</span></div></div></div>`).join('')||noData}
  </div>
  <div class="chart-card"><h4>우선순위별</h4>
  ${['Highest','High','Medium','Low'].map(p=>{const v=priCnt[p]||0;const mx=Math.max(1,...Object.values(priCnt));return`
  <div class="bar-row"><div class="bar-lbl">${p}</div>
  <div class="bar-track"><div class="bar-fill" style="width:${Math.round(v/mx*100)}%;background:${PC[p]||'#94a3b8'}aa"><span class="bar-n">${v}</span></div></div></div>`;}).join('')}
  </div>`;

  // 팀원 랭킹
  const byAssignee={};
  ISSUES.forEach(i=>{
    if(!i.assignee||i.assignee==='-')return;
    if(!byAssignee[i.assignee])byAssignee[i.assignee]={total:0,done:0};
    byAssignee[i.assignee].total++;
    if(i.status==='완료')byAssignee[i.assignee].done++;
  });
  const ranked=Object.entries(byAssignee).map(([n,v])=>({name:n,...v,rate:v.total?Math.round(v.done/v.total*100):0}));
  const byHandled=[...ranked].sort((a,b)=>b.total-a.total).slice(0,8);
  const maxH=Math.max(1,...byHandled.map(x=>x.total));
  document.getElementById('rank-handled').innerHTML=byHandled.map((r,idx)=>`
  <div class="rank-row">
    <span class="rank-pos ${idx===0?'top1':idx===1?'top2':idx===2?'top3':''}">${idx+1}</span>
    <span class="rank-name">${escapeHtml(r.name)}${r.name===CURRENT_USER?' <span class="u-caccent-fs9px">(나)</span>':''}</span>
    <span class="rank-stat">${r.total}건</span>
    <div class="rank-bar"><div class="rank-bar-fill" style="width:${Math.round(r.total/maxH*100)}%"></div></div>
  </div>`).join('')||noData;
  const byRate=ranked.filter(x=>x.total>=5).sort((a,b)=>b.rate-a.rate).slice(0,8);
  document.getElementById('rank-rate').innerHTML=byRate.map((r,idx)=>`
  <div class="rank-row">
    <span class="rank-pos ${idx===0?'top1':idx===1?'top2':idx===2?'top3':''}">${idx+1}</span>
    <span class="rank-name">${escapeHtml(r.name)}${r.name===CURRENT_USER?' <span class="u-caccent-fs9px">(나)</span>':''}</span>
    <span class="rank-stat">${r.rate}% (${r.done}/${r.total})</span>
    <div class="rank-bar"><div class="rank-bar-fill" style="width:${r.rate}%"></div></div>
  </div>`).join('')||'<div class="u-ctext3-fs11px">5건 이상 담당자 없음</div>';

  // 월별 추이
  const monthCnt={};
  for(let m=5;m>=0;m--){const d=new Date();d.setMonth(d.getMonth()-m);monthCnt[d.toISOString().slice(0,7)]={c:0,d:0};}
  ISSUES.forEach(i=>{if(!i.date)return;const k=i.date.slice(0,7);if(monthCnt[k]){monthCnt[k].c++;if(i.status==='완료')monthCnt[k].d++;}});
  const mks=Object.keys(monthCnt);
  const maxM=Math.max(1,...mks.map(k=>monthCnt[k].c));
  const W=400,H=140,P=20;
  const xStep=(W-P*2)/(mks.length-1||1);
  let pathC='',pathD='',pts='';
  mks.forEach((k,idx)=>{
    const x=P+xStep*idx;
    const yC=H-P-(monthCnt[k].c/maxM)*(H-P*2);
    const yD=H-P-(monthCnt[k].d/maxM)*(H-P*2);
    pathC+=(idx===0?'M':'L')+x+','+yC+' ';
    pathD+=(idx===0?'M':'L')+x+','+yD+' ';
    pts+=`<text x="${x}" y="${H-5}" fill="#94a3b8" font-size="9" text-anchor="middle">${k.slice(2,7)}</text>`;
    pts+=`<circle cx="${x}" cy="${yC}" r="3" fill="#818cf8"/>`;
    pts+=`<circle cx="${x}" cy="${yD}" r="3" fill="#22d3a5"/>`;
    pts+=`<text x="${x}" y="${yC-6}" fill="#a5b4fc" font-size="9" text-anchor="middle">${monthCnt[k].c}</text>`;
  });
  document.getElementById('trend-chart').innerHTML=`
    <path d="${pathC}" stroke="#818cf8" stroke-width="2" fill="none"/>
    <path d="${pathD}" stroke="#22d3a5" stroke-width="2" fill="none" stroke-dasharray="3,3"/>
    ${pts}
    <text x="${W-10}" y="15" fill="#818cf8" font-size="10" text-anchor="end">전체</text>
    <text x="${W-10}" y="30" fill="#22d3a5" font-size="10" text-anchor="end">완료</text>`;

  const dl=document.getElementById('dash-list');
  dl.innerHTML=ISSUES.slice(0,10).map(i=>issueRowHTML(i,false)).join('');
  dl.querySelectorAll('.irow').forEach((el,idx)=>{el.onclick=()=>{showPage('issues',document.getElementById('nav-issues'));selectIssue(ISSUES[idx]);};});

  renderEosBanner();
  renderOverdueBanner();
}

// ── ISSUES ────────────────────────────────────────
function renderIssues_legacy_v1(){
  renderFilterTags();
  const fi=filteredIssues();
  const pgSize=parseInt(document.getElementById('f-pg')?.value||'20');
  const totalPages=Math.max(1,Math.ceil(fi.length/pgSize));
  if(PAGE>totalPages)PAGE=1;
  const start=(PAGE-1)*pgSize;
  const pageItems=fi.slice(start,start+pgSize);
  document.getElementById('f-count').textContent=`${fi.length}건 (${PAGE}/${totalPages})`;
  const wrap=document.getElementById('issue-list-wrap');
  wrap.innerHTML=pageItems.map(i=>issueRowHTML(i,true,SEL&&SEL.key===i.key)).join('');
  wrap.querySelectorAll('.irow').forEach((el,idx)=>{el.onclick=()=>selectIssue(pageItems[idx]);});
  const nav=document.getElementById('page-nav');
  if(!nav)return;
  if(fi.length<=pgSize){nav.innerHTML='';return;}
  const bs='background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:6px 12px;color:var(--text2);font-size:12px;cursor:pointer;font-family:inherit;min-width:34px';
  const as='background:linear-gradient(135deg,#4f46e5,#7c3aed);border:1px solid var(--accent);color:#fff;border-radius:8px;padding:6px 12px;font-size:12px;font-weight:700;min-width:34px';
  let html=`<button style="${bs}" ${PAGE===1?'disabled':''} onclick="PAGE=1;renderIssues()">«</button><button style="${bs}" ${PAGE===1?'disabled':''} onclick="PAGE--;renderIssues()">‹</button>`;
  const pStart=Math.max(1,PAGE-2),pEnd=Math.min(totalPages,PAGE+2);
  for(let p=pStart;p<=pEnd;p++)html+=`<button style="${p===PAGE?as:bs}" onclick="PAGE=${p};renderIssues()">${p}</button>`;
  html+=`<button style="${bs}" ${PAGE===totalPages?'disabled':''} onclick="PAGE++;renderIssues()">›</button><button style="${bs}" ${PAGE===totalPages?'disabled':''} onclick="PAGE=${totalPages};renderIssues()">»</button>`;
  nav.innerHTML=html;
}
function renderRightPanel(){
  if(!SEL)return;
  const i=SEL,sc=SC[i.status]||'#94a3b8',pc=PC[i.pri]||'#94a3b8';
  document.getElementById('right-panel').innerHTML=`
  <div class="rpanel">
    <div class="rp-title">${escapeHtml(cleanTitle(i.title))}</div>
    ${i._detailLoading?'<div class="sync-meta" style="margin:8px 0 12px">Jira 상세 내용을 불러오는 중입니다...</div>':''}
    ${i._detailError?`<div class="sync-meta" style="margin:8px 0 12px;color:var(--danger)">상세 조회 실패: ${escapeHtml(i._detailError)}</div>`:''}
    <div class="rp-badges">
      <span class="badge" style="background:${sc}22;color:${sc}">${i.status}</span>
      <span class="badge" style="background:${pc}22;color:${pc}">${i.pri}</span>
      ${i.labels.map(l=>`<span class="badge" style="background:${labelColor(l)}22;color:${labelColor(l)}">${escapeHtml(l)}</span>`).join('')}
    </div>
    <div class="rp-meta">
      ${(()=>{const na='<span class="u-cfbbf24-fw700">미입력</span>';
        const dueCell=i.due?(()=>{const d=daysUntil(i.due);const col=d<0?'#fc8181':d<=7?'#fbbf24':'var(--text)';return `<span style="color:${col}">${i.due} ${d<0?'(기한초과 '+Math.abs(d)+'일)':'(D-'+d+')'}</span>`;})():na;
        const custCell=(i.customers&&i.customers.length)?escapeHtml(i.customers.join(', ')):(i.customer?`<span>${escapeHtml(i.customer)} <span style="color:var(--text3);font-size:10px">(제목 추정)</span></span>`:na);
        const divCell=(i.division&&i.division.length)?escapeHtml(i.division.join(', ')):'<span class="u-muted">-</span>';
        const catCell=(i.category&&i.category!=='N/A')?escapeHtml(i.category):na;
        const labCell=(i.labels&&i.labels.length)?i.labels.map(l=>`<span class="badge" style="background:${labelColor(l)}22;color:${labelColor(l)}">${escapeHtml(l)}</span>`).join(' '):na;
        const rateCell=i.rating?escapeHtml(i.rating):'<span class="u-muted">-</span>';
        return `
      <div class="rp-row"><span>이슈키</span><span style="color:var(--accent3);font-weight:700;display:inline-flex;align-items:center;gap:7px">${i.key}<button onclick="copyText('${i.key}');event.stopPropagation()" title="이슈키 복사" style="background:none;border:none;color:var(--text3);cursor:pointer;padding:2px;display:inline-flex;border-radius:5px" onmouseover="this.style.color='var(--accent3)'" onmouseout="this.style.color='var(--text3)'"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></span></div>
      <div class="rp-row"><span>우선순위</span><span>${escapeHtml(i.pri)}</span></div>
      <div class="rp-row"><span>고객사</span><span>${custCell}</span></div>
      <div class="rp-row"><span>레이블</span><span>${labCell}</span></div>
      <div class="rp-row"><span>구분</span><span>${divCell}</span></div>
      <div class="rp-row"><span>범주</span><span>${catCell}</span></div>
      <div class="rp-row"><span>담당자</span><span>${escapeHtml(i.assignee||'-')}</span></div>
      <div class="rp-row"><span>보고자</span><span>${escapeHtml(i.reporter||'-')}</span></div>
      <div class="rp-row"><span>평가</span><span>${rateCell}</span></div>
      <div class="rp-row"><span>시작일</span><span>${i.startDate?fd(i.startDate):'<span class="u-muted">-</span>'}</span></div>
      <div class="rp-row"><span>기한</span><span>${dueCell}</span></div>
      <div class="rp-row"><span>접수일</span><span>${fd(i.date)}</span></div>
      <div class="rp-row"><span>수정일</span><span>${fd(i.updated)}</span></div>`;})()}
    </div>
    ${i.attachments&&i.attachments.length?`
    <div class="u-mb-12px">
      <div class="u-sec-label">📎 첨부파일 (${i.attachments.length})</div>
      ${i.attachments.map(a=>`<div class="rp-attach-item">📄 ${escapeHtml(a.name)} <span class="u-ctext3-mlauto">${(a.size/1024).toFixed(1)}KB</span></div>`).join('')}
    </div>`:''}
    ${i.desc?`<div class="rp-desc">${adfToHtml(i.desc)}</div>`:''}
    ${i.comments&&i.comments.length?`
    <div class="rp-comments">
      <div class="u-sec-label">💬 코멘트 (${i.comments.length})</div>
      ${i.comments.map(c=>`<div class="rp-comment-item">
        <div class="rp-comment-author">${escapeHtml(c.author)} · ${fdt(c.created)}</div>
        <div class="rp-comment-body">${adfToHtml(c.body)}</div>
      </div>`).join('')}
    </div>`:''}
    <div style="display:flex;justify-content:flex-end;margin-bottom:6px">
      <button onclick="openFullIssue()" style="background:none;border:none;color:var(--text3);font-size:11px;cursor:pointer;font-family:inherit;display:flex;align-items:center;gap:4px">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
        전체화면
      </button>
    </div>
    <div class="u-mb-10px" id="ai-analysis-sec"></div>
    <div class="detail-link-row">
      <a class="u-td-none" href="https://escare-engr.atlassian.net/browse/${i.key}" target="_blank">
        <button class="btn btn-ghost">Jira →</button>
      </a>
    </div>
  </div>`;
  try{ renderIssueAnalysis(i.key); }catch(_){}
}



// ── MODALS ────────────────────────────────────────
let _loadingTimer=null;



function openFullIssue(){
  if(!SEL)return;
  const i=SEL;
  const sc=SC[i.status]||'#94a3b8';
  const pc=PC[i.pri]||'#94a3b8';
  const commentHtml=i.comments.map(c=>`<div style="padding:12px 14px;background:rgba(255,255,255,.02);border-left:3px solid var(--accent2);border-radius:0 8px 8px 0;margin-bottom:8px">
    <div style="font-size:10px;color:var(--accent3);font-weight:700;margin-bottom:5px">${escapeHtml(c.author)} · ${fdt(c.created)}</div>
    <div style="font-size:12px;color:var(--text2);line-height:1.7;white-space:pre-wrap">${adfToHtml(c.body)}</div>
  </div>`).join('');
  const attachHtml=i.attachments.map(a=>`<span style="display:inline-flex;align-items:center;gap:5px;background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.2);color:var(--cyan);border-radius:8px;padding:4px 10px;font-size:11px">📄 ${escapeHtml(a.name)} <span class="u-muted">${(a.size/1024).toFixed(1)}KB</span></span>`).join(' ');
  openGenModal(`${i.key} — ${cleanTitle(i.title)}`,`
    <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px">
      <span class="badge" style="background:${sc}22;color:${sc}">${i.status}</span>
      <span class="badge" style="background:${pc}22;color:${pc}">${i.pri}</span>
      ${i.labels.map(l=>`<span class="badge" style="background:${labelColor(l)}22;color:${labelColor(l)}">${escapeHtml(l)}</span>`).join('')}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:14px;font-size:12px">
      <div><span class="u-muted">담당자</span>&nbsp;${escapeHtml(i.assignee)}</div>
      <div><span class="u-muted">고객사</span>&nbsp;${escapeHtml(i.customer||'-')}</div>
      <div><span class="u-muted">접수일</span>&nbsp;${fd(i.date)}</div>
      <div><span class="u-muted">수정일</span>&nbsp;${fd(i.updated)}</div>
    </div>
    ${attachHtml?`<div style="margin-bottom:14px;display:flex;flex-wrap:wrap;gap:6px">${attachHtml}</div>`:''}
    ${i.desc?`<div class="u-mb-16px"><div style="font-size:10px;color:var(--text3);font-weight:700;margin-bottom:6px;text-transform:uppercase">본문</div><div style="background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;padding:14px;font-size:12.5px;line-height:1.75;white-space:pre-wrap;max-height:400px;overflow-y:auto;color:var(--text2)">${adfToHtml(i.desc)}</div></div>`:''}
    ${commentHtml?`<div><div style="font-size:10px;color:var(--text3);font-weight:700;margin-bottom:8px;text-transform:uppercase">코멘트 (${i.comments.length})</div>${commentHtml}</div>`:''}
  `,`<a class="u-td-none" href="https://escare-engr.atlassian.net/browse/${i.key}" target="_blank"><button class="btn btn-ghost u-btn-inline">Jira에서 보기 →</button></a>`);
}

function openGenModal(title,bodyHTML,footHTML){
  document.getElementById('gen-modal-title').textContent=title;
  document.getElementById('gen-modal-body').innerHTML=bodyHTML;
  document.getElementById('gen-modal-foot').innerHTML=footHTML||'';
  document.getElementById('gen-modal').classList.add('show');
  setTimeout(enhanceDateButtons,0);
}
function closeGenModal(){if(window.__pinLock)return;document.getElementById('gen-modal').classList.remove('show');}
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    e.preventDefault();
    if(document.getElementById('gen-modal')?.classList.contains('show'))closeGenModal();
  }
});

// ── CASE ──────────────────────────────────────────
function renderCases_legacy_v1(){
  const q=(document.getElementById('case-q')||{}).value?.toLowerCase()||'';
  const cStat=document.getElementById('case-stat')?.value||'';
  const cAss=document.getElementById('case-ass')?.value||'';
  const cSla=parseInt(document.getElementById('case-sla')?.value||'0');
  const cases=getCases().filter(c=>{
    const txt=[c.caseNum,c.title,c.customer,c.assignee,(c.labels||[]).join(' ')].join(' ').toLowerCase();
    if(q&&!txt.includes(q))return false;
    if(cStat&&c.status!==cStat)return false;
    if(cAss&&c.assignee!==cAss)return false;
    if(cSla&&daysSince(c.date)<cSla)return false;
    return true;
  });
  const cAssEl=document.getElementById('case-ass');
  if(cAssEl){const allCases=getCases();const assignees=[...new Set(allCases.map(c=>c.assignee).filter(a=>a&&a!=='-'))].sort();const curAss=cAssEl.value;cAssEl.innerHTML='<option value="">전체 담당자</option>'+assignees.map(a=>`<option ${a===curAss?'selected':''}>${escapeHtml(a)}</option>`).join('');}
  const wrap=document.getElementById('case-list');
  const pageCases=sliceForPage(cases,'cases');
  document.getElementById('case-count').textContent=pageCountText('cases',cases.length);
  if(!pageCases.length){wrap.innerHTML=`<div class="u-empty">케이스 번호가 포함된 이슈가 없습니다</div>`;renderPager('case-pager','cases',cases.length,'renderCases');return;}
  wrap.innerHTML=pageCases.map((c,idx)=>{const days=daysSince(c.date);const slaBg=days>=7?'rgba(248,113,113,.2)':days>=5?'rgba(251,191,36,.2)':days>=3?'rgba(251,191,36,.12)':'rgba(34,211,165,.15)';const slaColor=days>=7?'#f87171':days>=5?'#fbbf24':days>=3?'#fbbf24':'#22d3a5';const sc=SC[c.status]||'#94a3b8';let t=c.title.replace(new RegExp('\[?\s*'+c.caseNum+'\s*\]?'),'').replace(/\[\s*\]/g,'').replace(/\s+/g,' ').trim();return `<div class="case-card${CASE_SEL&&CASE_SEL.caseNum===c.caseNum&&CASE_SEL.key===c.key?' selected':''}" style="--lc:${sc}" data-idx="${idx}"><div class="irow-top"><span class="case-num">📦 ${c.caseNum}</span><span class="badge" style="background:${sc}22;color:${sc}">${c.status}</span><span class="sla-badge" style="background:${slaBg};color:${slaColor}">${days}일 경과</span><span class="ititle">${escapeHtml(t)}</span><span class="imeta">${escapeHtml(c.customer||'-')}</span></div><div class="irow-bot">${c.labels.map(l=>`<span class="badge" style="background:${labelColor(l)}22;color:${labelColor(l)}">${escapeHtml(l)}</span>`).join('')}<span class="imeta">@${escapeHtml(c.assignee)}</span><span class="imeta">${fd(c.date)}</span></div></div>`;}).join('');
  wrap.querySelectorAll('.case-card').forEach((el,idx)=>{el.onclick=()=>{CASE_SEL=pageCases[idx];renderCases();renderCaseRight();};});
  renderPager('case-pager','cases',cases.length,'renderCases');
}

// ── EOS / LICENSE ─────────────────────────────────
async function loadEOS(){
  try{
    const r=await fetch(`${WORKERS}/eos`,{headers:authHeaders()});
    const d=await r.json();
    EOS_ITEMS=d.items||[];
    updateEosWarnBadge();
  }catch{}
}
async function loadEosWarnDays(){
  if(!IS_ADMIN&&!IS_SUPER)return;
  try{
    const r=await fetch(`${WORKERS}/admin/config`,{headers:authHeaders()});
    const d=await r.json();
    if(d.ok&&d.eosWarnDays){EOS_WARN_DAYS=d.eosWarnDays.split(',').map(s=>parseInt(s.trim())).filter(x=>x>0);}
  }catch{}
}
function updateEosWarnBadge(){
  const warnDay=Math.max(...EOS_WARN_DAYS,60);
  const warns=EOS_ITEMS.filter(it=>{
    if(!it.expireDate)return false;
    const d=daysUntil(it.expireDate);
    return d<=warnDay;
  });
  const badge=document.getElementById('eos-warn-badge');
  if(!badge)return;
  if(warns.length>0){badge.style.display='inline-block';badge.textContent=warns.length;}
  else badge.style.display='none';
}
function renderEosBanner(){
  const wrap=document.getElementById('eos-banner-wrap');
  if(!wrap)return;
  const warnDay=Math.max(...EOS_WARN_DAYS,60);
  const urgent=EOS_ITEMS.filter(it=>{
    if(!it.expireDate)return false;
    const d=daysUntil(it.expireDate);
    return d<=warnDay;
  }).sort((a,b)=>daysUntil(a.expireDate)-daysUntil(b.expireDate));
  if(!urgent.length){wrap.innerHTML='';return;}
  const top=urgent[0];
  const tDays=daysUntil(top.expireDate);
  wrap.innerHTML=`
  <div class="eos-banner">
    <div class="eos-banner-icon">⚠️</div>
    <div class="eos-banner-text">
      <div class="eos-banner-title">라이선스 만료 임박 ${urgent.length}건</div>
      <div class="eos-banner-detail">
        가장 임박: <strong class="u-c-fca5a5">${escapeHtml(top.customer||'-')}</strong> · ${escapeHtml(top.productDesc||top.product||'')} (${tDays}일 후 ${top.expireDate})
      </div>
    </div>
    <button class="eos-banner-btn" onclick="showPage('eos',document.getElementById('nav-eos'))">자세히 →</button>
  </div>`;
}