/* ── IA 7탭 재편 (신규 모듈) ─────────────────────────────
   원칙: 페이지·함수는 기존 그대로, 네비게이션 층만 재구성.
   최상위 7탭 + 서브탭 칩. 기존 점프 경로(showPage('cases') 등)는 전부 유효 —
   어떤 페이지로 가든 이 래퍼가 소속 그룹을 찾아 nav·서브탭을 동기화한다. */

const IA_GROUPS={dash:'home',mydesk:'home',quiz:'home',customers:'customers',owners:'customers',issues:'issues',cases:'issues',sales:'sales',eos:'sales',vt:'tools',links:'archive',knowledge:'archive',compat:'archive',audit:'admin',monitor:'admin',settings:'admin'};
const IA_NAV={home:'nav-dash',customers:'nav-customers',issues:'nav-issues',sales:'nav-sales',tools:'nav-vt',archive:'nav-links',admin:'nav-audit'};
const IA_SUBTABS={
  home:[['dash','대시보드'],['mydesk','My Desk'],['quiz','🧠 퀴즈']],
  customers:[['customers','고객사'],['owners','담당자 관리']],
  issues:[['issues','일반 이슈'],['cases','벤더 케이스']],
  sales:[['sales','영업 현황'],['eos','라이선스']],
  archive:[['links','업무 링크'],['knowledge','팀 노하우'],['compat','호환성 매트릭스']],
  admin:[['audit','감사 로그'],['monitor','팀 모니터'],['settings','설정']]
};

function iaSubtabVisible(page){
  if(page==='monitor')return !!(typeof MONITOR_ALLOWED!=='undefined'&&MONITOR_ALLOWED&&(typeof FEATURE_FLAGS==='undefined'||FEATURE_FLAGS.monitor!==false));
  if(page==='settings')return !!(typeof IS_SUPER!=='undefined'&&IS_SUPER);
  if(page==='audit')return !!((typeof IS_ADMIN!=='undefined'&&IS_ADMIN)||(typeof IS_SUPER!=='undefined'&&IS_SUPER));
  return true;
}

function renderIASubtabs(current){
  // 조회 기간 칩 — 모든 화면 상단에 데이터 기준 표시
  try{
    // 조회 기준 기간을 상단 시계 좌측에 시계와 동일 형태로 표시
    const m=(typeof SYNC_META!=='undefined'&&SYNC_META&&SYNC_META.rangeMonths)||localStorage.getItem('jira_range_months');
    const rc=document.getElementById('top-range'), rt=document.getElementById('top-range-text');
    if(rc&&rt){ if(m){rt.textContent=`최근 ${m}개월`;rc.style.display='';}else{rc.style.display='none';} }
  }catch(_){}
  const bar=document.getElementById('ia-subtabs');
  if(!bar)return;
  let group=IA_GROUPS[current];
  if(current==='mydesk'&&typeof USER_ROLE!=='undefined'&&USER_ROLE==='sales')group='sales';
  let tabs=(group&&IA_SUBTABS[group])||null;
  // 영업 역할: 사이드바는 '영업'만 남으므로 My Desk를 영업 서브탭으로 유지 (구 IA에서도 접근 가능했음)
  if(group==='sales'&&typeof USER_ROLE!=='undefined'&&USER_ROLE==='sales')tabs=[...tabs,['mydesk','My Desk']];
  // 최상위 nav active 동기화 (기존 showPage가 nav-<page>에 준 active는 서브페이지에선 no-op)
  document.querySelectorAll('.sb-btn').forEach(b=>b.classList.remove('active'));
  const rep=group&&document.getElementById(IA_NAV[group]);
  if(rep)rep.classList.add('active');
  if(!tabs||tabs.filter(([p])=>iaSubtabVisible(p)).length<2){bar.style.display='none';bar.innerHTML='';return;}
  bar.style.display='flex';
  let html=tabs.filter(([p])=>iaSubtabVisible(p)).map(([p,label])=>
    `<button class="ia-chip${p===current?' on':''}" onclick="showPage('${p}')">${label}</button>`).join('');
  // 홈(대시보드/My Desk) 줄 우측에 팀 다이제스트 버튼 — 모니터 허용자 + digest 기능 on
  if(group==='home'&&typeof MONITOR_ALLOWED!=='undefined'&&MONITOR_ALLOWED&&(typeof FEATURE_FLAGS==='undefined'||FEATURE_FLAGS.digest!==false)){
    html+=`<button class="ia-chip" style="margin-left:auto;background:var(--accent);border-color:var(--accent);color:#FFFDF9;font-weight:700" onclick="openDigest()">📤 팀 다이제스트</button>`;
  }
  bar.innerHTML=html;
}

/* 고객사 환경/사용 솔루션 — 상단 메타 테이블 행(솔루션·환경 메모)에 인라인. 조회 전 역할, 수정 기술팀·관리자 */
async function loadCustomerEnv(name){
  const solEl=document.getElementById('cust-sol-val'), envEl=document.getElementById('cust-env-val');
  if(!name||(!solEl&&!envEl))return;
  const canEdit=(typeof USER_ROLE!=='undefined'&&USER_ROLE!=='sales');
  const editWrap=document.getElementById('cust-env-edit'); if(editWrap){editWrap.style.display='none';editWrap.innerHTML='';}
  try{
    const d=await hubApi('/customer/env?name='+encodeURIComponent(name));
    const e=d.env||{};
    if(editWrap){editWrap.dataset.solutions=e.solutions||'';editWrap.dataset.envNote=e.env_note||'';editWrap.dataset.cust=name;}
    // 중복 제거: 솔루션이 입력돼 있으면 자동집계 '제품' 행 숨김(솔루션이 상위)
    const prodRow=document.getElementById('cust-prod-row'); if(prodRow)prodRow.style.display=e.solutions?'none':'';
    if(solEl)solEl.innerHTML=e.solutions?escapeHtml(e.solutions):'<span class="u-muted-11">미입력</span>';
    if(envEl)envEl.innerHTML=`<span style="white-space:pre-wrap">${e.env_note?escapeHtml(e.env_note):'<span class="u-muted-11">미입력</span>'}</span>`
      +(canEdit?` <button class="btn btn-ghost u-btn-xxs" style="margin-left:6px" onclick="editCustomerEnv(${jsAttr(name)})">✏️</button>`:'')
      +(e.updated_by?`<div class="u-muted-10" style="margin-top:3px">최근 수정: ${escapeHtml(e.updated_by)}${e.updated_at?' · '+new Date(e.updated_at).toLocaleDateString('ko-KR'):''}</div>`:'');
  }catch(err){ if(solEl)solEl.innerHTML='<span class="u-muted-10">조회 실패</span>'; if(envEl)envEl.innerHTML='<span class="u-muted-10">조회 실패</span>'; }
}

function editCustomerEnv(name){
  const editWrap=document.getElementById('cust-env-edit'); if(!editWrap)return;
  const sol=editWrap.dataset.solutions||'', note=editWrap.dataset.envNote||'';
  editWrap.style.display=''; editWrap.innerHTML=`
    <div style="font-size:10px;color:var(--text3);font-weight:700;margin:4px 0 6px">🖥 사용 솔루션 / 환경 편집</div>
    <input id="cust-env-sol" class="admin-input" style="margin-bottom:6px" placeholder="사용 솔루션 (예: DLP 16.0.2, SEP 14.3 RU9)" value="${escapeHtml(sol)}">
    <textarea id="cust-env-note" class="admin-textarea" style="min-height:80px" placeholder="환경 메모 — 서버 구성·OS·망 분리·특이사항 등">${escapeHtml(note)}</textarea>
    <div style="display:flex;gap:6px;margin-top:6px">
      <button class="btn btn-primary u-btn-xs" onclick="saveCustomerEnv(${jsAttr(name)})">저장</button>
      <button class="btn btn-ghost u-btn-xs" onclick="loadCustomerEnv(${jsAttr(name)})">취소</button>
    </div>`;
}

async function saveCustomerEnv(name){
  try{
    await hubApi('/customer/env',{method:'PUT',body:JSON.stringify({
      customer:name,
      solutions:document.getElementById('cust-env-sol')?.value||'',
      env_note:document.getElementById('cust-env-note')?.value||''
    })});
    toast('환경 정보 저장 완료');
    loadCustomerEnv(name);
  }catch(e){toast('저장 실패: '+e.message,true);}
}

/* showPage 최종 래퍼 — 서브탭 동기화 */
const showPageBeforeIA=showPage;
showPage=function(name,btn){
  const result=showPageBeforeIA(name,btn);
  try{
    const pageName=name==='dashboard'?'dash':(name==='admin'?'settings':name);
    renderIASubtabs(pageName);
  }catch(_){}
  return result;
};
const enterAppBeforeIA=enterApp;
enterApp=function(){
  const result=enterAppBeforeIA();
  try{ renderIASubtabs((document.querySelector('.page.active')||{}).id?.replace('page-','')||'dash'); }catch(_){}
  return result;
};
/* 자동로그인 레이스 방어: 세션복원 fetch가 빨리 끝나면 enterApp이 이 파일 로드 전에
   실행될 수 있다(스크립트 경계에서 마이크로태스크 드레인). 이미 입장한 상태면 즉시 렌더. */
try{
  if(document.body.classList.contains('app-entered'))
    renderIASubtabs(((document.querySelector('.page.active')||{}).id||'page-dash').replace('page-',''));
}catch(_){}
