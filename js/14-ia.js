/* ── IA 7탭 재편 (신규 모듈) ─────────────────────────────
   원칙: 페이지·함수는 기존 그대로, 네비게이션 층만 재구성.
   최상위 7탭 + 서브탭 칩. 기존 점프 경로(showPage('cases') 등)는 전부 유효 —
   어떤 페이지로 가든 이 래퍼가 소속 그룹을 찾아 nav·서브탭을 동기화한다. */

const IA_GROUPS={dash:'home',mydesk:'home',customers:'customers',issues:'issues',cases:'issues',sales:'sales',eos:'sales',vt:'tools',links:'archive',knowledge:'archive',compat:'archive',audit:'admin',monitor:'admin',settings:'admin'};
const IA_NAV={home:'nav-dash',customers:'nav-customers',issues:'nav-issues',sales:'nav-sales',tools:'nav-vt',archive:'nav-links',admin:'nav-audit'};
const IA_SUBTABS={
  home:[['dash','대시보드'],['mydesk','My Desk']],
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
    const rc=document.getElementById('range-chip');
    if(rc){
      const m=(typeof SYNC_META!=='undefined'&&SYNC_META&&SYNC_META.rangeMonths)||localStorage.getItem('jira_range_months');
      if(m){rc.textContent=`📅 데이터 기준: 최근 ${m}개월`;rc.style.display='inline-block';}
    }
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
  bar.innerHTML=tabs.filter(([p])=>iaSubtabVisible(p)).map(([p,label])=>
    `<button class="ia-chip${p===current?' on':''}" onclick="showPage('${p}')">${label}</button>`).join('');
}

/* 고객사 환경/사용 솔루션 — 조회는 전 역할, 수정은 기술팀·관리자 */
async function loadCustomerEnv(name){
  const sec=document.getElementById('cust-env-sec');
  if(!sec||!name)return;
  const canEdit=(typeof USER_ROLE!=='undefined'&&USER_ROLE!=='sales');
  try{
    const d=await hubApi('/customer/env?name='+encodeURIComponent(name));
    const e=d.env||{};
    const view=`<div style="font-size:10px;color:var(--text3);font-weight:700;margin:12px 0 6px">🖥 사용 솔루션 / 환경 ${canEdit?`<button class="btn btn-ghost u-btn-xxs" style="margin-left:6px" onclick="editCustomerEnv(${jsAttr(name)})">✏️ 편집</button>`:''}</div>
      <div id="cust-env-view" style="font-size:12px;line-height:1.65;background:rgba(255,255,255,.04);border-radius:8px;padding:9px 11px">
        <div><b style="color:var(--text3);font-size:10.5px">솔루션</b> <span>${escapeHtml(e.solutions||'미입력')}</span></div>
        <div style="margin-top:4px;white-space:pre-wrap"><b style="color:var(--text3);font-size:10.5px">환경 메모</b> ${escapeHtml(e.env_note||'미입력')}</div>
        ${e.updated_by?`<div class="u-muted-10" style="margin-top:5px">최근 수정: ${escapeHtml(e.updated_by)} · ${e.updated_at?new Date(e.updated_at).toLocaleDateString('ko-KR'):''}</div>`:''}
      </div>`;
    sec.innerHTML=view;
    sec.dataset.solutions=e.solutions||'';
    sec.dataset.envNote=e.env_note||'';
  }catch(err){sec.innerHTML=`<div class="u-muted-10">환경 정보 조회 실패: ${escapeHtml(err.message)}</div>`;}
}

function editCustomerEnv(name){
  const sec=document.getElementById('cust-env-sec');
  if(!sec)return;
  const sol=sec.dataset.solutions||'', note=sec.dataset.envNote||'';
  sec.innerHTML=`<div style="font-size:10px;color:var(--text3);font-weight:700;margin:12px 0 6px">🖥 사용 솔루션 / 환경 편집</div>
    <input id="cust-env-sol" class="admin-input" style="margin-bottom:6px" placeholder="사용 솔루션 (예: DLP 16.0.2, SEP 14.3 RU9)" value="${escapeHtml(sol)}">
    <textarea id="cust-env-note" class="admin-textarea" style="min-height:90px" placeholder="환경 메모 — 서버 구성·OS·망 분리·특이사항 등">${escapeHtml(note)}</textarea>
    <div style="display:flex;gap:6px;margin-top:6px">
      <button class="btn btn-indigo u-btn-xs" onclick="saveCustomerEnv(${jsAttr(name)})">저장</button>
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
