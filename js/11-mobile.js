
function expandActiveNavGroup(name){
  const btn=document.getElementById('nav-'+name);
  const g=btn&&btn.closest('.sb-group');
  if(g)g.classList.remove('collapsed');
}
function ensureMobileMoreMenu(){
  const nav=document.querySelector('.sb-nav');
  if(!nav)return;
  [...MOBILE_PRIMARY_NAV,...MOBILE_MORE_NAV].forEach(id=>{
    const el=document.getElementById(id);
    if(!el)return;
    el.classList.toggle('mobile-primary',MOBILE_PRIMARY_NAV.includes(id));
    el.classList.toggle('mobile-secondary',MOBILE_MORE_NAV.includes(id));
  });
  if(!document.getElementById('nav-more-mobile')){
    nav.insertAdjacentHTML('beforeend',`<button class="sb-btn mobile-more-btn" id="nav-more-mobile" type="button" onclick="toggleMobileMoreMenu(event)" aria-label="더보기"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/></svg>더보기</button>`);
  }
  if(!document.getElementById('mobile-more-panel')){
    document.body.insertAdjacentHTML('beforeend',`<div class="mobile-more-backdrop" onclick="closeMobileMoreMenu()"></div><div class="mobile-more-panel" id="mobile-more-panel" role="dialog" aria-modal="true" aria-label="모바일 추가 메뉴"><div class="mobile-more-head"><span>더보기</span><button type="button" class="mobile-more-close" onclick="closeMobileMoreMenu()" aria-label="닫기">×</button></div><div class="mobile-more-list" id="mobile-more-list"></div></div>`);
  }
  renderMobileMoreMenu();
}
function renderMobileMoreMenu(){
  const list=document.getElementById('mobile-more-list');
  if(!list)return;
  list.innerHTML=MOBILE_MORE_NAV.filter(canShowMobileMoreItem).map(id=>{
    const page=mobilePageNameFromNav(id);
    const src=document.getElementById(id);
    const icon=src?.querySelector('svg')?.outerHTML||'<span></span>';
    return `<button type="button" class="mobile-more-item" data-page="${page}" onclick="mobileMoreGo('${page}')">${icon}<span>${MOBILE_NAV_LABELS[page]||page}</span></button>`;
  }).join('');
  syncMobileMoreState();
}
function toggleMobileMoreMenu(ev){
  ev?.stopPropagation();
  ensureMobileMoreMenu();
  document.body.classList.toggle('mobile-more-open');
}
function closeMobileMoreMenu(){
  document.body.classList.remove('mobile-more-open');
}
function mobileMoreGo(page){
  closeMobileMoreMenu();
  const nav=document.getElementById('nav-'+page);
  showPage(page,nav);
}
function syncMobileMoreState(page){
  const activePage=page||document.querySelector('.page.active')?.id?.replace('page-','')||'';
  const more=document.getElementById('nav-more-mobile');
  if(more)more.classList.toggle('active',MOBILE_MORE_NAV.includes('nav-'+activePage));
  document.querySelectorAll('.mobile-more-item').forEach(btn=>btn.classList.toggle('active',btn.dataset.page===activePage));
}
function normalizeAdminSettingsUI(){
  const root=document.getElementById('page-settings');
  if(!root)return;
  const title=root.querySelector('.sec-title');
  if(title)title.textContent='관리자 설정';
  const summaries=[
    ['기본 설정','조회 기간, 세션, 라이선스, AI 지침'],
    ['사용자 / 권한','계정 등록과 역할 관리'],
    ['PIN 관리','사용자 PIN 초기화'],
    ['저장소','KV 사용량, 백업'],
    ['위험 작업','캐시, 감사 로그, 전체 초기화']
  ];
  root.querySelectorAll('.admin-section:not(.np)').forEach((section,idx)=>{
    const s=section.querySelector('summary');
    if(s&&summaries[idx])s.innerHTML=`<span>${summaries[idx][0]}</span><small>${summaries[idx][1]}</small>`;
    if(idx>0)section.open=false;
  });
  const heads=['운영 기본값','사용자 계정','관리자 권한','권한 안내','사용자 PIN 초기화','저장소 / KV 사용량','주의 작업'];
  root.querySelectorAll('.admin-section:not(.np) .admin-card h3').forEach((h,idx)=>{if(heads[idx])h.textContent=heads[idx];});
  const guide=root.querySelector('.admin-section:not(.np) .admin-card.soft');
  if(guide)guide.style.display='none';
  const labels=[['cfg-range','데이터 조회 기간'],['cfg-session','세션 타임아웃'],['cfg-eos-warn','라이선스 경고 일수']];
  labels.forEach(([id,text])=>{const input=document.getElementById(id);const label=input?.closest('.admin-row')?.querySelector('label');if(label)label.textContent=text;});
  const placeholders={'cfg-eos-warn':'60,30,7','user-add-id':'계정 ID (예: mj.park)','user-add-display':'표시 이름','user-add-pin':'초기 PIN (선택)'};
  Object.entries(placeholders).forEach(([id,text])=>{const el=document.getElementById(id);if(el)el.placeholder=text;});
  const btnText={'storage-stats-btn':'저장소 / KV 사용량 조회','storage-backup-btn':'전체 HUB 데이터 백업','storage-audit-btn':'감사 로그 90일 초과 정리','storage-reset-btn':'전체 데이터 초기화'};
  Object.entries(btnText).forEach(([id,text])=>{const el=document.getElementById(id);if(el)el.textContent=text;});
}
const showPageBeforeMobilePolish=showPage;
showPage=function(name,btn){
  const pageName=name==='dashboard'?'dash':(name==='admin'?'settings':name);
  const result=showPageBeforeMobilePolish(name,btn);
  ensureMobileMoreMenu();
  syncMobileMoreState(pageName);
  normalizeAdminSettingsUI();
  return result;
};
const enterAppBeforeMobilePolish=enterApp;
enterApp=function(){
  const result=enterAppBeforeMobilePolish();
  ensureMobileMoreMenu();
  normalizeAdminSettingsUI();
  try{ if(typeof initPushOnLogin==='function')setTimeout(initPushOnLogin,400); }catch(_){}
  try{ if(typeof loadFeatureFlags==='function')setTimeout(loadFeatureFlags,300); }catch(_){}
  try{ if(typeof loadAnalysisLatest==='function')setTimeout(loadAnalysisLatest,600); }catch(_){}
  try{ if(typeof loadMyBriefing==='function')setTimeout(loadMyBriefing,700); }catch(_){}
  return result;
};

const codexMobileDarkStyle=document.getElementById('codex-mobile-dark');
if(codexMobileDarkStyle) document.head.appendChild(codexMobileDarkStyle);
const codexThemeStyle=document.getElementById('theme-style');
if(codexThemeStyle) document.head.appendChild(codexThemeStyle);
// 초기 로드 시 현재 테마에 맞춰 모바일 시트 적용(라이트=다크모바일 비활성화)
try{ if(typeof syncMobileThemeSheets==='function') syncMobileThemeSheets(); }catch(_){}
