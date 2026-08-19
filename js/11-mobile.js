
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
const showPageBeforeMobilePolish=showPage;
showPage=function(name,btn){
  const pageName=name==='dashboard'?'dash':(name==='admin'?'settings':name);
  const result=showPageBeforeMobilePolish(name,btn);
  ensureMobileMoreMenu();
  syncMobileMoreState(pageName);
  return result;
};
const enterAppBeforeMobilePolish=enterApp;
enterApp=function(){
  const result=enterAppBeforeMobilePolish();
  ensureMobileMoreMenu();
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
