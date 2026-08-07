
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

function injectV158Style(){
  if(document.getElementById('v158-style')) return;
  const st=document.createElement('style');
  st.id='v158-style';
  st.textContent=`
    .admin-section>summary{
      display:grid;
      grid-template-columns:minmax(160px,240px) minmax(0,1fr) auto;
      align-items:center;
      gap:10px;
      min-height:50px;
    }
    .admin-section>summary span{justify-self:start;min-width:0}
    .admin-section>summary small{justify-self:start;text-align:left;white-space:normal;line-height:1.35;color:var(--text3)}
    .admin-section>summary:after{justify-self:end}

    @media(max-width:700px){
      :root{--bg:#FAF1E6;--panel:#FFFDF9;--card:#FFFDF9;--border:#E7D8C4;--border2:#DECDB6;--text:#241B20;--text2:#5C4E3A;--text3:#8A7B62}
      html,body{background:#FAF1E6!important;color:#241B20!important;overflow-x:hidden!important}
      #app{display:flex!important;flex-direction:column!important;min-height:100vh!important;background:#FAF1E6!important;padding-bottom:78px!important;overflow-x:hidden!important}
      main{width:100%!important;max-width:100%!important;min-width:0!important;padding:0 0 14px!important;overflow-x:hidden!important;background:#FAF1E6!important}
      header{position:sticky!important;top:0!important;z-index:90!important;margin:0!important;padding:10px 12px!important;background:var(--control-bg)!important;border-bottom:1px solid #E7D8C4!important;box-shadow:0 2px 14px rgba(60,45,30,.06)!important;backdrop-filter:blur(10px)!important}
      .topbar{display:grid!important;grid-template-columns:minmax(0,1fr) auto!important;align-items:start!important;gap:8px!important;width:100%!important}
      .top-left{min-width:0!important}
      .top-title{font-size:17px!important;font-weight:800!important;color:#211D22!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important}
      .top-desc{display:block!important;font-size:10px!important;color:var(--text3)!important;margin-top:2px!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important}
      .top-status{grid-column:1/-1!important;display:flex!important;gap:6px!important;justify-content:flex-start!important;max-width:100%!important;overflow-x:auto!important;overflow-y:hidden!important;padding:4px 0 0!important;flex-wrap:nowrap!important;-webkit-overflow-scrolling:touch!important}
      .top-status::-webkit-scrollbar{height:0!important}
      .top-status-card,.top-pin,.top-refresh,.top-logout{flex:0 0 auto!important;height:32px!important;min-height:32px!important;border-radius:999px!important;background:#FFFDF9!important;border:1px solid #E1D0B8!important;color:#41372A!important;box-shadow:0 1px 5px rgba(60,45,30,.04)!important;padding:0 10px!important;white-space:nowrap!important}
      .top-status-card .label{display:none!important}
      .top-status-card .value{font-size:10.5px!important;color:#41372A!important;font-weight:800!important}
      .top-status-card .ok{color:var(--success)!important}
      .top-status-card .warn{color:#C07A10!important}
      .top-pin{color:var(--cyan)!important;background:#FBF1E8!important;border-color:#BFE0EC!important}
      .top-refresh{width:32px!important;padding:0!important}

      aside{position:fixed!important;left:0!important;right:0!important;bottom:0!important;top:auto!important;z-index:120!important;width:100%!important;height:66px!important;background:#FFFDF9!important;border-top:1px solid #E1D0B8!important;box-shadow:0 -8px 22px rgba(60,45,30,.10)!important;overflow:hidden!important}
      .sb-top{padding:0!important;height:100%!important}
      .sb-brand,.sb-bottom{display:none!important}
      .sb-nav{height:100%!important;display:flex!important;align-items:stretch!important;gap:0!important;margin:0!important;padding:0 6px!important;overflow-x:auto!important;overflow-y:hidden!important;scroll-snap-type:x proximity!important;-webkit-overflow-scrolling:touch!important}
      .sb-nav::-webkit-scrollbar{height:0!important}
      .sb-btn{flex:0 0 68px!important;width:68px!important;min-width:68px!important;height:58px!important;margin:4px 2px!important;padding:6px 4px!important;border-radius:16px!important;display:flex!important;flex-direction:column!important;align-items:center!important;justify-content:center!important;gap:4px!important;color:var(--text3)!important;background:transparent!important;border:0!important;font-size:10px!important;font-weight:800!important;text-align:center!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;scroll-snap-align:start!important}
      .sb-btn svg{width:18px!important;height:18px!important;flex:0 0 18px!important}
      .sb-btn.active{color:var(--success)!important;background:#D8F0E4!important}
      .sb-btn:hover{background:#F1EFE6!important;color:var(--cyan)!important}

      .page{width:100%!important;max-width:100%!important;padding:12px!important;overflow-x:hidden!important}
      .content,.panel,.admin-card,.kpi,.chart-card,.case-card,.irow,.link-card,.knowledge-card,.vt-result,.file-drop,.storage-summary,.storage-item{background:#FFFDF9!important;border-color:#E7D8C4!important;color:#241B20!important;box-shadow:0 2px 12px rgba(60,45,30,.04)!important}
      .card,.panel,.admin-card{border-radius:16px!important}
      .sec-title{font-size:13px!important;color:#41372A!important;margin:8px 0 10px!important}
      .sec-title::after{background:#E7D8C4!important}
      .alert,.sync-banner{background:#EAF5EF!important;border-color:#BFE0EC!important;color:var(--cyan)!important;border-radius:16px!important}
      .kpi-val{color:#211D22!important}
      .kpi-label,.kpi-sub,.imeta,.rank-stat,.link-desc,.link-url,.storage-note{color:var(--text3)!important}
      .ititle,.rank-name,.link-title,.admin-card h3,.rp-title{color:#211D22!important}
      .irow:hover,.case-card:hover{background:#FBF4EA!important}

      .filter-row,.action-row,.list-toolbar,.pager{max-width:100%!important}
      .filter-row input,.filter-row select,.admin-input,.admin-textarea,.log-textarea,.private-editor input,.private-editor textarea{background:#FFFDF9!important;border:1px solid #E1D0B8!important;color:#211D22!important;border-radius:12px!important}
      .btn-ghost,.filter-reset{background:#FFFDF9!important;border:1px solid #E1D0B8!important;color:#41372A!important;box-shadow:none!important}
      .btn{box-shadow:none!important}
      .btn:hover{transform:none!important}
      .two-col,.chart-grid,.storage-summary-top,.storage-grid,.vt-grid{grid-template-columns:1fr!important}
      .rpanel{position:static!important;max-height:none!important;background:#FFFDF9!important;color:#241B20!important;border-color:#E7D8C4!important;box-shadow:0 2px 12px rgba(60,45,30,.04)!important}
      .rp-desc,.rp-comment-item,.rp-meta,.rp-row{background:#FBF4EA!important;border-color:#E7D8C4!important;color:#41372A!important}
      .rp-row span:last-child{color:#211D22!important}

      .admin-section{background:#FFFDF9!important;border:1px solid #E1D0B8!important;border-radius:16px!important;box-shadow:0 2px 12px rgba(60,45,30,.04)!important;overflow:hidden!important}
      .admin-section>summary{display:grid!important;grid-template-columns:minmax(0,1fr) auto!important;align-items:center!important;gap:5px 8px!important;min-height:58px!important;padding:12px 13px!important;color:#211D22!important}
      .admin-section>summary span{grid-column:1/2!important;grid-row:1!important;font-size:13px!important;justify-self:start!important}
      .admin-section>summary small{grid-column:1/-1!important;grid-row:2!important;justify-self:start!important;text-align:left!important;white-space:normal!important;color:var(--text3)!important;font-size:10px!important;line-height:1.35!important}
      .admin-section>summary:after{grid-column:2!important;grid-row:1!important;background:var(--accent-soft)!important;border-color:#F3C9B4!important;color:#A83E1F!important}
      .admin-section .admin-card{margin:10px!important;background:#FBF4EA!important}
      .danger-section{border-color:#F3CFC9!important}
      .danger-section>summary:after{background:#fef2f2!important;border-color:#F3CFC9!important;color:#9E2E2A!important}
      .danger-card{background:#fff7f7!important;border-color:#F3CFC9!important}
      .admin-row,.admin-add-row,.safe-actions,.danger-actions,.storage-actions{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}
      .admin-row label{color:var(--text3)!important;min-width:0!important}
      .admin-add-row .btn,.storage-actions .btn,.safe-actions .btn,.danger-actions .btn{width:100%!important}

      .audit-table,.eos-table{display:block!important;width:100%!important;overflow-x:auto!important;-webkit-overflow-scrolling:touch!important;border-radius:12px!important}
      .audit-table table,.eos-table table{min-width:620px!important}
      .audit-table th,.audit-table td,.eos-table th,.eos-table td{white-space:nowrap!important;color:#41372A!important}
      .audit-table th,.eos-table th{background:#F6EEE2!important;color:#5C4E3A!important}
      .private-layout{grid-template-columns:1fr!important}
      .private-editor{background:#FFFDF9!important;border-color:#E7D8C4!important;border-radius:16px!important}
      .modal-card{max-width:calc(100vw - 24px)!important;background:#FFFDF9!important;color:#211D22!important;border-color:#E7D8C4!important}
      .modal-form label{color:#5C4E3A!important}
      .modal-form input,.modal-form select,.modal-form textarea{background:#FFFDF9!important;color:#211D22!important;border-color:#E1D0B8!important}
      [style*="min-width"]{max-width:100%!important}
      .link-url,.audit-detail,.vt-hist-name,.vt-hist-hash{overflow-wrap:anywhere!important;word-break:break-word!important}
      .topbar-right .search-box{display:none!important}
    }
  `;
  document.head.appendChild(st);
}
injectV158Style();
const codexMobileDarkStyle=document.getElementById('codex-mobile-dark');
if(codexMobileDarkStyle) document.head.appendChild(codexMobileDarkStyle);
const codexThemeStyle=document.getElementById('theme-style');
if(codexThemeStyle) document.head.appendChild(codexThemeStyle);
// 초기 로드 시 현재 테마에 맞춰 모바일 시트 적용(라이트=다크모바일 비활성화)
try{ if(typeof syncMobileThemeSheets==='function') syncMobileThemeSheets(); }catch(_){}
