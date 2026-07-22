
const WORKERS='https://engr-hub-proxy-dev.engr-jira.workers.dev';
const SUPER_ADMIN='mj.park';
const MAX_FILE_SIZE=20*1024*1024;
let ISSUES=[],SEL=null,CASE_SEL=null,PAGE=1;
let CURRENT_USER='',CURRENT_DISPLAY='',IS_ADMIN=false,IS_SUPER=false,USER_ROLE='user';
let SESSION_MIN=120, SESSION_DEADLINE=0, SESSION_TIMER=null;

// ── 전역 에러 핸들러 ──────────────────────────────
window.addEventListener('unhandledrejection',e=>{
  const msg=e?.reason?.message||String(e?.reason||'알 수 없는 오류');
  if(msg.includes('세션')||msg.includes('401')||msg.includes('403'))return;
  console.error('[HUB] Unhandled rejection:',e.reason);
  const t=document.getElementById('toast');
  if(t&&t.style.display!=='block'){t.textContent='오류가 발생했습니다: '+msg.slice(0,60);t.className='err';t.style.display='block';setTimeout(()=>t.style.display='none',3500);}
});
window.onerror=(msg,src,line,col,err)=>{
  console.error('[HUB] Global error:',msg,src,line,err);
  return false;
};
let AI_USAGE_LOADING=false, AI_USAGE_LAST=null;
let AI_PROVIDER='', AI_MODEL_LABEL='AI', LAST_AI_MODEL='';
let VT_HISTORY=JSON.parse(localStorage.getItem('vt_history')||'[]');
let LINKS=[],EOS_ITEMS=[],TEAM_NAMES=[];
let EOS_WARN_DAYS=[60,30,7];
let LOG_FILES=[];
const THEME_KEY='engr_theme';
let UI_THEME=normalizeTheme((function(){try{return localStorage.getItem(THEME_KEY)}catch(_){return null}})()||document.documentElement.getAttribute('data-theme')||'dark');

function normalizeTheme(theme){return theme==='light'?'light':'dark';}
function isMobileViewport(){try{return window.matchMedia('(max-width:700px)').matches;}catch(_){return false;}}
function applyTheme(theme, opts={}){
  UI_THEME=normalizeTheme(theme);
  // 모바일은 항상 다크로 렌더(라이트 누수 방지). 사용자 설정값(UI_THEME)은 그대로 저장되어 데스크톱에 적용됨.
  document.documentElement.setAttribute('data-theme', isMobileViewport()?'dark':UI_THEME);
  if(opts.persist!==false){
    try{localStorage.setItem(THEME_KEY,UI_THEME);}catch(_){}
  }
  syncThemeToggle();
  syncMobileThemeSheets();
}
// 모바일 다크 시트는 항상 활성(레이아웃 안정). 데스크톱/모바일 전환 시 data-theme도 재적용.
function syncMobileThemeSheets(){
  try{
    const darkEl=document.getElementById('codex-mobile-dark');
    if(darkEl) darkEl.media='all';
  }catch(_){}
}
try{
  const _mq=window.matchMedia('(max-width:700px)');
  const _onMq=()=>{document.documentElement.setAttribute('data-theme', isMobileViewport()?'dark':UI_THEME);};
  if(_mq.addEventListener)_mq.addEventListener('change',_onMq); else if(_mq.addListener)_mq.addListener(_onMq);
}catch(_){}
function toggleTheme(){applyTheme(UI_THEME==='light'?'dark':'light');}
function syncThemeToggle(){
  const btn=document.getElementById('theme-toggle');
  // 헤더 = 현재 상태, 버튼 = 전환할(반대) 상태 — 아이콘·문구 일치
  const light=UI_THEME==='light';
  const stEl=document.getElementById('top-theme-state');
  if(stEl)stEl.textContent=light?'라이트 모드':'다크 모드';
  if(!btn)return;
  btn.setAttribute('aria-pressed',light?'true':'false');
  btn.title=light?'다크 모드로 전환':'라이트 모드로 전환';
  const icon=document.getElementById('theme-icon');
  const label=document.getElementById('theme-label');
  if(icon)icon.textContent=light?'☾':'☀';   // 전환 대상 아이콘(→다크=달 / →라이트=해)
  if(label)label.textContent=light?'다크':'라이트';
}
applyTheme(UI_THEME,{persist:false});

const PAGE_SIZES={issues:10,cases:10,customers:10,eos:10,links:10,knowledge:10,vt:10};
const PAGE_STATE={issues:1,cases:1,customers:1,eos:1,links:1,knowledge:1,vt:1};
let SYNC_META=null;
function changePageSize(scope,val){PAGE_SIZES[scope]=parseInt(val,10)||10;PAGE_STATE[scope]=1;if(scope==='issues')PAGE=1;}
function sliceForPage(items,scope){const size=PAGE_SIZES[scope]||10;const pages=Math.max(1,Math.ceil(items.length/size));let page=PAGE_STATE[scope]||1;if(page<1)page=1;if(page>pages)page=pages;PAGE_STATE[scope]=page;return items.slice((page-1)*size,page*size);}
function pageCountText(scope,total,unit='건'){const size=PAGE_SIZES[scope]||10;const pages=Math.max(1,Math.ceil(total/size));const page=PAGE_STATE[scope]||1;return `${total}${unit} (${page}/${pages})`;}
function renderPager(id,scope,total,renderFn){
  const el=document.getElementById(id);if(!el)return;
  const size=PAGE_SIZES[scope]||10;const pages=Math.max(1,Math.ceil(total/size));
  if((PAGE_STATE[scope]||1)>pages)PAGE_STATE[scope]=pages;
  const page=PAGE_STATE[scope]||1;
  if(total<=size){el.innerHTML='';return;}
  el.innerHTML=`<button ${page<=1?'disabled':''} onclick="PAGE_STATE['${scope}']--;${renderFn}()">이전</button><span>${page} / ${pages}</span><button ${page>=pages?'disabled':''} onclick="PAGE_STATE['${scope}']++;${renderFn}()">다음</button>`;
}
function kstDayParts(date=new Date()){
  const parts=new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(date);
  const get=t=>parts.find(p=>p.type===t)?.value;
  return {day:`${get('year')}-${get('month')}-${get('day')}`,month:`${get('year')}-${get('month')}`};
}
function updateSyncMeta(meta=SYNC_META){
  SYNC_META=meta||SYNC_META||{};
  const range=SYNC_META.rangeMonths||localStorage.getItem('jira_range_months')||'-';
  const count=SYNC_META.count!=null?`${SYNC_META.count}건`:(ISSUES.length?`${ISSUES.length}건`:'-');
  const when=SYNC_META.syncedAt?fdt(SYNC_META.syncedAt):'-';
  const by=SYNC_META.syncedBy||'';
  const text=`최근 ${range}개월 기준 · ${count} · ${when}${by?' · '+escapeHtml(by):''}`;
  const side=document.getElementById('jira-sync-meta');if(side)side.innerHTML=text;
  const banner=document.getElementById('jira-sync-banner');
  if(banner){banner.style.display='flex';banner.innerHTML=`<span><b>Jira 동기화 기준</b> ${text}</span><button class="btn btn-ghost" onclick="syncJira()" style="width:auto;padding:7px 12px;font-size:11px">새로고침</button>`;}
}
async function loadSyncMeta(){
  try{const r=await fetch(`${WORKERS}/config/public`);if(r.ok){const d=await r.json();if(d.rangeMonths)localStorage.setItem('jira_range_months',d.rangeMonths);if(d.aiProvider)AI_PROVIDER=d.aiProvider;if(d.aiModel)AI_MODEL_LABEL=aiModelLabel(d.aiModel);updateSyncMeta(d.lastSync?{...d.lastSync,rangeMonths:d.rangeMonths}:{rangeMonths:d.rangeMonths});return;}}catch{}
  updateSyncMeta();
}

const SC={'완료':'#22d3a5','진행 중':'#818cf8','미해결':'#94a3b8','보류':'#fbbf24'};
const PC={'Highest':'#f87171','High':'#fb923c','Medium':'#fbbf24','Low':'#4ade80'};
const LC_MAP={'DLP':'#f87171','PP':'#f472b6','SEP':'#22d3a5','SEPM':'#22d3a5','ProxySG':'#22d3ee','CloudSWG':'#818cf8','CASB':'#a78bfa'};
function labelColor(l){return LC_MAP[l]||'#94a3b8';}

function fd(d){return d?new Date(d).toLocaleDateString('ko-KR',{year:'2-digit',month:'2-digit',day:'2-digit'}):'-';}
function fdt(d){if(!d)return '-';const dd=(typeof d==='number')?new Date(d):new Date(d);return dd.toLocaleString('ko-KR',{year:'2-digit',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});}
function daysSince(d){return d?Math.floor((Date.now()-new Date(d))/86400000):0;}
function age(d){return daysSince(d);}
function daysUntil(d){return d?Math.ceil((new Date(d)-Date.now())/86400000):0;}
function toast(msg,err){const t=document.getElementById('toast');t.textContent=msg;t.className=err?'err':'';t.style.display='block';setTimeout(()=>t.style.display='none',2800);}
function copyText(text){navigator.clipboard.writeText(text).then(()=>toast('복사됐어요!')).catch(()=>{});}
function encUser(n){try{return btoa(unescape(encodeURIComponent(n)));}catch{return btoa(n);}}
function authHeaders(extra={}){
  const token=localStorage.getItem('engr_session_token')||'';
  return {...extra,'X-User':encUser(CURRENT_USER),...(token?{'X-Session-Token':token}:{})};
}
function escapeHtml(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function normalizeExternalUrl(url){
  const raw=(url||'').trim();
  if(!raw)return '';
  if(/^(https?:|mailto:|tel:)/i.test(raw))return raw;
  if(/^\/\//.test(raw))return 'https:'+raw;
  return 'https://'+raw.replace(/^\/+/, '');
}

// ── AUTH ──────────────────────────────────────────
function togglePinView(){
  const el=document.getElementById('l-pin'),b=document.getElementById('l-pin-eye');
  if(!el)return;
  const show=el.type==='password';
  el.type=show?'text':'password';
  if(b)b.textContent=show?'🙈':'👁';
  el.focus();
}
async function login(opts){
  const name=document.getElementById('l-name').value.trim();
  const pin=document.getElementById('l-pin').value.trim();
  if(!name||!pin){toast('계정 ID와 PIN을 입력해주세요',true);return;}
  const btn=document.getElementById('login-btn');
  btn.disabled=true;btn.textContent='확인 중...';
  try{
    const r=await fetch(`${WORKERS}/auth/login`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,pin})});
    const d=await r.json();
    if(!d.ok){
      // 자동 로그인(저장 PIN)이 실패하면 저장정보가 낡은 것 → 깨끗이 비우고 수동 입력 유도(반복 실패 방지)
      if(opts&&opts.auto){
        ['engr_remember','engr_saved_user','engr_saved_pin'].forEach(k=>localStorage.removeItem(k));
        const pe=document.getElementById('l-pin'); if(pe){pe.value='';}
        const rc=document.getElementById('l-remember'); if(rc)rc.checked=false;
        toast('저장된 자동 로그인 정보가 만료되어 해제했습니다. PIN을 다시 입력해 주세요.',true);
        if(pe)pe.focus();
      }else{
        toast(d.message||'로그인 실패',true);
      }
      btn.disabled=false;btn.textContent='접속하기 →';return;
    }
    CURRENT_USER=d.userId||d.name||name.toLowerCase();
    CURRENT_DISPLAY=d.displayName||CURRENT_USER;
    IS_ADMIN=d.isAdmin;IS_SUPER=d.isSuperAdmin;USER_ROLE=d.role||'user';SESSION_MIN=d.sessionMin||120;
    MUST_CHANGE_PIN=!!d.mustChangePin;
    SESSION_DEADLINE=Date.now()+SESSION_MIN*60000;
    localStorage.setItem('engr_user',CURRENT_USER);localStorage.setItem('engr_display',CURRENT_DISPLAY);localStorage.removeItem('engr_pin');
    localStorage.setItem('engr_role',USER_ROLE);
    localStorage.setItem('engr_is_admin',IS_ADMIN?'1':'0');
    localStorage.setItem('engr_is_super',IS_SUPER?'1':'0');
    localStorage.setItem('engr_session_min',String(SESSION_MIN));
    if(d.sessionToken)localStorage.setItem('engr_session_token',d.sessionToken);
    localStorage.setItem('engr_session_deadline',SESSION_DEADLINE);
    // 로그인 유지: 아이디·PIN 저장(자동 로그인). 미체크 시 저장정보 삭제.
    const remember=document.getElementById('l-remember')?.checked;
    if(remember){
      try{
        localStorage.setItem('engr_remember','1');
        localStorage.setItem('engr_saved_user',name);
        localStorage.setItem('engr_saved_pin',btoa(unescape(encodeURIComponent(pin))));
      }catch(_){}
    }else{
      ['engr_remember','engr_saved_user','engr_saved_pin'].forEach(k=>localStorage.removeItem(k));
    }
    enterApp();
    if(MUST_CHANGE_PIN)setTimeout(forcePinChange,200);
  }catch(e){toast('서버 연결 실패',true);btn.disabled=false;btn.textContent='접속하기 →';}
}
function startSessionTimer(){
  if(SESSION_TIMER)clearInterval(SESSION_TIMER);
  let _warned5=false,_warned1=false;
  SESSION_TIMER=setInterval(()=>{
    const remain=SESSION_DEADLINE-Date.now();
    if(remain<=0){clearInterval(SESSION_TIMER);toast('세션이 만료되었습니다. 다시 로그인해주세요.',true);setTimeout(forceLogout,1800);return;}
    const m=Math.floor(remain/60000),s=Math.floor((remain%60000)/1000);
    document.getElementById('session-timer').textContent=`세션 ${m}:${String(s).padStart(2,'0')}`;
    if(!_warned5&&remain<=300000&&remain>298000){_warned5=true;toast('⏰ 세션이 5분 후 만료됩니다. 화면을 클릭하면 연장됩니다.');}
    if(!_warned1&&remain<=60000&&remain>58000){_warned1=true;toast('⚠️ 세션이 1분 후 만료됩니다!',true);}
    if(remain>310000){_warned5=false;}
    if(remain>70000){_warned1=false;}
  },1000);
}
function extendSession(){SESSION_DEADLINE=Date.now()+SESSION_MIN*60000;localStorage.setItem('engr_session_deadline',SESSION_DEADLINE);}
document.addEventListener('click',extendSession);
document.addEventListener('keydown',extendSession);
function clearLocalSession(){['engr_user','engr_display','engr_pin','engr_session_token','engr_session_deadline','engr_role','engr_is_admin','engr_is_super','engr_session_min'].forEach(k=>localStorage.removeItem(k));}
function forceLogout(){clearLocalSession();location.reload();}
function logout(){if(!confirm('로그아웃 하시겠어요?'))return;['engr_remember','engr_saved_user','engr_saved_pin'].forEach(k=>localStorage.removeItem(k));forceLogout();}

// ── AI 사용량 ──────────────────────────────────────
function setAIUsageText(id,text){const el=document.getElementById(id);if(el)el.textContent=text;}
function fmtUsageCount(v){return `${Number(v||0)}회`;}
function fmtClock(ts){
  try{return new Date(ts||Date.now()).toLocaleTimeString('ko-KR',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});}catch{return '-';}
}
function setAIUsageLoading(reason='manual'){
  const btn=document.getElementById('ai-usage-refresh');
  if(btn){btn.disabled=true;btn.textContent='조회 중';}
  setAIUsageText('ai-usage-state',reason==='login'?'로그인 갱신':'수동 갱신');
  ['ai-my-today','ai-my-month','ai-team-today','ai-team-month','ai-success-month','ai-fail-month'].forEach(id=>setAIUsageText(id,'계산 중...'));
  setAIUsageText('ai-usage-updated','조회 중...');
  const fill=document.getElementById('ai-usage-fill');if(fill){fill.style.width='0%';fill.style.background='';}
}
function finishAIUsageLoading(){
  AI_USAGE_LOADING=false;
  const btn=document.getElementById('ai-usage-refresh');
  if(btn){btn.disabled=false;btn.textContent='↻ 갱신';}
}
function applyAIUsage(usage){
  const me=usage.me||{};
  const team=usage.team||usage||{};
  AI_USAGE_LAST=usage;
  try{localStorage.setItem('engr_ai_usage_last',JSON.stringify(usage));}catch(_){ }
  setAIUsageText('ai-usage-state','갱신됨');
  setAIUsageText('ai-my-today',fmtUsageCount(me.today));
  setAIUsageText('ai-my-month',fmtUsageCount(me.month));
  setAIUsageText('ai-team-today',fmtUsageCount(team.today));
  setAIUsageText('ai-team-month',fmtUsageCount(team.month));
  setAIUsageText('ai-success-month',fmtUsageCount(team.successMonth));
  setAIUsageText('ai-fail-month',fmtUsageCount(team.failMonth));
  const mt=team.modelsToday||{};
  setAIUsageText('ai-model-gemini',fmtUsageCount(mt.gemini));
  setAIUsageText('ai-model-llama',fmtUsageCount(mt.llama));
  setAIUsageText('ai-active-model',(AI_PROVIDER==='gemini'?'Gemini 활성':AI_PROVIDER==='llama'?'Llama 활성':'-'));
  setAIUsageText('ai-usage-updated',`갱신 ${fmtClock(usage.asOf)} · ${usage.timezone||'Asia/Seoul'}`);
  const fill=document.getElementById('ai-usage-fill');
  if(fill){
    const pct=Math.min(Math.round(Number(team.today||0)/200*100),100);
    fill.style.width=pct+'%';
    fill.style.background=pct>80?'#ef4444':pct>50?'#fbbf24':'';
  }
}
function applyCachedAIUsage(){
  try{
    const raw=localStorage.getItem('engr_ai_usage_last');
    if(!raw)return;
    const usage=JSON.parse(raw);
    if(usage&&usage.asOf){applyAIUsage(usage);setAIUsageText('ai-usage-state','이전 값');}
  }catch(_){ }
}
async function loadAIUsage(options={}){
  if(AI_USAGE_LOADING)return;
  AI_USAGE_LOADING=true;
  const reason=options.reason||'manual';
  if(reason==='login')applyCachedAIUsage();
  setAIUsageLoading(reason);
  try{
    const usageEndpoint=(IS_ADMIN||IS_SUPER)?'/kv/usage':'/kv/usage/me';
    const r=await fetch(`${WORKERS}${usageEndpoint}`,{headers:authHeaders()});
    if(!r.ok)throw new Error('usage endpoint unavailable');
    const usage=await r.json();
    applyAIUsage(usage);
  }catch(e){
    console.warn('AI usage load failed:', e);
    setAIUsageText('ai-usage-state','오류');
    setAIUsageText('ai-usage-updated','사용량 조회 실패 · 새로고침 버튼으로 재시도');
    const fill=document.getElementById('ai-usage-fill');if(fill)fill.style.width='0%';
  }finally{
    finishAIUsageLoading();
  }
}

function refreshAIUsage(){loadAIUsage({reason:'manual'});}

// ── PAGE NAV ──────────────────────────────────────
const pageTitles={
  dash:['대시보드','팀 현황 및 개인별 진행 통계'],
  issues:['이슈 관리','전체 이슈 목록 및 상세 조회'],
  cases:['케이스 트래커','벤더 케이스 현황 및 AI 가이드'],
  customers:['고객사 프로필','Jira 기반 고객사별 현황 자동 집계'],
  eos:['라이선스','고객사 라이선스 만료 관리'],
  log:['로그 분석기','솔루션 로그 AI 분석'],
  vt:['VirusTotal 조회','해시값 기반 악성 여부 분석'],
  links:['업무 링크','자주 접근하는 URL 모음'],
  knowledge:['팀 노하우','팀원이 공유하는 Known Issue, 워크어라운드, 팁'],
  audit:['감사 로그','접속 및 사용 이력'],
  settings:['관리자 설정','시스템 설정 및 권한 관리']
};
function resetCustomerFilters(){['cust-q','cust-prod','cust-ass'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});PAGE_STATE.customers=1;renderCustomers();}
function resetEosFilters(){
  ['eos-q'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  PAGE_STATE.eos=1;renderEosList();
}
function resetLinkFilters(){['links-q','links-cat'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});PAGE_STATE.links=1;renderLinks();}
function resetKnowledgeFilters(){
  ['know-q','know-prod','know-cat'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  PAGE_STATE.knowledge=1;renderKnowledge();
}

// ── JIRA ──────────────────────────────────────────
async function ensureIssueDetail(issue){
  if(!issue || issue._detailLoaded || issue._detailLoading)return issue;
  issue._detailLoading=true;
  try{
    const detail=await fetchIssueDetail(issue.key);
    Object.assign(issue,detail,{_detailLoaded:true,_detailLoading:false,_detailError:''});
  }catch(e){
    issue._detailLoading=false;
    issue._detailError=e.message||String(e);
  }
  return issue;
}
async function selectIssue(issue){
  if(!issue)return;
  SEL=issue;
  renderIssues();
  renderRightPanel();
  if(window.innerWidth<=700){syncMobSheet('right-panel');openMobSheet();}
  await ensureIssueDetail(issue);
  if(SEL&&SEL.key===issue.key){
    renderIssues();
    renderRightPanel();
    if(window.innerWidth<=700)syncMobSheet('right-panel');
  }
}



// ── ADF Parser (Atlassian Document Format) ────────
function extractADF(node){
  if(!node)return '';
  let out='';
  function walk(n,depth){
    if(!n)return;
    if(Array.isArray(n)){n.forEach(c=>walk(c,depth));return;}
    const type=n.type;
    const marks=n.marks||[];
    if(type==='text'){
      let t=n.text||'';
      if(marks.some(m=>m.type==='strong'))t='**'+t+'**';
      if(marks.some(m=>m.type==='code'))t='`'+t+'`';
      if(marks.some(m=>m.type==='link')){
        const href=marks.find(m=>m.type==='link')?.attrs?.href||'';
        t=t+' ('+href+')';
      }
      out+=t;return;
    }
    if(type==='hardBreak'){out+='\n';return;}
    if(type==='paragraph'){if(n.content)walk(n.content,depth);out+='\n';return;}
    if(type==='heading'){
      const lvl=n.attrs?.level||1;
      out+='\n'+'#'.repeat(lvl)+' ';
      if(n.content)walk(n.content,depth);
      out+='\n';return;
    }
    if(type==='bulletList'||type==='orderedList'){if(n.content)walk(n.content,depth+1);out+='\n';return;}
    if(type==='listItem'){
      out+='  '.repeat(Math.max(0,depth-1))+'• ';
      if(n.content)walk(n.content,depth);
      return;
    }
    if(type==='codeBlock'){
      out+='\n```\n';
      if(n.content)walk(n.content,depth);
      out+='```\n';return;
    }
    if(type==='blockquote'){out+='> ';if(n.content)walk(n.content,depth);return;}
    if(type==='rule'){out+='\n---\n';return;}
    if(type==='mention'){out+='@'+(n.attrs?.text||'');return;}
    if(n.content)walk(n.content,depth);
  }
  walk(node.content||node,0);
  return out.replace(/\n{3,}/g,'\n\n').trim().slice(0,8000);
}
function extractADFPlain(node){
  if(!node)return '';
  const texts=[];
  function walk(nodes){if(!nodes)return;nodes.forEach(n=>{if(n.type==='text'&&n.text)texts.push(n.text);if(n.content)walk(n.content);});}
  walk(node.content||node);
  return texts.join(' ').slice(0,3000);
}
function extractCommentsArr(comment){
  if(!comment||!comment.comments)return [];
  return comment.comments.slice(-20).map(c=>({
    author:c.author?.displayName||'-',
    body:extractADF(c.body),
    bodyPlain:extractADFPlain(c.body),
    created:c.created||''
  }));
}
function extractAttachments(att){
  if(!att||!Array.isArray(att))return [];
  return att.map(a=>({name:a.filename||'unknown',size:a.size||0,mime:a.mimeType||''}));
}
function isRealCust(v){const s=String(v==null?'':v).trim().toLowerCase();return !!s&&!['none','null','n/a','na','-','없음','미정','undefined'].includes(s);}
const NON_CUST_TAGS=['hands-on','handson','hands on','none','null','n/a','na','test','테스트','내부','검토','긴급','urgent','poc'];
function extractCustomer(title){
  const matches=title.match(/\[([^\]]+)\]/g)||[];
  for(const m of matches){
    const inner=m.slice(1,-1).trim();
    if(!inner||/^\d+$/.test(inner))continue;
    if(NON_CUST_TAGS.includes(inner.toLowerCase()))continue;
    return inner;
  }
  return '';
}


function adfToHtml(text){
  if(!text)return '';
  let h=escapeHtml(text);
  h=h.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
  h=h.replace(/`([^`]+)`/g,'<code>$1</code>');
  h=h.replace(/^### (.+)$/gm,'<strong style="color:var(--accent3);display:block;margin-top:6px">$1</strong>');
  h=h.replace(/^## (.+)$/gm,'<strong style="color:var(--accent3);display:block;margin-top:8px">$1</strong>');
  h=h.replace(/^# (.+)$/gm,'<strong style="color:var(--accent3);display:block;margin-top:10px;font-size:13px">$1</strong>');
  h=h.replace(/^---$/gm,'<hr style="border:none;border-top:1px solid var(--border);margin:8px 0">');
  return h;
}