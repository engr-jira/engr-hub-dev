
/* ===== My Desk (mydesk.html) merged natively — isolated in IIFE ===== */
(function(){
/* ---------- storage: claude.ai artifact KV  →  local file localStorage  →  memory ---------- */
const ART = !!(window.storage && typeof window.storage.get === 'function');
const LS  = (function(){ try{ localStorage.setItem('__t','1'); localStorage.removeItem('__t'); return true; }catch(e){ return false; } })();
let storageOK = ART || LS;
const _pending = {}, _timers = {};
// 서버(KV) 기반 사용자별 저장. window.__MD_STORE가 서버에서 로드된 캐시.
// 로그인/서버 로드 전(__mdLoaded=false)에는 localStorage로 임시 표시.
async function load(key, def){
  try{
    if(window.__mdLoaded){ const v=(window.__MD_STORE||{})[key]; return v!==undefined?v:def; }
    if(LS){ const v = localStorage.getItem('escare:'+key); return v!=null ? JSON.parse(v) : def; }
  }catch(e){}
  return def;
}
function save(key, val){
  if(!window.__MD_STORE)window.__MD_STORE={};
  window.__MD_STORE[key]=val;
  if(LS){ try{ localStorage.setItem('escare:'+key, JSON.stringify(val)); }catch(e){} }
  if(window.__mdQueueServerSave)window.__mdQueueServerSave();
  markSavedByKey(key); flashSaved();
}
function saveNow(key,val){
  if(!window.__MD_STORE)window.__MD_STORE={};
  window.__MD_STORE[key]=val;
  if(LS){ try{ localStorage.setItem('escare:'+key, JSON.stringify(val)); }catch(e){} }
  if(window.__mdServerSaveNow)window.__mdServerSaveNow(); else if(window.__mdQueueServerSave)window.__mdQueueServerSave();
  markSavedByKey(key); flashSaved();
}
let saveTimer;
function flashSaved(){ const el=document.getElementById('saved'); el.textContent='저장됨'; el.style.color='var(--teal)'; el.classList.add('show'); clearTimeout(saveTimer); saveTimer=setTimeout(()=>el.classList.remove('show'),1100); }
function showDegraded(){ const el=document.getElementById('saved'); el.textContent='⚠ 저장 불가 — 세션 내에서만 유지'; el.style.color='var(--amber)'; el.classList.add('show'); }
const KEY_CARD={'routine-items':'routine','routine-state':'routine','team-members':'team','team-data':'team','weekly-meeting':'weekly','todos':'todos','notes':'notes','links':'shortcuts','rdps':'shortcuts','cases':'cases','accounts':'accounts','acct-state':'accounts'};
function markCardSaved(card){ const el=document.getElementById(card+'-saved'); if(!el) return; const t=new Date(); const p=n=>String(n).padStart(2,'0'); el.textContent='✓ 저장됨 '+p(t.getHours())+':'+p(t.getMinutes())+':'+p(t.getSeconds()); el.classList.add('ok'); }
function markSavedByKey(key){ const c=KEY_CARD[key]; if(c) markCardSaved(c); }
function cardSave(card){
  if(card==='routine'){ saveNow('routine-items',routineItems); saveNow('routine-state',{date:todayKey(),checks:routineChecks}); }
  else if(card==='team'){ saveNow('team-members',teamMembers); saveNow('team-data',teamData); }
  else if(card==='weekly'){ saveNow('weekly-meeting',{title:document.getElementById('wk-title').value,date:document.getElementById('wk-date').value,time:document.getElementById('wk-time').value}); }
  else if(card==='todos'){ saveNow('todos',todos); }
  else if(card==='notes'){ saveNow('notes',document.getElementById('notes').value); }
  else if(card==='shortcuts'){ saveNow('links',links); saveNow('rdps',rdps); }
  else if(card==='cases'){ saveNow('cases',cases); }
  else if(card==='accounts'){ saveNow('accounts',accounts); saveNow('acct-state',acctState); }
  markCardSaved(card);
}

/* ---------- date / clock ---------- */
const DAYS=['일','월','화','수','목','금','토'];
function todayKey(){ const d=new Date(); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
function tickClock(){ const c=document.getElementById('clock'); if(c){const d=new Date();c.textContent=String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0'); const ds=document.getElementById('datestr'); if(ds)ds.textContent=d.getFullYear()+'.'+String(d.getMonth()+1).padStart(2,'0')+'.'+String(d.getDate()).padStart(2,'0')+' ('+DAYS[d.getDay()]+')';} }
function setGreeting(){ const h=new Date().getHours(); let g,s;
  if(h<6){g='늦은 시간까지 고생 많으십니다';s='무리하지 마세요.';}
  else if(h<11){g='좋은 아침입니다';s='오늘 루틴부터 가볍게 점검해 보세요.';}
  else if(h<14){g='점심 무렵이네요';s='오전 진행 상황을 정리할 시간입니다.';}
  else if(h<18){g='오후도 힘내세요';s='회신 대기·케이스 상태를 확인해 보세요.';}
  else{g='하루 마무리 시간입니다';s='지원내역 기록과 내일 우선순위를 정리해 보세요.';}
  const ge=document.getElementById('greeting'); if(ge)ge.innerHTML=g+', <span class="name">'+(window.__HUB_DISPLAY||'팀원')+' 님</span>'; const se=document.getElementById('subline'); if(se)se.textContent=s; }
function injectMyDeskHeader(){
  const pg=document.getElementById('page-mydesk'); if(!pg||document.getElementById('greeting'))return;
  pg.insertAdjacentHTML('afterbegin','<style>#greeting .name{color:#a78bfa}</style><div style="display:flex;justify-content:space-between;align-items:flex-end;margin:0 0 16px;flex-wrap:wrap;gap:10px"><div><div id="greeting" style="font-size:18px;font-weight:800;color:var(--text,#e8edff)"></div><div id="subline" style="font-size:12px;color:var(--text3);margin-top:3px"></div></div><div class="u-ta-right"><div id="clock" style="font-size:22px;font-weight:800;color:var(--text,#e8edff);font-variant-numeric:tabular-nums;line-height:1"></div><div id="datestr" style="font-size:11px;color:var(--text3);margin-top:2px"></div></div></div>');
}

/* ---------- ROUTINE ---------- */
const DEFAULT_ROUTINE=[];
const GROUP_ORDER=['아침 · 시작','업무 중','마감'];
let routineItems=[]; let routineChecks={};
function renderRoutine(){
  const root=document.getElementById('routine'); root.innerHTML='';
  const byGroup={}; routineItems.forEach(it=>{ (byGroup[it.g]=byGroup[it.g]||[]).push(it); });
  const groups=GROUP_ORDER.concat(Object.keys(byGroup).filter(g=>!GROUP_ORDER.includes(g)));
  groups.forEach(g=>{
    const wrap=document.createElement('div'); wrap.className='group';
    const lbl=document.createElement('div'); lbl.className='group-label'; lbl.textContent=g; wrap.appendChild(lbl);
    (byGroup[g]||[]).forEach(it=>{
      const done=!!routineChecks[it.id];
      const row=document.createElement('div'); row.className='item'+(done?' done':'');
      row.innerHTML='<span class="check"><svg width="11" height="11" viewBox="0 0 11 11"><path d="M2 5.5L4.3 8L9 2.5" stroke="#1a140a" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></span><span class="txt" contenteditable="false">'+escapeHtml(it.t)+'</span><button class="rm" title="삭제">×</button>';
      const txt=row.querySelector('.txt');
      row.addEventListener('click',e=>{ if(e.target.closest('.rm')||e.target===txt) return; routineChecks[it.id]=!routineChecks[it.id]; renderRoutine(); persistRoutineState(); });
      txt.addEventListener('dblclick',()=>{ txt.contentEditable='true'; txt.focus(); });
      txt.addEventListener('blur',()=>{ txt.contentEditable='false'; it.t=txt.textContent.trim()||it.t; txt.textContent=it.t; save('routine-items',routineItems); });
      txt.addEventListener('keydown',e=>{ if(e.key==='Enter'){ e.preventDefault(); txt.blur(); }});
      row.querySelector('.rm').addEventListener('click',()=>{ routineItems=routineItems.filter(x=>x.id!==it.id); delete routineChecks[it.id]; save('routine-items',routineItems); persistRoutineState(); renderRoutine(); });
      wrap.appendChild(row);
    });
    const ar=document.createElement('div'); ar.className='add-row';
    ar.innerHTML='<input type="text" placeholder="항목 추가…"><button title="추가">+</button>';
    const inp=ar.querySelector('input');
    const addFn=()=>{ const v=inp.value.trim(); if(!v) return; routineItems.push({id:'r'+Date.now(),g:g,t:v}); inp.value=''; save('routine-items',routineItems); renderRoutine(); };
    ar.querySelector('button').addEventListener('click',addFn);
    inp.addEventListener('keydown',e=>{ if(e.key==='Enter') addFn(); });
    wrap.appendChild(ar); root.appendChild(wrap);
  });
  updateRing();
}
function updateRing(){ const total=routineItems.length, done=routineItems.filter(it=>routineChecks[it.id]).length; const pct=total?Math.round(done/total*100):0; document.getElementById('routine-count').textContent=done+' / '+total; document.getElementById('ring-pct').textContent=pct+'%'; document.getElementById('ring-fg').style.strokeDashoffset=(2*Math.PI*22)*(1-pct/100); }
function persistRoutineState(){ save('routine-state',{date:todayKey(),checks:routineChecks}); updateRing(); }
let routineResetArmed=false; let routineResetTimer=null;
function wireRoutineReset(){
  const btn=document.getElementById('routine-reset'); if(!btn) return;
  btn.addEventListener('click',()=>{
    if(!routineResetArmed){ routineResetArmed=true; btn.classList.add('arm'); btn.textContent='한번 더 누르면 초기화'; routineResetTimer=setTimeout(()=>{ routineResetArmed=false; btn.classList.remove('arm'); btn.textContent='비우기'; },3000); return; }
    clearTimeout(routineResetTimer); routineResetArmed=false; btn.classList.remove('arm'); btn.textContent='비우기';
    routineItems=DEFAULT_ROUTINE.map(it=>({id:it.id,g:it.g,t:it.t})); routineChecks={};
    saveNow('routine-items',routineItems); saveNow('routine-state',{date:todayKey(),checks:routineChecks});
    renderRoutine(); toast('루틴을 비웠습니다');
  });
}

/* ---------- TEAM (체크 칩 + 전일/금일 보고) ---------- */
const DEFAULT_TEAM=[{id:'m1',name:'이서현'},{id:'m2',name:'김민지'},{id:'m3',name:'최시온'},{id:'m4',name:'이효성'},{id:'m5',name:'박예림'},{id:'m6',name:'박진표'}];
let teamMembers=[]; let teamData={checks:{},prev:'',today:''};
function renderTeamRow(){
  const root=document.getElementById('team-row'); root.innerHTML='';
  teamMembers.forEach(m=>{
    const done=!!teamData.checks[m.id];
    const chip=document.createElement('div'); chip.className='chip'+(done?' done':'');
    chip.innerHTML='<span class="cdot"></span><span class="cname" contenteditable="false">'+escapeHtml(m.name)+'</span><button class="crm" title="삭제">×</button>';
    const name=chip.querySelector('.cname');
    chip.addEventListener('click',e=>{ if(e.target.closest('.crm')||e.target===name) return; teamData.checks[m.id]=!teamData.checks[m.id]; saveTeam(); renderTeamRow(); });
    name.addEventListener('dblclick',e=>{ e.stopPropagation(); name.contentEditable='true'; name.focus(); });
    name.addEventListener('click',e=>{ if(name.isContentEditable) e.stopPropagation(); });
    name.addEventListener('blur',()=>{ name.contentEditable='false'; m.name=name.textContent.trim()||m.name; name.textContent=m.name; save('team-members',teamMembers); });
    name.addEventListener('keydown',e=>{ if(e.key==='Enter'){ e.preventDefault(); name.blur(); }});
    chip.querySelector('.crm').addEventListener('click',e=>{ e.stopPropagation(); teamMembers=teamMembers.filter(x=>x.id!==m.id); delete teamData.checks[m.id]; save('team-members',teamMembers); saveTeam(); renderTeamRow(); });
    root.appendChild(chip);
  });
  const add=document.createElement('div'); add.className='chip-add';
  add.innerHTML='<input type="text" placeholder="+ 팀원">';
  const inp=add.querySelector('input');
  const addFn=()=>{ const v=inp.value.trim(); if(!v) return; teamMembers.push({id:'m'+Date.now(),name:v}); inp.value=''; save('team-members',teamMembers); renderTeamRow(); };
  inp.addEventListener('keydown',e=>{ if(e.key==='Enter') addFn(); });
  inp.addEventListener('blur',addFn);
  root.appendChild(add);
  updateTeamCount();
}
function updateTeamCount(){ const total=teamMembers.length, done=teamMembers.filter(m=>teamData.checks[m.id]).length; document.getElementById('team-count').textContent=done+' / '+total; }
function saveTeam(){ save('team-data',teamData); updateTeamCount(); }
function fmtDate(k){ try{ const d=new Date(k+'T00:00:00'); return k+' ('+DAYS[d.getDay()]+')'; }catch(e){ return k; } }
function renderHistory(){
  const list=document.getElementById('history-list'); if(!list) return;
  if(!Array.isArray(teamData.history)) teamData.history=[];
  const h=teamData.history;
  document.getElementById('history-count').textContent='('+h.length+'/7)';
  list.innerHTML='';
  if(!h.length){ list.innerHTML='<div class="history-empty">누적된 일보고가 없습니다. ‘다음 날’ 버튼을 누르면 그날 금일 내용이 여기 쌓입니다 (최대 7일).</div>'; return; }
  [...h].reverse().forEach(e=>{
    const el=document.createElement('div'); el.className='hentry';
    el.innerHTML='<div class="hdate"><span>'+fmtDate(e.date)+'</span><button class="hrm" title="삭제">×</button></div><div class="htext">'+escapeHtml(e.text||'')+'</div>';
    el.querySelector('.hrm').addEventListener('click',()=>{ teamData.history=teamData.history.filter(x=>x.id!==e.id); saveTeam(); renderHistory(); });
    list.appendChild(el);
  });
}
function copyHistory(){
  const h=Array.isArray(teamData.history)?teamData.history:[];
  if(!h.length && !(teamData.today&&teamData.today.trim())){ toast('누적된 일보고가 없습니다'); return; }
  let out='주간 일보고 누적 (최근 '+h.length+'일)\n\n';
  h.forEach(e=>{ out+='=== '+fmtDate(e.date)+' ===\n'+(e.text||'')+'\n\n'; });
  if(teamData.today && teamData.today.trim()){ out+='=== (작성 중) 금일 '+fmtDate(todayKey())+' ===\n'+teamData.today+'\n\n'; }
  out=out.trim();
  tryCopy(out).then(ok=>{ if(ok) toast('주간 누적 복사됨 — 미팅 메모에 붙여넣기'); else openCopyModal(out,'주간 일보고 누적'); });
}

/* ---------- WEEKLY MEETING ---------- */
function ddayText(date){
  if(!date) return {t:'날짜 미설정',c:''};
  const today=new Date(); today.setHours(0,0,0,0);
  const d=new Date(date+'T00:00:00'); const diff=Math.round((d-today)/86400000);
  const md=date.replace(/-/g,'.'); const wd=DAYS[d.getDay()]; let t,c;
  if(diff<0){t='지남 '+(-diff)+'일';c='over';}
  else if(diff===0){t='오늘';c='today';}
  else if(diff===1){t='내일';c='soon';}
  else{t='D-'+diff;c=diff<=3?'soon':'';}
  return {t:md+' ('+wd+') · '+t,c:c};
}
function refreshWeekly(){ const info=ddayText(document.getElementById('wk-date').value); const tv=(document.getElementById('wk-time')||{}).value||''; const el=document.getElementById('wk-dday'); el.textContent=info.t+(tv?(' · '+tv):''); el.className='dday meta'+(info.c?' '+info.c:''); }

/* ---------- TASKS ---------- */
let todos=[]; let prio='M';
const expanded=new Set(); const editing=new Set();
const PRIO_RANK={H:0,M:1,L:2};
function dueInfo(due){
  if(!due) return null;
  const today=new Date(); today.setHours(0,0,0,0);
  const d=new Date(due+'T00:00:00'); const diff=Math.round((d-today)/86400000);
  const md=due.slice(5).replace('-','.'); let label,cls;
  if(diff<0){label='지남 '+(-diff)+'일';cls='overdue';}
  else if(diff===0){label='오늘';cls='today';}
  else if(diff===1){label='내일';cls='soon';}
  else{label='D-'+diff;cls=diff<=3?'soon':'future';}
  return {label:label+' · '+md,cls:cls};
}
function renderTodos(){
  const root=document.getElementById('todos'); root.innerHTML='';
  const key=t=>(t.due||'9999-99-99');
  const sorted=[...todos].sort((a,b)=>(a.done-b.done)||(PRIO_RANK[a.p]-PRIO_RANK[b.p])||(key(a)<key(b)?-1:key(a)>key(b)?1:0));
  document.getElementById('todo-count').textContent=todos.filter(t=>!t.done).length+'건';
  if(!todos.length){ root.innerHTML='<div class="empty">등록된 할 일이 없습니다.</div>'; return; }
  sorted.forEach(t=>{
    if(!t.subs) t.subs=[];
    if(editing.has(t.id)){
      const wrap=document.createElement('div'); wrap.className='task'; wrap.dataset.p=t.p;
      const ed=document.createElement('div'); ed.className='task-edit';
      ed.innerHTML='<input class="te-text" type="text"><div class="te-prio"><button data-p="H">높음</button><button data-p="M">보통</button><button data-p="L">낮음</button></div><input class="te-due" type="date"><div class="te-actions"><button class="te-cancel">취소</button><button class="te-save">저장</button></div>';
      const teText=ed.querySelector('.te-text'); teText.value=t.t;
      const teDue=ed.querySelector('.te-due'); teDue.value=t.due||'';
      let curP=t.p; const pbtns=[...ed.querySelectorAll('.te-prio button')];
      const markP=()=>pbtns.forEach(b=>b.classList.toggle('sel', b.dataset.p===curP)); markP();
      pbtns.forEach(b=>b.addEventListener('click',()=>{ curP=b.dataset.p; markP(); }));
      const commit=()=>{ t.t=teText.value.trim()||t.t; t.p=curP; t.due=teDue.value||null; editing.delete(t.id); save('todos',todos); renderTodos(); };
      ed.querySelector('.te-save').addEventListener('click',commit);
      ed.querySelector('.te-cancel').addEventListener('click',()=>{ editing.delete(t.id); renderTodos(); });
      teText.addEventListener('keydown',e=>{ if(e.key==='Enter') commit(); if(e.key==='Escape'){ editing.delete(t.id); renderTodos(); } });
      wrap.appendChild(ed); root.appendChild(wrap); setTimeout(()=>{ teText.focus(); teText.select(); },30); return;
    }
    const subDone=t.subs.filter(s=>s.done).length; const isOpen=expanded.has(t.id); const di=dueInfo(t.due);
    const wrap=document.createElement('div'); wrap.className='task'+(t.done?' done':'')+(isOpen?' expanded':''); wrap.dataset.p=t.p;
    const head=document.createElement('div'); head.className='task-head';
    head.innerHTML='<span class="bar"></span><span class="chev">▶</span><span class="tcheck"></span><span class="ttxt">'+escapeHtml(t.t)+'</span>'+(t.subs.length?'<span class="sub-prog">'+subDone+'/'+t.subs.length+'</span>':'')+(di?'<span class="due '+di.cls+'">'+di.label+'</span>':'')+'<button class="edit" title="수정">✎</button><button class="rm" title="삭제">×</button>';
    head.querySelector('.chev').addEventListener('click',e=>{ e.stopPropagation(); if(expanded.has(t.id)) expanded.delete(t.id); else expanded.add(t.id); renderTodos(); });
    head.querySelector('.tcheck').addEventListener('click',()=>{ t.done=!t.done; save('todos',todos); renderTodos(); });
    head.querySelector('.edit').addEventListener('click',()=>{ editing.add(t.id); renderTodos(); });
    head.querySelector('.rm').addEventListener('click',()=>{ todos=todos.filter(x=>x.id!==t.id); expanded.delete(t.id); editing.delete(t.id); save('todos',todos); renderTodos(); });
    wrap.appendChild(head);
    const subs=document.createElement('div'); subs.className='subs';
    t.subs.forEach(s=>{
      const sr=document.createElement('div'); sr.className='sub'+(s.done?' done':'');
      sr.innerHTML='<span class="scheck"></span><span class="stxt">'+escapeHtml(s.t)+'</span><button class="rm">×</button>';
      sr.querySelector('.scheck').addEventListener('click',()=>{ s.done=!s.done; save('todos',todos); renderTodos(); });
      sr.querySelector('.rm').addEventListener('click',()=>{ t.subs=t.subs.filter(x=>x.id!==s.id); save('todos',todos); renderTodos(); });
      subs.appendChild(sr);
    });
    const sa=document.createElement('div'); sa.className='sub-add';
    sa.innerHTML='<input type="text" placeholder="하위 항목 추가…"><button>+</button>';
    const sinp=sa.querySelector('input');
    const addSub=()=>{ const v=sinp.value.trim(); if(!v) return; t.subs.push({id:'s'+Date.now(),t:v,done:false}); sinp.value=''; expanded.add(t.id); save('todos',todos); renderTodos(); };
    sa.querySelector('button').addEventListener('click',addSub);
    sinp.addEventListener('keydown',e=>{ if(e.key==='Enter') addSub(); });
    subs.appendChild(sa); wrap.appendChild(subs); root.appendChild(wrap);
  });
}
function addTodo(){ const inp=document.getElementById('todo-text'); const v=inp.value.trim(); if(!v) return; const dueEl=document.getElementById('todo-due'); todos.push({id:'t'+Date.now(),t:v,p:prio,done:false,due:dueEl.value||null,subs:[]}); inp.value=''; dueEl.value=''; save('todos',todos); renderTodos(); }

/* ---------- SHORTCUTS (링크 + RDP) ---------- */
let links=[]; let rdps=[];
const editLink=new Set(), editRdp=new Set();
function openUrl(u){ if(!u) return; let url=String(u).trim(); if(!/^https?:\/\//i.test(url)) url='https://'+url; window.open(url,'_blank','noopener'); }
function downloadRdp(ip,user,label,port){
  if(!ip){ toast('IP가 없습니다'); return; }
  const addr=ip+(port?(':'+String(port).trim()):'');
  const lines=['screen mode id:i:2','use multimon:i:0','full address:s:'+addr,'username:s:'+(user||''),'prompt for credentials:i:1','authentication level:i:2','redirectclipboard:i:1','administrative session:i:0'];
  const blob=new Blob([lines.join('\r\n')+'\r\n'],{type:'application/x-rdp'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=url; a.download=(String(label||ip).replace(/[^\w가-힣.\-]/g,'_')||'remote')+'.rdp';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url),1500);
  toast('.rdp 다운로드 — 열면 mstsc 연결');
}
function renderLinks(){
  const root=document.getElementById('sc-links'); if(!root) return; root.innerHTML='';
  if(!links.length && !editLink.size) root.innerHTML='';
  links.forEach(l=>{
    if(editLink.has(l.id)){
      const ed=document.createElement('div'); ed.className='sc-add';
      ed.innerHTML='<input class="a-name" type="text"><input class="a-url" type="text"><button class="e-save">저장</button><button class="e-cancel">취소</button>';
      const n=ed.querySelector('.a-name'), u=ed.querySelector('.a-url'); n.value=l.label||''; u.value=l.url||'';
      ed.querySelector('.e-save').addEventListener('click',()=>{ l.url=u.value.trim()||l.url; l.label=n.value.trim()||l.url; editLink.delete(l.id); saveNow('links',links); renderLinks(); });
      ed.querySelector('.e-cancel').addEventListener('click',()=>{ editLink.delete(l.id); renderLinks(); });
      root.appendChild(ed); return;
    }
    const row=document.createElement('div'); row.className='sc-row';
    row.innerHTML='<div class="sc-main"><span class="sc-name">🔗 '+escapeHtml(l.label||l.url)+'</span><span class="sc-sub">'+escapeHtml(l.url)+'</span></div><button class="sc-go">열기</button><button class="sc-act ed" title="수정">✎</button><button class="sc-act del" title="삭제">×</button>';
    row.querySelector('.sc-main').addEventListener('click',()=>openUrl(l.url));
    row.querySelector('.sc-go').addEventListener('click',()=>openUrl(l.url));
    row.querySelector('.ed').addEventListener('click',()=>{ editLink.add(l.id); renderLinks(); });
    row.querySelector('.del').addEventListener('click',()=>{ links=links.filter(x=>x.id!==l.id); saveNow('links',links); renderLinks(); });
    root.appendChild(row);
  });
  const add=document.createElement('div'); add.className='sc-add';
  add.innerHTML='<input class="a-name" type="text" placeholder="이름"><input class="a-url" type="text" placeholder="https://..."><button title="추가">+</button>';
  const n=add.querySelector('.a-name'), u=add.querySelector('.a-url');
  const addFn=()=>{ const url=u.value.trim(); if(!url) return; links.push({id:'l'+Date.now(),label:n.value.trim()||url,url:url}); n.value='';u.value=''; saveNow('links',links); renderLinks(); };
  add.querySelector('button').addEventListener('click',addFn);
  u.addEventListener('keydown',e=>{ if(e.key==='Enter') addFn(); });
  root.appendChild(add);
}
function renderRdps(){
  const root=document.getElementById('sc-rdps'); if(!root) return; root.innerHTML='';
  rdps.forEach(r=>{
    if(editRdp.has(r.id)){
      const ed=document.createElement('div'); ed.className='sc-add';
      ed.innerHTML='<input class="a-name" type="text"><input class="a-ip" type="text"><input class="a-port" type="text" inputmode="numeric" placeholder="포트"><input class="a-user" type="text"><button class="e-save">저장</button><button class="e-cancel">취소</button>';
      const n=ed.querySelector('.a-name'), ip=ed.querySelector('.a-ip'), po=ed.querySelector('.a-port'), us=ed.querySelector('.a-user'); n.value=r.label||''; ip.value=r.ip||''; po.value=r.port||''; us.value=r.user||'';
      ed.querySelector('.e-save').addEventListener('click',()=>{ r.ip=ip.value.trim()||r.ip; r.port=po.value.trim(); r.user=us.value.trim(); r.label=n.value.trim()||r.ip; editRdp.delete(r.id); saveNow('rdps',rdps); renderRdps(); });
      ed.querySelector('.e-cancel').addEventListener('click',()=>{ editRdp.delete(r.id); renderRdps(); });
      root.appendChild(ed); return;
    }
    const row=document.createElement('div'); row.className='sc-row';
    row.innerHTML='<div class="sc-main"><span class="sc-name">🖥 '+escapeHtml(r.label||r.ip)+'</span><span class="sc-sub">'+escapeHtml(r.ip+(r.port?':'+r.port:''))+(r.user?' / '+escapeHtml(r.user):'')+'</span></div><button class="sc-go">접속</button><button class="sc-cmd" title="mstsc 명령 복사">cmd</button><button class="sc-act ed" title="수정">✎</button><button class="sc-act del" title="삭제">×</button>';
    row.querySelector('.sc-go').addEventListener('click',()=>downloadRdp(r.ip,r.user,r.label,r.port));
    row.querySelector('.sc-cmd').addEventListener('click',()=>{ const c='mstsc /v:'+r.ip+(r.port?':'+r.port:''); tryCopy(c).then(ok=>toast(ok?('복사됨: '+c):'복사 실패')); });
    row.querySelector('.ed').addEventListener('click',()=>{ editRdp.add(r.id); renderRdps(); });
    row.querySelector('.del').addEventListener('click',()=>{ rdps=rdps.filter(x=>x.id!==r.id); saveNow('rdps',rdps); renderRdps(); });
    root.appendChild(row);
  });
  const add=document.createElement('div'); add.className='sc-add';
  add.innerHTML='<input class="a-name" type="text" placeholder="이름"><input class="a-ip" type="text" placeholder="IP/호스트"><input class="a-port" type="text" inputmode="numeric" placeholder="포트"><input class="a-user" type="text" placeholder="계정"><button title="추가">+</button>';
  const n=add.querySelector('.a-name'), ip=add.querySelector('.a-ip'), po=add.querySelector('.a-port'), us=add.querySelector('.a-user');
  const addFn=()=>{ const v=ip.value.trim(); if(!v) return; rdps.push({id:'d'+Date.now(),label:n.value.trim()||v,ip:v,port:po.value.trim(),user:us.value.trim()}); n.value='';ip.value='';po.value='';us.value=''; saveNow('rdps',rdps); renderRdps(); };
  add.querySelector('button').addEventListener('click',addFn);
  us.addEventListener('keydown',e=>{ if(e.key==='Enter') addFn(); });
  ip.addEventListener('keydown',e=>{ if(e.key==='Enter') addFn(); });
  root.appendChild(add);
}

/* ---------- CASES (벤더 케이스 트래커) ---------- */
let cases=[]; const editCase=new Set();
const CASE_ST=['대기','진행','종료']; const CASE_RANK={'진행':0,'대기':1,'종료':2};
function fmtMd(d){ return d?d.slice(5).replace('-','.'):''; }
function renderCases(){
  const root=document.getElementById('cases-list'); if(!root) return; root.innerHTML='';
  const sorted=[...cases].sort((a,b)=>(CASE_RANK[a.status]-CASE_RANK[b.status])||((a.updated||'')<(b.updated||'')?1:(a.updated||'')>(b.updated||'')?-1:0));
  const active=cases.filter(c=>c.status!=='종료').length;
  const cc=document.getElementById('cases-count'); if(cc) cc.textContent=active+'건 진행중';
  if(!cases.length){ root.innerHTML='<div class="case-empty">등록된 케이스가 없습니다.</div>'; }
  sorted.forEach(c=>{
    if(editCase.has(c.id)){ root.appendChild(caseEditRow(c)); return; }
    const row=document.createElement('div'); row.className='case'+(c.status==='종료'?' done':'');
    row.innerHTML='<span class="case-st" data-st="'+c.status+'">'+c.status+'</span><div class="case-main"><span class="case-title">'+escapeHtml(c.title)+'</span><span class="case-sub">'+escapeHtml(c.customer||'')+(c.updated?' · 오픈 '+fmtMd(c.updated):'')+'</span></div><button class="ed" title="수정">✎</button><button class="rm" title="삭제">×</button>';
    row.querySelector('.case-st').addEventListener('click',()=>{ const i=CASE_ST.indexOf(c.status); c.status=CASE_ST[(i+1)%CASE_ST.length]; saveNow('cases',cases); renderCases(); });
    row.querySelector('.ed').addEventListener('click',()=>{ editCase.add(c.id); renderCases(); });
    row.querySelector('.rm').addEventListener('click',()=>{ cases=cases.filter(x=>x.id!==c.id); saveNow('cases',cases); renderCases(); });
    root.appendChild(row);
  });
  const add=document.createElement('div'); add.className='case-add';
  add.innerHTML='<input class="c-title" type="text" placeholder="케이스/제목"><input class="c-cust" type="text" placeholder="고객사" list="customer-list"><span class="c-date-cap">오픈일</span><input class="c-date" type="date" title="케이스 오픈일"><button title="추가">+</button>';
  const t=add.querySelector('.c-title'), cu=add.querySelector('.c-cust'), dt=add.querySelector('.c-date');
  const addFn=()=>{ const v=t.value.trim(); if(!v) return; cases.push({id:'c'+Date.now()+Math.random().toString(36).slice(2,7),title:v,customer:cu.value.trim(),status:'대기',updated:dt.value||''}); t.value='';cu.value='';dt.value=''; saveNow('cases',cases); renderCases(); };
  add.querySelector('button').addEventListener('click',addFn);
  t.addEventListener('keydown',e=>{ if(e.key==='Enter') addFn(); });
  root.appendChild(add);
}
function caseEditRow(c){
  const ed=document.createElement('div'); ed.className='case-add';
  ed.innerHTML='<input class="c-title" type="text"><input class="c-cust" type="text" list="customer-list"><span class="c-date-cap">오픈일</span><input class="c-date" type="date" title="케이스 오픈일"><button class="e-save">저장</button><button class="e-cancel">취소</button>';
  const t=ed.querySelector('.c-title'), cu=ed.querySelector('.c-cust'), dt=ed.querySelector('.c-date'); t.value=c.title||''; cu.value=c.customer||''; dt.value=c.updated||'';
  ed.querySelector('.e-save').addEventListener('click',()=>{ c.title=t.value.trim()||c.title; c.customer=cu.value.trim(); c.updated=dt.value||''; editCase.delete(c.id); saveNow('cases',cases); renderCases(); });
  ed.querySelector('.e-cancel').addEventListener('click',()=>{ editCase.delete(c.id); renderCases(); });
  return ed;
}

/* ---------- ACCOUNTS (고객사 핀/현황) ---------- */
const DEFAULT_ACCOUNTS=['우리은행','우리FIS','아모레퍼시픽','라이나생명','KB증권','케이뱅크','세방그룹','대덕전자','종근당','처브라이프','우리카드','하나투어','카카오뱅크','동양생명','르노코리아'].map((n,i)=>({id:'a'+(i+1),name:n}));
let accounts=[]; let acctState={pinned:{},notes:{}};
function persistAccounts(){ saveNow('acct-state',acctState); }
function renderAccounts(){
  const chips=document.getElementById('acct-chips'); if(!chips) return; chips.innerHTML='';
  accounts.forEach(a=>{
    const pin=!!acctState.pinned[a.id];
    const chip=document.createElement('div'); chip.className='acct-chip'+(pin?' pin':'');
    chip.innerHTML='<span class="pdot"></span><span class="aname" contenteditable="false">'+escapeHtml(a.name)+'</span><button class="arm" title="삭제">×</button>';
    const nm=chip.querySelector('.aname');
    chip.addEventListener('click',e=>{ if(e.target.closest('.arm')||e.target===nm) return; acctState.pinned[a.id]=!acctState.pinned[a.id]; persistAccounts(); renderAccounts(); });
    nm.addEventListener('dblclick',e=>{ e.stopPropagation(); nm.contentEditable='true'; nm.focus(); });
    nm.addEventListener('click',e=>{ if(nm.isContentEditable) e.stopPropagation(); });
    nm.addEventListener('blur',()=>{ nm.contentEditable='false'; a.name=nm.textContent.trim()||a.name; nm.textContent=a.name; saveNow('accounts',accounts); renderAccounts(); });
    nm.addEventListener('keydown',e=>{ if(e.key==='Enter'){ e.preventDefault(); nm.blur(); }});
    chip.querySelector('.arm').addEventListener('click',e=>{ e.stopPropagation(); accounts=accounts.filter(x=>x.id!==a.id); delete acctState.pinned[a.id]; delete acctState.notes[a.id]; saveNow('accounts',accounts); persistAccounts(); renderAccounts(); });
    chips.appendChild(chip);
  });
  const add=document.createElement('div'); add.className='acct-add';
  add.innerHTML='<input type="text" placeholder="+ 고객사" list="customer-list">';
  const inp=add.querySelector('input');
  const addFn=()=>{ const v=inp.value.trim(); if(!v) return; accounts.push({id:'a'+Date.now(),name:v}); inp.value=''; saveNow('accounts',accounts); renderAccounts(); };
  inp.addEventListener('keydown',e=>{ if(e.key==='Enter') addFn(); });
  inp.addEventListener('blur',addFn);
  chips.appendChild(add);
  const notes=document.getElementById('acct-notes'); notes.innerHTML='';
  const pinned=accounts.filter(a=>acctState.pinned[a.id]);
  const ac=document.getElementById('accounts-count'); if(ac) ac.textContent='주목 '+pinned.length;
  if(!pinned.length){ notes.innerHTML='<div class="acct-empty">칩을 클릭해 ‘오늘 주목’으로 지정하면 메모 칸이 생깁니다.</div>'; return; }
  pinned.forEach(a=>{
    const row=document.createElement('div'); row.className='acct-note-row';
    row.innerHTML='<span class="an-name">'+escapeHtml(a.name)+'</span><input type="text" placeholder="메모…">';
    const ni=row.querySelector('input'); ni.value=acctState.notes[a.id]||'';
    let dt; ni.addEventListener('input',()=>{ acctState.notes[a.id]=ni.value; clearTimeout(dt); dt=setTimeout(persistAccounts,400); });
    notes.appendChild(row);
  });
}

/* ---------- TOOLS ---------- */
const TOOLS=[
  {name:'벤더 케이스 초안',desc:'Broadcom 영문 케이스',prompt:
`Broadcom 지원 케이스 영문 초안을 작성해줘. 아래 정보를 기준으로 (제품/버전, 증상, 재현 절차, 로그, 시도한 조치 구조로):
- 제품:
- 버전:
- 증상:
- 재현 절차:
- 관련 로그:
- 시도한 조치:`},
  {name:'로그 분석',desc:'핵심 문구부터',prompt:
`아래 로그를 분석해줘. 핵심 문구/필드/이벤트를 먼저 제시하고, [확인된 사실 → 원인 → 영향 범위 → 조치안 → 검증 방법] 순으로 정리해줘:
\`\`\`
(로그 붙여넣기)
\`\`\``},
  {name:'취약점 영향도',desc:'CVE → 우리 환경',prompt:
`다음 CVE의 우리 환경 영향도를 확인해줘 (영향 제품/버전, 노출 조건, 실무 조치, 검증 방법). 최신 정보는 웹 검색으로 확인하고 출처 표기:
- CVE:
- 대상 제품/버전:`},
  {name:'지원내역 보고서',desc:'내부 공유용 양식',prompt:
`오늘 지원내역을 내부 공유용 보고서로 작성해줘 (제목/요약/처리내역/결과/후속조치 구조). 내용:
- 고객사:
- 이슈:
- 처리 내용:`},
  {name:'내부 공유용 문서',desc:'제목/요약/비교표…',prompt:
`다음 주제로 내부 공유용 문서를 만들어줘 (제목 / 요약 / 비교표 / 기술 설명 / 개선 권고 / 공유용 정리 구조):
- 주제:`},
  {name:'DB 쿼리 지원',desc:'Oracle / MS-SQL',prompt:
`다음 작업을 위한 쿼리를 작성해줘 (대상 DB, 테이블, 목적 명시). 변경 쿼리면 영향 범위와 롤백 방법도 포함:
- DB(Oracle/MS-SQL):
- 목적:
- 대상 테이블:`},
];
function renderTools(){
  const root=document.getElementById('tools'); root.innerHTML='';
  TOOLS.forEach(tool=>{
    const b=document.createElement('button'); b.className='tool';
    b.innerHTML='<span class="t-name">'+tool.name+'</span><span class="t-desc">'+tool.desc+'</span>';
    b.addEventListener('click',()=>{
      if(typeof window.sendPrompt==='function'){ try{ window.sendPrompt(tool.prompt); toast("'"+tool.name+"' 채팅에 전송됨"); return; }catch(e){} }
      tryCopy(tool.prompt).then(ok=>{ if(ok) toast("'"+tool.name+"' 복사됨 — 채팅에 붙여넣기"); else openCopyModal(tool.prompt, tool.name); });
    });
    root.appendChild(b);
  });
}
async function tryCopy(text){
  try{ if(navigator.clipboard && navigator.clipboard.writeText){ await navigator.clipboard.writeText(text); return true; } }catch(e){}
  try{ const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.top='-1000px'; ta.setAttribute('readonly',''); document.body.appendChild(ta); ta.focus(); ta.select(); const ok=document.execCommand('copy'); document.body.removeChild(ta); return ok; }catch(e){ return false; }
}
function openCopyModal(text,name){ document.getElementById('modal-title').textContent=name; const ta=document.getElementById('modal-text'); ta.value=text; document.getElementById('modal-bg').classList.add('show'); setTimeout(()=>{ ta.focus(); ta.select(); },60); }

/* ---------- helpers ---------- */
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
let toastTimer;
function toast(msg){ const t=document.getElementById('md-toast'); t.textContent=msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer=setTimeout(()=>t.classList.remove('show'),1900); }

/* ---------- LAYOUT (drag reorder, 3 columns) ---------- */
const COLS=['col-1','col-2','col-3'];
const DEFAULT_LAYOUT={'col-1':['weekly','todos','notes','shortcuts'],'col-2':['routine','tools','cases'],'col-3':['team','accounts']};
function saveLayout(){ const lay={}; COLS.forEach(id=>{ lay[id]=[...document.getElementById(id).children].map(c=>c.dataset.card).filter(Boolean); }); save('layout3',lay); }
async function applyLayout(){
  let lay=await load('layout3',null); if(!lay) lay=DEFAULT_LAYOUT;
  const seen=new Set();
  COLS.forEach(id=>{ const ids=lay[id]; if(!ids) return; const col=document.getElementById(id); if(!col) return; ids.forEach(cid=>{ const p=document.querySelector('#page-mydesk .panel[data-card="'+cid+'"]'); if(p){ col.appendChild(p); seen.add(cid); } }); });
  document.querySelectorAll('#page-mydesk .panel[data-card]').forEach(p=>{ if(!seen.has(p.dataset.card)) document.getElementById('col-1').appendChild(p); });
}
function initSortable(){
  if(!window.Sortable) return;
  COLS.forEach(id=>{
    new Sortable(document.getElementById(id),{group:'cards',handle:'.grip',animation:160,ghostClass:'sortable-ghost',chosenClass:'sortable-chosen',dragClass:'sortable-drag',onEnd:saveLayout});
  });
}
/* ---------- 열 수 조절 (취향에 맞게 1/2/3열) ---------- */
function setMyDeskCols(n, redistribute){
  n=Math.max(1,Math.min(3,parseInt(n)||3));
  const grid=document.querySelector('#page-mydesk .grid'); if(!grid)return;
  if(redistribute){
    // 모든 카드를 순서대로 모아 선택한 열 수로 라운드로빈 재배치
    const cards=[];
    COLS.forEach(id=>{const c=document.getElementById(id);if(c)[...c.children].forEach(ch=>{if(ch.dataset&&ch.dataset.card)cards.push(ch);});});
    cards.forEach((card,i)=>{const t=document.getElementById(COLS[i%n]);if(t)t.appendChild(card);});
  }else{
    // 로드 시: 숨겨질 열에 남은 카드를 보이는 열로 회수
    for(let idx=n;idx<COLS.length;idx++){const c=document.getElementById(COLS[idx]);if(!c)continue;[...c.children].forEach((ch,j)=>{if(ch.dataset&&ch.dataset.card){const t=document.getElementById(COLS[j%n]);if(t)t.appendChild(ch);}});}
  }
  COLS.forEach((id,idx)=>{const c=document.getElementById(id);if(c)c.style.display=idx<n?'':'none';});
  grid.classList.remove('cols-1','cols-2','cols-3'); grid.classList.add('cols-'+n);
  document.querySelectorAll('#md-cols-ctrl button').forEach(b=>b.classList.toggle('active',(+b.dataset.cols)===n));
  saveNow('mdCols',n);
  if(redistribute) saveLayout();
}
try{ window.setMyDeskCols=setMyDeskCols; }catch(_){}

/* ---------- CARD DOCK (표시/숨김) ---------- */
const CARD_META=[
  {id:'routine',name:'루틴',color:'var(--gold)'},
  {id:'team',name:'팀 일보고',color:'var(--teal)'},
  {id:'weekly',name:'주간 미팅',color:'var(--blue)'},
  {id:'todos',name:'할 일',color:'var(--teal)'},
  {id:'tools',name:'빠른 도구',color:'var(--amber)'},
  {id:'notes',name:'메모',color:'var(--red)'},
  {id:'shortcuts',name:'바로가기·원격',color:'var(--blue)'},
  {id:'cases',name:'벤더 케이스 메모',color:'var(--amber)'},
  {id:'accounts',name:'고객사',color:'var(--green)'},
];
let hiddenCards=new Set();
function renderDock(){
  const root=document.getElementById('dock'); if(!root) return;
  root.innerHTML='<span class="dock-label">카드</span>';
  CARD_META.forEach(c=>{
    if(c.id==='team' && !window.__HUB_IS_ADMIN) return; // 팀 일보고는 관리자만
    const on=!hiddenCards.has(c.id);
    const b=document.createElement('button'); b.className='dock-chip '+(on?'on':'off'); b.dataset.card=c.id;
    b.innerHTML='<span class="dock-dot" style="background:'+c.color+'"></span>'+c.name;
    b.addEventListener('click',()=>{ if(hiddenCards.has(c.id)) hiddenCards.delete(c.id); else hiddenCards.add(c.id); applyHidden(); saveNow('hidden',[...hiddenCards]); renderDock(); });
    root.appendChild(b);
  });
}
function applyHidden(){ document.querySelectorAll('#page-mydesk .panel[data-card]').forEach(p=>{
  if(p.dataset.card==='team' && !window.__HUB_IS_ADMIN){ p.style.display='none'; return; }
  p.style.display = hiddenCards.has(p.dataset.card)?'none':'';
}); }

/* ---------- init ---------- */
async function init(){
  injectMyDeskHeader(); tickClock(); setInterval(tickClock,15000); setGreeting();
  await applyLayout();
  try{ setMyDeskCols(await load('mdCols',3), false); }catch(_){}
  hiddenCards=new Set(await load('hidden',[]));
  renderDock(); applyHidden();

  routineItems=await load('routine-items',null);
  if(!routineItems){ routineItems=DEFAULT_ROUTINE.slice(); save('routine-items',routineItems); }
  if(Array.isArray(routineItems)&&routineItems.length===7){
    const seed=['이메일 확인 - CASE / 일반','JIRA 확인','ESXI 상태 확인','CASE 모니터링','고객사 이슈 지원','내일 예정사항 검토','일보고'];
    if(routineItems.every((it,idx)=>it&&it.t===seed[idx])){ routineItems=[]; saveNow('routine-items',routineItems); }
  }
  const rs=await load('routine-state',{date:'',checks:{}});
  routineChecks=(rs.date===todayKey())?(rs.checks||{}):{};
  if(rs.date!==todayKey()) persistRoutineState();
  renderRoutine(); wireRoutineReset();

  teamMembers=await load('team-members',null);
  if(!teamMembers){ teamMembers=DEFAULT_TEAM.slice(); save('team-members',teamMembers); }
  teamData=await load('team-data',{checks:{},prev:'',today:'',history:[]});
  if(!teamData.checks) teamData.checks={};
  if(!Array.isArray(teamData.history)) teamData.history=[];
  renderTeamRow();
  renderHistory();
  document.getElementById('history-toggle').addEventListener('click',()=>document.getElementById('history').classList.toggle('open'));
  document.getElementById('history-copy').addEventListener('click',copyHistory);
  const rp=document.getElementById('report-prev'), rt=document.getElementById('report-today');
  rp.value=teamData.prev||''; rt.value=teamData.today||'';
  let rpt,rtt;
  rp.addEventListener('input',()=>{ teamData.prev=rp.value; clearTimeout(rpt); rpt=setTimeout(saveTeam,500); });
  rt.addEventListener('input',()=>{ teamData.today=rt.value; clearTimeout(rtt); rtt=setTimeout(saveTeam,500); });
  const roll=document.getElementById('rollover'); let armed=false,armTimer;
  const resetRoll=()=>{ armed=false; clearTimeout(armTimer); roll.classList.remove('armed'); roll.textContent='다음 날 (금일 → 전일)'; };
  roll.addEventListener('click',()=>{
    if(!armed){ armed=true; roll.classList.add('armed'); roll.textContent='확인: 다시 클릭 (금일 누적+전일 이동)'; clearTimeout(armTimer); armTimer=setTimeout(resetRoll,3500); return; }
    resetRoll();
    if(teamData.today && teamData.today.trim()){
      teamData.history.push({id:'h'+Date.now(), date:todayKey(), text:teamData.today});
      while(teamData.history.length>7) teamData.history.shift();
    }
    teamData.prev=teamData.today; teamData.today=''; teamData.checks={};
    rp.value=teamData.prev; rt.value='';
    saveTeam(); renderTeamRow(); renderHistory(); toast('금일 → 전일 이동 · 주간 누적에 기록됨');
  });

  const wk=await load('weekly-meeting',{title:'',date:'',time:''});
  document.getElementById('wk-title').value=wk.title||'';
  document.getElementById('wk-date').value=wk.date||'';
  document.getElementById('wk-time').value=wk.time||'';
  refreshWeekly();
  let wkt; const saveWk=()=>{ save('weekly-meeting',{title:document.getElementById('wk-title').value,date:document.getElementById('wk-date').value,time:document.getElementById('wk-time').value}); refreshWeekly(); };
  document.getElementById('wk-title').addEventListener('input',()=>{ clearTimeout(wkt); wkt=setTimeout(saveWk,500); });
  document.getElementById('wk-date').addEventListener('change',saveWk);
  document.getElementById('wk-time').addEventListener('change',saveWk);

  todos=await load('todos',[]); renderTodos();
  document.getElementById('prio-sel').addEventListener('click',e=>{ const btn=e.target.closest('button'); if(!btn) return; prio=btn.dataset.p; [...document.querySelectorAll('#prio-sel button')].forEach(b=>b.classList.toggle('sel', b===btn)); });
  document.getElementById('todo-add').addEventListener('click',addTodo);
  document.getElementById('todo-text').addEventListener('keydown',e=>{ if(e.key==='Enter') addTodo(); });

  renderTools();

  const notes=document.getElementById('notes');
  notes.value=await load('notes','');
  let nt; notes.addEventListener('input',()=>{ clearTimeout(nt); nt=setTimeout(()=>save('notes',notes.value),500); });

  links=await load('links',[]); rdps=await load('rdps',[]); renderLinks(); renderRdps();

  cases=await load('cases',[]); renderCases();
  accounts=await load('accounts',null); if(!accounts){ accounts=DEFAULT_ACCOUNTS.slice(); saveNow('accounts',accounts); }
  acctState=await load('acct-state',{pinned:{},notes:{}}); if(!acctState.pinned) acctState.pinned={}; if(!acctState.notes) acctState.notes={};
  renderAccounts();

  document.querySelectorAll('#page-mydesk .card-save').forEach(b=>b.addEventListener('click',()=>cardSave(b.dataset.card)));

  document.getElementById('modal-copy').addEventListener('click',()=>{ const ta=document.getElementById('modal-text'); ta.focus(); ta.select(); let ok=false; try{ ok=document.execCommand('copy'); }catch(e){} toast(ok?'복사됨':'텍스트를 직접 선택해 복사하세요'); });
  document.getElementById('modal-close').addEventListener('click',()=>document.getElementById('modal-bg').classList.remove('show'));
  document.getElementById('modal-bg').addEventListener('click',e=>{ if(e.target.id==='modal-bg') document.getElementById('modal-bg').classList.remove('show'); });

  initSortable();
}
// 자동 실행하지 않음: 첫 My Desk 진입 시 서버 데이터 로드 후 loadMyDeskForUser()가 1회 호출.
window.__mydeskInit=init;
})();
