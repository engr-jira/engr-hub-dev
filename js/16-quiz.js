/* ── 🧠 주간 퀴즈 (P1) — 응시·즉시 피드백·XP/레벨/뱃지·리더보드 ───────────
   서버: /quiz/current /quiz/submit /quiz/me /quiz/leaderboard (worker.js)
   관리자 문제은행·출제는 16b(관리자 설정 섹션)에서. */
let QUIZ_CUR=null, QUIZ_ANS={};

function quizProdBadge(p){ const c=(typeof LC_MAP!=='undefined'&&LC_MAP[p])||'#9F6BB5'; return p?`<span class="badge" style="background:${c}22;color:${c}">${escapeHtml(p)}</span>`:''; }
function quizDiffStars(d){ return '<span style="color:var(--warn);letter-spacing:1px">'+'★'.repeat(Math.max(1,Math.min(3,d||1)))+'</span>'; }
function quizLadderHtml(levels,curName){
  const ls=Array.isArray(levels)&&levels.length?levels:[{xp:0,name:'🥉 새싹'},{xp:100,name:'🥈 견습'},{xp:300,name:'🥇 숙련'},{xp:700,name:'💎 마스터'},{xp:1500,name:'👑 전설'}];
  return ls.map(l=>{
    const cur=l.name===curName;
    return `<span style="display:inline-flex;flex-direction:column;align-items:center;gap:1px;padding:3px 9px;border-radius:9px;${cur?'background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid var(--accent)':'opacity:.55'}">
      <span style="font-size:12px;font-weight:${cur?'800':'600'};color:${cur?'var(--accent)':'var(--text2)'};white-space:nowrap">${escapeHtml(l.name)}${cur?' ◂':''}</span>
      <span style="font-size:9.5px;color:var(--text3)">${l.xp}+</span>
    </span>`;
  }).join('<span style="color:var(--text3);opacity:.5">›</span>');
}
function quizHeroHtml(d){
  const me=d.me||{}; const lv=me.level||{name:'🥉 새싹',next:null};
  const badges=(me.badges||[]).map(b=>`<span class="badge" style="background:rgba(159,107,181,.14);color:#9F6BB5;font-weight:700">${escapeHtml(b)}</span>`).join(' ');
  return `<div class="chart-card" style="margin-bottom:10px;padding:12px 16px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <span style="font-size:13.5px;font-weight:800;color:var(--text-strong)">${escapeHtml(d.intro||'🧠 이번 주 보안 퀴즈')}</span>
      ${d.prize?`<span class="badge" style="background:rgba(224,163,46,.14);color:#B27E00;font-weight:800">🎁 ${escapeHtml(d.prize)}</span>`:''}
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:9px">
      <span style="display:inline-flex;gap:4px;align-items:center;flex-wrap:wrap">${quizLadderHtml(d.levels,lv.name)}</span>
      <span style="font-size:12px;color:var(--text2)">내 XP <b style="color:var(--accent)">${me.xp||0}</b>${lv.next?` · ${escapeHtml(lv.next.name)}까지 <b>${lv.next.need}</b>`:''}</span>
      ${me.streak>=2?`<span class="badge" style="background:rgba(224,106,99,.14);color:#E06A63;font-weight:800">🔥 ${me.streak}주</span>`:''}
      ${badges}
    </div>
  </div>`;
}
async function loadQuizPage(){
  const hero=document.getElementById('quiz-hero'), body=document.getElementById('quiz-body');
  if(!hero||!body)return;
  hero.innerHTML='<div class="muted u-p-20px">불러오는 중...</div>'; body.innerHTML='';
  try{
    const d=await hubApi('/quiz/current');
    QUIZ_CUR=d; QUIZ_ANS={};
    hero.innerHTML=quizHeroHtml(d);
    if(!d.week){ body.innerHTML='<div class="chart-card"><div style="font-size:13px;color:var(--text2);padding:8px 2px">🕐 이번 주 퀴즈가 아직 오픈 전입니다. 출제되면 여기와 Teams에 공지돼요!</div></div>'; }
    else if(d.submitted){ renderQuizSubmitted(d); }
    else renderQuizForm(d);
  }catch(e){ hero.innerHTML=`<div class="chart-card"><div class="u-cdanger-p20px">퀴즈 조회 실패: ${escapeHtml(e.message)}</div></div>`; }
  loadQuizBoard('week');
}
function quizDdayTxt(closes){ const left=closes-Date.now(); if(left<=0)return '마감'; const d=Math.floor(left/86400000),h=Math.floor(left%86400000/3600000); return d>0?`마감까지 ${d}일 ${h}시간`:`마감까지 ${h}시간`; }
function renderQuizForm(d){
  const body=document.getElementById('quiz-body'); if(!body)return;
  const qs=d.questions||[];
  const cards=qs.map((q,i)=>{
    let input='';
    let choices=[]; try{choices=JSON.parse(q.choices||'[]');}catch(_){}
    if(q.type==='mc'&&choices.length){
      input=choices.map((c,ci)=>`<button type="button" class="quiz-opt" data-q="${q.id}" data-v="${escapeAttr(c)}" onclick="quizPick(${q.id},this)" style="display:block;width:100%;text-align:left;margin-top:6px;padding:9px 13px;border-radius:10px;border:1.5px solid var(--border);background:var(--card2);color:var(--text);font-family:inherit;font-size:12.5px;cursor:pointer">${String.fromCharCode(65+ci)}. ${escapeHtml(c)}</button>`).join('');
    }else if(q.type==='ox'){
      input=`<div style="display:flex;gap:8px;margin-top:6px">
        <button type="button" class="quiz-opt" data-q="${q.id}" data-v="O" onclick="quizPick(${q.id},this)" style="flex:1;padding:12px;border-radius:10px;border:1.5px solid var(--border);background:var(--card2);color:var(--success);font-size:17px;font-weight:800;cursor:pointer;font-family:inherit">⭕ O</button>
        <button type="button" class="quiz-opt" data-q="${q.id}" data-v="X" onclick="quizPick(${q.id},this)" style="flex:1;padding:12px;border-radius:10px;border:1.5px solid var(--border);background:var(--card2);color:var(--danger);font-size:17px;font-weight:800;cursor:pointer;font-family:inherit">❌ X</button>
      </div>`;
    }else{
      input=`<input type="text" data-qshort="${q.id}" oninput="quizShort(${q.id},this.value)" placeholder="답을 입력하세요 (단답형 — 부분점수 있음)" style="width:100%;box-sizing:border-box;margin-top:6px;background:var(--card2);border:1.5px solid var(--border);border-radius:10px;color:var(--text);padding:10px 13px;font-size:12.5px;font-family:inherit">`;
    }
    return `<div class="chart-card" style="margin-bottom:10px" id="quiz-q-${q.id}">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="font-size:11px;font-weight:800;color:var(--text3)">Q${i+1} / ${qs.length}</span>
        <span style="display:flex;gap:6px;align-items:center">${quizProdBadge(q.product)}${quizDiffStars(q.difficulty)}</span>
      </div>
      <div style="font-size:13.5px;font-weight:700;color:var(--text-strong);margin:8px 0 2px;line-height:1.6;white-space:pre-wrap">${escapeHtml(q.question)}</div>
      ${input}
    </div>`;
  }).join('');
  body.innerHTML=`
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
      <div id="quiz-progress" style="font-size:12px;font-weight:700;color:var(--text2)">0 / ${qs.length} 답변</div>
      <span class="badge" style="background:rgba(224,163,46,.12);color:#B27E00;font-weight:700">⏰ ${quizDdayTxt(d.closes_at)}</span>
    </div>
    ${cards}
    <div style="display:flex;gap:8px;align-items:center;margin-top:14px">
      <button class="btn btn-primary" style="width:auto;padding:10px 22px;font-weight:800" onclick="submitQuiz()">🚀 제출하고 바로 채점받기</button>
      <span class="u-muted-11">제출 즉시 점수·해설·XP가 공개됩니다</span>
    </div>`;
}
function quizPick(qid,btn){
  QUIZ_ANS[qid]=btn.dataset.v;
  document.querySelectorAll(`.quiz-opt[data-q="${qid}"]`).forEach(b=>{b.style.borderColor='var(--border)';b.style.background='var(--card2)';b.style.boxShadow='none';});
  btn.style.borderColor='var(--accent)'; btn.style.background='color-mix(in srgb,var(--accent) 10%,var(--card2))'; btn.style.boxShadow='0 0 0 1px var(--accent) inset';
  quizProgress();
}
function quizShort(qid,v){ if(String(v||'').trim())QUIZ_ANS[qid]=v; else delete QUIZ_ANS[qid]; quizProgress(); }
function quizProgress(){
  const total=(QUIZ_CUR&&QUIZ_CUR.questions||[]).length;
  const done=Object.keys(QUIZ_ANS).length;
  const el=document.getElementById('quiz-progress'); if(el)el.textContent=`${done} / ${total} 답변`;
}
async function submitQuiz(){
  const total=(QUIZ_CUR&&QUIZ_CUR.questions||[]).length;
  const done=Object.keys(QUIZ_ANS).length;
  if(!QUIZ_CUR||!QUIZ_CUR.week)return;
  if(done<total && !confirm(`아직 ${total-done}문제가 비어 있어요. 빈 문제는 0점 처리됩니다.\n그래도 제출할까요?`))return;
  if(done>=total && !confirm('제출하면 바로 채점됩니다. 준비되셨나요? 🎯'))return;
  try{
    const r=await hubApi('/quiz/submit',{method:'POST',body:JSON.stringify({week:QUIZ_CUR.week,answers:QUIZ_ANS})});
    renderQuizResult(r);
    loadQuizBoard('week');
    if(typeof toast==='function')toast('채점 완료!');
  }catch(e){ if(typeof toast==='function')toast('제출 실패: '+e.message,true); }
}
function quizScoreColor(s){ return s>=100?'var(--success)':s>0?'var(--warn)':'var(--danger)'; }
function quizSourceHtml(src){
  if(!src)return '';
  const m=String(src).match(/^([A-Z][A-Z0-9]*-\d+)$/);
  if(m)return ` · <a style="color:var(--cyan);cursor:pointer;font-weight:700" onclick="hubJumpKey('${m[1]}')">${m[1]}</a>`;
  if(/^https?:\/\//.test(src))return ` · <a href="${escapeAttr(src)}" target="_blank" rel="noopener" style="color:var(--cyan);font-weight:700">출처 보기</a>`;
  return ` · <span class="u-muted-11">${escapeHtml(src)}</span>`;
}
function renderQuizResult(r){
  const body=document.getElementById('quiz-body'), hero=document.getElementById('quiz-hero'); if(!body)return;
  const qs=(QUIZ_CUR&&QUIZ_CUR.questions||[]);
  const qmap={}; qs.forEach(q=>qmap[q.id]=q);
  const lv=r.level||{};
  const rows=(r.results||[]).map((res,i)=>{
    const q=qmap[res.id]||{};
    const my=QUIZ_ANS[res.id]!==undefined?QUIZ_ANS[res.id]:'(무응답)';
    return `<div class="chart-card" style="margin-bottom:8px;border-left:3px solid ${quizScoreColor(res.score)}">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
        <span style="font-size:11px;font-weight:800;color:var(--text3)">Q${i+1}</span>
        <span style="display:flex;gap:8px;align-items:center">
          ${res.note?`<span class="u-muted-10">${escapeHtml(res.note)}</span>`:''}
          <b style="color:${quizScoreColor(res.score)}">${res.score}점</b>
          <span class="badge" style="background:rgba(217,96,59,.12);color:var(--accent);font-weight:800">+${res.xp} XP</span>
        </span>
      </div>
      <div style="font-size:12.5px;color:var(--text2);margin:6px 0 2px;white-space:pre-wrap">${escapeHtml(q.question||'')}</div>
      <div style="font-size:12px;margin-top:6px"><span style="color:var(--text3)">내 답</span> <b style="color:${quizScoreColor(res.score)}">${escapeHtml(String(my))}</b> · <span style="color:var(--text3)">정답</span> <b style="color:var(--success)">${escapeHtml(res.answer||'')}</b></div>
      ${res.explanation?`<div style="font-size:12px;color:var(--text2);background:rgba(255,255,255,.04);border-radius:8px;padding:8px 11px;margin-top:7px;line-height:1.6">💡 ${escapeHtml(res.explanation)}${quizSourceHtml(res.source)}${res.credit?` <span class="u-muted-10">— 제보: ${escapeHtml(res.credit)} 🙌</span>`:''}</div>`:quizSourceHtml(res.source)?`<div style="font-size:12px;margin-top:6px">${quizSourceHtml(res.source)}</div>`:''}
    </div>`;
  }).join('');
  const badges=(r.badges||[]).map(b=>`<span class="badge" style="background:rgba(159,107,181,.14);color:#9F6BB5;font-weight:800">${escapeHtml(b)}</span>`).join(' ');
  body.innerHTML=`
    <div class="chart-card" style="margin-bottom:10px;text-align:center;padding:14px">
      <div style="font-size:30px;font-weight:900;color:${quizScoreColor(r.avg)}">${r.avg}점 <span style="font-size:13px;font-weight:800;color:var(--text-strong)">${escapeHtml(r.msg||'')}</span></div>
      ${r.comboMsg?`<div style="font-size:13px;font-weight:800;color:#E06A63;margin-top:4px">${escapeHtml(r.comboMsg)}</div>`:''}
      <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:12px;font-size:12.5px;color:var(--text2)">
        <span class="badge" style="background:rgba(217,96,59,.12);color:var(--accent);font-weight:800;font-size:13px">⚡ +${r.xpGained} XP</span>
        <span><b style="color:var(--text-strong)">${escapeHtml(lv.name||'')}</b> · 총 ${r.totalXp} XP${lv.next?` · ${escapeHtml(lv.next.name)}까지 ${lv.next.need} XP`:''}</span>
        ${r.streak>=2?`<span class="badge" style="background:rgba(224,106,99,.14);color:#E06A63;font-weight:800">🔥 ${r.streak}주 연속</span>`:''}
      </div>
      ${badges?`<div style="margin-top:8px">${badges}</div>`:''}
    </div>
    ${rows}
    <div style="margin-top:10px"><button class="btn btn-ghost u-btn-xs" onclick="loadQuizPage()">↻ 새로고침</button></div>`;
  if(hero&&QUIZ_CUR){ QUIZ_CUR.me={xp:r.totalXp,level:r.level,badges:r.badges,streak:r.streak}; hero.innerHTML=quizHeroHtml(QUIZ_CUR); }
}
function renderQuizSubmitted(d){
  const body=document.getElementById('quiz-body'); if(!body)return;
  const n=(d.myAnswers||[]).length;
  const avg=n?Math.round((d.myAnswers||[]).reduce((s,a)=>s+(a.score||0),0)/n):0;
  body.innerHTML=`<div class="chart-card" style="text-align:center;padding:22px">
    <div style="font-size:15px;font-weight:800;color:var(--text-strong)">✅ 이번 주 퀴즈 제출 완료</div>
    <div style="font-size:30px;font-weight:900;color:${quizScoreColor(avg)};margin-top:8px">${avg}점</div>
    <div class="u-muted-11" style="margin-top:6px">답변 ${n}건 · 마감(${new Date(d.closes_at).toLocaleDateString('ko-KR')}) 후 전체 해설이 공개됩니다</div>
    <div style="display:flex;gap:8px;justify-content:center;margin-top:14px">
      <button class="btn btn-ghost u-btn-xs" onclick="quizRetake()">✏️ 다시 풀기 (점수 갱신)</button>
    </div>
  </div>`;
}
function quizRetake(){ if(!QUIZ_CUR)return; if(!confirm('다시 제출하면 이전 점수를 덮어씁니다. 계속할까요?'))return; QUIZ_ANS={}; renderQuizForm(QUIZ_CUR); }
async function loadQuizBoard(scope){
  const board=document.getElementById('quiz-board'); if(!board)return;
  try{
    const d=await hubApi('/quiz/leaderboard?scope='+(scope||'week'));
    const meU=(typeof CURRENT_USER!=='undefined'&&CURRENT_USER)||'';
    const nameOf=u=>{ try{ const v=window.__userMap&&window.__userMap[u]; if(typeof v==='string')return v; if(v&&typeof v==='object')return String(v.name||v.display||v.displayName||u); }catch(_){} return String(u==null?'':u); };
    const chip=(r,i,val)=>`<span style="white-space:nowrap;${r.user===meU?'font-weight:800;color:var(--accent)':''}">${['🥇','🥈','🥉'][i]||(i+1)+'.'} ${escapeHtml(nameOf(r.user))} ${val}</span>`;
    const line=(label,inner)=>`<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:4px 0;font-size:12px;color:var(--text2)"><span style="font-weight:800;color:var(--text3);width:58px;flex-shrink:0">${label}</span>${inner}</div>`;
    let rankLine;
    if(d.scope==='month'){
      const rows=(d.rows||[]).sort((a,b)=>b.acc-a.acc).slice(0,5);
      rankLine=line('📅 월간',(rows.map((r,i)=>chip(r,i,`${Math.round(r.acc)}점·${r.weeks}주`)).join('<span style="color:var(--border2)">|</span>')||'<span class="u-muted-11">기록 없음</span>')+` <button class="btn btn-ghost u-btn-xxs" onclick="loadQuizBoard('week')">주간</button>`);
    }else{
      const rows=(d.rows||[]).sort((a,b)=>b.acc-a.acc).slice(0,5);
      rankLine=line('🎯 주간',(rows.map((r,i)=>chip(r,i,`${Math.round(r.acc)}점`)).join('<span style="color:var(--border2)">|</span>')||'<span class="u-muted-11">아직 아무도 도전 안 함 — 1등 찬스! 🏁</span>')+` <button class="btn btn-ghost u-btn-xxs" onclick="loadQuizBoard('month')">월간</button>`);
    }
    const xpTop=(d.xpRows||[]).slice(0,5);
    const xpLine=line('⚡ XP',xpTop.map((r,i)=>chip(r,i,`${escapeHtml(String(r.level||''))} ${r.xp}`)).join('<span style="color:var(--border2)">|</span>')||'<span class="u-muted-11">아직 XP 없음</span>');
    let goalLine='';
    if(d.teamGoal){
      const pct=Math.min(100,Math.round(d.teamGoal.current/d.teamGoal.goal*100));
      goalLine=line('🤝 목표',`<span style="flex:1;min-width:120px;max-width:260px;background:var(--card2);border-radius:20px;height:12px;overflow:hidden;border:1px solid var(--border);display:inline-block"><span style="display:block;width:${pct}%;height:100%;background:linear-gradient(90deg,var(--accent),#E0A32E)"></span></span><span>${d.teamGoal.current}/${d.teamGoal.goal}점${d.teamGoal.prize?` → 🎁 ${escapeHtml(d.teamGoal.prize)}`:''}</span>`);
    }
    board.innerHTML=`<div class="chart-card" style="margin-bottom:12px;padding:8px 16px">${rankLine}${xpLine}${goalLine}</div>`;
  }catch(e){ board.innerHTML=`<div class="u-muted-11">리더보드 조회 실패: ${escapeHtml(e.message)}</div>`; }
}
/* ── 🛠 관리자: 문제은행·주간 출제·설정 (퀴즈 페이지 내, IS_ADMIN 게이트) ── */
let QUIZ_BANK=[], QUIZ_PICKED=[];
const QUIZ_PRODUCTS=['DLP','SEP','S1','PP','공통'];
const QUIZ_TYPE_LABEL={mc:'객관식',ox:'OX',short:'단답형'};
function quizAdminShell(){
  return `<div class="chart-grid" style="grid-template-columns:1fr;gap:12px">
    <div class="chart-card"><h4>📢 이번 주 출제</h4><div id="quiz-week-box"></div></div>
    <div class="chart-card"><h4>🗂 문제은행 <span class="u-muted-11" id="quiz-bank-count"></span></h4>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 10px">
        <select id="qa-f-status" onchange="loadQuizBank()" class="admin-input" style="width:auto"><option value="">전체 상태</option><option value="approved">승인</option><option value="draft">초안</option><option value="archived">보관</option></select>
        <select id="qa-f-prod" onchange="loadQuizBank()" class="admin-input" style="width:auto"><option value="">전체 제품</option>${QUIZ_PRODUCTS.map(p=>`<option>${p}</option>`).join('')}</select>
        <button class="btn btn-primary u-btn-xs" onclick="quizEditQ(null)">➕ 새 문제</button>
      </div>
      <div id="quiz-bank"></div>
    </div>
    <div class="chart-card"><h4>⚙️ 퀴즈 설정 (문구·상품·팀 목표)</h4><div id="quiz-settings-box"></div></div>
  </div>
  <div id="quiz-q-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:99999;align-items:flex-start;justify-content:center;padding:4vh 16px;overflow:auto"></div>`;
}
async function loadQuizAdmin(){
  const el=document.getElementById('quiz-admin'); if(!el)return;
  if(!el.dataset.init){ el.innerHTML=quizAdminShell(); el.dataset.init='1'; }
  loadQuizBank(); renderQuizWeekBox(); loadQuizSettingsBox();
}
async function loadQuizBank(){
  const box=document.getElementById('quiz-bank'); if(!box)return;
  box.innerHTML='<div class="muted">불러오는 중...</div>';
  const st=(document.getElementById('qa-f-status')||{}).value||'', pr=(document.getElementById('qa-f-prod')||{}).value||'';
  try{
    const d=await hubApi('/quiz/questions?status='+encodeURIComponent(st)+'&product='+encodeURIComponent(pr));
    QUIZ_BANK=d.items||[];
    const cc=document.getElementById('quiz-bank-count'); if(cc)cc.textContent=`(${QUIZ_BANK.length}건 · 승인 ${QUIZ_BANK.filter(q=>q.status==='approved').length})`;
    if(!QUIZ_BANK.length){ box.innerHTML='<div class="empty">문제가 없습니다 — ➕ 새 문제로 시작하세요</div>'; return; }
    const stBadge=s=>s==='approved'?'<span class="badge" style="background:rgba(30,158,106,.14);color:var(--success)">승인</span>':s==='archived'?'<span class="badge" style="background:rgba(255,255,255,.08);color:var(--text3)">보관</span>':'<span class="badge" style="background:rgba(224,163,46,.14);color:#B27E00">초안</span>';
    box.innerHTML=QUIZ_BANK.map(q=>`<div style="display:flex;gap:8px;align-items:center;padding:8px 6px;border-bottom:1px solid var(--border);font-size:12px">
      <span class="u-muted-10" style="width:34px">#${q.id}</span>
      ${q.created_by==='engine'?'<span class="badge" style="background:rgba(63,163,196,.14);color:#3F8FC4;font-weight:800" title="분석 엔진이 자동 생성한 초안">🤖</span>':''}
      ${quizProdBadge(q.product)}<span style="width:44px;color:var(--text3)">${QUIZ_TYPE_LABEL[q.type]||q.type}</span>${quizDiffStars(q.difficulty)}
      <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text2)">${escapeHtml(q.question||'')}</span>
      ${stBadge(q.status)}
      <button class="btn btn-ghost u-btn-xxs" title="팀원에게 보이는 모습 미리보기" onclick="quizPreviewQ(${q.id})">👁</button>
      <button class="btn btn-ghost u-btn-xxs" onclick="quizEditQ(${q.id})">✏️</button>
      ${q.status!=='approved'?`<button class="btn btn-ghost u-btn-xxs" style="color:var(--success)" onclick="quizSetStatus(${q.id},'approved')">✔ 승인</button>`:`<button class="btn btn-ghost u-btn-xxs" onclick="quizSetStatus(${q.id},'archived')">보관</button>`}
      <button class="btn btn-ghost u-btn-xxs" style="color:var(--danger)" onclick="quizDelQ(${q.id})">✕</button>
    </div>`).join('');
  }catch(e){ box.innerHTML=`<div class="u-cdanger-p20px">${escapeHtml(e.message)}</div>`; }
}
function quizEditQ(id){
  const q=id?QUIZ_BANK.find(x=>x.id===id):null;
  let choices=[]; try{choices=JSON.parse((q&&q.choices)||'[]');}catch(_){}
  let accepts=[]; try{accepts=JSON.parse((q&&q.accepts)||'[]');}catch(_){}
  let keywords=[]; try{keywords=JSON.parse((q&&q.keywords)||'[]');}catch(_){}
  const m=document.getElementById('quiz-q-modal'); if(!m)return;
  m.style.display='flex';
  m.innerHTML=`<div style="background:var(--card);border:1px solid var(--border2);border-radius:16px;padding:20px;width:min(640px,96vw)">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><h3 style="margin:0;font-size:15px">${q?'✏️ 문제 수정 #'+q.id:'➕ 새 문제'}</h3><button class="btn btn-ghost u-btn-xs" onclick="document.getElementById('quiz-q-modal').style.display='none'">닫기</button></div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
      <select id="qe-product" class="admin-input" style="width:auto">${QUIZ_PRODUCTS.map(p=>`<option ${q&&q.product===p?'selected':''}>${p}</option>`).join('')}</select>
      <select id="qe-type" class="admin-input" style="width:auto" onchange="quizEditTypeSync()"><option value="mc" ${q&&q.type==='mc'?'selected':''}>객관식</option><option value="ox" ${q&&q.type==='ox'?'selected':''}>OX</option><option value="short" ${q&&q.type==='short'?'selected':''}>단답형</option></select>
      <select id="qe-diff" class="admin-input" style="width:auto"><option value="1" ${q&&q.difficulty===1?'selected':''}>★ 쉬움(10XP)</option><option value="2" ${q&&q.difficulty===2?'selected':''}>★★ 보통(20XP)</option><option value="3" ${q&&q.difficulty===3?'selected':''}>★★★ 어려움(30XP)</option></select>
      <select id="qe-status" class="admin-input" style="width:auto"><option value="draft" ${!q||q.status==='draft'?'selected':''}>초안</option><option value="approved" ${q&&q.status==='approved'?'selected':''}>승인</option><option value="archived" ${q&&q.status==='archived'?'selected':''}>보관</option></select>
    </div>
    <textarea id="qe-question" class="admin-textarea" style="min-height:70px" placeholder="문제 내용">${escapeHtml((q&&q.question)||'')}</textarea>
    <div id="qe-mc-wrap" style="display:${(!q||q.type==='mc')?'':'none'}"><div class="u-muted-10" style="margin:8px 0 3px">보기 (줄바꿈으로 구분, 2~8개)</div><textarea id="qe-choices" class="admin-textarea" style="min-height:80px" placeholder="보기1&#10;보기2&#10;보기3">${escapeHtml(choices.join('\n'))}</textarea></div>
    <div class="u-muted-10" style="margin:8px 0 3px">정답 <span style="color:var(--text3)">(OX는 O 또는 X · 객관식은 보기 원문)</span></div>
    <input id="qe-answer" class="admin-input" value="${escapeHtml((q&&q.answer)||'')}" placeholder="정답">
    <div id="qe-short-wrap" style="display:${q&&q.type==='short'?'':'none'}">
      <div class="u-muted-10" style="margin:8px 0 3px">추가 인정 답안 (콤마 구분 — 완전 일치 100점)</div>
      <input id="qe-accepts" class="admin-input" value="${escapeHtml(accepts.join(', '))}" placeholder="예: Endpoint Prevent, EP서버">
      <div class="u-muted-10" style="margin:8px 0 3px">부분점수 키워드 (콤마 구분 — 포함 개수 비례 점수)</div>
      <input id="qe-keywords" class="admin-input" value="${escapeHtml(keywords.join(', '))}" placeholder="예: 인덱스, 재시작">
    </div>
    <div class="u-muted-10" style="margin:8px 0 3px">해설 (마감 후·채점 직후 공개)</div>
    <textarea id="qe-explanation" class="admin-textarea" style="min-height:60px">${escapeHtml((q&&q.explanation)||'')}</textarea>
    <div style="display:flex;gap:6px;margin-top:8px">
      <input id="qe-source" class="admin-input" style="flex:1" value="${escapeHtml((q&&q.source)||'')}" placeholder="출처 (ENGR-1234 또는 KB URL)">
      <input id="qe-credit" class="admin-input" style="flex:1" value="${escapeHtml((q&&q.credit)||'')}" placeholder="제보자 (선택)">
    </div>
    <div style="display:flex;gap:8px;margin-top:14px"><button class="btn btn-primary u-btn-xs" onclick="quizSaveQ(${q?q.id:'null'})">💾 저장</button></div>
  </div>`;
}
function quizEditTypeSync(){
  const t=(document.getElementById('qe-type')||{}).value;
  const mc=document.getElementById('qe-mc-wrap'), sh=document.getElementById('qe-short-wrap');
  if(mc)mc.style.display=t==='mc'?'':'none';
  if(sh)sh.style.display=t==='short'?'':'none';
}
async function quizSaveQ(id){
  const v=x=>(document.getElementById(x)||{}).value||'';
  const csv=x=>v(x).split(',').map(s=>s.trim()).filter(Boolean);
  const body={id,product:v('qe-product'),type:v('qe-type'),difficulty:parseInt(v('qe-diff'))||1,question:v('qe-question').trim(),choices:v('qe-choices').split('\n').map(s=>s.trim()).filter(Boolean),answer:v('qe-answer').trim(),accepts:csv('qe-accepts'),keywords:csv('qe-keywords'),explanation:v('qe-explanation').trim(),source:v('qe-source').trim(),credit:v('qe-credit').trim(),status:v('qe-status')};
  if(!body.question||!body.answer){ if(typeof toast==='function')toast('문제와 정답은 필수입니다',true); return; }
  if(body.type==='mc'&&body.choices.length<2){ if(typeof toast==='function')toast('객관식은 보기 2개 이상 필요',true); return; }
  try{
    await hubApi('/quiz/question',{method:id?'PUT':'POST',body:JSON.stringify(body)});
    document.getElementById('quiz-q-modal').style.display='none';
    if(typeof toast==='function')toast('저장됨');
    loadQuizBank();
  }catch(e){ if(typeof toast==='function')toast('저장 실패: '+e.message,true); }
}
async function quizSetStatus(id,status){
  const q=QUIZ_BANK.find(x=>x.id===id); if(!q)return;
  let choices=[],accepts=[],keywords=[]; try{choices=JSON.parse(q.choices||'[]');accepts=JSON.parse(q.accepts||'[]');keywords=JSON.parse(q.keywords||'[]');}catch(_){}
  try{ await hubApi('/quiz/question',{method:'PUT',body:JSON.stringify({...q,choices,accepts,keywords,status})}); loadQuizBank(); }catch(e){ if(typeof toast==='function')toast('실패: '+e.message,true); }
}
async function quizDelQ(id){ if(!confirm('#'+id+' 문제를 삭제할까요?'))return; try{ await hubApi('/quiz/question?id='+id,{method:'DELETE'}); loadQuizBank(); }catch(e){ if(typeof toast==='function')toast('삭제 실패: '+e.message,true); } }
function renderQuizWeekBox(){
  const box=document.getElementById('quiz-week-box'); if(!box)return;
  const picked=QUIZ_PICKED.map((q,i)=>`<div style="display:flex;gap:8px;align-items:center;padding:6px 4px;border-bottom:1px solid var(--border);font-size:12px">
    <span class="u-muted-10">${i+1}.</span>${quizProdBadge(q.product)}${quizDiffStars(q.difficulty)}
    <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text2)">${escapeHtml(q.question||'')}</span>
    <button class="btn btn-ghost u-btn-xxs" title="다른 문제로 교체" onclick="quizSwapPick(${i})">↻</button>
    <button class="btn btn-ghost u-btn-xxs" style="color:var(--danger)" onclick="QUIZ_PICKED.splice(${i},1);renderQuizWeekBox()">✕</button>
  </div>`).join('');
  box.innerHTML=`
    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
      <button class="btn btn-primary u-btn-xs" onclick="quizSuggest()">🎲 승인 문제에서 랜덤 10개 추천</button>
      <span class="u-muted-11">추천 후 ↻교체·✕제거로 다듬고 확정하세요</span>
    </div>
    ${picked||'<div class="empty">아직 추천 전입니다</div>'}
    ${QUIZ_PICKED.length?`<div style="display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap">
      <span class="u-muted-11">마감일</span><input type="date" id="quiz-closes" class="admin-input" style="width:auto" value="${new Date(Date.now()+7*86400000).toISOString().slice(0,10)}">
      <button class="btn u-btn-xs" style="background:var(--accent);color:#FFFDF9;border-color:var(--accent);font-weight:800" onclick="quizPublishWeek()">📢 이번 주 출제 확정 (${QUIZ_PICKED.length}문제)</button>
    </div>`:''}`;
}
async function quizSuggest(){
  try{ const d=await hubApi('/quiz/suggest?n=10'); QUIZ_PICKED=d.items||[]; if(!QUIZ_PICKED.length&&typeof toast==='function')toast('승인된 문제가 없습니다 — 먼저 문제를 승인하세요',true); renderQuizWeekBox(); }
  catch(e){ if(typeof toast==='function')toast('추천 실패: '+e.message,true); }
}
async function quizSwapPick(i){
  try{ const d=await hubApi('/quiz/suggest?n=10'); const cur=new Set(QUIZ_PICKED.map(q=>q.id)); const cand=(d.items||[]).find(q=>!cur.has(q.id)); if(!cand){ if(typeof toast==='function')toast('교체할 다른 승인 문제가 없습니다',true); return; } QUIZ_PICKED[i]=cand; renderQuizWeekBox(); }
  catch(e){ if(typeof toast==='function')toast('교체 실패: '+e.message,true); }
}
async function quizPublishWeek(){
  if(!QUIZ_PICKED.length)return;
  const closes=(document.getElementById('quiz-closes')||{}).value;
  if(!confirm(`${QUIZ_PICKED.length}문제를 이번 주 퀴즈로 출제합니다.\n팀원 전체에게 공개돼요. 확정할까요?`))return;
  try{
    const closesAt=closes?new Date(closes+'T23:59:59+09:00').getTime():Date.now()+7*86400000;
    const r=await hubApi('/quiz/week',{method:'PUT',body:JSON.stringify({question_ids:QUIZ_PICKED.map(q=>q.id),opens_at:Date.now(),closes_at:closesAt})});
    if(typeof toast==='function')toast(`📢 ${r.week} 출제 완료!`);
    QUIZ_PICKED=[]; renderQuizWeekBox(); loadQuizPage();
  }catch(e){ if(typeof toast==='function')toast('출제 실패: '+e.message,true); }
}
async function loadQuizSettingsBox(){
  const box=document.getElementById('quiz-settings-box'); if(!box)return;
  try{
    const d=await hubApi('/quiz/settings'); const s=d.settings||{};
    box.innerHTML=`
      <div class="u-muted-10" style="margin-bottom:3px">인트로 문구</div><input id="qs-intro" class="admin-input" value="${escapeHtml(s.intro||'')}">
      <div class="u-muted-10" style="margin:8px 0 3px">이번 주 상품 안내 (비우면 미표시)</div><input id="qs-prize" class="admin-input" value="${escapeHtml(s.prize||'')}" placeholder="예: 1등 스타벅스 기프티콘 ☕">
      <div style="display:flex;gap:6px;margin-top:8px;align-items:center;flex-wrap:wrap">
        <span class="u-muted-10">팀 공동 목표: 이달 평균</span><input id="qs-goal" class="admin-input" style="width:70px" type="number" min="0" max="100" value="${s.teamGoal||0}"><span class="u-muted-10">점 (0=비활성) · 보상</span>
        <input id="qs-goalprize" class="admin-input" style="flex:1;min-width:140px" value="${escapeHtml(s.teamGoalPrize||'')}" placeholder="예: 전원 치킨 🍗">
      </div>
      <div class="u-muted-10" style="margin:10px 0 3px">게임마스터 멘트 (100/80+/50+/50미만/콤보 — {n}=연속 수)</div>
      <input id="qs-m-perfect" class="admin-input" style="margin-bottom:4px" value="${escapeHtml((s.msgs||{}).perfect||'')}">
      <input id="qs-m-great" class="admin-input" style="margin-bottom:4px" value="${escapeHtml((s.msgs||{}).great||'')}">
      <input id="qs-m-good" class="admin-input" style="margin-bottom:4px" value="${escapeHtml((s.msgs||{}).good||'')}">
      <input id="qs-m-tryagain" class="admin-input" style="margin-bottom:4px" value="${escapeHtml((s.msgs||{}).tryagain||'')}">
      <input id="qs-m-combo" class="admin-input" value="${escapeHtml((s.msgs||{}).combo||'')}">
      <div style="margin-top:10px"><button class="btn btn-primary u-btn-xs" onclick="quizSaveSettings()">💾 설정 저장</button></div>`;
  }catch(e){ box.innerHTML=`<div class="u-cdanger-p20px">${escapeHtml(e.message)}</div>`; }
}
async function quizSaveSettings(){
  const v=x=>(document.getElementById(x)||{}).value||'';
  try{
    await hubApi('/quiz/settings',{method:'POST',body:JSON.stringify({settings:{intro:v('qs-intro'),prize:v('qs-prize'),teamGoal:parseInt(v('qs-goal'))||0,teamGoalPrize:v('qs-goalprize'),msgs:{perfect:v('qs-m-perfect'),great:v('qs-m-great'),good:v('qs-m-good'),tryagain:v('qs-m-tryagain'),combo:v('qs-m-combo')}}})});
    if(typeof toast==='function')toast('설정 저장됨'); loadQuizPage();
  }catch(e){ if(typeof toast==='function')toast('저장 실패: '+e.message,true); }
}
function quizPreviewQ(id){
  const q=QUIZ_BANK.find(x=>x.id===id); if(!q)return;
  let choices=[],accepts=[],keywords=[]; try{choices=JSON.parse(q.choices||'[]');accepts=JSON.parse(q.accepts||'[]');keywords=JSON.parse(q.keywords||'[]');}catch(_){}
  let input='';
  if(q.type==='mc'&&choices.length){ input=choices.map((c,ci)=>`<div style="margin-top:6px;padding:9px 13px;border-radius:10px;border:1.5px solid ${quizNormEq(c,q.answer)?'var(--success)':'var(--border)'};background:var(--card2);color:var(--text);font-size:12.5px">${String.fromCharCode(65+ci)}. ${escapeHtml(c)}${quizNormEq(c,q.answer)?' <b style="color:var(--success)">✔ 정답</b>':''}</div>`).join(''); }
  else if(q.type==='ox'){ input=`<div style="display:flex;gap:8px;margin-top:6px"><div style="flex:1;padding:12px;text-align:center;border-radius:10px;border:1.5px solid ${/^o$/i.test(q.answer)?'var(--success)':'var(--border)'};background:var(--card2);color:var(--success);font-size:17px;font-weight:800">⭕ O${/^o$/i.test(q.answer)?' ✔':''}</div><div style="flex:1;padding:12px;text-align:center;border-radius:10px;border:1.5px solid ${/^x$/i.test(q.answer)?'var(--success)':'var(--border)'};background:var(--card2);color:var(--danger);font-size:17px;font-weight:800">❌ X${/^x$/i.test(q.answer)?' ✔':''}</div></div>`; }
  else{ input=`<div style="margin-top:6px;padding:10px 13px;border-radius:10px;border:1.5px dashed var(--border);color:var(--text3);font-size:12px">단답 입력란 — 정답 <b style="color:var(--success)">${escapeHtml(q.answer)}</b>${accepts.length?` · 인정: ${escapeHtml(accepts.join(', '))}`:''}${keywords.length?` · 부분점수 키워드: ${escapeHtml(keywords.join(', '))}`:''}</div>`; }
  const m=document.getElementById('quiz-q-modal'); if(!m)return;
  m.style.display='flex';
  m.innerHTML=`<div style="background:var(--card);border:1px solid var(--border2);border-radius:16px;padding:20px;width:min(600px,96vw)">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><h3 style="margin:0;font-size:15px">👁 미리보기 #${q.id} <span class="u-muted-11" style="font-weight:400">— 팀원에게 보이는 모습 (+정답 표시)</span></h3><button class="btn btn-ghost u-btn-xs" onclick="document.getElementById('quiz-q-modal').style.display='none'">닫기</button></div>
    <div class="chart-card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><span style="font-size:11px;font-weight:800;color:var(--text3)">Q1 / 10</span><span style="display:flex;gap:6px;align-items:center">${quizProdBadge(q.product)}${quizDiffStars(q.difficulty)}</span></div>
      <div style="font-size:13.5px;font-weight:700;color:var(--text-strong);margin:8px 0 2px;line-height:1.6;white-space:pre-wrap">${escapeHtml(q.question)}</div>
      ${input}
      ${q.explanation?`<div style="font-size:12px;color:var(--text2);background:rgba(255,255,255,.04);border-radius:8px;padding:8px 11px;margin-top:10px;line-height:1.6">💡 ${escapeHtml(q.explanation)}${quizSourceHtml(q.source)}${q.credit?` <span class="u-muted-10">— 제보: ${escapeHtml(q.credit)} 🙌</span>`:''}</div>`:''}
    </div>
    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn btn-ghost u-btn-xs" onclick="document.getElementById('quiz-q-modal').style.display='none';quizEditQ(${q.id})">✏️ 수정</button>${q.status!=='approved'?`<button class="btn btn-primary u-btn-xs" onclick="quizSetStatus(${q.id},'approved');document.getElementById('quiz-q-modal').style.display='none'">✔ 승인</button>`:''}</div>
  </div>`;
}
function quizNormEq(a,b){ const n=s=>String(s==null?'':s).toLowerCase().replace(/[\s.,·\-_/()]+/g,''); return n(a)===n(b); }
window.loadQuizPage=loadQuizPage; window.submitQuiz=submitQuiz; window.quizPick=quizPick; window.quizShort=quizShort; window.loadQuizBoard=loadQuizBoard; window.quizRetake=quizRetake;
window.loadQuizAdmin=loadQuizAdmin; window.loadQuizBank=loadQuizBank; window.quizEditQ=quizEditQ; window.quizEditTypeSync=quizEditTypeSync; window.quizSaveQ=quizSaveQ; window.quizSetStatus=quizSetStatus; window.quizDelQ=quizDelQ; window.quizSuggest=quizSuggest; window.quizSwapPick=quizSwapPick; window.quizPublishWeek=quizPublishWeek; window.quizSaveSettings=quizSaveSettings; window.quizPreviewQ=quizPreviewQ;
