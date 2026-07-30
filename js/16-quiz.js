/* ── 🧠 주간 퀴즈 (P1) — 응시·즉시 피드백·XP/레벨/뱃지·리더보드 ───────────
   서버: /quiz/current /quiz/submit /quiz/me /quiz/leaderboard (worker.js)
   관리자 문제은행·출제는 16b(관리자 설정 섹션)에서. */
let QUIZ_CUR=null, QUIZ_ANS={};

function quizProdBadge(p){ const c=(typeof LC_MAP!=='undefined'&&LC_MAP[p])||'#9F6BB5'; return p?`<span class="badge" style="background:${c}22;color:${c}">${escapeHtml(p)}</span>`:''; }
function quizDiffStars(d){ return '<span style="color:var(--warn);letter-spacing:1px">'+'★'.repeat(Math.max(1,Math.min(3,d||1)))+'</span>'; }
function quizXpBar(me){
  if(!me)return '';
  const lv=me.level||{}; const next=lv.next;
  const pct=next?Math.max(4,Math.min(100,Math.round(100-((next.need)/(next.need+1)*0)))):100; // 진행률은 아래에서 계산
  return '';
}
function quizHeroHtml(d){
  const me=d.me||{}; const lv=me.level||{name:'🥉 새싹',next:null};
  const nextTxt=lv.next?`다음 레벨 <b>${escapeHtml(lv.next.name)}</b>까지 <b style="color:var(--accent)">${lv.next.need} XP</b>`:'최고 레벨!';
  const badges=(me.badges||[]).map(b=>`<span class="badge" style="background:rgba(159,107,181,.14);color:#9F6BB5;font-weight:700">${escapeHtml(b)}</span>`).join(' ');
  return `<div class="chart-card" style="margin-bottom:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div style="font-size:14.5px;font-weight:800;color:var(--text-strong)">${escapeHtml(d.intro||'🧠 이번 주 보안 퀴즈')}</div>
      ${d.prize?`<span class="badge" style="background:rgba(224,163,46,.14);color:#B27E00;font-weight:800">🎁 ${escapeHtml(d.prize)}</span>`:''}
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin-top:10px;font-size:12.5px;color:var(--text2)">
      <span><b style="font-size:15px;color:var(--text-strong)">${escapeHtml(lv.name)}</b> · <b style="color:var(--accent)">${me.xp||0} XP</b></span>
      <span>${nextTxt}</span>
      ${me.streak>=2?`<span class="badge" style="background:rgba(224,106,99,.14);color:#E06A63;font-weight:800">🔥 ${me.streak}주 연속</span>`:''}
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
    <div class="chart-card" style="margin-bottom:14px;text-align:center;padding:22px">
      <div style="font-size:38px;font-weight:900;color:${quizScoreColor(r.avg)}">${r.avg}점</div>
      <div style="font-size:14px;font-weight:800;color:var(--text-strong);margin-top:6px">${escapeHtml(r.msg||'')}</div>
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
    const nameOf=u=>{ try{ if(typeof window.__userMap==='object'&&window.__userMap&&window.__userMap[u])return window.__userMap[u]; }catch(_){} return u; };
    const hl=u=>u===meU?'style="background:color-mix(in srgb,var(--accent) 7%,transparent);border-radius:8px"':'';
    let weekCard='';
    if(d.scope==='month'){
      const rows=(d.rows||[]).sort((a,b)=>b.acc-a.acc).map((r,i)=>`<div ${hl(r.user)} class="u-fs12px" style="display:flex;justify-content:space-between;padding:5px 8px"><span>${['🥇','🥈','🥉'][i]||(i+1)+'.'} <b>${escapeHtml(nameOf(r.user))}</b></span><span>${Math.round(r.acc)}점 · ${r.answered}답 · ${r.weeks}주</span></div>`).join('');
      weekCard=`<div class="chart-card"><h4>📅 이번 달 종합</h4>${rows||'<div class="empty">이번 달 기록이 아직 없어요</div>'}<div style="margin-top:8px"><button class="btn btn-ghost u-btn-xxs" onclick="loadQuizBoard('week')">← 주간 보기</button></div></div>`;
    }else{
      const rows=(d.rows||[]).sort((a,b)=>b.acc-a.acc).map((r,i)=>`<div ${hl(r.user)} class="u-fs12px" style="display:flex;justify-content:space-between;padding:5px 8px"><span>${['🥇','🥈','🥉'][i]||(i+1)+'.'} <b>${escapeHtml(nameOf(r.user))}</b></span><span>${Math.round(r.acc)}점 · ${r.answered}${d.totalQ?'/'+d.totalQ:''}답</span></div>`).join('');
      weekCard=`<div class="chart-card"><h4>🎯 이번 주 (${escapeHtml(d.week||'')})</h4>${rows||'<div class="empty">아직 아무도 도전 안 했어요 — 1등 찬스! 🏁</div>'}<div style="margin-top:8px"><button class="btn btn-ghost u-btn-xxs" onclick="loadQuizBoard('month')">📅 월간 보기</button></div></div>`;
    }
    const xpRows=(d.xpRows||[]).slice(0,10).map((r,i)=>`<div ${hl(r.user)} class="u-fs12px" style="display:flex;justify-content:space-between;padding:5px 8px"><span>${['🥇','🥈','🥉'][i]||(i+1)+'.'} <b>${escapeHtml(nameOf(r.user))}</b></span><span>${escapeHtml(r.level)} · ${r.xp} XP</span></div>`).join('');
    let goalCard='';
    if(d.teamGoal){
      const pct=Math.min(100,Math.round(d.teamGoal.current/d.teamGoal.goal*100));
      goalCard=`<div class="chart-card"><h4>🤝 팀 공동 목표</h4>
        <div class="u-fs12px" style="color:var(--text2);margin-bottom:8px">이달 팀 평균 <b>${d.teamGoal.goal}점</b> 달성 시 ${d.teamGoal.prize?`<b style="color:#B27E00">🎁 ${escapeHtml(d.teamGoal.prize)}</b>`:'전원 보상!'}</div>
        <div style="background:var(--card2);border-radius:20px;height:18px;overflow:hidden;border:1px solid var(--border)"><div style="width:${pct}%;height:100%;background:linear-gradient(90deg,var(--accent),#E0A32E);border-radius:20px;transition:width .5s"></div></div>
        <div class="u-fs11px-ctext3-mb6px" style="margin-top:5px;text-align:right">현재 ${d.teamGoal.current}점 / ${d.teamGoal.goal}점 (${pct}%)</div>
      </div>`;
    }
    board.innerHTML=`<div class="chart-grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))">${weekCard}<div class="chart-card"><h4>⚡ 성장 랭킹 (누적 XP)</h4>${xpRows||'<div class="empty">아직 XP가 없어요</div>'}</div>${goalCard}</div>`;
  }catch(e){ board.innerHTML=`<div class="u-muted-11">리더보드 조회 실패: ${escapeHtml(e.message)}</div>`; }
}
window.loadQuizPage=loadQuizPage; window.submitQuiz=submitQuiz; window.quizPick=quizPick; window.quizShort=quizShort; window.loadQuizBoard=loadQuizBoard; window.quizRetake=quizRetake;
