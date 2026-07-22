
async function downloadHubBackup(){
  const btn=document.getElementById('storage-backup-btn');
  const old=btn?.textContent;
  if(btn){btn.disabled=true;btn.textContent='백업 생성 중...';}
  try{
    const r=await fetch(`${WORKERS}/admin/storage/backup`,{headers:authHeaders()});
    const d=await r.json();
    if(!d.ok)throw new Error(d.message||'백업 실패');
    const blob=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a=document.createElement('a');
    const ts=new Date().toISOString().replace(/[:.]/g,'-');
    a.href=URL.createObjectURL(blob);
    a.download=`engr-hub-backup-${ts}.json`;
    document.body.appendChild(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(a.href),1000);
    toast('전체 HUB 데이터 백업 파일을 생성했습니다.');
    setAdminActionStatus('전체 HUB 데이터 백업 파일 생성 완료');
  }catch(e){toast('백업 오류: '+e.message,true);setAdminActionStatus('백업 생성 실패: '+e.message,'err');}
  finally{if(btn){btn.disabled=false;btn.textContent=old||'⬇ 전체 HUB 데이터 백업';}}
}
async function cleanupOldAuditLogs(){
  const btn=document.getElementById('storage-audit-btn');
  const old=btn?.textContent;
  if(btn){btn.disabled=true;btn.textContent='대상 확인 중...';}
  try{
    const headers=authHeaders({'Content-Type':'application/json'});
    const dry=await fetch(`${WORKERS}/admin/storage/cleanup`,{method:'POST',headers,body:JSON.stringify({target:'audit-old',days:90,dryRun:true,max:500})});
    const dd=await dry.json();
    if(!dd.ok)throw new Error(dd.message||'정리 대상 확인 실패');
    if(!dd.matched){toast('정리할 90일 초과 감사 로그가 없습니다.');setAdminActionStatus('감사 로그 정리 대상 없음','info');return;}
    const msg=`90일 초과 감사 로그 인덱스/본문 ${dd.matched}개를 정리할 수 있습니다.
이번 실행 최대 ${dd.scanned}개를 검사했습니다.

계속 진행할까요?`;
    if(!confirm(msg))return;
    if(btn)btn.textContent='정리 중...';
    const r=await fetch(`${WORKERS}/admin/storage/cleanup`,{method:'POST',headers,body:JSON.stringify({target:'audit-old',days:90,dryRun:false,max:500})});
    const d=await r.json();
    if(!d.ok)throw new Error(d.message||'정리 실패');
    toast(`감사 로그 정리 완료: ${d.deleted}개 삭제${d.truncated?' · 남은 대상이 있을 수 있습니다. 다시 실행하세요.':''}`);
    setAdminActionStatus(`감사 로그 정리 완료: ${d.deleted}개 삭제${d.truncated?' · 남은 대상이 있을 수 있습니다.':''}`);
    await refreshStorageStats();
  }catch(e){toast('정리 오류: '+e.message,true);setAdminActionStatus('감사 로그 정리 실패: '+e.message,'err');}
  finally{if(btn){btn.disabled=false;btn.textContent=old||'🧹 감사 로그 90일 초과 정리';}}
}
let MUST_CHANGE_PIN=false;
function forcePinChange(){   // H-1: 공유 PIN 폴백 로그인 시 개인 PIN 설정 강제(닫기 불가)
  window.__pinLock=true;
  openGenModal('🔐 개인 PIN 설정 필요',`
  <div style="background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.3);border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:12.5px;color:var(--warn)">보안을 위해 공유 PIN 대신 <b>개인 PIN</b>을 설정해야 계속 사용할 수 있습니다.</div>
  <div class="modal-form">
    <div class="full"><label>현재 PIN(공유/기존)</label><input id="pin-old" type="password" autocomplete="current-password"></div>
    <div class="full"><label>새 개인 PIN</label><input id="pin-new" type="password" autocomplete="new-password" placeholder="6자 이상"></div>
    <div class="full"><label>새 PIN 확인</label><input id="pin-new2" type="password" autocomplete="new-password"></div>
  </div>`,
  `<button class="btn btn-ghost" onclick="window.__pinLock=false;forceLogout()" style="width:auto;padding:8px 18px">로그아웃</button>
   <button class="btn btn-indigo" onclick="changeMyPin()" style="width:auto;padding:8px 18px">개인 PIN 설정하고 계속</button>`);
}
function openChangePinModal(){
  openGenModal('내 PIN 변경',`
  <div class="modal-form">
    <div class="full"><label>현재 PIN</label><input id="pin-old" type="password" autocomplete="current-password"></div>
    <div class="full"><label>새 PIN</label><input id="pin-new" type="password" autocomplete="new-password" placeholder="6자 이상"></div>
    <div class="full"><label>새 PIN 확인</label><input id="pin-new2" type="password" autocomplete="new-password"></div>
  </div>`,
  `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">취소</button>
   <button class="btn btn-indigo" onclick="changeMyPin()" style="width:auto;padding:8px 18px">변경</button>`);
}
async function changeMyPin(){
  const oldPin=document.getElementById('pin-old').value;
  const newPin=document.getElementById('pin-new').value;
  const newPin2=document.getElementById('pin-new2').value;
  if(!oldPin||!newPin){toast('현재 PIN과 새 PIN을 입력하세요',true);return;}
  if(newPin!==newPin2){toast('새 PIN 확인이 일치하지 않습니다',true);return;}
  try{
    await hubApi('/auth/change-pin',{method:'POST',body:JSON.stringify({oldPin,newPin})});
    if(window.__pinLock){window.__pinLock=false;MUST_CHANGE_PIN=false;}  // H-1: 강제 게이트 해제
    closeGenModal();toast('PIN이 변경됐습니다');
  }catch(e){toast('PIN 변경 실패: '+e.message,true);}
}
async function resetUserPin(){
  const target=document.getElementById('pin-reset-user')?.value||'';
  if(!target){toast('팀원을 선택하세요',true);return;}
  if(!confirm(`${target}님의 PIN을 초기값으로 변경할까요?`))return;
  try{
    await hubApi('/admin/user-pin/reset',{method:'POST',body:JSON.stringify({user:target})});
    toast(`${target} PIN을 초기화했습니다`);
    setAdminActionStatus(`${target} PIN 초기화 완료`);
  }catch(e){toast('PIN 초기화 실패: '+e.message,true);setAdminActionStatus('PIN 초기화 실패: '+e.message,'err');}
}
function resetAllHubData(){
  if(!confirm('업무 링크, 노하우, 라이선스, 개인 메모, VT 이력, AI 캐시/사용량/감사 로그를 초기화합니다.\n관리자/시스템 설정은 유지됩니다.\n\n계속하려면 로그인 PIN을 입력해야 합니다.'))return;
  // 기존 모달 재활용 or 인라인 PIN 입력
  const pin=window.__resetPin||(()=>{
    const p=document.createElement('div');
    p.style.cssText='position:fixed;inset:0;background:rgba(5,8,16,.85);z-index:9999;display:flex;align-items:center;justify-content:center';
    p.innerHTML=`<div style="background:var(--card);border:1px solid var(--border);border-radius:16px;padding:28px 24px;width:320px;box-shadow:0 20px 60px rgba(0,0,0,.5)">
      <div style="font-size:14px;font-weight:700;color:var(--text);margin-bottom:8px">⚠ 전체 데이터 초기화</div>
      <div style="font-size:12px;color:var(--text2);margin-bottom:16px;line-height:1.6">로그인 PIN을 입력하면 초기화가 시작됩니다.</div>
      <input id="reset-pin-input" type="password" placeholder="PIN 입력" style="width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text);font-size:14px;box-sizing:border-box;margin-bottom:12px" autocomplete="current-password">
      <div style="display:flex;gap:8px">
        <button id="reset-pin-cancel" class="btn btn-ghost" style="flex:1">취소</button>
        <button id="reset-pin-ok" class="btn btn-red" style="flex:1">초기화</button>
      </div>
    </div>`;
    document.body.appendChild(p);
    document.getElementById('reset-pin-input').focus();
    return new Promise(resolve=>{
      document.getElementById('reset-pin-cancel').onclick=()=>{p.remove();resolve(null);};
      document.getElementById('reset-pin-ok').onclick=()=>{const v=document.getElementById('reset-pin-input').value;p.remove();resolve(v||null);};
      document.getElementById('reset-pin-input').onkeydown=e=>{if(e.key==='Enter'){const v=document.getElementById('reset-pin-input').value;p.remove();resolve(v||null);}if(e.key==='Escape'){p.remove();resolve(null);}};
    });
  })();
  Promise.resolve(pin).then(async resolvedPin=>{
    if(!resolvedPin)return;
    const btn=document.getElementById('storage-reset-btn');
    const old=btn?.textContent;
    if(btn){btn.disabled=true;btn.textContent='초기화 중...';}
    try{
      const d=await hubApi('/admin/storage/reset',{method:'POST',body:JSON.stringify({pin:resolvedPin})});
      LINKS=[];KNOWLEDGE=[];EOS_ITEMS=[];VT_HISTORY=[];
      localStorage.removeItem('vt_history');
      toast(`초기화 완료: ${d.deleted||0}개 삭제${d.truncated?' · 일부 데이터가 남아 다시 실행 필요':''}`);
      setAdminActionStatus(`전체 데이터 초기화 완료: ${d.deleted||0}개 삭제${d.truncated?' · 일부 데이터가 남아 다시 실행 필요':''}`);
      renderCurrent();
    }catch(e){toast('초기화 실패: '+e.message,true);setAdminActionStatus('초기화 실패: '+e.message,'err');}
    finally{if(btn){btn.disabled=false;btn.textContent=old||'⚠ 전체 데이터 초기화';}}
  });
}
async function addAdmin(){
  const name=document.getElementById('admin-add-name').value;
  const role=document.getElementById('admin-add-role').value;
  if(!name){toast('팀원을 선택해주세요',true);return;}
  try{
    const r=await fetch(`${WORKERS}/admin/update`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({action:'add',user:name,role})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'실패',true);setAdminActionStatus(d.message||'관리자 권한 추가 실패','err');return;}
    toast(`${name} (${role==='super'?'최상위':'일반'} 관리자) 추가`);loadSettings();
    setAdminActionStatus(`${name} 관리자 권한 추가 완료`);
  }catch(e){toast('오류: '+e.message,true);setAdminActionStatus('관리자 권한 추가 실패: '+e.message,'err');}
}
async function changeRole(name,newRole){
  try{
    const r=await fetch(`${WORKERS}/admin/update`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({action:'changeRole',user:name,role:newRole})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'실패',true);setAdminActionStatus(d.message||'관리자 권한 변경 실패','err');loadSettings();return;}
    toast(`${name} 권한 변경`);
    setAdminActionStatus(`${name} 관리자 권한 변경 완료`);
  }catch(e){toast('오류: '+e.message,true);setAdminActionStatus('관리자 권한 변경 실패: '+e.message,'err');}
}
async function removeAdmin(name){
  if(!confirm(`${name}의 관리자 권한을 회수하시겠어요?`))return;
  try{
    const r=await fetch(`${WORKERS}/admin/update`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({action:'remove',user:name})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'실패',true);setAdminActionStatus(d.message||'관리자 권한 회수 실패','err');return;}
    toast(`${name} 권한 회수`);loadSettings();
    setAdminActionStatus(`${name} 관리자 권한 회수 완료`);
  }catch(e){toast('오류: '+e.message,true);setAdminActionStatus('관리자 권한 회수 실패: '+e.message,'err');}
}


// ── 고객사 프로필 ─────────────────────────────────
let CUST_SEL=null;
// renderCustomers: duplicate removed, using definition below
function renderCustomers(){
  const q=(document.getElementById("cust-q")||{}).value?.toLowerCase()||"";
  const prod=(document.getElementById("cust-prod")||{}).value||"";
  const ass=(document.getElementById("cust-ass")||{}).value||"";
  let custs=buildCustomers();
  const allProds=new Set(), allAss=new Set();
  custs.forEach(c=>{c.products.forEach(p=>allProds.add(p));c.assignees.forEach(a=>allAss.add(a));});
  const pdSel=document.getElementById("cust-prod");
  if(pdSel){const cur=pdSel.value;pdSel.innerHTML='<option value="">전체 제품</option>'+Array.from(allProds).sort().map(p=>`<option ${p===cur?"selected":""}>${escapeHtml(p)}</option>`).join("");}
  const assSel=document.getElementById("cust-ass");
  if(assSel){const cur=assSel.value;assSel.innerHTML='<option value="">전체 담당자</option>'+Array.from(allAss).sort().map(a=>`<option ${a===cur?"selected":""}>${escapeHtml(a)}</option>`).join("");}
  if(prod)custs=custs.filter(c=>c.products.has(prod));
  if(ass)custs=custs.filter(c=>c.assignees.has(ass));
  if(q)custs=custs.filter(c=>[c.name,[...c.products].join(" "),[...c.assignees].join(" ")].join(" ").toLowerCase().includes(q));
  const wrap=document.getElementById("cust-list");
  const pageCusts=sliceForPage(custs,'customers');
  document.getElementById("cust-count").textContent=pageCountText('customers',custs.length,'개');
  if(!pageCusts.length){wrap.innerHTML=`<div style="text-align:center;padding:40px;color:var(--text3);font-size:13px">Jira 동기화 후 자동 집계되거나 조건에 맞는 고객사가 없습니다</div>`;renderPager('cust-pager','customers',custs.length,'renderCustomers');return;}
  wrap.innerHTML=pageCusts.map((c,idx)=>{
    const done=c.general.filter(i=>isDoneStatus(i.status)).length;
    const open=c.general.filter(i=>isOpenStatus(i.status)).length;
    const caseOpen=c.cases.filter(i=>isOpenStatus(i.status)).length;
    const rate=c.general.length?Math.round(done/c.general.length*100):0;
    const prods=[...c.products].join(", ")||"-";
    const isSel=CUST_SEL&&CUST_SEL.name===c.name;
    return `<div onclick="selectCustomer(${idx},this.dataset.name)" data-name="${escapeHtml(c.name)}" style="background:#262d47;border:1.5px solid ${isSel?"var(--accent)":"var(--border)"};border-radius:12px;padding:14px 16px;cursor:pointer;transition:all .15s">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <span style="font-size:13px;font-weight:700;color:#f0f4ff">${escapeHtml(c.name)}</span>
        <span style="font-size:10px;background:rgba(196,206,255,.15);color:#c4ceff;padding:2px 9px;border-radius:20px;font-weight:700">일반 ${c.general.length} · 케이스 ${c.cases.length}</span>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-bottom:6px">${escapeHtml(prods)}</div>
      <div style="display:flex;gap:10px;font-size:11px;flex-wrap:wrap">
        <span style="color:#2de6b8">일반 완료 ${done}</span>
        <span style="color:#fc8181">일반 미완료 ${open}</span>
        <span style="color:#fcd34d">케이스 미완료 ${caseOpen}</span>
        <span style="color:var(--text3);margin-left:auto">완료율 ${rate}%</span>
      </div>
    </div>`;
  }).join("");
  renderPager('cust-pager','customers',custs.length,'renderCustomers');
}


// ── 팀 노하우 ─────────────────────────────────────
let KNOWLEDGE=[];
async function loadKnowledge(){
  try{const r=await fetch(`${WORKERS}/knowledge`,{headers:authHeaders()});const d=await r.json();KNOWLEDGE=d.items||[];}catch{}
}
function renderKnowledge(){
  renderCommentFeed('knowledge-comment-feed','knowledge',KNOWLEDGE);
  const prod=document.getElementById("know-prod")?.value||"";
  const cat=document.getElementById("know-cat")?.value||"";
  const q=(document.getElementById("know-q")?.value||"").toLowerCase();
  let list=KNOWLEDGE.filter(k=>{
    const txt=[k.title,k.content,k.category,k.product,k.link,k.createdBy,(k.comments||[]).map(c=>c.text).join(' ')].join(" ").toLowerCase();
    return (!prod||k.product===prod)&&(!cat||k.category===cat)&&(!q||txt.includes(q));
  });
  const cnt=document.getElementById('know-count');if(cnt)cnt.textContent=`총 ${list.length}건 · ${PAGE_SIZES.knowledge}건씩 표시`;
  const pageKnowledge=sliceForPage(list,'knowledge');
  const wrap=document.getElementById("knowledge-grid");
  if(!pageKnowledge.length){wrap.innerHTML=`<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--text3);font-size:13px">등록된 노하우가 없거나 조건에 맞는 노하우가 없습니다</div>`;renderPager('know-pager','knowledge',list.length,'renderKnowledge');return;}
  wrap.innerHTML=pageKnowledge.map(k=>{
    const href=normalizeExternalUrl(k.link||'');
    const commentCount=(k.comments||[]).length;
    const canEdit=(k.createdBy===CURRENT_USER||IS_ADMIN||IS_SUPER);
    return `<div class="card knowledge-card" onclick="openKnowledgeDetail('${k.id}')" style="padding:14px;position:relative;cursor:pointer"><div style="position:absolute;top:10px;right:10px;display:flex;gap:4px;align-items:center">${canEdit?`<input type="checkbox" class="kno-pick" data-id="${k.id}" onclick="event.stopPropagation()" style="width:15px;height:15px;cursor:pointer">`:''}<button onclick="event.stopPropagation();openKnowledgeDetail('${k.id}')" style="background:transparent;border:0;color:var(--text3);cursor:pointer;font-size:11px">댓글 ${commentCount}</button>${canEdit?`<button onclick="event.stopPropagation();openKnowledgeModal('${k.id}')" style="background:transparent;border:0;color:var(--text3);cursor:pointer">✎</button><button onclick="event.stopPropagation();deleteKnowledge('${k.id}')" style="background:transparent;border:0;color:var(--danger);cursor:pointer">×</button>`:''}</div><div style="display:flex;gap:6px;margin-bottom:8px"><span class="badge" style="background:${labelColor(k.product||'기타')}22;color:${labelColor(k.product||'기타')}">${escapeHtml(k.product||'기타')}</span><span class="badge" style="background:rgba(196,206,255,.12);color:#c4ceff">${escapeHtml(k.category||'')}</span></div><div style="font-size:14px;font-weight:800;color:#f0f4ff;margin-bottom:8px;padding-right:70px">${escapeHtml(k.title||'')}</div>${k.content?`<div class="knowledge-excerpt" style="font-size:12px;color:var(--text2);line-height:1.6;white-space:pre-wrap;margin-bottom:10px">${escapeHtml(k.content)}</div>`:''}${href?`<a onclick="event.stopPropagation()" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:var(--cyan);text-decoration:none">참고 링크 ↗</a>`:''}<div style="font-size:10px;color:var(--text3);margin-top:10px">${escapeHtml(k.createdBy||'-')} · ${k.updatedAt?'수정 '+fd(k.updatedAt):fd(k.createdAt)}</div></div>`;
  }).join("");
  renderPager('know-pager','knowledge',list.length,'renderKnowledge');
}

function openKnowledgeDetail(id){
  const k=KNOWLEDGE.find(x=>x.id===id);
  if(!k)return;
  const href=normalizeExternalUrl(k.link||'');
  openGenModal(k.title||'노하우 상세',`
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
      <span class="badge" style="background:${labelColor(k.product||'기타')}22;color:${labelColor(k.product||'기타')}">${escapeHtml(k.product||'기타')}</span>
      <span class="badge" style="background:rgba(196,206,255,.12);color:#c4ceff">${escapeHtml(k.category||'')}</span>
    </div>
    <div style="font-size:13px;color:var(--text2);line-height:1.75;white-space:pre-wrap">${escapeHtml(k.content||'내용 없음')}</div>
    ${href?`<div style="margin-top:14px"><a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" style="font-size:12px;color:var(--cyan);text-decoration:none">참고 링크 열기 ↗</a></div>`:''}
    <div style="font-size:10px;color:var(--text3);margin-top:16px">${escapeHtml(k.createdBy||'-')} · ${k.updatedAt?'수정 '+fd(k.updatedAt):fd(k.createdAt)}</div>
    ${itemCommentsHtml('knowledge',k)}`,
    `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">닫기</button>
     <button class="btn btn-indigo" onclick="openKnowledgeModal('${id}')" style="width:auto;padding:8px 18px">수정</button>`);
}

function openKnowledgeModal(id){
  const ex=id?KNOWLEDGE.find(k=>k.id===id):null;
  openGenModal(ex?"노하우 수정":"노하우 등록",`
  <div class="modal-form">
    <div><label>제품</label>
      <select id="know-form-prod">${["SEP","SEPM","DLP","PP","ProxySG","CloudSWG","CASB","기타"].map(p=>`<option ${ex?.product===p?"selected":""}>${p}</option>`).join("")}</select>
    </div>
    <div><label>분류</label>
      <select id="know-form-cat">${["Known Issue","워크어라운드","설치/설정","KB/문서","팁"].map(c=>`<option ${ex?.category===c?"selected":""}>${c}</option>`).join("")}</select>
    </div>
    <div class="full"><label>제목 *</label><input id="know-form-title" value="${escapeHtml(ex?.title||"")}" placeholder="간결하게 문제/팁을 설명"></div>
    <div class="full"><label>내용</label><textarea id="know-form-content" style="min-height:100px">${escapeHtml(ex?.content||"")}</textarea></div>
    <div class="full"><label>KB/참고 링크</label><input id="know-form-link" value="${escapeHtml(ex?.link||"")}" placeholder="https://knowledge.broadcom.com/..."></div>
  </div>`,
  `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">취소</button>
   <button class="btn btn-indigo" onclick="${ex?`updateKnowledge('${id}')`:"saveKnowledge()"}" style="width:auto;padding:8px 18px">저장</button>`);
}
async function saveKnowledge(){
  const title=document.getElementById("know-form-title").value.trim();
  if(!title){toast("제목은 필수입니다",true);return;}
  const rawLink=document.getElementById("know-form-link").value.trim();
  const link=normalizeExternalUrl(rawLink);
  if(link&&!link.includes('broadcom.com')&&!confirm('입력한 링크가 broadcom.com 도메인이 아닙니다.\n계속 등록하시겠어요?'))return;
  const body={product:document.getElementById("know-form-prod").value,category:document.getElementById("know-form-cat").value,title,content:document.getElementById("know-form-content").value.trim(),link};
  try{const r=await fetch(`${WORKERS}/knowledge`,{method:"POST",headers:authHeaders({"Content-Type":"application/json"}),body:JSON.stringify(body)});const d=await r.json();if(!d.ok){toast(d.message||"저장 실패",true);return;}toast("등록 완료");closeGenModal();await loadKnowledge();renderKnowledge();}catch(e){toast("오류: "+e.message,true);}
}
async function updateKnowledge(id){
  const title=document.getElementById("know-form-title").value.trim();
  if(!title){toast("제목은 필수입니다",true);return;}
  const rawLink=document.getElementById("know-form-link").value.trim();
  const link=normalizeExternalUrl(rawLink);
  if(link&&!link.includes('broadcom.com')&&!confirm('입력한 링크가 broadcom.com 도메인이 아닙니다.\n계속 수정하시겠어요?'))return;
  const body={product:document.getElementById("know-form-prod").value,category:document.getElementById("know-form-cat").value,title,content:document.getElementById("know-form-content").value.trim(),link};
  try{const r=await fetch(`${WORKERS}/knowledge/${id}`,{method:"PUT",headers:authHeaders({"Content-Type":"application/json"}),body:JSON.stringify(body)});const d=await r.json();if(!d.ok){toast(d.message||"수정 실패",true);return;}toast("수정 완료");closeGenModal();await loadKnowledge();renderKnowledge();}catch(e){toast("오류: "+e.message,true);}
}
async function deleteKnowledge(id){
  if(!confirm("삭제하시겠어요?"))return;
  try{const r=await fetch(`${WORKERS}/knowledge/${id}`,{method:"DELETE",headers:authHeaders()});const d=await r.json();if(!d.ok){toast(d.message||"실패",true);return;}toast("삭제됨");await loadKnowledge();renderKnowledge();}catch(e){toast("오류: "+e.message,true);}
}

// ── 저장소 안내 ───────────────────────────────────
function showStorageInfo(tab){
  const info={
    vt:"<strong>VT 조회 이력</strong><br>최대 15건 · 브라우저 localStorage 저장<br>로그아웃 후에도 유지 (같은 브라우저/기기 기준)<br>다른 기기에서는 보이지 않음",
    issues:"<strong>Jira 이슈</strong><br>Jira에서 실시간 동기화 · 브라우저 메모리 저장<br>새로고침 시 재동기화 · 로그아웃/탭 닫으면 초기화",
    links:"<strong>업무 링크</strong><br>Cloudflare KV 서버 저장 · 영구 보존<br>모든 팀원이 동일하게 조회",
    knowledge:"<strong>팀 노하우</strong><br>Cloudflare KV 서버 저장 · 영구 보존<br>모든 팀원이 동일하게 조회",
    eos:"<strong>라이선스</strong><br>Cloudflare KV 서버 저장 · 영구 보존<br>모든 팀원이 동일하게 조회",
    audit:"<strong>감사 로그</strong><br>Cloudflare KV 서버 저장 · 90일 자동 삭제<br>최대 500건 표시",
  };
  if(!info[tab])return;
  openGenModal("📦 데이터 저장 안내",`<div style="font-size:13px;color:var(--text2);line-height:2.2">${info[tab]}</div>`,"<button class='btn btn-ghost' onclick='closeGenModal()' style='width:auto;padding:8px 18px'>닫기</button>");
}


// ── KB 시드 데이터 자동 등록 ─────────────────────────────
const KB_SEED = [
  // ── SEP/SEPM ──────────────────────────────────────────
  {category:'KB-SEP', title:'Versions, system requirements, release dates - SEP/SES 14.3.x',
   url:'https://knowledge.broadcom.com/external/article/154575',
   desc:'SEP 14.3.x 버전별 릴리스 날짜, 빌드번호, 시스템 요구사항, RU별 수정사항 종합'},
  {category:'KB-SEP', title:'Versions, system requirements, release dates - SEP/SES 16.x',
   url:'https://knowledge.broadcom.com/external/article/397614',
   desc:'SEP 16.x 버전별 릴리스 날짜, 빌드번호, 시스템 요구사항'},
  {category:'KB-SEP', title:'New fixes and component versions in SEP 14.3 RU10',
   url:'https://knowledge.broadcom.com/external/article/386578',
   desc:'SEP 14.3 RU10 (14.3.12154.10000) 수정 사항 및 컴포넌트 버전 목록'},
  {category:'KB-SEP', title:'New fixes and component versions in SEP 14.4',
   url:'https://knowledge.broadcom.com/external/article/430629',
   desc:'SEP 14.4 (14.4.115.0000) 수정 사항 및 컴포넌트 버전 목록'},
  {category:'KB-SEP', title:"What's new for all releases of Symantec Endpoint Protection 14.x",
   url:'https://knowledge.broadcom.com/external/article/185214',
   desc:'SEP 14.x 전 릴리스 신규 기능 요약'},
  {category:'KB-SEP', title:'Windows compatibility with Symantec Endpoint Protection clients',
   url:'https://knowledge.broadcom.com/external/article/163625',
   desc:'Windows OS별 SEP 클라이언트 호환성 매트릭스 (Windows 10/11/Server 포함)'},
  {category:'KB-SEP', title:'Product guides for Symantec Endpoint Protection',
   url:'https://knowledge.broadcom.com/external/article/185213',
   desc:'SEP 전 버전 설치 가이드, 관리 가이드, 릴리스 노트 다운로드 링크'},
  {category:'KB-SEP', title:'End of Service dates for Symantec Endpoint Protection',
   url:'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/product-advisories/End-of-Service-Dates-for-Symantec-Endpoint-Protection/7637',
   desc:'SEP 버전별 EOS 날짜 공식 표'},
  {category:'KB-SEP', title:'Download the latest version of Endpoint Protection',
   url:'https://knowledge.broadcom.com/external/article/157395',
   desc:'SEP 최신 버전 다운로드 방법 및 Broadcom 포털 접근 가이드'},
  {category:'KB-SEP', title:'SEP CVE/취약점 보안 권고 포털',
   url:'https://knowledge.broadcom.com/external/article/225891',
   desc:'Broadcom/Symantec 제품 CVE, 취약점, 보안 권고 통합 검색 포털'},

  // ── DLP ──────────────────────────────────────────────
  {category:'KB-DLP', title:'End of Service dates for Symantec Data Loss Prevention',
   url:'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/product-advisories/End-of-Service-dates-for-Symantec-Data-Loss-Prevention/16164',
   desc:'DLP 버전별 EOS 날짜 공식 표 (16.0, 16.1, 25.1 등)'},
  {category:'KB-DLP', title:'DLP Endpoint Agent build numbers and latest hotfix information',
   url:'https://knowledge.broadcom.com/external/article/185118',
   desc:'DLP 에이전트 브랜치별 최신 빌드번호 및 핫픽스 정보 (16.0 RU1 MP1 등)'},
  {category:'KB-DLP', title:'Symantec Data Loss Prevention - Release types',
   url:'https://knowledge.broadcom.com/external/article/164993',
   desc:'DLP Major/Minor/RU/MP/Hotfix 릴리스 유형별 특성 및 업그레이드 순서'},
  {category:'KB-DLP', title:'DLP Quick Upgrade Guides',
   url:'https://knowledge.broadcom.com/external/article/270589',
   desc:'DLP 버전별 업그레이드 가이드 링크 모음 (16.x → 25.1 포함)'},
  {category:'KB-DLP', title:'High Level Steps for Upgrading DLP',
   url:'https://knowledge.broadcom.com/external/article/247415',
   desc:'DLP 업그레이드 전체 절차 (Oracle 포함), 주의사항, URT 실행 순서'},
  {category:'KB-DLP', title:'DLP Release Cadence',
   url:'https://knowledge.broadcom.com/external/article/211665',
   desc:'DLP 릴리스 주기 및 MP 배포 일정 정책'},
  {category:'KB-DLP', title:'You want to see a list of recent DLP Product Advisories',
   url:'https://knowledge.broadcom.com/external/article/269358',
   desc:'DLP 최신 제품 권고, 릴리스 공지, 크리티컬 알림 목록 찾는 방법'},
  {category:'KB-DLP', title:'DLP CVE-2025-22228 - Spring Security 취약점 영향 여부',
   url:'https://knowledge.broadcom.com/external/article/430578',
   desc:'RHEL DLP Detection 서버 취약점 스캔 CVE-2025-22228 영향 분석 (2026.02)'},
  {category:'KB-DLP', title:'DLP CVE-2025-41249 - Spring Framework 취약점 영향 여부',
   url:'https://knowledge.broadcom.com/external/article/417005',
   desc:'DLP spring-web CVE-2025-41249 취약점 영향 여부 분석'},
  {category:'KB-DLP', title:'DLP CVE-2025-21587 - AdoptOpenJRE 취약점 영향 여부',
   url:'https://knowledge.broadcom.com/external/article/404445',
   desc:'Enforce 서버 CVE-2025-21587 취약점 영향 없음 공식 확인'},
  {category:'KB-DLP', title:'DLP CVE-2025-22233 - Spring 취약점 영향 여부',
   url:'https://knowledge.broadcom.com/external/article/404795',
   desc:'DLP CVE-2025-22233 비영향 확인'},
  {category:'KB-DLP', title:'Is DLP vulnerable to CVE-2025-48976',
   url:'https://knowledge.broadcom.com/external/article/417030',
   desc:'Apache Commons FileUpload CVE-2025-48976 DLP 비영향 확인'},

  // ── ProxySG / Edge SWG ──────────────────────────────
  {category:'KB-ProxySG', title:'End of life and product lifecycle for Edge SWG (ProxySG) and ASG',
   url:'https://knowledge.broadcom.com/external/article/151102',
   desc:'ProxySG/ASG EOL 날짜 및 2024~2026 유지보수 릴리스 일정'},
  {category:'KB-ProxySG', title:'Edge SWG (ProxySG) - Network Web Prevent DLP integration',
   url:'https://knowledge.broadcom.com/external/article/230914',
   desc:'ProxySG + DLP Network Prevent ICAP 연동 트래픽 흐름, 액세스 로깅 설명'},
  {category:'KB-ProxySG', title:'Secure ICAP between DLP detection server and ProxySG',
   url:'https://knowledge.broadcom.com/external/article/383826',
   desc:'DLP Detection 서버와 ProxySG 간 Secure ICAP 설정 절차'},
  {category:'KB-ProxySG', title:'Is ISG, MC, SGOS, Reporter vulnerable to CVE-2025-32728',
   url:'https://knowledge.broadcom.com/external/article/400771',
   desc:'ProxySG(SGOS)/ISG/MC/CAS/Reporter CVE-2025-32728 취약점 영향 여부'},

  // ── 포털 / 공통 ─────────────────────────────────────
  {category:'포털', title:'Broadcom Support Portal',
   url:'https://support.broadcom.com',
   desc:'케이스 오픈, 제품 다운로드, 라이선스 관리, KB 검색 통합 포털'},
  {category:'포털', title:'My Broadcom',
   url:'https://my.broadcom.com',
   desc:'Broadcom 제품 등록, 라이선스 활성화, 계정 관리'},
  {category:'포털', title:'Broadcom Software Downloads',
   url:'https://support.broadcom.com/group/ecx/productdownloads',
   desc:'SEP, DLP, ProxySG 등 최신 버전 바이너리 다운로드'},
  {category:'포털', title:'Product Lifecycle (EOS/EOL 조회)',
   url:'https://support.broadcom.com/group/ecx/productlifecycle',
   desc:'제품/버전별 EOS, EOL 날짜 공식 조회. Cyber Security Software 선택 후 제품명 검색'},
  {category:'포털', title:'Broadcom CVE/Security Advisory 포털',
   url:'https://knowledge.broadcom.com/external/article/225891',
   desc:'Broadcom/Symantec/VMware 전 제품 CVE, 취약점, 보안 권고 통합 검색'},
  {category:'포털', title:'VirusTotal',
   url:'https://www.virustotal.com',
   desc:'파일 해시(MD5/SHA1/SHA256) 악성 여부 조회'},
  {category:'포털', title:'Symantec False Positive 신청',
   url:'https://symsubmit.symantec.com',
   desc:'Symantec 제품 오탐 신고 및 화이트리스트 신청 포털'},
];

async function importRecentKBLinks(){
  if(!confirm('비용이 발생하지 않는 방식으로 Broadcom KB article을 수집해 업무 링크에 자동 등록할까요?'))return;
  const btn=document.getElementById('kb-seed-btn');
  const oldText=btn?btn.textContent:'';
  if(btn){btn.disabled=true;btn.textContent='KB 수집 준비...';}
  let cursor='';
  let imported=0,duplicated=0,inaccessible=0,scanned=0,attempts=0,errors=0,batch=0;
  try{
    do{
      batch++;
      const qs=new URLSearchParams({years:'5',limit:'20'});
      if(cursor)qs.set('cursor',cursor);
      if(btn)btn.textContent=`KB 수집 중... ${batch}차`;
      const r=await fetch(`${WORKERS}/links/kb/import?${qs.toString()}`,{method:'POST',headers:authHeaders()});
      if(!r.ok){toast('Worker 업데이트 후 사용 가능합니다',true);setAdminActionStatus('KB 수집 실패: Worker 업데이트 후 사용 가능합니다','err');return;}
      const d=await r.json();
      if(d.ok===false){toast(d.message||'KB 수집 설정이 필요합니다',true);setAdminActionStatus(d.message||'KB 수집 설정이 필요합니다','err');return;}
      imported+=d.imported||d.added||0;
      duplicated+=d.duplicated||d.skipped||0;
      inaccessible+=d.inaccessible||0;
      scanned+=d.scanned||0;
      attempts+=d.attempts||0;
      errors+=d.errors||0;
      cursor=d.nextCursor||'';
      if(btn)btn.textContent=`KB 수집 중... 신규 ${imported} / 확인 ${scanned}`;
      if(cursor)await new Promise(r=>setTimeout(r,250));
    }while(cursor);
    await loadLinks();
    if(document.getElementById('page-links')?.classList.contains('active'))renderLinks();
    const searchNote=attempts?` / 검색 API ${attempts}회`:' / 검색 API 0회';
    toast(`KB 무료 수집 완료: 신규 ${imported}건 / 중복 ${duplicated}건 / 접근불가 ${inaccessible}건${searchNote}${errors?` / 오류 ${errors}회`:''}`);
    setAdminActionStatus(`KB 수집 완료: 신규 ${imported}건 / 중복 ${duplicated}건 / 접근불가 ${inaccessible}건${errors?` / 오류 ${errors}회`:''}`);
  }catch(e){toast('오류: '+e.message,true);setAdminActionStatus('KB 수집 실패: '+e.message,'err');}
  finally{if(btn){btn.disabled=false;btn.textContent=oldText||'📥 무료 KB article 수집';}}
}
async function collectCompatMatrix(){
  if(typeof VENDOR_KB==='undefined'){toast('호환성 매트릭스 페이지를 한 번 연 뒤 시도하세요');return;}
  if(!confirm('DLP·SEP 주요 버전의 호환성 매트릭스를 AI로 수집해 매트릭스에 초안으로 자동 등록합니다.\n(여러 번 AI 호출 — 1분 내외 소요) 계속할까요?'))return;
  const btn=document.getElementById('collect-compat-btn'), st=document.getElementById('collect-status');
  if(btn){btn.disabled=true;btn.textContent='수집 중...';}
  const targets=[]; ['DLP','SEP'].forEach(prod=>{(VENDOR_KB[prod]||[]).slice(0,4).forEach(e=>targets.push({prod,e}));});
  let total=0, done=0;
  for(const {prod,e} of targets){
    done++; const brand='Symantec '+prod;
    if(st)st.textContent=`(${done}/${targets.length}) ${brand} ${e.v} 수집 중... 누적 ${total}건`;
    const pr=`너는 보안제품 호환성 DB 보조자다. "${brand} ${e.v}"의 지원 OS 매트릭스를 JSON 배열로만 답하라(설명·코드블록 금지). 지원상태가 같은 OS는 한 행으로 묶어라(os 필드에 "Windows 10 / 11, Server 2016~2022"처럼). 총 2~4행. 각 원소: {"os":"","os_version":"","supported":"지원|미지원|조건부","eos_date":"","eol_date":"","note":"서버/엔드포인트 등"}.`;
    try{
      const txt=await callAI(pr,'cmpx',{feature:'collect'});
      const mt=txt.match(/\[[\s\S]*\]/); const arr=mt?JSON.parse(mt[0]):[];
      for(const o of (Array.isArray(arr)?arr:[]).slice(0,6)){
        try{ await hubApi('/compat',{method:'POST',body:JSON.stringify({product:brand,product_version:e.v,os:o.os||'',os_version:o.os_version||'',supported:o.supported||'',eos_date:o.eos_date||'',eol_date:o.eol_date||'',note:o.note||'',source:e.sysreq||('AI 수집 · '+aiModelLabel(LAST_AI_MODEL))})}); total++; }catch(_){}
      }
    }catch(_){}
  }
  if(st)st.textContent=`완료 — ${total}건 초안 등록. 호환성 매트릭스에서 검토·확정하세요.`;
  if(btn){btn.disabled=false;btn.textContent='🧩 호환성 매트릭스 수집 (DLP·SEP)';}
  toast(`매트릭스 ${total}건 초안 수집 완료`);
  if(typeof loadCompat==='function')loadCompat();
}
async function importKBSeed(){
  if(!confirm(`총 ${KB_SEED.length}개 KB 링크를 업무 링크에 등록합니다.\n기존 링크와 중복되는 것은 별도 체크하지 않습니다.\n\n계속하시겠어요?`))return;
  const btn=document.getElementById('kb-seed-btn');
  btn.disabled=true;
  let ok=0,fail=0;
  for(const item of KB_SEED){
    try{
      const r=await fetch(`${WORKERS}/links`,{
        method:'POST',
        headers:authHeaders({'Content-Type':'application/json'}),
        body:JSON.stringify({title:item.title,url:item.url,category:item.category,desc:item.desc})
      });
      const d=await r.json();
      if(d.ok)ok++;else fail++;
    }catch{fail++;}
    btn.textContent=`등록 중... (${ok+fail}/${KB_SEED.length})`;
    await new Promise(r=>setTimeout(r,120)); // rate limit 방지
  }
  btn.disabled=false;
  btn.textContent=`📥 KB 초기 데이터 가져오기 (${KB_SEED.length}건)`;
  toast(`완료: 성공 ${ok}건 / 실패 ${fail}건`);
  setAdminActionStatus(`KB 초기 데이터 등록 완료: 성공 ${ok}건 / 실패 ${fail}건`,fail?'info':'ok');
  await loadLinks();
  if(document.getElementById('page-links').classList.contains('active'))renderLinks();
}

// ── 저장소 관리 ───────────────────────────────────
function fmtBytes(n){
  n=Number(n||0);
  if(n<1024)return `${n} B`;
  if(n<1024*1024)return `${(n/1024).toFixed(1)} KB`;
  return `${(n/1024/1024).toFixed(2)} MB`;
}