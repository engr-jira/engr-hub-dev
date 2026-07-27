/* ── 고객사 담당자 관리 (#4 → 확장) ─────────────────────────────
   엑셀(정/부/영업 담당·제품·지원·계약여부) 기반 단일 소스.
   관리 탭에서 편집(제품·지원·정/부/영업담당·계약), 고객사·영업·이슈에 자동 반영.
   담당 인물은 HUB 등록 전체 사용자에서 선택. 조회=전 역할, 수정=관리자. */
let OWNER_MAP=null, OWNER_ROWS=[], HUB_USERS=null;
const OWNER_TEAM_FALLBACK=['이서현','박진표','최시온','박예림','김민지','이효성'];

async function loadCustomerOwners(){
  try{ const d=await hubApi('/customer/owners'); OWNER_ROWS=d.items||[]; OWNER_MAP={}; OWNER_ROWS.forEach(r=>{OWNER_MAP[r.customer]=r;}); }
  catch(_){ OWNER_MAP=OWNER_MAP||{}; }
  try{
    if(((document.querySelector('.page.active')||{}).id)==='page-owners')renderOwners();
    else if(typeof renderCurrent==='function')renderCurrent();
  }catch(_){}
}
// HUB 등록 전체 사용자 (담당 선택용) — 관리자 편집 시 로드
async function loadHubUsers(){
  if(HUB_USERS&&HUB_USERS.length)return HUB_USERS;
  try{
    if(window.__userMap&&Object.keys(window.__userMap).length)
      HUB_USERS=Object.values(window.__userMap).filter(u=>u&&u.active!==false).map(u=>u.displayName||u.id);
  }catch(_){}
  if(!HUB_USERS||!HUB_USERS.length){
    try{ const d=await hubApi('/admin/list'); HUB_USERS=(d.users||[]).filter(u=>u.active!==false).map(u=>u.displayName||u.id); }
    catch(_){ HUB_USERS=null; }
  }
  return (HUB_USERS&&HUB_USERS.length)?HUB_USERS:OWNER_TEAM_FALLBACK;
}

function ownerOf(name){
  if(!OWNER_MAP||!name)return null;
  const c=(typeof canonCustomer==='function'?canonCustomer(name):name);
  return OWNER_MAP[c]||OWNER_MAP[name]||null;
}
// Jira 범주(customfield_10036 → ISSUES[].category)가 영업담당자명. 고객사별 최빈 범주로 자동 도출.
function salesRepFromIssues(name){
  if(typeof ISSUES==='undefined'||!ISSUES||!ISSUES.length||!name)return '';
  const canon=(typeof canonCustomer==='function'?canonCustomer(name):name);
  const counts={};
  for(const i of ISSUES){
    const cat=(i.category||'').trim(); if(!cat||cat==='N/A')continue;
    const custs=(i.customers&&i.customers.length?i.customers:[i.customer]).filter(Boolean);
    if(!custs.some(c=>(typeof canonCustomer==='function'?canonCustomer(c):c)===canon))continue;
    counts[cat]=(counts[cat]||0)+1;
  }
  let best='',bn=0; for(const k in counts)if(counts[k]>bn){bn=counts[k];best=k;}
  return best;
}
// 명시 저장값(관리자 지정) 우선, 없으면 Jira 범주에서 자동 도출
function salesOwnerOf(name){ const o=ownerOf(name); const explicit=o?(o.sales_owner||''):''; return explicit||salesRepFromIssues(name); }
function isOwnerInactive(name){ const o=ownerOf(name); return !!(o&&(o.active===0||o.active===false)); }
// 정/부 담당 배지 (고객사 프로필/영업에 자동 반영)
function ownerMetaHtml(name){
  const o=ownerOf(name); if(!o)return '';
  const inactive=(o.active===0||o.active===false);
  const p=o.primary_owner||'', s=o.secondary_owner||'';
  return `<span class="badge" style="background:var(--accent-soft);color:var(--accent)">정 ${escapeHtml(p||'-')}</span>${s?` <span class="badge" style="background:var(--surface-hover);color:var(--text2)">부 ${escapeHtml(s)}</span>`:''}${inactive?` <span class="badge" style="background:color-mix(in srgb,var(--danger) 15%,transparent);color:var(--danger)">계약종료</span>`:''}`;
}
// #5 고객사명 바로 뒤 영업담당 이름 (칩)
function salesOwnerChip(name){
  const s=salesOwnerOf(name); if(!s)return '';
  return ` <span class="badge" style="background:color-mix(in srgb,var(--cyan) 15%,transparent);color:var(--cyan);font-weight:700" title="영업 담당">${escapeHtml(s)}</span>`;
}

function renderOwners(){
  const wrap=document.getElementById('owners-body'); if(!wrap)return;
  const isAdm=(typeof IS_ADMIN!=='undefined'&&IS_ADMIN)||(typeof IS_SUPER!=='undefined'&&IS_SUPER);
  const q=(document.getElementById('owners-q')?.value||'').trim().toLowerCase();
  let rows=(OWNER_ROWS||[]).slice().sort((a,b)=>(a.customer||'').localeCompare(b.customer||'','ko'));
  if(q)rows=rows.filter(r=>qMatch(q,[r.customer,r.primary_owner,r.secondary_owner,r.sales_owner,r.products]));
  const active=rows.filter(r=>r.active!==0).length, ended=rows.length-active;
  const cnt=document.getElementById('owners-count'); if(cnt)cnt.textContent=`${rows.length}곳 · 계약중 ${active} · 종료 ${ended}`;
  const mint=`background:color-mix(in srgb,var(--success) 14%,transparent);color:var(--success)`;
  const red=`background:color-mix(in srgb,var(--danger) 15%,transparent);color:var(--danger)`;
  if(!rows.length){wrap.innerHTML='<div class="u-empty">담당자 데이터가 없습니다.</div>';return;}
  wrap.innerHTML=`<div class="panel" style="overflow-x:auto;padding:0"><table class="own-tbl">
    <thead><tr><th>고객사</th><th>영업 담당</th><th>제품</th><th>지원</th><th>정 담당</th><th>부 담당</th><th>계약</th>${isAdm?'<th></th>':''}</tr></thead>
    <tbody>${rows.map(r=>{
      const inactive=r.active===0;
      const so=r.sales_owner||salesRepFromIssues(r.customer);
      return `<tr style="${inactive?'opacity:.6':''}">
        <td class="u-ws-nowrap"><b>${escapeHtml(r.customer)}</b></td>
        <td class="u-ws-nowrap">${so?`<span class="badge" style="background:color-mix(in srgb,var(--cyan) 15%,transparent);color:var(--cyan)">${escapeHtml(so)}</span>${!r.sales_owner?' <span class="u-muted-11" title="Jira 범주에서 자동 도출">·자동</span>':''}`:'<span class="u-muted-11">-</span>'}</td>
        <td class="u-muted-11">${escapeHtml(r.products||'-')}</td>
        <td class="u-muted-11">${escapeHtml(r.support||'-')}</td>
        <td>${escapeHtml(r.primary_owner||'-')}</td>
        <td class="u-muted-11">${escapeHtml(r.secondary_owner||'-')}</td>
        <td><span class="badge" style="${inactive?red:mint}">${inactive?'종료':'계약중'}</span></td>
        ${isAdm?`<td class="u-ws-nowrap"><button class="btn btn-ghost u-btn-xxs" onclick="editOwner(${jsAttr(r.customer)})">✏️</button></td>`:''}
      </tr>`;
    }).join('')}</tbody></table></div>`;
}

function personOptions(sel){
  const base=((HUB_USERS&&HUB_USERS.length)?HUB_USERS:OWNER_TEAM_FALLBACK).slice().sort((a,b)=>a.localeCompare(b,'ko'));
  if(sel&&!base.includes(sel))base.unshift(sel);
  return '<option value="">—</option>'+base.map(n=>`<option${n===sel?' selected':''}>${escapeHtml(n)}</option>`).join('');
}
async function editOwner(customer){
  const r=(OWNER_ROWS||[]).find(x=>x.customer===customer); if(!r)return;
  await loadHubUsers();
  const wrap=document.getElementById('owners-body');
  const box=document.getElementById('owner-edit')||document.createElement('div');
  const isNew=!box.id; box.id='owner-edit';
  box.innerHTML=`<div class="panel" style="margin-bottom:12px;padding:14px;border-color:var(--accent-border)">
    <div style="font-weight:700;margin-bottom:10px">✏️ ${escapeHtml(customer)} — 담당자 편집</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;align-items:end">
      <label class="u-muted-10">제품<br><input id="ow-products" class="admin-input" value="${escapeHtml(r.products||'')}" placeholder="예: DLP, SEP"></label>
      <label class="u-muted-10">지원<br><input id="ow-support" class="admin-input" value="${escapeHtml(r.support||'')}" placeholder="예: Onsite / Remote"></label>
      <label class="u-muted-10">영업 담당<br><select id="ow-sales" class="admin-input">${personOptions(r.sales_owner||salesRepFromIssues(customer))}</select></label>
      <label class="u-muted-10">정 담당<br><select id="ow-primary" class="admin-input">${personOptions(r.primary_owner)}</select></label>
      <label class="u-muted-10">부 담당<br><select id="ow-secondary" class="admin-input">${personOptions(r.secondary_owner)}</select></label>
      <label class="u-muted-10">계약 상태<br><select id="ow-active" class="admin-input"><option value="1"${r.active!==0?' selected':''}>계약중</option><option value="0"${r.active===0?' selected':''}>계약 종료</option></select></label>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button class="btn btn-primary u-btn-xs" onclick="saveOwner(${jsAttr(customer)})">저장</button>
      <button class="btn btn-ghost u-btn-xs" onclick="document.getElementById('owner-edit')?.remove()">취소</button>
    </div></div>`;
  if(isNew&&wrap)wrap.parentElement.insertBefore(box,wrap);
  box.scrollIntoView({behavior:'smooth',block:'nearest'});
}
async function saveOwner(customer){
  try{
    await hubApi('/customer/owner',{method:'PUT',body:JSON.stringify({
      customer,
      products:document.getElementById('ow-products')?.value||'',
      support:document.getElementById('ow-support')?.value||'',
      sales_owner:document.getElementById('ow-sales')?.value||'',
      primary:document.getElementById('ow-primary')?.value||'',
      secondary:document.getElementById('ow-secondary')?.value||'',
      active:document.getElementById('ow-active')?.value!=='0'
    })});
    toast('담당자 저장 완료 — 고객사·영업에 자동 반영됩니다');
    document.getElementById('owner-edit')?.remove();
    await loadCustomerOwners();
  }catch(e){toast('저장 실패: '+e.message,true);}
}

/* showPage 래퍼 — 담당자 페이지 렌더 (14-ia 래퍼 이후 로드되어 서브탭 동기화 유지) */
const showPageBeforeOwners=showPage;
showPage=function(name,btn){
  const r=showPageBeforeOwners(name,btn);
  try{ if(name==='owners')renderOwners(); }catch(_){}
  return r;
};
