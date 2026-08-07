/* ── STEP 6 영업 현황 (신규 모듈) ─────────────────────────────
   원칙: 모든 지표는 규칙 기반(AI 무관) — PC가 꺼져 있어도 영업팀은 100% 동작.
   서버(/sales/overview)가 집계·제목만 반환하며 이슈 본문·코멘트는 오지 않는다. */

let SALES_DATA=null, SALES_LOADING=false;
const SALES_STATUS=['미착수','협의중','견적발송','계약완료','실패'];
const SALES_STATUS_COLOR={'미착수':'#A2917A','협의중':'#E0A32E','견적발송':'#3FBE92','계약완료':'#3FBE92','실패':'#E06A63'};

function salesNoteKey(c,p){return String(c||'')+'||'+String(p||'').slice(0,120);}  // 서버가 product를 120자 절단 저장 — 키 규칙 일치 필수

async function loadSalesOverview(force){
  if(SALES_LOADING)return;
  if(SALES_DATA&&!force){renderSalesPage();return;}
  SALES_LOADING=true;
  const wrap=document.getElementById('sales-body');
  if(wrap&&!SALES_DATA)wrap.innerHTML='<div class="loading">영업 현황 집계 중...</div>';
  try{
    const d=await hubApi('/sales/overview');
    SALES_DATA=d;
    renderSalesPage();
  }catch(e){
    if(wrap)wrap.innerHTML=`<div class="u-err-12">집계 실패: ${escapeHtml(e.message)}</div>`;
  }finally{SALES_LOADING=false;}
}

function salesRenewalRows(d){
  const notes=new Map((d.notes||[]).map(n=>[salesNoteKey(n.customer,n.product),n]));
  const rows=(d.eos||[]).filter(e=>e.expireDate||e.perpetual).map(e=>{
    const prod=e.productDesc||e.product||'';
    const perp=!!e.perpetual;
    const dd=perp?Infinity:daysUntil(e.expireDate);   // Perpetual은 항상 맨 뒤 + KPI(만료임박·경과)에서 자동 제외
    return {customer:e.customer||'-',product:prod,expire:perp?'Perpetual':e.expireDate,dd,perp,
      note:notes.get(salesNoteKey(e.customer,prod))||null};
  });
  rows.sort((a,b)=>a.dd-b.dd);
  return rows;
}

// ── 영업 현황 필터 ─────────────────────────────────────────────────────────
// 두 섹션은 데이터가 달라(라이선스 vs 이슈) 필터를 완전히 분리한다.
// SALES_FILTER = 🔑 갱신 기회 전용 / SALES_CFILTER = 🏢 고객사 대응 현황 전용.
let SALES_FILTER={q:'',owner:'',status:'',exp:''};
let __salesQT=null, __custQT=null;
function salesMyName(){
  const uid=(typeof CURRENT_USER!=='undefined')?CURRENT_USER:'';
  if(!uid)return '';
  try{
    if(typeof HUB_USERS!=='undefined'&&HUB_USERS){
      const arr=Array.isArray(HUB_USERS)?HUB_USERS:Object.values(HUB_USERS);
      const m=arr.find(u=>u&&u.id===uid); if(m&&m.displayName)return m.displayName;
    }
  }catch(_){}
  try{ const m=window.__userMap; if(m&&m[uid])return m[uid]; }catch(_){}
  return '';
}
function salesOwnerName(cust){ return (typeof salesOwnerOf==='function'?(salesOwnerOf(cust)||''):''); }
function ownerPass(sel,cust){
  if(!sel)return true;
  const o=salesOwnerName(cust);
  if(sel==='__me__'){ const me=salesMyName(); return !!me&&o===me; }
  return o===sel;
}
function qPass(q,fields){
  const s=String(q||'').trim().toLowerCase(); if(!s)return true;
  if(typeof qMatch==='function')return qMatch(s,fields);
  return fields.filter(Boolean).join(' ').toLowerCase().includes(s);
}
function salesRowPass(r){
  if(!qPass(SALES_FILTER.q,[r.customer,r.product]))return false;
  if(!ownerPass(SALES_FILTER.owner,r.customer))return false;
  if(SALES_FILTER.status&&String((r.note&&r.note.status)||'미착수')!==SALES_FILTER.status)return false;
  const e=SALES_FILTER.exp;
  if(e){
    if(e==='perp')return !!r.perp;
    if(r.perp)return false;
    if(e==='past')return r.dd<0;
    if(e==='d90')return r.dd>=0&&r.dd<=90;
    if(e==='d365')return r.dd>=0&&r.dd<=365;
  }
  return true;
}
function salesFilterActive(){ return !!(SALES_FILTER.q||SALES_FILTER.owner||SALES_FILTER.status||SALES_FILTER.exp); }

// ── 🏢 고객사 대응 현황 전용 필터 ──
let SALES_CFILTER={q:'',owner:'',state:'',overdueOnly:false,sort:'name'};
const CUST_STATES=[['','대응 상태 — 전체'],['active','활발'],['warn','주의'],['stale','정체'],['none','이슈 없음']];
const CUST_SORTS=[['name','이름순'],['stale','정체 오래된순'],['overdue','기한초과 많은순'],['open','진행 많은순']];
function custStatePass(x){
  const f=SALES_CFILTER;
  if(!qPass(f.q,[x.c.name]))return false;
  if(!ownerPass(f.owner,x.c.name))return false;
  if(f.state&&x.state!==f.state)return false;
  if(f.overdueOnly&&!((x.c.overdue||0)>0))return false;
  return true;
}
function custSortFn(k){
  const byName=(a,b)=>(a.c.name||'').localeCompare(b.c.name||'','ko');
  if(k==='stale')return (a,b)=>(a.noAct?1:0)-(b.noAct?1:0)||b.days-a.days||byName(a,b);   // 이슈 없음은 뒤로
  if(k==='overdue')return (a,b)=>(b.c.overdue||0)-(a.c.overdue||0)||byName(a,b);
  if(k==='open')return (a,b)=>(b.c.open||0)-(a.c.open||0)||byName(a,b);
  return byName;
}
function salesCustFilterActive(){ const f=SALES_CFILTER; return !!(f.q||f.owner||f.state||f.overdueOnly); }
function onSalesFilterQ(el){ SALES_FILTER.q=el.value; clearTimeout(__salesQT); __salesQT=setTimeout(()=>renderSalesBodies(),180); }
function onCustFilterQ(el){ SALES_CFILTER.q=el.value; clearTimeout(__custQT); __custQT=setTimeout(()=>renderSalesBodies(),180); }
function setSalesFilter(k,v){ SALES_FILTER[k]=v; renderSalesBodies(); }
function setCustFilter(k,v){ SALES_CFILTER[k]=v; renderSalesBodies(); }
function resetSalesFilter(){
  SALES_FILTER={q:'',owner:'',status:'',exp:''};
  ['rn-q','rn-owner','rn-status','rn-exp'].forEach(id=>{ const e=document.getElementById(id); if(e)e.value=''; });
  renderSalesBodies();
}
function resetCustFilter(){
  SALES_CFILTER={q:'',owner:'',state:'',overdueOnly:false,sort:'name'};
  ['ct-q','ct-owner','ct-state'].forEach(id=>{ const e=document.getElementById(id); if(e)e.value=''; });
  const s=document.getElementById('ct-sort'); if(s)s.value='name';
  const o=document.getElementById('ct-over'); if(o)o.checked=false;
  renderSalesBodies();
}
window.onSalesFilterQ=onSalesFilterQ; window.onCustFilterQ=onCustFilterQ;
window.setSalesFilter=setSalesFilter; window.setCustFilter=setCustFilter;
window.resetSalesFilter=resetSalesFilter; window.resetCustFilter=resetCustFilter;

function salesOwnerOptions(names){
  const owners=[...new Set(names.map(salesOwnerName).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'ko'));
  const me=salesMyName();
  return `<option value="">영업 담당 — 전체</option>`
    +(me?`<option value="__me__">👤 내 담당 (${escapeHtml(me)})</option>`:'')
    +owners.map(o=>`<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
}
// 필터 바·검색창은 한 번만 만들고 이후엔 본문(#…-body)만 다시 그린다 — 타이핑 중 포커스 유지
function salesSkeletonHtml(d){
  const eosNames=((d&&d.eos)||[]).map(e=>e.customer||'');
  const custNames=[...(((d&&d.customers)||[]).map(c=>c.name||'')),...((typeof OWNER_ROWS!=='undefined'&&OWNER_ROWS?OWNER_ROWS:[]).map(r=>r.customer||''))];
  const bar='class="panel" style="padding:9px 11px;margin-bottom:10px;display:flex;gap:6px;flex-wrap:wrap;align-items:center"';
  return `<div id="sales-kpi"></div>
  <div class="sec-title" style="margin:0 0 8px">🔑 갱신 기회 — 만료 임박순</div>
  <div id="sales-renew-bar" ${bar}>
    <input id="rn-q" class="admin-input" style="flex:1;min-width:160px;font-size:12px" placeholder="고객사 / 제품 검색..." oninput="onSalesFilterQ(this)">
    <select id="rn-owner" class="admin-input" style="width:auto;font-size:11.5px" onchange="setSalesFilter('owner',this.value)">${salesOwnerOptions(eosNames)}</select>
    <select id="rn-status" class="admin-input" style="width:auto;font-size:11.5px" onchange="setSalesFilter('status',this.value)">
      <option value="">진행 상태 — 전체</option>${SALES_STATUS.map(s=>`<option value="${s}">${s}</option>`).join('')}
    </select>
    <select id="rn-exp" class="admin-input" style="width:auto;font-size:11.5px" onchange="setSalesFilter('exp',this.value)">
      <option value="">만료 — 전체</option><option value="past">만료 경과</option><option value="d90">90일 내</option><option value="d365">1년 내</option><option value="perp">Perpetual</option>
    </select>
    <button class="btn btn-ghost u-btn-xxs" onclick="resetSalesFilter()">초기화</button>
    <span id="rn-note" class="u-muted-10"></span>
  </div>
  <div id="sales-renew-body"></div>

  <div class="sec-title" style="margin:22px 0 8px" id="sales-cust-title">🏢 고객사 대응 현황</div>
  <div id="sales-cust-bar" ${bar}>
    <input id="ct-q" class="admin-input" style="flex:1;min-width:160px;font-size:12px" placeholder="고객사 검색..." oninput="onCustFilterQ(this)">
    <select id="ct-owner" class="admin-input" style="width:auto;font-size:11.5px" onchange="setCustFilter('owner',this.value)">${salesOwnerOptions(custNames)}</select>
    <select id="ct-state" class="admin-input" style="width:auto;font-size:11.5px" onchange="setCustFilter('state',this.value)">
      ${CUST_STATES.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}
    </select>
    <label style="display:inline-flex;align-items:center;gap:5px;font-size:11.5px;color:var(--text2);cursor:pointer">
      <input type="checkbox" id="ct-over" onchange="setCustFilter('overdueOnly',this.checked)"> 기한초과만
    </label>
    <select id="ct-sort" class="admin-input" style="width:auto;font-size:11.5px" onchange="setCustFilter('sort',this.value)">
      ${CUST_SORTS.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}
    </select>
    <button class="btn btn-ghost u-btn-xxs" onclick="resetCustFilter()">초기화</button>
    <span id="ct-note" class="u-muted-10"></span>
  </div>
  <div id="sales-cust-body"></div>
  <div id="sales-foot"></div>`;
}

function salesDDayBadge(dd,perp){
  if(perp)return `<span class="badge" style="background:color-mix(in srgb,var(--success) 15%,transparent);color:var(--success)">Perpetual</span>`;
  if(dd<0)return `<span class="badge" style="background:rgba(248,113,113,.15);color:var(--danger)">만료 ${-dd}일 경과</span>`;
  if(dd<=30)return `<span class="badge" style="background:rgba(248,113,113,.12);color:#fb923c">D-${dd}</span>`;
  if(dd<=90)return `<span class="badge" style="background:rgba(251,191,36,.13);color:var(--warn)">D-${dd}</span>`;
  return `<span class="badge" style="background:rgba(63,190,146,.12);color:var(--success)">D-${dd}</span>`;
}

function salesStatusBadge(st){
  const c=SALES_STATUS_COLOR[st]||'#A2917A';
  return `<span class="badge" style="background:${c}22;color:${c}">${escapeHtml(st||'미착수')}</span>`;
}

function renderSalesPage(){
  const wrap=document.getElementById('sales-body');
  if(!wrap)return;
  const d=SALES_DATA;
  if(!d){loadSalesOverview();return;}
  // 골격(필터 바 포함)은 1회만 생성 — 이후 renderSalesBodies가 본문만 교체하므로 검색창 포커스가 유지된다
  if(!document.getElementById('sales-renew-body')) wrap.innerHTML=salesSkeletonHtml(d);
  renderSalesBodies();
}

function renderSalesBodies(){
  const d=SALES_DATA; if(!d)return;
  const renewBox=document.getElementById('sales-renew-body');
  const custBox=document.getElementById('sales-cust-body');
  if(!renewBox||!custBox)return;

  const allRows=salesRenewalRows(d);
  const rows=allRows.filter(salesRowPass);
  const near=rows.filter(r=>r.dd>=0&&r.dd<=90).length;
  const past=rows.filter(r=>r.dd<0).length;
  const canEdit=(typeof USER_ROLE!=='undefined'&&(USER_ROLE==='sales'||USER_ROLE==='admin'||USER_ROLE==='super'));
  const stale=d.staleDays||14;

  const _canonC=n=>typeof canonCustomer==='function'?canonCustomer(n):n;
  const _custBase=(d.customers||[]).filter(c=>c.name&&c.name!=='None');
  const _seenC=new Set(_custBase.map(c=>_canonC(c.name)));
  // #1 담당자 관리에 등록된 전 고객사 포함 — 이슈가 없어도 담당자 정보 노출
  (typeof OWNER_ROWS!=='undefined'&&OWNER_ROWS?OWNER_ROWS:[]).forEach(r=>{const k=_canonC(r.customer);if(r.customer&&!_seenC.has(k)){_custBase.push({name:r.customer,open:0,overdue:0,issues:[],lastActivity:null,_noIssues:true});_seenC.add(k);}});
  // 대응 상태를 먼저 산출해야 상태 필터(활발/주의/정체/이슈없음)를 걸 수 있다
  const custAll=_custBase.map(c=>{
    const days=c.lastActivity?daysSince(c.lastActivity.slice(0,10)):999;
    const noAct=c._noIssues||(!(c.issues&&c.issues.length)&&!c.open);
    const state=noAct?'none':days>=stale?'stale':days>=Math.ceil(stale/2)?'warn':'active';
    return {c,days,noAct,state};
  });
  const custList=custAll.filter(custStatePass).sort(custSortFn(SALES_CFILTER.sort));
  const openTotal=custList.reduce((s,x)=>s+(x.c.open||0),0);

  const rnote=document.getElementById('rn-note');
  if(rnote)rnote.innerHTML=salesFilterActive()?`<span style="color:var(--accent)">${rows.length}/${allRows.length}건</span>`:`${allRows.length}건`;
  const cnote=document.getElementById('ct-note');
  if(cnote)cnote.innerHTML=salesCustFilterActive()?`<span style="color:var(--accent)">${custList.length}/${custAll.length}곳</span>`:`${custAll.length}곳`;
  const ctitle=document.getElementById('sales-cust-title');
  if(ctitle)ctitle.innerHTML=`🏢 고객사 대응 현황 <span class="u-muted-11" style="font-weight:400">— 정체 기준 ${stale}일(관리자 설정)</span>`;

  const kpi=`<div class="kpi-grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:16px">
    <div class="kpi"><div class="kpi-val" style="color:var(--warn)">${near}</div><div class="kpi-label">90일 내 만료</div></div>
    <div class="kpi"><div class="kpi-val" style="color:var(--danger)">${past}</div><div class="kpi-label">만료 경과</div></div>
    <div class="kpi"><div class="kpi-val">${custList.length}</div><div class="kpi-label">대응 중 고객사</div></div>
    <div class="kpi"><div class="kpi-val">${openTotal}</div><div class="kpi-label">진행중 이슈</div></div>
  </div>`;

  const renew=`<div class="panel" style="overflow-x:auto;padding:0">
  <table class="sales-tbl">
    <thead><tr><th>고객사</th><th>제품</th><th>만료</th><th>진행 상태</th><th>영업 메모</th><th>다음 컨택</th>${canEdit?'<th></th>':''}</tr></thead>
    <tbody>${rows.map((r,i)=>{
      const n=r.note||{};
      return `<tr>
        <td class="u-ws-nowrap"><b>${escapeHtml(r.customer)}</b>${(typeof ownerMetaHtml==='function'&&ownerMetaHtml(r.customer))?`<div style="margin-top:3px">${ownerMetaHtml(r.customer)}</div>`:''}</td>
        <td>${escapeHtml(r.product)}</td>
        <td class="u-ws-nowrap">${salesDDayBadge(r.dd,r.perp)}<div class="u-muted-10">${escapeHtml(r.expire)}</div></td>
        <td>${salesStatusBadge(n.status)}</td>
        <td style="max-width:260px">${escapeHtml(n.body||'—')}</td>
        <td class="u-ws-nowrap">${escapeHtml(n.next_contact||'—')}</td>
        ${canEdit?`<td><button class="btn btn-ghost u-btn-xxs" onclick="toggleSalesEdit(${i})">✏️</button></td>`:''}
      </tr>
      ${canEdit?`<tr id="sales-edit-${i}" style="display:none"><td colspan="7" style="background:rgba(239,131,84,.05);padding:10px 12px">
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <select id="se-status-${i}" class="admin-input" style="max-width:130px">${SALES_STATUS.map(s=>`<option${(n.status||'미착수')===s?' selected':''}>${s}</option>`).join('')}</select>
          <input id="se-body-${i}" class="admin-input" style="flex:1;min-width:200px" placeholder="영업 메모" value="${escapeHtml(n.body||'')}">
          <input id="se-next-${i}" type="date" class="admin-input" style="max-width:150px" value="${escapeHtml(n.next_contact||'')}">
          <button class="btn btn-primary u-btn-xs" onclick="saveSalesNoteUI(${i},${jsAttr(r.customer)},${jsAttr(r.product)})">저장</button>
        </div>
      </td></tr>`:''}`;
    }).join('')||`<tr><td colspan="7" class="u-empty">${salesFilterActive()?'조건에 맞는 라이선스가 없습니다':'라이선스 데이터가 없습니다'}</td></tr>`}</tbody>
  </table></div>`;

  const custRows=custList.map(({c,days,noAct})=>{
    const judge = noAct?`<span class="badge" style="background:rgba(148,137,126,.15);color:var(--text3);font-size:11.5px">이슈 없음</span>`
      : days>=stale?`<span class="badge" style="background:rgba(248,113,113,.13);color:var(--danger);font-size:11.5px">정체 ${days}일</span>`
      : days>=Math.ceil(stale/2)?`<span class="badge" style="background:rgba(251,191,36,.13);color:var(--warn);font-size:11.5px">주의</span>`
      : `<span class="badge" style="background:rgba(63,190,146,.12);color:var(--success);font-size:11.5px">활발</span>`;
    const issues=(c.issues||[]).map(i=>{
      const od=i.due&&daysUntil(i.due)<0;
      return `<div style="display:flex;gap:8px;align-items:center;padding:5px 0;border-bottom:1px solid rgba(58,52,59,.35)">
        <span style="color:var(--accent3);font-weight:700;font-size:12px" class="u-ws-nowrap">${escapeHtml(i.key)}</span>
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px">${escapeHtml(i.title)}</span>
        <span class="u-ws-nowrap" style="font-size:11.5px;color:var(--text3)">${escapeHtml(i.status)}</span>
        ${i.due?`<span class="u-ws-nowrap" style="font-size:11px;color:${od?'var(--danger)':'var(--text3)'}">${od?'기한초과 ':''}${escapeHtml(i.due)}</span>`:''}
      </div>`;
    }).join('');
    const top=(c.issues||[])[0];
    return `<details class="sales-cust"><summary style="display:flex;gap:12px;align-items:center;cursor:pointer;padding:11px 14px">
      <b style="min-width:130px;font-size:14px">${escapeHtml(c.name)}</b>
      ${(typeof salesOwnerChip==='function')?salesOwnerChip(c.name):''}
      ${(typeof ownerMetaHtml==='function'&&ownerMetaHtml(c.name))?`<span class="u-ws-nowrap" style="font-size:11px">${ownerMetaHtml(c.name)}</span>`:''}
      <span style="font-size:12.5px;color:var(--text2)" class="u-ws-nowrap">진행 <b>${c.open}</b></span>
      <span class="u-ws-nowrap" style="font-size:12.5px;color:${c.overdue?'var(--danger)':'var(--text3)'}">기한초과 <b>${c.overdue}</b></span>
      <span class="u-ws-nowrap" style="font-size:12.5px;color:var(--text3)">최근 ${days>=999?'—':days===0?'오늘':days+'일 전'}</span>
      ${top?`<span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--text3)">└ ${escapeHtml(top.title)}</span>`:'<span style="flex:1"></span>'}
      <span style="margin-left:auto">${judge}</span>
    </summary><div style="padding:4px 16px 12px">${issues||'<div class="u-muted-11">이슈 없음</div>'}</div></details>`;
  }).join('');

  const cust=`<div class="panel" style="padding:4px 0">${custRows||'<div class="u-empty">'+(salesCustFilterActive()?'조건에 맞는 고객사가 없습니다':'이슈 데이터가 없습니다'+(d.jiraOk?'':' (Jira 조회 실패 — 라이선스만 표시)'))+'</div>'}</div>`;

  const foot=`<div class="u-muted-10" style="margin-top:12px">🕐 ${new Date(d.built_at).toLocaleTimeString('ko-KR',{hour:'2-digit',minute:'2-digit'})} 집계 · 조회 기간 ${d.rangeMonths}개월 · AI 미사용(실시간 규칙 집계)
  <button class="btn btn-ghost u-btn-xxs" style="margin-left:8px" onclick="loadSalesOverview(true)">새로고침</button></div>`;

  const kbox=document.getElementById('sales-kpi'); if(kbox)kbox.innerHTML=kpi;
  renewBox.innerHTML=renew;
  custBox.innerHTML=cust;
  const fbox=document.getElementById('sales-foot'); if(fbox)fbox.innerHTML=foot;
}

function toggleSalesEdit(i){
  const r=document.getElementById('sales-edit-'+i);
  if(r)r.style.display=r.style.display==='none'?'':'none';
}

async function saveSalesNoteUI(i,customer,product){
  try{
    const body={customer,product:String(product).slice(0,120),
      status:document.getElementById('se-status-'+i)?.value||'',
      body:document.getElementById('se-body-'+i)?.value||'',
      next_contact:document.getElementById('se-next-'+i)?.value||''};
    await hubApi('/sales/note',{method:'PUT',body:JSON.stringify(body)});
    toast('영업 메모 저장 완료');
    await loadSalesOverview(true);
  }catch(e){toast('저장 실패: '+e.message,true);}
}

/* 영업 역할 UI: 서버가 이미 차단하지만 화면에서도 허용 메뉴만 노출 */
function applySalesRoleUI(){
  const isSales=(typeof USER_ROLE!=='undefined'&&USER_ROLE==='sales');
  document.body.classList.toggle('is-sales',isSales);
  if(isSales){ try{ showPage('sales',document.getElementById('nav-sales')); }catch(_){} }
}

const enterAppBeforeSales=enterApp;
enterApp=function(){
  const result=enterAppBeforeSales();
  try{ applySalesRoleUI(); }catch(_){}
  return result;
};
