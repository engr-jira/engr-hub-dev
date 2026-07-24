/* ── STEP 6 영업 현황 (신규 모듈) ─────────────────────────────
   원칙: 모든 지표는 규칙 기반(AI 무관) — PC가 꺼져 있어도 영업팀은 100% 동작.
   서버(/sales/overview)가 집계·제목만 반환하며 이슈 본문·코멘트는 오지 않는다. */

let SALES_DATA=null, SALES_LOADING=false;
const SALES_STATUS=['미착수','협의중','견적발송','계약완료','실패'];
const SALES_STATUS_COLOR={'미착수':'#94a3b8','협의중':'#fbbf24','견적발송':'#34d399','계약완료':'#2de6b8','실패':'#f87171'};

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
  const rows=(d.eos||[]).filter(e=>e.expireDate).map(e=>{
    const prod=e.productDesc||e.product||'';
    const dd=daysUntil(e.expireDate);
    return {customer:e.customer||'-',product:prod,expire:e.expireDate,dd,
      note:notes.get(salesNoteKey(e.customer,prod))||null};
  });
  rows.sort((a,b)=>a.dd-b.dd);
  return rows;
}

function salesDDayBadge(dd){
  if(dd<0)return `<span class="badge" style="background:rgba(248,113,113,.15);color:#f87171">만료 ${-dd}일 경과</span>`;
  if(dd<=30)return `<span class="badge" style="background:rgba(248,113,113,.12);color:#fb923c">D-${dd}</span>`;
  if(dd<=90)return `<span class="badge" style="background:rgba(251,191,36,.13);color:#fbbf24">D-${dd}</span>`;
  return `<span class="badge" style="background:rgba(52,211,153,.12);color:#34d399">D-${dd}</span>`;
}

function salesStatusBadge(st){
  const c=SALES_STATUS_COLOR[st]||'#94a3b8';
  return `<span class="badge" style="background:${c}22;color:${c}">${escapeHtml(st||'미착수')}</span>`;
}

function renderSalesPage(){
  const wrap=document.getElementById('sales-body');
  if(!wrap)return;
  const d=SALES_DATA;
  if(!d){loadSalesOverview();return;}

  const rows=salesRenewalRows(d);
  const near=rows.filter(r=>r.dd>=0&&r.dd<=90).length;
  const past=rows.filter(r=>r.dd<0).length;
  const openTotal=(d.customers||[]).reduce((s,c)=>s+c.open,0);
  const canEdit=(typeof USER_ROLE!=='undefined'&&(USER_ROLE==='sales'||USER_ROLE==='admin'||USER_ROLE==='super'));
  const stale=d.staleDays||14;

  const kpi=`<div class="kpi-grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:16px">
    <div class="kpi"><div class="kpi-val" style="color:#fbbf24">${near}</div><div class="kpi-label">90일 내 만료</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#f87171">${past}</div><div class="kpi-label">만료 경과</div></div>
    <div class="kpi"><div class="kpi-val">${(d.customers||[]).length}</div><div class="kpi-label">대응 중 고객사</div></div>
    <div class="kpi"><div class="kpi-val">${openTotal}</div><div class="kpi-label">진행중 이슈</div></div>
  </div>`;

  const renew=`<div class="sec-title">🔑 갱신 기회 — 만료 임박순</div>
  <div class="panel" style="overflow-x:auto;padding:0">
  <table class="sales-tbl">
    <thead><tr><th>고객사</th><th>제품</th><th>만료</th><th>진행 상태</th><th>영업 메모</th><th>다음 컨택</th>${canEdit?'<th></th>':''}</tr></thead>
    <tbody>${rows.map((r,i)=>{
      const n=r.note||{};
      return `<tr>
        <td class="u-ws-nowrap"><b>${escapeHtml(r.customer)}</b></td>
        <td>${escapeHtml(r.product)}</td>
        <td class="u-ws-nowrap">${salesDDayBadge(r.dd)}<div class="u-muted-10">${escapeHtml(r.expire)}</div></td>
        <td>${salesStatusBadge(n.status)}</td>
        <td style="max-width:260px">${escapeHtml(n.body||'—')}</td>
        <td class="u-ws-nowrap">${escapeHtml(n.next_contact||'—')}</td>
        ${canEdit?`<td><button class="btn btn-ghost u-btn-xxs" onclick="toggleSalesEdit(${i})">✏️</button></td>`:''}
      </tr>
      ${canEdit?`<tr id="sales-edit-${i}" style="display:none"><td colspan="7" style="background:rgba(129,140,248,.05);padding:10px 12px">
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <select id="se-status-${i}" class="admin-input" style="max-width:130px">${SALES_STATUS.map(s=>`<option${(n.status||'미착수')===s?' selected':''}>${s}</option>`).join('')}</select>
          <input id="se-body-${i}" class="admin-input" style="flex:1;min-width:200px" placeholder="영업 메모" value="${escapeHtml(n.body||'')}">
          <input id="se-next-${i}" type="date" class="admin-input" style="max-width:150px" value="${escapeHtml(n.next_contact||'')}">
          <button class="btn btn-indigo u-btn-xs" onclick="saveSalesNoteUI(${i},${jsAttr(r.customer)},${jsAttr(r.product)})">저장</button>
        </div>
      </td></tr>`:''}`;
    }).join('')||'<tr><td colspan="7" class="u-empty">라이선스 데이터가 없습니다</td></tr>'}</tbody>
  </table></div>`;

  const custRows=(d.customers||[]).filter(c=>c.name&&c.name!=='None').map(c=>{
    const days=c.lastActivity?daysSince(c.lastActivity.slice(0,10)):999;
    const judge = days>=stale?`<span class="badge" style="background:rgba(248,113,113,.13);color:#f87171;font-size:11.5px">정체 ${days}일</span>`
      : days>=Math.ceil(stale/2)?`<span class="badge" style="background:rgba(251,191,36,.13);color:#fbbf24;font-size:11.5px">주의</span>`
      : `<span class="badge" style="background:rgba(52,211,153,.12);color:#34d399;font-size:11.5px">활발</span>`;
    const issues=(c.issues||[]).map(i=>{
      const od=i.due&&daysUntil(i.due)<0;
      return `<div style="display:flex;gap:8px;align-items:center;padding:5px 0;border-bottom:1px solid rgba(44,55,87,.35)">
        <span style="color:var(--accent3);font-weight:700;font-size:12px" class="u-ws-nowrap">${escapeHtml(i.key)}</span>
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px">${escapeHtml(i.title)}</span>
        <span class="u-ws-nowrap" style="font-size:11.5px;color:var(--text3)">${escapeHtml(i.status)}</span>
        ${i.due?`<span class="u-ws-nowrap" style="font-size:11px;color:${od?'#f87171':'var(--text3)'}">${od?'기한초과 ':''}${escapeHtml(i.due)}</span>`:''}
      </div>`;
    }).join('');
    const top=(c.issues||[])[0];
    return `<details class="sales-cust"><summary style="display:flex;gap:12px;align-items:center;cursor:pointer;padding:11px 14px">
      <b style="min-width:130px;font-size:14px">${escapeHtml(c.name)}</b>
      <span style="font-size:12.5px;color:var(--text2)" class="u-ws-nowrap">진행 <b>${c.open}</b></span>
      <span class="u-ws-nowrap" style="font-size:12.5px;color:${c.overdue?'#f87171':'var(--text3)'}">기한초과 <b>${c.overdue}</b></span>
      <span class="u-ws-nowrap" style="font-size:12.5px;color:var(--text3)">최근 ${days>=999?'—':days===0?'오늘':days+'일 전'}</span>
      ${top?`<span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--text3)">└ ${escapeHtml(top.title)}</span>`:'<span style="flex:1"></span>'}
      <span style="margin-left:auto">${judge}</span>
    </summary><div style="padding:4px 16px 12px">${issues||'<div class="u-muted-11">이슈 없음</div>'}</div></details>`;
  }).join('');

  const cust=`<div class="sec-title" style="margin-top:20px">🏢 고객사 대응 현황 <span class="u-muted-11" style="font-weight:400">— 정체 기준 ${stale}일(관리자 설정)</span></div>
  <div class="panel" style="padding:4px 0">${custRows||'<div class="u-empty">이슈 데이터가 없습니다'+(d.jiraOk?'':' (Jira 조회 실패 — 라이선스만 표시)')+'</div>'}</div>`;

  const foot=`<div class="u-muted-10" style="margin-top:12px">🕐 ${new Date(d.built_at).toLocaleTimeString('ko-KR',{hour:'2-digit',minute:'2-digit'})} 집계 · 조회 기간 ${d.rangeMonths}개월 · AI 미사용(실시간 규칙 집계)
  <button class="btn btn-ghost u-btn-xxs" style="margin-left:8px" onclick="loadSalesOverview(true)">새로고침</button></div>`;

  wrap.innerHTML=kpi+renew+cust+foot;
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
