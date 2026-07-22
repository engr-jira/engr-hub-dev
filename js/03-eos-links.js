
function renderEosList(){
  const q=(document.getElementById('eos-q')||{}).value?.toLowerCase()||'';
  let list=[...EOS_ITEMS];
  if(q)list=list.filter(it=>[it.customer,it.productDesc,it.product,it.siteId,it.serial].some(v=>(v||'').toString().toLowerCase().includes(q)));
  list.sort((a,b)=>{
    const da=a.expireDate?new Date(a.expireDate).getTime():Infinity;
    const db=b.expireDate?new Date(b.expireDate).getTime():Infinity;
    return da-db;
  });
  const pageList=sliceForPage(list,'eos');
  document.getElementById('eos-count').textContent=pageCountText('eos',list.length);
  const tbody=document.getElementById('eos-tbody');
  if(!pageList.length){tbody.innerHTML=`<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text3)">등록된 라이선스가 없습니다</td></tr>`;renderPager('eos-pager','eos',list.length,'renderEosList');return;}
  tbody.innerHTML=pageList.map(it=>{
    const hasEnd=!!it.expireDate;
    const days=hasEnd?daysUntil(it.expireDate):null;
    let rowClass='',badgeBg='rgba(148,163,184,.15)',badgeColor='var(--text3)',badgeText='—';
    if(hasEnd){
      const wd=(typeof EOS_WARN_DAYS!=='undefined'&&EOS_WARN_DAYS.length?[...EOS_WARN_DAYS].map(Number).filter(n=>n>0).sort((a,b)=>a-b):[7,30,60]);
      const w0=wd[0]||7, w1=wd[1]||w0, w2=wd[2]||w1;
      if(days<0){rowClass='eos-warn';badgeBg='rgba(248,113,113,.2)';badgeColor='#f87171';badgeText='만료';}
      else if(days<=w0){rowClass='eos-warn';badgeBg='rgba(248,113,113,.2)';badgeColor='#f87171';badgeText='D-'+days;}
      else if(days<=w1){rowClass='eos-warn-near';badgeBg='rgba(251,191,36,.2)';badgeColor='#fbbf24';badgeText='D-'+days;}
      else if(days<=w2){badgeBg='rgba(251,191,36,.12)';badgeColor='#fbbf24';badgeText='D-'+days;}
      else {badgeBg='rgba(34,211,165,.15)';badgeColor='#22d3a5';badgeText='D-'+days;}
    }
    const pd=it.productDesc||it.product||'-';
    const period=[it.startDate,it.expireDate].filter(Boolean).join(' ~ ')||'-';
    return `<tr class="${rowClass}" onclick="openEosDetailModal('${it.id}')" style="cursor:pointer">
      <td onclick="event.stopPropagation()"><input type="checkbox" class="eos-pick" data-id="${it.id}"></td>
      <td style="font-weight:700">${escapeHtml(it.customer||'-')}</td>
      <td>${escapeHtml(pd)}</td>
      <td style="color:var(--text2)">${escapeHtml(it.siteId||'-')}</td>
      <td style="text-align:right" data-sort="${parseInt(String(it.quantity).replace(/[^0-9]/g,''))||0}">${escapeHtml(String(it.quantity||'-'))}</td>
      <td style="font-family:'Consolas',monospace;font-size:11px">${escapeHtml(it.serial||'-')}</td>
      <td style="font-size:11px;color:var(--text2);white-space:nowrap" data-sort="${escapeHtml(it.startDate||'')}">${escapeHtml(period)}</td>
      <td data-sort="${hasEnd?days:99999}"><span class="eos-day-badge" style="background:${badgeBg};color:${badgeColor}">${badgeText}</span></td>
      <td style="white-space:nowrap">
        <button onclick="event.stopPropagation();openEosEditModal('${it.id}')" style="background:none;border:1px solid var(--border2);border-radius:6px;color:var(--text3);cursor:pointer;font-size:11px;padding:3px 8px;font-family:inherit;margin-right:4px">✎ 수정</button>
        <button onclick="event.stopPropagation();deleteEos('${it.id}')" style="background:none;border:none;color:var(--danger);cursor:pointer;font-size:14px">×</button>
      </td>
    </tr>`;
  }).join('');
  renderPager('eos-pager','eos',list.length,'renderEosList');
}
function openEosDetailModal(id){
  const it=EOS_ITEMS.find(x=>x.id===id);
  if(!it){toast('항목을 찾을 수 없습니다',true);return;}
  const hasEnd=!!it.expireDate;
  const d=hasEnd?daysUntil(it.expireDate):null;
  const color=!hasEnd?'var(--text3)':d<0?'#f87171':d<=30?'#fbbf24':'#22d3a5';
  const pd=it.productDesc||it.product||'-';
  openGenModal('라이선스 상세',`
  <div class="rp-meta">
    <div class="rp-row"><span>고객사</span><span>${escapeHtml(it.customer||'-')}</span></div>
    <div class="rp-row"><span>Product Description</span><span>${escapeHtml(pd)}</span></div>
    <div class="rp-row"><span>Enterprise Site ID</span><span>${escapeHtml(it.siteId||'-')}</span></div>
    <div class="rp-row"><span>Quantity</span><span>${escapeHtml(String(it.quantity||'-'))}</span></div>
    <div class="rp-row"><span>Serial Number</span><span>${escapeHtml(it.serial||'-')}</span></div>
    <div class="rp-row"><span>Start Date</span><span>${escapeHtml(it.startDate||'-')}</span></div>
    <div class="rp-row"><span>End Date</span><span>${escapeHtml(it.expireDate||'-')}</span></div>
    <div class="rp-row"><span>D-Day</span><span style="color:${color};font-weight:900">${!hasEnd?'-':d<0?'만료':`D-${d}`}</span></div>
    <div class="rp-row"><span>등록</span><span>${escapeHtml(it.createdBy||'-')} · ${fd(it.createdAt)}</span></div>
  </div>
  ${it.memo?`<div class="rp-desc" style="margin-top:12px">${escapeHtml(it.memo)}</div>`:''}`,
  `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">닫기</button>
   <button class="btn btn-indigo" onclick="openEosEditModal('${id}')" style="width:auto;padding:8px 18px">수정</button>`);
}
function openEosModal(){
  openGenModal('고객사 라이선스 등록',`
  <div class="modal-form">
    <div class="full"><label>고객사 *</label><input id="eos-form-customer" placeholder="고객사명" list="customer-list"></div>
    <div class="full">
      <label>라이선스 항목 <span style="text-transform:none;color:var(--text3);font-weight:400">— 사진의 한 줄 = 한 항목. 여러 개면 아래에서 추가</span></label>
      <div id="eos-lines"></div>
      <button type="button" class="btn btn-ghost" onclick="addEosLine()" style="width:auto;padding:7px 14px;font-size:12px;margin-top:6px">+ 라이선스 추가</button>
    </div>
    <div class="full"><label>메모 <span style="text-transform:none;color:var(--text3);font-weight:400">(공통 · 선택)</span></label><textarea id="eos-form-memo" placeholder="비고"></textarea></div>
  </div>`,
  `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">취소</button>
   <button class="btn btn-indigo" onclick="saveEos()" style="width:auto;padding:8px 18px">저장</button>`);
  addEosLine();
}
function addEosLine(){
  const wrap=document.getElementById('eos-lines'); if(!wrap)return;
  const row=document.createElement('div'); row.className='eos-lic';
  row.innerHTML='<button type="button" class="eos-lic-rm" title="이 항목 삭제">×</button>'
    +'<input class="el-desc" placeholder="Product Description *" title="제품 설명">'
    +'<div class="eos-lic-grid"><input class="el-site" placeholder="Enterprise Site ID"><input class="el-qty" type="number" placeholder="수량"><input class="el-serial" placeholder="Serial Number"></div>'
    +'<div class="eos-lic-dates">'
      +'<label>START DATE<span class="el-date-wrap"><input type="date" class="el-start" data-date-button="1"><button type="button" class="el-cal" tabindex="-1" title="달력 열기">📅</button></span></label>'
      +'<label>END DATE (만료)<span class="el-date-wrap"><input type="date" class="el-end" data-date-button="1"><button type="button" class="el-cal" tabindex="-1" title="달력 열기">📅</button></span></label>'
    +'</div>';
  row.querySelector('.eos-lic-rm').addEventListener('click',()=>{ row.remove(); if(!wrap.children.length)addEosLine(); });
  row.querySelectorAll('.el-cal').forEach(b=>b.addEventListener('click',()=>{ const i=b.previousElementSibling; try{ i.showPicker?i.showPicker():i.focus(); }catch(_){ i.focus(); } }));
  wrap.appendChild(row);
  const f=row.querySelector('.el-desc'); if(f)setTimeout(()=>f.focus(),0);
}
window.addEosLine=addEosLine;
async function saveEos(){
  const customer=document.getElementById('eos-form-customer').value.trim();
  const memo=document.getElementById('eos-form-memo').value.trim();
  if(!customer){toast('고객사는 필수입니다',true);return;}
  const blocks=[...document.querySelectorAll('#eos-lines .eos-lic')].map(b=>({
    productDesc:(b.querySelector('.el-desc').value||'').trim(),
    siteId:(b.querySelector('.el-site').value||'').trim(),
    quantity:(b.querySelector('.el-qty').value||'').trim(),
    serial:(b.querySelector('.el-serial').value||'').trim(),
    startDate:b.querySelector('.el-start').value,
    expireDate:b.querySelector('.el-end').value
  }));
  const filled=blocks.filter(l=>l.productDesc||l.serial||l.expireDate||l.siteId);
  if(!filled.length){toast('라이선스 항목을 1개 이상 입력하세요',true);return;}
  if(filled.find(l=>!l.productDesc)){toast('Product Description은 필수입니다',true);return;}
  const items=filled.map(l=>({customer,memo,...l}));
  try{
    const r=await fetch(`${WORKERS}/eos/bulk`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({items})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'저장 실패',true);return;}
    toast((d.created>1?d.created+'건 ':'')+'등록 완료');closeGenModal();await loadEOS();renderEosList();
  }catch(e){toast('오류: '+e.message,true);}
}
function openEosEditModal(id){
  const it=EOS_ITEMS.find(x=>x.id===id);
  if(!it){toast('항목을 찾을 수 없습니다',true);return;}
  openGenModal('라이선스 수정',`
  <div class="modal-form">
    <div class="full"><label>고객사 *</label><input id="eos-edit-customer" value="${escapeHtml(it.customer||'')}"></div>
    <div class="full"><label>Product Description *</label><input id="eos-edit-desc" value="${escapeHtml(it.productDesc||it.product||'')}"></div>
    <div><label>Enterprise Site ID</label><input id="eos-edit-site" value="${escapeHtml(it.siteId||'')}"></div>
    <div><label>Quantity</label><input id="eos-edit-qty" type="number" value="${escapeHtml(String(it.quantity||''))}"></div>
    <div class="full"><label>Serial Number</label><input id="eos-edit-serial" value="${escapeHtml(it.serial||'')}"></div>
    <div><label>Start Date</label><input type="date" id="eos-edit-start" value="${it.startDate||''}"></div>
    <div><label>End Date (만료)</label><input type="date" id="eos-edit-end" value="${it.expireDate||''}"></div>
    <div class="full"><label>메모</label><textarea id="eos-edit-memo">${escapeHtml(it.memo||'')}</textarea></div>
  </div>`,
  `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">취소</button>
   <button class="btn btn-indigo" onclick="updateEos('${id}')" style="width:auto;padding:8px 18px">저장</button>`);
}
async function updateEos(id){
  const customer=document.getElementById('eos-edit-customer').value.trim();
  const productDesc=document.getElementById('eos-edit-desc').value.trim();
  const siteId=document.getElementById('eos-edit-site').value.trim();
  const quantity=document.getElementById('eos-edit-qty').value.trim();
  const serial=document.getElementById('eos-edit-serial').value.trim();
  const startDate=document.getElementById('eos-edit-start').value;
  const expireDate=document.getElementById('eos-edit-end').value;
  const memo=document.getElementById('eos-edit-memo').value.trim();
  if(!customer||!productDesc){toast('고객사와 Product Description은 필수입니다',true);return;}
  try{
    const r=await fetch(`${WORKERS}/eos/${id}`,{method:'PUT',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({customer,productDesc,siteId,quantity,serial,startDate,expireDate,memo})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'수정 실패',true);return;}
    toast('수정 완료');closeGenModal();await loadEOS();renderEosList();
  }catch(e){toast('오류: '+e.message,true);}
}
async function deleteEos(id){
  if(!confirm('삭제하시겠어요?'))return;
  try{
    const r=await fetch(`${WORKERS}/eos/${id}`,{method:'DELETE',headers:authHeaders()});
    const d=await r.json();
    if(!d.ok){toast(d.message||'실패',true);return;}
    toast('삭제됨');await loadEOS();renderEosList();
  }catch(e){toast('오류: '+e.message,true);}
}

// ── LINKS ─────────────────────────────────────────
async function loadLinks(){
  try{
    const r=await fetch(`${WORKERS}/links`,{headers:authHeaders()});
    const d=await r.json();
    LINKS=d.links||[];
  }catch{}
}
function renderCommentFeed(containerId, kind, items){
  const el=document.getElementById(containerId);
  if(!el)return;
  const rows=(items||[]).flatMap(item=>(item.comments||[]).map(c=>({
    kind,
    itemId:item.id,
    itemTitle:item.title||'(제목 없음)',
    itemMeta:kind==='links'?(item.category||item.cat||'업무 링크'):[item.product,item.category].filter(Boolean).join(' · '),
    text:c.text||'',
    createdBy:c.createdBy||'-',
    createdAt:c.createdAt||item.updatedAt||item.createdAt||''
  }))).sort((a,b)=>new Date(b.createdAt||0)-new Date(a.createdAt||0)).slice(0,5);
  if(!rows.length){
    el.classList.remove('show');
    el.innerHTML='';
    return;
  }
  const title=kind==='links'?'업무 링크 최근 댓글':'팀 노하우 최근 댓글';
  const openFn=kind==='links'?'openLinkDetail':'openKnowledgeDetail';
  el.classList.add('show');
  el.innerHTML=`<div class="comment-feed-head"><span>💬 ${title}</span><span>최근 ${rows.length}건</span></div>
    <div class="comment-feed-list">${rows.map(r=>`<div class="comment-feed-item" onclick="${openFn}(${jsAttr(r.itemId)})">
      <div class="comment-feed-title">${escapeHtml(r.itemTitle)}</div>
      <div class="comment-feed-meta">${escapeHtml(r.createdBy)} · ${fdt(r.createdAt)} · ${escapeHtml(r.itemMeta||'-')}</div>
      <div class="comment-feed-text">${escapeHtml(r.text)}</div>
    </div>`).join('')}</div>`;
}
function renderLinks(){
  renderCommentFeed('links-comment-feed','links',LINKS);
  const catSel=document.getElementById('links-cat');
  if(catSel){
    const cur=catSel.value;
    const opts=[...new Set(LINKS.map(l=>l.category||l.cat).filter(Boolean))].sort();
    catSel.innerHTML='<option value="">전체 분류</option>'+opts.map(c=>`<option ${c===cur?"selected":""}>${escapeHtml(c)}</option>`).join('');
  }
  const q=(document.getElementById('links-q')||{}).value?.toLowerCase()||'';
  const cat=(document.getElementById('links-cat')||{}).value||'';
  const list=LINKS.filter(l=>{
    const itemCat=l.category||l.cat||'';
    const txt=[l.title,l.desc,l.url,itemCat,l.createdBy,(l.comments||[]).map(c=>c.text).join(' ')].join(' ').toLowerCase();
    return (!cat||itemCat===cat)&&(!q||txt.includes(q));
  });
  const pageLinks=sliceForPage(list,'links');
  const cnt=document.getElementById('links-count');if(cnt)cnt.textContent=pageCountText('links',list.length);
  const wrap=document.getElementById('links-grid');
  if(!pageLinks.length){wrap.innerHTML=`<div style="text-align:center;padding:40px;color:var(--text3);font-size:13px">등록된 링크가 없거나 조건에 맞는 링크가 없습니다</div>`;renderPager('links-pager','links',list.length,'renderLinks');return;}
  wrap.innerHTML=pageLinks.map(l=>{
    const commentCount=(l.comments||[]).length;
    const cat=escapeHtml(l.category||l.cat||'기타');
    const title=escapeHtml(l.title||'');
    const url=escapeHtml(l.url||'');
    const meta=`by ${escapeHtml(l.createdBy||'-')}${l.createdAt?' · '+fd(l.createdAt):''}`;
    const canEdit=(l.createdBy===CURRENT_USER||IS_ADMIN||IS_SUPER);
    return `<div class="link-card" style="position:relative" onclick="window.open('${escapeHtml(normalizeExternalUrl(l.url))}','_blank')">${canEdit?`<input type="checkbox" class="lnk-pick" data-id="${escapeAttr(l.id)}" onclick="event.stopPropagation()" style="position:absolute;top:7px;left:7px;z-index:3;width:15px;height:15px;cursor:pointer">`:''}<span class="link-cat">${cat}</span><div class="link-info"><div class="link-title">${title}</div><div class="link-meta">${meta}</div></div>${l.desc?`<div class="link-desc">${escapeHtml(l.desc)}</div>`:''}<div class="link-url">${url}</div><div class="link-actions" style="flex-shrink:0;display:flex;gap:4px;opacity:0;transition:opacity .15s"><button onclick="event.stopPropagation();openLinkDetail('${escapeAttr(l.id)}')" style="background:var(--card2);border:1px solid var(--border2);border-radius:6px;color:var(--text3);cursor:pointer;font-size:10px;padding:2px 8px;font-family:inherit">댓글 ${commentCount}</button>${canEdit?`<button onclick="event.stopPropagation();openLinkEditModal('${escapeAttr(l.id)}')" style="background:var(--card2);border:1px solid var(--border2);border-radius:6px;color:var(--text3);cursor:pointer;font-size:10px;padding:2px 8px;font-family:inherit">✎</button><button onclick="event.stopPropagation();deleteLink('${escapeAttr(l.id)}')" style="background:var(--card2);border:1px solid var(--border2);border-radius:6px;color:var(--danger);cursor:pointer;font-size:12px;padding:2px 7px;font-family:inherit">×</button>`:''}</div></div>`;
  }).join('');
  renderPager('links-pager','links',list.length,'renderLinks');
}

function itemCommentsHtml(kind,item){
  const comments=item.comments||[];
  const title=kind==='links'?'링크 의견':'노하우 의견';
  const rows=comments.length?comments.map(c=>{
    const canDelete=IS_ADMIN||c.createdBy===CURRENT_USER;
    return `<div class="item-comment">
      <div class="item-comment-meta"><span>${escapeHtml(c.createdBy||'-')} · ${fdt(c.createdAt)}</span>${canDelete?`<button class="item-comment-del" onclick="deleteItemComment('${kind}','${escapeHtml(item.id)}','${escapeHtml(c.id)}')">×</button>`:''}</div>
      <div class="item-comment-body">${escapeHtml(c.text||'')}</div>
    </div>`;
  }).join(''):`<div style="font-size:12px;color:var(--text3);padding:10px 0">아직 댓글이 없습니다.</div>`;
  return `<div class="item-comments">
    <h4>${title} (${comments.length})</h4>
    ${rows}
    <div class="item-comment-form">
      <textarea id="${kind}-comment-text-${escapeHtml(item.id)}" class="admin-textarea" placeholder="의견, 보완할 점, 참고 내용을 남겨주세요"></textarea>
      <button class="btn btn-indigo" onclick="addItemComment('${kind}','${escapeHtml(item.id)}')" style="width:auto;padding:8px 16px">댓글</button>
    </div>
  </div>`;
}
function openLinkDetail(id){
  const l=LINKS.find(x=>x.id===id);
  if(!l){toast('링크를 찾을 수 없습니다',true);return;}
  const href=normalizeExternalUrl(l.url||'');
  openGenModal(l.title||'업무 링크 상세',`
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
      <span class="link-cat">${escapeHtml(l.category||l.cat||'기타')}</span>
    </div>
    ${l.desc?`<div style="font-size:13px;color:var(--text2);line-height:1.7;white-space:pre-wrap;margin-bottom:12px">${escapeHtml(l.desc)}</div>`:''}
    <div class="link-url" style="margin-bottom:10px">${escapeHtml(l.url||'')}</div>
    <div style="font-size:10px;color:var(--text3);margin-bottom:12px">${escapeHtml(l.createdBy||'-')} · ${l.updatedAt?'수정 '+fd(l.updatedAt):fd(l.createdAt)}</div>
    ${itemCommentsHtml('links',l)}`,
    `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none"><button class="btn btn-ghost" style="width:auto;padding:8px 18px">열기 →</button></a>
     <button class="btn btn-indigo" onclick="openLinkEditModal('${id}')" style="width:auto;padding:8px 18px">수정</button>
     <button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">닫기</button>`);
}
async function addItemComment(kind,id){
  const text=document.getElementById(`${kind}-comment-text-${id}`)?.value.trim()||'';
  if(!text){toast('댓글 내용을 입력하세요',true);return;}
  const base=kind==='links'?'links':'knowledge';
  try{
    const d=await hubApi(`/${base}/${encodeURIComponent(id)}/comments`,{method:'POST',body:JSON.stringify({text})});
    toast(`댓글 등록 완료`);
    if(base==='links'){await loadLinks();renderLinks();openLinkDetail(id);}
    else{await loadKnowledge();renderKnowledge();openKnowledgeDetail(id);}
    return d;
  }catch(e){toast('댓글 등록 실패: '+e.message,true);}
}
async function deleteItemComment(kind,id,commentId){
  if(!confirm('댓글을 삭제할까요?'))return;
  const base=kind==='links'?'links':'knowledge';
  try{
    await hubApi(`/${base}/${encodeURIComponent(id)}/comments/${encodeURIComponent(commentId)}`,{method:'DELETE'});
    toast('댓글 삭제 완료');
    if(base==='links'){await loadLinks();renderLinks();openLinkDetail(id);}
    else{await loadKnowledge();renderKnowledge();openKnowledgeDetail(id);}
  }catch(e){toast('댓글 삭제 실패: '+e.message,true);}
}

function openLinkModal(){
  if(!CURRENT_USER){toast('로그인이 필요합니다',true);return;}
  openGenModal('업무 링크 등록',`
  <div class="modal-form">
    <div><label>분류</label><input id="link-form-cat" placeholder="예: 모니터링, 매뉴얼" value="기타"></div>
    <div><label>제목 *</label><input id="link-form-title" placeholder="링크 제목"></div>
    <div class="full"><label>URL *</label><input id="link-form-url" placeholder="https://..."></div>
    <div class="full"><label>설명</label><textarea id="link-form-desc" placeholder="설명 (선택)"></textarea></div>
  </div>`,
  `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">취소</button>
   <button class="btn btn-indigo" onclick="saveLink()" style="width:auto;padding:8px 18px">저장</button>`);
}
async function saveLink(){
  const title=document.getElementById('link-form-title').value.trim();
  const url=document.getElementById('link-form-url').value.trim();
  const category=document.getElementById('link-form-cat').value.trim()||'기타';
  const desc=document.getElementById('link-form-desc').value.trim();
  if(!title||!url){toast('제목과 URL은 필수',true);return;}
  if(!url.startsWith('http')){toast('URL은 http로 시작해야 합니다',true);return;}
  try{
    const r=await fetch(`${WORKERS}/links`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({title,url,category,desc})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'저장 실패',true);return;}
    toast('등록됨');closeGenModal();await loadLinks();renderLinks();
  }catch(e){toast('오류: '+e.message,true);}
}
function openLinkEditModal(id){
  const l=LINKS.find(x=>x.id===id);
  if(!l){toast('링크를 찾을 수 없습니다',true);return;}
  openGenModal('업무 링크 수정',`
  <div class="modal-form">
    <div><label>분류</label><input id="link-edit-cat" value="${escapeHtml(l.category||'기타')}"></div>
    <div><label>제목 *</label><input id="link-edit-title" value="${escapeHtml(l.title||'')}"></div>
    <div class="full"><label>URL *</label><input id="link-edit-url" value="${escapeHtml(l.url||'')}"></div>
    <div class="full"><label>설명</label><textarea id="link-edit-desc">${escapeHtml(l.desc||'')}</textarea></div>
  </div>`,
  `<button class="btn btn-ghost" onclick="closeGenModal()" style="width:auto;padding:8px 18px">취소</button>
   <button class="btn btn-indigo" onclick="updateLink('${id}')" style="width:auto;padding:8px 18px">저장</button>`);
}
async function updateLink(id){
  const title=document.getElementById('link-edit-title').value.trim();
  const url=document.getElementById('link-edit-url').value.trim();
  const category=document.getElementById('link-edit-cat').value.trim()||'기타';
  const desc=document.getElementById('link-edit-desc').value.trim();
  if(!title||!url){toast('제목과 URL은 필수',true);return;}
  if(!url.startsWith('http')){toast('URL은 http로 시작해야 합니다',true);return;}
  try{
    const r=await fetch(`${WORKERS}/links/${id}`,{method:'PUT',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({title,url,category,desc})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'수정 실패',true);return;}
    toast('수정 완료');closeGenModal();await loadLinks();renderLinks();
  }catch(e){toast('오류: '+e.message,true);}
}
async function deleteLink(id){
  if(!confirm('삭제하시겠어요?'))return;
  try{
    const r=await fetch(`${WORKERS}/links/${id}`,{method:'DELETE',headers:authHeaders()});
    const d=await r.json();
    if(!d.ok){toast(d.message||'실패',true);return;}
    toast('삭제됨');await loadLinks();renderLinks();
  }catch(e){toast('오류: '+e.message,true);}
}

// ── LOG ANALYZER ──────────────────────────────────
function bindFileUpload(){
  const drop=document.getElementById('log-drop');
  const input=document.getElementById('log-file');
  if(!drop||!input)return;
  input.onchange=e=>handleFiles(e.target.files);
  drop.ondragover=e=>{e.preventDefault();drop.classList.add('drag');};
  drop.ondragleave=()=>drop.classList.remove('drag');
  drop.ondrop=e=>{e.preventDefault();drop.classList.remove('drag');handleFiles(e.dataTransfer.files);};
}
async function handleFiles(files){
  for(const f of files){
    if(f.size>MAX_FILE_SIZE){toast(`${f.name}: 20MB 초과`,true);continue;}
    if(LOG_FILES.find(x=>x.name===f.name)){toast(`${f.name}: 이미 추가됨`,true);continue;}
    const ext=f.name.split('.').pop().toLowerCase();
    if(ext==='zip'){
      try{
        if(typeof JSZip==='undefined'){toast('ZIP 라이브러리 로드 실패. 압축을 풀어 업로드해주세요.',true);continue;}
        const zip=await JSZip.loadAsync(f);
        for(const [name,entry] of Object.entries(zip.files)){
          if(entry.dir)continue;
          if(!/\.(log|txt|csv|xml|json|conf|ini|out|err)$/i.test(name))continue;
          const content=await entry.async('string');
          LOG_FILES.push({name:`${f.name}/${name}`,size:content.length,content:sampleLogContent(content,14000)});
          if(LOG_FILES.length>=20){toast('ZIP 내 파일은 최대 20개까지만 분석에 포함합니다.');break;}
        }
      }catch(e){toast('ZIP 읽기 실패: '+e.message,true);}
    }else{
      try{const content=await f.text();LOG_FILES.push({name:f.name,size:f.size,content:sampleLogContent(content,20000)});}
      catch(e){toast('파일 읽기 실패: '+e.message,true);}
    }
  }
  renderLogFiles();
}
function sampleLogContent(content,limit=12000){
  const s=String(content||'');
  if(s.length<=limit)return s;
  const half=Math.floor((limit-180)/2);
  return `${s.slice(0,half)}\n\n...[중간 ${s.length-limit}자 생략: 파일 끝부분 포함]...\n\n${s.slice(-half)}`;
}
function renderLogFiles(){
  const wrap=document.getElementById('log-file-list');
  if(!LOG_FILES.length){wrap.innerHTML='';return;}
  wrap.innerHTML=LOG_FILES.map((f,idx)=>`<div class="file-item">
    <span class="file-name">📄 ${escapeHtml(f.name)}</span>
    <span class="file-size">${(f.size/1024).toFixed(1)}KB</span>
    <span class="file-del" onclick="event.stopPropagation();removeLogFile(${idx})">✕</span>
  </div>`).join('');
}
function removeLogFile(idx){LOG_FILES.splice(idx,1);renderLogFiles();}
function clearLogInput(){document.getElementById('log-input').value='';const s=document.getElementById('log-symptom');if(s)s.value='';const r=document.getElementById('log-result');if(r)r.innerHTML='';LOG_FILES=[];renderLogFiles();updateLogCharCount();}
function updateLogCharCount(){const t=document.getElementById('log-input');const el=document.getElementById('log-charcount');if(!t||!el)return;const n=t.value.length;el.textContent=n>=10000?`${(n/1000).toFixed(1)}천자`:`${n.toLocaleString()}자`;el.style.color=n>20000?'var(--warn,#fbbf24)':'var(--text3)';}
async function pasteLogFromClipboard(){
  const t=document.getElementById('log-input');if(!t)return;
  try{
    const txt=await navigator.clipboard.readText();
    if(!txt){toast('클립보드가 비어 있습니다.',true);return;}
    t.value=t.value?(t.value.replace(/\s*$/,'')+'\n'+txt):txt;
    updateLogCharCount();toast('클립보드 내용을 붙여넣었습니다.');
    t.focus();
  }catch(e){toast('클립보드 접근 권한이 없습니다. Ctrl+V로 직접 붙여넣어 주세요.',true);t.focus();}
}
function collectLogContent(){
  const t=document.getElementById('log-input').value.trim();
  const f=LOG_FILES.map(x=>`[파일: ${x.name}]\n${x.content}`).join('\n\n');
  return [t,f].filter(Boolean).join('\n\n').slice(0,28000);
}
async function analyzeLogs(){
  const log=collectLogContent();
  const symptom=(document.getElementById('log-symptom')?.value||'').trim();
  const res=document.getElementById('log-result');
  if(!log){toast('로그를 입력하거나 파일을 올려주세요',true);return;}
  const btn=document.getElementById('log-btn');
  btn.disabled=true;btn.textContent='발췌 중...';
  if(res)res.innerHTML='<div class="loading">에러·경고·특이사항 발췌 중...</div>';
  try{
    const raw=await callAI(`당신은 보안/인프라 로그 분석가입니다. 아래 증상과 로그를 보고 (1) 제품·벤더 식별 (2) ERROR/WARN/실패/예외/타임아웃/비정상 등 "특이사항" 라인만 시간순 발췌 (3) 핵심 이슈와 검색 키워드 추출.
${symptom?('증상/제품: '+symptom):'(증상 입력 없음 — 로그로 추정)'}
출력은 아래 JSON "하나만" (그 외 설명/마크다운 금지):
{"product":"구체 제품명(예: Symantec SEP, Windows Server, Oracle DB; 모르면 \\"\\")","vendor":"broadcom|microsoft|oracle|other","excerpt":"발췌 로그 — 시간순, 원문 그대로, 줄바꿈 \\n 포함","issues":[{"level":"error|warn|info","summary":"한국어 한 줄","term":"검색 키워드/에러코드(영문 위주, 5단어 이내)"}]}
벤더 기준: SEP/SEPM/DLP/Endpoint/ProxySG/BlueCoat/Carbon Black/PacketShaper/CASB/Symantec=broadcom · Windows/MSSQL/SQL Server/.NET/AD/IIS/Azure=microsoft · Oracle DB=oracle · 그 외=other.
issues 최대 6개. 특이사항 없으면 issues는 [].

로그:
${log.slice(0,28000)}`,'logx',{size:log.length});
    let data=null;
    try{ const m=raw&&raw.match(/\{[\s\S]*\}/); data=JSON.parse(m?m[0]:raw); }catch(_){}
    if(!data||typeof data.excerpt!=='string'){
      res.innerHTML=`<div class="vt-result"><div class="sec-title">분석 결과</div><pre class="logx-pre">${escapeHtml(raw||'(빈 응답)')}</pre><button class="btn btn-cyan" data-t="${escapeHtml(raw||'')}" onclick="copyText(this.dataset.t)" style="width:auto;padding:8px 16px;margin-top:10px">📋 복사</button></div>`;
    }else{
      res.innerHTML=renderLogResult(data);
    }
  }catch(e){ if(res)res.innerHTML=`<div style="color:var(--danger);padding:16px">오류: ${escapeHtml(e.message)}</div>`; }
  btn.disabled=false;btn.textContent='🔬 에러 발췌 & 링크 찾기';
}
// 제품명을 항상 검색어에 포함(엉뚱한 결과 방지). Google / KB / Broadcom 3종, 해당 없으면 url=null(없음).
function logSearchLinks(term, product, vendor){
  const pt=((product||'').trim()+' '+(term||'')).trim() || (term||'');
  const q=encodeURIComponent(pt);
  const links=[{key:'Google', label:'🔍 Google', url:`https://www.google.com/search?q=${q}`}];
  if(vendor==='microsoft') links.push({key:'KB', label:'📚 MS Learn', url:`https://learn.microsoft.com/search/?terms=${q}`});
  else if(vendor==='broadcom') links.push({key:'KB', label:'📚 KB', url:`https://www.google.com/search?q=${encodeURIComponent(pt+' site:knowledge.broadcom.com')}`});
  else if(vendor==='oracle') links.push({key:'KB', label:'📚 Oracle Docs', url:`https://www.google.com/search?q=${encodeURIComponent(pt+' site:docs.oracle.com')}`});
  else links.push({key:'KB', label:'KB', url:null});
  if(vendor==='broadcom') links.push({key:'Broadcom', label:'🏢 Broadcom', url:`https://support.broadcom.com/web/ecx/search?searchString=${q}`});
  else links.push({key:'Broadcom', label:'Broadcom', url:null});
  return links;
}
function renderLogResult(data){
  const col=l=>l==='error'?'#f87171':l==='warn'?'#fbbf24':'#22d3a5';
  const product=(data.product||'').trim();
  const vendor=data.vendor||'other';
  const excerpt=data.excerpt||'특이사항 없음';
  const issues=Array.isArray(data.issues)?data.issues:[];
  const issuesHtml=issues.map(it=>{
    const links=logSearchLinks(it.term||it.summary||'', product, vendor);
    const rows=links.map(ln=>{
      if(!ln.url) return `<div class="logx-link logx-none">${ln.key} 없음</div>`;
      const title=`[${product||'로그'}] ${(it.term||it.summary||'').slice(0,50)} · ${ln.key}`;
      return `<div class="logx-link"><a href="${ln.url}" target="_blank" rel="noopener">${ln.label}</a><button class="logx-reg" data-title="${escapeHtml(title)}" data-url="${escapeHtml(ln.url)}" onclick="registerLogLink(this.dataset.title,this.dataset.url,this)" title="업무 링크에 등록">➕</button></div>`;
    }).join('');
    return `<div class="logx-issue">
      <div class="logx-issue-head"><span class="badge" style="background:${col(it.level)}22;color:${col(it.level)}">${String(it.level||'info').toUpperCase()}</span><span class="logx-sum">${escapeHtml(it.summary||it.term||'')}</span></div>
      ${it.term?`<div class="logx-term">${escapeHtml(it.term)}</div>`:''}
      <div class="logx-links">${rows}</div>
    </div>`;
  }).join('');
  const prodLabel=product?`<span style="font-weight:400;color:var(--text3);font-size:11px">— 제품: ${escapeHtml(product)}</span>`:'<span style="font-weight:400;color:var(--warn,#fbbf24);font-size:11px">— 제품 미상(증상에 제품명을 적으면 정확해져요)</span>';
  return `<div class="vt-result">
    <div class="sec-title" style="display:flex;justify-content:space-between;align-items:center;gap:8px">📋 발췌된 로그 (시간순)<button class="btn btn-cyan" data-t="${escapeHtml(excerpt)}" onclick="copyText(this.dataset.t)" style="width:auto;padding:6px 14px;font-size:11px">📋 복사</button></div>
    <pre class="logx-pre">${escapeHtml(excerpt)}</pre>
    ${issues.length?`<div class="sec-title" style="margin-top:16px">🔎 핵심 이슈 & 추천 링크 ${prodLabel}</div>${issuesHtml}`:'<div style="color:var(--text3);font-size:12px;margin-top:10px">추출된 핵심 이슈가 없습니다.</div>'}
  </div>`;
}
async function registerLogLink(title, url, btn){
  if(!url){toast('URL이 없습니다',true);return;}
  try{
    const r=await fetch(`${WORKERS}/links`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({title:String(title).slice(0,120),url,category:'로그분석',desc:'로그 분석에서 등록'})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'등록 실패',true);return;}
    toast('업무 링크에 등록됨 ✓');
    if(btn){btn.textContent='✓ 등록됨';btn.disabled=true;btn.classList.add('done');}
    try{await loadLinks();renderLinks();}catch(_){}
  }catch(e){toast('오류: '+e.message,true);}
}

// ── VIRUSTOTAL ────────────────────────────────────
const VT_HASH_RE=/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
function vtClientType(s){
  s=String(s||'').trim();
  if(VT_HASH_RE.test(s))return 'hash';
  if(/^(\d{1,3}\.){3}\d{1,3}$/.test(s)||/^[0-9a-f:]+:[0-9a-f:]+$/i.test(s))return 'ip';
  if(/^https?:\/\//i.test(s)||s.includes('/'))return 'url';
  if(/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(s))return 'domain';
  return '';
}
const VT_TYPE_LABEL={hash:'파일해시',ip:'IP',domain:'도메인',url:'URL'};
function vtParseHashes(){
  const raw=(document.getElementById('vt-input')?.value||'');
  const toks=raw.split(/[\s,;\n]+/).map(s=>s.trim()).filter(Boolean);
  const seen=new Set(),valid=[],invalid=[];
  toks.forEach(t=>{const ty=vtClientType(t); if(ty){const k=t.toLowerCase(); if(!seen.has(k)){seen.add(k);valid.push({value:t,type:ty});}} else invalid.push(t);});
  return {valid,invalid};
}