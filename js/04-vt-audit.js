
function vtUpdateCount(){
  const {valid,invalid}=vtParseHashes();
  const el=document.getElementById('vt-count');
  if(!el)return;
  const by={}; valid.forEach(v=>{by[v.type]=(by[v.type]||0)+1;});
  const parts=Object.entries(by).map(([t,n])=>`${VT_TYPE_LABEL[t]} ${n}`);
  el.textContent=(parts.length?parts.join(' · '):'입력 0')+(invalid.length?` · 형식오류 ${invalid.length}`:'');
}
function vtRiskColor(mal){return mal>=5?'#f87171':mal>=1?'#fbbf24':'#22d3a5';}
async function vtLookupOne(item, noAudit){
  const value=typeof item==='string'?item:item.value;
  try{
    const r=await fetch(`${WORKERS}/vt/lookup`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({value, noAudit:!!noAudit})});
    const d=await r.json();
    if(d.error){const msg=d.error.message||'조회 실패';return {value,hash:value,ok:false,error:msg,notFound:/not\s*found/i.test(msg)};}
    const t=d._type||(typeof item==='object'?item.type:vtClientType(value));
    const attrs=d.data?.attributes||{};
    const stats=attrs.last_analysis_stats||{};
    const total=(stats.malicious||0)+(stats.undetected||0)+(stats.harmless||0)+(stats.suspicious||0);
    const mal=stats.malicious||0;
    const eng=attrs.last_analysis_results||{};
    const detections=Object.entries(eng).filter(([,v])=>v.category==='malicious'||v.category==='suspicious').map(([k,v])=>`${k}: ${v.result||v.category}`);
    let name='-',link='https://www.virustotal.com/',info='';
    if(t==='hash'){name=attrs.meaningful_name||attrs.names?.[0]||'-';info=attrs.type_description||'';link=`https://www.virustotal.com/gui/file/${value.toLowerCase()}`;
      VT_HISTORY=VT_HISTORY.filter(h=>h.hash!==value.toLowerCase());VT_HISTORY.unshift({hash:value.toLowerCase(),mal,total,name,size:attrs.size||0,type:info,user:(typeof CURRENT_USER!=='undefined'?CURRENT_USER:''),ts:Date.now()});if(VT_HISTORY.length>50)VT_HISTORY=VT_HISTORY.slice(0,50);try{localStorage.setItem('vt_history',JSON.stringify(VT_HISTORY));}catch(_){}}
    else if(t==='ip'){name=value;info=[attrs.country,attrs.as_owner].filter(Boolean).join(' · ');link=`https://www.virustotal.com/gui/ip-address/${value}`;}
    else if(t==='domain'){name=value;info=attrs.registrar?('등록기관: '+attrs.registrar):'';link=`https://www.virustotal.com/gui/domain/${value}`;}
    else if(t==='url'){name=attrs.title||attrs.url||value;info=attrs.last_final_url||attrs.url||value;link=d.data?.id?`https://www.virustotal.com/gui/url/${d.data.id}`:'https://www.virustotal.com/';}
    return {value,hash:value,ok:true,vtType:t,mal,total,name,size:attrs.size||0,info,rep:attrs.reputation,stats,attrs,detections,link};
  }catch(e){return {value,hash:value,ok:false,error:e.message};}
}
async function vtLookup(){
  const {valid,invalid}=vtParseHashes();
  const btn=document.getElementById('vt-btn'),res=document.getElementById('vt-result');
  if(!valid.length){toast(invalid.length?'유효한 값이 없습니다 (해시/IP/도메인/URL 확인).':'해시·IP·도메인·URL을 입력하세요.',true);return;}
  const list=valid.slice(0,100);
  if(valid.length>100)toast('한 번에 최대 100개까지 조회합니다.',true);
  btn.disabled=true;
  if(list.length===1){
    btn.textContent='조회 중...';
    res.innerHTML='<div class="loading">VirusTotal 조회 중...</div>';
    const rec=await vtLookupOne(list[0]); renderVTHistory();
    res.innerHTML=rec.ok?renderVtRich(rec):`<div style="color:var(--danger);font-size:12px;padding:16px">${escapeHtml(rec.error)}</div>`;
    btn.disabled=false;btn.textContent='🔍 조회';return;
  }
  const results=[];
  for(let i=0;i<list.length;i++){
    btn.textContent=`조회 중 ${i+1}/${list.length}`;
    res.innerHTML=vtTableHtml(results,list.length,i);
    results.push(await vtLookupOne(list[i], true));   // 개별 감사로그 생략(일괄 1건으로 기록)
    renderVTHistory();
    await new Promise(r=>setTimeout(r,350));
  }
  res.innerHTML=vtTableHtml(results,list.length,list.length);
  btn.disabled=false;btn.textContent='🔍 조회';
  const okN=results.filter(r=>r.ok).length, malN=results.filter(r=>r.ok&&r.mal>0).length;
  try{ await fetch(`${WORKERS}/vt/audit-batch`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({count:list.length,mal:malN})}); }catch(_){}
  toast(`VT 조회 완료: ${okN}/${list.length}건 성공 · 악성/의심 ${malN}건`);
}
function vtFileDrop(e){
  e.preventDefault();
  const el=document.getElementById('vt-file-drop'); if(el)el.classList.remove('drag');
  const f=e.dataTransfer?.files?.[0]; if(f)vtFileScan(f);
}
async function vtFileScan(file){
  if(!file)return;
  const st=document.getElementById('vt-file-status'),res=document.getElementById('vt-result');
  const MAX=32*1024*1024;
  if(file.size>MAX){st.innerHTML=`<span class="u-err-12">파일이 너무 큽니다 (${(file.size/1048576).toFixed(1)}MB · 최대 32MB)</span>`;return;}
  st.innerHTML=`<span class="u-fs12px-ctext2"><span class="spin">⏳</span> 업로드 중… <b>${escapeHtml(file.name)}</b> (${(file.size/1024).toFixed(0)}KB)</span>`;
  try{
    const fd=new FormData(); fd.append('file',file,file.name);
    const up=await fetch(`${WORKERS}/vt/file`,{method:'POST',headers:authHeaders(),body:fd});
    const ud=await up.json();
    if(!up.ok||!ud.analysisId){throw new Error(ud.error?.message||ud.error||'업로드 실패');}
    st.innerHTML=`<span class="u-fs12px-ctext2"><span class="spin">⏳</span> VirusTotal 분석 중… (수십 초 소요될 수 있어요)</span>`;
    let an=null;
    for(let i=0;i<20;i++){
      const ar=await fetch(`${WORKERS}/vt/analysis?id=${encodeURIComponent(ud.analysisId)}`,{headers:authHeaders()});
      const ad=await ar.json();
      const status=ad.data?.attributes?.status;
      if(status==='completed'){an=ad;break;}
      await new Promise(r=>setTimeout(r,3000));
    }
    if(!an){st.innerHTML=`<span style="color:var(--warn,#fbbf24);font-size:12px">분석이 아직 진행 중입니다. 잠시 후 해시로 다시 조회해 주세요.</span>`;return;}
    const at=an.data.attributes||{};
    const stats=at.stats||{};
    const total=(stats.malicious||0)+(stats.undetected||0)+(stats.harmless||0)+(stats.suspicious||0);
    const mal=stats.malicious||0;
    const fi=an.meta?.file_info||{};
    const sha=fi.sha256||fi.sha1||fi.md5||'';
    const eng=at.results||{};
    const detections=Object.entries(eng).filter(([,v])=>v.category==='malicious'||v.category==='suspicious').map(([k,v])=>`${k}: ${v.result||v.category}`);
    const attrs={last_analysis_results:eng,last_analysis_stats:stats,size:fi.size||file.size,type_description:fi.type_description||'',meaningful_name:file.name};
    const rec={value:sha||file.name,hash:sha,ok:true,vtType:'hash',mal,total,name:file.name,size:attrs.size,info:attrs.type_description,stats,attrs,detections,link:sha?`https://www.virustotal.com/gui/file/${sha}`:'https://www.virustotal.com/'};
    st.innerHTML=`<span style="font-size:12px;color:var(--ok,#22d3a5)">✓ 분석 완료 · <b>${escapeHtml(file.name)}</b></span>`;
    res.innerHTML=renderVtRich(rec);
    if(sha){VT_HISTORY=VT_HISTORY.filter(h=>h.hash!==sha.toLowerCase());VT_HISTORY.unshift({hash:sha.toLowerCase(),mal,total,name:file.name,size:attrs.size,type:attrs.type_description,user:(typeof CURRENT_USER!=='undefined'?CURRENT_USER:''),ts:Date.now()});if(VT_HISTORY.length>50)VT_HISTORY=VT_HISTORY.slice(0,50);try{localStorage.setItem('vt_history',JSON.stringify(VT_HISTORY));}catch(_){}renderVTHistory();}
    const fin=document.getElementById('vt-file-input'); if(fin)fin.value='';
  }catch(e){st.innerHTML=`<span class="u-err-12">파일 검사 실패: ${escapeHtml(e.message)}</span>`;}
}
function vtTableHtml(results,total,done){
  window.__vtLastResults=results;
  const ok=results.filter(r=>r.ok);
  const nf=results.filter(r=>!r.ok);
  const okRows=ok.map(r=>{
    const col=vtRiskColor(r.mal),label=r.mal>=5?'악성':r.mal>=1?'의심':'안전';
    const dets=r.detections||[];
    const detShort=dets.length?escapeHtml(dets.slice(0,2).join(' · '))+(dets.length>2?` <span class="u-muted">외 ${dets.length-2}</span>`:''):(r.info?escapeHtml(String(r.info).slice(0,60)):'<span class="u-muted">-</span>');
    return `<tr>
      <td><span class="badge" style="background:var(--accent-soft,rgba(99,102,241,.14));color:var(--accent3)">${VT_TYPE_LABEL[r.vtType]||r.vtType}</span></td>
      <td style="font-family:monospace;font-size:11px;white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(r.value)}">${escapeHtml(String(r.value).slice(0,30))}${String(r.value).length>30?'…':''}</td>
      <td style="font-weight:800;color:${col};white-space:nowrap">${r.mal}/${r.total}</td>
      <td><span class="badge" style="background:${col}22;color:${col}">${label}</span></td>
      <td style="font-size:10.5px;color:var(--text2);max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(dets.join(' | ')||String(r.info||''))}">${detShort}</td>
      <td><a href="${r.link||'#'}" target="_blank" style="color:var(--cyan);font-size:11px;text-decoration:none">VT↗</a></td>
    </tr>`;
  }).join('');
  const nfRows=nf.map(r=>`<tr><td style="font-family:monospace;font-size:11px">${escapeHtml(r.value||r.hash)}</td><td style="font-size:11px;color:${r.notFound?'var(--text3)':'var(--danger)'}">${r.notFound?'미발견 (VT 미등록)':escapeHtml(r.error||'오류')}</td></tr>`).join('');
  const head=done<total
    ?`<div style="font-size:12px;color:var(--text2);margin-bottom:10px"><span class="loading"></span> 조회 중 ${done}/${total} …</div>`
    :`<div style="font-size:12px;color:var(--text2);margin-bottom:10px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px"><span>완료 ${results.length}/${total}건 · 성공 ${ok.length} · 미발견/오류 ${nf.length}</span><span class="u-c-f87171">악성/의심 ${ok.filter(r=>r.mal>0).length}건</span></div>`;
  const copyBar=done>=total?`<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
    <button onclick="vtCopyResults('tsv')" class="btn btn-ghost u-btn-xs">📋 표 복사(엑셀 붙여넣기)</button>
    <button onclick="vtCopyResults('csv')" class="btn btn-ghost u-btn-xs">📋 CSV 복사</button>
    ${nf.length?`<button onclick="vtCopyResults('notfound')" class="btn btn-ghost u-btn-xs">📋 미발견 해시 복사 (${nf.length})</button>`:''}
  </div>`:'';
  return `<div class="vt-result">${head}${copyBar}
    ${ok.length?`<div class="sec-title" style="margin:4px 0 8px">✅ 조회 성공 ${ok.length}건</div>
      <table class="eos-table srt"><thead><tr><th>유형</th><th>대상</th><th>탐지</th><th>위험도</th><th>탐지명 / 정보</th><th>VT</th></tr></thead><tbody>${okRows}</tbody></table>`:''}
    ${nf.length?`<div class="sec-title" style="margin:16px 0 8px">❔ 미발견 / 오류 ${nf.length}건</div>
      <table class="eos-table"><thead><tr><th>대상</th><th>사유</th></tr></thead><tbody>${nfRows}</tbody></table>`:''}
  </div>`;
}
function vtCopyResults(mode){
  const results=window.__vtLastResults||[];
  let text='';
  if(mode==='notfound'){
    text=results.filter(r=>!r.ok).map(r=>r.value||r.hash).join('\n');
  }else{
    const sep=mode==='csv'?',':'\t';
    const q=mode==='csv'?(s=>`"${String(s==null?'':s).replace(/"/g,'""')}"`):(s=>String(s==null?'':s).replace(/[\t\n]/g,' '));
    const lines=[['유형','대상','악성','전체','위험도','탐지명/정보','상태'].map(q).join(sep)];
    results.forEach(r=>{
      if(r.ok){const label=r.mal>=5?'악성':r.mal>=1?'의심':'안전';lines.push([VT_TYPE_LABEL[r.vtType]||r.vtType,r.value,r.mal,r.total,label,(r.detections||[]).join('; ')||r.info||'','성공'].map(q).join(sep));}
      else lines.push([(r.vtType?VT_TYPE_LABEL[r.vtType]:''),r.value||r.hash,'','','','',r.notFound?'미발견':(r.error||'오류')].map(q).join(sep));
    });
    text=lines.join('\n');
  }
  if(!text){toast('복사할 내용이 없습니다.',true);return;}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(()=>toast('클립보드에 복사됨'),()=>vtFallbackCopy(text));}
  else vtFallbackCopy(text);
}
function vtFallbackCopy(text){const ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.left='-9999px';document.body.appendChild(ta);ta.focus();ta.select();try{document.execCommand('copy');toast('클립보드에 복사됨');}catch(e){toast('복사 실패 — 직접 선택하세요',true);}document.body.removeChild(ta);}
function renderVtRich(rec){
  const {mal,total,stats,attrs,name,info,link,detections}=rec;
  const value=rec.value||rec.hash;
  const t=rec.vtType||'hash';
  const riskColor=vtRiskColor(mal);
  const riskLabel=mal>=5?'⚠ 악성':mal>=1?'🔶 의심':'✅ 안전';
  const engines=attrs.last_analysis_results||{};
  const malEngines=Object.entries(engines).filter(([,v])=>v.category==='malicious'||v.category==='suspicious').map(([k,v])=>`${k}: ${v.result||v.category}`).slice(0,8);
  // 유형별 메타 셀
  let metaCells='';
  if(t==='hash'){
    metaCells=`<div class="vt-cell u-gc-span2"><div class="vt-cell-label">파일명</div><div class="vt-cell-val u-fs-11px">${escapeHtml(name||'-')}</div></div>
      ${attrs.size?`<div class="vt-cell"><div class="vt-cell-label">크기</div><div class="vt-cell-val u-fs-11px">${(attrs.size/1024).toFixed(1)}KB</div></div>`:''}
      ${attrs.type_description?`<div class="vt-cell"><div class="vt-cell-label">파일유형</div><div class="vt-cell-val u-fs-11px">${escapeHtml(attrs.type_description)}</div></div>`:''}`;
  }else if(t==='ip'){
    metaCells=`${attrs.country?`<div class="vt-cell"><div class="vt-cell-label">국가</div><div class="vt-cell-val" style="font-size:12px">${escapeHtml(attrs.country)}</div></div>`:''}
      ${attrs.as_owner?`<div class="vt-cell u-gc-span2"><div class="vt-cell-label">소유 (AS)</div><div class="vt-cell-val u-fs-11px">${escapeHtml(attrs.as_owner)}</div></div>`:''}
      ${attrs.network?`<div class="vt-cell"><div class="vt-cell-label">네트워크</div><div class="vt-cell-val u-fs-11px">${escapeHtml(attrs.network)}</div></div>`:''}`;
  }else if(t==='domain'){
    metaCells=`${attrs.registrar?`<div class="vt-cell u-gc-span2"><div class="vt-cell-label">등록기관</div><div class="vt-cell-val u-fs-11px">${escapeHtml(attrs.registrar)}</div></div>`:''}
      ${attrs.creation_date?`<div class="vt-cell u-gc-span2"><div class="vt-cell-label">생성일</div><div class="vt-cell-val u-fs-11px">${escapeHtml(fdt(attrs.creation_date*1000))}</div></div>`:''}`;
  }else if(t==='url'){
    const fin=attrs.last_final_url||attrs.url||value;
    metaCells=`<div class="vt-cell u-gc-span4"><div class="vt-cell-label">최종 URL</div><div class="vt-cell-val u-fs11px-worbreaka">${escapeHtml(fin)}</div></div>
      ${attrs.title?`<div class="vt-cell u-gc-span4"><div class="vt-cell-label">제목</div><div class="vt-cell-val u-fs-11px">${escapeHtml(attrs.title)}</div></div>`:''}`;
  }
  const aiArg=encodeURIComponent(JSON.stringify({value,vtType:t,mal,total}));
  return `<div class="vt-result">
      <div style="text-align:center;margin-bottom:14px">
        <span class="badge" style="background:var(--accent-soft,rgba(99,102,241,.14));color:var(--accent3);margin-bottom:8px">${VT_TYPE_LABEL[t]||t}</span>
        <div style="font-size:11px;color:var(--text3);margin:6px 0 4px;word-break:break-all">${escapeHtml(value)}</div>
        <div class="vt-score" style="color:${riskColor}">${mal} / ${total}</div>
        <span class="badge" style="background:${riskColor}22;color:${riskColor};font-size:13px;padding:5px 16px">${riskLabel}</span>
      </div>
      <div class="vt-grid">
        <div class="vt-cell"><div class="vt-cell-label">악성</div><div class="vt-cell-val u-c-f87171">${stats.malicious||0}</div></div>
        <div class="vt-cell"><div class="vt-cell-label">의심</div><div class="vt-cell-val u-c-fbbf24">${stats.suspicious||0}</div></div>
        <div class="vt-cell"><div class="vt-cell-label">안전</div><div class="vt-cell-val" style="color:#22d3a5">${stats.harmless||0}</div></div>
        <div class="vt-cell"><div class="vt-cell-label">미탐지</div><div class="vt-cell-val">${stats.undetected||0}</div></div>
        ${metaCells}
      </div>
      ${malEngines.length?`<div class="u-mt-14px"><div class="sec-title u-mb-8px">탐지 엔진 (${malEngines.length}개)</div>
      ${malEngines.map(e=>`<div style="font-size:11px;color:var(--danger);padding:4px 0;border-bottom:1px solid var(--border)">${escapeHtml(e)}</div>`).join('')}</div>`:''}
      <div style="margin-top:14px;display:flex;gap:8px">
        <button class="btn btn-purple u-wauto-p8px16p-fs11px" onclick="vtAIAnalysis('${aiArg}')">🤖 AI 위험도 분석</button>
        <a class="u-td-none" href="${link||'https://www.virustotal.com/'}" target="_blank">
          <button class="btn btn-ghost u-wauto-p8px16p-fs11px">VT에서 보기 →</button>
        </a>
      </div>
    </div>`;
}
async function vtAIAnalysis(arg,malArg,totalArg){
  // 신형: arg = encodeURIComponent(JSON {value,vtType,mal,total}). 구형: (hash,mal,total)
  let value,vtType,mal,total;
  try{const o=JSON.parse(decodeURIComponent(arg));value=o.value;vtType=o.vtType||'hash';mal=o.mal;total=o.total;}
  catch(_){value=arg;vtType='hash';mal=malArg;total=totalArg;}
  const tLabel=VT_TYPE_LABEL[vtType]||vtType;
  openAIModal('🛡','VT 위험도 분석',`${tLabel} · ${String(value).slice(0,20)}${String(value).length>20?'…':''}`,'<div class="loading">분석 중...</div>');
  try{
    const text=await callAI(`VirusTotal 탐지 결과 분석.
유형: ${tLabel}
대상: ${value}
탐지: ${mal}/${total}개 엔진

**🎯 종합 판정** (악성/오탐/안전)
**📊 탐지율 해석**
**⚡ 권장 조치** (${vtType==='ip'?'IP 차단/모니터링':vtType==='domain'?'도메인 차단/DNS 싱크홀':vtType==='url'?'URL 차단/사용자 경고':'파일 격리/삭제'} 관점)
**📰 관련 공개 자료 확인**
- 이 ${tLabel}로 공개 기사, 벤더 권고, 보안 블로그를 찾아볼 때 쓸 검색 키워드
- 검색 결과가 없을 때의 해석
**📝 오탐 가능성**`,'vt',{value:String(value).slice(0,32),vtType,mal,total});
    const links=`\n\n### 관련 자료 빠른 검색\n- [Google 검색](https://www.google.com/search?q=${encodeURIComponent(value)})\n- [Google News 검색](https://news.google.com/search?q=${encodeURIComponent(value)})\n- [Broadcom KB 검색](https://support.broadcom.com/web/ecx/search?searchString=${encodeURIComponent(value)})`;
    setAIModalBody(text+links);
    document.getElementById('ai-modal-meta').textContent=`${mal}/${total} 탐지`;
  }catch(e){setAIModalBody(`<div class="u-cdanger-p20px">오류: ${e.message}</div>`,true);}
}

// ── MONTHLY/PATTERN ───────────────────────────────
async function runMonthly(){
  openAIModal('📊','월간 동향 분석','','<div class="loading">분석 중...</div>');
  const list=ISSUES.slice(0,80).map(i=>`[${i.key}]${i.title}|${i.customer||'-'}|${i.status}|${i.labels.join(',')}|${i.date}`).join('\n');
  try{
    const text=await callAI(`아래 이슈 목록의 월간 동향 보고서.
1.이슈 유형별 현황 2.고객사별 현황(상위5사) 3.반복 패턴 4.특이사항 5.다음 기간 권고
이슈:\n${list}`,'monthly',{count:ISSUES.length});
    setAIModalBody(text);
    document.getElementById('ai-modal-meta').textContent=`${ISSUES.length}건 분석`;
  }catch(e){setAIModalBody(`<div class="u-cdanger-p20px">오류: ${e.message}</div>`,true);}
}
async function runPattern(){
  openAIModal('🔍','고객사 패턴 분석','','<div class="loading">분석 중...</div>');
  const cusCnt={};ISSUES.forEach(i=>{if(i.customer)cusCnt[i.customer]=(cusCnt[i.customer]||0)+1;});
  const topCus=Object.entries(cusCnt).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([k])=>k);
  const list=ISSUES.filter(i=>topCus.includes(i.customer)).map(i=>`[${i.customer}]${i.title}|${i.status}|${i.labels.join(',')}|${i.date}`).join('\n');
  try{
    const text=await callAI(`상위 5개 고객사 이슈 패턴 분석.
1.주요 이슈 유형 2.반복 문제 3.관리 포인트 4.예방 조치
이슈:\n${list}`,'pattern',{customers:topCus.join(',')});
    setAIModalBody(text);
    document.getElementById('ai-modal-meta').textContent=`상위 ${topCus.length}개 고객사`;
  }catch(e){setAIModalBody(`<div class="u-cdanger-p20px">오류: ${e.message}</div>`,true);}
}

// ── AUDIT ─────────────────────────────────────────
async function loadAudit(){
  const tbody=document.getElementById('audit-tbody');
  tbody.innerHTML=`<tr><td colspan="5"><div class="loading">로딩...</div></td></tr>`;
  const filter=document.getElementById('audit-filter')?.value||'';
  const limit=document.getElementById('audit-limit')?.value||'100';
  try{
    const url=`${WORKERS}/kv/audit?limit=${limit}${filter?'&filter='+filter:''}`;
    const r=await fetch(url,{headers:authHeaders()});
    const items=await r.json();
    document.getElementById('audit-count').textContent=items.length+'건';
    const ts={
      LOGIN:{bg:'rgba(34,211,165,.12)',color:'#22d3a5',label:'LOGIN'},
      AI_REQUEST:{bg:'rgba(167,139,250,.12)',color:'#a78bfa',label:'AI'},
      AI_CALL:{bg:'rgba(167,139,250,.12)',color:'#a78bfa',label:'AI'},
      VT_LOOKUP:{bg:'rgba(248,113,113,.12)',color:'#f87171',label:'VT'},
      ADMIN_CHANGE:{bg:'rgba(248,113,113,.12)',color:'#f87171',label:'권한'},
      CONFIG_CHANGE:{bg:'rgba(99,102,241,.12)',color:'#818cf8',label:'설정'},
      LINK_ADD:{bg:'rgba(34,211,238,.12)',color:'#22d3ee',label:'링크+'},
      LINK_DELETE:{bg:'rgba(248,113,113,.12)',color:'#f87171',label:'링크-'},
      EOS_ADD:{bg:'rgba(251,191,36,.12)',color:'#fbbf24',label:'라이선스+'},
      EOS_ADD_BULK:{bg:'rgba(251,191,36,.12)',color:'#fbbf24',label:'라이선스+'},
      PUSH_SEND:{bg:'rgba(45,230,184,.12)',color:'#22d3a5',label:'알림'},
      EOS_DELETE:{bg:'rgba(248,113,113,.12)',color:'#f87171',label:'라이선스-'},
      EOS_UPDATE:{bg:'rgba(251,191,36,.12)',color:'#fbbf24',label:'라이선스✎'},
      MATRIX_ADD:{bg:'rgba(96,165,250,.12)',color:'#60a5fa',label:'매트릭스+'},
      MATRIX_UPDATE:{bg:'rgba(96,165,250,.12)',color:'#60a5fa',label:'매트릭스✎'},
      MATRIX_CONFIRM:{bg:'rgba(52,211,153,.12)',color:'#34d399',label:'매트릭스✓'},
      MATRIX_DELETE:{bg:'rgba(248,113,113,.12)',color:'#f87171',label:'매트릭스-'},
      HIST_VIEW:{bg:'rgba(148,163,184,.12)',color:'#94a3b8',label:'이력조회'},
      MON_VIEW:{bg:'rgba(148,163,184,.12)',color:'#94a3b8',label:'팀모니터'},
      FEATURE_TOGGLE:{bg:'rgba(99,102,241,.12)',color:'#818cf8',label:'기능토글'},
      AUDIT_MIGRATE:{bg:'rgba(99,102,241,.12)',color:'#818cf8',label:'감사이전'},
    };
    tbody.innerHTML=items.map(a=>{
      const t=ts[a.type]||{bg:'rgba(148,163,184,.12)',color:'#94a3b8',label:a.type};
      let target='', detail='';
      if(a.type==='AI_REQUEST'||a.type==='AI_CALL'){
        target=a.mode||'-';
        const it=[];
        if(a.issue)it.push(`이슈:${escapeHtml(a.issue)}`);
        if(a.title)it.push(escapeHtml(a.title.slice(0,40)));
        if(a.caseNum)it.push(`케이스:${a.caseNum}`);
        if(a.product)it.push(`제품:${escapeHtml(a.product)}`);
        if(a.files&&a.files!=='직접입력')it.push(`파일:${escapeHtml(a.files)}`);
        if(a.hash)it.push(`해시:${a.hash}`);
        if(a.customers)it.push(`고객사:${escapeHtml(a.customers)}`);
        if(a.count)it.push(`${a.count}건`);
        it.push(`${a.promptLen||0}자`);
        detail=it.join(' · ');
      }else if(a.type==='VT_LOOKUP'){
        if(a.batch||a.count>1){ target=`${a.count||0}건 일괄 조회`; detail=`악성/의심 ${a.mal||0}건`; }
        else { target=a.value||a.name||a.hash||'-'; detail=(a.vtType?`[${a.vtType}] `:'')+(a.mal!=null?`${a.mal||0}건 탐지`:''); }
      }else if(a.type==='ADMIN_CHANGE'){
        target=a.target||'-';
        detail=`${a.action==='add'?'부여':a.action==='remove'?'회수':'변경'} (${a.role||'admin'})`;
      }else if(a.type==='CONFIG_CHANGE'){
        target='설정';detail=(a.keys||[]).join(', ');
      }else if(a.type==='LINK_ADD'){
        target=a.title||'-';
      }else if(a.type==='EOS_ADD_BULK'){
        target=`${a.customer||'-'} (${a.count||0}건)`;
        detail=`[라이선스] 일괄 등록 ${a.count||0}건`;
      }else if(a.type==='PUSH_SEND'){
        target=a.title||'알림';
        detail=`${a.count||0}명 발송${a.skipped?` · ${a.skipped}명 제외`:''}`;
      }else if(a.type==='EOS_ADD'||a.type==='EOS_UPDATE'||a.type==='EOS_DELETE'){
        target=`${a.customer||'-'} · ${a.product||'-'}`;
        const eosTypeLabel='라이선스';
        const action=a.type==='EOS_ADD'?'등록':a.type==='EOS_UPDATE'?'수정':'삭제';
        detail=`[${eosTypeLabel}] ${action} · 만료 ${a.expire||'-'}${a.licenseName?' · '+escapeHtml(a.licenseName):''}`;
      }else if(a.type==='LOGIN'){
        target=a.role||'user';
      }
      return `<tr>
        <td><span class="audit-type-badge" style="background:${t.bg};color:${t.color}">${t.label}</span></td>
        <td style="font-weight:700;color:var(--accent3)">${escapeHtml(a.user||'-')}</td>
        <td>${escapeHtml(target)}</td>
        <td><div class="audit-detail" title="${escapeHtml(detail)}">${detail||'<span class="u-muted">-</span>'}</div></td>
        <td style="color:var(--text3);font-size:11px;white-space:nowrap" data-sort="${a.tsNum||Date.parse(a.ts)||0}">${fdt(a.tsNum||a.ts)}</td>
      </tr>`;
    }).join('')||`<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text3)">로그 없음</td></tr>`;
  }catch(e){tbody.innerHTML=`<tr><td class="u-cdanger-p16px" colspan="5">로드 실패: ${e.message}</td></tr>`;}
}

// ── SETTINGS ──────────────────────────────────────
function setAdminActionStatus(message,type='ok'){
  const el=document.getElementById('admin-action-status');
  if(!el)return;
  el.textContent=message;
  el.className=`admin-action-status show ${type==='err'?'err':type==='info'?'info':''}`.trim();
}
async function loadSettings(){
  try{
    const r=await fetch(`${WORKERS}/admin/config`,{headers:authHeaders()});
    const d=await r.json();
    if(d.ok){
      document.getElementById('cfg-range').value=d.rangeMonths;
      document.getElementById('cfg-session').value=d.sessionMin;
      document.getElementById('cfg-ai-system').value=d.aiSystem||'';
      document.getElementById('cfg-eos-warn').value=d.eosWarnDays||'60,30,7';
    }
  }catch(e){toast('설정 로드 실패',true);}
  const wrap=document.getElementById('admin-list-wrap');
  wrap.innerHTML='<div class="loading">로딩...</div>';
  try{
    const r=await fetch(`${WORKERS}/admin/list`,{headers:authHeaders()});
    const d=await r.json();
    TEAM_NAMES=d.teamNames||[];
    const userMap=Object.fromEntries((d.users||[]).map(u=>[u.id,u]));
    const userLabel=id=>{
      const u=userMap[id]||{};
      return u.displayName?`${u.displayName} (${id})`:id;
    };
    renderUserAccounts(d.users||[]);
    const admins=d.admins||{};
    wrap.innerHTML=Object.entries(admins).map(([name,role])=>{
      const isSuperRole=role==='super';
      return `<div class="admin-list-item">
        <div style="display:flex;align-items:center;gap:10px">
          <span style="font-size:10px;padding:2px 9px;border-radius:20px;background:${isSuperRole?'rgba(248,113,113,.15)':'rgba(99,102,241,.15)'};color:${isSuperRole?'#f87171':'var(--accent3)'};font-weight:700">${isSuperRole?'최상위':'관리자'}</span>
          <span style="font-weight:700;color:var(--text)">${escapeHtml(userLabel(name))}</span>
        </div>
        ${name!==SUPER_ADMIN?`<div style="display:flex;gap:6px">
          <select onchange="changeRole('${escapeHtml(name)}',this.value)" style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:4px 8px;color:var(--text);font-size:11px;outline:none">
            <option value="admin" ${role==='admin'?'selected':''}>일반 관리자</option>
            <option value="super" ${role==='super'?'selected':''}>최상위 관리자</option>
          </select>
          <button onclick="removeAdmin('${escapeHtml(name)}')" class="btn btn-red u-btn-xxs">회수</button>
        </div>`:'<span class="u-muted-11">변경 불가</span>'}
      </div>`;
    }).join('');
    const adminNames=Object.keys(admins);
    const candidates=TEAM_NAMES.filter(n=>!adminNames.includes(n));
    document.getElementById('admin-add-name').innerHTML='<option value="">팀원 선택</option>'+candidates.map(n=>`<option value="${escapeHtml(n)}">${escapeHtml(userLabel(n))}</option>`).join('');
    const pinReset=document.getElementById('pin-reset-user');
    if(pinReset)pinReset.innerHTML='<option value="">팀원 선택</option>'+TEAM_NAMES.map(n=>`<option value="${escapeHtml(n)}">${escapeHtml(userLabel(n))}</option>`).join('');
    window.__userMap=userMap; window.__teamNames=TEAM_NAMES;
    if(typeof loadPushSettings==='function')loadPushSettings();
    if(typeof loadUsageStats==='function')loadUsageStats();
  }catch(e){wrap.innerHTML=`<div class="u-err-12">로드 실패: ${e.message}</div>`;}
}
// ── 기능 사용 현황(컷 판단용) : audit_log 집계 렌더 ──
const USAGE_FEATURE_MAP={AI_CALL:'로그/이슈 AI분석',AI_DEBUG:'AI 디버그',VT_LOOKUP:'VirusTotal 조회',VT_UPLOAD:'VirusTotal 파일',MON_VIEW:'팀 업무 모니터',HIST_VIEW:'고객사 이력',MATRIX_ADD:'호환성 매트릭스',MATRIX_UPDATE:'호환성 매트릭스',MATRIX_DELETE:'호환성 매트릭스',MATRIX_CONFIRM:'호환성 매트릭스',LINK_ADD:'업무 링크',LINK_UPDATE:'업무 링크',LINK_DELETE:'업무 링크',KNOWLEDGE_ADD:'팀 노하우',KNOWLEDGE_UPDATE:'팀 노하우',KNOWLEDGE_DELETE:'팀 노하우',EOS_ADD:'라이선스',EOS_ADD_BULK:'라이선스',EOS_UPDATE:'라이선스',EOS_DELETE:'라이선스',PUSH_SEND:'푸시 발송',PUSH_SETTINGS_CHANGE:'푸시 설정',LOGIN:'로그인',PIN_CHANGE:'PIN 변경',PIN_RESET:'PIN 초기화'};
const USAGE_PAGE_LABEL={dash:'대시보드',issues:'이슈 관리',cases:'케이스 트래커',customers:'고객사 프로필',eos:'라이선스',log:'로그 분석기',vt:'VirusTotal 조회',links:'업무 링크',knowledge:'팀 노하우',audit:'감사 로그',settings:'관리자 설정',mydesk:'My Desk',compat:'호환성 매트릭스',nsis:'NSIS 분석기',monitor:'팀 업무 모니터'};
async function loadUsageStats(){
  const wrap=document.getElementById('usage-stats-wrap'); if(!wrap)return;
  const days=parseInt((document.getElementById('usage-days')||{}).value||'90',10)||90;
  wrap.innerHTML='<div class="loading">로딩...</div>';
  try{
    const r=await fetch(`${WORKERS}/admin/usage/features?days=${days}`,{headers:authHeaders()});
    const d=await r.json();
    if(!d||!d.ok){wrap.innerHTML=`<div class="u-err-12">집계 실패: ${escapeHtml((d&&d.message)||'응답 오류')}</div>`;return;}
    const feat={};
    const add=(name,cnt,last,users)=>{ if(!feat[name])feat[name]={count:0,last:0,users:0}; feat[name].count+=cnt||0; feat[name].last=Math.max(feat[name].last,last||0); feat[name].users=Math.max(feat[name].users,users||0); };
    (d.byType||[]).forEach(t=>{ const nm=USAGE_FEATURE_MAP[t.type]; if(nm)add(nm,t.count,t.last,t.users); });
    (d.byPage||[]).forEach(p=>{ const nm=USAGE_PAGE_LABEL[p.page]||('페이지:'+p.page); add(nm,p.count,p.last,p.users); });
    Object.values(USAGE_PAGE_LABEL).forEach(nm=>{ if(!feat[nm])feat[nm]={count:0,last:0,users:0}; });
    const now=Date.now();
    const rows=Object.entries(feat).map(([name,v])=>({name,...v})).sort((a,b)=>a.count-b.count||b.last-a.last);
    const fmtLast=ts=>{ if(!ts)return '—'; const dd=Math.floor((now-ts)/86400000); return dd<=0?'오늘':(dd+'일 전'); };
    const badge=v=>{ if(v.count===0)return '<span style="color:#f87171;font-weight:700">🔴 컷후보</span>'; if(v.users<=1)return '<span class="u-cfbbf24-fw700">🟡 1인</span>'; return ''; };
    wrap.innerHTML=`<table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="color:var(--text3);text-align:left;border-bottom:1px solid var(--border)"><th class="u-p-6px4px">기능</th><th class="u-p6px4px-taright">호출수</th><th class="u-p6px4px-taright">사용자</th><th class="u-p6px4px-taright">최근</th><th class="u-p-6px4px">판정</th></tr></thead>
      <tbody>${rows.map(v=>`<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px 4px;color:var(--text)">${escapeHtml(v.name)}</td><td style="padding:6px 4px;text-align:right;color:var(--text)">${v.count}</td><td class="u-p6px4px-taright-ctext3">${v.users?('≥'+v.users):'—'}</td><td class="u-p6px4px-taright-ctext3">${fmtLast(v.last)}</td><td class="u-p-6px4px">${badge(v)}</td></tr>`).join('')}</tbody></table>`;
    const cov=document.getElementById('usage-coverage');
    if(cov){ const cs=d.coverageStart?new Date(d.coverageStart):null; cov.textContent=cs?`※ 집계 데이터 보유 시작: ${cs.toISOString().slice(0,10)} — 그 이전 기간은 0으로 표시될 수 있음`:'※ 아직 집계 데이터 없음(비콘 배포 후 누적)'; }
  }catch(e){wrap.innerHTML=`<div class="u-err-12">로드 실패: ${escapeHtml(e.message)}</div>`;}
}
function renderUserAccounts(users=[]){
  const wrap=document.getElementById('user-list-wrap');if(!wrap)return;
  wrap.innerHTML=users.map(u=>`<div class="admin-list-item">
    <div style="display:flex;align-items:center;gap:10px;min-width:0">
      <span style="font-size:10px;padding:2px 9px;border-radius:20px;background:${u.active===false?'rgba(148,163,184,.14)':u.role==='super'?'rgba(248,113,113,.15)':u.role==='admin'?'rgba(99,102,241,.15)':'rgba(45,230,184,.12)'};color:${u.active===false?'var(--text3)':u.role==='super'?'#f87171':u.role==='admin'?'var(--accent3)':'var(--accent2)'};font-weight:800">${u.active===false?'비활성':u.role==='super'?'SUPER':u.role==='admin'?'ADMIN':'USER'}</span>
      <span style="font-weight:800;color:var(--text)">${escapeHtml(u.displayName||u.id)}</span>
      <span class="u-muted-11">${escapeHtml(u.id)}</span>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">
      <button class="btn btn-ghost u-btn-xxs" onclick="fillUserForm(${jsAttr(u.id)},${jsAttr(u.displayName||'')},${jsAttr(u.role||'user')})">수정</button>
      ${u.id!==SUPER_ADMIN&&u.active!==false?`<button class="btn btn-red u-btn-xxs" onclick="deleteUserAccount('${escapeHtml(u.id)}')">로그인 차단</button>`:''}
      ${u.id!==SUPER_ADMIN?`<button class="btn btn-red" onclick="purgeUserAccount('${escapeHtml(u.id)}')" style="width:auto;padding:4px 12px;font-size:11px;opacity:.7">계정 삭제</button>`:''}
    </div>
  </div>`).join('')||'<div class="empty">등록된 사용자가 없습니다.</div>';
}
function fillUserForm(id,displayName,role){
  document.getElementById('user-add-id').value=id||'';
  document.getElementById('user-add-display').value=displayName||'';
  document.getElementById('user-add-role').value=role||'user';
  document.getElementById('user-add-pin').value='';
}
async function saveUserAccount(){
  const id=document.getElementById('user-add-id').value.trim().toLowerCase();
  const displayName=document.getElementById('user-add-display').value.trim();
  const role=document.getElementById('user-add-role').value;
  const initialPin=document.getElementById('user-add-pin').value;
  if(!/^[a-z0-9._-]{2,40}$/.test(id)){toast('계정 ID는 영문/숫자/점/하이픈/언더바 2~40자만 가능합니다',true);return;}
  if(!displayName){toast('표시 이름을 입력해주세요',true);return;}
  try{
    const r=await fetch(`${WORKERS}/admin/users`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify({id,displayName,role,initialPin})});
    const d=await r.json();
    if(!d.ok){toast(d.message||'사용자 저장 실패',true);setAdminActionStatus(d.message||'사용자 저장 실패','err');return;}
    toast('사용자 저장 완료');
    setAdminActionStatus(`${id} 사용자 저장 완료`);
    ['user-add-id','user-add-display','user-add-pin'].forEach(x=>document.getElementById(x).value='');
    document.getElementById('user-add-role').value='user';
    loadSettings();
  }catch(e){toast('사용자 저장 오류: '+e.message,true);setAdminActionStatus('사용자 저장 실패: '+e.message,'err');}
}
async function deleteUserAccount(id){
  if(!id||id===SUPER_ADMIN)return;
  if(!confirm(`${id} 계정의 로그인을 차단할까요?\n등록자가 만든 업무 데이터는 삭제하지 않습니다.`))return;
  try{
    const d=await hubApi(`/admin/users/${encodeURIComponent(id)}`,{method:'DELETE'});
    toast(`${d.user||id} 로그인 차단 완료`);
    setAdminActionStatus(`${d.user||id} 계정 로그인을 차단했습니다. 기존 등록 데이터는 유지됩니다.`);
    await loadSettings();
  }catch(e){toast('사용자 차단 실패: '+e.message,true);setAdminActionStatus('사용자 로그인 차단 실패: '+e.message,'err');}
}
async function purgeUserAccount(id){
  if(!id||id===SUPER_ADMIN){toast('최고 관리자는 삭제할 수 없습니다.',true);return;}
  if(!confirm(`⚠ ${id} 계정을 완전히 삭제하시겠습니까?\n\n이 작업은 되돌릴 수 없으며 계정 정보와 PIN이 삭제됩니다.\n등록자가 만든 업무 데이터(링크/노하우/라이선스 등)는 유지됩니다.`))return;
  if(!confirm(`정말로 ${id} 계정을 삭제합니까?`))return;
  try{
    const d=await hubApi(`/admin/users/${encodeURIComponent(id)}?purge=true`,{method:'DELETE'});
    toast(`${d.user||id} 계정이 삭제됐습니다.`);
    setAdminActionStatus(`${d.user||id} 계정 삭제 완료.`);
    await loadSettings();
  }catch(e){toast('계정 삭제 실패: '+e.message,true);setAdminActionStatus('계정 삭제 실패: '+e.message,'err');}
}
async function saveConfig(){
  const body={
    rangeMonths:parseInt(document.getElementById('cfg-range').value),
    sessionMin:parseInt(document.getElementById('cfg-session').value),
    aiSystem:document.getElementById('cfg-ai-system').value,
    eosWarnDays:document.getElementById('cfg-eos-warn').value.trim()||'60,30,7',
  };
  try{
    const r=await fetch(`${WORKERS}/admin/config`,{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){toast(d.message||'저장 실패',true);setAdminActionStatus(d.message||'시스템 설정 저장 실패','err');return;}
    toast('저장 완료. 일부 설정은 새로고침 후 반영됩니다.');
    setAdminActionStatus('시스템 설정 저장 완료. 일부 설정은 새로고침 후 반영됩니다.');
    loadEosWarnDays();
  }catch(e){toast('오류: '+e.message,true);setAdminActionStatus('시스템 설정 저장 실패: '+e.message,'err');}
}
async function clearCache(){
  if(!confirm(`AI 응답 캐시(ai:*)를 삭제하시겠어요?\n캐시만 삭제되며 업무 링크/노하우/Jira 데이터는 삭제되지 않습니다.`))return;
  const btn=document.getElementById('storage-cache-btn');
  const old=btn?.textContent;
  if(btn){btn.disabled=true;btn.textContent='정리 중...';}
  try{
    const r=await fetch(`${WORKERS}/admin/cache/clear`,{method:'POST',headers:authHeaders()});
    const d=await r.json();
    if(!d.ok){toast(d.message||'실패',true);setAdminActionStatus(d.message||'AI 응답 캐시 정리 실패','err');return;}
    toast(`AI 캐시 ${d.cleared}개 삭제${d.truncated?' · 추가 캐시가 남아있을 수 있습니다. 다시 실행하세요.':''}`);
    setAdminActionStatus(`AI 응답 캐시 정리 완료: ${d.cleared}개 삭제${d.truncated?' · 남은 캐시가 있을 수 있습니다.':''}`);
    await refreshStorageStats();
  }catch(e){toast('오류: '+e.message,true);setAdminActionStatus('AI 응답 캐시 정리 실패: '+e.message,'err');}
  finally{if(btn){btn.disabled=false;btn.textContent=old||'🧹 AI 응답 캐시 초기화';}}
}