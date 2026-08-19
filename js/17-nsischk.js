/* ── 🧩 NSIS ↔ 순서도 정합성 검사 (규칙 기반, AI 미사용) ────────────────────
   .nsi 스크립트와 그 순서도(.pptx)를 대조해 어긋난 곳과 개선점을 찾는다.

   설계 원칙
   - 파일은 **브라우저 안에서만** 파싱한다. 서버로 업로드하지 않는다(스크립트에
     암호·GUID 같은 민감값이 들어 있는 경우가 많다).
   - 판정은 전부 결정적 규칙이다. AI를 쓰지 않으므로 같은 입력이면 같은 결과가 나온다.
   - .nsi 는 보통 CP949(EUC-KR)로 저장돼 있다. UTF-8로 읽으면 한글 주석이 깨진다.
   - .pptx 해제는 브라우저 내장 DecompressionStream 을 쓴다(외부 zip 라이브러리 없음).
     순서도가 **도형**으로 그려진 PPT만 읽을 수 있다 — 캡처 이미지는 읽지 못한다. */

let NSC = { nsi: null, ppt: null, nsiName: '', pptName: '' };

/* ── 인코딩 ─────────────────────────────────────────────────────────────── */
function nscDecode(buf) {
  const bytes = new Uint8Array(buf);
  try { return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), enc: 'UTF-8' }; }
  catch (_) {}
  for (const enc of ['euc-kr', 'windows-949']) {
    try { return { text: new TextDecoder(enc).decode(bytes), enc: 'CP949' }; } catch (_) {}
  }
  return { text: new TextDecoder('utf-8').decode(bytes), enc: 'UTF-8(대체)' };
}

/* ── .nsi 파서 ──────────────────────────────────────────────────────────── */
function nscParseNsi(text) {
  const raw = text.split(/\r?\n/);
  const out = {
    lines: raw.length, defines: [], labels: [], gotos: [], chains: [], execs: [],
    relJumps: [], fileChecks: [], absPaths: [], logFiles: [], sections: [], functions: [],
    jumpTargets: [],
  };
  let chain = null, inFunc = null;
  raw.forEach((full, idx) => {
    const n = idx + 1;
    const line = full.replace(/;.*$/, '').trim();          // 줄 주석 제거(문자열 안 세미콜론은 드묾)
    if (!line) return;
    let m;
    if (/^FunctionEnd/i.test(line)) inFunc = null;
    if ((m = line.match(/^!define\s+(\S+)\s+(.+)$/i))) out.defines.push({ n, name: m[1], value: m[2].replace(/^["']|["']$/g, '') });
    if ((m = line.match(/^Section\s+(.*)$/i))) out.sections.push({ n, name: m[1].replace(/"/g, '').trim() });
    if ((m = line.match(/^Function\s+(\S+)/i))) { out.functions.push({ n, name: m[1] }); inFunc = m[1]; }
    if ((m = line.match(/^([A-Za-z_][A-Za-z0-9_]*):\s*$/))) out.labels.push({ n, name: m[1] });
    if ((m = line.match(/^Goto\s+(\S+)/i))) out.gotos.push({ n, target: m[1] });
    // 조건 명령의 분기 대상도 라벨 사용처다 (IfFileExists <경로> <참라벨> <거짓라벨>)
    if ((m = line.match(/^(?:IfFileExists|IfErrors|StrCmp|StrCmpS|IntCmp|IntCmpU|IfSilent|IfRebootFlag|IfAbort)\b(.*)$/i))) {
      const rest = m[1].replace(/"[^"]*"/g, ' ').replace(/'[^']*'/g, ' ').replace(/\$\{[^}]*\}/g, ' ');
      rest.trim().split(/\s+/).forEach(tk => {
        if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tk)) out.jumpTargets.push({ n, target: tk });
      });
      const rel = line.match(/(^|\s)([+-]\d+)(\s|$)/g);
      if (rel) out.relJumps.push({ n, line, jumps: rel.map(x => x.trim()), fn: inFunc });
    }
    if ((m = line.match(/^IfFileExists\s+"?([^"]+?)"?\s+(\S+)\s+(\S+)/i))) out.fileChecks.push({ n, path: m[1] });
    if ((m = line.match(/nsExec::Exec\w*\s+'([^']*)'/i)) || (m = line.match(/nsExec::Exec\w*\s+"([^"]*)"/i))) out.execs.push({ n, cmd: m[1], checked: false });
    // ${if}/${elseif}/${else}/${endif} 체인 — 같은 변수를 비교하는 분기 묶음을 만든다
    if ((m = line.match(/^\$\{(if|elseif)\}\s+(\$\w+)\s*==\s*"([^"]*)"/i))) {
      const kind = m[1].toLowerCase(), v = m[2], lit = m[3];
      if (kind === 'if' || !chain || chain.varName !== v) chain = { varName: v, start: n, items: [] };
      if (kind === 'if') out.chains.push(chain);
      else if (!out.chains.includes(chain)) out.chains.push(chain);
      chain.items.push({ n, literal: lit });
      chain.end = n;
    }
    if (/^\$\{endif\}/i.test(line)) chain = null;
    const abs = line.match(/["']([A-Za-z]:\\[^"']+)["']/g);
    if (abs) abs.forEach(a => out.absPaths.push({ n, path: a.replace(/^["']|["']$/g, '') }));
    if ((m = line.match(/FileOpen\s+\$\d+\s+"([^"]+)"/i))) out.logFiles.push({ n, path: m[1] });
  });
  // nsExec 결과 검사 여부 — Pop 이후 20줄 안에서 $0 을 비교하면 '확인함'
  out.execs.forEach(e => {
    const win = raw.slice(e.n, e.n + 20).join('\n');
    e.checked = /\$\{if\}\s*\$0|StrCmp\s+\$0|IntCmp\s+\$0/i.test(win);
  });
  out.versions = [...new Set(out.chains.flatMap(c => c.items.map(i => i.literal)).filter(v => /^\d+(\.\d+)+$/.test(v)))];
  out.guids = [...new Set((text.match(/\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}/g) || []))];
  return out;
}

/* ── .pptx 리더 (DecompressionStream 기반 최소 ZIP) ─────────────────────── */
async function nscInflate(bytes, method) {
  if (method === 0) return bytes;
  if (typeof DecompressionStream === 'undefined') throw new Error('이 브라우저는 DecompressionStream 을 지원하지 않습니다(최신 Chrome/Edge 필요).');
  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function nscUnzip(buf, wantRe) {
  const b = new Uint8Array(buf), dv = new DataView(buf);
  let eocd = -1;
  for (let i = b.length - 22; i >= 0 && i > b.length - 66000; i--) { if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; } }
  if (eocd < 0) throw new Error('ZIP 구조를 읽지 못했습니다(.pptx 파일이 맞는지 확인해 주세요).');
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const files = {};
  for (let i = 0; i < count; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const csize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), cmtLen = dv.getUint16(p + 32, true);
    const lho = dv.getUint32(p + 42, true);
    const name = new TextDecoder('utf-8').decode(b.subarray(p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + cmtLen;
    if (!wantRe.test(name)) continue;
    const lnLen = dv.getUint16(lho + 26, true), leLen = dv.getUint16(lho + 28, true);
    const start = lho + 30 + lnLen + leLen;
    files[name] = await nscInflate(b.subarray(start, start + csize), method);
  }
  return files;
}
async function nscParsePptx(buf) {
  const files = await nscUnzip(buf, /^ppt\/slides\/slide\d+\.xml$/);
  const names = Object.keys(files).sort((a, b) => (+a.match(/\d+/)[0]) - (+b.match(/\d+/)[0]));
  if (!names.length) throw new Error('슬라이드를 찾지 못했습니다.');
  const dec = new TextDecoder('utf-8');
  return names.map(nm => {
    const xml = dec.decode(files[nm]);
    const texts = [...xml.matchAll(/<a:t>([\s\S]*?)<\/a:t>/g)]
      .map(m => m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').trim()).filter(Boolean);
    const g = nscSlideGraph(xml);
    return {
      name: nm.replace('ppt/slides/', ''),
      texts,
      shapes: (xml.match(/<p:sp>/g) || []).length,
      conns: (xml.match(/<p:cxnSp>/g) || []).length,
      nodes: g.nodes, edges: g.edges,
    };
  });
}

/* ── 슬라이드 1장 → 방향 그래프 ─────────────────────────────────────────────
   도형: <p:sp> 의 prstGeom 으로 시작/종료(Terminator) · 판단(Decision) · 처리(Process)를 가른다.
   엣지: <p:cxnSp> 의 <a:stCxn id>/<a:endCxn id> 가 곧 출발·도착 도형 id 다.
   Y/N : 연결선에 붙은 글자가 아니라 **별도 텍스트 상자**다. 화살표가 출발하는 쪽에 놓이므로
         연결선의 '시작점' 기준 거리로, 판단에서 나가는 엣지에 한해, 전역 최소거리로 짝짓는다.
         (끝점 기준이면 한 도형에서 갈라지는 두 화살표를 구분하지 못한다.) */
function nscSlideGraph(xml) {
  const boxOf = b => {
    const o = b.match(/<a:off x="(-?\d+)" y="(-?\d+)"\/><a:ext cx="(\d+)" cy="(\d+)"\/>/);
    if (!o) return null;
    const x = +o[1], y = +o[2], cx = +o[3], cy = +o[4];
    return { x, y, cx, cy, mx: x + cx / 2, my: y + cy / 2 };
  };
  const textOf = b => [...b.matchAll(/<a:t>([\s\S]*?)<\/a:t>/g)].map(m => m[1]).join(' ')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();

  const nodes = [], labels = [];
  [...xml.matchAll(/<p:sp>[\s\S]*?<\/p:sp>/g)].forEach(m => {
    const b = m[0];
    const id = (b.match(/<p:cNvPr id="(\d+)"/) || [])[1]; if (!id) return;
    const geom = (b.match(/<a:prstGeom prst="(\w+)"/) || [])[1] || '';
    const t = textOf(b), g = boxOf(b); if (!g) return;
    if (/^(Y|N|예|아니오|아니요|yes|no)$/i.test(t)) { labels.push({ t: /^(Y|예|yes)$/i.test(t) ? 'Y' : 'N', ...g }); return; }
    const kind = /Terminator/i.test(geom) ? (/시작|start|begin/i.test(t) ? 'start' : 'end')
      : /Decision/i.test(geom) ? 'decision'
      : /Process|Predefined|Alternate|Manual/i.test(geom) ? 'process' : 'note';
    nodes.push({ id, kind, text: t, ...g });
  });

  const edges = [];
  [...xml.matchAll(/<p:cxnSp>[\s\S]*?<\/p:cxnSp>/g)].forEach(m => {
    const b = m[0];
    const from = (b.match(/<a:stCxn id="(\d+)"/) || [])[1];
    const to = (b.match(/<a:endCxn id="(\d+)"/) || [])[1];
    const g = boxOf(b); if (!from || !to || !g) return;
    const fl = (b.match(/<a:xfrm([^>]*)>/) || [])[1] || '';
    edges.push({ from, to, ...g, flipH: /flipH="1"/.test(fl), flipV: /flipV="1"/.test(fl), yn: '' });
  });

  const isDec = id => (nodes.find(n => n.id === id) || {}).kind === 'decision';
  const pairs = [];
  labels.forEach((L, li) => edges.forEach((e, ei) => {
    if (!isDec(e.from)) return;
    const sx = e.flipH ? e.x + e.cx : e.x, sy = e.flipV ? e.y + e.cy : e.y;
    pairs.push({ li, ei, d: Math.hypot(sx - L.mx, sy - L.my) });
  }));
  pairs.sort((a, b) => a.d - b.d);
  const usedL = new Set(), usedE = new Set();
  pairs.forEach(p => {
    if (usedL.has(p.li) || usedE.has(p.ei)) return;
    usedL.add(p.li); usedE.add(p.ei); edges[p.ei].yn = labels[p.li].t;
  });
  return { nodes, edges };
}

/* 시작 → 종료 경로를 전부 전개한다(경우의 수). 순환은 방문한 노드 재진입 금지로 끊고,
   폭발을 막으려 60개에서 자른다(잘리면 화면에 그 사실을 알린다). */
function nscFlowPaths(slide, cap) {
  cap = cap || 60;
  if (!slide || !slide.nodes || !slide.nodes.length) return { paths: [], truncated: false };
  const byId = {}; slide.nodes.forEach(n => { byId[n.id] = n; });
  const start = slide.nodes.find(n => n.kind === 'start');
  if (!start) return { paths: [], truncated: false };
  const out = []; let cut = false;
  (function walk(id, seen, acc) {
    if (out.length >= cap) { cut = true; return; }
    const node = byId[id]; if (!node) return;
    const here = { text: node.text, kind: node.kind, yn: '' };
    const path = acc.concat([here]);
    if (node.kind === 'end') { out.push(path); return; }
    const nx = slide.edges.filter(e => e.from === id && !seen.has(e.to));
    if (!nx.length) { out.push(path); return; }
    nx.forEach(e => {
      const p2 = path.map(x => ({ ...x }));
      p2[p2.length - 1].yn = e.yn;
      walk(e.to, new Set([...seen, id]), p2);
    });
  })(start.id, new Set(), []);
  return { paths: out, truncated: cut };
}

/* ── 제품 힌트로 슬라이드 고르기 ────────────────────────────────────────────
   PPT 한 파일에 여러 제품 순서도가 함께 있으면(예: DLP·SEP 각 1장) 전부를 대조하면
   "SEP 스크립트에 Cleanagent 가 없다" 같은 헛된 지적이 난다. .nsi 의 Name/OutFile 에서
   제품 토큰을 뽑아 해당 슬라이드만 쓴다. 못 고르면 전체를 쓰되 화면에 그 사실을 알린다. */
function nscProductHint(nsi) {
  const t = nsi._raw || '';
  const cands = [];
  let m;
  if ((m = t.match(/^\s*Name\s+"([^"]+)"/im))) cands.push(m[1]);
  if ((m = t.match(/^\s*OutFile\s+"([^"]+)"/im))) cands.push(m[1]);
  const toks = cands.join(' ').toUpperCase().match(/\b(DLP|SEP|PP|S1|EDR|EPP)\b/g) || [];
  return [...new Set(toks)];
}
function nscPickSlides(nsi, slides) {
  if (!slides || !slides.length) return { slides: null, note: '' };
  const hints = nscProductHint(nsi);
  if (!hints.length) return { slides, note: `제품을 판별하지 못해 슬라이드 ${slides.length}장 전체와 대조합니다.` };
  const hit = slides.filter(s => hints.some(h => new RegExp('\\b' + h + '\\b', 'i').test(s.texts.join(' '))));
  if (!hit.length) return { slides, note: `${hints.join('/')} 순서도를 찾지 못해 슬라이드 ${slides.length}장 전체와 대조합니다.` };
  return { slides: hit, note: `${hints.join('/')} 기준 ${hit.map(s => s.name).join(', ')} 와 대조합니다.` };
}

/* ── 규칙 ───────────────────────────────────────────────────────────────── */
/* 각 단계가 코드 '어디에' 있는지(줄번호)까지 찾는다. 0 이면 없음.
   존재 여부만 보면 순서가 뒤바뀐 스크립트를 잡지 못하고, result 를 exists 와 같은
   IfFileExists 로 판정하면 둘이 항상 함께 잡혀 대조가 무의미해진다.
   → result 는 '제거 실행 이후의' 존재 확인으로 정의한다. */
function nscFirstLine(nsi, re) {
  const lines = (nsi._raw || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return 0;
}
const NSC_STEPS = [
  { key: 'arch', label: 'OS 아키텍처 확인', ppt: /아키텍처|비트|64\s*bit|x64|32\s*bit/i,
    at: n => nscFirstLine(n, /WindowsPlatformArchitecture|RunningX64|GetVersion::WindowsPlatform/i) },
  { key: 'exists', label: '설치 유무 확인(제거 전)', ppt: /유무\s*확인|설치\s*(유무|여부)|존재\s*(유무|여부|확인)/i,
    at: (n, ctx) => { const f = n.fileChecks.find(x => !ctx.uninstAt || x.n < ctx.uninstAt); return f ? f.n : 0; } },
  { key: 'ver', label: '버전 확인', ppt: /버전\s*(체크|확인|분기|판별)/i,
    at: n => nscFirstLine(n, /GetFileVersion|GetDLLVersion/i) || ((n.chains[0] || {}).start || 0) },
  { key: 'uninst', label: '제거 실행', ppt: /삭제|제거|언인스톨|uninstall/i,
    at: n => (n.execs.find(e => /msiexec|uninstall|removal|setup\.exe/i.test(e.cmd)) || {}).n || 0 },
  { key: 'clean', label: '강제 제거(Cleanagent)', ppt: /clean\s*agent|cleanagent|cleanwipe|강제\s*(삭제|제거)/i,
    at: n => (n.execs.find(e => /clean_?agent|cleanwipe/i.test(e.cmd)) || {}).n || 0 },
  { key: 'result', label: '결과 확인(제거 후)', ppt: /성공|실패|결과\s*확인/i,
    at: (n, ctx) => { if (!ctx.uninstAt) return 0; const f = n.fileChecks.find(x => x.n > ctx.uninstAt); return f ? f.n : 0; } },
];
function nscRules(nsi, ppt) {
  const F = [];
  const steps = [];      // 단계 대조표 — 지적이 없어도 "무엇을 대조했는지" 화면에 보여준다
  const codeAt = {};
  let flowPaths = [], flowCut = false;   // 순서도에서 전개한 경우의 수
  const add = (level, rule, title, detail, where, suggest) => F.push({ level, rule, title, detail, where: where || '', suggest: suggest || '' });

  // R1 — 같은 변수를 보는 분기 체인끼리 버전 집합이 다른가 (가장 치명적)
  const byVar = {};
  nsi.chains.forEach(c => { (byVar[c.varName] = byVar[c.varName] || []).push(c); });
  Object.entries(byVar).forEach(([v, chains]) => {
    if (chains.length < 2) return;
    const sets = chains.map(c => new Set(c.items.map(i => i.literal)));
    const all = new Set(chains.flatMap(c => c.items.map(i => i.literal)));
    const diffs = [...all].filter(lit => !sets.every(s => s.has(lit)));
    if (!diffs.length) return;
    add('high', 'R1', `${v} 분기 목록이 서로 다릅니다`,
      `이 변수를 보는 분기가 ${chains.length}곳인데 다루는 값이 일치하지 않습니다. 어긋난 값: ${diffs.join(', ')}. ` +
      `한쪽에만 있는 값은 그 단계에서 \${else} 로 빠져 아무 처리도 되지 않습니다.`,
      chains.map(c => `${c.start}~${c.end}행: ${[...sets[chains.indexOf(c)]].join(', ')}`).join(' / '),
      '두 목록을 같게 맞추거나, 버전 목록을 !define 상수 한 곳으로 모아 재사용하세요.');
  });

  // R2 — 평문 자격증명
  nsi.defines.filter(d => /PW|PASS|PWD|SECRET|TOKEN|CRED/i.test(d.name) && d.value && d.value.length > 2)
    .forEach(d => add('high', 'R2', `평문 자격증명 상수 ${d.name}`,
      '컴파일된 .exe 에서 문자열로 그대로 추출됩니다. 이 툴이 단말에 배포되면 해당 암호가 사실상 공개됩니다.',
      `${d.n}행`, '빌드 시 주입하거나, 서버에서 일회성으로 받아오는 방식으로 바꾸세요. 최소한 이 값이 노출됐다고 보고 로테이션을 검토하세요.'));
  const inlinePw = [];
  nsi.execs.forEach(e => { if (/PASSWORD\s*=\s*"?[^"\s$]{3,}/i.test(e.cmd) && !/\$\{/.test(e.cmd.match(/PASSWORD\s*=\s*"?([^"\s]*)/i)[1] || '')) inlinePw.push(e.n); });
  if (inlinePw.length) add('high', 'R2', '실행 명령에 암호가 직접 박혀 있습니다', '명령줄 인자는 프로세스 목록에도 노출될 수 있습니다.', inlinePw.map(n => n + '행').join(', '), '상수/변수로 분리하고 위와 같이 주입 방식을 검토하세요.');

  // R3 — 라벨 정합
  const labelNames = new Set(nsi.labels.map(l => l.name));
  const missing = nsi.gotos.filter(g => !labelNames.has(g.target) && !/^[+-]\d+$/.test(g.target));
  if (missing.length) add('high', 'R3', '정의되지 않은 라벨로 점프합니다',
    missing.map(g => `${g.target}(${g.n}행)`).join(', '), '', '라벨 이름을 확인하세요. 컴파일 에러 또는 의도치 않은 흐름이 됩니다.');
  const usedLabels = new Set([...nsi.gotos.map(g => g.target), ...(nsi.jumpTargets || []).map(j => j.target)]);
  const unused = nsi.labels.filter(l => !usedLabels.has(l.name));
  if (unused.length) add('low', 'R3', '아무도 점프하지 않는 라벨',
    unused.map(l => `${l.name}(${l.n}행)`).join(', '), '', '위에서 자연스럽게 흘러 들어오는 라벨이면 정상입니다(구역 표시용). 아니면 죽은 코드입니다.');

  // R4 — 상대 점프. 본 흐름(Section)에 있는 것만 실질 위험, 유틸 함수 안은 보통 정형 코드라 참고용.
  const relMain = nsi.relJumps.filter(r => !r.fn), relFn = nsi.relJumps.filter(r => r.fn);
  if (relMain.length) add('med', 'R4', `본 흐름에 상대 점프 ${relMain.length}곳`,
    '`+3` 같은 상대 점프는 사이에 명령을 한 줄만 넣어도 목적지가 어긋납니다. NSIS 는 줄이 아니라 명령 개수로 셉니다.',
    relMain.map(r => r.n + '행').join(', '),
    '라벨로 바꾸면 이후 수정에 안전해집니다.');
  if (relFn.length) add('low', 'R4', `유틸 함수 안 상대 점프 ${relFn.length}곳`,
    `${[...new Set(relFn.map(r => r.fn))].join(', ')} 안에 있습니다. 정형 코드면 그대로 둬도 무방합니다.`,
    '', '');

  // R5 — nsExec 결과 미검사
  const unchecked = nsi.execs.filter(e => !e.checked);
  if (unchecked.length) add('med', 'R5', `실행 결과를 확인하지 않는 명령 ${unchecked.length}건`,
    'Pop 으로 꺼내기만 하고 종료코드($0)를 비교하지 않으면, 실패해도 성공처럼 다음 단계로 넘어갑니다.',
    unchecked.map(e => e.n + '행').join(', '),
    'Pop $0 뒤에 ${if} $0 != 0 분기를 넣어 로그에 남기세요.');

  // R6 — 하드코딩 절대경로 / 로그 위치
  const uniqPaths = [...new Set(nsi.absPaths.map(p => p.path))];
  if (uniqPaths.length) add('low', 'R6', `하드코딩 절대경로 ${uniqPaths.length}종`,
    uniqPaths.slice(0, 6).join(' · ') + (uniqPaths.length > 6 ? ' 외' : ''), '',
    '설치 경로가 다른 환경(다른 드라이브·기본 경로 변경)에서는 찾지 못합니다. 레지스트리에서 설치 경로를 읽는 방식을 검토하세요.');
  const rootLogs = nsi.logFiles.filter(l => /^[A-Za-z]:\\[^\\]+$/.test(l.path));
  if (rootLogs.length) add('low', 'R7', '로그를 시스템 드라이브 루트에 씁니다',
    rootLogs.map(l => l.path).join(', '), rootLogs.map(l => l.n + '행').join(', '),
    '$TEMP 나 ProgramData 하위를 권합니다. 루트 쓰기는 보안 제품이 차단하는 경우가 있습니다.');

  // R8 — PPT 대조 (순서도가 있을 때만)
  if (ppt && ppt.length) {
    const pptText = ppt.map(s => s.texts.join(' ')).join(' ');
    /* 순서도 쪽 단계 순서는 '텍스트가 XML에 실린 순서'가 아니라 **화살표를 따라간 순서**로 뽑는다.
       예전엔 z-order 를 흐름으로 착각해 '버전 확인이 맨 마지막'처럼 엉뚱하게 판정했다. */
    const flow = ppt.map(sl => nscFlowPaths(sl)).find(f => f.paths.length) || { paths: [], truncated: false };
    flowPaths = flow.paths; flowCut = flow.truncated;
    const stepOfText = t => (NSC_STEPS.find(st => st.ppt.test(t)) || {}).key || '';
    const seqOf = p => { const o = []; p.forEach(n => { const k = stepOfText(n.text); if (k && !o.includes(k)) o.push(k); }); return o; };
    // 가장 많은 단계를 지나는 경로 = 정상 흐름으로 본다(중간에 빠져나가는 경로는 예외 처리).
    /* 제거 실행 줄을 먼저 확정한다 — exists(제거 전)·result(제거 후)가 이 기준으로 갈린다.
       같은 IfFileExists 한 줄이 둘 다로 잡히면 순서 비교가 무의미해진다. */
    const ctx = { uninstAt: (NSC_STEPS.find(x => x.key === 'uninst').at(nsi, {}) || 0) };
    NSC_STEPS.forEach(st => { codeAt[st.key] = st.at(nsi, ctx) || 0; });
    NSC_STEPS.forEach(st => {
      const inPpt = st.ppt.test(pptText), inCode = codeAt[st.key] > 0;
      steps.push({ key: st.key, label: st.label, ppt: inPpt, code: inCode, line: codeAt[st.key] });
      if (inPpt && !inCode) add('high', 'R8', `순서도에만 있는 단계: ${st.label}`,
        '순서도에는 그려져 있는데 스크립트에서 해당 처리를 찾지 못했습니다.', '', '스크립트에 단계를 추가하거나 순서도를 수정하세요.');
      if (!inPpt && inCode) add('med', 'R8', `스크립트에만 있는 단계: ${st.label}`,
        '스크립트는 이 처리를 하는데 순서도에는 없습니다.', `${codeAt[st.key]}행`, '순서도를 갱신하면 인수인계·검토가 쉬워집니다.');
    });

    /* R10 — 흐름(순서) 대조. 양쪽 모두에 있는 단계만 놓고 상대 순서를 비교한다.
       PPT 쪽 순서는 도형이 XML에 실린 순서(대체로 그린 순서)라 절대적이지 않다 →
       high 가 아니라 med 로 두고, 화살표 기준으로 확인하라고 안내한다. */
    const LBL = Object.fromEntries(NSC_STEPS.map(st => [st.key, st.label]));
    let pptSeq = [];
    if (flowPaths.length) {
      flowPaths.forEach(p => { const q = seqOf(p); if (q.length > pptSeq.length) pptSeq = q; });
    } else {  // 도형/연결선을 못 읽는 순서도(이미지 등) — 텍스트 순서로 폴백
      ppt.forEach(sl => sl.texts.forEach(t => { const k = stepOfText(t); if (k && !pptSeq.includes(k)) pptSeq.push(k); }));
    }
    const codeSeq = NSC_STEPS.filter(st => codeAt[st.key] > 0)
      .sort((a, b) => codeAt[a.key] - codeAt[b.key]).map(st => st.key);
    const pSeq = pptSeq.filter(k => codeSeq.includes(k));
    const cSeq = codeSeq.filter(k => pptSeq.includes(k));
    if (pSeq.length >= 2 && pSeq.join('>') !== cSeq.join('>')) {
      add('high', 'R10', '순서도와 스크립트의 단계 순서가 다릅니다',
        `순서도(화살표 기준): ${pSeq.map(k => LBL[k]).join(' → ')}  |  스크립트(줄 순서): ${cSeq.map(k => LBL[k]).join(' → ')}`,
        cSeq.map(k => `${LBL[k]} ${codeAt[k]}행`).join(' · '),
        '어느 쪽이 맞는지 정하고 한쪽을 고치세요. 순서가 다르면 실제 동작도 달라집니다.');
    }
    // R9 — 버전 개수 대조 (표기법이 달라 값 비교는 사람이 판단)
    const pptVers = [...new Set((pptText.match(/\d+\.\d+(\.\d+){0,3}(MP\d+|RU\d+|HF)?/gi) || []))];
    if (nsi.versions.length && pptVers.length && nsi.versions.length !== pptVers.length) {
      add('med', 'R9', `대상 버전 개수가 다릅니다 (코드 ${nsi.versions.length} / 순서도 ${pptVers.length})`,
        `코드: ${nsi.versions.join(', ')}  |  순서도: ${pptVers.join(', ')}`, '',
        '순서도는 마케팅 표기(15.7MP1HF 등), 코드는 빌드 번호라 값 자체는 다를 수 있습니다. 개수와 대응 관계를 확인해 주세요.');
    }
  }
  const order = { high: 0, med: 1, low: 2 };
  F.sort((a, b) => order[a.level] - order[b.level]);
  return { findings: F, steps, flowPaths, flowCut };
}

/* ── 화면 ───────────────────────────────────────────────────────────────── */
function nscReset() {
  NSC = { nsi: null, ppt: null, nsiName: '', pptName: '' };
  ['nsc-nsi-info', 'nsc-ppt-info'].forEach(id => { const e = document.getElementById(id); if (e) e.innerHTML = '<span class="u-muted-10">선택 안 됨</span>'; });
  const r = document.getElementById('nsc-result'); if (r) r.innerHTML = '';
  const f = document.getElementById('nsc-nsi-file'); if (f) f.value = '';
  const g = document.getElementById('nsc-ppt-file'); if (g) g.value = '';
}
async function nscPickNsi(input) {
  const file = input.files && input.files[0]; if (!file) return;
  const info = document.getElementById('nsc-nsi-info');
  try {
    const { text, enc } = nscDecode(await file.arrayBuffer());
    const parsed = nscParseNsi(text); parsed._raw = text;
    NSC.nsi = parsed; NSC.nsiName = file.name;
    info.innerHTML = `<b style="color:var(--text2)">${escapeHtml(file.name)}</b> · ${parsed.lines}줄 · 인코딩 ${enc}`
      + ` · 분기 ${parsed.chains.length} · 버전 ${parsed.versions.length} · 실행 ${parsed.execs.length}`
      + ` <span class="u-muted-10">· ${nscNowLabel()} 읽음</span>`;
  } catch (e) { info.innerHTML = `<span style="color:var(--danger)">읽기 실패: ${escapeHtml(e.message)}</span>`; }
  /* ⚠️ 값을 비워야 '같은 파일'을 다시 골랐을 때도 change 가 뜬다.
     안 비우면 파일 내용을 고쳐도 브라우저가 이벤트를 안 쏴서 예전 파싱 결과가 그대로 남는다. */
  input.value = '';
  if (NSC.nsi) nscRun();
}
async function nscPickPpt(input) {
  const file = input.files && input.files[0]; if (!file) return;
  const info = document.getElementById('nsc-ppt-info');
  info.innerHTML = '<span class="u-muted-10">해제 중...</span>';
  try {
    const slides = await nscParsePptx(await file.arrayBuffer());
    NSC.ppt = slides; NSC.pptName = file.name;
    const shp = slides.reduce((s, x) => s + x.shapes, 0), cn = slides.reduce((s, x) => s + x.conns, 0);
    info.innerHTML = `<b style="color:var(--text2)">${escapeHtml(file.name)}</b> · 슬라이드 ${slides.length} · 도형 ${shp} · 연결선 ${cn}`
      + ` <span class="u-muted-10">· ${nscNowLabel()} 읽음</span>`
      + (shp === 0 ? ' <span style="color:var(--warn)">— 도형이 없습니다(이미지 순서도는 읽지 못합니다)</span>' : '');
  } catch (e) { info.innerHTML = `<span style="color:var(--danger)">읽기 실패: ${escapeHtml(e.message)}</span>`; }
  input.value = '';                       // 같은 파일 재선택 대응 (위 주석 참조)
  if (NSC.nsi) nscRun();
}
function nscRun() {
  const box = document.getElementById('nsc-result'); if (!box) return;
  if (!NSC.nsi) { box.innerHTML = '<div class="u-empty">.nsi 파일을 먼저 선택하세요.</div>'; return; }
  const pick = nscPickSlides(NSC.nsi, NSC.ppt);
  const { findings: F, steps, flowPaths, flowCut } = nscRules(NSC.nsi, pick.slides);
  const LV = { high: ['🔴', 'var(--danger)', '즉시 확인'], med: ['🟡', 'var(--warn)', '유지보수 위험'], low: ['🔵', 'var(--cyan)', '개선 제안'] };
  const cnt = { high: 0, med: 0, low: 0 }; F.forEach(f => cnt[f.level]++);
  const head = `<div class="kpi-grid" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));margin-bottom:14px">
    ${['high', 'med', 'low'].map(k => `<div class="kpi"><div class="kpi-val" style="color:${LV[k][1]}">${cnt[k]}</div><div class="kpi-label">${LV[k][0]} ${LV[k][2]}</div></div>`).join('')}
  </div>`;
  const meta = `<div class="u-muted-10" style="margin-bottom:10px">${escapeHtml(NSC.nsiName)}${NSC.pptName ? ' ↔ ' + escapeHtml(NSC.pptName) : ' <span style="color:var(--warn)">(순서도 없음 — 코드 규칙만 검사)</span>'} · ${nscNowLabel()} 검사 · 규칙 기반(AI 미사용) · 파일은 브라우저 밖으로 나가지 않습니다${pick.note ? '<br>' + escapeHtml(pick.note) : ''}</div>`;
  const rows = F.map(f => `<div class="panel" style="padding:11px 13px;margin-bottom:8px;border-left:3px solid ${LV[f.level][1]}">
      <div style="display:flex;gap:8px;align-items:baseline;flex-wrap:wrap">
        <span>${LV[f.level][0]}</span>
        <b style="font-size:13px;color:var(--text-strong)">${escapeHtml(f.title)}</b>
        <span class="u-muted-10" style="margin-left:auto">${f.rule}</span>
      </div>
      <div style="font-size:12px;line-height:1.6;color:var(--text2);margin-top:5px">${escapeHtml(f.detail)}</div>
      ${f.where ? `<div class="u-muted-10" style="margin-top:4px;font-family:var(--mono,monospace)">${escapeHtml(f.where)}</div>` : ''}
      ${f.suggest ? `<div style="font-size:11.5px;color:var(--success);margin-top:5px">💡 ${escapeHtml(f.suggest)}</div>` : ''}
    </div>`).join('');
  // 지적이 없어도 무엇을 대조했는지 보여준다 — "비교를 안 한 것 같다"는 오해를 막는다.
  const table = steps.length ? `<div class="panel" style="padding:10px 13px;margin-bottom:10px">
    <div class="u-muted-10" style="margin-bottom:6px">단계별 대조 — 순서도 ↔ 스크립트</div>
    <table class="srt" style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr><th style="text-align:left;padding:4px 0">단계</th><th>순서도</th><th>스크립트</th><th style="text-align:right">위치</th></tr></thead>
      <tbody>${steps.map(x => `<tr>
        <td style="padding:3px 0">${escapeHtml(x.label)}</td>
        <td style="text-align:center">${x.ppt ? '✅' : '<span class="u-muted-10">—</span>'}</td>
        <td style="text-align:center">${x.code ? '✅' : '<span class="u-muted-10">—</span>'}</td>
        <td style="text-align:right" class="u-muted-10">${x.line ? x.line + '행' : '-'}</td>
      </tr>`).join('')}</tbody>
    </table></div>` : '';
  const flowHtml = flowPaths.length ? `<div class="panel" style="padding:10px 13px;margin-bottom:10px">
    <div class="u-muted-10" style="margin-bottom:6px">순서도 경로 — 경우의 수 ${flowPaths.length}개${flowCut ? ' (표시 상한 도달)' : ''} · 화살표와 Y/N 을 따라 전개했습니다</div>
    ${flowPaths.map((p, i) => `<div style="font-size:11.5px;line-height:1.7;color:var(--text2);padding:2px 0">
      <span class="u-muted-10">${i + 1}.</span> ${p.map(n => escapeHtml(n.text) + (n.yn ? ` <b style="color:${n.yn === 'Y' ? 'var(--success)' : 'var(--danger)'}">─${n.yn}→</b> ` : '')).join('')}
    </div>`).join('')}</div>` : '';
  box.innerHTML = meta + head + table + flowHtml + (rows || '<div class="u-empty">규칙 위반이 없습니다.</div>');
}
function nscNowLabel() {
  const d = new Date(), p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function nscCopyReport() {
  if (!NSC.nsi) { toast('검사 결과가 없습니다', true); return; }
  const { findings: F } = nscRules(NSC.nsi, nscPickSlides(NSC.nsi, NSC.ppt).slides);
  const t = [`NSIS 정합성 검사 — ${NSC.nsiName}${NSC.pptName ? ' ↔ ' + NSC.pptName : ''}`, ''];
  F.forEach(f => { t.push(`[${f.level.toUpperCase()}] ${f.rule} ${f.title}`); t.push(`  ${f.detail}`); if (f.where) t.push(`  위치: ${f.where}`); if (f.suggest) t.push(`  제안: ${f.suggest}`); t.push(''); });
  if (!F.length) t.push('규칙 위반 없음');
  navigator.clipboard.writeText(t.join('\n')).then(() => toast('검사 결과를 복사했습니다')).catch(() => toast('복사 실패', true));
}
window.nscPickNsi = nscPickNsi; window.nscPickPpt = nscPickPpt; window.nscRun = nscRun;
window.nscReset = nscReset; window.nscCopyReport = nscCopyReport;
