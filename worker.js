// ENGR HUB Cloudflare Worker v1.5.11
//
//
//
const ALLOWED_ORIGINS = [
  'https://engr-jira.github.io',
  'https://engr-jira.github.io/engr-hub',
  'https://engr-jira.github.io/engr-hub-dev',
];

function getCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User, X-Session-Token',
    'Vary': 'Origin',
  };
}

// Legacy static headers (OPTIONS preflight 전용)
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://engr-jira.github.io',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User, X-Session-Token',
};

const SUPER_ADMIN = 'mj.park';
const DEFAULT_USERS = [
  { id: 'mj.park', displayName: '\uBC15\uBBFC\uC900', role: 'super', active: true },
  { id: 'hs.lee', displayName: '\uC774\uD6A8\uC131', role: 'user', active: true },
  { id: 'mj.kim', displayName: '\uAE40\uBBFC\uC9C0', role: 'user', active: true },
  { id: 'kt.chae', displayName: '\uCC44\uAE30\uD0DC', role: 'admin', active: true },
  { id: 'sh.lee', displayName: '\uC774\uC11C\uD604', role: 'user', active: true },
  { id: 'so.choi', displayName: '\uCD5C\uC2DC\uC628', role: 'user', active: true },
  { id: 'jp.park', displayName: '\uBC15\uC9C4\uD45C', role: 'user', active: true },
  { id: 'yr.park', displayName: '\uBC15\uC608\uB9BC', role: 'user', active: true },
];
const DEFAULT_KV_STORAGE_LIMIT_BYTES = 1024 * 1024 * 1024; // Cloudflare Workers KV default 1GB basis

function corsResponse(body, status = 200, request = null) {
  const headers = request ? getCorsHeaders(request) : CORS_HEADERS;
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function decUser(encoded) {
  if (!encoded) return '';
  try {
    const binStr = atob(encoded);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  } catch { return encoded; }
}

function normalizeUserId(id = '') {
  return String(id || '').trim().toLowerCase();
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSession(env, user, minutes = 120) {
  const token = crypto.randomUUID() + '.' + crypto.randomUUID();
  const hash = await sha256Hex(token);
  const ttl = Math.max(5, Math.min(1440, parseInt(minutes, 10) || 120)) * 60;
  await env.ENGR_KV.put(`session:${hash}`, JSON.stringify({ user, createdAt: new Date().toISOString() }), { expirationTtl: ttl });
  return token;
}

async function revokeUserSessions(env, user) {
  const id = normalizeUserId(user);
  if (!id) return;
  await env.ENGR_KV.put(`session:revokedBefore:${id}`, new Date().toISOString(), { expirationTtl: 60 * 60 * 48 });
}

async function getSessionUser(env, token) {
  if (!token) return '';
  try {
    const hash = await sha256Hex(token);
    const raw = await env.ENGR_KV.get(`session:${hash}`);
    if (!raw) return '';
    const session = JSON.parse(raw);
    const user = normalizeUserId(session.user || '');
    if (!user) return '';
    const revokedBefore = await env.ENGR_KV.get(`session:revokedBefore:${user}`);
    if (revokedBefore) {
      const createdAt = Date.parse(session.createdAt || 0);
      const revokedAt = Date.parse(revokedBefore);
      if (Number.isFinite(createdAt) && Number.isFinite(revokedAt) && createdAt <= revokedAt) return '';
    }
    return user;
  } catch (_) {
    return '';
  }
}

function defaultUserMap() {
  return Object.fromEntries(DEFAULT_USERS.map(u => [u.id, { ...u }]));
}

async function getUsers(env) {
  let users = defaultUserMap();
  try {
    const raw = await env.ENGR_KV.get('config:users');
    if (raw) {
      const parsed = JSON.parse(raw);
      const list = Array.isArray(parsed) ? parsed : Object.entries(parsed).map(([id, value]) => ({ id, ...(typeof value === 'object' ? value : { role: value }) }));
      for (const item of list) {
        const id = normalizeUserId(item.id || item.userId);
        if (!id) continue;
        users[id] = {
          id,
          displayName: item.displayName || item.name || id,
          role: ['super', 'admin', 'user'].includes(item.role) ? item.role : 'user',
          active: item.active !== false,
        };
      }
    }
  } catch (_) {}

  try {
    const admins = await getAdmins(env, { skipUsers: true });
    for (const [idRaw, role] of Object.entries(admins)) {
      const id = normalizeUserId(idRaw);
      if (!id) continue;
      users[id] = users[id] || { id, displayName: id, role: 'user', active: true };
      users[id].role = role === 'super' ? 'super' : 'admin';
    }
  } catch (_) {}

  users[SUPER_ADMIN] = users[SUPER_ADMIN] || { id: SUPER_ADMIN, displayName: 'mj.park', role: 'super', active: true };
  users[SUPER_ADMIN].role = 'super';
  users[SUPER_ADMIN].active = true;
  return users;
}

async function getUserAccount(env, id) {
  const users = await getUsers(env);
  return users[normalizeUserId(id)] || null;
}
async function saveUserAccount(env, account) {
  const id = normalizeUserId(account.id || account.userId);
  if (!id || !/^[a-z0-9._-]{2,40}$/.test(id)) {
    throw new Error('\uACC4\uC815 ID\uB294 \uC601\uBB38/\uC22B\uC790/\uC810/\uD558\uC774\uD508/\uC5B8\uB354\uBC14\uB9CC \uD5C8\uC6A9\uB429\uB2C8\uB2E4.');
  }
  const users = await getUsers(env);
  users[id] = {
    id,
    displayName: String(account.displayName || account.name || id).trim(),
    role: ['super', 'admin', 'user'].includes(account.role) ? account.role : 'user',
    active: account.active !== false,
  };
  users[SUPER_ADMIN] = users[SUPER_ADMIN] || { id: SUPER_ADMIN, displayName: 'mj.park', role: 'super', active: true };
  users[SUPER_ADMIN].role = 'super';
  users[SUPER_ADMIN].active = true;
  await env.ENGR_KV.put('config:users', JSON.stringify(Object.values(users)));
  return users[id];
}
async function deactivateUserAccount(env, idRaw) {
  const id = normalizeUserId(idRaw);
  if (!id) throw new Error('\uB300\uC0C1 \uC0AC\uC6A9\uC790\uB97C \uC120\uD0DD\uD558\uC138\uC694.');
  if (id === SUPER_ADMIN) throw new Error('\uCD5C\uACE0 \uAD00\uB9AC\uC790\uB294 \uBE44\uD65C\uC131\uD654\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.');
  const users = await getUsers(env);
  const account = users[id];
  if (!account) return null;
  users[id] = { ...account, active: false };
  users[SUPER_ADMIN] = users[SUPER_ADMIN] || { id: SUPER_ADMIN, displayName: 'mj.park', role: 'super', active: true };
  users[SUPER_ADMIN].role = 'super';
  users[SUPER_ADMIN].active = true;
  await env.ENGR_KV.put('config:users', JSON.stringify(Object.values(users)));

  const admins = await getAdmins(env, { skipUsers: true });
  delete admins[id];
  admins[SUPER_ADMIN] = 'super';
  await env.ENGR_KV.put('config:admins', JSON.stringify(admins));
  await revokeUserSessions(env, id);
  return users[id];
}

async function purgeUserAccount(env, idRaw) {
  const id = normalizeUserId(idRaw);
  if (!id) throw new Error('대상 사용자를 선택하세요.');
  if (id === SUPER_ADMIN) throw new Error('최고 관리자는 삭제할 수 없습니다.');
  const users = await getUsers(env);
  if (!users[id]) throw new Error('등록된 계정이 아닙니다.');
  delete users[id];
  users[SUPER_ADMIN] = users[SUPER_ADMIN] || { id: SUPER_ADMIN, displayName: 'mj.park', role: 'super', active: true };
  users[SUPER_ADMIN].role = 'super';
  users[SUPER_ADMIN].active = true;
  await env.ENGR_KV.put('config:users', JSON.stringify(Object.values(users)));
  const admins = await getAdmins(env, { skipUsers: true });
  delete admins[id];
  admins[SUPER_ADMIN] = 'super';
  await env.ENGR_KV.put('config:admins', JSON.stringify(admins));
  try { await env.ENGR_KV.delete(`userpin:${id}`); } catch (_) {}
  await revokeUserSessions(env, id);
  return id;
}

// Team ID validation
function getTeamNames(env) {
  const raw = env.TEAM_NAMES || '';
  const ids = raw.split(',').map(s => normalizeUserId(s)).filter(Boolean);
  return [...new Set([...DEFAULT_USERS.map(u => u.id), ...ids])];
}
function getDefaultResetPin(env) {
  return env.DEFAULT_RESET_PIN || '';
}

function normalizeAIMode(mode = '') {
  const aliases = {
    analyze: 'technical_analysis',
    reply: 'reply_draft',
    similar: 'similar_issues',
  };
  return aliases[mode] || mode || 'technical_analysis';
}

function redactSensitiveText(text = '') {
  return String(text)
    .replace(/(authorization\s*[:=]\s*)(bearer\s+)?[^\s"'<>]+/gi, '$1[REDACTED]')
    .replace(/(cookie\s*[:=]\s*)[^\n\r]+/gi, '$1[REDACTED]')
    .replace(/((api[_-]?key|token|secret|password|passwd|pin)\s*[:=]\s*)[^\s"'<>]+/gi, '$1[REDACTED]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP_REDACTED]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL_REDACTED]');
}

function isValidVtHash(hash = '') {
  return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(String(hash).trim());
}
function vtDetectType(v = '') {
  const s = String(v).trim();
  if (isValidVtHash(s)) return 'hash';
  if (/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(s)) return 'ip';  // L-23: IPv4 옥텟 0-255 검증
  if (/^https?:\/\//i.test(s) || s.includes('/')) return 'url';
  if (/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(s)) return 'domain';
  return '';
}
function vtUrlId(u) { // base64url(url) without padding — VirusTotal URL identifier
  return btoa(unescape(encodeURIComponent(u))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function vtPollAnalysis(vtKey, id, tries = 6) {
  for (let i = 0; i < tries; i++) {
    const r = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers: { 'x-apikey': vtKey } });
    const d = await r.json();
    const status = d?.data?.attributes?.status;
    if (status === 'completed') return d;
    await new Promise(res => setTimeout(res, 1500));
  }
  return null;
}

async function canModifyItem(env, user, item) {
  if (!user || !item) return false;
  if (await isAdmin(env, user)) return true;
  return item.createdBy === user;
}
function cleanCommentText(text = '') {
  return String(text || '').trim().slice(0, 2000);
}
async function addCollectionComment(env, key, id, user, text, auditType) {
  const body = cleanCommentText(text);
  if (!body) return { status: 400, body: { ok: false, message: '\uB313\uAE00 \uB0B4\uC6A9\uC744 \uC785\uB825\uD558\uC138\uC694.' } };
  const raw = await env.ENGR_KV.get(key);
  const items = raw ? JSON.parse(raw) : [];
  const target = items.find(item => item.id === id);
  if (!target) return { status: 404, body: { ok: false, message: '\uB300\uC0C1\uC744 \uCC3E\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' } };
  const now = new Date().toISOString();
  const comment = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    text: body,
    createdBy: user,
    createdAt: now,
  };
  target.comments = Array.isArray(target.comments) ? target.comments : [];
  target.comments.push(comment);
  if (target.comments.length > 100) target.comments = target.comments.slice(-100);
  target.updatedAt = now;
  await env.ENGR_KV.put(key, JSON.stringify(items));
  await auditLog(env, user, auditType, { id, commentId: comment.id });
  return { status: 200, body: { ok: true, comment }, item: target };
}
async function deleteCollectionComment(env, key, id, commentId, user, auditType) {
  const raw = await env.ENGR_KV.get(key);
  const items = raw ? JSON.parse(raw) : [];
  const target = items.find(item => item.id === id);
  if (!target) return { status: 404, body: { ok: false, message: '\uB300\uC0C1\uC744 \uCC3E\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' } };
  const comments = Array.isArray(target.comments) ? target.comments : [];
  const comment = comments.find(c => c.id === commentId);
  if (!comment) return { status: 404, body: { ok: false, message: '\uB313\uAE00\uC744 \uCC3E\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' } };
  if (!await isAdmin(env, user) && comment.createdBy !== user) {
    return { status: 403, body: { ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' } };
  }
  target.comments = comments.filter(c => c.id !== commentId);
  target.updatedAt = new Date().toISOString();
  await env.ENGR_KV.put(key, JSON.stringify(items));
  await auditLog(env, user, auditType, { id, commentId });
  return { status: 200, body: { ok: true, deleted: 1 } };
}
async function loadPrivateNotes(env, user) {
  const key = `private:${user}:notes`;
  const raw = await env.ENGR_KV.get(key);
  if (raw) return { key, items: JSON.parse(raw) };

  const account = await getUserAccount(env, user);
  if (account?.displayName && account.displayName !== user) {
    const legacyKey = `private:${account.displayName}:notes`;
    const legacyRaw = await env.ENGR_KV.get(legacyKey);
    if (legacyRaw) {
      const items = JSON.parse(legacyRaw).slice(0, 300);   // L-1: 저장본과 동일하게 슬라이스해 반환(첫 GET 초과노출 방지)
      await env.ENGR_KV.put(key, JSON.stringify(items));
      return { key, items, migratedFrom: legacyKey };
    }
  }
  return { key, items: [] };
}
async function getUserPinHash(env, name) {
  if (!name) return '';
  try { return await env.ENGR_KV.get(`userpin:${name}`) || ''; } catch (_) { return ''; }
}
async function validateUserPin(env, name, pin) {
  const userHash = await getUserPinHash(env, name);
  if (userHash) return (await sha256Hex(pin)) === userHash;
  if (env.TEAM_PIN) return pin === env.TEAM_PIN;
  if (env.PIN_HASH) return (await sha256Hex(pin)) === env.PIN_HASH;
  return false;
}
async function setUserPin(env, name, pin) {
  await env.ENGR_KV.put(`userpin:${name}`, await sha256Hex(pin));
}

//
//
//
async function getAdmins(env, options = {}) {
  if (!options.skipUsers) {
    const users = await getUsers(env);
    const adminsFromUsers = {};
    Object.values(users).forEach(u => {
      if (u.active !== false && (u.role === 'admin' || u.role === 'super')) adminsFromUsers[u.id] = u.role;
    });
    if (Object.keys(adminsFromUsers).length) return adminsFromUsers;
  }
  const raw = await env.ENGR_KV.get('config:admins');
  if (!raw) return { [SUPER_ADMIN]: 'super' };
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      const obj = {};
      parsed.forEach(n => {
        const id = normalizeUserId(n);
        if (id) obj[id] = (id === SUPER_ADMIN) ? 'super' : 'admin';
      });
      return obj;
    }
    if (!parsed[SUPER_ADMIN]) parsed[SUPER_ADMIN] = 'super';
    return Object.fromEntries(Object.entries(parsed).map(([id, role]) => [normalizeUserId(id), role]));
  } catch { return { [SUPER_ADMIN]: 'super' }; }
}

async function isSuper(env, user) {
  if (user === SUPER_ADMIN) return true;
  const admins = await getAdmins(env);
  return admins[user] === 'super';
}
async function isAdmin(env, user) {
  const admins = await getAdmins(env);
  return !!admins[user];
}

//
//


//
async function getVtHistory(env) {
  const raw = await env.ENGR_KV.get('vt:history');
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.slice(0, 20) : [];
  } catch { return []; }
}
async function saveVtHistory(env, user, hash, attrs = {}) {
  try {
    const stats = attrs.last_analysis_stats || {};
    const total = (stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0) + (stats.suspicious || 0);
    const item = {
      ts: new Date().toISOString(),
      user: user || 'unknown',
      hash,
      mal: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total,
      name: attrs.meaningful_name || (Array.isArray(attrs.names) ? attrs.names[0] : '') || '',
      size: attrs.size || 0,
      type: attrs.type_description || '',
    };
    const cur = await getVtHistory(env);
    const next = [item, ...cur.filter(x => x && x.hash !== hash)].slice(0, 20);
    await env.ENGR_KV.put('vt:history', JSON.stringify(next));
    return next;
  } catch (_) {
    return null;
  }
}

async function auditLog(env, user, type, detail = {}) {
  try {
    const now = Date.now();
    const rand = crypto.randomUUID().slice(0, 8);
    const rev = String(9999999999999 - now).padStart(13, '0');
    const id = `${rev}:${type}:${rand}`;
    const tsIso = new Date(now).toISOString();
    const item = JSON.stringify({ ...detail, ts: tsIso, tsNum: now, user, type });
    const ttl = { expirationTtl: 60 * 60 * 24 * 90 };
    // §H 1단계: KV(기존, 소스 유지) + D1(audit_log, 가산) 이중쓰기. 둘 다 best-effort, 동일 id로 멱등.
    const kvP = env.ENGR_KV.put(`auditLatest:${id}`, item, ttl);
    const d1P = env.DB
      ? env.DB.prepare('INSERT OR IGNORE INTO audit_log (id,ts,ts_num,user,type,detail_json) VALUES (?,?,?,?,?,?)').bind(id, tsIso, now, user, type, JSON.stringify(detail)).run()
      : Promise.resolve();
    await Promise.allSettled([kvP, d1P]);
  } catch (_) {}
}

//
function usageKeys(now=new Date()){
  const p=kstParts(now);
  return { day:`${p.year}-${p.month}-${p.day}`, month:`${p.year}-${p.month}` };
}
function createUsageBucket(){ return { today:0, month:0, successToday:0, successMonth:0, failToday:0, failMonth:0 }; }
function createUsageStore(){ return { team:createUsageBucket(), users:{} }; }
function ensureUserUsage(store,user){
  if(!user)return createUsageBucket();
  if(!store.users)store.users={};
  if(!store.users[user])store.users[user]=createUsageBucket();
  return store.users[user];
}
function bumpUsageBucket(b,type,scope){
  if(type==='AI_REQUEST') b[scope==='day'?'today':'month']=(b[scope==='day'?'today':'month']||0)+1;
  if(type==='AI_SUCCESS') b[scope==='day'?'successToday':'successMonth']=(b[scope==='day'?'successToday':'successMonth']||0)+1;
  if(type==='AI_FAIL') b[scope==='day'?'failToday':'failMonth']=(b[scope==='day'?'failToday':'failMonth']||0)+1;
}
async function updateAIUsage(env,user,outcome,model){
  if(!['success','fail','cached'].includes(outcome))return;
  try{
    const keys=usageKeys();
    const kvKey=`usage:v2:${keys.month}`;
    let store={days:{},team:createUsageBucket(),users:{}};
    try{const raw=await env.ENGR_KV.get(kvKey);if(raw)store=JSON.parse(raw);}catch(_){ }
    if(!store.days)store.days={};
    if(!store.days[keys.day])store.days[keys.day]={team:createUsageBucket(),users:{}};
    if(!store.team)store.team=createUsageBucket();
    if(!store.users)store.users={};
    const dayStore=store.days[keys.day];
    if(!dayStore.team)dayStore.team=createUsageBucket();
    if(!dayStore.users)dayStore.users={};
    const type=outcome==='fail'?'AI_FAIL':'AI_SUCCESS';
    bumpUsageBucket(dayStore.team,'AI_REQUEST','day');
    bumpUsageBucket(store.team,'AI_REQUEST','month');
    bumpUsageBucket(dayStore.team,type,'day');
    bumpUsageBucket(store.team,type,'month');
    // 모델(제공자)별 호출 카운트 — 실제 호출(성공/캐시)만
    if(outcome!=='fail'){
      const provider=String(model||'').includes('gemini')?'gemini':'llama';
      if(!dayStore.team.models)dayStore.team.models={};
      if(!store.team.models)store.team.models={};
      dayStore.team.models[provider]=(dayStore.team.models[provider]||0)+1;
      store.team.models[provider]=(store.team.models[provider]||0)+1;
    }
    if(user){
      bumpUsageBucket(ensureUserUsage(dayStore,user),'AI_REQUEST','day');
      bumpUsageBucket(ensureUserUsage(store,user),'AI_REQUEST','month');
      bumpUsageBucket(ensureUserUsage(dayStore,user),type,'day');
      bumpUsageBucket(ensureUserUsage(store,user),type,'month');
    }
    store.updatedAt=new Date().toISOString();
    await env.ENGR_KV.put(kvKey,JSON.stringify(store),{expirationTtl:60*60*24*400});
  }catch(_){ }
}
async function readUsageCounter(env,user=''){
  const keys=usageKeys();
  try{
    const raw=await env.ENGR_KV.get(`usage:v2:${keys.month}`);
    if(raw){
      const store=JSON.parse(raw);
      const day=store.days?.[keys.day]||{};
      const u=(user||'').trim();
      const team={
        today:day.team?.today||0,
        month:store.team?.month||0,
        successToday:day.team?.successToday||0,
        successMonth:store.team?.successMonth||0,
        failToday:day.team?.failToday||0,
        failMonth:store.team?.failMonth||0,
        modelsToday:day.team?.models||{},
        modelsMonth:store.team?.models||{},
      };
      const du=u?(day.users?.[u]||{}):{};
      const mu=u?(store.users?.[u]||{}):{};
      const me={
        today:du.today||0,
        month:mu.month||0,
        successToday:du.successToday||0,
        successMonth:mu.successMonth||0,
        failToday:du.failToday||0,
        failMonth:mu.failMonth||0,
      };
      return {ok:true,timezone:'Asia/Seoul',asOf:new Date().toISOString(),source:'counter_v2',note: 'AI usage counter data.',me,team};
    }
  }catch(_){ }
  let daily=null, monthly=null;
  try{const raw=await env.ENGR_KV.get(`usage:daily:${keys.day}`);if(raw)daily=JSON.parse(raw);}catch(_){ }
  try{const raw=await env.ENGR_KV.get(`usage:monthly:${keys.month}`);if(raw)monthly=JSON.parse(raw);}catch(_){ }
  if(!daily&&!monthly)return null;
  const u=(user||'').trim();
  const team={
    today:daily?.team?.today||0,
    month:monthly?.team?.month||0,
    successToday:daily?.team?.successToday||0,
    successMonth:monthly?.team?.successMonth||0,
    failToday:daily?.team?.failToday||0,
    failMonth:monthly?.team?.failMonth||0,
  };
  const du=u?(daily?.users?.[u]||{}):{};
  const mu=u?(monthly?.users?.[u]||{}):{};
  const me={
    today:du.today||0,
    month:mu.month||0,
    successToday:du.successToday||0,
    successMonth:mu.successMonth||0,
    failToday:du.failToday||0,
    failMonth:mu.failMonth||0,
  };
  return {ok:true,timezone:'Asia/Seoul',asOf:new Date().toISOString(),source:'counter',note: 'AI usage counter data.',me,team};
}

//
async function callAI(env, userPrompt, mode = 'technical_analysis') {
  mode = normalizeAIMode(mode);
  //
  let systemPrompt = '';
  try { systemPrompt = await env.ENGR_KV.get('config:ai_system') || ''; } catch (_) {}

  if (!systemPrompt.trim()) {
    systemPrompt = `You are a security engineering operations assistant for ENGR HUB.
Separate confirmed facts from assumptions. Do not invent Jira, log, KB, or customer data.
Mask or omit credentials, PINs, API keys, tokens, cookies, internal URLs, and personal data.
For log analysis, start with evidence from logs, then facts, possible causes, impact, checks, actions, and next questions.
Customer-facing drafts must be concise, polite, and limited to confirmed facts.
All outputs are review drafts for humans; never instruct automatic customer sending, Jira changes, policy changes, or data deletion.`.trim();
  }
  const promptLimit = mode === 'log' ? 18000 : 24000;
  const rawPrompt = redactSensitiveText(userPrompt || '');
  const clippedPrompt = rawPrompt.length > promptLimit
    ? rawPrompt.slice(0, promptLimit) + `\n\n[\uC785\uB825\uC774 \uB108\uBB34 \uAE38\uC5B4 ${promptLimit}\uC790\uB85C \uC904\uC600\uC2B5\uB2C8\uB2E4.]`
    : rawPrompt;

  //
  const fullText = `[SYSTEM]${systemPrompt}\n[USER]${clippedPrompt}`;
  const hash = await sha256Hex(mode + '|' + fullText);
  const cacheKey = `ai:v3:${mode}:${hash.slice(0, 40)}`;  // v3: 옛 워커가 text를 배열로 저장한 오염 캐시 무효화(callAI 비-string 방어와 함께)

  //
  try {
    const cached = await env.ENGR_KV.get(cacheKey);
    if (cached) {
      const data = JSON.parse(cached);
      data._cached = true;
      return data;
    }
  } catch (_) {}

  //
  let userText = clippedPrompt;

  //
  let text = '';
  let modelUsed = '';

  // 1\uC21C\uC704: Google Gemini (\uBB34\uB8CC \uB4F1\uAE09) \u2014 GEMINI_API_KEY \uB610\uB294 GEMINI_KEY \uC124\uC815 \uC2DC
  const geminiKey = env.GEMINI_API_KEY || env.GEMINI_KEY;
  if (geminiKey) {
    try {
      const gModel = env.GEMINI_MODEL || 'gemini-2.5-flash';
      const gRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${gModel}:generateContent?key=${geminiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: 'user', parts: [{ text: userText }] }],
          // maxOutputTokens 상향 + thinking 비활성화(2.5-flash는 사고 토큰이 출력예산을 잠식해 답변이 잘림)
          generationConfig: { temperature: 0.4, maxOutputTokens: 8192, thinkingConfig: { thinkingBudget: 0 } },
        }),
      });
      if (gRes.ok) {
        const gData = await gRes.json();
        text = (gData?.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('') || '';
        if (text) modelUsed = gModel;
      }
    } catch (_) {}
  }

  // \uD3F4\uBC31: Cloudflare Workers AI (Llama) \u2014 Gemini \uBBF8\uC124\uC815/\uC2E4\uD328 \uC2DC (\uBB34\uBE44\uC6A9)
  if (!text) {
    const response = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userText },
      ],
      max_tokens: 8192,
      temperature: 0.4,
    });
    text = response?.response || '';
    if (text) modelUsed = 'llama-3.3-70b';
  }

  if (!text) throw new Error('AI \uC751\uB2F5\uC774 \uBE44\uC5B4 \uC788\uC2B5\uB2C8\uB2E4.');

  //
  const result = {
    candidates: [{ content: { parts: [{ text }] } }],
    _model: modelUsed,
  };

  //
  try {
    await env.ENGR_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: 60 * 60 * 24 * 7 });
  } catch (_) {}

  return result;
}

//
async function handleJiraSearch(env, user = "") {
  let months = 3;
  try {
    const cfg = await env.ENGR_KV.get('config:range_months') || await env.ENGR_KV.get('config:jira_range_months');
    if (cfg) months = parseInt(cfg, 10) || 3;
  } catch (_) {}
  months = Math.max(1, Math.min(60, months));

  const d = new Date();
  d.setMonth(d.getMonth() - months);
  const dateStr = d.toISOString().slice(0, 10);
  const jql = `project=ENGR AND created >= "${dateStr}" ORDER BY created DESC`;

  const jiraAuth = 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN);
  const headers = {
    'Authorization': jiraAuth,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };

  //
  const fields = ['summary','status','priority','assignee','reporter','created','updated','labels','issuetype','parent','duedate','customfield_10134','customfield_10036','customfield_10178','customfield_10015','customfield_10244'];

  let allIssues = [];
  let nextPageToken = undefined;
  let pageCount = 0;
  const maxPages = 12; // Up to 1,200 issues per sync to protect Worker CPU.
  do {
    const body = { jql, maxResults: 100, fieldsByKeys: false, fields };
    if (nextPageToken) body.nextPageToken = nextPageToken;
    const res = await fetch('https://escare-engr.atlassian.net/rest/api/3/search/jql', {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errText = await res.text();
      return new Response(errText, { status: res.status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8' } });
    }
    const page = await res.json();
    allIssues = allIssues.concat(page.issues || []);
    nextPageToken = page.nextPageToken;
    pageCount++;
  } while (nextPageToken && pageCount < maxPages);

  const sync = { rangeMonths: months, count: allIssues.length, syncedAt: new Date().toISOString(), syncedBy: user || 'system', jql, lightweight: true, truncated: !!nextPageToken, pages: pageCount };
  try { await env.ENGR_KV.put('config:last_jira_sync', JSON.stringify(sync)); } catch (_) {}
  return new Response(JSON.stringify({ issues: allIssues, total: allIssues.length, rangeMonths: months, sync }), {
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8' },
  });
}


//
const KB_PRODUCT_SEED = [
  { product:'DLP', q:'Symantec Data Loss Prevention DLP', topics:['install upgrade','agent endpoint','policy detection','incident response','enforce server','database oracle','email prevent','network prevent','discover scan','troubleshooting logs'] },
  { product:'SEP', q:'Symantec Endpoint Protection SEP SEPM 14.3', topics:['install upgrade','client communication','definitions LiveUpdate','policy configuration','content update','database embedded','replication','EDR ATP integration','uninstall cleanwipe','troubleshooting logs'] },
  { product:'CASB', q:'CloudSOC CASB Gatelet Securlet', topics:['gatelet','securlet','SAML SSO','user sync','policy incident','data exposure','API connection','office 365','salesforce','troubleshooting'] },
  { product:'SWG', q:'Cloud SWG Secure Web Gateway', topics:['policy','access method','authentication','SAML','PAC file','traffic forwarding','SSL interception','reporting','agent','troubleshooting'] },
  { product:'WSS', q:'Web Security Service WSS Cloud SWG', topics:['WSS Agent','explicit proxy','IPSec','auth connector','portal policy','SSL inspection','bypass','roaming users','reporting','troubleshooting'] },
  { product:'LUA', q:'Symantec LiveUpdate Administrator LUA', topics:['install upgrade','download schedule','distribution center','SEP content','proxy setting','certificate','database','cleanup','performance','troubleshooting logs'] },
  { product:'ProxySG', q:'ProxySG SGOS Advanced Secure Gateway', topics:['SGOS upgrade','policy CPL','SSL proxy','authentication realm','ICAP','content filtering','access log','proxy forwarding','certificate','troubleshooting'] },
];
function kbSeedItems(){
  return KB_PRODUCT_SEED.flatMap(seed=>seed.topics.map(topic=>({
    title:`KB recent 5 years - ${seed.product} - ${topic}`,
    category:'Broadcom KB',
    product:seed.product,
    q:`${seed.q} ${topic}`,
  })));
}
function htmlDecode(s=''){
  return String(s)
    .replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;|&apos;/g,"'")
    .replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/\s+/g,' ').trim();
}
function stripTags(s=''){return htmlDecode(String(s).replace(/<[^>]+>/g,' '));}
function kbArticleTitleFromSlug(slug=''){
  return slug.replace(/-/g,' ').replace(/\s+/g,' ').trim().replace(/\b\w/g,m=>m.toUpperCase());
}
function kbCursorEncode(cursor){
  try{return btoa(JSON.stringify(cursor)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}catch(_){return '';}
}
function kbCursorDecode(raw){
  if(!raw)return { task:0, page:0 };
  try{
    const padded = String(raw).replace(/-/g,'+').replace(/_/g,'/');
    return { task:0, page:0, ...JSON.parse(atob(padded + '==='.slice((padded.length + 3) % 4))) };
  }catch(_){return { task:0, page:0 };}
}
function normalizeKbArticleUrl(raw=''){
  try{
    const u = new URL(String(raw).trim());
    if(u.hostname !== 'knowledge.broadcom.com')return null;
    const m = u.pathname.match(/^\/external\/article\/(\d+)(?:\/([^/?#]+))?/i);
    if(!m)return null;
    const slug = (m[2] || '').replace(/\.html$/i,'');
    const path = slug ? `/external/article/${m[1]}/${slug}` : `/external/article/${m[1]}`;
    return { articleId:m[1], slug, url:`https://knowledge.broadcom.com${path}` };
  }catch(_){return null;}
}
function extractKbDate(html=''){
  const text = stripTags(html).slice(0, 12000);
  const metaPatterns = [
    /(?:dateModified|article:modified_time|modified_time|lastmod)["'][^>]+content=["']([^"']+)["']/i,
    /(?:datePublished|article:published_time|published_time)["'][^>]+content=["']([^"']+)["']/i,
    /(?:Updated|Last Updated|Modified|Published)\s*:?\s*([A-Z][a-z]+ \d{1,2}, \d{4}|\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{4})/i
  ];
  for(const re of metaPatterns){
    const m = html.match(re) || text.match(re);
    if(m){
      const d = new Date(m[1]);
      if(!Number.isNaN(d.getTime()))return d.toISOString();
    }
  }
  return null;
}
function extractKbTitle(html='', fallback=''){
  const candidates = [
    html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i)?.[1],
    html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1],
    html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i)?.[1],
    fallback
  ];
  return stripTags(candidates.find(Boolean) || '').replace(/\s*\|\s*Broadcom\s*$/i,'') || fallback;
}
function kbSearchTasks(){
  return kbSeedItems().map(seed=>({
    product: seed.product,
    q: `site:knowledge.broadcom.com/external/article ${seed.q}`,
    queryLabel: seed.q
  }));
}
const KB_VERIFIED_SEED = [
  { product:'SEP', title:'Versions, system requirements, release dates - SEP/SES 14.3.x', url:'https://knowledge.broadcom.com/external/article/154575' },
  { product:'SEP', title:'Versions, system requirements, release dates - SEP/SES 16.x', url:'https://knowledge.broadcom.com/external/article/397614' },
  { product:'SEP', title:'New fixes and component versions in SEP 14.3 RU10', url:'https://knowledge.broadcom.com/external/article/386578' },
  { product:'SEP', title:'New fixes and component versions in SEP 14.4', url:'https://knowledge.broadcom.com/external/article/430629' },
  { product:'SEP', title:"What's new for all releases of Symantec Endpoint Protection 14.x", url:'https://knowledge.broadcom.com/external/article/185214' },
  { product:'SEP', title:'Windows compatibility with Symantec Endpoint Protection clients', url:'https://knowledge.broadcom.com/external/article/163625' },
  { product:'SEP', title:'Product guides for Symantec Endpoint Protection', url:'https://knowledge.broadcom.com/external/article/185213' },
  { product:'SEP', title:'Download the latest version of Endpoint Protection', url:'https://knowledge.broadcom.com/external/article/157395' },
  { product:'SEP', title:'SEP CVE/security advisory portal', url:'https://knowledge.broadcom.com/external/article/225891' },
  { product:'DLP', title:'DLP Endpoint Agent build numbers and latest hotfix information', url:'https://knowledge.broadcom.com/external/article/185118' },
  { product:'DLP', title:'Symantec Data Loss Prevention - Release types', url:'https://knowledge.broadcom.com/external/article/164993' },
  { product:'DLP', title:'DLP Quick Upgrade Guides', url:'https://knowledge.broadcom.com/external/article/270589' },
  { product:'DLP', title:'High Level Steps for Upgrading DLP', url:'https://knowledge.broadcom.com/external/article/247415' },
  { product:'DLP', title:'DLP Release Cadence', url:'https://knowledge.broadcom.com/external/article/211665' },
  { product:'DLP', title:'Recent DLP Product Advisories', url:'https://knowledge.broadcom.com/external/article/269358' },
  { product:'DLP', title:'DLP CVE-2025-22228 impact', url:'https://knowledge.broadcom.com/external/article/430578' },
  { product:'DLP', title:'DLP CVE-2025-41249 impact', url:'https://knowledge.broadcom.com/external/article/417005' },
  { product:'DLP', title:'DLP CVE-2025-21587 impact', url:'https://knowledge.broadcom.com/external/article/404445' },
  { product:'DLP', title:'DLP CVE-2025-22233 impact', url:'https://knowledge.broadcom.com/external/article/404795' },
  { product:'DLP', title:'DLP CVE-2025-48976 impact', url:'https://knowledge.broadcom.com/external/article/417030' },
  { product:'ProxySG', title:'End of life and lifecycle for Edge SWG/ProxySG/ASG', url:'https://knowledge.broadcom.com/external/article/151102' },
  { product:'ProxySG', title:'Edge SWG ProxySG - Network Web Prevent DLP integration', url:'https://knowledge.broadcom.com/external/article/230914' },
  { product:'ProxySG', title:'Secure ICAP between DLP detection server and ProxySG', url:'https://knowledge.broadcom.com/external/article/383826' },
  { product:'ProxySG', title:'ISG/MC/SGOS/Reporter CVE-2025-32728 impact', url:'https://knowledge.broadcom.com/external/article/400771' },
  { product:'Support', title:'Advanced search options on the Broadcom Support Portal', url:'https://knowledge.broadcom.com/external/article/200997' },
  { product:'Support', title:'Search personalization features on the Broadcom Support Portal', url:'https://knowledge.broadcom.com/external/article/201253' },
  { product:'Support', title:'Subscribe to a Broadcom knowledge article by article or product', url:'https://knowledge.broadcom.com/external/article/275360' },
  { product:'Support', title:'Accessing Broadcom knowledge base articles from a case', url:'https://knowledge.broadcom.com/external/article/252162' },
];
function collectKbUrlsFromText(value, source='text'){
  const text = typeof value === 'string' ? value : JSON.stringify(value || '');
  const out = [];
  const full = /https?:\/\/knowledge\.broadcom\.com\/external\/article\/\d+(?:\/[A-Za-z0-9-]+)?/gi;
  const query = /https?:\/\/knowledge\.broadcom\.com\/external\/article\?articleId=(\d+)/gi;
  let m;
  while((m=full.exec(text)))out.push({ url:m[0], source });
  while((m=query.exec(text)))out.push({ url:`https://knowledge.broadcom.com/external/article/${m[1]}`, source });
  return out;
}
async function discoverKbFromJira(env, limit=80){
  if(!env.JIRA_TOKEN)return [];
  const jiraAuth = 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN);
  const body = {
    jql:'project=ENGR AND text ~ "knowledge.broadcom.com/external/article" ORDER BY updated DESC',
    maxResults:Math.max(1, Math.min(100, limit)),
    fieldsByKeys:false,
    fields:['summary','description','comment','labels','updated']
  };
  try{
    const res = await fetch('https://escare-engr.atlassian.net/rest/api/3/search/jql', {
      method:'POST',
      headers:{ 'Authorization':jiraAuth, 'Content-Type':'application/json', 'Accept':'application/json' },
      body:JSON.stringify(body)
    });
    if(!res.ok)return [];
    const data = await res.json();
    return (data.issues || []).flatMap(issue=>collectKbUrlsFromText(issue, `jira:${issue.key || ''}`));
  }catch(_){ return []; }
}
async function importFreeKbLinks(env, user, years=5, opts={}){
  const raw = await env.ENGR_KV.get('config:links') || await env.ENGR_KV.get('links');
  const links = raw ? JSON.parse(raw) : [];
  const cutoff = new Date(); cutoff.setUTCFullYear(cutoff.getUTCFullYear() - years);
  const limit = Math.max(1, Math.min(120, parseInt(opts.limit || '80', 10) || 80));
  const candidates = [
    ...KB_VERIFIED_SEED.map(x=>({ ...x, source:'curated_seed' })),
    ...links.flatMap(l=>collectKbUrlsFromText(l, 'existing_links')),
    ...(await discoverKbFromJira(env, limit))
  ];
  const existingArticleIds = new Set(links.map(l=>String(l.articleId || normalizeKbArticleUrl(l.url)?.articleId || '')).filter(Boolean));
  const existingUrls = new Set(links.map(l=>String(l.url || '').replace(/[?#].*$/,'')));
  const seen = new Set();
  let imported = 0, duplicated = 0, inaccessible = 0, scanned = 0, discovered = 0;
  for(const candidate of candidates){
    if(scanned >= limit)break;
    const normalized = normalizeKbArticleUrl(candidate.url);
    if(!normalized){ inaccessible++; continue; }
    if(seen.has(normalized.articleId)){ duplicated++; continue; }
    seen.add(normalized.articleId);
    scanned++; discovered++;
    if(existingArticleIds.has(normalized.articleId) || existingUrls.has(normalized.url)){ duplicated++; continue; }
    const article = await verifyKbArticle({ ...candidate, url:normalized.url, product:candidate.product || 'Broadcom', title:candidate.title || '' }, cutoff);
    if(!article.ok){ inaccessible++; continue; }
    const now = new Date().toISOString();
    links.unshift({
      id: crypto.randomUUID(),
      category:'Broadcom KB',
      product:article.product,
      articleId:article.articleId,
      source:'broadcom-kb-free-import',
      title:`[${article.product}] ${article.title}`,
      url:article.url,
      desc:`Free verified import from ${candidate.source || 'known source'}. ${article.dateUnknown ? 'Document date unknown' : 'Document date ' + article.updatedAt.slice(0,10)}. Verified ${now.slice(0,10)}`,
      updatedAt:article.updatedAt || null,
      dateUnknown:article.dateUnknown,
      verifiedAt:now,
      createdBy:user || 'system',
      createdAt:now
    });
    existingArticleIds.add(article.articleId);
    existingUrls.add(article.url);
    imported++;
  }
  if(imported > 0)await env.ENGR_KV.put('config:links', JSON.stringify(links));
  await auditLog(env, user || 'system', 'LINK_KB_IMPORT', { years, imported, duplicated, inaccessible, scanned, discovered, mode:'free_verified' });
  return { ok:true, imported, added:imported, duplicated, skipped:duplicated, inaccessible, scanned, discovered, years, total:links.length, attempts:0, errors:0, nextCursor:null, mode:'free_verified', cost:'free' };
}
async function googleKbSearch(env, task, years, page){
  const key = env.GOOGLE_SEARCH_KEY;
  const cx = env.GOOGLE_SEARCH_CX;
  if(!key || !cx)throw new Error('GOOGLE_SEARCH_KEY and GOOGLE_SEARCH_CX are required for Broadcom KB import.');
  const api = new URL('https://www.googleapis.com/customsearch/v1');
  api.searchParams.set('key', key);
  api.searchParams.set('cx', cx);
  api.searchParams.set('q', task.q);
  api.searchParams.set('dateRestrict', `y${years}`);
  api.searchParams.set('num', '10');
  api.searchParams.set('start', String(page * 10 + 1));
  const res = await fetch(api.toString(), { headers:{ 'Accept':'application/json' } });
  if(!res.ok)throw new Error(`Google search failed: ${res.status}`);
  const data = await res.json();
  return (data.items || []).map(item=>({
    title: item.title || '',
    url: item.link || '',
    snippet: item.snippet || '',
    product: task.product,
    queryLabel: task.queryLabel
  }));
}
async function verifyKbArticle(candidate, cutoff){
  const normalized = normalizeKbArticleUrl(candidate.url);
  if(!normalized)return { ok:false, reason:'not_article' };
  const res = await fetch(normalized.url, { headers:{ 'Accept':'text/html,application/xhtml+xml', 'User-Agent':'ENGR-HUB-KB-Importer/1.1' } });
  if(!res.ok)return { ok:false, reason:`http_${res.status}`, articleId:normalized.articleId, url:normalized.url };
  const html = await res.text();
  const updatedAt = extractKbDate(html);
  const dateUnknown = !updatedAt;
  if(updatedAt && new Date(updatedAt) < cutoff)return { ok:false, reason:'older_than_range', articleId:normalized.articleId, url:normalized.url };
  const title = extractKbTitle(html, candidate.title || kbArticleTitleFromSlug(normalized.slug) || `Broadcom KB ${normalized.articleId}`);
  return { ok:true, articleId:normalized.articleId, url:normalized.url, title, product:candidate.product, updatedAt, dateUnknown, queryLabel:candidate.queryLabel };
}
async function importPaidKbLinks(env, user, years=5, opts={}){
  if(!env.GOOGLE_SEARCH_KEY || !env.GOOGLE_SEARCH_CX){
    return { ok:false, message:'GOOGLE_SEARCH_KEY and GOOGLE_SEARCH_CX Worker secrets are required for Broadcom KB import.', imported:0, duplicated:0, inaccessible:0, scanned:0, discovered:0, mode:'search_api_required' };
  }
  const raw = await env.ENGR_KV.get('config:links') || await env.ENGR_KV.get('links');
  const links = raw ? JSON.parse(raw) : [];
  let imported = 0, duplicated = 0, inaccessible = 0, scanned = 0, discovered = 0, attempts = 0, errors = 0;
  const cutoff = new Date(); cutoff.setUTCFullYear(cutoff.getUTCFullYear() - years);
  const limit = Math.max(1, Math.min(50, parseInt(opts.limit || '20', 10) || 20));
  const maxQueries = Math.max(1, Math.min(6, parseInt(opts.maxQueries || '3', 10) || 3));
  const maxPagesPerTask = Math.max(1, Math.min(10, parseInt(opts.maxPagesPerTask || '3', 10) || 3));
  const tasks = kbSearchTasks();
  const cursor = kbCursorDecode(opts.cursor || '');
  let taskIndex = Math.max(0, Math.min(tasks.length, parseInt(cursor.task || 0, 10) || 0));
  let page = Math.max(0, Math.min(maxPagesPerTask - 1, parseInt(cursor.page || 0, 10) || 0));
  const seenInRun = new Set();
  const existingArticleIds = new Set(links.map(l=>String(l.articleId || normalizeKbArticleUrl(l.url)?.articleId || '')).filter(Boolean));
  const existingUrls = new Set(links.map(l=>String(l.url || '').replace(/[?#].*$/,'')));
  while(taskIndex < tasks.length && attempts < maxQueries && scanned < limit){
    const task = tasks[taskIndex];
    try{
      attempts++;
      const results = await googleKbSearch(env, task, years, page);
      if(!results.length){
        page = maxPagesPerTask;
      }
      for(const result of results){
        if(scanned >= limit)break;
        scanned++;
        const normalized = normalizeKbArticleUrl(result.url);
        if(!normalized){ inaccessible++; continue; }
        if(seenInRun.has(normalized.articleId)){ duplicated++; continue; }
        seenInRun.add(normalized.articleId);
        discovered++;
        if(existingArticleIds.has(normalized.articleId) || existingUrls.has(normalized.url)){ duplicated++; continue; }
        const article = await verifyKbArticle({ ...result, url: normalized.url }, cutoff);
        if(!article.ok){ inaccessible++; continue; }
        const now = new Date().toISOString();
        const item = {
          id: crypto.randomUUID(),
          category: 'Broadcom KB',
          product: article.product,
          articleId: article.articleId,
          source: 'broadcom-kb-import',
          title: `[${article.product}] ${article.title}`,
          url: article.url,
          desc: `Broadcom KB Article ${article.articleId}. Imported from ${article.queryLabel}. ${article.dateUnknown ? 'Document date unknown' : 'Document date ' + article.updatedAt.slice(0,10)}. Verified ${now.slice(0,10)}`,
          updatedAt: article.updatedAt || null,
          dateUnknown: article.dateUnknown,
          verifiedAt: now,
          createdBy: user || 'system',
          createdAt: now
        };
        links.unshift(item);
        existingArticleIds.add(article.articleId);
        existingUrls.add(article.url);
        imported++;
      }
      page++;
      if(page >= maxPagesPerTask){ taskIndex++; page = 0; }
    }catch(e){
      errors++;
      page++;
      if(page >= maxPagesPerTask){ taskIndex++; page = 0; }
    }
  }
  if(imported > 0)await env.ENGR_KV.put('config:links', JSON.stringify(links));
  const nextCursor = taskIndex < tasks.length ? kbCursorEncode({ task:taskIndex, page }) : null;
  await auditLog(env, user || 'system', 'LINK_KB_IMPORT', { years, imported, duplicated, inaccessible, scanned, discovered, attempts, errors, nextCursor:!!nextCursor, mode:'articles' });
  return { ok:true, imported, added:imported, duplicated, skipped:duplicated, inaccessible, scanned, discovered, years, total:links.length, attempts, errors, nextCursor, mode:'articles' };
}
async function importRecentKBLinks(env, user, years=5, opts={}){
  const provider = String(opts.provider || '').toLowerCase();
  const paidAllowed = env.KB_ALLOW_PAID_SEARCH === 'true' || provider === 'google';
  if(paidAllowed)return await importPaidKbLinks(env, user, years, opts);
  return await importFreeKbLinks(env, user, years, opts);
}
function kstParts(d){
  const fmt = new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'});
  return Object.fromEntries(fmt.formatToParts(d).filter(p=>p.type!=='literal').map(p=>[p.type,p.value]));
}
function emptyUsageStats(){
  return { today:0, month:0, successToday:0, successMonth:0, failToday:0, failMonth:0 };
}
function addUsage(stats, field, isToday, isMonth){
  if (isToday) stats[field+'Today'] = (stats[field+'Today'] || 0) + 1;
  if (isMonth) stats[field+'Month'] = (stats[field+'Month'] || 0) + 1;
}
async function getUsage(env, user='') {
  const cached = await readUsageCounter(env, user);
  if (cached) return cached;
  return {
    ok: true,
    timezone: 'Asia/Seoul',
    asOf: new Date().toISOString(),
    source: 'counter_empty',
    note: 'AI usage counter data.',
    me: emptyUsageStats(),
    team: emptyUsageStats(),
  };
}


//
function configuredBytes(env, name, fallback) {
  const raw = env?.[name];
  if (!raw) return fallback;
  const n = Number(String(raw).replace(/,/g, '').trim());
  return Number.isFinite(n) && n > 0 ? n : fallback;
}
function storageCountLabel(r) {
  return r.truncated ? `${r.count}+` : String(r.count);
}
async function countKVKeys(env, prefix, max = 1000) {
  let cursor, count = 0, truncated = false;
  do {
    const page = await env.ENGR_KV.list({ prefix, cursor, limit: 100 });
    const keys = page.keys || [];
    count += keys.length;
    cursor = page.cursor;
    if (count >= max && cursor) { truncated = true; break; }
  } while (cursor);
  return { count, truncated };
}
async function kvSize(env, key) {
  try {
    const raw = await env.ENGR_KV.get(key);
    return raw ? new TextEncoder().encode(raw).length : 0;
  } catch (_) { return 0; }
}
async function estimatePrefixBytes(env, prefix, max = 1000, sampleSize = 5) {
  let cursor, count = 0, truncated = false;
  const sample = [];
  do {
    const page = await env.ENGR_KV.list({ prefix, cursor, limit: 100 });
    const keys = page.keys || [];
    for (const k of keys) {
      count++;
      if (sample.length < sampleSize) sample.push(k.name);
      if (count >= max) break;
    }
    cursor = page.cursor;
    if (count >= max && cursor) { truncated = true; break; }
  } while (cursor);
  let bytes = 0, sampled = 0;
  for (const key of sample) {
    const b = await kvSize(env, key);
    if (b > 0) { bytes += b; sampled++; }
  }
  const avg = sampled ? bytes / sampled : 0;
  return { count, truncated, bytes: Math.round(avg * count), estimated: true, sampled };
}
async function getStorageStats(env) {
  const DEFAULT_KV_STORAGE_LIMIT_BYTES = 1024 * 1024 * 1024; // Cloudflare Workers KV default 1GB basis
  const quotaBytes = configuredBytes(env, 'KV_STORAGE_LIMIT_BYTES', DEFAULT_KV_STORAGE_LIMIT_BYTES);
  const quotaLabel = quotaBytes >= 1024 * 1024 * 1024
    ? `${(quotaBytes / (1024 * 1024 * 1024)).toFixed(quotaBytes % (1024 * 1024 * 1024) ? 2 : 0)} GB`
    : `${(quotaBytes / (1024 * 1024)).toFixed(0)} MB`;

  const linksBytes = await kvSize(env, 'config:links');
  const knowledgeBytes = await kvSize(env, 'config:knowledge');
  const eosBytes = await kvSize(env, 'config:eos');
  const adminsBytes = await kvSize(env, 'config:admins');
  const audit = await estimatePrefixBytes(env, 'auditLatest:', 1000, 5);
  const aiCache = await estimatePrefixBytes(env, 'ai:', 1000, 5);
  const usage = await estimatePrefixBytes(env, 'usage:', 1000, 5);
  const usageCounter = await readUsageCounter(env, '');
  const aiToday = usageCounter?.team?.today || 0;
  const aiMonth = usageCounter?.team?.month || 0;
  const aiSuccessToday = usageCounter?.team?.successToday || 0;
  const aiFailToday = usageCounter?.team?.failToday || 0;
  const estimatedOldAiWritesToday = aiSuccessToday * 11 + aiFailToday * 8;
  const estimatedNewAiWritesToday = aiSuccessToday * 3 + aiFailToday * 2;
  const estimatedSavedWritesToday = Math.max(0, estimatedOldAiWritesToday - estimatedNewAiWritesToday);
  const operationBudget = {
    plan: 'Workers KV Free',
    resetAtUtc: '00:00',
    dailyLimits: { reads: 100000, writes: 1000, deletes: 1000, lists: 1000 },
    aiToday,
    aiMonth,
    aiSuccessToday,
    aiFailToday,
    estimatedOldAiWritesToday,
    estimatedNewAiWritesToday,
    estimatedSavedWritesToday,
    estimatedNewWritePct: estimatedNewAiWritesToday / 1000 * 100,
    notes: [
      'Operational usage note.',
      'Operational usage note.',
      'Operational usage note.',
    ],
    reductions: [
      { item: 'audit log', before: 'multiple KV writes per event', after: 'one KV write per event' },
      { item: 'AI usage counter', before: 'several usage get/put operations', after: 'one compact counter update' },
      { item: 'AI audit log', before: 'request/success/failure logged separately', after: 'final outcome logged once' },
    ],
  };

  const items = [
    { label: 'Links', count: '1 JSON', bytes: linksBytes, note: 'config:links' },
    { label: 'Knowledge', count: '1 JSON', bytes: knowledgeBytes, note: 'config:knowledge' },
    { label: 'EOS/EOL', count: '1 JSON', bytes: eosBytes, note: 'config:eos' },
    { label: 'Admin config', count: 'config', bytes: adminsBytes, note: 'admin list and basic settings' },
    { label: 'Audit logs', count: storageCountLabel(audit), bytes: audit.bytes, estimated: true, note: `audit:* / 90d TTL / sampled ${audit.sampled}` },
    { label: 'AI response cache', count: storageCountLabel(aiCache), bytes: aiCache.bytes, estimated: true, note: `ai:* / 7d TTL / sampled ${aiCache.sampled}` },
    { label: 'AI usage counters', count: storageCountLabel(usage), bytes: usage.bytes, estimated: true, note: `usage:* / 400d TTL / sampled ${usage.sampled}` },
  ];
  const usedBytes = items.reduce((sum, item) => sum + (Number(item.bytes) || 0), 0);
  const itemCount = items.reduce((sum, item) => {
    const n = Number(String(item.count || '').replace(/[^0-9]/g, ''));
    return sum + (Number.isFinite(n) ? n : 0);
  }, 0);
  return {
    ok: true,
    asOf: new Date().toISOString(),
    summary: {
      quotaBytes,
      quotaLabel,
      usedBytes,
      usedPct: quotaBytes ? usedBytes / quotaBytes * 100 : 0,
      itemCount,
      quotaNote: env.KV_STORAGE_LIMIT_BYTES ? 'Configured by KV_STORAGE_LIMIT_BYTES' : 'Cloudflare Workers KV default 1GB basis',
      thresholds: { warnPct: 70, dangerPct: 90 },
      operationBudget,
    },
    items,
  };
}

async function readJsonKey(env, key, fallback = null) {
  try {
    const raw = await env.ENGR_KV.get(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch (_) { return fallback; }
}
async function getPlainKey(env, key, fallback = '') {
  try { return await env.ENGR_KV.get(key) || fallback; } catch (_) { return fallback; }
}
async function buildHubBackup(env, user) {
  const generatedAt = new Date().toISOString();
  return {
    ok: true,
    backupType: 'ENGR_HUB_CONFIG_BACKUP',
    version: '1.4.4',
    generatedAt,
    generatedBy: user || '',
    excludes: ['TEAM_PIN', 'JIRA_TOKEN', 'GEMINI_KEY', 'VT_KEY', 'Cloudflare Worker secrets/environment secrets'],
    data: {
      links: await readJsonKey(env, 'config:links', []),
      knowledge: await readJsonKey(env, 'config:knowledge', []),
      eos: await readJsonKey(env, 'config:eos', []),
      admins: await readJsonKey(env, 'config:admins', { [SUPER_ADMIN]: 'super' }),
      settings: {
        rangeMonths: await getPlainKey(env, 'config:range_months', '3'),
        sessionMin: await getPlainKey(env, 'config:session_min', '120'),
        eosWarnDays: await getPlainKey(env, 'config:eos_warn_days', '60,30,7'),
        aiSystem: await getPlainKey(env, 'config:ai_system', ''),
      },
    },
  };
}
function auditTimestampFromKey(name) {
  if (name.startsWith('audit:')) {
    const n = Number(name.split(':')[1]);
    return Number.isFinite(n) ? n : 0;
  }
  if (name.startsWith('auditLatest:')) {
    const rev = Number(name.split(':')[1]);
    return Number.isFinite(rev) ? 9999999999999 - rev : 0;
  }
  if (name.startsWith('auditType:')) {
    const parts = name.split(':');
    const rev = Number(parts[2]);
    return Number.isFinite(rev) ? 9999999999999 - rev : 0;
  }
  return 0;
}
async function cleanupOldAudit(env, days = 90, dryRun = true, max = 500) {
  const cutoff = Date.now() - Math.max(1, Number(days) || 90) * 24 * 60 * 60 * 1000;
  const prefixes = ['audit:', 'auditLatest:', 'auditType:'];
  let scanned = 0, matched = 0, deleted = 0, truncated = false;
  for (const prefix of prefixes) {
    let cursor;
    do {
      const page = await env.ENGR_KV.list({ prefix, cursor, limit: 100 });
      for (const key of page.keys || []) {
        scanned++;
        const ts = auditTimestampFromKey(key.name);
        if (ts && ts < cutoff) {
          matched++;
          if (!dryRun) { await env.ENGR_KV.delete(key.name); deleted++; }
        }
        if (scanned >= max) { truncated = !!(page.cursor || prefix !== prefixes[prefixes.length - 1]); break; }
      }
      cursor = page.cursor;
      if (scanned >= max) break;
    } while (cursor);
    if (scanned >= max) break;
  }
  return { ok: true, target: 'audit-old', days, dryRun, scanned, matched, deleted, truncated, cutoff: new Date(cutoff).toISOString() };
}
async function deleteKvPrefix(env, prefix, max = 1000) {
  let cursor, deleted = 0, truncated = false;
  do {
    const page = await env.ENGR_KV.list({ prefix, cursor, limit: 100 });
    for (const key of page.keys || []) {
      await env.ENGR_KV.delete(key.name);
      deleted++;
      if (deleted >= max) break;
    }
    cursor = page.cursor;
    if (deleted >= max && cursor) { truncated = true; break; }
  } while (cursor);
  return { deleted, truncated };
}
async function resetHubData(env) {
  const fixedKeys = ['config:links','links','config:knowledge','config:eos','vt:history','config:last_jira_sync'];
  let deleted = 0, truncated = false;
  for (const key of fixedKeys) {
    try { await env.ENGR_KV.delete(key); deleted++; } catch (_) {}
  }
  for (const prefix of ['private:','ai:','usage:','audit:','auditLatest:','auditType:']) {
    const r = await deleteKvPrefix(env, prefix, 1000);
    deleted += r.deleted;
    truncated = truncated || r.truncated;
  }
  return { ok: true, deleted, truncated };
}

// ════════════════ Web Push (VAPID, payload-less + SW pending fetch) ════════════════
// 이벤트 등록 시 구독자에게 OS 알림. 본인(actor) 제외 · 사용자 opt-out · 관리자 기능별 on/off · 대상 지정 · 멘트 템플릿.
const PUSH_EVENTS = {
  link:      { label: '업무 링크 등록',    defTitle: '🔗 새 업무 링크',     defBody: "{user}님이 '{target}' 등록", page: 'links' },
  knowledge: { label: '팀 노하우 등록',    defTitle: '📚 새 팀 노하우',     defBody: "{user}님이 '{target}' 등록", page: 'knowledge' },
  eos:       { label: '라이선스 등록', defTitle: '⏳ 라이선스 등록', defBody: "{user}님이 '{target}' 등록", page: 'eos' },
};
function u8ToB64url(u){ let s=''; for(let i=0;i<u.length;i++)s+=String.fromCharCode(u[i]); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
async function vapidAuthHeader(env, audience){
  const jwkRaw = env.VAPID_PRIVATE_JWK, pub = env.VAPID_PUBLIC_KEY, sub = env.VAPID_SUBJECT || 'mailto:admin@example.com';
  if(!jwkRaw || !pub) throw new Error('VAPID not configured');
  const jwk = typeof jwkRaw === 'string' ? JSON.parse(jwkRaw) : jwkRaw;
  const key = await crypto.subtle.importKey('jwk', { kty:'EC', crv:'P-256', d:jwk.d, x:jwk.x, y:jwk.y, ext:true }, { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
  const enc = new TextEncoder();
  const header = u8ToB64url(enc.encode(JSON.stringify({ typ:'JWT', alg:'ES256' })));
  const payload = u8ToB64url(enc.encode(JSON.stringify({ aud:audience, exp:Math.floor(Date.now()/1000)+12*3600, sub })));
  const signingInput = `${header}.${payload}`;
  const sig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, key, enc.encode(signingInput));
  return { Authorization:`vapid t=${signingInput}.${u8ToB64url(new Uint8Array(sig))}, k=${pub}` };
}
async function sendWebPush(env, sub, ttl=86400){
  const u = new URL(sub.endpoint);
  const auth = await vapidAuthHeader(env, `${u.protocol}//${u.host}`);
  const res = await fetch(sub.endpoint, { method:'POST', headers:{ ...auth, TTL:String(ttl) } });
  return res.status; // 201=ok, 404/410=만료(구독 제거)
}
async function getPushSubs(env){ try{ const r=await env.ENGR_KV.get('push:subs'); return r?JSON.parse(r):{}; }catch(_){ return {}; } }
async function savePushSubs(env, s){ await env.ENGR_KV.put('push:subs', JSON.stringify(s)); }
async function getPushSettings(env){
  let s={}; try{ const r=await env.ENGR_KV.get('push:settings'); if(r)s=JSON.parse(r); }catch(_){}
  const events={};
  for(const [k,def] of Object.entries(PUSH_EVENTS)){
    const e=(s.events&&s.events[k])||{};
    let title=(e.title||def.defTitle), body=(e.body||def.defBody);
    // 옛 'EOS/라이선스' 문구 자가 치환(저장된 멘트 마이그레이션)
    title=title.replace(/EOS\s*\/\s*라이선스/g,'라이선스'); body=body.replace(/EOS\s*\/\s*라이선스/g,'라이선스');
    events[k]={ enabled:e.enabled!==false, title, body, label:def.label };
  }
  return { events, include:Array.isArray(s.include)?s.include:[], exclude:Array.isArray(s.exclude)?s.exclude:[] };
}
function fillTemplate(tpl, vars){ return String(tpl||'').replace(/\{(\w+)\}/g,(m,k)=> vars[k]!==undefined?vars[k]:m); }
async function endpointHash(endpoint){ const b=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint)); return u8ToB64url(new Uint8Array(b)).slice(0,40); }
async function enqueuePending(env, endpoint, payload){
  const pk='push:pending:'+await endpointHash(endpoint);
  let pend=[]; try{ const r=await env.ENGR_KV.get(pk); if(r)pend=JSON.parse(r); }catch(_){}
  pend.push(payload); if(pend.length>30)pend=pend.slice(-30);
  await env.ENGR_KV.put(pk, JSON.stringify(pend), { expirationTtl:60*60*24*7 });
}
async function pushNotify(env, eventKey, actorId, vars){
  try{
    const def=PUSH_EVENTS[eventKey]; if(!def)return;
    const settings=await getPushSettings(env);
    const ev=settings.events[eventKey];
    if(!ev || !ev.enabled) return;
    const subs=await getPushSubs(env);
    const actorNorm=normalizeUserId(actorId||'');
    const include=settings.include.map(normalizeUserId).filter(Boolean);
    const exclude=settings.exclude.map(normalizeUserId).filter(Boolean);
    let recipients=Object.keys(subs);
    if(include.length) recipients=recipients.filter(u=>include.includes(u));
    recipients=recipients.filter(u=> !exclude.includes(u) && u!==actorNorm);
    if(!recipients.length) return;
    let users={}; try{ users=await getUsers(env); }catch(_){}
    const actorName=(users[actorNorm]&&users[actorNorm].displayName)||actorId||'팀원';
    const fullVars={ user:actorName, event:def.label, ...vars };
    const payload={ title:fillTemplate(ev.title,fullVars), body:fillTemplate(ev.body,fullVars), page:def.page, ts:Date.now(), tag:eventKey };
    let changed=false;
    for(const uid of recipients){
      let pref={}; try{ const pr=await env.ENGR_KV.get('push:pref:'+uid); if(pr)pref=JSON.parse(pr); }catch(_){}
      if(pref.enabled===false) continue;
      const list=subs[uid]||[];
      for(const s of list){
        try{ await enqueuePending(env, s.endpoint, payload); }catch(_){}
        try{ const st=await sendWebPush(env, s); if(st===404||st===410){ subs[uid]=(subs[uid]||[]).filter(x=>x.endpoint!==s.endpoint); changed=true; } }catch(_){}
      }
      if(subs[uid] && !subs[uid].length){ delete subs[uid]; changed=true; }
    }
    if(changed) await savePushSubs(env, subs);
  }catch(_){}
}

// ════════════ Phase 0 · D1 foundation (feat/hub-d1-foundation) — spec §C/§B ════════════
// 커스텀 JQL Jira 검색 (자격증명 서버측 = mj.park 토큰, 클라 노출 0)
async function jiraSearchJql(env, jql, fields, maxPages = 8) {
  if (!env.JIRA_TOKEN) throw new Error('JIRA_TOKEN 미설정');
  const headers = { 'Authorization': 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN), 'Content-Type': 'application/json', 'Accept': 'application/json' };
  let all = [], token, pages = 0;
  do {
    const body = { jql, maxResults: 100, fieldsByKeys: false, fields };
    if (token) body.nextPageToken = token;
    const res = await fetch('https://escare-engr.atlassian.net/rest/api/3/search/jql', { method: 'POST', headers, body: JSON.stringify(body) });
    if (!res.ok) throw new Error('Jira ' + res.status + ': ' + (await res.text()).slice(0, 160));
    const page = await res.json();
    all = all.concat(page.issues || []);
    token = page.nextPageToken; pages++;
  } while (token && pages < maxPages);
  return all;
}
// 브래킷 분류(§B): customer / vendorcase / unclassified / internal / none
function extractBracket(s) { const m = /^\s*\[([^\]]+)\]/.exec(s || ''); return m ? m[1].trim() : ''; }
const INTERNAL_TAGS = ['hands-on', 'handson', 'hands on', 'none', 'null', 'n/a', 'na', 'test', '테스트', '내부', '검토', '긴급', 'urgent', 'poc'];
function classifyBracket(summary, custList) {
  // L-16: 프론트 extractCustomer와 동일하게 제목 내 '모든' 브래킷을 스캔(선두 숫자 케이스번호 등 건너뜀)
  const brackets = (String(summary || '').match(/\[([^\]]+)\]/g) || []).map(m => m.slice(1, -1).trim()).filter(Boolean);
  if (!brackets.length) return { kind: 'none', bracket: '' };
  for (const b of brackets) { for (const c of custList) { if (c.name === b || (c.aliases || []).includes(b)) return { kind: 'customer', bracket: b, customer: c.name }; } }  // M-5: 등록 고객사/별칭 우선
  // 고객사 후보 = 숫자(케이스번호)·내부태그 아닌 첫 브래킷 (프론트와 일치)
  const cand = brackets.find(b => !/^\d+$/.test(b) && !INTERNAL_TAGS.includes(b.toLowerCase()));
  if (cand) {
    if (/^[A-Z]{2,3}\d+$/i.test(cand) || /^hands[\s-]?on$/i.test(cand)) return { kind: 'vendorcase', bracket: cand };
    if (/[가-힣]/.test(cand)) return { kind: 'customer', bracket: cand, customer: cand };   // 한글 = 고객사(MJ 요청)
    return { kind: 'unclassified', bracket: cand };   // H-3: 미등록·비한글 모호 → ⚑ 검토 필요
  }
  const first = brackets[0];   // 전부 숫자/내부태그
  if (INTERNAL_TAGS.includes(first.toLowerCase())) return { kind: 'internal', bracket: first };
  return { kind: 'vendorcase', bracket: first };   // 숫자 케이스번호 등
}
async function getCustomersD1(env) {
  try { const r = await env.DB.prepare('SELECT name, aliases FROM customers WHERE active=1').all(); return (r.results || []).map(c => ({ name: c.name, aliases: (() => { try { return JSON.parse(c.aliases || '[]'); } catch { return []; } })() })); }
  catch (_) { return []; }
}
async function getMonitorAllowlist(env) {
  try { const r = await env.DB.prepare("SELECT value FROM app_settings WHERE key='monitor_allowlist'").first(); if (r && r.value) return JSON.parse(r.value); } catch (_) {}
  return ['mj.park'];
}
async function isMonitorAllowed(env, user) { const list = await getMonitorAllowlist(env); return list.map(normalizeUserId).includes(normalizeUserId(user)); }
async function getFeatureFlags(env) {
  const def = { compat: true, history: true, monitor: true, nsis: true };
  try { const r = await env.DB.prepare("SELECT value FROM app_settings WHERE key='feature_flags'").first(); if (r && r.value) return { ...def, ...JSON.parse(r.value) }; } catch (_) {}
  return def;
}
async function getAuditReadD1(env) {
  try { const r = await env.DB.prepare("SELECT value FROM app_settings WHERE key='audit_read_d1'").first(); return r?.value === 'on'; } catch (_) { return false; }
}
function jqlEsc(s) { return String(s).replace(/[\r\n]+/g, ' ').replace(/["\\]/g, '\\$&'); }
function jqlTextEsc(s) { return jqlEsc(String(s).replace(/[*?~^:"]/g, ' ')); }  // L-14: text ~ 우변(Lucene) 메타문자 제거 → 비균형 와일드카드 Jira 400 방지
function okDate(s) { s = String(s == null ? '' : s).trim(); return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ''; }  // M-7: 날짜 형식 검증(아니면 빈값) — XSS 근원 차단 + 정렬 NaN 방지
function nextDayStr(d) { const dt = new Date(d + 'T00:00:00Z'); dt.setUTCDate(dt.getUTCDate() + 1); return dt.toISOString().slice(0, 10); }
const TEAM_FIELDS = ['summary', 'status', 'assignee', 'reporter', 'labels', 'issuetype', 'created', 'updated', 'duedate', 'customfield_10134'];
function mapJiraIssue(it, custList) {
  const f = it.fields || {};
  return { key: it.key, summary: f.summary || '', status: f.status?.name || '', assignee: f.assignee?.displayName || '-', labels: f.labels || [], type: f.issuetype?.subtask ? 'subtask' : 'task', created: f.created || '', updated: f.updated || '', duedate: f.duedate || '', cls: classifyBracket(f.summary, custList) };
}
async function buildDailySnapshot(env, day) {
  try {
    const jql = `project = ENGR AND updated >= "${day}" AND updated < "${nextDayStr(day)}" ORDER BY updated DESC`;
    const issues = await jiraSearchJql(env, jql, TEAM_FIELDS, 12);
    const custList = await getCustomersD1(env);
    const items = issues.map(it => mapJiraIssue(it, custList));
    const payload = { day, count: items.length, items };
    const built_at = new Date().toISOString();
    try { await env.DB.prepare("INSERT INTO team_daily_snapshot (day,payload_json,built_at) VALUES (?,?,?) ON CONFLICT(day) DO UPDATE SET payload_json=excluded.payload_json, built_at=excluded.built_at").bind(day, JSON.stringify(payload), built_at).run(); } catch (_) {}
    return { ...payload, built_at };
  } catch (e) {  // L-21: cron 스냅샷 실패가 조용히 묻히지 않게 감사 기록(관측성)
    try { await auditLog(env, 'system', 'MON_SNAPSHOT_FAIL', { monType: 'snapshot', day, error: String((e && e.message) || e).slice(0, 200) }); } catch (_) {}
    return { day, count: 0, items: [], error: String((e && e.message) || e) };
  }
}

//
export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: getCorsHeaders(request) });

    const url = new URL(request.url);
    const path = url.pathname;
    const headerUser = normalizeUserId(decUser(request.headers.get('X-User') || ''));
    const sessionUser = await getSessionUser(env, request.headers.get('X-Session-Token') || '');
    const hasSession = !!sessionUser && (!headerUser || headerUser === sessionUser);
    const user = sessionUser || headerUser;

    try {
      //
      if (path === '/debug') {
        return corsResponse({ ok: true, ts: new Date().toISOString(), worker: 'engr-hub-proxy', model: '@cf/meta/llama-3.3-70b-instruct-fp8-fast' });
      }

      //
      if (path === '/debug/ai') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        if (!await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 사용할 수 있습니다.' }, 403);
        const result = await callAI(env, 'Reply with test success in Korean.', 'debug');
        await auditLog(env, user, 'AI_DEBUG', { path: '/debug/ai' });
        return corsResponse({ ok: true, text: result?.candidates?.[0]?.content?.parts?.[0]?.text });
      }

      //
      if (path === '/auth/session' && request.method === 'GET') {
        if (!hasSession || !sessionUser) return corsResponse({ ok: false, message: '세션이 만료되었습니다.' }, 401);
        const account = await getUserAccount(env, sessionUser);
        if (!account || account.active === false) return corsResponse({ ok: false, message: '비활성화된 계정입니다.' }, 403);
        const admins = await getAdmins(env);
        const role = account.role || admins[sessionUser] || 'user';
        let sessionMin = 120;
        try {
          const cfg = await env.ENGR_KV.get('config:session_min');
          if (cfg) sessionMin = parseInt(cfg) || 120;
        } catch (_) {}
        const mustChangePin = !(await getUserPinHash(env, sessionUser));  // H-1: 세션 복원 시에도 개인 PIN 미설정이면 강제 변경 유지
        return corsResponse({
          ok: true,
          name: sessionUser,
          userId: sessionUser,
          displayName: account.displayName || sessionUser,
          isAdmin: role === 'admin' || role === 'super',
          isSuperAdmin: role === 'super',
          role,
          sessionMin,
          mustChangePin,
        });
      }

      if (path === '/auth/login' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { name, pin } = body;
        const userId = normalizeUserId(name);
        if (!userId || !pin) return corsResponse({ ok: false, message: '\uACC4\uC815 ID\uC640 PIN\uC744 \uC785\uB825\uD558\uC138\uC694.' }, 400);

        const account = await getUserAccount(env, userId);
        if (!account || account.active === false) {
          return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uB9CC \uC811\uC18D\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        }

        let pinOk = await validateUserPin(env, userId, pin);
        // M-2: displayName 폴백 제거 — PIN은 항상 정규화 id로 저장되어 폴백은 dead이고, 교차계정 PIN 매칭 위험만 유발(레거시는 TEAM_PIN→H-1로 graceful)
        if (!pinOk) return corsResponse({ ok: false, message: 'PIN\uC774 \uC62C\uBC14\uB974\uC9C0 \uC54A\uC2B5\uB2C8\uB2E4.' }, 401);
        // \uC8FC\uC758: \uB85C\uADF8\uC778 \uC2DC PIN \uC790\uB3D9 \uB36E\uC5B4\uC4F0\uAE30 \uC81C\uAC70. PIN\uC740 \uC624\uC9C1 /auth/change-pin(\uBA85\uC2DC\uC801 'PIN \uBCC0\uACBD')\uC73C\uB85C\uB9CC \uBCC0\uACBD\uB428.

        const admins = await getAdmins(env);
        const role = account.role || admins[userId] || 'user';

        let sessionMin = 120;
        try {
          const cfg = await env.ENGR_KV.get('config:session_min');
          if (cfg) sessionMin = parseInt(cfg) || 120;
        } catch (_) {}

        const sessionToken = await createSession(env, userId, sessionMin);
        const mustChangePin = !(await getUserPinHash(env, userId));  // H-1: 개인 PIN 미설정(공유 PIN 폴백 로그인) → 최초 1회 강제 변경
        await auditLog(env, userId, 'LOGIN', { role, viaSharedPin: mustChangePin });
        return corsResponse({
          ok: true,
          name: userId,
          userId,
          displayName: account.displayName || userId,
          isAdmin: role === 'admin' || role === 'super',
          isSuperAdmin: role === 'super',
          role, sessionMin, sessionToken, mustChangePin,
        });
      }

      if (path === '/auth/change-pin' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const oldPin = body.oldPin || '';
        const newPin = body.newPin || '';
        if (!oldPin || !newPin) return corsResponse({ ok: false, message: '\uD604\uC7AC PIN\uACFC \uC0C8 PIN\uC744 \uC785\uB825\uD558\uC138\uC694.' }, 400);
        if (String(newPin).length < 6) return corsResponse({ ok: false, message: '\uC0C8 PIN\uC740 6\uC790 \uC774\uC0C1\uC774\uC5B4\uC57C \uD569\uB2C8\uB2E4.' }, 400);
        if (!await validateUserPin(env, user, oldPin)) return corsResponse({ ok: false, message: '\uD604\uC7AC PIN\uC774 \uC62C\uBC14\uB974\uC9C0 \uC54A\uC2B5\uB2C8\uB2E4.' }, 401);
        await setUserPin(env, user, newPin);
        await auditLog(env, user, 'PIN_CHANGE', {});
        return corsResponse({ ok: true });
      }

      //
      if (path === '/config/public' && request.method === 'GET') {
        const sessionRaw = await env.ENGR_KV.get('config:session_min');
        const rangeRaw = await env.ENGR_KV.get('config:range_months') || await env.ENGR_KV.get('config:jira_range_months');
        let lastSync = null;
        try { const raw = await env.ENGR_KV.get('config:last_jira_sync'); if (raw) lastSync = JSON.parse(raw); } catch (_) {}
        const geminiOn = !!(env.GEMINI_API_KEY || env.GEMINI_KEY);
        const aiProvider = geminiOn ? 'gemini' : 'llama';
        const aiModel = geminiOn ? (env.GEMINI_MODEL || 'gemini-2.5-flash') : 'llama-3.3-70b';
        return corsResponse({ sessionMin: parseInt(sessionRaw || '120') || 120, rangeMonths: parseInt(rangeRaw || '6') || 6, lastSync, aiProvider, aiModel });
      }
      if (path === '/kv/usage' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        return corsResponse(await getUsage(env, user));
      }
      // 일반 유저용 개인 AI 사용량 (팀 통계 미포함)
      if (path === '/kv/usage/me' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const usage = await getUsage(env, user);
        return corsResponse({ ok: true, me: usage.me, asOf: usage.asOf, timezone: usage.timezone, source: usage.source });
      }
      if (path === '/links/kb/import' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const years = Math.max(1, Math.min(10, parseInt(url.searchParams.get('years') || '5', 10) || 5));
        const limit = Math.max(1, Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10) || 20));
        const cursor = url.searchParams.get('cursor') || '';
        const provider = url.searchParams.get('provider') || '';
        return corsResponse(await importRecentKBLinks(env, user, years, { limit, cursor, provider }));
      }

      //
      if (path.startsWith('/jira/')) {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const jiraPath = path.replace('/jira/', '');
        if (jiraPath === 'search' || jiraPath === 'search/jql') {
          return await handleJiraSearch(env, user);
        }
        const jiraAuth = 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN);
        const jiraUrl = `https://escare-engr.atlassian.net/rest/api/3/${jiraPath}${url.search}`;
        const jiraRes = await fetch(jiraUrl, {
          method: request.method,
          headers: { 'Authorization': jiraAuth, 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: request.method !== 'GET' ? await request.text() : undefined,
        });
        const data = await jiraRes.text();
        return new Response(data, { status: jiraRes.status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8' } });
      }

      //
      if (path === '/ai/generate' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const { contents, mode = 'technical_analysis' } = body;
        let detail = (body.detail && typeof body.detail === 'object' && !Array.isArray(body.detail)) ? body.detail : {};
        try { if (JSON.stringify(detail).length > 1000) detail = { _truncated: true }; } catch (_) { detail = {}; }  // L-31: detail 크기 캡(감사로그/D1 비대화 방지)
        const prompt = contents?.[0]?.parts?.[0]?.text;
        if (!prompt) return corsResponse({ ok: false, message: '\uD504\uB86C\uD504\uD2B8\uAC00 \uBE44\uC5B4 \uC788\uC2B5\uB2C8\uB2E4.' }, 400);

        // AI daily rate limit check
        const AI_DAILY_LIMIT = parseInt(env.AI_DAILY_LIMIT || '300', 10);
        const AI_USER_DAILY_LIMIT = parseInt(env.AI_USER_DAILY_LIMIT || '80', 10);
        try {
          const usageNow = await readUsageCounter(env, user);
          if ((usageNow?.team?.today || 0) >= AI_DAILY_LIMIT) {
            return corsResponse({ ok: false, message: `\ud300 \uc77c\uc77c AI \uc694\uccad \ud55c\ub3c4(${AI_DAILY_LIMIT}\ud68c)\uc5d0 \ub3c4\ub2ec\ud588\uc2b5\uB2C8\uB2E4.` }, 429);
          }
          if ((usageNow?.me?.today || 0) >= AI_USER_DAILY_LIMIT) {
            return corsResponse({ ok: false, message: `\uac1c\uc778 \uc77c\uc77c AI \uc694\uccad \ud55c\ub3c4(${AI_USER_DAILY_LIMIT}\ud68c)\uc5d0 \ub3c4\ub2ec\ud588\uc2b5\uB2C8\uB2E4.` }, 429);
          }
        } catch (_) {}

        const reqId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
        try {
          const safeMode = normalizeAIMode(mode);
          const result = await callAI(env, prompt, safeMode);
          const outcome = result._cached ? 'cached' : 'success';
          await auditLog(env, user, 'AI_CALL', { ...detail, reqId, mode: safeMode, promptLen: prompt.length, outcome, model: result._model });  // M-9: 클라 detail을 앞에 두어 서버 계산값이 항상 우선(감사 위조 방지)
          await updateAIUsage(env, user, outcome, result._model);
          return corsResponse(result);
        } catch (e) {
          await updateAIUsage(env, user, 'fail');
          return corsResponse({ ok: false, message: e.message || 'AI \uD638\uCD9C \uC2E4\uD328' }, 502);
        }
      }

      // VT \uBA40\uD2F0 \uD0C0\uC785 \uC870\uD68C (\uD574\uC2DC/IP/\uB3C4\uBA54\uC778/URL)
      if (path === '/vt/lookup' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ error: { message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 401);
        const body = await request.json().catch(() => ({}));
        const vtKey = env.VT_KEY || env.VT_API_KEY || '';
        if (!vtKey) return corsResponse({ error: { message: 'VT_KEY \uD658\uACBD\uBCC0\uC218\uAC00 \uC124\uC815\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.' } }, 500);
        const raw = String(body.value || body.hash || '').trim();
        if (!raw) return corsResponse({ error: { message: '\uC870\uD68C\uD560 \uAC12\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 400);
        const type = (body.type && body.type !== 'auto') ? body.type : vtDetectType(raw);
        if (!type) return corsResponse({ error: { message: '\uD574\uC2DC/IP/\uB3C4\uBA54\uC778/URL \uD615\uC2DD\uC774 \uC544\uB2D9\uB2C8\uB2E4.' } }, 400);
        const H = { 'x-apikey': vtKey };
        try {
          if (type === 'url') {
            const sres = await fetch('https://www.virustotal.com/api/v3/urls', { method: 'POST', headers: { ...H, 'content-type': 'application/x-www-form-urlencoded' }, body: `url=${encodeURIComponent(raw)}` });
            const sdata = await sres.json();
            if (!sres.ok) return corsResponse(sdata, sres.status);
            const aid = sdata?.data?.id;
            if (aid) await vtPollAnalysis(vtKey, aid, 6);
            const ures = await fetch(`https://www.virustotal.com/api/v3/urls/${vtUrlId(raw)}`, { headers: H });
            const udata = await ures.json();
            if (!body.noAudit && ures.ok && udata?.data?.attributes) await auditLog(env, user, 'VT_LOOKUP', { vtType: type, value: raw.slice(0, 60), mal: udata.data.attributes.last_analysis_stats?.malicious || 0 });
            return corsResponse({ ...udata, _type: 'url', _value: raw }, ures.status);
          }
          let vtUrl;
          if (type === 'hash') vtUrl = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(raw.toLowerCase())}`;
          else if (type === 'ip') vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(raw)}`;
          else if (type === 'domain') vtUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(raw)}`;
          const vtRes = await fetch(vtUrl, { headers: H });
          const data = await vtRes.json();
          if (vtRes.ok && data?.data?.attributes) {
            if (!body.noAudit) await auditLog(env, user, 'VT_LOOKUP', { vtType: type, value: raw.slice(0, 60), mal: data.data.attributes.last_analysis_stats?.malicious || 0 });
            if (type === 'hash') await saveVtHistory(env, user, raw.toLowerCase(), data.data.attributes);
          }
          return corsResponse({ ...data, _type: type, _value: raw }, vtRes.status);
        } catch (e) { return corsResponse({ error: { message: e.message || 'VT \uC870\uD68C \uC2E4\uD328' } }, 502); }
      }
      // \uC5EC\uB7EC \uAC74 \uC77C\uAD04 \uC870\uD68C \uC2DC \uAC10\uC0AC\uB85C\uADF8 1\uAC74\uC73C\uB85C \uC694\uC57D(\uAC1C\uBCC4 \uC870\uD68C\uB294 noAudit\uB85C \uAE30\uB85D \uC0DD\uB7B5)
      if (path === '/vt/audit-batch' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const count = Math.max(1, parseInt(body.count) || 1);
        const mal = Math.max(0, parseInt(body.mal) || 0);
        await auditLog(env, user, 'VT_LOOKUP', { count, mal, batch: true, value: `${count}\uAC74 \uC77C\uAD04 \uC870\uD68C` });
        return corsResponse({ ok: true });
      }
      // VT \uD30C\uC77C \uC5C5\uB85C\uB4DC \u2192 \uBD84\uC11D ID \uBC18\uD658
      if (path === '/vt/file' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ error: { message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 401);
        const vtKey = env.VT_KEY || env.VT_API_KEY || '';
        if (!vtKey) return corsResponse({ error: { message: 'VT_KEY \uD658\uACBD\uBCC0\uC218\uAC00 \uC124\uC815\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.' } }, 500);
        try {
          const form = await request.formData();
          const file = form.get('file');
          if (!file || typeof file === 'string') return corsResponse({ error: { message: '\uD30C\uC77C\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 400);
          if (file.size > 32 * 1024 * 1024) return corsResponse({ error: { message: '\uBB34\uB8CC \uC5C5\uB85C\uB4DC\uB294 \uCD5C\uB300 32MB\uC785\uB2C8\uB2E4.' } }, 400);
          const vform = new FormData();
          vform.append('file', file, file.name || 'upload.bin');
          const ures = await fetch('https://www.virustotal.com/api/v3/files', { method: 'POST', headers: { 'x-apikey': vtKey }, body: vform });
          const udata = await ures.json();
          if (!ures.ok) return corsResponse(udata, ures.status);
          await auditLog(env, user, 'VT_UPLOAD', { name: file.name || '', size: file.size || 0 });
          return corsResponse({ ok: true, analysisId: udata?.data?.id, name: file.name || '' }, 200);
        } catch (e) { return corsResponse({ error: { message: e.message || '\uC5C5\uB85C\uB4DC \uC2E4\uD328' } }, 502); }
      }
      // VT \uBD84\uC11D \uC0C1\uD0DC \uD3F4\uB9C1 (\uD30C\uC77C \uC5C5\uB85C\uB4DC \uD6C4)
      if (path === '/vt/analysis' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ error: { message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 401);
        const vtKey = env.VT_KEY || env.VT_API_KEY || '';
        if (!vtKey) return corsResponse({ error: { message: 'VT_KEY \uBBF8\uC124\uC815' } }, 500);
        const id = url.searchParams.get('id') || '';
        if (!id) return corsResponse({ error: { message: 'id \uD544\uC694' } }, 400);
        const ares = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`, { headers: { 'x-apikey': vtKey } });
        const adata = await ares.json();
        return corsResponse(adata, ares.status);
      }

      //
      if (path === '/vt/history' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const history = await getVtHistory(env);
        return corsResponse({ ok: true, history });
      }

      //
      if (path === '/kv/audit' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const limit = Math.max(1, Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10) || 50));
        const filter = url.searchParams.get('filter') || '';
        // §H 3단계: 읽기 D1 우선(app_settings audit_read_d1='on') → D1 비었으면 KV 폴백
        if (await getAuditReadD1(env)) {
          try {
            const q = filter
              ? env.DB.prepare('SELECT ts,ts_num,user,type,detail_json FROM audit_log WHERE type=? ORDER BY ts_num DESC LIMIT ?').bind(filter, limit)
              : env.DB.prepare('SELECT ts,ts_num,user,type,detail_json FROM audit_log ORDER BY ts_num DESC LIMIT ?').bind(limit);
            const r = await q.all();
            const rows = r.results || [];
            if (rows.length) {
              const logs = rows.map(x => ({ ts: x.ts, tsNum: x.ts_num, user: x.user, type: x.type, ...(() => { try { return JSON.parse(x.detail_json || '{}'); } catch { return {}; } })() }));
              return corsResponse(logs);
            }
          } catch (_) {}
        }
        const prefix = 'auditLatest:';
        let list = await env.ENGR_KV.list({ prefix, limit });

        //
        if ((!list.keys || !list.keys.length) && !filter) {
          list = await env.ENGR_KV.list({ prefix: 'audit:', limit });
          list.keys = (list.keys || []).sort((a, b) => b.name.localeCompare(a.name));
        }

        const logs = [];
        for (const key of list.keys || []) {
          if (logs.length >= limit) break;
          const val = await env.ENGR_KV.get(key.name);
          if (!val) continue;
          try {
            const item = JSON.parse(val);
            if (!filter || item.type === filter) logs.push(item);
          } catch (_) {}
        }
        return corsResponse(logs);
      }

      // ── §H 감사로그 KV→D1 마이그레이션 (슈퍼) ──
      if (path === '/admin/migrate/audit-status' && request.method === 'GET') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: '슈퍼 관리자만 가능합니다.' }, 403);
        let d1Count = 0; try { const r = await env.DB.prepare('SELECT count(*) AS c FROM audit_log').first(); d1Count = r?.c || 0; } catch (_) {}
        return corsResponse({ ok: true, d1Count, readD1: await getAuditReadD1(env) });
      }
      if (path === '/admin/migrate/audit-backfill' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: '슈퍼 관리자만 가능합니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const prefix = body.prefix === 'audit:' ? 'audit:' : 'auditLatest:';
        const page = await env.ENGR_KV.list({ prefix, cursor: body.cursor || undefined, limit: 100 });
        const keys = page.keys || [];
        const vals = await Promise.all(keys.map(k => env.ENGR_KV.get(k.name).catch(() => null)));
        const stmts = [];
        keys.forEach((k, i) => {
          if (!vals[i]) return;
          let item; try { item = JSON.parse(vals[i]); } catch { return; }
          const id = k.name.replace(/^(auditLatest:|audit:)/, '');
          const tsNum = item.tsNum || Date.parse(item.ts) || 0;
          const { ts, tsNum: _t, user: u, type: ty, ...detail } = item;
          stmts.push(env.DB.prepare('INSERT OR IGNORE INTO audit_log (id,ts,ts_num,user,type,detail_json) VALUES (?,?,?,?,?,?)').bind(id, ts || new Date(tsNum).toISOString(), tsNum, u || '', ty || '', JSON.stringify(detail)));
        });
        let inserted = 0;
        if (stmts.length) { try { const res = await env.DB.batch(stmts); inserted = res.reduce((n, r) => n + (r.meta?.changes || 0), 0); } catch (e) { return corsResponse({ ok: false, message: 'D1 배치 실패: ' + e.message }, 500); } }
        await auditLog(env, user, 'AUDIT_MIGRATE', { migPhase: 'backfill', prefix, scanned: keys.length, inserted });
        return corsResponse({ ok: true, scanned: keys.length, inserted, cursor: page.list_complete ? null : page.cursor, done: !!page.list_complete });
      }
      if (path === '/admin/migrate/audit-readsource' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: '슈퍼 관리자만 가능합니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const v = body.d1 ? 'on' : 'off';
        try { await env.DB.prepare("INSERT INTO app_settings (key,value) VALUES ('audit_read_d1',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(v).run(); }
        catch (e) { return corsResponse({ ok: false, message: '저장 실패: ' + e.message }, 500); }
        await auditLog(env, user, 'AUDIT_MIGRATE', { migPhase: 'readsource', readD1: v });
        return corsResponse({ ok: true, readD1: v === 'on' });
      }

      //
      if (path === '/admin/list' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const admins = await getAdmins(env);
        const users = await getUsers(env);
        const teamNames = Object.keys(users).filter(id => users[id].active !== false);
        const teamUsers = Object.keys(users).sort().map(id => ({
          id,
          displayName: users[id].displayName || id,
          role: users[id].role || admins[id] || 'user',
          active: users[id].active !== false,
        }));
        return corsResponse({ ok: true, admins, teamNames, users: teamUsers });
      }

      if (path === '/admin/users' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const account = await saveUserAccount(env, {
          id: body.id || body.userId,
          displayName: body.displayName,
          role: body.role || 'user',
          active: body.active !== false,
        });
        if (body.initialPin) {
          if (String(body.initialPin).length < 6) return corsResponse({ ok: false, message: '\uCD08\uAE30 PIN\uC740 6\uC790 \uC774\uC0C1\uC774\uC5B4\uC57C \uD569\uB2C8\uB2E4.' }, 400);
          await setUserPin(env, account.id, String(body.initialPin));
        }
        const admins = await getAdmins(env, { skipUsers: true });
        if (account.role === 'admin' || account.role === 'super') admins[account.id] = account.role;
        else delete admins[account.id];
        admins[SUPER_ADMIN] = 'super';
        await env.ENGR_KV.put('config:admins', JSON.stringify(admins));
        await auditLog(env, user, 'USER_SAVE', { target: account.id, role: account.role });
        return corsResponse({ ok: true, user: account });
      }

      if (path.startsWith('/admin/users/') && request.method === 'DELETE') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const target = decodeURIComponent(path.split('/')[3] || '');
        const urlObj = new URL(request.url);
        const purge = urlObj.searchParams.get('purge') === 'true';
        try {
          if (purge) {
            const deletedId = await purgeUserAccount(env, target);
            await auditLog(env, user, 'USER_PURGE', { target: deletedId });
            return corsResponse({ ok: true, user: deletedId, purged: true });
          } else {
            const account = await deactivateUserAccount(env, target);
            if (!account) return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 404);
            await auditLog(env, user, 'USER_DISABLE', { target: account.id });
            return corsResponse({ ok: true, user: account.id, active: false });
          }
        } catch (e) {
          return corsResponse({ ok: false, message: e.message || '\uC0AC\uC6A9\uC790 \uCC98\uB9AC \uC2E4\uD328' }, 400);
        }
      }

      //
      if (path === '/admin/update' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const { action, user: targetUser, role: newRole } = body;
        const targetId = normalizeUserId(targetUser);

        // Team ID validation
        const teamNames = getTeamNames(env);
        if (action === 'add' && teamNames.length && !teamNames.includes(targetId)) {
          return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 400);
        }

        const admins = await getAdmins(env);
        const users = await getUsers(env);
        if (!targetId || !users[targetId]) return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 400);

        if (action === 'add') {
          if (targetId === SUPER_ADMIN) {
            return corsResponse({ ok: false, message: '\uCD5C\uACE0 \uAD00\uB9AC\uC790\uB294 \uBCC0\uACBD\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 400);
          }
          admins[targetId] = (newRole === 'super') ? 'super' : 'admin';
        } else if (action === 'remove') {
          if (targetId === SUPER_ADMIN) {
            return corsResponse({ ok: false, message: '\uCD5C\uACE0 \uAD00\uB9AC\uC790\uB294 \uD68C\uC218\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 403);
          }
          delete admins[targetId];
        } else if (action === 'changeRole') {
          if (targetId === SUPER_ADMIN) {
            return corsResponse({ ok: false, message: '\uCD5C\uACE0 \uAD00\uB9AC\uC790\uB294 \uBCC0\uACBD\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 400);
          }
          if (!admins[targetId]) {
            return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB418\uC9C0 \uC54A\uC740 \uAD00\uB9AC\uC790\uC785\uB2C8\uB2E4.' }, 400);
          }
          admins[targetId] = (newRole === 'super') ? 'super' : 'admin';
        }

        // H-4: getAdmins가 config:users의 role을 우선 사용하므로, config:users도 동기화해야 강등/승급이 실제 적용됨
        if (users[targetId]) {
          const syncRole = action === 'remove' ? 'user' : ((newRole === 'super') ? 'super' : 'admin');
          await saveUserAccount(env, { id: targetId, displayName: users[targetId].displayName, role: syncRole, active: users[targetId].active !== false });
        }
        await env.ENGR_KV.put('config:admins', JSON.stringify(admins));
        await auditLog(env, user, 'ADMIN_CHANGE', { action, target: targetId, role: newRole });
        return corsResponse({ ok: true, admins });
      }

      //
      if (path === '/admin/config' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const rangeMonths = await env.ENGR_KV.get('config:range_months') || '3';
        const sessionMin = await env.ENGR_KV.get('config:session_min') || '120';
        const aiSystem = await env.ENGR_KV.get('config:ai_system') || '';
        const eosWarnDays = await env.ENGR_KV.get('config:eos_warn_days') || '60,30,7';
        return corsResponse({
          ok: true,
          rangeMonths: parseInt(rangeMonths),
          sessionMin: parseInt(sessionMin),
          aiSystem,
          eosWarnDays,
        });
      }
      if (path === '/admin/config' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        if (body.rangeMonths !== undefined) await env.ENGR_KV.put('config:range_months', String(body.rangeMonths));
        if (body.sessionMin !== undefined) await env.ENGR_KV.put('config:session_min', String(body.sessionMin));
        if (body.aiSystem !== undefined) await env.ENGR_KV.put('config:ai_system', body.aiSystem);
        if (body.eosWarnDays !== undefined) await env.ENGR_KV.put('config:eos_warn_days', body.eosWarnDays);
        await auditLog(env, user, 'CONFIG_CHANGE', { keys: Object.keys(body) });
        return corsResponse({ ok: true });
      }

      //
      if (path === '/admin/cache/clear' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        let cursor, cnt = 0, truncated = false;
        const max = 1000;
        do {
          const list = await env.ENGR_KV.list({ prefix: 'ai:', cursor, limit: 100 });
          for (const key of list.keys || []) {
            await env.ENGR_KV.delete(key.name);
            cnt++;
            if (cnt >= max) break;
          }
          cursor = list.cursor;
          if (cnt >= max && cursor) { truncated = true; break; }
        } while (cursor);
        await auditLog(env, user, 'AI_CACHE_CLEAR', { cleared: cnt, truncated });
        return corsResponse({ ok: true, cleared: cnt, truncated });
      }

      if (path === '/admin/storage/reset' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        if (!body.pin || !await validateUserPin(env, user, body.pin)) return corsResponse({ ok: false, message: 'PIN \uD655\uC778\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4.' }, 401);
        const result = await resetHubData(env);
        await auditLog(env, user, 'HUB_DATA_RESET', { deleted: result.deleted, truncated: result.truncated });
        return corsResponse(result);
      }

      if (path === '/admin/user-pin/reset' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const target = normalizeUserId(body.user || '');
        if (!target) return corsResponse({ ok: false, message: '\uB300\uC0C1 \uC0AC\uC6A9\uC790\uB97C \uC120\uD0DD\uD558\uC138\uC694.' }, 400);
        const account = await getUserAccount(env, target);
        if (!account) return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 400);
        const resetPin = getDefaultResetPin(env);
        if (!resetPin) return corsResponse({ ok: false, message: 'DEFAULT_RESET_PIN is not configured.' }, 500);
        await setUserPin(env, target, resetPin);
        await revokeUserSessions(env, target);  // L-3: PIN 리셋 시 대상의 기존 세션 무효화(재인증 강제)
        await auditLog(env, user, 'PIN_RESET', { target });
        return corsResponse({ ok: true, user: target });
      }

      //
      if (path === '/admin/storage/stats' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        return corsResponse(await getStorageStats(env));
      }

      //
      if (path === '/admin/storage/backup' && request.method === 'GET') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const backup = await buildHubBackup(env, user);
        await auditLog(env, user, 'HUB_BACKUP_EXPORT', { keys: Object.keys(backup.data || {}) });
        return corsResponse(backup);
      }

      //
      if (path === '/admin/storage/cleanup' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        if (body.target !== 'audit-old') return corsResponse({ ok: false, message: '\uC9C0\uC6D0\uD558\uC9C0 \uC54A\uB294 \uC815\uB9AC \uB300\uC0C1\uC785\uB2C8\uB2E4.' }, 400);
        const days = Math.max(1, Math.min(3650, parseInt(body.days || '90', 10) || 90));
        const max = Math.max(50, Math.min(1000, parseInt(body.max || '500', 10) || 500));
        const dryRun = body.dryRun !== false;
        const result = await cleanupOldAudit(env, days, dryRun, max);
        if (!dryRun) await auditLog(env, user, 'AUDIT_CLEANUP', { days, scanned: result.scanned, deleted: result.deleted, truncated: result.truncated });
        return corsResponse(result);
      }

      //
      if (path === '/links' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const raw = await env.ENGR_KV.get('config:links');
        return corsResponse({ ok: true, links: raw ? JSON.parse(raw) : [] });
      }
      //
      if (path === '/links' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const newLink = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          title: body.title || '',
          url: body.url || '',
          category: body.category || '\uAE30\uD0C0',
          desc: body.desc || '',
          comments: [],
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        links.push(newLink);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_ADD', { title: newLink.title });
        ctx.waitUntil(pushNotify(env, 'link', user, { target: newLink.title || '제목 없음' }));
        return corsResponse({ ok: true, link: newLink });
      }
      if (path.match(/^\/links\/[^/]+\/comments(?:\/[^/]+)?$/)) {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const parts = path.split('/');
        const id = decodeURIComponent(parts[2] || '');
        if (request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const result = await addCollectionComment(env, 'config:links', id, user, body.text, 'LINK_COMMENT_ADD');
          return corsResponse(result.body, result.status);
        }
        if (request.method === 'DELETE') {
          const commentId = decodeURIComponent(parts[4] || '');
          const result = await deleteCollectionComment(env, 'config:links', id, commentId, user, 'LINK_COMMENT_DELETE');
          return corsResponse(result.body, result.status);
        }
      }
      //
      if (/^\/links\/[^/]+$/.test(path) && request.method === 'PUT') {  // L-8: /links/{id}/comments \uD761\uC218 \uBC29\uC9C0(\uC815\uD655 \uB9E4\uCE6D)
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const target = links.find(l => l.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const lf = {}; ['title', 'url', 'category', 'desc'].forEach(k => { if (body[k] !== undefined) lf[k] = body[k]; });  // M-3: 허용 필드만(createdBy/createdAt/comments 보존)
        links = links.map(l => l.id === id ? { ...l, ...lf, id, updatedBy: user, updatedAt: new Date().toISOString() } : l);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_UPDATE', { id, title: body.title });
        return corsResponse({ ok: true });
      }

      //
      if (/^\/links\/[^/]+$/.test(path) && request.method === 'DELETE') {  // L-8: /links/{id}/comments \uD761\uC218 \uBC29\uC9C0(\uC815\uD655 \uB9E4\uCE6D)
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const delLink = links.find(l => l.id === id);
        if (!await canModifyItem(env, user, delLink)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const before = links.length;
        links = links.filter(l => l.id !== id);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_DELETE', { id, title: delLink?.title });
        return corsResponse({ ok: true, deleted: before - links.length });
      }

      //
      if (path === '/knowledge' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const raw = await env.ENGR_KV.get('config:knowledge');
        return corsResponse({ ok: true, items: raw ? JSON.parse(raw) : [] });
      }
      //
      // \u2500\u2500 My Desk \uAC1C\uC778 \uB370\uC774\uD130 (\uC0AC\uC6A9\uC790\uBCC4, \uAE30\uAE30 \uAC04 \uB3D9\uAE30\uD654) \u2500\u2500
      if (path === '/mydesk' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        let store = {};
        try { const raw = await env.ENGR_KV.get(`mydesk:${user}`); if (raw) store = JSON.parse(raw); } catch (_) {}
        return corsResponse({ ok: true, data: store });
      }
      if (path === '/mydesk' && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const store = (body && body.store && typeof body.store === 'object') ? body.store : {};
        try { await env.ENGR_KV.put(`mydesk:${user}`, JSON.stringify(store)); }
        catch (e) { return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328' }, 500); }
        return corsResponse({ ok: true });
      }
      if (path === '/mydesk' && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        try { await env.ENGR_KV.delete(`mydesk:${user}`); } catch (_) {}
        return corsResponse({ ok: true });
      }
      // \u2500\u2500 Web Push \u2500\u2500
      if (path === '/push/public-key' && request.method === 'GET') {
        return corsResponse({ ok: true, publicKey: env.VAPID_PUBLIC_KEY || '', configured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_JWK) });
      }
      if (path === '/push/subscribe' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const sub = body.subscription;
        if (!sub || !sub.endpoint) return corsResponse({ ok: false, message: '\uAD6C\uB3C5 \uC815\uBCF4\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 400);
        const subs = await getPushSubs(env);
        const list = (subs[user] || []).filter(s => s.endpoint !== sub.endpoint);
        list.push({ endpoint: sub.endpoint, keys: sub.keys || {}, ua: (request.headers.get('user-agent') || '').slice(0, 140), ts: Date.now() });
        subs[user] = list;
        await savePushSubs(env, subs);
        await env.ENGR_KV.put('push:pref:' + user, JSON.stringify({ enabled: true }));
        return corsResponse({ ok: true });
      }
      if (path === '/push/unsubscribe' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const subs = await getPushSubs(env);
        if (subs[user]) {
          if (body.endpoint) subs[user] = subs[user].filter(s => s.endpoint !== body.endpoint);
          else delete subs[user];
          if (subs[user] && !subs[user].length) delete subs[user];
          await savePushSubs(env, subs);
        }
        await env.ENGR_KV.put('push:pref:' + user, JSON.stringify({ enabled: false }));
        return corsResponse({ ok: true });
      }
      if (path === '/push/pending' && request.method === 'POST') {
        // \uC11C\uBE44\uC2A4\uC6CC\uCEE4\uAC00 \uD638\uCD9C: \uC5D4\uB4DC\uD3EC\uC778\uD2B8 \uC18C\uC720 \uC99D\uBA85\uB9CC\uC73C\uB85C \uBCF4\uB958 \uC54C\uB9BC \uC218\uB839 \uD6C4 \uBE44\uC6C0(\uC138\uC158 \uBD88\uD544\uC694)
        const body = await request.json().catch(() => ({}));
        if (!body.endpoint) return corsResponse({ ok: false, items: [] }, 400);
        const pk = 'push:pending:' + await endpointHash(body.endpoint);
        let pend = []; try { const r = await env.ENGR_KV.get(pk); if (r) pend = JSON.parse(r); } catch (_) {}
        if (pend.length) await env.ENGR_KV.delete(pk);
        return corsResponse({ ok: true, items: pend });
      }
      if (path === '/push/pref' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        let pref = { enabled: true }; try { const r = await env.ENGR_KV.get('push:pref:' + user); if (r) pref = JSON.parse(r); } catch (_) {}
        const subs = await getPushSubs(env);
        return corsResponse({ ok: true, enabled: pref.enabled !== false, subscribed: !!(subs[user] && subs[user].length), configured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_JWK) });
      }
      if (path === '/push/pref' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        await env.ENGR_KV.put('push:pref:' + user, JSON.stringify({ enabled: body.enabled !== false }));
        return corsResponse({ ok: true });
      }
      if (path === '/push/test' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const subs = await getPushSubs(env);
        const list = subs[user] || [];
        if (!list.length) return corsResponse({ ok: false, message: '\uC774 \uAE30\uAE30\uC5D0\uC11C \uBA3C\uC800 \uC54C\uB9BC\uC744 \uCF1C\uC8FC\uC138\uC694.' }, 400);
        const payload = { title: '\uD83D\uDD14 \uD14C\uC2A4\uD2B8 \uC54C\uB9BC', body: '\uC54C\uB9BC\uC774 \uC815\uC0C1 \uB3D9\uC791\uD569\uB2C8\uB2E4.', page: 'mydesk', ts: Date.now(), tag: 'test' };
        let sent = 0, gone = 0, changed = false;
        for (const s of list) {
          try {
            const st = await sendWebPush(env, s);
            if (st >= 200 && st < 300) { sent++; try { await enqueuePending(env, s.endpoint, payload); } catch (_) {} }  // L-28: 성공 시에만 pending
            else if (st === 404 || st === 410) { gone++; subs[user] = (subs[user] || []).filter(x => x.endpoint !== s.endpoint); changed = true; }  // L-27: 만료 endpoint 제거
          } catch (_) {}
        }
        if (subs[user] && !subs[user].length) { delete subs[user]; changed = true; }
        if (changed) await savePushSubs(env, subs);
        return corsResponse({ ok: true, sent, gone });
      }
      if (path === '/push/send' && request.method === 'POST') {
        // 관리자: 선택한 인원에게 직접 알림 발송
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 사용할 수 있습니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const title = String(body.title || '').slice(0, 80).trim();
        const text = String(body.body || '').slice(0, 300).trim();
        const page = String(body.page || '').slice(0, 40);
        const includeMuted = !!body.includeMuted;
        const recipients = Array.isArray(body.recipients) ? [...new Set(body.recipients.map(normalizeUserId).filter(Boolean))] : [];
        if (!title && !text) return corsResponse({ ok: false, message: '제목 또는 내용을 입력하세요.' }, 400);
        if (!recipients.length) return corsResponse({ ok: false, message: '받을 사람을 선택하세요.' }, 400);
        const subs = await getPushSubs(env);
        const payload = { title: title || '📢 알림', body: text, page, ts: Date.now(), tag: 'admin-msg', from: user };
        let sent = 0, changed = false; const skipped = [];
        for (const uid of recipients) {
          if (!includeMuted) {
            let pref = {}; try { const pr = await env.ENGR_KV.get('push:pref:' + uid); if (pr) pref = JSON.parse(pr); } catch (_) {}
            if (pref.enabled === false) { skipped.push(uid); continue; }
          }
          const list = subs[uid] || [];
          if (!list.length) { skipped.push(uid); continue; }
          for (const s of list) {
            try { await enqueuePending(env, s.endpoint, payload); } catch (_) {}
            try { const st = await sendWebPush(env, s); if (st >= 200 && st < 300) sent++; else if (st === 404 || st === 410) { subs[uid] = (subs[uid] || []).filter(x => x.endpoint !== s.endpoint); changed = true; } } catch (_) {}
          }
          if (subs[uid] && !subs[uid].length) { delete subs[uid]; changed = true; }
        }
        if (changed) await savePushSubs(env, subs);
        await auditLog(env, user, 'PUSH_SEND', { count: sent, to: recipients.length, skipped: skipped.length, title: title || '(제목없음)' });
        return corsResponse({ ok: true, sent, skipped });
      }
      if (path === '/push/settings' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const settings = await getPushSettings(env);
        const subs = await getPushSubs(env);
        const subscribers = [];
        for (const u of Object.keys(subs)) {
          let pf = {}; try { const pr = await env.ENGR_KV.get('push:pref:' + u); if (pr) pf = JSON.parse(pr); } catch (_) {}
          if (pf.enabled === false) continue;   // 알림 끈 사용자는 발송 대상이 아니므로 목록에서 제외
          subscribers.push({ id: u, devices: (subs[u] || []).length });
        }
        return corsResponse({ ok: true, settings, subscribers, configured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_JWK) });
      }
      if (path === '/push/settings' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const body = await request.json().catch(() => ({}));
        const cur = await getPushSettings(env);
        const events = {};
        for (const k of Object.keys(PUSH_EVENTS)) {
          const inc = (body.events && body.events[k]) || {};
          const base = cur.events[k];
          events[k] = {
            enabled: inc.enabled !== undefined ? !!inc.enabled : base.enabled,
            title: inc.title !== undefined ? String(inc.title).slice(0, 80) : base.title,
            body: inc.body !== undefined ? String(inc.body).slice(0, 160) : base.body,
          };
        }
        const include = Array.isArray(body.include) ? body.include.map(normalizeUserId).filter(Boolean) : cur.include;
        const exclude = Array.isArray(body.exclude) ? body.exclude.map(normalizeUserId).filter(Boolean) : cur.exclude;
        await env.ENGR_KV.put('push:settings', JSON.stringify({ events, include, exclude }));
        await auditLog(env, user, 'PUSH_SETTINGS_CHANGE', { keys: Object.keys(body) });
        return corsResponse({ ok: true });
      }
      if (path === '/private-notes' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const notes = await loadPrivateNotes(env, user);
        return corsResponse({ ok: true, items: notes.items });
      }
      if (path === '/private-notes' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const notes = await loadPrivateNotes(env, user);
        let items = notes.items;
        const item = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
          type: body.type || 'todo',
          title: body.title || '',
          content: body.content || '',
          dueDate: body.dueDate || '',
          status: body.status || 'open',
          priority: body.priority || 'normal',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        items.unshift(item);
        await env.ENGR_KV.put(notes.key, JSON.stringify(items.slice(0, 300)));
        return corsResponse({ ok: true, item });
      }
      if (path.startsWith('/private-notes/') && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const body = await request.json().catch(() => ({}));
        const notes = await loadPrivateNotes(env, user);
        let items = notes.items;
        items = items.map(it => it.id === id ? { ...it, ...body, id, updatedAt: new Date().toISOString() } : it);
        await env.ENGR_KV.put(notes.key, JSON.stringify(items.slice(0, 300)));
        return corsResponse({ ok: true });
      }
      if (path.startsWith('/private-notes/') && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const notes = await loadPrivateNotes(env, user);
        let items = notes.items;
        const before = items.length;
        items = items.filter(it => it.id !== id);
        await env.ENGR_KV.put(notes.key, JSON.stringify(items));
        return corsResponse({ ok: true, deleted: before - items.length });
      }
      //
      if (path === '/knowledge' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const newItem = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          product: body.product || '\uAE30\uD0C0',
          category: body.category || '\uD301',
          title: body.title || '',
          content: body.content || '',
          link: body.link || '',
          comments: [],
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        items.push(newItem);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_ADD', { product: newItem.product, title: newItem.title });
        ctx.waitUntil(pushNotify(env, 'knowledge', user, { target: newItem.title || newItem.product || '노하우' }));
        return corsResponse({ ok: true, item: newItem });
      }
      if (path.match(/^\/knowledge\/[^/]+\/comments(?:\/[^/]+)?$/)) {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const parts = path.split('/');
        const id = decodeURIComponent(parts[2] || '');
        if (request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const result = await addCollectionComment(env, 'config:knowledge', id, user, body.text, 'KNOWLEDGE_COMMENT_ADD');
          return corsResponse(result.body, result.status);
        }
        if (request.method === 'DELETE') {
          const commentId = decodeURIComponent(parts[4] || '');
          const result = await deleteCollectionComment(env, 'config:knowledge', id, commentId, user, 'KNOWLEDGE_COMMENT_DELETE');
          return corsResponse(result.body, result.status);
        }
      }
      //
      if (path.startsWith('/knowledge/') && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);  // L-10: \uB313\uAE00 \uB77C\uC6B0\uD2B8\uC640 \uB514\uCF54\uB529 \uD1B5\uC77C
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const kf = {}; ['product', 'category', 'title', 'content', 'link'].forEach(k => { if (body[k] !== undefined) kf[k] = body[k]; });  // M-4: 허용 필드만(createdBy/createdAt/comments 보존)
        items = items.map(it => it.id === id ? { ...it, ...kf, id, updatedBy: user, updatedAt: new Date().toISOString() } : it);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_UPDATE', { id, title: body.title || target?.title });
        return corsResponse({ ok: true });
      }
      //
      if (path.startsWith('/knowledge/') && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);  // L-10: \uB313\uAE00 \uB77C\uC6B0\uD2B8\uC640 \uB514\uCF54\uB529 \uD1B5\uC77C
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        items = items.filter(it => it.id !== id);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_DELETE', { id, title: target?.title });
        return corsResponse({ ok: true });
      }

      //
      if (path === '/eos' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        let eosItems = [];
        try { const raw = await env.ENGR_KV.get('config:eos'); if (raw) eosItems = JSON.parse(raw); } catch (_) {}
        return corsResponse({ ok: true, items: eosItems });
      }
      //
      if (path === '/eos' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const newItem = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          customer: body.customer || '',
          productDesc: body.productDesc || '',
          siteId: body.siteId || '',
          quantity: body.quantity || '',
          serial: body.serial || '',
          startDate: okDate(body.startDate),
          expireDate: okDate(body.expireDate),   // End Date (지원/만료 종료일 — D-day 기준)
          memo: body.memo || '',
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        items.push(newItem);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_ADD', { customer: newItem.customer, product: newItem.productDesc, expire: newItem.expireDate });
        ctx.waitUntil(pushNotify(env, 'eos', user, { target: [newItem.productDesc, newItem.customer].filter(Boolean).join(' / ') || '라이선스' }));
        return corsResponse({ ok: true, item: newItem });
      }
      if (path === '/eos/bulk' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const body = await request.json().catch(() => ({}));
        const items = Array.isArray(body.items) ? body.items : [];
        if (!items.length) return corsResponse({ ok: false, message: '등록할 항목이 없습니다.' }, 400);
        if (items.length > 200) return corsResponse({ ok: false, message: '한 번에 최대 200건까지 등록할 수 있습니다.' }, 400);  // M-8: KV 비대화 방지
        const raw = await env.ENGR_KV.get('config:eos');
        let store = raw ? JSON.parse(raw) : [];
        const created = [];
        for (const b of items) {
          if (!b || !b.productDesc) continue;
          const it = {
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            customer: b.customer || '', productDesc: b.productDesc || '', siteId: b.siteId || '',
            quantity: b.quantity || '', serial: b.serial || '', startDate: okDate(b.startDate),
            expireDate: okDate(b.expireDate), memo: b.memo || '', createdBy: user, createdAt: new Date().toISOString(),
          };
          store.push(it); created.push(it);
        }
        if (!created.length) return corsResponse({ ok: false, message: 'Product Description이 있는 항목이 없습니다.' }, 400);
        await env.ENGR_KV.put('config:eos', JSON.stringify(store));
        await auditLog(env, user, 'EOS_ADD_BULK', { count: created.length, customer: created[0].customer });
        const cust = created[0].customer || '';
        const tgt = created.length > 1 ? `${cust} ${created[0].productDesc} 외 ${created.length - 1}건` : [created[0].productDesc, cust].filter(Boolean).join(' / ');
        ctx.waitUntil(pushNotify(env, 'eos', user, { target: tgt }));
        return corsResponse({ ok: true, created: created.length, items: created });
      }
      //
      if (path.startsWith('/eos/') && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const before = items.length;
        items = items.filter(it => it.id !== id);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_DELETE', { id });
        return corsResponse({ ok: true, deleted: before - items.length });
      }
      //
      if (path.startsWith('/eos/') && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const ef = {}; ['customer', 'productDesc', 'siteId', 'quantity', 'serial', 'memo'].forEach(k => { if (body[k] !== undefined) ef[k] = body[k]; });  // M-3/M-7: 허용필드+날짜검증
        if (body.startDate !== undefined) ef.startDate = okDate(body.startDate);
        if (body.expireDate !== undefined) ef.expireDate = okDate(body.expireDate);
        items = items.map(it => it.id === id ? { ...it, ...ef, id, updatedBy: user, updatedAt: new Date().toISOString() } : it);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_UPDATE', { id, customer: target?.customer, product: body.productDesc || target?.productDesc, expire: body.expireDate || target?.expireDate });
        return corsResponse({ ok: true });
      }


      // \u2500\u2500 \u00A75 \uAE30\uB2A5 \uD1A0\uAE00 (feature_flags \u00B7 app_settings) \u2500\u2500
      if (path === '/features' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        return corsResponse({ ok: true, flags: await getFeatureFlags(env), monAllowed: await isMonitorAllowed(env, user) });
      }
      if (path === '/features' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const b = await request.json().catch(() => ({}));
        const next = { ...await getFeatureFlags(env), ...(b.flags || {}) };
        next.settings = true; next.dash = true;  // L-6: 보호 토글(설정·대시보드)은 서버에서 강제 ON — 클라 가드 의존 제거
        try { await env.DB.prepare("INSERT INTO app_settings (key,value) VALUES ('feature_flags',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(JSON.stringify(next)).run(); }
        catch (e) { return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328: ' + e.message }, 500); }
        await auditLog(env, user, 'FEATURE_TOGGLE', { featFlags: next });
        return corsResponse({ ok: true, flags: next });
      }

      // \u2500\u2500 \u00A71 \uD638\uD658\uC131\u00B7EOS \uB9E4\uD2B8\uB9AD\uC2A4 (compat_matrix \u00B7 D1) \u2500\u2500
      if (path === '/compat' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        const q = (new URL(request.url).searchParams.get('q') || '').trim().toLowerCase();
        let rows = [];
        try { const r = await env.DB.prepare('SELECT * FROM compat_matrix ORDER BY product, product_version, os').all(); rows = r.results || []; } catch (_) {}
        if (q) rows = rows.filter(x => [x.product, x.product_version, x.os, x.os_version, x.note, x.supported].some(v => (v || '').toLowerCase().includes(q)));
        return corsResponse({ ok: true, items: rows });
      }
      if (path === '/compat' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);  // L-11
        const b = await request.json().catch(() => ({}));
        const now = new Date().toISOString();
        try {
          const r = await env.DB.prepare('INSERT INTO compat_matrix (product,product_version,os,os_version,supported,eos_date,eol_date,note,source,status,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.product || '', b.product_version || '', b.os || '', b.os_version || '', b.supported || '', b.eos_date || '', b.eol_date || '', b.note || '', b.source || '', 'draft', now).run();
          await auditLog(env, user, 'MATRIX_ADD', { matrixType: 'compat', product: b.product || '', os: b.os || '' });
          return corsResponse({ ok: true, id: r.meta?.last_row_id });
        } catch (e) { return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328: ' + e.message }, 500); }
      }
      if (path.startsWith('/compat/') && path.endsWith('/confirm') && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);  // L-11
        const id = parseInt(path.split('/')[2]) || 0;
        if (!(id > 0)) return corsResponse({ ok: false, message: '잘못된 id 입니다.' }, 400);
        try { await env.DB.prepare("UPDATE compat_matrix SET status='confirmed', verified_by=?, verified_at=? WHERE id=?").bind(user, new Date().toISOString(), id).run(); await auditLog(env, user, 'MATRIX_CONFIRM', { matrixType: 'compat', id }); return corsResponse({ ok: true }); }
        catch (e) { return corsResponse({ ok: false, message: e.message }, 500); }
      }
      if (/^\/compat\/\d+$/.test(path) && request.method === 'PUT') {  // L-12: /compat/{id}/confirm 흡수 방지(정확 매칭)
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '비활성화된 기능입니다.' }, 403);  // L-11
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const id = parseInt(path.split('/')[2]) || 0;
        if (!(id > 0)) return corsResponse({ ok: false, message: '잘못된 id 입니다.' }, 400);
        const b = await request.json().catch(() => ({}));
        try {
          await env.DB.prepare('UPDATE compat_matrix SET product=?,product_version=?,os=?,os_version=?,supported=?,eos_date=?,eol_date=?,note=?,source=?,updated_at=? WHERE id=?')
            .bind(b.product || '', b.product_version || '', b.os || '', b.os_version || '', b.supported || '', b.eos_date || '', b.eol_date || '', b.note || '', b.source || '', new Date().toISOString(), id).run();
          await auditLog(env, user, 'MATRIX_UPDATE', { matrixType: 'compat', id });
          return corsResponse({ ok: true });
        } catch (e) { return corsResponse({ ok: false, message: e.message }, 500); }
      }
      if (/^\/compat\/\d+$/.test(path) && request.method === 'DELETE') {  // L-12: /compat/{id}/confirm 흡수 방지(정확 매칭)
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '비활성화된 기능입니다.' }, 403);  // L-11
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const id = parseInt(path.split('/')[2]) || 0;
        if (!(id > 0)) return corsResponse({ ok: false, message: '잘못된 id 입니다.' }, 400);
        try { await env.DB.prepare('DELETE FROM compat_matrix WHERE id=?').bind(id).run(); await auditLog(env, user, 'MATRIX_DELETE', { matrixType: 'compat', id }); return corsResponse({ ok: true }); }
        catch (e) { return corsResponse({ ok: false, message: e.message }, 500); }
      }

      // \u2500\u2500 F2/F3 JQL \uC804\uC6A9 \uC5D4\uB4DC\uD3EC\uC778\uD2B8 (Phase 0 \uACE8\uACA9, \uB85C\uC9C1\uC740 \u00A72/\u00A73\uC5D0\uC11C \uD655\uC7A5) \u2500\u2500
      if (path === '/team/history' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).history) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        const body = await request.json().catch(() => ({}));
        const df = (body.dateField === 'updated') ? 'updated' : 'created';
        const parts = ['project = ENGR'];
        if (/^\d{4}-\d{2}-\d{2}$/.test(body.from || '')) parts.push(`${df} >= "${body.from}"`);
        if (/^\d{4}-\d{2}-\d{2}$/.test(body.to || '')) parts.push(`${df} <= "${body.to} 23:59"`);
        if (body.customer) parts.push(`text ~ "${jqlTextEsc(body.customer)}"`);  // L-14   // summary~만이면 점검 등 요약 외 위치 누락 → text(요약+설명+댓글+텍스트필드)로 포함
        if (body.product) parts.push(`labels = "${jqlEsc(body.product)}"`);
        if (body.status) parts.push(`status = "${jqlEsc(body.status)}"`);
        if (body.type === 'subtask') parts.push('issuetype = "\uD558\uC704 \uC791\uC5C5"');
        else if (body.type === 'task') parts.push('issuetype = "\uC791\uC5C5"');
        const jql = parts.join(' AND ') + ` ORDER BY ${df} DESC`;
        let issues; try { issues = await jiraSearchJql(env, jql, TEAM_FIELDS, 10); } catch (e) { return corsResponse({ ok: false, message: 'Jira \uC870\uD68C \uC2E4\uD328: ' + e.message }, 502); }
        const custList = await getCustomersD1(env);
        let items = issues.map(it => mapJiraIssue(it, custList));
        // \uACE0\uAC1D\uC0AC \uD544\uD130\uB294 JQL(summary ~ "\uACE0\uAC1D\uC0AC")\uC774 \uC774\uBBF8 \uCC98\uB9AC. \uBE0C\uB798\uD0B7 \uC815\uBC00 \uC7AC\uD544\uD130\uB294 \uC815\uB2F9 \uC774\uC288\uB97C \uC870\uC6A9\uD788 \uB204\uB77D\uC2DC\uCF1C \uC81C\uAC70(\uBD84\uB958\uB294 cls \uBC30\uC9C0\uB85C\uB9CC \uD45C\uC2DC).
        if (body.assignee) items = items.filter(x => x.assignee === body.assignee);   // \uB2F4\uB2F9\uC790 \uD6C4\uCC98\uB9AC(\u00A72\uC5D0\uC11C accountId \uB9E4\uD551 \uC608\uC815)
        await auditLog(env, user, 'HIST_VIEW', { histType: 'history', count: items.length });
        return corsResponse({ ok: true, jql, count: items.length, items });
      }
      if ((path === '/team/daily' || path === '/team/weekly') && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).monitor) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        const isDaily = path === '/team/daily';
        if (!await isMonitorAllowed(env, user)) { await auditLog(env, user, 'MON_VIEW', { monType: isDaily ? 'daily' : 'weekly', denied: true }); return corsResponse({ ok: false, message: '\uC811\uADFC \uAD8C\uD55C\uC774 \uC5C6\uC2B5\uB2C8\uB2E4(\uD300 \uBAA8\uB2C8\uD130 \uD5C8\uC6A9\uBAA9\uB85D).' }, 403); }
        const body = await request.json().catch(() => ({}));
        let jql, meta;
        if (isDaily) {
          const day = /^\d{4}-\d{2}-\d{2}$/.test(body.day || '') ? body.day : new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10);  // M-6: 기본 '오늘'을 KST 기준으로(cron과 일치)
          jql = `project = ENGR AND updated >= "${day}" AND updated < "${nextDayStr(day)}" ORDER BY updated DESC`;
          meta = { monType: 'daily', day };
        } else {
          const days = Math.max(1, Math.min(31, parseInt(body.days) || 7));
          jql = `project = ENGR AND updated >= "-${days}d" ORDER BY updated DESC`;
          meta = { monType: 'weekly', days };
        }
        let issues; try { issues = await jiraSearchJql(env, jql, TEAM_FIELDS, 12); } catch (e) { return corsResponse({ ok: false, message: 'Jira \uC870\uD68C \uC2E4\uD328: ' + e.message }, 502); }
        const custList = await getCustomersD1(env);
        const items = issues.map(it => mapJiraIssue(it, custList));
        await auditLog(env, user, 'MON_VIEW', { ...meta, count: items.length });
        return corsResponse({ ok: true, ...meta, count: items.length, items });
      }

      // \u2500\u2500 \u00A73 \uD300 \uBAA8\uB2C8\uD130 \uC2A4\uB0C5\uC0F7 \uC870\uD68C (mj.park) \u2500\u2500
      if (path === '/team/snapshot' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).monitor) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        if (!await isMonitorAllowed(env, user)) { await auditLog(env, user, 'MON_VIEW', { monType: 'snapshot', denied: true }); return corsResponse({ ok: false, message: '\uC811\uADFC \uAD8C\uD55C\uC774 \uC5C6\uC2B5\uB2C8\uB2E4(\uD300 \uBAA8\uB2C8\uD130 \uD5C8\uC6A9\uBAA9\uB85D).' }, 403); }
        let snap = null;
        try { const r = await env.DB.prepare('SELECT day,payload_json,built_at FROM team_daily_snapshot ORDER BY day DESC LIMIT 1').first(); if (r && r.payload_json) snap = { day: r.day, built_at: r.built_at, ...JSON.parse(r.payload_json) }; } catch (_) {}
        await auditLog(env, user, 'MON_VIEW', { monType: 'snapshot', count: snap?.count || 0 });
        return corsResponse({ ok: true, snapshot: snap });
      }

      return corsResponse({ ok: false, message: '\uC5C6\uB294 \uACBD\uB85C\uC785\uB2C8\uB2E4.' }, 404);
    } catch (err) {
      return corsResponse({ ok: false, message: err.message || '\uC11C\uBC84 \uC624\uB958' }, 500);
    }
  },

  // \u2500\u2500 Cron Scheduled Handler \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  async scheduled(event, env, ctx) {
    // §3 일일 팀 업무 스냅샷 (08:30 KST = 23:30 UTC). KST 전일(완료된 하루) updated 이슈 저장.
    try {
      const _kst = new Date(Date.now() + 9 * 3600e3); _kst.setUTCDate(_kst.getUTCDate() - 1);  // 08:30 KST 실행 → 전일을 스냅샷(당일은 00:00~08:30분만이라 거의 공백)
      const kstDay = _kst.toISOString().slice(0, 10);
      ctx.waitUntil(buildDailySnapshot(env, kstDay));
    } catch (_) {}
  },
};
