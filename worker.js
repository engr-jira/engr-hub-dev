// ENGR HUB Cloudflare Worker v1.5.8
//
//
//
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
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

function corsResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8' },
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

async function getSessionUser(env, token) {
  if (!token) return '';
  try {
    const hash = await sha256Hex(token);
    const raw = await env.ENGR_KV.get(`session:${hash}`);
    return raw ? (JSON.parse(raw).user || '') : '';
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

async function canModifyItem(env, user, item) {
  if (!user || !item) return false;
  if (await isAdmin(env, user)) return true;
  return item.createdBy === user;
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
      const items = JSON.parse(legacyRaw);
      await env.ENGR_KV.put(key, JSON.stringify(items.slice(0, 300)));
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
    const item = JSON.stringify({
      ts: new Date(now).toISOString(),
      tsNum: now,
      user, type, ...detail,
    });
    const ttl = { expirationTtl: 60 * 60 * 24 * 90 };
    await env.ENGR_KV.put(`auditLatest:${rev}:${type}:${rand}`, item, ttl);
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
async function updateAIUsage(env,user,outcome){
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
  const cacheKey = `ai:${mode}:${hash.slice(0, 40)}`;

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
  const response = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userText },
    ],
    max_tokens: 2048,
    temperature: 0.4,
  });

  const text = response?.response || '';
  if (!text) throw new Error('AI \uC751\uB2F5\uC774 \uBE44\uC5B4 \uC788\uC2B5\uB2C8\uB2E4.');

  //
  const result = {
    candidates: [{ content: { parts: [{ text }] } }],
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
  const fields = ['summary','status','priority','assignee','reporter','created','updated','labels','issuetype','parent'];

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

//
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

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
        const result = await callAI(env, 'Reply with test success in Korean.', 'debug');
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
        return corsResponse({
          ok: true,
          name: sessionUser,
          userId: sessionUser,
          displayName: account.displayName || sessionUser,
          isAdmin: role === 'admin' || role === 'super',
          isSuperAdmin: role === 'super',
          role,
          sessionMin,
        });
      }

      if (path === '/auth/login' && request.method === 'POST') {
        const body = await request.json();
        const { name, pin } = body;
        const userId = normalizeUserId(name);
        if (!userId || !pin) return corsResponse({ ok: false, message: '\uACC4\uC815 ID\uC640 PIN\uC744 \uC785\uB825\uD558\uC138\uC694.' }, 400);

        const account = await getUserAccount(env, userId);
        if (!account || account.active === false) {
          return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uB9CC \uC811\uC18D\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        }

        let pinOk = await validateUserPin(env, userId, pin);
        if (!pinOk && account.displayName) pinOk = await validateUserPin(env, account.displayName, pin);
        if (!pinOk) return corsResponse({ ok: false, message: 'PIN\uC774 \uC62C\uBC14\uB974\uC9C0 \uC54A\uC2B5\uB2C8\uB2E4.' }, 401);
        try { await setUserPin(env, userId, pin); } catch (_) {}

        const admins = await getAdmins(env);
        const role = account.role || admins[userId] || 'user';

        let sessionMin = 120;
        try {
          const cfg = await env.ENGR_KV.get('config:session_min');
          if (cfg) sessionMin = parseInt(cfg) || 120;
        } catch (_) {}

        const sessionToken = await createSession(env, userId, sessionMin);
        await auditLog(env, userId, 'LOGIN', { role });
        return corsResponse({
          ok: true,
          name: userId,
          userId,
          displayName: account.displayName || userId,
          isAdmin: role === 'admin' || role === 'super',
          isSuperAdmin: role === 'super',
          role, sessionMin, sessionToken,
        });
      }

      if (path === '/auth/change-pin' && request.method === 'POST') {
        if (!user) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json();
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
        return corsResponse({ sessionMin: parseInt(sessionRaw || '120') || 120, rangeMonths: parseInt(rangeRaw || '6') || 6, lastSync });
      }
      if (path === '/kv/usage' && request.method === 'GET') {
        return corsResponse(await getUsage(env, user));
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
        const body = await request.json();
        const { contents, mode = 'technical_analysis', detail = {} } = body;
        const prompt = contents?.[0]?.parts?.[0]?.text;
        if (!prompt) return corsResponse({ ok: false, message: '\uD504\uB86C\uD504\uD2B8\uAC00 \uBE44\uC5B4 \uC788\uC2B5\uB2C8\uB2E4.' }, 400);

        const reqId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
        try {
          const safeMode = normalizeAIMode(mode);
          const result = await callAI(env, prompt, safeMode);
          const outcome = result._cached ? 'cached' : 'success';
          await auditLog(env, user, 'AI_CALL', { reqId, mode: safeMode, promptLen: prompt.length, outcome, ...detail });
          await updateAIUsage(env, user, outcome);
          return corsResponse(result);
        } catch (e) {
          await updateAIUsage(env, user, 'fail');
          return corsResponse({ ok: false, message: e.message || 'AI \uD638\uCD9C \uC2E4\uD328' }, 502);
        }
      }

      //
      if (path === '/vt/lookup' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ error: { message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 401);
        const body = await request.json();
        const hash = String(body.hash || '').trim().toLowerCase();
        if (!hash) return corsResponse({ error: { message: 'hash \uD544\uC694' } }, 400);
        if (!isValidVtHash(hash)) return corsResponse({ error: { message: 'MD5/SHA-1/SHA-256 \uD574\uC2DC \uD615\uC2DD\uC774 \uC544\uB2D9\uB2C8\uB2E4.' } }, 400);
        const vtKey = env.VT_KEY || env.VT_API_KEY || '';
        if (!vtKey) return corsResponse({ error: { message: 'VT_KEY \uD658\uACBD\uBCC0\uC218\uAC00 \uC124\uC815\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.' } }, 500);

        const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'x-apikey': vtKey },
        });
        const data = await vtRes.json();
        if (vtRes.ok && data?.data?.attributes) {
          await auditLog(env, user, 'VT_LOOKUP', {
            hash: hash.slice(0, 16),
            name: data.data.attributes.meaningful_name || '',
            mal: data.data.attributes.last_analysis_stats?.malicious || 0,
          });
          await saveVtHistory(env, user, hash, data.data.attributes);
        }
        return corsResponse(data, vtRes.status);
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


      //
      if (path === '/admin/list' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const admins = await getAdmins(env);
        const users = await getUsers(env);
        const teamNames = Object.keys(users).filter(id => users[id].active !== false);
        const teamUsers = teamNames.map(id => ({
          id,
          displayName: users[id].displayName || id,
          role: users[id].role || admins[id] || 'user',
          active: users[id].active !== false,
        }));
        return corsResponse({ ok: true, admins, teamNames, users: teamUsers });
      }

      if (path === '/admin/users' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json();
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

      //
      if (path === '/admin/update' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json();
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
        const body = await request.json();
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
        const raw = await env.ENGR_KV.get('config:links');
        return corsResponse({ ok: true, links: raw ? JSON.parse(raw) : [] });
      }
      //
      if (path === '/links' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json();
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const newLink = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          title: body.title || '',
          url: body.url || '',
          category: body.category || '\u6E72\uACE0?',
          desc: body.desc || '',
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        links.push(newLink);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_ADD', { title: newLink.title });
        return corsResponse({ ok: true, link: newLink });
      }
      //
      if (path.startsWith('/links/') && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const body = await request.json();
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const target = links.find(l => l.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        links = links.map(l => l.id === id ? { ...l, ...body, id, updatedBy: user, updatedAt: new Date().toISOString() } : l);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_UPDATE', { id, title: body.title });
        return corsResponse({ ok: true });
      }

      //
      if (path.startsWith('/links/') && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
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
        const raw = await env.ENGR_KV.get('config:knowledge');
        return corsResponse({ ok: true, items: raw ? JSON.parse(raw) : [] });
      }
      //
      if (path === '/private-notes' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const notes = await loadPrivateNotes(env, user);
        return corsResponse({ ok: true, items: notes.items });
      }
      if (path === '/private-notes' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json();
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
        const body = await request.json();
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
        const body = await request.json();
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const newItem = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          product: body.product || '\uAE30\uD0C0',
          category: body.category || '\uD301',
          title: body.title || '',
          content: body.content || '',
          link: body.link || '',
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        items.push(newItem);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_ADD', { product: newItem.product, title: newItem.title });
        return corsResponse({ ok: true, item: newItem });
      }
      //
      if (path.startsWith('/knowledge/') && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const body = await request.json();
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        items = items.map(it => it.id === id ? { ...it, ...body, id, updatedBy: user, updatedAt: new Date().toISOString() } : it);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_UPDATE', { id, title: body.title || target?.title });
        return corsResponse({ ok: true });
      }
      //
      if (path.startsWith('/knowledge/') && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
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
        const raw = await env.ENGR_KV.get('config:eos');
        return corsResponse({ ok: true, items: raw ? JSON.parse(raw) : [] });
      }
      //
      if (path === '/eos' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json();
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const newItem = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          type: body.type || 'eos',                  // 'eos' or 'license'
          customer: body.customer || '',
          product: body.product || '',
          version: body.version || '',
          licenseName: body.licenseName || '',
          expireDate: body.expireDate || '',
          memo: body.memo || '',
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        items.push(newItem);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_ADD', { itemType: newItem.type, customer: newItem.customer, product: newItem.product, expire: newItem.expireDate, licenseName: newItem.licenseName });
        return corsResponse({ ok: true, item: newItem });
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
        const body = await request.json();
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        items = items.map(it => it.id === id ? { ...it, ...body, id, updatedBy: user, updatedAt: new Date().toISOString() } : it);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_UPDATE', { id, itemType: target?.type, customer: target?.customer, product: target?.product, expire: body.expireDate || target?.expireDate, licenseName: body.licenseName || target?.licenseName });
        return corsResponse({ ok: true });
      }

      return corsResponse({ ok: false, message: '\uC5C6\uB294 \uACBD\uB85C\uC785\uB2C8\uB2E4.' }, 404);
    } catch (err) {
      return corsResponse({ ok: false, message: err.message || '\uC11C\uBC84 \uC624\uB958' }, 500);
    }
  },
};


