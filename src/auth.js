// ENGR HUB worker — auth.js
// (worker.js에서 이동. 로직 변경 없음)

import { DEFAULT_USERS, SUPER_ADMIN } from './config.js';

export function normalizeUserId(id = '') {
  return String(id || '').trim().toLowerCase();
}

export async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function createSession(env, user, minutes = 120) {
  const token = crypto.randomUUID() + '.' + crypto.randomUUID();
  const hash = await sha256Hex(token);
  const ttl = Math.max(5, Math.min(1440, parseInt(minutes, 10) || 120)) * 60;
  await env.ENGR_KV.put(`session:${hash}`, JSON.stringify({ user, createdAt: new Date().toISOString() }), { expirationTtl: ttl });
  return token;
}

export async function revokeUserSessions(env, user) {
  const id = normalizeUserId(user);
  if (!id) return;
  await env.ENGR_KV.put(`session:revokedBefore:${id}`, new Date().toISOString(), { expirationTtl: 60 * 60 * 48 });
}

export async function getSessionUser(env, token) {
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

export function defaultUserMap() {
  return Object.fromEntries(DEFAULT_USERS.map(u => [u.id, { ...u }]));
}

export async function getUsers(env) {
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
          role: ['super', 'admin', 'user', 'sales'].includes(item.role) ? item.role : 'user',
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

export async function getUserAccount(env, id) {
  const users = await getUsers(env);
  return users[normalizeUserId(id)] || null;
}

export async function saveUserAccount(env, account) {
  const id = normalizeUserId(account.id || account.userId);
  if (!id || !/^[a-z0-9._-]{2,40}$/.test(id)) {
    throw new Error('\uACC4\uC815 ID\uB294 \uC601\uBB38/\uC22B\uC790/\uC810/\uD558\uC774\uD508/\uC5B8\uB354\uBC14\uB9CC \uD5C8\uC6A9\uB429\uB2C8\uB2E4.');
  }
  const users = await getUsers(env);
  users[id] = {
    id,
    displayName: String(account.displayName || account.name || id).trim(),
    role: ['super', 'admin', 'user', 'sales'].includes(account.role) ? account.role : 'user',
    active: account.active !== false,
  };
  users[SUPER_ADMIN] = users[SUPER_ADMIN] || { id: SUPER_ADMIN, displayName: 'mj.park', role: 'super', active: true };
  users[SUPER_ADMIN].role = 'super';
  users[SUPER_ADMIN].active = true;
  await env.ENGR_KV.put('config:users', JSON.stringify(Object.values(users)));
  return users[id];
}

export async function deactivateUserAccount(env, idRaw) {
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

export async function purgeUserAccount(env, idRaw) {
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

export function getTeamNames(env) {
  const raw = env.TEAM_NAMES || '';
  const ids = raw.split(',').map(s => normalizeUserId(s)).filter(Boolean);
  return [...new Set([...DEFAULT_USERS.map(u => u.id), ...ids])];
}

export function getDefaultResetPin(env) {
  return env.DEFAULT_RESET_PIN || '';
}

export async function getUserPinHash(env, name) {
  if (!name) return '';
  try { return await env.ENGR_KV.get(`userpin:${name}`) || ''; } catch (_) { return ''; }
}

export async function validateUserPin(env, name, pin) {
  const userHash = await getUserPinHash(env, name);
  if (userHash) return (await sha256Hex(pin)) === userHash;
  if (env.TEAM_PIN) return pin === env.TEAM_PIN;
  if (env.PIN_HASH) return (await sha256Hex(pin)) === env.PIN_HASH;
  return false;
}

export async function setUserPin(env, name, pin) {
  await env.ENGR_KV.put(`userpin:${name}`, await sha256Hex(pin));
}

export async function getAdmins(env, options = {}) {
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

export async function isSuper(env, user) {
  if (user === SUPER_ADMIN) return true;
  const admins = await getAdmins(env);
  return admins[user] === 'super';
}

export async function isAdmin(env, user) {
  const admins = await getAdmins(env);
  return !!admins[user];
}

export const SALES_ALLOW = [
  { m: ['GET', 'POST'], re: /^\/auth\// },
  { m: ['GET'], re: /^\/config\/public$/ },
  { m: ['POST'], re: /^\/usage\/pageview$/ },
  { m: ['GET', 'POST'], re: /^\/push\// },
  { m: ['GET'], re: /^\/features$/ },
  { m: ['GET', 'PUT', 'DELETE'], re: /^\/mydesk$/ },      // 개인 영역
  { m: ['GET', 'POST', 'PUT', 'DELETE'], re: /^\/eos(\/|$)/ },  // 라이선스: 영업·기술 공동 편집(MJ 확정)
  { m: ['GET', 'POST', 'PUT', 'DELETE'], re: /^\/sales(\/|$)/ }, // 영업 전용 API (STEP 6에서 신설)
];

export async function isSalesRole(env, user) {
  try { const acc = await getUserAccount(env, user); return acc && acc.role === 'sales'; } catch (_) { return false; }
}

export function salesPathAllowed(path, method) {
  return SALES_ALLOW.some(r => r.re.test(path) && r.m.includes(method));
}
