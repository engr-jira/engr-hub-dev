// ENGR HUB worker — config.js
// (worker.js에서 이동. 로직 변경 없음)

export const ALLOWED_ORIGINS = [
  'https://engr-jira.github.io',
  'https://engr-jira.github.io/engr-hub',
  'https://engr-jira.github.io/engr-hub-dev',
];

export function getCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User, X-Session-Token',
    'Vary': 'Origin',
  };
}

export const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://engr-jira.github.io',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User, X-Session-Token',
};

export const SUPER_ADMIN = 'mj.park';

export const DEFAULT_USERS = [
  { id: 'mj.park', displayName: '\uBC15\uBBFC\uC900', role: 'super', active: true },
  { id: 'hs.lee', displayName: '\uC774\uD6A8\uC131', role: 'user', active: true },
  { id: 'mj.kim', displayName: '\uAE40\uBBFC\uC9C0', role: 'user', active: true },
  { id: 'kt.chae', displayName: '\uCC44\uAE30\uD0DC', role: 'admin', active: true },
  { id: 'sh.lee', displayName: '\uC774\uC11C\uD604', role: 'user', active: true },
  { id: 'so.choi', displayName: '\uCD5C\uC2DC\uC628', role: 'user', active: true },
  { id: 'jp.park', displayName: '\uBC15\uC9C4\uD45C', role: 'user', active: true },
  { id: 'yr.park', displayName: '\uBC15\uC608\uB9BC', role: 'user', active: true },
];

export const DEFAULT_KV_STORAGE_LIMIT_BYTES = 1024 * 1024 * 1024;

export function corsResponse(body, status = 200, request = null) {
  const headers = request ? getCorsHeaders(request) : CORS_HEADERS;
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export function decUser(encoded) {
  if (!encoded) return '';
  try {
    const binStr = atob(encoded);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  } catch { return encoded; }
}

export const INTERNAL_TAGS = ['hands-on', 'handson', 'hands on', 'none', 'null', 'n/a', 'na', 'test', '테스트', '내부', '검토', '긴급', 'urgent', 'poc'];

export const TEAM_FIELDS = ['summary', 'status', 'assignee', 'reporter', 'labels', 'issuetype', 'created', 'updated', 'duedate', 'customfield_10134'];
