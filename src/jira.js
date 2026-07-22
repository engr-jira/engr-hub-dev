// ENGR HUB worker — jira.js
// (worker.js에서 이동. 로직 변경 없음)

import { CORS_HEADERS, INTERNAL_TAGS, TEAM_FIELDS } from './config.js';
import { auditLog } from './audit.js';
import { normalizeUserId } from './auth.js';

export async function handleJiraSearch(env, user = "") {
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

export function kstParts(d){
  const fmt = new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'});
  return Object.fromEntries(fmt.formatToParts(d).filter(p=>p.type!=='literal').map(p=>[p.type,p.value]));
}

export async function jiraSearchJql(env, jql, fields, maxPages = 8) {
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

export function extractBracket(s) { const m = /^\s*\[([^\]]+)\]/.exec(s || ''); return m ? m[1].trim() : ''; }

export function classifyBracket(summary, custList) {
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

export async function getCustomersD1(env) {
  try { const r = await env.DB.prepare('SELECT name, aliases FROM customers WHERE active=1').all(); return (r.results || []).map(c => ({ name: c.name, aliases: (() => { try { return JSON.parse(c.aliases || '[]'); } catch { return []; } })() })); }
  catch (_) { return []; }
}

export async function getMonitorAllowlist(env) {
  try { const r = await env.DB.prepare("SELECT value FROM app_settings WHERE key='monitor_allowlist'").first(); if (r && r.value) return JSON.parse(r.value); } catch (_) {}
  return ['mj.park'];
}

export async function isMonitorAllowed(env, user) { const list = await getMonitorAllowlist(env); return list.map(normalizeUserId).includes(normalizeUserId(user)); }

export function jqlEsc(s) { return String(s).replace(/[\r\n]+/g, ' ').replace(/["\\]/g, '\\$&'); }

export function jqlTextEsc(s) { return jqlEsc(String(s).replace(/[*?~^:"]/g, ' ')); }

export function okDate(s) { s = String(s == null ? '' : s).trim(); return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ''; }

export function nextDayStr(d) { const dt = new Date(d + 'T00:00:00Z'); dt.setUTCDate(dt.getUTCDate() + 1); return dt.toISOString().slice(0, 10); }

export function mapJiraIssue(it, custList) {
  const f = it.fields || {};
  return { key: it.key, summary: f.summary || '', status: f.status?.name || '', assignee: f.assignee?.displayName || '-', labels: f.labels || [], type: f.issuetype?.subtask ? 'subtask' : 'task', created: f.created || '', updated: f.updated || '', duedate: f.duedate || '', cls: classifyBracket(f.summary, custList) };
}

export async function buildDailySnapshot(env, day) {
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
