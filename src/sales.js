// ENGR HUB worker — sales.js (STEP 6 신규: 영업 현황)
// 원칙: 모든 지표는 AI 산출물 없이 규칙 기반으로 계산한다(PC 꺼져도 영업팀 100% 동작).
// 영업(sales) 역할에게 이슈 "본문·코멘트"는 절대 내려보내지 않는다 — 제목·상태·기한까지만(MJ 확정).

import { jiraSearchJql } from './jira.js';
import { INTERNAL_TAGS } from './config.js';

// 고객사 추출: customfield_10134(정식) 우선, 없으면 제목 [브래킷] 추정(내부 태그·8자리 케이스번호 제외)
function issueCustomers(f) {
  const cf = f.customfield_10134;
  if (Array.isArray(cf) && cf.length) return cf.map(String).filter(Boolean);
  const m = String(f.summary || '').match(/^\s*\[([^\]]+)\]/);
  if (!m) return [];
  const tag = m[1].trim();
  if (/^\d{8}$/.test(tag)) return [];
  if (INTERNAL_TAGS.includes(tag.toLowerCase())) return [];
  return [tag];
}

export async function getSalesStaleDays(env) {
  try { const v = await env.ENGR_KV.get('config:sales_stale_days'); const n = parseInt(v || '14', 10); return (n >= 1 && n <= 365) ? n : 14; } catch (_) { return 14; }
}

async function ensureSalesTable(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS sales_notes (customer TEXT NOT NULL, product TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '', next_contact TEXT NOT NULL DEFAULT '', updated_by TEXT, updated_at INTEGER, PRIMARY KEY (customer, product))").run();
}

export async function loadSalesNotes(env) {
  try {
    await ensureSalesTable(env);
    const r = await env.DB.prepare('SELECT customer, product, status, body, next_contact, updated_by, updated_at FROM sales_notes').all();
    return r.results || [];
  } catch (_) { return []; }
}

export async function saveSalesNote(env, user, note) {
  await ensureSalesTable(env);
  const customer = String(note.customer || '').trim().slice(0, 80);
  const product = String(note.product || '').trim().slice(0, 120);
  if (!customer) throw new Error('고객사는 필수입니다.');
  const status = String(note.status || '').trim().slice(0, 20);
  const body = String(note.body || '').trim().slice(0, 2000);
  const nextContact = String(note.next_contact || '').trim().slice(0, 10);
  await env.DB.prepare('INSERT INTO sales_notes (customer, product, status, body, next_contact, updated_by, updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(customer, product) DO UPDATE SET status=excluded.status, body=excluded.body, next_contact=excluded.next_contact, updated_by=excluded.updated_by, updated_at=excluded.updated_at')
    .bind(customer, product, status, body, nextContact, user, Date.now()).run();
  return { customer, product, status };
}

// 영업 현황 집계 — Jira 원문은 서버 안에서만 소비하고 집계·제목만 반환
export async function buildSalesOverview(env) {
  const staleDays = await getSalesStaleDays(env);
  let rangeMonths = 6;
  try { rangeMonths = parseInt(await env.ENGR_KV.get('config:range_months') || '6', 10) || 6; } catch (_) {}
  const days = rangeMonths * 30;

  // 라이선스(만료 임박 정렬은 프론트에서 D-day 계산)
  let eos = [];
  try { const raw = await env.ENGR_KV.get('config:eos'); if (raw) eos = JSON.parse(raw); } catch (_) {}

  // 미완료 이슈 → 고객사별 규칙 기반 집계
  const jql = `project = ENGR AND statusCategory != Done AND created >= "-${days}d" ORDER BY duedate ASC`;
  const fields = ['summary', 'status', 'duedate', 'updated', 'assignee', 'customfield_10134'];
  let issues = [];
  try { issues = await jiraSearchJql(env, jql, fields, 8); } catch (e) { /* Jira 실패 시 라이선스만이라도 */ }

  const today = new Date().toISOString().slice(0, 10);
  const map = new Map();
  for (const it of issues) {
    const f = it.fields || {};
    const custs = issueCustomers(f);
    if (!custs.length) continue;
    const due = f.duedate || '';
    const updated = f.updated || '';
    const overdue = !!(due && due < today);
    const row = { key: it.key, title: f.summary || '', status: f.status?.name || '', due, assignee: f.assignee?.displayName || '-' };
    for (const c of custs) {
      if (!map.has(c)) map.set(c, { name: c, open: 0, overdue: 0, lastActivity: '', issues: [] });
      const g = map.get(c);
      g.open++;
      if (overdue) g.overdue++;
      if (updated > g.lastActivity) g.lastActivity = updated;
      if (g.issues.length < 30) g.issues.push(row);
    }
  }
  const customers = [...map.values()].sort((a, b) => b.overdue - a.overdue || b.open - a.open);

  return {
    ok: true, built_at: Date.now(), staleDays, rangeMonths,
    jiraOk: issues.length > 0 || false,
    customers,
    eos,
    notes: await loadSalesNotes(env),
  };
}
