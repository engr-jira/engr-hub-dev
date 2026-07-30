// ENGR HUB Cloudflare Worker v1.5.11
//
//
//

import { CORS_HEADERS, SUPER_ADMIN, TEAM_FIELDS, corsResponse, decUser, getCorsHeaders } from './src/config.js';
import { PUSH_EVENTS, endpointHash, enqueuePending, getPushSettings, getPushSubs, pushNotify, savePushSubs, sendWebPush } from './src/push.js';
import { addCollectionComment, canModifyItem, deleteCollectionComment } from './src/items.js';
import { auditLog, cleanupOldAudit, getAuditReadD1 } from './src/audit.js';
import { buildDailySnapshot, getCustomersD1, handleJiraSearch, isMonitorAllowed, jiraSearchJql, jqlEsc, jqlTextEsc, mapJiraIssue, nextDayStr, okDate } from './src/jira.js';
import { buildHubBackup, getStorageStats, resetHubData } from './src/kv.js';
import { createSession, deactivateUserAccount, getAdmins, getDefaultResetPin, getSessionUser, getTeamNames, getUserAccount, getUserPinHash, getUsers, isAdmin, isSalesRole, isSuper, normalizeUserId, purgeUserAccount, revokeUserSessions, salesPathAllowed, saveUserAccount, setUserPin, validateUserPin } from './src/auth.js';
import { getFeatureFlags } from './src/settings.js';
import { getVtHistory, saveVtHistory, vtDetectType, vtPollAnalysis, vtUrlId } from './src/vt.js';
import { importRecentKBLinks } from './src/kb.js';
import { buildSalesOverview, saveSalesNote, getSalesStaleDays } from './src/sales.js';

// ── 자료실(newsroom) 최근 업데이트 집계 — /analysis/latest·/team/digest 공용, 결정적·비용0 ──
async function buildArchiveUpdates(env, days = 7) {
  const cutoff = Date.now() - days * 86400000;
  const parseT = s => { const t = Date.parse(s || ''); return isNaN(t) ? 0 : t; };
  const readArr = async k => { try { const raw = await env.ENGR_KV.get(k); const a = raw ? JSON.parse(raw) : []; return Array.isArray(a) ? a : []; } catch (_) { return []; } };
  const out = [];
  const counts = { links: 0, knowledge: 0, eos: 0, compat: 0 };
  for (const it of await readArr('config:links')) {
    const created = parseT(it.createdAt), t = Math.max(created, parseT(it.updatedAt));
    if (t < cutoff) continue; counts.links++;
    out.push({ kind: 'link', icon: '🔗', label: '링크', title: String(it.title || it.url || '').slice(0, 90), when: t, by: it.updatedBy || it.createdBy || '', ai: !!it.aiSuggested, isNew: created >= cutoff });
  }
  for (const it of await readArr('config:knowledge')) {
    const created = parseT(it.createdAt), t = Math.max(created, parseT(it.updatedAt));
    if (t < cutoff) continue; counts.knowledge++;
    out.push({ kind: 'know', icon: '📘', label: '노하우', title: String(it.title || '').slice(0, 90), when: t, by: it.updatedBy || it.createdBy || '', isNew: created >= cutoff });
  }
  for (const it of await readArr('config:eos')) {
    const created = parseT(it.createdAt);
    if (created < cutoff) continue; counts.eos++;
    out.push({ kind: 'eos', icon: '📄', label: '라이선스', title: `${it.customer || ''} ${it.productDesc || it.product || ''}`.trim().slice(0, 90), when: created, by: it.createdBy || '', isNew: true });
  }
  try {
    const r = await env.DB.prepare("SELECT product, product_version, os, status, verified_by, verified_at, updated_at FROM compat_matrix").all();
    for (const row of (r.results || [])) {
      const vt = parseT(row.verified_at), t = Math.max(vt, parseT(row.updated_at));
      if (t < cutoff) continue;
      const confirmed = row.status === 'confirmed' && vt >= cutoff; counts.compat++;
      out.push({ kind: 'compat', icon: '🧩', label: confirmed ? '매트릭스 확정' : '매트릭스 초안', title: `${row.product || ''} ${row.product_version || ''}/${row.os || ''}`.trim().slice(0, 90), when: t, by: (confirmed ? row.verified_by : '') || '', isNew: !confirmed });
    }
  } catch (_) {}
  out.sort((a, b) => b.when - a.when);
  return { days, counts, items: out.slice(0, 8) };
}

// ── 다이제스트 데이터 집계 (텍스트/카드 공용) — 주 쿼리 실패 시 throw ──
async function buildDigestData(env) {
  const day = new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10);  // KST 오늘
  const dayMs = new Date(day + 'T00:00:00Z').getTime();
  const issues = await jiraSearchJql(env, `project = ENGR AND statusCategory != Done AND duedate <= "${day}" ORDER BY duedate ASC`, TEAM_FIELDS, 5);
  const custList = await getCustomersD1(env);
  const mapped = issues.map(it => mapJiraIssue(it, custList)).filter(i => !/hands[\s-]?on/i.test(i.summary || ''));
  const dueToday = [], overdue = [];
  for (const i of mapped) {
    const dd = (i.duedate || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dd)) continue;
    const cust = (i.cls && (i.cls.customer || i.cls.bracket)) || '';
    const row = { key: i.key, assignee: i.assignee || '-', customer: cust, summary: (i.summary || '').replace(/^\s*\[[^\]]*\]\s*/, ''), duedate: dd };
    if (dd === day) dueToday.push(row);
    else if (dd < day) { row.overdueDays = Math.round((dayMs - new Date(dd + 'T00:00:00Z').getTime()) / 86400000); overdue.push(row); }
  }
  let eosItems = [];
  try { const raw = await env.ENGR_KV.get('config:eos'); if (raw) eosItems = JSON.parse(raw); } catch (_) {}
  const licenseSoon = [];
  for (const e of (Array.isArray(eosItems) ? eosItems : [])) {
    const exp = (e.expireDate || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(exp)) continue;
    const dday = Math.ceil((new Date(exp + 'T00:00:00Z').getTime() - dayMs) / 86400000);
    if (dday >= 0 && dday <= 30) licenseSoon.push({ customer: e.customer || '', product: e.productDesc || e.product || '', dday, expireDate: exp });
  }
  licenseSoon.sort((a, b) => a.dday - b.dday);
  let metaIssues = [];
  try { metaIssues = await jiraSearchJql(env, `project = ENGR AND statusCategory != Done ORDER BY updated DESC`, [...TEAM_FIELDS, 'customfield_10036'], 5); } catch (_) {}
  const metaByA = {};
  for (const it of metaIssues) {
    const f = it.fields || {};
    if (/hands[\s-]?on/i.test(f.summary || '')) continue;
    const miss = [];
    if (!(Array.isArray(f.customfield_10134) && f.customfield_10134.length)) miss.push('고객사');
    if (!((f.labels || []).length)) miss.push('레이블');
    const cat = f.customfield_10036 && f.customfield_10036.value;
    if (!cat || cat === 'N/A') miss.push('범주');
    if (!f.duedate) miss.push('기한');
    if (!miss.length) continue;
    const a = (f.assignee && f.assignee.displayName) || '(미지정)';
    const g = metaByA[a] || (metaByA[a] = { count: 0, fields: {} });
    g.count++; miss.forEach(m => g.fields[m] = (g.fields[m] || 0) + 1);
  }
  const metaRows = Object.entries(metaByA).sort((a, b) => b[1].count - a[1].count).map(([assignee, v]) => ({ assignee, count: v.count, fields: v.fields }));
  const metaTotal = metaRows.reduce((s, r) => s + r.count, 0);
  let team = null;
  try { const ts = await env.DB.prepare("SELECT payload_json FROM analysis_snapshot WHERE kind='team' ORDER BY built_at DESC LIMIT 1").first(); if (ts) team = JSON.parse(ts.payload_json); } catch (_) {}
  let archive = null;
  try { archive = await buildArchiveUpdates(env, 7); } catch (_) {}
  const ydayMs = dayMs - 86400000;
  const yday = new Date(ydayMs).toISOString().slice(0, 10);
  let doneY = [];
  try {
    const di = await jiraSearchJql(env, `project = ENGR AND resolved >= "${yday}" AND resolved < "${day}" ORDER BY resolved DESC`, TEAM_FIELDS, 3);
    doneY = di.map(it => mapJiraIssue(it, custList)).filter(i => !/hands[\s-]?on/i.test(i.summary || '')).map(i => ({ key: i.key, assignee: i.assignee || '-', customer: (i.cls && (i.cls.customer || i.cls.bracket)) || '', summary: (i.summary || '').replace(/^\s*\[[^\]]*\]\s*/, '') }));
  } catch (_) {}
  const WD = ['일', '월', '화', '수', '목', '금', '토'];
  const dObj = new Date(day + 'T00:00:00Z');
  const dateLabel = `${dObj.getUTCMonth() + 1}/${dObj.getUTCDate()}(${WD[dObj.getUTCDay()]})`;
  const sents = (txt, n) => String(txt || '').split(/(?<=다\.)\s+/).map(s => s.trim()).filter(Boolean).slice(0, n);
  const mgmtTotal = dueToday.length + overdue.length + metaTotal + licenseSoon.length;
  const headline = team ? [...sents(team.monthly, 2), ...sents(team.patterns, 1)].filter(Boolean).slice(0, 3) : [];
  const patternLines = team ? sents(team.patterns, 3) : [];
  const archItems = (archive && archive.items) || [];
  return { day, dateLabel, dueToday, overdue, metaRows, metaTotal, licenseSoon, doneY, archItems, archiveDays: (archive && archive.days) || 7, headline, patternLines, mgmtTotal };
}

// ── 다이제스트 → Teams Adaptive Card (Power Automate flow가 GET해서 채널에 게시) ──
function buildDigestCard(D, hubUrl, notice) {
  const esc = s => String(s || '').replace(/\s+/g, ' ').trim();
  const tb = (text, opt) => Object.assign({ type: 'TextBlock', text, wrap: true }, opt || {});
  const clip = (s, n) => { const x = esc(s); return x.length > n ? x.slice(0, n - 1) + '…' : x; };
  const body = [];
  body.push({ type: 'Container', style: 'accent', bleed: true, items: [tb(`📰 보안기술팀 브리핑 — ${D.dateLabel}`, { weight: 'Bolder', size: 'Large' })] });
  if (notice && String(notice).trim()) {
    const nlines = String(notice).split('\n').map(x => x.trim()).filter(Boolean);
    const nitems = [tb('📢 공지사항', { weight: 'Bolder' })];
    nlines.forEach(ln => nitems.push(tb('• ' + esc(ln), { weight: 'Bolder', spacing: 'Small' })));
    body.push({ type: 'Container', style: 'warning', spacing: 'Small', items: nitems });
  }
  const empty = !D.mgmtTotal && !D.headline.length && !D.doneY.length;
  if (empty) {
    body.push({ type: 'Container', style: 'good', spacing: 'Medium', items: [tb('🎉 오늘은 관리 필요·신규 소식이 없습니다 — 깔끔한 하루 되세요!', { weight: 'Bolder', color: 'Good' })] });
  } else {
    body.push(tb(`⚡ 관리 필요 ${D.mgmtTotal}   ·   마감 ${D.dueToday.length}   ·   지연 ${D.overdue.length}   ·   미기입 ${D.metaTotal}   ·   만료임박 ${D.licenseSoon.length}`, { isSubtle: true, spacing: 'Small' }));
    const bullet = (it, t, opt) => it.push(tb('• ' + t, Object.assign({ spacing: 'Small' }, opt || {})));
    const section = (title, style, headColor, build) => { const it = [tb(title, { weight: 'Bolder', size: 'Medium', color: headColor || 'Accent' })]; build(it, bullet); body.push({ type: 'Container', style: style || 'emphasis', spacing: 'Medium', separator: true, items: it }); };
    const more = (it, n) => { if (n > 0) it.push(tb(`…외 ${n}건 → HUB에서`, { isSubtle: true, size: 'Small', spacing: 'Small' })); };
    if (D.headline.length) section('🗞 헤드라인', 'emphasis', 'Accent', (it, b) => D.headline.slice(0, 2).forEach(s => b(it, clip(s, 120))));
    if (D.doneY.length) section(`📌 어제의 성과 (완료 ${D.doneY.length}건)`, 'good', 'Good', (it, b) => { D.doneY.slice(0, 5).forEach(r => b(it, `**${r.assignee}**: ${r.customer ? '[' + r.customer + '] ' : ''}${clip(r.summary, 48)}`)); more(it, D.doneY.length - 5); });
    if (D.mgmtTotal) section('🚨 지금 관리 필요', 'attention', 'Attention', (it, b) => {
      if (D.dueToday.length) { it.push(tb(`⏰ 오늘 마감 ${D.dueToday.length}`, { weight: 'Bolder', spacing: 'Medium' })); D.dueToday.slice(0, 6).forEach(r => b(it, `${r.assignee}: ${r.customer ? '[' + r.customer + '] ' : ''}${clip(r.summary, 50)} (${r.key})`)); more(it, D.dueToday.length - 6); }
      if (D.overdue.length) { it.push(tb(`🔴 지연 ${D.overdue.length}`, { weight: 'Bolder', spacing: 'Medium' })); D.overdue.slice(0, 6).forEach(r => b(it, `${r.assignee}: ${r.customer ? '[' + r.customer + '] ' : ''}${clip(r.summary, 50)} (D+${r.overdueDays}, ${r.key})`)); more(it, D.overdue.length - 6); }
      if (D.metaTotal) { it.push(tb(`📝 메타 미기입 ${D.metaTotal}`, { weight: 'Bolder', spacing: 'Medium' })); D.metaRows.forEach(r => { const fs = Object.entries(r.fields).sort((a, b2) => b2[1] - a[1]).map(([k, n]) => `${k} ${n}`).join(' · '); b(it, `${r.assignee}: ${r.count}건 (${fs})`); }); }
      if (D.licenseSoon.length) { it.push(tb(`📄 라이선스 만료 임박 ${D.licenseSoon.length}`, { weight: 'Bolder', spacing: 'Medium' })); D.licenseSoon.slice(0, 6).forEach(r => b(it, `${r.customer} ${clip(r.product, 38)} — D-${r.dday}`)); more(it, D.licenseSoon.length - 6); }
    });
  }
  const base = String(hubUrl || 'https://engr-jira.github.io/engr-hub-dev/').replace(/\/+$/, '');
  const actions = [{ type: 'Action.OpenUrl', title: '🔗 HUB 열기', url: base + '/' }];
  if (D.mgmtTotal) actions.push({ type: 'Action.OpenUrl', title: '🚨 이슈 관리', url: base + '/?go=issues' });
  if (D.licenseSoon.length) actions.push({ type: 'Action.OpenUrl', title: '📄 라이선스', url: base + '/?go=eos' });
  actions.push({ type: 'Action.OpenUrl', title: '📚 자료실', url: base + '/?go=links' });
  return { type: 'AdaptiveCard', $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', version: '1.4', body, actions, msteams: { width: 'Full' } };
}

// ── 다이제스트 카드를 Teams 채널로 전송 (TEAMS_WEBHOOK_URL 시크릿 설정 시에만; MJ의 Power Automate 웹훅 flow가 수신·게시) ──
async function postDigestToTeams(env, hubUrl, notice) {
  if (!env.TEAMS_WEBHOOK_URL) return { ok: false, reason: 'no-webhook' };
  const D = await buildDigestData(env);
  const card = buildDigestCard(D, hubUrl || 'https://engr-jira.github.io/engr-hub-dev/', notice);
  const resp = await fetch(env.TEAMS_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: card }] })
  });
  return { ok: resp.ok, status: resp.status, day: D.day, mgmt: D.mgmtTotal };
}

// ══ 🧠 팀 퀴즈 헬퍼 (P1) ══
function quizWeekId(ms) { const d = new Date(ms); d.setUTCHours(0, 0, 0, 0); d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7)); const ys = new Date(Date.UTC(d.getUTCFullYear(), 0, 1)); const wn = Math.ceil(((d - ys) / 86400000 + 1) / 7); return d.getUTCFullYear() + '-W' + String(wn).padStart(2, '0'); }
function quizNorm(s) { return String(s == null ? '' : s).toLowerCase().replace(/[\s.,·\-_/()]+/g, ''); }
function gradeQuiz(q, userAns) {
  const ua = String(userAns == null ? '' : userAns).trim();
  if (!ua) return { score: 0 };
  if (q.type === 'mc' || q.type === 'ox') return { score: quizNorm(ua) === quizNorm(q.answer) ? 100 : 0 };
  const nu = quizNorm(ua);
  let accepts = []; try { accepts = JSON.parse(q.accepts || '[]'); } catch (_) {}
  if ([q.answer, ...accepts].filter(Boolean).some(t => quizNorm(t) === nu)) return { score: 100 };
  let kws = []; try { kws = JSON.parse(q.keywords || '[]'); } catch (_) {}
  if (kws.length) { const hit = kws.filter(k => k && nu.includes(quizNorm(k))).length; return { score: Math.round(hit / kws.length * 100), note: `키워드 ${hit}/${kws.length}` }; }
  const na = quizNorm(q.answer);
  return { score: (na && (nu.includes(na) || na.includes(nu))) ? 60 : 0 };
}
// 출제 확정 시 Teams 오픈 알림 카드 (+지난주 TOP3) — TEAMS_WEBHOOK_URL 설정 시에만
async function quizNotifyTeams(env, week, count, closesAt) {
  if (!env.TEAMS_WEBHOOK_URL) return;
  const tb = (text, opt) => Object.assign({ type: 'TextBlock', text, wrap: true }, opt || {});
  const body = [
    { type: 'Container', style: 'accent', bleed: true, items: [tb('🧠 이번 주 보안 퀴즈 오픈!', { weight: 'Bolder', size: 'Large' })] },
    tb(`${week} · ${count}문제 · 마감 ${new Date(closesAt + 9 * 3600e3).toISOString().slice(5, 10).replace('-', '/')} — 제출 즉시 채점·XP 지급! ⚡`, { spacing: 'Small' })
  ];
  try {
    const prevWeek = quizWeekId(Date.now() + 9 * 3600e3 - 7 * 86400000);
    const r = await env.DB.prepare("SELECT user, AVG(score) AS acc, SUM(xp) AS wxp FROM quiz_answer WHERE week=? GROUP BY user ORDER BY acc DESC LIMIT 3").bind(prevWeek).all();
    const tops = (r.results || []);
    if (tops.length) {
      const it = [tb('🏆 지난 주 TOP', { weight: 'Bolder', color: 'Good' })];
      tops.forEach((t, i) => it.push(tb(`${['🥇', '🥈', '🥉'][i]} ${t.user} — ${Math.round(t.acc)}점 · +${t.wxp || 0} XP`, { spacing: 'Small' })));
      body.push({ type: 'Container', style: 'good', spacing: 'Medium', items: it });
    }
  } catch (_) {}
  const card = { type: 'AdaptiveCard', $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', version: '1.4', body, actions: [{ type: 'Action.OpenUrl', title: '🚀 지금 도전하기', url: 'https://engr-jira.github.io/engr-hub-dev/?go=quiz' }], msteams: { width: 'Full' } };
  try { await fetch(env.TEAMS_WEBHOOK_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: card }] }) }); } catch (_) {}
}
async function quizEnsureTables(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS quiz_question (id INTEGER PRIMARY KEY AUTOINCREMENT, product TEXT, type TEXT, difficulty INTEGER DEFAULT 1, question TEXT, choices TEXT, answer TEXT, accepts TEXT, keywords TEXT, explanation TEXT, source TEXT, tags TEXT, status TEXT DEFAULT 'draft', created_by TEXT, created_at INTEGER, updated_at INTEGER)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS quiz_week (week TEXT PRIMARY KEY, question_ids TEXT, opens_at INTEGER, closes_at INTEGER, published_by TEXT, published_at INTEGER)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS quiz_answer (week TEXT, user TEXT, question_id INTEGER, answer TEXT, score REAL, graded_by TEXT, note TEXT, submitted_at INTEGER, PRIMARY KEY (week, user, question_id))").run();
  try { await env.DB.prepare('ALTER TABLE quiz_question ADD COLUMN credit TEXT').run(); } catch (_) {}
  try { await env.DB.prepare('ALTER TABLE quiz_answer ADD COLUMN xp INTEGER').run(); } catch (_) {}
}
// 게임화: 난이도별 XP(만점 기준 10/20/30, 부분점수 비례) · 레벨 티어 · 게임마스터 멘트(quiz_settings로 편집 가능)
const QUIZ_XP_BY_DIFF = { 1: 10, 2: 20, 3: 30 };
const QUIZ_DEFAULT_SETTINGS = {
  levels: [{ xp: 0, name: '🥉 새싹', }, { xp: 100, name: '🥈 견습' }, { xp: 300, name: '🥇 숙련' }, { xp: 700, name: '💎 마스터' }, { xp: 1500, name: '👑 전설' }],
  msgs: { perfect: '💯 퍼펙트! 오늘 최고의 플레이!', great: '🔥 대단해요! 거의 다 맞혔어요', good: '😎 좋아요! 조금만 더!', tryagain: '💪 아쉽! 해설 보고 다음 주에 설욕전', combo: '🔥 {n}연속 정답!' },
  intro: '🧠 이번 주 보안 퀴즈 — 실전에서 바로 쓰는 지식!',
  prize: '', teamGoal: 0, teamGoalPrize: ''
};
async function quizGetSettings(env) {
  try { const r = await env.DB.prepare("SELECT value FROM app_settings WHERE key='quiz_settings'").first(); if (r && r.value) return Object.assign({}, QUIZ_DEFAULT_SETTINGS, JSON.parse(r.value)); } catch (_) {}
  return QUIZ_DEFAULT_SETTINGS;
}
function quizLevelOf(xp, levels) { let cur = levels[0], next = null; for (const l of levels) { if (xp >= l.xp) cur = l; else { next = l; break; } } return { name: cur.name, next: next ? { name: next.name, need: next.xp - xp } : null }; }
function quizMsgFor(avg, msgs) { return avg >= 100 ? msgs.perfect : avg >= 80 ? msgs.great : avg >= 50 ? msgs.good : msgs.tryagain; }
async function quizBadges(env, user) {
  const badges = [];
  try {
    const rows = (await env.DB.prepare("SELECT a.week, a.score, q.product, q.difficulty FROM quiz_answer a LEFT JOIN quiz_question q ON q.id=a.question_id WHERE a.user=?").bind(user).all()).results || [];
    const byWeek = {}; rows.forEach(r => { (byWeek[r.week] = byWeek[r.week] || []).push(r); });
    const weeks = Object.keys(byWeek).sort();
    if (weeks.some(w => byWeek[w].length >= 5 && byWeek[w].every(r => r.score === 100))) badges.push('💯 퍼펙트 위크');
    // 제품 마스터: 해당 제품 10문제 이상 & 평균 90+
    const byProd = {}; rows.forEach(r => { if (!r.product) return; (byProd[r.product] = byProd[r.product] || []).push(r.score); });
    for (const [p, arr] of Object.entries(byProd)) { if (arr.length >= 10 && arr.reduce((s, x) => s + x, 0) / arr.length >= 90) badges.push(`🎯 ${p} 마스터`); }
    // 스트릭: 최근 주부터 역방향 연속 참여 주 수
    let streak = 0; if (weeks.length) { const now = Date.now(); for (let i = 0; ; i++) { const wid = quizWeekId(now + 9 * 3600e3 - i * 7 * 86400000); if (byWeek[wid]) streak++; else if (i === 0) continue; else break; if (i > 60) break; } }
    if (streak >= 3) badges.push(`🔥 ${streak}주 연속`);
    return { badges, streak };
  } catch (_) { return { badges, streak: 0 }; }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: getCorsHeaders(request) });

    const url = new URL(request.url);
    const path = url.pathname;
    const headerUser = normalizeUserId(decUser(request.headers.get('X-User') || ''));
    const sessionUser = await getSessionUser(env, request.headers.get('X-Session-Token') || '');
    const hasSession = !!sessionUser && (!headerUser || headerUser === sessionUser);
    const user = sessionUser || headerUser;

    // ── 영업 역할 화이트리스트 강제 (라우팅 이전) ──
    // 클라이언트에서 메뉴를 숨기는 것만으로는 API가 그대로 열리므로 서버에서 차단한다.
    if (hasSession && await isSalesRole(env, user)) {
      if (!salesPathAllowed(path, request.method)) {
        ctx.waitUntil(auditLog(env, user, 'SALES_DENY', { denyPath: path, denyMethod: request.method }));
        return corsResponse({ ok: false, message: '접근 권한이 없습니다.' }, 403);
      }
    }

    try {
      //
      // 고객사 정식명·별칭 (D1 customers) — 프론트 별칭 정규화용
      if (path === '/customers' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        let items = [];
        try {
          const r = await env.DB.prepare('SELECT name, aliases FROM customers WHERE active=1').all();
          items = (r.results || []).map(x => { let a = []; try { a = JSON.parse(x.aliases || '[]'); } catch (_) {} return { name: x.name, aliases: a }; });
        } catch (_) {}
        return corsResponse({ ok: true, items });
      }

      //
      

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
        return corsResponse({ sessionMin: parseInt(sessionRaw || '120') || 120, rangeMonths: parseInt(rangeRaw || '6') || 6, lastSync });
      }
      
      // 일반 유저용 개인 AI 사용량 (팀 통계 미포함)
      
      if (path === '/links/kb/import' && request.method === 'POST') {
        // 관리자 세션 또는 분석 토큰(초기 대량 수집·증분 트리거)
        const anaOkK = !!env.ANALYSIS_WRITE_TOKEN && (request.headers.get('x-analysis-token') || '') === env.ANALYSIS_WRITE_TOKEN;
        if (!anaOkK && (!hasSession || !await isAdmin(env, user))) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const years = Math.max(1, Math.min(10, parseInt(url.searchParams.get('years') || '5', 10) || 5));
        const limit = Math.max(1, Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10) || 20));
        const cursor = url.searchParams.get('cursor') || '';
        const provider = url.searchParams.get('provider') || '';
        return corsResponse(await importRecentKBLinks(env, user, years, { limit, cursor, provider }));
      }

      //
      // ── 스케줄 엔진용 Jira 첨부 프록시 (분석 토큰 인증) : 첨부 로그 분석의 통로 ──
      // 일반 /jira/ 봉인보다 먼저 매칭되어야 함. 5MB 상한(로그 텍스트 위주).
      if (path.startsWith('/jira/attach/') && request.method === 'GET') {
        const tok = request.headers.get('x-analysis-token') || '';
        if (!env.ANALYSIS_WRITE_TOKEN || tok !== env.ANALYSIS_WRITE_TOKEN) return corsResponse({ ok: false, message: '인증 실패' }, 401);
        const attId = path.split('/')[3] || '';
        if (!/^\d+$/.test(attId)) return corsResponse({ ok: false, message: '잘못된 첨부 ID' }, 400);
        const jiraAuth = 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN);
        const jr = await fetch(`https://escare-engr.atlassian.net/rest/api/3/attachment/content/${attId}`, { headers: { 'Authorization': jiraAuth } });
        if (!jr.ok) return corsResponse({ ok: false, message: '첨부 조회 실패 ' + jr.status }, 502);
        const buf = await jr.arrayBuffer();
        if (buf.byteLength > 30 * 1024 * 1024) return corsResponse({ ok: false, message: '30MB 초과 첨부는 분석 제외' }, 413);
        return new Response(buf, { status: 200, headers: { ...CORS_HEADERS, 'Content-Type': jr.headers.get('Content-Type') || 'application/octet-stream' } });
      }
      if (path.startsWith('/jira/')) {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const jiraPath = path.replace('/jira/', '');
        if (jiraPath === 'search' || jiraPath === 'search/jql') {
          return await handleJiraSearch(env, user);
        }
        // ── 프록시 봉인: 프론트가 실제로 쓰는 GET issue/{KEY} 만 허용 ──
        // (이전엔 전 메서드·임의 경로가 mj.park 인증으로 통과 → Jira 임의 읽기/쓰기 가능했음)
        if (request.method !== 'GET') {
          ctx.waitUntil(auditLog(env, user, 'JIRA_PROXY_DENY', { jiraPath, denyMethod: request.method }));
          return corsResponse({ ok: false, message: '허용되지 않은 메서드입니다.' }, 405);
        }
        if (!/^issue\/[A-Z][A-Z0-9]*-\d+$/.test(jiraPath)) {
          ctx.waitUntil(auditLog(env, user, 'JIRA_PROXY_DENY', { jiraPath, denyMethod: 'GET' }));
          return corsResponse({ ok: false, message: '허용되지 않은 경로입니다.' }, 403);
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
              : env.DB.prepare("SELECT ts,ts_num,user,type,detail_json FROM audit_log WHERE type != 'PAGE_VIEW' ORDER BY ts_num DESC LIMIT ?").bind(limit);
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
            if (!filter && item.type === 'PAGE_VIEW') continue;
            if (!filter || item.type === filter) logs.push(item);
          } catch (_) {}
        }
        return corsResponse(logs);
      }

      // ── 기능 사용 현황 집계(관리자) : D1 audit_log GROUP BY. 컷 판단용. 읽기전용 ──
      if (path === '/admin/usage/features' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        const days = Math.max(1, Math.min(365, parseInt(url.searchParams.get('days') || '90', 10) || 90));
        const since = Date.now() - days * 86400000;
        try {
          const byTypeQ = await env.DB.prepare("SELECT type, COUNT(*) AS cnt, MAX(ts_num) AS last, COUNT(DISTINCT user) AS uu FROM audit_log WHERE ts_num >= ? GROUP BY type").bind(since).all();
          const byPageQ = await env.DB.prepare("SELECT json_extract(detail_json,'$.page') AS page, COUNT(*) AS cnt, MAX(ts_num) AS last, COUNT(DISTINCT user) AS uu FROM audit_log WHERE type='PAGE_VIEW' AND ts_num >= ? GROUP BY page").bind(since).all();
          let coverageStart = null; try { const c = await env.DB.prepare("SELECT MIN(ts_num) AS first FROM audit_log").first(); coverageStart = (c && c.first) ? c.first : null; } catch (_) {}
          return corsResponse({
            ok: true, days, since, coverageStart,
            byType: (byTypeQ.results || []).map(r => ({ type: r.type, count: r.cnt, last: r.last, users: r.uu })),
            byPage: (byPageQ.results || []).filter(r => r.page).map(r => ({ page: r.page, count: r.cnt, last: r.last, users: r.uu }))
          });
        } catch (e) { return corsResponse({ ok: false, message: '집계 실패: ' + (e && e.message || e) }, 500); }
      }

      // ── 페이지 방문 비콘(로그인 사용자) : 열람형 기능 사용 측정. 세션당 페이지 1회(클라 스로틀). 감사 기본뷰에선 제외됨 ──
      if (path === '/usage/pageview' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false }, 401);
        const body = await request.json().catch(() => ({}));
        const ALLOWED = ['dash', 'issues', 'cases', 'customers', 'eos', 'log', 'vt', 'links', 'knowledge', 'audit', 'settings', 'mydesk', 'compat', 'nsis', 'monitor', 'sales'];
        const pv = ALLOWED.includes(body.page) ? body.page : null;
        if (!pv) return corsResponse({ ok: false }, 400);
        ctx.waitUntil(auditLog(env, user, 'PAGE_VIEW', { page: pv }));
        return corsResponse({ ok: true });
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
        const eosWarnDays = await env.ENGR_KV.get('config:eos_warn_days') || '60,30,7';
        const salesStaleDays = await getSalesStaleDays(env);
        return corsResponse({
          ok: true,
          rangeMonths: parseInt(rangeMonths),
          sessionMin: parseInt(sessionMin),
          eosWarnDays,
          salesStaleDays,
        });
      }
      if (path === '/admin/config' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        if (body.rangeMonths !== undefined) await env.ENGR_KV.put('config:range_months', String(body.rangeMonths));
        if (body.sessionMin !== undefined) await env.ENGR_KV.put('config:session_min', String(body.sessionMin));
        if (body.eosWarnDays !== undefined) await env.ENGR_KV.put('config:eos_warn_days', body.eosWarnDays);
        if (body.salesStaleDays !== undefined) await env.ENGR_KV.put('config:sales_stale_days', String(parseInt(body.salesStaleDays,10)||14));
        await auditLog(env, user, 'CONFIG_CHANGE', { keys: Object.keys(body) });
        return corsResponse({ ok: true });
      }

      //
      

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
        // 세션 또는 분석 토큰(엔진의 중복 URL 확인용)
        const anaOkL = !!env.ANALYSIS_WRITE_TOKEN && (request.headers.get('x-analysis-token') || '') === env.ANALYSIS_WRITE_TOKEN;
        if (!hasSession && !anaOkL) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const raw = await env.ENGR_KV.get('config:links');
        return corsResponse({ ok: true, links: raw ? JSON.parse(raw) : [] });
      }
      //
      if (path === '/links' && request.method === 'POST') {
        // 세션 또는 분석 토큰(엔진의 'AI 추천' 링크 — 강제 aiSuggested·중복 URL 거부)
        const anaOkL = !!env.ANALYSIS_WRITE_TOKEN && (request.headers.get('x-analysis-token') || '') === env.ANALYSIS_WRITE_TOKEN;
        if (!hasSession && !anaOkL) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const byEngine = anaOkL && !hasSession;
        const actorL = byEngine ? 'AI \uCD94\uCC9C(\uBD84\uC11D \uC5D4\uC9C4)' : user;
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        if (byEngine && links.some(l => (l.url || '').replace(/\/$/, '') === String(body.url || '').replace(/\/$/, ''))) {
          return corsResponse({ ok: false, message: '\uC774\uBBF8 \uB4F1\uB85D\uB41C URL' }, 409);
        }
        const newLink = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          title: body.title || '',
          url: body.url || '',
          category: body.category || '\uAE30\uD0C0',
          desc: body.desc || '',
          comments: [],
          createdBy: actorL,
          createdAt: new Date().toISOString(),
          ...(byEngine ? { aiSuggested: true } : {}),
        };
        links.push(newLink);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, actorL, 'LINK_ADD', { title: newLink.title, aiLink: byEngine ? 1 : 0 });
        ctx.waitUntil(pushNotify(env, 'link', actorL, { target: newLink.title || '제목 없음' }));
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
        // 세션 또는 분석 토큰(엔진의 diff 비교용 읽기)
        const anaOkC = !!env.ANALYSIS_WRITE_TOKEN && (request.headers.get('x-analysis-token') || '') === env.ANALYSIS_WRITE_TOKEN;
        if (!hasSession && !anaOkC) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        const q = (new URL(request.url).searchParams.get('q') || '').trim().toLowerCase();
        let rows = [];
        try { const r = await env.DB.prepare('SELECT * FROM compat_matrix ORDER BY product, product_version, os').all(); rows = r.results || []; } catch (_) {}
        if (q) rows = rows.filter(x => [x.product, x.product_version, x.os, x.os_version, x.note, x.supported].some(v => (v || '').toLowerCase().includes(q)));
        return corsResponse({ ok: true, items: rows });
      }
      if (path === '/compat' && request.method === 'POST') {
        // \uAD00\uB9AC\uC790 \uB610\uB294 \uBD84\uC11D \uD1A0\uD070(\uC5D4\uC9C4\uC758 \uCD08\uC548 \uB4F1\uB85D \uC804\uC6A9 \u2014 status\uB294 \uD56D\uC0C1 draft)
        const anaOkP = !!env.ANALYSIS_WRITE_TOKEN && (request.headers.get('x-analysis-token') || '') === env.ANALYSIS_WRITE_TOKEN;
        if (!anaOkP && (!hasSession || !await isAdmin(env, user))) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);  // L-11
        const b = await request.json().catch(() => ({}));
        const now = new Date().toISOString();
        try {
          const r = await env.DB.prepare('INSERT INTO compat_matrix (product,product_version,os,os_version,supported,eos_date,eol_date,note,source,status,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.product || '', b.product_version || '', b.os || '', b.os_version || '', b.supported || '', b.eos_date || '', b.eol_date || '', b.note || '', b.source || '', 'draft', now).run();
          const actorC = (anaOkP && !hasSession) ? 'analysis-engine' : user;
          await auditLog(env, actorC, 'MATRIX_ADD', { matrixType: 'compat', product: b.product || '', os: b.os || '', aiDraft: (anaOkP && !hasSession) ? 1 : 0 });
          if (anaOkP && !hasSession) ctx.waitUntil(pushNotify(env, 'compat', actorC, { target: `${b.product || ''} ${b.product_version || ''}`.trim() || '\uB9E4\uD2B8\uB9AD\uC2A4' }));
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

      // ── A안: 팀 데일리 다이제스트 생성 (mj.park 전용, 조회 전용·외부발송 없음) ──
      if (path === '/team/digest' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        if (!(await getFeatureFlags(env)).digest) return corsResponse({ ok: false, message: '비활성화된 기능입니다.' }, 403);
        if (!await isMonitorAllowed(env, user)) { await auditLog(env, user, 'DIGEST_GEN', { digDate: '', denied: true }); return corsResponse({ ok: false, message: '접근 권한이 없습니다(팀 모니터 허용목록).' }, 403); }
        let D; try { D = await buildDigestData(env); } catch (e) { return corsResponse({ ok: false, message: 'Jira 조회 실패: ' + e.message }, 502); }
        const { day, dateLabel, dueToday, overdue, metaRows, metaTotal, licenseSoon, doneY, archItems, archiveDays, headline, patternLines, mgmtTotal } = D;
        const esc = s => String(s || '').replace(/\s+/g, ' ').trim();
        const empty = !mgmtTotal && !headline.length && !doneY.length;
        const lines = [`📰 보안기술팀 브리핑 — ${dateLabel}`];
        if (empty) {
          lines.push('', '🎉 오늘은 관리 필요·신규 소식이 없습니다 — 깔끔한 하루 되세요!');
        } else {
          lines.push(`⚡ 관리 필요 ${mgmtTotal} — 마감 ${dueToday.length} · 지연 ${overdue.length} · 미기입 ${metaTotal} · 만료임박 ${licenseSoon.length}`);
          if (headline.length) { lines.push('', '🗞 헤드라인'); headline.forEach(s => lines.push(`· ${esc(s)}`)); }
          if (doneY.length) { lines.push('', `📌 어제의 성과 (완료 ${doneY.length}건)`); doneY.slice(0, 8).forEach(r => lines.push(`· ${r.assignee}: ${r.customer ? '[' + r.customer + '] ' : ''}${esc(r.summary)} (${r.key})`)); if (doneY.length > 8) lines.push(`· …외 ${doneY.length - 8}건`); }
          if (mgmtTotal) {
            lines.push('', '🚨 지금 관리 필요');
            if (dueToday.length) { lines.push(`⏰ 오늘 마감 (${dueToday.length}건)`); dueToday.forEach(r => lines.push(`· ${r.assignee}: ${r.customer ? '[' + r.customer + '] ' : ''}${esc(r.summary)} (${r.key})`)); }
            if (overdue.length) { lines.push(`🔴 지연 중 (${overdue.length}건)`); overdue.forEach(r => lines.push(`· ${r.assignee}: ${r.customer ? '[' + r.customer + '] ' : ''}${esc(r.summary)} (D+${r.overdueDays}, ${r.key})`)); }
            if (metaTotal) { lines.push(`📝 메타 미기입 (${metaTotal}건)`); metaRows.forEach(r => { const fs = Object.entries(r.fields).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} ${n}`).join(' · '); lines.push(`· ${r.assignee}: ${r.count}건 (${fs})`); }); }
            if (licenseSoon.length) { lines.push(`📄 라이선스 만료 임박 (${licenseSoon.length}건)`); licenseSoon.forEach(r => lines.push(`· ${r.customer} ${esc(r.product)} — D-${r.dday} (${r.expireDate})`)); }
          }
        }
        lines.push('', '🔗 HUB에서 전체 보기 → {HUB_URL}');
        const text = lines.join('\n');
        await auditLog(env, user, 'DIGEST_GEN', { digDate: day, digCounts: { due: dueToday.length, overdue: overdue.length, meta: metaTotal, lic: licenseSoon.length, arch: archItems.length, hl: headline.length, rec: doneY.length } });
        return corsResponse({ ok: true, date: day, sections: { dueToday, overdue, metaIncomplete: metaRows, licenseSoon, archive: archItems, headline, patterns: patternLines, doneYesterday: doneY }, text });
      }

      // ── 다이제스트 Adaptive Card (x-analysis-token 게이트) — Power Automate flow가 GET해 채널에 게시. 워커는 외부 발송 없음, 카드 JSON만 서빙 ──
      if (path === '/team/digest/card' && request.method === 'GET') {
        const tok = request.headers.get('x-analysis-token') || '';
        if (!env.ANALYSIS_WRITE_TOKEN || tok !== env.ANALYSIS_WRITE_TOKEN) return corsResponse({ ok: false, message: '인증 실패' }, 401);
        if (!(await getFeatureFlags(env)).digest) return corsResponse({ ok: false, message: '비활성화된 기능입니다.' }, 403);
        const hubUrl = url.searchParams.get('hub') || 'https://engr-jira.github.io/engr-hub-dev/';
        let D; try { D = await buildDigestData(env); } catch (e) { return corsResponse({ ok: false, message: 'Jira 조회 실패: ' + e.message }, 502); }
        const card = buildDigestCard(D, hubUrl, url.searchParams.get('notice') || '');
        await auditLog(env, 'teams-flow', 'DIGEST_GEN', { digDate: D.day, via: 'card', mgmt: D.mgmtTotal });
        // ?raw=1 → 카드 JSON만 그대로 반환 (Power Automate '적응형 카드 게시'에 body 통째로 매핑 가능)
        if (url.searchParams.get('raw') === '1') return corsResponse(card);
        return corsResponse({ ok: true, card, attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: card }] });
      }

      // ── 다이제스트를 Teams 채널로 즉시 전송 (수동/테스트, x-analysis-token 게이트) ──
      if (path === '/team/digest/push' && request.method === 'POST') {
        const tok = request.headers.get('x-analysis-token') || '';
        const viaToken = env.ANALYSIS_WRITE_TOKEN && tok === env.ANALYSIS_WRITE_TOKEN;
        const viaSession = hasSession && await isMonitorAllowed(env, user);  // mj.park 수동 발사(모달 버튼)
        if (!viaToken && !viaSession) return corsResponse({ ok: false, message: '권한이 없습니다(mj.park 또는 분석 토큰).' }, 401);
        if (!(await getFeatureFlags(env)).digest) return corsResponse({ ok: false, message: '비활성화된 기능입니다.' }, 403);
        if (!env.TEAMS_WEBHOOK_URL) return corsResponse({ ok: false, message: 'Teams 웹훅이 설정되지 않았습니다.' }, 400);
        const pushBody = await request.json().catch(() => ({}));
        const notice = (pushBody && typeof pushBody.notice === 'string') ? pushBody.notice.slice(0, 500) : '';
        const hubUrl = url.searchParams.get('hub') || 'https://engr-jira.github.io/engr-hub-dev/';
        let r; try { r = await postDigestToTeams(env, hubUrl, notice); } catch (e) { return corsResponse({ ok: false, message: '전송 실패: ' + e.message }, 502); }
        await auditLog(env, viaSession ? user : 'teams-flow', 'DIGEST_GEN', { via: 'teams-manual', status: r.status, digDate: r.day });
        return corsResponse({ ok: r.ok, status: r.status, day: r.day });
      }

      // ══ 🧠 팀 퀴즈 (P1) — 문제은행·주간출제(관리자) / 응시·채점·순위(세션) ══
      if (path === '/quiz/questions' && request.method === 'GET') {
        const qTok = request.headers.get('x-analysis-token') || '';
        const qViaEngine = env.ANALYSIS_WRITE_TOKEN && qTok === env.ANALYSIS_WRITE_TOKEN;   // 분석 엔진(초안 중복·수량 확인용)
        if (!qViaEngine && (!hasSession || !await isAdmin(env, user))) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        await quizEnsureTables(env);
        const prod = url.searchParams.get('product') || '', st = url.searchParams.get('status') || '';
        let sql = 'SELECT * FROM quiz_question', cond = [], bind = [];
        if (prod) { cond.push('product=?'); bind.push(prod); }
        if (st) { cond.push('status=?'); bind.push(st); }
        if (cond.length) sql += ' WHERE ' + cond.join(' AND ');
        sql += ' ORDER BY (status=\'approved\') DESC, updated_at DESC LIMIT 500';
        const r = await env.DB.prepare(sql).bind(...bind).all();
        return corsResponse({ ok: true, items: (r.results || []) });
      }
      if (path === '/quiz/question' && (request.method === 'POST' || request.method === 'PUT')) {
        const qTok = request.headers.get('x-analysis-token') || '';
        const qViaEngine = request.method === 'POST' && env.ANALYSIS_WRITE_TOKEN && qTok === env.ANALYSIS_WRITE_TOKEN;   // 엔진 자동 초안(POST만, 수정 불가)
        if (!qViaEngine && (!hasSession || !await isAdmin(env, user))) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        await quizEnsureTables(env);
        const b = await request.json().catch(() => ({}));
        if (qViaEngine) {
          b.status = 'draft';   // 엔진 초안은 무조건 초안 — 승인은 관리자만
          const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM quiz_question WHERE status='draft' AND created_by='engine'").first();
          if (Number(cnt && cnt.n) >= 30) return corsResponse({ ok: false, message: '엔진 초안 상한(30) 도달 — 관리자 검토 후 재적재' }, 429);
        }
        const now = Date.now();
        const F = { product: String(b.product || '').slice(0, 20), type: ['mc', 'ox', 'short'].includes(b.type) ? b.type : 'mc', difficulty: Math.max(1, Math.min(3, parseInt(b.difficulty) || 1)), question: String(b.question || '').slice(0, 2000), choices: JSON.stringify(Array.isArray(b.choices) ? b.choices.slice(0, 8) : []), answer: String(b.answer || '').slice(0, 500), accepts: JSON.stringify(Array.isArray(b.accepts) ? b.accepts.slice(0, 20) : []), keywords: JSON.stringify(Array.isArray(b.keywords) ? b.keywords.slice(0, 20) : []), explanation: String(b.explanation || '').slice(0, 3000), source: String(b.source || '').slice(0, 300), tags: String(b.tags || '').slice(0, 200), status: ['draft', 'approved', 'archived'].includes(b.status) ? b.status : 'draft', credit: String(b.credit || '').slice(0, 60) };
        if (request.method === 'PUT' && b.id) {
          await env.DB.prepare("UPDATE quiz_question SET product=?,type=?,difficulty=?,question=?,choices=?,answer=?,accepts=?,keywords=?,explanation=?,source=?,tags=?,status=?,credit=?,updated_at=? WHERE id=?").bind(F.product, F.type, F.difficulty, F.question, F.choices, F.answer, F.accepts, F.keywords, F.explanation, F.source, F.tags, F.status, F.credit, now, parseInt(b.id)).run();
          await auditLog(env, user, 'QUIZ_Q', { quizAct: 'update', qid: parseInt(b.id) });
          return corsResponse({ ok: true, id: parseInt(b.id) });
        }
        const ins = await env.DB.prepare("INSERT INTO quiz_question (product,type,difficulty,question,choices,answer,accepts,keywords,explanation,source,tags,status,credit,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(F.product, F.type, F.difficulty, F.question, F.choices, F.answer, F.accepts, F.keywords, F.explanation, F.source, F.tags, F.status, F.credit, qViaEngine ? 'engine' : user, now, now).run();
        await auditLog(env, qViaEngine ? 'analysis-agent' : user, 'QUIZ_Q', { quizAct: qViaEngine ? 'engine-draft' : 'create' });
        return corsResponse({ ok: true, id: ins.meta && ins.meta.last_row_id });
      }
      if (path === '/quiz/question' && request.method === 'DELETE') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        await quizEnsureTables(env);
        const id = parseInt(url.searchParams.get('id') || '0'); if (!id) return corsResponse({ ok: false, message: 'id 필요' }, 400);
        await env.DB.prepare('DELETE FROM quiz_question WHERE id=?').bind(id).run();
        await auditLog(env, user, 'QUIZ_Q', { quizAct: 'delete', qid: id });
        return corsResponse({ ok: true });
      }
      if (path === '/quiz/suggest' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        await quizEnsureTables(env);
        const n = Math.max(1, Math.min(20, parseInt(url.searchParams.get('n') || '10')));
        const prod = url.searchParams.get('product') || '';
        const r = await env.DB.prepare(`SELECT * FROM quiz_question WHERE status='approved'${prod ? ' AND product=?' : ''} ORDER BY RANDOM() LIMIT ?`).bind(...(prod ? [prod, n] : [n])).all();
        return corsResponse({ ok: true, items: (r.results || []) });
      }
      if (path === '/quiz/week' && request.method === 'PUT') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        await quizEnsureTables(env);
        const b = await request.json().catch(() => ({}));
        const week = String(b.week || quizWeekId(Date.now() + 9 * 3600e3)).slice(0, 10);
        const ids = (Array.isArray(b.question_ids) ? b.question_ids : []).map(x => parseInt(x)).filter(Boolean).slice(0, 20);
        const opens = Number(b.opens_at) || Date.now();
        const closes = Number(b.closes_at) || (opens + 7 * 86400000);
        await env.DB.prepare("INSERT OR REPLACE INTO quiz_week (week,question_ids,opens_at,closes_at,published_by,published_at) VALUES (?,?,?,?,?,?)").bind(week, JSON.stringify(ids), opens, closes, user, Date.now()).run();
        await auditLog(env, user, 'QUIZ_WEEK', { week, n: ids.length });
        try { ctx.waitUntil(quizNotifyTeams(env, week, ids.length, closes)); } catch (_) {}
        return corsResponse({ ok: true, week, count: ids.length });
      }
      if (path === '/quiz/current' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        await quizEnsureTables(env);
        const now = Date.now();
        const w = await env.DB.prepare("SELECT * FROM quiz_week WHERE opens_at<=? AND closes_at>=? ORDER BY opens_at DESC LIMIT 1").bind(now, now).first();
        if (!w) {
          const S0 = await quizGetSettings(env);
          let x0 = 0; try { const x = await env.DB.prepare("SELECT SUM(xp) AS s FROM quiz_answer WHERE user=?").bind(user).first(); x0 = Number(x && x.s) || 0; } catch (_) {}
          const bd0 = await quizBadges(env, user);
          return corsResponse({ ok: true, week: null, intro: S0.intro, prize: S0.prize, levels: S0.levels, me: { xp: x0, level: quizLevelOf(x0, S0.levels), badges: bd0.badges, streak: bd0.streak } });
        }
        let ids = []; try { ids = JSON.parse(w.question_ids || '[]'); } catch (_) {}
        let questions = [];
        if (ids.length) { const r = await env.DB.prepare(`SELECT id,product,type,difficulty,question,choices FROM quiz_question WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids).all(); const map = {}; (r.results || []).forEach(q => map[q.id] = q); questions = ids.map(id => map[id]).filter(Boolean); }
        const mine = await env.DB.prepare("SELECT question_id,answer,score FROM quiz_answer WHERE week=? AND user=?").bind(w.week, user).all();
        const S = await quizGetSettings(env);
        let myXp = 0; try { const x = await env.DB.prepare("SELECT SUM(xp) AS s FROM quiz_answer WHERE user=?").bind(user).first(); myXp = Number(x && x.s) || 0; } catch (_) {}
        const bd = await quizBadges(env, user);
        return corsResponse({ ok: true, week: w.week, opens_at: w.opens_at, closes_at: w.closes_at, questions, submitted: (mine.results || []).length > 0, myAnswers: (mine.results || []), intro: S.intro, prize: S.prize, levels: S.levels, me: { xp: myXp, level: quizLevelOf(myXp, S.levels), badges: bd.badges, streak: bd.streak } });
      }
      if (path === '/quiz/submit' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        await quizEnsureTables(env);
        const b = await request.json().catch(() => ({}));
        const now = Date.now();
        const w = await env.DB.prepare("SELECT * FROM quiz_week WHERE week=?").bind(String(b.week || '')).first();
        if (!w) return corsResponse({ ok: false, message: '퀴즈 주차를 찾을 수 없습니다.' }, 404);
        if (now < w.opens_at || now > w.closes_at) return corsResponse({ ok: false, message: '응시 기간이 아닙니다.' }, 400);
        let ids = []; try { ids = JSON.parse(w.question_ids || '[]'); } catch (_) {}
        if (!ids.length) return corsResponse({ ok: false, message: '문제가 없습니다.' }, 400);
        const qr = await env.DB.prepare(`SELECT * FROM quiz_question WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids).all();
        const qmap = {}; (qr.results || []).forEach(q => qmap[q.id] = q);
        const answers = b.answers || {};
        const S = await quizGetSettings(env);
        let total = 0, n = 0, xpSum = 0, combo = 0, maxCombo = 0;
        const results = [];
        for (const id of ids) {
          const q = qmap[id]; if (!q) continue;
          const ua = (answers[id] !== undefined) ? answers[id] : answers[String(id)];
          const g = gradeQuiz(q, ua);
          const xp = Math.round((QUIZ_XP_BY_DIFF[q.difficulty] || 10) * g.score / 100);
          total += g.score; n++; xpSum += xp;
          if (g.score === 100) { combo++; if (combo > maxCombo) maxCombo = combo; } else combo = 0;
          results.push({ id, score: g.score, xp, note: g.note || '', answer: q.answer, explanation: q.explanation || '', source: q.source || '', credit: q.credit || '' });
          await env.DB.prepare("INSERT INTO quiz_answer (week,user,question_id,answer,score,graded_by,note,submitted_at,xp) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(week,user,question_id) DO UPDATE SET answer=excluded.answer,score=excluded.score,graded_by=excluded.graded_by,note=excluded.note,submitted_at=excluded.submitted_at,xp=excluded.xp").bind(w.week, user, id, String(ua == null ? '' : ua).slice(0, 1000), g.score, 'auto', String(g.note || '').slice(0, 80), now, xp).run();
        }
        const avg = n ? Math.round(total / n) : 0;
        // 누적 XP·레벨·뱃지 (즉시 피드백용)
        let myXp = 0; try { const x = await env.DB.prepare("SELECT SUM(xp) AS s FROM quiz_answer WHERE user=?").bind(user).first(); myXp = Number(x && x.s) || 0; } catch (_) {}
        const level = quizLevelOf(myXp, S.levels);
        const bd = await quizBadges(env, user);
        await auditLog(env, user, 'QUIZ_SUBMIT', { week: w.week, score: avg, quizXp: xpSum });
        return corsResponse({ ok: true, week: w.week, avg, answered: n, results, xpGained: xpSum, totalXp: myXp, level, maxCombo, comboMsg: maxCombo >= 2 ? String(S.msgs.combo || '').replace('{n}', maxCombo) : '', msg: quizMsgFor(avg, S.msgs), badges: bd.badges, streak: bd.streak });
      }
      if (path === '/quiz/me' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        await quizEnsureTables(env);
        const week = String(url.searchParams.get('week') || '');
        const w = await env.DB.prepare("SELECT * FROM quiz_week WHERE week=?").bind(week).first();
        if (!w) return corsResponse({ ok: true, week: null });
        const closed = Date.now() > w.closes_at;
        const mine = await env.DB.prepare("SELECT question_id,answer,score,note FROM quiz_answer WHERE week=? AND user=?").bind(week, user).all();
        let review = null;
        if (closed) { let ids = []; try { ids = JSON.parse(w.question_ids || '[]'); } catch (_) {} if (ids.length) { const r = await env.DB.prepare(`SELECT id,question,type,choices,answer,explanation,source FROM quiz_question WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids).all(); review = (r.results || []); } }
        return corsResponse({ ok: true, week, closed, myAnswers: (mine.results || []), review });
      }
      if (path === '/quiz/leaderboard' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        await quizEnsureTables(env);
        const scope = url.searchParams.get('scope') || 'week';
        if (scope === 'month') {
          const kst = new Date(Date.now() + 9 * 3600e3); const ms = Date.UTC(kst.getUTCFullYear(), kst.getUTCMonth(), 1) - 9 * 3600e3; const me = Date.UTC(kst.getUTCFullYear(), kst.getUTCMonth() + 1, 1) - 9 * 3600e3;
          const r = await env.DB.prepare("SELECT user, AVG(score) AS acc, COUNT(*) AS answered, COUNT(DISTINCT week) AS weeks FROM quiz_answer WHERE submitted_at>=? AND submitted_at<? GROUP BY user").bind(ms, me).all();
          return corsResponse({ ok: true, scope: 'month', rows: (r.results || []) });
        }
        const week = String(url.searchParams.get('week') || quizWeekId(Date.now() + 9 * 3600e3));
        const w = await env.DB.prepare("SELECT * FROM quiz_week WHERE week=?").bind(week).first();
        let totalQ = 0; if (w) { try { totalQ = JSON.parse(w.question_ids || '[]').length; } catch (_) {} }
        const r = await env.DB.prepare("SELECT user, AVG(score) AS acc, COUNT(*) AS answered, SUM(xp) AS wxp, MAX(submitted_at) AS last FROM quiz_answer WHERE week=? GROUP BY user").bind(week).all();
        // 누적 XP·레벨(성장 축) + 이달 팀 목표 진행률(협동 축)
        const S = await quizGetSettings(env);
        const xr = await env.DB.prepare("SELECT user, SUM(xp) AS xp FROM quiz_answer GROUP BY user ORDER BY xp DESC").all();
        const xpRows = (xr.results || []).map(x => ({ user: x.user, xp: Number(x.xp) || 0, level: quizLevelOf(Number(x.xp) || 0, S.levels).name }));
        let teamGoal = null;
        if (S.teamGoal > 0) {
          const kst = new Date(Date.now() + 9 * 3600e3); const ms = Date.UTC(kst.getUTCFullYear(), kst.getUTCMonth(), 1) - 9 * 3600e3; const me2 = Date.UTC(kst.getUTCFullYear(), kst.getUTCMonth() + 1, 1) - 9 * 3600e3;
          const t = await env.DB.prepare("SELECT AVG(score) AS acc FROM quiz_answer WHERE submitted_at>=? AND submitted_at<?").bind(ms, me2).first();
          teamGoal = { goal: S.teamGoal, current: Math.round(Number(t && t.acc) || 0), prize: S.teamGoalPrize || '' };
        }
        return corsResponse({ ok: true, scope: 'week', week, totalQ, rows: (r.results || []), xpRows, teamGoal });
      }
      if (path === '/quiz/settings' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        return corsResponse({ ok: true, settings: await quizGetSettings(env) });
      }
      if (path === '/quiz/settings' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        const b = await request.json().catch(() => ({}));
        const cur = await quizGetSettings(env);
        const next = Object.assign({}, cur, b.settings || {});
        try { await env.DB.prepare("INSERT INTO app_settings (key,value) VALUES ('quiz_settings',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(JSON.stringify(next)).run(); } catch (_) {}
        await auditLog(env, user, 'QUIZ_SET', { keys: Object.keys(b.settings || {}).join(',').slice(0, 100) });
        return corsResponse({ ok: true, settings: next });
      }

      // \u2500\u2500 \uC2A4\uCF00\uC904 \uBD84\uC11D \uC5D4\uC9C4(B\uC548) \uACB0\uACFC \uC800\uC7A5/\uC870\uD68C : Claude \uC5D0\uC774\uC804\uD2B8\uAC00 \uC4F0\uACE0 \uD300\uC6D0\uC740 \uBDF0\uB9CC \u2500\u2500
      if (path === '/analysis' && request.method === 'PUT') {
        const tok = request.headers.get('x-analysis-token') || '';
        if (!env.ANALYSIS_WRITE_TOKEN || tok !== env.ANALYSIS_WRITE_TOKEN) return corsResponse({ ok: false, message: '\uC778\uC99D \uC2E4\uD328' }, 401);
        const body = await request.json().catch(() => null);
        if (!body || !body.built_at || !body.day) return corsResponse({ ok: false, message: 'built_at/day \uD544\uC694' }, 400);
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS analysis_snapshot (kind TEXT NOT NULL, built_at INTEGER NOT NULL, day TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY (kind, built_at))").run();
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS issue_analysis (issue_key TEXT NOT NULL, built_at INTEGER NOT NULL, day TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY (issue_key, built_at))").run();
          const builtAt = Number(body.built_at); const day = String(body.day).slice(0, 10);
          let issueN = 0;
          if (body.team) {
            await env.DB.prepare("INSERT OR REPLACE INTO analysis_snapshot (kind, built_at, day, payload_json) VALUES ('team', ?, ?, ?)").bind(builtAt, day, JSON.stringify(body.team)).run();
          }
          for (const it of (Array.isArray(body.issues) ? body.issues : [])) {
            if (!it || !/^[A-Z][A-Z0-9]*-\d+$/.test(it.key || '') || !it.payload) continue;
            await env.DB.prepare("INSERT OR REPLACE INTO issue_analysis (issue_key, built_at, day, payload_json) VALUES (?, ?, ?, ?)").bind(it.key, builtAt, day, JSON.stringify(it.payload)).run();
            issueN++;
          }
          // \uB2F4\uB2F9\uC790 \uC751\uB2F5 \uC9C0\uD45C (\uCF54\uBA58\uD2B8 \uAE30\uBC18, \uC2A4\uCF00\uC904 \uC5D4\uC9C4\uC774 \uACC4\uC0B0\uD574 \uC804\uB2EC)
          try {
            if (Array.isArray(body.resp) && body.resp.length) {
              await env.DB.prepare("CREATE TABLE IF NOT EXISTS issue_resp (issue_key TEXT PRIMARY KEY, assignee TEXT, is_case INTEGER, first_resp REAL, avg_resp REAL, last_comment REAL, comments INTEGER, computed_at INTEGER)").run();
              // 케이스 회신 주체 컬럼 (구 테이블 호환 — 이미 있으면 에러 무시)
              try { await env.DB.prepare('ALTER TABLE issue_resp ADD COLUMN last_comm REAL').run(); } catch (_) {}
              try { await env.DB.prepare('ALTER TABLE issue_resp ADD COLUMN ball TEXT').run(); } catch (_) {}
              try { await env.DB.prepare('ALTER TABLE issue_resp ADD COLUMN ball_note TEXT').run(); } catch (_) {}
              try { await env.DB.prepare('ALTER TABLE issue_resp ADD COLUMN is_open INTEGER').run(); } catch (_) {}
              for (const r of body.resp) {
                if (!r || !/^[A-Z][A-Z0-9]*-\d+$/.test(r.key || '')) continue;
                await env.DB.prepare('INSERT INTO issue_resp (issue_key, assignee, is_case, first_resp, avg_resp, last_comment, comments, computed_at, last_comm, ball, ball_note, is_open) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(issue_key) DO UPDATE SET assignee=excluded.assignee, is_case=excluded.is_case, first_resp=excluded.first_resp, avg_resp=excluded.avg_resp, last_comment=excluded.last_comment, comments=excluded.comments, computed_at=excluded.computed_at, last_comm=excluded.last_comm, ball=excluded.ball, ball_note=excluded.ball_note, is_open=excluded.is_open')
                  .bind(r.key, String(r.assignee || ''), r.isCase ? 1 : 0, r.firstRespDays ?? null, r.avgRespDays ?? null, r.lastCommentDays ?? null, Number(r.comments) || 0, builtAt, r.lastCommDays ?? null, String(r.ball || ''), String(r.ballNote || '').slice(0, 160), r.isOpen ? 1 : 0).run();
              }
            }
          } catch (_) {}
          const cutoff = Date.now() - 180 * 86400000;   // \uBCF4\uC874 180\uC77C
          try { await env.DB.prepare('DELETE FROM issue_analysis WHERE built_at < ?').bind(cutoff).run(); await env.DB.prepare('DELETE FROM analysis_snapshot WHERE built_at < ?').bind(cutoff).run(); } catch (_) {}
          try {
            await env.DB.prepare("CREATE TABLE IF NOT EXISTS analysis_request (issue_key TEXT PRIMARY KEY, requested_at INTEGER, requested_by TEXT)").run();
            for (const it of (Array.isArray(body.issues) ? body.issues : [])) { if (it && it.key) await env.DB.prepare('DELETE FROM analysis_request WHERE issue_key = ?').bind(it.key).run(); }
          } catch (_) {}
          // 실제 마지막 분석(증분) 실행 시각 기록 — team 갱신이 없어도 매 PUT마다
          try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)").run(); await env.DB.prepare("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('analysis_last_run', ?)").bind(String(builtAt)).run(); } catch (_) {}
          await auditLog(env, 'analysis-agent', 'ANALYSIS_RUN', { issues: issueN, hasTeam: !!body.team, day });
          return corsResponse({ ok: true, issues: issueN, team: !!body.team });
        } catch (e) {
          await auditLog(env, 'analysis-agent', 'ANALYSIS_FAIL', { message: String(e && e.message || e).slice(0, 200) });
          return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328: ' + (e && e.message || e) }, 500);
        }
      }
      if (path === '/analysis/latest' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        let team = null, builtAt = null, keys = [];
        try {
          const t = await env.DB.prepare("SELECT built_at, day, payload_json FROM analysis_snapshot WHERE kind='team' ORDER BY built_at DESC LIMIT 1").first();
          if (t) { team = JSON.parse(t.payload_json); builtAt = t.built_at; }
          const last = await env.DB.prepare('SELECT MAX(built_at) AS b FROM issue_analysis').first();
          if (last && last.b) {
            // 증분 분석 지원: 최신 배치만이 아니라 최근 14일 내 분석 이력이 있는 전체 키 반환
            const r = await env.DB.prepare('SELECT DISTINCT issue_key FROM issue_analysis WHERE built_at >= ?').bind(Date.now() - 14 * 86400000).all();
            keys = (r.results || []).map(x => x.issue_key);
            if (!builtAt) builtAt = last.b;
          }
        } catch (_) {}
        let archive = null;
        try { archive = await buildArchiveUpdates(env, 7); } catch (_) {}
        let lastRun = null;
        try { const lr = await env.DB.prepare("SELECT value FROM app_settings WHERE key='analysis_last_run'").first(); if (lr && lr.value) lastRun = Number(lr.value); } catch (_) {}
        return corsResponse({ ok: true, built_at: builtAt, last_run: lastRun, team, issueKeys: keys, archive });
      }
      if (path === '/analysis/resp' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        let items = [];
        try { const r = await env.DB.prepare('SELECT issue_key AS key, assignee, is_case, first_resp, avg_resp, last_comment, comments, computed_at, last_comm, ball, ball_note, is_open FROM issue_resp WHERE computed_at >= ?').bind(Date.now() - 30 * 86400000).all(); items = r.results || []; } catch (_) {}
        return corsResponse({ ok: true, items });
      }
      if (path.startsWith('/analysis/issue/') && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const key = decodeURIComponent(path.split('/')[3] || '');
        if (!/^[A-Z][A-Z0-9]*-\d+$/.test(key)) return corsResponse({ ok: false, message: '\uC798\uBABB\uB41C \uC774\uC288 \uD0A4' }, 400);
        let row = null;
        try { const r = await env.DB.prepare('SELECT built_at, day, payload_json FROM issue_analysis WHERE issue_key = ? ORDER BY built_at DESC LIMIT 1').bind(key).first(); if (r) row = { built_at: r.built_at, day: r.day, ...JSON.parse(r.payload_json) }; } catch (_) {}
        return corsResponse({ ok: true, key, analysis: row });
      }
      if (path.startsWith('/analysis/request/') && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 가능합니다.' }, 403);
        const key = decodeURIComponent(path.split('/')[3] || '');
        if (!/^[A-Z][A-Z0-9]*-\d+$/.test(key)) return corsResponse({ ok: false, message: '잘못된 이슈 키' }, 400);
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS analysis_request (issue_key TEXT PRIMARY KEY, requested_at INTEGER, requested_by TEXT)").run();
          await env.DB.prepare('INSERT OR REPLACE INTO analysis_request (issue_key, requested_at, requested_by) VALUES (?, ?, ?)').bind(key, Date.now(), user).run();
          await auditLog(env, user, 'ANALYSIS_REQ', { reqKey: key });
          return corsResponse({ ok: true });
        } catch (e) { return corsResponse({ ok: false, message: '요청 실패: ' + (e && e.message || e) }, 500); }
      }
      if (path === '/analysis/requests' && request.method === 'GET') {
        const tok = request.headers.get('x-analysis-token') || '';
        if (!env.ANALYSIS_WRITE_TOKEN || tok !== env.ANALYSIS_WRITE_TOKEN) return corsResponse({ ok: false, message: '인증 실패' }, 401);
        let keys = [];
        try { const r = await env.DB.prepare('SELECT issue_key FROM analysis_request ORDER BY requested_at ASC').all(); keys = (r.results || []).map(x => x.issue_key); } catch (_) {}
        return corsResponse({ ok: true, keys });
      }

      // ── 고객사 담당자 관리 (정/부 담당 + 계약여부) : 조회=세션(영업 포함), 수정=관리자 ──
      // 이슈·지원건·영업에 담당 메타를 자동 반영하기 위한 단일 소스.
      if (path === '/customer/owners' && request.method === 'GET') {
        const anaOkO = !!env.ANALYSIS_WRITE_TOKEN && (request.headers.get('x-analysis-token') || '') === env.ANALYSIS_WRITE_TOKEN;
        if (!hasSession && !anaOkO) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        let items = [];
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS customer_owner (customer TEXT PRIMARY KEY, primary_owner TEXT NOT NULL DEFAULT '', secondary_owner TEXT NOT NULL DEFAULT '', products TEXT NOT NULL DEFAULT '', support TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, updated_by TEXT, updated_at INTEGER)").run();
          try { await env.DB.prepare("ALTER TABLE customer_owner ADD COLUMN sales_owner TEXT NOT NULL DEFAULT ''").run(); } catch (_) {}
          try { await env.DB.prepare("ALTER TABLE customer_owner ADD COLUMN users INTEGER DEFAULT 0").run(); } catch (_) {}
          const r = await env.DB.prepare('SELECT customer, primary_owner, secondary_owner, sales_owner, products, support, active, users, updated_by, updated_at FROM customer_owner ORDER BY active DESC, customer').all();
          items = r.results || [];
        } catch (_) {}
        return corsResponse({ ok: true, items });
      }
      if (path === '/customer/owner' && request.method === 'PUT') {
        // 관리자 또는 분석 토큰(시드). 계약종료·담당 변경은 관리자.
        const anaOkO = !!env.ANALYSIS_WRITE_TOKEN && (request.headers.get('x-analysis-token') || '') === env.ANALYSIS_WRITE_TOKEN;
        if (!anaOkO && (!hasSession || !await isAdmin(env, user))) return corsResponse({ ok: false, message: '관리자만 수정할 수 있습니다.' }, 403);
        const b = await request.json().catch(() => ({}));
        const customer = String(b.customer || '').trim().slice(0, 80);
        if (!customer) return corsResponse({ ok: false, message: '고객사명이 필요합니다.' }, 400);
        const actor = (anaOkO && !hasSession) ? 'seed(엑셀)' : user;
        const isSeed = anaOkO && !hasSession;
        // 시드(엑셀)는 빈 값이면 기존값 보존, 관리자 편집은 직접 덮어씀(제품·지원·영업담당 편집 가능)
        const keepIfEmpty = (col) => `CASE WHEN excluded.${col}!='' THEN excluded.${col} ELSE customer_owner.${col} END`;
        const prodSet = isSeed ? keepIfEmpty('products') : 'excluded.products';
        const suppSet = isSeed ? keepIfEmpty('support') : 'excluded.support';
        const salesSet = isSeed ? keepIfEmpty('sales_owner') : 'excluded.sales_owner';
        const usersSet = 'CASE WHEN excluded.users IS NOT NULL THEN excluded.users ELSE customer_owner.users END';
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS customer_owner (customer TEXT PRIMARY KEY, primary_owner TEXT NOT NULL DEFAULT '', secondary_owner TEXT NOT NULL DEFAULT '', products TEXT NOT NULL DEFAULT '', support TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, updated_by TEXT, updated_at INTEGER)").run();
          try { await env.DB.prepare("ALTER TABLE customer_owner ADD COLUMN sales_owner TEXT NOT NULL DEFAULT ''").run(); } catch (_) {}
          try { await env.DB.prepare("ALTER TABLE customer_owner ADD COLUMN users INTEGER DEFAULT 0").run(); } catch (_) {}
          await env.DB.prepare(`INSERT INTO customer_owner (customer, primary_owner, secondary_owner, sales_owner, products, support, active, users, updated_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(customer) DO UPDATE SET primary_owner=excluded.primary_owner, secondary_owner=excluded.secondary_owner, sales_owner=${salesSet}, products=${prodSet}, support=${suppSet}, active=excluded.active, users=${usersSet}, updated_by=excluded.updated_by, updated_at=excluded.updated_at`)
            .bind(customer, String(b.primary || '').slice(0, 40), String(b.secondary || '').slice(0, 40), String(b.sales_owner || '').slice(0, 40), String(b.products || '').slice(0, 120), String(b.support || '').slice(0, 40), b.active === false || b.active === 0 ? 0 : 1, (b.users===undefined?null:(parseInt(b.users,10)||0)), actor, Date.now()).run();
          if (!isSeed) await auditLog(env, user, 'CUST_OWNER', { ownerCustomer: customer, ownerActive: b.active === false ? 0 : 1 });
          return corsResponse({ ok: true });
        } catch (e) { return corsResponse({ ok: false, message: '저장 실패: ' + (e && e.message || e) }, 500); }
      }

      // ── 고객사 환경/사용 솔루션 (IA 재편) : 조회=세션(영업 포함), 수정=기술팀·관리자 ──
      if (path === '/customer/env' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const name = (url.searchParams.get('name') || '').trim().slice(0, 80);
        if (!name) return corsResponse({ ok: false, message: '고객사명이 필요합니다.' }, 400);
        let row = null;
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS customer_env (customer TEXT PRIMARY KEY, solutions TEXT NOT NULL DEFAULT '', env_note TEXT NOT NULL DEFAULT '', updated_by TEXT, updated_at INTEGER)").run();
          row = await env.DB.prepare('SELECT customer, solutions, env_note, updated_by, updated_at FROM customer_env WHERE customer = ?').bind(name).first();
        } catch (_) {}
        return corsResponse({ ok: true, env: row || null });
      }
      if (path === '/customer/env' && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        if (await isSalesRole(env, user)) return corsResponse({ ok: false, message: '환경 정보는 기술팀만 수정할 수 있습니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const customer = String(body.customer || '').trim().slice(0, 80);
        if (!customer) return corsResponse({ ok: false, message: '고객사명이 필요합니다.' }, 400);
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS customer_env (customer TEXT PRIMARY KEY, solutions TEXT NOT NULL DEFAULT '', env_note TEXT NOT NULL DEFAULT '', updated_by TEXT, updated_at INTEGER)").run();
          await env.DB.prepare('INSERT INTO customer_env (customer, solutions, env_note, updated_by, updated_at) VALUES (?,?,?,?,?) ON CONFLICT(customer) DO UPDATE SET solutions=excluded.solutions, env_note=excluded.env_note, updated_by=excluded.updated_by, updated_at=excluded.updated_at')
            .bind(customer, String(body.solutions || '').slice(0, 500), String(body.env_note || '').slice(0, 3000), user, Date.now()).run();
          await auditLog(env, user, 'CUST_ENV', { envCustomer: customer });
          return corsResponse({ ok: true });
        } catch (e) { return corsResponse({ ok: false, message: '저장 실패: ' + (e && e.message || e) }, 500); }
      }

      // ── STEP 6 영업 현황 : 규칙 기반 집계(AI 무관), 이슈 본문·코멘트는 반환하지 않음 ──
      if (path === '/sales/overview' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        try {
          const data = await buildSalesOverview(env);
          return corsResponse(data);
        } catch (e) { return corsResponse({ ok: false, message: '집계 실패: ' + (e && e.message || e) }, 500); }
      }
      if (path === '/sales/note' && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const salesOk = (await isSalesRole(env, user)) || (await isAdmin(env, user));
        if (!salesOk) return corsResponse({ ok: false, message: '영업·관리자만 수정할 수 있습니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        try {
          const saved = await saveSalesNote(env, user, body);
          await auditLog(env, user, 'SALES_NOTE', { noteCustomer: saved.customer, noteProduct: saved.product, noteStatus: saved.status });
          return corsResponse({ ok: true, saved });
        } catch (e) { return corsResponse({ ok: false, message: '저장 실패: ' + (e && e.message || e) }, 400); }
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
    // 자료실 KB 증분 수집 (매일, 무료 모드: 시드+기존링크+Jira 참조 KB, 2년 컷오프·중복 자동 제거)
    try { ctx.waitUntil(importRecentKBLinks(env, 'system(cron)', 2, { limit: 120 })); } catch (_) {}
    // 팀 다이제스트 카드를 Teams 채널로 자동 게시 (TEAMS_WEBHOOK_URL 시크릿 설정 시에만)
    if (env.TEAMS_WEBHOOK_URL) {
      ctx.waitUntil((async () => {
        try {
          if (!(await getFeatureFlags(env)).digest) return;
          const r = await postDigestToTeams(env, 'https://engr-jira.github.io/engr-hub-dev/');
          await auditLog(env, 'system(cron)', 'DIGEST_GEN', { via: 'teams', status: r.status, digDate: r.day });
        } catch (_) {}
      })());
    }
  },
};
