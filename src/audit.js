// ENGR HUB worker — audit.js
// (worker.js에서 이동. 로직 변경 없음)

export async function auditLog(env, user, type, detail = {}) {
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

export function auditTimestampFromKey(name) {
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

export async function cleanupOldAudit(env, days = 90, dryRun = true, max = 500) {
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

export async function getAuditReadD1(env) {
  try { const r = await env.DB.prepare("SELECT value FROM app_settings WHERE key='audit_read_d1'").first(); return r?.value === 'on'; } catch (_) { return false; }
}
