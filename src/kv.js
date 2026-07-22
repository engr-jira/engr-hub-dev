// ENGR HUB worker — kv.js
// (worker.js에서 이동. 로직 변경 없음)

import { DEFAULT_KV_STORAGE_LIMIT_BYTES, SUPER_ADMIN } from './config.js';
import { readUsageCounter } from './usage.js';

export function configuredBytes(env, name, fallback) {
  const raw = env?.[name];
  if (!raw) return fallback;
  const n = Number(String(raw).replace(/,/g, '').trim());
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export function storageCountLabel(r) {
  return r.truncated ? `${r.count}+` : String(r.count);
}

export async function countKVKeys(env, prefix, max = 1000) {
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

export async function kvSize(env, key) {
  try {
    const raw = await env.ENGR_KV.get(key);
    return raw ? new TextEncoder().encode(raw).length : 0;
  } catch (_) { return 0; }
}

export async function estimatePrefixBytes(env, prefix, max = 1000, sampleSize = 5) {
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

export async function getStorageStats(env) {
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

export async function readJsonKey(env, key, fallback = null) {
  try {
    const raw = await env.ENGR_KV.get(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch (_) { return fallback; }
}

export async function getPlainKey(env, key, fallback = '') {
  try { return await env.ENGR_KV.get(key) || fallback; } catch (_) { return fallback; }
}

export async function buildHubBackup(env, user) {
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

export async function deleteKvPrefix(env, prefix, max = 1000) {
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

export async function resetHubData(env) {
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
