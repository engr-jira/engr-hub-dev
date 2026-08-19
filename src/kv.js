// ENGR HUB worker — kv.js
// (worker.js에서 이동. 로직 변경 없음)

import { DEFAULT_KV_STORAGE_LIMIT_BYTES, SUPER_ADMIN } from './config.js';

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
  // 예전엔 여기서 AI 호출 수로 일일 write 를 추정했으나, 워커에 AI 코드가 없어진 뒤로
  // 근거가 되는 카운터(aiToday/aiSuccessToday 등)가 사라져 ReferenceError 로 조회가 통째로 실패했다.
  // 실측 가능한 값이 없는 추정치는 지우고, 참고용 한도만 남긴다.
  const operationBudget = {
    plan: 'Workers KV Free',
    resetAtUtc: '00:00',
    dailyLimits: { reads: 100000, writes: 1000, deletes: 1000, lists: 1000 },
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
    excludes: ['TEAM_PIN', 'JIRA_TOKEN', 'VT_KEY', 'Cloudflare Worker secrets/environment secrets'],
    data: {
      links: await readJsonKey(env, 'config:links', []),
      knowledge: await readJsonKey(env, 'config:knowledge', []),
      eos: await readJsonKey(env, 'config:eos', []),
      admins: await readJsonKey(env, 'config:admins', { [SUPER_ADMIN]: 'super' }),
      settings: {
        rangeMonths: await getPlainKey(env, 'config:range_months', '3'),
        sessionMin: await getPlainKey(env, 'config:session_min', '120'),
        eosWarnDays: await getPlainKey(env, 'config:eos_warn_days', '60,30,7'),
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

// ── 낙관적 잠금: KV 배열 컬렉션 갱신 ────────────────────────────────────────
// KV에는 CAS가 없다. get → 수정 → put 사이에 다른 요청이 put 하면 그쪽 항목이 통째로 사라진다(lost update).
// 여기서는 ① 쓰기 직전에 다시 읽어 스냅샷과 대조하고 ② 값이 바뀌었으면 "최신 배열에 델타를 다시 적용"한다.
//   apply(list) 는 배열을 받아 { list } 를 돌려주는 **순수 델타 함수**여야 한다 —
//   재시도 때 최신 배열로 다시 호출되므로, 바깥에서 미리 계산한 배열을 넘기면 안 된다.
//   중단하려면 { abort: { body, status } } 를 돌려준다(권한 없음·중복 등).
// ⚠️ 완전한 상호배제가 아니다. 재확인과 put 사이(수 ms) 창이 남고, KV 최종 일관성 탓에
//    재확인이 낡은 값을 볼 수도 있다. 창을 없애려면 소스를 D1로 옮겨야 한다.
// 배열이든 객체(map)든 쓸 수 있는 일반형. apply 는 { data }(또는 { list })로 새 값을 돌려준다.
// ⚠️ config:admins 처럼 **map** 인 키에 배열 강제 버전을 쓰면 통째로 날아간다 — 반드시 이쪽을 쓸 것.
export async function kvMutateJson(env, key, apply, opts = {}) {
  const retries = opts.retries == null ? 4 : opts.retries;
  const empty = opts.empty === undefined ? [] : opts.empty;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const raw = await env.ENGR_KV.get(key);
    const snapshot = raw == null ? '' : raw;
    let cur = empty;
    if (raw) { try { cur = JSON.parse(raw); } catch (_) { cur = empty; } }
    if (opts.forceArray && !Array.isArray(cur)) cur = [];
    const out = await apply(cur, attempt);
    if (out && out.abort) return { abort: out.abort, attempts: attempt + 1 };
    const chosen = out ? (out.data !== undefined ? out.data : out.list) : undefined;
    const next = JSON.stringify(chosen === undefined ? empty : chosen);
    if (next === snapshot) return { ok: true, noop: true, value: out && out.value, attempts: attempt + 1 };
    const recheck = await env.ENGR_KV.get(key);
    if ((recheck == null ? '' : recheck) === snapshot) {
      await env.ENGR_KV.put(key, next);
      return { ok: true, value: out && out.value, attempts: attempt + 1, retried: attempt };
    }
    // 그 사이 다른 요청이 썼다 → 루프 처음으로 돌아가 최신 값에 델타를 다시 적용
  }
  return { conflict: true, attempts: retries + 1 };
}
// 배열 전용 래퍼 (기존 호출부 호환)
export async function kvMutateArray(env, key, apply, opts = {}) {
  return kvMutateJson(env, key, apply, { ...opts, empty: [], forceArray: true });
}
// 동시 수정으로 끝내 저장하지 못했을 때의 공통 응답
export const KV_CONFLICT_RESPONSE = { ok: false, message: '다른 사용자가 동시에 수정 중입니다. 잠시 후 다시 시도해 주세요.' };
