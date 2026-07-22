// ENGR HUB worker — vt.js
// (worker.js에서 이동. 로직 변경 없음)

export function isValidVtHash(hash = '') {
  return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(String(hash).trim());
}

export function vtDetectType(v = '') {
  const s = String(v).trim();
  if (isValidVtHash(s)) return 'hash';
  if (/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(s)) return 'ip';  // L-23: IPv4 옥텟 0-255 검증
  if (/^https?:\/\//i.test(s) || s.includes('/')) return 'url';
  if (/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(s)) return 'domain';
  return '';
}

export function vtUrlId(u) { // base64url(url) without padding — VirusTotal URL identifier
  return btoa(unescape(encodeURIComponent(u))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function vtPollAnalysis(vtKey, id, tries = 6) {
  for (let i = 0; i < tries; i++) {
    const r = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers: { 'x-apikey': vtKey } });
    const d = await r.json();
    const status = d?.data?.attributes?.status;
    if (status === 'completed') return d;
    await new Promise(res => setTimeout(res, 1500));
  }
  return null;
}

export async function getVtHistory(env) {
  const raw = await env.ENGR_KV.get('vt:history');
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.slice(0, 20) : [];
  } catch { return []; }
}

export async function saveVtHistory(env, user, hash, attrs = {}) {
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
