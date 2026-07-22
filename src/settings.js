// ENGR HUB worker — settings.js
// (worker.js에서 이동. 로직 변경 없음)

export async function getFeatureFlags(env) {
  const def = { compat: true, history: true, monitor: true, nsis: true };
  try { const r = await env.DB.prepare("SELECT value FROM app_settings WHERE key='feature_flags'").first(); if (r && r.value) return { ...def, ...JSON.parse(r.value) }; } catch (_) {}
  return def;
}
