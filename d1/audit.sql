-- ENGR HUB · §H KV→D1 마이그레이션 (1단계: 감사로그 audit_log)
-- id = KV 키 접미사 `${rev}:${type}:${rand}` 와 동일 → 이중쓰기·백필 멱등(INSERT OR IGNORE).
-- dev 적용: CLOUDFLARE_API_TOKEN=... npx wrangler d1 execute engr-hub-dev-db --remote --file d1/audit.sql --config wrangler.jsonc
-- 운영(prod)은 MJ 명시 요청 시에만.

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TEXT,
  ts_num INTEGER,
  user TEXT,
  type TEXT,
  detail_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_tsnum ON audit_log(ts_num DESC);
CREATE INDEX IF NOT EXISTS idx_audit_type  ON audit_log(type);
