-- ENGR HUB · D1 schema (Phase 0 · feat/hub-d1-foundation) — spec §C
-- dev: engr-hub-dev-db (b3da16b6-16ac-4181-871b-a7eca09dc046). 운영은 추후 별도 DB.
-- 적용: CLOUDFLARE_API_TOKEN=... npx wrangler d1 execute engr-hub-dev-db --remote --file d1/schema.sql --config wrangler.jsonc

CREATE TABLE IF NOT EXISTS compat_matrix (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product TEXT, product_version TEXT, os TEXT, os_version TEXT, supported TEXT,
  eos_date TEXT, eol_date TEXT, note TEXT, source TEXT,
  status TEXT DEFAULT 'draft', verified_by TEXT, verified_at TEXT, updated_at TEXT
);

CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE, aliases TEXT, active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS app_settings ( key TEXT PRIMARY KEY, value TEXT );

CREATE TABLE IF NOT EXISTS team_daily_snapshot ( day TEXT PRIMARY KEY, payload_json TEXT, built_at TEXT );

CREATE INDEX IF NOT EXISTS idx_cm_product ON compat_matrix(product);
CREATE INDEX IF NOT EXISTS idx_cm_status  ON compat_matrix(status);
