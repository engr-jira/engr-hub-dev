-- ENGR HUB · D1 seed (Phase 0) — spec §C·§B. 멱등(INSERT OR IGNORE).
-- customers = §B 확인 브래킷 14곳(+알려진 별칭). aliases = JSON 배열. MJ가 추후 보강.

INSERT OR IGNORE INTO customers (name, aliases) VALUES
  ('우리은행','[]'),
  ('카카오뱅크','[]'),
  ('메리츠증권','[]'),
  ('하나투어','[]'),
  ('종근당','[]'),
  ('라이나생명','[]'),
  ('대덕전자','[]'),
  ('제주드림타워','[]'),
  ('경보제약','[]'),
  ('우리에프아이에스','["우리FIS"]'),
  ('우리카드','["우리카드(인터넷망)"]'),
  ('중국건설은행','[]'),
  ('폭스바겐파이낸셜','["폭스바겐","폭스바겐파이낸셜코리아"]'),
  ('미디어윌네트웍스','["미디어윌"]');

INSERT OR IGNORE INTO app_settings (key, value) VALUES
  ('monitor_allowlist','["mj.park"]'),
  ('monitor_daily_time','08:30');
