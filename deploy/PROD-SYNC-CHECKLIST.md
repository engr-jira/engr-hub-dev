# 운영(prod) 동기화 체크리스트 — ⚠️ 순서 엄수

> dev worker.js 를 prod 로 복사하면 worker 가 `env.DB`(D1)를 호출한다. **prod 에 D1 바인딩이 없으면**
> 호환성 매트릭스/고객사 이력/팀 모니터/기능 토글/감사 D1 이 전부 try-catch 에 먹혀 **무증상 degrade**,
> `scheduled()` cron 스냅샷은 영영 안 돈다. 아래 0~3 을 끝내기 전엔 절대 worker 를 prod 에 올리지 말 것.
>
> **운영 반영(마이그레이션 포함)은 MJ 명시 요청 시에만.**

## 0. 사전 — prod D1 생성 (1회)
커스텀 API 토큰(D1 Edit + Workers KV Storage Edit) 필요. 토큰은 코드/문서 금지, 작업 후 삭제.
```bash
T="$(cat <토큰파일>)"
CLOUDFLARE_API_TOKEN="$T" npx wrangler d1 create engr-hub-prod-db   # database_id 출력 → 기록
```

## 1. prod wrangler.jsonc 에 바인딩 + cron 추가
`C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc` 에:
```jsonc
"d1_databases": [{ "binding": "DB", "database_name": "engr-hub-prod-db", "database_id": "<위 출력>" }],
"triggers": { "crons": ["30 23 * * *"] }   // 08:30 KST 팀 모니터 스냅샷
```

## 2. prod D1 스키마/시드 적용
```bash
for f in d1/schema.sql d1/seed.sql d1/audit.sql; do
  CLOUDFLARE_API_TOKEN="$T" npx wrangler d1 execute engr-hub-prod-db --remote --file "$f" \
    --config C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc
done
# customers 시드는 운영 실데이터에 맞게 MJ 검토 후 보정.
```

## 3. 검증 (배포 전)
```bash
CLOUDFLARE_API_TOKEN="$T" npx wrangler d1 execute engr-hub-prod-db --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table';" \
  --config C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc
# compat_matrix, customers, app_settings, team_daily_snapshot, audit_log 5개 확인.
```

## 4. 코드 동기화 (CLAUDE.md §1 정석)
```bash
cp dev/worker.js prod/worker.js
cp dev/index.html prod/index.html
cp dev/sw.js prod/sw.js
cp -r dev/vendor prod/vendor                 # Mermaid 번들
cp dev/.nojekyll dev/.gitattributes prod/
sed -i 's/engr-hub-proxy-dev\.mj-park\.workers\.dev/engr-hub-proxy.mj-park.workers.dev/g' prod/index.html prod/sw.js
grep -oc 'engr-hub-proxy-dev' prod/index.html prod/sw.js   # 둘 다 0 이어야 함
node -c prod/worker.js
```

## 5. 배포
```bash
npx wrangler deploy --config C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc   # 출력에 env.DB(D1)·schedule 확인
git -C prod add -A && git -C prod commit -m "..." && git -C prod push origin main
```
- ⚠️ prod worker secret(VAPID_PRIVATE_JWK, JIRA_TOKEN, GEMINI/VT 키)도 prod 에 설정돼 있어야 함.

## 6. 감사로그 KV→D1 마이그레이션 (선택, MJ 요청 시)
이중쓰기는 배포 즉시 시작됨(코드). 컷오버는 **데이터 플래그**라 코드 동기화만으론 자동 전환 안 됨.
1. 관리자설정 → 🗄️ 감사로그 D1 이전 → **과거 KV→D1 백필**(루프) → 상태에서 KV건수 ≈ D1건수 확인.
2. **읽기 D1 전환** → 표본 검증.
3. (유예 후) KV 미러 중단은 별도 코드 플립.

## 가드 한 줄
> prod worker 배포 출력에 `env.DB (engr-hub-prod-db) → D1 Database` 와 `schedule: 30 23 * * *` 두 줄이
> 안 보이면 **롤백**하고 0~2 부터 다시.
