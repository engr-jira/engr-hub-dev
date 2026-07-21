# 운영(prod) 배포 체크리스트 — ⚠️ 순서 엄수 · prod-readiness 감사 반영판

> **판정: 현 상태 No-Go → 아래 BLOCKER 5개 전부 해소 시 조건부 Go.**
> 코드는 기본값 폴백·코드상수 부트스트랩으로 graceful degrade하도록 설계됨. 그러나 아래 5개가
> 미해소면 **즉시·전면 장애가 확정적**이다. 운영 반영(마이그레이션 포함)은 **MJ 명시 요청 시에만.**
> 본 문서에는 **비밀값(PIN/키)을 절대 기재하지 말 것** — 시크릿 이름만 기재, 값은 wrangler secret으로.

## 🔴 BLOCKER (해소 전 배포 금지)
- **B1. `TEAM_PIN`(또는 `PIN_HASH`) 시크릿 미설정 → 전원 로그인 불가(콜드스타트 데드락).**
  신규 prod는 개인 PIN 0개라 모든 최초 로그인이 공유 PIN 폴백에만 의존. 둘 다 없으면 mj.park 포함
  누구도 로그인 불가 + 개인 PIN 심는 경로는 전부 로그인 후(isSuper)라 **복구 경로도 없음**. 최우선·치명.
- **B2. `index.html:2675` `const WORKERS`가 dev URL 하드코딩** → prod 프론트가 dev 백엔드 호출(데이터 혼선).
- **B3. `sw.js:3` `const WORKER`가 dev URL 하드코딩** → 푸시 무증상 오배달.
- **B4. prod 전용 `wrangler.jsonc` 필요** — dev 파일로 배포 시 dev 워커 덮어쓰기 + prod 바인딩 부재.
- **B5. prod D1 생성·바인딩·스키마 적용을 worker 배포보다 먼저** 안 하면 compat/기능토글/감사 쓰기 경로 500.

---

## [0단계] prod D1 인프라 (worker 배포 이전 — B5)
커스텀 API 토큰(D1 Edit + Workers KV Storage Edit) 필요. **토큰은 코드/문서 금지, 작업 후 삭제.**
> 이전 토큰은 §H 이후 삭제됨 → **MJ 재발급 필요.**
```bash
T="$(cat <토큰파일>)"
# 1) prod D1 생성 → database_id 기록
CLOUDFLARE_API_TOKEN="$T" npx wrangler d1 create engr-hub-prod-db
# 2) 스키마 + 시드 + 감사 적용 (prod wrangler.jsonc 준비 후)
for f in d1/schema.sql d1/seed.sql d1/audit.sql; do
  CLOUDFLARE_API_TOKEN="$T" npx wrangler d1 execute engr-hub-prod-db --remote --file "$f" \
    --config C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc
done
# 3) 검증 — 5개 테이블 확인
CLOUDFLARE_API_TOKEN="$T" npx wrangler d1 execute engr-hub-prod-db --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table';" \
  --config C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc
# compat_matrix, customers, app_settings, team_daily_snapshot, audit_log 5개
```
- `d1/seed.sql`(고객사 14곳)을 **반드시** 적용 — 미적용 시 cls 배지가 전부 "미분류⚑"(W3).
- customers 시드는 운영 실데이터에 맞게 MJ 검토 후 보정.

## [1단계] prod `wrangler.jsonc` 작성 (dev 파일 복사 금지 — B4)
`C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc`:
```jsonc
{
  "name": "engr-hub-proxy",                  // ← dev: engr-hub-proxy-dev
  "main": "worker.js",
  "compatibility_date": "2026-04-30",
  "ai": { "binding": "AI" },                 // ← W2: 반드시 포함(AI 폴백 보장)
  "kv_namespaces": [{ "binding": "ENGR_KV", "id": "<prod KV id>" }],
  "d1_databases": [{ "binding": "DB", "database_name": "engr-hub-prod-db", "database_id": "<0단계 출력>" }],
  "vars": {
    "KB_ALLOW_PAID_SEARCH": "false",
    "VAPID_PUBLIC_KEY": "<dev와 동일 키쌍의 public>",   // W7: private JWK와 매칭 필수
    "VAPID_SUBJECT": "mailto:<운영 연락처>"             // dev는 passikmj@gmail.com — 운영용 확인
  },
  "triggers": { "crons": ["30 23 * * *"] }   // 08:30 KST 팀 모니터 스냅샷 (W9)
}
```

## [2단계] prod 워커 시크릿/vars (worker 배포 이전)
`wrangler secret put <NAME> --config <prod wrangler.jsonc>` — **값은 입력 프롬프트로만**:
| 시크릿 | 필수도 | 미설정 시 |
|---|---|---|
| **`TEAM_PIN`** (또는 `PIN_HASH`) | 🔴 **필수** | **전원 로그인 불가 (B1)** |
| **`JIRA_TOKEN`** | 🔴 준필수 | 이슈/대시보드/모니터 빈 화면 (W1). ※코드가 `mj.park@escare.co.kr:`+토큰으로 Basic 인증 |
| `GEMINI_API_KEY` (또는 `GEMINI_KEY`) | 🟡 권장 | AI가 Llama 폴백으로 동작(품질↓) (W2) |
| `VAPID_PRIVATE_JWK` | 🟡 푸시 사용 시 | 푸시 발송 전량 실패(구독은 됨) — public(var)와 동일 키쌍 (W7) |
| `VT_API_KEY` (또는 `VT_KEY`) | 🟢 VT 사용 시 | VT 기능만 500(격리) (W10) |
| `GOOGLE_SEARCH_KEY` + `GOOGLE_SEARCH_CX` | 🟢 선택 | 유료 KB 검색만(기본 off라 무관) |

선택 vars(코드 디폴트 있음, 파리티 권장 — W15): `GEMINI_MODEL`, `AI_DAILY_LIMIT`(300), `AI_USER_DAILY_LIMIT`(80), `KV_STORAGE_LIMIT_BYTES`, `TEAM_NAMES`, **`DEFAULT_RESET_PIN`**(미설정 시 PIN 분실 복구 불가 — W8).

## [3단계] 코드 동기화 + URL 스왑 (복사 직후 · push 직전 — B2/B3)
```bash
cp dev/worker.js dev/index.html dev/sw.js prod/
cp -r dev/vendor prod/                            # Mermaid 번들
cp dev/.nojekyll dev/.gitattributes dev/manifest.webmanifest dev/icon.svg prod/
cp dev/manual.html dev/manual-user.html dev/mydesk.html prod/   # 매뉴얼/스탠드얼론(운영서 쓰면)
# ⚠ wrangler.jsonc 는 복사 금지(B4). design-preview.html 은 dev 산출물 — 선택.
sed -i 's/engr-hub-proxy-dev\.engr-jira\.workers\.dev/engr-hub-proxy.engr-jira.workers.dev/g' prod/index.html prod/sw.js
grep -c 'engr-hub-proxy-dev' prod/index.html prod/sw.js   # 둘 다 0 이어야 함 (B2/B3)
node -c prod/worker.js                                     # 구문 검사
```

## [4단계] 배포 및 검증
```bash
npx wrangler deploy --config C:/Users/passi/Downloads/engr-hub-prod/wrangler.jsonc   # ← 반드시 prod 설정(B4)
# 출력에 두 줄 확인, 없으면 롤백:
#   env.DB (engr-hub-prod-db) → D1 Database
#   schedule: 30 23 * * *
git -C prod add -A && git -C prod commit -m "..." && git -C prod push origin main   # 프론트(GitHub Pages)
```

## [5단계] 컷오버 직후 스모크 테스트 (정상처럼 보이는데 핵심만 죽는 유형 차단)
1. 공유 PIN 로그인 → **강제 PIN 변경 모달**(H-1) 뜨고 개인 PIN 설정되는지 (B1/O3)
2. 대시보드 **이슈 로드**(Jira 연결) — 빈 화면 아닌지 (W1)
3. 관리자 **기능 토글 저장 / compat 매트릭스 추가**가 500 안 나는지 (B5)
4. 고객사 **cls 배지가 미분류⚑ 일색이 아닌지**(시드 검증) + 모니터 카드 (W3/W6)
5. 푸시 구독·발송 1건 (W7, 사용 시)

## ⛔ 하지 말 것
- **감사 readsource 컷오버(`audit_read_d1='on'`) 금지** — 신규 prod는 KV 이중쓰기 grace로 둘 것.
  컷오버하려면 backfill 선행 필요(§H). 이중쓰기는 배포 즉시 자동 시작(코드).
- dev `wrangler.jsonc` 를 prod 로 복사 금지(B4).
- 시크릿 값을 코드/커밋/이 문서에 기입 금지.

## 🟡 운영 롤아웃 주의
- **H-1**: 첫 배포 시 팀 전원이 첫 로그인에서 강제 PIN설정 게이트를 만남(정상 온보딩). **사전 공지 권장.**
- **W11**: "로그인 유지" 저장 PIN이 개인 PIN 변경 후 stale → 다음 자동로그인 1회 401(수동 재로그인하면 해소).
- **W14**: dev·prod 동일 호스트(engr-jira.github.io)라 localStorage 세션 상호 간섭 가능.

## ❓ 배포 직전 별도 확인(코드만으론 불가)
- prod `wrangler.jsonc` 의 `AI` 바인딩 실제 포함 여부 (W2)
- prod D1 id / VAPID 키쌍 / cron 실제 값 (prod 리포 직접 확인)
- 고객사 시드 14곳 적용 여부
- GitHub Pages 커스텀 도메인 미사용 → 실제 Origin = `https://engr-jira.github.io` (CORS 허용값과 일치, W12)

## 가드 한 줄
> prod worker 배포 출력에 `env.DB (engr-hub-prod-db) → D1 Database` 와 `schedule: 30 23 * * *` 두 줄이
> 안 보이면 **롤백**하고 0~2 단계부터 다시. 로그인 안 되면 **B1(TEAM_PIN)** 부터 확인.
