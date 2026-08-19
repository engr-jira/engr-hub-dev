# 개발 ↔ 운영 동기화 — 2026-08-19 이관 완료 기준

> **운영이 정본, 개발은 같은 데이터로 테스트하는 곳.** 두 곳은 **같게 동작해야 한다.**
> 이관은 2026-08-19 에 끝났다. 이 문서는 이후 **차이가 생기지 않게 유지하는 절차**다.
> 비밀값(PIN·토큰·웹훅 URL)은 여기에 절대 적지 않는다 — 이름만, 값은 wrangler secret 으로.

---

## 0. 지금 상태 (2026-08-19 실측)

| | 개발 | 운영 |
|---|---|---|
| 프론트 | `index.html` + `js/` 18 + `src/` 11 | **동일** |
| 워커 | 같은 `worker.js` + `src/` | **동일** (주소만 다름) |
| cron | `0,30 * * * *` | **동일** |
| 시크릿 | 9종 | **동일 9종** |
| `feature_flags` | 14키 전부 true | **동일** |
| 담당자 / 환경 / 퀴즈 / 매트릭스 | 39 / 40 / 32 / 36 | **동일** |
| 이슈분석 / 스냅샷 / 응답지표 | 615 / 31 / 152 | **동일** |
| 계정 | 11 | 12 (운영이 정본 — `jy.jang` 포함) |
| My Desk · PIN · 푸시구독 | 환경별 (**섞지 않는다**) | 환경별 |

**남은 차이 1건** — `audit_read_d1`: 개발 `on`(D1에서 읽음) / 운영 미설정(KV에서 읽음).
운영 KV 849건 중 D1에는 571건만 있어 그냥 켜면 과거 로그가 안 보인다.
→ 운영 **관리자 설정 → 🗄️ 데이터 → 감사로그 D1 이전**에서 `과거 KV→D1 백필` 누른 뒤 `읽기 D1 전환`.
슈퍼 세션이 필요해 버튼으로만 가능하다.

---

## 1. 코드를 개발에서 운영으로 옮길 때

```bash
D=C:/Users/passi/Downloads/engr-hub-dev
P=C:/Users/passi/Downloads/engr-hub-prod

cp -r $D/js $D/src $D/d1 $P/
cp $D/index.html $D/sw.js $D/worker.js $D/manual.html $D/manual-user.html $P/

node $P/scripts/prepare-prod.js    # 워커 주소 치환(js/01-core.js · sw.js · index.html) + 잔여 dev 주소 0건 검증
node $P/scripts/stamp-assets.js    # js 캐시 스탬프 — 안 하면 최대 10분간 예전 js 가 쓰인다
node $P/.github/scripts/check-syntax.js

npx wrangler deploy --config $P/wrangler.jsonc     # 워커 먼저
git -C $P add -A && git -C $P commit && git -C $P push origin main
```

- ⚠️ **`wrangler.jsonc` 는 복사하지 않는다** — 운영 전용 KV·D1 바인딩이 들어 있다.
- 개발 쪽도 `stamp-assets.js` 를 돌리고 push 한다(같은 이유).

## 2. 스케줄 분석 엔진

`~/.claude/scheduled-tasks/engr-analysis-am|pm, engr-queue-check` 의 SKILL.md 는
**개발·운영 양쪽을 대상**으로 한다(2026-08-19 변경).

- 읽기(조회 기간·기존 qa·기존 초안·첨부) = **운영만** — 같은 Jira 라 중복 조회는 낭비다
- 요청 큐 `/analysis/requests` = **양쪽 GET → 키 합집합** (어느 화면에서 눌러도 처리)
- 쓰기 `PUT /analysis`, `POST /compat`·`/quiz/question`·`/links` = **양쪽에 동일하게**
- 분석·생성은 **1회만** 하고 결과를 두 번 전송한다 → Jira·AI 사용량은 늘지 않는다
- 토큰 `ANALYSIS_WRITE_TOKEN` 은 두 환경이 같은 값이다

## 3. 설정(app_settings)을 바꿀 때

`feature_flags` · `quiz_settings` · `digest_schedule` · `digest_recipients` · `monitor_*` 는
**양쪽에 같은 값**을 넣는다. 한쪽만 바꾸면 화면 구성이 갈린다.
런타임 마커(`analysis_last_run` `cron_daily_last`)는 환경별이라 그대로 둔다.

## 4. 절대 섞지 않는 것

`mydesk:*` · `userpin:*` · `push:pref:*` · `push:subs` · `push:settings` · `auditLatest:*` ·
`session:*` · `jira:*` · `usage:*` · `vt:*` — 개인 데이터와 환경별 이력이다.
**개발 값으로 운영을 덮으면 팀원 My Desk 와 PIN 이 사라진다.**

## 5. 되돌리기

- 프론트: `git revert` 후 push (1~2분)
- 워커: Cloudflare 대시보드에서 이전 버전 롤백
- 데이터: `C:\Users\passi\Downloads\engr-hub-prod-backup-20260819` (KV 36키 · D1 5테이블 · 이전 index/worker)
- D1 작업은 `INSERT OR REPLACE` 만 쓰고 `DELETE`/`DROP` 은 쓰지 않는다

## 6. 배포 후 확인

- 탭 제목이 `[운영] ENGR AI v2.0` / `[개발] …` 인지, 사이드바 배지가 제이드 **운영** / 앰버 **개발** 인지
- 로그인(PIN 은 MJ) → 이슈 목록 → 콘솔 에러 0
- **My Desk 가 그대로 보이는지** — 안 보이면 즉시 롤백
- 관리자 설정 5섹션 · 저장소 조회 성공
- 다음 07시 분석이 **양쪽 D1** 에 `issue_analysis` 를 쓰는지

> ⚠️ 개발·운영이 같은 호스트(`engr-jira.github.io`)라 **localStorage 세션을 공유**한다.
> 한쪽에서 로그인한 토큰은 다른 쪽 워커가 거부하므로, 환경을 옮기면 다시 로그인해야 한다.
