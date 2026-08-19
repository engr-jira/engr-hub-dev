# 운영(prod) 이관 체크리스트 — 2026-08-19 실측 기준

> **판정: 코드는 Go, 데이터는 조건부.**
> 운영계는 죽어 있지 않다. **My Desk 5명 · PIN 10개 · 푸시 구독 6명**이 살아 있고 감사 로그도
> 849건 쌓여 있다. dev KV/D1 를 통째로 덮어쓰면 **팀원 개인 데이터가 사라진다.**
> 아래 §4 의 키별 판정을 지켜 **선택적으로만** 옮길 것.
>
> 비밀값(PIN·토큰·웹훅 URL)은 이 문서에 절대 기재하지 않는다 — 이름만 적고 값은 wrangler secret 으로.

---

## 0. 실측 현황

| | dev | prod |
|---|---|---|
| 프론트 | `index.html` + `js/` 18파일 + `src/` 11모듈 | **`index.html` 단일 9,208줄** (모듈화 이전) |
| 워커 | 2,130줄 + src 11모듈 · 엔드포인트 64 | 2,590줄 단일 · 엔드포인트 42 · **AI(Gemini) 코드 있음** |
| D1 테이블 | 16 | 5 |
| KV 키 | 1,236 (auditLatest 1,194) | 914 (auditLatest 849) |
| My Desk | 2명 | **5명** |
| userpin | 8 | **10** |
| push:pref | 2 | **6** |
| cron | `0,30 * * * *` | `30 23 * * *` |

---

## 1. BLOCKER — 해소 전 배포 금지

**B1. prod 워커 secret 2개 누락**
`ANALYSIS_WRITE_TOKEN` (분석 엔진 쓰기) · `TEAMS_WEBHOOK_URL` (개인 브리핑 DM).
없으면 스케줄 분석 저장이 401, 브리핑 발송이 무음 실패한다.
```
printf '%s' "$(tr -d '\r\n' < <토큰파일>)" | npx wrangler secret put ANALYSIS_WRITE_TOKEN --config <prod>/wrangler.jsonc
```

**B2. prod cron 이 하루 1회**
새 worker.js 의 `scheduled()` 는 **30분마다 기상**해서 KST 시각과 `app_settings.digest_schedule` 을
보고 자기 차례만 실행하는 구조다. prod 의 `30 23 * * *` 그대로면 브리핑 시각 설정이 무의미해진다.
→ prod `wrangler.jsonc` 의 crons 를 `["0,30 * * * *"]` 로 바꾼 뒤 배포.

**B3. 사용자 계정이 갈라져 있다**
- dev 에만: `jm.yang`
- prod 에만: `jy.jang`
`config:users` 를 dev 것으로 덮으면 **`jy.jang` 계정이 사라진다.** 어느 쪽이 맞는지 MJ 확인 후
병합본을 만들어 넣을 것. (자동 판단 금지)

**B4. prod 개인 데이터 보호**
`mydesk:*`(5) · `userpin:*`(10) · `push:pref:*`(6) · `push:subs` 는 **prod 것을 그대로 둔다.**
dev 값으로 덮으면 3명의 My Desk 가 날아가고 로그인 PIN 이 초기화된다.

---

## 2. 코드 이관

prod 는 모듈화 이전 단일 파일 구조다. **`index.html` 만 복사하면 흰 화면이 된다** — `js/*.js` 가
없어 전역 함수가 하나도 정의되지 않는다.

```bash
D=C:/Users/passi/Downloads/engr-hub-dev
P=C:/Users/passi/Downloads/engr-hub-prod

# 1) 복사 (디렉터리 통째로)
cp -r  $D/js        $P/
cp -r  $D/src       $P/
cp -r  $D/d1        $P/
cp     $D/index.html $D/sw.js $D/worker.js $D/manual.html $D/manual-user.html $P/
cp     $D/icon.svg  $D/manifest.webmanifest $P/
cp -r  $D/scripts   $P/            # stamp-assets.js 포함 (prepare-prod.js 는 prod 것 유지)

# 2) 운영 주소 치환 + 잔여 검사 (js/01-core.js · sw.js · index.html)
node $P/scripts/prepare-prod.js

# 3) 캐시 스탬프 → 배포 직후 바로 반영
node $P/scripts/stamp-assets.js

# 4) 문법 검사
node $P/.github/scripts/check-syntax.js     # 없으면 dev 에서 .github 도 복사
```

**prod 에만 있는 잔재** — `mydesk.html`, `vendor/mermaid.min.js`.
새 `index.html` 은 둘 다 참조하지 않으므로 고아가 된다. 지워도 되고 남겨도 무해하다.

**⚠️ `wrangler.jsonc` 는 복사하지 말 것** — prod 전용 바인딩(KV·D1 id)이 들어 있다. B2 의 cron 만 손댄다.

---

## 3. D1

**DDL 작업 불필요.** prod 에 없는 10개 테이블(`analysis_request` `analysis_snapshot` `customer_env`
`customer_owner` `issue_analysis` `issue_resp` `quiz_answer` `quiz_question` `quiz_week` `sales_notes`)은
전부 워커가 `CREATE TABLE IF NOT EXISTS` 로 첫 호출 때 만든다. 기존 5개는 이미 있다.

| 테이블 | dev | prod | 이관 |
|---|---|---|---|
| `customer_owner` | 39 | — | **옮긴다** (담당자 실데이터) |
| `customer_env` | 40 | — | **옮긴다** (고객사 환경 실데이터) |
| `compat_matrix` | 24 | 12 | **옮긴다** — prod 12건과 중복 확인 후 병합 |
| `quiz_question` | 32 | — | **옮긴다** (문제은행) |
| `quiz_week` / `quiz_answer` | 1 / 1 | — | 옮기지 않음 (dev 테스트 응시분) |
| `app_settings` | 9 | 3 | **선별** — feature_flags·monitor_allowlist·digest_* 만 |
| `customers` | 14 | 14 | 동일(시드) — 손대지 않음 |
| `issue_analysis` | 615 | — | 선택 — 안 옮겨도 07시 분석이 다시 채운다 |
| `analysis_snapshot` / `issue_resp` | 31 / 152 | — | 선택 — 위와 동일 |
| `audit_log` | 1,146 | 571 | **옮기지 않음** — 각 환경의 이력이다 |
| `team_daily_snapshot` | 70 | 68 | **옮기지 않음** — 환경별 집계 |
| `sales_notes` | 0 | — | 없음 |

---

## 4. KV — 키별 판정

| 키 | 판정 | 근거 |
|---|---|---|
| `config:links` | **dev → prod 덮어쓰기** | dev 70건 vs prod 19건. 단, prod 19건 중 dev 에 없는 URL 이 있는지 먼저 대조 |
| `config:eos` | **대조 후 병합** | dev 4건 vs prod 3건. 망 필드는 dev 에만 있음 |
| `config:knowledge` | 둘 다 비어 있음(`[]`) | 작업 없음 |
| `config:admins` | 동일(37B) | 작업 없음 |
| `config:users` | **MJ 확인 필요** | B3 — 계정 1개씩 서로 다름 |
| `config:range_months` `session_min` `eos_warn_days` `ai_system` | prod 값 유지 | 운영 설정은 운영이 정본 |
| `config:email_templates` | dev 에만 존재 | 필요하면 신규 생성 |
| `mydesk:*` `userpin:*` `push:pref:*` `push:subs` `push:settings` | **prod 유지 — 건드리지 말 것** | B4 |
| `auditLatest:*` | 각자 유지 | 환경별 이력 |
| `session:*` `jira:*` `usage:*` `vt:*` `private:*` | 이관 불필요 | 캐시·세션 |
| prod 의 `audit_1776…` 키 | 구스키마 잔재 | 정리 대상(선택) |

---

## 5. 사용자가 체감할 기능 변화

운영 사용자 입장에서 **없어지는 것**이 있으므로 사전 공지가 필요하다.

- **AI 버튼이 사라진다** — prod 워커에는 아직 Gemini 온디맨드 분석(요약·기술분석·회신초안·인수인계·
  유사이슈)이 살아 있다. 새 워커에는 AI 코드가 없고, 대신 **07시 스케줄 분석**이 이슈 상세를 미리 채운다.
- **로그 분석기가 사라진다** — 이슈에 로그를 첨부하면 스케줄 분석이 읽어 `📎 첨부 로그 분석`에 남긴다.
- 새로 생기는 것 — 영업 현황 · 담당자 관리 · 호환성 매트릭스 · 주간 퀴즈 · NSIS 정합성 검사 ·
  팀/개인 브리핑 · 라이선스 망 필드 · 관리자 설정 5섹션 개편 · 「막둥」 Jira 질의응답.

---

## 6. 실행 순서

1. **백업** — prod 관리자 설정 → 데이터 → `⬇ 전체 HUB 데이터 백업`. D1 은 각 테이블 SELECT 를 파일로.
2. B1 secret 2개 등록 · B2 cron 변경
3. B3 사용자 계정 병합안 확정(MJ)
4. §2 코드 복사 + `prepare-prod.js` + `stamp-assets.js` + 문법 검사
5. `npx wrangler deploy --config <prod>/wrangler.jsonc` (**워커 먼저**)
6. `/config/public` 200 확인 → 프론트 `git push origin main`
7. §3·§4 데이터 이관 (개인 데이터 키는 제외)
8. §8 검증

---

## 7. 롤백

- **프론트**: `git revert` 후 push (1~2분). 이전 커밋 `e1c5f15` 로 되돌리면 옛 단일 파일 구조 복귀.
- **워커**: Cloudflare 대시보드에서 이전 버전으로 롤백, 또는 이전 `worker.js` 재배포.
- **KV**: 덮어쓴 키는 1의 백업 JSON 에서 복원. **덮어쓰기 전 백업이 유일한 안전망이다.**
- **D1**: 새로 넣은 행만 지우면 되도록 `INSERT` 위주로 진행하고 `DELETE`/`DROP` 은 쓰지 않는다.

---

## 8. 검증 (배포 후)

- 탭 제목이 `[운영] ENGR AI v2.0` 인지 · 사이드바 배지가 **제이드 '운영'** 인지
  (개발 배지가 뜨면 경로 판별이 잘못된 것)
- 로그인(PIN 은 MJ) → 이슈 목록 로드 → 콘솔 에러 0
- 관리자 설정 5섹션 · 저장소 조회 성공 · 사용자 목록에 기존 10명 PIN 유지
- My Desk 5명분이 그대로 보이는지 (**가장 중요** — 날아갔으면 즉시 롤백)
- 라이선스 망 컬럼 · 영업 현황 2표 · NSIS 페이지 진입
- 다음 07시 분석이 prod D1 에 `issue_analysis` 를 쓰는지 (ANALYSIS_WRITE_TOKEN 확인)
