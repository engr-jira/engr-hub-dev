# ENGR HUB — 프로젝트 메모 (Claude 작업 가이드)

ESCARE 보안기술팀 내부 통합 허브. 단일 `index.html`(약 7,800줄) + Cloudflare Worker(`worker.js`).
현재 버전: **v1.9.0** (웹 푸시 알림)

---

## 1. 구조 / 배포 (가장 중요)

**저장소 2개 (dev → prod 동일 코드, 워커 URL만 다름)**
| | 프론트(GitHub Pages) | 워커(Cloudflare) | 로컬 경로 |
|---|---|---|---|
| dev | `engr-jira.github.io/engr-hub-dev` (repo `engr-hub-dev`) | `engr-hub-proxy-dev.mj-park.workers.dev` | `C:\Users\passi\Downloads\engr-hub-dev` |
| prod | `engr-jira.github.io/engr-hub` (repo `engr-hub`, origin `engr-jira/engr-hub.git`) | `engr-hub-proxy.mj-park.workers.dev` | `C:\Users\passi\Downloads\engr-hub-prod` |

**프론트 배포** = `git push origin main` (GitHub Pages 자동 빌드, **반영까지 1~2분** 소요).
**워커 배포** = `npx wrangler deploy --config <경로>/wrangler.jsonc`
  - ⚠️ `--config` 플래그 필수. (그냥 `wrangler deploy` 하면 `C:\Users\passi\Application Data` 정션 EPERM으로 실패)
  - 워커 변경 시에만 배포 필요. 프론트만 바뀌면 git push만.

**dev → prod 동기화** (정석 순서):
```bash
cp dev/worker.js  prod/worker.js              # 워커는 그대로 복사
cp dev/index.html prod/index.html
cp dev/sw.js      prod/sw.js                   # ⚠️ sw.js도 워커 URL 하드코딩 → 반드시 복사+스왑
sed -i 's/engr-hub-proxy-dev\.mj-park\.workers\.dev/engr-hub-proxy.mj-park.workers.dev/g' prod/index.html prod/sw.js
# 확인: grep -oc 'engr-hub-proxy-dev' prod/index.html prod/sw.js  → 둘 다 0 이어야 함
git -C <repo> add -A && git -C <repo> commit -m "..." && git -C <repo> push origin main
```
- ⚠️ 워커 vars/secret도 dev·prod 각각 설정 필요(아래 푸시 참고). prod 워커 배포는 `wrangler deploy --config prod/wrangler.jsonc`.
- `git -C <절대경로>` 사용 권장 (Bash cwd가 종종 리셋됨).
- 커밋 trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

**문법 검사** (배포 전 항상):
```bash
node -c worker.js
node -e 'const fs=require("fs"),vm=require("vm");const h=fs.readFileSync("index.html","utf8");const re=/<script>([\s\S]*?)<\/script>/g;let m,i=0,bad=0;while((m=re.exec(h)))(()=>{i++;try{new vm.Script(m[1])}catch(e){bad++;console.log(i,e.message)}})();console.log(bad?"FAIL":"OK")'
```

---

## 2. 코드 함정 (꼭 기억)

- **중복 함수 정의 다수**: 같은 이름 함수가 여러 번 정의됨 → **마지막 정의가 적용**(hoisting). 반드시 *활성(마지막)* 정의를 수정. 예: `renderTopbarStatus` = `renderTopbarStatusV159`(마지막).
- **My Desk JS는 IIFE 스코프**: `init/applyLayout/COLS/saveLayout/setMyDeskCols` 등은 `window`에 없음. 인라인 `onclick`에서 쓰려면 `window.fn=fn`으로 노출 필요. (단, `resetMyDesk`는 메인 스크립트에 있어 전역)
- **⚠️ `normalizeAdminSettingsUI()` 함정**: 관리자 설정의 `.admin-section` summary/`.admin-card h3`/`.admin-card.soft`를 **DOM 순서(index) 기준으로 덮어씀**. 설정 페이지에 새 섹션/카드 추가 시 인덱스가 밀려 라벨이 깨짐. **새 섹션은 반드시 `class="admin-section np"`** 부여(정규화 셀렉터가 `:not(.np)`로 제외). 푸시 섹션이 이 방식으로 보호됨.
- **My Desk @scope**: `@scope (#page-mydesk){...}` + 별도 `--serif/--sans/--gold` 등 자체 변수. 라이트모드는 `#mydesk-light` 스타일에서 스코프 변수 재정의.
- **My Desk 저장**: 서버 KV `mydesk:<user>` ↔ `/mydesk` GET/PUT. 클라 헬퍼 `load/save/saveNow`, `window.__MD_STORE` 캐시. 카드순서=`layout3`, 숨김=`hidden`, 열수=`mdCols`.
  - **저장 동기화(손실 방지)**: `__mdQueueServerSave`=디바운스 600ms+**최대대기 3s**, 2초 주기 백스톱, `pagehide`/`visibilitychange` 시 `__mdFlushNow`(keepalive) flush. `__mdServerSaveNow`=즉시. ⚠️ 로드 GET 실패 시 **빈 store로 덮어쓰지 말 것**(`__mdLoaded=false`로 저장 보류 — 안 그러면 다음 save가 서버 원본 파괴). `loadMyDeskForUser`는 `!CURRENT_USER`면 return + `__mdInited`로 init 1회 보장(리스너 중복=todo 중복입력 방지).

---

## 3. 테마 / 모바일 / PWA

- **테마**: `html[data-theme="light|dark"]`. `applyTheme()`가 적용·저장(`engr_theme`). CSS 변수 기반.
- **모바일(≤700px)은 다크 전용 강제**: `applyTheme`/초기 스크립트가 모바일이면 `data-theme=dark` 강제(라이트 누수로 글자 안보임 방지). 사용자 설정값은 보존되어 데스크톱엔 적용.
  - 모바일 스타일: 정적 `#codex-mobile-dark`(다크, head 끝으로 re-append) + `#v158-style`(원래 라이트 모바일, 미완성). 둘 다 무가드 @media라 충돌했었음 → 다크 강제로 해결.
- **상단바**: 데스크톱 = 큰 시계(날짜+시간 한 줄) + 사용자 드롭다운 메뉴(Jira상태/동기화/새로고침/매뉴얼/앱설치/테마/PIN변경/로그아웃). 모바일 = 시계 숨김, 메뉴 버튼만(팝오버는 버튼 기준 fixed 배치).
- **헤더 하단 구분선**: 사이드바·상단바 개별 border 제거하고 `#app::before/::after` 단일 오버레이(top:58px)로 그림 → 줌/DPI 단차 방지.
- **PWA**: `manifest.webmanifest` + `icon.svg`. 설치는 상단 메뉴 "앱 설치"(beforeinstallprompt). 앱 이름="ESCARE - 보안기술팀"(설치 시점 캐시 → 변경 시 재설치 필요). 창제목 끝 "- 회사"는 크롬 프로필명(웹 제어 불가).

---

## 4. 기능/연동 현황

- **AI**: worker `callAI` → 1순위 Gemini(`GEMINI_API_KEY`/`GEMINI_KEY`, `gemini-2.5-flash`, **thinking 비활성+maxOutputTokens 8192**, 잘림 방지), 실패 시 Cloudflare Workers AI Llama(`@cf/meta/llama-3.3-70b...`). 응답 캐시 `ai:v2:<mode>:<hash>` 7일.
- **VT**: `/vt/lookup`(value+type 자동인식: hash/ip/domain/url), `/vt/file`(파일 업로드 ≤32MB), `/vt/analysis`(폴링). 키 `VT_KEY`/`VT_API_KEY`.
- **Jira**: 워커 프록시. 커스텀필드 — 고객사 `customfield_10134`(array), 구분 `_10178`, 범주 `_10036.value`, 평가 `_10244.value`, 시작일 `_10015`, 기한 `duedate`. 미기입(meta) 점검 시 `[Hands-on]` 제외. 고객사 None/비-고객사 태그는 `isRealCust`/`NON_CUST_TAGS`로 필터.
- **로그 분석**: 업로드 ≤20MB, 붙여넣기/글자수/Ctrl+Enter, 결과는 AI 모달(📋 복사).
- **매뉴얼**: 관리자=`manual.html`(full), 일반=`manual-user.html`. (별도 폴더 `engr-hub-manual`에서 `build-manual.js`로 스크린샷 base64 내장 빌드)
- **권한**: `window.__HUB_IS_ADMIN`. 팀 일보고/감사로그/관리자설정 = 관리자/슈퍼만. 슈퍼 = mj.park(박민준).
- **Teams 임베드**: iframe 불가(MS가 X-Frame 차단). 딥링크 버튼만 가능. Graph API 연동은 Azure AD 앱+관리자 승인 필요.
- **웹 푸시 알림(Web Push, Option B)**:
  - **구성**: `sw.js`(서비스워커, fetch 핸들러 없음=캐시 안 함) + VAPID. **공개키=wrangler.jsonc `vars.VAPID_PUBLIC_KEY`**(공개), **개인키=secret `VAPID_PRIVATE_JWK`**(JWK JSON), `vars.VAPID_SUBJECT`=mailto. dev·prod 동일 키쌍 사용(둘 다 secret 설정 완료).
  - **방식**: payload-less 푸시(VAPID ES256 JWT만) → SW가 `/push/pending`(엔드포인트 소유 증명, 세션불필요)에서 보류 알림 받아 표시. 암호화(aes128gcm) 미사용.
  - **워커**: `pushNotify(env,eventKey,actorId,vars)` — 본인(actor) 제외, 사용자 opt-out(`push:pref:<user>`), 관리자 기능별 on/off + 대상 지정(include/exclude) + 멘트 템플릿(`{user}{target}{event}`). KV: `push:subs`(전체 구독 1키), `push:pending:<hash>`, `push:settings`, `push:pref:<user>`. 이벤트 레지스트리 `PUSH_EVENTS`(link/knowledge/eos) → 각 POST 핸들러에서 `ctx.waitUntil(pushNotify(...))`.
  - **엔드포인트**: `/push/public-key`(GET,무인증) `/push/subscribe` `/push/unsubscribe` `/push/pending`(무인증) `/push/pref`(GET/POST) `/push/test`(POST) `/push/settings`(GET/POST, 관리자).
  - **클라**: `initPushOnLogin()`(enterApp에서 호출, SW등록+권한있으면 조용히 재구독+`?go=`/postMessage 네비), `enablePush/disablePush/togglePushFromMenu`(상단메뉴 🔔 토글), 관리자설정 `loadPushSettings/savePushSettings`(loadSettings 끝에서 호출, `window.__userMap/__teamNames` 사용).
  - **제약**: iOS는 **설치형 PWA(홈화면 추가)에서만** 동작(16.4+) — 미설치 iOS는 토글 숨김. 각 사용자가 브라우저에서 "알림 허용" 직접 눌러야 함(Claude/IT 승인 불가). 실제 토스트 표시는 **실기기 확인 필수**.
  - **이벤트 추가법**: 워커 `PUSH_EVENTS`에 키 추가 + 해당 POST 핸들러에 `ctx.waitUntil(pushNotify(...))` 한 줄. 관리자 UI/타겟팅은 자동 반영. (케이스 트래커는 My Desk 개인데이터라 공유 이벤트 불가)

---

## 5. 검증/제약

- **로그인 PIN은 Claude가 입력 불가**(보안). 로그아웃 상태에선 화면 검증 제한.
- 같은 호스트(engr-jira.github.io)라 dev↔prod **localStorage 세션 공유** → prod 방문 시 dev 세션 풀릴 수 있음.
- 브라우저(Chrome MCP) 스크린샷은 항상 데스크톱 폭(1920)으로 렌더 → **모바일 픽셀 검증 불가**, 실기기 확인 필요.
- 배포 확인: `?v=숫자` 캐시버스트로 새로고침 후 확인.
- 비밀값(GEMINI/VT 키, PIN)은 절대 코드/문서에 넣지 말 것. 워커 secret으로만.

---

## 6. 최근 작업 로그 (v1.8.x)
- VT 멀티타입(IP/도메인/URL/파일) 통합 조회
- AI 응답 잘림 수정(Gemini thinking off + 8192)
- 로그인 시네마틱 배경(다크/라이트)
- 모바일 다크 전용 안정화 + 통합 필터(한 줄)
- 이슈 디테일(고객사 None 정리, 이슈키 복사 버튼)
- 버튼 모던화(채우기→소프트), 아이콘 정리
- 상단바 개편(큰 시계 + 그룹 메뉴), 헤더 구분선 단일 오버레이
- 로그인 유지/자동로그인(아이디·PIN 저장)
- PWA(홈화면/바탕화면 설치), 앱 제목 "ESCARE - 보안기술팀"
- My Desk: 카드 제목 폰트 통일(sans), 열 수 1/2/3 토글(사용자별 저장)
- 상단바: 큰시계 + 그룹메뉴(검색 제거, 연결상태 폰트 확대), 헤더 구분선 `#app::before/::after` 단일 오버레이
- 아이폰 상단 메뉴 잘림 수정: 팝오버를 body로 이동(상단바 backdrop-filter가 fixed 기준이 돼 잘림)
- 로그 분석 단발성 개편(`analyzeLogs`→JSON): 에러/경고/특이사항 시간순 발췌(복사) + 이슈별 KB/커뮤니티 검색링크 + `registerLogLink`로 업무링크 ➕등록. (worker AI mode `logx`, `extractKeywords` 제거)
- **My Desk 데이터 손실 버그 수정**: 연속 입력 중 디바운스가 계속 밀려 PUT이 안 나가던 문제 → 최대대기 3s + 2초 백스톱 + 이탈 시 keepalive flush. 로드 실패 시 빈 값 덮어쓰기 금지. (모든 카드 save 경로 검증 완료)
- **웹 푸시 알림(Option B) 구축**: sw.js + VAPID(ES256) + payload-less. 본인 제외/사용자 opt-out/관리자 기능별 on·off/대상 지정(include·exclude)/멘트 템플릿. 이벤트=업무링크·팀노하우·EOS 등록. 상단메뉴 🔔 토글 + 관리자설정 섹션. (실기기 알림 표시 검증 사용자 필요)
- 푸시 관리자 섹션 표시 수정(normalizeAdminSettingsUI index 충돌 → `.np` 제외). My Desk: 주간미팅 시간 입력, 벤더케이스 날짜=오픈일 명확화, 바로가기 RDP 포트 입력(.rdp/mstsc 반영).
