// ENGR HUB Cloudflare Worker v1.5.11
//
//
//

import { CORS_HEADERS, SUPER_ADMIN, TEAM_FIELDS, corsResponse, decUser, getCorsHeaders } from './src/config.js';
import { PUSH_EVENTS, endpointHash, enqueuePending, getPushSettings, getPushSubs, pushNotify, savePushSubs, sendWebPush } from './src/push.js';
import { addCollectionComment, canModifyItem, deleteCollectionComment } from './src/items.js';
import { auditLog, cleanupOldAudit, getAuditReadD1 } from './src/audit.js';
import { buildDailySnapshot, getCustomersD1, handleJiraSearch, isMonitorAllowed, jiraSearchJql, jqlEsc, jqlTextEsc, mapJiraIssue, nextDayStr, okDate } from './src/jira.js';
import { buildHubBackup, getStorageStats, resetHubData } from './src/kv.js';
import { createSession, deactivateUserAccount, getAdmins, getDefaultResetPin, getSessionUser, getTeamNames, getUserAccount, getUserPinHash, getUsers, isAdmin, isSalesRole, isSuper, normalizeUserId, purgeUserAccount, revokeUserSessions, salesPathAllowed, saveUserAccount, setUserPin, validateUserPin } from './src/auth.js';
import { getFeatureFlags } from './src/settings.js';
import { getVtHistory, saveVtHistory, vtDetectType, vtPollAnalysis, vtUrlId } from './src/vt.js';
import { importRecentKBLinks } from './src/kb.js';
import { buildSalesOverview, saveSalesNote, getSalesStaleDays } from './src/sales.js';

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: getCorsHeaders(request) });

    const url = new URL(request.url);
    const path = url.pathname;
    const headerUser = normalizeUserId(decUser(request.headers.get('X-User') || ''));
    const sessionUser = await getSessionUser(env, request.headers.get('X-Session-Token') || '');
    const hasSession = !!sessionUser && (!headerUser || headerUser === sessionUser);
    const user = sessionUser || headerUser;

    // ── 영업 역할 화이트리스트 강제 (라우팅 이전) ──
    // 클라이언트에서 메뉴를 숨기는 것만으로는 API가 그대로 열리므로 서버에서 차단한다.
    if (hasSession && await isSalesRole(env, user)) {
      if (!salesPathAllowed(path, request.method)) {
        ctx.waitUntil(auditLog(env, user, 'SALES_DENY', { denyPath: path, denyMethod: request.method }));
        return corsResponse({ ok: false, message: '접근 권한이 없습니다.' }, 403);
      }
    }

    try {
      //
      if (path === '/debug') {
        return corsResponse({ ok: true, ts: new Date().toISOString(), worker: 'engr-hub-proxy', model: '@cf/meta/llama-3.3-70b-instruct-fp8-fast' });
      }

      //
      

      //
      if (path === '/auth/session' && request.method === 'GET') {
        if (!hasSession || !sessionUser) return corsResponse({ ok: false, message: '세션이 만료되었습니다.' }, 401);
        const account = await getUserAccount(env, sessionUser);
        if (!account || account.active === false) return corsResponse({ ok: false, message: '비활성화된 계정입니다.' }, 403);
        const admins = await getAdmins(env);
        const role = account.role || admins[sessionUser] || 'user';
        let sessionMin = 120;
        try {
          const cfg = await env.ENGR_KV.get('config:session_min');
          if (cfg) sessionMin = parseInt(cfg) || 120;
        } catch (_) {}
        const mustChangePin = !(await getUserPinHash(env, sessionUser));  // H-1: 세션 복원 시에도 개인 PIN 미설정이면 강제 변경 유지
        return corsResponse({
          ok: true,
          name: sessionUser,
          userId: sessionUser,
          displayName: account.displayName || sessionUser,
          isAdmin: role === 'admin' || role === 'super',
          isSuperAdmin: role === 'super',
          role,
          sessionMin,
          mustChangePin,
        });
      }

      if (path === '/auth/login' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { name, pin } = body;
        const userId = normalizeUserId(name);
        if (!userId || !pin) return corsResponse({ ok: false, message: '\uACC4\uC815 ID\uC640 PIN\uC744 \uC785\uB825\uD558\uC138\uC694.' }, 400);

        const account = await getUserAccount(env, userId);
        if (!account || account.active === false) {
          return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uB9CC \uC811\uC18D\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        }

        let pinOk = await validateUserPin(env, userId, pin);
        // M-2: displayName 폴백 제거 — PIN은 항상 정규화 id로 저장되어 폴백은 dead이고, 교차계정 PIN 매칭 위험만 유발(레거시는 TEAM_PIN→H-1로 graceful)
        if (!pinOk) return corsResponse({ ok: false, message: 'PIN\uC774 \uC62C\uBC14\uB974\uC9C0 \uC54A\uC2B5\uB2C8\uB2E4.' }, 401);
        // \uC8FC\uC758: \uB85C\uADF8\uC778 \uC2DC PIN \uC790\uB3D9 \uB36E\uC5B4\uC4F0\uAE30 \uC81C\uAC70. PIN\uC740 \uC624\uC9C1 /auth/change-pin(\uBA85\uC2DC\uC801 'PIN \uBCC0\uACBD')\uC73C\uB85C\uB9CC \uBCC0\uACBD\uB428.

        const admins = await getAdmins(env);
        const role = account.role || admins[userId] || 'user';

        let sessionMin = 120;
        try {
          const cfg = await env.ENGR_KV.get('config:session_min');
          if (cfg) sessionMin = parseInt(cfg) || 120;
        } catch (_) {}

        const sessionToken = await createSession(env, userId, sessionMin);
        const mustChangePin = !(await getUserPinHash(env, userId));  // H-1: 개인 PIN 미설정(공유 PIN 폴백 로그인) → 최초 1회 강제 변경
        await auditLog(env, userId, 'LOGIN', { role, viaSharedPin: mustChangePin });
        return corsResponse({
          ok: true,
          name: userId,
          userId,
          displayName: account.displayName || userId,
          isAdmin: role === 'admin' || role === 'super',
          isSuperAdmin: role === 'super',
          role, sessionMin, sessionToken, mustChangePin,
        });
      }

      if (path === '/auth/change-pin' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const oldPin = body.oldPin || '';
        const newPin = body.newPin || '';
        if (!oldPin || !newPin) return corsResponse({ ok: false, message: '\uD604\uC7AC PIN\uACFC \uC0C8 PIN\uC744 \uC785\uB825\uD558\uC138\uC694.' }, 400);
        if (String(newPin).length < 6) return corsResponse({ ok: false, message: '\uC0C8 PIN\uC740 6\uC790 \uC774\uC0C1\uC774\uC5B4\uC57C \uD569\uB2C8\uB2E4.' }, 400);
        if (!await validateUserPin(env, user, oldPin)) return corsResponse({ ok: false, message: '\uD604\uC7AC PIN\uC774 \uC62C\uBC14\uB974\uC9C0 \uC54A\uC2B5\uB2C8\uB2E4.' }, 401);
        await setUserPin(env, user, newPin);
        await auditLog(env, user, 'PIN_CHANGE', {});
        return corsResponse({ ok: true });
      }

      //
      if (path === '/config/public' && request.method === 'GET') {
        const sessionRaw = await env.ENGR_KV.get('config:session_min');
        const rangeRaw = await env.ENGR_KV.get('config:range_months') || await env.ENGR_KV.get('config:jira_range_months');
        let lastSync = null;
        try { const raw = await env.ENGR_KV.get('config:last_jira_sync'); if (raw) lastSync = JSON.parse(raw); } catch (_) {}
        return corsResponse({ sessionMin: parseInt(sessionRaw || '120') || 120, rangeMonths: parseInt(rangeRaw || '6') || 6, lastSync });
      }
      
      // 일반 유저용 개인 AI 사용량 (팀 통계 미포함)
      
      if (path === '/links/kb/import' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const years = Math.max(1, Math.min(10, parseInt(url.searchParams.get('years') || '5', 10) || 5));
        const limit = Math.max(1, Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10) || 20));
        const cursor = url.searchParams.get('cursor') || '';
        const provider = url.searchParams.get('provider') || '';
        return corsResponse(await importRecentKBLinks(env, user, years, { limit, cursor, provider }));
      }

      //
      // ── 스케줄 엔진용 Jira 첨부 프록시 (분석 토큰 인증) : 첨부 로그 분석의 통로 ──
      // 일반 /jira/ 봉인보다 먼저 매칭되어야 함. 5MB 상한(로그 텍스트 위주).
      if (path.startsWith('/jira/attach/') && request.method === 'GET') {
        const tok = request.headers.get('x-analysis-token') || '';
        if (!env.ANALYSIS_WRITE_TOKEN || tok !== env.ANALYSIS_WRITE_TOKEN) return corsResponse({ ok: false, message: '인증 실패' }, 401);
        const attId = path.split('/')[3] || '';
        if (!/^\d+$/.test(attId)) return corsResponse({ ok: false, message: '잘못된 첨부 ID' }, 400);
        const jiraAuth = 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN);
        const jr = await fetch(`https://escare-engr.atlassian.net/rest/api/3/attachment/content/${attId}`, { headers: { 'Authorization': jiraAuth } });
        if (!jr.ok) return corsResponse({ ok: false, message: '첨부 조회 실패 ' + jr.status }, 502);
        const buf = await jr.arrayBuffer();
        if (buf.byteLength > 30 * 1024 * 1024) return corsResponse({ ok: false, message: '30MB 초과 첨부는 분석 제외' }, 413);
        return new Response(buf, { status: 200, headers: { ...CORS_HEADERS, 'Content-Type': jr.headers.get('Content-Type') || 'application/octet-stream' } });
      }
      if (path.startsWith('/jira/')) {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const jiraPath = path.replace('/jira/', '');
        if (jiraPath === 'search' || jiraPath === 'search/jql') {
          return await handleJiraSearch(env, user);
        }
        // ── 프록시 봉인: 프론트가 실제로 쓰는 GET issue/{KEY} 만 허용 ──
        // (이전엔 전 메서드·임의 경로가 mj.park 인증으로 통과 → Jira 임의 읽기/쓰기 가능했음)
        if (request.method !== 'GET') {
          ctx.waitUntil(auditLog(env, user, 'JIRA_PROXY_DENY', { jiraPath, denyMethod: request.method }));
          return corsResponse({ ok: false, message: '허용되지 않은 메서드입니다.' }, 405);
        }
        if (!/^issue\/[A-Z][A-Z0-9]*-\d+$/.test(jiraPath)) {
          ctx.waitUntil(auditLog(env, user, 'JIRA_PROXY_DENY', { jiraPath, denyMethod: 'GET' }));
          return corsResponse({ ok: false, message: '허용되지 않은 경로입니다.' }, 403);
        }
        const jiraAuth = 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN);
        const jiraUrl = `https://escare-engr.atlassian.net/rest/api/3/${jiraPath}${url.search}`;
        const jiraRes = await fetch(jiraUrl, {
          method: request.method,
          headers: { 'Authorization': jiraAuth, 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: request.method !== 'GET' ? await request.text() : undefined,
        });
        const data = await jiraRes.text();
        return new Response(data, { status: jiraRes.status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8' } });
      }

      //
      

      // VT \uBA40\uD2F0 \uD0C0\uC785 \uC870\uD68C (\uD574\uC2DC/IP/\uB3C4\uBA54\uC778/URL)
      if (path === '/vt/lookup' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ error: { message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 401);
        const body = await request.json().catch(() => ({}));
        const vtKey = env.VT_KEY || env.VT_API_KEY || '';
        if (!vtKey) return corsResponse({ error: { message: 'VT_KEY \uD658\uACBD\uBCC0\uC218\uAC00 \uC124\uC815\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.' } }, 500);
        const raw = String(body.value || body.hash || '').trim();
        if (!raw) return corsResponse({ error: { message: '\uC870\uD68C\uD560 \uAC12\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 400);
        const type = (body.type && body.type !== 'auto') ? body.type : vtDetectType(raw);
        if (!type) return corsResponse({ error: { message: '\uD574\uC2DC/IP/\uB3C4\uBA54\uC778/URL \uD615\uC2DD\uC774 \uC544\uB2D9\uB2C8\uB2E4.' } }, 400);
        const H = { 'x-apikey': vtKey };
        try {
          if (type === 'url') {
            const sres = await fetch('https://www.virustotal.com/api/v3/urls', { method: 'POST', headers: { ...H, 'content-type': 'application/x-www-form-urlencoded' }, body: `url=${encodeURIComponent(raw)}` });
            const sdata = await sres.json();
            if (!sres.ok) return corsResponse(sdata, sres.status);
            const aid = sdata?.data?.id;
            if (aid) await vtPollAnalysis(vtKey, aid, 6);
            const ures = await fetch(`https://www.virustotal.com/api/v3/urls/${vtUrlId(raw)}`, { headers: H });
            const udata = await ures.json();
            if (!body.noAudit && ures.ok && udata?.data?.attributes) await auditLog(env, user, 'VT_LOOKUP', { vtType: type, value: raw.slice(0, 60), mal: udata.data.attributes.last_analysis_stats?.malicious || 0 });
            return corsResponse({ ...udata, _type: 'url', _value: raw }, ures.status);
          }
          let vtUrl;
          if (type === 'hash') vtUrl = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(raw.toLowerCase())}`;
          else if (type === 'ip') vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(raw)}`;
          else if (type === 'domain') vtUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(raw)}`;
          const vtRes = await fetch(vtUrl, { headers: H });
          const data = await vtRes.json();
          if (vtRes.ok && data?.data?.attributes) {
            if (!body.noAudit) await auditLog(env, user, 'VT_LOOKUP', { vtType: type, value: raw.slice(0, 60), mal: data.data.attributes.last_analysis_stats?.malicious || 0 });
            if (type === 'hash') await saveVtHistory(env, user, raw.toLowerCase(), data.data.attributes);
          }
          return corsResponse({ ...data, _type: type, _value: raw }, vtRes.status);
        } catch (e) { return corsResponse({ error: { message: e.message || 'VT \uC870\uD68C \uC2E4\uD328' } }, 502); }
      }
      // \uC5EC\uB7EC \uAC74 \uC77C\uAD04 \uC870\uD68C \uC2DC \uAC10\uC0AC\uB85C\uADF8 1\uAC74\uC73C\uB85C \uC694\uC57D(\uAC1C\uBCC4 \uC870\uD68C\uB294 noAudit\uB85C \uAE30\uB85D \uC0DD\uB7B5)
      if (path === '/vt/audit-batch' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const count = Math.max(1, parseInt(body.count) || 1);
        const mal = Math.max(0, parseInt(body.mal) || 0);
        await auditLog(env, user, 'VT_LOOKUP', { count, mal, batch: true, value: `${count}\uAC74 \uC77C\uAD04 \uC870\uD68C` });
        return corsResponse({ ok: true });
      }
      // VT \uD30C\uC77C \uC5C5\uB85C\uB4DC \u2192 \uBD84\uC11D ID \uBC18\uD658
      if (path === '/vt/file' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ error: { message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 401);
        const vtKey = env.VT_KEY || env.VT_API_KEY || '';
        if (!vtKey) return corsResponse({ error: { message: 'VT_KEY \uD658\uACBD\uBCC0\uC218\uAC00 \uC124\uC815\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.' } }, 500);
        try {
          const form = await request.formData();
          const file = form.get('file');
          if (!file || typeof file === 'string') return corsResponse({ error: { message: '\uD30C\uC77C\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 400);
          if (file.size > 32 * 1024 * 1024) return corsResponse({ error: { message: '\uBB34\uB8CC \uC5C5\uB85C\uB4DC\uB294 \uCD5C\uB300 32MB\uC785\uB2C8\uB2E4.' } }, 400);
          const vform = new FormData();
          vform.append('file', file, file.name || 'upload.bin');
          const ures = await fetch('https://www.virustotal.com/api/v3/files', { method: 'POST', headers: { 'x-apikey': vtKey }, body: vform });
          const udata = await ures.json();
          if (!ures.ok) return corsResponse(udata, ures.status);
          await auditLog(env, user, 'VT_UPLOAD', { name: file.name || '', size: file.size || 0 });
          return corsResponse({ ok: true, analysisId: udata?.data?.id, name: file.name || '' }, 200);
        } catch (e) { return corsResponse({ error: { message: e.message || '\uC5C5\uB85C\uB4DC \uC2E4\uD328' } }, 502); }
      }
      // VT \uBD84\uC11D \uC0C1\uD0DC \uD3F4\uB9C1 (\uD30C\uC77C \uC5C5\uB85C\uB4DC \uD6C4)
      if (path === '/vt/analysis' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ error: { message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' } }, 401);
        const vtKey = env.VT_KEY || env.VT_API_KEY || '';
        if (!vtKey) return corsResponse({ error: { message: 'VT_KEY \uBBF8\uC124\uC815' } }, 500);
        const id = url.searchParams.get('id') || '';
        if (!id) return corsResponse({ error: { message: 'id \uD544\uC694' } }, 400);
        const ares = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`, { headers: { 'x-apikey': vtKey } });
        const adata = await ares.json();
        return corsResponse(adata, ares.status);
      }

      //
      if (path === '/vt/history' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const history = await getVtHistory(env);
        return corsResponse({ ok: true, history });
      }

      //
      if (path === '/kv/audit' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const limit = Math.max(1, Math.min(100, parseInt(url.searchParams.get('limit') || '50', 10) || 50));
        const filter = url.searchParams.get('filter') || '';
        // §H 3단계: 읽기 D1 우선(app_settings audit_read_d1='on') → D1 비었으면 KV 폴백
        if (await getAuditReadD1(env)) {
          try {
            const q = filter
              ? env.DB.prepare('SELECT ts,ts_num,user,type,detail_json FROM audit_log WHERE type=? ORDER BY ts_num DESC LIMIT ?').bind(filter, limit)
              : env.DB.prepare("SELECT ts,ts_num,user,type,detail_json FROM audit_log WHERE type != 'PAGE_VIEW' ORDER BY ts_num DESC LIMIT ?").bind(limit);
            const r = await q.all();
            const rows = r.results || [];
            if (rows.length) {
              const logs = rows.map(x => ({ ts: x.ts, tsNum: x.ts_num, user: x.user, type: x.type, ...(() => { try { return JSON.parse(x.detail_json || '{}'); } catch { return {}; } })() }));
              return corsResponse(logs);
            }
          } catch (_) {}
        }
        const prefix = 'auditLatest:';
        let list = await env.ENGR_KV.list({ prefix, limit });

        //
        if ((!list.keys || !list.keys.length) && !filter) {
          list = await env.ENGR_KV.list({ prefix: 'audit:', limit });
          list.keys = (list.keys || []).sort((a, b) => b.name.localeCompare(a.name));
        }

        const logs = [];
        for (const key of list.keys || []) {
          if (logs.length >= limit) break;
          const val = await env.ENGR_KV.get(key.name);
          if (!val) continue;
          try {
            const item = JSON.parse(val);
            if (!filter && item.type === 'PAGE_VIEW') continue;
            if (!filter || item.type === filter) logs.push(item);
          } catch (_) {}
        }
        return corsResponse(logs);
      }

      // ── 기능 사용 현황 집계(관리자) : D1 audit_log GROUP BY. 컷 판단용. 읽기전용 ──
      if (path === '/admin/usage/features' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 접근할 수 있습니다.' }, 403);
        const days = Math.max(1, Math.min(365, parseInt(url.searchParams.get('days') || '90', 10) || 90));
        const since = Date.now() - days * 86400000;
        try {
          const byTypeQ = await env.DB.prepare("SELECT type, COUNT(*) AS cnt, MAX(ts_num) AS last, COUNT(DISTINCT user) AS uu FROM audit_log WHERE ts_num >= ? GROUP BY type").bind(since).all();
          const byPageQ = await env.DB.prepare("SELECT json_extract(detail_json,'$.page') AS page, COUNT(*) AS cnt, MAX(ts_num) AS last, COUNT(DISTINCT user) AS uu FROM audit_log WHERE type='PAGE_VIEW' AND ts_num >= ? GROUP BY page").bind(since).all();
          let coverageStart = null; try { const c = await env.DB.prepare("SELECT MIN(ts_num) AS first FROM audit_log").first(); coverageStart = (c && c.first) ? c.first : null; } catch (_) {}
          return corsResponse({
            ok: true, days, since, coverageStart,
            byType: (byTypeQ.results || []).map(r => ({ type: r.type, count: r.cnt, last: r.last, users: r.uu })),
            byPage: (byPageQ.results || []).filter(r => r.page).map(r => ({ page: r.page, count: r.cnt, last: r.last, users: r.uu }))
          });
        } catch (e) { return corsResponse({ ok: false, message: '집계 실패: ' + (e && e.message || e) }, 500); }
      }

      // ── 페이지 방문 비콘(로그인 사용자) : 열람형 기능 사용 측정. 세션당 페이지 1회(클라 스로틀). 감사 기본뷰에선 제외됨 ──
      if (path === '/usage/pageview' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false }, 401);
        const body = await request.json().catch(() => ({}));
        const ALLOWED = ['dash', 'issues', 'cases', 'customers', 'eos', 'log', 'vt', 'links', 'knowledge', 'audit', 'settings', 'mydesk', 'compat', 'nsis', 'monitor', 'sales'];
        const pv = ALLOWED.includes(body.page) ? body.page : null;
        if (!pv) return corsResponse({ ok: false }, 400);
        ctx.waitUntil(auditLog(env, user, 'PAGE_VIEW', { page: pv }));
        return corsResponse({ ok: true });
      }

      // ── §H 감사로그 KV→D1 마이그레이션 (슈퍼) ──
      if (path === '/admin/migrate/audit-status' && request.method === 'GET') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: '슈퍼 관리자만 가능합니다.' }, 403);
        let d1Count = 0; try { const r = await env.DB.prepare('SELECT count(*) AS c FROM audit_log').first(); d1Count = r?.c || 0; } catch (_) {}
        return corsResponse({ ok: true, d1Count, readD1: await getAuditReadD1(env) });
      }
      if (path === '/admin/migrate/audit-backfill' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: '슈퍼 관리자만 가능합니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const prefix = body.prefix === 'audit:' ? 'audit:' : 'auditLatest:';
        const page = await env.ENGR_KV.list({ prefix, cursor: body.cursor || undefined, limit: 100 });
        const keys = page.keys || [];
        const vals = await Promise.all(keys.map(k => env.ENGR_KV.get(k.name).catch(() => null)));
        const stmts = [];
        keys.forEach((k, i) => {
          if (!vals[i]) return;
          let item; try { item = JSON.parse(vals[i]); } catch { return; }
          const id = k.name.replace(/^(auditLatest:|audit:)/, '');
          const tsNum = item.tsNum || Date.parse(item.ts) || 0;
          const { ts, tsNum: _t, user: u, type: ty, ...detail } = item;
          stmts.push(env.DB.prepare('INSERT OR IGNORE INTO audit_log (id,ts,ts_num,user,type,detail_json) VALUES (?,?,?,?,?,?)').bind(id, ts || new Date(tsNum).toISOString(), tsNum, u || '', ty || '', JSON.stringify(detail)));
        });
        let inserted = 0;
        if (stmts.length) { try { const res = await env.DB.batch(stmts); inserted = res.reduce((n, r) => n + (r.meta?.changes || 0), 0); } catch (e) { return corsResponse({ ok: false, message: 'D1 배치 실패: ' + e.message }, 500); } }
        await auditLog(env, user, 'AUDIT_MIGRATE', { migPhase: 'backfill', prefix, scanned: keys.length, inserted });
        return corsResponse({ ok: true, scanned: keys.length, inserted, cursor: page.list_complete ? null : page.cursor, done: !!page.list_complete });
      }
      if (path === '/admin/migrate/audit-readsource' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: '슈퍼 관리자만 가능합니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const v = body.d1 ? 'on' : 'off';
        try { await env.DB.prepare("INSERT INTO app_settings (key,value) VALUES ('audit_read_d1',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(v).run(); }
        catch (e) { return corsResponse({ ok: false, message: '저장 실패: ' + e.message }, 500); }
        await auditLog(env, user, 'AUDIT_MIGRATE', { migPhase: 'readsource', readD1: v });
        return corsResponse({ ok: true, readD1: v === 'on' });
      }

      //
      if (path === '/admin/list' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const admins = await getAdmins(env);
        const users = await getUsers(env);
        const teamNames = Object.keys(users).filter(id => users[id].active !== false);
        const teamUsers = Object.keys(users).sort().map(id => ({
          id,
          displayName: users[id].displayName || id,
          role: users[id].role || admins[id] || 'user',
          active: users[id].active !== false,
        }));
        return corsResponse({ ok: true, admins, teamNames, users: teamUsers });
      }

      if (path === '/admin/users' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const account = await saveUserAccount(env, {
          id: body.id || body.userId,
          displayName: body.displayName,
          role: body.role || 'user',
          active: body.active !== false,
        });
        if (body.initialPin) {
          if (String(body.initialPin).length < 6) return corsResponse({ ok: false, message: '\uCD08\uAE30 PIN\uC740 6\uC790 \uC774\uC0C1\uC774\uC5B4\uC57C \uD569\uB2C8\uB2E4.' }, 400);
          await setUserPin(env, account.id, String(body.initialPin));
        }
        const admins = await getAdmins(env, { skipUsers: true });
        if (account.role === 'admin' || account.role === 'super') admins[account.id] = account.role;
        else delete admins[account.id];
        admins[SUPER_ADMIN] = 'super';
        await env.ENGR_KV.put('config:admins', JSON.stringify(admins));
        await auditLog(env, user, 'USER_SAVE', { target: account.id, role: account.role });
        return corsResponse({ ok: true, user: account });
      }

      if (path.startsWith('/admin/users/') && request.method === 'DELETE') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const target = decodeURIComponent(path.split('/')[3] || '');
        const urlObj = new URL(request.url);
        const purge = urlObj.searchParams.get('purge') === 'true';
        try {
          if (purge) {
            const deletedId = await purgeUserAccount(env, target);
            await auditLog(env, user, 'USER_PURGE', { target: deletedId });
            return corsResponse({ ok: true, user: deletedId, purged: true });
          } else {
            const account = await deactivateUserAccount(env, target);
            if (!account) return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 404);
            await auditLog(env, user, 'USER_DISABLE', { target: account.id });
            return corsResponse({ ok: true, user: account.id, active: false });
          }
        } catch (e) {
          return corsResponse({ ok: false, message: e.message || '\uC0AC\uC6A9\uC790 \uCC98\uB9AC \uC2E4\uD328' }, 400);
        }
      }

      //
      if (path === '/admin/update' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const { action, user: targetUser, role: newRole } = body;
        const targetId = normalizeUserId(targetUser);

        // Team ID validation
        const teamNames = getTeamNames(env);
        if (action === 'add' && teamNames.length && !teamNames.includes(targetId)) {
          return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 400);
        }

        const admins = await getAdmins(env);
        const users = await getUsers(env);
        if (!targetId || !users[targetId]) return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 400);

        if (action === 'add') {
          if (targetId === SUPER_ADMIN) {
            return corsResponse({ ok: false, message: '\uCD5C\uACE0 \uAD00\uB9AC\uC790\uB294 \uBCC0\uACBD\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 400);
          }
          admins[targetId] = (newRole === 'super') ? 'super' : 'admin';
        } else if (action === 'remove') {
          if (targetId === SUPER_ADMIN) {
            return corsResponse({ ok: false, message: '\uCD5C\uACE0 \uAD00\uB9AC\uC790\uB294 \uD68C\uC218\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 403);
          }
          delete admins[targetId];
        } else if (action === 'changeRole') {
          if (targetId === SUPER_ADMIN) {
            return corsResponse({ ok: false, message: '\uCD5C\uACE0 \uAD00\uB9AC\uC790\uB294 \uBCC0\uACBD\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 400);
          }
          if (!admins[targetId]) {
            return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB418\uC9C0 \uC54A\uC740 \uAD00\uB9AC\uC790\uC785\uB2C8\uB2E4.' }, 400);
          }
          admins[targetId] = (newRole === 'super') ? 'super' : 'admin';
        }

        // H-4: getAdmins가 config:users의 role을 우선 사용하므로, config:users도 동기화해야 강등/승급이 실제 적용됨
        if (users[targetId]) {
          const syncRole = action === 'remove' ? 'user' : ((newRole === 'super') ? 'super' : 'admin');
          await saveUserAccount(env, { id: targetId, displayName: users[targetId].displayName, role: syncRole, active: users[targetId].active !== false });
        }
        await env.ENGR_KV.put('config:admins', JSON.stringify(admins));
        await auditLog(env, user, 'ADMIN_CHANGE', { action, target: targetId, role: newRole });
        return corsResponse({ ok: true, admins });
      }

      //
      if (path === '/admin/config' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const rangeMonths = await env.ENGR_KV.get('config:range_months') || '3';
        const sessionMin = await env.ENGR_KV.get('config:session_min') || '120';
        const eosWarnDays = await env.ENGR_KV.get('config:eos_warn_days') || '60,30,7';
        const salesStaleDays = await getSalesStaleDays(env);
        return corsResponse({
          ok: true,
          rangeMonths: parseInt(rangeMonths),
          sessionMin: parseInt(sessionMin),
          eosWarnDays,
          salesStaleDays,
        });
      }
      if (path === '/admin/config' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        if (body.rangeMonths !== undefined) await env.ENGR_KV.put('config:range_months', String(body.rangeMonths));
        if (body.sessionMin !== undefined) await env.ENGR_KV.put('config:session_min', String(body.sessionMin));
        if (body.eosWarnDays !== undefined) await env.ENGR_KV.put('config:eos_warn_days', body.eosWarnDays);
        if (body.salesStaleDays !== undefined) await env.ENGR_KV.put('config:sales_stale_days', String(parseInt(body.salesStaleDays,10)||14));
        await auditLog(env, user, 'CONFIG_CHANGE', { keys: Object.keys(body) });
        return corsResponse({ ok: true });
      }

      //
      

      if (path === '/admin/storage/reset' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        if (!body.pin || !await validateUserPin(env, user, body.pin)) return corsResponse({ ok: false, message: 'PIN \uD655\uC778\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4.' }, 401);
        const result = await resetHubData(env);
        await auditLog(env, user, 'HUB_DATA_RESET', { deleted: result.deleted, truncated: result.truncated });
        return corsResponse(result);
      }

      if (path === '/admin/user-pin/reset' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const target = normalizeUserId(body.user || '');
        if (!target) return corsResponse({ ok: false, message: '\uB300\uC0C1 \uC0AC\uC6A9\uC790\uB97C \uC120\uD0DD\uD558\uC138\uC694.' }, 400);
        const account = await getUserAccount(env, target);
        if (!account) return corsResponse({ ok: false, message: '\uB4F1\uB85D\uB41C \uACC4\uC815\uC774 \uC544\uB2D9\uB2C8\uB2E4.' }, 400);
        const resetPin = getDefaultResetPin(env);
        if (!resetPin) return corsResponse({ ok: false, message: 'DEFAULT_RESET_PIN is not configured.' }, 500);
        await setUserPin(env, target, resetPin);
        await revokeUserSessions(env, target);  // L-3: PIN 리셋 시 대상의 기존 세션 무효화(재인증 강제)
        await auditLog(env, user, 'PIN_RESET', { target });
        return corsResponse({ ok: true, user: target });
      }

      //
      if (path === '/admin/storage/stats' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        return corsResponse(await getStorageStats(env));
      }

      //
      if (path === '/admin/storage/backup' && request.method === 'GET') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const backup = await buildHubBackup(env, user);
        await auditLog(env, user, 'HUB_BACKUP_EXPORT', { keys: Object.keys(backup.data || {}) });
        return corsResponse(backup);
      }

      //
      if (path === '/admin/storage/cleanup' && request.method === 'POST') {
        if (!hasSession || !await isSuper(env, user)) return corsResponse({ ok: false, message: 'Forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        if (body.target !== 'audit-old') return corsResponse({ ok: false, message: '\uC9C0\uC6D0\uD558\uC9C0 \uC54A\uB294 \uC815\uB9AC \uB300\uC0C1\uC785\uB2C8\uB2E4.' }, 400);
        const days = Math.max(1, Math.min(3650, parseInt(body.days || '90', 10) || 90));
        const max = Math.max(50, Math.min(1000, parseInt(body.max || '500', 10) || 500));
        const dryRun = body.dryRun !== false;
        const result = await cleanupOldAudit(env, days, dryRun, max);
        if (!dryRun) await auditLog(env, user, 'AUDIT_CLEANUP', { days, scanned: result.scanned, deleted: result.deleted, truncated: result.truncated });
        return corsResponse(result);
      }

      //
      if (path === '/links' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const raw = await env.ENGR_KV.get('config:links');
        return corsResponse({ ok: true, links: raw ? JSON.parse(raw) : [] });
      }
      //
      if (path === '/links' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const newLink = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          title: body.title || '',
          url: body.url || '',
          category: body.category || '\uAE30\uD0C0',
          desc: body.desc || '',
          comments: [],
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        links.push(newLink);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_ADD', { title: newLink.title });
        ctx.waitUntil(pushNotify(env, 'link', user, { target: newLink.title || '제목 없음' }));
        return corsResponse({ ok: true, link: newLink });
      }
      if (path.match(/^\/links\/[^/]+\/comments(?:\/[^/]+)?$/)) {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const parts = path.split('/');
        const id = decodeURIComponent(parts[2] || '');
        if (request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const result = await addCollectionComment(env, 'config:links', id, user, body.text, 'LINK_COMMENT_ADD');
          return corsResponse(result.body, result.status);
        }
        if (request.method === 'DELETE') {
          const commentId = decodeURIComponent(parts[4] || '');
          const result = await deleteCollectionComment(env, 'config:links', id, commentId, user, 'LINK_COMMENT_DELETE');
          return corsResponse(result.body, result.status);
        }
      }
      //
      if (/^\/links\/[^/]+$/.test(path) && request.method === 'PUT') {  // L-8: /links/{id}/comments \uD761\uC218 \uBC29\uC9C0(\uC815\uD655 \uB9E4\uCE6D)
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const target = links.find(l => l.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const lf = {}; ['title', 'url', 'category', 'desc'].forEach(k => { if (body[k] !== undefined) lf[k] = body[k]; });  // M-3: 허용 필드만(createdBy/createdAt/comments 보존)
        links = links.map(l => l.id === id ? { ...l, ...lf, id, updatedBy: user, updatedAt: new Date().toISOString() } : l);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_UPDATE', { id, title: body.title });
        return corsResponse({ ok: true });
      }

      //
      if (/^\/links\/[^/]+$/.test(path) && request.method === 'DELETE') {  // L-8: /links/{id}/comments \uD761\uC218 \uBC29\uC9C0(\uC815\uD655 \uB9E4\uCE6D)
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);
        const raw = await env.ENGR_KV.get('config:links');
        let links = raw ? JSON.parse(raw) : [];
        const delLink = links.find(l => l.id === id);
        if (!await canModifyItem(env, user, delLink)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const before = links.length;
        links = links.filter(l => l.id !== id);
        await env.ENGR_KV.put('config:links', JSON.stringify(links));
        await auditLog(env, user, 'LINK_DELETE', { id, title: delLink?.title });
        return corsResponse({ ok: true, deleted: before - links.length });
      }

      //
      if (path === '/knowledge' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const raw = await env.ENGR_KV.get('config:knowledge');
        return corsResponse({ ok: true, items: raw ? JSON.parse(raw) : [] });
      }
      //
      // \u2500\u2500 My Desk \uAC1C\uC778 \uB370\uC774\uD130 (\uC0AC\uC6A9\uC790\uBCC4, \uAE30\uAE30 \uAC04 \uB3D9\uAE30\uD654) \u2500\u2500
      if (path === '/mydesk' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        let store = {};
        try { const raw = await env.ENGR_KV.get(`mydesk:${user}`); if (raw) store = JSON.parse(raw); } catch (_) {}
        return corsResponse({ ok: true, data: store });
      }
      if (path === '/mydesk' && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const store = (body && body.store && typeof body.store === 'object') ? body.store : {};
        try { await env.ENGR_KV.put(`mydesk:${user}`, JSON.stringify(store)); }
        catch (e) { return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328' }, 500); }
        return corsResponse({ ok: true });
      }
      if (path === '/mydesk' && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        try { await env.ENGR_KV.delete(`mydesk:${user}`); } catch (_) {}
        return corsResponse({ ok: true });
      }
      // \u2500\u2500 Web Push \u2500\u2500
      if (path === '/push/public-key' && request.method === 'GET') {
        return corsResponse({ ok: true, publicKey: env.VAPID_PUBLIC_KEY || '', configured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_JWK) });
      }
      if (path === '/push/subscribe' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const sub = body.subscription;
        if (!sub || !sub.endpoint) return corsResponse({ ok: false, message: '\uAD6C\uB3C5 \uC815\uBCF4\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4.' }, 400);
        const subs = await getPushSubs(env);
        const list = (subs[user] || []).filter(s => s.endpoint !== sub.endpoint);
        list.push({ endpoint: sub.endpoint, keys: sub.keys || {}, ua: (request.headers.get('user-agent') || '').slice(0, 140), ts: Date.now() });
        subs[user] = list;
        await savePushSubs(env, subs);
        await env.ENGR_KV.put('push:pref:' + user, JSON.stringify({ enabled: true }));
        return corsResponse({ ok: true });
      }
      if (path === '/push/unsubscribe' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const subs = await getPushSubs(env);
        if (subs[user]) {
          if (body.endpoint) subs[user] = subs[user].filter(s => s.endpoint !== body.endpoint);
          else delete subs[user];
          if (subs[user] && !subs[user].length) delete subs[user];
          await savePushSubs(env, subs);
        }
        await env.ENGR_KV.put('push:pref:' + user, JSON.stringify({ enabled: false }));
        return corsResponse({ ok: true });
      }
      if (path === '/push/pending' && request.method === 'POST') {
        // \uC11C\uBE44\uC2A4\uC6CC\uCEE4\uAC00 \uD638\uCD9C: \uC5D4\uB4DC\uD3EC\uC778\uD2B8 \uC18C\uC720 \uC99D\uBA85\uB9CC\uC73C\uB85C \uBCF4\uB958 \uC54C\uB9BC \uC218\uB839 \uD6C4 \uBE44\uC6C0(\uC138\uC158 \uBD88\uD544\uC694)
        const body = await request.json().catch(() => ({}));
        if (!body.endpoint) return corsResponse({ ok: false, items: [] }, 400);
        const pk = 'push:pending:' + await endpointHash(body.endpoint);
        let pend = []; try { const r = await env.ENGR_KV.get(pk); if (r) pend = JSON.parse(r); } catch (_) {}
        if (pend.length) await env.ENGR_KV.delete(pk);
        return corsResponse({ ok: true, items: pend });
      }
      if (path === '/push/pref' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        let pref = { enabled: true }; try { const r = await env.ENGR_KV.get('push:pref:' + user); if (r) pref = JSON.parse(r); } catch (_) {}
        const subs = await getPushSubs(env);
        return corsResponse({ ok: true, enabled: pref.enabled !== false, subscribed: !!(subs[user] && subs[user].length), configured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_JWK) });
      }
      if (path === '/push/pref' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        await env.ENGR_KV.put('push:pref:' + user, JSON.stringify({ enabled: body.enabled !== false }));
        return corsResponse({ ok: true });
      }
      if (path === '/push/test' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const subs = await getPushSubs(env);
        const list = subs[user] || [];
        if (!list.length) return corsResponse({ ok: false, message: '\uC774 \uAE30\uAE30\uC5D0\uC11C \uBA3C\uC800 \uC54C\uB9BC\uC744 \uCF1C\uC8FC\uC138\uC694.' }, 400);
        const payload = { title: '\uD83D\uDD14 \uD14C\uC2A4\uD2B8 \uC54C\uB9BC', body: '\uC54C\uB9BC\uC774 \uC815\uC0C1 \uB3D9\uC791\uD569\uB2C8\uB2E4.', page: 'mydesk', ts: Date.now(), tag: 'test' };
        let sent = 0, gone = 0, changed = false;
        for (const s of list) {
          try {
            const st = await sendWebPush(env, s);
            if (st >= 200 && st < 300) { sent++; try { await enqueuePending(env, s.endpoint, payload); } catch (_) {} }  // L-28: 성공 시에만 pending
            else if (st === 404 || st === 410) { gone++; subs[user] = (subs[user] || []).filter(x => x.endpoint !== s.endpoint); changed = true; }  // L-27: 만료 endpoint 제거
          } catch (_) {}
        }
        if (subs[user] && !subs[user].length) { delete subs[user]; changed = true; }
        if (changed) await savePushSubs(env, subs);
        return corsResponse({ ok: true, sent, gone });
      }
      if (path === '/push/send' && request.method === 'POST') {
        // 관리자: 선택한 인원에게 직접 알림 발송
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 사용할 수 있습니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const title = String(body.title || '').slice(0, 80).trim();
        const text = String(body.body || '').slice(0, 300).trim();
        const page = String(body.page || '').slice(0, 40);
        const includeMuted = !!body.includeMuted;
        const recipients = Array.isArray(body.recipients) ? [...new Set(body.recipients.map(normalizeUserId).filter(Boolean))] : [];
        if (!title && !text) return corsResponse({ ok: false, message: '제목 또는 내용을 입력하세요.' }, 400);
        if (!recipients.length) return corsResponse({ ok: false, message: '받을 사람을 선택하세요.' }, 400);
        const subs = await getPushSubs(env);
        const payload = { title: title || '📢 알림', body: text, page, ts: Date.now(), tag: 'admin-msg', from: user };
        let sent = 0, changed = false; const skipped = [];
        for (const uid of recipients) {
          if (!includeMuted) {
            let pref = {}; try { const pr = await env.ENGR_KV.get('push:pref:' + uid); if (pr) pref = JSON.parse(pr); } catch (_) {}
            if (pref.enabled === false) { skipped.push(uid); continue; }
          }
          const list = subs[uid] || [];
          if (!list.length) { skipped.push(uid); continue; }
          for (const s of list) {
            try { await enqueuePending(env, s.endpoint, payload); } catch (_) {}
            try { const st = await sendWebPush(env, s); if (st >= 200 && st < 300) sent++; else if (st === 404 || st === 410) { subs[uid] = (subs[uid] || []).filter(x => x.endpoint !== s.endpoint); changed = true; } } catch (_) {}
          }
          if (subs[uid] && !subs[uid].length) { delete subs[uid]; changed = true; }
        }
        if (changed) await savePushSubs(env, subs);
        await auditLog(env, user, 'PUSH_SEND', { count: sent, to: recipients.length, skipped: skipped.length, title: title || '(제목없음)' });
        return corsResponse({ ok: true, sent, skipped });
      }
      if (path === '/push/settings' && request.method === 'GET') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const settings = await getPushSettings(env);
        const subs = await getPushSubs(env);
        const subscribers = [];
        for (const u of Object.keys(subs)) {
          let pf = {}; try { const pr = await env.ENGR_KV.get('push:pref:' + u); if (pr) pf = JSON.parse(pr); } catch (_) {}
          if (pf.enabled === false) continue;   // 알림 끈 사용자는 발송 대상이 아니므로 목록에서 제외
          subscribers.push({ id: u, devices: (subs[u] || []).length });
        }
        return corsResponse({ ok: true, settings, subscribers, configured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_JWK) });
      }
      if (path === '/push/settings' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC811\uADFC\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const body = await request.json().catch(() => ({}));
        const cur = await getPushSettings(env);
        const events = {};
        for (const k of Object.keys(PUSH_EVENTS)) {
          const inc = (body.events && body.events[k]) || {};
          const base = cur.events[k];
          events[k] = {
            enabled: inc.enabled !== undefined ? !!inc.enabled : base.enabled,
            title: inc.title !== undefined ? String(inc.title).slice(0, 80) : base.title,
            body: inc.body !== undefined ? String(inc.body).slice(0, 160) : base.body,
          };
        }
        const include = Array.isArray(body.include) ? body.include.map(normalizeUserId).filter(Boolean) : cur.include;
        const exclude = Array.isArray(body.exclude) ? body.exclude.map(normalizeUserId).filter(Boolean) : cur.exclude;
        await env.ENGR_KV.put('push:settings', JSON.stringify({ events, include, exclude }));
        await auditLog(env, user, 'PUSH_SETTINGS_CHANGE', { keys: Object.keys(body) });
        return corsResponse({ ok: true });
      }
      //
      if (path === '/knowledge' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const newItem = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          product: body.product || '\uAE30\uD0C0',
          category: body.category || '\uD301',
          title: body.title || '',
          content: body.content || '',
          link: body.link || '',
          comments: [],
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        items.push(newItem);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_ADD', { product: newItem.product, title: newItem.title });
        ctx.waitUntil(pushNotify(env, 'knowledge', user, { target: newItem.title || newItem.product || '노하우' }));
        return corsResponse({ ok: true, item: newItem });
      }
      if (path.match(/^\/knowledge\/[^/]+\/comments(?:\/[^/]+)?$/)) {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const parts = path.split('/');
        const id = decodeURIComponent(parts[2] || '');
        if (request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const result = await addCollectionComment(env, 'config:knowledge', id, user, body.text, 'KNOWLEDGE_COMMENT_ADD');
          return corsResponse(result.body, result.status);
        }
        if (request.method === 'DELETE') {
          const commentId = decodeURIComponent(parts[4] || '');
          const result = await deleteCollectionComment(env, 'config:knowledge', id, commentId, user, 'KNOWLEDGE_COMMENT_DELETE');
          return corsResponse(result.body, result.status);
        }
      }
      //
      if (path.startsWith('/knowledge/') && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);  // L-10: \uB313\uAE00 \uB77C\uC6B0\uD2B8\uC640 \uB514\uCF54\uB529 \uD1B5\uC77C
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const kf = {}; ['product', 'category', 'title', 'content', 'link'].forEach(k => { if (body[k] !== undefined) kf[k] = body[k]; });  // M-4: 허용 필드만(createdBy/createdAt/comments 보존)
        items = items.map(it => it.id === id ? { ...it, ...kf, id, updatedBy: user, updatedAt: new Date().toISOString() } : it);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_UPDATE', { id, title: body.title || target?.title });
        return corsResponse({ ok: true });
      }
      //
      if (path.startsWith('/knowledge/') && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = decodeURIComponent(path.split('/')[2]);  // L-10: \uB313\uAE00 \uB77C\uC6B0\uD2B8\uC640 \uB514\uCF54\uB529 \uD1B5\uC77C
        const raw = await env.ENGR_KV.get('config:knowledge');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        items = items.filter(it => it.id !== id);
        await env.ENGR_KV.put('config:knowledge', JSON.stringify(items));
        await auditLog(env, user, 'KNOWLEDGE_DELETE', { id, title: target?.title });
        return corsResponse({ ok: true });
      }

      //
      if (path === '/eos' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        let eosItems = [];
        try { const raw = await env.ENGR_KV.get('config:eos'); if (raw) eosItems = JSON.parse(raw); } catch (_) {}
        return corsResponse({ ok: true, items: eosItems });
      }
      //
      if (path === '/eos' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const newItem = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
          customer: body.customer || '',
          productDesc: body.productDesc || '',
          siteId: body.siteId || '',
          quantity: body.quantity || '',
          serial: body.serial || '',
          startDate: okDate(body.startDate),
          expireDate: okDate(body.expireDate),   // End Date (지원/만료 종료일 — D-day 기준)
          memo: body.memo || '',
          createdBy: user,
          createdAt: new Date().toISOString(),
        };
        items.push(newItem);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_ADD', { customer: newItem.customer, product: newItem.productDesc, expire: newItem.expireDate });
        ctx.waitUntil(pushNotify(env, 'eos', user, { target: [newItem.productDesc, newItem.customer].filter(Boolean).join(' / ') || '라이선스' }));
        return corsResponse({ ok: true, item: newItem });
      }
      if (path === '/eos/bulk' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const body = await request.json().catch(() => ({}));
        const items = Array.isArray(body.items) ? body.items : [];
        if (!items.length) return corsResponse({ ok: false, message: '등록할 항목이 없습니다.' }, 400);
        if (items.length > 200) return corsResponse({ ok: false, message: '한 번에 최대 200건까지 등록할 수 있습니다.' }, 400);  // M-8: KV 비대화 방지
        const raw = await env.ENGR_KV.get('config:eos');
        let store = raw ? JSON.parse(raw) : [];
        const created = [];
        for (const b of items) {
          if (!b || !b.productDesc) continue;
          const it = {
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            customer: b.customer || '', productDesc: b.productDesc || '', siteId: b.siteId || '',
            quantity: b.quantity || '', serial: b.serial || '', startDate: okDate(b.startDate),
            expireDate: okDate(b.expireDate), memo: b.memo || '', createdBy: user, createdAt: new Date().toISOString(),
          };
          store.push(it); created.push(it);
        }
        if (!created.length) return corsResponse({ ok: false, message: 'Product Description이 있는 항목이 없습니다.' }, 400);
        await env.ENGR_KV.put('config:eos', JSON.stringify(store));
        await auditLog(env, user, 'EOS_ADD_BULK', { count: created.length, customer: created[0].customer });
        const cust = created[0].customer || '';
        const tgt = created.length > 1 ? `${cust} ${created[0].productDesc} 외 ${created.length - 1}건` : [created[0].productDesc, cust].filter(Boolean).join(' / ');
        ctx.waitUntil(pushNotify(env, 'eos', user, { target: tgt }));
        return corsResponse({ ok: true, created: created.length, items: created });
      }
      //
      if (path.startsWith('/eos/') && request.method === 'DELETE') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const before = items.length;
        items = items.filter(it => it.id !== id);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_DELETE', { id });
        return corsResponse({ ok: true, deleted: before - items.length });
      }
      //
      if (path.startsWith('/eos/') && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const id = path.split('/')[2];
        const body = await request.json().catch(() => ({}));
        const raw = await env.ENGR_KV.get('config:eos');
        let items = raw ? JSON.parse(raw) : [];
        const target = items.find(it => it.id === id);
        if (!await canModifyItem(env, user, target)) return corsResponse({ ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC218\uC815\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const ef = {}; ['customer', 'productDesc', 'siteId', 'quantity', 'serial', 'memo'].forEach(k => { if (body[k] !== undefined) ef[k] = body[k]; });  // M-3/M-7: 허용필드+날짜검증
        if (body.startDate !== undefined) ef.startDate = okDate(body.startDate);
        if (body.expireDate !== undefined) ef.expireDate = okDate(body.expireDate);
        items = items.map(it => it.id === id ? { ...it, ...ef, id, updatedBy: user, updatedAt: new Date().toISOString() } : it);
        await env.ENGR_KV.put('config:eos', JSON.stringify(items));
        await auditLog(env, user, 'EOS_UPDATE', { id, customer: target?.customer, product: body.productDesc || target?.productDesc, expire: body.expireDate || target?.expireDate });
        return corsResponse({ ok: true });
      }


      // \u2500\u2500 \u00A75 \uAE30\uB2A5 \uD1A0\uAE00 (feature_flags \u00B7 app_settings) \u2500\u2500
      if (path === '/features' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        return corsResponse({ ok: true, flags: await getFeatureFlags(env), monAllowed: await isMonitorAllowed(env, user) });
      }
      if (path === '/features' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const b = await request.json().catch(() => ({}));
        const next = { ...await getFeatureFlags(env), ...(b.flags || {}) };
        next.settings = true; next.dash = true;  // L-6: 보호 토글(설정·대시보드)은 서버에서 강제 ON — 클라 가드 의존 제거
        try { await env.DB.prepare("INSERT INTO app_settings (key,value) VALUES ('feature_flags',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(JSON.stringify(next)).run(); }
        catch (e) { return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328: ' + e.message }, 500); }
        await auditLog(env, user, 'FEATURE_TOGGLE', { featFlags: next });
        return corsResponse({ ok: true, flags: next });
      }

      // \u2500\u2500 \u00A71 \uD638\uD658\uC131\u00B7EOS \uB9E4\uD2B8\uB9AD\uC2A4 (compat_matrix \u00B7 D1) \u2500\u2500
      if (path === '/compat' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        const q = (new URL(request.url).searchParams.get('q') || '').trim().toLowerCase();
        let rows = [];
        try { const r = await env.DB.prepare('SELECT * FROM compat_matrix ORDER BY product, product_version, os').all(); rows = r.results || []; } catch (_) {}
        if (q) rows = rows.filter(x => [x.product, x.product_version, x.os, x.os_version, x.note, x.supported].some(v => (v || '').toLowerCase().includes(q)));
        return corsResponse({ ok: true, items: rows });
      }
      if (path === '/compat' && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);  // L-11
        const b = await request.json().catch(() => ({}));
        const now = new Date().toISOString();
        try {
          const r = await env.DB.prepare('INSERT INTO compat_matrix (product,product_version,os,os_version,supported,eos_date,eol_date,note,source,status,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
            .bind(b.product || '', b.product_version || '', b.os || '', b.os_version || '', b.supported || '', b.eos_date || '', b.eol_date || '', b.note || '', b.source || '', 'draft', now).run();
          await auditLog(env, user, 'MATRIX_ADD', { matrixType: 'compat', product: b.product || '', os: b.os || '' });
          return corsResponse({ ok: true, id: r.meta?.last_row_id });
        } catch (e) { return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328: ' + e.message }, 500); }
      }
      
      if (path.startsWith('/compat/') && path.endsWith('/confirm') && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);  // L-11
        const id = parseInt(path.split('/')[2]) || 0;
        if (!(id > 0)) return corsResponse({ ok: false, message: '잘못된 id 입니다.' }, 400);
        try { await env.DB.prepare("UPDATE compat_matrix SET status='confirmed', verified_by=?, verified_at=? WHERE id=?").bind(user, new Date().toISOString(), id).run(); await auditLog(env, user, 'MATRIX_CONFIRM', { matrixType: 'compat', id }); return corsResponse({ ok: true }); }
        catch (e) { return corsResponse({ ok: false, message: e.message }, 500); }
      }
      if (/^\/compat\/\d+$/.test(path) && request.method === 'PUT') {  // L-12: /compat/{id}/confirm 흡수 방지(정확 매칭)
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '비활성화된 기능입니다.' }, 403);  // L-11
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const id = parseInt(path.split('/')[2]) || 0;
        if (!(id > 0)) return corsResponse({ ok: false, message: '잘못된 id 입니다.' }, 400);
        const b = await request.json().catch(() => ({}));
        try {
          await env.DB.prepare('UPDATE compat_matrix SET product=?,product_version=?,os=?,os_version=?,supported=?,eos_date=?,eol_date=?,note=?,source=?,updated_at=? WHERE id=?')
            .bind(b.product || '', b.product_version || '', b.os || '', b.os_version || '', b.supported || '', b.eos_date || '', b.eol_date || '', b.note || '', b.source || '', new Date().toISOString(), id).run();
          await auditLog(env, user, 'MATRIX_UPDATE', { matrixType: 'compat', id });
          return corsResponse({ ok: true });
        } catch (e) { return corsResponse({ ok: false, message: e.message }, 500); }
      }
      if (/^\/compat\/\d+$/.test(path) && request.method === 'DELETE') {  // L-12: /compat/{id}/confirm 흡수 방지(정확 매칭)
        if (!(await getFeatureFlags(env)).compat) return corsResponse({ ok: false, message: '비활성화된 기능입니다.' }, 403);  // L-11
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '\uAD00\uB9AC\uC790\uB9CC \uC0AC\uC6A9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' }, 403);
        const id = parseInt(path.split('/')[2]) || 0;
        if (!(id > 0)) return corsResponse({ ok: false, message: '잘못된 id 입니다.' }, 400);
        try { await env.DB.prepare('DELETE FROM compat_matrix WHERE id=?').bind(id).run(); await auditLog(env, user, 'MATRIX_DELETE', { matrixType: 'compat', id }); return corsResponse({ ok: true }); }
        catch (e) { return corsResponse({ ok: false, message: e.message }, 500); }
      }

      // \u2500\u2500 F2/F3 JQL \uC804\uC6A9 \uC5D4\uB4DC\uD3EC\uC778\uD2B8 (Phase 0 \uACE8\uACA9, \uB85C\uC9C1\uC740 \u00A72/\u00A73\uC5D0\uC11C \uD655\uC7A5) \u2500\u2500
      if (path === '/team/history' && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).history) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        const body = await request.json().catch(() => ({}));
        const df = (body.dateField === 'updated') ? 'updated' : 'created';
        const parts = ['project = ENGR'];
        if (/^\d{4}-\d{2}-\d{2}$/.test(body.from || '')) parts.push(`${df} >= "${body.from}"`);
        if (/^\d{4}-\d{2}-\d{2}$/.test(body.to || '')) parts.push(`${df} <= "${body.to} 23:59"`);
        if (body.customer) parts.push(`text ~ "${jqlTextEsc(body.customer)}"`);  // L-14   // summary~만이면 점검 등 요약 외 위치 누락 → text(요약+설명+댓글+텍스트필드)로 포함
        if (body.product) parts.push(`labels = "${jqlEsc(body.product)}"`);
        if (body.status) parts.push(`status = "${jqlEsc(body.status)}"`);
        if (body.type === 'subtask') parts.push('issuetype = "\uD558\uC704 \uC791\uC5C5"');
        else if (body.type === 'task') parts.push('issuetype = "\uC791\uC5C5"');
        const jql = parts.join(' AND ') + ` ORDER BY ${df} DESC`;
        let issues; try { issues = await jiraSearchJql(env, jql, TEAM_FIELDS, 10); } catch (e) { return corsResponse({ ok: false, message: 'Jira \uC870\uD68C \uC2E4\uD328: ' + e.message }, 502); }
        const custList = await getCustomersD1(env);
        let items = issues.map(it => mapJiraIssue(it, custList));
        // \uACE0\uAC1D\uC0AC \uD544\uD130\uB294 JQL(summary ~ "\uACE0\uAC1D\uC0AC")\uC774 \uC774\uBBF8 \uCC98\uB9AC. \uBE0C\uB798\uD0B7 \uC815\uBC00 \uC7AC\uD544\uD130\uB294 \uC815\uB2F9 \uC774\uC288\uB97C \uC870\uC6A9\uD788 \uB204\uB77D\uC2DC\uCF1C \uC81C\uAC70(\uBD84\uB958\uB294 cls \uBC30\uC9C0\uB85C\uB9CC \uD45C\uC2DC).
        if (body.assignee) items = items.filter(x => x.assignee === body.assignee);   // \uB2F4\uB2F9\uC790 \uD6C4\uCC98\uB9AC(\u00A72\uC5D0\uC11C accountId \uB9E4\uD551 \uC608\uC815)
        await auditLog(env, user, 'HIST_VIEW', { histType: 'history', count: items.length });
        return corsResponse({ ok: true, jql, count: items.length, items });
      }
      if ((path === '/team/daily' || path === '/team/weekly') && request.method === 'POST') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).monitor) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        const isDaily = path === '/team/daily';
        if (!await isMonitorAllowed(env, user)) { await auditLog(env, user, 'MON_VIEW', { monType: isDaily ? 'daily' : 'weekly', denied: true }); return corsResponse({ ok: false, message: '\uC811\uADFC \uAD8C\uD55C\uC774 \uC5C6\uC2B5\uB2C8\uB2E4(\uD300 \uBAA8\uB2C8\uD130 \uD5C8\uC6A9\uBAA9\uB85D).' }, 403); }
        const body = await request.json().catch(() => ({}));
        let jql, meta;
        if (isDaily) {
          const day = /^\d{4}-\d{2}-\d{2}$/.test(body.day || '') ? body.day : new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10);  // M-6: 기본 '오늘'을 KST 기준으로(cron과 일치)
          jql = `project = ENGR AND updated >= "${day}" AND updated < "${nextDayStr(day)}" ORDER BY updated DESC`;
          meta = { monType: 'daily', day };
        } else {
          const days = Math.max(1, Math.min(31, parseInt(body.days) || 7));
          jql = `project = ENGR AND updated >= "-${days}d" ORDER BY updated DESC`;
          meta = { monType: 'weekly', days };
        }
        let issues; try { issues = await jiraSearchJql(env, jql, TEAM_FIELDS, 12); } catch (e) { return corsResponse({ ok: false, message: 'Jira \uC870\uD68C \uC2E4\uD328: ' + e.message }, 502); }
        const custList = await getCustomersD1(env);
        const items = issues.map(it => mapJiraIssue(it, custList));
        await auditLog(env, user, 'MON_VIEW', { ...meta, count: items.length });
        return corsResponse({ ok: true, ...meta, count: items.length, items });
      }

      // \u2500\u2500 \u00A73 \uD300 \uBAA8\uB2C8\uD130 \uC2A4\uB0C5\uC0F7 \uC870\uD68C (mj.park) \u2500\u2500
      if (path === '/team/snapshot' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        if (!(await getFeatureFlags(env)).monitor) return corsResponse({ ok: false, message: '\uBE44\uD65C\uC131\uD654\uB41C \uAE30\uB2A5\uC785\uB2C8\uB2E4.' }, 403);
        if (!await isMonitorAllowed(env, user)) { await auditLog(env, user, 'MON_VIEW', { monType: 'snapshot', denied: true }); return corsResponse({ ok: false, message: '\uC811\uADFC \uAD8C\uD55C\uC774 \uC5C6\uC2B5\uB2C8\uB2E4(\uD300 \uBAA8\uB2C8\uD130 \uD5C8\uC6A9\uBAA9\uB85D).' }, 403); }
        let snap = null;
        try { const r = await env.DB.prepare('SELECT day,payload_json,built_at FROM team_daily_snapshot ORDER BY day DESC LIMIT 1').first(); if (r && r.payload_json) snap = { day: r.day, built_at: r.built_at, ...JSON.parse(r.payload_json) }; } catch (_) {}
        await auditLog(env, user, 'MON_VIEW', { monType: 'snapshot', count: snap?.count || 0 });
        return corsResponse({ ok: true, snapshot: snap });
      }

      // \u2500\u2500 \uC2A4\uCF00\uC904 \uBD84\uC11D \uC5D4\uC9C4(B\uC548) \uACB0\uACFC \uC800\uC7A5/\uC870\uD68C : Claude \uC5D0\uC774\uC804\uD2B8\uAC00 \uC4F0\uACE0 \uD300\uC6D0\uC740 \uBDF0\uB9CC \u2500\u2500
      if (path === '/analysis' && request.method === 'PUT') {
        const tok = request.headers.get('x-analysis-token') || '';
        if (!env.ANALYSIS_WRITE_TOKEN || tok !== env.ANALYSIS_WRITE_TOKEN) return corsResponse({ ok: false, message: '\uC778\uC99D \uC2E4\uD328' }, 401);
        const body = await request.json().catch(() => null);
        if (!body || !body.built_at || !body.day) return corsResponse({ ok: false, message: 'built_at/day \uD544\uC694' }, 400);
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS analysis_snapshot (kind TEXT NOT NULL, built_at INTEGER NOT NULL, day TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY (kind, built_at))").run();
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS issue_analysis (issue_key TEXT NOT NULL, built_at INTEGER NOT NULL, day TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY (issue_key, built_at))").run();
          const builtAt = Number(body.built_at); const day = String(body.day).slice(0, 10);
          let issueN = 0;
          if (body.team) {
            await env.DB.prepare("INSERT OR REPLACE INTO analysis_snapshot (kind, built_at, day, payload_json) VALUES ('team', ?, ?, ?)").bind(builtAt, day, JSON.stringify(body.team)).run();
          }
          for (const it of (Array.isArray(body.issues) ? body.issues : [])) {
            if (!it || !/^[A-Z][A-Z0-9]*-\d+$/.test(it.key || '') || !it.payload) continue;
            await env.DB.prepare("INSERT OR REPLACE INTO issue_analysis (issue_key, built_at, day, payload_json) VALUES (?, ?, ?, ?)").bind(it.key, builtAt, day, JSON.stringify(it.payload)).run();
            issueN++;
          }
          // \uB2F4\uB2F9\uC790 \uC751\uB2F5 \uC9C0\uD45C (\uCF54\uBA58\uD2B8 \uAE30\uBC18, \uC2A4\uCF00\uC904 \uC5D4\uC9C4\uC774 \uACC4\uC0B0\uD574 \uC804\uB2EC)
          try {
            if (Array.isArray(body.resp) && body.resp.length) {
              await env.DB.prepare("CREATE TABLE IF NOT EXISTS issue_resp (issue_key TEXT PRIMARY KEY, assignee TEXT, is_case INTEGER, first_resp REAL, avg_resp REAL, last_comment REAL, comments INTEGER, computed_at INTEGER)").run();
              // 케이스 회신 주체 컬럼 (구 테이블 호환 — 이미 있으면 에러 무시)
              try { await env.DB.prepare('ALTER TABLE issue_resp ADD COLUMN last_comm REAL').run(); } catch (_) {}
              try { await env.DB.prepare('ALTER TABLE issue_resp ADD COLUMN ball TEXT').run(); } catch (_) {}
              try { await env.DB.prepare('ALTER TABLE issue_resp ADD COLUMN ball_note TEXT').run(); } catch (_) {}
              for (const r of body.resp) {
                if (!r || !/^[A-Z][A-Z0-9]*-\d+$/.test(r.key || '')) continue;
                await env.DB.prepare('INSERT INTO issue_resp (issue_key, assignee, is_case, first_resp, avg_resp, last_comment, comments, computed_at, last_comm, ball, ball_note) VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(issue_key) DO UPDATE SET assignee=excluded.assignee, is_case=excluded.is_case, first_resp=excluded.first_resp, avg_resp=excluded.avg_resp, last_comment=excluded.last_comment, comments=excluded.comments, computed_at=excluded.computed_at, last_comm=excluded.last_comm, ball=excluded.ball, ball_note=excluded.ball_note')
                  .bind(r.key, String(r.assignee || ''), r.isCase ? 1 : 0, r.firstRespDays ?? null, r.avgRespDays ?? null, r.lastCommentDays ?? null, Number(r.comments) || 0, builtAt, r.lastCommDays ?? null, String(r.ball || ''), String(r.ballNote || '').slice(0, 160)).run();
              }
            }
          } catch (_) {}
          const cutoff = Date.now() - 180 * 86400000;   // \uBCF4\uC874 180\uC77C
          try { await env.DB.prepare('DELETE FROM issue_analysis WHERE built_at < ?').bind(cutoff).run(); await env.DB.prepare('DELETE FROM analysis_snapshot WHERE built_at < ?').bind(cutoff).run(); } catch (_) {}
          try {
            await env.DB.prepare("CREATE TABLE IF NOT EXISTS analysis_request (issue_key TEXT PRIMARY KEY, requested_at INTEGER, requested_by TEXT)").run();
            for (const it of (Array.isArray(body.issues) ? body.issues : [])) { if (it && it.key) await env.DB.prepare('DELETE FROM analysis_request WHERE issue_key = ?').bind(it.key).run(); }
          } catch (_) {}
          await auditLog(env, 'analysis-agent', 'ANALYSIS_RUN', { issues: issueN, hasTeam: !!body.team, day });
          return corsResponse({ ok: true, issues: issueN, team: !!body.team });
        } catch (e) {
          await auditLog(env, 'analysis-agent', 'ANALYSIS_FAIL', { message: String(e && e.message || e).slice(0, 200) });
          return corsResponse({ ok: false, message: '\uC800\uC7A5 \uC2E4\uD328: ' + (e && e.message || e) }, 500);
        }
      }
      if (path === '/analysis/latest' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        let team = null, builtAt = null, keys = [];
        try {
          const t = await env.DB.prepare("SELECT built_at, day, payload_json FROM analysis_snapshot WHERE kind='team' ORDER BY built_at DESC LIMIT 1").first();
          if (t) { team = JSON.parse(t.payload_json); builtAt = t.built_at; }
          const last = await env.DB.prepare('SELECT MAX(built_at) AS b FROM issue_analysis').first();
          if (last && last.b) {
            // 증분 분석 지원: 최신 배치만이 아니라 최근 14일 내 분석 이력이 있는 전체 키 반환
            const r = await env.DB.prepare('SELECT DISTINCT issue_key FROM issue_analysis WHERE built_at >= ?').bind(Date.now() - 14 * 86400000).all();
            keys = (r.results || []).map(x => x.issue_key);
            if (!builtAt) builtAt = last.b;
          }
        } catch (_) {}
        return corsResponse({ ok: true, built_at: builtAt, team, issueKeys: keys });
      }
      if (path === '/analysis/resp' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        let items = [];
        try { const r = await env.DB.prepare('SELECT issue_key AS key, assignee, is_case, first_resp, avg_resp, last_comment, comments, computed_at, last_comm, ball, ball_note FROM issue_resp WHERE computed_at >= ?').bind(Date.now() - 30 * 86400000).all(); items = r.results || []; } catch (_) {}
        return corsResponse({ ok: true, items });
      }
      if (path.startsWith('/analysis/issue/') && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '\uB85C\uADF8\uC778\uC774 \uD544\uC694\uD569\uB2C8\uB2E4.' }, 401);
        const key = decodeURIComponent(path.split('/')[3] || '');
        if (!/^[A-Z][A-Z0-9]*-\d+$/.test(key)) return corsResponse({ ok: false, message: '\uC798\uBABB\uB41C \uC774\uC288 \uD0A4' }, 400);
        let row = null;
        try { const r = await env.DB.prepare('SELECT built_at, day, payload_json FROM issue_analysis WHERE issue_key = ? ORDER BY built_at DESC LIMIT 1').bind(key).first(); if (r) row = { built_at: r.built_at, day: r.day, ...JSON.parse(r.payload_json) }; } catch (_) {}
        return corsResponse({ ok: true, key, analysis: row });
      }
      if (path.startsWith('/analysis/request/') && request.method === 'POST') {
        if (!hasSession || !await isAdmin(env, user)) return corsResponse({ ok: false, message: '관리자만 가능합니다.' }, 403);
        const key = decodeURIComponent(path.split('/')[3] || '');
        if (!/^[A-Z][A-Z0-9]*-\d+$/.test(key)) return corsResponse({ ok: false, message: '잘못된 이슈 키' }, 400);
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS analysis_request (issue_key TEXT PRIMARY KEY, requested_at INTEGER, requested_by TEXT)").run();
          await env.DB.prepare('INSERT OR REPLACE INTO analysis_request (issue_key, requested_at, requested_by) VALUES (?, ?, ?)').bind(key, Date.now(), user).run();
          await auditLog(env, user, 'ANALYSIS_REQ', { reqKey: key });
          return corsResponse({ ok: true });
        } catch (e) { return corsResponse({ ok: false, message: '요청 실패: ' + (e && e.message || e) }, 500); }
      }
      if (path === '/analysis/requests' && request.method === 'GET') {
        const tok = request.headers.get('x-analysis-token') || '';
        if (!env.ANALYSIS_WRITE_TOKEN || tok !== env.ANALYSIS_WRITE_TOKEN) return corsResponse({ ok: false, message: '인증 실패' }, 401);
        let keys = [];
        try { const r = await env.DB.prepare('SELECT issue_key FROM analysis_request ORDER BY requested_at ASC').all(); keys = (r.results || []).map(x => x.issue_key); } catch (_) {}
        return corsResponse({ ok: true, keys });
      }

      // ── 고객사 환경/사용 솔루션 (IA 재편) : 조회=세션(영업 포함), 수정=기술팀·관리자 ──
      if (path === '/customer/env' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const name = (url.searchParams.get('name') || '').trim().slice(0, 80);
        if (!name) return corsResponse({ ok: false, message: '고객사명이 필요합니다.' }, 400);
        let row = null;
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS customer_env (customer TEXT PRIMARY KEY, solutions TEXT NOT NULL DEFAULT '', env_note TEXT NOT NULL DEFAULT '', updated_by TEXT, updated_at INTEGER)").run();
          row = await env.DB.prepare('SELECT customer, solutions, env_note, updated_by, updated_at FROM customer_env WHERE customer = ?').bind(name).first();
        } catch (_) {}
        return corsResponse({ ok: true, env: row || null });
      }
      if (path === '/customer/env' && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        if (await isSalesRole(env, user)) return corsResponse({ ok: false, message: '환경 정보는 기술팀만 수정할 수 있습니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        const customer = String(body.customer || '').trim().slice(0, 80);
        if (!customer) return corsResponse({ ok: false, message: '고객사명이 필요합니다.' }, 400);
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS customer_env (customer TEXT PRIMARY KEY, solutions TEXT NOT NULL DEFAULT '', env_note TEXT NOT NULL DEFAULT '', updated_by TEXT, updated_at INTEGER)").run();
          await env.DB.prepare('INSERT INTO customer_env (customer, solutions, env_note, updated_by, updated_at) VALUES (?,?,?,?,?) ON CONFLICT(customer) DO UPDATE SET solutions=excluded.solutions, env_note=excluded.env_note, updated_by=excluded.updated_by, updated_at=excluded.updated_at')
            .bind(customer, String(body.solutions || '').slice(0, 500), String(body.env_note || '').slice(0, 3000), user, Date.now()).run();
          await auditLog(env, user, 'CUST_ENV', { envCustomer: customer });
          return corsResponse({ ok: true });
        } catch (e) { return corsResponse({ ok: false, message: '저장 실패: ' + (e && e.message || e) }, 500); }
      }

      // ── STEP 6 영업 현황 : 규칙 기반 집계(AI 무관), 이슈 본문·코멘트는 반환하지 않음 ──
      if (path === '/sales/overview' && request.method === 'GET') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        try {
          const data = await buildSalesOverview(env);
          return corsResponse(data);
        } catch (e) { return corsResponse({ ok: false, message: '집계 실패: ' + (e && e.message || e) }, 500); }
      }
      if (path === '/sales/note' && request.method === 'PUT') {
        if (!hasSession) return corsResponse({ ok: false, message: '로그인이 필요합니다.' }, 401);
        const salesOk = (await isSalesRole(env, user)) || (await isAdmin(env, user));
        if (!salesOk) return corsResponse({ ok: false, message: '영업·관리자만 수정할 수 있습니다.' }, 403);
        const body = await request.json().catch(() => ({}));
        try {
          const saved = await saveSalesNote(env, user, body);
          await auditLog(env, user, 'SALES_NOTE', { noteCustomer: saved.customer, noteProduct: saved.product, noteStatus: saved.status });
          return corsResponse({ ok: true, saved });
        } catch (e) { return corsResponse({ ok: false, message: '저장 실패: ' + (e && e.message || e) }, 400); }
      }

      return corsResponse({ ok: false, message: '\uC5C6\uB294 \uACBD\uB85C\uC785\uB2C8\uB2E4.' }, 404);
    } catch (err) {
      return corsResponse({ ok: false, message: err.message || '\uC11C\uBC84 \uC624\uB958' }, 500);
    }
  },

  // \u2500\u2500 Cron Scheduled Handler \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  async scheduled(event, env, ctx) {
    // §3 일일 팀 업무 스냅샷 (08:30 KST = 23:30 UTC). KST 전일(완료된 하루) updated 이슈 저장.
    try {
      const _kst = new Date(Date.now() + 9 * 3600e3); _kst.setUTCDate(_kst.getUTCDate() - 1);  // 08:30 KST 실행 → 전일을 스냅샷(당일은 00:00~08:30분만이라 거의 공백)
      const kstDay = _kst.toISOString().slice(0, 10);
      ctx.waitUntil(buildDailySnapshot(env, kstDay));
    } catch (_) {}
  },
};
