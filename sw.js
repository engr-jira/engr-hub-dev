// ESCARE 보안기술팀 — Service Worker (Web Push 전용)
// 의도적으로 fetch 핸들러 없음 → 어떤 요청도 캐시/가로채지 않음(구버전 코드 노출 방지).
const WORKER = 'https://engr-hub-proxy-dev.mj-park.workers.dev';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// 푸시 수신: payload-less 가능 → 서버에서 보류 알림을 받아와 표시
self.addEventListener('push', (event) => {
  event.waitUntil((async () => {
    let items = [];
    // 1) 페이로드가 실려 있으면 우선 사용
    try {
      if (event.data) {
        const d = event.data.json();
        if (d && (d.title || d.body)) items = Array.isArray(d) ? d : [d];
      }
    } catch (_) {
      try { if (event.data) items = [{ title: 'ENGR HUB', body: event.data.text() }]; } catch (_) {}
    }
    // 2) payload-less면 서버에서 보류 알림 fetch
    if (!items.length) {
      try {
        const sub = await self.registration.pushManager.getSubscription();
        if (sub) {
          const r = await fetch(WORKER + '/push/pending', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ endpoint: sub.endpoint }),
          });
          const j = await r.json();
          items = (j && j.items) || [];
        }
      } catch (_) {}
    }
    if (!items.length) items = [{ title: 'ENGR HUB', body: '새 알림이 있습니다.' }];

    for (const it of items) {
      await self.registration.showNotification(it.title || 'ENGR HUB', {
        body: it.body || '',
        icon: './icon.svg',
        badge: './icon.svg',
        tag: it.tag ? (it.tag + ':' + (it.ts || '')) : ('engr:' + (it.ts || Date.now())),
        data: { page: it.page || '' },
        renotify: false,
        requireInteraction: false,
      });
    }
  })());
});

// 알림 클릭: 열린 창이 있으면 포커스+해당 화면 이동, 없으면 새 창
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const page = (event.notification.data && event.notification.data.page) || '';
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if (/engr-hub/.test(c.url) && 'focus' in c) {
        try { c.postMessage({ type: 'navigate', page }); } catch (_) {}
        return c.focus();
      }
    }
    if (self.clients.openWindow) {
      const url = './' + (page ? ('?go=' + encodeURIComponent(page)) : '');
      return self.clients.openWindow(url);
    }
  })());
});
