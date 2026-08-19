
(function(){
  try {
    var saved = localStorage.getItem('engr_theme');
    // 저장값이 'dark'일 때만 다크. 기본은 라이트(살구 페이퍼).
    document.documentElement.setAttribute('data-theme', saved === 'dark' ? 'dark' : 'light');
  } catch (_) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
  /* 개발계/운영계 구분 — 같은 호스트(engr-jira.github.io)에 나란히 있어 탭만 보고는 구분이
     안 된다. 경로로 판별해 <html data-env>에 심고, CSS 가 사이드바 배지 문구를 그린다.
     dev = /engr-hub-dev/, prod = /engr-hub/ */
  var IS_DEV = /\/engr-hub-dev(\/|$)/.test(location.pathname);
  document.documentElement.setAttribute('data-env', IS_DEV ? 'dev' : 'prod');
  document.title = (IS_DEV ? '[개발] ' : '[운영] ') + 'ENGR AI v2.0 - ESCARE Security Hub';
  // 설치형 PWA(앱)로 실행 시 창 제목
  try{ if(window.matchMedia('(display-mode:standalone)').matches||window.navigator.standalone){ document.title=(IS_DEV?'[개발] ':'')+'ESCARE - 보안기술팀'; } }catch(e){}
})();
