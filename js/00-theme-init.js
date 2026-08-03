
(function(){
  try {
    var saved = localStorage.getItem('engr_theme');
    // 저장값이 'dark'일 때만 다크. 기본은 라이트(살구 페이퍼).
    document.documentElement.setAttribute('data-theme', saved === 'dark' ? 'dark' : 'light');
  } catch (_) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
  // 설치형 PWA(앱)로 실행 시 창 제목
  try{ if(window.matchMedia('(display-mode:standalone)').matches||window.navigator.standalone){ document.title='ESCARE - 보안기술팀'; } }catch(e){}
})();
