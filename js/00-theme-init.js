
(function(){
  try {
    var saved = localStorage.getItem('engr_theme');
    var isMob = false; try{ isMob = window.matchMedia('(max-width:700px)').matches; }catch(e){}
    // 모바일은 항상 다크로 렌더(라이트 누수로 인한 글자 안보임/레이아웃 깨짐 방지). 데스크톱만 사용자 설정 적용.
    document.documentElement.setAttribute('data-theme', (saved === 'light' && !isMob) ? 'light' : 'dark');
  } catch (_) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
  // 설치형 PWA(앱)로 실행 시 창 제목
  try{ if(window.matchMedia('(display-mode:standalone)').matches||window.navigator.standalone){ document.title='ESCARE - 보안기술팀'; } }catch(e){}
})();
