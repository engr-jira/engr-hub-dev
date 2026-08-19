// index.html 의 <script src="js/…"> 에 배포 버전을 찍는다.
//
// 왜 필요한가: GitHub Pages 는 js 를 max-age=600 으로 준다. index.html 만 새로 받아도
// js 는 최대 10분간 예전 것이 쓰여서, 배포 직후 "안 고쳐졌다"로 보인다(실제로 두 번 겪음).
// src 에 ?b=<타임스탬프> 를 붙이면 주소가 바뀌므로 브라우저가 곧바로 새로 받는다.
//
// 사용: node scripts/stamp-assets.js   ← 프론트 커밋 직전에 실행
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const P = path.join(ROOT, 'index.html');
const s = fs.readFileSync(P, 'utf8');

const d = new Date();
const p2 = n => String(n).padStart(2, '0');
const stamp = `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}${p2(d.getHours())}${p2(d.getMinutes())}`;

let n = 0;
const out = s.replace(/(<script\s+src=")(js\/[A-Za-z0-9._-]+\.js)(?:\?b=[0-9]+)?(")/g, (_, a, file, c) => {
  n++;
  return `${a}${file}?b=${stamp}${c}`;
});

if (!n) { console.error('script src="js/…" 를 찾지 못했습니다 — index.html 구조 확인 필요'); process.exit(1); }
if (out === s) { console.log(`이미 ?b=${stamp} — 변경 없음 (${n}개)`); process.exit(0); }
fs.writeFileSync(P, out);
console.log(`?b=${stamp} 로 스탬프: ${n}개`);
