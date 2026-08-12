// 문법 검사 — 실행하지 않고 파싱만 한다. 실패 시 exit 1.
//
// ⚠️ node -c / node --check 는 파일을 CommonJS로 파싱할 수 있고, CJS에서는 최상위 return 이
//    합법이다. 그래서 워커(ESM)에서 블록이 깨져 return 이 최상위로 튀어나와도 통과해버린다.
//    실제로 그 상태로 wrangler 빌드가 "Unexpected return" 으로 실패한 적이 있다(2026-08-07).
//    → worker.js 와 src/*.js 는 .mjs 사본으로 복사해 **ESM으로 강제 파싱**한다.
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");
const { execFileSync } = require("child_process");

let bad = 0;
const fail = (what, msg) => { bad++; console.error("FAIL " + what + " :: " + msg); };

// ── 1) 워커 + src 모듈: ESM 파싱 ──────────────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "syntax-"));
const esmTargets = ["worker.js"].concat(
  fs.existsSync("src") ? fs.readdirSync("src").filter(n => n.endsWith(".js")).map(n => "src/" + n) : []
);
for (const rel of esmTargets) {
  const copy = path.join(tmp, rel.replace(/[\\/]/g, "_") + ".mjs");
  fs.copyFileSync(rel, copy);
  try {
    execFileSync(process.execPath, ["--check", copy], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (e) {
    fail(rel + " (ESM)", String((e.stderr || "").toString().split("\n").filter(Boolean).slice(0, 3).join(" | ")));
  }
}

// ── 2) 프론트 js/*.js: 클래식 스크립트 파싱 ────────────────────────────────
const jsFiles = fs.existsSync("js") ? fs.readdirSync("js").filter(n => n.endsWith(".js")) : [];
for (const f of jsFiles) {
  try { new vm.Script(fs.readFileSync("js/" + f, "utf8")); }
  catch (e) { fail("js/" + f, e.message); }
}

// ── 3) index.html 인라인 스크립트 ─────────────────────────────────────────
const h = fs.readFileSync("index.html", "utf8");
const OPEN = /<script([^>]*)>/g;
let m, total = 0, inline = 0;
while ((m = OPEN.exec(h))) {
  total++;
  if (m[1].includes("src=")) continue;
  const start = OPEN.lastIndex, end = h.indexOf("</script>", start);
  if (end < 0) { fail("index.html script#" + total, "닫는 태그 없음"); continue; }
  inline++;
  try { new vm.Script(h.slice(start, end)); }
  catch (e) { fail("index.html inline#" + total, e.message); }
}

console.log(`ESM ${esmTargets.length}개 · js/*.js ${jsFiles.length}개 · index.html script ${total}개(인라인 ${inline}개)`);
console.log(bad ? `FAIL ${bad}건` : "OK");
process.exit(bad ? 1 : 0);
