// js/*.js (클래식 스크립트) + index.html 인라인 스크립트 파싱 검사.
// 실행하지 않고 파싱만 한다. 실패 시 exit 1.
const fs = require("fs"), vm = require("vm");
let bad = 0;

for (const f of fs.readdirSync("js").filter(n => n.endsWith(".js"))) {
  try { new vm.Script(fs.readFileSync("js/" + f, "utf8")); }
  catch (e) { bad++; console.error("FAIL js/" + f + " :: " + e.message); }
}

const h = fs.readFileSync("index.html", "utf8");
const OPEN = /<script([^>]*)>/g;
let m, total = 0, inline = 0;
while ((m = OPEN.exec(h))) {
  total++;
  if (m[1].includes("src=")) continue;              // 외부 스크립트는 파일 검사로 커버
  const start = OPEN.lastIndex, end = h.indexOf("</script>", start);
  if (end < 0) { bad++; console.error("FAIL index.html script#" + total + " :: 닫는 태그 없음"); continue; }
  inline++;
  try { new vm.Script(h.slice(start, end)); }
  catch (e) { bad++; console.error("FAIL index.html inline#" + total + " :: " + e.message); }
}

console.log(`js/*.js ${fs.readdirSync("js").filter(n=>n.endsWith(".js")).length}개 · index.html script ${total}개(인라인 ${inline}개)`);
console.log(bad ? `FAIL ${bad}건` : "OK");
process.exit(bad ? 1 : 0);
