/* master.html 을 진짜 브라우저로 열어 "정말 되는지" 확인한다.
 *
 *   node check_app.js <교사용 암호>
 *
 * 왜 필요한가:
 *   지금까지는 고칠 때마다 손으로 눌러 확인해 오셨습니다. 꼼꼼하지만 도구가 수십 개라
 *   매번 다 눌러 보기는 어렵습니다. 자주 확인하는 것만 기계에게 맡깁니다.
 *   "AI나 사람이 다 됐다고 말하는 것"과 "실제로 되는 것"은 다르니까요.
 *
 * 처음 한 번만 준비:
 *   npm install playwright
 *   npx playwright install chromium
 *
 * 무엇을 보는가 (연수 자료의 정상 · 잘못된 입력 · 다시 사용 세 가지):
 *   정상        암호로 열림 · 카드가 그려짐 · 링크와 QR이 만들어짐 · 내보내기가 받아짐
 *   잘못된 입력  틀린 암호로는 안 열림
 *   다시 사용    새로고침해도 기억된 암호로 바로 열림
 *   그 밖에     콘솔 오류 없음 · 바깥으로 나가는 요청 없음 · 모바일에서 가로 스크롤 없음
 *              잠긴 상태의 소스에 과목 이름이 새지 않음
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PW = process.argv[2];
if (!PW) {
  console.error('쓰는 법: node check_app.js <교사용 암호>');
  process.exit(2);
}

let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (e) {
  console.error('playwright 가 없습니다. 먼저 한 번만:');
  console.error('  npm install playwright');
  console.error('  npx playwright install chromium');
  process.exit(2);
}

const HERE = __dirname;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.enc': 'application/json',
               '.css': 'text/css', '.txt': 'text/plain', '.json': 'application/json' };

function serve() {
  return new Promise(res => {
    const s = http.createServer((req, rq) => {
      const rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'master.html';
      const fp = path.join(HERE, rel);
      if (!fp.startsWith(HERE) || !fs.existsSync(fp) || fs.statSync(fp).isDirectory()) {
        rq.writeHead(404); rq.end('not found'); return;
      }
      rq.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
      fs.createReadStream(fp).pipe(rq);
    });
    s.listen(0, '127.0.0.1', () => res(s));
  });
}

let fail = 0;
const ok = (label, cond, extra) => {
  console.log('  ' + (cond ? '✅' : '❌') + ' ' + label + (extra ? ' — ' + extra : ''));
  if (!cond) fail++;
};

async function unlock(p, url, pw) {
  await p.goto(url, { waitUntil: 'networkidle' });
  await p.fill('#gimPw', pw);
  await p.click('#gimGo');
  const go2 = await p.waitForSelector('#gimGo2', { timeout: 15000 }).catch(() => null);
  if (go2) await go2.click();          // 교사용은 주간 코드 화면을 한 번 거친다
  await p.waitForTimeout(1200);
}

(async () => {
  const server = await serve();
  const url = 'http://127.0.0.1:' + server.address().port + '/master.html';
  const b = await chromium.launch();

  // ── 잠긴 상태에서 무엇이 새는지
  console.log('■ 잠긴 상태에서 소스로 새는 것이 없는가');
  const peek = await b.newPage();
  const src = await (await peek.goto(url)).text();
  const enc = JSON.parse(fs.readFileSync(path.join(HERE, 'tools.enc'), 'utf-8'));
  ok('tools.enc 가 암호화되어 있음', !!enc.data && !!enc.keys);
  // AREAS-START ~ AREAS-END 사이에 목록이 남아 있으면 잠겨 있어도 소스로 다 보인다
  const seg = src.split('/* AREAS-START */')[1];
  const moved = seg !== undefined && seg.split('/* AREAS-END */')[0].trim() === 'const AREAS = window.HUB_AREAS || [];';
  ok('소스에 분야·과목 목록이 없음', moved,
     moved ? '목록은 tools.enc 안에 있음'
           : 'master.html 에 아직 남아 있습니다 — build_lock.py 를 한 번 돌리면 옮겨집니다');
  await peek.close();

  // ── 정상
  console.log('■ 정상 — 암호로 열고 링크·QR·내보내기까지');
  const ctx = await b.newContext({ viewport: { width: 1280, height: 1100 } });
  const p = await ctx.newPage();
  const errs = [], ext = [];
  p.on('pageerror', e => errs.push('PAGEERROR ' + e.message.slice(0, 150)));
  p.on('console', m => { if (m.type() === 'error') errs.push(m.text().slice(0, 150)); });
  p.on('request', r => { if (!r.url().startsWith('http://127.0.0.1')) ext.push(r.url()); });

  await unlock(p, url, PW);
  ok('라이브러리가 vendor/ 에서 로드됨',
     await p.evaluate(() => typeof LZString !== 'undefined' && typeof qrcode !== 'undefined'));
  const cards = await p.locator('.item.card').count();
  ok('도구 카드가 그려짐', cards > 0, cards + '개');
  const areas = await p.locator('details.area').count();
  ok('분야 밴드가 그려짐', areas > 0, areas + '개');
  const names = await p.evaluate(() =>
    [...document.querySelectorAll('summary.areahd')].map(e => e.textContent));
  ok('내부·관리용이 맨 아래에 있음',
     !names.length || names[names.length - 1].includes('내부'));

  await p.click('#expAll');
  await p.waitForTimeout(500);
  const boxes = p.locator('.item.card input[type=checkbox]');
  await boxes.nth(0).check();
  if (cards > 1) await boxes.nth(1).check();
  await p.fill('#title', '점검용 묶음');
  await p.click('#linkBtn');
  await p.waitForTimeout(3000);
  ok('QR 이미지가 만들어짐', await p.locator('#qrBox img').count() > 0);
  const lo = await p.locator('#linkOut').innerText().catch(() => '');
  ok('공유 링크가 만들어짐', lo.includes('s.html'), lo.slice(0, 60).replace(/\n/g, ' '));

  const dl = p.waitForEvent('download', { timeout: 15000 }).catch(() => null);
  await p.click('#exportBtn');
  const got = await dl;
  ok('내보내기 파일이 받아짐', !!got, got ? await got.suggestedFilename() : '실패');

  ok('바깥으로 나간 요청이 없음', ext.length === 0, ext.join(', ') || '없음');
  ok('콘솔 오류가 없음', errs.length === 0, errs.join(' | ') || '없음');

  // ── 다시 사용 (같은 기기는 기억한다)
  console.log('■ 다시 사용 — 새로고침해도 바로 열리는가');
  const again = await ctx.newPage();
  await again.goto(url, { waitUntil: 'networkidle' });
  await again.waitForTimeout(2000);
  const go2 = await again.$('#gimGo2');
  if (go2) await go2.click();
  await again.waitForTimeout(1000);
  ok('기억된 암호로 다시 열림', await again.locator('.item.card').count() > 0);

  // ── 잘못된 입력
  console.log('■ 잘못된 입력 — 틀린 암호로는 안 열리는가');
  const bad = await (await b.newContext()).newPage();
  await bad.goto(url, { waitUntil: 'networkidle' });
  await bad.fill('#gimPw', '이건틀린암호9999');
  await bad.click('#gimGo');
  await bad.waitForTimeout(2500);
  ok('틀린 암호는 막힘', (await bad.innerText('body')).includes('맞지 않습니다'));
  ok('틀린 암호로는 목록이 안 나옴', await bad.locator('.item.card').count() === 0);

  // ── 잘못된 방법으로 열었을 때 (암호 탓으로 돌리지 않는지)
  console.log('■ 파일로 열었을 때 — 원인을 제대로 알려 주는가');
  const f = await (await b.newContext()).newPage();
  await f.goto('file://' + path.join(HERE, 'master.html'));
  await f.waitForTimeout(1200);
  const ftxt = await f.locator('#gimBox').innerText().catch(() => '');
  ok('"암호가 맞지 않습니다" 로 넘기지 않음', !ftxt.includes('암호가 맞지 않'));
  ok('여는 방법을 알려 줌', ftxt.includes('http.server') || ftxt.includes('localhost'),
     ftxt.split('\n').filter(Boolean)[1] || '(안내 없음)');
  ok('암호를 묻지 않음', await f.locator('#gimPw').count() === 0);
  ok('목록은 잠긴 채로 둠', await f.locator('.item.card').count() === 0);

  // ── 모바일
  console.log('■ 모바일 390px');
  const m = await (await b.newContext({ viewport: { width: 390, height: 844 } })).newPage();
  await unlock(m, url, PW);
  ok('가로 스크롤이 없음',
     !(await m.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)));
  ok('카드가 보임', await m.locator('.item.card').count() > 0);

  console.log('\n' + (fail ? '결과: ' + fail + '개 실패 — 고친 뒤 다시 돌려 보세요' : '결과: 전부 통과 ✅'));
  await b.close();
  server.close();
  process.exit(fail ? 1 : 0);
})();
