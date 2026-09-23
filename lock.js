/* =========================================================
   마스터 링크 허브 — 잠금 해제

   정적 호스팅에서는 "화면에 비밀번호 칸"만 두면 보호가 되지 않는다.
   주소를 직접 치면 데이터 파일이 그대로 받아지기 때문이다.
   그래서 도구 목록(tools.enc)을 실제로 AES-GCM 으로 암호화해서 올리고,
   여기서 WebCrypto 로 푼다. 암호가 틀리면 복호화가 실패한다.

   암호는 두 종류다 (수업용).
     교사용 — 문구형, 만료 없음. 열면 그 주 학생 코드가 화면에 바로 나온다.
     학생용 — 8자리 숫자, 그 주 월요일 ~ 다음 월요일 7일만.
   본문은 내용키(CK) 하나로 암호화돼 있고, CK 가 암호마다 따로 감싸여 있다.
   그래서 어떤 암호로 열든 같은 자료가 나오지만, 기간은 암호문 안에 박혀 있어
   화면이나 이 파일을 고쳐도 만료를 넘길 수 없다.

   한 번 연 기기는 암호를 저장해 두고 다음부터 바로 들어간다.
   ========================================================= */
window.HubLock = (function () {
  /* 저장 키가 두 개다.
       LS_OWN    이 도구에서 성공한 암호
       LS_SHARED 도구 전체 공용 — 도구가 모두 hongyul67-cpu.github.io 한 곳에 있어
                 localStorage 를 공유하므로, 어디서든 한 번 열면 나머지도 그냥 열린다.
     실패했을 때 공용 키는 지우지 않는다. 이 도구에서 안 맞는 암호가
     다른 도구에서는 맞을 수 있어, 지우면 남의 기억까지 날리게 된다.
     기간이 있는 학생 코드는 공용 키에 넣지 않는다 — 다른 도구가 만료된 것을 물게 된다. */
  var LS_OWN = 'hub_pw_v1';
  var LS_SHARED = 'hong_pw_v1';

  var ck = null;           // 내용키 — 데이터와 도판을 모두 이걸로 푼다
  var onOpen = null;
  var info = null;         // 열어 준 암호의 정보 (역할·기간)
  var kit = null;          // 감싼 키 묶음 — 공유 파일에 그대로 넣어 받은 사람이 암호로 풀게 한다

  function b64(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function b64s(u) { var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function $(id) { return document.getElementById(id); }
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function iso(d) { return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }
  function monday(d) { var x = new Date(d); var w = (x.getDay() + 6) % 7; x.setDate(x.getDate() - w); x.setHours(0, 0, 0, 0); return x; }
  function addDays(d, n) { var x = new Date(d); x.setDate(x.getDate() + n); return x; }
  function pretty(c) { return c.slice(0, 4) + ' ' + c.slice(4); }

  /* nonce(12바이트) + 암호문 형태로 봉해 둔 것을 내용키로 푼다 */
  function unseal(buf) {
    var u = new Uint8Array(buf);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, ck, u.slice(12));
  }

  function derive(pw, salt, iter) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: iter, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      });
  }

  /* 감싼 키들을 훑어 맞는 것을 찾는다. AES-GCM 은 즉시라 수백 개도 순식간이다.
     PBKDF2 는 salt 를 공유하므로 딱 한 번만 돈다. */
  function findKey(kek, keys) {
    var i = 0;
    function next() {
      if (i >= keys.length) return Promise.reject(new Error('BADPW'));
      var k = keys[i++];
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(k.iv) }, kek, b64(k.blob))
        .then(function (plain) { return JSON.parse(new TextDecoder().decode(plain)); })
        .catch(next);
    }
    return next();
  }

  function checkPeriod(nfo) {
    var today = iso(new Date());
    if (nfo.nbf && today < nfo.nbf) { var e = new Error('NOTYET'); e.when = nfo.nbf; throw e; }
    if (nfo.exp && today >= nfo.exp) { var x = new Error('EXPIRED'); x.when = nfo.exp; throw x; }
    return nfo;
  }

  /* 암호를 물어 볼 것도 없이 이 환경에서는 아예 안 되는 경우를 먼저 가려낸다.
     이걸 안 하면 무엇이 잘못됐든 화면에는 "암호가 맞지 않습니다" 만 떠서,
     암호를 몇 번이고 다시 치게 된다. 실제로 file:// 로 열었을 때 그랬다. */
  function blocker() {
    if (location.protocol === 'file:') return {
      t: '파일로 열면 목록을 못 읽어요',
      m: '브라우저가 <b>file://</b> 에서는 목록 파일(tools.enc)을 읽지 못하게 막습니다.<br>' +
         '암호 문제가 아니라 <b>여는 방법</b> 문제입니다.<br><br>' +
         '· 인터넷 주소로 열면 그냥 됩니다<br><br>' +
         '· 내 PC에서 보려면 이 폴더에서 아래를 실행한 뒤<br>' +
         '<code style="display:block;margin:6px 0;padding:7px 10px;background:#241a44;' +
         'border-radius:8px;color:#cfc4f0;font-size:13px">python -m http.server</code>' +
         '&nbsp;&nbsp;<b>http://localhost:8000/master.html</b> 로 들어오세요'
    };
    if (!(window.crypto && crypto.subtle)) return {
      t: '이 주소에서는 열 수 없어요',
      m: '암호를 푸는 기능(crypto.subtle)이 이 환경에서 막혀 있습니다.<br>' +
         '<b>https://</b> 주소나 <b>http://localhost</b> 로 들어와야 합니다.<br>' +
         '(http:// 로 된 다른 PC 주소로 들어오면 브라우저가 막습니다)'
    };
    if (typeof DecompressionStream === 'undefined') return {
      t: '이 브라우저에서는 열 수 없어요',
      m: '목록의 압축을 푸는 기능이 이 브라우저에 없습니다.<br>' +
         '<b>크롬이나 엣지를 최신으로 올린 뒤</b> 다시 열어 주세요.<br>' +
         '(크롬·엣지 80, 사파리 16.4, 파이어폭스 113 이상)'
    };
    return null;
  }

  function open(pw, quiet) {
    if (!quiet) say('여는 중…', 'dim');
    return fetch('tools.enc', { cache: 'no-cache' })
      .catch(function () { throw new Error('NOFETCH'); })   // 망이 끊겼거나 주소가 막혔다
      .then(function (r) {
        if (!r.ok) { var e = new Error('NOFILE'); e.code = r.status; throw e; }
        return r.json();
      })
      .then(function (blob) {
        kit = { kdf: { salt: blob.kdf.salt, iter: blob.kdf.iter }, keys: blob.keys };
        return derive(pw, b64(blob.kdf.salt), blob.kdf.iter)
          .then(function (kek) { return findKey(kek, blob.keys); })
          .then(checkPeriod)
          .then(function (nfo) {
            info = nfo;
            return crypto.subtle.importKey('raw', b64(nfo.ck), { name: 'AES-GCM' }, false, ['decrypt'])
              .then(function (k) { ck = k; return unseal(b64(blob.data).buffer); });
          })
          .then(function (gz) {
            /* gzip 해제 — 브라우저 내장 */
            var ds = new DecompressionStream('gzip');
            return new Response(new Blob([gz]).stream().pipeThrough(ds)).text();
          })
          .then(function (txt) {
            /* 담긴 형태가 두 가지다.
                 옛것  [ {도구}, {도구}, ... ]                 — 도구 목록만
                 새것  { tools:[...], areas:[...] }            — 분야·과목 목록도 함께
               분야 목록을 master.html 에 평문으로 두면 잠금 화면에서도 소스 보기로
               과목 이름이 다 보여서, 그것도 tools.enc 안으로 옮겼다.
               예전에 만든 tools.enc 로도 그대로 열려야 하므로 둘 다 받는다. */
            var d = JSON.parse(txt);
            if (Array.isArray(d)) {
              window.HUB_TOOLS = d;
            } else {
              window.HUB_TOOLS = d.tools || [];
              if (d.areas) window.HUB_AREAS = d.areas;
            }
            try {
              localStorage.setItem(LS_OWN, pw);
              /* 만료되는 코드는 공용에 넣지 않는다 */
              if (!info.exp) localStorage.setItem(LS_SHARED, pw);
            } catch (e) {}
            /* 교사용으로 직접 열었을 때만 코드 화면을 띄운다.
               저장된 암호로 조용히 열릴 때(quiet)는 수업 중이므로 바로 들어간다. */
            if (!quiet && info.role === 'teacher' && info.ms) showCodes();
            else enter();
            return true;
          });
      })
      .catch(function (e) {
        ck = null; info = null;
        var m = e && e.message;
        /* 목록 파일을 못 받은 것은 암호 문제가 아니다 — 기억해 둔 암호를 지우면 안 된다.
           지우면 망이 잠깐 끊긴 것만으로 다음에 또 암호를 물어보게 된다. */
        var pwWrong = (m !== 'NOFETCH' && m !== 'NOFILE');
        if (pwWrong) { try { localStorage.removeItem(LS_OWN); } catch (e2) {} }   // 공용 키는 건드리지 않는다
        if (!quiet) {
          if (m === 'EXPIRED') say('사용 기간이 끝난 코드입니다 (' + e.when + '까지).<br>선생님께 이번 주 코드를 받으세요.', 'bad');
          else if (m === 'NOTYET') say('아직 쓸 수 없는 코드입니다.<br>' + e.when + '부터 쓸 수 있어요.', 'bad');
          else if (m === 'NOFETCH') say('목록 파일(tools.enc)을 받아오지 못했습니다.<br>' +
                                        '<b>암호 문제가 아닙니다.</b> 인터넷 연결을 확인해 주세요.', 'bad');
          else if (m === 'NOFILE') say('목록 파일(tools.enc)이 없습니다 (' + e.code + ').<br>' +
                                       '<b>암호 문제가 아닙니다.</b> python build_lock.py 로 만든 뒤 올려 주세요.', 'bad');
          else say('암호가 맞지 않습니다.', 'bad');
          shake();
        } else { say('', 'dim'); }
        /* 암호가 틀렸을 때만 입력칸을 비운다. 파일을 못 받은 것이면 그대로 두어
           연결을 고친 뒤 [열기] 만 다시 누르면 되게 한다. */
        var pwEl = $('gimPw');
        if (pwEl) { if (pwWrong) pwEl.value = ''; pwEl.focus(); }
        return false;
      });
  }

  /* 교사용으로 열었을 때 — 그 주 코드를 크게 보여 준다.
     코드표 파일을 뒤질 필요 없이 여기서 읽어 학생에게 불러 주면 된다. */
  function weekCode(ms, mon) {
    return crypto.subtle.importKey('raw', ms, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      /* 접두어는 암호문 안(info.prefix)에서 온다 — 도구가 모두 같은 값을 쓴다 */
      .then(function (k) { return crypto.subtle.sign('HMAC', k, new TextEncoder().encode((info.prefix || 'HONGW|') + iso(mon))); })
      .then(function (sig) {
        var u = new Uint8Array(sig);
        var n = ((u[0] << 24) >>> 0) + (u[1] << 16) + (u[2] << 8) + u[3];
        return String(n % 90000000 + 10000000);
      });
  }

  /* 배포용으로 미리 불러 줘야 하므로 3개월(13주)치를 보여 준다.
     교실 화면에 띄울 때는 다음 주 코드가 보이지 않게 접어 둘 수 있다. */
  var WEEKS_SHOWN = 13;

  function codeRows(ms, n) {
    var thisMon = monday(new Date());
    var mons = [];
    for (var i = 0; i < n; i++) mons.push(addDays(thisMon, i * 7));
    return Promise.all(mons.map(function (m) { return weekCode(ms, m); }))
      .then(function (cs) {
        return mons.map(function (m, i) {
          return { mon: m, end: addDays(m, 7), code: cs[i], now: i === 0 };
        });
      });
  }

  function tableHTML(rows, folded) {
    return '<table class="codes"><tbody>' + rows.map(function (r, i) {
      var hide = folded && i > 0;
      return '<tr class="' + (r.now ? 'now' : '') + (hide ? ' fold' : '') + '">' +
             '<td>' + (i + 1) + '주</td>' +
             '<td>' + iso(r.mon).slice(5) + ' ~ ' + iso(r.end).slice(5) + '</td>' +
             '<td class="c">' + (hide ? '••••&nbsp;••••' : pretty(r.code)) + '</td>' +
             '<td><button class="cp" data-code="' + r.code + '">복사</button></td></tr>';
    }).join('') + '</tbody></table>';
  }

  function wireCopy(root) {
    Array.prototype.forEach.call(root.querySelectorAll('.cp'), function (b) {
      b.onclick = function (e) {
        e.stopPropagation();
        var v = b.getAttribute('data-code'), old = b.textContent;
        var done = function () { b.textContent = '됐어요'; setTimeout(function () { b.textContent = old; }, 1200); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(v).then(done, done);
        else done();
      };
    });
  }

  function showCodes() {
    var ms = b64(info.ms);
    codeRows(ms, WEEKS_SHOWN).then(function (rows) {
      var box = $('gimBox');
      box.innerHTML =
        '<div class="ico">🧑‍🏫</div>' +
        '<h1>이번 주 학생 코드</h1>' +
        '<div class="bigcode">' + pretty(rows[0].code) + '</div>' +
        '<p class="sub">' + iso(rows[0].mon) + ' ~ ' + iso(rows[0].end) + ' 까지 씁니다</p>' +
        '<div class="foldwarn" id="gimFold">교실 화면이면 <b>접어 두세요</b> · 눌러서 3개월치 보기</div>' +
        '<div class="codewrap">' + tableHTML(rows, true) + '</div>' +
        '<button id="gimGo2">목록 열기</button>' +
        '<div class="note">학생에게는 이 8자리 숫자만 알려 주세요.<br>' +
        '교사용 암호를 알려 주면 기간 제한 없이 열립니다.</div>';
      var folded = true;
      $('gimFold').onclick = function () {
        folded = !folded;
        box.querySelector('.codewrap').innerHTML = tableHTML(rows, folded);
        wireCopy(box);
        $('gimFold').innerHTML = folded
          ? '교실 화면이면 <b>접어 두세요</b> · 눌러서 3개월치 보기'
          : '3개월치를 보고 있습니다 · 눌러서 접기';
      };
      wireCopy(box);
      $('gimGo2').onclick = enter;
    }).catch(enter);
  }

  /* 잠금이 풀린 뒤에도 코드를 다시 꺼내 볼 수 있게 (배포용) */
  function panel() {
    if (!info || info.role !== 'teacher' || !info.ms) return false;
    var ms = b64(info.ms);
    codeRows(ms, WEEKS_SHOWN).then(function (rows) {
      var ov = document.createElement('div');
      ov.id = 'gimPanel';
      ov.innerHTML = '<div id="gimBox">' +
        '<div class="ico">🔑</div><h1>주간 학생 코드</h1>' +
        '<div class="bigcode">' + pretty(rows[0].code) + '</div>' +
        '<p class="sub">이번 주 · ' + iso(rows[0].mon) + ' ~ ' + iso(rows[0].end) + '</p>' +
        '<div class="codewrap">' + tableHTML(rows, false) + '</div>' +
        '<button id="gimClose">닫기</button>' +
        '<div class="note">한 코드로 공업일반 · 허브 · 반도체 · NCS 가 모두 열립니다.<br>' +
        '코드는 그 주 월요일부터 7일간만 통합니다.</div></div>';
      document.body.appendChild(ov);
      wireCopy(ov);
      var close = function () { ov.remove(); };
      ov.querySelector('#gimClose').onclick = close;
      ov.onclick = function (e) { if (e.target === ov) close(); };
    });
    return true;
  }

  function enter() {
    var ov = $('gimLock'); if (ov) ov.remove();
    document.body.classList.remove('locked');
    if (onOpen) { var f = onOpen; onOpen = null; f(); }
  }

  function say(t, c) {
    var m = $('gimMsg'); if (!m) return;
    m.innerHTML = t;
    m.style.color = c === 'bad' ? '#ff8a8a' : (c === 'ok' ? '#7ee7a0' : '#9b8fc4');
  }
  function shake() {
    var b = $('gimBox'); if (!b) return;
    b.style.animation = 'none'; void b.offsetWidth; b.style.animation = 'gimShake .3s';
  }

  var CSS = '' +
    '#gimLock{position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;' +
    'background:radial-gradient(1200px 700px at 50% 0%,#241a44 0%,#120c22 60%,#0b0716 100%);padding:20px;overflow:auto}' +
    '#gimBox{width:min(440px,92vw);background:#1a1030;border:1px solid #3b2a63;border-radius:20px;' +
    'padding:34px 30px;box-shadow:0 24px 70px rgba(0,0,0,.55);text-align:center;margin:auto}' +
    '#gimBox .ico{font-size:44px;line-height:1}' +
    '#gimBox h1{margin:12px 0 4px;font-size:23px;color:#efe9ff;font-weight:800;letter-spacing:-.3px}' +
    '#gimBox p{margin:0 0 20px;font-size:14px;color:#9b8fc4;line-height:1.6}' +
    '#gimBox p.sub{margin:6px 0 18px}' +
    '#gimPw{width:100%;box-sizing:border-box;padding:14px 16px;font-size:17px;text-align:center;' +
    'letter-spacing:2px;border-radius:12px;border:1px solid #4a3878;background:#120c22;color:#efe9ff;outline:none}' +
    /* 비밀번호 칸(type=password)은 휴대폰 키보드가 한글 조합을 끈다 — 천지인은 획을 모아
       글자를 만드는 방식이라 아예 입력이 안 된다(쿼티는 되는 것처럼 보임). 그래서 보통 글자 칸에
       점으로 가리기만 한다. */
    '#gimPw{-webkit-text-security:disc;text-security:disc}' +
    '#gimPw:placeholder-shown{-webkit-text-security:none}' +
    '#gimPw::placeholder{color:#5d5285;letter-spacing:0;font-size:13.5px}' +
    '#gimPw:focus{border-color:#8a6dff;box-shadow:0 0 0 3px rgba(138,109,255,.22)}' +
    '#gimGo,#gimGo2{width:100%;margin-top:12px;padding:14px;font-size:16px;font-weight:800;border:0;border-radius:12px;' +
    'background:linear-gradient(135deg,#8a6dff,#5b3fd6);color:#fff;cursor:pointer}' +
    '#gimGo:active,#gimGo2:active{transform:translateY(1px)}' +
    '#gimMsg{margin-top:14px;font-size:13.5px;min-height:19px;color:#9b8fc4;line-height:1.5}' +
    '#gimBox .note{margin-top:18px;padding-top:16px;border-top:1px solid #2e2150;font-size:12px;color:#7a6ea0;line-height:1.6}' +
    '#gimBox .bigcode{margin:10px 0 0;font-size:40px;font-weight:900;letter-spacing:4px;color:#ffd76a;' +
    'font-variant-numeric:tabular-nums}' +
    '#gimBox table.codes{width:100%;border-collapse:collapse;margin:6px 0 4px;font-size:13px}' +
    '#gimBox table.codes td{padding:6px 8px;border-top:1px solid #2e2150;color:#9b8fc4;text-align:left}' +
    '#gimBox table.codes td.c{text-align:right;color:#cfc4f0;font-weight:700;font-variant-numeric:tabular-nums}' +
    '#gimBox table.codes tr.now td{color:#ffd76a}' +
    '#gimBox table.codes tr.fold td.c{color:#5d5285;letter-spacing:1px}' +
    '#gimBox .codewrap{max-height:38vh;overflow:auto;margin:4px 0 2px}' +
    '#gimBox .foldwarn{margin:12px 0 4px;font-size:12.5px;color:#9b8fc4;cursor:pointer;' +
      'background:#241a44;border:1px solid #3b2a63;border-radius:10px;padding:8px 10px}' +
    '#gimBox button.cp{background:#2e2150;border:1px solid #4a3878;color:#cfc4f0;border-radius:8px;' +
      'padding:3px 8px;font-size:11.5px;cursor:pointer;font-family:inherit}' +
    '#gimBox button.cp:hover{background:#3b2a63}' +
    '#gimPanel{position:fixed;inset:0;z-index:99998;display:flex;align-items:center;justify-content:center;' +
      'background:rgba(9,6,20,.86);padding:20px;overflow:auto}' +
    '@keyframes gimShake{0%,100%{transform:translateX(0)}25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}' +
    'body.locked{overflow:hidden}';

  var HTML = '' +
    '<div id="gimLock"><div id="gimBox">' +
    '<div class="ico">🔒</div>' +
    '<h1>학습도구 허브</h1>' +
    '<p>관리용 목록입니다.<br>암호나 이번 주 코드를 넣어 주세요.</p>' +
    '<input id="gimPw" type="text" inputmode="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="8자 · 이번 주 코드 또는 이름번호" aria-label="암호">' +
    '<button id="gimGo">열기</button>' +
    '<div id="gimMsg"></div>' +
    '<div class="note">학생 코드는 그 주 월요일부터 7일간 씁니다.<br>' +
    '한 번 열면 이 기기에서는 다음부터 바로 들어갑니다.</div>' +
    '</div></div>';

  /* cb = 암호가 풀린 뒤 실행할 앱 시작 함수 */
  function mount(cb) {
    onOpen = cb;
    var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
    document.body.insertAdjacentHTML('beforeend', HTML);
    document.body.classList.add('locked');

    /* 이 환경에서 아예 안 되는 경우라면 암호를 묻지 않는다.
       입력칸을 그대로 두면 무엇이 문제인지 모른 채 암호만 다시 치게 된다. */
    var bad = blocker();
    if (bad) {
      var box = $('gimBox');
      box.innerHTML = '<div class="ico">⚠️</div><h1>' + bad.t + '</h1>' +
                      '<p style="text-align:left;line-height:1.7">' + bad.m + '</p>' +
                      '<div class="note">목록은 잠긴 채로 둡니다.</div>';
      return;
    }

    /* NFC — 조합이 덜 끝난 자모(ㅎㅗㅇ)가 섞여 들어와도 완성형(홍)과 같은 암호로 본다 */
    $('gimGo').onclick = function () { open($('gimPw').value.replace(/\s+/g, '').normalize('NFC')); };
    $('gimPw').addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.isComposing && e.keyCode !== 229) $('gimGo').click();
    });

    /* 이 도구에서 쓰던 것 → 공용 것 순서로 조용히 시도한다.
       교사용으로 자동 해제될 때는 코드 화면을 띄우지 않고 바로 들어간다
       (수업 중에 매번 코드표가 뜨면 방해가 된다). */
    var tries = [];
    try {
      var a = localStorage.getItem(LS_OWN), b = localStorage.getItem(LS_SHARED);
      if (a) tries.push(a);
      if (b && b !== a) tries.push(b);
    } catch (e) {}
    (function next(i) {
      if (i >= tries.length) { $('gimPw').focus(); return; }
      open(tries[i], true).then(function (ok) { if (!ok) next(i + 1); });
    })(0);
  }

  /* 이 기기(이 브라우저)에 기억된 암호를 지운다 — 공용 PC 에서 쓰고 난 뒤, 암호를 바꾼 뒤.
     허브 것(LS_OWN) · 도구 공용(LS_SHARED) · 잠긴 공유 링크에서 넣은 것(share_pw_v1) 을 모두 지운다.
     도구들이 같은 주소(hongyul67-cpu.github.io)라 공용 키를 지우면 다른 잠긴 도구도 다시 묻는다 — 그래서 먼저 묻는다.
     ask=false 면 묻지 않고 지운다. */
  function forget(ask) {
    if (ask !== false && !confirm(
      '이 기기에 기억된 암호를 지울까요?\n\n' +
      '· 이 허브를 다시 열 때 암호(또는 이번 주 코드)를 다시 넣어야 합니다.\n' +
      '· 같은 브라우저의 다른 잠긴 도구(기출문제 등)도 다시 묻습니다.\n' +
      '· 교사용 암호 자체가 바뀌는 것은 아닙니다.')) return false;
    try {
      localStorage.removeItem(LS_OWN);
      localStorage.removeItem(LS_SHARED);
      localStorage.removeItem('share_pw_v1');
    } catch (e) {}
    location.reload();
    return true;
  }

  /* 교사용으로 열려 있을 때 그 주 코드를 다시 보고 싶을 때 쓴다 */
  /* 이번 주 코드와 기간. 교사용으로 열었을 때만 값을 준다 —
     학생 코드로 들어온 사람에게 다음 주 코드까지 보여 주면 안 되기 때문이다. */
  function codes() {
    if (!info || info.role !== 'teacher' || !info.ms) return Promise.resolve(null);
    var mon = monday(new Date());
    return weekCode(b64(info.ms), mon).then(function (c) {
      return { code: pretty(c), raw: c, from: iso(mon), to: iso(addDays(mon, 7)) };
    });
  }

  /* 공유 링크·내보내기 파일을 잠그는 데 쓴다.
     sk 는 암호문 안에만 있으므로, 받은 사람도 교사용 암호나 그 주 코드를 넣어야 풀린다.
     tools.enc 가 sk 를 넣기 전 빌드면 null — 그때는 build_lock.py 를 다시 돌린다. */
  function shareKit() {
    if (!info || !info.sk || !kit) return null;
    return { sk: info.sk, kdf: kit.kdf, keys: kit.keys };
  }

  return { mount: mount, open: open, forget: forget, codes: codes, panel: panel, shareKit: shareKit,
           role: function () { return info && info.role; } };
})();
