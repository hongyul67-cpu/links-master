# 도구 목록(tools.js) -> 암호화(tools.enc)
#
#   python build_lock.py --pw <교사용 암호>
#
# 왜 이렇게 하나:
#   정적 호스팅(GitHub Pages)에서는 "화면에 비밀번호 입력칸"을 두어도 보호가 되지 않는다.
#   master.html 을 그대로 받아 열면 목록이 다 보이기 때문이다.
#   그래서 목록 자체를 AES-GCM 으로 암호화해서 올리고, 브라우저에서 WebCrypto 로 푼다.
#
# 암호가 두 종류인 이유:
#   교사용 - 문구형, 만료 없음. 열면 그 주 학생 코드가 화면에 바로 나온다.
#   학생용 - 8자리 숫자, 그 주 월요일 ~ 다음 월요일 7일만.
#   목록은 임의의 내용키(CK)로 한 번 암호화하고, CK 를 암호마다 따로 감싼다.
#   감싼 것들은 순서를 섞어 어느 것이 교사용인지 알 수 없다.
#
#   시크릿·기준일·접두어는 _weekly/secret.json 에 모아 두고 모든 도구가 함께 쓴다.
#   그래서 어느 도구에서든 같은 8자리가 통하고, 다시 빌드해도 코드가 바뀌지 않는다.
#
# 주의: 평문 tools.js 는 .gitignore 에 있다. 절대 커밋하지 말 것.
#       암호를 이 스크립트에 적어 두지 말 것 - 공개 저장소에 그대로 남는다.
import io, os, re, json, gzip, base64, argparse, sys, subprocess, tempfile, secrets, hmac, hashlib
from datetime import date
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "_weekly"))
import weekly                                   # 도구 공용 주간 코드
ITER = 200_000


def eval_js(name):
    """node 로 <name>.js 를 평가해 JSON 문자열로 받는다."""
    driver = "process.stdout.write(JSON.stringify(require('./%s')));" % name
    with tempfile.NamedTemporaryFile("w", suffix=".js", dir=HERE, delete=False, encoding="utf-8") as f:
        f.write(driver)
        tmp = f.name
    try:
        r = subprocess.run(["node", tmp], capture_output=True, text=True, encoding="utf-8", cwd=HERE)
        if r.returncode:
            raise SystemExit("node 평가 실패(%s):\n%s" % (name, r.stderr))
        return r.stdout
    finally:
        os.remove(tmp)


def eval_tools():
    return eval_js("tools.js")


AREAS_START = "/* AREAS-START */"
AREAS_END = "/* AREAS-END */"
AREAS_GONE = "const AREAS = window.HUB_AREAS || [];"


def load_areas():
    """분야·과목 목록을 areas.js 에서 읽는다.

    areas.js 가 아직 없으면 master.html 안에 남아 있는 목록을 꺼내 만들어 준다(한 번만).
    master.html 의 그 자리는 빈 [] 로 바꿔 둔다 — 그 블록은 잠금이 가려 주지 못해서,
    그냥 두면 잠금 화면에서 소스 보기만 해도 과목 이름이 전부 보이기 때문이다.
    옮긴 뒤로는 tools.enc 안에 암호화되어 들어가고, 화면은 거기서 받아 쓴다.
    """
    fp = os.path.join(HERE, "areas.js")
    mfp = os.path.join(HERE, "master.html")
    html = io.open(mfp, encoding="utf-8").read()

    if not os.path.exists(fp):
        if AREAS_START not in html or AREAS_END not in html:
            raise SystemExit(
                "areas.js 도 없고 master.html 에서 분야 목록도 찾지 못했습니다.\n"
                "  master.html 의 /* AREAS-START */ ~ /* AREAS-END */ 표시를 확인하세요.")
        i = html.index(AREAS_START) + len(AREAS_START)
        j = html.index(AREAS_END)
        block = html[i:j]
        body = block[block.index("["):block.rindex("]") + 1]
        io.open(fp, "w", encoding="utf-8").write(
            "// 분야(대분류) → 그 아래 과목(중분류) 순서.\n"
            "// master.html 에 두면 잠금 화면에서도 소스 보기로 다 보여서 이리로 옮겼습니다.\n"
            "// .gitignore 에 있어 올라가지 않습니다. 올라가는 것은 암호화본 tools.enc 뿐입니다.\n"
            "// 새 과목을 만들면 tools.js 의 cat 과 글자가 정확히 같아야 합니다.\n"
            "//\n"
            "// ⚠️ 맨 끝 줄은 화면에서 항상 맨 아래로 내려갑니다 (내부·관리용 자리).\n"
            "//   새 분야는 그 앞에 넣으세요. 맨 뒤에 붙이면 내부용이 위로 올라옵니다.\n"
            "module.exports = " + body + ";\n")
        print("  · 분야 목록을 master.html 에서 areas.js 로 옮겼습니다 (이제 tools.enc 안에 암호화됩니다)")

    if AREAS_START in html and AREAS_END in html:
        i, j = html.index(AREAS_START), html.index(AREAS_END) + len(AREAS_END)
        if AREAS_GONE not in html[i:j]:
            io.open(mfp, "w", encoding="utf-8").write(
                html[:i] + AREAS_START + "\n" + AREAS_GONE + "\n" + AREAS_END + html[j:])
            print("  · master.html 에 남아 있던 분야 목록을 지웠습니다")

    return json.loads(eval_js("areas.js"))



def read_deployed(pw):
    """지금 올라가 있는 tools.enc 를 같은 교사용 암호로 풀어 도구 이름을 돌려준다.

    tools.js 는 .gitignore 라 내 PC에만 있다. 다른 기기/세션에서 추가한 카드는
    tools.enc 에만 들어 있어서, 낡은 tools.js 로 그냥 다시 빌드하면 그 카드가
    조용히 사라진다(2026-08-25 에 실제로 2장이 사라질 뻔했다).
    그래서 빌드 전에 지금 파일을 풀어 이름을 맞춰 본다.
    """
    fp = os.path.join(HERE, "tools.enc")
    if not os.path.exists(fp):
        return None
    try:
        enc = json.loads(io.open(fp, encoding="utf-8").read())
        salt = base64.b64decode(enc["kdf"]["salt"])
        it = enc["kdf"].get("iter", ITER)
        key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=it).derive(pw.encode("utf-8"))
        ck = None
        for k in enc["keys"]:                      # 어느 것이 교사용인지 감춰 뒀으니 다 해 본다
            try:
                info = json.loads(AESGCM(key).decrypt(
                    base64.b64decode(k["iv"]), base64.b64decode(k["blob"]), None))
                ck = base64.b64decode(info["ck"]); break
            except Exception:
                continue
        if ck is None:
            return None                            # 암호가 다르거나 형식이 바뀐 경우
        body = base64.b64decode(enc["data"])
        gz = AESGCM(ck).decrypt(body[:12], body[12:], None)
        old = json.loads(gzip.decompress(gz).decode("utf-8"))
        if isinstance(old, dict):          # 새 형식 {tools, areas} · 옛 형식은 배열이었다
            old = old.get("tools", [])
        return [t.get("name") for t in old]
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pw", help="교사용 암호 (만료 없음). 생략하면 _weekly/secret.json 의 teacher_pw 를 쓴다")
    ap.add_argument("--allow-remove", action="store_true",
                    help="지금 올라간 목록에서 카드가 빠지는 것을 알고도 진행")
    ap.add_argument("--show-pw", action="store_true",
                    help="끝에 교사용 암호를 가리지 않고 그대로 찍는다 (옆에 사람이 없을 때만)")
    a = ap.parse_args()

    cfg = weekly.load()
    # 교사용 암호도 주간 코드와 같은 공용 설정에서 가져온다.
    # 손으로 넣지 않아도 되고, 도구 넷이 같은 암호를 쓰게 되어 어긋날 일이 없다.
    # (--pw 를 주면 그쪽이 우선 — 암호를 바꿀 때만 쓴다)
    if not a.pw:
        a.pw = cfg.get("teacher_pw")
        if not a.pw:
            raise SystemExit("교사용 암호가 없습니다 - --pw 로 주거나 _weekly/secret.json 에 teacher_pw 를 넣으세요")
    start = date.fromisoformat(cfg["epoch"])
    nweeks = cfg["weeks"]

    tools = json.loads(eval_tools())
    areas = load_areas()          # 분야·과목 목록도 함께 암호화해 넣는다

    # 낡은 tools.js 로 덮어써서 남의 카드를 지우는 사고를 막는다
    old_names = read_deployed(a.pw)
    if old_names is None:
        print("  ⚠ 지금 올라간 tools.enc 를 풀어 보지 못했습니다 — 목록 비교를 건너뜁니다.")
    else:
        new_names = [t.get("name") for t in tools]
        lost = [n for n in old_names if n not in set(new_names)]
        added = [n for n in new_names if n not in set(old_names)]
        print("  지금 올라간 목록 %d개 · 새로 올릴 목록 %d개" % (len(old_names), len(new_names)))
        for n in added:
            print("    + %s" % n)
        if lost:
            print("")
            print("  ⛔ 아래 %d개가 이 빌드에서 사라집니다:" % len(lost))
            for n in lost:
                print("    - %s" % n)
            if not a.allow_remove:
                raise SystemExit(
                    "\n  내 tools.js 가 배포본보다 뒤처져 있을 수 있습니다.\n"
                    "  먼저 위 카드를 tools.js 에 되살리세요.\n"
                    "  정말로 빼려는 것이면 --allow-remove 를 붙이세요.")
            print("  --allow-remove 가 있어 그대로 진행합니다.")

    payload = json.dumps({"tools": tools, "areas": areas},
                         ensure_ascii=False, separators=(",", ":"))
    raw = payload.encode("utf-8")
    gz = gzip.compress(raw, 9)

    # 1) 목록을 임의의 내용키(CK)로 한 번만 암호화
    CK = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    body = nonce + AESGCM(CK).encrypt(nonce, gz, None)

    # 2) 암호마다 CK 를 감싼다 (salt 를 공유해 해제 시 PBKDF2 는 딱 1회)
    salt = secrets.token_bytes(16)
    MASTER = base64.b64decode(cfg["secret"])     # 도구 공용 - 새로 만들지 않는다

    def derive(p):
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                          salt=salt, iterations=ITER).derive(p.encode("utf-8"))

    def wrap(p, info):
        iv = secrets.token_bytes(12)
        blob = AESGCM(derive(p)).encrypt(iv, json.dumps(info).encode("utf-8"), None)
        return {"iv": base64.b64encode(iv).decode(),
                "blob": base64.b64encode(blob).decode()}

    ck_b64 = base64.b64encode(CK).decode()
    # 공유 키(sk) - [링크+QR]·[HTML 내보내기]로 나가는 도구 목록을 이 키로 암호화한다.
    # 받은 사람은 교사용 암호나 그 주 코드로 여기 감싼 것을 풀어야 sk 를 얻는다.
    # 시크릿에서 뽑으므로 다시 빌드해도 바뀌지 않는다 - 바뀌면 나눠 준 링크가 전부 안 열린다.
    sk_b64 = base64.b64encode(hmac.new(MASTER, b"HONG-SHARE|v1", hashlib.sha256).digest()).decode()
    keys = [wrap(a.pw, {"ck": ck_b64, "sk": sk_b64, "exp": None, "role": "teacher", "label": "교사용",
                        "ms": base64.b64encode(MASTER).decode(),
                        "epoch": start.isoformat(), "weeks": nweeks,
                        "prefix": cfg["prefix"]})]

    print("  키 감싸기 교사용 1개 + 학생용 %d주치 ..." % nweeks, end="", flush=True)
    sheet = weekly.weeks(cfg)
    for n, d0, d1, c in sheet:
        keys.append(wrap(c, {"ck": ck_b64, "sk": sk_b64, "nbf": d0.isoformat(), "exp": d1.isoformat(),
                             "role": "student", "label": d0.isoformat()}))
    print(" 완료")
    secrets.SystemRandom().shuffle(keys)         # 어느 것이 교사용인지 감춘다

    io.open(os.path.join(HERE, "tools.enc"), "w", encoding="utf-8").write(json.dumps({
        "v": 2, "cipher": "AES-GCM", "gz": True,
        "kdf": {"name": "PBKDF2", "hash": "SHA-256", "iter": ITER,
                "salt": base64.b64encode(salt).decode()},
        "data": base64.b64encode(body).decode(),
        "keys": keys,
    }))

    # master.html 이 부르는 lock.js 주소에 빌드 표식을 박는다.
    # 안 하면 브라우저가 옛 lock.js 를 캐시에서 꺼내 쓴다.
    build_id = secrets.token_hex(4)
    fp = os.path.join(HERE, "master.html")
    html = io.open(fp, encoding="utf-8").read()
    fixed = re.sub(r"lock\.js\?v=[A-Za-z0-9]*", "lock.js?v=" + build_id, html)
    if fixed != html:
        io.open(fp, "w", encoding="utf-8").write(fixed)

    # master.html 에 목록이 남아 있지 않은지 스스로 확인한다
    mh = io.open(os.path.join(HERE, "master.html"), encoding="utf-8").read()
    for t in tools[:20]:
        if t["name"] in mh:
            raise SystemExit("master.html 에 도구 이름이 남아 있습니다: " + t["name"])
    # 분야·과목 이름도 마찬가지다. 이 파일은 잠금이 가려 주지 못한다.
    for area in areas:
        if area[0] in mh:
            raise SystemExit("master.html 에 분야 이름이 남아 있습니다: " + area[0])
        for c in area[1]:
            if c in mh:
                raise SystemExit("master.html 에 과목 이름이 남아 있습니다: " + c)

    # master.html 과 links/s.html 의 잠금 코드가 아직 같은지 확인한다.
    # 한쪽만 고치면 "내 화면에서는 되는데 받은 사람은 안 열리는" 일이 생긴다.
    # links 저장소를 옆에 받아 두지 않았으면 조용히 건너뛴다.
    try:
        import check_sync
        if check_sync.main() != 0:
            raise SystemExit("\n  잠금 코드가 어긋났습니다. 위 차이를 맞춘 뒤 다시 빌드하세요.")
    except ImportError:
        pass

    cur = weekly.this_week(cfg)
    print("  도구 %d개 · 원본 %dKB -> gzip %dKB -> tools.enc %dKB"
          % (len(tools), len(raw) // 1024, len(gz) // 1024,
             os.path.getsize(os.path.join(HERE, "tools.enc")) // 1024))
    print("")
    # 암호를 통째로 찍지 않는다. 연수 시연이나 화면 공유 중에 그대로 보이기 때문이다.
    # 맞게 들어갔는지만 확인하면 되므로 앞 두 글자와 길이만 보여 준다.
    shown = a.pw if a.show_pw else (a.pw[:2] + "*" * (len(a.pw) - 2) + " (%d자)" % len(a.pw))
    print("  교사용 암호 : %s   (만료 없음)" % shown)
    if not a.show_pw:
        print("                전체를 보려면 --show-pw 를 붙이세요 (옆에 사람이 없을 때만)")
    print("  학생 코드   : %d주치  %s ~ %s  (도구 공용)" % (nweeks, start, sheet[-1][2]))
    if cur:
        print("  이번 주 코드: %s %s   (%s ~ %s)" % (cur[3][:4], cur[3][4:], cur[1], cur[2]))


if __name__ == "__main__":
    main()
