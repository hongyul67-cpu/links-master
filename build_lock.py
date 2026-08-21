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
import io, os, re, json, gzip, base64, argparse, sys, subprocess, tempfile, secrets
from datetime import date
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "_weekly"))
import weekly                                   # 도구 공용 주간 코드
ITER = 200_000


def eval_tools():
    driver = "process.stdout.write(JSON.stringify(require('./tools.js')));"
    with tempfile.NamedTemporaryFile("w", suffix=".js", dir=HERE, delete=False, encoding="utf-8") as f:
        f.write(driver)
        tmp = f.name
    try:
        r = subprocess.run(["node", tmp], capture_output=True, text=True, encoding="utf-8", cwd=HERE)
        if r.returncode:
            raise SystemExit("node 평가 실패:\n" + r.stderr)
        return r.stdout
    finally:
        os.remove(tmp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pw", required=True, help="교사용 암호 (만료 없음)")
    a = ap.parse_args()

    cfg = weekly.load()
    start = date.fromisoformat(cfg["epoch"])
    nweeks = cfg["weeks"]

    payload = eval_tools()
    tools = json.loads(payload)
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
    keys = [wrap(a.pw, {"ck": ck_b64, "exp": None, "role": "teacher", "label": "교사용",
                        "ms": base64.b64encode(MASTER).decode(),
                        "epoch": start.isoformat(), "weeks": nweeks,
                        "prefix": cfg["prefix"]})]

    print("  키 감싸기 교사용 1개 + 학생용 %d주치 ..." % nweeks, end="", flush=True)
    sheet = weekly.weeks(cfg)
    for n, d0, d1, c in sheet:
        keys.append(wrap(c, {"ck": ck_b64, "nbf": d0.isoformat(), "exp": d1.isoformat(),
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

    cur = weekly.this_week(cfg)
    print("  도구 %d개 · 원본 %dKB -> gzip %dKB -> tools.enc %dKB"
          % (len(tools), len(raw) // 1024, len(gz) // 1024,
             os.path.getsize(os.path.join(HERE, "tools.enc")) // 1024))
    print("")
    print("  교사용 암호 : %s   (만료 없음)" % a.pw)
    print("  학생 코드   : %d주치  %s ~ %s  (도구 공용)" % (nweeks, start, sheet[-1][2]))
    if cur:
        print("  이번 주 코드: %s %s   (%s ~ %s)" % (cur[3][:4], cur[3][4:], cur[1], cur[2]))


if __name__ == "__main__":
    main()
