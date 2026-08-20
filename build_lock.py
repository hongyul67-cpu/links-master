# 도구 목록(tools.js) → 암호화(tools.enc)
#
#   python build_lock.py --pw <암호>
#
# 왜 이렇게 하나:
#   정적 호스팅(GitHub Pages)에서는 "화면에 비밀번호 입력칸"을 두어도 보호가 되지 않는다.
#   master.html 을 그대로 받아 열면 목록이 다 보이기 때문이다.
#   그래서 목록 자체를 AES-GCM 으로 암호화해서 올리고, 브라우저에서 WebCrypto 로 푼다.
#
# ⚠️ 평문 tools.js 는 .gitignore 에 들어 있다. 절대 커밋하지 말 것.
#    암호를 이 스크립트에 적어 두지 말 것 — 공개 저장소에 그대로 남는다.
import io, os, json, gzip, base64, argparse, sys, subprocess, tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ITER = 200_000


def eval_tools():
    driver = "process.stdout.write(JSON.stringify(require('./tools.js')));"
    with tempfile.NamedTemporaryFile("w", suffix=".js", dir=HERE, delete=False, encoding="utf-8") as f:
        f.write(driver); tmp = f.name
    try:
        r = subprocess.run(["node", tmp], capture_output=True, text=True, encoding="utf-8", cwd=HERE)
        if r.returncode:
            raise SystemExit("node 평가 실패:\n" + r.stderr)
        return r.stdout
    finally:
        os.remove(tmp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pw", required=True)
    a = ap.parse_args()

    payload = eval_tools()
    tools = json.loads(payload)
    raw = payload.encode("utf-8")
    gz = gzip.compress(raw, 9)

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=ITER).derive(a.pw.encode("utf-8"))
    ct = nonce + AESGCM(key).encrypt(nonce, gz, None)

    io.open(os.path.join(HERE, "tools.enc"), "w", encoding="utf-8").write(json.dumps({
        "v": 1, "iter": ITER,
        "salt": base64.b64encode(salt).decode(),
        "data": base64.b64encode(ct).decode(),
    }))

    # master.html 에 목록이 남아 있지 않은지 스스로 확인한다
    mh = io.open(os.path.join(HERE, "master.html"), encoding="utf-8").read()
    for t in tools[:20]:
        if t["name"] in mh:
            raise SystemExit("master.html 에 도구 이름이 남아 있습니다: " + t["name"])

    print("도구 %d개 · 원본 %dKB → gzip %dKB → tools.enc %dKB"
          % (len(tools), len(raw)//1024, len(gz)//1024,
             os.path.getsize(os.path.join(HERE, "tools.enc"))//1024))


if __name__ == "__main__":
    main()
