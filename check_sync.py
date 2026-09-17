# master.html 과 links/s.html 의 "같아야 하는 코드"가 아직 같은지 검사한다.
#
#   python check_sync.py                    ← ../links/s.html 을 찾아서 비교
#   python check_sync.py 다른/경로/s.html   ← 경로를 직접 줄 때
#
# 왜 필요한가:
#   공유 잠금 코드(gB64 · gateTry · gateUnseal · gateMount)는 두 파일에 같은 내용이
#   들어 있어야 한다. 내보내기 파일이 이 함수들을 toString() 으로 그대로 퍼 담기 때문에
#   한쪽만 고치면 "내 화면에서는 되는데 받은 사람은 안 열리는" 일이 생긴다.
#   지금까지는 주석에 "고치면 둘 다 고칠 것"이라고 적어 두고 손으로 지켜 왔는데,
#   바쁠 때 한 번 놓치면 알아채기가 어렵다. 그래서 기계가 대신 봐 준다.
#
#   ※ 저장소가 둘로 나뉘어 있어(links-master / links) 파일 하나로 합칠 수가 없다.
#     s.html 을 links-master 로 옮기면 학생이 주소를 잘라 전체 목록을 보게 된다.
#     그래서 "합치기" 대신 "어긋나면 알려 주기"로 간다.
import io, os, sys, difflib

HERE = os.path.dirname(os.path.abspath(__file__))
START = "function gB64("
LAST = "function gateMount("


def grab(path):
    """두 파일에 공통으로 들어 있는 잠금 코드 덩어리를 뽑아낸다."""
    s = io.open(path, encoding="utf-8").read()
    try:
        i = s.index(START)
        j = s.index(LAST)
        k = s.index("\n}\n", j) + 3          # gateMount 가 끝나는 줄머리 }
    except ValueError:
        raise SystemExit("  ⛔ %s 에서 잠금 코드를 찾지 못했습니다.\n"
                         "     함수 이름이 바뀌었다면 check_sync.py 의 START·LAST 도 고쳐 주세요." % path)
    return s[i:k]


def main(other=None):
    """other 를 주지 않으면 ../links/s.html 을 찾는다.
    build_lock.py 가 부를 때도 쓰므로 sys.argv 는 __main__ 에서만 본다."""
    mine = os.path.join(HERE, "master.html")
    if other is None:
        other = os.path.join(os.path.dirname(HERE), "links", "s.html")

    if not os.path.exists(other):
        print("  · s.html 을 찾지 못해 비교를 건너뜁니다: %s" % other)
        print("    (links 저장소를 옆에 받아 두면 자동으로 검사합니다)")
        return 0

    a, b = grab(mine), grab(other)
    if a == b:
        print("  ✅ master.html 과 s.html 의 잠금 코드가 같습니다 (%d줄)" % a.count("\n"))
        return 0

    print("  ⛔ master.html 과 s.html 의 잠금 코드가 어긋났습니다.")
    print("     내보내기 파일이 받는 사람 쪽에서 안 열릴 수 있습니다. 둘을 맞춰 주세요.")
    print("")
    for line in difflib.unified_diff(a.splitlines(), b.splitlines(),
                                     "master.html", os.path.basename(other), lineterm="", n=2):
        print("     " + line)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
