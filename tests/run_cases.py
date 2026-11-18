"""
run_cases.py - 명령행 검증 도구

도구 실행 :python3 tests/run_cases.py tests/cases_fixed.csv

case 파일을 읽어 세 서버(취약 / 일반 패치 / 허니패치)에 요청을 보내고
각 입력의 판정과 근거(응답 내용, 진짜 토큰 포함 여부, 포크 여부)를 출력한다

종료 코드는 기대 판정과 모두 일치하면 0 하나라도 다르면 1이다

판정
    ok          : 정상 응답, 포크 없음, 진짜 토큰 없음
    leak        : 정상 응답처럼 보이지만 진짜 토큰이 노출됨
    error       : 오류 응답
    fork_noleak : decoy로 포크, 오류 없이 응답, 진짜 토큰 없음
"""

import csv
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client  # noqa: E402

# honeypatch/
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# honeypatch/tests/victims.txt 
VICTIMS = os.path.join(ROOT, "tests", "victims.txt")

# (서버 이름, case 파일에서 읽을 열 이름) 목록
# case 파일 형식 참고
SERVERS = [
    ("vuln", "expect_vuln"),
    ("patch", "expect_patch"),
    ("honey", "expect_honey"),
]

# 화면에 보여줄 한국어 이름
LABELS = {"vuln": "취약 서버", "patch": "일반 패치 서버", "honey": "허니패치 서버"}


# victims.txt에서 진짜 비밀 토큰 읽기
# 명령행 도구가 진짜 비밀을 알고 있기에 서버의 응답에서 비밀이 노출되었는지를 판단할 수 있다
def load_victim_tokens():
    tokens = {}
    with open(VICTIMS) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                tokens[parts[0]] = parts[1].encode()
    return tokens

# case 파일 읽기
# 주석을 제거하고 각 줄을 딕셔너리로 만든다
def load_cases(path):
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))

# 서버를 실행하고 종료한다 (with 문으로 사용)
class Server:

    def __init__(self, name, port, binary=None, env_extra=None):
        self.name = name
        self.port = port
        self.binary = binary or os.path.join(ROOT, "bin", name)
        self.log = os.path.join(ROOT, "logs", f"{name}.log")
        self.env_extra = env_extra or {}
        self.proc = None

    # 서버 시작
    def __enter__(self):
        # logs/ 디렉토리가 없다면 만든다
        os.makedirs(os.path.dirname(self.log), exist_ok=True)
        # 로그 파일을 "w"로 열어 내용을 비우고
        open(self.log, "w").close()
        # 현재 환경 변수에 HP_LOG 환경 변수를 추가한 env를 만든다 
        env = dict(os.environ, HP_LOG=self.log, **self.env_extra)

        # 서버를 자식 프로세스로 실행한다
        self.proc = subprocess.Popen(
            [self.binary, str(self.port), VICTIMS],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            # 서버는 새 프로세스 그룹으로 시작한다
            start_new_session=True,
        )

        if not client.wait_port(self.port):
            raise RuntimeError(f"{self.name} 서버가 시작되지 않았습니다")
        return self

    def __exit__(self, *exc):
        try:
            # 프로세스 그룹 전체를 종료한다
            # start_new_session=True로 서버가 새 그룹의 leader가 되었고 
            # 서버(target)가 fork로 생성한 decoy는 target과 같은 프로세스 그룹에 속한다
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait()

    ''' 로그 읽기 보조 함수 '''
    
    # 로그를 줄 단위로 읽어 리스트를 돌려준다
    def log_lines(self):
        with open(self.log) as f:
            return f.read().splitlines()

    # 전체 fork 횟수를 돌려준다 ([HP] fork decoy 줄의 개수)
    def fork_count(self):
        return sum("[HP] fork decoy" in ln for ln in self.log_lines())

    # 전체 메모리 영역의 크기를 돌려준다
    def arena_size(self):
        for ln in self.log_lines():
            if "arena=" in ln:
                return int(ln.split("arena=")[1].split()[0])
        return None

# 관찰 결과를 판정으로 요약한다
def judge(status, data, L, payload, leaked, forked, arena):
    
    if status == client.ST_ERR:
        return "error"
    expect_len = min(L, arena) if arena else L
    if len(data) != expect_len:
        return f"bad_len({len(data)})"
    if leaked:
        return "leak" if not forked else "fork_leak"
    if forked:
        return "fork_noleak"
    if L <= len(payload) and data != payload.encode()[:L]:
        return "bad_data"
    return "ok"

# 서버 응답을 사람이 읽을 수 있는 문자열로 바꿔준다
def preview(data, n=24):
    shown = data[:n]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in shown)
    return text + ("..." if len(data) > n else "")

# 사례 하나 실행
def run_case(srv, case, tokens):

    # 사례에서 L과 payload를 읽는다
    L = int(case["L"])
    payload = case["payload"]

    # fork 횟수가 늘었는지 판단하기 위해 요청 전 횟수를 저장한다
    before = srv.fork_count()

    # heartbeat 요청 전송 후 응답을 받는다
    status, data, rtt = client.heartbeat(srv.port, L, payload)

    # target과 client의 race를 고려해 요청 후 횟수를 세기 전에 잠시 대기한다
    # 환경에 따라 이 시간이 너무 짧으면 fork 기록을 세지 못할 수도 있다
    time.sleep(0.2)   

    # 요청 전, 후 fork 횟수 비교
    forked = srv.fork_count() > before

    # 비밀 토큰이 유출되었는지 판단
    leaked = [name for name, tok in tokens.items() if tok in data]

    # target이 다른 사용자의 요청을 계속 처리하는지 검증
    try:
        # 새 연결로 정상 요청을 보내본다
        st2, data2, _ = client.heartbeat(srv.port, 4, "PING")
        legit_ok = st2 == client.ST_OK and data2 == b"PING"
    except OSError:
        legit_ok = False

    # judge()로 얻은 판정과 기타 근거들을 딕셔너리로 만들어 돌려준다
    verdict = judge(status, data, L, payload, leaked, forked, srv.arena_size())
    return {
        "verdict": verdict, "status": status, "data": data, "rtt": rtt,
        "forked": forked, "leaked": leaked, "legit_ok": legit_ok,
    }


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    # case 읽기
    cases = load_cases(sys.argv[1])
    if not cases:
        print("검증 사례가 없습니다.")
        return 0

    # 진짜 토큰 읽기
    tokens = load_victim_tokens()

    # total = 전체 개수
    # passed = 통과 개수
    total = passed = 0

    for idx, (name, col) in enumerate(SERVERS):
        print(f"\n===== {LABELS[name]} ({name}) =====")

        with Server(name, 9100 + idx) as srv:       # enumerate()가 붙인 번호로 서버마다 다른 포트를 사용한다
            for case in cases:
                # 사례를 하나씩 실행한다
                r = run_case(srv, case, tokens)

                # case 파일에서 기대 판정을 꺼낸다
                expect = case[col]
                
                # 기대 판정과 일치 + 공격 이후 target이 정상 사용자 서비스 모두 만족해야 PASS(1)
                ok = r["verdict"] == expect and r["legit_ok"]

                total += 1
                passed += ok

                # 정보 출력
                st = "OK" if r["status"] == client.ST_OK else "ERROR"
                print(f"[{case['case']}] L={case['L']} P={case['payload']}  "
                      f"판정: {r['verdict']}  (기대: {expect})  -> {'PASS' if ok else 'FAIL'}")
                print(f"    응답: 상태 {st}, {len(r['data'])}바이트  \"{preview(r['data'])}\"")
                print(f"    진짜 토큰 포함: {', '.join(r['leaked']) if r['leaked'] else '없음'}"
                      f"  |  decoy 포크: {'예' if r['forked'] else '아니오'}"
                      f"  |  공격 직후 정상 요청: {'성공' if r['legit_ok'] else '실패'}")

    print(f"\n결과: {passed}/{total} PASS")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
