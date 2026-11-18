""" client.py - 하트비트 프로토콜 클라이언트 """

'''
요청: [레코드 길이 2B][선언 길이 L 2B][payload] (빅엔디언, 레코드 길이 = 2 + |P|)
응답: [상태 1B][길이 2B][데이터]
'''

import socket
import struct
import time

ST_OK = 0x00
ST_ERR = 0x01

# 정확히 n바이트 받기
# server.c의 recv_all()과 같은 역할
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf

# 서버에 접속
def connect(port, host="127.0.0.1", timeout=3.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s

# 요청 하나를 보내고 (상태, 데이터)를 돌려준다
def send_heartbeat(sock, L, payload):

    if isinstance(payload, str):
        payload = payload.encode()

    ''' 요청 형식 [레코드 길이 2B][선언 길이 L 2B][payload] '''
    req = struct.pack(">HH", 2 + len(payload), L) + payload
    sock.sendall(req)
    status, length = struct.unpack(">BH", _recv_exact(sock, 3))
    data = _recv_exact(sock, length) if length else b""
    return status, data

# 새 연결로 요청 하나를 보내고 (상태, 데이터, 걸린 시간 초)를 돌려준다
def heartbeat(port, L, payload, host="127.0.0.1"):

    t0 = time.perf_counter()
    with connect(port, host) as s:
        status, data = send_heartbeat(s, L, payload)
    return status, data, time.perf_counter() - t0


def wait_port(port, host="127.0.0.1", timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False
