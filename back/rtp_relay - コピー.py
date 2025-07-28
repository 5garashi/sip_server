import socket
import threading
import time
import queue

# 使用可能なUDPポート範囲
RTP_PORT_MIN = 10000
RTP_PORT_MAX = 11000

import os
from datetime import datetime

LOG_FILE_PATH = "logs/rtp_relay.log"

def log(message, level="debug"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] [{level.upper()}] {message}"
    
    # コンソール出力
    print(log_entry)

    # ログディレクトリがなければ作成
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)

    # ファイル追記
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")
        
def is_rtcp_packet(data: bytes) -> bool:
    if len(data) < 4:
        return False
    version = (data[0] >> 6) & 0b11
    pt = data[1]
    return (
        version == 2 and  # RTP/RTCPのVersionは2
        pt in {200, 201, 202, 203, 204}  # RTCPパケット（Payload Type 200〜204）をスキップ
    )
    
class RTPRelay:
    def __init__(self, port, is_rtcp=False):
        self.port = port
        self.is_rtcp = is_rtcp
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.sessions = {}  # call_id: {"a": addr, "b": addr}
        self.running = True
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def add_session(self, call_id):
        self.sessions[call_id] = {
            "a": None,
            "b": None,
            "last_recv_time": time.time()
        }

    def get_port(self):
        return self.port

    def stop(self):
        self.running = False
        self.sock.close()

    def _receive_loop(self):
        proto = "RTCP" if self.is_rtcp else "RTP"
        log(f"{proto}Relay listening on port {self.port}", "debug")
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._handle_rtp(addr, data)
            except Exception as e:
                log(f"{proto}Relay Error: {e}", "error")

    def _handle_rtp(self, addr, data):
        # # RTPの処理なら、RTCPっぽいパケット（Payload Type 200〜204）をスキップ
        # if self.is_rtcp is False and data and (200 <= data[1] <= 204):  # RTCPのパケットタイプ範囲
        #     log(f"[{self.port}] Warning: RTCPっぽいパケットをRTPリレーで受信: {addr}, PT={data[1]}", "warning")
        #     return
        # 正確なRTCP判定
        if not self.is_rtcp and is_rtcp_packet(data):
            log(f"[{self.port}] Warning: RTCPパケットをRTPリレーで受信: {addr}, PT={data[1]}", "warning")
            return

        now = time.time()
        for call_id, sess in self.sessions.items():
            a, b = sess["a"], sess["b"]
            if a is None and b != addr:
                sess["a"] = addr
                log(f"[{self.port}] Set a={addr} for call_id={call_id}", "debug")
            elif b is None and a != addr:
                sess["b"] = addr
                log(f"[{self.port}] Set b={addr} for call_id={call_id}", "debug")

            if a and b:
                dst = b if addr == a else a
                self.sock.sendto(data, dst)
                sess["last_recv_time"] = now
                return

class RTPRelayPool:
    def __init__(self):
        self.relays = {}  # key = f"{call_id}:rtp"/":rtcp"
        self.available_ports = queue.Queue()
        for port in range(RTP_PORT_MIN, RTP_PORT_MAX, 2):  # 10000, 10002, ...
            self.available_ports.put(port)

    def create_session(self, call_id):
        if call_id in self.relays:
            return self.relays[call_id]

        if self.available_ports.qsize() < 1:
            raise RuntimeError("No available RTP/RTCP port pairs")

        rtp_port = self.available_ports.get()
        rtcp_port = rtp_port + 1  # RTPとRTCPはペア（連番）

        # RTCPポートがすでに他で使われていないか確認
        if rtcp_port >= RTP_PORT_MAX:
            raise RuntimeError("Not enough port range for RTP/RTCP pair")

        rtp_relay = RTPRelay(rtp_port, is_rtcp=False)
        rtcp_relay = RTPRelay(rtcp_port, is_rtcp=True)
        
        rtp_relay.add_session(call_id)
        rtcp_relay.add_session(call_id)

        self.relays[call_id] = (rtp_relay, rtcp_relay)

        log(f"Created RTP/RTCP Relay for call_id={call_id} on ports={rtp_port}/{rtcp_port}", "debug")
        return rtp_relay, rtcp_relay
    
    def get_ports(self, call_id):
        relays = self.relays.get(call_id)
        if relays:
            rtp_relay, rtcp_relay = relays
            return rtp_relay.get_port(), rtcp_relay.get_port()
        return None, None


    def remove_session(self, call_id):
        relays = self.relays.pop(call_id, None)
        if relays:
            for relay in relays:
                port = relay.get_port()
                relay.stop()
                self.available_ports.put(port)
                log(f"Removed Relay for call_id={call_id}, port {port} released", "debug")

