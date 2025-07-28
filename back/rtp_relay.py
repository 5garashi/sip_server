import socket
import threading
import time
import queue
import os
from datetime import datetime, timedelta
import re

RTP_PORT_MIN = 10000
RTP_PORT_MAX = 11000
LOG_FILE_PATH = "logs/rtp_relay.log"
MAX_LOG_DAYS = 7

def log(msg, level="brief"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted_msg = f"[{timestamp}] {msg}"
    if level == "debug" or level == "brief":
        print(formatted_msg)
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")
        # cleanup_old_logs()
    except Exception as e:
        print(f"[ERROR] Failed to write to log file: {e}")
        
def start_rtp_log_cleanup_thread():
    def cleanup_loop():
        while True:
            cleanup_old_logs()
            time.sleep(3600)  # once an hour
    threading.Thread(target=cleanup_loop, daemon=True).start()
    
def cleanup_old_logs():
    try:
        cutoff = datetime.now() - timedelta(days=MAX_LOG_DAYS)
        lines = []
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            for line in f:
                match = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', line)
                if match:
                    log_time = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                    if log_time >= cutoff:
                        lines.append(line)
                # Skip (remove) lines not starting with a timestamp
        with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"[ERROR] failure in cleanup_old_logs: {e}")
        
def is_rtcp_packet(data: bytes) -> bool:
    if len(data) < 2:
        return False
    pt = data[1]
    return 200 <= pt <= 204  # SR, RR, SDES, BYE, APP

# ==== 1 relay = 1 session UDPrelay ====
class UDPRelay:
    def __init__(self, port, call_id: str, is_rtcp=False):
        self.port = port
        self.call_id = call_id
        self.is_rtcp = is_rtcp
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.peer_a = None
        self.peer_b = None
        self.last_recv_time = time.time()
        self.running = True
        threading.Thread(target=self._receive_loop, daemon=True).start()

        proto = "RTCP" if self.is_rtcp else "RTP"
        log(f"{proto}Relay listening on port {port}", "debug")

    def get_port(self):
        return self.port

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except:
            pass

    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._handle_packet(addr, data)
            except Exception as e:
                log(f"Relay Error (port={self.port}): {e}", "error")

    def _handle_packet(self, addr, data):
        if not self.is_rtcp and is_rtcp_packet(data):
            log(f"[{self.port}] Warning: RTCP packet received on RTP relay from {addr}", "debug")
            return

        now = time.time()

        if self.peer_a is None and addr != self.peer_b:
            self.peer_a = addr
            log(f"[{self.port}] Set a={addr} for call_id={self.call_id}", "debug")
        elif self.peer_b is None and addr != self.peer_a:
            self.peer_b = addr
            log(f"[{self.port}] Set b={addr} for call_id={self.call_id}", "debug")

        if self.peer_a and self.peer_b:
            dst = self.peer_b if addr == self.peer_a else self.peer_a
            self.sock.sendto(data, dst)
            self.last_recv_time = now

class RTPRelayPool:
    TIMEOUT = 30  # sec. If there is no communication for this period, delete session.

    def __init__(self):
        self.sessions = {}  # call_id -> (rtpRelay, rtcpRelay)
        self.available_ports = queue.Queue()
        for port in range(RTP_PORT_MIN, RTP_PORT_MAX, 2):
            self.available_ports.put(port)

        # start monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_sessions, daemon=True)
        self.monitor_thread.start()

    def get_session(self, call_id: str):
        if call_id in self.sessions:
            return self.sessions[call_id]
        else:
            return None, None
        
    def create_session(self, call_id: str):
        if call_id in self.sessions:
            return self.sessions[call_id]

        if self.available_ports.empty():
            raise RuntimeError("No available RTP/RTCP ports")

        rtp_port = self.available_ports.get()
        rtcp_port = rtp_port + 1

        rtp_relay = UDPRelay(rtp_port, call_id, is_rtcp=False)
        rtcp_relay = UDPRelay(rtcp_port, call_id, is_rtcp=True)

        self.sessions[call_id] = (rtp_relay, rtcp_relay)
        log(f"Created RTP/RTCP Relay for call_id={call_id} on ports={rtp_port}/{rtcp_port}", "debug")
        return rtp_relay, rtcp_relay

    def get_ports(self, call_id: str):
        relays = self.sessions.get(call_id)
        if relays:
            return relays[0].get_port(), relays[1].get_port()
        return None, None

    def remove_session(self, call_id: str):
        relays = self.sessions.pop(call_id, None)
        if relays:
            for relay in relays:
                port = relay.get_port()
                relay.stop()
                self.available_ports.put(port)
                log(f"Removed Relay for call_id={call_id}, port {port} released", "debug")

    def _monitor_sessions(self):
        while True:
            now = time.time()
            to_remove = []
            for call_id, (rtp, rtcp) in list(self.sessions.items()):
                last_active = max(rtp.last_recv_time, rtcp.last_recv_time)
                if now - last_active > self.TIMEOUT:
                    log(f"[TIMEOUT] call_id={call_id} idle for {int(now - last_active)}s → delete sessions", "debug")
                    to_remove.append(call_id)

            for call_id in to_remove:
                self.remove_session(call_id)

            time.sleep(5)  # every 5 sec
