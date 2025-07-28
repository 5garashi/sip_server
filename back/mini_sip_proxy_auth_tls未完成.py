#===未完成===

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ssl
import threading
import re
import hashlib
import time
from datetime import datetime, timedelta
from rtp_relay import RTPRelayPool
import os

# ===================== 設定 =====================
TLS_PORT = 5061
CERT_FILE = "cert.pem"
KEY_FILE = "privkey.pem"
LISTEN_ADDR = "0.0.0.0"
BUFFER_SIZE = 8192

realm = "mini_sip_proxy_tls"
LOG_FILE_PATH = "sip_tls_server.log"
log_mode = "brief"
MAX_LOG_DAYS = 7

REWRITE_CONTACT = True
REWRITE_SDP = True
REWRITE_VIA = True

DUPLICATE_SUPPRESS_SECONDS = 5
silent_drop_unknown_users = True

# 登録ユーザー
auth_users = {
    "alice": "password1",
    "bob": "password2"
}

registered_users = {}  # user: (addr, contact, expire_time)
duplicate_cache = {}   # via_branch: timestamp
rtp_pool = RTPRelayPool()

# ===================== ログ関数 =====================
def log(msg, level="info"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{level.upper()}] {now} {msg}"
    print(line)
    with open(LOG_FILE_PATH, 'a') as f:
        f.write(line + "\n")

# ===================== ユーティリティ =====================
def parse_header(msg, name):
    for line in msg.split("\r\n"):
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return ""

def extract_username(msg):
    from_header = parse_header(msg, "From")
    match = re.search(r"sip:([^@;>"]+)", from_header)
    return match.group(1) if match else ""

def generate_nonce():
    return hashlib.md5(str(random()).encode()).hexdigest()

def is_duplicate(msg):
    match = re.search(r"Via:.*branch=([^;\s]+)", msg)
    if not match:
        return False
    branch = match.group(1)
    now = time.time()
    if branch in duplicate_cache and now - duplicate_cache[branch] < DUPLICATE_SUPPRESS_SECONDS:
        return True
    duplicate_cache[branch] = now
    return False

def rewrite_headers(msg, addr):
    lines = msg.split("\r\n")
    new_lines = []
    for line in lines:
        if REWRITE_CONTACT and line.lower().startswith("contact:"):
            m = re.search(r"sip:([^@>]+)@[^:>]+", line)
            if m:
                username = m.group(1)
                new_lines.append(f"Contact: <sip:{username}@{addr[0]}:{addr[1]}>")
                continue
        elif REWRITE_VIA and line.lower().startswith("via:"):
            line = re.sub(r"received=[^;\s]+", f"received={addr[0]}", line)
        new_lines.append(line)
    return "\r\n".join(new_lines)

def rewrite_sdp(msg, addr):
    if not REWRITE_SDP:
        return msg
    parts = msg.split("\r\n\r\n", 1)
    if len(parts) != 2:
        return msg
    headers, body = parts
    body = re.sub(r"c=IN IP4 [^\r\n]+", f"c=IN IP4 {addr[0]}", body)
    return headers + "\r\n\r\n" + body

# ===================== 認証処理 =====================
def check_auth(msg):
    auth = parse_header(msg, "Authorization")
    if not auth:
        return False
    match = re.search(r'username="([^"]+)", realm="([^"]+)", nonce="([^"]+)", uri="([^"]+)", response="([^"]+)"', auth)
    if not match:
        return False
    username, recv_realm, nonce, uri, response = match.groups()
    if username not in auth_users:
        return False
    ha1 = hashlib.md5(f"{username}:{recv_realm}:{auth_users[username]}".encode()).hexdigest()
    ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
    expected_response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return response == expected_response

# ===================== SIP処理 =====================
def handle_register(msg, addr, conn):
    username = extract_username(msg)
    if silent_drop_unknown_users and username not in auth_users:
        log(f"[SECURITY] Unknown user '{username}' → silent drop", "debug")
        return

    if "Authorization:" not in msg:
        nonce = generate_nonce()
        response = ("SIP/2.0 401 Unauthorized\r\n"
                    f"WWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\"\r\n"
                    "Content-Length: 0\r\n\r\n")
        conn.send(response.encode())
        return

    if not check_auth(msg):
        log(f"[AUTH] Failed auth: {username}", "warn")
        return

    registered_users[username] = (addr, parse_header(msg, "Contact"), datetime.now() + timedelta(minutes=30))
    log(f"[AUTH] Registered: {username} from {addr}", "info")
    conn.send(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")

# ===================== メイン受信処理 =====================
def handle_client(connstream, addr):
    try:
        data = connstream.recv(BUFFER_SIZE).decode(errors='ignore')
        if not data:
            return
        if is_duplicate(data):
            return

        method = data.split(" ", 1)[0]
        data = rewrite_headers(data, addr)
        data = rewrite_sdp(data, addr)

        if method == "REGISTER":
            handle_register(data, addr, connstream)
        else:
            log(f"[RECV] {method} from {addr}\n{data}", "debug")
            connstream.send(b"SIP/2.0 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
    except Exception as e:
        log(f"[ERROR] handle_client {addr} → {e}", "error")
    finally:
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except:
            pass
        connstream.close()

# ===================== メイン =====================
def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.bind((LISTEN_ADDR, TLS_PORT))
    bindsock.listen(5)

    log(f"[INFO] TLS SIP Proxy started on port {TLS_PORT}")

    while True:
        newsock, fromaddr = bindsock.accept()
        try:
            connstream = context.wrap_socket(newsock, server_side=True)
            threading.Thread(target=handle_client, args=(connstream, fromaddr), daemon=True).start()
        except ssl.SSLError as e:
            log(f"[TLS ERROR] Handshake failed from {fromaddr} → {e}", "error")

if __name__ == '__main__':
    main()
