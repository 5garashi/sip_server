#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import re
from datetime import datetime
import sys
import hashlib
import random

# ========== 設定 ==========
SIP_PORT = 5060
SIP_IP = '0.0.0.0'
BUFFER_SIZE = 8192
realm = "mini_sip_proxy"

LOG_MODE = "brief"
if len(sys.argv) >= 2 and sys.argv[1] == "debug":
    LOG_MODE = "debug"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SIP_IP, SIP_PORT))
print(f"[INFO] SIPサーバー起動 on {SIP_IP}:{SIP_PORT}")

auth_users = {
    "001": "www001",
    "002": "www001",
    "003": "www001",
    "user1": "www001"
}
nonces = {}
registered_users = {}
call_sessions = {}

# ========== ログ ==========
def log(msg, level="brief"):
    if LOG_MODE == "debug" or level == "brief":
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

# ========== ヘッダー解析 ==========
def parse_header(header_name, data):
    pattern = rf'^{header_name}:\s*(.*)$'
    for line in data.splitlines():
        match = re.match(pattern, line, re.IGNORECASE)
        if match:
            return match.group(0).strip()
    return ''

def parse_username(sip_uri):
    match = re.search(r'sip:([^@]+)@', sip_uri)
    return match.group(1) if match else None

# ========== 認証処理 ==========
def generate_nonce():
    return hashlib.md5(str(random.random()).encode()).hexdigest()

def parse_digest_auth(header):
    auth_data = {}

    # Authorization: Digest ... の Digest 以降を取り出す
    match = re.search(r'Digest\s+(.*)', header)
    if not match:
        return None

    digest_fields = match.group(1)
    parts = digest_fields.split(',')

    for part in parts:
        if '=' in part:
            k, v = part.strip().split('=', 1)
            auth_data[k.strip()] = v.strip().strip('"')

    return auth_data

# def parse_digest_auth(header):
#     auth_data = {}
#     if 'Digest' not in header:
#         return None
#     parts = header.replace("Digest", "").strip().split(",")
#     for part in parts:
#         if '=' in part:
#             k, v = part.strip().split('=', 1)
#             auth_data[k.strip()] = v.strip().strip('"')
#     return auth_data

def validate_digest(auth_data, method):
    username = auth_data.get("username")
    password = auth_users.get(username)
    if not password:
        return False
    a1 = f'{username}:{realm}:{password}'
    a2 = f'{method}:{auth_data.get("uri")}'
    ha1 = hashlib.md5(a1.encode()).hexdigest()
    ha2 = hashlib.md5(a2.encode()).hexdigest()
    expected_response = hashlib.md5(f'{ha1}:{auth_data.get("nonce")}:{ha2}'.encode()).hexdigest()
    return expected_response == auth_data.get("response")

def send_to(message, dst_addr):
    try:
        sock.sendto(message.encode(), dst_addr)
        log(f"[send_to] {message} → {dst_addr}")
    except Exception as e:
        log(f"[ERROR] send_to(): {e}")

def send_response(code, reason, original_msg, dst_addr, add_tag=False, level="brief"):
    via = parse_header("Via", original_msg)
    to = parse_header("To", original_msg)
    from_ = parse_header("From", original_msg)
    call_id = parse_header("Call-ID", original_msg)
    cseq = parse_header("CSeq", original_msg)
    if add_tag:
        to += ";tag=67890"
    response = f"SIP/2.0 {code} {reason}\r\n{via}\r\n{to}\r\n{from_}\r\n{call_id}\r\n{cseq}\r\nContent-Length: 0\r\n\r\n"
    send_to(response, dst_addr)
    log(f"[送信] {code} {reason} → {dst_addr}", level)

def send_401_unauthorized(data, addr):
    via = parse_header("Via", data)
    to = parse_header("To", data)
    from_ = parse_header("From", data)
    call_id = parse_header("Call-ID", data)
    cseq = parse_header("CSeq", data)

    username = parse_username(to)
    nonce = generate_nonce()
    if username:
        nonces[username] = nonce

    auth_header = f'WWW-Authenticate: Digest realm="{realm}", nonce="{nonce}", algorithm=MD5'
    response = f"SIP/2.0 401 Unauthorized\r\n{via}\r\n{to}\r\n{from_}\r\n{call_id}\r\n{cseq}\r\n{auth_header}\r\nContent-Length: 0\r\n\r\n"
    send_to(response, addr)
    log(f"[送信] 401 Unauthorized → {addr} (nonce: {nonce})")

# ========== REGISTER ==========
def handle_register(data, udp_src_addr):
    method = "REGISTER"
    auth_header = parse_header("Authorization", data)

    if not auth_header:
        log(f"[INFO] Authorization ヘッダーなし → 401 を返す", "debug")
        send_401_unauthorized(data, udp_src_addr)
        return

    auth_data = parse_digest_auth(auth_header)
    if not auth_data or not validate_digest(auth_data, method):
        log(f"[WARN] Digest認証失敗 (REGISTER): {auth_data}", "debug")
        send_401_unauthorized(data, udp_src_addr)
        return

    username = auth_data.get("username")
    registered_users[username] = udp_src_addr
    log(f"[INFO] REGISTER 認証成功: {username} → {udp_src_addr}", "debug")
    send_response("200", "OK", data, udp_src_addr, add_tag=False, level="debug")

# ========== INVITE ==========
def handle_invite(data, udp_src_addr):
    method = "INVITE"
    auth_header = parse_header("Authorization", data)

    if not auth_header:
        log(f"[INFO] Authorization ヘッダーなし → 401 を返す", "debug")
        send_401_unauthorized(data, udp_src_addr)
        return

    auth_data = parse_digest_auth(auth_header)
    if not auth_data or not validate_digest(auth_data, method):
        log(f"[WARN] Digest認証失敗 (INVITE): {auth_data}", "debug")
        send_401_unauthorized(data, udp_src_addr)
        return

    callee = parse_username(parse_header("To", data))
    caller = parse_username(parse_header("From", data))
    call_id = parse_header("Call-ID", data)

    if callee == "999":
        log(f"[INFO] ダイヤル999受信 → 登録ユーザー一覧を表示")
        for user, (ip, port) in registered_users.items():
            print(f"[REGISTERED] {user}: {ip}:{port}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return

    send_response("100", "Trying", data, udp_src_addr, add_tag=True)

    if callee in registered_users:
        dst = registered_users[callee]
        call_sessions[call_id] = {'from': udp_src_addr, 'to': dst}
        send_to(data, dst)
        log(f"[INFO] INVITE 転送 → {callee} ({dst})")
    else:
        log(f"[WARN] 宛先ユーザー未登録: {callee}", "debug")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)

# ========== その他 ==========
def handle_response(data, udp_src_addr):
    call_id = parse_header("Call-ID", data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']
        send_to(data, dst)
        log(f"[INFO] RESPONSE 転送 → {dst}")

def handle_ack_or_bye(data, udp_src_addr):
    call_id = parse_header("Call-ID", data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']
        send_to(data, dst)
        if data.startswith("BYE"):
            log(f"[INFO] BYE 転送 → {dst}")
            call_sessions.pop(call_id, None)
        elif data.startswith("ACK"):
            log(f"[INFO] ACK 転送 → {dst}")

def get_sip_method(msg):
    try:
        first_line = msg.splitlines()[0].strip().upper()
    except IndexError:
        return "IndexError"
    if first_line.startswith("REGISTER"):
        return "REGISTER"
    if first_line.startswith("INVITE"):
        return "INVITE"
    if first_line.startswith("ACK"):
        return "ACK"
    if first_line.startswith("BYE"):
        return "BYE"
    if first_line.startswith("SIP/2.0"):
        return "RESPONSE"
    return "UNKNOWN"

def main_loop():
    while True:
        data, udp_src_addr = sock.recvfrom(BUFFER_SIZE)
        try:
            msg = data.decode(errors="ignore").lstrip()
        except Exception as e:
            log(f"[ERROR] デコード失敗 from {udp_src_addr}: {e}", "debug")
            continue

        method = get_sip_method(msg)
        log(f"[受信] {method} from {udp_src_addr}", "debug")

        if method == "REGISTER":
            handle_register(msg, udp_src_addr)
        elif method == "INVITE":
            handle_invite(msg, udp_src_addr)
        elif method == "ACK" or method == "BYE":
            handle_ack_or_bye(msg, udp_src_addr)
        elif method == "RESPONSE":
            handle_response(msg, udp_src_addr)
        else:
            log(f"[WARN] 未サポートのSIPメソッド: {method}", "debug")

if __name__ == "__main__":
    main_loop()
