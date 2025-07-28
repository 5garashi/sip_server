#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import re
from datetime import datetime, timedelta
import sys
import hashlib
import random
import os

# ========== 設定 ==========
SIP_PORT = 5060
SIP_IP = '0.0.0.0'
BUFFER_SIZE = 8192
realm = "mini_sip_proxy"
LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sip_server.log")
LOG_MODE = "brief"
MAX_LOG_DAYS = 7


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
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted_msg = f"[{timestamp}] {msg}"
    if LOG_MODE == "debug" or level == "brief":
        print(formatted_msg)
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")
        cleanup_old_logs()
    except Exception as e:
        print(f"[ERROR] ログファイル書き込み失敗: {e}")

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
                # タイムスタンプで始まらない行はスキップ（削除）
        with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"[ERROR] ログの整理失敗: {e}")

# ========== ヘッダー解析 ==========
# def parse_header(header_name, data):
#     pattern = rf'^{header_name}:\s*(.*)$'
#     for line in data.splitlines():
#         match = re.match(pattern, line, re.IGNORECASE)
#         if match:
#             return match.group(0).strip()
#     return ''
def parse_header(header_name, data):
    if isinstance(data, bytes):
        data = data.decode(errors="ignore")
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
        if isinstance(message, str):
            message = message.encode()
        sock.sendto(message, dst_addr)
        log(f"[send_to] {message.decode(errors='ignore')} → {dst_addr}","debug")
    except Exception as e:
        log(f"[ERROR] send_to(): {e}")


# def send_to(message, dst_addr):
#     try:
#         sock.sendto(message.encode(), dst_addr)
#         log(f"[send_to] {message} → {dst_addr}")
#     except Exception as e:
#         log(f"[ERROR] send_to(): {e}")

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

# ========== 400 Bad Request 送信 ==========
def send_400_bad_request(original_msg, dst_addr):
    send_response("400", "Bad Request", original_msg, dst_addr, add_tag=False)
    log(f"[INFO] 400 Bad Request 送信 → {dst_addr}", level="debug")

# ========== 401 Unauthorized 送信 ==========
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
    
# ========== 487 Request Terminated 送信 ==========
def send_487_terminated(original_msg, dst_addr):
    call_id = parse_header("Call-ID", original_msg)
    call_sessions.pop(call_id, None)  # セッション削除
    send_response("487", "Request Terminated", original_msg, dst_addr, add_tag=True)
    log(f"[INFO] 487 Request Terminated 送信 → {dst_addr}", level="debug")
    log(f"[INFO] call_sessions から削除: Call-ID={call_id}", level="debug")

# def send_487_terminated(original_msg, dst_addr):
#     call_id = parse_header("Call-ID", original_msg)
#     call_sessions.pop(call_id, None)  # セッション削除
#     send_response("487", "Request Terminated", original_msg, dst_addr, add_tag=True)
#     log(f"[INFO] 487 Request Terminated 送信 → {dst_addr}", level="debug")
    
# ========== 603 Decline 送信 ==========
def send_603_decline(original_msg, dst_addr):
    call_id = parse_header("Call-ID", original_msg)
    call_sessions.pop(call_id, None)  # セッション削除
    send_response("603", "Decline", original_msg, dst_addr, add_tag=True)
    log(f"[INFO] 603 Decline 送信 → {dst_addr}", level="debug")


# ========== REGISTER ==========
# Contactヘッダー自動書き換えを有効にするか
REWRITE_CONTACT = False  # ← 端末側のSTUN設定を基本とするため、Contactの書き換えは無効にする

def rewrite_contact_header(msg, src_addr):
    # Contact: <sip:002@192.168.25.14:5064> をグローバルIPに書き換える
    if not REWRITE_CONTACT:
        return msg

    new_msg_lines = []
    for line in msg.splitlines():
        if line.lower().startswith("contact:"):
            match = re.search(r'sip:([^@>]+)@([^:>]+)(?::(\d+))?', line)
            if match:
                username = match.group(1)
                ip = src_addr[0]
                port = str(src_addr[1])
                new_contact = f"Contact: <sip:{username}@{ip}:{port}>"
                new_msg_lines.append(new_contact)
                continue
        new_msg_lines.append(line)
    return "\r\n".join(new_msg_lines)

def handle_register(data, udp_src_addr):
    method = "REGISTER"
    if isinstance(data, bytes):
        data = data.decode(errors="ignore")
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

    if REWRITE_CONTACT:
        data = rewrite_contact_header(data, udp_src_addr)

    log(f"[INFO] REGISTER 認証成功: {username} → {udp_src_addr}", "debug")
    send_response("200", "OK", data, udp_src_addr, add_tag=False, level="debug")
    
# ========== BYE ==========    
# def handle_bye(data, udp_src_addr):
#     call_id = parse_header("Call-ID", data)
#     session = call_sessions.pop(call_id, None)

#     if session:
#         # もう一方の相手を判定して転送
#         if udp_src_addr == session["from"]:
#             target = session["to"]
#         else:
#             target = session["from"]

#         send_to(data, target)
#         log(f"[INFO] BYE転送: Call-ID={call_id} → {target}")
#     else:
#         log(f"[WARN] BYE対象なし: Call-ID={call_id}", "debug")

# ========== CANCEL ==========
def handle_cancel(data, udp_src_addr):
    call_id = parse_header("Call-ID", data)
    session = call_sessions.get(call_id)

    if session:
        # INVITEを転送した相手にCANCELを送る
        send_to(data, session["to"])
        log(f"[INFO] CANCEL転送: Call-ID={call_id} → {session['to']}")
    else:
        log(f"[WARN] CANCEL対象なし: Call-ID={call_id}", "debug")

# ========== 888ダイヤルで call_sessions 出力 ==========
def print_call_sessions():
    log("[INFO] call_sessions 内容:")
    if not call_sessions:
        log("[SESSION] (空です)")
    for call_id, session in call_sessions.items():
        log(f"[SESSION] Call-ID: {call_id}, from: {session['from']}, to: {session['to']}")

# ========== 990ダイヤルで registered_users を NOTIFY ==========
def notify_registered_users(to_addr, request_msg):
    via = parse_header("Via", request_msg)
    from_ = parse_header("From", request_msg)
    to = parse_header("To", request_msg)
    call_id = parse_header("Call-ID", request_msg)
    cseq = "CSeq: 1 NOTIFY"
    contact = "Contact: <sip:server@localhost>"
    event = "Event: registered-users"
    content_type = "Content-Type: text/plain"
    body = "\r\n".join([f"{u} → {ip}:{port}" for u, (ip, port) in registered_users.items()])
    content_length = f"Content-Length: {len(body)}"

    notify = f"NOTIFY sip:{parse_username(to)} SIP/2.0\r\n{via}\r\n{to}\r\n{from_}\r\n{call_id}\r\n{cseq}\r\n{contact}\r\n{event}\r\n{content_type}\r\n{content_length}\r\n\r\n{body}"
    send_to(notify, to_addr)
    log(f"[INFO] NOTIFY 送信（registered_users）→ {to_addr}")

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

    if callee == "888":
        log(f"[INFO] ダイヤル888受信 → call_sessionsを表示")
        print_call_sessions()
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return

    if callee == "990":
        log(f"[INFO] ダイヤル990受信 → 登録ユーザー一覧をNOTIFYで通知")
        notify_registered_users(udp_src_addr, data)
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return

    if callee == "999":
        log(f"[INFO] ダイヤル999受信 → 登録ユーザー一覧を表示")
        for user, (ip, port) in registered_users.items():
            log(f"[REGISTERED] {user}: {ip}:{port}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return

    send_response("100", "Trying", data, udp_src_addr, add_tag=True)

    if callee in registered_users:
        dst = registered_users[callee]
        call_sessions[call_id] = {'from': udp_src_addr, 'to': dst}
        send_to(data, dst)
        log(f"[送信] INVITE 転送 → {callee} ({dst})")
        
        # target_addr = registered_users[callee]
        # # active_calls に登録
        # active_calls[call_id] = {
        #     "caller_addr": udp_src_addr,
        #     "callee_addr": target_addr,
        # }
        # log(f"[INFO] INVITE保存: Call-ID={call_id}, from={udp_src_addr}, to={target_addr}", "debug")

    else:
        log(f"[WARN] 宛先ユーザー未登録: {callee}", "debug")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)

# ========== その他 ==========
# def handle_response(data, udp_src_addr):
#     call_id = parse_header("Call-ID", data)
#     if call_id in call_sessions:
#         session = call_sessions[call_id]
#         dst = session['from'] if udp_src_addr == session['to'] else session['to']
#         send_to(data, dst)
#         log(f"[INFO] RESPONSE 転送 → {dst}")
        
def handle_response(data, udp_src_addr):
    call_id = parse_header("Call-ID",data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']#addrと違う方を指定（相手を指定）
        log(f"dst:{dst}, addr:{udp_src_addr}, session['from']{session['from']}, session['to']:{session['to']}")
        # send_to(data, dst)
        # log(f"[送信] → {dst}")
        status_line = data.splitlines()[0].strip().upper()
        log(f"[RESPONSE DATA] {status_line} → {dst}")
        if "180 RINGING" in status_line:
            send_to(data, dst)
            log(f"[送信] 180 Ringing → {dst}")
        elif "200 OK" in status_line:
            send_to(data, dst)
            log(f"[送信] 200 OK → {dst}")
        elif "100 TRYING" in status_line:
            log(f"[INFO] 100 Trying → {dst}")
        elif "400 BAD REQUEST" in status_line:
            # send_400_bad_request(data, dst)
            log(f"[INFO] 400 Bad Request → {dst}")
        elif "487 REQUEST TERMINATED" in status_line:
            send_487_terminated(data, dst)
            log(f"[送信] 487 Request Terminated → 発信者 {dst} に転送", "debug")
        elif "603 DECLINE" in status_line:
            send_603_decline(data, dst)
            log(f"[送信] 603 Decline → {dst}")
        else:
            log(f"[送信] UNKNOWN → {dst}")
            log(f"[INFO] {data} → {dst}","debug")
            send_to(data, dst)
            
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
    if first_line.startswith("CANCEL"):
        return "CANCEL"
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
        elif method == "CANCEL":
            handle_cancel(data, udp_src_addr)
        else:
            log(f"[WARN] 未サポートのSIPメソッド: {method}", "debug")

if __name__ == "__main__":
    main_loop()
