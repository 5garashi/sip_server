#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# from multiprocessing.reduction import duplicate
import socket
import re
from datetime import datetime, timedelta
import sys
import hashlib
import random
import os
import ipaddress
import threading
import time
#rep_relayを開始：
from rtp_relay import RTPRelayPool
rtp_pool = RTPRelayPool()


# ========== 設定 ==========
SIP_PORT = 5060
SIP_IP = '0.0.0.0'
BUFFER_SIZE = 8192
realm = "mini_sip_proxy"
LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sip_server.log")
log_mode = "brief"
MAX_LOG_DAYS = 7
DUPLICATE_SUPPRESS_SECONDS = 5  # 重複メッセージを無視する秒数
duplicate= False  # 重複メッセージを無視するかどうか
# Contactヘッダー書き換え
rewrite_contact = False  # ← 端末側のSTUN設定を基本とするため、Contactの書き換えは無効にする
# SDPのc=アドレス書き換え
rewrite_sdp = False
# Viaヘッダーの書き換え
rewrite_via = False  # Viaヘッダーの書き換えを有効にする（NAT環境での受信元IPアドレスを追加）
# オプション設定: True にすると自分自身のIPとポートをViaヘッダーに使用
silent = False  # True にすると、認証されていないユーザーからのパケットは無応答で破棄
USE_PROXY_ADDR_IN_VIA = True

# プロキシ自身のグローバルIPとポート（SIPでバインドしているもの）
PROXY_PUBLIC_IP = "3.212.8.147"
PROXY_SIP_PORT = 5060

msg=''
if len(sys.argv) >= 2:
    if "debug" in sys.argv:
        log_mode = "debug"
        msg=log_mode+", "
    if "re_contact" in sys.argv:
        rewrite_contact = True
        msg+= "REWRITE_CONTACT, "
    if "re_sdp" in sys.argv:
        rewrite_sdp = True
        msg+= "REWRITE_SDP, "
    if "re_via" in sys.argv:
        rewrite_via = True
        msg+= "REWRITE_VIA, "
    if "duplicate" in sys.argv:
        duplicate = True
        msg+= "DUPLICATE, "
    if "silent" in sys.argv:
        silent = True
        msg+= "SILENT"
        
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SIP_IP, SIP_PORT))
print(f"[INFO] SIPサーバー起動 on {SIP_IP}:{SIP_PORT} {msg}")

auth_users = {
    "001": "www001",
    "002": "www001",
    "003": "www001",
    "004": "www001",
    "005": "www001",
    "006": "www001",
    "007": "www001",
    "008": "www001",
    "009": "www001",
    "user1": "www001"
}
nonces = {}
registered_users = {}
call_sessions = {}
# call_sessions[call_id] = {
#     "from": from_addr,
#     "to": to_addr,
#     "last_activity": datetime.now()
# }
last_received_messages = {}  # Call-ID + CSeq をキーにして5秒以内の重複を無視する

# ========== ログ ==========
def log(msg, level="brief"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted_msg = f"[{timestamp}] {msg}"
    if log_mode == "debug" or level == "brief":
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
    log(f"[送信] 401 Unauthorized → {addr} (nonce: {nonce})","debug")
    
# ========== 487 Request Terminated 送信 ==========
def send_487_terminated(original_msg, dst_addr):
    call_id = parse_header("Call-ID", original_msg)
    call_sessions.pop(call_id, None)  # セッション削除
    rtp_pool.remove_session(call_id)
    send_response("487", "Request Terminated", original_msg, dst_addr, add_tag=True)
    log(f"[INFO] 487 Request Terminated 送信 → {dst_addr}", level="debug")
    log(f"[INFO] call_sessions から削除: Call-ID={call_id}", level="debug")
  
# ========== 603 Decline 送信 ==========
def send_603_decline(original_msg, dst_addr):
    call_id = parse_header("Call-ID", original_msg)
    call_sessions.pop(call_id, None)  # セッション削除
    rtp_pool.remove_session(call_id)
    send_response("603", "Decline", original_msg, dst_addr, add_tag=True)
    log(f"[INFO] 603 Decline 送信 → {dst_addr}", level="debug")
# ========== SDPのc=アドレスの書き換え ==========
def allocate_rtp_port() -> int:
    """使用可能なUDPポートを動的に確保して返す（偶数ポート）"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()

    # RTPは偶数ポートが慣例（RTCP用に隣を空ける）
    return port if port % 2 == 0 else port - 1

def rewrite_sdp_media_port(msg: str, new_port: int) -> str:
    """
    SDPの m= 行（m=audio, m=video, m=applicationなど）のポート番号をすべて指定されたポートに書き換える。
    
    Parameters:
        msg (str): SIPメッセージ全体
        new_port (int): 書き換えるポート番号（RTP中継で使用するポート）
    
    Returns:
        str: 書き換え後のメッセージ文字列
    """
    lines = msg.splitlines()
    new_lines = []
    in_sdp = False

    for line in lines:
        # SDPセクションに入ってからm=行を探す
        if in_sdp and line.startswith("m="):
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1].isdigit():
                parts[1] = str(new_port)  # ポート番号だけを書き換える
                line = " ".join(parts)

        new_lines.append(line)

        # 空行を境にSDPセクション開始と判定
        if line.strip() == "":
            in_sdp = True

    return "\r\n".join(new_lines) + "\r\n"



def extract_sdp_connection_address(msg: str) -> str:
    """
    SIPメッセージからSDPセクション内の c=IN IP4 アドレスを抽出する。
    
    Parameters:
        msg (str): SIPメッセージ全体

    Returns:
        str | None: IPアドレス（例: "192.168.1.10"）または見つからなければ None
    """
    in_sdp = False
    for line in msg.splitlines():
        if in_sdp and line.startswith("c=IN IP4 "):
            parts = line.strip().split()
            if len(parts) == 3:
                return parts[2]
        if line.strip() == "":
            in_sdp = True  # 空行を境にSDPセクションが始まる
    return None

def rewrite_sdp_connection_address(msg: str, ip: str, rtp_port: int) -> str:
    new_msg_lines = []
    in_sdp = False
    for line in msg.splitlines():
        if in_sdp:
            if line.startswith("c=IN IP4 "):
                new_msg_lines.append(f"c=IN IP4 {ip}")
                continue
            if line.startswith("m=audio "):
                parts = line.strip().split()
                if len(parts) >= 2:
                    parts[1] = str(rtp_port)
                    new_msg_lines.append(" ".join(parts))
                    continue
        new_msg_lines.append(line)
        if line.strip() == "":
            in_sdp = True
    return "\r\n".join(new_msg_lines) + "\r\n"


# ========== Contactヘッダーの書き換え ==========
# Contactヘッダーを送信元のIPアドレスに書き換える
# 送信元IPが信頼できない場合は、PUBLIC_IPに置き換える
# 信頼できないIPアドレス帯は UNTRUSTED_PREFIXES

# def is_untrusted_ip(ip):
#     return any(ip.startswith(prefix) for prefix in UNTRUSTED_PREFIXES)
# def is_untrusted_ip(ip):
#     return ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172.")

def is_global_ip(ip: str) -> bool:
    # プライベートIPアドレス範囲かどうかを判定
    return not (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31
    )



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
    call_id = parse_header("Call-ID", data)
    data = rewrite_contact_and_sdp_for_nat(data, udp_src_addr, call_id, rtp_pool)

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
        # 相手に CANCEL 転送
        send_to(data, session["to"])
        log(f"[INFO] CANCEL転送: Call-ID={call_id} → {session['to']}")

        # CANCEL 送信者に 200 OK 応答（CANCEL自体に対して）
        send_response("200", "OK", data, udp_src_addr, add_tag=True)
        log(f"[INFO] CANCEL元に 200 OK 送信 → {udp_src_addr}")

        # CANCEL に対応する ACK（元のINVITEのACKではなく、CANCEL受領に対するOK）
        # SIPでは CANCEL には 200 OK を返すだけで ACK は不要です。
        # ACK は INVITE に対する 200 OK に返信されるため、CANCELでは通常送られません。
    else:
        log(f"[WARN] CANCEL対象なし: Call-ID={call_id}", "debug")
        send_response("481", "Call/Transaction Does Not Exist", data, udp_src_addr, add_tag=True)
        log(f"[INFO] CANCEL元に 481 応答 → {udp_src_addr}")

# def handle_cancel(data, udp_src_addr):
#     call_id = parse_header("Call-ID", data)
#     session = call_sessions.get(call_id)

#     if session:
#         # INVITEを転送した相手にCANCELを送る
#         send_to(data, session["to"])
#         log(f"[INFO] CANCEL転送: Call-ID={call_id} → {session['to']}")
#     else:
#         log(f"[WARN] CANCEL対象なし: Call-ID={call_id}", "debug")

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

    # # ✅ セッション単位で重複INVITE防止（5秒以内）
    # now = datetime.now()
    # session = call_sessions.get(call_id)
    # if session:
    #     elapsed = (now - session["timestamp"]).total_seconds()
    #     if elapsed < DUPLICATE_SUPPRESS_SECONDS:
    #         log(f"[INFO] INVITE 無視（{elapsed:.1f}秒以内の重複）: Call-ID={call_id}", "debug")
    #         return
    global rewrite_contact
    global rewrite_sdp
    global log_mode
    global rewrite_via
    global duplicate
    global silent
    if callee == "985":
        silent =  False
        log(f"[INFO] ダイヤル{callee}受信 → silent={silent}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "986":
        silent =  True
        log(f"[INFO] ダイヤル{callee}受信 → silent={silent}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return    
    if callee == "987":
        duplicate =  False
        log(f"[INFO] ダイヤル{callee}受信 → duplicate={duplicate}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "988":
        duplicate =  True
        log(f"[INFO] ダイヤル{callee}受信 → duplicate={duplicate}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return    
    if callee == "989":
        log_mode =  "brief"
        log(f"[INFO] ダイヤル{callee}受信 → log_mode={log_mode}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "990":
        log_mode =  "debug"
        log(f"[INFO] ダイヤル{callee}受信 → log_mode={log_mode }")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "991":
        rewrite_via =  False
        log(f"[INFO] ダイヤル{callee}受信 → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "992":
        rewrite_via =  True
        log(f"[INFO] ダイヤル{callee}受信 → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "993":
        rewrite_sdp =  False
        log(f"[INFO] ダイヤル{callee}受信 → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "994":
        rewrite_sdp = True
        log(f"[INFO] ダイヤル{callee}受信 → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "995":
        rewrite_contact = False
        log(f"[INFO] ダイヤル{callee}受信 → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "996":
        rewrite_contact = True
        log(f"[INFO] ダイヤル{callee}受信 → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "997":
        log(f"[INFO] ダイヤル{callee}受信 → call_sessionsを表示")
        print_call_sessions()
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "998":
        log(f"[INFO] ダイヤル{callee}受信 → 登録ユーザー一覧をNOTIFYで通知")
        notify_registered_users(udp_src_addr, data)
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "999":
        log(f"[INFO] ダイヤル{callee}受信 → 登録ユーザー一覧を表示")
        for user, (ip, port) in registered_users.items():
            log(f"[REGISTERED] {user}: {ip}:{port}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return

    send_response("100", "Trying", data, udp_src_addr, add_tag=True)

    if callee in registered_users:
        dst = registered_users[callee]
        call_sessions[call_id] = {'from': udp_src_addr, 'to': dst}
        rtp_relay, rtcp_relay = rtp_pool.create_session(call_id)
        data = rewrite_contact_and_sdp_for_nat(data, udp_src_addr, call_id, rtp_pool)
        send_to(data, dst)
        log(f"[送信] INVITE 転送 → {callee} ({dst})")
    else:
        log(f"[WARN] 宛先ユーザー未登録: {callee}", "debug")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)

# ========== その他 ==========
        
def handle_response(data, udp_src_addr):
    call_id = parse_header("Call-ID",data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']#addrと違う方を指定（相手を指定）
        log(f"dst:{dst}, addr:{udp_src_addr}, session['from']{session['from']}, session['to']:{session['to']}")
        data = rewrite_contact_and_sdp_for_nat(data, udp_src_addr, call_id, rtp_pool)            
        status_line = data.splitlines()[0].strip().upper()
        log(f"[RESPONSE DATA] {status_line} → {dst}")
        if "100 TRYING" in status_line:
            log(f"[INFO] 100 Trying → {dst}")
        elif "180 RINGING" in status_line:
            send_to(data, dst)
            log(f"[送信] 180 Ringing → {dst}")
        elif "183 SESSION PROGRESS" in status_line:
            send_to(data, dst)
            log(f"[送信] 183 Session Progress → {dst}")
        elif "200 OK" in status_line:
            cseq_line = parse_header("CSeq", data)
            if "BYE" in cseq_line:
                log(f"[送信] 200 OK (BYE) → {dst}")
                call_sessions.pop(call_id, None)
                rtp_pool.remove_session(call_id)
            elif "INVITE" in cseq_line:
                log(f"[送信] 200 OK (INVITE) → {dst}")
            else:
                log(f"[送信] 200 OK (Other) → {dst}")
            send_to(data, dst)

        elif "400 BAD REQUEST" in status_line:
            # send_400_bad_request(data, dst)
            log(f"[INFO] 400 Bad Request → {dst}")
        elif "404 NOT FOUND" in status_line:
            call_sessions.pop(call_id, None)
            rtp_pool.remove_session(call_id)
            log(f"[送信] 404 Not Found → {dst}（セッション削除）")
            send_to(data, dst)
        elif "408 REQUEST TIMEOUT" in status_line:
            call_sessions.pop(call_id, None)
            rtp_pool.remove_session(call_id)
            log(f"[送信] 408 Request Timeout → {dst}（セッション削除）")
            send_to(data, dst)
        elif "481 CALL/TRANSACTION DOES NOT EXIST" in status_line:
            # Call-IDに対応するセッションが存在しない場合の処理
            call_sessions.pop(call_id, None)
            rtp_pool.remove_session(call_id)
            log(f"[INFO] 481 Call/Transaction Does Not Exist → セッション削除 Call-ID={call_id}", "debug")
            send_to(data, dst)
            log(f"[送信] 481 Call/Transaction Does Not Exist → {dst}")
        elif "486 BUSY HERE" in status_line:
            call_sessions.pop(call_id, None)
            rtp_pool.remove_session(call_id)
            send_to(data, dst)
            log(f"[送信] 486 Busy Here → {dst}（セッション削除）", "debug")
        elif "487 REQUEST TERMINATED" in status_line:
            send_487_terminated(data, dst)
            log(f"[送信] 487 Request Terminated → 発信者 {dst} に転送", "debug")
        elif "488 NOT ACCEPTABLE HERE" in status_line:
            call_sessions.pop(call_id, None)
            rtp_pool.remove_session(call_id)
            log(f"[送信] 488 Not Acceptable Here → {dst}（セッション削除）")
            send_to(data, dst)
        elif "603 DECLINE" in status_line:
            send_603_decline(data, dst)
            log(f"[送信] 603 Decline → {dst}")
        else:
            log(f"[INFO] {data} → {dst}","debug")
            # log(f"[送信] UNKNOWN → {dst}")
            # send_to(data, dst)

def extract_from_username(msg: str) -> str | None:
    """
    SIPメッセージのFromヘッダーからユーザー名を抽出する。
    例:
        From: "004" <sip:004@1.2.3.4>              → '004'
        From: <sip:004@[3.212.8.147:5060]>         → '004'
        From: sip:004@192.168.1.1                  → '004'
    """
    match = re.search(r'^From:\s*.*?<?sip:([^@>]+)@\[?[^\]>]+]?(?::\d+)?>?', msg, re.MULTILINE | re.IGNORECASE)
    return match.group(1) if match else None


def extract_to_username(msg: str) -> str | None:
    """
    SIPメッセージのToヘッダーからユーザー名を抽出する。
    例:
        To: <sip:002@1.2.3.4>         → '002'
        To: <sip:002@[3.212.8.147:5060]> → '002'
    """
    match = re.search(r'^To:\s*.*?<?sip:([^@>]+)@\[?[^\]>]+]?(?::\d+)?>?', msg, re.MULTILINE | re.IGNORECASE)
    return match.group(1) if match else None

def should_forward_ack(msg: str) -> bool:
    # ACKでなければFalse
    if not msg.startswith("ACK") and "ACK" not in msg.splitlines()[0]:
        return False

    # To: ヘッダーから tag の有無を確認
    match = re.search(r"^To:\s.*tag=([\w\-\.]+)", msg, re.MULTILINE | re.IGNORECASE)
    if match:
        return True  # tagがある → 200 OKへのACK → 転送すべき
    else:
        return False  # tagがない → 401などへのACK → 転送不要


def handle_ack(msg: str, src_addr: tuple):
    if not should_forward_ack(msg):
        log(f"[ACK] 401 Unauthorized等tagがないACKは、転送せず", "debug")
        return
    from_user = extract_from_username(msg)
    to_user = extract_to_username(msg)

    if to_user in registered_users:
        ip, port = registered_users[to_user]
        log(f"[送信] ACK: {from_user} → {to_user} @ {ip}:{port}")
        sock.sendto(msg.encode(), (ip, port))
    else:
        log(f"[WARN] ACK宛先 {to_user} が未登録のため転送不可", "warn") 
            
def handle_bye(data, udp_src_addr):
    call_id = parse_header("Call-ID", data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']
        data = rewrite_contact_and_sdp_for_nat(data, udp_src_addr, call_id, rtp_pool)

        send_to(data, dst)
        if data.startswith("BYE"):
            log(f"[INFO] BYE 転送 → {dst}")
            # call_sessions.pop(call_id, None)
            # rtp_pool.remove_session(call_id)
        elif data.startswith("ACK"):
            log(f"[INFO] ACK 転送 → {dst}")
def handle_options(msg: str, src_addr: tuple):
    log(f"[受信] OPTIONS from {src_addr}")

    via = parse_header("Via", msg)
    to = parse_header("To", msg)
    from_ = parse_header("From", msg)
    call_id = parse_header("Call-ID", msg)
    cseq = parse_header("CSeq", msg)

    response = f"""SIP/2.0 200 OK
{via}
{to}
{from_}
{call_id}
{cseq}
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER
Content-Length: 0

"""
    send_to(response, src_addr)
    log(f"[送信] OPTIONS応答 200 OK → {src_addr}")


def rewrite_via_header(msg: str, src_addr: tuple) -> str:
    """
    Viaヘッダーに received と rport を追加する（SIPリクエスト時）。
    src_addr: NAT後の送信元IP/Port（ソースアドレス）
    オプションで、received/rport に SIPプロキシ自身のIP/Portを使うことも可能。
    """
    new_lines = []
    for line in msg.splitlines():
        if line.lower().startswith("via:"):
            ip = PROXY_PUBLIC_IP if USE_PROXY_ADDR_IN_VIA else src_addr[0]
            port = PROXY_SIP_PORT if USE_PROXY_ADDR_IN_VIA else src_addr[1]

            # rport が存在するが値が未設定の場合 → 追加
            if "rport" in line:
                line = re.sub(r"rport(?!\=)", f"rport={port}", line)
            else:
                # rport がない場合 → 末尾に追加
                line = line.strip() + f";rport={port}"

            # received がない場合 → 追加
            if "received=" not in line:
                line = line.strip() + f";received={ip}"

        new_lines.append(line)

    return "\r\n".join(new_lines) + "\r\n"

#未使用
def rewrite_sip_headers_for_nat(msg: str, src_addr: tuple) -> str:
    msg = rewrite_via_header(msg, src_addr)
    msg = rewrite_contact_header(msg, src_addr)
    return msg
#未使用
def rewrite_contact_header(msg: str, src_addr: tuple) -> str:
    """
    ContactヘッダーのIPアドレスがプライベートIPであれば、
    グローバルIP（src_addr）に書き換える。
    """
    new_lines = []
    for line in msg.splitlines():
        if line.lower().startswith("contact:"):
            match = re.search(r'sip:([^@>]+)@([^:;>]+)(?::(\d+))?', line)
            if match:
                username = match.group(1)
                host = match.group(2)
                port = match.group(3) or str(src_addr[1])

                try:
                    import ipaddress
                    ip_obj = ipaddress.ip_address(host)
                    if ip_obj.is_private:
                        # プライベートIP → グローバルIPに書き換え
                        new_contact = f"Contact: <sip:{username}@{src_addr[0]}:{port}>"
                        new_lines.append(new_contact)
                        continue
                except ValueError:
                    # IPでない場合（ホスト名など）は書き換え
                    new_contact = f"Contact: <sip:{username}@{src_addr[0]}:{port}>"
                    new_lines.append(new_contact)
                    continue

        new_lines.append(line)
    return "\r\n".join(new_lines) + "\r\n"

def rewrite_contact_and_sdp_for_nat(msg: str, src_addr: tuple, call_id: str, rtp_pool) -> str:

    if rewrite_via:
        msg = rewrite_via_header(msg, src_addr)
        
    """
    ContactヘッダとSDPのc=行/m=行を書き換え、ICE属性を除去する。
    """
    if not rewrite_contact and not rewrite_sdp:
        return msg

    ip = PROXY_PUBLIC_IP
    rtp_relay, rtcp_relay = rtp_pool.create_session(call_id)
    relay_port = rtp_relay.port  # 
    rtcp_port = rtcp_relay.port  # 
    log(f"[rewrite_contact_and_sdp_for_nat] Call-ID {call_id} に RTPポート {relay_port} を割当て", "debug")

    new_lines = []
    in_sdp = False
    sdp_started = False
    sdp_triggered = False

    for line in msg.splitlines():
        stripped = line.strip()
        if rewrite_sdp:
            # SDP開始トリガー：Content-Type: application/sdp が現れた後の空行から
            if not sdp_triggered and stripped.lower().startswith("content-type:") and "sdp" in stripped.lower():
                sdp_triggered = True
            elif sdp_triggered and stripped == "":
                in_sdp = True
                new_lines.append(line)
                continue

            # SDP内処理
            # c= と m= のみ書き換えれば RTPリレーは可能
            # o= は絶対に書き換えない（登録や通話が異常終了する原因になる）
            if in_sdp:
                if stripped.startswith("a=ice-") or stripped.startswith("a=candidate") or stripped.startswith("a=end-of-candidates"):
                    continue
                # elif stripped.startswith("o="):
                #     parts = stripped.split()
                #     if len(parts) == 6 and parts[4] == "IP4":
                #         parts[5] = ip  # ← PUBLIC_IP に置き換える
                #         new_lines.append(" ".join(parts))
                #         continue
                elif stripped.startswith("c=IN IP4"):
                    new_lines.append(f"c=IN IP4 {ip}")
                    continue
                elif stripped.startswith("m="):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        parts[1] = str(relay_port)
                        new_lines.append(" ".join(parts))
                        continue
                elif stripped.startswith("a=rtcp:"):
                    new_lines.append(f"a=rtcp:{rtcp_port} IN IP4 {ip}")
                    # continue
                    parts = stripped.split()
                    if len(parts) >= 2:
                        parts[0] = f"a=rtcp:{relay_port}"  # RTPと同じポートでもOK
                        parts[-1] = ip                    # 最後のIPをPUBLIC_IPに
                        new_lines.append(" ".join(parts))
                        continue

        if rewrite_contact:
            if stripped.lower().startswith("contact:"):
                match = re.search(r'^(Contact:\s*.*?<sip:[^@>]+)@([^;>]+)([^>]*)>', line)
                if match:
                    prefix = match.group(1)  # Contact: "002" <sip:002
                    suffix = match.group(3)  # ;transport=udp など
                    new_contact = f"{prefix}@{ip}:{SIP_PORT}{suffix}>"
                    new_lines.append(new_contact)
                    continue
        new_lines.append(line)
    modified_msg = "\r\n".join(new_lines) + "\r\n"
    # 変更検出：先頭・末尾の空白・改行を無視して比較（中の空白は保持）
    if msg.strip() != modified_msg.strip():
        log(f"[MESSAGE REWRITE] SIPメッセージ変更あり: Call-ID={call_id}")
        log("[BEFORE REWRITE]\n" + msg, "debug")
        log("[AFTER REWRITE]\n" + modified_msg, "debug")
    return modified_msg

def get_sip_method(msg):
    call_id = parse_header("Call-ID", msg)
    if call_id in call_sessions:
        call_sessions[call_id]["last_activity"] = datetime.now()
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
    if first_line.startswith("OPTIONS"):
        return "OPTIONS"
    if first_line.startswith("MESSAGE"):
        return "MESSAGE"
    if first_line.startswith("INFO"):
        return "INFO"
    if first_line.startswith("NOTIFY"):
        return "NOTIFY"
    if first_line.startswith("SUBSCRIBE"):
        return "SUBSCRIBE"
    if first_line.startswith("PRACK"):
        return "PRACK"
    if first_line.startswith("UPDATE"):
        return "UPDATE"
    if first_line.startswith("SIP/2.0"):
        return "RESPONSE"

    log(f"[WARN] 未知のSIPメソッド: {first_line}", "debug")
    return "UNKNOWN"

# def get_sip_method(msg):
#     call_id = parse_header("Call-ID", msg)
#     if call_id in call_sessions:
#         call_sessions[call_id]["last_activity"] = datetime.now()
#     try:
#         first_line = msg.splitlines()[0].strip().upper()
#     except IndexError:
#         return "IndexError"
#     if first_line.startswith("REGISTER"):
#         return "REGISTER"
#     if first_line.startswith("INVITE"):
#         return "INVITE"
#     if first_line.startswith("CANCEL"):
#         return "CANCEL"
#     if first_line.startswith("ACK"):
#         return "ACK"
#     if first_line.startswith("BYE"):
#         return "BYE"
#     if first_line.startswith("OPTIONS"):
#         return "OPTIONS"
#     if first_line.startswith("SIP/2.0"):
#         return "RESPONSE"
#     log(f"[WARN] 未知のSIPメソッド: {first_line}", "debug")  
#     return "UNKNOWN"

from datetime import datetime
import re

# # 重複判定記録用辞書
# last_received_messages = {}
# DUPLICATE_SUPPRESS_SECONDS = 5  # 秒数のしきい値

def is_duplicate_sip_message(data, udp_src_addr):
    """
    重複SIPメッセージかどうかを判定する。
    識別キー: Call-ID + CSeq + 1行目 + Via branch + 送信元IP:ポート
    """
    if isinstance(data, bytes):
        data = data.decode(errors="ignore")

    call_id = parse_header("Call-ID", data)
    cseq = parse_header("CSeq", data)
    lines = data.splitlines()
    if not call_id or not cseq or not lines:
        return False  # 判定できないメッセージは処理対象とする

    first_line = lines[0].strip()
    if not first_line:
        return False

    # Viaヘッダーからbranchパラメータを抽出
    via = parse_header("Via", data)
    branch = ""
    match = re.search(r"branch=([^\s;]+)", via or "")
    if match:
        branch = match.group(1)

    # 識別子作成：Call-ID + CSeq + First-Line + branch + srcIP:port
    message_id = f"{call_id}|{cseq}|{first_line}|{branch}|{udp_src_addr[0]}:{udp_src_addr[1]}"

    now = datetime.now()
    if message_id in last_received_messages:
        elapsed = (now - last_received_messages[message_id]).total_seconds()
        if elapsed < DUPLICATE_SUPPRESS_SECONDS:
            log(f"[INFO] 重複SIPメッセージ無視（{elapsed:.1f}秒）: {message_id}", "debug")
            return True

    last_received_messages[message_id] = now
    return False

def hexdump_bytes(data, label=""):
    log(f"[HexDump] 非SIPメッセージ {label} の内容（{len(data)}バイト）:","debug")
    hex_width = 16
    for i in range(0, len(data), hex_width):
        chunk = data[i:i + hex_width]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        #print(f"{i:08X}  {hex_str:<48}  {ascii_str}")
        log(f"{i:08X}  {hex_str:<48}  {ascii_str}","debug")

def is_sip_message(data: bytes) -> bool:
    try:
        # 最初の行だけ取り出す（CRLFまたはLFまで）
        line = data.split(b'\r\n', 1)[0].strip()
        sip_methods = [
            b"INVITE", b"ACK", b"BYE", b"CANCEL", b"REGISTER", b"OPTIONS", b"MESSAGE",
            b"SIP/2.0"  # 応答系
        ]
        return any(line.startswith(method) for method in sip_methods)
    except Exception:
        return False

#Silent Drop for Unauthorized SIP Requests
def is_known_user(msg: str) -> bool:
    from_user = extract_from_username(msg)
    if not from_user:
        log("[SECURITY] Fromヘッダーにユーザー名が見つからない → 無応答で破棄", "debug")
        return False
    if from_user not in auth_users:
        log(f"[SECURITY] 未登録ユーザー '{from_user}' からのSIPパケットを無視", "debug")
        return False
    return True


def main_loop():
    while True:
        data, udp_src_addr = sock.recvfrom(BUFFER_SIZE)

        # SIPかどうかチェック（非SIPなら無視）
        if not is_sip_message(data):
            hexdump_bytes(data, label=str(udp_src_addr))
            log(f"[INFO] 非SIPメッセージ from {udp_src_addr}", "debug")
            continue

        try:
            msg = data.decode(errors="ignore").lstrip()
        except Exception as e:
            log(f"[ERROR] デコード失敗 from {udp_src_addr}: {e}", "debug")
            continue

        # ✅ 5秒以内の重複メッセージは無視
        if duplicate:
            if is_duplicate_sip_message(msg, udp_src_addr):
                continue
        if silent:
            if not is_known_user(msg):
                return
        method = get_sip_method(msg)
        log(f"[受信] {method} from {udp_src_addr}", "debug")

        if method == "REGISTER":
            handle_register(msg, udp_src_addr)
        elif method == "INVITE":
            handle_invite(msg, udp_src_addr)
        elif method == "ACK":
            handle_ack(msg, udp_src_addr)
        elif method == "BYE":
            handle_bye(msg, udp_src_addr)
        elif method == "RESPONSE":
            handle_response(msg, udp_src_addr)
        elif method == "CANCEL":
            handle_cancel(data, udp_src_addr)
        elif method == "OPTIONS":
            handle_options(data, udp_src_addr)
        elif method in ["INFO", "MESSAGE", "NOTIFY"]:
            # ログ出力
            log(f"[INFO] {method} 受信 from {udp_src_addr}", "debug")
            log(f"[SIP DUMP] --- {method} BEGIN ---", "debug")
            log(msg.strip(), "debug")
            log(f"[SIP DUMP] --- {method} END ---", "debug")

            # 最低限の 200 OK 応答を返す
            via = parse_header("Via", msg)
            to = parse_header("To", msg)
            from_ = parse_header("From", msg)
            call_id = parse_header("Call-ID", msg)
            cseq = parse_header("CSeq", msg)

            response = f"SIP/2.0 200 OK\r\n{via}\r\n{to}\r\n{from_}\r\n{call_id}\r\n{cseq}\r\nContent-Length: 0\r\n\r\n"
            send_to(response, udp_src_addr)
            log(f"[送信] 200 OK ({method}) → {udp_src_addr}", "debug")
        # ★ 未処理メソッドのログ＋無視処理
        elif method in ["SUBSCRIBE", "PRACK", "UPDATE"]:
            log(f"[INFO] 未処理メソッド {method} を受信 → 処理せず無視（from {udp_src_addr})", "debug")
        else:
            hexdump_bytes(data, label=str(udp_src_addr))
            log(f"[WARN] 未サポートのSIPメソッド: {method}", "debug")

def start_cleanup_thread(timeout_sec=30, interval_sec=5):
    def cleanup():
        while True:
            now = datetime.now()

            # call_sessionsのタイムアウト処理
            expired_calls = []
            for call_id, session in call_sessions.items():
                if now - session["last_activity"] > timedelta(seconds=timeout_sec):
                    expired_calls.append(call_id)

            for call_id in expired_calls:
                log(f"[CLEANUP] call_sessionsタイムアウト → {call_id}", "debug")
                call_sessions.pop(call_id, None)
                rtp_pool.remove_session(call_id)

            time.sleep(interval_sec)

    threading.Thread(target=cleanup, daemon=True).start()

if __name__ == "__main__":
    start_cleanup_thread(timeout_sec=30, interval_sec=5)
    main_loop()
