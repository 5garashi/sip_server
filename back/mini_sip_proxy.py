#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import re
from datetime import datetime
import sys

LOG_MODE = "brief"  # デフォルト: brief（詳細ログ抑制）
if len(sys.argv) >= 2 and sys.argv[1] == "debug":
    LOG_MODE = "debug"

SIP_PORT = 5060
SIP_IP = '0.0.0.0'
BUFFER_SIZE = 8192

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SIP_IP, SIP_PORT))
print(f"[INFO] SIPサーバー起動 on {SIP_IP}:{SIP_PORT}")

registered_users = {}
call_sessions = {}

#def log(msg):
#    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")
def log(msg, level="brief"):
    if LOG_MODE == "debug" or level == "brief":
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def hexdump_bytes(data, label=""):
    log(f"[HexDump] 非SIPメッセージ {label} の内容（{len(data)}バイト）:","debug")
    hex_width = 16
    for i in range(0, len(data), hex_width):
        chunk = data[i:i + hex_width]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        #print(f"{i:08X}  {hex_str:<48}  {ascii_str}")
        log(f"{i:08X}  {hex_str:<48}  {ascii_str}","debug")

def parse_header(header_name, data):
    pattern = rf'^{header_name}:\s*(.*)$'
    for line in data.splitlines():
        match = re.match(pattern, line, re.IGNORECASE)
        if match:
            return match.group(0).strip()  # Return full header line
    return ''

# def extract_call_id(data):
#     match = re.search(r'^Call-ID:\s*(.*)$', data, re.MULTILINE | re.IGNORECASE)
#     return match.group(1).strip() if match else None


def parse_username(sip_uri):
    match = re.search(r'sip:([^@]+)@', sip_uri)
    return match.group(1) if match else None

def send_to(message, dst_addr):
    try:
        sock.sendto(message.encode(), dst_addr)
        log(f"[send_to] {message} → {dst_addr}")
    except Exception as e:
        log(f"[ERROR] send_to():デコード失敗: {e}")

def send_response(code, reason, original_msg, dst_addr, add_tag=False, level="brief"):
    via = parse_header("Via", original_msg)
    to = parse_header("To", original_msg)
    from_ = parse_header("From", original_msg)
    call_id = parse_header("Call-ID",original_msg)
    cseq = parse_header("CSeq", original_msg)
    if add_tag:
        to += ";tag=67890"
    # response = f"SIP/2.0 {code} {reason}\r\n{via}\r\nTo: {to}\r\nFrom: {from_}\r\n"
    response = f"SIP/2.0 {code} {reason}\r\n{via}\r\n{to}\r\n{from_}\r\n"
    response += f"{call_id}\r\n{cseq}\r\nContent-Length: 0\r\n\r\n"
    send_to(response, dst_addr)
    log(f"[送信] {code} {reason} → {dst_addr}",level)

def extract_cseq_number(cseq_header):
    # CSeq: 123 INVITE のようなヘッダーから123だけを抽出
    if ":" in cseq_header:
        return cseq_header.split(":")[1].strip().split()[0]
    else:
        return cseq_header.strip().split()[0]

#未使用 
def build_sip_message(method, target, dst, to_header, from_header, call_id, cseq_number):
    msg = f"{method} sip:{target}@{dst[0]} SIP/2.0\r\n"
    msg += f"{to_header.replace('To:','').strip()}\r\n"
    msg += f"{from_header.replace('From:','').strip()}\r\n"
    msg += f"{call_id}\r\n"
    msg += f"CSeq: {cseq_number} {method}\r\n"
    msg += "Content-Length: 0\r\n\r\n"
    return msg 
#未使用
def send_ack(response_msg):
    contact = parse_header("Contact", response_msg)
    match = re.search(r'sip:[^@]+@([\d\.]+):(\d+)', contact)
    if not match:
        log("[WARN] Contactヘッダーに有効なIP:PORTが見つかりません。ACK送信不可。","debug")
        return
    dst = (match.group(1), int(match.group(2)))

    call_id = parse_header("Call-ID",response_msg)
    to_header = parse_header("To", response_msg)
    from_header = parse_header("From", response_msg)
    cseq_header = parse_header("CSeq", response_msg)
    cseq_number = extract_cseq_number(cseq_header)
    target = parse_username(to_header)

    # ack_msg = f"ACK sip:{target}@{dst[0]} SIP/2.0\r\n"
    # ack_msg += f"{to_header.replace('To:','').strip()}\r\n"
    # ack_msg += f"{from_header.replace('From:','').strip()}\r\n"
    # ack_msg += f"{call_id}\r\n"
    # ack_msg += f"CSeq: {cseq_number} ACK\r\n"
    # ack_msg += "Content-Length: 0\r\n\r\n"

    msg = build_sip_message("ACK", target, dst, to_header, from_header, call_id, cseq_number)
    send_to(msg, dst)
    log(f"[DEBUG] ACK内容:\n{'-'*40}\n{msg.strip()}\n{'-'*40}","debug")
    log(f"[送信] proxy ACK → {dst}")

def get_sip_method(msg):
    try:
        first_line = msg.splitlines()[0].strip().upper()
    except IndexError:
        return "IndexError"
    
    if first_line.startswith("ACK"):
        return "ACK"
    elif first_line.startswith("BYE"):
        return "BYE"
    elif first_line.startswith("INVITE"):
        return "INVITE"
    elif first_line.startswith("REGISTER"):
        return "REGISTER"
    elif first_line.startswith("CANCEL"):
        return "CANCEL"
    elif first_line.startswith("SIP"):
        return "RESPONSE"
    else:
        log(f"[WARN] UNKNOWNメソッド: {first_line}","debug")
        return "UNKNOWNメソッド"

def handle_register(data, udp_src_addr):
    username = parse_username(parse_header("To", data))
    if username:
        registered_users[username] = udp_src_addr
        log(f"[INFO] REGISTER リクエスト受信: {username} → {udp_src_addr}","debug")
        send_response("200", "OK", data, udp_src_addr,add_tag=False,level="debug")

def handle_invite(data, udp_src_addr):
    callee = parse_username(parse_header("To", data))
    caller = parse_username(parse_header("From", data))
    call_id = parse_header("Call-ID",data)
    via = parse_header("Via", data)
    from_ = parse_header("From", data)
    to = parse_header("To", data)
    cseq = parse_header("CSeq", data)
    target = parse_username(to)

    # def strip_header_prefix(header_line, prefix):
    #     if header_line.lower().startswith(prefix.lower() + ":"):
    #         return header_line[len(prefix)+1:].strip()
    #     return header_line.strip()

    if callee == "999":
        log(f"[INFO] ダイヤル999受信 → 登録ユーザー一覧を表示")
        for user, (ip, port) in registered_users.items():
            print(f"[REGISTERED] {user}: {ip}:{port}")

        # 発信者へのBYE送信（ポートも適切に）
        # to_value = strip_header_prefix(to, "To")
        # from_value = strip_header_prefix(from_, "From")
        # session = call_sessions.get(call_id)
        # dst = session['from'] if session else udp_src_addr

        # #Request-Line: BYE sip:003@192.168.25.8;transport=udp SIP/2.0
        # dst = registered_users[caller]
        # bye_msg = f"BYE sip:{caller}@{dst[0]} SIP/2.0\r\n"
        # # bye_msg = f"BYE sip:{caller}@{udp_src_addr} SIP/2.0\r\n"
        # bye_msg += f"{via}\r\n"
        # bye_msg += f"{to}\r\n"
        # bye_msg += f"{from_}\r\n"
        # bye_msg += f"{call_id}\r\n"
        # # Extract only the sequence number from the CSeq header
        # cseq_number = extract_cseq_number(cseq)
        # bye_msg += f"CSeq: {cseq_number} BYE\r\n"
        # bye_msg += "Content-Length: 0\r\n\r\n"
        
        # send_to(bye_msg, dst)
        # log(f"[INFO] BYE 強制送信 → {dst}（通話終了）")
        # msg = build_sip_message("BYE", target, dst, to, from_, call_id, cseq_number)
        # send_to(msg, dst)
        send_response("404", "Not Found", data, udp_src_addr,add_tag=True)
        return

    send_response("100", "Trying", data, udp_src_addr,add_tag=True)

    if callee and callee in registered_users:
        dst = registered_users[callee]
        call_sessions[call_id] = {'from': udp_src_addr, 'to': dst}
        send_to(data, dst)
        log(f"[送信] → {dst}")
        log(f"[INFO] INVITE 転送 → {callee} ({dst})")
    else:
        log(f"[WARN] 宛先ユーザー未登録: {callee}", "debug")
        send_response("404", "Not Found", data, udp_src_addr,add_tag=True)
#未使用
def transfer_message(data, udp_src_addr):
    callee = parse_username(parse_header("To", data))
    call_id = parse_header("Call-ID",data)
    if callee and callee in registered_users:
        dst = registered_users[callee]
        call_sessions[call_id] = {'from': udp_src_addr, 'to': dst}
        send_to(data, dst)
        log(f"[送信] → {dst}")
        log(f"transfer_message → {callee} ({dst})","debug")
    else:
        log(f"[WARN] 宛先ユーザー未登録: {callee}","debug")
        send_response("404", "Not Found", data, udp_src_addr)

def handle_response(data, udp_src_addr):
    call_id = parse_header("Call-ID",data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']#addrと違う方を指定（相手を指定）
        log(f"dst:{dst}, addr:{udp_src_addr}, session['from']{session['from']}, session['to']:{session['to']}")
        # send_to(data, dst)
        log(f"[送信] → {dst}")
        status_line = data.splitlines()[0].strip().upper()
        log(f"[RESPONSE DATA] {status_line} → {dst}")
        if "180 RINGING" in status_line:
            #transfer_message(data, addr)
            send_to(data, dst)
            log(f"[INFO] 180 Ringing → {dst}")
        elif "200 OK" in status_line:
            #transfer_message(data, addr)
            send_to(data, dst)
            log(f"[INFO] 200 OK → {dst}")
        elif "100 TRYING" in status_line:
            #transfer_message(data, addr)
            log(f"[INFO] 100 Trying → {dst}")
            #send_ack(data)
        #else:
            #send_to(data, dst)

    else:
        log(f"[WARN] Call-ID未登録（応答無視）: {call_id}","debug")

def handle_ack_or_bye(data, udp_src_addr):
    call_id = parse_header("Call-ID",data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']
        send_to(data, dst)
        log(f"[送信] → {dst}")
        if data.startswith("BYE"):
            log(f"[INFO] BYE 転送 → {dst}（通話終了）")
            call_sessions.pop(call_id, None)
        elif data.startswith("ACK"):
            log(f"[INFO] ACK 転送 → {dst}")
    else:
        log(f"[WARN] Call-ID未登録（ACK/BYE無視）: {call_id}","debug")

def handle_unknown(data, udp_src_addr):
    try:
        msg = data.decode(errors="ignore")
    except Exception as e:
        log(f"[ERROR] handle_unknown: デコード失敗 from {udp_src_addr}: {e}","debug")
        return

    call_id = parse_header("Call-ID",msg)
    if call_id and call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']
        send_to(data, dst)
        log(f"[送信] → {dst}")
        log(f"[INFO] 非判定メッセージ転送 → {dst} [Call-ID: {call_id}]")
    else:
        log(f"[WARN] Call-ID未登録 or 抽出不可。未判定メッセージ転送不能。","debug")

def main_loop():
    while True:
        data, udp_src_addr = sock.recvfrom(BUFFER_SIZE)
        if "77.110.114.15" in udp_src_addr[0]:
            continue
        try:
            msg = data.decode(errors="ignore").lstrip()
        except Exception as e:
            log(f"[ERROR] デコード失敗 from {udp_src_addr}: {e}","debug")
            continue

        log(f"[受信] from {udp_src_addr}\n{'-'*60}\n{msg.strip()}\n{'-'*60}","debug")

        method = get_sip_method(msg)
        if not method:
            method = ""
        if "REGISTER" in method or "UNKNOWN" in method or "Error" in method:
            log(f"[判定] get_sip_method → {method}","debug")
        else:
            log(f"[判定] get_sip_method → {method}")

        if method == "INVITE":
            handle_invite(msg, udp_src_addr)
        elif method == "REGISTER":
            handle_register(msg, udp_src_addr)
        elif method == "ACK" or method == "BYE":
            handle_ack_or_bye(msg, udp_src_addr)
        elif method == "RESPONSE":
            handle_response(msg, udp_src_addr)
        elif method == "UNKNOWN":
            log(f"[INFO] 未判定メッセージ → 転送試行","debug")
            hexdump_bytes(data, label=str(udp_src_addr))
            handle_unknown(data, udp_src_addr)
        else:
            log(f"[WARN] 処理できないメッセージ種別 → {method}","debug")

if __name__ == "__main__":
    main_loop()

           