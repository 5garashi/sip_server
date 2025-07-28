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
import json

######
# .env file exsample
# AUTH_USERS_ENV={"001":"www001","002":"www001","admin":"adminpass"}

# Default user-password mapping if no environment variable is set
default_auth_users = {
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

# Attempt to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("[INFO] .env loaded successfully.")
except ImportError:
    print("[WARN] python-dotenv is not installed. Skipping .env loading.")

# Get AUTH_USERS_ENV from environment variables
auth_users_env = os.getenv("AUTH_USERS_ENV")

# Parse AUTH_USERS_ENV if available and valid; otherwise, fall back to default_auth_users
try:
    if auth_users_env:
        auth_users = json.loads(auth_users_env)
        print("[INFO] AUTH_USERS_ENV loaded from environment.")
    else:
        auth_users = default_auth_users
        print("[INFO] Using default auth_users.")
except json.JSONDecodeError:
    print("[ERROR] AUTH_USERS_ENV is not valid JSON. Using default auth_users.")
    auth_users = default_auth_users

######


#start rtp_relay：
from rtp_relay import RTPRelayPool,start_rtp_log_cleanup_thread, LOG_FILE_PATH
os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
start_rtp_log_cleanup_thread()
rtp_pool = RTPRelayPool()

SIP_PORT = 5060
SIP_IP = '0.0.0.0'
BUFFER_SIZE = 8192
realm = "mini_sip_proxy"
LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sip_server.log")
log_mode = "brief"
MAX_LOG_DAYS = 7
DUPLICATE_SUPPRESS_SECONDS = 5  # ignore duplicate message period
duplicate= False  # Whether to ignore duplicated messages
# rewrite Contact header
rewrite_contact = False 
# rewrite SDP:c=sddres
rewrite_sdp = False
# rewite Via header
rewrite_via = False
silent = False  # Keep silence if SIP message is from unregistered　 user.
USE_PROXY_ADDR_IN_VIA = True

# Proxy server global IP & port (Global IP & port of this server)
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
print(f"[INFO] SIP server started on {SIP_IP}:{SIP_PORT} {msg}")

nonces = {}
registered_users = {}
call_sessions = {}
# call_sessions[call_id] = {
#     "from": from_addr,
#     "to": to_addr,
#     "last_activity": datetime.now()
# }
last_received_messages = {}  # Call-ID + CSeq is the key for duplicated SIP messages.

# ========== Log ==========
def log(msg, level="brief"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted_msg = f"[{timestamp}] {msg}"
    if log_mode == "debug" or level == "brief":
        print(formatted_msg)
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")
    except Exception as e:
        print(f"[ERROR] failure on writing Log file: {e}")

def start_sip_log_cleanup_thread():
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
                # Skip lines that do not start with a timestamp (delete)
        with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"[ERROR] fail in cleanup_olod_logs(): {e}")

# ========== parse header ==========
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

# ========== Auth ==========
def generate_nonce():
    return hashlib.md5(str(random.random()).encode()).hexdigest()

def parse_digest_auth(header):
    auth_data = {}

    # Authorization: get str after 'Digest'
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
    log(f"[SEND] {code} {reason} → {dst_addr}", level)

# ========== Send 400 Bad Request ==========
def send_400_bad_request(original_msg, dst_addr):
    send_response("400", "Bad Request", original_msg, dst_addr, add_tag=False)
    log(f"[INFO] Sent 400 Bad Request → {dst_addr}", level="debug")

# ========== Send 401 Unauthorized ==========
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
    log(f"[SEND] 401 Unauthorized → {addr} (nonce: {nonce})")

def clear_session(call_id):
    """Delete session for Call-ID """
    if call_id in call_sessions:
        del call_sessions[call_id]
        rtp_pool.remove_session(call_id)
        log(f"[INFO] Session Deleted: Call-ID={call_id}", "debug")
    else:
        log(f"[WARN] Fail in Deleting Session: Call-ID={call_id} does not exist", "debug")

# ========== Send 487 Request Terminated ==========
def send_487_terminated(original_msg, dst_addr):
    call_id = parse_header("Call-ID", original_msg)
    rtp_pool.remove_session(call_id)
    send_response("487", "Request Terminated", original_msg, dst_addr, add_tag=True)
    log(f"[INFO] Sent 487 Request Terminated → {dst_addr}", level="debug")
  
# ========== Send 603 Decline ==========
def send_603_decline(original_msg, dst_addr):
    call_id = parse_header("Call-ID", original_msg)
    send_response("603", "Decline", original_msg, dst_addr, add_tag=True)
    log(f"[INFO] Sent 603 Decline → {dst_addr}", level="debug")

def allocate_rtp_port() -> int:
    """ Allocate an even-numbered port for RTP """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()

    # RTP uses even ports; adjacent odd port reserved for RTCP
    return port if port % 2 == 0 else port - 1

def rewrite_sdp_media_port(msg: str, new_port: int) -> str:
    """
    SDP m= row（m=audio, m=video, m=application etc）rewrite port number.
    
    Parameters:
        msg (str): SIP message
        new_port (int): port for rtp relay
    
    Returns:
        str: message strings after rewrite
    """
    lines = msg.splitlines()
    new_lines = []
    in_sdp = False

    for line in lines:
        if in_sdp and line.startswith("m="):
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1].isdigit():
                parts[1] = str(new_port)  # rewrite only port number.
                line = " ".join(parts)

        new_lines.append(line)

        # SDP section starts after empty row.
        if line.strip() == "":
            in_sdp = True

    return "\r\n".join(new_lines) + "\r\n"

def extract_sdp_connection_address(msg: str) -> str:
    """
    Extract c=IN IP4 address in SDP section.    
    Parameters:
        msg (str): SIP message

    Returns:
        str | None: IP addres(ex: "192.168.1.10"）or None
    """
    in_sdp = False
    for line in msg.splitlines():
        if in_sdp and line.startswith("c=IN IP4 "):
            parts = line.strip().split()
            if len(parts) == 3:
                return parts[2]
        if line.strip() == "":
            in_sdp = True  #Starts SDP section after empty row.
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

def is_global_ip(ip: str) -> bool:
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
        send_401_unauthorized(data, udp_src_addr)
        log(f"[INFO] Authorization header missing - 401 Unauthorized sent", "debug")
        return

    auth_data = parse_digest_auth(auth_header)
    if not auth_data or not validate_digest(auth_data, method):
        log(f"[WARN] Digest Auth Failed (REGISTER): {auth_data}", "debug")
        send_401_unauthorized(data, udp_src_addr)
        return

    username = auth_data.get("username")
    registered_users[username] = udp_src_addr
    call_id = parse_header("Call-ID", data)
    data = rewrite_contact_header(data)
    
    log(f"[INFO] REGISTER authentication succeeded: {username} → {udp_src_addr}", "debug")
    send_response("200", "OK", data, udp_src_addr, add_tag=False, level="debug")

# ========== CANCEL ==========
def handle_cancel(data, udp_src_addr):
    call_id = parse_header("Call-ID", data)
    session = call_sessions.get(call_id)

    if session:
        # transfer CANCEL
        send_to(data, session["to"])
        log(f"[INFO] CANCEL転送: Call-ID={call_id} → {session['to']}")

        # send back response 200 OK to CANCEL (response to CANCEL),ACK is not needed.
        send_response("200", "OK", data, udp_src_addr, add_tag=True)
        log(f"[INFO] respose back 200 OK to CANCEL → {udp_src_addr}")
    else:
        log(f"[WARN] no session for CANCEL: Call-ID={call_id}", "debug")
        send_response("481", "Call/Transaction Does Not Exist", data, udp_src_addr, add_tag=True)
        log(f"[INFO] response back 481 to CANCEL → {udp_src_addr}")

# ========== 888 show call_sessions  ==========
def print_call_sessions():
    log("[INFO] call_sessions:")
    if not call_sessions:
        log("[SESSION] (empty)")
    for call_id, session in call_sessions.items():
        log(f"[SESSION] Call-ID: {call_id}, from: {session['from']}, to: {session['to']}")

# ========== 990 registered_users on NOTIFY ==========
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
    log(f"[INFO] Sent NOTIFY (registered_users)→ {to_addr}")

# ========== INVITE ==========
def handle_invite(data, udp_src_addr):
    method = "INVITE"
    auth_header = parse_header("Authorization", data)

    if not auth_header:
        send_401_unauthorized(data, udp_src_addr)
        log(f"[INFO] No Authorization header → Sent 401", "debug")
        return

    auth_data = parse_digest_auth(auth_header)
    if not auth_data or not validate_digest(auth_data, method):
        log(f"[WARN] Digest Auth failed (INVITE): {auth_data}", "debug")
        send_401_unauthorized(data, udp_src_addr)
        return

    callee = parse_username(parse_header("To", data))
    caller = parse_username(parse_header("From", data))
    call_id = parse_header("Call-ID", data)

    global rewrite_contact
    global rewrite_sdp
    global log_mode
    global rewrite_via
    global duplicate
    global silent
    if callee == "985":
        silent =  False
        log(f"[INFO] Dial:{callee}Received → silent={silent}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "986":
        silent =  True
        log(f"[INFO] DIAL:{callee}Received → silent={silent}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return    
    if callee == "987":
        duplicate =  False
        log(f"[INFO] DIAL:{callee}Received → duplicate={duplicate}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "988":
        duplicate =  True
        log(f"[INFO] DIAL:{callee}Received → duplicate={duplicate}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return    
    if callee == "989":
        log_mode =  "brief"
        log(f"[INFO] DIAL:{callee}Received → log_mode={log_mode}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "990":
        log_mode =  "debug"
        log(f"[INFO] DIAL:{callee}Received → log_mode={log_mode }")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "991":
        rewrite_via =  False
        log(f"[INFO] DIAL:{callee}Received → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "992":
        rewrite_via =  True
        log(f"[INFO] DIAL:{callee}Received → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "993":
        rewrite_sdp =  False
        log(f"[INFO] DIAL:{callee}Received → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "994":
        rewrite_sdp = True
        log(f"[INFO] DIAL:{callee}Received → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "995":
        rewrite_contact = False
        log(f"[INFO] DIAL:{callee}Received → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "996":
        rewrite_contact = True
        log(f"[INFO] DIAL:{callee}Received → REWRITE_CONTACT={rewrite_contact}, REWRITE_SDP={rewrite_sdp},REWRITE_VIA={rewrite_via}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "997":
        log(f"[INFO] DIAL:{callee}Received → show call_sessions")
        print_call_sessions()
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "998":
        log(f"[INFO] DIAL:{callee}Received → Registered users on NOTIFY")
        notify_registered_users(udp_src_addr, data)
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return
    if callee == "999":
        log(f"[INFO] DIAL:{callee}Received → show Registered users")
        for user, (ip, port) in registered_users.items():
            log(f"[REGISTERED] {user}: {ip}:{port}")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        return

    send_response("100", "Trying", data, udp_src_addr, add_tag=True)

    if callee in registered_users:
        dst = registered_users[callee]
        call_sessions[call_id] = {'from': udp_src_addr, 'to': dst,"last_activity": datetime.now()}
        rtp_pool.create_session(call_id)
        data = rewrite_contact_and_sdp_for_nat(data, udp_src_addr, call_id, rtp_pool)
        send_to(data, dst)
        log(f"[SEND] INVITE transfer to → {callee} ({dst})")
    else:
        log(f"[WARN] Destination user not registered: {callee}", "debug")
        send_response("404", "Not Found", data, udp_src_addr, add_tag=True)
        
def handle_response(data, udp_src_addr):
    call_id = parse_header("Call-ID",data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']#Specify the counterpart to 'addr'
        log(f"dst:{dst}, addr:{udp_src_addr}, session['from']{session['from']}, session['to']:{session['to']}")
        data = rewrite_contact_and_sdp_for_nat(data, udp_src_addr, call_id, rtp_pool)            
        status_line = data.splitlines()[0].strip().upper()
        log(f"[RESPONSE DATA] {status_line} → {dst}")
        if "100 TRYING" in status_line:
            log(f"[INFO] 100 Trying → {dst}")
        elif "180 RINGING" in status_line:
            send_to(data, dst)
            log(f"[SEND] 180 Ringing → {dst}")
        elif "183 SESSION PROGRESS" in status_line:
            send_to(data, dst)
            log(f"[SEND] 183 Session Progress → {dst}")
        elif "200 OK" in status_line:
            cseq_line = parse_header("CSeq", data)
            if "BYE" in cseq_line:
                log(f"[SEND] 200 OK (BYE) → {dst}")
            elif "INVITE" in cseq_line:
                log(f"[SEND] 200 OK (INVITE) → {dst}")
            else:
                log(f"[SEND] 200 OK (Other) → {dst}")
            send_to(data, dst)

        elif "400 BAD REQUEST" in status_line:
            # send_400_bad_request(data, dst)
            log(f"[INFO] 400 Bad Request → {dst}")
        elif "404 NOT FOUND" in status_line:
            log(f"[SEND] 404 Not Found → {dst}")
            send_to(data, dst)
        elif "408 REQUEST TIMEOUT" in status_line:
            log(f"[SEND] 408 Request Timeout → {dst}")
            send_to(data, dst)
        elif "481 CALL/TRANSACTION DOES NOT EXIST" in status_line:
            log(f"[INFO] 481 Call/Transaction Does Not Exist → Call-ID={call_id}", "debug")
            send_to(data, dst)
            log(f"[SEND] 481 Call/Transaction Does Not Exist → {dst}")
        elif "486 BUSY HERE" in status_line:
            send_to(data, dst)
            log(f"[SEND] 486 Busy Here → {dst}")
        elif "487 REQUEST TERMINATED" in status_line:
            send_487_terminated(data, dst)
            log(f"[SEND] 487 Request Terminated → transfer to caller: {dst}")
        elif "488 NOT ACCEPTABLE HERE" in status_line:
            send_to(data, dst)
            log(f"[SEND] 488 Not Acceptable Here → {dst}")
        elif "603 DECLINE" in status_line:
            send_603_decline(data, dst)
            log(f"[SEND] 603 Decline → {dst}")
        else:
            log(f"[INFO] {data} → {dst}", "debug")

def extract_from_username(msg: str) -> str | None:
    match = re.search(r'^From:\s*.*?<?sip:([^@>]+)@\[?[^\]>]+]?(?::\d+)?>?', msg, re.MULTILINE | re.IGNORECASE)
    return match.group(1) if match else None


def extract_to_username(msg: str) -> str | None:
    match = re.search(r'^To:\s*.*?<?sip:([^@>]+)@\[?[^\]>]+]?(?::\d+)?>?', msg, re.MULTILINE | re.IGNORECASE)
    return match.group(1) if match else None

def should_forward_ack(msg: str) -> bool:
    # return if not ACK
    if not msg.startswith("ACK") and "ACK" not in msg.splitlines()[0]:
        return False

    # Tcheck if there is tag in To: header
    match = re.search(r"^To:\s.*tag=([\w\-\.]+)", msg, re.MULTILINE | re.IGNORECASE)
    if match:
        return True  # if tag exist → return ACK to 200 OK → transfer
    else:
        return False  # if no tag → no ACK needed → no transfer


def handle_ack(msg: str, src_addr: tuple):
    if not should_forward_ack(msg):
        log(f"[ACK] if no tag (401 Unauthorized etc), no transfer", "debug")
        return
    from_user = extract_from_username(msg)
    to_user = extract_to_username(msg)

    if to_user in registered_users:
        ip, port = registered_users[to_user]
        sock.sendto(msg.encode(), (ip, port))
        log(f"[SEND] ACK: {from_user} → {to_user} @ {ip}:{port}")
    else:
        log(f"[WARN] ACK: {to_user} is not registered , no transfer", "warn") 
            
def handle_bye(data, udp_src_addr):
    call_id = parse_header("Call-ID", data)
    if call_id in call_sessions:
        session = call_sessions[call_id]
        dst = session['from'] if udp_src_addr == session['to'] else session['to']
        data = rewrite_contact_and_sdp_for_nat(data, udp_src_addr, call_id, rtp_pool)

        send_to(data, dst)
        if data.startswith("BYE"):
            log(f"[INFO] BYE transfer → {dst}")
        elif data.startswith("ACK"):
            log(f"[INFO] ACK transfer → {dst}")
            
def handle_options(msg: str, src_addr: tuple):
    log(f"[RECEIVE] OPTIONS from {src_addr}")

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
    log(f"[SEND] OPTIONS 200 OK → {src_addr}")


def rewrite_via_header(msg: str, src_addr: tuple) -> str:
    """
    add reveived and rport to Via header (for SIP request)
    src_addr: src IP/Port after NAT
    """
    new_lines = []
    for line in msg.splitlines():
        if line.lower().startswith("via:"):
            ip = PROXY_PUBLIC_IP if USE_PROXY_ADDR_IN_VIA else src_addr[0]
            port = PROXY_SIP_PORT if USE_PROXY_ADDR_IN_VIA else src_addr[1]

            # rport has no value → add value.
            if "rport" in line:
                line = re.sub(r"rport(?!\=)", f"rport={port}", line)
            else:
                # no rport → add
                line = line.strip() + f";rport={port}"

            # no received → add
            if "received=" not in line:
                line = line.strip() + f";received={ip}"

        new_lines.append(line)

    return "\r\n".join(new_lines) + "\r\n"

#not used
# def rewrite_sip_headers_for_nat(msg: str, src_addr: tuple) -> str:
def rewrite_contact_and_sdp_for_nat(msg: str, src_addr: tuple, call_id: str, rtp_pool) -> str:
    modified_msg = msg
    if rewrite_via:
        modified_msg = rewrite_via_header(modified_msg, src_addr)
    if rewrite_sdp:
        modified_msg = rewrite_sdp_header(modified_msg, call_id, rtp_pool)
    if rewrite_contact:    
        modified_msg = rewrite_contact_header(modified_msg)
    # Check if the message was modified
    if msg.strip() != modified_msg.strip():
        log(f"[MESSAGE REWRITE] Rewritten has been done on SIP message: Call-ID={call_id}")
        log("[BEFORE REWRITE]\n" + msg, "debug")
        log("[AFTER REWRITE]\n" + modified_msg, "debug")     
    return modified_msg

def rewrite_contact_header(msg: str) -> str:
    """
    If Contact header has private IP address,
    rewrite to Global IP(src_addr).
    """
    new_lines = []
    for line in msg.splitlines():
        stripped = line.strip()
        if rewrite_contact:
            if stripped.lower().startswith("contact:"):
                match = re.search(r'^(Contact:\s*.*?<sip:[^@>]+)@([^;>]+)([^>]*)>', line)
                if match:
                    prefix = match.group(1)  # Contact: "002" <sip:002
                    suffix = match.group(3)  # ;transport=udp etc
                    new_contact = f"{prefix}@{PROXY_PUBLIC_IP}:{SIP_PORT}{suffix}>"
                    new_lines.append(new_contact)
                    continue
        new_lines.append(line)
        
    return "\r\n".join(new_lines) + "\r\n"

def rewrite_sdp_header(msg: str, call_id: str, rtp_pool) -> str:

    rtp_relay, rtcp_relay = rtp_pool.get_session(call_id)
    if rtp_relay and rtcp_relay:
        relay_port = rtp_relay.port  # 
        rtcp_port = rtcp_relay.port  # 
        log(f"[rewrite sdp] Call-ID {call_id} : rewritten to RTP port {relay_port}", "debug")
    else:
        return msg

    new_lines = []
    in_sdp = False
    sdp_started = False
    sdp_triggered = False

    for line in msg.splitlines():
        stripped = line.strip()
        # SDP starts：empty row after Content-Type: application/sdp
        if not sdp_triggered and stripped.lower().startswith("content-type:") and "sdp" in stripped.lower():
            sdp_triggered = True
        elif sdp_triggered and stripped == "":
            in_sdp = True
            new_lines.append(line)
            continue

        # SDP
        # rewrite c= and m= for RTP relay
        # o= must not rewritten
        if in_sdp:
            #delete "a=ice-","a=candidate","a=end-of-candidates" lines
            if stripped.startswith("a=ice-") or stripped.startswith("a=candidate") or stripped.startswith("a=end-of-candidates"):
                continue
            # elif stripped.startswith("o="):
            #     parts = stripped.split()
            #     if len(parts) == 6 and parts[4] == "IP4":
            #         parts[5] = ip  # ← PUBLIC_IP に置き換える
            #         new_lines.append(" ".join(parts))
            #         continue
            elif stripped.startswith("c=IN IP4"):
                new_lines.append(f"c=IN IP4 {PROXY_PUBLIC_IP}")
                continue
            elif stripped.startswith("m="):
                parts = stripped.split()
                if len(parts) >= 2:
                    parts[1] = str(relay_port)
                    new_lines.append(" ".join(parts))
                    continue
            elif stripped.startswith("a=rtcp:"):
                new_lines.append(f"a=rtcp:{rtcp_port} IN IP4 {PROXY_PUBLIC_IP}")
                # continue
                parts = stripped.split()
                if len(parts) >= 2:
                    parts[0] = f"a=rtcp:{relay_port}"  
                    parts[-1] = PROXY_PUBLIC_IP     # set PUBLIC_IP to the last IP
                    new_lines.append(" ".join(parts))
                    continue
        new_lines.append(line)
    modified_msg = "\r\n".join(new_lines) + "\r\n"
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

    log(f"[WARN] Unknown method: {first_line}", "debug")
    return "UNKNOWN"

from datetime import datetime
import re

def is_duplicate_sip_message(data, udp_src_addr):
    if isinstance(data, bytes):
        data = data.decode(errors="ignore")

    call_id = parse_header("Call-ID", data)
    cseq = parse_header("CSeq", data)
    lines = data.splitlines()
    if not call_id or not cseq or not lines:
        return False

    first_line = lines[0].strip()
    if not first_line:
        return False

    # get branch params from Via header
    via = parse_header("Via", data)
    branch = ""
    match = re.search(r"branch=([^\s;]+)", via or "")
    if match:
        branch = match.group(1)

    # Create：Call-ID + CSeq + First-Line + branch + srcIP:port
    message_id = f"{call_id}|{cseq}|{first_line}|{branch}|{udp_src_addr[0]}:{udp_src_addr[1]}"

    now = datetime.now()
    if message_id in last_received_messages:
        elapsed = (now - last_received_messages[message_id]).total_seconds()
        if elapsed < DUPLICATE_SUPPRESS_SECONDS:
            log(f"[INFO] Ignore duplicated SIP message({elapsed:.1f}sec): {message_id}", "debug")
            return True

    last_received_messages[message_id] = now
    return False

def hexdump_bytes(data, label=""):
    log(f"[HexDump] Non-SIP message {label} （{len(data)}Bytes）:","debug")
    hex_width = 16
    for i in range(0, len(data), hex_width):
        chunk = data[i:i + hex_width]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        #print(f"{i:08X}  {hex_str:<48}  {ascii_str}")
        log(f"{i:08X}  {hex_str:<48}  {ascii_str}","debug")

def is_sip_message(data: bytes) -> bool:
    try:
        # get 1st row
        line = data.split(b'\r\n', 1)[0].strip()
        sip_methods = [
            b"INVITE", b"ACK", b"BYE", b"CANCEL", b"REGISTER", b"OPTIONS", b"MESSAGE",
            b"INFO", b"SUBSCRIBE", b"PRACK", b"UPDATE", b"NOTIFY", b"SIP/2.0", # 応答系
        ]
        return any(line.startswith(method) for method in sip_methods)
    except Exception:
        return False

#Silent Drop for Unauthorized SIP Requests
def is_known_user(msg: str) -> bool:
    from_user = extract_from_username(msg)
    if not from_user:
        log("[SECURITY] From header has no user name :ignore", "debug")
        return False
    if from_user not in auth_users:
        log(f"[SECURITY]  Unregistered user'{from_user}' :ignore", "debug")
        return False
    return True

def handle_misc_method(method, msg, udp_src_addr):
    """
    Log and send back 200 OK to INFO, MESSAGE, NOTIFY
    """
    log(f"[INFO] {method} 受信 from {udp_src_addr}", "debug")
    log(f"[SIP DUMP] --- {method} BEGIN ---", "debug")
    log(msg.strip(), "debug")
    log(f"[SIP DUMP] --- {method} END ---", "debug")

    # header
    via = parse_header("Via", msg)
    to = parse_header("To", msg)
    from_ = parse_header("From", msg)
    call_id = parse_header("Call-ID", msg)
    cseq = parse_header("CSeq", msg)

    # 200 OK (minimum)
    response = f"SIP/2.0 200 OK\r\n{via}\r\n{to}\r\n{from_}\r\n{call_id}\r\n{cseq}\r\nContent-Length: 0\r\n\r\n"
    send_to(response, udp_src_addr)
    log(f"[SEND] 200 OK ({method}) → {udp_src_addr}", "debug")


def main_loop():
    while True:
        data, udp_src_addr = sock.recvfrom(BUFFER_SIZE)

        # if not SIP, ignore
        if not is_sip_message(data):
            if log_mode == "debug":
                hexdump_bytes(data, label=str(udp_src_addr))
                log(f"[INFO] Non-SIP message from {udp_src_addr}", "debug")
            continue

        try:
            msg = data.decode(errors="ignore").lstrip()
        except Exception as e:
            log(f"[ERROR] Decode failed from {udp_src_addr}: {e}", "debug")
            continue

        # ✅ ignore duplicated message
        if duplicate:
            if is_duplicate_sip_message(msg, udp_src_addr):
                continue
        if silent:
            if not is_known_user(msg):
                return
        method = get_sip_method(msg)
        log(f"[RECEIVE] {method} from {udp_src_addr}")

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
            handle_misc_method(method, msg, udp_src_addr)
        # unhandled SIP method
        elif method in ["SUBSCRIBE", "PRACK", "UPDATE"]:
            log(f"[INFO] Received unhandled method '{method}' → Ignored (from {udp_src_addr})", "debug")
        else:
            hexdump_bytes(data, label=str(udp_src_addr))
            log(f"[WARN] unhandled SIP method : {method}", "debug")

def start_cleanup_thread(timeout_sec=30, interval_sec=5):
    def cleanup():
        while True:
            now = datetime.now()

            # call_sessions timeout process
            expired_calls = []
            for call_id, session in call_sessions.items():
                if now - session["last_activity"] > timedelta(seconds=timeout_sec):
                    expired_calls.append(call_id)

            for call_id in expired_calls:
                log(f"[CLEANUP] call_sessions timeout → {call_id}", "debug")
                clear_session(call_id)

            time.sleep(interval_sec)

    threading.Thread(target=cleanup, daemon=True).start()

if __name__ == "__main__":
    start_cleanup_thread(timeout_sec=30, interval_sec=5)
    start_sip_log_cleanup_thread()
    main_loop()
