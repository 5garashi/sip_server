import socket
import time
from datetime import datetime

# ========= 設定 =========
SIP_SERVER_IP   = "3.212.8.147"       # mini_sip_proxy.py を動かしているサーバーのパブリックIP
SIP_SERVER_PORT = 5060

PUBLIC_IP       = "3.212.8.147"       # このクライアントが外部から見えるグローバルIP
BIND_IP         = "0.0.0.0"           # 実際にbindできるIP（0.0.0.0でOK）
LOCAL_PORT      = 5070                # クライアントが使う送信元ポート

LOCAL_USER      = "user1"             # このクライアントのユーザー名
TARGET_USER     = "user2"             # 発信先ユーザー名（登録済み）

# ========= ソケット準備 =========
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((BIND_IP, LOCAL_PORT))

# ========= 共通関数 =========
def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def send_sip(message, label):
    print(f"\n[{now()}] >>> 送信 ({label}) → {SIP_SERVER_IP}:{SIP_SERVER_PORT}")
    print("-" * 60)
    print(message.strip())
    print("-" * 60)
    sock.sendto(message.encode(), (SIP_SERVER_IP, SIP_SERVER_PORT))

def receive_sip():
    sock.settimeout(3)
    try:
        data, addr = sock.recvfrom(4096)
        print(f"\n[{now()}] <<< 受信 from {addr}")
        print("-" * 60)
        print(data.decode(errors='replace').strip())
        print("-" * 60)
    except socket.timeout:
        print(f"[{now()}] [WARN] 応答なし（タイムアウト）")

# ========= REGISTER =========
register_msg = (
    f"REGISTER sip:{SIP_SERVER_IP} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP {PUBLIC_IP}:{LOCAL_PORT}\r\n"
    f"From: <sip:{LOCAL_USER}@{SIP_SERVER_IP}>\r\n"
    f"To: <sip:{LOCAL_USER}@{SIP_SERVER_IP}>\r\n"
    f"Call-ID: reg1234@{PUBLIC_IP}\r\n"
    f"CSeq: 1 REGISTER\r\n"
    f"Contact: <sip:{LOCAL_USER}@{PUBLIC_IP}:{LOCAL_PORT}>\r\n"
    f"Content-Length: 0\r\n\r\n"
)
send_sip(register_msg, "REGISTER")
receive_sip()
time.sleep(1)

# ========= INVITE =========
invite_msg = (
    f"INVITE sip:{TARGET_USER}@{SIP_SERVER_IP} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP {PUBLIC_IP}:{LOCAL_PORT}\r\n"
    f"From: <sip:{LOCAL_USER}@{SIP_SERVER_IP}>\r\n"
    f"To: <sip:{TARGET_USER}@{SIP_SERVER_IP}>\r\n"
    f"Call-ID: call5678@{PUBLIC_IP}\r\n"
    f"CSeq: 1 INVITE\r\n"
    f"Contact: <sip:{LOCAL_USER}@{PUBLIC_IP}:{LOCAL_PORT}>\r\n"
    f"Content-Type: application/sdp\r\n"
    f"Content-Length: 0\r\n\r\n"
)
send_sip(invite_msg, "INVITE")
receive_sip()
time.sleep(1)

# ========= BYE =========
bye_msg = (
    f"BYE sip:{TARGET_USER}@{SIP_SERVER_IP} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP {PUBLIC_IP}:{LOCAL_PORT}\r\n"
    f"From: <sip:{LOCAL_USER}@{SIP_SERVER_IP}>\r\n"
    f"To: <sip:{TARGET_USER}@{SIP_SERVER_IP}>\r\n"
    f"Call-ID: call5678@{PUBLIC_IP}\r\n"
    f"CSeq: 2 BYE\r\n"
    f"Content-Length: 0\r\n\r\n"
)
send_sip(bye_msg, "BYE")
receive_sip()

sock.cl
