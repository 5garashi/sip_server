import socket

# SIPのポート（通常5060）
SIP_PORT = 5060
SIP_IP = "0.0.0.0"  # 全てのインターフェースで待ち受け

# ソケット作成（UDP）
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SIP_IP, SIP_PORT))

print(f"[INFO] SIPサーバーが {SIP_IP}:{SIP_PORT} で起動しました。")

while True:
    data, addr = sock.recvfrom(4096)
    message = data.decode(errors="ignore")
    print(f"\n--- 受信 from {addr} ---\n{message}")

    # シンプルなREGISTER応答
    if message.startswith("REGISTER"):
        response = (
            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP {}\r\n"
            "From: <sip:test@localhost>\r\n"
            "To: <sip:test@localhost>\r\n"
            "Call-ID: abc123\r\n"
            "CSeq: 1 REGISTER\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).format(addr[0])
        sock.sendto(response.encode(), addr)
        print("[INFO] 200 OKを送信しました")
