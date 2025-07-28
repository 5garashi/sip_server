import socket
import threading

# プロキシの待ち受けIPとポート
PROXY_IP = '0.0.0.0'
PROXY_PORT = 5060

# クライアントのレジストリ情報（FromのURIと宛先アドレス）
client_registry = {}

def parse_sip_message(message):
    lines = message.split('\r\n')
    headers = {}
    body_index = -1
    for i, line in enumerate(lines):
        if not line:
            body_index = i + 1
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    body = '\r\n'.join(lines[body_index:]) if body_index != -1 else ''
    
    method = None
    request_uri = None
    status_code = None
    status_text = ""

    if lines and lines[0]:
        parts = lines[0].split(' ', 2)
        if len(parts) >= 3 and parts[2].startswith('SIP/'):
            # リクエスト行: INVITE sip:bob@...
            method = parts[0]
            request_uri = parts[1]
        elif len(parts) >= 2 and parts[0].startswith('SIP/'):
            # ステータス行: SIP/2.0 180 Ringing
            status_code = int(parts[1])
            status_text = parts[2] if len(parts) > 2 else ""

    return method, request_uri, headers, body, status_code, status_text

def build_sip_message(method, uri, headers, body, status_code=None, status_text=None):
    lines = []

    if method and uri:
        lines.append(f"{method} {uri} SIP/2.0")
    elif status_code:
        lines.append(f"SIP/2.0 {status_code} {status_text}")
    else:
        lines.append("")

    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    lines.append('')  # 空行でヘッダ終了
    if body:
        lines.append(body)
    return '\r\n'.join(lines)

def handle_sip_request(data, addr, sock):
    method, request_uri, headers, body, _, _ = parse_sip_message(data.decode())

    print(f"[Request] {method} from {addr}")

    # 登録処理 (REGISTER)
    if method == 'REGISTER':
        from_uri = headers.get('From', '').split(';')[0]
        client_registry[from_uri] = addr
        print(f"Registered {from_uri} -> {addr}")
        return

    # 転送処理（INVITEなど）
    if method in ('INVITE', 'ACK', 'BYE'):
        to_uri = headers.get('To', '').split(';')[0]
        dest_addr = client_registry.get(to_uri)
        if dest_addr:
            # Viaを1つ追加
            via = headers.get('Via', '')
            headers['Via'] = f"SIP/2.0/UDP {PROXY_IP}:{PROXY_PORT};branch=z9hG4bK1234\r\nVia: {via}"

            new_message = build_sip_message(method, request_uri, headers, body)
            sock.sendto(new_message.encode(), dest_addr)
            print(f"Forwarded {method} to {dest_addr}")
        else:
            print(f"Unknown destination: {to_uri}")

def handle_sip_response(data, addr, sock):
    _, _, headers, body, status_code, status_text = parse_sip_message(data.decode())

    print(f"[Response] {status_code} from {addr}")

    # Viaヘッダから最初の送信元を決定（複数Viaの先頭に戻す）
    via = headers.get('Via', '')
    via_lines = via.split('\r\nVia:')
    if len(via_lines) > 1:
        headers['Via'] = '\r\nVia:'.join(via_lines[1:])
    else:
        headers.pop('Via', None)

    from_uri = headers.get('To', '').split(';')[0]
    dest_addr = client_registry.get(from_uri)

    if dest_addr:
        new_message = build_sip_message(None, None, headers, body, status_code=status_code, status_text=status_text)
        sock.sendto(new_message.encode(), dest_addr)
        print(f"Forwarded response {status_code} to {dest_addr}")
    else:
        print(f"Destination not found for {from_uri}")

def sip_proxy():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((PROXY_IP, PROXY_PORT))
    print(f"SIP Proxy listening on {PROXY_IP}:{PROXY_PORT}")

    while True:
        data, addr = sock.recvfrom(65535)
        if not data:
            continue

        first_line = data.decode().split('\r\n', 1)[0]
        if first_line.startswith('SIP/2.0'):
            threading.Thread(target=handle_sip_response, args=(data, addr, sock)).start()
        else:
            threading.Thread(target=handle_sip_request, args=(data, addr, sock)).start()

if __name__ == '__main__':
    sip_proxy()
