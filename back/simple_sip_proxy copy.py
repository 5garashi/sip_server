import socket
import re
from urllib.parse import urlparse

# --- SIPプロキシの設定 ---
SIP_PROXY_IP = '127.0.0.1'  # プロキシがリッスンするIPアドレス (通常は外部からアクセス可能なIP)
SIP_PROXY_PORT = 5060       # プロキシがリッスンするポート

# 簡易的なUA情報（本来はレジストラから取得）
# この例では、UA2はPublic IPを持つと仮定
UA_MAPPING = {
    'alice': {'ip': '192.168.1.100', 'port': 5060, 'nat_ip': '203.0.113.1', 'nat_port': 50000}, # NAT内UA
    'bob': {'ip': '200.200.200.200', 'port': 5060, 'nat_ip': None, 'nat_port': None} # Public IP UA
}

# --- ヘルパー関数 ---

def parse_sip_message(message):
    """
    SIPメッセージをヘッダとボディにパースする
    非常にシンプルな実装で、完全なSIPパースは行わない
    """
    lines = message.split('\r\n')
    headers = {}
    body_index = -1
    for i, line in enumerate(lines):
        if not line: # 空行がヘッダとボディの区切り
            body_index = i + 1
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    body = '\r\n'.join(lines[body_index:]) if body_index != -1 else ''
    
    # SIPメソッドとRequest-URIの抽出（リクエストラインから）
    method = None
    request_uri = None
    if lines and lines[0]:
        parts = lines[0].split(' ')
        if len(parts) >= 3 and parts[2].startswith('SIP/'):
            method = parts[0]
            request_uri = parts[1]
    
    return method, request_uri, headers, body

def build_sip_message(method, request_uri, headers, body):
    """
    パースした情報からSIPメッセージを再構築する
    """
    first_line = f"{method} {request_uri} SIP/2.0" if method and request_uri else ""
    header_lines = [f"{k}: {v}" for k, v in headers.items()]
    
    return "\r\n".join([first_line] + header_lines + ["", body])

def get_header_value(headers, key):
    """ヘッダの値を取得（大文字小文字を区別しない）"""
    for k, v in headers.items():
        if k.lower() == key.lower():
            return v
    return None

def set_header_value(headers, key, value):
    """ヘッダの値を設定（既存があれば更新、なければ追加）"""
    found = False
    for k in list(headers.keys()): # keys()のコピーを作成してイテレーション中に変更可能にする
        if k.lower() == key.lower():
            headers[k] = value
            found = True
            break
    if not found:
        headers[key] = value
    return headers

def parse_uri_host_port(uri_str):
    """SIP URIからホストとポートをパースする"""
    if not uri_str.startswith('sip:') and not uri_str.startswith('sips:'):
        return None, None
    
    parts = urlparse(uri_str)
    host = parts.hostname
    port = parts.port if parts.port else 5060 # デフォルトポートは5060
    return host, port

def add_via_header(headers, proxy_ip, proxy_port):
    """Viaヘッダを最上位に追加"""
    current_via = get_header_value(headers, 'Via')
    new_via_entry = f"SIP/2.0/UDP {proxy_ip}:{proxy_port};branch=z9hG4bK-proxy-{uuid.uuid4().hex}"
    
    if current_via:
        headers['Via'] = f"{new_via_entry}\r\n{current_via}"
    else:
        headers['Via'] = new_via_entry
    return headers

def update_contact_for_nat(headers, original_contact, nat_ip, nat_port):
    """ContactヘッダをNAT後のアドレスに書き換える"""
    # 非常に単純な実装。Contact URIのホスト部分のみを置き換える
    if not original_contact:
        return headers

    match = re.search(r'(sip:[^@]+@)([^:;]+)(:(\d+))?', original_contact)
    if match:
        user_part = match.group(1)
        #port_part = match.group(3) if match.group(3) else f":{nat_port}" if nat_port else ""
        
        # ポートはnat_portがあればそれを使い、なければ元のポートを使う
        original_port = match.group(4)
        port_to_use = nat_port if nat_port else original_port if original_port else 5060
        port_string = f":{port_to_use}" if port_to_use != 5060 else "" # 5060は省略可能
        
        new_contact_value = f"{user_part}{nat_ip}{port_string}"
        headers = set_header_value(headers, 'Contact', new_contact_value)
    return headers

import uuid # branchタグ生成用

# --- SIPプロキシの主要ロジック ---

def handle_sip_request(data, addr, proxy_socket):
    """SIPリクエスト（INVITE, ACK, BYEなど）を処理する"""
    print(f"\n--- 受信リクエスト from {addr[0]}:{addr[1]} ---\n{data.decode()}")
    
    method, request_uri, headers, body = parse_sip_message(data.decode())
    
    if not method:
        print("エラー: SIPメソッドをパースできませんでした。")
        return

    # NATの内側から来たリクエストの場合、ViaとContactを更新
    # この例では、UA1がNATの内側にいると仮定
    if addr[0] == UA_MAPPING['alice']['ip'] or (UA_MAPPING['alice']['nat_ip'] and addr[0] == UA_MAPPING['alice']['nat_ip']):
        # Viaヘッダにreceived/rportを追加（プロキシが受信したIPとポート）
        # このプロキシ自身がUA1の直接の隣接ホップになるので、この段階で追加
        via_header_val = get_header_value(headers, 'Via')
        if via_header_val:
            # 最上位のViaにのみ付加
            first_via_line = via_header_val.split('\r\n')[0]
            if ';received=' not in first_via_line: # 既に追加されていなければ
                first_via_line_updated = f"{first_via_line};received={addr[0]};rport={addr[1]}"
                headers['Via'] = headers['Via'].replace(first_via_line, first_via_line_updated, 1)
            
            # Record-Routeヘッダを追加 (INVITEの場合のみ)
            if method == 'INVITE':
                record_route_entry = f"sip:{SIP_PROXY_IP}:{SIP_PROXY_PORT};lr" # lrはLoose Routing
                current_record_route = get_header_value(headers, 'Record-Route')
                if current_record_route:
                    headers = set_header_value(headers, 'Record-Route', f"{record_route_entry},{current_record_route}")
                else:
                    headers = set_header_value(headers, 'Record-Route', record_route_entry)
            
            # ContactヘッダをNAT後のアドレスに書き換え（UA1がNAT内なので）
            # これはプロキシの責任で書き換える
            contact_header_val = get_header_value(headers, 'Contact')
            if contact_header_val and UA_MAPPING['alice']['nat_ip']:
                headers = update_contact_for_nat(headers, contact_header_val,
                                                 UA_MAPPING['alice']['nat_ip'], UA_MAPPING['alice']['nat_port'])
        
    # --- ルーティングの決定 ---
    # Request-URIまたはRouteヘッダを優先して次のホップを決定
    next_hop_ip = None
    next_hop_port = None
    
    route_header = get_header_value(headers, 'Route')
    if route_header:
        # Record-Routeから変換されたRouteヘッダを優先的に処理
        # 最上位のRouteヘッダを取り除く
        first_route_entry = route_header.split(',')[0].strip()
        
        # Route URIからホストとポートを抽出
        next_hop_ip, next_hop_port = parse_uri_host_port(first_route_entry)
        
        # Routeヘッダを更新（最上位のエントリを削除）
        if ',' in route_header:
            set_header_value(headers, 'Route', route_header.split(',', 1)[1].strip())
        else:
            del headers['Route'] # Routeヘッダを削除
            
    else:
        # Routeヘッダがない場合、Request-URIを見る
        # 簡単のため、Request-URIのユーザー名でルーティングを決定
        if request_uri:
            parsed_uri = urlparse(request_uri)
            if parsed_uri.hostname in [v['ip'] for v in UA_MAPPING.values() if v['ip']]:
                next_hop_ip = parsed_uri.hostname
                next_hop_port = parsed_uri.port if parsed_uri.port else 5060
            else: # ユーザー名@ドメイン形式の場合
                user_part = parsed_uri.username
                if user_part == 'bob': # 宛先がUA2の場合
                    next_hop_ip = UA_MAPPING['bob']['ip']
                    next_hop_port = UA_MAPPING['bob']['port']
                elif user_part == 'alice': # 宛先がUA1の場合（BYEなど）
                    # BYEがプロキシ経由でUA1に来る場合は、Contactヘッダを見るべき
                    # 今回はRecord-Route経由なので、Routeヘッダが優先されるはず
                    # Routeヘッダがない場合は、ダイアログ内のTo/Fromタグなどから解決すべきだが、簡易化
                    contact_header = get_header_value(headers, 'Contact')
                    if contact_header:
                        next_hop_ip, next_hop_port = parse_uri_host_port(contact_header)
                        # NAT後のIPの場合がある
                        if next_hop_ip == UA_MAPPING['alice']['nat_ip']:
                            next_hop_ip = UA_MAPPING['alice']['nat_ip']
                            next_hop_port = UA_MAPPING['alice']['nat_port']
                        else: # ローカルIPの場合
                             next_hop_ip = UA_MAPPING['alice']['ip']
                             next_hop_port = UA_MAPPING['alice']['port']
                    else:
                        print(f"警告: Request-URIのユーザー名 '{user_part}' に対応する宛先が見つかりません。")
                        return # エラーレスポンスを返すのが適切

    if not next_hop_ip:
        print("エラー: 次のホップIPが見つかりません。")
        return

    # プロキシ自身のViaヘッダを追加
    # Note: ACKやBYEはダイアログ内リクエストなので、Viaは既存のチェーンに追加される形
    headers = add_via_header(headers, SIP_PROXY_IP, SIP_PROXY_PORT)
    
    # メッセージを再構築
    new_message = build_sip_message(method, request_uri, headers, body)
    
    print(f"\n--- 転送リクエスト to {next_hop_ip}:{next_hop_port} ---\n{new_message}")
    
    try:
        proxy_socket.sendto(new_message.encode(), (next_hop_ip, next_hop_port))
    except Exception as e:
        print(f"メッセージ転送エラー: {e}")

def handle_sip_response(data, addr, proxy_socket):
    """SIP応答（1xx, 200 OKなど）を処理する"""
    print(f"\n--- 受信応答 from {addr[0]}:{addr[1]} ---\n{data.decode()}")
    
    lines = data.decode().split('\r\n')
    status_line = lines[0]
    headers = {}
    body_index = -1
    for i, line in enumerate(lines[1:]):
        if not line:
            body_index = i + 2 # 0-indexed, skip status line and empty line
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    body = '\r\n'.join(lines[body_index:]) if body_index != -1 else ''

    # Viaヘッダを処理して次のホップを決定
    via_header = get_header_value(headers, 'Via')
    if not via_header:
        print("エラー: Viaヘッダが見つかりません。")
        return

    # 最上位のViaエントリを削除し、次のホップの情報を取得
    via_entries = via_header.split('\r\n')
    first_via_entry = via_entries[0]
    
    next_hop_ip = None
    next_hop_port = None
    
    match_rport = re.search(r';received=([^;]+);rport=(\d+)', first_via_entry)
    if match_rport:
        next_hop_ip = match_rport.group(1)
        next_hop_port = int(match_rport.group(2))
    else:
        # received/rportがない場合、Viaのホスト/ポートを見る
        match_host_port = re.search(r'SIP/2.0/UDP\s+([^:]+):(\d+)', first_via_entry)
        if match_host_port:
            next_hop_ip = match_host_port.group(1)
            next_hop_port = int(match_host_port.group(2))
    
    if not next_hop_ip:
        print("エラー: 応答の次のホップIPが見つかりません。")
        return
        
    # Viaヘッダを更新（最上位のエントリを削除）
    if len(via_entries) > 1:
        set_header_value(headers, 'Via', '\r\n'.join(via_entries[1:]))
    else:
        del headers['Via'] # Viaヘッダを削除

    # 200 OK の場合、応答側のContactヘッダをNAT対応に書き換える可能性
    if status_line.startswith('SIP/2.0 200 OK'):
        contact_header_val = get_header_value(headers, 'Contact')
        # UA2がPublic IPなので、通常は書き換え不要だが、SBCの例として
        # もしUA2もNAT内なら、ここで処理が必要になる。この例ではUA2はPublicなのでスキップ
        pass # 現状UA2はPublicなので書き換えは不要

    # メッセージを再構築
    new_message = build_sip_message(None, None, headers, body) # 応答なのでメソッドとURIはNone
    new_message = f"{status_line}\r\n{new_message}" # ステータスラインを先頭に追加

    print(f"\n--- 転送応答 to {next_hop_ip}:{next_hop_port} ---\n{new_message}")

    try:
        proxy_socket.sendto(new_message.encode(), (next_hop_ip, next_hop_port))
    except Exception as e:
        print(f"メッセージ転送エラー: {e}")

# --- メインのプロキシサーバ ---

def run_proxy():
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_socket.bind((SIP_PROXY_IP, SIP_PROXY_PORT))
    print(f"SIPプロキシが {SIP_PROXY_IP}:{SIP_PROXY_PORT} でリッスン中...")

    while True:
        try:
            data, addr = proxy_socket.recvfrom(4096) # バッファサイズを大きく
            message = data.decode()

            if message.startswith('SIP/2.0'): # これは応答
                handle_sip_response(data, addr, proxy_socket)
            else: # これはリクエスト
                handle_sip_request(data, addr, proxy_socket)
        except Exception as e:
            print(f"ソケットエラー: {e}")

if __name__ == "__main__":
    run_proxy()