import socket
import re
from urllib.parse import urlparse
import uuid
import time # 有効期限管理のため追加

# --- SIPプロキシの設定 ---
# !!! 重要 !!! プロキシがリッスンするIPアドレスと、SIPヘッダに挿入する自身のIPアドレスは異なる場合があります。
# AWS EC2などの環境では、外部IPアドレスを明示的に指定する必要があります。
# ここでは、プロキシがリッスンするアドレスと、SIPヘッダに挿入する自身のIPを分けて考えます。

# リッスンするIPアドレス (通常は '0.0.0.0' で全てのインターフェースをリッスン)
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 5060

# SIPヘッダ（Via, Contactなど）に挿入するプロキシ自身のグローバルIPアドレス
# ここをあなたのEC2インスタンスのElastic IPなど、外部からアクセス可能なIPに設定してください。
# 例: PUBLIC_SIP_PROXY_IP = 'XX.XX.XX.XX' (あなたの実際のIP)
PUBLIC_SIP_PROXY_IP = '3.212.8.147' # 仮のIPアドレス。実際のIPに置き換えてください。

# UAの登録情報を動的に保存する辞書
# key: username (e.g., 'alice'), value: {'ip': 'local_ip', 'port': local_port, 'nat_ip': 'global_ip', 'nat_port': global_port, 'expires': expiry_time}
# 'nat_ip'と'nat_port'は、プロキシが受信した実際の送信元IP/ポートを記録する
UA_MAPPING = {}

# トランザクション情報を保存する辞書
# INVITEを送ったクライアントの情報を、その後の応答（1xx, 2xxなど）のために保持
# key: (Call-ID, CSeq, Branch) -> value: {'client_addr': (ip, port), 'timestamp': time.time()}
TRANSACTIONS = {}

# クリーンアップ間隔 (秒)
CLEANUP_INTERVAL = 300 # 5分ごとに古いトランザクションを削除

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
    status_code = None
    
    if lines and lines[0]:
        parts = lines[0].split(' ')
        if len(parts) >= 3 and parts[2].startswith('SIP/'):
            # リクエスト
            method = parts[0]
            request_uri = parts[1]
        elif len(parts) >= 3 and parts[0].startswith('SIP/'):
            # 応答
            method = None # 応答なのでメソッドはない
            status_code = int(parts[1])
            request_uri = None # 応答なのでRequest-URIはない

    return method, request_uri, headers, body, status_code

def build_sip_message(method, request_uri, headers, body, status_code=None, status_text=""):
    """
    パースした情報からSIPメッセージを再構築する
    """
    if method and request_uri: # リクエストの場合
        first_line = f"{method} {request_uri} SIP/2.0"
    elif status_code: # 応答の場合
        first_line = f"SIP/2.0 {status_code} {status_text}"
    else: # どちらでもない場合（エラーなど）
        first_line = ""

    header_lines = [f"{k}: {str(v).strip()}" for k, v in headers.items() if v is not None]
    
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

def parse_uri_host_port_user(uri_str):
    """SIP URIからホスト、ポート、ユーザー名をパースする"""
    if not uri_str:
        return None, None, None

    # <> で囲まれている場合を考慮し、内部のURIを抽出
    match_angle = re.match(r'^<(.*)>$', uri_str)
    if match_angle:
        uri_str = match_angle.group(1)

    # SIP URI形式 (sip:user@host:port)
    # ユーザー名に '+' を含む可能性も考慮
    match_sip_uri = re.match(r'^sip:([^\s@:]+)?@?([^:;]+)(?::(\d+))?.*', uri_str)
    if match_sip_uri:
        user = match_sip_uri.group(1) if match_sip_uri.group(1) else None
        host = match_sip_uri.group(2)
        port = int(match_sip_uri.group(3)) if match_sip_uri.group(3) else 5060
        return host, port, user
    
    # ホスト名/IPアドレスとポートのみの形式 (host:port または IP:port)
    match_host_port = re.match(r'^([^:]+):(\d+)$', uri_str)
    if match_host_port:
        host = match_host_port.group(1)
        port = int(match_host_port.group(2))
        return host, port, None # ユーザー名なし

    # IPアドレスのみの形式
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', uri_str):
        return uri_str, 5060, None # デフォルトポート5060, ユーザー名なし

    return None, None, None

def add_via_header(headers, proxy_ip, proxy_port, client_addr):
    """Viaヘッダを最上位に追加し、received/rportを追加"""
    current_via = get_header_value(headers, 'Via')
    
    # プロキシがメッセージを受信したIPとポートをreceived/rportとして追加
    # この情報は、応答をルーティングする際に必要
    new_via_entry = f"SIP/2.0/UDP {proxy_ip}:{proxy_port};branch=z9hG4bK-{uuid.uuid4().hex};rport={client_addr[1]};received={client_addr[0]}"
    
    if current_via:
        headers['Via'] = f"{new_via_entry}\r\n{current_via}"
    else:
        headers['Via'] = new_via_entry
    return headers

def remove_top_via_header(headers):
    """Viaヘッダの最上位エントリを削除し、残りを返す"""
    via_header = get_header_value(headers, 'Via')
    if not via_header:
        print("エラー: remove_top_via_header - Viaヘッダが見つかりません。")
        return headers, None

    via_entries = via_header.split('\r\n')
    
    # 最上位のViaエントリを取得
    top_via = via_entries[0]

    if len(via_entries) > 1:
        # 最上位以外のエントリを再結合
        remaining_via = '\r\n'.join(via_entries[1:])
        set_header_value(headers, 'Via', remaining_via)
    else:
        # Viaヘッダが1つしかなければ削除
        del headers['Via']
    
    return headers, top_via # 削除後のヘッダと削除されたトップのViaエントリを返す

def update_contact_for_nat(headers, original_contact, nat_ip, nat_port, expires=None):
    """
    ContactヘッダをNAT後のアドレスに書き換える (expiresパラメータも考慮)
    この関数は主にINVITEなどの転送時に使用する。REGISTERの200 OKでは異なる処理。
    """
    if not original_contact:
        return headers

    match = re.search(r'((?:<)?sip:[^\s@:]+@)([^:;>]+)(:(\d+))?([^>]*>)?(.*)', original_contact)
    if match:
        user_host_prefix = match.group(1) 
        # original_host = match.group(2) # 使わないのでコメントアウト
        original_port_str = match.group(4)
        suffix_in_angle = match.group(5) if match.group(5) else '' 
        rest_of_params = match.group(6) if match.group(6) else '' 

        port_to_use = nat_port if nat_port else (int(original_port_str) if original_port_str else 5060)
        port_string = f":{port_to_use}" if port_to_use != 5060 else ""
        
        new_contact_uri_part = f"{user_host_prefix}{nat_ip}{port_string}"
        
        expires_str_to_add = ""
        if expires is not None:
            if re.search(r';expires=\d+', rest_of_params):
                rest_of_params = re.sub(r';expires=\d+', f';expires={expires}', rest_of_params)
            else:
                expires_str_to_add = f";expires={expires}"

        # receivedパラメータはContactヘッダには通常記載しないため削除
        # rportはViaヘッダ用なのでここから削除
        rest_of_params = re.sub(r';received=[^;]+', '', rest_of_params)
        rest_of_params = re.sub(r';rport=[^;]+', '', rest_of_params)

        final_contact_value = f"{new_contact_uri_part}{suffix_in_angle}{rest_of_params}{expires_str_to_add}"
        headers = set_header_value(headers, 'Contact', final_contact_value)
    else:
        print(f"警告: Contactヘッダのパースに失敗しました: {original_contact}。デフォルト処理を試みます。")
        if nat_ip and nat_port:
            headers = set_header_value(headers, 'Contact', f"<sip:unknown@{nat_ip}:{nat_port}>;expires={expires if expires is not None else 3600}")

    return headers

def generate_200_ok(original_headers_dict, registered_contact_info=None):
    # 必要なヘッダーを辞書から取得 (get_header_valueを使う)
    via = get_header_value(original_headers_dict, "Via")
    from_ = get_header_value(original_headers_dict, "From")
    to = get_header_value(original_headers_dict, "To")
    call_id = get_header_value(original_headers_dict, "Call-ID")
    cseq = get_header_value(original_headers_dict, "CSeq")
    
    # Toヘッダーにtagを追加 (既に存在しない場合のみ)
    if to and 'tag=' not in to:
        to += ';' + 'tag=' + uuid.uuid4().hex # Toヘッダにタグを追加
    set_header_value(original_headers_dict, 'To', to) # 更新したToヘッダをセット

    # REGISTERの200 OKでは、Contactヘッダは登録された情報を使う
    contact_header_value = ""
    if registered_contact_info:
        # REGISTERの200 OKに対するContactは、登録されたContact URIを反映し、
        # Expiresパラメータを含むべき
        expires_val = registered_contact_info.get('expires', 3600)
        contact_header_value = f"<sip:{registered_contact_info['user']}@{registered_contact_info['nat_ip']}:{registered_contact_info['nat_port']}>;expires={expires_val}"
    else:
        # それ以外の200 OKの場合、元のContactヘッダを使用
        contact_header_value = get_header_value(original_headers_dict, "Contact")
    
    response_headers = {
        "Via": via,
        "From": from_,
        "To": to,
        "Call-ID": call_id,
        "CSeq": cseq,
        "Contact": contact_header_value, # 登録情報に基づいて設定
        "Expires": "3600", # REGISTER応答用、他のメッセージでは上書きされる
        "Content-Length": "0"
    }
    
    response_message = build_sip_message(None, None, response_headers, '', status_code=200, status_text="OK")
    return response_message

def send_sip_response(status_code, status_text, original_headers, proxy_socket, client_addr):
    """汎用的なSIP応答を生成して送信する"""
    response_headers = {
        'Via': get_header_value(original_headers, 'Via'),
        'From': get_header_value(original_headers, 'From'),
        'To': get_header_value(original_headers, 'To'),
        'Call-ID': get_header_value(original_headers, 'Call-ID'),
        'CSeq': get_header_value(original_headers, 'CSeq'),
        'Server': 'SimplePythonSIPProxy/0.1',
        'Content-Length': '0'
    }
    # ヘッダの値がNoneの場合に空文字列に変換
    for k, v in response_headers.items():
        if v is None:
            response_headers[k] = ""
    
    response_message = build_sip_message(None, None, response_headers, '', status_code=status_code, status_text=status_text)
    
    print(f"\n--- Sending {status_code} {status_text} to {client_addr[0]}:{client_addr[1]} ---")
    try: 
        proxy_socket.sendto(response_message.encode(), client_addr)
    except Exception as e:
        print(f"{status_code} {status_text} 送信エラー: {e}")


# --- SIPプロキシの主要ロジック ---

def handle_sip_request(data, addr, proxy_socket):
    """SIPリクエスト（INVITE, ACK, BYE, REGISTERなど）を処理する"""
    print(f"\n--- 受信リクエスト from {addr[0]}:{addr[1]} ---\n{data.decode()}")
    
    method, request_uri, headers, body, _ = parse_sip_message(data.decode())
    
    if not method:
        print("エラー: SIPメソッドをパースできませんでした。")
        return

    # Fromヘッダからユーザー名を抽出
    from_header = get_header_value(headers, 'From')
    from_user = None
    if from_header:
        match = re.search(r'sip:([^\s@:]+)', from_header)
        if match:
            from_user = match.group(1)

    # --- INVITE リクエストの処理 ---
    if method == 'INVITE':
        # INVITEを受信したらすぐに100 Tryingを返す
        send_sip_response(100, "Trying", headers, proxy_socket, addr) 

    # --- REGISTER リクエストの処理 ---
    if method == 'REGISTER':
        contact_header_val = get_header_value(headers, 'Contact')
        expires = None
        if contact_header_val:
            match_expires = re.search(r'expires=(\d+)', contact_header_val)
            if match_expires:
                expires = int(match_expires.group(1))
            else:
                expires = 3600 # Explicitly set a default if not found

        if from_user and contact_header_val:
            ua_local_ip, ua_local_port, _ = parse_uri_host_port_user(contact_header_val)
            
            # 受信元アドレス (addr) はプロキシから見たUAのIP/ポート（NAT後の可能性あり）
            is_behind_nat = (ua_local_ip != addr[0]) or (ua_local_port != addr[1] and ua_local_port is not None)
            
            # UA_MAPPING を更新
            # REGISTERのContact URIにはユーザー名が含まれるはず
            contact_user = None
            contact_match = re.search(r'sip:([^\s@:]+)', contact_header_val)
            if contact_match:
                contact_user = contact_match.group(1)

            UA_MAPPING[from_user] = {
                'ip': ua_local_ip,
                'port': ua_local_port,
                'nat_ip': addr[0] if is_behind_nat else None, # NAT後のIP
                'nat_port': addr[1] if is_behind_nat else None, # NAT後のポート
                'expires': expires, # 有効期限も記録
                'user': contact_user if contact_user else from_user # Contact URIのユーザー名、なければFromのユーザー名
            }
            print(f"REGISTERed: User '{from_user}' mapped to {UA_MAPPING[from_user]}")

            # REGISTERに対する200 OKをすぐに返す (簡易的なレジストラ動作)
            response_message = generate_200_ok(headers, UA_MAPPING[from_user])
            
            print(f"\n--- REGISTER 200 OK to {addr[0]}:{addr[1]} ---\n{response_message}")
            try:
                proxy_socket.sendto(response_message.encode(), addr)
            except Exception as e:
                print(f"REGISTER 200 OK 送信エラー: {e}")
            return # REGISTERは転送しない

    # --- その他のリクエスト (INVITE, ACK, BYE, CANCELなど) の処理 ---
    # まずプロキシ自身のViaヘッダを追加
    # PUBLIC_SIP_PROXY_IP を使用
    headers = add_via_header(headers, PUBLIC_SIP_PROXY_IP, LISTEN_PORT, addr)

    # Record-Routeヘッダを追加 (INVITEの場合のみ)
    if method == 'INVITE':
        # PUBLIC_SIP_PROXY_IP を使用
        record_route_entry = f"<sip:{PUBLIC_SIP_PROXY_IP}:{LISTEN_PORT};lr>" # lrはLoose Routing
        current_record_route = get_header_value(headers, 'Record-Route')
        if current_record_route:
            headers = set_header_value(headers, 'Record-Route', f"{record_route_entry},{current_record_route}")
        else:
            headers = set_header_value(headers, 'Record-Route', record_route_entry)
    
    # ContactヘッダをNAT後のアドレスに書き換え（UAがNAT内と判断された場合）
    contact_header_val = get_header_value(headers, 'Contact')
    if from_user and from_user in UA_MAPPING and UA_MAPPING[from_user]['nat_ip']:
        # ContactヘッダのNAT対応処理は `update_contact_for_nat` を利用
        # `expires` はUAが指定した値を使用するか、デフォルト値を渡す
        headers = update_contact_for_nat(headers, contact_header_val,
                                         UA_MAPPING[from_user]['nat_ip'], UA_MAPPING[from_user]['nat_port'],
                                         UA_MAPPING[from_user].get('expires'))
            
    # --- ルーティングの決定 ---
    next_hop_ip = None
    next_hop_port = None
    target_user = None

    # Routeヘッダの処理 (Loose Routingに従う)
    route_header = get_header_value(headers, 'Route')
    if route_header:
        # Routeヘッダをコンマで分割し、最初のURIを取得
        route_entries = re.split(r',\s*(?=<sip:)|,\s*(?=sip:)', route_header) # <sip:...>またはsip:...で分割
        first_route_entry = route_entries[0].strip()
        
        next_hop_ip, next_hop_port, _ = parse_uri_host_port_user(first_route_entry)
        
        # 処理したRouteエントリを削除
        if len(route_entries) > 1:
            set_header_value(headers, 'Route', ','.join(route_entries[1:]))
        else:
            del headers['Route']
            
        # ルートヘッダのホストがプロキシ自身の場合、Request-URIをターゲットとする
        if next_hop_ip == PUBLIC_SIP_PROXY_IP:
            # プロキシ自身へのルーティングなので、Request-URIを次のホップとする
            next_hop_ip, next_hop_port, target_user = parse_uri_host_port_user(request_uri)
            
    else: # Routeヘッダがない場合、Request-URIを直接ターゲットとする (UASへのルーティング)
        if request_uri:
            match_user = re.search(r'sip:([^\s@:]+)', request_uri)
            if match_user:
                target_user = match_user.group(1)
            else:
                target_user = urlparse(request_uri).username # fallback

            if target_user == '999':
                print("\n--- Received INVITE to 999. Printing UA_MAPPING: ---")
                if not UA_MAPPING:
                    print(" UA_MAPPING is empty.")
                else:
                    for user, info in UA_MAPPING.items():
                        print(f" User: {user}, Info: {info}")
                print("--------------------------------------------------")
                send_sip_response(404, "Not Found", headers, proxy_socket, addr) 
                return 

            if target_user and target_user in UA_MAPPING:
                ua_info = UA_MAPPING[target_user]
                if ua_info['nat_ip']:
                    next_hop_ip = ua_info['nat_ip']
                    next_hop_port = ua_info['nat_port']
                else:
                    next_hop_ip = ua_info['ip']
                    next_hop_port = ua_info['port']
            else:
                print(f"警告: Request-URIのユーザー名 '{target_user}' に対応する登録済みUAが見つかりません。")
                send_sip_response(404, "Not Found", headers, proxy_socket, addr)
                return

    if not next_hop_ip:
        print("エラー: 次のホップIPが見つかりません。")
        send_sip_response(500, "Internal Server Error", headers, proxy_socket, addr)
        return

    # INVITEリクエストの場合、トランザクション情報を保存
    if method == 'INVITE':
        call_id = get_header_value(headers, 'Call-ID')
        cseq = get_header_value(headers, 'CSeq')
        via_branch = re.search(r'branch=([^;]+)', get_header_value(headers, 'Via')).group(1)
        
        # トランザクションキー: (Call-ID, CSeq番号, Branch)
        transaction_key = (call_id, cseq.split(' ')[0], via_branch)
        TRANSACTIONS[transaction_key] = {
            'client_addr': addr, # 最初にINVITEを送ってきたクライアントのアドレス
            'timestamp': time.time()
        }
        print(f"デバッグ: トランザクション保存: {transaction_key} -> {TRANSACTIONS[transaction_key]}")


    new_message = build_sip_message(method, request_uri, headers, body)
    
    print(f"\n--- 転送リクエスト to {next_hop_ip}:{next_hop_port} ---\n{new_message}")
    
    try:
        proxy_socket.sendto(new_message.encode(), (next_hop_ip, next_hop_port))
    except Exception as e:
        print(f"メッセージ転送エラー: {e}")


def handle_sip_response(data, addr, proxy_socket):
    """SIP応答（1xx, 200 OKなど）を処理する"""
    print(f"\n--- 受信応答 from {addr[0]}:{addr[1]} ---\n{data.decode()}")
    
    # メッセージのパース
    _, _, headers, body, status_code = parse_sip_message(data.decode())
    
    # Call-IDとCSeqから関連するトランザクションを検索
    call_id = get_header_value(headers, 'Call-ID')
    cseq = get_header_value(headers, 'CSeq')
    
    # 応答のViaヘッダからプロキシ自身が追加したViaを探す
    via_header = get_header_value(headers, 'Via')
    if not via_header:
        print("エラー: 応答のViaヘッダが見つかりません。転送できません。")
        return

    via_entries = via_header.split('\r\n')
    
    # 最上位のViaエントリは、応答側が追加したもの。
    # その次のViaエントリが、プロキシ自身が追加したもの。
    # RFC 3261 16.6.6 Response Processing: プロキシは自身のViaを削除して転送する
    
    # プロキシが追加したViaヘッダを特定
    # 実際には、複数のプロキシが存在する場合、Viaスタックはより長くなる
    # ここでは、プロキシが自身を特定するための `branch` パラメータが重要
    
    # プロキシ自身のViaエントリを特定するために、`branch` に `z9hG4bK-proxy-` を含むものを探す
    proxy_via_entry_index = -1
    for i, entry in enumerate(via_entries):
        if f"SIP/2.0/UDP {PUBLIC_SIP_PROXY_IP}:{LISTEN_PORT}" in entry or f"SIP/2.0/UDP {LISTEN_IP}:{LISTEN_PORT}" in entry:
            # branch=z9hG4bK-proxy- のようなパターンで絞り込むのがより確実
            if "branch=z9hG4bK-proxy-" in entry: # 修正: uuid.uuid4().hexで生成したブランチを識別
                 proxy_via_entry_index = i
                 break
        elif f"received={PUBLIC_SIP_PROXY_IP}" in entry and f"rport={LISTEN_PORT}" in entry:
            if "branch=z9hG4bK-proxy-" in entry: # 修正: uuid.uuid4().hexで生成したブランチを識別
                 proxy_via_entry_index = i
                 break

    if proxy_via_entry_index == -1:
        print(f"警告: 応答 {status_code} のViaスタックにプロキシ自身のViaエントリが見つかりません。")
        # トランザクション情報を基に、直接発信元に転送を試みる
        found_transaction = None
        for key, tx_info in TRANSACTIONS.items():
            tx_call_id, tx_cseq_num, _ = key
            if tx_call_id == call_id and tx_cseq_num == cseq.split(' ')[0]:
                found_transaction = tx_info
                break

        if found_transaction:
            next_hop_ip = found_transaction['client_addr'][0]
            next_hop_port = found_transaction['client_addr'][1]
            print(f"デバッグ: トランザクション情報に基づき転送: {next_hop_ip}:{next_hop_port}")
            # この場合、Viaヘッダは変更せずそのまま転送
            new_message = build_sip_message(None, None, headers, body, status_code=status_code, status_text=status_line.split(' ', 2)[2])
            print(f"\n--- 転送応答 (Via無しトランザクションベース) to {next_hop_ip}:{next_hop_port} ---\n{new_message}")
            try:
                proxy_socket.sendto(new_message.encode(), (next_hop_ip, next_hop_port))
            except Exception as e:
                print(f"メッセージ転送エラー (Via無しトランザクションベース): {e}")
            return
        else:
            print("エラー: プロキシ自身のViaエントリがなく、対応するトランザクションも見つかりません。応答を転送できません。")
            return


    # プロキシ自身のViaエントリを削除
    del via_entries[proxy_via_entry_index]
    if via_entries:
        set_header_value(headers, 'Via', '\r\n'.join(via_entries))
    else:
        del headers['Via'] # Viaヘッダが空になる場合は削除

    # 削除後のViaスタックの最上位から次のホップを決定
    next_hop_ip = None
    next_hop_port = None
    
    if via_entries:
        # 新しい最上位のViaエントリを取得
        next_via_entry = via_entries[0]
        
        # `rport` と `received` を使用して次のホップを特定
        # LinphoneクライアントからのViaヘッダには、通常この情報が含まれる
        match_rport_received = re.search(r';received=([^;]+)(?:;rport=(\d+))?', next_via_entry)
        if match_rport_received:
            next_hop_ip = match_rport_received.group(1)
            # rport が存在しない場合もあるため、group(2) は None の可能性を考慮し、デフォルト5060
            next_hop_port = int(match_rport_received.group(2)) if match_rport_received.group(2) else 5060 
            print(f"デバッグ: handle_sip_response - Extracted via received/rport: {next_hop_ip}:{next_hop_port}")
        else:
            # received/rport がない場合は、ViaヘッダのIP:ポートを直接パース
            # このパスに来る場合は、Viaヘッダが不正な可能性があります
            match_host_port = re.search(r'SIP/2.0/UDP\s+([^:]+):(\d+)', next_via_entry)
            if match_host_port:
                next_hop_ip = match_host_port.group(1)
                next_hop_port = int(match_host_port.group(2))
                print(f"デバッグ: handle_sip_response - Extracted via host/port: {next_hop_ip}:{next_hop_port}")
            else:
                print(f"エラー: 応答の次のホップIP/ポートをViaヘッダ '{next_via_entry}' から抽出できませんでした。")
                send_sip_response(500, "Internal Server Error", headers, proxy_socket, addr) # 自身にエラーを返す
                return
    else:
        # Viaヘッダが残っていない（最終ホップである）場合
        # このシナリオは通常発生しないはず
        print("警告: 応答のViaヘッダスタックが空になりました。ルーティングに問題がある可能性があります。")
        # この場合は、対応するトランザクション情報から元のクライアントに送り返す
        found_transaction = None
        for key, tx_info in TRANSACTIONS.items():
            tx_call_id, tx_cseq_num, _ = key
            if tx_call_id == call_id and tx_cseq_num == cseq.split(' ')[0]:
                found_transaction = tx_info
                break

        if found_transaction:
            next_hop_ip = found_transaction['client_addr'][0]
            next_hop_port = found_transaction['client_addr'][1]
            print(f"デバッグ: 空のViaスタック、トランザクション情報に基づき転送: {next_hop_ip}:{next_hop_port}")
        else:
            print("エラー: Viaスタックが空で、対応するトランザクションが見つかりません。応答を転送できません。")
            return

    if not next_hop_ip or not next_hop_port:
        print("エラー: 応答の次のホップIPまたはポートが見つかりません。")
        send_sip_response(500, "Internal Server Error", headers, proxy_socket, addr)
        return
        
    # メッセージを再構築
    new_message = build_sip_message(None, None, headers, body, status_code=status_code, status_text=status_line.split(' ', 2)[2])

    print(f"\n--- 転送応答 to {next_hop_ip}:{next_hop_port} ---\n{new_message}")

    try:
        proxy_socket.sendto(new_message.encode(), (next_hop_ip, next_hop_port))
    except Exception as e:
        print(f"メッセージ転送エラー: {e}")

def cleanup_old_transactions():
    """期限切れのトランザクションを削除する"""
    current_time = time.time()
    keys_to_delete = []
    for key, tx_info in TRANSACTIONS.items():
        # INVITEトランザクションは通常64秒程度でタイムアウト
        # ここでは余裕を見て数分で削除する
        if current_time - tx_info['timestamp'] > 120: # 120秒 (2分) を超えたら削除
            keys_to_delete.append(key)
    
    for key in keys_to_delete:
        del TRANSACTIONS[key]
        print(f"デバッグ: 古いトランザクションを削除しました: {key}")

def cleanup_old_registrations():
    """期限切れのUA登録を削除する"""
    current_time = time.time()
    users_to_delete = []
    for user, info in UA_MAPPING.items():
        # REGISTERでExpires: 0 が送られた場合、または登録期限が切れた場合
        # ここでは実装の簡易化のため、Expiresヘッダで指定された秒数を使用
        # 厳密には、REGISTERの200 OKのExpiresヘッダを記録し、その時刻まで有効とする
        # 現状のUA_MAPPINGにはexpiresが秒数として保存されているので、単純に時刻を計算する
        
        # 現状のコードではUA_MAPPINGにタイムスタンプがないため、expiresだけでは自動削除は不完全
        # ここでは一旦、expiresが0のものを削除する簡易実装とする
        if info.get('expires') == 0:
            users_to_delete.append(user)
        # もしタイムスタンプを追加するなら、例えば register_time を追加
        # if current_time - info.get('register_time', 0) > info.get('expires', 0):
        #    users_to_delete.append(user)

    for user in users_to_delete:
        del UA_MAPPING[user]
        print(f"デバッグ: 期限切れの登録を削除しました: {user}")

# --- メインのプロキシサーバ ---

def run_proxy():
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_socket.bind((LISTEN_IP, LISTEN_PORT))
    print(f"SIPプロキシが {LISTEN_IP}:{LISTEN_PORT} でリッスン中... (Public IP: {PUBLIC_SIP_PROXY_IP})")

    last_cleanup_time = time.time()

    while True:
        try:
            data, addr = proxy_socket.recvfrom(8192) # 4096から8192に増やしました。大きなSIPメッセージに対応
            
            # クリーンアップの実行
            current_time = time.time()
            if current_time - last_cleanup_time > CLEANUP_INTERVAL:
                cleanup_old_transactions()
                cleanup_old_registrations() # REGISTER期限切れの処理を追加
                last_cleanup_time = current_time

            # SIPメッセージの開始行をチェック
            try:
                message_start = data[:100].decode('utf-8', errors='ignore') 
                if not (message_start.startswith(("INVITE", "REGISTER", "ACK", "BYE", "CANCEL", "OPTIONS", 
                                                "MESSAGE", "SUBSCRIBE", "NOTIFY", "INFO", "PRACK", 
                                                "REFER", "UPDATE", "PUBLISH", "SIP/2.0"))): 
                    print(f"警告: SIPメッセージではない可能性があるデータを受信しました from {addr[0]}:{addr[1]}")
                    continue 

                message = data.decode('utf-8') 
            except UnicodeDecodeError as e:
                print(f"ソケットエラー (デコード): {e}")
                print(f"受信リクエスト from {addr[0]}:{addr[1]} --- (バイナリデータまたは不正なエンコーディング)")
                continue 
            except Exception as e: 
                print(f"ソケットエラー (メッセージ解析前): {e}")
                continue

            if message.startswith('SIP/2.0'):
                handle_sip_response(data, addr, proxy_socket)
            else:
                handle_sip_request(data, addr, proxy_socket)
        except Exception as e:
            print(f"ソケットエラー (受信ループ): {e}")

if __name__ == "__main__":
    run_proxy()