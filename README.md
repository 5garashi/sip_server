以下に、「構成図」と「SIP応答の流れ図」を含めた `README.md` の完全版を提供します。\*\*テキストベースの図（ASCIIアート）\*\*を用いて、ファイル単体で見やすく設計しています。

---

```markdown
# mini_sip_proxy_auth.py

## 概要

`mini_sip_proxy_auth.py` は、簡易SIPプロキシサーバーであり、以下の機能を提供します：

- Digest認証（REGISTER / INVITE 対応）
- NAT越え支援（Contact / SDP / Via ヘッダーの動的書き換え）
- RTP/RTCP リレーによる音声パケット中継
- セッション監視とタイムアウト自動解放
- 重複メッセージの抑止機能
- 未登録ユーザーからのSIPパケットを無応答で破棄するステルスモード
 （Silent Drop for Unknown Users）
- デバッグ用ダイヤルコマンド（985〜999）

---

## システム構成図

```

+----------+         +----------------------+          +----------+
\| UA A     | <--->   | mini\_sip\_proxy\_auth  |  <---->  | UA B     |
\| (Client) |  SIP    |  + RTPRelayPool       |   SIP   | (Client) |
+----------+         +----------------------+          +----------+
\|                        |    ^
\|---- REGISTER --------->|    |
|<--- 401 + nonce -------|    |
\|---- REGISTER + Auth -->|    |
|<--- 200 OK ------------|    |
\|                        |    |
\|---- INVITE ----------->|    |
\|                        |----> look up callee
\|                        |----> forward INVITE to UA B
\|                        |<---- 180 Ringing / 200 OK
|<-----------------------|<---- forward response
\|---- ACK -------------->|----> ACK
\|                        |<==== RTP relay ====>|

```

---

## SIP応答の流れ（INVITE〜BYE）

```

```
Caller (UA A)                Proxy                 Callee (UA B)
    |                          |                        |
    |-------- INVITE --------->|                        |
    |                          |--- INVITE ------------>|
    |                          |<-- 180 Ringing --------|
    |<------ 180 Ringing ------|                        |
    |                          |<-- 200 OK -------------|
    |<------- 200 OK ----------|                        |
    |-------- ACK ------------>|--- ACK --------------->|
    |======== RTP Stream (Relayed via Proxy) ==========>|
    |                          |                        |
    |-------- BYE ------------>|--- BYE --------------->|
    |                          |<-- 200 OK -------------|
    |<------- 200 OK ----------|                        |
```

````

---

## 起動方法

```bash
python3 mini_sip_proxy_auth.py [オプション]
````

### オプション例

| オプション名       | 説明                          |
| ------------ | --------------------------- |
| `debug`      | 詳細ログ（SIP全文、HexDump含む）を出力    |
| `re_contact` | Contactヘッダー書き換えを有効化         |
| `re_sdp`     | SDP内のc=, m=, rtcp行の書き換えを有効化 |
| `re_via`     | Viaヘッダーに received/rport を追加 |
| `duplicate`  | 重複SIPメッセージを5秒以内に無視          |
| `silent`     | 未登録ユーザーのSIPを無視          |
```bash
python3 mini_sip_proxy_auth.py debug re_contact re_sdp re_via duplicate
```

---

## デバッグ用ダイヤル番号（INVITE時）

| ダイヤル番号 | 動作内容                  |
| ------ | --------------------- |
| 985    | silent drop 機能 OFF |
| 986    | silent drop 機能 ON  |
| 987    | 重複抑止（duplicate）機能 OFF |
| 988    | 重複抑止（duplicate）機能 ON  |
| 989    | ログモード brief に変更       |
| 990    | ログモード debug に変更       |
| 991    | Via書き換え OFF           |
| 992    | Via書き換え ON            |
| 993    | SDP書き換え OFF           |
| 994    | SDP書き換え ON            |
| 995    | Contact書き換え OFF       |
| 996    | Contact書き換え ON        |
| 997    | 現在のセッション情報をログに出力      |
| 998    | 登録ユーザー一覧をNOTIFYで送信    |
| 999    | 登録ユーザー一覧をログに出力        |

---

## セッション管理

* セッションは `call_sessions` により管理
* タイムアウト：30秒間通信がないと自動削除
* RTP/RTCP中継ポートはセッションごとに割り当て

---

## ログファイル

| 項目     | 内容                        |
| ------ | ------------------------- |
| ログファイル | `sip_server.log` に出力      |
| モード    | `brief`（簡易） / `debug`（詳細） |
| 保持期間   | 最大7日（古いログは自動削除）           |

---

## 登録ユーザー（Digest認証）

登録可能ユーザーは、スクリプト内の `auth_users` にて定義：

```python
auth_users = {
    "001": "****",
    "002": "****",
    ...
}
```

---

## 依存モジュール（標準）

* `socket`
* `re`
* `datetime`
* `hashlib`
* `threading`
* `os`
* `random`
* `ipaddress`

---

## 補足

* このサーバーは **UDPポート5060専用**
* SIP over TCP/TLS は未対応
* 外部公開する場合はファイアウォールやACL等でアクセス制御推奨
* 本格的運用にはログローテートやDB連携の追加も検討ください

---



# Mini SIP Proxy のデーモン化手順

このドキュメントでは、`mini_sip_proxy_auth.py` を Linux サーバー上でバックグラウンド起動（デーモン化）する2つの方法を説明します。

---

## ✅ 方法 1：systemd サービスとして登録（推奨）

### 🔧 ステップ 1：サービスファイルを作成

```bash
sudo nano /etc/systemd/system/sip_proxy.service
````

内容例：

```ini
[Unit]
Description=Mini SIP Proxy Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/ubuntu/sip_server/mini_sip_proxy_auth.py
WorkingDirectory=/home/ubuntu/sip_server
StandardOutput=append:/var/log/sip_proxy.out.log
StandardError=append:/var/log/sip_proxy.err.log
Restart=always
User=ubuntu

[Install]
WantedBy=multi-user.target
```

※ `ExecStart` のパスや `User` は環境に応じて調整してください。

---

### 🔧 ステップ 2：サービスを有効化・起動

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable sip_proxy.service
sudo systemctl start sip_proxy.service
```

---

### 🔍 状態確認

```bash
sudo systemctl status sip_proxy.service
```

---

### 📦 自動起動確認（reboot後も起動するか）

```bash
systemctl is-enabled sip_proxy.service
```

---

## ✅ 方法 2：nohup を使った簡易デーモン化（開発向け）

ログをファイルに保存しつつ、バックグラウンドで実行します。

### 🔧 実行コマンド

```bash
sudo touch /var/log/sip_proxy.out.log
sudo chown ubuntu:ubuntu /var/log/sip_proxy.out.log
nohup python3 /home/ubuntu/sip_server/mini_sip_proxy_auth.py  re_sdp re_contact re_via silent > /var/log/sip_proxy.out.log 2>&1 &
```

---

### 🔍 実行確認

```bash
ps aux | grep mini_sip_proxy_auth.py
```

---

### 🔧 停止するには

```bash
kill <プロセスID>
```

---

## 📎 補足：ログ保存ディレクトリの作成

ログディレクトリが存在しないと書き込みに失敗します。

```bash
sudo mkdir -p /var/log
sudo chown ubuntu:ubuntu /var/log
```

---

## ✅ 推奨

| 方法        | 対象 | 特徴                 |
| --------- | -- | ------------------ |
| `systemd` | 本番 | 自動起動・自動再起動・ログ管理に対応 |
| `nohup &` | 開発 | 一時的なバックグラウンド起動に便利  |

---

## ✅ 備考

* `systemd` を使う場合、ログは `/var/log/sip_proxy.out.log` に保存されます。
* 複数のプロセスが同じログファイルに書き込まないよう注意してください。


## 著者・ライセンス

* 作者: motomasa igarashi
* ライセンス: MIT（自由に改変・再配布可能）


---


# mini_sip_proxy_auth.py におけるヘッダー書き換えの目的と効果

このドキュメントでは、`mini_sip_proxy_auth.py` に実装されている SIP メッセージの下記ヘッダー／情報の書き換え処理について、それぞれの目的・動作・効果を詳しく解説します。

- Contact ヘッダーの書き換え
- SDP（Session Description Protocol）の書き換え
- Via ヘッダーの書き換え（または挿入）

---

## 1. 📮 Contact ヘッダーの書き換え

### ✅ 目的
- Contact ヘッダーは、**将来のSIPリクエスト（BYE・再INVITEなど）の送信先を示す**アドレスです。
- NAT配下のUA（ユーザーエージェント）は、ContactにプライベートIPを含めるため、**相手側が後続リクエストを送れない問題**が発生します。

### ✍️ 書き換え内容（例）:
```

元: Contact: [sip\:alice@192.168.1.10:5060](sip:alice@192.168.1.10:5060)
変更後: Contact: [sip\:alice@203.0.113.10:62000](sip:alice@203.0.113.10:62000) （プロキシが受けたIP/Port）

```

### 💡 効果
- 応答側（受信UA）やプロキシが、**正しいパブリックIPとポートへSIPメッセージを返送できるようになる**。
- コール中にBYEやre-INVITEを送信するとき、**このContactに送信される**ため、正確である必要がある。

---

## 2. 🎧 SDP（c=行, a=rtcp行）の書き換え

### ✅ 目的
- SDPは、RTP/RTCPによる**音声通話のIP・ポート情報**を伝える領域です。
- NAT配下のUAが**プライベートIP**を記載するため、音声通話（RTP）が届かなくなる問題が発生します。

### ✍️ 書き換え内容（例）:
```

元: c=IN IP4 192.168.1.10
変更後: c=IN IP4 203.0.113.10 （プロキシ自身のグローバルIP）

元: a=rtcp:49170
変更後: a=rtcp:60002 （プロキシが中継用に割り当てたポート）

```

### 💡 効果
- 双方のUAが直接RTPを送れなくても、**プロキシがRTPリレー（中継）することで通話を成立させる**。
- 音声・映像のメディアセッションがNATを越えて接続できるようになる。

---

## 3. 🛣️ Via ヘッダーの書き換え・挿入

### ✅ 目的
- Viaヘッダーは、**リクエストが通過した経路情報**を保持し、**レスポンスを戻すための道しるべ**となります。
- NAT環境では、ViaにプライベートIPが入っていると、**レスポンス（例：200 OK）が戻らなくなる**ため、プロキシが正しい情報を挿入・書き換える必要があります。

### ✍️ 書き換え・挿入内容（例）:
```

元: Via: SIP/2.0/UDP 192.168.1.10:5060;branch=abc123
変更後: Via: SIP/2.0/UDP 203.0.113.10:5060;branch=abc123 （プロキシが処理用に追加）

※最終的にレスポンスはこのViaヘッダーを元に戻される

```

### 💡 効果
- 200 OK や 100 Trying などの**レスポンスが発信元へ正しく戻る**。
- プロキシ経由のコールセットアップに必須。

---

## 🎯 Contact と Via の効果の違い

| 比較項目       | Contact ヘッダー                          | Via ヘッダー                            |
|----------------|-------------------------------------------|------------------------------------------|
| 目的           | 将来のリクエスト（BYE, re-INVITE）の宛先 | レスポンス（200 OKなど）の戻り先ルート  |
| 使用タイミング | 通話中の次のSIPメッセージ送信            | 通話確立時の応答ルーティング            |
| NAT問題        | プライベートIPだとリクエストが届かない    | プライベートIPだと応答が戻らない        |
| 書き換え効果   | 相手UAが正しくリクエストを送れるようになる| 応答が元のUAに正しく戻るようになる     |

---

## ✅ まとめ

- `Contact` は「後で使う送信先」
- `Via` は「今返すべき返信ルート」
- `SDP` は「音声通信の実体」

すべてを正しく書き換えることで、**NAT配下のUA同士でも通話が成立するSIPプロキシ**が実現します。

---


