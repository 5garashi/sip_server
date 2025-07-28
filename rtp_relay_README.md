以下は `rtp_relay.py` に対応した `README.md` のテンプレートです。`mini_sip_proxy_auth.py` との連携を前提とした **RTP/RTCP中継モジュール**の機能説明、使用方法、構成、設計思想などを明記しています。

---

````markdown
# rtp_relay.py

## 概要

`rtp_relay.py` は、SIPプロキシサーバー `mini_sip_proxy_auth.py` 向けの **RTP / RTCP 中継モジュール**です。NAT越えやセキュリティの観点から、クライアント間の直接メディア通信を避け、プロキシ経由でRTP/RTCPパケットを中継します。

---

## 主な機能

- セッションごとに **RTP用/RTCP用UDPポート**をペアで動的に割り当て
- 各ポートは **1対1通信セッションに専用化**
- 片側のRTPパケットが到着するまで **待機して対向先を特定**
- **双方向中継**（IP/ポート変化に対応）
- 一定時間パケットのないセッションは自動削除（タイムアウト）

---

## 使用例（mini_sip_proxy_auth.py 内部連携）

```python
from rtp_relay import RTPRelayPool
rtp_pool = RTPRelayPool()

# セッション作成（Call-ID単位）
rtp_relay, rtcp_relay = rtp_pool.create_session(call_id)

# SDP書き換え時に rtp_relay.port や rtcp_relay.port を参照
````

---

## 内部構成図

```
       +-------------------------+
       |     RTPRelayPool       |         ← セッションプール
       +-------------------------+
                  |
    +-------------+----------------+
    |                              |
+-----------+              +-------------+
| UDPRelay  | (RTP)        | UDPRelay    | (RTCP)
+-----------+              +-------------+
  port=N                     port=N+1
  ↔ 双方向転送 ↔            ↔ 双方向転送 ↔
```

---

## クラス構成

### `UDPRelay`

* 片方向UDP中継器（1ポート分）
* 最初の受信元を「送信元1」とみなし、以降「送信元2」から来たパケットを送信元1に転送
* `last_recv_time` によりタイムアウト検知可能
* `start()` でスレッド起動

### `RTPRelayPool`

* `call_id` 単位で `UDPRelay` のペア（RTP/RTCP）を生成・管理
* 利用ポートを偶数・奇数のセットで割り当て
* `remove_session(call_id)` でセッション解放
* `cleanup_expired_sessions(timeout_sec)` でタイムアウト検出と削除

---

## セッションタイムアウト管理

* 各 `UDPRelay` に `last_recv_time` が記録される
* `RTPRelayPool.cleanup_expired_sessions()` で定期的に確認
* `mini_sip_proxy_auth.py` ではバックグラウンドスレッドで5秒ごとにチェック

---

## ログ出力（例）
保持期間: 最大7日（古いログは自動削除）           |
```
[RTPRelay] RTP中継セッション開始: port=40000
[RTPRelay] 送信先確定: 192.168.1.10:6000 → 3.212.8.147:51000
[RTPRelay] セッションタイムアウト → 解放
```

---

## 推奨使用ポート範囲

UDPポートは動的に確保しますが、ファイアウォール/NAT越えのため以下を推奨：

* UDPポート範囲： **40000〜50000**
* すべて偶数（RTP）/奇数（RTCP）のセット

---

## 依存モジュール（標準）

* `socket`
* `threading`
* `time`
* `random`
* `datetime`

---

## 使用上の注意

* `RTPRelayPool` は同時に多数のセッションを扱えるよう設計されていますが、リソース制限にご注意ください
* `start()` はスレッド起動のため、過剰にセッションが増えるとCPUリソースを消費します
* リレーを使用しない場合は SDP書き換え機能をOFFにしてください

---

## ライセンス

MIT License（自由に改変・再利用可能）

---

## 補足資料

* このモジュールは `mini_sip_proxy_auth.py` 専用に最適化されています。
* 単独で使用することも可能ですが、セッション管理ロジックは外部で行う必要があります。

```

---

画像付きの中継フロー図や、コード断片を組み込んだバージョンも作成可能です。必要であれば併せてお知らせください。
```
