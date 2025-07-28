# SIP Port Watcher

このツールは、SIP 通信に使われるポート（UDP 5060 / 5070 および TCP 5061）への外部からのアクセスを監視し、リアルタイムでログファイルに記録します。

## 📦 特徴

- `Scapy` によるパッシブキャプチャ（既存のSIPサービスと干渉なし）
- ログファイル形式: `/var/log/sip_access.log`
- ログ例:
  ```
  [2025-07-13 10:00:00] UDP 192.0.2.10:5060 -> 203.0.113.1:5060 len=152
  ```

## 🔧 要件

- Python 3.8+
- scapy >= 2.5

インストールコマンド例（Ubuntu）:

```bash
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy
```

## 🚀 インストール手順

1. スクリプトの配置:

```bash
sudo cp sip_port_watcher.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/sip_port_watcher.py
```

2. ログファイルの準備:

```bash
sudo touch /var/log/sip_access.log
sudo chmod 644 /var/log/sip_access.log
```

## ▶ 実行方法

```bash
sudo /usr/local/bin/sip_port_watcher.py
```

ログは次のように確認できます:

```bash
tail -f /var/log/sip_access.log
```

## 🔄 systemd への登録（任意）

`/etc/systemd/system/sip-watcher.service` を作成して次を記述:

```ini
[Unit]
Description=SIP port watcher
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/sip_port_watcher.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

サービス有効化:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sip-watcher
```

## 🛡️ セキュリティグループ設定（EC2の場合）

| ポート | プロトコル | 用途           |
|--------|------------|----------------|
| 5060   | UDP        | SIP            |
| 5070   | UDP        | カスタムSIP    |
| 5061   | TCP        | SIP over TLS   |

インバウンドルールに上記を追加してください（テスト時はIP制限も推奨）。

## 🪪 ライセンス

MIT
