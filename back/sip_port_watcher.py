#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIP ポート (UDP 5060, TCP 5061) を監視してアクセスを /var/log/sip_access.log へ記録
root で実行してください
"""
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

LOG_FILE = "/var/log/sip_access.log"

def _log(msg: str) -> None:
    """ログファイルに追記"""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def handle_packet(pkt):
    """パケット 1 本ごとに呼ばれるコールバック"""
    # IP ヘッダ必須
    if IP not in pkt:
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    length = len(pkt)

    proto = None
    sport = dport = None

    # UDP 5060
    if UDP in pkt and (pkt[UDP].sport == 5060 or pkt[UDP].dport == 5060):
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    # TCP/TLS 5061
    elif TCP in pkt and (pkt[TCP].sport == 5061 or pkt[TCP].dport == 5061):
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

    # UDP 5070
    if UDP in pkt and (pkt[UDP].sport == 5070 or pkt[UDP].dport == 5070):
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport





    if proto:
        log_line = (f"[{ts}] {proto} {src_ip}:{sport} -> {dst_ip}:{dport} "
                    f"len={length}")
        _log(log_line)

def main():
    # pcap BPF フィルタ（UDP 5060 と TCP 5061）
    bpf = "(udp port 5060) or (tcp port 5061) or (udp port 5070)"
    sniff(filter=bpf, prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
