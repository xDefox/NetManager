"""
Network Guard — Console Interface
==================================
Запуск: python main.py (требуются права администратора)

Меню:
1. Сканировать сеть
2. ARP-spoof атака (обрыв связи цели)
3. Мониторинг (ARP-spoof + перехват трафика)
4. Найти самое активное устройство
5. Остановить атаку
6. Выход
7. DHCP Spoof (обход статического ARP)
"""

from __future__ import annotations

import os
import sys
import time

import ctypes

from core.network import NetworkTool


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def console_main() -> None:
    """Запустить консольный интерфейс."""
    if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
        print("Требуются права администратора!")
        sys.exit(1)

    tool = NetworkTool()
    tool.update_devices()

    while True:
        clear_screen()
        print("--- [ NETWORK GUARD v3.0 ] ---")
        print(f"MY IP: {tool.my_ip} | GW: {tool.router_ip} ({tool.router_mac})")
        print("-" * 55)

        if tool.is_attacking:
            print(f"● СТАТУС: АТАКА АКТИВНА | ЦЕЛЬ: {tool.target_info['ip']}")
            print(f"   ПАКЕТОВ: {tool.target_info['packets']}")
        else:
            print("○ СТАТУС: ОЖИДАНИЕ")

        print("-" * 55)
        print("ID | IP АДРЕС       | MAC АДРЕС         | ИМЯ")
        for i, d in enumerate(tool.found_devices):
            print(f"{i:2} | {d['ip'].ljust(14)} | {d['mac']} | {d['name']}")
        print("-" * 55)
        print("1. Сканировать | 2. Атака | 3. Мониторинг | 4. По шуму | 5. СТОП | 6. Выход")

        cmd = input(">> ").strip()
        if cmd == "1":
            tool.update_devices()
        elif cmd == "2":
            try:
                idx = int(input("Введите ID цели: "))
                target = tool.found_devices[idx]
                tool.attack(target["ip"], target["mac"])
            except (ValueError, IndexError):
                pass
        elif cmd == "3":
            try:
                idx = int(input("Введите ID для мониторинга: "))
                target = tool.found_devices[idx]
                tool.start_monitor(target["ip"], target["mac"])
            except (ValueError, IndexError):
                pass
        elif cmd == "4":
            print("Сканирую сеть 7 секунд...")
            noisy_ip = tool.find_noisy_guy()
            if noisy_ip:
                mac = tool._get_mac(noisy_ip)
                if mac:
                    tool.attack(noisy_ip, mac)
            else:
                print("Активных устройств не найдено.")
                time.sleep(1)
        elif cmd == "5":
            tool.stop()
        elif cmd == "6":
            tool.stop()
            break


if __name__ == "__main__":
    console_main()