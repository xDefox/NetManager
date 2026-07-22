"""
Network Guard v3.0 — GUI (Flet)
================================
Тёмная тема, таблица устройств, логи атаки/мониторинга, досье цели.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Optional

import ctypes

import flet as ft

from core.network import NetworkTool


def _is_admin() -> bool:
    """Проверить, запущено ли приложение с правами администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


_update_queues: dict[int, list] = {}
_main_page_ref: list = []


def _safe_page_update(page: ft.Page) -> None:
    """Вызвать page.update() потокобезопасно из любого потока."""
    if threading.current_thread() is threading.main_thread():
        page.update()
    else:
        # В фоновом потоке ставим обновление в очередь
        try:
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(
                _coro_update(page), loop
            )
        except RuntimeError:
            pass


async def _coro_update(page: ft.Page) -> None:
    """Корутина для обновления страницы из фонового потока."""
    page.update()


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

async def main_ui(page: ft.Page) -> None:
    # Проверка прав администратора
    if not _is_admin():
        page.add(
            ft.Container(
                content=ft.Column([
                    ft.Icon(ft.Icons.WARNING_AMBER, size=64, color="red"),
                    ft.Text(
                        "Требуются права администратора!",
                        size=24, weight="bold", color="red",
                    ),
                    ft.Text(
                        "Перезапустите приложение от имени администратора.",
                        size=16, color="grey",
                    ),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=20),
                alignment=ft.alignment.center,
                expand=True,
            )
        )
        page.update()
        return

    page.title = "Network Guard v3.0"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 1100
    page.window_height = 950
    page.padding = 20

    tool = NetworkTool()
    state: dict = {"ip": None, "mode": None}

    # ---- 1. Лог-виджеты ----
    attack_log = ft.ListView(expand=True, spacing=5, padding=10)
    monitor_log = ft.ListView(expand=True, spacing=5, padding=10)

    # ---- 2. Инфо-панели ----
    # "Обо мне"
    user_info = ft.Container(
        content=ft.Row([
            ft.Icon(ft.Icons.PERSON_PIN, color="blue200", size=20),
            ft.Text("MY IP:", size=12, color="grey"),
            ft.Text(f"{tool.my_ip}", size=13, weight="bold", color="blue200"),
            ft.VerticalDivider(width=20),

            ft.Icon(ft.Icons.ROUTER, color="amber200", size=20),
            ft.Text("ROUTER:", size=12, color="grey"),
            ft.Text(f"{tool.router_ip}", size=13, weight="bold", color="amber200"),
            ft.Text(f"({tool.router_mac})", size=11, color="grey400"),

            ft.VerticalDivider(width=20),
            ft.Icon(ft.Icons.LANGUAGE, color="green200", size=20),
            ft.Text("RANGE:", size=12, color="grey"),
            ft.Text(f"{tool.network_range}", size=13, weight="bold", color="green200"),
        ], alignment=ft.MainAxisAlignment.CENTER),
        padding=10,
        bgcolor="white10",
        border_radius=8,
        border=ft.Border.all(1, "white10"),
    )

    # Досье цели (компактное)
    target_device_name = ft.Text("None", weight="bold", color="blue200")
    target_os_view = ft.Text("Detecting...", weight="bold", color="amber200")
    target_packets_view = ft.Text("0 Pkts", weight="bold", color="green200")

    target_card = ft.Container(
        content=ft.Row([
            ft.Icon(ft.Icons.PERSON, size=20, color="red400"),
            ft.Text("TARGET:", size=12, color="grey"),
            target_device_name,
            ft.VerticalDivider(width=20),
            ft.Text("OS:", size=12, color="grey"),
            target_os_view,
            ft.VerticalDivider(width=20),
            ft.Text("ACTIVITY:", size=12, color="grey"),
            target_packets_view,
        ], alignment=ft.MainAxisAlignment.CENTER),
        bgcolor="black26",
        padding=10,
        border_radius=8,
        border=ft.Border.all(1, "red900"),
        visible=False,
        height=50,
    )

    # ---- 3. Функции логирования (thread-safe) ----
    def log_to_attack(message: str) -> None:
        attack_log.controls.append(
            ft.Text(f"> {message}", color="red200", size=12, font_family="monospace")
        )
        _safe_page_update(page)

    def log_to_monitor(message: str) -> None:
        monitor_log.controls.append(
            ft.Text(f">> {message}", color="green200", size=12, font_family="monospace")
        )
        _safe_page_update(page)

    tool.on_attack_log = log_to_attack
    tool.on_monitor_log = log_to_monitor

    # ---- 4. Статус-бар ----
    status_text = ft.Text("Сканирование...", color="blue400")
    attack_status_view = ft.Text("СТАТУС: ОЖИДАНИЕ", color="grey", weight="bold")
    progress_bar = ft.ProgressBar(width=400, color="blue", visible=False)

    # ---- 5. Логика управления ----
    def stop_engine() -> None:
        tool.stop()
        state["ip"], state["mode"] = None, None
        attack_status_view.value = "СТАТУС: ОЖИДАНИЕ"
        attack_status_view.color = "grey"
        target_card.visible = False
        _safe_page_update(page)

    def start_engine(device: dict, mode: str) -> None:
        tool.stop()
        time.sleep(0.2)

        state["ip"], state["mode"] = device["ip"], mode

        if mode == "attack":
            tool.attack(device["ip"], device["mac"])
            attack_status_view.value = f"● АТАКА: {device['ip']}"
            attack_status_view.color = "red"
        else:
            tool.start_monitor(device["ip"], device["mac"])
            attack_status_view.value = f"● МОНИТОРИНГ: {device['ip']}"
            attack_status_view.color = "yellow"

        target_card.visible = True
        _safe_page_update(page)

    def handle_click(device: dict, mode: str) -> None:
        if state["ip"] == device["ip"] and state["mode"] == mode:
            stop_engine()
        else:
            start_engine(device, mode)
        rebuild_table()
        _safe_page_update(page)

    # ---- 6. Таблица устройств ----
    devices_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text(x))
            for x in ["IP", "MAC", "ИМЯ", "ДЕЙСТВИЕ", "СТАТУС"]
        ],
        rows=[],
        column_spacing=20,
    )

    def build_table_rows() -> list[ft.DataRow]:
        rows: list[ft.DataRow] = []
        for d in tool.found_devices:
            ip = d["ip"]
            is_atk = state["ip"] == ip and state["mode"] == "attack"
            is_mon = state["ip"] == ip and state["mode"] == "monitor"

            # Статус
            if is_atk:
                status_text_val = "ACTIVE"
                status_color = "red"
            elif is_mon:
                status_text_val = "ACTIVE"
                status_color = "yellow"
            else:
                status_text_val = "IDLE"
                status_color = "grey"

            rows.append(ft.DataRow(cells=[
                ft.DataCell(ft.Text(ip)),
                ft.DataCell(ft.Text(d["mac"])),
                ft.DataCell(ft.Text(d["name"])),
                ft.DataCell(ft.Row([
                    ft.IconButton(
                        ft.Icons.BLOCK,
                        icon_color="red" if is_atk else "grey700",
                        on_click=lambda e, d=d: handle_click(d, "attack"),
                        tooltip="Атака (ARP + DHCP)",
                    ),
                    ft.IconButton(
                        ft.Icons.REMOVE_RED_EYE,
                        icon_color="yellow" if is_mon else "grey700",
                        on_click=lambda e, d=d: handle_click(d, "monitor"),
                        tooltip="Мониторинг",
                    ),
                ])),
                ft.DataCell(ft.Text(
                    status_text_val,
                    color=status_color,
                )),
            ]))
        return rows

    def rebuild_table() -> None:
        devices_table.rows = build_table_rows()

    # ---- 7. Цикл обновления UI ----
    async def update_ui_loop() -> None:
        scan_timer = 0
        while True:
            try:
                if scan_timer <= 0:
                    progress_bar.visible = True
                    _safe_page_update(page)
                    try:
                        await asyncio.to_thread(tool.update_devices)
                    except Exception as exc:
                        status_text.value = f"Ошибка сканирования: {exc}"
                        progress_bar.visible = False
                        _safe_page_update(page)
                        await asyncio.sleep(1)
                        scan_timer = 5
                        continue

                    rebuild_table()
                    progress_bar.visible = False
                    status_text.value = (
                        f"Устройств в сети: {len(tool.found_devices)}"
                    )
                    scan_timer = 20

                if tool.is_attacking:
                    target_card.visible = True
                    target_device_name.value = tool.target_info.get("name", "None")

                    current_ip = tool.target_info.get("ip")
                    # Пытаемся найти ОС из найденных устройств
                    detected_os: Optional[str] = None
                    for d in tool.found_devices:
                        if d["ip"] == current_ip:
                            detected_os = d.get("os")
                            break

                    target_os_view.value = (
                        tool.target_info.get("os")
                        or detected_os
                        or "Detecting..."
                    )
                    target_packets_view.value = (
                        f"{tool.target_info.get('packets', 0)} Pkts"
                    )
                else:
                    target_card.visible = False

                _safe_page_update(page)
            except Exception:
                pass  # Не даём упасть циклу

            await asyncio.sleep(0.5)
            scan_timer -= 0.5

    # ---- 8. Терминалы ----
    def create_terminal(title: str, log_view: ft.ListView) -> ft.Container:
        return ft.Container(
            content=ft.Column([
                ft.Text(title, weight="bold", size=14),
                ft.Container(
                    content=log_view,
                    bgcolor="black",
                    border_radius=5,
                    expand=True,
                ),
            ]),
            expand=True,
            border=ft.Border.all(1, "grey800"),
            padding=10,
            height=350,
        )

    # ---- 9. Сборка интерфейса ----
    page.add(
        ft.AppBar(
            title=ft.Text("Network Guard v3.0"),
            bgcolor="surfacevariant",
            center_title=True,
        ),
        user_info,
        ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.NETWORK_CHECK, color="blue"),
                status_text,
                progress_bar,
                attack_status_view,
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=20),
            padding=10,
            bgcolor="black26",
            border_radius=10,
        ),
        target_card,
        ft.Text(" Список обнаруженных устройств:", size=14, weight="bold"),
        ft.Container(
            content=ft.ListView([devices_table], height=180),
            border=ft.Border.all(1, "grey800"),
            border_radius=10,
        ),
        ft.Row([
            create_terminal("ОТЧЕТ АТАКИ", attack_log),
            create_terminal("ПЕРЕХВАТ (MONITOR)", monitor_log),
        ], expand=True),
    )

    asyncio.create_task(update_ui_loop())


if __name__ == "__main__":
    ft.run(main_ui)