import flet as ft
import asyncio
import threading
from main import NetworkTool


async def main_ui(page: ft.Page):
    page.title = "Network Guard v3.0"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 1100
    page.window_height = 950
    page.padding = 20

    tool = NetworkTool()

    # --- 1. СОСТОЯНИЕ (Должно быть в самом начале) ---
    # Храним текущую активную цель: {"ip": str, "mode": "attack"|"monitor"|None}
    state = {"ip": None, "mode": None}

    # --- 2. ЭЛЕМЕНТЫ ЛОГА ---
    attack_log = ft.ListView(expand=True, spacing=5, padding=10)
    monitor_log = ft.ListView(expand=True, spacing=5, padding=10)

    def log_to_attack(message):
        attack_log.controls.append(ft.Text(f"> {message}", color="red200", size=12, font_family="monospace"))
        attack_log.scroll_to(offset=-1)
        page.update()

    def log_to_monitor(message):
        monitor_log.controls.append(ft.Text(f">> {message}", color="green200", size=12, font_family="monospace"))
        monitor_log.scroll_to(offset=-1)
        page.update()

    # Привязываем колбэки к инструменту
    tool.on_attack_log = log_to_attack
    tool.on_monitor_log = log_to_monitor

    # --- 3. UI ЭЛЕМЕНТЫ СТАТУСА ---
    status_text = ft.Text("Сканирование...", color="blue400")
    attack_status_view = ft.Text("СТАТУС: ОЖИДАНИЕ", color="grey", weight="bold")
    progress_bar = ft.ProgressBar(width=400, color="blue", visible=False)

    # --- 4. ЛОГИКА ДВИЖКА (Engine) ---
    def stop_engine():
        tool.is_attacking = False
        state["ip"] = None
        state["mode"] = None
        attack_status_view.value = "СТАТУС: ОЖИДАНИЕ"
        attack_status_view.color = "grey"
        page.update()

    def start_engine(device, mode):
        # Сначала всё гасим
        tool.is_attacking = False

        tool.target_info.update({
            "ip": device['ip'],
            "mac": device['mac'],
            "name": device['name'],
            "packets": 0
        })

        state["ip"] = device['ip']
        state["mode"] = mode
        tool.is_attacking = True

        if mode == "attack":
            threading.Thread(target=tool.attack_process, daemon=True).start()
            attack_status_view.value = f"● АТАКА: {device['ip']}"
            attack_status_view.color = "red"
        else:
            threading.Thread(target=tool.monitor_process, daemon=True).start()
            attack_status_view.value = f"● МОНИТОРИНГ: {device['ip']}"
            attack_status_view.color = "yellow"
        page.update()

    def build_table_rows():
        rows = []
        for d in tool.found_devices:
            ip = d['ip']
            is_this_attack = (state["ip"] == ip and state["mode"] == "attack")
            is_this_monitor = (state["ip"] == ip and state["mode"] == "monitor")

            rows.append(
                ft.DataRow(cells=[
                    ft.DataCell(ft.Text(ip)),
                    ft.DataCell(ft.Text(d['mac'])),
                    ft.DataCell(ft.Text(d['name'])),
                    ft.DataCell(ft.Row([
                        ft.IconButton(
                            icon=ft.Icons.BLOCK,
                            icon_color="red" if is_this_attack else "grey700",
                            on_click=lambda e, d=d: handle_click(d, "attack")
                        ),
                        ft.IconButton(
                            icon=ft.Icons.REMOVE_RED_EYE,
                            icon_color="yellow" if is_this_monitor else "grey700",
                            on_click=lambda e, d=d: handle_click(d, "monitor")
                        ),
                    ])),
                    ft.DataCell(
                        ft.Text(
                            "ACTIVE" if (is_this_attack or is_this_monitor) else "IDLE",
                            color="red" if is_this_attack else "yellow" if is_this_monitor else "grey"
                        )
                    ),
                ])
            )
        return rows

    # --- Обновленный обработчик клика ---
    def handle_click(device, mode):
        if state["ip"] == device['ip'] and state["mode"] == mode:
            target_log = log_to_attack if mode == "attack" else log_to_monitor
            target_log(f"Остановка {mode} для {device['ip']}")
            stop_engine()
        else:
            if mode == "attack":
                log_to_attack(f"Запуск атаки на {device['ip']}...")
            else:
                log_to_monitor(f"Запуск мониторинга на {device['ip']}...")
            start_engine(device, mode)

        # КРИТИЧЕСКИЙ МОМЕНТ: Обновляем строки таблицы СРАЗУ после изменения состояния
        devices_table.rows = build_table_rows()
        page.update()

    # --- 5. ТАБЛИЦА ---
    devices_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("IP")),
            ft.DataColumn(ft.Text("MAC")),
            ft.DataColumn(ft.Text("ИМЯ")),
            ft.DataColumn(ft.Text("ДЕЙСТВИЕ")),
            ft.DataColumn(ft.Text("СТАТУС")),
        ],
        rows=[]
    )

    # --- 6. ФОНОВЫЙ ЦИКЛ ОБНОВЛЕНИЯ ---
    async def update_ui_loop():
        while True:
            progress_bar.visible = True
            page.update()

            await asyncio.to_thread(tool.update_devices)

            devices_table.rows = build_table_rows()  # Используем ту же логику

            progress_bar.visible = False
            status_text.value = f"Устройств в сети: {len(tool.found_devices)}"
            page.update()
            await asyncio.sleep(15)

    # --- 7. СБОРКА ИНТЕРФЕЙСА ---
    def create_terminal(title, log_view):
        return ft.Container(
            content=ft.Column([
                ft.Text(title, weight="bold", size=14),
                ft.Container(content=log_view, bgcolor="black", border_radius=5, expand=True)
            ]),
            expand=True, border=ft.border.all(1, "grey800"), padding=10, height=350
        )

    page.add(
        ft.AppBar(title=ft.Text("Network Guard v3.0"), bgcolor="surfacevariant", center_title=True),
        ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.NETWORK_CHECK, color="blue"),
                status_text,
                progress_bar,
                attack_status_view
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=20),
            padding=10, bgcolor="black26", border_radius=10
        ),
        ft.Divider(),
        ft.Text(" Список обнаруженных устройств:", size=14, weight="bold"),
        ft.Container(
            content=ft.ListView([devices_table], height=250),
            border=ft.border.all(1, "grey800"),
            border_radius=10
        ),
        ft.Row([
            create_terminal("ОТЧЕТ АТАКИ", attack_log),
            create_terminal("ПЕРЕХВАТ (MONITOR)", monitor_log)
        ], expand=True)
    )

    asyncio.create_task(update_ui_loop())


if __name__ == "__main__":
    ft.run(main_ui)