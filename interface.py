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
    state = {"ip": None, "mode": None}

    # --- 1. ЭЛЕМЕНТЫ ЛОГА ---
    attack_log = ft.ListView(expand=True, spacing=5, padding=10)
    monitor_log = ft.ListView(expand=True, spacing=5, padding=10)

    # --- 2. ВИДЖЕТЫ ДОСЬЕ (Создаем заранее) ---
    target_device_name = ft.Text("Не выбрано", size=18, weight="bold")
    target_os_view = ft.Text("Ожидание...", size=18, weight="bold", color="blue200")
    target_packets_view = ft.Text("0 Pkts", size=18, weight="bold", color="green200")

    # Блок "Обо мне"
    # Блок "Обо мне" (Технические данные системы)
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
        border=ft.Border.all(1, "white10")
    )

    # Компактное досье (в одну строку)
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
        height=50
    )

    # --- 3. ФУНКЦИИ ЛОГИРОВАНИЯ ---
    def log_to_attack(message):
        attack_log.controls.append(ft.Text(f"> {message}", color="red200", size=12, font_family="monospace"))
        attack_log.scroll_to(offset=-1, duration=100)
        page.update()

    def log_to_monitor(message):
        monitor_log.controls.append(ft.Text(f">> {message}", color="green200", size=12, font_family="monospace"))
        monitor_log.scroll_to(offset=-1, duration=100)
        page.update()

    tool.on_attack_log = log_to_attack
    tool.on_monitor_log = log_to_monitor

    # --- 4. СТАТУС БАР ---
    status_text = ft.Text("Сканирование...", color="blue400")
    attack_status_view = ft.Text("СТАТУС: ОЖИДАНИЕ", color="grey", weight="bold")
    progress_bar = ft.ProgressBar(width=400, color="blue", visible=False)

    # --- 5. ЛОГИКА ДВИЖКА ---
    def stop_engine():
        tool.is_attacking = False
        state["ip"], state["mode"] = None, None
        attack_status_view.value = "СТАТУС: ОЖИДАНИЕ"
        attack_status_view.color = "grey"
        target_card.visible = False
        page.update()

    def start_engine(device, mode):
        tool.is_attacking = False
        tool.target_info.update({
            "ip": device['ip'], "mac": device['mac'],
            "name": device['name'], "packets": 0, "os": "Определяется..."
        })
        state["ip"], state["mode"] = device['ip'], mode
        tool.is_attacking = True

        if mode == "attack":
            threading.Thread(target=tool.attack_process, daemon=True).start()
            attack_status_view.value, attack_status_view.color = f"● АТАКА: {device['ip']}", "red"
        else:
            threading.Thread(target=tool.monitor_process, daemon=True).start()
            attack_status_view.value, attack_status_view.color = f"● МОНИТОРИНГ: {device['ip']}", "yellow"

        target_card.visible = True
        page.update()

    def handle_click(device, mode):
        if state["ip"] == device['ip'] and state["mode"] == mode:
            stop_engine()
        else:
            start_engine(device, mode)
        devices_table.rows = build_table_rows()
        page.update()

    def build_table_rows():
        rows = []
        for d in tool.found_devices:
            ip = d['ip']
            is_atk = (state["ip"] == ip and state["mode"] == "attack")
            is_mon = (state["ip"] == ip and state["mode"] == "monitor")
            rows.append(ft.DataRow(cells=[
                ft.DataCell(ft.Text(ip)),
                ft.DataCell(ft.Text(d['mac'])),
                ft.DataCell(ft.Text(d['name'])),
                ft.DataCell(ft.Row([
                    ft.IconButton(ft.Icons.BLOCK, icon_color="red" if is_atk else "grey700",
                                  on_click=lambda e, d=d: handle_click(d, "attack")),
                    ft.IconButton(ft.Icons.REMOVE_RED_EYE, icon_color="yellow" if is_mon else "grey700",
                                  on_click=lambda e, d=d: handle_click(d, "monitor")),
                ])),
                ft.DataCell(ft.Text("ACTIVE" if (is_atk or is_mon) else "IDLE",
                                    color="red" if is_atk else "yellow" if is_mon else "grey")),
            ]))
        return rows

    devices_table = ft.DataTable(
        columns=[ft.DataColumn(ft.Text(x)) for x in ["IP", "MAC", "ИМЯ", "ДЕЙСТВИЕ", "СТАТУС"]],
        rows=[]
    )

    # --- 6. ОБНОВЛЕНИЕ UI (Исправленный цикл) ---
    async def update_ui_loop():
        scan_timer = 0
        while True:
            if scan_timer <= 0:
                progress_bar.visible = True
                page.update()
                await asyncio.to_thread(tool.update_devices)
                devices_table.rows = build_table_rows()
                progress_bar.visible = False
                status_text.value = f"Устройств в сети: {len(tool.found_devices)}"
                scan_timer = 20

            if tool.is_attacking:
                target_card.visible = True
                target_device_name.value = tool.target_info.get('name', 'None')

                # Ищем актуальную ОС из списка найденных устройств или из перехвата
                current_ip = tool.target_info.get('ip')
                # Пытаемся найти инфу об ОС в общем списке найденных устройств
                for d in tool.found_devices:
                    if d['ip'] == current_ip:
                        tool.target_info['os'] = d.get('os', 'Detecting...')
                        break

                target_os_view.value = tool.target_info.get('os', "Detecting...")
                target_packets_view.value = f"{tool.target_info.get('packets', 0)} Pkts"
            else:
                target_card.visible = False

            page.update()
            await asyncio.sleep(0.5)
            scan_timer -= 0.5

    # --- 7. СБОРКА ИНТЕРФЕЙСА ---
    def create_terminal(title, log_view):
        return ft.Container(
            content=ft.Column([
                ft.Text(title, weight="bold", size=14),
                ft.Container(content=log_view, bgcolor="black", border_radius=5, expand=True)
            ]),
            expand=True, border=ft.Border.all(1, "grey800"), padding=10, height=350
        )

    page.add(
        ft.AppBar(title=ft.Text("Network Guard v3.0"), bgcolor="surfacevariant", center_title=True),
        user_info,  # Твоя инфа теперь в самом верху
        ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.NETWORK_CHECK, color="blue"),
                status_text,
                progress_bar,
                attack_status_view
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=20),
            padding=10, bgcolor="black26", border_radius=10
        ),
        target_card,  # Компактное досье сразу под статус-баром
        ft.Text(" Список обнаруженных устройств:", size=14, weight="bold"),
        ft.Container(content=ft.ListView([devices_table], height=180), border=ft.Border.all(1, "grey800"),
                     border_radius=10),
        ft.Row([
            create_terminal("ОТЧЕТ АТАКИ", attack_log),
            create_terminal("ПЕРЕХВАТ (MONITOR)", monitor_log)
        ], expand=True)
    )

    asyncio.create_task(update_ui_loop())


if __name__ == "__main__":
    ft.run(main_ui)