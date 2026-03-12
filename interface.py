import flet as ft
import asyncio


async def main_ui(page: ft.Page):
    page.title = "Network Guard v3.0"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 500
    page.window_height = 800

    devices_list = ft.ListView(expand=True, spacing=10, padding=20)

    async def scan_clicked(e):
        e.control.disabled = True
        page.update()  # БЕЗ await

        devices_list.controls.clear()

        # Имитация тяжелого процесса (оставляем await)
        await asyncio.sleep(0.5)

        devices_list.controls.append(
            ft.ListTile(
                leading=ft.Icon("cellphone_android", color="blue"),
                title=ft.Text("10.165.160.157", weight="bold"),
                subtitle=ft.Text("Target Device"),
                trailing=ft.PopupMenuButton(
                    items=[
                        ft.PopupMenuItem(
                            content=ft.Row(
                                [ft.Icon("block"), ft.Text("Блокировать")]
                            )
                        ),
                        ft.PopupMenuItem(
                            content=ft.Row(
                                [ft.Icon("remove_red_eye"), ft.Text("Мониторинг")]
                            )
                        ),
                    ]
                )
            )
        )

        e.control.disabled = False
        page.update()  # БЕЗ await

    page.add(  # БЕЗ await
        ft.AppBar(
            title=ft.Text("Network Hybrid Tool"),
            bgcolor="surfacevariant",
            center_title=True
        ),
        devices_list,
        ft.FloatingActionButton(
            content=ft.Icon("search"),
            on_click=scan_clicked,
            bgcolor="blue700"
        )
    )


if __name__ == "__main__":
    ft.run(main_ui)