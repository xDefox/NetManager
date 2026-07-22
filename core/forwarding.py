"""
IP Forwarding — управление форвардингом пакетов в Windows.

Работает через:
1. Реестр IPEnableRouter
2. PowerShell Set-NetIPInterface
3. netsh advfirewall

Это вспомогательный механизм. Основной форвардинг делается
на уровне пользователя в monitor.py (_forward_packet).
"""

from __future__ import annotations

import os
import subprocess


def _enable_firewall_forwarding(enable: bool = True) -> None:
    """Вкл/выкл правила фаервола для IP forwarding."""
    if os.name != "nt":
        return
    action = "allow" if enable else "block"
    for profile in ("any",):
        cmd = (
            f'netsh advfirewall firewall add rule '
            f'name="NetManager Forward" '
            f'dir=in action={action} '
            f'profile={profile} '
            f"enable={'yes' if enable else 'no'} "
            f'description="NetManager MITM forwarding"'
        )
        subprocess.run(cmd, shell=True, capture_output=True, timeout=5)


def toggle_forwarding(state: bool = True) -> None:
    """Включить/выключить IP-форвардинг в Windows.

    Args:
        state: True — включить, False — выключить
    """
    if os.name != "nt":
        return

    val = 1 if state else 0

    # 1. Реестр
    try:
        subprocess.run(
            f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services'
            f'\\Tcpip\\Parameters" /v IPEnableRouter /t REG_DWORD /d {val} /f',
            shell=True, capture_output=True, text=True, timeout=5,
        )
    except Exception:
        pass

    # 2. PowerShell (может не работать без полного админа)
    try:
        ps_cmd = (
            f'powershell -NoProfile -Command "'
            f'Get-NetIPInterface | Set-NetIPInterface -Forwarding '
            f'{"Enabled" if state else "Disabled"} -ErrorAction SilentlyContinue'
            f'"'
        )
        subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, timeout=10)
    except Exception:
        pass

    # 3. Firewall
    try:
        _enable_firewall_forwarding(state)
    except Exception:
        pass