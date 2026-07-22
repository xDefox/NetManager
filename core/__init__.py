"""
Network Guard Core Engine
=========================
MITM tool: ARP spoofing + ICMP Redirect + traffic monitoring.

Содержит все сетевые модули:
- vendor   — разрешение вендора по MAC
- network  — базовые операции: сканирование, ARP, gateway
- attack   — ARP-spoof, DHCP-spoof, мониторинг
- monitor  — перехват трафика, OS fingerprint, DNS/SNI
- forwarding — IP forwarding для Windows
"""

from core.vendor import VendorResolver
from core.network import NetworkTool