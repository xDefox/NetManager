# NetManager (Network Guard)

**NetManager** — утилита для анализа и тестирования защищённости **собственной** локальной сети. Показывает устройства в сети, определяет их вендора по MAC и позволяет проверить, насколько сеть устойчива к атакам уровня L2 (ARP/DHCP). Написана на Python с GUI на [Flet](https://flet.dev) и сетевого движка на [Scapy](https://scapy.net).

> ⚠️ **Только для авторизованного тестирования.** Запускайте инструмент исключительно в своей сети или там, где у вас есть письменное разрешение. Использование против чужих сетей незаконно.

## Возможности

- ARP-сканирование подсети (/24) и список активных устройств
- Определение вендора по MAC-адресу (JSON-кэш, TTL 24 ч)
- Проверка устойчивости сети к ARP-spoof и DHCP-spoof
- Мониторинг трафика выбранной цели: DNS-запросы, TLS SNI, HTTP
- OS fingerprinting по TTL
- Восстановление ARP-таблиц при остановке
- GUI (тёмная тема, таблица устройств, логи) и консольный режим

Актуальный статус проекта и известные ограничения — в [STATUS.md](STATUS.md), планы — в [ROADMAP.md](ROADMAP.md).

## Требования

- Windows 10 / 11 (использует WinAPI и `netsh`)
- [Npcap](https://npcap.com/) с WinPcap API (для Scapy)
- Python 3.12+
- Права администратора

## Установка и запуск

```bash
git clone https://github.com/xDefox/NetManager.git
cd NetManager
pip install -r requirements.txt

python main.py          # консольный режим
python interface.py     # GUI
```

## Сборка .exe

```bash
pip install pyinstaller
pyinstaller NetManager.spec
```

Готовый файл появится в `dist/`.

## Структура

```
main.py            # консольный интерфейс
interface.py       # GUI на Flet
NetManager.spec    # конфигурация PyInstaller
core/
  network.py       # NetworkTool: сканирование, атака, мониторинг, форвардинг
  vendor.py        # VendorResolver: вендор по MAC с кэшем
  forwarding.py    # пересылка пакетов
  monitor.py       # перехват трафика цели
  attack.py        # ARP/DHCP-spoof
STATUS.md          # статус и метрики
ROADMAP.md         # планы развития
```
