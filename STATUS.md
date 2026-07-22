# Project Status: Network Guard / NetManager

> **Дата:** 22.07.2026  
> **Версия:** v3.0 (refactored)  
> **Репозиторий:** `origin: https://github.com/xDefox/NetManager.git`  
> **Последний коммит:** `39353b7d0131f0e3852f1c2a37fdfa9a0d318a44`

---

## 📋 Общая информация

| Параметр | Значение |
|----------|----------|
| Язык | Python 3.13 |
| GUI-фреймворк | Flet |
| Сетевой движок | Scapy |
| ОС | Windows 11 (только NT) |
| Сборка | PyInstaller (NetManager.spec) |
| Лицензия | MIT |

---

## 🏗 Архитектура

```
revange/
├── main.py          # Ядро: NetworkTool, VendorResolver, console UI
├── interface.py     # GUI на Flet
├── NetManager.spec  # PyInstaller spec (точка входа: interface.py)
├── ROADMAP.md       # Идеи и планы
├── STATUS.md        # Этот файл
├── build/           # Артефакты сборки
└── .venv/           # Виртуальное окружение
```

### main.py (708 строк)
- **VendorResolver** — разрешение вендора по MAC с JSON-кэшем (24ч TTL)
- **NetworkTool** — основной класс:
  - `update_devices()` — ARP-сканирование сети
  - `attack(ip, mac)` — ARP-spoof + ICMP Redirect
  - `start_monitor(ip, mac)` — ARP-spoof + перехват + user-space forwarding
  - `stop()` — остановка + восстановление ARP
  - `find_noisy_guy()` — поиск самого активного устройства
  - `_forward_packet()` — пересылка пакетов между целью и роутером
  - `_packet_callback()` — OS fingerprinting, DNS/SNI/HTTP capture
  - `toggle_forwarding()` — OS-level IP forwarding (реестр + PowerShell + netsh)
- **console_main()** — консольный UI (альтернатива GUI)

### interface.py (~320 строк)
- Тёмная тема, таблица устройств, два терминала (Attack / Monitor)
- Thread-safe обновление через `asyncio.run_coroutine_threadsafe()`
- Проверка администратора при запуске
- Авто-сканирование каждые 20 секунд
- Досье цели: имя, ОС, количество пакетов

---

## ✅ Что работает

- [x] ARP-сканирование сети (/24)
- [x] Определение вендора по MAC (кэш + API)
- [x] ARP-spoof атака (dual-пакет: жертва + роутер)
- [x] ICMP Redirect (L3-перенаправление)
- [x] Режим «Засада» — ожидание возвращения цели
- [x] OS fingerprinting по TTL
- [x] DNS-перехват с фильтром мусора
- [x] HTTPS SNI-сниффинг
- [x] HTTP raw-перехват
- [x] User-space packet forwarding (scapy)
- [x] Восстановление ARP-таблицы при остановке
- [x] GUI на Flet (тёмная тема, таблица, логи)
- [x] Thread-safe обновление UI
- [x] Консольный UI (без Flet)
- [x] Проверка прав администратора
- [x] Vendor-кэш (JSON, 24ч)

---

## ❌ Что не работает / баги

| Проблема | Статус | Причина |
|----------|--------|---------|
| **OS-level IP Forwarding** | ⚠️ Частично | `Set-NetIPInterface` требует полного админ-доступа CIM. User-space forwarding работает |
| **Мониторинг: цель теряет интернет** | ⚠️ | Если OS-forwarding не включён, пакеты не доходят до роутера. User-space forwarding должен решать, но может не успевать |
| **Scroll в логах** | ⚠️ | `scroll_to()` — корутина, не вызывается (был RuntimeWarning, убран) |
| **Multi-target** | ❌ | Только одна цель за раз |
| **IPv6** | ❌ | Только IPv4 /24 |
| **Сборка .exe** | ❓ | Не тестировалась после рефакторинга |

---

## 📊 Метрики кода

| Метрика | Значение |
|---------|----------|
| Всего строк кода | ~1028 |
| main.py | 708 строк |
| interface.py | ~320 строк |
| Классов | 3 (VendorResolver, NetworkTool, GUI) |
| Публичных методов | 6 (attack, start_monitor, stop, update_devices, find_noisy_guy, toggle_forwarding) |
| Зависимости | scapy, flet, ctypes, urllib, json, socket, subprocess, threading, asyncio |
| Type hints покрытие | ~80% |

---

## 🧪 Зависимости

```
scapy>=2.5.0
flet>=0.25.0
# mac-vendor-lookup (удалён — не используется)
```

Системные требования:
- Windows 11 (или 10)
- Npcap с WinPcap API (для Scapy)
- Python 3.12+
- Права администратора

---

## 🚀 Ближайшие шаги

1. **Починить OS-forwarding** — использовать WinDivert вместо PowerShell
2. **PCAP-лог** — сохранять трафик цели в файл
3. **Multi-target** — атака на несколько устройств
4. **Telegram Bot** — уведомления об атаке
5. **Config-файл** — вынести настройки из кода

---

## 📝 История изменений

### v3.0 (текущая) — рефакторинг
- Исправлены crash-баги (`_log_monitor54`, дублированный TLS-блок)
- Починен OS-detection (TTL)
- Добавлен VendorResolver с кэшем
- Добавлен user-space forwarding
- Добавлен публичный API (attack/start_monitor/stop)
- Thread-safe GUI
- Проверка администратора
- Удалён дублирующийся spec-файл

### v2.5 (оригинал)
- Первая рабочая версия
- ARP-spoof + ICMP Redirect
- GUI на Flet
- Консольный UI