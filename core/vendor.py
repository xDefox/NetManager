"""
VendorResolver — разрешение вендора по MAC-адресу.

Поддерживает:
- JSON-кэш (24ч TTL)
- Хардкод-список популярных вендоров
- API macvendors.com (резерв)
- Определение Private / Random MAC
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import urllib.request


VENDOR_CACHE_FILE = Path.home() / ".netmanager_vendor_cache.json"
VENDOR_CACHE_TTL = 86400  # 24 hours

COMMON_VENDORS: dict[str, str] = {
    "4c:a9:19": "Xiaomi",
    "54:6c:eb": "Samsung",
    "6a:35:9a": "Apple",
    "00:0c:29": "VMware",
    "b8:27:eb": "Raspberry Pi",
    "00:50:56": "VMware",
    "00:15:5d": "Hyper-V",
    "00:1b:21": "Intel",
    "d4:6d:6d": "Intel",
    "e0:2b:e9": "Asus",
    "e8:9f:6d": "LG",
    "34:f6:4b": "Huawei",
}


class VendorResolver:
    """Локальное разрешение вендора по MAC + кэш + API."""

    def __init__(self) -> None:
        self._cache: dict[str, dict] = self._load_cache()

    # ------------------------------------------------------------------
    def _load_cache(self) -> dict[str, dict]:
        if VENDOR_CACHE_FILE.exists():
            try:
                data = json.loads(VENDOR_CACHE_FILE.read_text(encoding="utf-8"))
                now = time.time()
                return {
                    mac: entry for mac, entry in data.items()
                    if entry.get("ts", 0) + VENDOR_CACHE_TTL > now
                }
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_cache(self) -> None:
        try:
            VENDOR_CACHE_FILE.write_text(
                json.dumps(self._cache, indent=2), encoding="utf-8",
            )
        except OSError:
            pass  # Кэш не критичен

    # ------------------------------------------------------------------
    def resolve(self, mac: str) -> str:
        """Вернуть имя вендора (или 'Unknown Device')."""
        key = mac.lower()

        # 1. Локальный кэш
        if entry := self._cache.get(key):
            return entry["name"]

        # 2. Хардкод
        prefix = key[:8]
        if prefix in COMMON_VENDORS:
            self._cache[key] = {"name": COMMON_VENDORS[prefix], "ts": time.time()}
            return COMMON_VENDORS[prefix]

        # 3. API
        try:
            url = f"https://api.macvendors.com/{mac}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                name = resp.read().decode("utf-8").strip() or "Unknown Device"
        except Exception:
            name = "Unknown Device"

        # Random-MAC detection
        if name == "Unknown Device" and mac[1].lower() in "26ae":
            name = "Private / Random MAC"

        self._cache[key] = {"name": name, "ts": time.time()}
        self._save_cache()
        return name