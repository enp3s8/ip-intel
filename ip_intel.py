#!/usr/bin/env python3
"""
IP Intelligence Lookup Tool
Собирает информацию об IP-адресе (или домене) сразу из 4 источников:
  1. Shodan (API с ключом или бесплатный InternetDB без ключа)
  2. ipinfo.io (с токеном или без)
  3. 2ip (api.2ip.io + RIPE-провайдер с api.2ip.me)
  4. MaxMind (GeoLite2/GeoIP2 Web API и/или локальные .mmdb базы без внешних зависимостей)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False


USER_AGENT = "ip-intel-cli/1.0"
DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Загрузка .env (без сторонних библиотек)
# ---------------------------------------------------------------------------

def load_dotenv(env_path: Path) -> None:
    if not env_path.is_file():
        return
    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Встроенный pure-Python читатель баз MaxMind DB (.mmdb, формат v2.0)
# ---------------------------------------------------------------------------

class MMDBReader:
    """Минималистичный pure-Python парсер формата MaxMind DB v2 (.mmdb)."""

    METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, path: Path) -> None:
        self.path = path
        self._buf = path.read_bytes()
        marker_idx = self._buf.rfind(self.METADATA_MARKER)
        if marker_idx == -1:
            raise ValueError(f"Файл {path} не является валидной базой MaxMind DB")

        meta_start = marker_idx + len(self.METADATA_MARKER)
        self.metadata, _ = self._decode(meta_start, 0)
        if not isinstance(self.metadata, dict):
            raise ValueError(f"Повреждённые метаданные в {path}")

        self.node_count: int = int(self.metadata["node_count"])
        self.record_size: int = int(self.metadata["record_size"])
        self.ip_version: int = int(self.metadata["ip_version"])
        self.node_byte_size: int = (self.record_size * 2) // 8
        self.search_tree_size: int = self.node_count * self.node_byte_size
        self.data_section_start: int = self.search_tree_size + 16
        self._ipv4_start_node: int | None = None

    @property
    def database_type(self) -> str:
        return str(self.metadata.get("database_type", "Unknown"))

    @property
    def build_date(self) -> str:
        epoch = self.metadata.get("build_epoch")
        if isinstance(epoch, int):
            return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")
        return "unknown"

    def _read_node(self, node_num: int, bit: int) -> int:
        offset = node_num * self.node_byte_size
        buf = self._buf
        if self.record_size == 24:
            o = offset + (3 if bit else 0)
            return (buf[o] << 16) | (buf[o + 1] << 8) | buf[o + 2]
        if self.record_size == 28:
            middle = buf[offset + 3]
            if bit == 0:
                return ((middle & 0xF0) << 20) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
            return ((middle & 0x0F) << 24) | (buf[offset + 4] << 16) | (buf[offset + 5] << 8) | buf[offset + 6]
        if self.record_size == 32:
            o = offset + (4 if bit else 0)
            return int.from_bytes(buf[o : o + 4], "big")
        raise ValueError(f"Неподдерживаемый record_size: {self.record_size}")

    def _get_ipv4_start_node(self) -> int:
        if self._ipv4_start_node is not None:
            return self._ipv4_start_node
        node = 0
        if self.ip_version == 6:
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._read_node(node, 0)
        self._ipv4_start_node = node
        return node

    def lookup(self, ip_str: str) -> Any:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 6 and self.ip_version == 4:
            return None

        packed = ip_obj.packed
        node = self._get_ipv4_start_node() if ip_obj.version == 4 else 0
        bit_count = len(packed) * 8

        for i in range(bit_count):
            if node >= self.node_count:
                break
            byte = packed[i >> 3]
            bit = (byte >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)

        if node == self.node_count:
            return None
        if node > self.node_count:
            data_offset = (node - self.node_count) - 16
            val, _ = self._decode(self.data_section_start, data_offset)
            return val
        return None

    def _decode(self, base: int, offset: int) -> tuple[Any, int]:
        buf = self._buf
        ctrl = buf[base + offset]
        offset += 1
        dtype = ctrl >> 5

        if dtype == 1:  # pointer
            psize = (ctrl >> 3) & 0x03
            v = ctrl & 0x07
            if psize == 0:
                ptr = (v << 8) | buf[base + offset]
                offset += 1
            elif psize == 1:
                ptr = ((v << 16) | int.from_bytes(buf[base + offset : base + offset + 2], "big")) + 2048
                offset += 2
            elif psize == 2:
                ptr = ((v << 24) | int.from_bytes(buf[base + offset : base + offset + 3], "big")) + 526336
                offset += 3
            else:
                ptr = int.from_bytes(buf[base + offset : base + offset + 4], "big")
                offset += 4
            val, _ = self._decode(base, ptr)
            return val, offset

        if dtype == 0:  # extended type
            dtype = buf[base + offset] + 7
            offset += 1

        size = ctrl & 0x1F
        if size == 29:
            size = 29 + buf[base + offset]
            offset += 1
        elif size == 30:
            size = 285 + int.from_bytes(buf[base + offset : base + offset + 2], "big")
            offset += 2
        elif size == 31:
            size = 65821 + int.from_bytes(buf[base + offset : base + offset + 3], "big")
            offset += 3

        pos = base + offset
        if dtype == 2:  # utf8_string
            return buf[pos : pos + size].decode("utf-8", errors="replace"), offset + size
        if dtype == 3:  # double
            return struct.unpack(">d", buf[pos : pos + 8])[0], offset + 8
        if dtype == 4:  # bytes
            return buf[pos : pos + size].hex(), offset + size
        if dtype in (5, 6, 9, 10):  # uint16, uint32, uint64, uint128
            return int.from_bytes(buf[pos : pos + size], "big", signed=False), offset + size
        if dtype == 8:  # int32
            raw = buf[pos : pos + size]
            return int.from_bytes(raw, "big", signed=(len(raw) == 4)), offset + size
        if dtype == 7:  # map
            result: dict[str, Any] = {}
            for _ in range(size):
                k, offset = self._decode(base, offset)
                v, offset = self._decode(base, offset)
                result[str(k)] = v
            return result, offset
        if dtype == 11:  # array
            items: list[Any] = []
            for _ in range(size):
                v, offset = self._decode(base, offset)
                items.append(v)
            return items, offset
        if dtype == 14:  # boolean
            return bool(size), offset
        if dtype == 15:  # float
            return struct.unpack(">f", buf[pos : pos + 4])[0], offset + 4
        if dtype in (12, 13):  # cache container / end marker
            return None, offset
        raise ValueError(f"Неизвестный тип данных MMDB: {dtype}")


# ---------------------------------------------------------------------------
# Клиенты к 4 источникам
# ---------------------------------------------------------------------------

def _http_get_json(
    url: str,
    *,
    timeout: int,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    auth: tuple[str, str] | None = None,
) -> tuple[int, dict[str, Any] | None, str | None]:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.get(url, headers=hdrs, params=params, auth=auth, timeout=timeout)
        try:
            data = resp.json()
        except ValueError:
            data = None
        if resp.status_code == 200 and isinstance(data, dict):
            return resp.status_code, data, None
        err_msg = None
        if isinstance(data, dict):
            err_msg = data.get("error") or data.get("message") or data.get("detail")
            if isinstance(err_msg, dict):
                err_msg = err_msg.get("message") or str(err_msg)
        return resp.status_code, data, str(err_msg or f"HTTP {resp.status_code}")
    except requests.RequestException as exc:
        return 0, None, str(exc)


def fetch_shodan(ip: str, timeout: int) -> dict[str, Any]:
    api_key = os.environ.get("SHODAN_API_KEY", "").strip()
    result: dict[str, Any] = {"source": "Shodan", "ok": False}

    if api_key:
        status, data, err = _http_get_json(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=timeout,
        )
        if status == 200 and data:
            services = []
            for svc in data.get("data", [])[:15]:
                services.append(
                    {
                        "port": svc.get("port"),
                        "transport": svc.get("transport"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "module": (svc.get("_shodan") or {}).get("module"),
                    }
                )
            result.update(
                {
                    "ok": True,
                    "mode": "Shodan Host API",
                    "ip": data.get("ip_str", ip),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                    "os": data.get("os"),
                    "country": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "city": data.get("city"),
                    "hostnames": data.get("hostnames") or [],
                    "domains": data.get("domains") or [],
                    "ports": sorted(data.get("ports") or []),
                    "vulns": sorted(data.get("vulns") or []),
                    "tags": data.get("tags") or [],
                    "last_update": data.get("last_update"),
                    "services": services,
                }
            )
            return result
        if status == 404:
            result["note"] = "Хост не найден в Shodan API, проверяю InternetDB..."
        else:
            result["note"] = f"Shodan Host API недоступен ({err}), переключено на InternetDB"

    # Бесплатный Shodan InternetDB (без ключа)
    status, data, err = _http_get_json(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
    if status == 200 and data:
        result.update(
            {
                "ok": True,
                "mode": "Shodan InternetDB (free)",
                "ip": data.get("ip", ip),
                "ports": sorted(data.get("ports") or []),
                "hostnames": data.get("hostnames") or [],
                "cpes": data.get("cpes") or [],
                "tags": data.get("tags") or [],
                "vulns": sorted(data.get("vulns") or []),
            }
        )
    elif status == 404:
        result.update(
            {
                "ok": True,
                "mode": "Shodan InternetDB (free)",
                "ip": ip,
                "ports": [],
                "hostnames": [],
                "cpes": [],
                "tags": [],
                "vulns": [],
                "info": "Нет открытых портов / записей в Shodan InternetDB",
            }
        )
    else:
        result["error"] = err or f"HTTP {status}"
    return result


def fetch_ipinfo(ip: str, timeout: int) -> dict[str, Any]:
    token = os.environ.get("IPINFO_TOKEN", "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else None
    result: dict[str, Any] = {
        "source": "ipinfo.io",
        "mode": "API (with token)" if token else "Free API",
        "ok": False,
    }

    status, data, err = _http_get_json(
        f"https://ipinfo.io/{ip}/json",
        headers=headers,
        timeout=timeout,
    )
    if status == 200 and data:
        cleaned = {k: v for k, v in data.items() if k != "readme"}
        result["ok"] = True
        result.update(cleaned)
    else:
        result["error"] = err or f"HTTP {status}"
    return result


def fetch_2ip(ip: str, timeout: int) -> dict[str, Any]:
    token = os.environ.get("TWOIP_TOKEN", "").strip()
    result: dict[str, Any] = {
        "source": "2ip",
        "mode": "api.2ip.io (token)" if token else "api.2ip.io + api.2ip.me",
        "ok": False,
    }

    params = {"token": token} if token else None
    status, data, err = _http_get_json(f"https://api.2ip.io/{ip}", params=params, timeout=timeout)
    if status == 200 and data:
        asn_info = data.get("asn") if isinstance(data.get("asn"), dict) else {}
        result.update(
            {
                "ok": True,
                "ip": data.get("ip", ip),
                "country": data.get("country"),
                "country_code": data.get("code"),
                "emoji": data.get("emoji"),
                "region": data.get("region"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "asn_id": asn_info.get("id"),
                "asn_name": asn_info.get("name"),
                "hosting": asn_info.get("hosting"),
            }
        )
    else:
        # Fallback на api.2ip.me/geo.json
        st2, geo2, err2 = _http_get_json(
            "https://api.2ip.me/geo.json",
            params={"ip": ip},
            timeout=timeout,
        )
        if st2 == 200 and geo2:
            result.update(
                {
                    "ok": True,
                    "mode": "api.2ip.me (fallback)",
                    "ip": geo2.get("ip", ip),
                    "country": geo2.get("country"),
                    "country_rus": geo2.get("country_rus"),
                    "country_code": geo2.get("country_code"),
                    "region": geo2.get("region"),
                    "region_rus": geo2.get("region_rus"),
                    "city": geo2.get("city"),
                    "city_rus": geo2.get("city_rus"),
                    "lat": geo2.get("latitude"),
                    "lon": geo2.get("longitude"),
                    "timezone": geo2.get("time_zone"),
                }
            )
        else:
            result["error"] = f"2ip.io: {err}; 2ip.me: {err2}"

    # Дополнительно подтягиваем RIPE-провайдера и подсеть с api.2ip.me/provider.json
    st_p, prov, _ = _http_get_json(
        "https://api.2ip.me/provider.json",
        params={"ip": ip},
        timeout=timeout,
    )
    if st_p == 200 and prov:
        result["ok"] = True
        provider_name = prov.get("name_ripe") or prov.get("name_rus") or prov.get("name_ua")
        if provider_name:
            result["provider"] = provider_name
        if prov.get("site"):
            result["provider_site"] = prov.get("site")
        if prov.get("as") and not result.get("asn_id"):
            result["asn_id"] = prov.get("as")
        if prov.get("mask"):
            result["prefix_mask"] = f"/{prov.get('mask')}"
        if prov.get("ip_range_start") and prov.get("ip_range_end"):
            try:
                start_ip = str(ipaddress.IPv4Address(int(prov["ip_range_start"])))
                end_ip = str(ipaddress.IPv4Address(int(prov["ip_range_end"])))
                result["ip_range"] = f"{start_ip} - {end_ip}"
            except (ValueError, TypeError):
                pass

    return result


def discover_mmdb_files(extra_paths: list[str] | None = None) -> list[Path]:
    candidates: list[Path] = []
    if extra_paths:
        for p in extra_paths:
            path = Path(p).expanduser()
            if path.is_file():
                candidates.append(path)
            elif path.is_dir():
                candidates.extend(sorted(path.glob("*.mmdb")))

    env_paths = os.environ.get("MAXMIND_MMDB_PATHS", "").strip()
    if env_paths:
        for raw in env_paths.split(":"):
            p = Path(raw.strip()).expanduser()
            if p.is_file():
                candidates.append(p)
            elif p.is_dir():
                candidates.extend(sorted(p.glob("*.mmdb")))

    script_dir = Path(__file__).resolve().parent
    search_dirs = [
        script_dir,
        script_dir / "mmdb",
        Path.home() / ".local/share/GeoIP",
        Path("/usr/share/GeoIP"),
        Path("/var/lib/GeoIP"),
        Path.home() / ".local/share/io.github.clash-verge-rev.clash-verge-rev",
        Path("/usr/lib/Clash Verge/resources"),
    ]
    for d in search_dirs:
        if d.is_dir():
            candidates.extend(sorted(d.glob("*.mmdb")))

    seen_resolved: set[Path] = set()
    unique: list[Path] = []
    for c in candidates:
        try:
            r = c.resolve()
        except OSError:
            continue
        if r not in seen_resolved and r.is_file():
            seen_resolved.add(r)
            unique.append(r)
    return unique


def _pick_name(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    names = obj.get("names")
    if isinstance(names, dict):
        ru = names.get("ru")
        en = names.get("en")
        if ru and en and ru != en:
            return f"{en} ({ru})"
        return ru or en
    return None


def fetch_maxmind(ip: str, timeout: int, extra_mmdb: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"source": "MaxMind", "ok": False}

    account_id = os.environ.get("MAXMIND_ACCOUNT_ID", "").strip()
    license_key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    endpoint = os.environ.get("MAXMIND_ENDPOINT", "geolite").strip().lower()

    # 1) Web Services API (если указаны креды)
    if account_id and license_key:
        if endpoint == "paid":
            base_url = "https://geoip.maxmind.com/geoip/v2.1/city"
            mode_label = "GeoIP2 Web API"
        elif endpoint.startswith("http://") or endpoint.startswith("https://"):
            base_url = endpoint.rstrip("/")
            mode_label = "Custom MaxMind API"
        else:
            base_url = "https://geolite.info/geoip/v2.1/city"
            mode_label = "GeoLite2 Web API"

        status, data, err = _http_get_json(
            f"{base_url}/{ip}",
            auth=(account_id, license_key),
            timeout=timeout,
        )
        if status == 200 and data:
            loc = data.get("location") or {}
            traits = data.get("traits") or {}
            subdivs = data.get("subdivisions") or []
            result.update(
                {
                    "ok": True,
                    "mode": mode_label,
                    "country": _pick_name(data.get("country")),
                    "country_code": (data.get("country") or {}).get("iso_code"),
                    "continent": _pick_name(data.get("continent")),
                    "region": _pick_name(subdivs[0]) if subdivs else None,
                    "city": _pick_name(data.get("city")),
                    "postal": (data.get("postal") or {}).get("code"),
                    "lat": loc.get("latitude"),
                    "lon": loc.get("longitude"),
                    "accuracy_radius_km": loc.get("accuracy_radius"),
                    "timezone": loc.get("time_zone"),
                    "asn": traits.get("autonomous_system_number"),
                    "asn_org": traits.get("autonomous_system_organization"),
                    "isp": traits.get("isp"),
                    "org": traits.get("organization"),
                    "network": traits.get("network"),
                }
            )
            return result
        result["api_error"] = err or f"HTTP {status}"

    # 2) Локальные .mmdb файлы (GeoLite2-City / Country / ASN)
    mmdb_files = discover_mmdb_files(extra_mmdb)
    if not mmdb_files:
        if "api_error" in result:
            result["error"] = f"Web API: {result['api_error']}; локальные .mmdb не найдены"
        else:
            result["error"] = (
                "Не настроено: укажите MAXMIND_ACCOUNT_ID + MAXMIND_LICENSE_KEY в .env "
                "или положите GeoLite2-City.mmdb / GeoLite2-ASN.mmdb рядом со скриптом"
            )
        return result

    used_dbs: list[str] = []
    seen_types: set[str] = set()
    # Сначала читаем City, потом Country, потом ASN, чтобы City имел приоритет
    readers: list[MMDBReader] = []
    for path in mmdb_files:
        try:
            readers.append(MMDBReader(path))
        except Exception:
            continue

    def _priority(r: MMDBReader) -> int:
        t = r.database_type.lower()
        if "city" in t:
            return 0
        if "country" in t:
            return 1
        if "asn" in t:
            return 2
        return 3

    readers.sort(key=_priority)

    for reader in readers:
        db_type = reader.database_type
        if db_type in seen_types:
            continue
        # Если уже нашли City, Country не перезаписываем
        if "country" in db_type.lower() and any("city" in t.lower() for t in seen_types):
            continue

        try:
            rec = reader.lookup(ip)
        except Exception:
            continue

        seen_types.add(db_type)
        used_dbs.append(f"{reader.path.name} ({db_type}, {reader.build_date})")

        if not isinstance(rec, dict):
            continue

        result["ok"] = True

        # Поля ASN базы
        if "autonomous_system_number" in rec:
            result["asn"] = rec.get("autonomous_system_number")
        if "autonomous_system_organization" in rec:
            result["asn_org"] = rec.get("autonomous_system_organization")

        # Поля Country / City базы
        country_obj = rec.get("country") or rec.get("registered_country")
        if country_obj and not result.get("country"):
            result["country"] = _pick_name(country_obj)
            result["country_code"] = country_obj.get("iso_code")
        if rec.get("continent") and not result.get("continent"):
            result["continent"] = _pick_name(rec.get("continent"))
        subdivs = rec.get("subdivisions")
        if isinstance(subdivs, list) and subdivs and not result.get("region"):
            result["region"] = _pick_name(subdivs[0])
        if rec.get("city") and not result.get("city"):
            result["city"] = _pick_name(rec.get("city"))
        if isinstance(rec.get("postal"), dict) and not result.get("postal"):
            result["postal"] = rec["postal"].get("code")
        if isinstance(rec.get("location"), dict):
            loc = rec["location"]
            if loc.get("latitude") is not None and result.get("lat") is None:
                result["lat"] = loc.get("latitude")
                result["lon"] = loc.get("longitude")
            if loc.get("time_zone") and not result.get("timezone"):
                result["timezone"] = loc.get("time_zone")
            if loc.get("accuracy_radius") and not result.get("accuracy_radius_km"):
                result["accuracy_radius_km"] = loc.get("accuracy_radius")

    if used_dbs:
        result["mode"] = "Local MMDB"
        result["databases"] = used_dbs
        if not result["ok"]:
            result["ok"] = True
            result["info"] = "Запись для данного IP не найдена в локальных MMDB"
    else:
        result["error"] = "Не удалось прочитать найденные .mmdb файлы"

    return result


# ---------------------------------------------------------------------------
# Оркестратор и резолв входа
# ---------------------------------------------------------------------------

def resolve_target(target: str) -> tuple[str, str | None]:
    target = target.strip()
    try:
        ip_obj = ipaddress.ip_address(target)
        return str(ip_obj), None
    except ValueError:
        pass

    # Возможно, введён домен или URL
    host = target
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split(":", 1)[0]

    infos = socket.getaddrinfo(host, None)
    # Предпочитаем IPv4, если есть
    ipv4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    if ipv4:
        return ipv4[0], host
    return infos[0][4][0], host


def lookup_ip(ip: str, timeout: int, extra_mmdb: list[str] | None = None) -> dict[str, Any]:
    ip_obj = ipaddress.ip_address(ip)
    meta = {
        "ip": ip,
        "version": f"IPv{ip_obj.version}",
        "is_private": ip_obj.is_private,
        "is_global": ip_obj.is_global,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        fut_shodan = pool.submit(fetch_shodan, ip, timeout)
        fut_ipinfo = pool.submit(fetch_ipinfo, ip, timeout)
        fut_2ip = pool.submit(fetch_2ip, ip, timeout)
        fut_maxmind = pool.submit(fetch_maxmind, ip, timeout, extra_mmdb)

        results = {
            "shodan": fut_shodan.result(),
            "ipinfo": fut_ipinfo.result(),
            "2ip": fut_2ip.result(),
            "maxmind": fut_maxmind.result(),
        }

    return {"target": meta, "sources": results}


# ---------------------------------------------------------------------------
# Вывод результатов (Rich или обычный текст)
# ---------------------------------------------------------------------------

def _fmt_list(items: list[Any], limit: int = 20) -> str:
    if not items:
        return "—"
    shown = [str(x) for x in items[:limit]]
    tail = f" (+{len(items) - limit})" if len(items) > limit else ""
    return ", ".join(shown) + tail


def _fmt_coords(lat: Any, lon: Any) -> str | None:
    if lat is not None and lon is not None:
        return f"{lat}, {lon}"
    return None


def _build_rows_shodan(d: dict[str, Any]) -> list[tuple[str, str]]:
    if not d.get("ok"):
        return [("Ошибка", str(d.get("error", "неизвестно")))]
    rows: list[tuple[str, str]] = [("Режим", str(d.get("mode", "Shodan")))]
    if d.get("note"):
        rows.append(("Примечание", str(d["note"])))
    if d.get("info"):
        rows.append(("Статус", str(d["info"])))
    for label, key in [
        ("Организация", "org"),
        ("Провайдер (ISP)", "isp"),
        ("ASN", "asn"),
        ("ОС", "os"),
        ("Страна", "country"),
        ("Город", "city"),
        ("Обновлено", "last_update"),
    ]:
        if d.get(key):
            rows.append((label, str(d[key])))
    rows.append(("Открытые порты", _fmt_list(d.get("ports") or [], 30)))
    if d.get("hostnames"):
        rows.append(("Hostnames", _fmt_list(d["hostnames"], 10)))
    if d.get("domains"):
        rows.append(("Домены", _fmt_list(d["domains"], 10)))
    if d.get("cpes"):
        rows.append(("CPE", _fmt_list(d["cpes"], 10)))
    if d.get("tags"):
        rows.append(("Теги", _fmt_list(d["tags"], 15)))
    vulns = d.get("vulns") or []
    rows.append(("Уязвимости (CVE)", _fmt_list(vulns, 15) if vulns else "Не обнаружены"))
    if d.get("services"):
        svc_lines = []
        for s in d["services"][:10]:
            parts = [f"{s.get('port')}/{s.get('transport') or 'tcp'}"]
            prod = " ".join(x for x in [s.get("product"), s.get("version")] if x)
            if prod:
                parts.append(prod)
            elif s.get("module"):
                parts.append(str(s["module"]))
            svc_lines.append(" — ".join(parts))
        rows.append(("Сервисы", "\n".join(svc_lines)))
    return rows


def _build_rows_ipinfo(d: dict[str, Any]) -> list[tuple[str, str]]:
    if not d.get("ok"):
        return [("Ошибка", str(d.get("error", "неизвестно")))]
    rows: list[tuple[str, str]] = [("Режим", str(d.get("mode", "ipinfo.io")))]
    for label, key in [
        ("Hostname (PTR)", "hostname"),
        ("Страна", "country"),
        ("Регион", "region"),
        ("Город", "city"),
        ("Индекс", "postal"),
        ("Координаты", "loc"),
        ("Часовой пояс", "timezone"),
        ("Организация / ASN", "org"),
    ]:
        if d.get(key):
            rows.append((label, str(d[key])))
    if d.get("anycast"):
        rows.append(("Anycast", "Да"))
    if isinstance(d.get("privacy"), dict):
        flags = [k.upper() for k, v in d["privacy"].items() if v is True]
        rows.append(("Privacy / VPN", ", ".join(flags) if flags else "Нет флагов"))
    if isinstance(d.get("company"), dict):
        comp = d["company"]
        rows.append(("Компания", f"{comp.get('name', '')} ({comp.get('type', '')})".strip()))
    if isinstance(d.get("abuse"), dict) and d["abuse"].get("email"):
        rows.append(("Abuse Email", str(d["abuse"]["email"])))
    return rows


def _build_rows_2ip(d: dict[str, Any]) -> list[tuple[str, str]]:
    if not d.get("ok"):
        return [("Ошибка", str(d.get("error", "неизвестно")))]
    rows: list[tuple[str, str]] = [("Режим", str(d.get("mode", "2ip")))]
    country = d.get("country")
    if country and d.get("country_code"):
        country = f"{country} ({d['country_code']})"
    if d.get("emoji") and country:
        country = f"{d['emoji']} {country}"
    if country:
        rows.append(("Страна", country))
    for label, key in [
        ("Регион", "region"),
        ("Город", "city"),
        ("Часовой пояс", "timezone"),
    ]:
        if d.get(key):
            rows.append((label, str(d[key])))
    coords = _fmt_coords(d.get("lat"), d.get("lon"))
    if coords:
        rows.append(("Координаты", coords))
    if d.get("asn_id"):
        asn_str = f"AS{d['asn_id']}"
        if d.get("asn_name"):
            asn_str += f" ({d['asn_name']})"
        rows.append(("ASN", asn_str))
    if d.get("hosting") is not None:
        rows.append(("Хостинг / ЦОД", "Да" if d["hosting"] else "Нет"))
    if d.get("provider"):
        rows.append(("Провайдер (RIPE)", str(d["provider"])))
    if d.get("provider_site"):
        rows.append(("Сайт провайдера", str(d["provider_site"])))
    if d.get("ip_range"):
        rng = str(d["ip_range"])
        if d.get("prefix_mask"):
            rng += f" ({d['prefix_mask']})"
        rows.append(("Подсеть / Диапазон", rng))
    return rows


def _build_rows_maxmind(d: dict[str, Any]) -> list[tuple[str, str]]:
    if not d.get("ok"):
        return [("Ошибка", str(d.get("error", "неизвестно")))]
    rows: list[tuple[str, str]] = [("Режим", str(d.get("mode", "MaxMind")))]
    if d.get("databases"):
        rows.append(("Базы MMDB", "\n".join(d["databases"])))
    if d.get("info"):
        rows.append(("Статус", str(d["info"])))
    country = d.get("country")
    cc = d.get("country_code")
    if country and cc:
        country = f"{country} [{cc}]"
    elif cc:
        country = str(cc)
    if country:
        rows.append(("Страна / Тег", country))
    for label, key in [
        ("Континент", "continent"),
        ("Регион", "region"),
        ("Город", "city"),
        ("Индекс", "postal"),
        ("Часовой пояс", "timezone"),
    ]:
        if d.get(key):
            rows.append((label, str(d[key])))
    coords = _fmt_coords(d.get("lat"), d.get("lon"))
    if coords:
        if d.get("accuracy_radius_km"):
            coords += f" (±{d['accuracy_radius_km']} км)"
        rows.append(("Координаты", coords))
    if d.get("asn"):
        asn_str = f"AS{d['asn']}"
        if d.get("asn_org"):
            asn_str += f" — {d['asn_org']}"
        rows.append(("ASN", asn_str))
    elif d.get("asn_org"):
        rows.append(("ASN Орг.", str(d["asn_org"])))
    for label, key in [("ISP", "isp"), ("Организация", "org"), ("Сеть", "network")]:
        if d.get(key):
            rows.append((label, str(d[key])))
    return rows


def render_report(report: dict[str, Any], domain: str | None = None) -> None:
    meta = report["target"]
    src = report["sources"]
    ip = meta["ip"]

    # Сводка по 4 источникам
    sh = src["shodan"]
    ii = src["ipinfo"]
    t2 = src["2ip"]
    mm = src["maxmind"]

    geo_parts = [
        ii.get("country") or t2.get("country_code") or mm.get("country_code"),
        ii.get("city") or t2.get("city") or mm.get("city"),
    ]
    geo_summary = ", ".join(p for p in geo_parts if p) or "—"
    org_summary = ii.get("org") or sh.get("org") or (f"AS{mm['asn']} {mm.get('asn_org', '')}".strip() if mm.get("asn") else None) or t2.get("provider") or "—"
    ports_cnt = len(sh.get("ports") or []) if sh.get("ok") else "?"
    vulns_cnt = len(sh.get("vulns") or []) if sh.get("ok") else "?"

    header_title = f"IP: {ip}" + (f" (домен: {domain})" if domain else "")

    sections = [
        ("Shodan", "cyan", _build_rows_shodan(sh), sh.get("ok")),
        ("ipinfo.io", "green", _build_rows_ipinfo(ii), ii.get("ok")),
        ("2ip", "yellow", _build_rows_2ip(t2), t2.get("ok")),
        ("MaxMind", "magenta", _build_rows_maxmind(mm), mm.get("ok")),
    ]

    if HAS_RICH:
        console = Console()
        summary_text = Text()
        summary_text.append(f"{header_title}  ", style="bold white")
        summary_text.append(f"[{meta['version']}]", style="dim")
        if meta["is_private"]:
            summary_text.append("  [PRIVATE/RESERVED IP]", style="bold red")
        summary_text.append(f"\nГеолокация: ", style="bold")
        summary_text.append(f"{geo_summary}   ")
        summary_text.append("ASN / Орг: ", style="bold")
        summary_text.append(f"{org_summary}\n")
        summary_text.append("Порты (Shodan): ", style="bold")
        summary_text.append(f"{ports_cnt}   ", style="cyan")
        summary_text.append("CVE (Shodan): ", style="bold")
        summary_text.append(f"{vulns_cnt}", style="red" if isinstance(vulns_cnt, int) and vulns_cnt > 0 else "green")
        summary_text.append(f"   Проверено: {meta['checked_at']}", style="dim")

        console.print()
        console.print(Panel(summary_text, title="Сводка IP Intelligence", border_style="bright_blue", box=box.ROUNDED))

        for title, color, rows, ok in sections:
            tbl = Table(
                title=f"{'✔' if ok else '✖'} {title}",
                title_style=f"bold {color if ok else 'red'}",
                box=box.ROUNDED,
                show_header=False,
                expand=True,
                border_style=color if ok else "red",
            )
            tbl.add_column("Поле", style="bold", width=22, no_wrap=True)
            tbl.add_column("Значение", overflow="fold")
            for k, v in rows:
                tbl.add_row(k, v)
            console.print(tbl)
    else:
        print(f"\n{'=' * 70}\n{header_title} [{meta['version']}]\nГео: {geo_summary} | Орг: {org_summary} | Порты: {ports_cnt} | CVE: {vulns_cnt}\n{'=' * 70}")
        for title, _, rows, ok in sections:
            print(f"\n--- [{'OK' if ok else 'ERR'}] {title} ---")
            for k, v in rows:
                print(f"  {k:20}: {v}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Проверка IP-адреса через Shodan + ipinfo.io + 2ip + MaxMind",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="IP-адрес(а) или домен(ы). Если не указано — запросит интерактивно.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Вывести результат в формате JSON",
    )
    parser.add_argument(
        "--save",
        metavar="FILE",
        help="Сохранить полный JSON-отчёт в файл",
    )
    parser.add_argument(
        "--mmdb",
        action="append",
        default=[],
        help="Путь к локальному файлу/папке .mmdb для MaxMind (можно указать несколько раз)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Таймаут HTTP-запросов в секундах (по умолчанию {DEFAULT_TIMEOUT})",
    )
    return parser.parse_args()


def main() -> int:
    load_dotenv(Path(__file__).resolve().parent / ".env")
    args = parse_args()

    targets = list(args.targets)
    if not targets:
        try:
            if sys.stdin.isatty():
                sys.stderr.write("Введите IP-адрес (или домен): ")
                sys.stderr.flush()
            raw = sys.stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return 130
        if not raw:
            print("IP-адрес не указан.", file=sys.stderr)
            return 1
        targets = raw.split()

    all_reports: list[dict[str, Any]] = []

    for raw_target in targets:
        try:
            ip, domain = resolve_target(raw_target)
        except Exception as exc:
            print(f"[Ошибка] Не удалось распознать '{raw_target}': {exc}", file=sys.stderr)
            continue

        report = lookup_ip(ip, timeout=args.timeout, extra_mmdb=args.mmdb)
        if domain:
            report["target"]["domain"] = domain
        all_reports.append(report)

        if not args.json:
            render_report(report, domain=domain)

    if args.json:
        output = all_reports[0] if len(all_reports) == 1 else all_reports
        print(json.dumps(output, ensure_ascii=False, indent=2))

    if args.save:
        save_path = Path(args.save).expanduser()
        output = all_reports[0] if len(all_reports) == 1 else all_reports
        save_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
        if not args.json:
            print(f"\nОтчёт сохранён в: {save_path}")

    return 0 if all_reports else 1


if __name__ == "__main__":
    raise SystemExit(main())
