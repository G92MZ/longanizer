"""GeoIP/ASN con bases DB-IP Lite (gratuitas, CC-BY, sin cuenta).

- Descarga bajo demanda (botón) los .mmdb de país y ASN de DB-IP a
  `geoip_data/`; una vez están, funciona 100% offline.
- Marcado de IPs privadas/RFC1918 (y loopback, link-local, etc.) SIN base,
  solo con la stdlib.
- Lectura con la librería `maxminddb` (opcional: si falta, solo RFC1918).

Atribución DB-IP Lite requerida al mostrar datos: "IP Geolocation by DB-IP"
(https://db-ip.com). El país/ASN solo aparece si se ha descargado la base.
"""
from __future__ import annotations

import datetime
import gzip
import ipaddress
import os
import shutil
import tempfile
import time
import urllib.request
from typing import Any, Optional

try:
    import maxminddb
    MMDB_OK = True
except Exception:  # noqa: BLE001
    maxminddb = None
    MMDB_OK = False

_ROOT = os.path.dirname(os.path.dirname(__file__))
GEO_DIR = os.path.join(_ROOT, "geoip_data")
COUNTRY_MMDB = os.path.join(GEO_DIR, "dbip-country-lite.mmdb")
ASN_MMDB = os.path.join(GEO_DIR, "dbip-asn-lite.mmdb")
_BASE = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"

_readers: dict[str, Any] = {}
_mtimes: dict[str, float] = {}


# ---------------------------------------------------------------------------
# RFC1918 / IP privada (sin base de datos)
# ---------------------------------------------------------------------------
_PRIVATE_NETS = [ipaddress.ip_network(x) for x in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
    "127.0.0.0/8", "169.254.0.0/16",                   # loopback / link-local
    "::1/128", "fc00::/7", "fe80::/10",                 # IPv6 loopback/ULA/LL
)]


def is_private(ip: str) -> Optional[bool]:
    """True si la IP es de red interna (RFC1918/loopback/link-local/ULA).
    Las de documentación (TEST-NET) se consideran externas a efectos de análisis."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(a in n for n in _PRIVATE_NETS)


# ---------------------------------------------------------------------------
# Lectura
# ---------------------------------------------------------------------------
def _reader(path: str):
    if not (MMDB_OK and os.path.exists(path)):
        return None
    mt = os.path.getmtime(path)
    if _readers.get(path) is None or _mtimes.get(path) != mt:
        try:
            _readers[path] = maxminddb.open_database(path)
            _mtimes[path] = mt
        except Exception:  # noqa: BLE001
            _readers[path] = None
    return _readers.get(path)


def lookup(ip: str) -> dict[str, Any]:
    """{ip, private, country, country_code, asn, org}. País/ASN solo si hay base."""
    priv = is_private(ip)
    out: dict[str, Any] = {"ip": ip, "private": priv, "country": None,
                           "country_code": None, "asn": None, "org": None}
    if priv or priv is None:
        return out
    rc = _reader(COUNTRY_MMDB)
    if rc is not None:
        try:
            rec = rc.get(ip) or {}
            c = rec.get("country") or {}
            out["country_code"] = c.get("iso_code")
            out["country"] = (c.get("names") or {}).get("en")
        except Exception:  # noqa: BLE001
            pass
    ra = _reader(ASN_MMDB)
    if ra is not None:
        try:
            rec = ra.get(ip) or {}
            out["asn"] = rec.get("autonomous_system_number")
            out["org"] = rec.get("autonomous_system_organization")
        except Exception:  # noqa: BLE001
            pass
    return out


# ---------------------------------------------------------------------------
# Descarga (bajo demanda)
# ---------------------------------------------------------------------------
def _recent_months(n: int = 4) -> list[str]:
    """Últimos n meses como 'YYYY-MM' (la publicación del mes actual tarda)."""
    out = []
    d = datetime.date.today().replace(day=1)
    for _ in range(n):
        out.append(d.strftime("%Y-%m"))
        d = (d - datetime.timedelta(days=1)).replace(day=1)
    return out


def _download_one(kind: str, dest: str) -> str:
    last = None
    for ym in _recent_months():
        url = _BASE.format(kind=kind, ym=ym)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "loganalyzer"})
            data = urllib.request.urlopen(req, timeout=120).read()
            raw = gzip.decompress(data)
            with open(dest, "wb") as fh:
                fh.write(raw)
            return ym
        except Exception as e:  # noqa: BLE001
            last = e
            continue
    raise RuntimeError(f"no se pudo descargar dbip-{kind}-lite: {last}")


def refresh() -> dict:
    if not MMDB_OK:
        raise RuntimeError("falta la librería 'maxminddb' (pip install maxminddb)")
    os.makedirs(GEO_DIR, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="geoip_")
    try:
        cm = _download_one("country", os.path.join(tmp, "country.mmdb"))
        am = _download_one("asn", os.path.join(tmp, "asn.mmdb"))
        shutil.move(os.path.join(tmp, "country.mmdb"), COUNTRY_MMDB)
        shutil.move(os.path.join(tmp, "asn.mmdb"), ASN_MMDB)
        _readers.clear(); _mtimes.clear()
        return {"country": cm, "asn": am, **status()}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def status() -> dict:
    def info(p):
        if not os.path.exists(p):
            return None
        return time.strftime("%Y-%m-%d", time.gmtime(os.path.getmtime(p)))
    return {"maxminddb": MMDB_OK,
            "country": info(COUNTRY_MMDB), "asn": info(ASN_MMDB)}


# ---------------------------------------------------------------------------
# Auto-actualización al arrancar (no bloqueante)
# ---------------------------------------------------------------------------
def _age_days(p: str):
    if not os.path.exists(p):
        return None
    return (time.time() - os.path.getmtime(p)) / 86400.0


def needs_update(max_age_days: int = 30) -> bool:
    """True si falta alguna base o tiene más de max_age_days (DB-IP Lite se
    publica mensualmente, así que 30 días es el umbral natural)."""
    if not MMDB_OK:
        return False
    for p in (COUNTRY_MMDB, ASN_MMDB):
        age = _age_days(p)
        if age is None or age > max_age_days:
            return True
    return False


def auto_refresh_async(max_age_days: int = 30):
    """Lanza refresh() en un hilo demonio SOLO si la base falta o está caducada.
    No bloquea el arranque y es silenciosa ante cualquier error (p. ej. sin red,
    entornos aislados). Devuelve el hilo lanzado o None si no hacía falta."""
    if not needs_update(max_age_days):
        return None

    def _worker():
        try:
            refresh()
        except Exception:  # noqa: BLE001
            pass  # silencioso: sin red / aislado / sin permiso de salida

    import threading
    t = threading.Thread(target=_worker, daemon=True, name="geoip-autorefresh")
    t.start()
    return t
