"""Extracción de IOCs presentes en los datos cargados (lo contrario del IOC
sweep: aquí DESCUBRIMOS los indicadores que ya están en los logs/EVTX).

Diseño conservador: regex estrictas + validación, para minimizar falsos
positivos (p.ej. no confundir un blob hex `saddr=` de auditd con un MD5, ni
`payload.sh` con un dominio .sh). Todo offline.

Tipos (comunes): ipv4, ipv6, domain, url, email, md5, sha1, sha256, imphash,
filepath. Windows (flag windows=True): registry, pipe.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterator, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Patrones
# ---------------------------------------------------------------------------
_RE_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
# candidato IPv6: grupos hex separados por ':' (admite '::'); se valida después.
_RE_IPV6 = re.compile(r"(?<![\w:.])([A-Fa-f0-9]{0,4}(?::[A-Fa-f0-9]{0,4}){2,7})(?![\w:.])")
_RE_URL = re.compile(r"\b(?:https?|ftps?)://[^\s\"'`<>\]\[{}|\\^]+", re.IGNORECASE)
_RE_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![\w.-])")
_RE_DOMAIN = re.compile(r"(?<![\w@.\-/])((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![\w\-])")
_RE_MD5 = re.compile(r"(?<![\w])([A-Fa-f0-9]{32})(?![\w])")
_RE_SHA1 = re.compile(r"(?<![\w])([A-Fa-f0-9]{40})(?![\w])")
_RE_SHA256 = re.compile(r"(?<![\w])([A-Fa-f0-9]{64})(?![\w])")
_RE_IMPHASH = re.compile(r"IMPHASH=([A-Fa-f0-9]{32})", re.IGNORECASE)
_RE_WINPATH = re.compile(r"(?<![\w])([A-Za-z]:\\(?:[^\\/:*?\"<>|\s]+\\?)+)")
_RE_UNIXPATH = re.compile(r"(?<![\w])(/(?:[\w.@\-]+/)+[\w.@\-]+)")
_RE_REGISTRY = re.compile(r"(?<![\w])((?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_[A-Z_]+)\\[^\s\"'`<>|?*\r\n]+)", re.IGNORECASE)
_RE_PIPE = re.compile(r"(\\\\[.\w\-]+\\pipe\\[^\s\"'`<>|?*\r\n]+|\\pipe\\[\w.\-{}]+)", re.IGNORECASE)
# campos hex de auditd que NO son hashes (saddr empaquetado, proctitle/args hex)
_RE_AUDIT_HEX = re.compile(r"(?i)\b(?:saddr|proctitle|a\d+|cwd|exe)=[0-9a-f]{8,}\b")

# gTLDs frecuentes (los ccTLD de 2 letras se aceptan por longitud). No incluye
# extensiones de fichero, así evitamos .exe/.dll/.log como dominios.
_GTLDS = {
    "com", "net", "org", "info", "biz", "gov", "edu", "mil", "int", "name",
    "pro", "mobi", "asia", "tel", "io", "co", "ai", "app", "dev", "xyz",
    "online", "site", "top", "club", "shop", "store", "tech", "cloud", "live",
    "icu", "vip", "work", "link", "click", "download", "host", "space",
    "website", "email", "fun", "life", "world", "today", "news", "blog",
    "page", "run", "zip", "mov", "cc", "tv", "me", "su", "pw", "cyou", "sbs",
    "lol", "monster", "quest", "rest", "cfd", "bond", "digital", "agency",
    "solutions", "services", "network", "systems", "group", "team", "center",
}
# Extensiones de fichero que colisionan con ccTLDs/gTLDs -> nunca son dominio.
_FILE_EXT = {
    "sh", "py", "pl", "rb", "ps1", "bat", "cmd", "vbs", "js", "jse", "wsf",
    "exe", "dll", "sys", "so", "bin", "dat", "db", "log", "conf", "cfg",
    "ini", "txt", "md", "yml", "yaml", "json", "xml", "csv", "tsv", "html",
    "htm", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "pdf", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "zip", "tar", "gz", "tgz", "bz2",
    "xz", "rar", "7z", "iso", "img", "tmp", "bak", "old", "swp", "lock",
    "pid", "sock", "key", "pem", "crt", "cer", "php", "asp", "aspx", "jsp",
    "jar", "war", "class", "o", "a", "ko", "map", "lnk", "url", "reg",
}

_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
              "2001:db8::/32")]


def _valid_ipv4(s: str) -> Optional[str]:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_reserved or s == "255.255.255.255":
        return None
    return str(ip)


def _valid_ipv6(s: str) -> Optional[str]:
    try:
        ip = ipaddress.IPv6Address(s)
    except ValueError:
        return None
    if ":" not in s or ip.is_unspecified:
        return None
    return ip.compressed


# dominios "boilerplate" de namespaces XML/EVTX (no son IOCs)
_DOMAIN_DENY = {
    "schemas.microsoft.com", "schemas.xmlsoap.org", "www.w3.org",
    "schemas.openxmlformats.org",
}


def ip_class(ip: str) -> str:
    """internal / external / documentation / loopback …"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if a.is_loopback:
        return "loopback"
    if any(a in n for n in _DOC_NETS):
        return "documentation"
    if a.is_private or a.is_link_local:
        return "internal"
    if a.is_multicast:
        return "multicast"
    return "external"


def _valid_domain(d: str) -> Optional[str]:
    d = d.rstrip(".").lower()
    if len(d) > 253 or "." not in d or d in _DOMAIN_DENY:
        return None
    tld = d.rsplit(".", 1)[1]
    if tld in _FILE_EXT:
        return None
    if not (len(tld) == 2 or tld in _GTLDS):
        return None
    # no es una IP disfrazada
    try:
        ipaddress.ip_address(d)
        return None
    except ValueError:
        pass
    return d


def _clean_url(u: str) -> str:
    return u.rstrip(".,);]}\"'>")


# ---------------------------------------------------------------------------
# Extracción
# ---------------------------------------------------------------------------
def iter_iocs(general: str, hashes_text: str,
              windows: bool = False) -> Iterator[tuple[str, str]]:
    """Genera (tipo, valor) a partir del texto. `general` se escanea para
    ip/url/domain/email/path/registry/pipe; `hashes_text` (curado, sin blobs
    hex de auditd) para md5/sha1/sha256/imphash."""
    g = general or ""
    # URLs: se emiten, se saca su host como dominio/IP, y se blanquean del texto
    # para que su ruta no se confunda con un filepath ni su host se re-escanee.
    rest = []
    last = 0
    for m in _RE_URL.finditer(g):
        u = _clean_url(m.group(0))
        if len(u) > 8:
            yield "url", u
            try:
                host = urlsplit(u).hostname or ""
            except ValueError:
                host = ""
            if host:
                if _valid_ipv4(host):
                    yield "ipv4", host
                elif _valid_domain(host):
                    yield "domain", host
        rest.append(g[last:m.start()])
        rest.append(" " * (m.end() - m.start()))
        last = m.end()
    rest.append(g[last:])
    g2 = "".join(rest)

    for m in _RE_IPV4.finditer(g2):
        v = _valid_ipv4(m.group(1))
        if v:
            yield "ipv4", v
    for m in _RE_IPV6.finditer(g2):
        v = _valid_ipv6(m.group(1))
        if v:
            yield "ipv6", v
    for m in _RE_EMAIL.finditer(g2):
        e = m.group(1).lower()
        if _valid_domain(e.split("@", 1)[1]):
            yield "email", e
    for m in _RE_DOMAIN.finditer(g2):
        d = _valid_domain(m.group(1))
        if d:
            yield "domain", d
    for m in _RE_WINPATH.finditer(g2):
        yield "filepath", m.group(1).rstrip("\\")
    for m in _RE_UNIXPATH.finditer(g2):
        yield "filepath", m.group(1)
    if windows:
        for m in _RE_REGISTRY.finditer(g2):
            yield "registry", m.group(1)
        for m in _RE_PIPE.finditer(g2):
            yield "pipe", m.group(1)

    # hashes (texto curado; se quitan los blobs hex de auditd que no son hashes;
    # imphash no se re-reporta como md5)
    h = _RE_AUDIT_HEX.sub(" ", hashes_text or "")
    imph = set()
    for m in _RE_IMPHASH.finditer(h):
        v = m.group(1).lower()
        imph.add(v)
        yield "imphash", v
    for m in _RE_SHA256.finditer(h):
        yield "sha256", m.group(1).lower()
    for m in _RE_SHA1.finditer(h):
        yield "sha1", m.group(1).lower()
    for m in _RE_MD5.finditer(h):
        v = m.group(1).lower()
        if v not in imph:
            yield "md5", v


# etiqueta legible por tipo (orden de presentación)
IOC_TYPES = ["ipv4", "ipv6", "domain", "url", "email",
             "sha256", "sha1", "md5", "imphash", "filepath",
             "registry", "pipe", "service", "task"]
IOC_LABEL = {
    "ipv4": "IPv4", "ipv6": "IPv6", "domain": "Domains", "url": "URLs",
    "email": "Emails", "sha256": "SHA256", "sha1": "SHA1", "md5": "MD5",
    "imphash": "Imphash", "filepath": "File paths", "registry": "Registry keys",
    "pipe": "Named pipes", "service": "Services", "task": "Scheduled tasks",
}
