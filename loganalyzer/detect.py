"""Detección del tipo de log.

Dos niveles:
  1. Por nombre de fichero (rápido y fiable cuando el nombre se conserva).
  2. Por CONTENIDO (olfateo de las primeras líneas / bytes), para ficheros
     rotados o renombrados (secure.1, messages.2.gz, un volcado sin nombre).

`detect_type(path)` combina ambos: primero el nombre; si no hay pista, mira
el contenido. `sniff_content(path)` fuerza solo el olfateo.

Solo se admiten logs de TEXTO; los binarios (p.ej. wtmp/btmp) no se
soportan y la ingesta los rechaza.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from typing import Optional

from .parsers import (
    _SYSLOG_RE, _SYSLOG_ISO_RE, _ACCESS_RE, _ACCESS_NS_RE,
    _AUDIT_PREFIX_RE, _NGINX_ERR_RE, _APACHE_ERR_RE, _APPLOG_RE, _KV_RE,
    line_has_ts, _csv_split, looks_like_header,
    _DMESG_RE, _LOGSTART_RE, _DPKG_VERB_RE, _FONTCONFIG_RE, _UDEV_HDR_RE,
)
from . import compress

# --- nivel 1: nombre ---
_NAME_HINTS = [
    (re.compile(r"audit\.log|auditd|audit"), "auditd"),
    (re.compile(r"auth\.log|secure"), "auth"),
    (re.compile(r"kern\.log|\bkern\b"), "kern"),
    (re.compile(r"cron"), "cron"),
    (re.compile(r"syslog|messages"), "syslog"),
    (re.compile(r"error[._-]?log|error_log"), "weberror"),
    (re.compile(r"access[._-]?log|access"), "access"),
    (re.compile(r"bash_history|\.history"), "bash_history"),
    (re.compile(r"\.csv$"), "csv"),
    (re.compile(r"dmesg"), "dmesg"),
    (re.compile(r"term\.log|dpkg|apt.*term|apt/history"), "apt"),
    (re.compile(r"fontconfig|fc-cache"), "fontconfig"),
    (re.compile(r"udev(adm)?(monitor)?"), "udev"),
]

# Programas típicos de auth.log/secure
_AUTH_PROGRAMS = {
    "sudo", "su", "login", "sshd", "systemd-logind", "polkitd",
    "polkit", "unix_chkpwd", "gdm-password", "gdm", "passwd", "useradd",
    "usermod", "groupadd", "sshd-session",
}


def detect_by_name(filename: str) -> Optional[str]:
    base = os.path.basename(filename)
    base = compress.strip_comp_suffix(base).lower()
    # quitar sufijo numérico de rotado para que 'auth.log.1' case
    base = re.sub(r"\.\d+$", "", base)
    for rx, typ in _NAME_HINTS:
        if rx.search(base):
            return typ
    return None


def _read_head_lines(path: str, n: int = 200) -> list[str]:
    out: list[str] = []
    try:
        for line in compress.open_text_lines(path):
            s = line.rstrip("\n")
            if s.strip():
                out.append(s)
            if len(out) >= n:
                break
    except OSError:
        pass
    return out


def _looks_command_line(s: str) -> bool:
    """Heurística de línea de bash_history (comando de shell)."""
    if s.startswith("#") and s[1:].strip().isdigit():
        return True  # marca de tiempo HISTTIMEFORMAT
    if _SYSLOG_RE.match(s) or _ACCESS_RE.match(s):
        return False
    tok = s.split()
    if not tok:
        return False
    first = tok[0]
    # un comando no suele empezar por fecha ni llevar ' : ' de sudo/syslog
    return bool(re.match(r"^[\w./~-]+$", first)) and not first.endswith(":")


def _looks_csv(lines: list[str]) -> bool:
    """Cabecera + columnas separadas por comas, con nº de campos consistente."""
    if len(lines) < 2 or "," not in lines[0]:
        return False
    hdr = _csv_split(lines[0])
    if not looks_like_header(hdr) or len(hdr) < 3:
        return False
    ncol = len(hdr)
    good = checked = 0
    for ln in lines[1:80]:
        if not ln.strip():
            continue
        checked += 1
        cells = _csv_split(ln)
        if len(cells) >= 2 and abs(len(cells) - ncol) <= 1:
            good += 1
    return checked > 0 and good / checked >= 0.8


def sniff_content(path: str) -> Optional[str]:
    """Detecta el tipo mirando el contenido. None si no hay confianza."""
    if compress.is_archive(path):
        return None  # es un contenedor; se expande en la ingesta
    lines = _read_head_lines(path, 200)
    if not lines:
        return None
    total = len(lines)

    # auditd: líneas type=... msg=audit(epoch:serial):
    audit_hits = sum(1 for ln in lines if _AUDIT_PREFIX_RE.match(ln))
    if audit_hits / total >= 0.6:
        return "auditd"

    # error.log web (nginx o apache)
    weberr_hits = sum(1 for ln in lines
                      if _NGINX_ERR_RE.match(ln) or _APACHE_ERR_RE.match(ln))
    if weberr_hits / total >= 0.6:
        return "weberror"

    access_hits = sum(1 for ln in lines
                      if _ACCESS_RE.match(ln) or _ACCESS_NS_RE.match(ln))
    if access_hits / total >= 0.6:
        return "access"

    # CSV: primera línea con pinta de cabecera y nº de columnas (>=3) estable
    # en el resto. Exige comas para no confundirlo con otros formatos.
    if _looks_csv(lines):
        return "csv"

    # dmesg: la mayoría de líneas con prefijo "[  segundos.micro]".
    if sum(1 for ln in lines if _DMESG_RE.match(ln)) / total >= 0.6:
        return "dmesg"

    # udevadm monitor: cabeceras UEVENT[epoch]/UDEV [epoch].
    if sum(1 for ln in lines if _UDEV_HDR_RE.match(ln.strip())) >= 2:
        return "udev"

    # apt/dpkg term.log: "Log started:" + verbos de dpkg (Unpacking/Setting up).
    if (any(_LOGSTART_RE.match(ln.strip()) for ln in lines)
            and sum(1 for ln in lines if _DPKG_VERB_RE.match(ln)) >= 2):
        return "apt"

    # fontconfig / fc-cache.
    if sum(1 for ln in lines if _FONTCONFIG_RE.search(ln)) / total >= 0.6:
        return "fontconfig"

    prog_counter: Counter[str] = Counter()
    syslog_hits = 0
    for ln in lines:
        m = _SYSLOG_RE.match(ln) or _SYSLOG_ISO_RE.match(ln)
        if m:
            syslog_hits += 1
            prog_counter[m.group("prog")] += 1

    if syslog_hits / total >= 0.6 and syslog_hits:
        kern = prog_counter.get("kernel", 0)
        cron = prog_counter.get("CRON", 0) + prog_counter.get("cron", 0)
        auth = sum(c for p, c in prog_counter.items()
                   if p in _AUTH_PROGRAMS or p.startswith("sshd"))
        if kern / syslog_hits >= 0.7:
            return "kern"
        if cron / syslog_hits >= 0.7:
            return "cron"
        if auth / syslog_hits >= 0.4:
            return "auth"
        return "syslog"  # mezcla genérica

    # logfmt: líneas con varios pares clave=valor (campos desconocidos).
    # Antes que applog, para que un "ts=... k=v k=v" se trate como logfmt.
    logfmt_hits = sum(1 for ln in lines if len(_KV_RE.findall(ln)) >= 2)
    if logfmt_hits / total >= 0.6:
        return "logfmt"

    # applog: líneas de aplicación con timestamp (ISO/Python al inicio, o
    # ctime/YYYY-MM-DD-slash/ISO-entre-corchetes/embebido en cualquier parte).
    # Último recurso "tiene timestamps": umbral bajo (0.3) para que entren
    # logs mixtos donde solo parte de las líneas llevan fecha; los ficheros
    # sin ninguna fecha (dmesg, lspci, banners, configs) siguen quedando fuera.
    app_hits = sum(1 for ln in lines if _APPLOG_RE.match(ln) or line_has_ts(ln))
    if app_hits / total >= 0.3:
        return "applog"

    # bash_history: SOLO si hay marcas #epoch (HISTTIMEFORMAT). Sin ellas, un
    # history es indistinguible de texto libre, así que se deja al nombre para
    # no tragarse ficheros de prosa (notas, READMEs, etc.).
    epoch_marks = sum(1 for ln in lines if ln.startswith("#") and ln[1:].strip().isdigit())
    cmd_hits = sum(1 for ln in lines if _looks_command_line(ln))
    if epoch_marks >= 1 and cmd_hits / total >= 0.7:
        return "bash_history"

    return None


def detect_type(path: str, prefer_content: bool = False) -> Optional[str]:
    """Nombre primero (salvo prefer_content), luego contenido."""
    if prefer_content:
        return sniff_content(path) or detect_by_name(path)
    return detect_by_name(path) or sniff_content(path)
