"""Mapeo entre el esquema de LogAnalyzer y la taxonomía Sigma.

Sin dependencias externas (no importa pySigma): lo usa tanto la ingesta
(clasificación de cada evento) como el motor Sigma (predicados de logsource
y resolución de campos). La capa ECS es conceptual: en la práctica cada
campo Sigma se resuelve a una expresión SQL sobre la tabla `events`.
"""
from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# 1) Clasificación por evento (ingesta): sigma_ok + etiqueta de logsource.
#    sigma_ok=1 marca los eventos atacables por Sigma (para no barrer el resto).
# ---------------------------------------------------------------------------
def classify(source: Optional[str], event: Optional[str],
             program: Optional[str]) -> tuple[int, Optional[str]]:
    src = (source or "").lower()
    ev = (event or "").lower()
    prog = (program or "").lower()
    if src == "auth":
        if prog.startswith("sshd"):
            return 1, "linux/sshd"
        if prog == "sudo":
            return 1, "linux/sudo"
        return 1, "linux/auth"
    if src == "auditd":
        return 1, ("linux/process_creation" if ev == "execve" else "linux/auditd")
    if src == "cron":
        return 1, "linux/cron"
    if src in ("syslog", "kern"):
        return 1, "linux/syslog"
    if src == "access":
        return 1, "webserver"
    if src == "weberror":
        # error.log de nginx/apache: ModSecurity suele loguear aquí
        return 1, "linux/modsecurity"
    # logfmt, applog, bash_history, raw, desconocidos -> fuera del motor
    return 0, None


# ---------------------------------------------------------------------------
# 2) Predicados de logsource: qué eventos (en NUESTRO esquema) alimentan cada
#    logsource Sigma. El motor enruta cada regla con su predicado + sigma_ok=1.
#    Alias de tabla esperado: ev.
# ---------------------------------------------------------------------------
LOGSOURCE_PREDICATES: dict[str, str] = {
    "linux/process_creation": "ev.source='auditd' AND ev.event='execve'",
    "linux/network_connection": "ev.source='auditd' AND (ev.extra->>'dst_ip') IS NOT NULL",
    "linux/file_event": "ev.source='auditd' AND ev.event IN ('path','openat','open','create','unlink')",
    "linux/auditd": "ev.source='auditd'",
    "linux/auth": "ev.source='auth'",
    "linux/sshd": "ev.source='auth' AND lower(ev.program) LIKE 'sshd%'",
    "linux/sudo": "(ev.source='auth' AND (lower(ev.program)='sudo' OR ev.raw LIKE '%sudo:%'))",
    "linux/cron": "(ev.source='cron' OR (ev.source='syslog' AND lower(ev.program) LIKE 'cron%'))",
    "linux/syslog": "ev.source IN ('syslog','kern')",
    "linux/clamav": "((ev.source IN ('syslog','kern') AND lower(ev.program) LIKE 'clam%') OR ev.source='clamav')",
    "linux/vsftpd": "(ev.source='syslog' AND lower(ev.program) LIKE 'vsftpd%')",
    "linux/guacamole": "(ev.source='syslog' AND lower(ev.program) LIKE 'guac%')",
    "linux/sysmon": "ev.source='auditd' AND ev.event='execve'",  # Sysmon-for-Linux ~ process_creation
    "linux/modsecurity": "ev.source='weberror'",
    "webserver": "ev.source='access'",
    # genérico: cualquier product:linux cuyo service/category no tenga predicado propio
    "linux": "ev.source IN ('auth','auditd','syslog','kern','cron')",
}


def rule_logsource_key(product: Optional[str], category: Optional[str],
                       service: Optional[str]) -> Optional[str]:
    """Logsource de una regla -> clave de LOGSOURCE_PREDICATES, o None si la
    regla NO aplica a datos Linux (Windows, cloud, dispositivos de red...).

    Solo entran: product=linux (y sus category/service), webserver y modsecurity.
    """
    p = (product or "").lower()
    c = (category or "").lower()
    s = (service or "").lower()
    if c == "webserver" or p in ("apache", "nginx", "iis") or s in ("apache", "nginx"):
        return "webserver"
    if p == "modsecurity" or s == "modsecurity":
        return "linux/modsecurity"
    if p == "linux":
        if c:
            key = f"linux/{c}"
            return key if key in LOGSOURCE_PREDICATES else "linux"
        if s:
            key = f"linux/{s}"
            return key if key in LOGSOURCE_PREDICATES else "linux"
        return "linux"
    return None  # no aplica a Linux/web -> se descarta


# ---------------------------------------------------------------------------
# 3) Resolución de campos: campo Sigma (por logsource) -> expresión SQL.
#    Lo no mapeado cae a (extra->>'campo'), que cubre logfmt/auditd y reglas
#    propias. Un campo ausente da NULL -> no casa (seguro, sin falsos positivos).
# ---------------------------------------------------------------------------
_CMDLINE = "COALESCE(NULLIF(ev.\"message\",''), ev.\"exe\")"

_PROCESS = {
    "Image": 'ev."exe"',
    "CommandLine": _CMDLINE,
    "ParentImage": "(ev.extra->>'parent_exe')",
    "ParentCommandLine": "NULL",
    "CurrentDirectory": "(ev.extra->>'cwd')",
    "User": 'ev."user"',
    "LogonId": "NULL",
    "DestinationIp": "(ev.extra->>'dst_ip')",
    "DestinationPort": "(ev.extra->>'dst_port')",
    "DestinationHostname": "(ev.extra->>'dst_ip')",
}
_WEB = {
    "c-ip": 'ev."src_ip"', "cs-method": 'ev."method"', "sc-status": 'ev."status"',
    "cs-uri": 'ev."path"', "cs-uri-stem": 'ev."path"', "cs-uri-query": 'ev."path"',
    "c-uri": 'ev."path"', "c-uri-query": 'ev."path"', "cs-uri-stem-query": 'ev."path"',
    "cs-user-agent": 'ev."user_agent"', "cs-User-Agent": 'ev."user_agent"',
    "cs-referer": 'ev."referer"', "cs-Referer": 'ev."referer"',
    "sc-bytes": 'ev."bytes"', "cs-bytes": 'ev."bytes"', "cs-host": 'ev."host"',
}
_COMMON = {
    "User": 'ev."user"', "user": 'ev."user"', "exe": 'ev."exe"', "Image": 'ev."exe"',
    "CommandLine": _CMDLINE, "pid": 'ev."pid"', "host": 'ev."host"',
    "hostname": 'ev."host"', "program": 'ev."program"', "process": 'ev."program"',
    "src_ip": 'ev."src_ip"', "SourceIp": 'ev."src_ip"',
    "DestinationIp": "(ev.extra->>'dst_ip')", "DestinationPort": "(ev.extra->>'dst_port')",
}


def resolve_field_for_process(field: str) -> str:
    """Resolución para campos de proceso (usada también por la correlación)."""
    return _PROCESS.get(field) or _COMMON.get(field) or _extra(field)

_SAFE_KEY = re.compile(r"[^\w.\-]")


def _extra(field: str) -> str:
    key = _SAFE_KEY.sub("", field or "")
    return f"(ev.extra->>'{key}')" if key else "NULL"


def resolve_field(logsource_key: Optional[str], field: str) -> str:
    """Expresión SQL para un campo Sigma dentro de un logsource dado."""
    if field == "type":
        return 'upper(ev."event")'
    if logsource_key == "webserver" and field in _WEB:
        return _WEB[field]
    if logsource_key == "linux/process_creation" and field in _PROCESS:
        return _PROCESS[field]
    if field in _COMMON:
        return _COMMON[field]
    return _extra(field)
