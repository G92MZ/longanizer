"""Esquema normalizado común para todos los tipos de log.

Todos los parsers emiten objetos Event con estos campos. Los campos
que no apliquen a un tipo concreto quedan a None. Así se puede tirar
una sola query SQL sobre eventos de orígenes distintos.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional


# Orden de columnas tal como se crean en DuckDB.
COLUMNS: list[tuple[str, str]] = [
    ("ts", "TIMESTAMP"),        # marca temporal del evento (puede ser NULL si el log no la trae)
    ("source", "VARCHAR"),      # tipo de log: auth, syslog, kern, cron, access, auditd, weberror, bash_history
    ("host", "VARCHAR"),        # hostname que emite (cabecera syslog)
    ("program", "VARCHAR"),     # proceso/programa (sshd, sudo, CRON, kernel...)
    ("pid", "INTEGER"),         # PID si aparece
    ("severity", "VARCHAR"),    # severidad/estado normalizado (info, fail, accept, error...)
    ("user", "VARCHAR"),        # usuario implicado (acct/uid en auditd)
    ("src_ip", "VARCHAR"),      # IP de origen
    ("src_port", "INTEGER"),    # puerto de origen
    ("exe", "VARCHAR"),         # ejecutable implicado (auditd exe=, o binario)
    # --- campos de access log ---
    ("method", "VARCHAR"),
    ("path", "VARCHAR"),
    ("status", "INTEGER"),
    ("bytes", "BIGINT"),
    ("referer", "VARCHAR"),
    ("user_agent", "VARCHAR"),
    # --- metadatos ---
    ("event", "VARCHAR"),       # etiqueta de evento reconocido (ssh_accepted, execve, web_error, etc.)
    ("message", "VARCHAR"),     # mensaje libre / resto de la línea
    ("extra", "JSON"),          # campos específicos del origen (auditd: syscall, key, serial...); consultable con extra->>'campo'
    ("src_file", "VARCHAR"),    # fichero de origen
    ("line_no", "INTEGER"),     # nº de línea en el fichero
    ("raw", "VARCHAR"),         # línea original tal cual
    # --- Sigma ---
    ("sigma_ok", "INTEGER"),        # 1 si el evento pertenece a un logsource atacable por Sigma (prune)
    ("sigma_logsource", "VARCHAR"), # etiqueta primaria del logsource (linux/auth, webserver, ...)
]

COLUMN_NAMES = [c[0] for c in COLUMNS]


@dataclass
class Event:
    ts: Optional[datetime] = None
    source: Optional[str] = None
    host: Optional[str] = None
    program: Optional[str] = None
    pid: Optional[int] = None
    severity: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    exe: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    bytes: Optional[int] = None
    referer: Optional[str] = None
    user_agent: Optional[str] = None
    event: Optional[str] = None
    message: Optional[str] = None
    extra: Optional[str] = None
    src_file: Optional[str] = None
    line_no: Optional[int] = None
    raw: Optional[str] = None
    sigma_ok: Optional[int] = None
    sigma_logsource: Optional[str] = None

    def as_row(self) -> tuple:
        d = asdict(self)
        return tuple(d[name] for name in COLUMN_NAMES)
