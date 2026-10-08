"""Parsers de los logs de Linux más habituales en forense.

Cada parser recibe líneas y un contexto (año base, fichero de origen)
y devuelve Events normalizados.

Puntos delicados que se resuelven aquí:
  * Cabecera syslog SIN año (auth.log, syslog, kern.log, cron) -> se
    infiere el año y se maneja el salto dic->ene.
  * access log combined -> regex con campos opcionales.
  * auditd (audit.log) -> formato clave=valor con audit(epoch:serial); epoch
    en UTC. Campos propios en la columna JSON `extra`.
  * error.log web (nginx/apache) -> hora local del servidor (usa tz_offset).
  * bash_history normalmente no lleva timestamp, salvo HISTTIMEFORMAT
    (líneas '#<epoch>' intercaladas).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional

from .schema import Event

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Cabecera syslog clásica: "Sep 30 22:15:01 host program[pid]: msg".
# El año NO aparece. Admite además:
#   - prefijo "TimeStamp=" (appliances BSD tipo ADC),
#   - etiqueta BSD de facilidad/prioridad "<local7.notice>" tras la hora.
_SYSLOG_RE = re.compile(
    r"^(?:TimeStamp=)?"
    r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?:<(?P<facility>[^>]+)>\s+)?"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<msg>.*)$"
)

# Cabecera syslog con año / ISO8601 (rsyslog moderno), con etiqueta BSD opcional.
_SYSLOG_ISO_RE = re.compile(
    r"^(?:TimeStamp=)?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?:<(?P<facility>[^>]+)>\s+)?"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<msg>.*)$"
)

# Prioridad syslog -> severidad normalizada
_PRIO_SEV = {
    "emerg": "error", "alert": "error", "crit": "error", "err": "error",
    "error": "error", "warning": "warn", "warn": "warn", "notice": "info",
    "info": "info", "debug": "debug",
}


def _sev_from_facility(fac: Optional[str]) -> Optional[str]:
    if not fac:
        return None
    prio = fac.rsplit(".", 1)[-1].lower() if "." in fac else fac.lower()
    return _PRIO_SEV.get(prio)


class YearResolver:
    """Asigna año a timestamps syslog sin año, manejando el salto dic->ene.

    Los logs forenses se leen en orden cronológico ascendente. Si el mes
    retrocede (p.ej. de Dic a Ene), se asume cambio de año.
    """

    def __init__(self, base_year: int):
        self.year = base_year
        self._prev_month: Optional[int] = None

    def resolve(self, month: int, day: int, hh: int, mm: int, ss: int) -> datetime:
        if self._prev_month is not None and month < self._prev_month - 1:
            # retroceso claro de mes -> nuevo año (tolerancia de 1 mes por
            # si hay líneas ligeramente desordenadas).
            self.year += 1
        self._prev_month = month
        return datetime(self.year, month, day, hh, mm, ss)


# ---------------------------------------------------------------------------
# Detección de eventos concretos dentro de auth.log / secure
# ---------------------------------------------------------------------------
_RE_SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+) port (?P<port>\d+)"
)
_RE_SSH_FAILED = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+) port (?P<port>\d+)"
)
_RE_SSH_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)(?: port (?P<port>\d+))?"
)
_RE_SUDO = re.compile(
    r"\s*(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
)
_RE_SESSION_OPEN = re.compile(
    r"session opened for user (?P<user>\S+)"
)
_RE_SESSION_CLOSE = re.compile(
    r"session closed for user (?P<user>\S+)"
)


def _classify_auth(prog: str, msg: str, ev: Event) -> None:
    """Rellena event/user/src_ip/severity a partir del mensaje de auth."""
    m = _RE_SSH_ACCEPTED.search(msg)
    if m:
        ev.event = "ssh_accepted"
        ev.severity = "accept"
        ev.user = m.group("user")
        ev.src_ip = m.group("ip")
        ev.src_port = int(m.group("port"))
        return
    m = _RE_SSH_FAILED.search(msg)
    if m:
        ev.event = "ssh_failed"
        ev.severity = "fail"
        ev.user = m.group("user")
        ev.src_ip = m.group("ip")
        ev.src_port = int(m.group("port"))
        return
    m = _RE_SSH_INVALID.search(msg)
    if m:
        ev.event = "ssh_invalid_user"
        ev.severity = "fail"
        ev.user = m.group("user")
        ev.src_ip = m.group("ip")
        if m.group("port"):
            ev.src_port = int(m.group("port"))
        return
    if prog == "sudo":
        m = _RE_SUDO.search(msg)
        if m:
            ev.event = "sudo"
            ev.severity = "info"
            ev.user = m.group("user")
            return
    m = _RE_SESSION_OPEN.search(msg)
    if m:
        ev.event = "session_opened"
        ev.severity = "info"
        ev.user = m.group("user")
        return
    m = _RE_SESSION_CLOSE.search(msg)
    if m:
        ev.event = "session_closed"
        ev.severity = "info"
        ev.user = m.group("user")
        return


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normaliza a UTC y quita tzinfo, para que todos los orígenes sean
    comparables entre sí y DuckDB no aplique conversiones de zona."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _parse_iso_ts(s: str) -> Optional[datetime]:
    s = s.replace("T", " ")
    s = s.replace("Z", "+00:00")
    try:
        return _to_naive_utc(datetime.fromisoformat(s))
    except ValueError:
        try:
            return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def parse_syslog_family(
    lines: Iterable[str],
    source: str,
    base_year: int,
    src_file: str = "",
    tz_offset_minutes: int = 0,
    **_: object,
) -> Iterator[Event]:
    """Parser genérico de la familia syslog (auth, syslog, kern, cron, messages).

    `source` etiqueta el origen y activa la clasificación específica de
    auth cuando source == 'auth'. `tz_offset_minutes` es la zona horaria
    en que estaba configurada la máquina (estos logs no la registran); se
    resta para dejar el ts en UTC naive, comparable con access/auditd.
    """
    yr = YearResolver(base_year)
    tz_delta = timedelta(minutes=tz_offset_minutes)
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue

        ev = Event(source=source, src_file=src_file, line_no=i, raw=line)

        m = _SYSLOG_RE.match(line)
        if m:
            month = MONTHS.get(m.group("mon"))
            if month is None:
                ev.message = line
                yield ev
                continue
            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            ev.ts = yr.resolve(month, int(m.group("day")), hh, mm, ss) - tz_delta
            ev.host = m.group("host")
            ev.program = m.group("prog")
            ev.pid = int(m.group("pid")) if m.group("pid") else None
            ev.severity = _sev_from_facility(m.group("facility"))
            ev.message = m.group("msg")
            if source == "auth":
                _classify_auth(ev.program, ev.message, ev)
            yield ev
            continue

        m = _SYSLOG_ISO_RE.match(line)
        if m:
            ev.ts = _parse_iso_ts(m.group("ts"))
            ev.host = m.group("host")
            ev.program = m.group("prog")
            ev.pid = int(m.group("pid")) if m.group("pid") else None
            ev.severity = _sev_from_facility(m.group("facility"))
            ev.message = m.group("msg")
            if source == "auth":
                _classify_auth(ev.program, ev.message, ev)
            yield ev
            continue

        # línea no reconocida: se intenta extraer un timestamp embebido
        # (ctime, ISO, YYYY/MM/DD…) para que aparezca en la timeline igual.
        ev.ts = scan_ts(line, tz_delta)
        ev.message = line
        yield ev


# ---------------------------------------------------------------------------
# Access log (combined / common)
# ---------------------------------------------------------------------------
_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
# Variante de appliance BSD (ADC):
#   SRC -> DST - - [ts] [pid] "req" status bytes "ref" "ua" ["Time: ..."]
_ACCESS_NS_RE = re.compile(
    r'^(?P<ip>\S+)\s+->\s+(?P<dst>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'(?:\[(?P<pid>\d+)\]\s+)?'
    r'"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_ACCESS_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_access_log(
    lines: Iterable[str],
    source: str = "access",
    src_file: str = "",
    **_: object,
) -> Iterator[Event]:
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        ev = Event(source=source, src_file=src_file, line_no=i, raw=line)
        m = _ACCESS_RE.match(line) or _ACCESS_NS_RE.match(line)
        if not m:
            # línea no-access (p.ej. 'newsyslog ... logfile turned over'):
            # se intenta extraer un timestamp embebido para la timeline.
            ev.ts = scan_ts(line)
            ev.message = line
            yield ev
            continue
        gd = m.groupdict()
        try:
            ts = datetime.strptime(m.group("ts"), _ACCESS_TS_FMT)
            # el access log trae offset explícito -> normalizamos a UTC naive
            ev.ts = _to_naive_utc(ts)
        except ValueError:
            ev.ts = None
        ev.src_ip = None if m.group("ip") == "-" else m.group("ip")
        ev.user = None if m.group("user") == "-" else m.group("user")
        if gd.get("pid"):
            ev.pid = int(gd["pid"])
        if gd.get("dst"):
            import json as _json
            ev.extra = _json.dumps({"dst": gd["dst"]}, ensure_ascii=False)
        req = m.group("req").split()
        if len(req) >= 2:
            ev.method = req[0]
            ev.path = req[1]
        elif req:
            ev.path = req[0]
        ev.status = None if m.group("status") == "-" else int(m.group("status"))
        ev.bytes = None if m.group("bytes") == "-" else int(m.group("bytes"))
        ev.referer = m.group("referer") or None
        ev.user_agent = m.group("ua") or None
        ev.program = "http"
        ev.event = "http_request"
        if ev.status is not None:
            ev.severity = "error" if ev.status >= 500 else ("warn" if ev.status >= 400 else "info")
        ev.message = m.group("req")
        yield ev


# ---------------------------------------------------------------------------
# auditd  (audit.log)
# Formato: type=XXX msg=audit(<epoch>.<ms>:<serial>): k=v k="v" ...
#   los registros USER_* llevan un msg='...' anidado con más k=v.
# ---------------------------------------------------------------------------
_AUDIT_PREFIX_RE = re.compile(
    r"^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\):\s*(?P<body>.*)$"
)
# clave=valor con valor "entrecomillado", 'entrecomillado' o palabra suelta
_KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _parse_kv(body: str) -> dict[str, str]:
    return {k: _unquote(v) for k, v in _KV_RE.findall(body)}


_HEX_RE = re.compile(r"[0-9A-Fa-f]+")


def _auditd_decode2(v: Optional[str]):
    """Como _auditd_decode pero devuelve (texto, decodificado_bool) para que la
    UI pueda señalar los valores que se tradujeron de hex a texto."""
    if v and len(v) % 2 == 0 and _HEX_RE.fullmatch(v):
        try:
            dec = bytes.fromhex(v).decode("utf-8", "replace").replace("\x00", " ").strip()
            if dec:
                return dec, True
        except ValueError:
            return v, False
    return v, False


def _auditd_decode(v: Optional[str]) -> Optional[str]:
    """Decodifica un valor auditd hex (args con espacios, proctitle, cwd...).
    auditd solo codifica en hex valores con caracteres especiales; un valor
    normal va entrecomillado (sin hex), así que decodificamos solo hex par."""
    return _auditd_decode2(v)[0]


def _mark_decoded(kv: dict, key: str) -> None:
    """Anota en kv['_dec'] (set) que el campo `key` se tradujo de hex; se
    serializa a cadena coma-separada antes de volcar el JSON de `extra`."""
    s = kv.get("_dec")
    if not isinstance(s, set):
        s = set()
        kv["_dec"] = s
    s.add(key)


def _decode_saddr(h: Optional[str]):
    """saddr empaquetado -> (ip, port) para AF_INET; None en otro caso."""
    if not h or len(h) < 16:
        return None
    try:
        fam = int(h[2:4] + h[0:2], 16)        # familia, little-endian
        if fam != 2:                           # AF_INET
            return None
        port = int(h[4:8], 16)                 # puerto, big-endian
        ip = ".".join(str(int(h[8 + 2 * k:10 + 2 * k], 16)) for k in range(4))
        return ip, port
    except ValueError:
        return None


def _parse_auditd_line(line: str, i: int, src_file: str):
    """Parsea una línea auditd -> (atype, kv, Event). atype=None si no casa."""
    ev = Event(source="auditd", program="auditd", src_file=src_file,
               line_no=i, raw=line)
    m = _AUDIT_PREFIX_RE.match(line)
    if not m:
        ev.message = line
        return None, None, ev
    atype = m.group("type")
    ev.event = atype.lower()
    try:
        ev.ts = datetime.utcfromtimestamp(int(m.group("epoch")))
    except (ValueError, OverflowError):
        ev.ts = None
    kv = _parse_kv(m.group("body"))
    if "msg" in kv and "=" in kv["msg"]:
        inner = _parse_kv(kv.pop("msg"))
        inner.update({k: v for k, v in kv.items()})
        kv = {**kv, **inner}
    kv["serial"] = m.group("serial")
    ev.pid = int(kv["pid"]) if kv.get("pid", "").isdigit() else None
    ev.exe = kv.get("exe")
    ev.src_ip = kv.get("addr") if kv.get("addr") not in (None, "?") else None
    ev.user = kv.get("acct") or kv.get("auid") or kv.get("uid")
    succ = kv.get("success") or kv.get("res")
    if succ in ("no", "failed"):
        ev.severity = "fail"
    elif succ in ("yes", "success"):
        ev.severity = "info"
    if atype == "EXECVE":
        try:
            argc = int(kv.get("argc", "0"))
        except ValueError:
            argc = 0
        args = []
        any_dec = False
        for j in range(argc):
            t, d = _auditd_decode2(kv.get(f"a{j}", ""))
            if t:
                args.append(t)
            any_dec = any_dec or d
        ev.message = " ".join(args) or m.group("body")
        if any_dec:
            _mark_decoded(kv, "cmd")   # la command line se reconstruyó de hex
    else:
        ev.message = kv.get("comm") or kv.get("op") or m.group("body")[:500]
    return atype, kv, ev


def parse_auditd(lines, source="auditd", src_file="", **_):
    """auditd con COSIDO por `serial`: enriquece cada EXECVE con exe/ppid/cwd/
    proctitle del mismo evento (registros SYSCALL/CWD/PROCTITLE del mismo serial)
    y con parent_exe (ppid->exe visto antes). NO borra registros: SYSCALL, PATH,
    etc. siguen existiendo para las reglas de servicio `auditd`. Decodifica saddr
    (-> dst_ip/dst_port) y los valores hex (args, proctitle, cwd)."""
    import json
    pid_exe: dict[str, str] = {}   # pid -> exe (ParentImage best-effort)

    def flush(group):
        if not group:
            return
        gexe = gppid = gcwd = gproc = gdst = None
        gcwd_dec = gproc_dec = False
        for atype, kv, ev in group:
            if atype == "SYSCALL":
                gexe = gexe or kv.get("exe")
                gppid = gppid or kv.get("ppid")
            elif atype == "CWD":
                if gcwd is None:
                    gcwd, gcwd_dec = _auditd_decode2(kv.get("cwd"))
            elif atype == "PROCTITLE":
                if gproc is None:
                    gproc, gproc_dec = _auditd_decode2(kv.get("proctitle"))
            if "saddr" in kv:
                d = _decode_saddr(kv["saddr"])
                if d:
                    gdst = d
            if kv.get("pid") and kv.get("exe"):
                pid_exe[kv["pid"]] = kv["exe"]
        for atype, kv, ev in group:
            if atype == "EXECVE":
                if not ev.exe and gexe:
                    ev.exe = gexe
                if gcwd:
                    kv["cwd"] = gcwd
                    if gcwd_dec:
                        _mark_decoded(kv, "cwd")
                if gppid:
                    kv["ppid"] = gppid
                    if pid_exe.get(gppid):
                        kv["parent_exe"] = pid_exe[gppid]
                if gproc:
                    kv["proctitle"] = gproc
                    if gproc_dec:
                        _mark_decoded(kv, "proctitle")
            if gdst and atype in ("SYSCALL", "SOCKADDR"):
                kv["dst_ip"] = gdst[0]
                kv["dst_port"] = str(gdst[1])
                _mark_decoded(kv, "dst_ip")   # saddr (hex) -> ip:puerto
                _mark_decoded(kv, "dst_port")
            if isinstance(kv.get("_dec"), set):
                kv["_dec"] = ",".join(sorted(kv["_dec"])) if kv["_dec"] else None
                if not kv["_dec"]:
                    kv.pop("_dec", None)
            try:
                ev.extra = json.dumps(kv, ensure_ascii=False)
            except (TypeError, ValueError):
                ev.extra = None
            yield ev

    group: list = []
    cur = None
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        atype, kv, ev = _parse_auditd_line(line, i, src_file)
        if atype is None:
            yield from flush(group)
            group, cur = [], None
            yield ev
            continue
        serial = kv.get("serial")
        if cur is not None and serial != cur:
            yield from flush(group)
            group = []
        cur = serial
        group.append((atype, kv, ev))
    yield from flush(group)


# ---------------------------------------------------------------------------
# error.log del servidor web (nginx y apache)
# ---------------------------------------------------------------------------
# nginx: 2026/09/30 22:14:05 [error] 1234#0: *5 mensaje..., client: IP, request: "GET /p HTTP/1.1", ...
_NGINX_ERR_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] "
    r"(?P<pid>\d+)#\d+:\s*(?P<msg>.*)$"
)
# apache: [Wed Sep 30 22:14:05.123456 2026] [core:error] [pid 1234] [client 1.2.3.4:55] mensaje
_APACHE_ERR_RE = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] "
    r"\[(?:(?P<module>[\w-]+):)?(?P<level>\w+)\] "
    r"(?:\[pid (?P<pid>\d+)(?::tid \d+)?\] )?"
    r"(?:\[client (?P<client>[^\]]+)\] )?"
    r"(?P<msg>.*)$"
)
_NGINX_CLIENT_RE = re.compile(r"client:\s*(?P<ip>[\da-fA-F:.]+)")
_NGINX_REQ_RE = re.compile(r'request:\s*"(?P<method>\S+) (?P<path>\S+)[^"]*"')


def parse_web_error(
    lines: Iterable[str],
    source: str = "weberror",
    src_file: str = "",
    tz_offset_minutes: int = 0,
    **_: object,
) -> Iterator[Event]:
    tz_delta = timedelta(minutes=tz_offset_minutes)
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        ev = Event(source="weberror", event="web_error", src_file=src_file,
                   line_no=i, raw=line)

        m = _NGINX_ERR_RE.match(line)
        if m:
            ev.program = "nginx"
            try:
                ev.ts = datetime.strptime(m.group("ts"), "%Y/%m/%d %H:%M:%S") - tz_delta
            except ValueError:
                ev.ts = None
            ev.severity = m.group("level")
            ev.pid = int(m.group("pid"))
            msg = m.group("msg")
            cm = _NGINX_CLIENT_RE.search(msg)
            if cm:
                ev.src_ip = cm.group("ip")
            rm = _NGINX_REQ_RE.search(msg)
            if rm:
                ev.method = rm.group("method")
                ev.path = rm.group("path")
            ev.message = msg
            yield ev
            continue

        m = _APACHE_ERR_RE.match(line)
        if m:
            ev.program = "apache"
            ts_raw = m.group("ts")
            for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
                try:
                    ev.ts = datetime.strptime(ts_raw, fmt) - tz_delta
                    break
                except ValueError:
                    ev.ts = None
            ev.severity = m.group("level")
            if m.group("pid"):
                ev.pid = int(m.group("pid"))
            if m.group("client"):
                ev.src_ip = m.group("client").rsplit(":", 1)[0]
            ev.message = m.group("msg")
            yield ev
            continue

        ev.message = line
        yield ev


# ---------------------------------------------------------------------------
# bash_history  (opcionalmente con timestamps HISTTIMEFORMAT: líneas '#epoch')
# ---------------------------------------------------------------------------
def parse_bash_history(
    lines: Iterable[str],
    source: str = "bash_history",
    src_file: str = "",
    user: Optional[str] = None,
    **_: object,
) -> Iterator[Event]:
    pending_ts: Optional[datetime] = None
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line:
            continue
        if line.startswith("#") and line[1:].strip().isdigit():
            try:
                pending_ts = datetime.fromtimestamp(int(line[1:].strip()), tz=timezone.utc).replace(tzinfo=None)
            except (ValueError, OverflowError):
                pending_ts = None
            continue
        ev = Event(
            source=source, src_file=src_file, line_no=i, raw=line,
            ts=pending_ts, user=user, program="bash", event="command",
            message=line,
        )
        yield ev
        pending_ts = None


# ---------------------------------------------------------------------------
# applog: logs de aplicación con timestamp al inicio (ISO8601 con Z/offset,
# "YYYY-MM-DD HH:MM:SS,ms LEVEL", "[LEVEL]"...). Admite prefijo TimeStamp=.
# ---------------------------------------------------------------------------
_APPLOG_RE = re.compile(
    r"^(?:TimeStamp=)?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<rest>.*)$"
)
_APPLOG_LVL_RE = re.compile(
    r"^\[?(?P<lvl>INFO|DEBUG|WARN|WARNING|ERROR|ERR|NOTICE|CRIT|CRITICAL|TRACE|FATAL)\]?"
    r"\s*:?\s*(?P<msg>.*)$", re.IGNORECASE)
_APPLOG_SEV = {
    "fatal": "error", "critical": "error", "crit": "error", "error": "error",
    "err": "error", "warning": "warn", "warn": "warn", "notice": "info",
    "info": "info", "debug": "debug", "trace": "debug",
}

# --- extractor de timestamp genérico (en cualquier parte de la línea) ---
# Cubre formatos de appliances/apps aunque no se parseen los campos:
#   ISO (suelto o entre corchetes), YYYY/MM/DD HH:MM:SS, y ctime
#   "Wed Jul  1 10:17:41 2026" / "Sun Sep 27 17:09:52 UTC 2026"
#   (incluso embebido: "COLLECTOR::CRITICAL::Wed Jul 1 ... 2026:").
_TS_ISO = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
_TS_SLASH = re.compile(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
_TS_CTIME = re.compile(
    r"(?:[A-Z][a-z]{2}\s+)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})(?:\s+(?P<tz>[A-Z]{2,4}))?\s+(?P<year>\d{4})")


def line_has_ts(line: str) -> bool:
    """¿La línea contiene algún timestamp reconocible (para detección)?"""
    return bool(_TS_ISO.search(line) or _TS_SLASH.search(line)
                or _TS_CTIME.search(line))


def scan_ts(line: str, tz_delta: timedelta = timedelta()) -> Optional[datetime]:
    """Extrae un timestamp de cualquier parte de la línea -> UTC naive.
    No parsea los demás campos; solo sitúa el evento en la timeline."""
    m = _TS_ISO.search(line)
    if m:
        dt = _parse_iso_ts(m.group(0).replace(",", "."))
        if dt is not None:
            # si no traía zona, era hora local -> a UTC
            if not re.search(r"(Z|[+-]\d{2}:?\d{2})$", m.group(0)):
                dt = dt - tz_delta
            return dt
    m = _TS_SLASH.search(line)
    if m:
        try:
            return datetime.strptime(m.group(0), "%Y/%m/%d %H:%M:%S") - tz_delta
        except ValueError:
            pass
    m = _TS_CTIME.search(line)
    if m:
        mon = MONTHS.get(m.group("mon"))
        if mon:
            try:
                hh, mm, ss = (int(x) for x in m.group("time").split(":"))
                dt = datetime(int(m.group("year")), mon, int(m.group("day")), hh, mm, ss)
                if m.group("tz") in ("UTC", "GMT", "Z"):
                    return dt
                return dt - tz_delta
            except ValueError:
                pass
    return None


def parse_applog(
    lines: Iterable[str],
    source: str = "applog",
    src_file: str = "",
    tz_offset_minutes: int = 0,
    **_: object,
) -> Iterator[Event]:
    tz_delta = timedelta(minutes=tz_offset_minutes)
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        ev = Event(source="applog", src_file=src_file, line_no=i, raw=line)
        m = _APPLOG_RE.match(line)
        if not m:
            # otros formatos (ctime, YYYY/MM/DD, ISO entre corchetes, embebidos):
            # se extrae el timestamp y se deja la línea entera como mensaje.
            ev.ts = scan_ts(line, tz_delta)
            ev.message = line
            yield ev
            continue
        ts_raw = m.group("ts").replace(",", ".")
        ts = _parse_iso_ts(ts_raw)
        # si la marca no traía zona, está en hora local -> pasar a UTC
        if ts is not None and ("Z" not in m.group("ts")
                               and "+" not in m.group("ts")
                               and not re.search(r"-\d{2}:?\d{2}$", m.group("ts"))):
            ts = ts - tz_delta
        ev.ts = ts
        rest = m.group("rest")
        lm = _APPLOG_LVL_RE.match(rest)
        if lm:
            ev.severity = _APPLOG_SEV.get(lm.group("lvl").lower())
            ev.message = lm.group("msg") or rest
        else:
            ev.message = rest
        yield ev


# ---------------------------------------------------------------------------
# logfmt: "timestamp clave1=valor1 clave2=valor2 ..." (campos desconocidos).
# Extrae el ts, mapea las claves CONOCIDAS a columnas y el resto a `extra`.
# ---------------------------------------------------------------------------
# claves habituales -> columna del esquema (no se mapea a source/ts/event)
_LOGFMT_MAP = {
    "user": "user", "usr": "user", "username": "user", "acct": "user", "account": "user",
    "src_ip": "src_ip", "srcip": "src_ip", "ip": "src_ip", "addr": "src_ip",
    "client": "src_ip", "clientip": "src_ip", "remote": "src_ip", "remote_addr": "src_ip",
    "host": "host", "hostname": "host",
    "pid": "pid",
    "port": "src_port", "sport": "src_port", "src_port": "src_port",
    "status": "status", "code": "status", "status_code": "status", "statuscode": "status",
    "method": "method", "verb": "method",
    "path": "path", "url": "path", "uri": "path", "request": "path",
    "exe": "exe", "cmd": "exe", "command": "exe", "executable": "exe",
    "program": "program", "proc": "program", "process": "program", "service": "program", "prog": "program", "app": "program",
    "severity": "severity", "level": "severity", "lvl": "severity", "sev": "severity",
    "bytes": "bytes", "size": "bytes", "length": "bytes", "bytes_sent": "bytes",
    "referer": "referer", "referrer": "referer",
    "user_agent": "user_agent", "ua": "user_agent", "useragent": "user_agent",
    "msg": "message", "message": "message",
}
_LOGFMT_TS_KEYS = ("ts", "time", "timestamp", "date", "@timestamp", "datetime", "eventtime")
_INT_COLS = {"pid", "status", "bytes", "src_port"}


def parse_logfmt(
    lines: Iterable[str],
    source: str = "logfmt",
    src_file: str = "",
    tz_offset_minutes: int = 0,
    **_: object,
) -> Iterator[Event]:
    import json
    tz_delta = timedelta(minutes=tz_offset_minutes)
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        ev = Event(source="logfmt", src_file=src_file, line_no=i, raw=line)
        kv = _parse_kv(line)
        # timestamp: una clave de tiempo conocida, o escaneo genérico de la línea
        ts = None
        for k in _LOGFMT_TS_KEYS:
            if k in kv:
                ts = _parse_iso_ts(kv[k].replace(",", "."))
                if ts is None:
                    ts = scan_ts(kv[k], tz_delta)
                break
        if ts is None:
            ts = scan_ts(line, tz_delta)
        ev.ts = ts

        extra = {}
        for k, v in kv.items():
            if k in _LOGFMT_TS_KEYS:
                continue
            col = _LOGFMT_MAP.get(k.lower())
            if col and getattr(ev, col) in (None, ""):
                if col in _INT_COLS:
                    try:
                        setattr(ev, col, int(v))
                    except ValueError:
                        extra[k] = v
                elif col == "severity":
                    ev.severity = _APPLOG_SEV.get(v.lower(), v)
                else:
                    setattr(ev, col, v)
            else:
                extra[k] = v
        if not ev.message:
            ev.message = line
        if extra:
            try:
                ev.extra = json.dumps(extra, ensure_ascii=False)
            except (TypeError, ValueError):
                ev.extra = None
        yield ev


# ---------------------------------------------------------------------------
# CSV: ficheros de valores separados por comas. Si la primera fila parece una
# cabecera, sus nombres se usan como campos; cada fila siguiente = un evento.
# Los nombres conocidos (user, ip, status…) se mapean a columnas del esquema y
# el resto va al JSON `extra`. El ts sale de una columna de fecha/hora si la
# hay, o se escanea de la línea. Respeta comillas (módulo csv estándar).
# ---------------------------------------------------------------------------
import csv as _csv

_CSV_TS_KEYS = {"ts", "time", "timestamp", "datetime", "date", "@timestamp",
                "eventtime", "_time", "time_generated", "timegenerated"}


def _csv_split(line: str, delimiter: str = ",") -> list[str]:
    try:
        return next(_csv.reader([line], delimiter=delimiter))
    except Exception:  # noqa: BLE001
        return line.split(delimiter)


def looks_like_header(cells: list[str]) -> bool:
    """La fila parece una cabecera: >=2 celdas, todas no vacías, con pinta de
    nombre de campo (no números, ni IPs, ni fechas)."""
    if len(cells) < 2:
        return False
    for c in cells:
        c = c.strip()
        if not c:
            return False
        if re.fullmatch(r"-?\d+(?:[.,]\d+)?", c):      # número
            return False
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", c):  # IP
            return False
        if not re.fullmatch(r"[A-Za-z_][\w .\-/@]{0,48}", c):
            return False
    return True


def parse_csv(lines, source="csv", src_file="", tz_offset_minutes=0,
              delimiter=",", **_):
    import json
    tzd = timedelta(minutes=tz_offset_minutes)
    header: Optional[list[str]] = None
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        cells = _csv_split(line, delimiter)
        if header is None:
            if looks_like_header(cells):
                header = [c.strip() or f"col{j+1}" for j, c in enumerate(cells)]
                continue
            # sin cabecera: nombres sintéticos y esta línea ya es un dato
            header = [f"col{j+1}" for j in range(len(cells))]
        ev = Event(source=source, src_file=src_file, line_no=i, raw=line,
                   event="csv")
        extra: dict = {}
        ts = None
        for j, val in enumerate(cells):
            name = header[j] if j < len(header) else f"col{j+1}"
            lk = name.strip().lower()
            val = (val or "").strip()
            if lk in _CSV_TS_KEYS:
                if ts is None and val:
                    ts = _parse_iso_ts(val.replace(",", ".")) or scan_ts(val, tzd)
                if val:
                    extra[name] = val
                continue
            col = _LOGFMT_MAP.get(lk)
            if col and getattr(ev, col) in (None, ""):
                if col in _INT_COLS:
                    try:
                        setattr(ev, col, int(val))
                    except ValueError:
                        if val:
                            extra[name] = val
                elif col == "severity":
                    ev.severity = _APPLOG_SEV.get(val.lower(), val)
                else:
                    setattr(ev, col, val)
            elif val != "":
                extra[name] = val
        if ts is None:
            try:
                ts = scan_ts(line, tzd) if line_has_ts(line) else None
            except Exception:  # noqa: BLE001
                ts = None
        ev.ts = ts
        if not ev.message:
            ev.message = line
        if extra:
            try:
                ev.extra = json.dumps(extra, ensure_ascii=False)
            except (TypeError, ValueError):
                ev.extra = None
        yield ev


# ---------------------------------------------------------------------------
# dmesg (anillo del kernel): "[    0.000000] mensaje".
# El corchete es el tiempo DESDE EL ARRANQUE (segundos), NO una fecha real,
# así que ts queda a None (se ingesta igual, sin timeline) y el offset va a
# extra.ktime. 1 línea = 1 evento. Nada se descarta.
# ---------------------------------------------------------------------------
_DMESG_RE = re.compile(r"^\[\s*(\d+\.\d+)\]\s?(.*)$")


def parse_dmesg(lines, source="dmesg", src_file="", tz_offset_minutes=0,
                base_year=None, **_):
    import json
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        m = _DMESG_RE.match(line)
        if m:
            ev = Event(source="dmesg", raw=line, message=m.group(2),
                       ts=None, src_file=src_file, line_no=i, event="kernel",
                       program="kernel")
            try:
                ev.extra = json.dumps({"ktime": float(m.group(1))})
            except (TypeError, ValueError):
                ev.extra = None
            yield ev
        else:
            # banner / continuación sin corchete: se conserva igualmente
            yield Event(source="dmesg", raw=line, message=line, ts=None,
                        src_file=src_file, line_no=i, event="kernel",
                        program="kernel")


# ---------------------------------------------------------------------------
# apt/dpkg term.log: bloques "Log started: <fecha>" … "Log ended: <fecha>".
# Cada bloque = 1 evento (ts = Log started; resumen = acciones de paquete;
# bloque completo en raw). Un bloque sin "Log ended" (fichero truncado) se
# cierra en el siguiente "Log started" o al final.
# ---------------------------------------------------------------------------
_LOGSTART_RE = re.compile(r"^Log started:\s*(.+)$", re.I)
_LOGEND_RE = re.compile(r"^Log ended:\s*(.+)$", re.I)
_DPKG_VERB_RE = re.compile(
    r"^(Unpacking|Setting up|Removing|Installing|Purging|Selecting|"
    r"Preparing|Processing|Configuring)\b")


def parse_apt_term(lines, source="apt", src_file="", tz_offset_minutes=0,
                   base_year=None, **_):
    import json
    tzd = timedelta(minutes=tz_offset_minutes)

    def _ts(s):
        s = re.sub(r"\s+", " ", s.strip())
        return _parse_iso_ts(s) or scan_ts(s, tzd)

    start_raw = None
    start_ts = None
    buf: list[str] = []
    ln0 = 1

    def flush(end_ts=None):
        if start_raw is None and not buf:
            return None
        block = "\n".join(([start_raw] if start_raw else []) + buf)
        acts = [b for b in buf if _DPKG_VERB_RE.match(b)]
        msg = "; ".join(acts) if acts else (buf[0] if buf else (start_raw or ""))
        ev = Event(source="apt", raw=block, message=msg[:2000], ts=start_ts,
                   src_file=src_file, line_no=ln0, event="dpkg", program="dpkg")
        extra = {}
        if end_ts:
            extra["log_ended"] = end_ts
        if acts:
            extra["actions"] = len(acts)
        if extra:
            try:
                ev.extra = json.dumps(extra, ensure_ascii=False)
            except (TypeError, ValueError):
                ev.extra = None
        return ev

    idx = 0
    for idx, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        s = line.strip()
        ms = _LOGSTART_RE.match(s)
        me = _LOGEND_RE.match(s)
        if ms:
            ev = flush()
            if ev:
                yield ev
            start_raw, start_ts, buf, ln0 = line, _ts(ms.group(1)), [], idx
        elif me:
            buf.append(line)
            ev = flush(end_ts=re.sub(r"\s+", " ", me.group(1).strip()))
            if ev:
                yield ev
            start_raw, start_ts, buf = None, None, []
        elif not s:
            continue
        elif start_raw is None:
            # línea suelta fuera de un bloque: evento individual (no perder)
            yield Event(source="apt", raw=line, message=line, ts=None,
                        src_file=src_file, line_no=idx, event="dpkg",
                        program="dpkg")
        else:
            buf.append(line)
    ev = flush()
    if ev:
        yield ev


# ---------------------------------------------------------------------------
# fontconfig (fc-cache): "/ruta: caching, new cache contents: …", "fc-cache:
# succeeded". Sin fecha. 1 línea = 1 evento.
# ---------------------------------------------------------------------------
_FONTCONFIG_RE = re.compile(
    r"(: caching,|: skipping,|: cleaning |: not cleaning|^fc-cache:|"
    r"caching, new cache contents:)")


def parse_fontconfig(lines, source="fontconfig", src_file="",
                     tz_offset_minutes=0, base_year=None, **_):
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        path = line.split(":", 1)[0].strip() if ":" in line else None
        ev = Event(source="fontconfig", raw=line, message=line, ts=None,
                   src_file=src_file, line_no=i, event="fontconfig")
        if path and ("/" in path):
            ev.path = path
        yield ev


# ---------------------------------------------------------------------------
# udevadm monitor: bloques "UEVENT[epoch] add /ruta (subsys)" + líneas
# CLAVE=valor, separados por línea en blanco. Cada bloque = 1 evento; el epoch
# del corchete es hora real (UTC). Los CLAVE=valor van a `extra`.
# ---------------------------------------------------------------------------
_UDEV_HDR_RE = re.compile(
    r"^(UEVENT|UDEV)\s*\[\s*(\d+(?:\.\d+)?)\]\s+(\S+)\s+(.*)$")


def parse_udev(lines, source="udev", src_file="", tz_offset_minutes=0,
               base_year=None, **_):
    import json
    cur = None        # (kind, epoch, action, dev)
    hdr = None
    buf: list[str] = []
    ln0 = 1

    def flush():
        if cur is None:
            return None
        kind, epoch, action, dev = cur
        extra = {}
        for b in buf:
            if "=" in b:
                k, v = b.split("=", 1)
                extra[k.strip()] = v.strip()
        ts = None
        try:
            ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc) \
                .replace(tzinfo=None)
        except (TypeError, ValueError, OSError):
            ts = None
        ev = Event(source="udev", raw="\n".join([hdr] + buf),
                   message=f"{kind} {action} {dev}".strip(), ts=ts,
                   src_file=src_file, line_no=ln0, event=kind.lower(),
                   program="udev")
        if extra.get("DEVPATH"):
            ev.path = extra["DEVPATH"]
        if extra:
            try:
                ev.extra = json.dumps(extra, ensure_ascii=False)
            except (TypeError, ValueError):
                ev.extra = None
        return ev

    idx = 0
    for idx, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        m = _UDEV_HDR_RE.match(line.strip())
        if m:
            ev = flush()
            if ev:
                yield ev
            cur = (m.group(1), m.group(2), m.group(3), m.group(4))
            hdr, buf, ln0 = line, [], idx
        elif not line.strip():
            ev = flush()
            if ev:
                yield ev
            cur, hdr, buf = None, None, []
        elif cur is not None:
            buf.append(line)
        else:
            # línea antes del primer bloque (banner "udevmonitor will print…")
            yield Event(source="udev", raw=line, message=line, ts=None,
                        src_file=src_file, line_no=idx, event="udev",
                        program="udev")
    ev = flush()
    if ev:
        yield ev


def parse_raw(lines, source="raw", src_file="", tz_offset_minutes=0,
              base_year=None, **_):
    """Catch-all: cada línea no vacía -> un evento con la línea en `raw`/`message`.

    Se usa para logs que no encajan en ningún parser y no son clave=valor: no
    desglosa campos, pero deja todo BUSCABLE y en la timeline (con su ts si la
    línea trae alguno). Así ninguna línea se pierde para las reglas keyword."""
    tzd = timedelta(minutes=tz_offset_minutes)
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        ts = None
        try:
            if line_has_ts(line):
                ts = scan_ts(line, tzd)
        except Exception:  # noqa: BLE001
            ts = None
        yield Event(source=source, raw=line, message=line, ts=ts,
                    src_file=src_file, line_no=i, event="raw")


# Registro de parsers de texto disponibles por nombre de tipo.
TEXT_PARSERS = {
    "auth": lambda lines, **kw: parse_syslog_family(lines, "auth", **kw),
    "syslog": lambda lines, **kw: parse_syslog_family(lines, "syslog", **kw),
    "messages": lambda lines, **kw: parse_syslog_family(lines, "syslog", **kw),
    "kern": lambda lines, **kw: parse_syslog_family(lines, "kern", **kw),
    "cron": lambda lines, **kw: parse_syslog_family(lines, "cron", **kw),
    "access": parse_access_log,
    "auditd": parse_auditd,
    "weberror": parse_web_error,
    "logfmt": parse_logfmt,
    "applog": parse_applog,
    "bash_history": parse_bash_history,
    "csv": parse_csv,
    "dmesg": parse_dmesg,
    "apt": parse_apt_term,
    "fontconfig": parse_fontconfig,
    "udev": parse_udev,
    "raw": parse_raw,
}
