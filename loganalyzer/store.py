"""Almacén DuckDB para los eventos normalizados."""
from __future__ import annotations

import bisect
import ipaddress
import re
import datetime as _dt
import threading
from typing import Any, Optional

import duckdb

from .schema import COLUMNS, COLUMN_NAMES


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """¿La IP (str) cae dentro del CIDR? v4 y v6, cualquier prefijo. Robusta
    ante valores no-IP (devuelve False). La usa el motor Sigma para traducir
    SigmaCIDRExpression sin depender de prefijos alineados a octeto."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(ip.strip())
        return addr.version == net.version and addr in net
    except (ValueError, AttributeError):
        return False


def _register_udfs(con) -> None:
    """Registra funciones escalares Python usadas por el SQL generado (p.ej.
    el match CIDR del motor Sigma). Silenciosa si la versión de DuckDB no lo
    soporta: el resto de la app sigue funcionando."""
    try:
        con.create_function("sigma_ip_in_cidr", _ip_in_cidr)
    except Exception:  # noqa: BLE001
        pass


class EventStore:
    """Envuelve una conexión DuckDB con la tabla `events`.

    path=":memory:" para analisis efímero; un fichero .duckdb para persistir.
    """

    # texto sobre el que busca el explorador:
    #  - substring/tokens: campos normalizados + línea original (amplio, para IOCs)
    #  - regex: la línea original (raw), para que ^/$ anclen como en grep
    _SEARCH_TEXT = ("concat_ws(' ', message, raw, image, command_line, "
                    "parent_image, original_filename, hashes, target_filename, "
                    "image_loaded, \"user\", sid, src_ip, dst_ip, program, source)")
    _REGEX_TEXT = "coalesce(raw, message, '')"

    # --- sintaxis de búsqueda avanzada del explorador ---------------------
    # texto libre  -> contains sobre _SEARCH_TEXT (varias palabras = AND)
    # campo:valor  -> ese campo CONTIENE valor (ILIKE, sin mayúsculas)
    # campo=valor  -> ese campo es EXACTAMENTE valor
    # campo!=valor -> ese campo NO es valor
    # -algo        -> NOT (excluye); vale con texto libre o con campo:valor
    # x:clave:valor o extra.clave:valor -> busca en una clave del JSON extra
    _FIELD_ALIASES = {"ip": "src_ip", "sip": "src_ip", "dip": "dst_ip",
                      "eventid": "eid", "id": "eid", "channel": "source",
                      "cmd": "command_line", "cmdline": "command_line",
                      "img": "image", "image_": "image", "parent": "parent_image",
                      "pimg": "parent_image", "hash": "hashes", "msg": "message",
                      "target": "target_filename", "proc": "program"}
    _NUM_COLS = {name for name, typ in COLUMNS if typ in ("INTEGER", "BIGINT")}

    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._con = duckdb.connect(path)
        _register_udfs(self._con)
        # RLock (reentrant) so query methods can call _ensure_seqmap() while
        # already holding the lock without deadlocking.
        self._lock = threading.RLock()
        # seqmap (id -> timeline position) is materialised lazily and marked
        # dirty on every insert/reset, so it is rebuilt once per ingest batch
        # instead of recomputed on every search/context query.
        self._seq_dirty = True
        self._init_schema()
        # id incremental persistente (continúa desde el máximo existente)
        self._next_id = self._con.execute(
            "SELECT coalesce(max(id), 0) + 1 FROM events"
        ).fetchone()[0]

    def _init_schema(self) -> None:
        # `id` da un orden estable y sirve de ancla para el contexto ±N
        cols = ", ".join(f'"{name}" {typ}' for name, typ in COLUMNS)
        with self._lock:
            self._con.execute(
                f"CREATE TABLE IF NOT EXISTS events (id BIGINT, {cols})"
            )
            # migración: añade columnas nuevas a bases creadas con versiones
            # anteriores (p. ej. sigma_ok/sigma_logsource) sin perder datos.
            for name, typ in COLUMNS:
                try:
                    self._con.execute(
                        f'ALTER TABLE events ADD COLUMN IF NOT EXISTS "{name}" {typ}')
                except duckdb.Error:
                    pass
            # marcas de triage (TP/FP/pendiente/descartado) por evento; viajan
            # con el fichero de caso .duckdb (persisten entre reinicios).
            self._con.execute(
                "CREATE TABLE IF NOT EXISTS marcas ("
                "mid BIGINT, event_id BIGINT, estado VARCHAR, "
                "etiqueta VARCHAR, nota VARCHAR, creado VARCHAR, "
                "contexto VARCHAR, regla VARCHAR)")
            # migración: añade contexto/regla a casos creados con versiones previas
            for _c in ("contexto", "regla"):
                try:
                    self._con.execute(
                        f"ALTER TABLE marcas ADD COLUMN IF NOT EXISTS {_c} VARCHAR")
                except duckdb.Error:
                    pass
            self._mark_next = self._con.execute(
                "SELECT coalesce(max(mid),0)+1 FROM marcas").fetchone()[0]
            # ART index on events.id: makes the context anchor lookup
            # (WHERE id = ?) a point lookup instead of a scan.
            try:
                self._con.execute(
                    "CREATE INDEX IF NOT EXISTS ix_events_id ON events(id)")
            except duckdb.Error:
                pass

    def _ensure_seqmap(self) -> None:
        """Rebuild the id->seq (timeline position) table if events changed.

        Caller may or may not hold the lock; RLock makes re-entry safe. The
        full window sort runs once here per ingest batch, not on every query.
        """
        with self._lock:
            if not self._seq_dirty:
                return
            self._con.execute(
                "CREATE OR REPLACE TABLE seqmap AS "
                "SELECT id, row_number() OVER (ORDER BY ts NULLS LAST, id) AS seq "
                "FROM events")
            for stmt in (
                "CREATE INDEX IF NOT EXISTS ix_seqmap_id ON seqmap(id)",
                "CREATE INDEX IF NOT EXISTS ix_seqmap_seq ON seqmap(seq)"):
                try:
                    self._con.execute(stmt)
                except duckdb.Error:
                    pass
            self._seq_dirty = False

    def insert_events(self, rows: list[tuple],
                      ts_from: 'Optional[_dt.datetime]' = None,
                      ts_to:   'Optional[_dt.datetime]' = None) -> int:
        """Inserta eventos. ts_from/ts_to (datetime UTC) filtran antes de insertar."""
        if not rows:
            return 0
        if ts_from is not None or ts_to is not None:
            ts_idx = list(COLUMN_NAMES).index('ts')
            # ts_from/ts_to son aware-UTC; los ts de los EVTX pueden ser naive
            # (ya en UTC) o aware. Normalizamos todo a naive-UTC para comparar.
            _tf = ts_from.replace(tzinfo=None) if ts_from is not None else None
            _tt = ts_to.replace(tzinfo=None)   if ts_to   is not None else None
            def _ok(r):
                v = r[ts_idx]
                if v is None: return True
                # normalizar v a naive
                vn = v.replace(tzinfo=None) if getattr(v, 'tzinfo', None) else v
                if _tf is not None and vn < _tf: return False
                if _tt is not None and vn > _tt: return False
                return True
            rows = [r for r in rows if _ok(r)]
        if not rows:
            return 0
        n = len(rows)
        # Inserción en bloque columna a columna: en vez de una sentencia por
        # fila (executemany, ~900 filas/s en DuckDB), se pasan las columnas como
        # listas y DuckDB las "zipa" con unnest en un solo INSERT ... SELECT.
        # ~100x más rápido y sin dependencias extra (ni pandas ni pyarrow).
        colnames = ["id"] + list(COLUMN_NAMES)
        with self._lock:
            start = self._next_id
            self._next_id = start + n
            params: list[list] = [list(range(start, start + n))]
            for ci in range(len(COLUMN_NAMES)):
                params.append([r[ci] for r in rows])
            collist = ", ".join(f'"{c}"' for c in colnames)
            sel = ", ".join(f'unnest(?) AS "{c}"' for c in colnames)
            self._con.execute(
                f"INSERT INTO events ({collist}) "
                f"SELECT {collist} FROM (SELECT {sel})", params
            )
            self._seq_dirty = True  # timeline positions must be recomputed
        return n

    # ------------------------------------------------------------------
    # Explorador: búsqueda por string/regex y contexto ±N.
    # El nº visible '#' (seq) es la POSICIÓN EN LA TIMELINE: 1 = el evento
    # más antiguo (orden por ts; los sin timestamp van al final). Se calcula
    # dinámicamente, así que si cargas más logs se renumera solo.
    # ------------------------------------------------------------------
    # campos mostrados (sin seq/id, que se añaden alrededor) — todas las
    # columnas parseadas útiles, para verlas en la tabla de resultados
    _FIELDS = ["ts", "source", "host", "program", "event", "eid", "level",
               "user", "sid", "src_ip", "dst_ip", "image", "command_line",
               "parent_image", "original_filename", "hashes", "target_filename",
               "image_loaded", "logon_type", "record_id", "message",
               "extra", "src_file"]
    # subconsulta que asigna seq (posición temporal) a cada id. Lee de la
    # tabla materializada `seqmap` (reconstruida por _ensure_seqmap tras cada
    # ingesta), en vez de recalcular el window sort en cada consulta.
    _SEQ_SQL = "SELECT id, seq FROM seqmap"

    def _fields_sql(self, prefix: str = "") -> str:
        return ", ".join(f'{prefix}"{c}"' for c in self._FIELDS)

    def _order_clause(self, sort: Optional[str], desc: bool) -> str:
        """ORDER BY seguro (whitelist). Por defecto, cronológico (ts, id).

        Admite ordenar por una clave dinámica de `extra` con el prefijo
        'x:' (p.ej. sort='x:widget' -> ORDER BY (ev.extra->>'widget')).
        """
        d = "DESC" if desc else "ASC"
        if not sort or sort in ("seq", "ts"):
            return f"ORDER BY ev.ts {d} NULLS LAST, ev.id {d}"
        if sort.startswith("x:"):
            key = sort[2:]
            if re.fullmatch(r"[\w.\-]{1,64}", key or ""):
                return (f"ORDER BY (ev.extra->>'{key}') {d} NULLS LAST, ev.id")
            return "ORDER BY ev.ts NULLS LAST, ev.id"
        if sort not in COLUMN_NAMES:
            return "ORDER BY ev.ts NULLS LAST, ev.id"
        return f'ORDER BY ev."{sort}" {d} NULLS LAST, ev.id'

    def extra_keys(self) -> list[str]:
        """Claves de nivel superior presentes en la columna `extra` (JSON).

        Sirven para ofrecer columnas dinámicas en la tabla con los campos
        auto-generados de logs desconocidos (logfmt, etc.)."""
        with self._lock:
            try:
                rows = self._con.execute(
                    "SELECT DISTINCT unnest(json_keys(extra)) AS k "
                    "FROM events WHERE extra IS NOT NULL ORDER BY k"
                ).fetchall()
            except duckdb.Error:
                return []
        return [r[0] for r in rows if r[0]]

    @staticmethod
    def _like_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _field_expr(self, field: str, prefix: str = ""):
        """Resuelve un nombre de campo a (expr_sql, es_numerico).

        Con prefijo x: / extra. apunta a una clave del JSON extra. Sin prefijo,
        solo acepta columnas reales o alias (ip->src_ip, id->eid…); un nombre
        desconocido devuelve None (para que se trate como texto libre y no
        rompa búsquedas con : o = en su interior)."""
        if prefix:                       # x: o extra. -> clave del JSON extra
            key = field.strip()          # se respeta el case (EventData es PascalCase)
            if re.fullmatch(r"[\w.\-]{1,64}", key):
                return f"(ev.extra->>'{key}')", False
            return None
        f = field.strip().lower()
        f = self._FIELD_ALIASES.get(f, f)
        if f in COLUMN_NAMES:
            return f'ev."{f}"', (f in self._NUM_COLS)
        return None

    def _clause_for_token(self, tok: str):
        """Traduce un token de búsqueda a (fragmento_sql, params).

        Admite regex por token (combinable con campos, NOT y AND):
        /patrón/ busca por regex en el texto completo, y campo:/patrón/ aplica
        la regex solo a ese campo. Para valores con espacios, entrecomilla el
        token: "command_line:/foo bar/"."""
        neg = False
        t = tok
        if t.startswith("-") and len(t) > 1:
            neg, t = True, t[1:]
        frag, params = None, []
        # /regex/ libre sobre el texto completo
        if len(t) > 2 and t.startswith("/") and t.endswith("/"):
            frag = f"regexp_matches({self._REGEX_TEXT}, ?, 'i')"
            params = [t[1:-1]]
        if frag is None:
            m = re.match(r"^((?:x:|extra\.))?([\w.\-]+?)(!=|=|:)(.*)$", t)
            if m:
                fx = self._field_expr(m.group(2), m.group(1) or "")
                if fx is not None:
                    expr, is_num = fx
                    op, val = m.group(3), m.group(4)
                    is_re = (op == ":" and len(val) > 2
                             and val.startswith("/") and val.endswith("/"))
                    if val == "*" and op in (":", "="):   # existe (con contenido)
                        frag = (f"({expr} IS NOT NULL AND "
                                f"CAST({expr} AS VARCHAR) <> '')")
                    elif val == "-" and op in (":", "="):  # vacío o nulo
                        frag = (f"({expr} IS NULL OR "
                                f"CAST({expr} AS VARCHAR) = '')")
                    elif is_re:                           # campo:/regex/
                        frag = f"regexp_matches(CAST({expr} AS VARCHAR), ?, 'i')"
                        params = [val[1:-1]]
                    elif op == ":":                     # contiene
                        frag = f"CAST({expr} AS VARCHAR) ILIKE ? ESCAPE '\\'"
                        params = [f"%{self._like_escape(val)}%"]
                    elif op == "=":                     # exacto
                        if is_num and re.fullmatch(r"-?\d+", val):
                            frag, params = f"{expr} = ?", [int(val)]
                        else:
                            frag = f"lower(CAST({expr} AS VARCHAR)) = lower(?)"
                            params = [val]
                    else:                               # != (no exacto)
                        frag = (f"({expr} IS NULL OR "
                                f"lower(CAST({expr} AS VARCHAR)) <> lower(?))")
                        params = [val]
        if frag is None:                            # texto libre
            frag = f"{self._SEARCH_TEXT} ILIKE ? ESCAPE '\\'"
            params = [f"%{self._like_escape(t)}%"]
        if neg:
            frag = f"NOT coalesce({frag}, FALSE)"
        return frag, params

    @staticmethod
    def _pre_contains(q: str) -> str:
        """Acepta la forma con palabra: «campo contains valor» -> campo:valor."""
        return re.sub(r'(?i)\b([\w.]+)\s+contains\s+("[^"]*"|\S+)',
                      lambda m: m.group(1) + ":" + m.group(2).strip('"'), q)

    @staticmethod
    def _tokenize(q: str) -> list[str]:
        """Separa por espacios respetando comillas, SIN tocar las barras
        invertidas (shlex se las comería y rompería las regex /\\s+\\w+/)."""
        toks: list[str] = []
        cur = ""
        quote = None
        for c in q:
            if quote:
                if c == quote:
                    quote = None
                else:
                    cur += c
            elif c in "\"'":
                quote = c
            elif c.isspace():
                if cur:
                    toks.append(cur)
                    cur = ""
            else:
                cur += c
        if cur:
            toks.append(cur)
        return toks

    def _parse_search(self, q: str):
        """Tokeniza respetando comillas y devuelve (where_frags, params)."""
        q = self._pre_contains(q)
        frags: list[str] = []
        params: list[Any] = []
        for tok in self._tokenize(q):
            if not tok:
                continue
            fr, ps = self._clause_for_token(tok)
            frags.append(fr)
            params.extend(ps)
        return frags, params

    def _facet_where(self, q: str, regex: bool, source: Optional[str],
                     start: Optional[str], end: Optional[str],
                     eid: Optional[str]):
        """WHERE común (mismo criterio que la búsqueda) para las facetas."""
        where: list[str] = []
        params: list[Any] = []
        q = (q or "").strip()
        if q:
            if regex:
                where.append(f"regexp_matches({self._REGEX_TEXT}, ?, 'i')")
                params.append(q)
            else:
                frags, fp = self._parse_search(q)
                where.extend(frags)
                params.extend(fp)
        if source and source not in ("", "(todos)", "(all)"):
            where.append("ev.source = ?")
            params.append(source)
        if eid not in (None, "", "(all)"):
            where.append("CAST(ev.eid AS VARCHAR) = ?")
            params.append(str(eid).strip())
        if start:
            where.append("ev.ts >= ?")
            params.append(start)
        if end:
            where.append("ev.ts <= ?")
            params.append(end)
        return (" AND ".join(where) if where else "TRUE"), params

    def _facet_expr(self, field: str):
        """Expresión SQL del campo a facetar: columna real o clave de extra."""
        f = (field or "").strip()
        if f.startswith("x:"):
            f = f[2:]
        elif f.startswith("extra."):
            f = f[6:]
        else:
            fl = self._FIELD_ALIASES.get(f.lower(), f.lower())
            if fl in COLUMN_NAMES:
                return f'ev."{fl}"'
        if re.fullmatch(r"[\w.\-]{1,64}", f):
            return f"(ev.extra->>'{f}')"
        return None

    def facet(self, field: str, q: str = "", regex: bool = False,
              source: Optional[str] = None, start: Optional[str] = None,
              end: Optional[str] = None, eid: Optional[str] = None,
              limit: int = 20) -> dict[str, Any]:
        """Top-N valores de un campo sobre el resultado de búsqueda actual."""
        expr = self._facet_expr(field)
        if expr is None:
            raise ValueError(f"Campo no válido para facetas: {field!r}")
        cond, params = self._facet_where(q, regex, source, start, end, eid)
        sql = (f"SELECT CAST({expr} AS VARCHAR) AS v, count(*) AS n "
               f"FROM events ev WHERE {cond} "
               f"AND {expr} IS NOT NULL AND CAST({expr} AS VARCHAR) <> '' "
               f"GROUP BY v ORDER BY n DESC, v LIMIT ?")
        with self._lock:
            matched = self._con.execute(
                f"SELECT count(*) FROM events ev WHERE {cond}", params).fetchone()[0]
            distinct = self._con.execute(
                f"SELECT count(DISTINCT CAST({expr} AS VARCHAR)) FROM events ev "
                f"WHERE {cond} AND {expr} IS NOT NULL AND CAST({expr} AS VARCHAR)<>''",
                params).fetchone()[0]
            rows = self._con.execute(sql, params + [int(limit)]).fetchall()
        return {"field": field, "matched": matched, "distinct": distinct,
                "values": [{"value": r[0], "count": r[1]} for r in rows]}

    def search(self, q: str, regex: bool = False, source: Optional[str] = None,
               limit: int = 500, offset: int = 0, sort: Optional[str] = None,
               desc: bool = False, start: Optional[str] = None,
               end: Optional[str] = None, eid: Optional[str] = None) -> dict[str, Any]:
        q = (q or "").strip()
        if not q:
            raise ValueError("Consulta de búsqueda vacía.")
        where = []
        params: list[Any] = []
        if regex:
            where.append(f"regexp_matches({self._REGEX_TEXT}, ?, 'i')")
            params.append(q)
        else:
            # sintaxis avanzada: texto libre + campo:valor + exacto + NOT
            frags, fparams = self._parse_search(q)
            if not frags:
                raise ValueError("Consulta de búsqueda vacía.")
            where.extend(frags)
            params.extend(fparams)
        if source and source not in ("", "(todos)", "(all)"):
            where.append("ev.source = ?")
            params.append(source)
        if eid not in (None, "", "(all)"):
            where.append("CAST(ev.eid AS VARCHAR) = ?")
            params.append(str(eid).strip())
        if start:                      # filtro temporal global (UTC)
            where.append("ev.ts >= ?")
            params.append(start)
        if end:
            where.append("ev.ts <= ?")
            params.append(end)
        cond = " AND ".join(where)
        self._ensure_seqmap()
        # se une con seq para mostrar la posición temporal de cada hit.
        # count(*) OVER () da el total en el MISMO escaneo que el SELECT, así
        # se evita un segundo recorrido completo de la tabla solo para contar.
        sql = (f"SELECT o.seq, {self._fields_sql('ev.')}, ev.id, "
               f"count(*) OVER () AS __total "
               f"FROM events ev JOIN ({self._SEQ_SQL}) o ON ev.id = o.id "
               f"WHERE {cond} {self._order_clause(sort, desc)} LIMIT ? OFFSET ?")
        with self._lock:
            cur = self._con.execute(sql, params + [int(limit), int(offset)])
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
            if rows:
                total = rows[0][-1]
            else:
                # página vacía (p. ej. offset más allá del final, o sin
                # coincidencias): recurrimos a un count directo.
                total = self._con.execute(
                    f"SELECT count(*) FROM events ev WHERE {cond}",
                    params).fetchone()[0]
        names = names[:-1]
        rows = [r[:-1] for r in rows]
        return {"columns": names,
                "rows": [[_jsonable(v) for v in r] for r in rows],
                "rowcount": len(rows), "total": total, "offset": int(offset)}

    def timeline(self, source: Optional[str] = None, limit: int = 2000,
                 offset: int = 0, start: Optional[str] = None,
                 end: Optional[str] = None, sort: Optional[str] = None,
                 desc: bool = False, eid: Optional[str] = None) -> dict[str, Any]:
        """Timeline completa: todos los eventos en orden cronológico, con su
        seq. Admite filtro por origen, EventID, rango temporal (start/end, UTC)
        y paginación (limit/offset)."""
        conds: list[str] = []
        params: list[Any] = []
        if source and source not in ("", "(todos)", "(all)"):
            conds.append("ev.source = ?")
            params.append(source)
        if eid not in (None, "", "(all)"):
            conds.append("CAST(ev.eid AS VARCHAR) = ?")
            params.append(str(eid).strip())
        if start:
            conds.append("ev.ts >= ?")
            params.append(start)
        if end:
            conds.append("ev.ts <= ?")
            params.append(end)
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        self._ensure_seqmap()
        sql = (f"SELECT o.seq, {self._fields_sql('ev.')}, ev.id, "
               f"count(*) OVER () AS __total "
               f"FROM events ev JOIN ({self._SEQ_SQL}) o ON ev.id = o.id "
               f"{where} {self._order_clause(sort, desc)} LIMIT ? OFFSET ?")
        with self._lock:
            cur = self._con.execute(sql, params + [int(limit), int(offset)])
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
            if rows:
                total = rows[0][-1]
            else:
                total = self._con.execute(
                    f"SELECT count(*) FROM events ev {where}",
                    params).fetchone()[0]
        names = names[:-1]
        rows = [r[:-1] for r in rows]
        return {"columns": names,
                "rows": [[_jsonable(v) for v in r] for r in rows],
                "rowcount": len(rows), "total": total, "offset": int(offset)}

    def context(self, row_id: Optional[int] = None, before: float = 5,
                after: float = 5, unit: str = "lines",
                seq: Optional[int] = None) -> dict[str, Any]:
        """Contexto alrededor de una línea.

        Se ancla por `row_id` (id interno, exacto) o por `seq` (posición en la
        timeline, 1 = más antiguo). unit: 'lines' | 'minutes' | 'seconds'.
        """
        self._ensure_seqmap()
        if seq is not None and row_id is None:
            with self._lock:
                r = self._con.execute(
                    "SELECT id FROM seqmap WHERE seq = ?",
                    [int(seq)]).fetchone()
            if not r:
                return {"columns": [], "rows": [], "rowcount": 0,
                        "note": f"No existe el #{int(seq)}."}
            row_id = r[0]
        if row_id is None:
            raise ValueError("Falta el ancla (id o seq).")
        row_id = int(row_id)
        if unit in ("minutes", "seconds"):
            return self._context_time(row_id, before, after, unit)
        return self._context_lines(row_id, int(before), int(after))

    def _context_lines(self, row_id: int, before: int, after: int) -> dict[str, Any]:
        before = max(0, min(before, 5000))
        after = max(0, min(after, 5000))
        # Usa la tabla materializada `seqmap`: localiza la posición del ancla
        # por índice y proyecta las columnas grandes (message/extra/…) SOLO de
        # la ventana ±N, en vez de materializar toda la tabla por consulta.
        sql = f"""
            WITH t AS (SELECT seq FROM seqmap WHERE id = ?)
            SELECT s.seq, {self._fields_sql('ev.')}, ev.id, (ev.id = ?) AS is_match
            FROM seqmap s
            JOIN t ON s.seq BETWEEN t.seq - ? AND t.seq + ?
            JOIN events ev ON ev.id = s.id
            ORDER BY s.seq
        """
        with self._lock:
            cur = self._con.execute(sql, [row_id, row_id, before, after])
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
        return {"columns": names, "mode": "lines",
                "rows": [[_jsonable(v) for v in r] for r in rows],
                "rowcount": len(rows)}

    _CTX_TIME_LIMIT = 800  # tope de filas para proteger la UI (ventanas densas)

    def _context_time(self, row_id: int, before: float, after: float,
                      unit: str) -> dict[str, Any]:
        factor = 60 if unit == "minutes" else 1
        before_s = max(0, before * factor)
        after_s = max(0, after * factor)
        join = f"FROM events ev JOIN ({self._SEQ_SQL}) o ON ev.id = o.id"
        sel = f"SELECT o.seq, {self._fields_sql('ev.')}, ev.id"
        with self._lock:
            anchor = self._con.execute(
                "SELECT ts FROM events WHERE id = ?", [row_id]).fetchone()
            anchor_ts = anchor[0] if anchor else None
            if anchor_ts is None:
                # sin timestamp no se puede abrir ventana temporal
                cur = self._con.execute(
                    f"{sel}, TRUE AS is_match {join} WHERE ev.id = ?", [row_id])
                names = [d[0] for d in cur.description]
                rows = cur.fetchall()
                return {"columns": names, "mode": "time", "rowcount": len(rows),
                        "rows": [[_jsonable(v) for v in r] for r in rows],
                        "note": "Esta línea no tiene timestamp; usa contexto por líneas."}
            sql = f"""
                {sel}, (ev.id = ?) AS is_match {join}
                WHERE ev.ts BETWEEN (? - (? * INTERVAL 1 SECOND))
                                AND (? + (? * INTERVAL 1 SECOND))
                ORDER BY ev.ts NULLS LAST, ev.id
                LIMIT {self._CTX_TIME_LIMIT + 1}
            """
            cur = self._con.execute(
                sql, [row_id, anchor_ts, before_s, anchor_ts, after_s])
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
        truncated = len(rows) > self._CTX_TIME_LIMIT
        rows = rows[: self._CTX_TIME_LIMIT]
        out = {"columns": names, "mode": "time",
               "rows": [[_jsonable(v) for v in r] for r in rows],
               "rowcount": len(rows),
               "window": f"±{before if unit=='minutes' else before_s} "
                         f"{'min' if unit=='minutes' else 's'}"}
        if truncated:
            out["note"] = f"Ventana muy amplia: mostrando las primeras {self._CTX_TIME_LIMIT} líneas."
        return out

    def query(self, sql: str, params: Optional[list] = None,
              limit: Optional[int] = 1000) -> dict[str, Any]:
        """Ejecuta SQL de solo lectura y devuelve columnas + filas.

        Se fuerza modo lectura por sesión para que una query no pueda
        alterar los datos forenses cargados.
        """
        stripped = sql.strip().rstrip(";")
        lowered = stripped.lower()
        if not (lowered.startswith("select") or lowered.startswith("with")
                or lowered.startswith("pragma") or lowered.startswith("describe")
                or lowered.startswith("summarize") or lowered.startswith("show")):
            raise ValueError("Solo se permiten consultas de lectura (SELECT/WITH/DESCRIBE/SUMMARIZE).")
        # Envolver con LIMIT si el usuario no puso uno y es un SELECT simple.
        if limit is not None and " limit " not in lowered and lowered.startswith("select"):
            stripped = f"SELECT * FROM ({stripped}) LIMIT {int(limit)}"
        with self._lock:
            cur = self._con.execute(stripped, params or [])
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchall()
        # serializar valores no-JSON (datetime) a iso
        out_rows = []
        for r in rows:
            out_rows.append([_jsonable(v) for v in r])
        return {"columns": cols, "rows": out_rows, "rowcount": len(out_rows)}

    # ------------------------------------------------------------------
    # Soporte del motor Sigma (where_sql lo construye sigma_engine).
    # ------------------------------------------------------------------
    def logsource_present(self, predicate: str) -> bool:
        """True si hay algún evento Sigma-apto de ese logsource (data-driven)."""
        with self._lock:
            try:
                row = self._con.execute(
                    f"SELECT 1 FROM events ev WHERE sigma_ok=1 AND ({predicate}) LIMIT 1"
                ).fetchone()
            except duckdb.Error:
                return False
        return bool(row)

    def sigma_run(self, where_sql: str, limit: int = 200,
                  extra_selects: Optional[list] = None) -> dict[str, Any]:
        """Ejecuta el WHERE de una regla: total de hits + muestra con su seq.
        extra_selects = [(alias, expr)] añade columnas (los campos que la regla
        referencia) para mostrar 'qué hizo match' en cada hit."""
        extra = ""
        if extra_selects:
            extra = ", " + ", ".join(f"{expr} AS {alias}"
                                     for alias, expr in extra_selects)
        self._ensure_seqmap()   # el SELECT de muestra se une con seqmap
        with self._lock:
            total = self._con.execute(
                f"SELECT count(*) FROM events ev WHERE {where_sql}").fetchone()[0]
            sql = (f"SELECT o.seq, ev.id, ev.ts, ev.source, ev.program, "
                   f"coalesce(ev.message, ev.raw) AS detalle, ev.src_file{extra} "
                   f"FROM events ev JOIN ({self._SEQ_SQL}) o ON ev.id = o.id "
                   f"WHERE {where_sql} ORDER BY ev.ts NULLS LAST, ev.id LIMIT ?")
            cur = self._con.execute(sql, [int(limit)])
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
        return {"total": total, "columns": names,
                "rows": [[_jsonable(v) for v in r] for r in rows]}

    def sigma_select(self, sql: str) -> dict[str, Any]:
        """SELECT/WITH interno del motor Sigma (correlación). Solo lectura."""
        low = sql.strip().lower()
        if not (low.startswith("select") or low.startswith("with")):
            raise ValueError("sigma_select solo admite SELECT/WITH.")
        with self._lock:
            cur = self._con.execute(sql)
            names = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchall()
        return {"columns": names, "rows": [[_jsonable(v) for v in r] for r in rows]}

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self._con.execute("SELECT count(*) FROM events").fetchone()[0]
            by_source = self._con.execute(
                "SELECT source, count(*) c, min(ts) tmin, max(ts) tmax "
                "FROM events GROUP BY source ORDER BY c DESC"
            ).fetchall()
            by_file = self._con.execute(
                "SELECT src_file, count(*) c FROM events GROUP BY src_file ORDER BY c DESC"
            ).fetchall()
            by_eid = self._con.execute(
                "SELECT eid, count(*) c FROM events WHERE eid IS NOT NULL "
                "GROUP BY eid ORDER BY eid"
            ).fetchall()
        return {
            "total_events": total,
            "by_source": [
                {"source": s, "count": c,
                 "ts_min": _jsonable(tmin), "ts_max": _jsonable(tmax)}
                for s, c, tmin, tmax in by_source
            ],
            "by_eid": [{"eid": e, "count": c} for e, c in by_eid],
            "by_file": [{"src_file": f, "count": c} for f, c in by_file],
            "extra_keys": self.extra_keys(),
        }

    def _hist_adaptive(self, nbuckets: int = 120) -> list:
        """Histograma temporal en ~nbuckets cubos de igual anchura (relleno con
        ceros). Evita el caso de agrupar por hora sobre rangos de años (miles de
        barras vacías). Devuelve [(ts_inicio_cubo, count)]."""
        import datetime as _dt
        with self._lock:
            mm = self._con.execute(
                "SELECT min(ts), max(ts) FROM events WHERE ts IS NOT NULL").fetchone()
        if not mm or mm[0] is None or mm[1] is None:
            return []
        tmn, tmx = mm[0], mm[1]
        span = (tmx - tmn).total_seconds()
        if span <= 0:
            with self._lock:
                n = self._con.execute(
                    "SELECT count(*) FROM events WHERE ts IS NOT NULL").fetchone()[0]
            return [(tmn, n)]
        bsec = span / nbuckets
        with self._lock:
            rows = self._con.execute(
                "SELECT CAST(floor((epoch(ts)-epoch(?::TIMESTAMP))/?) AS BIGINT) b, "
                "count(*) n FROM events WHERE ts IS NOT NULL GROUP BY b",
                [tmn, bsec]).fetchall()
        counts: dict = {}
        for b, n in rows:
            if b is None:
                continue
            i = min(int(b), nbuckets - 1)
            counts[i] = counts.get(i, 0) + n
        return [(tmn + _dt.timedelta(seconds=bsec * i), counts.get(i, 0))
                for i in range(nbuckets)]

    def dashboard(self, top_n: int = 10) -> dict[str, Any]:
        """Agregados para la pestaña Resumen (Windows): totales, rango, tops."""
        q_top = ("SELECT {c}, count(*) n FROM events "
                 "WHERE {c} IS NOT NULL AND CAST({c} AS VARCHAR)<>'' "
                 "GROUP BY {c} ORDER BY n DESC LIMIT ?")
        img = "lower(regexp_extract(coalesce(image,''),'([^\\\\/]+)$',1))"
        with self._lock:
            total = self._con.execute("SELECT count(*) FROM events").fetchone()[0]
            tmin, tmax = self._con.execute(
                "SELECT min(ts), max(ts) FROM events WHERE ts IS NOT NULL").fetchone()
            n_ip = self._con.execute(
                "SELECT count(DISTINCT x) FROM ("
                "SELECT src_ip x FROM events WHERE src_ip IS NOT NULL "
                "UNION SELECT dst_ip FROM events WHERE dst_ip IS NOT NULL)").fetchone()[0]
            n_user = self._con.execute(
                'SELECT count(DISTINCT "user") FROM events WHERE "user" IS NOT NULL').fetchone()[0]
            n_host = self._con.execute(
                "SELECT count(DISTINCT host) FROM events WHERE host IS NOT NULL").fetchone()[0]
            n_file = self._con.execute(
                "SELECT count(DISTINCT src_file) FROM events").fetchone()[0]
            by_source = self._con.execute(
                "SELECT source, count(*) n FROM events GROUP BY source ORDER BY n DESC").fetchall()
            lvl = self._con.execute(
                "SELECT coalesce(level,'—') s, count(*) n FROM events "
                "GROUP BY s ORDER BY n DESC").fetchall()
            top_eid = self._con.execute(
                "SELECT program || ' / ' || event AS k, count(*) n FROM events "
                "WHERE eid IS NOT NULL GROUP BY k ORDER BY n DESC LIMIT ?", [top_n]).fetchall()
            top_user = self._con.execute(q_top.format(c='"user"'), [top_n]).fetchall()
            top_host = self._con.execute(q_top.format(c="host"), [top_n]).fetchall()
            top_logon = self._con.execute(q_top.format(c="logon_type"), [top_n]).fetchall()
            top_img = self._con.execute(
                f"SELECT {img} b, count(*) n FROM events "
                "WHERE image IS NOT NULL AND image<>'' GROUP BY b ORDER BY n DESC LIMIT ?",
                [top_n]).fetchall()
            top_dst = self._con.execute(q_top.format(c="dst_ip"), [top_n]).fetchall()
            top_src = self._con.execute(q_top.format(c="src_ip"), [top_n]).fetchall()
            hist = self._hist_adaptive()
        def pairs(rows):
            return [{"k": ("" if k is None else str(k)), "n": n} for k, n in rows]
        return {
            "total": total,
            "ts_min": _jsonable(tmin), "ts_max": _jsonable(tmax),
            "distinct": {"ip": n_ip, "user": n_user, "host": n_host,
                         "file": n_file, "source": len(by_source)},
            "by_source": pairs(by_source),
            "level": pairs(lvl),
            "top_eid": pairs(top_eid),
            "top_user": pairs(top_user),
            "top_host": pairs(top_host),
            "top_logon": pairs(top_logon),
            "top_image": pairs(top_img),
            "top_dst_ip": pairs(top_dst),
            "top_src_ip": pairs(top_src),
            "hist": [{"h": _jsonable(h), "n": n} for h, n in hist],
        }

    # ------------------------------------------------------------------
    # Marcas / triage (persistidas en el .duckdb del caso)
    # ------------------------------------------------------------------
    def _mark_context(self, event_id: int, n: int = 10) -> Optional[str]:
        """Snapshot de texto del contexto alrededor de un evento (±n/2 por
        posición en la timeline), congelado en el momento de marcar."""
        if event_id is None:
            return None
        half = max(1, n // 2)
        self._ensure_seqmap()
        try:
            with self._lock:
                rows = self._con.execute(
                    "WITH t AS (SELECT seq FROM seqmap WHERE id = ?) "
                    "SELECT s.seq, ev.ts, ev.source, ev.eid, "
                    "coalesce(nullif(ev.message,''), ev.command_line, ev.image, "
                    "ev.target_filename, ev.raw) AS det, (ev.id = ?) AS hit "
                    "FROM seqmap s JOIN t ON s.seq BETWEEN t.seq-? AND t.seq+? "
                    "JOIN events ev ON ev.id = s.id ORDER BY s.seq",
                    [event_id, event_id, half, half]).fetchall()
        except duckdb.Error:
            return None
        lines = []
        for r in rows:
            mark = ">> " if r[5] else "   "
            det = (str(r[4])[:200] if r[4] is not None else "")
            lines.append(f"{mark}#{r[0]} {_jsonable(r[1])} [{r[2]}/{r[3]}] {det}")
        return "\n".join(lines) if lines else None

    def mark_add(self, event_id: Optional[int], estado: str = "pendiente",
                 etiqueta: Optional[str] = None, nota: Optional[str] = None,
                 regla: Optional[str] = None, ctx_n: int = 10) -> dict:
        import datetime as _dt
        creado = _dt.datetime.utcnow().isoformat(sep=" ", timespec="seconds")
        contexto = self._mark_context(event_id, ctx_n) if event_id is not None else None
        with self._lock:
            mid = self._mark_next
            self._mark_next += 1
            self._con.execute(
                "INSERT INTO marcas (mid, event_id, estado, etiqueta, nota, "
                "creado, contexto, regla) VALUES (?,?,?,?,?,?,?,?)",
                [mid, event_id, estado, etiqueta, nota, creado, contexto, regla])
        return {"mid": mid}

    def mark_list(self, estado: Optional[str] = None) -> list[dict]:
        where, params = "", []
        if estado:
            where = "WHERE m.estado = ?"
            params = [estado]
        sql = (
            f"WITH seq AS ({self._SEQ_SQL})\n"
            "SELECT m.mid, m.event_id, m.estado, m.etiqueta, m.nota, m.creado,\n"
            "  s.seq, ev.ts, ev.source, ev.\"user\",\n"
            "  coalesce(nullif(ev.message,''), ev.command_line, ev.image,\n"
            "           ev.target_filename, ev.raw) AS detalle,\n"
            "  m.contexto, m.regla\n"
            "FROM marcas m\n"
            "LEFT JOIN events ev ON ev.id = m.event_id\n"
            "LEFT JOIN seq s ON s.id = m.event_id\n"
            f"{where} ORDER BY m.creado DESC")
        self._ensure_seqmap()
        with self._lock:
            rows = self._con.execute(sql, params).fetchall()
        return [{"mid": r[0], "event_id": r[1], "estado": r[2], "etiqueta": r[3],
                 "nota": r[4], "creado": r[5], "seq": r[6], "ts": _jsonable(r[7]),
                 "source": r[8], "user": r[9], "detalle": r[10],
                 "contexto": r[11], "regla": r[12]} for r in rows]

    def mark_counts(self) -> dict:
        with self._lock:
            rows = self._con.execute(
                "SELECT estado, count(*) FROM marcas GROUP BY estado").fetchall()
        return {e: n for e, n in rows}

    def mark_update(self, mid: int, estado: Optional[str] = None,
                    etiqueta: Optional[str] = None, nota: Optional[str] = None) -> bool:
        sets, params = [], []
        if estado is not None:
            sets.append("estado = ?"); params.append(estado)
        if etiqueta is not None:
            sets.append("etiqueta = ?"); params.append(etiqueta)
        if nota is not None:
            sets.append("nota = ?"); params.append(nota)
        if not sets:
            return False
        params.append(mid)
        with self._lock:
            self._con.execute(
                f"UPDATE marcas SET {', '.join(sets)} WHERE mid = ?", params)
        return True

    def mark_delete(self, mid: int) -> bool:
        with self._lock:
            self._con.execute("DELETE FROM marcas WHERE mid = ?", [mid])
        return True

    def ip_detail(self, ip: str, samples: int = 10) -> dict[str, Any]:
        """Resumen de una IP (origen o destino): totales, primera/última vez,
        desglose por canal, logons fallidos (4625) y eventos de muestra."""
        w = "(src_ip = ? OR dst_ip = ?)"
        p = [ip, ip]
        with self._lock:
            total = self._con.execute(
                f"SELECT count(*) FROM events WHERE {w}", p).fetchone()[0]
            tmin, tmax = self._con.execute(
                f"SELECT min(ts), max(ts) FROM events WHERE {w} AND ts IS NOT NULL",
                p).fetchone()
            by_source = self._con.execute(
                f"SELECT source, count(*) n FROM events WHERE {w} "
                "GROUP BY source ORDER BY n DESC", p).fetchall()
            fails = self._con.execute(
                f"SELECT count(*) FROM events WHERE {w} AND eid = 4625", p).fetchone()[0]
            users = self._con.execute(
                f'SELECT "user", count(*) n FROM events WHERE {w} '
                'AND "user" IS NOT NULL GROUP BY "user" ORDER BY n DESC LIMIT 8',
                p).fetchall()
            rows = self._con.execute(
                f'SELECT id, ts, source, "user", coalesce(message, raw) AS detalle '
                f"FROM events WHERE {w} ORDER BY ts NULLS LAST, id LIMIT ?",
                p + [samples]).fetchall()
        return {
            "ip": ip, "total": total,
            "ts_min": _jsonable(tmin), "ts_max": _jsonable(tmax),
            "fails": fails,
            "by_source": [{"k": s, "n": n} for s, n in by_source],
            "users": [{"k": ("" if u is None else str(u)), "n": n} for u, n in users],
            "samples": [{"id": r[0], "ts": _jsonable(r[1]), "source": r[2],
                         "user": r[3], "detalle": r[4]} for r in rows],
        }

    def ip_counts(self) -> list[tuple]:
        """(ip, nº eventos) para TODAS las IPs (origen+destino) para agrupar por
        ISP/país."""
        with self._lock:
            return self._con.execute(
                "SELECT ip, sum(n) n FROM ("
                "  SELECT src_ip ip, count(*) n FROM events "
                "WHERE src_ip IS NOT NULL AND src_ip<>'' GROUP BY src_ip "
                "  UNION ALL "
                "  SELECT dst_ip ip, count(*) n FROM events "
                "WHERE dst_ip IS NOT NULL AND dst_ip<>'' GROUP BY dst_ip"
                ") GROUP BY ip").fetchall()

    # ------------------------------------------------------------------
    # Lookalike / masquerading: nombres de binario (basename de Image) con
    # distancia de Levenshtein <= N respecto a una referencia (sistema/LOLBAS),
    # excluyendo la coincidencia exacta (distancia 0 = el legítimo).
    # ------------------------------------------------------------------
    _IMG_BASE = r"lower(regexp_extract(coalesce(image,''),'([^\\/]+)$',1))"

    def lol_chart(self, where_sql: str, indicator_sql: str,
                  limit: int = 15) -> list[tuple]:
        """Top indicador (p.ej. binario/driver) por nº de EVENTOS que hacen hit
        en el WHERE combinado de un conjunto de reglas."""
        sql = (f"SELECT {indicator_sql} k, count(*) n FROM events ev "
               f"WHERE ({where_sql}) GROUP BY k HAVING k IS NOT NULL AND k<>'' "
               f"ORDER BY n DESC LIMIT {int(limit)}")
        with self._lock:
            return self._con.execute(sql).fetchall()

    def distinct_images(self) -> list[tuple]:
        """(basename de Image, nº eventos) distintos."""
        with self._lock:
            return self._con.execute(
                f"SELECT {self._IMG_BASE} b, count(*) n FROM events "
                "WHERE image IS NOT NULL AND image<>'' GROUP BY b "
                "HAVING b<>'' ORDER BY n DESC").fetchall()

    def lookalike(self, refs: list[str], max_dist: int = 2,
                  also_seen: bool = False) -> list[dict[str, Any]]:
        """Binarios vistos cuyo nombre (basename de Image) está a distancia
        1..max_dist de una referencia legítima (sistema/LOLBAS), excluyendo la
        coincidencia exacta. Si also_seen, compara también los vistos entre sí."""
        refs = [r.lower() for r in refs if r]
        out: list[dict] = []
        with self._lock:
            if refs:
                vals = ",".join("(?)" for _ in refs)
                sql = (
                    f"WITH imgs AS (SELECT {self._IMG_BASE} b, count(*) n, "
                    "min(id) sid FROM events "
                    "WHERE image IS NOT NULL AND image<>'' GROUP BY b HAVING b<>''), "
                    f"refs(r) AS (VALUES {vals}), "
                    "pairs AS (SELECT i.b, i.n, i.sid, r.r, levenshtein(i.b, r.r) d "
                    "FROM imgs i, refs r) "
                    "SELECT b, n, r, d, sid FROM pairs p WHERE d BETWEEN 1 AND ? "
                    "AND NOT EXISTS (SELECT 1 FROM refs r2 WHERE r2.r = p.b) "
                    "QUALIFY row_number() OVER (PARTITION BY b ORDER BY d) = 1 "
                    "ORDER BY d, n DESC")
                for b, n, r, d, sid in self._con.execute(
                        sql, refs + [max_dist]).fetchall():
                    out.append({"name": b, "count": n, "ref": r, "dist": d,
                                "kind": "ref", "id": sid})
            if also_seen:
                sql2 = (
                    f"WITH imgs AS (SELECT {self._IMG_BASE} b, count(*) n, "
                    "min(id) sid FROM events "
                    "WHERE image IS NOT NULL AND image<>'' GROUP BY b HAVING b<>'') "
                    "SELECT a.b, a.n, a.sid, c.b, c.n, c.sid, "
                    "levenshtein(a.b, c.b) d "
                    "FROM imgs a, imgs c WHERE a.b < c.b "
                    "AND levenshtein(a.b, c.b) BETWEEN 1 AND ? ORDER BY d, a.n DESC")
                for ab, an, asid, cb, cn, csid, d in self._con.execute(
                        sql2, [max_dist]).fetchall():
                    # el menos frecuente es el sospechoso frente al más común
                    if an <= cn:
                        sus, scount, ref, ssid = ab, an, cb, asid
                    else:
                        sus, scount, ref, ssid = cb, cn, ab, csid
                    out.append({"name": sus, "count": scount, "ref": ref,
                                "dist": d, "kind": "seen", "id": ssid})
        out.sort(key=lambda x: (x["dist"], -x["count"]))
        return out

    # ------------------------------------------------------------------
    # Fase 2: vistas avanzadas Windows
    # ------------------------------------------------------------------
    # Fuente "process_creation" estilo Sigma: Sysmon EID1 + Security 4688.
    # 4688 no tiene ProcessGuid, así que el enlace padre-hijo se hace por GUID
    # cuando existe (Sysmon) y, si no, por PID (ProcessId/NewProcessId, en hex
    # en 4688) dentro del mismo host y respetando el orden temporal.
    _PROC_WHERE = ("((source LIKE '%Sysmon%' AND eid=1) "
                   "OR (source='Security' AND eid=4688))")

    @staticmethod
    def _hexint(v):
        if v is None:
            return None
        s = str(v).strip()
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None

    def _proc_nodes(self) -> dict[int, dict]:
        """Carga los eventos de creación de proceso (Sysmon 1 + Security 4688)
        normalizados a un modelo común {id, ts, source, eid, host, guid, pguid,
        pid, ppid, image, cmd, parent_image, user}."""
        with self._lock:
            rows = self._con.execute(
                "SELECT id, ts, source, eid, host, "
                "(extra->>'ProcessGuid') pg, (extra->>'ParentProcessGuid') ppg, "
                "(extra->>'ProcessId') procid, (extra->>'ParentProcessId') sysppid, "
                "(extra->>'NewProcessId') newpid, "
                'image, command_line, parent_image, "user" '
                f"FROM events WHERE {self._PROC_WHERE} "
                "ORDER BY ts NULLS LAST, id").fetchall()
        nodes: dict[int, dict] = {}
        for r in rows:
            (rid, ts, source, eid, host, pg, ppg, procid, sysppid, newpid,
             image, cmd, pimg, user) = r
            if eid == 1:
                pid = self._hexint(procid)     # Sysmon: decimal
                ppid = self._hexint(sysppid)
                guid, pguid = pg, ppg
            else:                               # Security 4688
                pid = self._hexint(newpid)     # pid del nuevo proceso (hex)
                ppid = self._hexint(procid)    # pid del creador (hex)
                guid, pguid = None, None
            nodes[rid] = {"id": rid, "ts": _jsonable(ts), "_ts": ts,
                          "source": source, "eid": eid, "host": host,
                          "guid": guid, "pguid": pguid, "pid": pid, "ppid": ppid,
                          "image": image, "cmd": cmd, "parent_image": pimg,
                          "user": user, "children": []}
        # Dedupe: una misma creación puede venir por Sysmon(1) Y Security(4688).
        # Si hay un Sysmon con el mismo (host,pid) a <=5s, descartamos el 4688
        # (nos quedamos con Sysmon: trae GUID, línea de comandos y padre).
        sys_ts: dict = {}
        for n in nodes.values():
            if n["eid"] == 1 and n["pid"] is not None and n["_ts"] is not None:
                sys_ts.setdefault((n["host"], n["pid"]), []).append(n["_ts"])
        for lst in sys_ts.values():
            lst.sort()

        def _is_dup(n) -> bool:
            if n["eid"] != 4688 or n["pid"] is None or n["_ts"] is None:
                return False
            lst = sys_ts.get((n["host"], n["pid"]))
            if not lst:
                return False
            i = bisect.bisect_left(lst, n["_ts"])
            for j in (i - 1, i):
                if 0 <= j < len(lst) and abs((lst[j] - n["_ts"]).total_seconds()) <= 5:
                    return True
            return False

        return {i: n for i, n in nodes.items() if not _is_dup(n)}

    @staticmethod
    def _proc_seed_ids(nodes, pid=None, guid=None, image=None, node=None):
        if node is not None and str(node).strip():
            try:
                nid = int(str(node).strip())
            except ValueError:
                return []
            return [nid] if nid in nodes else []
        if guid and str(guid).strip():
            g = str(guid).strip()
            return [n["id"] for n in nodes.values() if n["guid"] == g]
        if pid is not None and str(pid).strip() != "":
            p = EventStore._hexint(pid)
            return [n["id"] for n in nodes.values() if n["pid"] == p and p is not None]
        if image and str(image).strip():
            low = str(image).strip().lower()
            return [n["id"] for n in nodes.values()
                    if (n["image"] or "").lower().find(low) >= 0]
        return []

    def proc_anchors(self, pid=None, guid=None, image=None,
                     limit: int = 50) -> list[dict]:
        """Procesos (Sysmon EID1 o Security 4688) que coinciden con el ancla,
        para elegir cuando un PID se ha reutilizado varias veces."""
        nodes = self._proc_nodes()
        ids = self._proc_seed_ids(nodes, pid=pid, guid=guid, image=image)
        out = []
        for i in ids[:limit]:
            n = nodes[i]
            out.append({"id": n["id"], "ts": n["ts"], "guid": n["guid"],
                        "pid": n["pid"], "image": n["image"], "cmd": n["cmd"],
                        "user": n["user"], "host": n["host"],
                        "source": n["source"], "eid": n["eid"]})
        return out

    def process_tree(self, pid=None, guid=None, image=None, node=None,
                     limit: int = 6000) -> list[dict]:
        """Árbol de procesos (Sigma process_creation = Sysmon EID1 + Security
        4688) anclado en un PID, ProcessGuid, imagen o id de evento. Devuelve el
        subárbol descendiente del ancla MÁS su cadena de ancestros. Sin ancla
        devuelve [] (cargar todos los procesos con muchos logs era inviable)."""
        nodes = self._proc_nodes()
        if not nodes:
            return []
        seeds = self._proc_seed_ids(nodes, pid=pid, guid=guid, image=image, node=node)
        if not seeds:
            return []
        # índices para resolver padres
        guid_index = {n["guid"]: n for n in nodes.values() if n["guid"]}
        pid_index: dict = {}
        for n in nodes.values():
            if n["pid"] is not None:
                pid_index.setdefault((n["host"], n["pid"]), []).append(n)
        for lst in pid_index.values():
            lst.sort(key=lambda n: (n["_ts"] is None, n["_ts"], n["id"]))

        def parent_of(n):
            if n["pguid"]:                       # Sysmon exacto por GUID
                p = guid_index.get(n["pguid"])
                if p is not None and p["id"] != n["id"]:
                    return p["id"]
            if n["ppid"] is not None:            # por PID (4688 o sin GUID padre)
                best = None
                for c in pid_index.get((n["host"], n["ppid"]), []):
                    if c["id"] == n["id"]:
                        continue
                    if (n["_ts"] is not None and c["_ts"] is not None
                            and c["_ts"] > n["_ts"]):
                        continue  # el padre no puede empezar después del hijo
                    best = c      # lista asc -> el último válido es el más cercano
                if best is not None:
                    return best["id"]
            return None

        par = {i: parent_of(nodes[i]) for i in nodes}
        children: dict = {}
        for cid, pid_ in par.items():
            if pid_ is not None:
                children.setdefault(pid_, []).append(cid)

        kept: set = set()
        stack = list(seeds)                      # descendientes
        while stack:
            x = stack.pop()
            if x in kept:
                continue
            kept.add(x)
            if len(kept) >= limit:
                break
            for c in children.get(x, []):
                if c not in kept:
                    stack.append(c)
        for s in seeds:                          # ancestros
            x, guard = par.get(s), 0
            while x is not None and x not in kept and guard < 2000:
                kept.add(x)
                x = par.get(x)
                guard += 1

        out_nodes = {i: dict(nodes[i], children=[]) for i in kept}
        roots = []
        for i in kept:
            p = par.get(i)
            if p is not None and p in kept:
                out_nodes[p]["children"].append(out_nodes[i])
            else:
                roots.append(out_nodes[i])

        def finish(ns):
            ns.sort(key=lambda d: (d.get("ts") or "", d["id"]))
            for d in ns:
                d.pop("_ts", None)
                finish(d["children"])
        finish(roots)
        return roots

    # Familia de autenticación estilo Sigma: no solo los logon clásicos de
    # Security, también Kerberos (DC), NTLM y RDP (varios canales).
    _LOGON_ACT = {
        4624: "logon", 4625: "failed logon", 4634: "logoff",
        4647: "user-initiated logoff", 4648: "explicit-cred logon",
        4672: "special privileges", 4768: "Kerberos TGT request",
        4769: "Kerberos service ticket", 4771: "Kerberos pre-auth failed",
        4776: "NTLM validation", 4778: "RDP session reconnect",
        4779: "RDP session disconnect", 1149: "RDP auth success",
        21: "RDP logon", 22: "RDP shell start", 24: "RDP disconnect",
        25: "RDP reconnect",
    }
    _LOGON_FAILED = {4625, 4771}

    def logons(self, limit: int = 1000, user=None, logon_type=None,
               src_ip=None, workstation=None, auth=None, host=None) -> list[dict]:
        # SELECT base con los campos normalizados a partir de cada fuente
        base = (
            "SELECT id, ts, source, eid, "
            "coalesce(\"user\", extra->>'TargetUserName', extra->>'AccountName', "
            "         extra->>'Param1') AS usr, "
            "logon_type, "
            "coalesce(src_ip, extra->>'IpAddress', extra->>'ClientAddress', "
            "         extra->>'Param3') AS sip, "
            "coalesce(extra->>'WorkstationName', extra->>'Workstation', "
            "         extra->>'ClientName', extra->>'Param2') AS ws, "
            "coalesce(extra->>'LogonProcessName', extra->>'ServiceName') AS lp, "
            "coalesce(extra->>'AuthenticationPackageName', "
            "  CASE WHEN eid IN (4768,4769,4771) THEN 'Kerberos' "
            "       WHEN eid=4776 THEN 'NTLM' "
            "       WHEN eid IN (4778,4779,1149,21,22,24,25) THEN 'RDP' END) AS ap, "
            "host AS hst "
            "FROM events WHERE "
            "  (source='Security' AND eid IN "
            "     (4624,4625,4634,4647,4648,4672,4768,4769,4771,4776,4778,4779)) "
            "  OR (source LIKE '%TerminalServices-RemoteConnectionManager%' AND eid=1149) "
            "  OR (source LIKE '%TerminalServices-LocalSessionManager%' AND eid IN (21,22,24,25))")
        conds: list[str] = []
        params: list[Any] = []

        def _like(col, val):
            conds.append(f"{col} ILIKE ?")
            params.append(f"%{str(val).strip()}%")
        if user and str(user).strip():
            _like("usr", user)
        if src_ip and str(src_ip).strip():
            _like("sip", src_ip)
        if workstation and str(workstation).strip():
            _like("ws", workstation)
        if auth and str(auth).strip():
            _like("ap", auth)
        if host and str(host).strip():
            _like("hst", host)
        if logon_type is not None and str(logon_type).strip():
            conds.append("CAST(logon_type AS VARCHAR) = ?")
            params.append(str(logon_type).strip())
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        sql = (f"SELECT * FROM ({base}) t{where} "
               "ORDER BY ts NULLS LAST, id LIMIT ?")
        with self._lock:
            rows = self._con.execute(sql, params + [limit]).fetchall()
        return [{"id": r[0], "ts": _jsonable(r[1]), "channel": r[2], "eid": r[3],
                 "action": self._LOGON_ACT.get(r[3], str(r[3])), "user": r[4],
                 "logon_type": r[5], "src_ip": r[6], "workstation": r[7],
                 "logon_process": r[8], "auth_pkg": r[9], "host": r[10],
                 "failed": r[3] in self._LOGON_FAILED} for r in rows]

    # Ubicaciones de autostart en registro (ASEP) a vigilar en Sysmon 12/13/14.
    # (patrón ILIKE sobre TargetObject, etiqueta de la técnica)
    _REG_ASEP = [
        ("%\\CurrentVersion\\Run%", "Run / RunOnce key"),
        ("%\\CurrentVersion\\Explorer\\Run%", "Explorer\\Run"),
        ("%\\Policies\\Explorer\\Run%", "Policies Explorer\\Run"),
        ("%\\Winlogon\\Shell%", "Winlogon Shell"),
        ("%\\Winlogon\\Userinit%", "Winlogon Userinit"),
        ("%\\Winlogon\\Notify%", "Winlogon Notify"),
        ("%\\Image File Execution Options\\%", "IFEO (Debugger/GlobalFlag)"),
        ("%\\SilentProcessExit\\%", "IFEO SilentProcessExit"),
        ("%AppInit_DLLs%", "AppInit_DLLs"),
        ("%AppCertDlls%", "AppCertDLLs"),
        ("%\\Windows\\Load%", "Windows\\Load"),
        ("%\\CurrentControlSet\\Services\\%", "Service (registry)"),
        ("%InprocServer32%", "COM hijack (InprocServer32)"),
        ("%\\Classes\\CLSID\\%", "COM / CLSID hijack"),
        ("%\\Control\\Lsa%", "LSA (Auth/Security/Notification pkg)"),
        ("%\\Terminal Server\\%", "Terminal Services / RDP"),
        ("%\\AppCompatFlags\\InstalledSDB%", "AppCompat shim (SDB)"),
        ("%\\Office\\%\\Addins%", "Office add-in"),
        ("%\\NetworkProvider\\Order%", "Network provider order"),
        ("%\\Print\\Monitors%", "Print monitor DLL"),
        ("%\\Control\\Print\\Environments%", "Print processor"),
        ("%SCRNSAVE.EXE%", "Screensaver"),
        ("%\\Session Manager\\BootExecute%", "BootExecute"),
        ("%ShellServiceObjectDelayLoad%", "SSODL"),
        ("%\\Active Setup\\Installed Components%", "Active Setup"),
        ("%\\CurrentVersion\\App Paths%", "App Paths"),
        ("%\\CurrentVersion\\Windows\\AppInit%", "AppInit_DLLs"),
        ("%\\Control\\SecurityProviders\\%", "Security providers (SSP)"),
        ("%\\Environment\\UserInitMprLogonScript%", "Logon script (registry)"),
        # --- ampliación ---
        ("%\\CurrentVersion\\RunOnceEx%", "RunOnceEx"),
        ("%\\CurrentVersion\\RunServices%", "RunServices (legacy)"),
        ("%\\Policies\\System\\Shell%", "Policies System Shell"),
        ("%\\Winlogon\\Userinit%", "Winlogon Userinit"),
        ("%\\Winlogon\\TaskMan%", "Winlogon TaskMan"),
        ("%\\Winlogon\\VmApplet%", "Winlogon VmApplet"),
        ("%\\Winlogon\\AppSetup%", "Winlogon AppSetup"),
        ("%\\Winlogon\\GpExtensions\\%", "Winlogon GPExtension DLL"),
        ("%\\Winlogon\\Credential Providers\\%", "Credential Provider"),
        ("%\\Session Manager\\KnownDlls%", "KnownDLLs"),
        ("%\\Session Manager\\Execute%", "Session Manager Execute"),
        ("%\\Session Manager\\SetupExecute%", "Session Manager SetupExecute"),
        ("%\\SafeBoot\\%", "SafeBoot"),
        ("%\\Command Processor\\AutoRun%", "cmd.exe AutoRun"),
        ("%\\Explorer\\Browser Helper Objects\\%", "Browser Helper Object (BHO)"),
        ("%\\shellex\\ContextMenuHandlers\\%", "Shell context-menu handler"),
        ("%\\ShellIconOverlayIdentifiers\\%", "Shell icon overlay handler"),
        ("%\\Explorer\\SharedTaskScheduler%", "SharedTaskScheduler"),
        ("%\\Explorer\\ShellExecuteHooks%", "ShellExecuteHooks"),
        ("%\\ShellServiceObjectDelayLoad%", "SSODL"),
        ("%\\Internet Explorer\\Extensions\\%", "IE extension"),
        ("%\\Windows Error Reporting\\Hangs%Debugger%", "WER debugger hijack"),
        ("%\\Image File Execution Options\\%VerifierDlls%", "AppVerifier DLL (IFEO)"),
        ("%\\Services\\%\\Parameters\\ServiceDll%", "Service DLL (svchost)"),
        ("%\\Services\\%\\ImagePath%", "Service ImagePath"),
        ("%\\W32Time\\TimeProviders\\%", "Time provider DLL"),
        ("%\\WinSock2\\Parameters%", "Winsock LSP"),
        ("%\\NetSh\\%", "NetSh helper DLL"),
        ("%\\Lsa\\Notification Packages%", "LSA notification package"),
        ("%\\Lsa\\Security Packages%", "LSA security package"),
        ("%\\Lsa\\Authentication Packages%", "LSA authentication package"),
        ("%\\Control\\Terminal Server\\Wds\\%\\StartupPrograms%", "RDP StartupPrograms"),
        ("%\\Terminal Server\\%InitialProgram%", "RDP InitialProgram"),
        ("%\\Font Drivers\\%", "Font driver"),
        ("%\\Group Policy\\Scripts\\%", "GPO logon/startup script"),
        ("%\\Policies\\%\\System\\Scripts%", "Policy script"),
        ("%\\CurrentVersion\\Explorer\\StartupApproved%", "StartupApproved"),
        ("%\\Accessibility\\ATs\\%", "Accessibility AT"),
        ("%\\Natural Language\\%", "Natural language handler"),
        ("%\\ContextMenuHandlers\\%", "Context-menu handler"),
    ]

    def persistence(self, limit: int = 2000) -> list[dict]:
        """Señales de persistencia (ASEP) — Sysmon y logs nativos de Windows.

        Cubre: autostart en registro en ~65 ubicaciones ASEP (Sysmon 12/13/14 y,
        sin Sysmon, Security 4657), carpeta de inicio y tarea soltada como XML
        (Sysmon 11 en \\Startup\\ y \\Tasks\\), instalación/alta de servicios
        (7045/4697) y cambio de tipo de arranque (7040), tareas programadas
        (4698-4702 / TaskScheduler 106/140/141/200/201), suscripciones WMI
        (Sysmon 19/20/21 y WMI-Activity 5859/5861), scripts de logon, creación de
        cuentas y alta en grupos privilegiados (4720/4722/4728/4732/4738/4756) y
        trabajos BITS (Bits-Client 3).
        """
        # CASE que etiqueta el ASEP de registro según el TargetObject
        case = "CASE\n"
        reg_or = []
        rp: list[Any] = []
        for pat, lab in self._REG_ASEP:
            case += f"      WHEN (extra->>'TargetObject') ILIKE ? THEN ?\n"
            rp.append(pat); rp.append(lab)
            reg_or.append("(extra->>'TargetObject') ILIKE ?")
        case += "      ELSE 'Registry autostart' END"
        reg_where = " OR ".join(reg_or)
        reg_params = rp + [p for p, _ in self._REG_ASEP]

        blocks = []
        params: list[Any] = []

        # 1) Autostart en registro (Sysmon 12/13/14)
        blocks.append(
            f"  SELECT id, ts, {case} AS ptype, eid, host, "
            "coalesce((extra->>'TargetObject'),'') || "
            "CASE WHEN (extra->>'Details') IS NOT NULL "
            "THEN '  =  ' || (extra->>'Details') ELSE '' END AS detail, "
            'image AS actor, "user" FROM events '
            "WHERE source LIKE '%Sysmon%' AND eid IN (12,13,14) "
            f"AND ({reg_where})")
        params += reg_params

        # 2) Carpeta de inicio (Sysmon 11 FileCreate en …\Startup\)
        blocks.append(
            "  SELECT id, ts, 'Startup folder', eid, host, "
            "target_filename, image, \"user\" FROM events "
            "WHERE source LIKE '%Sysmon%' AND eid=11 "
            "AND target_filename ILIKE '%\\Startup\\%'")

        # 3) Instalación / alta de servicio (System 7045, Security 4697)
        blocks.append(
            "  SELECT id, ts, 'Service install', eid, host, "
            "coalesce(extra->>'ServiceName', extra->>'param1', "
            "extra->>'ServiceFileName') || "
            "CASE WHEN coalesce(extra->>'ImagePath', extra->>'param2', "
            "extra->>'ServiceFileName') IS NOT NULL THEN '  ::  ' || "
            "coalesce(extra->>'ImagePath', extra->>'param2', "
            "extra->>'ServiceFileName') ELSE '' END, image, \"user\" "
            "FROM events WHERE eid IN (7045,4697)")

        # 4) Cambio de tipo de arranque de servicio (System 7040)
        blocks.append(
            "  SELECT id, ts, 'Service start-type change', eid, host, "
            "coalesce(message, extra->>'param1'), image, \"user\" "
            "FROM events WHERE eid=7040")

        # 5) Tareas programadas (Security + TaskScheduler Operational)
        blocks.append(
            "  SELECT id, ts, 'Scheduled task', eid, host, "
            "coalesce(extra->>'TaskName', extra->>'TaskContent', message), "
            'image, "user" FROM events '
            "WHERE eid IN (4698,4699,4700,4701,4702) "
            "OR (source LIKE '%TaskScheduler%' AND eid IN (106,140,141,200,201))")

        # 6) Suscripciones WMI (Sysmon 19/20/21 y WMI-Activity 5859/5861)
        blocks.append(
            "  SELECT id, ts, 'WMI subscription', eid, host, "
            "coalesce(extra->>'Consumer', extra->>'Query', "
            "extra->>'Destination', extra->>'Name', extra->>'Operation', message), "
            'image, "user" '
            "FROM events WHERE (source LIKE '%Sysmon%' AND eid IN (19,20,21)) "
            "OR (source LIKE '%WMI-Activity%' AND eid IN (5859,5861))")

        # 7) Cuentas y grupos privilegiados (Security)
        blocks.append(
            "  SELECT id, ts, CASE eid "
            "WHEN 4720 THEN 'New account' "
            "WHEN 4722 THEN 'Account enabled' "
            "WHEN 4738 THEN 'Account changed' "
            "ELSE 'Added to privileged group' END, eid, host, "
            "coalesce(extra->>'MemberName', extra->>'TargetUserName', message) || "
            "CASE WHEN (extra->>'TargetUserName') IS NOT NULL AND eid IN "
            "(4728,4732,4756) THEN '  ->  ' || (extra->>'TargetUserName') "
            "ELSE '' END, "
            "coalesce(extra->>'SubjectUserName', \"user\"), \"user\" "
            "FROM events WHERE eid IN (4720,4722,4738,4728,4732,4756)")

        # 8) Trabajos BITS creados (Bits-Client EID 3). Se omiten 59/60
        # (inicio/fin de transferencia) por ser muy ruidosos (Windows Update…).
        blocks.append(
            "  SELECT id, ts, 'BITS job created', eid, host, "
            "coalesce(extra->>'jobTitle', extra->>'url', extra->>'name', message), "
            'image, "user" FROM events '
            "WHERE source LIKE '%Bits-Client%' AND eid=3")

        # 9) Tarea programada soltada como XML (Sysmon 11 FileCreate en \Tasks\)
        blocks.append(
            "  SELECT id, ts, 'Scheduled task (file dropped)', eid, host, "
            'target_filename, image, "user" FROM events '
            "WHERE source LIKE '%Sysmon%' AND eid=11 "
            "AND (target_filename ILIKE '%\\System32\\Tasks\\%' "
            "     OR target_filename ILIKE '%\\Windows\\Tasks\\%')")

        # 10) Script de logon por WMI / otros (Sysmon 1: cscript/wscript con rutas
        # de arranque) — señal ligera de LogonScript persistente
        blocks.append(
            "  SELECT id, ts, 'Logon/startup script', eid, host, "
            "command_line, image, \"user\" FROM events "
            "WHERE source LIKE '%Sysmon%' AND eid=1 "
            "AND command_line ILIKE '%UserInitMprLogonScript%'")

        # 11) Valor de registro modificado (Security 4657, auditoría nativa) en
        # ubicaciones ASEP — equivalente sin Sysmon a los bloques 1.
        case2 = "CASE\n"
        reg_or2 = []
        rp2: list[Any] = []
        for pat, lab in self._REG_ASEP:
            case2 += "      WHEN (extra->>'ObjectName') ILIKE ? THEN ?\n"
            rp2.append(pat); rp2.append(lab)
            reg_or2.append("(extra->>'ObjectName') ILIKE ?")
        case2 += "      ELSE 'Registry autostart (audit)' END"
        reg_where2 = " OR ".join(reg_or2)
        blocks.append(
            f"  SELECT id, ts, {case2} AS ptype, eid, host, "
            "coalesce(extra->>'ObjectName','') || "
            "CASE WHEN (extra->>'ObjectValueName') IS NOT NULL "
            "THEN '  \\  ' || (extra->>'ObjectValueName') ELSE '' END AS detail, "
            "coalesce(extra->>'ProcessName', image) AS actor, \"user\" "
            f"FROM events WHERE eid=4657 AND ({reg_where2})")
        reg_params2 = rp2 + [p for p, _ in self._REG_ASEP]

        sql = ("SELECT * FROM (\n" + "\n  UNION ALL\n".join(blocks) +
               "\n) ORDER BY ts NULLS LAST, id LIMIT ?")
        params += reg_params2        # placeholders del bloque 11 (4657)
        params.append(limit)
        with self._lock:
            rows = self._con.execute(sql, params).fetchall()
        return [{"id": r[0], "ts": _jsonable(r[1]), "ptype": r[2],
                 "eid": r[3], "host": r[4], "detail": r[5],
                 "actor": r[6], "user": r[7]} for r in rows]

    def powershell(self, limit: int = 500,
                   q: Optional[str] = None) -> list[dict]:
        """Script blocks de PowerShell (4104), reensamblando multi-parte.

        Con `q` se filtran los scripts cuyo texto (ya reensamblado) contiene la
        subcadena (case-insensitive): así se localiza un script por una cadena
        concreta sin revisarlos todos. El filtro se hace en SQL por ScriptBlockId
        para traer SOLO los bloques que casan (y todas sus partes), de modo que
        escala aunque haya miles de eventos 4104.
        """
        q = (q or "").strip()
        base = ("FROM events WHERE source LIKE '%PowerShell%' AND eid=4104 "
                "AND (extra->>'ScriptBlockText') IS NOT NULL")
        sel = ("SELECT id, ts, (extra->>'ScriptBlockText') txt, "
               "(extra->>'Path') path, (extra->>'ScriptBlockId') sbid, "
               "TRY_CAST(extra->>'MessageNumber' AS INTEGER) mn, "
               "TRY_CAST(extra->>'MessageTotal' AS INTEGER) mt, "
               'host, "user" ')
        with self._lock:
            if q:
                like = f"%{q}%"
                # bloques (por ScriptBlockId, o sueltos) con alguna parte que casa
                rows = self._con.execute(
                    f"{sel}{base} AND ("
                    "  (extra->>'ScriptBlockId') IN ("
                    f"     SELECT DISTINCT (extra->>'ScriptBlockId') {base} "
                    "      AND (extra->>'ScriptBlockText') ILIKE ?)"
                    "  OR ((extra->>'ScriptBlockId') IS NULL "
                    "      AND (extra->>'ScriptBlockText') ILIKE ?)) "
                    "ORDER BY ts NULLS LAST, id LIMIT ?",
                    [like, like, max(limit * 40, 4000)]).fetchall()
            else:
                rows = self._con.execute(
                    f"{sel}{base} ORDER BY ts NULLS LAST, id LIMIT ?",
                    [limit]).fetchall()
        # reensamblar por ScriptBlockId (MessageNumber/MessageTotal)
        groups: dict = {}
        out: list[dict] = []
        for r in rows:
            sbid, mn, mt = r[4], r[5], r[6]
            rec = {"id": r[0], "ts": _jsonable(r[1]), "text": r[2],
                   "path": r[3], "host": r[7], "user": r[8],
                   "parts": (mt or 1)}
            if sbid and mt and mt > 1:
                g = groups.setdefault(sbid, {"first": rec, "parts": {}})
                g["parts"][mn or 0] = r[2]
                if mn == 1:
                    g["first"] = rec
            else:
                out.append(rec)
        for sbid, g in groups.items():
            rec = dict(g["first"])
            rec["text"] = "".join(g["parts"][k] for k in sorted(g["parts"]))
            out.append(rec)
        if q:
            ql = q.lower()
            out = [r for r in out if (r["text"] or "").lower().find(ql) >= 0]
        out.sort(key=lambda x: (x["ts"] or ""))
        return out[:limit]

    # Texto sobre el que casa un IOC (campos relevantes + registro crudo, para
    # encontrar el indicador aparezca donde aparezca en el evento).
    _IOC_TEXT = ("concat_ws(' ', src_ip, dst_ip, hashes, image, image_loaded, "
                 "target_filename, original_filename, command_line, parent_image, "
                 "message, host, \"user\", program, source, raw)")

    def ioc_sweep(self, iocs: list[str], per: int = 50) -> list[dict]:
        """Barrido de IOCs: por cada indicador, nº de eventos y una muestra.

        Búsqueda literal (case-insensitive) sobre campos relevantes + raw, así
        se localiza el IOC esté donde esté (IP, hash, nombre de fichero, dominio…).
        """
        out: list[dict] = []
        with self._lock:
            for raw_ioc in iocs:
                io = (raw_ioc or "").strip()
                if not io:
                    continue
                esc = (io.replace("\\", "\\\\").replace("%", "\\%")
                         .replace("_", "\\_"))
                like = f"%{esc}%"
                total = self._con.execute(
                    f"SELECT count(*) FROM events "
                    f"WHERE {self._IOC_TEXT} ILIKE ? ESCAPE '\\'",
                    [like]).fetchone()[0]
                rows = []
                if total:
                    rows = self._con.execute(
                        "SELECT id, ts, source, eid, host, \"user\", "
                        "coalesce(image, target_filename, image_loaded, "
                        "command_line, message, '') AS detail "
                        f"FROM events WHERE {self._IOC_TEXT} ILIKE ? ESCAPE '\\' "
                        "ORDER BY ts NULLS LAST, id LIMIT ?",
                        [like, per]).fetchall()
                out.append({"ioc": io, "count": total,
                            "hits": [{"id": r[0], "ts": _jsonable(r[1]),
                                      "source": r[2], "eid": r[3], "host": r[4],
                                      "user": r[5], "detail": r[6]} for r in rows]})
        return out

    _PROTO = {"6": "TCP", "17": "UDP", "1": "ICMP", "2": "IGMP", "47": "GRE",
              "58": "ICMPv6"}
    _DIRECTION = {"%%14592": "Inbound", "%%14593": "Outbound",
                  "true": "Outbound", "false": "Inbound"}

    def network(self, limit: int = 3000, kind=None, proto=None, image=None,
                ip=None, port=None) -> list[dict]:
        """Conexiones de red: Sysmon EID3 + DNS (22) y eventos NATIVOS de Windows
        (Filtering Platform 5156/5157 allow/block, 5158 bind). Campos
        normalizados por fuente."""
        base = (
            "SELECT id, ts, source, eid, host, "
            "CASE WHEN eid=22 THEN 'dns' WHEN eid=5158 THEN 'bind' "
            "     WHEN eid=5157 THEN 'blocked' ELSE 'conn' END AS kind, "
            "coalesce(extra->>'Protocol') AS proto, "
            "coalesce(extra->>'Initiated', extra->>'Direction') AS direction, "
            "coalesce(src_ip, extra->>'SourceAddress') AS sip, "
            "coalesce(extra->>'SourcePort') AS sport, "
            "coalesce(dst_ip, extra->>'DestAddress') AS dip, "
            "coalesce(extra->>'DestinationPort', extra->>'DestPort') AS dport, "
            "coalesce(image, extra->>'Application') AS app, "
            "coalesce(extra->>'DestinationHostname', extra->>'QueryName') AS hostn, "
            "extra->>'QueryResults' AS qres, \"user\" AS usr "
            "FROM events WHERE "
            "  (source LIKE '%Sysmon%' AND eid IN (3,22)) "
            "  OR (source='Security' AND eid IN (5156,5157,5158))")
        conds: list[str] = []
        params: list[Any] = []
        if kind and str(kind).strip():
            conds.append("kind=?"); params.append(str(kind).strip())
        if image and str(image).strip():
            conds.append("app ILIKE ?"); params.append(f"%{str(image).strip()}%")
        if ip and str(ip).strip():
            conds.append("(sip ILIKE ? OR dip ILIKE ? OR hostn ILIKE ?)")
            p = f"%{str(ip).strip()}%"; params += [p, p, p]
        if port and str(port).strip():
            conds.append("(CAST(sport AS VARCHAR)=? OR CAST(dport AS VARCHAR)=?)")
            params += [str(port).strip(), str(port).strip()]
        if proto and str(proto).strip():
            pr = str(proto).strip().upper()
            num = {"TCP": "6", "UDP": "17", "ICMP": "1"}.get(pr, pr)
            conds.append("(proto=? OR upper(proto)=?)"); params += [num, pr]
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        sql = (f"SELECT * FROM ({base}) t{where} "
               "ORDER BY ts NULLS LAST, id LIMIT ?")
        with self._lock:
            rows = self._con.execute(sql, params + [int(limit)]).fetchall()
        out = []
        for r in rows:
            proto_v = self._PROTO.get(str(r[6]), r[6]) if r[6] is not None else None
            dir_v = self._DIRECTION.get(str(r[7]).lower() if r[7] else r[7], r[7])
            out.append({"id": r[0], "ts": _jsonable(r[1]), "source": r[2],
                        "eid": r[3], "host": r[4], "kind": r[5], "proto": proto_v,
                        "direction": dir_v, "src_ip": r[8], "src_port": r[9],
                        "dst_ip": r[10], "dst_port": r[11], "app": r[12],
                        "hostname": r[13], "dns_result": r[14], "user": r[15]})
        return out

    def raw_event(self, row_id: int) -> dict[str, Any]:
        """Devuelve el registro completo de un evento (JSON crudo) para copiar."""
        with self._lock:
            r = self._con.execute(
                'SELECT id, ts, source, eid, host, raw, message '
                "FROM events WHERE id = ?", [int(row_id)]).fetchone()
        if not r:
            return {"found": False}
        raw = r[5]
        pretty = raw
        if raw:
            try:
                import json as _json
                pretty = _json.dumps(_json.loads(raw), indent=2, ensure_ascii=False)
            except Exception:  # noqa: BLE001
                pretty = raw
        return {"found": True, "id": r[0], "ts": _jsonable(r[1]),
                "source": r[2], "eid": r[3], "host": r[4],
                "raw": raw, "pretty": pretty}

    # ------------------------------------------------------------------
    # Extracción de IOCs: descubre los indicadores presentes en los EVTX
    # (lo contrario del IOC sweep). Offline, con validación estricta.
    # ------------------------------------------------------------------
    def extract_iocs(self, per_type: int = 400) -> dict:
        import json as _json
        from . import ioc_extract as X
        try:
            from . import geoip as geo
        except Exception:  # noqa: BLE001
            geo = None
        agg: dict = {}

        def _bump(typ, val, rid, ts):
            e = agg.get((typ, val))
            if e is None:
                agg[(typ, val)] = {"count": 1, "id": rid, "ts": ts}
            else:
                e["count"] += 1
                if rid < e["id"]:
                    e["id"], e["ts"] = rid, ts

        with self._lock:
            rows = self._con.execute(
                "SELECT id, ts, coalesce(message,''), "
                "coalesce(command_line,''), coalesce(image,''), "
                "coalesce(parent_image,''), coalesce(original_filename,''), "
                "coalesce(target_filename,''), coalesce(image_loaded,''), "
                "coalesce(hashes,''), coalesce(src_ip,''), coalesce(dst_ip,''), "
                "coalesce(host,''), coalesce(\"user\",''), "
                "coalesce(CAST(extra AS VARCHAR),'') "
                "FROM events").fetchall()
        for r in rows:
            rid, ts = r[0], r[1]
            (msg, cmd, img, pimg, ofn, tfn, iml, hsh, sip, dip,
             host, usr, extra) = r[2:]
            # valores ya parseados de EventData (sin el JSON escapado -> sin \\)
            ex = None
            if extra:
                try:
                    ex = _json.loads(extra)
                except Exception:  # noqa: BLE001
                    ex = None
            ex_vals = " ".join(str(v) for v in ex.values()
                               if isinstance(v, (str, int))) if isinstance(ex, dict) else ""
            general = " ".join((msg, cmd, img, pimg, ofn, tfn, iml,
                                sip, dip, host, usr, ex_vals))
            hashes_text = " ".join((hsh, cmd, img, ofn, msg))
            seen = set()
            for typ, val in X.iter_iocs(general, hashes_text, windows=True):
                if (typ, val) in seen:
                    continue
                seen.add((typ, val))
                _bump(typ, val, rid, ts)
            # extras por campo (más fiables que regex para registry/pipe/…)
            if isinstance(ex, dict):
                for key, typ in (("ServiceName", "service"),
                                 ("TaskName", "task"),
                                 ("PipeName", "pipe"),
                                 ("TargetObject", "registry"),
                                 ("UserAgent", "useragent"),
                                 ("cs(User-Agent)", "useragent"),
                                 ("User-Agent", "useragent")):
                    v = ex.get(key)
                    if isinstance(v, str) and v.strip() and v.strip() != "-" \
                            and (typ, v.strip()) not in seen:
                        seen.add((typ, v.strip()))
                        _bump(typ, v.strip(), rid, ts)
        return self._group_iocs(agg, per_type, X, geo)

    @staticmethod
    def _group_iocs(agg: dict, per_type: int, X, geo) -> dict:
        by_type: dict = {}
        for (typ, val), e in agg.items():
            by_type.setdefault(typ, []).append((val, e))
        groups = []
        total = 0
        geocache: dict = {}
        for typ in X.IOC_TYPES:
            items = by_type.get(typ)
            if not items:
                continue
            items.sort(key=lambda kv: (-kv[1]["count"], kv[0]))
            total += len(items)
            out_items = []
            for val, e in items[:per_type]:
                it = {"value": val, "count": e["count"], "id": e["id"],
                      "ts": _jsonable(e["ts"])}
                if typ in ("ipv4", "ipv6"):
                    it["klass"] = X.ip_class(val)
                    if geo is not None and it["klass"] == "external":
                        g = geocache.get(val)
                        if g is None:
                            try:
                                g = geo.lookup(val)
                            except Exception:  # noqa: BLE001
                                g = {}
                            geocache[val] = g
                        it["asn"] = (f"AS{g['asn']}" if g.get("asn") else None)
                        it["org"] = g.get("org")
                        it["country"] = g.get("country_code")
                out_items.append(it)
            groups.append({"type": typ, "label": X.IOC_LABEL.get(typ, typ),
                           "total": len(items), "items": out_items})
        return {"total": total, "groups": groups}

    def reset(self) -> None:
        with self._lock:
            self._con.execute("DELETE FROM events")
            self._seq_dirty = True

    def close(self) -> None:
        self._con.close()


def _jsonable(v: Any) -> Any:
    import datetime as _dt
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat(sep=" ")
    return v
