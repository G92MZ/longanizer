"""Almacén DuckDB para los eventos normalizados."""
from __future__ import annotations

import ipaddress
import re
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
    _SEARCH_TEXT = ("concat_ws(' ', message, raw, exe, path, \"user\", "
                    "src_ip, program, source)")
    _REGEX_TEXT = "coalesce(raw, message, '')"

    # --- sintaxis de búsqueda avanzada del explorador ---------------------
    # texto libre  -> contains sobre _SEARCH_TEXT (varias palabras = AND)
    # campo:valor  -> ese campo CONTIENE valor (ILIKE, sin mayúsculas)
    # campo=valor  -> ese campo es EXACTAMENTE valor
    # campo!=valor -> ese campo NO es valor
    # -algo        -> NOT (excluye); vale con texto libre o con campo:valor
    # x:clave:valor o extra.clave:valor -> busca en una clave del JSON extra
    _FIELD_ALIASES = {"ip": "src_ip", "sip": "src_ip", "sport": "src_port",
                      "dport": "src_port", "prog": "program", "proc": "program",
                      "msg": "message", "sev": "severity"}
    _NUM_COLS = {name for name, typ in COLUMNS if typ in ("INTEGER", "BIGINT")}

    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._con = duckdb.connect(path)
        _register_udfs(self._con)
        # RLock (reentrante) para que los métodos de consulta puedan llamar a
        # _ensure_seqmap() teniendo ya el lock sin bloquearse.
        self._lock = threading.RLock()
        # seqmap (id -> posición en la timeline) se materializa de forma
        # perezosa y se marca sucio en cada inserción/reset: se reconstruye una
        # vez por lote de ingesta en lugar de recalcularse en cada consulta.
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
            for _c in ("contexto", "regla"):
                try:
                    self._con.execute(
                        f"ALTER TABLE marcas ADD COLUMN IF NOT EXISTS {_c} VARCHAR")
                except duckdb.Error:
                    pass
            self._mark_next = self._con.execute(
                "SELECT coalesce(max(mid),0)+1 FROM marcas").fetchone()[0]
            # índice en events.id: el ancla de contexto (WHERE id = ?) es una
            # búsqueda puntual en vez de un escaneo.
            try:
                self._con.execute(
                    "CREATE INDEX IF NOT EXISTS ix_events_id ON events(id)")
            except duckdb.Error:
                pass

    def insert_events(self, rows: list[tuple]) -> int:
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
            self._seq_dirty = True   # la timeline debe renumerarse
        return n

    # ------------------------------------------------------------------
    # Explorador: búsqueda por string/regex y contexto ±N.
    # El nº visible '#' (seq) es la POSICIÓN EN LA TIMELINE: 1 = el evento
    # más antiguo (orden por ts; los sin timestamp van al final). Se calcula
    # dinámicamente, así que si cargas más logs se renumera solo.
    # ------------------------------------------------------------------
    # campos mostrados (sin seq/id, que se añaden alrededor) — todas las
    # columnas parseadas útiles, para verlas en la tabla de resultados
    _FIELDS = ["ts", "source", "host", "program", "pid", "severity", "user",
               "src_ip", "src_port", "exe", "method", "path", "status",
               "bytes", "referer", "user_agent", "event", "message",
               "extra", "src_file"]
    # subconsulta que asigna seq (posición temporal) a cada id
    # Lee la posición en la timeline de la tabla materializada `seqmap`
    # (reconstruida por _ensure_seqmap tras cada ingesta), en vez de recalcular
    # el window sort en cada consulta.
    _SEQ_SQL = "SELECT id, seq FROM seqmap"

    def _ensure_seqmap(self) -> None:
        """Reconstruye la tabla id->seq (posición temporal) si los eventos han
        cambiado. El window sort completo corre aquí una vez por lote de
        ingesta, no en cada consulta. RLock hace segura la reentrada."""
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
        return [r[0] for r in rows if r[0] and not r[0].startswith("_")]

    @staticmethod
    def _like_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _field_expr(self, field: str, prefix: str = ""):
        """Resuelve un nombre de campo a (expr_sql, es_numerico).

        Con prefijo x: / extra. apunta a una clave del JSON extra. Sin prefijo,
        solo acepta columnas reales o alias (ip->src_ip…); un nombre
        desconocido devuelve None (para que se trate como texto libre y no
        rompa búsquedas tipo http://… o foo=bar)."""
        if prefix:                       # x: o extra. -> clave del JSON extra
            key = field.strip()          # se respeta el case (auditd/logfmt lo distingue)
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
        token: "msg:/foo bar/"."""
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

    def search(self, q: str, regex: bool = False, source: Optional[str] = None,
               limit: int = 500, offset: int = 0, sort: Optional[str] = None,
               desc: bool = False, start: Optional[str] = None,
               end: Optional[str] = None) -> dict[str, Any]:
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
        if start:                      # filtro temporal global (UTC)
            where.append("ev.ts >= ?")
            params.append(start)
        if end:
            where.append("ev.ts <= ?")
            params.append(end)
        cond = " AND ".join(where)
        # se une con seq para mostrar la posición temporal de cada hit
        sql = (f"SELECT o.seq, {self._fields_sql('ev.')}, ev.id "
               f"FROM events ev JOIN ({self._SEQ_SQL}) o ON ev.id = o.id "
               f"WHERE {cond} {self._order_clause(sort, desc)} LIMIT ? OFFSET ?")
        self._ensure_seqmap()
        with self._lock:
            total = self._con.execute(
                f"SELECT count(*) FROM events ev WHERE {cond}", params).fetchone()[0]
            cur = self._con.execute(sql, params + [int(limit), int(offset)])
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
        return {"columns": names,
                "rows": [[_jsonable(v) for v in r] for r in rows],
                "rowcount": len(rows), "total": total, "offset": int(offset)}

    def _facet_where(self, q: str, regex: bool, source: Optional[str],
                     start: Optional[str], end: Optional[str]):
        """Construye el WHERE común (mismo criterio que la búsqueda) para las
        facetas. q puede ir vacío (faceta sobre todo lo filtrado)."""
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
              end: Optional[str] = None, limit: int = 20) -> dict[str, Any]:
        """Top-N valores de un campo sobre el resultado de búsqueda actual."""
        expr = self._facet_expr(field)
        if expr is None:
            raise ValueError(f"Campo no válido para facetas: {field!r}")
        cond, params = self._facet_where(q, regex, source, start, end)
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

    def timeline(self, source: Optional[str] = None, limit: int = 2000,
                 offset: int = 0, start: Optional[str] = None,
                 end: Optional[str] = None, sort: Optional[str] = None,
                 desc: bool = False) -> dict[str, Any]:
        """Timeline completa: todos los eventos en orden cronológico, con su
        seq. Admite filtro por origen, por rango temporal (start/end, en UTC)
        y paginación (limit/offset)."""
        conds: list[str] = []
        params: list[Any] = []
        if source and source not in ("", "(todos)", "(all)"):
            conds.append("ev.source = ?")
            params.append(source)
        if start:
            conds.append("ev.ts >= ?")
            params.append(start)
        if end:
            conds.append("ev.ts <= ?")
            params.append(end)
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        self._ensure_seqmap()
        with self._lock:
            total = self._con.execute(
                f"SELECT count(*) FROM events ev {where}", params).fetchone()[0]
            sql = (f"SELECT o.seq, {self._fields_sql('ev.')}, ev.id "
                   f"FROM events ev JOIN ({self._SEQ_SQL}) o ON ev.id = o.id "
                   f"{where} {self._order_clause(sort, desc)} LIMIT ? OFFSET ?")
            cur = self._con.execute(sql, params + [int(limit), int(offset)])
            names = [d[0] for d in cur.description]
            rows = cur.fetchall()
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
        if seq is not None and row_id is None:
            self._ensure_seqmap()
            with self._lock:
                r = self._con.execute(
                    f"SELECT id FROM ({self._SEQ_SQL}) WHERE seq = ?",
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
        # usa la tabla materializada seqmap en vez de recalcular el window sort
        sql = f"""
            WITH t AS (SELECT seq FROM seqmap WHERE id = ?)
            SELECT sm.seq, {self._fields_sql('ev.')}, ev.id, (ev.id = ?) AS is_match
            FROM seqmap sm JOIN events ev ON ev.id = sm.id, t
            WHERE sm.seq BETWEEN t.seq - ? AND t.seq + ?
            ORDER BY sm.seq
        """
        self._ensure_seqmap()
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
        self._ensure_seqmap()
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
        self._ensure_seqmap()
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
        return {
            "total_events": total,
            "by_source": [
                {"source": s, "count": c,
                 "ts_min": _jsonable(tmin), "ts_max": _jsonable(tmax)}
                for s, c, tmin, tmax in by_source
            ],
            "by_file": [{"src_file": f, "count": c} for f, c in by_file],
            "extra_keys": self.extra_keys(),
        }

    def _hist_adaptive(self, nbuckets: int = 120) -> list:
        """Histograma temporal en ~nbuckets cubos de igual anchura (relleno con
        ceros). Evita agrupar por hora sobre rangos de años (miles de barras)."""
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
        """Agregados para la pestaña Resumen: totales, rango, tops e histograma."""
        q_top = ("SELECT {c}, count(*) n FROM events "
                 "WHERE {c} IS NOT NULL AND CAST({c} AS VARCHAR)<>'' "
                 "GROUP BY {c} ORDER BY n DESC LIMIT ?")
        bin_expr = "lower(regexp_extract(coalesce(exe,''),'([^/]+)$',1))"
        with self._lock:
            total = self._con.execute("SELECT count(*) FROM events").fetchone()[0]
            tmin, tmax = self._con.execute(
                "SELECT min(ts), max(ts) FROM events WHERE ts IS NOT NULL").fetchone()
            n_ip = self._con.execute(
                "SELECT count(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL").fetchone()[0]
            n_user = self._con.execute(
                'SELECT count(DISTINCT "user") FROM events WHERE "user" IS NOT NULL').fetchone()[0]
            n_file = self._con.execute(
                "SELECT count(DISTINCT src_file) FROM events").fetchone()[0]
            by_source = self._con.execute(
                "SELECT source, count(*) n FROM events GROUP BY source ORDER BY n DESC").fetchall()
            sev = self._con.execute(
                "SELECT coalesce(severity,'—') s, count(*) n FROM events "
                "GROUP BY s ORDER BY n DESC").fetchall()
            top_ip = self._con.execute(q_top.format(c="src_ip"), [top_n]).fetchall()
            top_user = self._con.execute(q_top.format(c='"user"'), [top_n]).fetchall()
            top_prog = self._con.execute(q_top.format(c="program"), [top_n]).fetchall()
            top_bin = self._con.execute(
                f"SELECT {bin_expr} b, count(*) n FROM events "
                "WHERE exe IS NOT NULL AND exe<>'' GROUP BY b ORDER BY n DESC LIMIT ?",
                [top_n]).fetchall()
            hist = None
        hist = self._hist_adaptive()
        def pairs(rows):
            return [{"k": ("" if k is None else str(k)), "n": n} for k, n in rows]
        return {
            "total": total,
            "ts_min": _jsonable(tmin), "ts_max": _jsonable(tmax),
            "distinct": {"ip": n_ip, "user": n_user, "file": n_file,
                         "source": len(by_source)},
            "by_source": pairs(by_source),
            "severity": pairs(sev),
            "top_ip": pairs(top_ip),
            "top_user": pairs(top_user),
            "top_program": pairs(top_prog),
            "top_bin": pairs(top_bin),
            "hist": [{"h": _jsonable(h), "n": n} for h, n in hist],
        }

    # ------------------------------------------------------------------
    # Marcas / triage (persistidas en el .duckdb del caso)
    # ------------------------------------------------------------------
    def _mark_context(self, event_id: int, n: int = 10) -> Optional[str]:
        """Snapshot de texto del contexto alrededor de un evento (±n/2 por
        posición en la timeline), congelado al marcar."""
        if event_id is None:
            return None
        half = max(1, n // 2)
        try:
            self._ensure_seqmap()
            with self._lock:
                rows = self._con.execute(
                    f"WITH seq AS ({self._SEQ_SQL}), "
                    "t AS (SELECT seq FROM seq WHERE id = ?) "
                    "SELECT s.seq, ev.ts, ev.source, ev.program, "
                    "coalesce(nullif(ev.message,''), ev.raw, ev.exe) AS det, "
                    "(ev.id = ?) AS hit "
                    "FROM seq s JOIN t ON s.seq BETWEEN t.seq-? AND t.seq+? "
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
            "  coalesce(nullif(ev.message,''), ev.raw, ev.exe) AS detalle,\n"
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

    def ip_detail(self, ip: str, samples: int = 8) -> dict[str, Any]:
        """Resumen de una IP: totales, primera/última vez, desglose por origen,
        fallos de auth y eventos de muestra (con su id para ir al contexto)."""
        with self._lock:
            total = self._con.execute(
                "SELECT count(*) FROM events WHERE src_ip = ?", [ip]).fetchone()[0]
            tmin, tmax = self._con.execute(
                "SELECT min(ts), max(ts) FROM events WHERE src_ip = ? "
                "AND ts IS NOT NULL", [ip]).fetchone()
            by_source = self._con.execute(
                "SELECT source, count(*) n FROM events WHERE src_ip = ? "
                "GROUP BY source ORDER BY n DESC", [ip]).fetchall()
            fails = self._con.execute(
                "SELECT count(*) FROM events WHERE src_ip = ? AND severity = 'fail'",
                [ip]).fetchone()[0]
            users = self._con.execute(
                'SELECT "user", count(*) n FROM events WHERE src_ip = ? '
                'AND "user" IS NOT NULL GROUP BY "user" ORDER BY n DESC LIMIT 8',
                [ip]).fetchall()
            rows = self._con.execute(
                'SELECT id, ts, source, "user", '
                "coalesce(message, raw, exe) AS detalle "
                "FROM events WHERE src_ip = ? ORDER BY ts NULLS LAST, id LIMIT ?",
                [ip, samples]).fetchall()
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
        """(src_ip, nº eventos) para TODAS las IPs (para agrupar por ISP/país)."""
        with self._lock:
            return self._con.execute(
                "SELECT src_ip, count(*) n FROM events "
                "WHERE src_ip IS NOT NULL AND src_ip<>'' "
                "GROUP BY src_ip").fetchall()

    def network(self, limit: int = 3000, ip=None, port=None,
                source=None, event=None) -> list[dict]:
        """Vista de red para Linux: eventos con señal de conectividad —
        conexiones SSH (auth), accesos web (access/error), conexiones de
        auditd (syscall connect / SADDR=) y descartes de firewall (SRC=…)."""
        base = (
            "SELECT id, ts, source, event, program, src_ip, src_port, method, "
            "path, status, exe, \"user\" AS usr, host, message "
            "FROM events WHERE "
            "  src_ip IS NOT NULL OR source IN ('access','weberror') "
            "  OR event LIKE 'ssh%' OR message ILIKE '%SRC=%' "
            "  OR message ILIKE '%SADDR=%'")
        conds: list[str] = []
        params: list[Any] = []
        if ip and str(ip).strip():
            conds.append("(src_ip ILIKE ? OR message ILIKE ?)")
            p = f"%{str(ip).strip()}%"; params += [p, p]
        if port and str(port).strip():
            conds.append("(CAST(src_port AS VARCHAR)=? OR message ILIKE ?)")
            params += [str(port).strip(), f"%{str(port).strip()}%"]
        if source and str(source).strip():
            conds.append("source=?"); params.append(str(source).strip())
        if event and str(event).strip():
            conds.append("event ILIKE ?"); params.append(f"%{str(event).strip()}%")
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        sql = (f"SELECT * FROM ({base}) t{where} "
               "ORDER BY ts NULLS LAST, id LIMIT ?")
        with self._lock:
            rows = self._con.execute(sql, params + [int(limit)]).fetchall()
        return [{"id": r[0], "ts": _jsonable(r[1]), "source": r[2],
                 "event": r[3], "program": r[4], "src_ip": r[5],
                 "src_port": r[6], "method": r[7], "path": r[8],
                 "status": r[9], "exe": r[10], "user": r[11], "host": r[12],
                 "detail": r[13]} for r in rows]

    def raw_event(self, row_id: int) -> dict[str, Any]:
        """Devuelve el registro completo de un evento (línea cruda / JSON) para copiar."""
        with self._lock:
            r = self._con.execute(
                'SELECT id, ts, source, program, raw, message '
                "FROM events WHERE id = ?", [int(row_id)]).fetchone()
        if not r:
            return {"found": False}
        raw = r[4]
        pretty = raw
        if raw:
            try:
                import json as _json
                pretty = _json.dumps(_json.loads(raw), indent=2, ensure_ascii=False)
            except Exception:  # noqa: BLE001
                pretty = raw
        return {"found": True, "id": r[0], "ts": _jsonable(r[1]),
                "source": r[2], "program": r[3],
                "raw": raw, "pretty": pretty or r[5] or ""}

    _IOC_TEXT = ("concat_ws(' ', src_ip, exe, path, \"user\", method, "
                 "referer, user_agent, message, host, program, source, raw)")

    def ioc_sweep(self, iocs: list[str], per: int = 50) -> list[dict]:
        """Barrido de IOCs: por cada indicador, nº de eventos y una muestra.
        Búsqueda literal (case-insensitive) sobre campos relevantes + raw."""
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
                        "SELECT id, ts, source, program, host, \"user\", "
                        "coalesce(exe, path, message, '') AS detail "
                        f"FROM events WHERE {self._IOC_TEXT} ILIKE ? ESCAPE '\\' "
                        "ORDER BY ts NULLS LAST, id LIMIT ?",
                        [like, per]).fetchall()
                out.append({"ioc": io, "count": total,
                            "hits": [{"id": r[0], "ts": _jsonable(r[1]),
                                      "source": r[2], "program": r[3], "host": r[4],
                                      "user": r[5], "detail": r[6]} for r in rows]})
        return out

    def reset(self) -> None:
        with self._lock:
            self._con.execute("DELETE FROM events")
            self._seq_dirty = True

    # ------------------------------------------------------------------
    # GTFOBins: binarios realmente ejecutados en los logs cargados.
    # Señales: exe de auditd (execve), primer token de bash_history, el binario
    # de COMMAND= en sudo, y el binario de sh_command="…" / shell_command="…"
    # (logs de shell de appliance BSD: /var/log/sh.log, /var/log/bash.log).
    # Devuelve el basename en minúsculas.
    # ------------------------------------------------------------------
    _GTFO_B_EXE = r"lower(regexp_extract(coalesce(ev.exe,''),'([^/]+)$',1))"
    _GTFO_B_BASH = (r"lower(regexp_extract(regexp_extract(trim(coalesce(ev.message,'')),"
                    r"'^(\S+)',1),'([^/]+)$',1))")
    _GTFO_B_SUDO = (r"lower(regexp_extract(regexp_extract(coalesce(ev.message,''),"
                    r"'COMMAND=([^\s]+)',1),'([^/]+)$',1))")
    # appliance sh.log / bash.log: sh_command="<cmd> …" / shell_command="<cmd> …"
    _GTFO_B_NSSH = (r"lower(regexp_extract(regexp_extract(coalesce(ev.message,''),"
                    r"'(?:sh_command|shell_command)=\W?([A-Za-z0-9._/-]+)',1),"
                    r"'([^/]+)$',1))")
    _NSSH_WHERE = ("(ev.message LIKE '%sh_command=%' "
                   "OR ev.message LIKE '%shell_command=%')")

    def gtfobins_candidates(self) -> list[dict[str, Any]]:
        """Binarios ejecutados (basename) con su nº de apariciones."""
        sql = (
            "WITH cand AS (\n"
            f"  SELECT {self._GTFO_B_EXE} AS b, ev.id AS id FROM events ev "
            "WHERE ev.exe IS NOT NULL AND ev.exe<>''\n"
            "  UNION ALL\n"
            f"  SELECT {self._GTFO_B_BASH} AS b, ev.id AS id FROM events ev "
            "WHERE ev.source='bash_history' AND ev.message IS NOT NULL\n"
            "  UNION ALL\n"
            f"  SELECT {self._GTFO_B_SUDO} AS b, ev.id AS id FROM events ev "
            "WHERE ev.message LIKE '%COMMAND=%'\n"
            "  UNION ALL\n"
            f"  SELECT {self._GTFO_B_NSSH} AS b, ev.id AS id FROM events ev "
            f"WHERE {self._NSSH_WHERE}\n"
            ")\n"
            "SELECT b, count(*) AS c FROM cand "
            "WHERE b IS NOT NULL AND b<>'' GROUP BY b ORDER BY c DESC"
        )
        with self._lock:
            rows = self._con.execute(sql).fetchall()
        return [{"bin": r[0], "count": r[1]} for r in rows]

    def gtfobins_samples(self, binname: str, limit: int = 5) -> list[dict[str, Any]]:
        """Ejemplos reales de log donde ese binario aparece ejecutado."""
        sql = (
            'SELECT ev.id, ev.ts, ev.source, ev."user", '
            "coalesce(ev.message, ev.raw, ev.exe) AS detalle\n"
            "FROM events ev WHERE\n"
            f"  {self._GTFO_B_EXE} = ?\n"
            f"  OR (ev.source='bash_history' AND {self._GTFO_B_BASH} = ?)\n"
            f"  OR {self._GTFO_B_SUDO} = ?\n"
            f"  OR ({self._NSSH_WHERE} AND {self._GTFO_B_NSSH} = ?)\n"
            "ORDER BY ev.ts NULLS LAST, ev.id LIMIT ?"
        )
        with self._lock:
            rows = self._con.execute(
                sql, [binname, binname, binname, binname, limit]).fetchall()
        return [{"id": r[0], "ts": _jsonable(r[1]), "source": r[2],
                 "user": r[3], "detalle": r[4]} for r in rows]

    def gtfobins_privilege(self, binname: str) -> dict[str, Any]:
        """Contexto de privilegio con el que corrió ese binario:
        - via_sudo: apareció en un COMMAND= de sudo.
        - as_root: algún execve/syscall con euid=0 o uid=0.
        - escalation / login_users: euid=0 con usuario de login (auid) no-root
          (indicio de escalada). El bit SUID real NO es observable solo con logs.
        """
        sql_root = (
            "SELECT\n"
            "  max(CASE WHEN (ev.extra->>'euid')='0' OR (ev.extra->>'uid')='0' "
            "THEN 1 ELSE 0 END) AS as_root,\n"
            "  string_agg(DISTINCT CASE WHEN (ev.extra->>'auid') "
            "NOT IN ('0','4294967295') AND (ev.extra->>'auid') IS NOT NULL\n"
            "    AND ((ev.extra->>'euid')='0' OR (ev.extra->>'uid')='0') "
            "THEN (ev.extra->>'auid') END, ',') AS esc_auids\n"
            f"FROM events ev WHERE {self._GTFO_B_EXE} = ?"
        )
        sql_sudo = (
            "SELECT count(*) FROM events ev WHERE ev.message LIKE '%COMMAND=%' "
            f"AND {self._GTFO_B_SUDO} = ?"
        )
        # Shell de appliance BSD: el acceso a la BSD shell (sh_command=) es un
        # contexto privilegiado (root de la appliance), así que lo tratamos como as_root.
        sql_nssh = (
            f"SELECT count(*) FROM events ev WHERE {self._NSSH_WHERE} "
            f"AND {self._GTFO_B_NSSH} = ?"
        )
        with self._lock:
            r = self._con.execute(sql_root, [binname]).fetchone()
            sudo_n = self._con.execute(sql_sudo, [binname]).fetchone()[0]
            nssh_n = self._con.execute(sql_nssh, [binname]).fetchone()[0]
        as_root = bool(r[0]) if r and r[0] is not None else False
        esc = [a for a in (r[1].split(",") if r and r[1] else []) if a]
        return {"via_sudo": bool(sudo_n), "as_root": as_root or bool(nssh_n),
                "via_nssh": bool(nssh_n),
                "escalation": bool(esc), "login_users": esc}

    def close(self) -> None:
        self._con.close()


def _jsonable(v: Any) -> Any:
    import datetime as _dt
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat(sep=" ")
    return v
