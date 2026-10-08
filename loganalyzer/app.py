"""Servicio web FastAPI para parsear y consultar logs forenses de Linux.

Endpoints:
  POST /ingest/upload   -> sube ficheros de log (multipart) y los parsea
  POST /ingest/path     -> ingesta un path del servidor (fichero o carpeta)
  POST /query           -> ejecuta SQL de lectura sobre la tabla `events`
  POST /search          -> búsqueda por string/regex (orden y paginación)
  POST /timeline        -> timeline cronológica (filtros, orden, paginación)
  POST /context         -> contexto ±N líneas / ±X minutos de un evento
  POST /ai/chat         -> asistente IA (function calling de solo lectura)
  GET  /mcp/info        -> instrucciones/config del servidor MCP
  POST /sigma/load|run  -> cargar y ejecutar reglas Sigma sobre los eventos
  GET  /stats           -> resumen de lo cargado (incl. claves de `extra`)
  GET  /dbinfo          -> dónde se guarda el caso (fichero DuckDB o memoria)
  POST /reset           -> vacía el almacén
  GET  /schema          -> columnas disponibles
  GET  /                -> UI (Cargar, Explorador, SQL, IA, MCP, Ayuda)
"""
from __future__ import annotations

import datetime
import glob
import os
import re
import sys
import tempfile
import time
from typing import Optional

import json

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .schema import COLUMNS
from .store import EventStore
from .ingest import (ingest_file, ingest_path, iter_ingest_path, count_files,
                     count_bytes, TEXT_PARSERS)
from . import ai as ai_mod
from . import gtfobins as gtfo_mod
from . import geoip as geo_mod
from . import report as report_mod

# pySigma es opcional: si no está, la pestaña Sigma se desactiva sin romper nada.
try:
    from . import sigma_engine
    SIGMA_AVAILABLE = True
    SIGMA_IMPORT_ERROR = None
except Exception as _e:  # noqa: BLE001
    sigma_engine = None
    SIGMA_AVAILABLE = False
    SIGMA_IMPORT_ERROR = str(_e)

SIGMA_DIR = os.environ.get("SIGMA_RULES_DIR", "reglas_sigma")
SIGMA_RULES: list = []      # reglas cargadas en memoria
SIGMA_INFO: dict = {}       # resumen de la última carga

# Almacén. Comportamiento por defecto: NO se crea ningún fichero hasta que cargas
# el primer log; en ese momento se crea un caso con fecha y hora en ./casos (así no
# se acumulan ficheros vacíos y la hora del nombre es la de la carga real). Para
# elegir el fichero desde el inicio, o trabajar sin guardar nada, define DUCKDB_PATH
# (una ruta .duckdb, o ":memory:" para no persistir).
CASES_DIR = "casos"


def _auto_db_path() -> str:
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return os.path.join(CASES_DIR, f"bbdd_{ts}.duckdb")


_env_db = os.environ.get("DUCKDB_PATH")
if _env_db:
    # el usuario fijó el fichero (o ":memory:"): se usa tal cual desde el arranque
    DB_PATH = _env_db
    AUTO_PENDING = False
    STORE = EventStore(DB_PATH)
    if DB_PATH != ":memory:":
        print(f"[loganalyzer] Caso: {os.path.abspath(DB_PATH)}", file=sys.stderr)
else:
    # por defecto: en memoria y "pendiente"; se materializa a fichero al 1er log
    DB_PATH = ":memory:"
    AUTO_PENDING = True
    STORE = EventStore(":memory:")


def _ensure_persistent() -> None:
    """Materializa el caso por defecto a un fichero la primera vez que se va a
    cargar algo. El store en memoria está vacío en ese momento, así que el cambio
    no pierde datos."""
    global STORE, DB_PATH, AUTO_PENDING
    if not AUTO_PENDING:
        return
    os.makedirs(CASES_DIR, exist_ok=True)
    path = _auto_db_path()
    new_store = EventStore(path)
    old = STORE
    STORE = new_store
    DB_PATH = path
    AUTO_PENDING = False
    os.environ["DUCKDB_PATH"] = path
    try:
        old.close()
    except Exception:  # noqa: BLE001
        pass
    print(f"[loganalyzer] Caso guardado en: {os.path.abspath(path)}",
          file=sys.stderr)

app = FastAPI(title="Longanizer", version="1.0")


@app.on_event("startup")
def _geoip_autorefresh():
    """Al arrancar, actualiza GeoIP en segundo plano solo si falta o está
    caducada (>30 días). No bloquea el arranque y es silenciosa sin red."""
    try:
        geo_mod.auto_refresh_async(30)
    except Exception:  # noqa: BLE001
        pass


def esc_py(s: str) -> str:
    """Escapa texto para incrustarlo en HTML (bloques <pre>, etc.)."""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class QueryReq(BaseModel):
    sql: str
    params: Optional[list] = None
    limit: Optional[int] = 1000


class PathReq(BaseModel):
    path: str
    type: Optional[str] = None
    base_year: Optional[int] = None
    user: Optional[str] = None
    tz_offset_minutes: int = 0
    catch_all: bool = False


class SearchReq(BaseModel):
    q: str
    regex: bool = False
    source: Optional[str] = None
    limit: int = 500
    offset: int = 0
    sort: Optional[str] = None
    desc: bool = False
    start: Optional[str] = None
    end: Optional[str] = None


class IocReq(BaseModel):
    iocs: list[str] = []
    per: int = 50


class FacetReq(BaseModel):
    field: str
    q: str = ""
    regex: bool = False
    source: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    limit: int = 20


class TimelineReq(BaseModel):
    source: Optional[str] = None
    limit: int = 2000
    offset: int = 0
    start: Optional[str] = None   # ts mínimo (UTC), ej. "2026-09-29" o "2026-09-29 08:00"
    end: Optional[str] = None     # ts máximo (UTC)
    sort: Optional[str] = None
    desc: bool = False


class ContextReq(BaseModel):
    id: Optional[int] = None      # ancla exacta (id interno; al pinchar un hit)
    seq: Optional[int] = None     # ancla por posición en la timeline (# visible)
    before: float = 5
    after: float = 5
    unit: str = "lines"  # "lines" | "minutes" | "seconds"


class AiReq(BaseModel):
    message: str
    base_url: str                 # endpoint compatible OpenAI (/v1)
    model: str
    api_key: Optional[str] = None
    user: Optional[str] = None            # p.ej. usuario de LiteLLM
    extra_headers: Optional[dict] = None  # cabeceras extra (LiteLLM, etc.)
    history: Optional[list] = None        # turnos previos [{role,content}]


class SigmaLoadReq(BaseModel):
    path: Optional[str] = None    # carpeta de reglas (por defecto SIGMA_DIR)


class MarkReq(BaseModel):
    event_id: Optional[int] = None
    estado: str = "pendiente"
    etiqueta: Optional[str] = None
    nota: Optional[str] = None
    regla: Optional[str] = None
    ctx_n: int = 10


class MarkUpdateReq(BaseModel):
    mid: int
    estado: Optional[str] = None
    etiqueta: Optional[str] = None
    nota: Optional[str] = None


class MarkDeleteReq(BaseModel):
    mid: int


@app.get("/schema")
def schema():
    return {
        "columns": [{"name": n, "type": t} for n, t in COLUMNS],
        "log_types": list(TEXT_PARSERS),
    }


@app.get("/stats")
def stats():
    return STORE.stats()


@app.get("/dbinfo")
def dbinfo():
    """Dónde se está guardando el caso (para que el usuario lo sepa y lo encuentre)."""
    if AUTO_PENDING:
        return {"path": None, "memory": False, "pending": True, "filename": None}
    mem = DB_PATH == ":memory:"
    return {"path": None if mem else os.path.abspath(DB_PATH), "pending": False,
            "memory": mem, "filename": None if mem else os.path.basename(DB_PATH)}


@app.get("/db/list")
def db_list():
    """Lista los casos .duckdb guardados (carpeta ./casos y directorio actual),
    para poder abrir uno existente desde la interfaz sin escribir la ruta."""
    found: dict[str, dict] = {}
    for d in (CASES_DIR, os.getcwd()):
        if not os.path.isdir(d):
            continue
        for f in glob.glob(os.path.join(d, "*.duckdb")):
            try:
                stt = os.stat(f)
            except OSError:
                continue
            ap = os.path.abspath(f)
            found[ap] = {
                "path": ap, "name": os.path.basename(f), "size": stt.st_size,
                "mtime": datetime.datetime.fromtimestamp(stt.st_mtime)
                                 .strftime("%Y-%m-%d %H:%M"),
            }
    cases = sorted(found.values(), key=lambda x: x["mtime"], reverse=True)
    cur = None if DB_PATH == ":memory:" else os.path.abspath(DB_PATH)
    return {"current": cur, "cases": cases}


class DbOpenReq(BaseModel):
    path: str


@app.post("/db/open")
def db_open(req: DbOpenReq):
    """Cambia el almacén activo a un .duckdb existente (en caliente, sin reiniciar).

    Se valida que el fichero exista y que se pueda abrir como DuckDB con la tabla
    `events`; los datos quedan disponibles al momento en el Explorador."""
    global STORE, DB_PATH, AUTO_PENDING
    p = (req.path or "").strip()
    if not p:
        raise HTTPException(status_code=400, detail="Empty path.")
    if p != ":memory:" and not os.path.isfile(p):
        raise HTTPException(status_code=404, detail=f"File does not exist: {p}")
    try:
        new_store = EventStore(p)
        new_store.stats()  # comprobación de que es una base usable
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=400,
            detail=f"Could not open as DuckDB (invalid file or "
                   f"locked by another process?): {e}")
    old = STORE
    STORE = new_store
    DB_PATH = p
    AUTO_PENDING = False
    os.environ["DUCKDB_PATH"] = p
    try:
        old.close()
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True, "stats": STORE.stats(), "dbinfo": dbinfo()}


@app.post("/reset")
def reset():
    STORE.reset()
    return {"ok": True}


@app.post("/query")
def query(req: QueryReq):
    try:
        return STORE.query(req.sql, req.params, req.limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Error SQL: {e}")


def _geo_enrich(result: dict, ip_fields=("src_ip",)) -> dict:
    """Añade dos columnas calculadas a {columns, rows}: 'asn' (p.ej. AS3352) y
    'org' (nombre de la organización/ISP), resueltas por GeoIP a partir de la
    primera IP no vacía de la fila. Vacías si no hay base ASN o la IP es
    privada. Solo afecta a las filas de la página (barato)."""
    cols = result.get("columns")
    rows = result.get("rows")
    if not cols or rows is None or "asn" in cols:
        return result
    idxs = [cols.index(f) for f in ip_fields if f in cols]
    if not idxs:
        return result
    cache: dict[str, tuple] = {}
    out = []
    for r in rows:
        ip = None
        for ix in idxs:
            v = r[ix]
            if v:
                ip = str(v)
                break
        asn = org = None
        if ip:
            if ip in cache:
                asn, org = cache[ip]
            else:
                try:
                    g = geo_mod.lookup(ip)
                    asn = ("AS" + str(g["asn"])) if g.get("asn") else None
                    org = g.get("org")
                except Exception:  # noqa: BLE001
                    asn = org = None
                cache[ip] = (asn, org)
        out.append(list(r) + [asn, org])
    result = dict(result)
    result["columns"] = list(cols) + ["asn", "org"]
    result["rows"] = out
    return result


@app.post("/search")
def search(req: SearchReq):
    try:
        return _geo_enrich(STORE.search(req.q, req.regex, req.source, req.limit,
                            req.offset, req.sort, req.desc, req.start, req.end))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Search error: {e}")


def _facet_geo(req: "FacetReq") -> dict:
    """Facetas de asn/org: facetea src_ip y agrega por ASN u Org vía GeoIP."""
    base = STORE.facet("src_ip", req.q, req.regex, req.source,
                       req.start, req.end, 500)
    agg: dict[str, int] = {}
    for row in base["values"]:
        g = geo_mod.lookup(str(row["value"]))
        if req.field == "asn":
            key = ("AS" + str(g["asn"])) if g.get("asn") else None
        else:
            key = g.get("org")
        if not key:
            continue
        agg[key] = agg.get(key, 0) + row["count"]
    vals = sorted(({"value": k, "count": v} for k, v in agg.items()),
                  key=lambda x: -x["count"])[:req.limit]
    return {"field": req.field, "matched": base["matched"],
            "distinct": len(agg), "values": vals}


@app.post("/facets")
def facets_ep(req: FacetReq):
    try:
        if req.field in ("asn", "org"):
            return _facet_geo(req)
        return STORE.facet(req.field, req.q, req.regex, req.source,
                           req.start, req.end, req.limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/rawevent")
def rawevent_ep(id: int):
    return STORE.raw_event(id)


_IOC_IPRE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _ioc_geo(results: list) -> list:
    """Añade asn/org/private a los IOC que son una IP (vía GeoIP)."""
    for r in results:
        ioc = str(r.get("ioc", "")).strip()
        if _IOC_IPRE.match(ioc):
            try:
                g = geo_mod.lookup(ioc)
                r["private"] = g.get("private")
                if g.get("asn"):
                    r["asn"] = "AS" + str(g["asn"])
                if g.get("org"):
                    r["org"] = g["org"]
            except Exception:  # noqa: BLE001
                pass
    return results


@app.post("/ioc")
def ioc_ep(req: IocReq):
    return {"results": _ioc_geo(STORE.ioc_sweep(req.iocs[:1000],
                                                per=min(req.per, 200)))}


@app.get("/network")
def network_ep(ip: Optional[str] = None, port: Optional[str] = None,
               source: Optional[str] = None, event: Optional[str] = None):
    return {"rows": STORE.network(ip=ip, port=port, source=source, event=event)}


@app.get("/attack")
def attack_ep():
    return _attack_matrix()


@app.post("/attack/stream")
def attack_stream_ep():
    """Igual que /attack pero emite progreso por regla (NDJSON) y, al final, la
    matriz en el item {done:True, matrix:{...}} para que la barra avance."""
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=400, detail="pySigma not available")
    if not SIGMA_RULES:
        raise HTTPException(status_code=400, detail="No Sigma rules loaded.")

    def gen():
        try:
            for item in sigma_engine.iter_run(STORE, SIGMA_RULES, limit_per_rule=50):
                if item.get("done"):
                    item = {"done": True,
                            "matrix": _attack_build(item.get("findings", [])),
                            "i": item.get("rules_total"), "total": item.get("rules_total")}
                yield json.dumps(item, ensure_ascii=False, default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


_TACTICS = [("reconnaissance", "Reconnaissance"), ("resource-development", "Resource Dev"),
            ("initial-access", "Initial Access"), ("execution", "Execution"),
            ("persistence", "Persistence"), ("privilege-escalation", "Priv Esc"),
            ("defense-evasion", "Defense Evasion"), ("credential-access", "Credential Access"),
            ("discovery", "Discovery"), ("lateral-movement", "Lateral Movement"),
            ("collection", "Collection"), ("command-and-control", "C2"),
            ("exfiltration", "Exfiltration"), ("impact", "Impact")]
_LEVEL_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _worst_level(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if _LEVEL_ORDER.get(a, 0) >= _LEVEL_ORDER.get(b, 0) else b


def _attack_matrix():
    """Matriz ATT&CK del caso a partir de los hits de Sigma (ruleset cargado)."""
    if not SIGMA_AVAILABLE:
        return {"tactics": [], "total_findings": 0, "error": "pySigma not available"}
    if not SIGMA_RULES:
        return {"tactics": [], "total_findings": 0}
    try:
        res = sigma_engine.run(STORE, SIGMA_RULES, limit_per_rule=50)
    except Exception:  # noqa: BLE001
        return {"tactics": [], "total_findings": 0}
    return _attack_build(res.get("findings", []))


def _attack_build(findings):
    """Construye la matriz ATT&CK a partir de una lista de findings de Sigma."""
    import re as _re
    tac = {k: {"key": k, "label": lab, "techs": {}} for k, lab in _TACTICS}
    other = {"key": "other", "label": "(no tactic tag)", "techs": {}}
    nfind = 0
    for f in findings:
        nfind += 1
        tags = [str(t).lower() for t in f.get("tags", [])]
        tactics = [t.split("attack.", 1)[1] for t in tags
                   if t.startswith("attack.") and not _re.match(r"attack\.t\d", t)]
        techs = [t.split("attack.", 1)[1].upper() for t in tags
                 if _re.match(r"attack\.t\d", t)]
        sample_ids = [h[1] for h in f.get("hits", [])[:5] if len(h) > 1]
        buckets = [tac[t] for t in tactics if t in tac] or [other]
        for b in buckets:
            for tech in (techs or ["(no technique)"]):
                e = b["techs"].setdefault(
                    tech, {"tech": tech, "count": 0, "rules": [], "level": None, "ids": []})
                e["count"] += f.get("count", 0)
                e["rules"].append({"title": f.get("title"), "count": f.get("count"),
                                   "level": f.get("level")})
                e["ids"] = (e["ids"] + sample_ids)[:10]
                e["level"] = _worst_level(e["level"], f.get("level"))
    cols = []
    for k, _lab in _TACTICS:
        b = tac[k]
        if b["techs"]:
            cols.append(dict(b, techs=sorted(b["techs"].values(), key=lambda x: -x["count"])))
    if other["techs"]:
        cols.append(dict(other, techs=sorted(other["techs"].values(), key=lambda x: -x["count"])))
    return {"tactics": cols, "total_findings": nfind}


@app.post("/timeline")
def timeline(req: TimelineReq):
    try:
        return _geo_enrich(STORE.timeline(req.source, req.limit, req.offset,
                           req.start, req.end, req.sort, req.desc))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/context")
def context(req: ContextReq):
    try:
        return _geo_enrich(STORE.context(req.id, req.before, req.after,
                           req.unit, req.seq))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/mcp/info")
def mcp_info():
    """Instrucciones + config para conectar el servidor MCP a Claude Desktop/Code."""
    db = ":memory:" if AUTO_PENDING else DB_PATH
    db_show = db if db != ":memory:" else "/path/to/case.duckdb"
    persist_warn = ""
    if db == ":memory:":
        extra = (" You have not loaded any log yet, so there is no file yet; as "
                 "soon as you load the first one, a file will be created in <code>casos/</code> and "
                 "you will see its path here.") if AUTO_PENDING else ""
        persist_warn = (
            "<div class=\"err\" style=\"white-space:normal\">There is no case file in use "
            "right now, so the MCP server <b>would not see</b> this data." + extra +
            " To use MCP, load logs (the file will be created) or start with a fixed one: "
            "<code>DUCKDB_PATH=/ruta/al/caso.duckdb python -m loganalyzer.app</code> "
            "(or CLI ingest with <code>--db</code>) and point MCP at the same "
            "file.</div>")
    claude_json = (
        '{\n'
        '  "mcpServers": {\n'
        '    "longanizer": {\n'
        '      "command": "python",\n'
        '      "args": ["-m", "loganalyzer.mcp_server"],\n'
        '      "env": { "DUCKDB_PATH": "' + db_show + '" }\n'
        '    }\n'
        '  }\n'
        '}')
    html = f"""
   <p>The <b>MCP server</b> exposes your logs as <b>read-only</b> tools
   for an MCP client (Claude Desktop, Claude Code, or another): so you can ask
   in natural language from your own client, without the web API.</p>
   {persist_warn}
   <h3>1 · Start the MCP server (stdio)</h3>
   <pre>DUCKDB_PATH={db_show} python -m loganalyzer.mcp_server</pre>
   <p class="muted">Share the <b>same DuckDB file</b> as the web/ingest so it
   sees the same events.</p>
   <h3>2 · Claude Desktop</h3>
   <p>Edit <code>claude_desktop_config.json</code>
   (Settings &rarr; Developer &rarr; Edit Config) and add:</p>
   <pre>{esc_py(claude_json)}</pre>
   <h3>2 · (alternative) Claude Code</h3>
   <pre>claude mcp add longanizer -e DUCKDB_PATH={db_show} -- python -m loganalyzer.mcp_server</pre>
   <h3>3 · Available tools</h3>
   <ul>
    <li><code>buscar_logs(q, regex?, source?, limit?)</code> — text/IOC or regex search.</li>
    <li><code>consulta_sql(sql)</code> — read-only SQL over <code>events</code>.</li>
    <li><code>contexto(seq?/id?, before?, after?, unit?)</code> — lines around an event.</li>
    <li><code>estadisticas()</code> — summary of what is loaded.</li>
    <li><code>ver_timeline(source?, start?, end?, limit?)</code> — chronological timeline.</li>
   </ul>
   <p class="muted">All are read-only: none can modify the case data.</p>
"""
    return {"html": html, "db": db}


@app.post("/ai/chat")
def ai_chat(req: AiReq):
    """Pregunta en lenguaje natural; el modelo usa las herramientas de solo
    lectura (buscar/SQL/contexto/stats/timeline) para responder con datos."""
    cfg = {"base_url": req.base_url, "model": req.model, "api_key": req.api_key,
           "user": req.user, "extra_headers": req.extra_headers}
    try:
        return ai_mod.chat(STORE, req.message, cfg, history=req.history)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Error con el endpoint de IA: {e}")


@app.get("/sigma/status")
def sigma_status():
    return {"available": SIGMA_AVAILABLE, "error": SIGMA_IMPORT_ERROR,
            "rules_dir": os.path.abspath(SIGMA_DIR), "loaded": len(SIGMA_RULES),
            "info": SIGMA_INFO}


def _sigma_reload(path: str) -> dict:
    """Carga reglas desde `path`, deja un resumen con la vista de aplicabilidad."""
    rules, errors = sigma_engine.load_rules_dir(path)
    SIGMA_RULES[:] = rules
    pv = sigma_engine.preview(STORE, rules)
    global SIGMA_INFO
    SIGMA_INFO = {"loaded": len(rules), "errors": errors, "preview": pv,
                  "path": os.path.abspath(path)}
    return SIGMA_INFO


@app.post("/sigma/load")
def sigma_load(req: SigmaLoadReq):
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"pySigma not available: {SIGMA_IMPORT_ERROR}")
    path = (req.path or SIGMA_DIR).strip()
    if not os.path.exists(path):
        raise HTTPException(status_code=404,
                            detail=f"Rules folder does not exist: {path}")
    try:
        return _sigma_reload(path)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Error loading rules: {e}")


@app.post("/sigma/load/stream")
def sigma_load_stream(req: SigmaLoadReq):
    """Carga reglas fichero a fichero emitiendo progreso (NDJSON)."""
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"pySigma not available: {SIGMA_IMPORT_ERROR}")
    path = (req.path or SIGMA_DIR).strip()
    if not os.path.exists(path):
        raise HTTPException(status_code=404,
                            detail=f"Rules folder does not exist: {path}")

    def gen():
        try:
            files = sigma_engine.list_rule_files(path)
            yield json.dumps({"total": len(files)}) + "\n"
            rules: list = []
            errors: list = []
            for i, fp in enumerate(files, 1):
                r, e = sigma_engine.load_one_file(fp)
                rules.extend(r)
                errors.extend(e)
                yield json.dumps({"i": i, "total": len(files),
                                  "file": os.path.basename(fp),
                                  "loaded": len(rules),
                                  "errors": len(errors)}) + "\n"
            bulk = sigma_engine.try_bulk_load(files) if files else []
            final = bulk if bulk is not None else rules
            SIGMA_RULES[:] = final
            pv = sigma_engine.preview(STORE, final)
            global SIGMA_INFO
            SIGMA_INFO = {"loaded": len(final), "errors": errors, "preview": pv,
                          "path": os.path.abspath(path)}
            yield json.dumps({"done": True, "loaded": len(final),
                              "errors": errors, "preview": pv,
                              "path": os.path.abspath(path)}, default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@app.post("/sigma/upload")
async def sigma_upload(files: list[UploadFile] = File(...)):
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"pySigma not available: {SIGMA_IMPORT_ERROR}")
    os.makedirs(SIGMA_DIR, exist_ok=True)
    saved = 0
    for uf in files:
        name = os.path.basename(uf.filename or "")
        if not name.lower().endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(SIGMA_DIR, name), "wb") as fh:
            fh.write(await uf.read())
        saved += 1
    info = _sigma_reload(SIGMA_DIR)
    info["saved"] = saved
    return info


@app.get("/sigma/rules")
def sigma_rules_ep():
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"pySigma not available: {SIGMA_IMPORT_ERROR}")
    try:
        return {"rules": sigma_engine.list_rules(STORE, SIGMA_RULES)}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Error listing rules: {e}")


@app.post("/sigma/run")
def sigma_run_ep():
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"pySigma not available: {SIGMA_IMPORT_ERROR}")
    if not SIGMA_RULES:
        raise HTTPException(status_code=400,
                            detail="No rules loaded. Load a folder or upload .yml first.")
    try:
        return sigma_engine.run(STORE, SIGMA_RULES, limit_per_rule=200)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Error running Sigma: {e}")


@app.post("/sigma/run/stream")
def sigma_run_stream_ep():
    """Igual que /sigma/run pero emite progreso por regla en NDJSON: una línea
    {"i","total","title","found","hits"} por regla y una final {"done":true,...}
    con el resultado completo."""
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"pySigma not available: {SIGMA_IMPORT_ERROR}")
    if not SIGMA_RULES:
        raise HTTPException(status_code=400,
                            detail="No rules loaded. Load a folder or upload .yml first.")

    def gen():
        try:
            for item in sigma_engine.iter_run(STORE, SIGMA_RULES, limit_per_rule=200):
                yield json.dumps(item, ensure_ascii=False, default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


# ---------------------------------------------------------------------------
# GTFOBins: catálogo de abuso de binarios + chequeo de ejecuciones en los logs
# ---------------------------------------------------------------------------
@app.get("/gtfobins/status")
def gtfobins_status_ep():
    return gtfo_mod.status()


@app.post("/gtfobins/refresh")
def gtfobins_refresh_ep():
    try:
        return gtfo_mod.refresh()
    except Exception as e:  # noqa: BLE001
        msg = getattr(e, "stderr", None) or str(e)
        raise HTTPException(
            status_code=500,
            detail=("Could not update GTFOBins (neither via git nor download): "
                    f"{str(msg)[:200]}. The bundled catalog is still available; to "
                    "update manually, replace gtfobins_data/gtfobins.json."))


@app.get("/gtfobins/list")
def gtfobins_list_ep():
    d = gtfo_mod.load()
    if not d:
        raise HTTPException(status_code=400,
                            detail="GTFOBins catalog not loaded. Click «Update catalog».")
    return d


def _gtfobins_check_data() -> Optional[dict]:
    """Cruce catálogo×ejecutados (reutilizado por el endpoint y el informe).
    Devuelve None si el catálogo no está cargado."""
    d = gtfo_mod.load()
    if not d:
        return None
    bins = d.get("binaries", {})
    cands = STORE.gtfobins_candidates()
    matched = []
    for c in cands:
        name = c["bin"]
        info = bins.get(name)
        if not info:
            continue
        priv = STORE.gtfobins_privilege(name)
        danger = (priv["via_sudo"] or priv["as_root"]
                  or priv["escalation"] or priv.get("via_nssh"))
        matched.append({
            "bin": name, "count": c["count"],
            "functions": info["functions"],
            "samples": STORE.gtfobins_samples(name, 200),
            "privilege": priv, "danger": danger,
        })
    matched.sort(key=lambda x: (0 if x["danger"] else 1, -x["count"]))
    return {"matched": matched, "checked": len(cands), "catalog": d.get("count")}


@app.post("/gtfobins/check")
def gtfobins_check_ep():
    res = _gtfobins_check_data()
    if res is None:
        raise HTTPException(status_code=400,
                            detail="GTFOBins catalog not loaded. Click «Update catalog» first.")
    return res


@app.get("/gtfobins/samples")
def gtfobins_samples_ep(bin: str, limit: int = 100000):
    """Todas las apariciones de un binario concreto (para «Ver todos»)."""
    return {"bin": bin, "samples": STORE.gtfobins_samples(bin, limit)}


# ---------------------------------------------------------------------------
# Resumen / Dashboard  (+ GeoIP de las top IPs)
# ---------------------------------------------------------------------------
@app.get("/dashboard")
def dashboard_ep():
    d = STORE.dashboard()
    # enriquece las top IPs con interna/externa y país/ASN/ISP (si hay base)
    for row in d.get("top_ip", []):
        g = geo_mod.lookup(row["k"])
        row["private"] = g["private"]
        row["country"] = g["country"]
        row["country_code"] = g["country_code"]
        row["asn"] = g["asn"]
        row["org"] = g["org"]
    # Top ISP y Top países: agrupa el recuento por evento de TODAS las IPs
    from collections import Counter
    isp: Counter = Counter()
    country: Counter = Counter()
    for ip, n in STORE.ip_counts():
        g = geo_mod.lookup(ip)
        if g["private"]:
            isp["red interna"] += n
            country["red interna"] += n
            continue
        isp[g["org"] or "(desconocido)"] += n
        country[g["country"] or "(desconocido)"] += n
    d["top_isp"] = [{"k": k, "n": v} for k, v in isp.most_common(10)]
    d["top_country"] = [{"k": k, "n": v} for k, v in country.most_common(10)]
    d["geoip"] = geo_mod.status()
    return d


@app.get("/report")
def report_ep(download: int = 0):
    """Informe HTML autocontenido con todo el caso (colapsable)."""
    d = STORE.dashboard()
    for row in d.get("top_ip", []):
        g = geo_mod.lookup(row["k"])
        row["private"] = g["private"]; row["country"] = g["country"]
        row["country_code"] = g["country_code"]; row["asn"] = g["asn"]; row["org"] = g["org"]
    sigma_res = None
    if SIGMA_AVAILABLE and SIGMA_RULES:
        try:
            sigma_res = sigma_engine.run(STORE, SIGMA_RULES)
        except Exception:  # noqa: BLE001
            sigma_res = None
    gtfo_res = _gtfobins_check_data()
    marks = STORE.mark_list()
    case = None if (AUTO_PENDING or DB_PATH == ":memory:") else os.path.basename(DB_PATH)
    html_doc = report_mod.build(
        meta={"title": "Longanizer report",
              "generated": report_mod.generated_now(), "case": case},
        dashboard=d, sigma=sigma_res, gtfo=gtfo_res, marks=marks)
    headers = {}
    if download:
        fn = "longanizer_report_" + time.strftime("%Y%m%d_%H%M", time.gmtime()) + ".html"
        headers["Content-Disposition"] = f'attachment; filename="{fn}"'
    return HTMLResponse(content=html_doc, headers=headers)


@app.get("/ipinfo")
def ipinfo_ep(ip: str):
    d = STORE.ip_detail(ip)
    d["geo"] = geo_mod.lookup(ip)
    return d


@app.get("/geoip/status")
def geoip_status_ep():
    return geo_mod.status()


# ---------------------------------------------------------------------------
# Marcas / triage (persisten en el .duckdb del caso)
# ---------------------------------------------------------------------------
@app.get("/marks")
def marks_list_ep(estado: Optional[str] = None):
    return {"marks": STORE.mark_list(estado),
            "counts": STORE.mark_counts(),
            "persistent": (not AUTO_PENDING and DB_PATH != ":memory:")}


@app.post("/marks")
def marks_add_ep(req: MarkReq):
    _ensure_persistent()  # materializa el caso para que la marca persista
    return STORE.mark_add(req.event_id, req.estado, req.etiqueta, req.nota,
                          regla=req.regla, ctx_n=req.ctx_n)


@app.post("/marks/update")
def marks_update_ep(req: MarkUpdateReq):
    ok = STORE.mark_update(req.mid, req.estado, req.etiqueta, req.nota)
    if not ok:
        raise HTTPException(status_code=400, detail="Nothing to update.")
    return {"ok": True}


@app.post("/marks/delete")
def marks_delete_ep(req: MarkDeleteReq):
    STORE.mark_delete(req.mid)
    return {"ok": True}


@app.post("/geoip/refresh")
def geoip_refresh_ep():
    try:
        return geo_mod.refresh()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=("Could not download the GeoIP base (DB-IP Lite): "
                    f"{str(e)[:200]}. Internal/external IP tagging works "
                    "regardless, with no base."))


@app.post("/ingest/path/stream")
def ingest_path_stream_ep(req: PathReq):
    """Igual que /ingest/path pero emite el resultado de cada fichero en NDJSON
    según se procesa, para mostrar progreso en vivo. Primera línea: {"total": N}
    (estimación de ficheros, sin expandir comprimidos)."""
    if not os.path.exists(req.path):
        raise HTTPException(status_code=404, detail=f"Does not exist: {req.path}")
    _ensure_persistent()

    def gen():
        yield json.dumps({"total": count_files(req.path),
                          "total_bytes": count_bytes(req.path)}) + "\n"
        byte_prog = [0]
        try:
            for item in iter_ingest_path(STORE, req.path, req.type, req.base_year,
                                         req.user, req.tz_offset_minutes,
                                         skip_unknown=True, catch_all=req.catch_all,
                                         byte_prog=byte_prog):
                yield json.dumps(item, ensure_ascii=False, default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@app.post("/ingest/path")
def ingest_path_ep(req: PathReq):
    if not os.path.exists(req.path):
        raise HTTPException(status_code=404, detail=f"Does not exist: {req.path}")
    _ensure_persistent()
    try:
        res = ingest_path(STORE, req.path, req.type, req.base_year, req.user,
                          req.tz_offset_minutes, skip_unknown=True,
                          catch_all=req.catch_all)
        return {"ingested": res, "stats": STORE.stats()}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/ingest/upload")
async def ingest_upload(
    files: list[UploadFile] = File(...),
    type: Optional[str] = Form(None),
    base_year: Optional[int] = Form(None),
    user: Optional[str] = Form(None),
    tz_offset_minutes: int = Form(0),
    relpaths: list[str] = Form(default=[]),
    catch_all: bool = Form(False),
):
    _ensure_persistent()
    results = []
    for i, uf in enumerate(files):
        suffix = os.path.basename(uf.filename or "upload")
        # ruta relativa original (carpeta subida) si el cliente la envió
        label = relpaths[i] if i < len(relpaths) and relpaths[i] else suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix="_" + suffix) as tmp:
            tmp.write(await uf.read())
            tmp_path = tmp.name
        try:
            # renombrar para conservar pistas del nombre original en la detección
            real = os.path.join(os.path.dirname(tmp_path), suffix)
            os.replace(tmp_path, real)
            # ingest_path soporta archivos comprimidos subidos (.tar.gz/.zip/.gz...);
            # skip_unknown=True -> un no-log se marca 'saltado' en vez de error
            results.extend(ingest_path(STORE, real, type, base_year, user,
                                       tz_offset_minutes, skip_unknown=True,
                                       label=label, catch_all=catch_all))
        except Exception as e:  # noqa: BLE001
            results.append({"file": label, "error": str(e)})
        finally:
            for p in (tmp_path, locals().get("real", "")):
                if p and os.path.exists(p):
                    os.unlink(p)
    return {"ingested": results, "stats": STORE.stats()}


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Longanizer</title>
<link rel="icon" href="data:image/svg+xml,&lt;svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'&gt;&lt;path d='M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6' fill='none' stroke='%23141414' stroke-width='7.8' stroke-linecap='round'/&gt;&lt;path d='M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6' fill='none' stroke='%23e0485a' stroke-width='5.6' stroke-linecap='round'/&gt;&lt;path d='M7.4 16.8 C10 18.6 15.4 17.6 16.8 8' fill='none' stroke='%23f58a95' stroke-width='1.6' stroke-linecap='round' opacity='.85'/&gt;&lt;/svg&gt;">
<style>
 :root{--bg:#132743;--panel:#1b3357;--panel2:#23416b;--border:#345681;--fg:#eaf1fb;--muted:#a3b6d4;--accent:#5fa3ff;--accent-hi:#83baff;--ink:#07192f;--hit:#4a3d12;--radius:12px;--shadow:0 2px 10px rgba(0,0,0,.28);--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,sans-serif;font-size:14px;line-height:1.55}
 header{padding:18px 28px;border-bottom:1px solid var(--border);display:flex;gap:20px;align-items:baseline;flex-wrap:wrap;background:linear-gradient(180deg,#1d3860,#132743)}
 h1{font-size:19px;margin:0;letter-spacing:.2px}
 .muted{color:var(--muted);font-size:12px}
 .xdec em,em.xdec{font-style:italic}
 .qacwrap{position:relative}
 .qac{position:absolute;left:0;right:0;top:100%;z-index:40;background:var(--panel2);border:1px solid var(--border);border-top:0;border-radius:0 0 8px 8px;max-height:260px;overflow:auto;box-shadow:var(--shadow)}
 .qac.hidden{display:none}
 .qacit{padding:5px 10px;font-family:var(--mono);font-size:12px;cursor:pointer;color:var(--fg)}
 .qacit.on,.qacit:hover{background:var(--accent);color:var(--ink)}
 td.xdec em{font-style:italic;color:var(--accent,#7fd1ff);text-decoration:underline dotted;text-underline-offset:2px}
 main{padding:28px;max-width:1500px;margin:0 auto}
 .tabs{display:flex;gap:6px;margin-bottom:26px;flex-wrap:wrap;border-bottom:1px solid var(--border)}
 .tab{background:transparent;color:var(--muted);border:1px solid transparent;border-bottom:0;border-radius:9px 9px 0 0;padding:11px 20px;cursor:pointer;font-weight:500;margin-bottom:-1px}
 .tab:hover{color:var(--fg);background:var(--panel)}
 .tab.active{background:var(--panel);color:var(--accent);border-color:var(--border);font-weight:600}
 .subnav{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:-18px 0 24px;padding:8px 10px;background:var(--panel);border:1px solid var(--border);border-radius:10px}
 .subnav .subcap{color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-right:4px}
 .subnav .subtab{color:var(--muted);padding:7px 15px;border-radius:7px;cursor:pointer;font-size:13px;font-weight:500}
 .subnav .subtab:hover{color:var(--fg);background:var(--panel2)}
 .subnav .subtab.active{background:var(--accent);color:var(--ink);font-weight:600}
 .c-copy{width:30px;text-align:center;padding:0 2px}
 .copybtn{background:transparent;border:0;color:var(--muted);cursor:pointer;font-size:14px;padding:3px 6px;border-radius:6px;line-height:1}
 .copybtn:hover{color:var(--accent);background:var(--panel2)}
 .copybtn.copied{color:#51d88a}
 td.acts,th.acts{white-space:nowrap;width:1%;padding:2px 4px}
 .actinl{margin-right:8px;white-space:nowrap}
 .revbtn,.rawbtn{background:transparent;border:0;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:6px;line-height:1}
 .revbtn:hover{color:#e3b341;background:var(--panel2)} .revbtn.copied{color:#51d88a}
 .rawbtn:hover{color:var(--accent);background:var(--panel2)} .rawbtn.on{color:var(--accent)}
 .rawpre{background:var(--ink);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:4px 0;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);font-size:12px;max-height:360px;overflow:auto}
 tr.rawrow td{background:var(--bg);padding:6px 10px}
 details.ruleyaml{margin:2px 0 8px} details.ruleyaml>summary{cursor:pointer;color:var(--accent);font-size:12px;font-weight:600;padding:4px 0}
 .rawmodal{position:fixed;inset:0;background:rgba(3,10,22,.72);display:flex;align-items:center;justify-content:center;z-index:50;padding:24px}
 .rawmodal.hidden{display:none}
 .rawmbox{background:var(--panel);border:1px solid var(--border);border-radius:12px;max-width:900px;width:100%;max-height:82vh;display:flex;flex-direction:column;box-shadow:var(--shadow)}
 .rawmbar{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px}
 .rawmbox .rawpre{margin:0;border:0;border-radius:0 0 12px 12px;max-height:none;overflow:auto;flex:1}
 .mkctx{background:var(--ink);border:1px solid var(--border);border-radius:8px;padding:8px 10px;margin-top:6px;white-space:pre-wrap;font-family:var(--mono);font-size:11px;max-height:220px;overflow:auto;color:var(--muted)}
 .mkrule{display:inline-block;background:var(--panel2);border-radius:6px;padding:1px 8px;margin-left:6px;font-size:11px;color:var(--accent-hi)}
 details.mkctxd{margin-top:6px} details.mkctxd>summary{cursor:pointer;color:var(--muted);font-size:11px}
 .xcsv{font-size:11px;padding:3px 10px;margin-left:8px;vertical-align:middle}
 .iocard{border:1px solid var(--border);border-radius:10px;margin:12px 0;overflow:hidden}
 .iocard .iohead{padding:9px 12px;font-size:13px;background:var(--panel)}
 .iocard.ioc-hit .iohead{border-left:4px solid #f85149}
 .iocard.ioc-clean .iohead{border-left:4px solid #3fb950;color:var(--muted)}
 .attgrid{display:flex;gap:10px;overflow-x:auto;padding-bottom:12px;align-items:flex-start}
 .attcol{min-width:158px;flex:0 0 auto;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px}
 .atthead{font-size:12px;font-weight:700;color:var(--fg);margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:6px}
 .atttech{display:flex;justify-content:space-between;gap:8px;align-items:center;background:var(--panel2);border-left:3px solid var(--accent);border-radius:6px;padding:6px 8px;margin-bottom:6px;cursor:pointer;font-size:12px}
 .atttech:hover{filter:brightness(1.18)}
 .atttech .attt{font-family:var(--mono);font-weight:600;flex:1}
 .atttech .attn{background:rgba(0,0,0,.28);border-radius:9px;padding:0 7px;font-weight:700;font-size:11px}
 .atttechrev{order:3;margin-left:4px}
 .atttech.sev-critical{border-left-color:#f85149}
 .atttech.sev-high{border-left-color:#db6d28}
 .atttech.sev-medium,.atttech.sev-med{border-left-color:#d29922}
 .atttech.sev-low{border-left-color:#3fb950}
 .atttech.sev-info,.atttech.sev-informational{border-left-color:#58a6ff}
 .panel{display:none}
 .panel.active{display:block}
 section.panel{padding-top:2px}
 textarea{width:100%;min-height:100px;background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;font-family:var(--mono);font-size:13px;resize:vertical;line-height:1.55}
 input[type=text],input[type=number],select{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
 input[type=text]:focus,input[type=number]:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(95,163,255,.22)}
 .row{display:flex;gap:10px;align-items:center;margin:14px 0;flex-wrap:wrap}
 button{background:var(--accent);color:var(--ink);border:0;border-radius:8px;padding:10px 18px;font-weight:600;cursor:pointer;transition:background .12s}
 button:hover{background:var(--accent-hi)}
 button.sec{background:var(--panel2);color:var(--fg);border:1px solid var(--border)}
 button.sec:hover{background:var(--border)}
 button:disabled{opacity:.45;cursor:not-allowed}
 button:disabled:hover{background:var(--accent)}
 table{border-collapse:collapse;width:100%;margin-top:16px;font-family:var(--mono);font-size:12px}
 th,td{border:1px solid var(--border);padding:8px 12px;text-align:left;white-space:nowrap;max-width:420px;overflow:hidden;text-overflow:ellipsis}
 th{background:var(--panel2);position:sticky;top:0}
 th.sortable{cursor:pointer;user-select:none}
 th.sortable:hover{background:var(--border)}
 .wrap{overflow:auto;max-height:60vh;border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
 .wrap.wide{max-height:70vh}
 tr.hitrow{cursor:pointer}
 tr.hitrow:hover td{background:var(--panel2)}
 #colspanel{border:1px solid var(--border);border-radius:var(--radius);padding:16px;background:var(--panel);margin:12px 0;box-shadow:var(--shadow)}
 .ckwrap{display:flex;flex-wrap:wrap;gap:8px 20px}
 .colck{font-size:12px;color:var(--fg);white-space:nowrap}
 .colbtns{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px}
 .colcount{font-size:11px;color:var(--muted);margin-left:auto}
 .colhint{font-size:11px;color:var(--muted);margin-bottom:14px}
 .colrow{display:flex;align-items:center;gap:3px}
 .colgrid{display:flex;flex-wrap:wrap;gap:8px}
 .colchip{display:flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid var(--border);border-radius:9px;background:var(--bg);cursor:pointer;font-size:12px;user-select:none;transition:border-color .12s,background .12s,opacity .12s}
 .colchip:hover{border-color:var(--accent)}
 .colchip.on{background:var(--panel2);border-color:var(--accent)}
 .colchip.off{opacity:.5}
 .coldot{width:9px;height:9px;border-radius:50%;background:var(--muted);flex:none}
 .colchip.on .coldot{background:var(--accent);box-shadow:0 0 0 3px rgba(95,163,255,.22)}
 .collbl{font-family:var(--mono);color:var(--fg)}
 .colmv{display:flex;gap:3px;margin-left:2px}
 .xs{font-size:10px;line-height:1;padding:2px 5px;background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer}
 .xs.ph{visibility:hidden;border-color:transparent}
 .xtag{font-size:9px;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:0 3px;vertical-align:middle}
 .aicfg{display:flex;flex-wrap:wrap;gap:14px 18px;align-items:flex-end;margin:16px 0;padding:18px 20px;border:1px solid var(--border);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow)}
 .aicfg label{display:flex;flex-direction:column;font-size:11px;color:var(--muted);gap:4px}
 .aicfg label.wide{flex:1;min-width:220px}
 .aicfg input{font-family:var(--mono);font-size:12px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--fg)}
 .aiq{flex:1;min-width:260px}
 .aiout{margin-top:16px;display:flex;flex-direction:column;gap:12px}
 .aimsg{padding:12px 16px;border:1px solid var(--border);border-radius:var(--radius);white-space:pre-wrap;line-height:1.6}
 .aimsg.me{background:var(--panel)}
 .aimsg.bot{background:transparent}
 .aitrace{font-size:11px;color:var(--muted);font-family:var(--mono);border-left:2px solid var(--border);padding-left:10px;margin-top:8px}
 .sgfind{border:1px solid var(--border);border-radius:var(--radius);margin:12px 0;overflow:hidden;box-shadow:var(--shadow)}
 .sghead{padding:12px 14px;cursor:pointer;background:var(--panel);font-size:13px;border-left:4px solid var(--border)}
 .sghead:hover{background:var(--panel2)}
 .sgsev{font-weight:700;font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:4px;color:var(--ink)}
 .sev-crit{border-left-color:#f85149}.sev-crit .sgsev{background:#f85149}
 .sev-high{border-left-color:#db6d28}.sev-high .sgsev{background:#db6d28}
 .sev-med{border-left-color:#e3b341}.sev-med .sgsev{background:#e3b341}
 .sev-low{border-left-color:#3fb950}.sev-low .sgsev{background:#3fb950}
 .sev-info{border-left-color:#58a6ff}.sev-info .sgsev{background:#58a6ff}
 .sghits{padding:10px 14px}
 .sghits mark{background:#e3b341;color:#06121f;padding:0 1px;border-radius:2px}
 .sgmatch{font-family:var(--mono);font-size:11px;color:#56d364;max-width:320px}
 .sgerr{margin:8px 0;font-size:12px}
 .sgsql{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;margin:0;font-family:var(--mono);font-size:12px;white-space:pre-wrap;overflow:auto;max-height:340px;user-select:all}
 .sgcols{display:flex;gap:14px;flex-wrap:wrap}
 .sgcol{flex:1;min-width:280px}
 .sgcolh{font-size:11px;color:var(--muted);margin-bottom:5px}
 /* GTFOBins */
 .gbin{border:1px solid var(--border);border-radius:var(--radius);margin:12px 0;overflow:hidden;box-shadow:var(--shadow)}
 .gbhead{padding:12px 16px;background:var(--panel);cursor:pointer;display:flex;align-items:center;gap:12px;flex-wrap:wrap;border-left:4px solid var(--accent)}
 .gbhead:hover{background:var(--panel2)}
 .gbname{font-family:var(--mono);font-weight:700;font-size:15px;color:var(--accent)}
 .gbcount{font-size:12px;color:var(--muted)}
 .gbfns{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
 .gbfn{font-size:10px;font-family:var(--mono);background:var(--panel2);border:1px solid var(--border);border-radius:4px;padding:2px 7px;color:var(--fg)}
 .gbbody{padding:14px 16px;border-top:1px solid var(--border)}
 .gbsec{margin:4px 0 16px}
 .gbsech{font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:var(--accent);margin-bottom:6px}
 .gbctx{display:inline-block;font-size:9px;font-family:var(--mono);border:1px solid var(--border);border-radius:4px;padding:1px 6px;color:var(--muted);margin-left:6px;vertical-align:middle}
 .gbcode{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:6px 0;font-family:var(--mono);font-size:12px;white-space:pre-wrap;overflow:auto;user-select:all}
 .gbcomment{font-size:11px;color:var(--muted);margin:4px 0 2px}
 .gbsamph{font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin:10px 0 2px}
 .gbtrunc{font-weight:400;text-transform:none;letter-spacing:0;opacity:.8}
 .gblist{display:flex;flex-wrap:wrap;gap:7px;margin-top:10px}
 .gbchip{font-family:var(--mono);font-size:12px;border:1px solid var(--border);border-radius:8px;padding:6px 10px;background:var(--bg);cursor:pointer}
 .gbchip:hover{border-color:var(--accent);background:var(--panel2)}
 .gbchip .n{color:var(--muted);font-size:10px;margin-left:5px}
 .gbpriv{font-size:10px;font-family:var(--mono);border:1px solid var(--border);border-radius:4px;padding:2px 7px;color:var(--muted)}
 .gbpriv.danger{color:#ff7b72;border-color:#f85149;background:rgba(248,81,73,.12);font-weight:700}
 .gbin.danger .gbhead{border-left-color:#f85149}
 /* Dashboard */
 .dgrid{display:flex;flex-wrap:wrap;gap:14px;margin:4px 0 18px}
 .dtile{flex:1;min-width:140px;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}
 .dtile .v{font-size:23px;font-weight:700;color:var(--accent);font-family:var(--mono);line-height:1.1}
 .dtile .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
 .dtile .sub{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:3px}
 .dcols{display:flex;flex-wrap:wrap;gap:16px}
 .dcard{flex:1;min-width:310px;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow);margin-bottom:16px}
 .dcard h3{margin:0 0 10px;font-size:12px;letter-spacing:.5px;text-transform:uppercase;color:var(--accent)}
 .dbar{display:flex;align-items:center;gap:10px;margin:6px 0;cursor:pointer;font-size:12px}
 .dbar:hover .dbk{color:var(--accent)}
 .dbk{font-family:var(--mono);flex:0 0 44%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .dbtrack{flex:1;background:var(--bg);border-radius:4px;height:16px;overflow:hidden;border:1px solid var(--border)}
 .dbfill{height:100%;background:var(--accent);opacity:.85}
 .dbn{font-family:var(--mono);color:var(--muted);min-width:42px;text-align:right}
 .dtag{font-size:9px;font-family:var(--mono);border:1px solid var(--border);border-radius:4px;padding:0 5px;color:var(--muted);margin-left:5px}
 .dtag.ext{color:#ff7b72;border-color:#f85149}
 .dtag.int{color:#56d364;border-color:#3fb950}
 .dhist{display:flex;align-items:flex-end;gap:2px;height:96px;margin-top:8px;border-bottom:1px solid var(--border);padding-bottom:1px}
 .dhcol{flex:1;background:var(--accent);opacity:.8;min-width:2px;border-radius:2px 2px 0 0}
 .dhlbl{display:flex;justify-content:space-between;font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:4px}
 .ipcard{border-color:var(--accent)}
 .iphead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}
 .ipname{font-family:var(--mono);font-size:18px;font-weight:700;color:var(--accent)}
 .ipstats{display:flex;gap:20px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-bottom:10px}
 .ipstats b{color:var(--fg);font-family:var(--mono)}
 .iprow{display:flex;gap:26px;flex-wrap:wrap}
 /* Marcas */
 .mkitem{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--border);border-radius:9px;padding:10px 12px;margin:8px 0;background:var(--panel)}
 .mkbadge{font-size:10px;font-weight:700;font-family:var(--mono);padding:2px 8px;border-radius:4px;border:1px solid var(--border);white-space:nowrap}
 .mk-pendiente{color:#e3b341;border-color:#e3b341}
 .mk-TP{color:#ff7b72;border-color:#f85149;background:rgba(248,81,73,.12)}
 .mk-FP{color:#56d364;border-color:#3fb950}
 .mk-descartado{color:var(--muted)}
 .mkmain{flex:1;min-width:0}
 .mkdet{font-family:var(--mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
 .mkdet:hover{color:var(--accent)}
 .mkmeta{font-size:11px;color:var(--muted);margin-top:3px}
 .mknota{font-size:12px;margin-top:4px;color:var(--fg)}
 .mkact{display:flex;gap:6px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
 .mkfilt{cursor:pointer;border:1px solid var(--border);border-radius:999px;padding:4px 13px;font-size:12px;background:var(--panel)}
 .mkfilt.active{background:var(--accent);color:var(--ink);font-weight:600;border-color:var(--accent)}
 .err{color:#ff7b72;font-family:var(--mono);white-space:pre-wrap}
 .pill{background:var(--panel2);border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:12px}
 a{color:var(--accent)}
 /* explorador */
 .hit{padding:10px 14px;border:1px solid var(--border);border-radius:9px;margin:9px 0;cursor:pointer;font-family:var(--mono);font-size:12px;background:var(--panel)}
 .hit:hover{border-color:var(--accent);background:var(--panel2)}
 .hit .meta{color:var(--muted)}
 .idnum{display:inline-block;min-width:52px;color:#e3b341;font-weight:600}
 .src{display:inline-block;min-width:78px;color:var(--accent)}
 .fsrc{color:#7f93b4;font-size:11px}
 .ctx{margin:6px 0 18px 0;border-left:3px solid var(--accent);padding-left:0}
 .ctx table{margin-top:0}
 tr.match td{background:var(--hit);font-weight:600}
 .count{font-size:12px;color:var(--muted)}
 /* barra de controles del explorador: bloques etiquetados con aire */
 .toolbar{display:flex;flex-direction:column;gap:0;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:4px 20px;box-shadow:var(--shadow)}
 .tbgroup{display:flex;flex-direction:column;gap:9px;padding:16px 0;border-bottom:1px solid var(--border)}
 .tbgroup:last-child{border-bottom:0}
 .tbglabel{font-size:11px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--accent)}
 .tbrow{display:flex;gap:14px 18px;align-items:flex-end;flex-wrap:wrap}
 .fld{display:flex;flex-direction:column;gap:5px}
 .fld.grow{flex:1;min-width:240px}
 .fld>label{font-size:11px;color:var(--muted)}
 .fld .hintlbl{opacity:.65}
 .fld input,.fld select{width:100%}
 .qhelp{margin-top:8px;font-size:12px}
 .qhelp>summary{cursor:pointer;color:var(--accent);user-select:none;list-style:revert}
 .qhelp>summary:hover{text-decoration:underline}
 .qhelpbody{margin-top:8px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:rgba(127,127,127,.06)}
 .qhelpbody table{border-collapse:collapse}
 .qhelpbody td{padding:3px 10px 3px 0;vertical-align:top;color:var(--muted)}
 .qhelpbody td:first-child{white-space:nowrap}
 .qhelpbody code{background:rgba(127,127,127,.16);padding:1px 5px;border-radius:4px;color:var(--fg)}
 .qhelpbody p{margin:8px 0 0}
 .faccount{font-size:11px;color:var(--muted);margin:6px 0 4px}
 .facwrap{display:flex;flex-direction:column;gap:3px;max-width:640px;max-height:230px;overflow-y:auto;padding-right:4px}
 .facclose{margin-left:6px}
 .facrow{position:relative;display:flex;align-items:center;gap:8px;padding:4px 9px;border:1px solid var(--border);border-radius:6px;cursor:pointer;overflow:hidden;font-size:12px}
 .facrow:hover{border-color:var(--accent)}
 .facbar{position:absolute;left:0;top:0;bottom:0;background:rgba(80,150,255,.14);z-index:0}
 .facval{position:relative;z-index:1;font-family:var(--mono);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .facn{position:relative;z-index:1;font-weight:700;color:var(--accent)}
 .savlbl{font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin:8px 0 4px}
 .savclear{font-weight:400;text-transform:none;letter-spacing:0;color:var(--accent)}
 .savwrap{display:flex;flex-wrap:wrap;gap:6px}
 .savchip{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border:1px solid var(--border);border-radius:14px;cursor:pointer;font-size:12px;font-family:var(--mono)}
 .savchip:hover{border-color:var(--accent)}
 .savx{opacity:.5;cursor:pointer}
 .savx:hover{opacity:1;color:#f85149}
 .fld-chk .chk{display:flex;align-items:center;gap:7px;height:40px;color:var(--fg);font-size:13px;white-space:nowrap}
 .tbnote{margin:14px 2px 8px;line-height:1.55}
 /* ayuda */
 .help{max-width:860px;line-height:1.65}
 .help h3{margin:24px 0 8px;font-size:14px;color:var(--accent)}
 .help p{margin:8px 0}
 .help code{background:var(--panel2);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-family:var(--mono);font-size:12px}
 .help pre{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:14px;overflow:auto;font-family:var(--mono);font-size:12px}
 .help ul{margin:8px 0;padding-left:22px}
 .help li{margin:5px 0}
 /* landing / cargar */
 .landing{max-width:820px;display:flex;flex-direction:column;gap:18px}
 .drop{border:1px solid var(--border);border-radius:var(--radius);padding:20px 22px;background:var(--panel);box-shadow:var(--shadow)}
 .drop .row{margin:10px 0}
 #ingested{margin-top:18px}
 .st-ok{color:#56d364;font-weight:600}
 .st-skip{color:#e3b341;font-weight:600}
 .st-err{color:#ff7b72;font-weight:600}
 .st-arc{color:var(--muted);font-weight:600}
 .bigbtn{font-size:14px;padding:12px 22px}
 .hidden{display:none}
 #ingested h3{margin:20px 0 6px;font-size:13px}
 td.prevcell{white-space:normal;max-width:520px}
 .prev{margin:0;font-family:var(--mono);font-size:11px;color:var(--muted);white-space:pre-wrap;max-height:90px;overflow:auto}
</style>
<style id="colstyle"></style></head>
<body>
<header>
 <h1><svg viewBox="0 0 24 24" width="1.2em" height="1.2em" style="vertical-align:-.26em" aria-label="chorizo"><path d="M18.7 5.8 L20.9 3.9 M18.7 5.8 L20.3 7.9" fill="none" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#141414" stroke-width="7.8" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#e0485a" stroke-width="5.6" stroke-linecap="round"/><path d="M7.4 16.8 C10 18.6 15.4 17.6 16.8 8" fill="none" stroke="#f58a95" stroke-width="1.6" stroke-linecap="round" opacity=".85"/><path d="M10.6 19.9 l1.3 -2.4" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M14.8 19.2 l1.2 -2.3" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M3.7 20.2 L6.4 18.2 L5.9 21.2 Z" fill="#e0485a" stroke="#141414" stroke-width="1.1" stroke-linejoin="round"/></svg> Longanizer</h1>
 <span class="muted">auth/syslog/access/auditd/weberror/applog/bash_history &middot; DuckDB</span>
 <span id="stat" class="pill">loading&hellip;</span>
 <span id="dbpill" class="pill" title="Where this case is stored"></span>
</header>
<main>
 <div class="tabs">
  <div class="tab active" data-tab="landing" onclick="switchTab('landing')">Load</div>
  <div class="tab hidden" data-tab="dash" data-optional onclick="switchTab('dash')">Overview</div>
  <div class="tab hidden" data-tab="explorer" data-optional onclick="switchTab('explorer')">Explorer</div>
  <div class="tab hidden" data-tab="ioc" data-optional onclick="switchTab('ioc')">IOC sweep</div>
  <div class="tab hidden" data-tab="network" data-optional onclick="switchTab('network')">Network</div>
  <div class="tab hidden" data-tab="sql" data-optional onclick="switchTab('sql')">SQL</div>
  <div class="tab parent hidden" data-tab="__ai" data-optional onclick="openGroup('ai')">AI ▾</div>
  <div class="tab hidden" data-tab="sigma" data-optional onclick="switchTab('sigma')">Sigma</div>
  <div class="tab hidden" data-tab="attack" data-optional onclick="switchTab('attack')">ATT&amp;CK</div>
  <div class="tab hidden" data-tab="gtfo" data-optional onclick="switchTab('gtfo')">GTFOBins</div>
  <div class="tab hidden" data-tab="marks" data-optional onclick="switchTab('marks')">Marks</div>
  <div class="tab hidden" data-tab="help" data-optional onclick="switchTab('help')">Help</div>
 </div>
 <div id="subnav_ai" class="subnav hidden">
  <span class="subcap">AI</span>
  <div class="subtab" data-tab="ai" onclick="switchTab('ai')">AI (API)</div>
  <div class="subtab" data-tab="ailocal" onclick="switchTab('ailocal')">AI (local)</div>
  <div class="subtab" data-tab="mcp" onclick="switchTab('mcp')">MCP</div>
 </div>

 <!-- ============ CARGAR (inicio) ============ -->
 <section id="landing" class="panel active">
  <div class="landing">
   <p>Upload your Linux logs to start. They are parsed into a single timeline and,
   once done, the <b>Explorer</b>, <b>SQL</b> and <b>Help</b> tabs become available.</p>
   <div id="dbnote" class="muted" style="margin:-4px 0 10px"></div>

   <div class="drop">
    <div class="row">
     <b style="font-size:13px">Open a saved case:</b>
     <select id="dbsel" style="flex:1;min-width:240px"></select>
     <button class="sec" onclick="loadCases()" title="Refresh list">&#8635;</button>
     <button class="bigbtn" onclick="openSelectedDb()">Open case</button>
    </div>
    <div class="row">
     <span class="muted">or path to a .duckdb:</span>
     <input type="text" id="dbpath" placeholder="E:\path\to\case.duckdb" style="flex:1;min-width:240px">
     <button class="sec" onclick="openPathDb()">Open path</button>
    </div>
    <div class="muted">Open an existing database (from the <code>casos</code> folder or the path you give) and you get the whole case instantly, with no re-ingest. Only one process at a time on the same file.</div>
   </div>
   <div class="drop">
    <div class="row">
     <b style="font-size:13px">Load logs:</b>
     <label class="muted">files<input type="file" id="files" multiple></label>
     <label class="muted">or folder<input type="file" id="folder" webkitdirectory multiple></label>
     <label class="muted">time offset (min)<input type="number" id="tz" value="0" step="60" style="width:70px" title="minutes to adjust; 0 = UTC"></label>
     <button class="bigbtn" onclick="uploadFiles()">Upload and load</button>
     <button class="sec" onclick="clearPicks()">Clear selection</button>
    </div>
    <div class="row">
     <label class="colck" title="Ingest as 'raw' anything unrecognized that is not key=value (nothing is lost; adds some noise)"><input type="checkbox" id="catchall"> Catch-all: ingest unrecognized lines as <code>raw</code> (for keyword rules)</label>
    </div>
    <div class="row">
     <progress id="prog" value="0" max="100" style="width:220px;display:none"></progress>
     <span id="ingmsg" class="muted"></span>
    </div>
    <div class="muted"><b>Time offset:</b> default <b>0 (UTC)</b>. Only affects logs that do not store their timezone (syslog, auth, kern, cron, applog, web error.log); it is used to normalize them to UTC so the timeline lines up. If your logs are in local time, enter the offset in minutes: <code>+60</code> = +1 h (CET), <code>+120</code> = +2 h (CEST, Spain summer), <code>-300</code> = −5 h (EST). access and auditd are already in UTC and left untouched.</div>
    <div class="muted" style="margin-top:6px">With <b>folder</b> you pick a directory and it uploads <b>the whole tree</b> (subfolders included); with <b>files</b>, loose files or a <code>.zip</code>/<code>.tar.gz</code> (auto-extracted). Unrecognized files are skipped.</div>
   </div>

   <div class="drop" style="margin-top:12px">
    <div class="row">
     <b style="font-size:13px">Or a path on the server:</b>
     <input type="text" id="spath" placeholder="E:\path\to\case  (folder, file or .zip/.tar.gz)" style="flex:1;min-width:280px">
     <label class="muted">time offset (min)<input type="number" id="tzp" value="0" step="60" style="width:70px" title="minutes to adjust; 0 = UTC"></label>
     <button class="bigbtn" onclick="ingestPath()">Load from path</button>
    </div>
    <div class="muted">Faster when the logs are already <b>on this machine</b>: the server reads them straight from disk, without uploading through the browser, and you get <b>live progress</b> (files and events). Supports the same (folders with subfolders and archives). The path is on the machine running the server.</div>
   </div>

   <div id="ingested"></div>
   <div class="row"><button id="goexp" class="bigbtn hidden" onclick="switchTab('explorer')">Go to Explorer &rarr;</button></div>
  </div>
 </section>

 <!-- ============ OVERVIEW / DASHBOARD ============ -->
 <section id="dash" class="panel">
  <div class="row">
   <button class="bigbtn" onclick="loadDash()">Refresh overview</button>
   <button class="sec" onclick="window.open('/report','_blank')">HTML report</button>
   <button class="sec" onclick="window.location='/report?download=1'">Download report</button>
   <button class="sec" onclick="geoRefresh()" id="geo_btn">Update GeoIP database</button>
   <span id="geo_msg" class="muted"></span>
  </div>
  <div id="dash_out"><p class="muted">Click &laquo;Refresh overview&raquo;.</p></div>
 </section>

 <!-- ============ EXPLORER ============ -->
 <section id="explorer" class="panel">
  <div class="toolbar">
   <div class="tbgroup">
    <div class="tbglabel">Search</div>
    <div class="tbrow">
     <div class="fld grow qacwrap">
      <label for="q">Text, IOC, IP or hash <span class="hintlbl">· words = AND · <code>field:value</code> · <code>-exclude</code></span></label>
      <input type="text" id="q" placeholder="root  src_ip:192  -user:cron" autofocus autocomplete="off">
      <div id="qac" class="qac hidden"></div>
     </div>
     <div class="fld">
      <label for="src">Source</label>
      <select id="src"><option>(all)</option></select>
     </div>
     <div class="fld fld-chk">
      <label>Mode</label>
      <label class="chk"><input type="checkbox" id="rgx"> regular expression</label>
     </div>
     <button class="bigbtn" onclick="doSearch()">Search</button>
    </div>
    <details class="qhelp">
     <summary>How to filter &mdash; field search, exact match &amp; exclude (NOT)</summary>
     <div class="qhelpbody">
      <table>
       <tr><td><code>root ssh</code></td><td>free text; several words = <b>AND</b> (all must appear)</td></tr>
       <tr><td><code>src_ip:192</code></td><td>field <b>contains</b> (case-insensitive). Also <code>user:root</code>, <code>exe:wget</code>, <code>message:passwd</code></td></tr>
       <tr><td><code>src_ip&nbsp;contains&nbsp;192</code></td><td>same thing, written with the word <code>contains</code></td></tr>
       <tr><td><code>status=404</code></td><td>field <b>exactly</b> equals (<code>=</code>). <code>user=root</code> matches only «root», not «root2»</td></tr>
       <tr><td><code>user!=root</code></td><td>field is <b>not</b> that value</td></tr>
       <tr><td><code>-cron</code> &nbsp; <code>-user:root</code></td><td><b>exclude</b> (NOT): drop events with that text / field value. Several allowed</td></tr>
       <tr><td><code>x:syscall:execve</code></td><td>a key of the <code>extra</code> JSON (auditd/logfmt). Also <code>extra.syscall:execve</code></td></tr>
       <tr><td><code>/regex/</code></td><td>regex over the raw line, e.g. <code>/failed|invalid/</code>. Combine with fields &amp; NOT</td></tr>
       <tr><td><code>exe:/wget|curl/</code></td><td>regex on a single field. Quote if it has spaces: <code>"message:/a b/"</code></td></tr>
       <tr><td><code>user:*</code></td><td>the field <b>exists</b> / has a value. <code>-user:*</code> (or <code>user:-</code>) = <b>empty or missing</b></td></tr>
       <tr><td><code>user:"john doe"</code></td><td>use quotes for values with spaces</td></tr>
      </table>
      <p class="hintlbl">Mix freely: <code>ssh_failed src_ip:192 -user:root /enc\s+\w+/</code>. Fields: ts, source, host, program, user, src_ip, src_port, exe, method, path, status, event, message (aliases: ip, prog, msg…). The <b>regex</b> checkbox treats the WHOLE box as one regex; the <code>/…/</code> form above works token-by-token without it.</p>
     </div>
    </details>
    <details class="qhelp savedbox" ontoggle="if(this.open)renderSaved()">
     <summary>&#9733; Recent &amp; saved searches</summary>
     <div class="qhelpbody">
      <button class="sec" onclick="saveCurrent()">&#9733; Save current search</button>
      <div id="saved_out" style="margin-top:8px"></div>
     </div>
    </details>
   </div>

   <div class="tbgroup">
    <div class="tbglabel">Facets <span class="hintlbl">· top values of a field over the current results — click to filter</span></div>
    <div class="tbrow">
     <div class="fld">
      <label for="facfield">Field</label>
      <select id="facfield">
       <optgroup label="categorical">
        <option value="source">source</option><option value="user">user</option>
        <option value="src_ip">src_ip</option><option value="program">program</option>
        <option value="status">status</option><option value="event">event</option>
        <option value="severity">severity</option><option value="host">host</option>
        <option value="method">method</option><option value="asn">asn</option>
        <option value="org">org</option>
       </optgroup>
       <optgroup label="high cardinality">
        <option value="message">message</option><option value="exe">exe</option>
        <option value="path">path</option>
       </optgroup>
       <optgroup label="extra (JSON)" id="facextra"></optgroup>
      </select>
     </div>
     <button class="sec" onclick="loadFacets()">Top values</button>
    </div>
    <div id="fac_out"></div>
   </div>

   <div class="tbgroup">
    <div class="tbglabel">Event context</div>
    <div class="tbrow">
     <div class="fld">
      <label for="ctx">Window &plusmn;</label>
      <input type="number" id="ctx" value="5" min="0" max="1000" style="width:90px">
     </div>
     <div class="fld">
      <label for="unit">Unit</label>
      <select id="unit"><option value="lines">lines</option><option value="minutes">minutes</option></select>
     </div>
     <div class="fld">
      <label for="goto">Go to event #</label>
      <input type="number" id="goto" placeholder="123" style="width:110px">
     </div>
     <button class="sec" onclick="gotoId()">Show context</button>
    </div>
   </div>

   <div class="tbgroup">
    <div class="tbglabel">Time range <span class="hintlbl">· applies to search &amp; timeline</span></div>
    <div class="tbrow">
     <div class="fld">
      <label for="tstart">From (UTC, optional)</label>
      <input type="text" id="tstart" placeholder="2026-09-29" style="width:160px">
     </div>
     <div class="fld">
      <label for="tend">To (UTC, optional)</label>
      <input type="text" id="tend" placeholder="2026-09-29 12:00" style="width:180px">
     </div>
     <button class="sec" onclick="showTimeline()">Show full timeline</button>
    </div>
   </div>

   <div class="tbgroup">
    <div class="tbglabel">Options</div>
    <div class="tbrow">
     <div class="fld">
      <label for="pagesize">Events per page <span class="hintlbl">· and per &laquo;Load more&raquo;</span></label>
      <input type="number" id="pagesize" value="500" min="1" style="width:120px">
     </div>
     <button class="sec" onclick="toggleColsPanel()">Columns &#9662;</button>
    </div>
   </div>
  </div>

  <div id="colspanel" class="hidden"></div>
  <p class="muted tbnote">Searches message, raw line, exe, path, user and IP. Click a result (or use its <b>#</b>) to see its context: N lines or X minutes before and after by timestamp, across the whole timeline (not just that one log). The <b>#</b> is the position in the timeline (1 = oldest).</p>
  <div id="gotoout"></div>
  <div id="hits"></div>
 </section>

 <!-- ============ SQL ============ -->
 <section id="sql" class="panel">
  <div class="row">
   <select id="ex" title="Example queries"></select>
   <button class="sec" onclick="loadEx()">Load example</button>
   <span class="muted">Table: <code>events</code> &middot; <a href="/schema" target="_blank">view columns</a></span>
  </div>
  <textarea id="sqltext">SELECT ts, source, program, user, src_ip, event, message
FROM events
ORDER BY ts DESC
LIMIT 50;</textarea>
  <div class="row">
   <button onclick="runSql()">Run (Ctrl+Enter)</button>
   <span id="rc" class="muted"></span>
  </div>
  <div id="out"></div>
 </section>

 <!-- ============ IA (API remota / LiteLLM) ============ -->
 <section id="ai" class="panel">
  <div class="help">
   <p>Ask in natural language and the model uses this app's tools
   (<b>search</b>, <b>SQL</b>, <b>context</b>, <b>stats</b>, <b>timeline</b>, all
   <b>read-only</b>) to answer with real data from your logs. Connect to any
   <b>OpenAI-compatible endpoint</b>: your company's <b>LiteLLM</b> proxy or a
   provider's API.</p>
   <div class="muted">Nothing is stored or sent on its own: the endpoint you set
   here is only called when you ask a question. The key lives in your browser
   (localStorage), not on the server.</div>
  </div>
  <div class="aicfg">
   <label>base_url<input type="text" id="ai_base" placeholder="https://litellm.yourcompany.com/v1"></label>
   <label>model<input type="text" id="ai_model" placeholder="gpt-4o-mini / claude-3-5-sonnet / …"></label>
   <label>api_key<input type="password" id="ai_key" placeholder="sk-… (Bearer)"></label>
   <label>user (LiteLLM, optional)<input type="text" id="ai_user" placeholder="your-user"></label>
   <label class="wide">extra headers JSON (optional)<input type="text" id="ai_hdr" placeholder='{"x-my-header":"value"}'></label>
   <button class="sec" onclick="saveAiCfg('ai')">Save config</button>
  </div>
  <div class="row">
   <input type="text" id="ai_q" class="aiq" placeholder="Was there SSH brute force? Which IPs? Did anyone get in?">
   <button onclick="askAi('ai')">Ask</button>
  </div>
  <div id="ai_out" class="aiout"></div>
 </section>

 <!-- ============ AI (local app) ============ -->
 <section id="ailocal" class="panel">
  <div class="help">
   <p>Same as the <b>AI (API)</b> tab, but pointing to an <b>AI app running on your
   own machine</b> that exposes an OpenAI-compatible API: <b>Ollama</b>
   (<code>http://localhost:11434/v1</code>), <b>LM Studio</b>
   (<code>http://localhost:1234/v1</code>), <code>llama.cpp</code> server, etc. This
   way the data never leaves your machine.</p>
   <div class="muted">Most local apps need no key; leave api_key empty if they
   don't use one. Make sure you've pulled the model (e.g.
   <code>ollama pull llama3.1</code>) and that it supports <i>function calling</i>.</div>
  </div>
  <div class="aicfg">
   <label>base_url<input type="text" id="local_base" placeholder="http://localhost:11434/v1"></label>
   <label>model<input type="text" id="local_model" placeholder="llama3.1 / qwen2.5 / …"></label>
   <label>api_key (optional)<input type="password" id="local_key" placeholder="usually empty"></label>
   <button class="sec" onclick="saveAiCfg('local')">Save config</button>
  </div>
  <div class="row">
   <input type="text" id="local_q" class="aiq" placeholder="Ask about your logs…">
   <button onclick="askAi('local')">Ask</button>
  </div>
  <div id="local_out" class="aiout"></div>
 </section>

 <!-- ============ MCP ============ -->
 <section id="mcp" class="panel">
  <div id="mcp_help" class="help"><p class="muted">loading&hellip;</p></div>
 </section>

 <!-- ============ SIGMA ============ -->
 <section id="sigma" class="panel">
  <div class="help">
   <p>Run <b>Sigma</b> rules over the loaded logs (historical detection / retro-hunting).
   Only <b>Linux</b> and <b>webserver</b> rules whose logsource is present in the
   case are applied; the rest are skipped. Each rule is translated to SQL and runs over the <code>events</code> table.</p>
  </div>
  <div class="aicfg">
   <label class="wide">rules folder on the server<input type="text" id="sg_path" placeholder="reglas_sigma  (or an absolute path)"></label>
   <button class="bigbtn" onclick="sigmaLoad()">Load rules</button>
   <label class="muted">or upload .yml<input type="file" id="sg_files" accept=".yml,.yaml" multiple></label>
   <button class="sec" onclick="sigmaUpload()">Upload and load</button>
  </div>
  <div class="row">
   <button onclick="sigmaRun()" id="sg_runbtn" disabled>Run rules</button>
   <button class="sec" onclick="sigmaListRules()" id="sg_listbtn" disabled>View applicable rules (SQL)</button>
   <progress id="sg_prog" max="100" value="0" style="display:none;width:180px;vertical-align:middle"></progress>
   <span id="sg_msg" class="muted"></span>
  </div>
  <div id="sg_out"></div>
 </section>

 <!-- ============ GTFOBins ============ -->
 <section id="gtfo" class="panel">
  <div class="help">
   <p><b>GTFOBins</b> catalogs legitimate Unix binaries and the invocations used
   to abuse them (get a shell, escalate via <code>suid</code>/<code>sudo</code>,
   read/write files, reverse-shell…). Here that catalog is cross-referenced with the
   binaries that were <b>actually executed</b> in the loaded logs:
   auditd <code>execve</code>, <code>bash_history</code> commands and what was run
   via <code>sudo</code>.</p>
  </div>
  <div class="row">
   <button class="bigbtn" onclick="gtfoCheck()" id="gtfo_checkbtn">Check executed binaries</button>
   <button class="sec" onclick="gtfoRefresh()" id="gtfo_refreshbtn">Update catalog (GitHub)</button>
   <button class="sec" onclick="gtfoToggleList()" id="gtfo_listbtn">View full catalog</button>
   <span id="gtfo_msg" class="muted"></span>
  </div>
  <div id="gtfo_out"></div>
  <div id="gtfo_list" class="hidden"></div>
 </section>

 <!-- ============ IOC SWEEP ============ -->
 <section id="ioc" class="panel">
  <div class="help"><p>Paste a list of <b>IOCs</b> — IPs, hashes, file paths, binaries, user names, domains — one per line (or comma/semicolon separated) and sweep all loaded logs at once. Each IOC shows its hit count and a sample; the match looks across the relevant fields <i>and</i> the raw log line. Click a row for its context, or &#10697; to copy the full event.</p></div>
  <div class="row" style="align-items:flex-start">
   <textarea id="ioc_in" placeholder="8.8.8.8&#10;/tmp/.x/payload&#10;wget&#10;evil-domain.com&#10;root" style="min-height:130px;width:380px"></textarea>
   <div>
    <button class="bigbtn" onclick="runIoc()">Sweep</button>
    <button class="sec" onclick="clearIoc()">Clear</button>
    <div class="muted" style="margin-top:10px;max-width:260px">One IOC per line. Literal, case-insensitive. Up to 1000 IOCs.</div>
   </div>
   <span id="ioc_msg" class="muted"></span>
  </div>
  <div id="ioc_out"></div>
 </section>

 <!-- ============ NETWORK ============ -->
 <section id="network" class="panel">
  <div class="help"><p>Network connectivity from the logs — SSH auth (source IP), web access/error (<code>access</code>/<code>weberror</code>), auditd connections (<code>SADDR=</code>) and firewall drops (<code>SRC=</code>). Filter by IP, port, source or event.</p></div>
  <div class="row">
   <input id="nw_ip" placeholder="IP" style="width:150px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <input id="nw_port" placeholder="port" style="width:90px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <input id="nw_source" placeholder="source (auth/access…)" style="width:170px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <input id="nw_event" placeholder="event (ssh_failed…)" style="width:170px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <button class="bigbtn" onclick="loadNetwork()">Search</button>
   <button class="sec" onclick="clearNet()">Clear</button>
   <span id="nw_msg" class="muted"></span>
  </div>
  <div id="nw_out"></div>
 </section>

 <!-- ============ ATT&CK MATRIX ============ -->
 <section id="attack" class="panel">
  <div class="help"><p><b>ATT&amp;CK coverage</b> of this case, built from your matched <b>Sigma</b> rules. Techniques grouped by tactic, colored by rule level, number = matching events; click a technique to jump to a sample event. Load and run your Sigma rules first (they need <code>attack.*</code> tags).</p></div>
  <div class="row"><button class="bigbtn" onclick="loadAttack()" id="at_btn">Build / refresh matrix</button>
   <progress id="at_prog" max="100" value="0" style="display:none;width:180px;vertical-align:middle"></progress>
   <span id="at_msg" class="muted"></span></div>
  <div id="at_out"></div>
 </section>

 <!-- ============ MARKS / TRIAGE ============ -->
 <section id="marks" class="panel">
  <div class="help">
   <p>Mark events as <b>pendiente</b> (pending), <b>TP</b> (true positive),
   <b>FP</b> (false positive) or <b>descartado</b> (dismissed), with a note. Marks are
   stored <b>inside the case file</b> <code>.duckdb</code>, so they travel
   with the case and persist across restarts. To mark an event, open it in the
   <b>Explorer</b> and click &laquo;Mark event&raquo;, or add its <b>#</b> below.</p>
  </div>
  <div class="toolbar">
   <div class="tbgroup">
    <div class="tbglabel">Add a mark by event #</div>
    <div class="tbrow">
     <div class="fld"><label for="mk_id">event #</label>
      <input type="number" id="mk_id" placeholder="123" style="width:110px"></div>
     <div class="fld"><label for="mk_estado">Status</label>
      <select id="mk_estado">
       <option value="pendiente">pending</option>
       <option value="TP">TP (true positive)</option>
       <option value="FP">FP (false positive)</option>
       <option value="descartado">dismissed</option>
      </select></div>
     <div class="fld grow"><label for="mk_nota">Note (optional)</label>
      <input type="text" id="mk_nota" placeholder="what you saw, next step…"></div>
     <button onclick="markAddFromForm()">Add mark</button>
    </div>
   </div>
  </div>
  <div class="row" id="mk_filters"></div>
  <span id="mk_msg" class="muted"></span>
  <div id="mk_out"></div>
 </section>

 <!-- ============ AYUDA ============ -->
 <section id="help" class="panel">
  <div class="help">
   <p>Loaded logs are normalized into a single <code>events</code> table and stored
   in <b>UTC</b>, so you can correlate different sources on one timeline.</p>

   <h3>Explorer — search</h3>
   <ul>
    <li>Type any text: an IOC, an IP, a hash, a path, a piece of a command. Searches the message, the raw line, <code>exe</code>, path, user and IP. Case-insensitive.</li>
    <li><b>Multiple words = AND</b> (all must appear in the same event). E.g. <code>suid bash</code>.</li>
    <li><b>Filter by a field's content</b> with <code>field:value</code> (contains), e.g. <code>src_ip:192</code>, <code>user:root</code>, <code>exe:wget</code>. The word form <code>src_ip contains 192</code> works too. <code>field=value</code> is an <b>exact</b> match (<code>status=404</code>), <code>field!=value</code> is <b>not equal</b>.</li>
    <li><b>Exclude (NOT)</b> with a leading <code>-</code>: <code>-cron</code> drops events with that text, <code>-user:root</code> drops that field value. Several includes and excludes can be mixed: <code>ssh_failed src_ip:192 -user:root</code>.</li>
    <li>Reach an <code>extra</code> JSON key (auditd/logfmt/csv) with <code>x:key:value</code> or <code>extra.key:value</code>, e.g. <code>x:syscall:execve</code>. Quote values with spaces: <code>user:"john doe"</code>. There's a <b>«How to filter»</b> cheatsheet right under the search box, and the box <b>autocompletes field names</b> (including discovered <code>extra</code> keys).</li>
    <li><b>Regex per token</b> without the checkbox: <code>/regex/</code> matches the raw line and <code>field:/regex/</code> a single field (e.g. <code>exe:/wget|curl/</code>), both combinable with fields and <code>-</code>NOT. The <b>regex</b> checkbox instead treats the whole box as one regex (the <code>^</code>/<code>$</code> anchors apply to the raw line).</li>
    <li><b>Field exists / empty</b>: <code>field:*</code> keeps events where that field <b>has a value</b> (e.g. <code>src_ip:*</code>), and <code>-field:*</code> (or <code>field:-</code>) keeps those where it is <b>empty or missing</b>.</li>
    <li><b>Facets</b>: pick a field and click <b>Top values</b> to see its most frequent values over the current results (bars + counts); click one to add it to the search. Categorical fields (user, src_ip, status, asn, org…) are the useful ones. The list is scrollable and has a <b>✕ hide</b>; it follows the <b>current view</b> — the <b>timeline</b> facets over everything (its source/time filters), a <b>search</b> over its matches.</li>
    <li><b>Recent &amp; saved searches</b>: the box keeps your last searches and lets you save named ones (stored in this browser).</li>
    <li>The <b>(all)</b> dropdown filters by source (auth, access, auditd…).</li>
   </ul>

   <h3>Explorer — context</h3>
   <ul>
    <li>Each result carries a <b>#</b> = its position in the timeline (<b>#1 = oldest</b>).</li>
    <li>Click a result to expand its context; change <b>window ±</b> and the unit:
     <b>lines</b> (N events above/below) or <b>minutes</b> (time window around it). Decimals allowed (0.5 min = 30 s).</li>
    <li><b>Go to #</b>: type an event number and it opens its context directly (handy to return to a specific hit).</li>
    <li>Results come in a <b>table with every parsed column</b> (including the source file); if they don't fit, the table scrolls horizontally. Click a row to see its context above. The <b>&#10697;</b> button on every row — and in the context header — copies the <b>full event</b> (raw line / JSON) to the clipboard.</li>
    <li>Only <b>visible columns</b> are rendered and long cells are truncated (full value on hover), so the table stays fast with many events. <b>&#8615; CSV</b> exports the loaded rows.</li>
    <li>Two extra columns — <b>ASN</b> (e.g. <code>AS3352</code>) and <b>Org/ISP</b> — are filled from the first IP in each row via GeoIP. They need the <b>ASN database</b> downloaded (Overview → <b>Update GeoIP database</b>) and only apply to public IPs; private/internal rows stay empty. Hide or reorder them in the <b>Columns</b> panel like any other.</li>
    <li>The <b>events per page</b> field sets how many load at once and how many each «Load more» brings (default 500).</li>
    <li>The <b>Time range</b> (From / To, UTC) applies to <i>both</i> search and the full timeline.</li>
    <li><b>Sorting</b>: click a column <b>header</b> (asc/desc; the ▲/▼ arrow shows the order). The server sorts the whole set, not just the page.</li>
    <li>The <b>Columns</b> button opens a panel of <b>chips</b>: each column shows as on (visible) or off (hidden) and toggles with a click. Shortcuts <b>Show/Hide all</b> and <b>Hide empty</b>, <b>reorder</b> with ◀ ▶ and back to <b>Original order</b>. Applies instantly and remembers your choice.</li>
    <li><b><code>extra</code> columns</b>: the keys of the <code>extra</code> JSON (auditd, or those auto-generated from a <code>logfmt</code>) appear in the panel tagged «extra»; they start hidden — enable them to see them as a column and sort by them.</li>
    <li><b>Show full timeline</b>: lists everything in chronological order (paged). You can bound it with the <b>from … to …</b> fields (UTC, format <code>2026-09-29</code> or <code>2026-09-29 08:00</code>) to avoid loading everything.</li>
   </ul>

   <h3>IOC sweep</h3>
   <ul>
    <li>Paste a list of IOCs (one per line) — IPs, hashes, file paths, binaries, users, domains — and sweep all loaded logs at once. Each IOC shows its hit count and a sample; the match covers the relevant fields <i>and</i> the raw line. IP IOCs are tagged <b>internal</b> or with their <b>ASN · Org/ISP</b>. Export the summary as CSV.</li>
   </ul>

   <h3>AI and MCP <span class="hintlbl">· grouped under “AI ▾”</span></h3>
   <ul>
    <li><b>AI (API)</b>: ask in natural language; the model uses the read-only tools (search/SQL/context/stats/timeline). Connect to an OpenAI-compatible endpoint (your company's LiteLLM, a provider…). The key is stored only in your browser.</li>
    <li><b>AI (local)</b>: the same, pointing to a local app (Ollama, LM Studio…), so the data never leaves your machine.</li>
    <li><b>MCP</b>: exposes the logs as read-only MCP tools for Claude Desktop/Code. The MCP tab has the config ready to copy (it shares the case's DuckDB file).</li>
   </ul>

   <h3>Sigma</h3>
   <ul>
    <li>Run <b>Sigma</b> rules over the logs (historical detection). Drop your <code>.yml</code> files in <code>reglas_sigma/</code> (or upload them) and click <b>Load rules</b> → <b>Run</b>. Both <b>loading</b> (file by file) and running show a <b>progress bar</b>.</li>
    <li>Only <b>Linux</b> and <b>webserver</b> rules whose logsource is present are applied; the rest are skipped. Rules using something unsupported are skipped with a reason.</li>
    <li>Each finding carries a level and ATT&amp;CK; clicking a hit jumps to its context in the Explorer.</li>
    <li><b>Expand a detection</b> to see the <b>full rule (YAML)</b> that fired and the <b>structured raw log</b> of the matching event, side by side with the event fields.</li>
    <li>Every finding has the triage buttons (<b>⎘ copy</b>, <b>view structured</b> and the <b>mark</b> buttons) and an <b>add to review</b> action, so you can triage without leaving the tab.</li>
    <li>Requires <code>pysigma</code> installed; if missing, the tab warns and everything else still works.</li>
   </ul>

   <h3>ATT&amp;CK</h3>
   <ul>
    <li>Projects the Sigma findings onto the <b>MITRE ATT&amp;CK</b> matrix: each technique seen in the logs lights up with its hit count. Click a technique to jump to a sample event's context; each tile also has a <b>&#43;</b> to send a sample of that technique to review.</li>
   </ul>

   <h3>Network</h3>
   <ul>
    <li>Network-connectivity view built from the parsed logs (connections, source/destination IPs and ports, auth from remote hosts…). Rows carry the same triage buttons and jump to context; internal/external tagging and GeoIP apply as in the Dashboard.</li>
   </ul>

   <h3>GTFOBins</h3>
   <ul>
    <li>Catalog of legitimate Unix binaries and how they are abused. Click <b>Update catalog (GitHub)</b> to fetch/refresh it (needs <code>git</code> or outbound to GitHub); stored in <code>gtfobins_data/gtfobins.json</code>.</li>
    <li><b>Check executed binaries</b> cross-references the catalog with what was actually run in the logs (auditd <code>execve</code>, <code>bash_history</code>, what was launched via <code>sudo</code>, and the real binary inside <b>BSD appliance shell logs</b> — <code>sh_command="…"</code> / <code>shell_command="…"</code> in <code>/var/log/sh.log</code> and <code>/var/log/bash.log</code>) and shows a section per binary with its techniques, abuse examples and contexts (<code>sudo</code>/<code>suid</code>/…).</li>
    <li><b>View full catalog</b> lists the binaries with a filter; click one to see its invocations. In the results, each sample links to its context in the Explorer.</li>
    <li><b>Privilege context</b>: each binary is tagged <b>via sudo</b>, <b>as root</b>, <b>⚠ escalation</b> (euid=0 with a non-root login) or <b>appliance shell</b> (executed from the BSD appliance shell, a privileged context); the dangerous ones come first and in red. The real SUID bit is not observable from logs alone.</li>
    <li><b>Where it ran</b> lists up to 200 examples per binary; when there are more, the header shows «showing N of TOTAL» and a <b>See all N</b> button loads every hit. Each sample links to its context, and carries the <b>⎘ copy</b> and <b>mark</b> buttons.</li>
   </ul>

   <h3>Overview (Dashboard)</h3>
   <ul>
    <li>Counters, time range, events per hour and <i>tops</i> of IPs, users, binaries and programs. Each row jumps to the Explorer already filtered.</li>
    <li><b>GeoIP</b>: IPs are always tagged <b>internal</b>/<b>external</b> (no database needed). With <b>Update GeoIP database</b> the free <b>DB-IP Lite</b> bases are downloaded and then country, ASN and Org/ISP are shown (offline once downloaded). On startup the app <b>auto-updates GeoIP in the background</b> only if the base is missing or older than 30 days — silent if there's no network. Top source IPs here show <b>ASN · Org/ISP</b> inline.</li>
   </ul>

   <h3>Marks (triage)</h3>
   <ul>
    <li>Mark events as <b>pending / TP / FP / dismissed</b> with a note, from the «Mark event» button in the context or by adding the event <b>#</b>.</li>
    <li>The <b>mark buttons are available in every detection view</b> — Sigma, IOC sweep, ATT&amp;CK, Network, GTFOBins — right next to the copy / view-structured buttons, so you can triage a hit where you see it.</li>
    <li>Each mark created from a detection <b>freezes a context of the 10 surrounding events</b> plus the <b>rule/source</b> that produced it, so the triage record stays self-contained even if the logs change later.</li>
    <li>Marks can be <b>deleted</b> (with a confirmation prompt) and edited. They are stored <b>inside the case <code>.duckdb</code></b> (persist across restarts). Filter by status and jump to context.</li>
   </ul>

   <h3>SQL — most common filters</h3>
   <p>Everything is queried over the <code>events</code> table. Typical filters:</p>
   <pre>-- by source and event type
WHERE source = 'auth'
WHERE event IN ('ssh_failed','ssh_accepted')

-- by IP, user or executable
WHERE src_ip = '203.0.113.55'
WHERE user = 'root'
WHERE exe = '/usr/bin/wget'

-- partial text (like a grep)
WHERE message ILIKE '%/etc/passwd%'
WHERE raw ILIKE '%wget%'

-- time range (always in UTC)
WHERE ts BETWEEN TIMESTAMP '2026-09-30 20:00:00'
             AND TIMESTAMP '2026-09-30 20:15:00'

-- HTTP with error
WHERE source = 'access' AND status >= 400</pre>

   <h3>SQL — the <code>extra</code> JSON field (auditd)</h3>
   <p>auditd-specific fields (syscall, key, serial, acct…) live in the JSON
   <code>extra</code> column. Read them with <code>extra-&gt;&gt;'field'</code>, but DuckDB
   requires <b>wrapping it in parentheses</b>:</p>
   <pre>SELECT ts, exe, (extra-&gt;&gt;'key') AS rule
FROM events
WHERE source='auditd' AND (extra-&gt;&gt;'key') IS NOT NULL;</pre>
   <p>Alternative without parentheses: <code>json_extract_string(extra, '$.key')</code>.</p>

   <h3>Useful values</h3>
   <p><b>source</b>: auth, syslog, kern, cron, access, auditd, weberror, logfmt, applog, bash_history, <b>csv</b>, <b>dmesg</b>, <b>apt</b>, <b>fontconfig</b>, <b>udev</b>.</p>
   <p><b>event</b>: ssh_accepted, ssh_failed, ssh_invalid_user, sudo, session_opened/closed,
   http_request, execve, syscall, user_auth, web_error, command, kernel, dpkg, uevent.</p>
   <p>Columns: <a href="/schema" target="_blank">see all at /schema</a>. In the
   <b>SQL</b> tab there's a dropdown with ready-made example queries.</p>

   <h3>Recognised log formats</h3>
   <ul>
    <li><b>CSV</b> — comma-separated files. The header row (if present) names the fields; each row becomes one event. Known columns (user, ip, status, time…) map to real columns, the rest land in <code>extra</code> (toggle them in the <b>Columns</b> panel). Values with commas are handled if quoted.</li>
    <li><b>dmesg</b> — kernel ring buffer (<code>[&nbsp;&nbsp;&nbsp;0.000000] message</code>). One line = one event. The bracket is <b>seconds since boot</b>, not a date, so these events carry no timeline timestamp (the offset is kept in <code>extra.ktime</code>) — they're still fully searchable.</li>
    <li><b>apt / dpkg term.log</b> — <code>Log started:</code> … <code>Log ended:</code> blocks; each block is one event (timestamp from «Log started», package actions summarised, whole block in <code>raw</code>).</li>
    <li><b>fontconfig / fc-cache</b> — one line per event.</li>
    <li><b>udevadm monitor</b> — <code>UEVENT[epoch]</code> / <code>UDEV [epoch]</code> blocks separated by a blank line; each block is one event (epoch → real UTC time, the <code>KEY=value</code> lines go to <code>extra</code>).</li>
   </ul>
   <p class="hintlbl">Best results come from loading each format as its own file. A single file that mixes several formats is still fully ingested (nothing is dropped), but it's detected as one type.</p>

   <h3>When loading logs</h3>
   <p>Several logs (syslog/auth/kern/cron, applog and the web error.log) don't store their
   timezone. By default <b>UTC (offset 0)</b> is assumed. If your logs are in local time,
   give the offset in minutes when loading (field in the Load tab, <code>--tz</code> in the
   CLI or <code>tz_offset_minutes</code> in the API): <b>+120</b> = CEST (Spain summer),
   <b>+60</b> = CET, <b>-300</b> = EST. That way everything is in UTC and the timeline lines up.
   access and auditd are already in UTC and left untouched.
   Only text logs are accepted (a binary is rejected); folders and archives
   (.tar.gz/.zip/.gz…) are extracted and walked automatically.</p>
   <p>When reading from a <b>server path</b>, the progress bar now advances <b>by bytes</b>
   (reading X / Y MB · %), so it moves smoothly <i>within</i> a single large file, not just
   file by file. Events are inserted in batches as the file is read.</p>
  </div>
 </section>
</main>
<div id="rawmodal" class="rawmodal hidden" onclick="if(event.target===this)closeRaw()">
 <div class="rawmbox">
  <div class="rawmbar"><span>Structured event</span>
   <span><button class="sec" onclick="copyRawModal(this)">&#10697; Copy</button>
   <button class="sec" onclick="closeRaw()">&#10005; Close</button></span></div>
  <pre id="rawmodalpre" class="rawpre"></pre>
 </div>
</div>
<footer style="border-top:1px solid var(--border);margin-top:24px;padding:14px 16px;text-align:center;color:var(--muted);font-size:12px">
 <svg viewBox="0 0 24 24" width="1.2em" height="1.2em" style="vertical-align:-.26em" aria-label="chorizo"><path d="M18.7 5.8 L20.9 3.9 M18.7 5.8 L20.3 7.9" fill="none" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#141414" stroke-width="7.8" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#e0485a" stroke-width="5.6" stroke-linecap="round"/><path d="M7.4 16.8 C10 18.6 15.4 17.6 16.8 8" fill="none" stroke="#f58a95" stroke-width="1.6" stroke-linecap="round" opacity=".85"/><path d="M10.6 19.9 l1.3 -2.4" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M14.8 19.2 l1.2 -2.3" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M3.7 20.2 L6.4 18.2 L5.9 21.2 Z" fill="#e0485a" stroke="#141414" stroke-width="1.1" stroke-linejoin="round"/></svg> Longanizer &middot; made by <b style="color:var(--accent)">gmzpt</b>
</footer>
<script>
function esc(v){if(v===null||v===undefined)return '<span class=muted>&#8709;</span>';return String(v).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
/* Pestañas agrupadas: un padre abre una sub-barra con sus hijos. */
const GROUPS={ai:['ai','ailocal','mcp']};
let GROUP_LAST={ai:'ai'};
function groupOf(t){ for(const g in GROUPS){ if(GROUPS[g].includes(t)) return g; } return null; }
function openGroup(g){ switchTab(GROUP_LAST[g]||GROUPS[g][0]); }
function switchTab(t){
 const g=groupOf(t);
 if(g) GROUP_LAST[g]=t;
 document.querySelectorAll('.tab').forEach(x=>{
  const dt=x.dataset.tab;
  if(dt==='__ai') x.classList.toggle('active', g==='ai');
  else x.classList.toggle('active', dt===t);
 });
 document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('active',x.id===t));
 const sa=document.getElementById('subnav_ai');
 if(sa) sa.classList.toggle('hidden', g!=='ai');
 document.querySelectorAll('.subtab').forEach(x=>x.classList.toggle('active',x.dataset.tab===t));
 if(t==='mcp')loadMcpHelp();
 if(t==='sigma')sigmaInit();
 if(t==='dash' && !DASH_LOADED){ DASH_LOADED=true; loadDash(); geoStatus(); }
 if(t==='marks') loadMarks();
 if(t==='network' && !document.getElementById('nw_out').innerHTML) loadNetwork();
 if(t==='attack' && !document.getElementById('at_out').innerHTML) loadAttack();
}
/* autocompletado de campos para la caja de búsqueda (sintaxis campo:valor) */
const QFIELDS=['source','host','program','user','src_ip','src_port','exe','method','path','status','event','message','asn','org','ts'];
let QAC_FIELDS=[];
function buildFieldList(){
 QAC_FIELDS=QFIELDS.map(f=>f+':').concat((XKEYS||[]).map(k=>'x:'+k+':'));
 const fx=document.getElementById('facextra');
 if(fx) fx.innerHTML=(XKEYS||[]).map(k=>'<option value="x:'+esc(k)+'">'+esc(k)+'</option>').join('');
}
/* ---- autocompletado del token actual (funciona en cualquier punto, no solo
   el primer campo como hacía el <datalist> nativo) ---- */
let QAC_ACTIVE=-1, QAC_MATCHES=[];
function qacTokenBounds(v,pos){ let s=pos; while(s>0 && v[s-1]!==' ') s--; return {start:s,end:pos}; }
function qacUpdate(){
 const inp=document.getElementById('q'), box=document.getElementById('qac');
 if(!inp||!box) return;
 const v=inp.value, pos=inp.selectionStart==null?v.length:inp.selectionStart;
 const b=qacTokenBounds(v,pos); let tok=v.slice(b.start,b.end);
 let neg=''; if(tok[0]==='-'){ neg='-'; tok=tok.slice(1); }
 // no sugerir una vez el token ya trae operador de valor
 if(tok==='' || tok.indexOf(':')>=0 || tok.indexOf('=')>=0 || tok.indexOf('!')>=0){ qacHide(); return; }
 const low=tok.toLowerCase();
 QAC_MATCHES=QAC_FIELDS.filter(f=>f.toLowerCase().startsWith(low)).slice(0,12);
 if(!QAC_MATCHES.length){ qacHide(); return; }
 QAC_ACTIVE=0;
 box.innerHTML=QAC_MATCHES.map((f,i)=>'<div class="qacit'+(i===0?' on':'')+'" data-i="'+i+'" onmousedown="qacPick(event,'+i+')">'+esc(neg+f)+'</div>').join('');
 box.classList.remove('hidden');
}
function qacHide(){ const box=document.getElementById('qac'); if(box){box.classList.add('hidden'); box.innerHTML='';} QAC_ACTIVE=-1; QAC_MATCHES=[]; }
function qacMove(d){ const box=document.getElementById('qac'); if(!box||box.classList.contains('hidden')||!QAC_MATCHES.length) return false;
 QAC_ACTIVE=(QAC_ACTIVE+d+QAC_MATCHES.length)%QAC_MATCHES.length;
 [...box.children].forEach((c,i)=>c.classList.toggle('on',i===QAC_ACTIVE)); return true; }
function qacAccept(i){
 const inp=document.getElementById('q'); if(!inp||i<0||i>=QAC_MATCHES.length) return false;
 const v=inp.value, pos=inp.selectionStart==null?v.length:inp.selectionStart;
 const b=qacTokenBounds(v,pos); let tok=v.slice(b.start,b.end); let neg=tok[0]==='-'?'-':'';
 const ins=neg+QAC_MATCHES[i];
 const nv=v.slice(0,b.start)+ins+v.slice(b.end);
 inp.value=nv; const np=b.start+ins.length; inp.setSelectionRange(np,np); qacHide(); inp.focus(); return true;
}
function qacPick(ev,i){ ev.preventDefault(); qacAccept(i); }
function qacKey(ev){
 const box=document.getElementById('qac'); const open=box&&!box.classList.contains('hidden');
 if(ev.key==='ArrowDown'){ if(qacMove(1)){ev.preventDefault();ev.stopImmediatePropagation();} return; }
 if(ev.key==='ArrowUp'){ if(qacMove(-1)){ev.preventDefault();ev.stopImmediatePropagation();} return; }
 if((ev.key==='Enter'||ev.key==='Tab') && open && QAC_ACTIVE>=0){ if(qacAccept(QAC_ACTIVE)){ ev.preventDefault(); ev.stopImmediatePropagation(); } return; }
 if(ev.key==='Escape'){ if(open){ qacHide(); ev.preventDefault(); ev.stopImmediatePropagation(); } return; }
}
function qacInit(){
 const inp=document.getElementById('q'); if(!inp||inp._qac) return; inp._qac=true;
 inp.addEventListener('input', qacUpdate);
 inp.addEventListener('keydown', qacKey, true);   // captura: antes del handler de Enter=buscar
 inp.addEventListener('blur', ()=>setTimeout(qacHide,120));
}
/* ---------- Facetas (top valores de un campo sobre el resultado actual) ---------- */
async function loadFacets(){
 const out=document.getElementById('fac_out');
 const field=document.getElementById('facfield').value;
 out.innerHTML='<span class="muted">computing…</span>';
 // sigue la vista activa: en el timeline completo se ignora la caja (como el timeline)
 const qv=(LASTVIEW==='timeline')?'':document.getElementById('q').value.trim();
 const body={field, q:qv,
   regex:document.getElementById('rgx').checked,
   source:document.getElementById('src').value,
   start:document.getElementById('tstart').value.trim()||null,
   end:document.getElementById('tend').value.trim()||null, limit:20};
 try{
  const r=await fetch('/facets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  if(!r.ok){ out.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  if(!j.values.length){ out.innerHTML='<span class="muted">no values for «'+esc(field)+'» in the current results</span>'; return; }
  const max=j.values[0].count||1;
  const scope=(LASTVIEW==='timeline')?'timeline':'search';
  let h='<div class="faccount">'+j.distinct+' distinct · showing top '+j.values.length+' · '+j.matched+' events matched <span class="muted">('+scope+')</span> <button class="xs facclose" onclick="document.getElementById(\'fac_out\').innerHTML=\'\'" title="hide facets">&#10005; hide</button></div><div class="facwrap">';
  for(const v of j.values){
   h+='<div class="facrow" data-f="'+esc(field)+'" data-v="'+esc(v.value)+'" onclick="facPick(this)" title="add this value to the search">'
     +'<span class="facbar" style="width:'+Math.max(2,Math.round(v.count/max*100))+'%"></span>'
     +'<span class="facval">'+esc(v.value)+'</span><span class="facn">'+v.count+'</span></div>';
  }
  out.innerHTML=h+'</div>';
 }catch(e){ out.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
function facPick(el){
 const field=el.dataset.f, val=el.dataset.v||'';
 const tok=(/\s/.test(val)?field+':"'+val+'"':field+':'+val);
 const q=document.getElementById('q');
 q.value=(q.value.trim()+' '+tok).trim();
 doSearch();
}
async function refresh(){
 const s=document.getElementById('stat');
 try{const r=await fetch('/stats');const j=await r.json();
  s.textContent=j.total_events+' events · '+j.by_source.map(x=>x.source+':'+x.count).join('  ');
  const sel=document.getElementById('src');
  const cur=sel.value;
  sel.innerHTML='<option>(all)</option>'+j.by_source.map(x=>'<option>'+x.source+'</option>').join('');
  sel.value=cur;
  mergeExtraKeys(j.extra_keys);
  buildFieldList();
  updateNav(j.total_events);
  return j.total_events;
 }catch(e){s.textContent='no connection';return 0}
}
function updateNav(total){
 const has=total>0;
 document.querySelectorAll('.tab[data-optional]').forEach(t=>t.classList.toggle('hidden',!has));
 document.getElementById('goexp').classList.toggle('hidden',!has);
}
async function loadDbInfo(){
 try{
  const j=await (await fetch('/dbinfo')).json();
  const pill=document.getElementById('dbpill');
  const note=document.getElementById('dbnote');
  pill.style.color='';
  if(j.pending){
   pill.textContent='○ not saved yet';
   pill.style.color='#8b949e';
   note.innerHTML='Nothing loaded yet: a case file will be created in <code>casos/</code> <b>as soon as you load the first log</b> (or open an existing one below).';
  }else if(j.memory){
   pill.textContent='⚠ in memory (not saved)';
   pill.style.color='#d29922';
   note.innerHTML='⚠ This case runs <b>in memory</b>: it is lost on close. To keep it, start without setting <code>DUCKDB_PATH</code> or give it a <code>.duckdb</code> path.';
  }else{
   pill.textContent='💾 '+j.filename;
   note.innerHTML='Saving to <code>'+esc(j.path)+'</code>. You can close and reopen it pointing there; it is also what the MCP tab uses.';
  }
 }catch(_){}
}
function fmtSize(n){ if(n<1024)return n+' B'; if(n<1048576)return (n/1024).toFixed(0)+' KB'; return (n/1048576).toFixed(1)+' MB'; }
async function loadCases(){
 const sel=document.getElementById('dbsel');
 try{
  const j=await (await fetch('/db/list')).json();
  if(!j.cases.length){ sel.innerHTML='<option value="">(no saved cases in ./casos)</option>'; return; }
  sel.innerHTML=j.cases.map(c=>{
   const curtag=(c.path===j.current)?'  ← current':'';
   return '<option value="'+esc(c.path)+'">'+esc(c.name)+'  ('+c.mtime+', '+fmtSize(c.size)+')'+curtag+'</option>';
  }).join('');
  if(j.current) sel.value=j.current;
 }catch(_){ sel.innerHTML='<option value="">(could not list)</option>'; }
}
async function openDb(path){
 const msg=document.getElementById('ingmsg');
 if(!path){ msg.innerHTML='<span class="err">Pick a case or type the path to a .duckdb.</span>'; return; }
 msg.textContent='opening '+path+' …';
 try{
  const r=await fetch('/db/open',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
  const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  INGESTED=[]; renderIngested();
  msg.textContent='✓ case opened · '+j.stats.total_events+' events';
  loadDbInfo(); loadCases();
  const total=await refresh();
  if(total>0) switchTab('explorer');
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
function openSelectedDb(){ openDb(document.getElementById('dbsel').value); }
function openPathDb(){ openDb(document.getElementById('dbpath').value.trim()); }
async function init(){
 qacInit();
 loadDbInfo();
 loadCases();
 const total=await refresh();
 switchTab(total>0?'explorer':'landing');
}

/* ---------- Ingesta (por lotes, para que muchos ficheros vayan rapido) ---------- */
const UP_CHUNK=50;  // ficheros por peticion: menos viajes HTTP = mas rapido
function uploadChunk(files,tz,onprog){
 return new Promise((resolve,reject)=>{
  const xhr=new XMLHttpRequest();
  xhr.open('POST','/ingest/upload');
  xhr.upload.onprogress=e=>{ if(e.lengthComputable) onprog(e.loaded/e.total); };
  xhr.onload=()=>{ try{const j=JSON.parse(xhr.responseText); xhr.status<400?resolve(j):reject(j.detail||'error');}catch(_){reject('invalid response');} };
  xhr.onerror=()=>reject('network error');
  const fd=new FormData();
  fd.append('tz_offset_minutes',tz);
  fd.append('catch_all', document.getElementById('catchall').checked ? 'true':'false');
  for(const f of files){ fd.append('files',f); fd.append('relpaths', f.webkitRelativePath || f.name); }
  xhr.send(fd);
 });
}
function clearPicks(){
 document.getElementById('files').value='';
 document.getElementById('folder').value='';
 document.getElementById('ingmsg').textContent='selection cleared';
}
let INGESTED=[];  // manifiesto acumulado de ficheros procesados
/* Ingesta desde una ruta del propio servidor (sin subir por el navegador):
   el servidor lee del disco directo; admite carpeta, fichero o comprimido. */
/* ---- reloj de ingesta: hora de inicio, transcurrido y restante estimado ---- */
function _fmtDur(s){ s=Math.max(0,Math.round(s)); if(s<60)return s+'s'; const m=Math.floor(s/60),ss=s%60; if(m<60)return m+'m'+(ss?(' '+ss+'s'):''); const h=Math.floor(m/60),mm=m%60; return h+'h'+(mm?(' '+mm+'m'):''); }
function _clock(ms){ try{return new Date(ms).toLocaleTimeString();}catch(_){return '';} }
function ingClock(t0,frac,approx){
 const el=(Date.now()-t0)/1000;
 let s='started '+_clock(t0)+' · elapsed '+_fmtDur(el);
 if(frac>0.02 && frac<1){ s+=' · ~'+_fmtDur(el*(1-frac)/frac)+' left'+(approx?' (approx)':''); }
 return s;
}
async function ingestPath(){
 const msg=document.getElementById('ingmsg');
 const prog=document.getElementById('prog');
 const path=document.getElementById('spath').value.trim();
 if(!path){msg.textContent='Enter a server path.';return}
 const tz=parseInt(document.getElementById('tzp').value,10)||0;
 const t0=Date.now();
 msg.textContent='reading from disk: '+path+' … · started '+_clock(t0);
 prog.style.display=''; prog.value=0;
 let total=0, done=0, ev=0, ok=0, skip=0, err=0, totalBytes=0, bytesDone=0;
 const hb=n=>n>=1048576?(n/1048576).toFixed(1)+' MB':(n>=1024?(n/1024).toFixed(0)+' KB':n+' B');
 try{
  const r=await fetch('/ingest/path/stream',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({path,tz_offset_minutes:tz,catch_all:document.getElementById('catchall').checked})});
  if(!r.ok){ let d=''; try{d=(await r.json()).detail;}catch(_){} prog.style.display='none';
    msg.innerHTML='<span class="err">'+esc(d||('error '+r.status))+'</span>'; return; }
  const reader=r.body.getReader(); const dec=new TextDecoder(); let buf='';
  for(;;){
   const {value,done:fin}=await reader.read();
   if(fin)break;
   buf+=dec.decode(value,{stream:true});
   let nl;
   while((nl=buf.indexOf('\n'))>=0){
    const line=buf.slice(0,nl).trim(); buf=buf.slice(nl+1);
    if(!line)continue;
    let x; try{x=JSON.parse(line);}catch(_){continue;}
    if(x.total!=null){ total=x.total; if(x.total_bytes!=null) totalBytes=x.total_bytes; continue; }
    if(x.progress_bytes!=null){ // progreso POR BYTES (incl. dentro de un fichero)
     bytesDone=x.progress_bytes;
     if(totalBytes>0){ const p=Math.min(99,Math.round(bytesDone/totalBytes*100)); prog.value=p;
       msg.textContent='reading '+hb(bytesDone)+' / '+hb(totalBytes)+' · '+p+'% · '+ev+' events · '+ingClock(t0,bytesDone/totalBytes,false); }
     continue;
    }
    if(x.fatal){ INGESTED.push({file:path,error:x.fatal}); err++; done++; continue; }
    if(x.archive && x.events==null && x.error==null){ continue; } // contenedor: no cuenta
    INGESTED.push(x);
    if(x.events!=null){ok++; ev+=x.events; done++;}
    else if(x.skipped){skip++; done++;}
    else if(x.error){err++; done++;}
    // % preferentemente por bytes; si no hay bytes, por ficheros
    let pct=null;
    if(totalBytes>0) pct=Math.min(99,Math.round(bytesDone/totalBytes*100));
    else if(total>0) pct=Math.min(99,Math.round(done/total*100));
    if(pct!=null) prog.value=pct;
    const denom=(total>0 && done<=total)?('/≈'+total):'';
    const fr=(totalBytes>0)?(bytesDone/totalBytes):(total>0?done/total:0);
    msg.textContent='processing '+done+denom+' files'+(pct!=null?' · '+pct+'%':'')+' · '+ev+' events · '+ingClock(t0,fr,false);
    if(done%25===0) renderIngested();
   }
  }
  prog.value=100; prog.style.display='none';
  msg.textContent='✓ '+ev+' events · '+ok+' files loaded'
    +(skip?' · '+skip+' skipped':'')+(err?' · '+err+' errored':'')+' · took '+_fmtDur((Date.now()-t0)/1000);
  renderIngested(); await refresh(); loadDbInfo(); loadCases();
 }catch(e){ prog.style.display='none'; msg.innerHTML='<span class="err">'+esc(e)+'</span>'; renderIngested(); }
}
async function uploadFiles(){
 const msg=document.getElementById('ingmsg');
 const prog=document.getElementById('prog');
 const picks=[...document.getElementById('files').files, ...document.getElementById('folder').files];
 if(!picks.length){msg.textContent='Pick files or a folder first.';return}
 const tz=document.getElementById('tz').value||'0';
 const total=picks.length;
 const t0=Date.now();
 let done=0, ev=0, ok=0, skip=0, err=0;
 prog.style.display=''; prog.value=0;
 for(let i=0;i<picks.length;i+=UP_CHUNK){
  const chunk=picks.slice(i,i+UP_CHUNK);
  msg.textContent='uploading '+(done+1)+'-'+(done+chunk.length)+' / '+total+' files · '+ingClock(t0,done/total,false);
  try{
   const j=await uploadChunk(chunk,tz,frac=>{ const f=(done+frac*chunk.length)/total; prog.value=Math.round(f*100);
     msg.textContent='uploading '+(done+1)+'-'+(done+chunk.length)+' / '+total+' files · '+Math.round(f*100)+'% · '+ingClock(t0,f,false); });
   for(const x of (j.ingested||[])){
    INGESTED.push(x);
    if(x.events!=null){ok++; ev+=x.events;} else if(x.skipped){skip++;} else if(x.error){err++;}
   }
  }catch(e){ for(const f of chunk) INGESTED.push({file:(f.webkitRelativePath||f.name), error:String(e)}); err+=chunk.length; }
  done+=chunk.length;
  prog.value=Math.round((done/total)*100);
  msg.textContent='processing '+done+'/'+total+' ('+Math.round(done/total*100)+'%) · '+ingClock(t0,done/total,false);
  renderIngested();
 }
 prog.style.display='none';
 // vaciar la selección para no re-subir lo mismo (duplicaría)
 document.getElementById('files').value='';
 document.getElementById('folder').value='';
 msg.textContent='✓ '+ev+' events · '+ok+' files loaded'
   +(skip?' · '+skip+' skipped':'')+(err?' · '+err+' errored':'')+' · took '+_fmtDur((Date.now()-t0)/1000);
 renderIngested();
 await refresh(); loadDbInfo(); loadCases();
}
function renderIngested(){
 const box=document.getElementById('ingested');
 if(!INGESTED.length){box.innerHTML='';return}
 const loaded =INGESTED.filter(x=>x.events!=null);
 const skipped=INGESTED.filter(x=>x.skipped);
 const errored=INGESTED.filter(x=>x.error);
 const archived=INGESTED.filter(x=>x.archive && !x.error);
 let h='<div class="count">'+loaded.length+' loaded · '+skipped.length+' skipped · '+errored.length+' errored'
      +(archived.length?' · '+archived.length+' archives':'')+'</div>';
 h+=secOK('✓ Loaded ('+loaded.length+')', loaded);
 h+=secFail('⤼ Skipped ('+skipped.length+')','skipped','st-skip', skipped);
 h+=secFail('✗ Errored ('+errored.length+')','error','st-err', errored);
 if(archived.length){
  h+='<h3 class="st-arc">📦 Extracted archives ('+archived.length+')</h3>';
  h+='<div class="wrap"><table><thead><tr><th>file</th></tr></thead><tbody>';
  for(const x of archived) h+='<tr><td>'+esc(x.archive)+'</td></tr>';
  h+='</tbody></table></div>';
 }
 box.innerHTML=h;
}
function secOK(title,list){
 if(!list.length)return '';
 let h='<h3 class="st-ok">'+title+'</h3><div class="wrap"><table><thead><tr><th>file</th><th>type</th><th>events</th></tr></thead><tbody>';
 for(const x of list) h+='<tr><td title="'+esc(x.file)+'">'+esc(x.file)+'</td><td>'+esc(x.type)+'</td><td>'+esc(x.events)+'</td></tr>';
 return h+'</tbody></table></div>';
}
function secFail(title,key,cls,list){
 if(!list.length)return '';
 let h='<h3 class="'+cls+'">'+title+'</h3><div class="wrap"><table><thead><tr><th>file</th><th>reason</th><th>first lines</th></tr></thead><tbody>';
 for(const x of list){
  const name=x.file||x.archive||'';
  h+='<tr><td title="'+esc(name)+'">'+esc(name)+'</td><td title="'+esc(x[key])+'">'+esc(x[key])+'</td>'
    +'<td class="prevcell"><pre class="prev">'+esc(x.preview||'')+'</pre></td></tr>';
 }
 return h+'</tbody></table></div>';
}

/* Columnas mostradas en las tablas de resultados/timeline/contexto */
const BASECOLS=['seq','ts','source','host','program','pid','severity','user','src_ip','asn','org','src_port','method','path','status','bytes','exe','event','message','referer','user_agent','extra','src_file'];
const LABELS={seq:'#',src_file:'file',user_agent:'user-agent',asn:'ASN',org:'Org/ISP'};
function pageSize(){ const n=parseInt(document.getElementById('pagesize').value,10); return (Number.isInteger(n)&&n>0)?n:500; }
/* ---- columnas: orden + mostrar/ocultar (persistido en localStorage) ----
   Cada columna es un campo base (p.ej. 'status') o una clave dinámica de
   `extra` con prefijo 'x:' (p.ej. 'x:widget'), auto-descubierta de logs
   desconocidos (logfmt). Se pueden reordenar y ocultar. */
let COLS=loadOrder();
let XKEYS=[];                 // claves de extra ya descubiertas
let HIDDEN=loadHidden();
/* claves de localStorage propias de LogAnalyzer (no compartir con EVTXray) */
function loadOrder(){ try{const a=JSON.parse(localStorage.getItem('logan_colorder')||'null');
  if(Array.isArray(a)&&a.length){ for(const c of BASECOLS){ if(!a.includes(c)) a.push(c); } return a; }
 }catch(_){} return BASECOLS.slice(); }
function saveOrder(){ try{localStorage.setItem('logan_colorder',JSON.stringify(COLS));}catch(_){} }
function loadHidden(){ try{return new Set(JSON.parse(localStorage.getItem('logan_hidden')||'[]'));}catch(_){return new Set();} }
function saveHidden(){ try{localStorage.setItem('logan_hidden',JSON.stringify([...HIDDEN]));}catch(_){} }
function isX(c){ return c.indexOf('x:')===0; }
function colLabel(c){ return isX(c)?c.slice(2):(LABELS[c]||c); }
function colClass(c){ return 'c-'+c.replace(/[^\w-]/g,'_'); }  // c-status / c-x_widget
/* Sólo se renderizan como <td> las columnas visibles (las base siempre; las x:
   dinámicas sólo cuando están visibles). Antes se pintaban TODAS y se ocultaban
   por CSS: con muchos logs eran cientos de miles de celdas vacías -> lento. */
function renderCols(){ return COLS.filter(c=>!isX(c) || !HIDDEN.has(c)); }
function applyCols(){ document.getElementById('colstyle').textContent=[...HIDDEN].map(c=>'.'+colClass(c)+'{display:none}').join(''); }
function toggleCol(c,show){ if(show)HIDDEN.delete(c); else HIDDEN.add(c); saveHidden(); applyCols(); if(isX(c))rerender(); }
function allCols(show){ HIDDEN = show ? new Set() : new Set(COLS.filter(c=>c!=='seq'&&c!=='ts')); saveHidden(); applyCols(); buildColsPanel(); rerender(); }
function toggleColsPanel(){ document.getElementById('colspanel').classList.toggle('hidden'); }
/* incorpora claves de extra nuevas (de /stats) como columnas al final.
   Nacen OCULTAS (auditd y otros logs traen decenas de claves en extra); se
   activan con un clic en el panel de columnas, donde salen marcadas "extra". */
function mergeExtraKeys(keys){
 let changed=false;
 for(const k of (keys||[])){
  if(!XKEYS.includes(k))XKEYS.push(k);
  const id='x:'+k;
  if(!COLS.includes(id)){ COLS.push(id); HIDDEN.add(id); changed=true; }
 }
 if(changed){ saveOrder(); saveHidden(); applyCols(); buildColsPanel(); }
 return changed;
}
function moveCol(i,dir){ const j=i+dir; if(j<0||j>=COLS.length)return; const t=COLS[i];COLS[i]=COLS[j];COLS[j]=t; saveOrder(); buildColsPanel(); rerender(); }
function resetCols(){ COLS=BASECOLS.slice(); HIDDEN=new Set(); for(const k of XKEYS){const id='x:'+k;COLS.push(id);HIDDEN.add(id);} saveOrder(); saveHidden(); applyCols(); buildColsPanel(); rerender(); }
function rerender(){ if(LASTVIEW==='timeline')showTimeline(); else if(document.getElementById('q').value.trim())doSearch(); }
function buildColsPanel(){
 const p=document.getElementById('colspanel');
 const shown=COLS.filter(c=>!HIDDEN.has(c)).length;
 const chips=COLS.map((c,i)=>{
   const on=!HIDDEN.has(c);
   const lb=esc(colLabel(c));
   const up = i>0 ? '<button class="xs" onclick="event.stopPropagation();moveCol('+i+',-1)" title="move before">&#9664;</button>' : '';
   const dn = i<COLS.length-1 ? '<button class="xs" onclick="event.stopPropagation();moveCol('+i+',1)" title="move after">&#9654;</button>' : '';
   const tag = isX(c)?'<span class="xtag">extra</span>':'';
   return '<div class="colchip '+(on?'on':'off')+'" onclick="clickCol(\''+c+'\')" title="'+(on?'hide':'show')+' '+lb+'">'
     +'<span class="coldot"></span><span class="collbl">'+lb+'</span>'+tag
     +'<span class="colmv">'+up+dn+'</span></div>';
 }).join('');
 p.innerHTML='<div class="colbtns">'
   +'<button class="sec" onclick="allCols(true)">Show all</button>'
   +'<button class="sec" onclick="allCols(false)">Hide all</button>'
   +'<button class="sec" onclick="hideEmptyCols()">Hide empty</button>'
   +'<button class="sec" onclick="resetCols()">Original order</button>'
   +'<span class="colcount">'+shown+' of '+COLS.length+' columns visible</span></div>'
   +'<div class="colhint">Click a column to show or hide it · use &#9664; &#9654; to reorder · those tagged <span class="xtag">extra</span> come from the <code>extra</code> JSON</div>'
   +'<div class="colgrid">'+chips+'</div>';
}
function clickCol(c){ toggleCol(c, HIDDEN.has(c)); buildColsPanel(); }
/* oculta las columnas que están vacías en los resultados mostrados ahora */
function hideEmptyCols(){
 const rows=document.querySelectorAll('#hits table tbody tr');
 if(!rows.length)return;
 const cols=renderCols();
 cols.forEach((c,ci)=>{
  if(c==='seq'||c==='ts')return;
  let hasData=false;
  rows.forEach(tr=>{const td=tr.children[ci+1]; if(td){const t=td.textContent.trim(); if(t && t!=='∅') hasData=true;}});  // +1: celda copiar
  if(!hasData) HIDDEN.add(c);
 });
 saveHidden(); applyCols(); buildColsPanel(); rerender();
}
let LASTVIEW='search';
let SORT={col:null,desc:false};
function headHtml(sortable){
 return '<thead><tr><th class="acts" title="copy · review · raw"></th>'+renderCols().map(c=>{
   const lab=esc(colLabel(c)), cls=colClass(c);
   if(sortable){ const ar=(SORT.col===c)?(SORT.desc?' ▼':' ▲'):''; return '<th class="'+cls+' sortable" onclick="sortBy(\''+c+'\')">'+lab+ar+'</th>'; }
   return '<th class="'+cls+'">'+lab+'</th>';
 }).join('')+'</tr></thead>';
}
function sortBy(c){ if(SORT.col===c){SORT.desc=!SORT.desc;}else{SORT.col=c;SORT.desc=false;} if(LASTVIEW==='timeline')showTimeline(); else doSearch(); }
/* ================= Network (Linux) ================= */
let NET_ROWS=[];
function clearNet(){ for(const id of ['nw_ip','nw_port','nw_source','nw_event']) document.getElementById(id).value=''; loadNetwork(); }
async function loadNetwork(){
 const out=document.getElementById('nw_out'), msg=document.getElementById('nw_msg');
 const qs=new URLSearchParams();
 const m={ip:'nw_ip',port:'nw_port',source:'nw_source',event:'nw_event'};
 for(const k in m){ const el=document.getElementById(m[k]); const v=el?el.value.trim():''; if(v) qs.set(k,v); }
 msg.textContent='loading…';
 try{ const j=await (await fetch('/network'+(qs.toString()?'?'+qs:''))).json(); msg.textContent=''; NET_ROWS=j.rows||[];
  if(!NET_ROWS.length){ out.innerHTML='<p class="muted">No network events match.</p>'; return; }
  let h='<div class="count">'+NET_ROWS.length+' network event(s) '
    +'<button class="sec xcsv" onclick="csvObjs([\'ts\',\'source\',\'event\',\'src_ip\',\'src_port\',\'method\',\'path\',\'status\',\'exe\',\'user\',\'host\',\'detail\'],NET_ROWS,\'network.csv\')">&#8615; CSV</button></div>';
  h+='<div class="wrap wide"><table><thead><tr><th class="acts"></th><th>ts</th><th>source</th><th>event</th><th>src IP</th><th>sport</th><th>method</th><th>path</th><th>status</th><th>exe</th><th>user</th><th>host</th></tr></thead><tbody>';
  for(const n of NET_ROWS){ h+='<tr class="hitrow" onclick="openCtx('+n.id+')">'+actCell(n.id)+'<td>'+esc(n.ts)+'</td><td>'+esc(n.source)+'</td><td>'+esc(n.event)+'</td><td>'+esc(n.src_ip)+'</td><td>'+esc(n.src_port)+'</td><td>'+esc(n.method)+'</td><td title="'+esc(n.path)+'">'+esc((n.path||'').slice(0,60))+'</td><td>'+esc(n.status)+'</td><td title="'+esc(n.exe)+'">'+esc((n.exe||'').split('/').pop())+'</td><td>'+esc(n.user)+'</td><td>'+esc(n.host)+'</td></tr>'; }
  out.innerHTML=h+'</tbody></table></div>';
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
/* ================= ATT&CK matrix (Linux) ================= */
async function loadAttack(){
 const out=document.getElementById('at_out'), msg=document.getElementById('at_msg'),
       prog=document.getElementById('at_prog'), btn=document.getElementById('at_btn');
 msg.textContent='running Sigma…'; if(prog){prog.style.display='';prog.value=0;} if(btn)btn.disabled=true;
 let j=null;
 try{
  const r=await fetch('/attack/stream',{method:'POST'});
  if(!r.ok){ let d=''; try{d=(await r.json()).detail;}catch(_){}
    if(prog)prog.style.display='none'; if(btn)btn.disabled=false;
    out.innerHTML='<p class="muted">'+esc(d||('error '+r.status))+'</p>'; msg.textContent=''; return; }
  const reader=r.body.getReader(); const dec=new TextDecoder(); let buf='';
  for(;;){
   const {value,done:fin}=await reader.read(); if(fin)break;
   buf+=dec.decode(value,{stream:true}); let nl;
   while((nl=buf.indexOf('\n'))>=0){
    const line=buf.slice(0,nl).trim(); buf=buf.slice(nl+1);
    if(!line)continue; let x; try{x=JSON.parse(line);}catch(_){continue;}
    if(x.fatal){ if(prog)prog.style.display='none'; if(btn)btn.disabled=false;
      out.innerHTML='<p class="muted">'+esc(x.fatal)+'</p>'; msg.textContent=''; return; }
    if(x.done){ j=x.matrix||{}; continue; }
    if(prog&&x.total>0) prog.value=Math.round(x.i/x.total*100);
    msg.textContent='running rule '+x.i+'/'+x.total+' · '+x.found+' with findings…';
   }
  }
  if(prog){prog.value=100;prog.style.display='none';} if(btn)btn.disabled=false;
  msg.textContent='';
  if(!j){ out.innerHTML='<p class="muted">incomplete response</p>'; return; }
  if(j.error){ out.innerHTML='<p class="muted">'+esc(j.error)+'</p>'; return; }
  if(!j.tactics||!j.tactics.length){ out.innerHTML='<p class="muted">No ATT&CK-tagged Sigma hits yet. Load and run your Sigma rules first — techniques come from the <code>attack.*</code> tags on each rule.</p>'; return; }
  let h='<div class="count">'+j.total_findings+' matched rule(s) · click a technique to jump to a sample event</div><div class="attgrid">';
  for(const col of j.tactics){
   h+='<div class="attcol"><div class="atthead">'+esc(col.label)+' <span class="muted">('+col.techs.length+')</span></div>';
   for(const t of col.techs){ const lv=t.level||'info';
    const fid=(t.ids||[])[0];
    const rev=fid?'<button class="revbtn atttechrev" title="add a sample of this technique to review (mark pending, 10-event context)" onclick="event.stopPropagation();addReview('+fid+',this)" data-regla="'+esc('ATT&CK '+t.tech)+'">&#43;</button>':'';
    h+='<div class="atttech sev-'+lv+'" onclick="attackDrill(this)" data-ids="'+esc((t.ids||[]).join(','))+'" title="'+esc(t.rules.map(r=>r.title+' ('+r.count+')').join(' | '))+'">'+rev+'<span class="attt">'+esc(t.tech)+'</span><span class="attn">'+t.count+'</span></div>';
   }
   h+='</div>';
  }
  out.innerHTML=h+'</div>';
 }catch(e){ if(prog)prog.style.display='none'; if(btn)btn.disabled=false; msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
function attackDrill(el){ const ids=(el.dataset.ids||'').split(',').filter(Boolean); if(ids.length) sigmaGoto(parseInt(ids[0],10)); }
/* valor de una celda: campo base o clave de extra (x:) */
function cellVal(row,idx,c,xobj){ return isX(c) ? (xobj&&xobj[c.slice(2)]!=null?xobj[c.slice(2)]:'') : row[idx[c]]; }
function parseExtra(row,idx){ try{ return row[idx.extra]?JSON.parse(row[idx.extra]):null; }catch(_){ return null; } }
/* conjunto de campos que auditd tradujo de hex a texto (extra._dec = "cmd,cwd,…");
   'cmd' marca la command line (columna message). */
function decSet(xobj){ const s=new Set(); if(xobj&&xobj._dec){ for(const k of String(xobj._dec).split(',')) if(k) s.add(k); } return s; }
const CELL_MAX=240, CELL_TITLE_MAX=4000;
function tdCell(v,cls,dec){
 const ca=cls?(' class="'+cls+(dec?' xdec':'')+'"'):(dec?' class="xdec"':'');
 if(v===null||v===undefined)return '<td'+ca+'><span class=muted>&#8709;</span></td>';
 const s=String(v);
 const disp=s.length>CELL_MAX?esc(s.slice(0,CELL_MAX))+'<span class="muted">…</span>':esc(s);
 const title=esc(s.length>CELL_TITLE_MAX?s.slice(0,CELL_TITLE_MAX)+'…':s)+(dec?' — decoded from hex (auditd)':'');
 return '<td'+ca+' title="'+title+'">'+(dec?'<em>'+disp+'</em>':disp)+'</td>';
}
function rowCells(row,idx){
 const cols=renderCols();
 const needX=cols.some(isX)||cols.includes('message'); const xobj=needX?parseExtra(row,idx):null;
 const dec=decSet(xobj);
 return actCell(row[idx.id])+cols.map(function(c){
   const isDec = isX(c) ? dec.has(c.slice(2)) : (c==='message' && dec.has('cmd'));
   return tdCell(cellVal(row,idx,c,xobj), colClass(c), isDec);
 }).join('');
}
/* portapapeles robusto + copiar evento completo */
async function copyText(t){
 try{ if(navigator.clipboard && window.isSecureContext){ await navigator.clipboard.writeText(t); return true; } }catch(_){}
 try{ const ta=document.createElement('textarea'); ta.value=t; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); const ok=document.execCommand('copy'); document.body.removeChild(ta); return ok; }catch(_){ return false; }
}
function flashBtn(btn,sym){ if(!btn)return; const o=btn.dataset.o||btn.textContent; btn.dataset.o=o; btn.textContent=sym; btn.classList.add('copied'); setTimeout(()=>{btn.textContent=btn.dataset.o;btn.classList.remove('copied');},1000); }
async function copyEvent(id,btn){
 try{ const j=await (await fetch('/rawevent?id='+id)).json();
  if(!j.found){ flashBtn(btn,'✗'); return; }
  flashBtn(btn, (await copyText(j.pretty||j.raw||''))?'✓':'✗');
 }catch(e){ flashBtn(btn,'✗'); }
}
/* añadir evento a revisar (marca 'pendiente' en Marks) con ~10 eventos de
   contexto, y la regla si se marca desde una detección (via data-regla) */
async function addReview(id,btn){
 const regla=(btn&&btn.dataset&&btn.dataset.regla)?btn.dataset.regla:null;
 try{ const r=await fetch('/marks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({event_id:id,estado:'pendiente',regla:regla,ctx_n:10})});
  flashBtn(btn, r.ok?'✓':'✗');
 }catch(e){ flashBtn(btn,'✗'); }
}
/* ver el evento estructurado en una ventana modal (tablas y fuera de tablas) */
async function showRaw(id){
 const ov=document.getElementById('rawmodal'); const pre=document.getElementById('rawmodalpre');
 pre.textContent='loading…'; ov.classList.remove('hidden'); ov.dataset.id=id;
 try{ const j=await (await fetch('/rawevent?id='+id)).json(); pre.textContent=(j.pretty||j.raw||'(no raw stored)'); }catch(e){ pre.textContent='error'; }
}
function closeRaw(){ document.getElementById('rawmodal').classList.add('hidden'); }
async function copyRawModal(btn){ const t=document.getElementById('rawmodalpre').textContent||''; flashBtn(btn,(await copyText(t))?'✓ copied':'✗'); }
function _actBtns(id,regla){
 const dr=regla?(' data-regla="'+esc(regla)+'"'):'';
 return '<button class="copybtn" title="copy full event" onclick="event.stopPropagation();copyEvent('+id+',this)">&#10697;</button>'
  +'<button class="revbtn" title="add to review (mark pending, with 10-event context)" onclick="event.stopPropagation();addReview('+id+',this)"'+dr+'>&#43;</button>'
  +'<button class="rawbtn" title="view structured event" onclick="event.stopPropagation();showRaw('+id+')">&#9707;</button>';
}
function actCell(id,regla){ return '<td class="acts">'+_actBtns(id,regla)+'</td>'; }
function actInline(id,regla){ return '<span class="actinl">'+_actBtns(id,regla)+'</span>'; }
/* ---------- CSV ---------- */
function csvCell(v){ if(v===null||v===undefined)return ''; let s=String(v); return /[",\n]/.test(s)?('"'+s.replace(/"/g,'""')+'"'):s; }
function dlCSV(name,text){ const b=new Blob([text],{type:'text/csv;charset=utf-8'}); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(u),1500); }
function csvTable(cols,rows,name){ if(!rows||!rows.length)return; const text=[cols.map(csvCell).join(',')].concat(rows.map(r=>r.map(csvCell).join(','))).join('\n'); dlCSV(name||'export.csv',text); }
function csvObjs(headers,objs,name){ const text=[headers.map(csvCell).join(',')].concat(objs.map(o=>headers.map(k=>csvCell(o[k])).join(','))).join('\n'); dlCSV(name,text); }
function trStart(){ const e=document.getElementById('tstart'); return e?e.value.trim():''; }
function trEnd(){ const e=document.getElementById('tend'); return e?e.value.trim():''; }
/* ================= IOC sweep ================= */
let IOC_RES=[];
function iocList(){ return (document.getElementById('ioc_in').value||'').split(/[\n,;]+/).map(s=>s.trim()).filter(Boolean); }
function clearIoc(){ document.getElementById('ioc_in').value=''; document.getElementById('ioc_out').innerHTML=''; IOC_RES=[]; }
async function runIoc(){
 const out=document.getElementById('ioc_out'), msg=document.getElementById('ioc_msg');
 const iocs=iocList(); if(!iocs.length){ out.innerHTML='<p class="muted">Paste at least one IOC (one per line).</p>'; return; }
 msg.textContent='sweeping '+iocs.length+' IOC(s)…';
 try{ const j=await (await fetch('/ioc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({iocs})})).json();
  msg.textContent=''; IOC_RES=j.results||[];
  const withHits=IOC_RES.filter(r=>r.count>0).length;
  let h='<div class="count">'+IOC_RES.length+' IOC(s) · '+withHits+' with hits '
    +'<button class="sec xcsv" onclick="csvObjs([\'ioc\',\'count\'],IOC_RES,\'ioc_summary.csv\')">&#8615; CSV (summary)</button></div>';
  for(const r of IOC_RES){
   const cls=r.count>0?'ioc-hit':'ioc-clean';
   let iogeo='';
   if(r.private===true) iogeo=' <span class="dtag int">internal</span>';
   else if(r.asn||r.org) iogeo=' <span class="dtag ext">'+[r.asn,r.org].filter(Boolean).map(esc).join(' · ')+'</span>';
   h+='<div class="iocard '+cls+'"><div class="iohead">'+esc(r.ioc)+' — <b>'+r.count+'</b> event(s)'+iogeo+'</div>';
   if(r.hits.length){
    h+='<div class="wrap"><table><thead><tr><th class="acts"></th><th>ts</th><th>source</th><th>program</th><th>host</th><th>user</th><th>detail</th></tr></thead><tbody>';
    for(const x of r.hits){ h+='<tr class="hitrow" onclick="openCtx('+x.id+')">'+actCell(x.id)+'<td>'+esc(x.ts)+'</td><td>'+esc(x.source)+'</td><td>'+esc(x.program)+'</td><td>'+esc(x.host)+'</td><td>'+esc(x.user)+'</td><td>'+esc((x.detail||'').slice(0,220))+'</td></tr>'; }
    h+='</tbody></table></div>';
    if(r.count>r.hits.length) h+='<div class="muted" style="padding:4px 2px">… '+(r.count-r.hits.length)+' more (showing first '+r.hits.length+')</div>';
   }
   h+='</div>';
  }
  out.innerHTML=h;
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
/* filas <tr> clicables (abren el contexto del evento) */
function rowTrs(j){
 const idx=Object.fromEntries(j.columns.map((c,i)=>[c,i]));
 let h='';
 for(const row of j.rows){
  h+='<tr class="hitrow" onclick="openCtx('+row[idx.id]+')">'+rowCells(row,idx)+'</tr>';
 }
 return h;
}
/* tabla completa con cabecera y un tbody con id para paginar */
function tableHtml(j,bodyId){
 return '<div class="wrap wide"><table>'+headHtml(true)+'<tbody id="'+bodyId+'">'+rowTrs(j)+'</tbody></table></div>';
}

/* ---------- Explorador: búsqueda paginada ---------- */
let SE={q:'',regex:false,source:'',offset:0,total:0,start:'',end:'',cols:[],rows:[]};
/* ---------- Historial y búsquedas guardadas (localStorage namespaced) ---------- */
const QHIST_KEY='logan_qhistory', QSAVED_KEY='logan_qsaved';
function qGet(k){ try{return JSON.parse(localStorage.getItem(k)||'[]');}catch(_){return [];} }
function qSet(k,v){ try{localStorage.setItem(k,JSON.stringify(v));}catch(_){} }
function pushHistory(q){ q=(q||'').trim(); if(!q)return; let h=qGet(QHIST_KEY).filter(x=>x!==q); h.unshift(q); qSet(QHIST_KEY,h.slice(0,15)); }
function saveCurrent(){ const q=document.getElementById('q').value.trim(); if(!q){alert('Type a search first.');return;} const name=prompt('Name for this saved search:', q.slice(0,48)); if(name===null)return; const nm=(name.trim()||q.slice(0,48)); let s=qGet(QSAVED_KEY).filter(x=>x.name!==nm); s.unshift({name:nm,q}); qSet(QSAVED_KEY,s.slice(0,50)); renderSaved(); }
function delSaved(ev,name){ ev.stopPropagation(); qSet(QSAVED_KEY,qGet(QSAVED_KEY).filter(x=>x.name!==name)); renderSaved(); }
function clearHist(){ qSet(QHIST_KEY,[]); renderSaved(); }
function runQuery(q){ document.getElementById('q').value=q; doSearch(); }
function renderSaved(){
 const out=document.getElementById('saved_out'); if(!out)return;
 const saved=qGet(QSAVED_KEY), hist=qGet(QHIST_KEY);
 let h='';
 h+='<div class="savlbl">Saved</div>';
 h+= saved.length ? '<div class="savwrap">'+saved.map(s=>'<span class="savchip" title="'+esc(s.q)+'" onclick="runQuery('+JSON.stringify(s.q).replace(/"/g,'&quot;')+')"><b>'+esc(s.name)+'</b> <span class="savx" onclick=\'delSaved(event,'+JSON.stringify(s.name).replace(/"/g,'&quot;')+')\'>&#10005;</span></span>').join('')+'</div>' : '<div class="muted" style="font-size:12px">none yet — run a search and click «Save current search».</div>';
 h+='<div class="savlbl">Recent'+(hist.length?' <a href="#" onclick="clearHist();return false" class="savclear">clear</a>':'')+'</div>';
 h+= hist.length ? '<div class="savwrap">'+hist.map(q=>'<span class="savchip" onclick="runQuery('+JSON.stringify(q).replace(/"/g,'&quot;')+')">'+esc(q.length>60?q.slice(0,60)+'…':q)+'</span>').join('')+'</div>' : '<div class="muted" style="font-size:12px">no recent searches.</div>';
 out.innerHTML=h;
}
async function doSearch(){
 const q=document.getElementById('q').value.trim();
 const hits=document.getElementById('hits');
 if(!q){hits.innerHTML='<p class="muted">Type something to search.</p>';return}
 pushHistory(q);
 hits.innerHTML='<p class="muted">searching…</p>';
 LASTVIEW='search';
 SE={q, regex:document.getElementById('rgx').checked, source:document.getElementById('src').value, offset:0, total:0, start:trStart(), end:trEnd(), cols:[], rows:[]};
 try{
  const j=await fetchSearch(0);
  if(!j){hits.innerHTML='<div class="err">error</div>';return}
  if(!j.rows.length){hits.innerHTML='<p class="muted">No matches'+((SE.start||SE.end)?' in that time range':'')+'.</p>';return}
  SE.total=j.total; SE.offset=j.rows.length; SE.cols=j.columns; SE.rows=j.rows.slice();
  hits.innerHTML='<div class="count" id="secount"></div>'+tableHtml(j,'serows')+'<div class="row" id="semore"></div>';
  updateSeFooter();
 }catch(e){hits.innerHTML='<div class="err">'+e+'</div>'}
}
async function fetchSearch(offset){
 const r=await fetch('/search',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({q:SE.q,regex:SE.regex,source:SE.source,limit:pageSize(),offset,sort:SORT.col,desc:SORT.desc,start:SE.start||null,end:SE.end||null})});
 return r.ok ? await r.json() : null;
}
async function loadMoreSearch(){
 const btn=document.getElementById('sebtn'); if(btn){btn.disabled=true;btn.textContent='loading…';}
 const j=await fetchSearch(SE.offset);
 if(j && j.rows.length){
  document.getElementById('serows').insertAdjacentHTML('beforeend', rowTrs(j));
  SE.offset+=j.rows.length; SE.rows=SE.rows.concat(j.rows);
 }
 updateSeFooter();
}
function updateSeFooter(){
 document.getElementById('secount').innerHTML=SE.total+' matches · showing '+SE.offset
   +' <button class="sec xcsv" onclick="csvTable(SE.cols,SE.rows,\'search.csv\')">&#8615; CSV ('+SE.rows.length+')</button>';
 const rem=SE.total-SE.offset;
 document.getElementById('semore').innerHTML = rem>0
   ? '<button class="sec" id="sebtn" onclick="loadMoreSearch()">Load more ('+Math.min(pageSize(),rem)+' of '+rem+' remaining)</button>'
   : '';
}

/* ---- Timeline completa, paginada ---- */
let TL={source:'',offset:0,total:0,start:'',end:''};
async function showTimeline(){
 LASTVIEW='timeline';
 const hits=document.getElementById('hits');
 document.getElementById('gotoout').innerHTML='';
 hits.innerHTML='<p class="muted">loading timeline…</p>';
 TL={source:document.getElementById('src').value, offset:0, total:0,
     start:trStart(), end:trEnd(), cols:[], rows:[]};
 try{
  const j=await fetchTimeline(0);
  if(!j){hits.innerHTML='<div class="err">error</div>';return}
  if(!j.rows.length){hits.innerHTML='<p class="muted">'+((TL.start||TL.end)?'No events in that range.':'No events loaded.')+'</p>';return}
  TL.total=j.total; TL.offset=j.rows.length; TL.cols=j.columns; TL.rows=j.rows.slice();
  hits.innerHTML='<div class="count" id="tlcount"></div>'+tableHtml(j,'tlrows')+'<div class="row" id="tlmore"></div>';
  updateTlFooter();
 }catch(e){hits.innerHTML='<div class="err">'+e+'</div>'}
}
async function fetchTimeline(offset){
 const r=await fetch('/timeline',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({source:TL.source,limit:pageSize(),offset,start:TL.start||null,end:TL.end||null,sort:SORT.col,desc:SORT.desc})});
 return r.ok ? await r.json() : null;
}
async function loadMoreTimeline(){
 const btn=document.getElementById('tlbtn'); if(btn){btn.disabled=true;btn.textContent='loading…';}
 const j=await fetchTimeline(TL.offset);
 if(j && j.rows.length){
  document.getElementById('tlrows').insertAdjacentHTML('beforeend', rowTrs(j));
  TL.offset+=j.rows.length; TL.rows=TL.rows.concat(j.rows);
 }
 updateTlFooter();
}
function updateTlFooter(){
 const c=document.getElementById('tlcount');
 const more=document.getElementById('tlmore');
 const rng=(TL.start||TL.end)?(' · range '+(TL.start||'…')+' → '+(TL.end||'…')):'';
 c.innerHTML='Timeline'+(rng?' (filtered)':' (full)')+' · '+TL.total+' events'+rng+' · showing '+TL.offset
   +' <button class="sec xcsv" onclick="csvTable(TL.cols,TL.rows,\'timeline.csv\')">&#8615; CSV ('+TL.rows.length+')</button>';
 const rem=TL.total-TL.offset;
 more.innerHTML = rem>0
   ? '<button class="sec" id="tlbtn" onclick="loadMoreTimeline()">Load more ('+Math.min(pageSize(),rem)+' of '+rem+' remaining)</button>'
   : '<span class="muted">— end of timeline —</span>';
}
/* tabla de contexto (misma rejilla, con la fila del evento resaltada) */
function ctxHtml(j,unit,n){
 const idx=Object.fromEntries(j.columns.map((c,i)=>[c,i]));
 let h='';
 if(j.note)h+='<div class="count">'+esc(j.note)+'</div>';
 else if(unit==='minutes')h+='<div class="count">±'+n+' min · '+j.rowcount+' events in the window</div>';
 h+='<div class="wrap wide"><table>'+headHtml(false)+'<tbody>';
 for(const row of j.rows){
  const match=row[idx.is_match];
  h+='<tr class="'+(match?'match':'')+'">'+rowCells(row,idx)+'</tr>';
 }
 return h+'</tbody></table></div>';
}
async function fetchCtx(anchor,unit,n){
 const r=await fetch('/context',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({before:n,after:n,unit},anchor))});
 return [r, await r.json()];
}
/* abre el contexto de un evento (clic en una fila) en el panel superior */
async function openCtx(id){
 const n=parseFloat(document.getElementById('ctx').value||'5');
 const unit=document.getElementById('unit').value;
 const out=document.getElementById('gotoout');
 out.innerHTML='<span class="muted">loading context…</span>';
 out.scrollIntoView({behavior:'smooth',block:'nearest'});
 try{
  const [r,j]=await fetchCtx({id},unit,n);
  const bar='<div class="row" style="margin:2px 0 6px"><span class="count">Context</span>'
    +'<button class="sec" onclick="copyEvent('+id+',this)">&#10697; Copy event</button>'
    +'<button class="sec" onclick="markEvent('+id+')">&#128204; Mark event</button>'
    +'<span id="ctxmk" class="muted"></span></div>';
  out.innerHTML = r.ok ? bar+ctxHtml(j,unit,n) : '<div class="err">'+(j.detail||'error')+'</div>';
 }catch(e){out.innerHTML='<div class="err">'+e+'</div>'}
}
async function markEvent(id){
 const mk=document.getElementById('ctxmk');
 try{
  const r=await fetch('/marks',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({event_id:id,estado:'pendiente'})});
  const j=await r.json();
  if(!r.ok){ if(mk)mk.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  if(mk)mk.textContent='✓ event #'+id+' marked as pending (manage it in the Marks tab)';
 }catch(e){ if(mk)mk.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
async function gotoId(){
 const seq=parseInt(document.getElementById('goto').value,10);
 const out=document.getElementById('gotoout');
 if(!Number.isInteger(seq)){out.innerHTML='<div class="muted">Type a valid #.</div>';return}
 const n=parseFloat(document.getElementById('ctx').value||'5');
 const unit=document.getElementById('unit').value;
 out.innerHTML='<span class="muted">loading context for #'+seq+'…</span>';
 try{
  const [r,j]=await fetchCtx({seq},unit,n);
  if(!r.ok){out.innerHTML='<div class="err">'+(j.detail||'error')+'</div>';return}
  if(j.note && !j.rows.length){out.innerHTML='<div class="muted">'+esc(j.note)+'</div>';return}
  out.innerHTML='<div class="count">Context for #'+seq+'</div>'+ctxHtml(j,unit,n);
 }catch(e){out.innerHTML='<div class="err">'+e+'</div>'}
}
document.getElementById('q').addEventListener('keydown',e=>{if(e.key==='Enter')doSearch()});
document.getElementById('goto').addEventListener('keydown',e=>{if(e.key==='Enter')gotoId()});

/* ---------- SQL ---------- */
const EXAMPLES={
 "Top IPs with SSH failures":"SELECT src_ip, count(*) attempts\nFROM events\nWHERE event IN ('ssh_failed','ssh_invalid_user')\nGROUP BY src_ip ORDER BY attempts DESC LIMIT 20;",
 "Successful brute force (many failures then a login)":"WITH brute AS (\n  SELECT src_ip FROM events WHERE event='ssh_failed'\n  GROUP BY src_ip HAVING count(*) > 5)\nSELECT e.ts, e.event, e.user, e.src_ip\nFROM events e JOIN brute b USING(src_ip)\nWHERE e.event IN ('ssh_failed','ssh_accepted') ORDER BY e.ts;",
 "Global timeline from one IP (across all logs)":"SELECT ts, source, event, coalesce(exe,path,message) detail\nFROM events WHERE src_ip='203.0.113.55' ORDER BY ts;",
 "auditd: EXECVE with the SYSCALL exe (by serial)":"SELECT e.ts, e.message cmd, s.exe\nFROM events e JOIN events s ON (e.extra->>'serial')=(s.extra->>'serial') AND s.event='syscall'\nWHERE e.event='execve' ORDER BY e.ts;",
 "auditd: filter by a field in the extra JSON (parenthesize!)":"SELECT ts, exe, (extra->>'key') rule, (extra->>'syscall') syscall\nFROM events WHERE source='auditd' AND (extra->>'key') IS NOT NULL ORDER BY ts;",
 "Web error.log by level":"SELECT ts, program, severity, src_ip, method, path, message\nFROM events WHERE source='weberror' ORDER BY ts;",
 "Access log: 4xx/5xx":"SELECT ts, src_ip, method, path, status FROM events\nWHERE source='access' AND status>=400 ORDER BY ts;",
 "Time range (adjust dates)":"SELECT ts, source, program, message FROM events\nWHERE ts BETWEEN TIMESTAMP '2026-09-30 00:00:00' AND TIMESTAMP '2026-09-30 23:59:59'\nORDER BY ts;"
};
function fillEx(){const s=document.getElementById('ex');for(const k in EXAMPLES){const o=document.createElement('option');o.value=k;o.textContent=k;s.appendChild(o)}}
function loadEx(){const k=document.getElementById('ex').value;if(EXAMPLES[k])document.getElementById('sqltext').value=EXAMPLES[k]}
async function runSql(){
 const sql=document.getElementById('sqltext').value;
 const out=document.getElementById('out');const rc=document.getElementById('rc');
 out.innerHTML='';rc.textContent='running…';
 try{
  const r=await fetch('/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sql,limit:2000})});
  const j=await r.json();
  if(!r.ok){out.innerHTML='<div class="err">'+(j.detail||'error')+'</div>';rc.textContent='';return}
  rc.textContent=j.rowcount+' rows';
  if(!j.rows.length){out.innerHTML='<p class="muted">No results.</p>';return}
  let h='<div class="wrap"><table><thead><tr>';
  for(const c of j.columns)h+='<th>'+c+'</th>';h+='</tr></thead><tbody>';
  for(const row of j.rows){h+='<tr>';for(const v of row)h+='<td title="'+esc(v)+'">'+esc(v)+'</td>';h+='</tr>'}
  h+='</tbody></table></div>';out.innerHTML=h;
 }catch(e){out.innerHTML='<div class="err">'+e+'</div>';rc.textContent=''}
}
document.getElementById('sqltext').addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter')runSql()});

/* ---------- IA (API remota / local): function-calling de solo lectura ---------- */
const AI_HIST={ai:[], local:[]};   // historial por pestaña
function aiFields(ns){
 if(ns==='ai')return {base:'ai_base',model:'ai_model',key:'ai_key',user:'ai_user',hdr:'ai_hdr',q:'ai_q',out:'ai_out'};
 return {base:'local_base',model:'local_model',key:'local_key',q:'local_q',out:'local_out'};
}
function saveAiCfg(ns){
 const f=aiFields(ns);
 const cfg={base:val(f.base),model:val(f.model),key:val(f.key),user:f.user?val(f.user):'',hdr:f.hdr?val(f.hdr):''};
 try{localStorage.setItem('la_ai_'+ns,JSON.stringify(cfg));}catch(_){}
 const o=document.getElementById(f.out);
 o.insertAdjacentHTML('afterbegin','<div class="aitrace">config saved ✓</div>');
}
function loadAiCfg(ns){
 const f=aiFields(ns); let cfg={};
 try{cfg=JSON.parse(localStorage.getItem('la_ai_'+ns)||'{}');}catch(_){}
 if(cfg.base)set(f.base,cfg.base); if(cfg.model)set(f.model,cfg.model);
 if(cfg.key)set(f.key,cfg.key);
 if(f.user&&cfg.user)set(f.user,cfg.user); if(f.hdr&&cfg.hdr)set(f.hdr,cfg.hdr);
}
function val(id){const e=document.getElementById(id);return e?e.value.trim():'';}
function set(id,v){const e=document.getElementById(id);if(e)e.value=v;}
function traceHtml(tr){
 if(!tr||!tr.length)return '';
 return '<div class="aitrace">'+tr.map(t=>'· '+t.tool+'('+esc(JSON.stringify(t.args))+')'+(t.error?' ⚠ '+esc(t.error):' → '+(t.rowcount==null?'ok':t.rowcount+' rows'))).join('<br>')+'</div>';
}
async function askAi(ns){
 const f=aiFields(ns);
 const out=document.getElementById(f.out);
 const q=val(f.q);
 if(!q){return}
 const base=val(f.base), model=val(f.model);
 if(!base||!model){out.insertAdjacentHTML('afterbegin','<div class="aimsg bot"><div class="err">Fill in base_url and model (and save the config).</div></div>');return}
 let extra=null;
 if(f.hdr && val(f.hdr)){ try{extra=JSON.parse(val(f.hdr));}catch(_){out.insertAdjacentHTML('afterbegin','<div class="aimsg bot"><div class="err">extra headers are not valid JSON</div></div>');return} }
 set(f.q,'');
 out.insertAdjacentHTML('afterbegin','<div class="aimsg bot" id="ai_pending">thinking…</div>');
 out.insertAdjacentHTML('afterbegin','<div class="aimsg me"><b>You:</b> '+esc(q)+'</div>');
 const body={message:q,base_url:base,model:model,api_key:val(f.key),history:AI_HIST[ns].slice(-8)};
 if(f.user&&val(f.user))body.user=val(f.user);
 if(extra)body.extra_headers=extra;
 try{
  const r=await fetch('/ai/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  const pend=document.getElementById('ai_pending'); if(pend)pend.remove();
  if(!r.ok){out.insertAdjacentHTML('afterbegin','<div class="aimsg bot"><div class="err">'+esc(j.detail||'error')+'</div></div>');return}
  AI_HIST[ns].push({role:'user',content:q});
  AI_HIST[ns].push({role:'assistant',content:j.reply||''});
  out.insertAdjacentHTML('afterbegin','<div class="aimsg bot"><b>AI:</b> '+esc(j.reply||'(no reply)')+traceHtml(j.tool_trace)+'</div>');
 }catch(e){const pend=document.getElementById('ai_pending'); if(pend)pend.remove(); out.insertAdjacentHTML('afterbegin','<div class="aimsg bot"><div class="err">'+esc(e)+'</div></div>');}
}
document.getElementById('ai_q').addEventListener('keydown',e=>{if(e.key==='Enter')askAi('ai')});
document.getElementById('local_q').addEventListener('keydown',e=>{if(e.key==='Enter')askAi('local')});

/* ---------- MCP: instrucciones y config ---------- */
let MCP_LOADED=false;
async function loadMcpHelp(){
 if(MCP_LOADED)return; MCP_LOADED=true;
 const el=document.getElementById('mcp_help');
 try{
  const r=await fetch('/mcp/info'); const j=await r.json();
  el.innerHTML=j.html;
 }catch(e){el.innerHTML='<div class="err">could not load MCP info: '+esc(e)+'</div>';MCP_LOADED=false;}
}

/* ---------- Sigma ---------- */
let SIGMA_INIT=false;
async function sigmaInit(){
 if(SIGMA_INIT)return; SIGMA_INIT=true;
 try{
  const j=await (await fetch('/sigma/status')).json();
  const msg=document.getElementById('sg_msg');
  if(!j.available){ msg.innerHTML='<span class="err">pySigma is not installed on the server ('+esc(j.error||'')+'). Install <code>pysigma</code> and reload.</span>'; return; }
  if(!document.getElementById('sg_path').value) document.getElementById('sg_path').value=j.rules_dir;
  msg.textContent='Rules in: '+j.rules_dir+' · load a folder or upload .yml to start.';
 }catch(e){ SIGMA_INIT=false; }
}
function sigmaSummary(info){
 const p=info.preview||{};
 let h='<div class="count">'+info.loaded+' rules loaded · <b>'+(p.aplicables||0)+' applicable</b>'
  +(p.correlacion?' ('+p.correlacion+' correlation)':'')
  +' · '+(p.sin_datos||0)+' no logsource data · '+(p.no_linux||0)+' non-Linux (skipped)'
  +((info.errors&&info.errors.length)?' · '+info.errors.length+' with parse error':'')+'</div>';
 const by=p.por_logsource||{};
 const keys=Object.keys(by);
 if(keys.length) h+='<div class="muted">by logsource: '+keys.map(k=>k+' ('+by[k]+')').join(' · ')+'</div>';
 if(info.errors&&info.errors.length){
  h+='<details class="sgerr"><summary>'+info.errors.length+' file(s) with error</summary><div class="wrap"><table><thead><tr><th>file</th><th>error</th></tr></thead><tbody>';
  for(const e of info.errors) h+='<tr><td>'+esc(e.file)+'</td><td>'+esc(e.error)+'</td></tr>';
  h+='</tbody></table></div></details>';
 }
 document.getElementById('sg_out').innerHTML=h;
 const on=!(p.aplicables>0);
 document.getElementById('sg_runbtn').disabled=on;
 document.getElementById('sg_listbtn').disabled=on;
}
async function sigmaListRules(){
 const out=document.getElementById('sg_out'); const msg=document.getElementById('sg_msg');
 msg.textContent='listing rules…';
 try{
  const r=await fetch('/sigma/rules'); const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  msg.textContent='';
  const rules=j.rules||[];
  const apt=rules.filter(x=>x.applicable); const no=rules.filter(x=>!x.applicable);
  let h='<div class="count">'+apt.length+' applicable rules (click to see its SQL) · '+no.length+' not applicable</div>';
  if(apt.length) h+=sgToggleBar();
  for(const x of apt){
   const sv=SEVCLASS[x.level]||'sev-info';
   h+='<div class="sgfind"><div class="sghead '+sv+'" onclick="this.parentNode.querySelector(\'.sghits\').classList.toggle(\'hidden\')">'
     +'<span class="sgsev">'+esc((x.level||'?').toUpperCase())+'</span> '+esc(x.title)
     +' <span class="muted">· '+esc(x.logsource||'')+' · '+esc(x.type)+'</span></div>'
     +'<div class="sghits hidden"><div class="sgcols">'
     +'<div class="sgcol"><div class="sgcolh">YAML (logsource → condition)</div><pre class="sgsql">'+esc(x.yaml||'(not available)')+'</pre></div>'
     +'<div class="sgcol"><div class="sgcolh">Equivalent SQL</div><pre class="sgsql">'+esc(x.sql||'')+'</pre></div>'
     +'</div></div></div>';
  }
  if(no.length){
   h+='<details class="sgerr"><summary>'+no.length+' not applicable (reason)</summary><div class="wrap"><table><thead><tr><th>title</th><th>logsource</th><th>reason</th></tr></thead><tbody>';
   for(const x of no) h+='<tr><td title="'+esc(x.title)+'">'+esc(x.title)+'</td><td>'+esc(x.logsource||'')+'</td><td>'+esc(x.reason||'')+'</td></tr>';
   h+='</tbody></table></div></details>';
  }
  out.innerHTML=h;
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
/* Carga de reglas en streaming con barra de progreso.
   Lee NDJSON: {total} -> {i,total,file,loaded,errors} por fichero -> {done,...} */
async function streamRuleLoad(url, path, msgId, progId, onDone){
 const msg=document.getElementById(msgId); const prog=progId?document.getElementById(progId):null;
 msg.textContent='loading rules…'; if(prog){prog.style.display='';prog.value=0;}
 try{
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path||null})});
  if(!r.ok){ let d=''; try{d=(await r.json()).detail;}catch(_){ } if(prog)prog.style.display='none'; msg.innerHTML='<span class="err">'+esc(d||('error '+r.status))+'</span>'; return; }
  const reader=r.body.getReader(); const dec=new TextDecoder(); let buf=''; let total=0, done=null;
  for(;;){ const {value,done:fin}=await reader.read(); if(fin)break; buf+=dec.decode(value,{stream:true}); let nl;
   while((nl=buf.indexOf('\n'))>=0){ const line=buf.slice(0,nl).trim(); buf=buf.slice(nl+1); if(!line)continue; let x; try{x=JSON.parse(line);}catch(_){continue;}
    if(x.fatal){ if(prog)prog.style.display='none'; msg.innerHTML='<span class="err">'+esc(x.fatal)+'</span>'; return; }
    if(x.done){ done=x; if(prog){prog.value=100;prog.style.display='none';} continue; }
    if(x.i!=null){ if(prog&&total>0)prog.value=Math.round(x.i/total*100); msg.textContent='parsing '+x.i+'/'+total+' files · '+(x.loaded||0)+' rules'+(x.errors?' · '+x.errors+' errors':''); continue; }
    if(x.total!=null){ total=x.total; msg.textContent='parsing '+total+' rule files…'; }
   }
  }
  msg.textContent=''; if(done && onDone) onDone(done);
 }catch(e){ if(prog)prog.style.display='none'; msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
async function sigmaLoad(){
 const path=document.getElementById('sg_path').value.trim();
 await streamRuleLoad('/sigma/load/stream', path, 'sg_msg', 'sg_prog', sigmaSummary);
}
async function sigmaUpload(){
 const msg=document.getElementById('sg_msg'); const picks=document.getElementById('sg_files').files;
 if(!picks.length){ msg.textContent='Pick .yml files first.'; return; }
 msg.textContent='uploading rules…';
 const fd=new FormData(); for(const f of picks) fd.append('files',f);
 try{
  const r=await fetch('/sigma/upload',{method:'POST',body:fd}); const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  msg.textContent=(j.saved||0)+' rule(s) saved.'; sigmaSummary(j);
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
const SEVCLASS={critical:'sev-crit',high:'sev-high',medium:'sev-med',low:'sev-low',informational:'sev-info'};
async function sigmaRun(){
 const msg=document.getElementById('sg_msg'); const out=document.getElementById('sg_out');
 const prog=document.getElementById('sg_prog'); const btn=document.getElementById('sg_runbtn');
 msg.textContent='running rules…'; prog.style.display=''; prog.value=0; btn.disabled=true;
 let j=null;
 try{
  const r=await fetch('/sigma/run/stream',{method:'POST'});
  if(!r.ok){ let d=''; try{d=(await r.json()).detail;}catch(_){}
    prog.style.display='none'; btn.disabled=false;
    msg.innerHTML='<span class="err">'+esc(d||('error '+r.status))+'</span>'; return; }
  const reader=r.body.getReader(); const dec=new TextDecoder(); let buf='';
  for(;;){
   const {value,done:fin}=await reader.read();
   if(fin)break;
   buf+=dec.decode(value,{stream:true});
   let nl;
   while((nl=buf.indexOf('\n'))>=0){
    const line=buf.slice(0,nl).trim(); buf=buf.slice(nl+1);
    if(!line)continue;
    let x; try{x=JSON.parse(line);}catch(_){continue;}
    if(x.fatal){ prog.style.display='none'; btn.disabled=false;
      msg.innerHTML='<span class="err">'+esc(x.fatal)+'</span>'; return; }
    if(x.done){ j=x; continue; }
    if(x.total>0) prog.value=Math.round(x.i/x.total*100);
    msg.textContent='running rule '+x.i+'/'+x.total+' · '+x.found+' with findings…';
   }
  }
  prog.value=100; prog.style.display='none'; btn.disabled=false;
  if(!j){ msg.innerHTML='<span class="err">incomplete response</span>'; return; }
  msg.textContent='';
  let h='<div class="count">'+j.findings.length+' rules with findings · '+j.total_hits+' events · '
   +j.applied+' rules run of '+j.rules_total+'</div>';
  if(!j.findings.length){ h+='<p class="muted">No findings. (Rules ran but no match.)</p>'; }
  else h+=sgToggleBar();
  for(const f of j.findings){
   const sv=SEVCLASS[f.level]||'sev-info'; const rl=ruleLabel(f);
   h+='<div class="sgfind"><div class="sghead '+sv+'" onclick="this.parentNode.querySelector(\'.sghits\').classList.toggle(\'hidden\')">'
     +'<span class="sgsev">'+esc((f.level||'?').toUpperCase())+'</span> '+esc(f.title)
     +' <span class="muted">· '+esc(f.logsource)+' · ×'+f.count+(f.tags&&f.tags.length?' · '+f.tags.map(esc).join(' '):'')+'</span></div>';
   h+='<div class="sghits hidden">'+ruleYamlBlock(f)+'<div class="wrap"><table>';
   if(f.correlation){
    const nc=f.columns.length;
    h+='<thead><tr><th class="acts"></th>'+f.columns.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>';
    for(const row of f.hits){
     const sid=row[row.length-1];
     h+='<tr class="hitrow" onclick="sigmaGoto('+sid+')">'+actCell(sid,rl)+row.slice(0,nc).map(v=>'<td>'+esc(v)+'</td>').join('')+'</tr>';
    }
   }else{
    h+='<thead><tr><th class="acts"></th><th>#</th><th>ts</th><th>source</th><th>program</th><th>detail</th><th>what matched</th></tr></thead><tbody>';
    for(const row of f.hits){
     h+='<tr class="hitrow" onclick="sigmaGoto('+row[1]+')">'+actCell(row[1],rl)+'<td>'+esc(row[0])+'</td><td>'+esc(row[2])+'</td><td>'+esc(row[3])+'</td><td>'+esc(row[4])+'</td><td title="'+esc(row[5])+'">'+hlKw(row[5],f.keywords)+'</td><td class="sgmatch" title="'+esc(row[7]||'')+'">'+esc(row[7]||'')+'</td></tr>';
    }
    if(f.count>f.hits.length) h+='<tr><td colspan="7" class="muted">… '+(f.count-f.hits.length)+' more findings (sample limited to '+f.hits.length+')</td></tr>';
   }
   h+='</tbody></table></div></div></div>';
  }
  out.innerHTML=h;
 }catch(e){ prog.style.display='none'; btn.disabled=false; msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
function hlKw(text, kws){
 let h=esc(text);
 for(const k of (kws||[])){ if(!k)continue; try{ const rx=new RegExp('('+k.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','ig'); h=h.replace(rx,'<mark>$1</mark>'); }catch(_){}}
 return h;
}
function ruleYamlBlock(f){ return f.yaml ? '<details class="ruleyaml"><summary>&#9776; rule content (YAML)</summary><pre class="rawpre">'+esc(f.yaml)+'</pre></details>' : ''; }
function ruleLabel(f){ return (f.title||'rule')+(f.id?(' ['+f.id+']'):'')+(f.tags&&f.tags.length?(' · '+f.tags.join(' ')):''); }
function sgExpandAll(){ document.querySelectorAll('#sg_out .sghits').forEach(e=>e.classList.remove('hidden')); }
function sgCollapseAll(){ document.querySelectorAll('#sg_out .sghits').forEach(e=>e.classList.add('hidden')); }
function sgToggleBar(){ return '<div class="row" style="margin:4px 0 8px"><button class="sec" onclick="sgExpandAll()">Expand all</button> <button class="sec" onclick="sgCollapseAll()">Collapse all</button></div>'; }
function sigmaGoto(id){ switchTab('explorer'); openCtx(id); }

/* ================= GTFOBins ================= */
let GTFO_CATALOG=null;
async function gtfoStatus(){
 const msg=document.getElementById('gtfo_msg'); if(!msg)return;
 try{
  const r=await fetch('/gtfobins/status'); const j=await r.json();
  if(j.loaded) msg.textContent='Catalog: '+j.count+' binaries · '+(j.updated||'');
  else msg.innerHTML='Catalog not loaded — click «Update catalog (GitHub)».';
 }catch(e){}
}
async function gtfoRefresh(){
 const msg=document.getElementById('gtfo_msg'); const btn=document.getElementById('gtfo_refreshbtn');
 msg.textContent='updating from GitHub (may take a few seconds)…'; btn.disabled=true;
 try{
  const r=await fetch('/gtfobins/refresh',{method:'POST'}); const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; }
  else { msg.textContent='✓ catalog updated: '+j.count+' binaries · '+(j.updated||''); GTFO_CATALOG=null; }
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
 btn.disabled=false;
}
function gbFunctions(functions){
 let h='';
 for(const fn of Object.keys(functions)){
  h+='<div class="gbsec"><div class="gbsech">'+esc(fn)+'</div>';
  for(const e of functions[fn]){
   if(e.comment) h+='<div class="gbcomment">'+esc(e.comment)+'</div>';
   h+='<div class="gbcode">'+esc(e.code)+'</div>';
   if(e.contexts && e.contexts.length) h+='<div style="margin:2px 0 4px">'+e.contexts.map(c=>'<span class="gbctx">'+esc(c)+'</span>').join('')+'</div>';
  }
  h+='</div>';
 }
 return h;
}
function gbPrivBadge(p){
 if(!p) return '';
 let b=[];
 if(p.via_sudo) b.push('<span class="gbpriv danger" title="run via sudo">via sudo</span>');
 if(p.via_nssh) b.push('<span class="gbpriv danger" title="executed from the BSD appliance shell (sh_command / shell_command) — privileged context">appliance shell</span>');
 if(p.escalation) b.push('<span class="gbpriv danger" title="euid=0 with a non-root login user (auid '+esc((p.login_users||[]).join(','))+')">&#9888; escalation</span>');
 else if(p.as_root) b.push('<span class="gbpriv danger" title="run with euid/uid=0">as root</span>');
 if(!b.length) b.push('<span class="gbpriv" title="no elevated privileges">normal user</span>');
 return b.join(' ');
}
function gtfoBar(){ return '<div class="row" style="margin:4px 0 8px"><button class="sec" onclick="gtfoExpandAll()">Expand all</button> <button class="sec" onclick="gtfoCollapseAll()">Collapse all</button></div>'; }
function gtfoExpandAll(){ document.querySelectorAll('#gtfo_out .gbbody').forEach(e=>e.classList.remove('hidden')); }
function gtfoCollapseAll(){ document.querySelectorAll('#gtfo_out .gbbody').forEach(e=>e.classList.add('hidden')); }
async function gtfoAllHits(ev, binname){
 ev.stopPropagation();
 const btn=ev.target; const tb=btn.closest('.gbbody').querySelector('.gbsampb');
 if(!tb) return;
 btn.disabled=true; btn.textContent='loading…';
 try{
  const r=await fetch('/gtfobins/samples?bin='+encodeURIComponent(binname));
  const j=await r.json();
  if(!r.ok){ btn.textContent='error'; return; }
  let h='';
  for(const s of j.samples){
   h+='<tr class="hitrow" onclick="sigmaGoto('+s.id+')">'+actCell(s.id)+'<td>'+esc(s.id)+'</td><td>'+esc(s.ts)+'</td><td>'+esc(s.source)+'</td><td>'+esc(s.user)+'</td><td>'+esc(s.detalle)+'</td></tr>';
  }
  tb.innerHTML=h;
  const hdr=btn.closest('.gbsamph'); const tr=hdr.querySelector('.gbtrunc');
  if(tr) tr.textContent='— showing all '+j.samples.length;
  btn.remove();
 }catch(e){ btn.textContent='error'; btn.disabled=false; }
}
async function gtfoCheck(){
 const msg=document.getElementById('gtfo_msg'); const out=document.getElementById('gtfo_out');
 const btn=document.getElementById('gtfo_checkbtn');
 msg.textContent='checking executed binaries…'; btn.disabled=true;
 try{
  const r=await fetch('/gtfobins/check',{method:'POST'}); const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; btn.disabled=false; return; }
  msg.textContent='';
  if(!j.matched.length){ out.innerHTML='<p class="muted">No binary from the GTFOBins catalog ('+j.catalog+') appears executed among the '+j.checked+' distinct binaries seen in the logs.</p>'; btn.disabled=false; return; }
  let h='<div class="count">'+j.matched.length+' GTFOBins binaries executed · of '+j.checked+' distinct binaries seen · catalog: '+j.catalog+'</div>';
  h+='<div class="muted" style="margin:2px 0 6px">In red, privileged executions (via <code>sudo</code> or as root) — the truly dangerous ones. The real SUID bit is not observable from logs alone.</div>'+gtfoBar();
  for(const b of j.matched){
   const fnames=Object.keys(b.functions);
   h+='<div class="gbin'+(b.danger?' danger':'')+'"><div class="gbhead" onclick="this.parentNode.querySelector(\'.gbbody\').classList.toggle(\'hidden\')">'
     +'<span class="gbname">'+esc(b.bin)+'</span><span class="gbcount">×'+b.count+' executions</span> '+gbPrivBadge(b.privilege)
     +'<span class="gbfns">'+fnames.map(f=>'<span class="gbfn">'+esc(f)+'</span>').join('')+'</span></div>';
   h+='<div class="gbbody hidden">'+gbFunctions(b.functions);
   if(b.samples && b.samples.length){
    const _bq=b.bin.replace(/'/g,"\\'");
    h+='<div class="gbsamph">Where it ran (click to see its context)'
      +(b.count>b.samples.length?' <span class="gbtrunc">— showing '+b.samples.length+' of '+b.count+'</span> <button class="xs" onclick="gtfoAllHits(event,\''+esc(_bq)+'\')">See all '+b.count+'</button>':'')
      +'</div><div class="wrap"><table>'
      +'<thead><tr><th class="acts"></th><th>#</th><th>ts</th><th>source</th><th>user</th><th>detail</th></tr></thead><tbody class="gbsampb">';
    for(const s of b.samples){
     h+='<tr class="hitrow" onclick="sigmaGoto('+s.id+')">'+actCell(s.id)+'<td>'+esc(s.id)+'</td><td>'+esc(s.ts)+'</td><td>'+esc(s.source)+'</td><td>'+esc(s.user)+'</td><td>'+esc(s.detalle)+'</td></tr>';
    }
    h+='</tbody></table></div>';
   }
   h+='</div></div>';
  }
  out.innerHTML=h;
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
 btn.disabled=false;
}
async function gtfoToggleList(){
 const box=document.getElementById('gtfo_list');
 if(!box.classList.contains('hidden')){ box.classList.add('hidden'); return; }
 box.classList.remove('hidden');
 if(!GTFO_CATALOG){
  box.innerHTML='<p class="muted">loading catalog…</p>';
  try{ const r=await fetch('/gtfobins/list'); const j=await r.json();
   if(!r.ok){ box.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
   GTFO_CATALOG=j;
  }catch(e){ box.innerHTML='<span class="err">'+esc(e)+'</span>'; return; }
 }
 gtfoRenderList();
}
function gtfoRenderList(){
 const box=document.getElementById('gtfo_list'); const d=GTFO_CATALOG;
 const names=Object.keys(d.binaries).sort();
 let h='<div class="row" style="margin-top:10px"><input type="text" id="gtfo_filter" placeholder="filter binary…" oninput="gtfoFilterList()" style="min-width:220px"> <span class="muted">'+d.count+' binaries · '+esc(d.updated||'')+' · click one to see how it is abused</span></div>';
 h+='<div id="gtfo_detail"></div>';
 h+='<div class="gblist" id="gtfo_chips">'+names.map(n=>'<span class="gbchip" data-n="'+esc(n)+'" onclick="gtfoShowBin(this.dataset.n)">'+esc(n)+'<span class="n">'+Object.keys(d.binaries[n].functions).length+'</span></span>').join('')+'</div>';
 box.innerHTML=h;
}
function gtfoFilterList(){
 const q=(document.getElementById('gtfo_filter').value||'').toLowerCase();
 document.querySelectorAll('#gtfo_chips .gbchip').forEach(c=>{ c.style.display=c.dataset.n.toLowerCase().includes(q)?'':'none'; });
}
function gtfoShowBin(n){
 const d=GTFO_CATALOG; if(!d)return; const b=d.binaries[n]; if(!b)return;
 const det=document.getElementById('gtfo_detail');
 det.innerHTML='<div class="gbin"><div class="gbhead"><span class="gbname">'+esc(n)+'</span>'
   +'<span class="gbfns">'+Object.keys(b.functions).map(f=>'<span class="gbfn">'+esc(f)+'</span>').join('')+'</span></div>'
   +'<div class="gbbody">'+gbFunctions(b.functions)+'</div></div>';
 det.scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ================= Resumen / Dashboard ================= */
let DASH_LOADED=false;
function goExplore(q){ switchTab('explorer'); const el=document.getElementById('q'); if(el){ el.value=q; } doSearch(); }
function dBars(list, kind, clickable){
 if(clickable===undefined) clickable=true;
 if(!list||!list.length) return '<p class="muted">—</p>';
 const max=Math.max.apply(null, list.map(x=>x.n))||1;
 return list.map(x=>{
  const pct=Math.max(2,Math.round(x.n/max*100));
  const q=(x.k||'').replace(/'/g,"\\'");
  let tags='', title=clickable?'open in Explorer':'';
  if(kind==='ip'){
   if(x.private===true) tags=' <span class="dtag int">internal</span>';
   else if(x.private===false){
    const orgShort=x.org?(x.org.length>26?x.org.slice(0,26)+'…':x.org):null;
    const geo=[x.country_code, x.asn?('AS'+x.asn):null, orgShort].filter(Boolean).join(' · ');
    tags=' <span class="dtag ext">external'+(geo?' '+esc(geo):'')+'</span>';
    if(x.org) title='ISP: '+x.org+(clickable?' · open in Explorer':'');
   }
  }
  const fn=(kind==='ip')?'showIpDetail':'goExplore';
  const click=clickable?(' onclick="'+fn+'(\''+esc(q)+'\')"'):'';
  const cur=clickable?'':' style="cursor:default"';
  return '<div class="dbar"'+click+cur+' title="'+esc(title)+'">'
   +'<span class="dbk">'+esc(x.k||'—')+tags+'</span>'
   +'<span class="dbtrack"><span class="dbfill" style="width:'+pct+'%"></span></span>'
   +'<span class="dbn">'+x.n+'</span></div>';
 }).join('');
}
function dHist(hist){
 if(!hist||!hist.length) return '';
 const max=Math.max.apply(null, hist.map(x=>x.n))||1;
 const cols=hist.map(x=>'<div class="dhcol" style="height:'+Math.max(3,Math.round(x.n/max*100))+'%" title="'+esc(x.h)+': '+x.n+'"></div>').join('');
 const a=hist[0].h, b=hist[hist.length-1].h;
 return '<div class="dcard"><h3>Events per hour</h3><div class="dhist">'+cols+'</div><div class="dhlbl"><span>'+esc(a)+'</span><span>'+esc(b)+'</span></div></div>';
}
async function loadDash(){
 const out=document.getElementById('dash_out');
 out.innerHTML='<p class="muted">loading…</p>';
 try{
  const r=await fetch('/dashboard'); const j=await r.json();
  if(!r.ok){ out.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  const d=j.distinct||{};
  const rango=(j.ts_min&&j.ts_max)?(j.ts_min+' → '+j.ts_max):'no timestamps';
  let h='<div id="ip_detail"></div><div class="dgrid">'
   +'<div class="dtile"><div class="v">'+j.total+'</div><div class="l">events</div></div>'
   +'<div class="dtile"><div class="v">'+(d.source||0)+'</div><div class="l">sources</div></div>'
   +'<div class="dtile"><div class="v">'+(d.ip||0)+'</div><div class="l">distinct IPs</div></div>'
   +'<div class="dtile"><div class="v">'+(d.user||0)+'</div><div class="l">users</div></div>'
   +'<div class="dtile" style="flex:2;min-width:260px"><div class="l">time range (UTC)</div><div class="sub">'+esc(rango)+'</div></div>'
   +'</div>';
  h+=dHist(j.hist);
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Top source IPs</h3>'+dBars(j.top_ip,'ip')+'</div>'
   +'<div class="dcard"><h3>Top users</h3>'+dBars(j.top_user)+'</div></div>';
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Top ISP / operator</h3>'+dBars(j.top_isp,null,false)+'</div>'
   +'<div class="dcard"><h3>Top countries</h3>'+dBars(j.top_country,null,false)+'</div></div>';
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Top binaries (exe)</h3>'+dBars(j.top_bin)+'</div>'
   +'<div class="dcard"><h3>Top programs</h3>'+dBars(j.top_program)+'</div></div>';
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Events by source</h3>'+dBars(j.by_source)+'</div>'
   +'<div class="dcard"><h3>Severity</h3>'+dBars(j.severity)+'</div></div>';
  out.innerHTML=h;
  // estado geoip en el mensaje
  const g=j.geoip||{};
  const gm=document.getElementById('geo_msg');
  if(gm){ gm.textContent = (g.country||g.asn)
    ? ('GeoIP: country '+(g.country||'—')+', ASN '+(g.asn||'—')+' (DB-IP Lite)')
    : 'GeoIP without a base: internal/external only. Click «Update GeoIP database» for country/ASN.'; }
 }catch(e){ out.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
async function showIpDetail(ip){
 const box=document.getElementById('ip_detail'); if(!box)return;
 box.innerHTML='<div class="dcard"><p class="muted">loading '+esc(ip)+'…</p></div>';
 box.scrollIntoView({behavior:'smooth',block:'nearest'});
 try{
  const r=await fetch('/ipinfo?ip='+encodeURIComponent(ip)); const j=await r.json();
  if(!r.ok){ box.innerHTML='<div class="dcard"><span class="err">'+esc(j.detail||'error')+'</span></div>'; return; }
  const g=j.geo||{};
  const loc = g.private ? '<span class="dtag int">internal</span>'
    : ('<span class="dtag ext">external</span> '+[g.country, g.asn?('AS'+g.asn):null, g.org].filter(Boolean).map(esc).join(' · '));
  const q=ip.replace(/'/g,"\\'");
  let h='<div class="dcard ipcard"><div class="iphead"><span class="ipname">'+esc(ip)+'</span> '+loc
    +'<button class="sec" style="margin-left:auto" onclick="goExplore(\''+esc(q)+'\')">Open in Explorer</button>'
    +'<button class="xs" onclick="document.getElementById(\'ip_detail\').innerHTML=\'\'">close</button></div>';
  h+='<div class="ipstats"><span><b>'+j.total+'</b> events</span><span><b>'+j.fails+'</b> auth failures</span>'
    +'<span>first seen: '+esc(j.ts_min||'—')+'</span><span>last seen: '+esc(j.ts_max||'—')+'</span></div>';
  h+='<div class="iprow"><div><div class="sgcolh">By source</div>'
    +(j.by_source.map(s=>'<span class="dtag">'+esc(s.k)+' ×'+s.n+'</span>').join(' ')||'—')+'</div>'
    +'<div><div class="sgcolh">Users seen</div>'
    +(j.users.map(s=>'<span class="dtag">'+esc(s.k||'—')+' ×'+s.n+'</span>').join(' ')||'—')+'</div></div>';
  if(j.samples && j.samples.length){
   h+='<div class="sgcolh" style="margin-top:10px">Sample events (click → context)</div><div class="wrap"><table>'
     +'<thead><tr><th>#</th><th>ts</th><th>source</th><th>user</th><th>detail</th></tr></thead><tbody>';
   for(const s of j.samples){ h+='<tr class="hitrow" onclick="sigmaGoto('+s.id+')"><td>'+esc(s.id)+'</td><td>'+esc(s.ts)+'</td><td>'+esc(s.source)+'</td><td>'+esc(s.user)+'</td><td>'+esc(s.detalle)+'</td></tr>'; }
   h+='</tbody></table></div>';
  }
  h+='</div>';
  box.innerHTML=h;
  box.scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){ box.innerHTML='<div class="dcard"><span class="err">'+esc(e)+'</span></div>'; }
}
async function geoStatus(){
 try{ const r=await fetch('/geoip/status'); const g=await r.json();
  const gm=document.getElementById('geo_msg'); if(!gm)return;
  if(g.country||g.asn) gm.textContent='GeoIP: DB-IP Lite base loaded (country '+(g.country||'—')+', ASN '+(g.asn||'—')+').';
  else if(!g.maxminddb) gm.textContent='GeoIP: maxminddb library missing; internal/external only.';
  else gm.textContent='GeoIP without a base: internal/external only. Click «Update GeoIP database» for country/ASN.';
 }catch(e){}
}
async function geoRefresh(){
 const gm=document.getElementById('geo_msg'); const btn=document.getElementById('geo_btn');
 gm.textContent='downloading DB-IP Lite bases (may take a while)…'; btn.disabled=true;
 try{ const r=await fetch('/geoip/refresh',{method:'POST'}); const g=await r.json();
  if(!r.ok){ gm.innerHTML='<span class="err">'+esc(g.detail||'error')+'</span>'; }
  else { gm.textContent='✓ GeoIP updated (country '+(g.country||'?')+', ASN '+(g.asn||'?')+').'; DASH_LOADED=false; loadDash(); }
 }catch(e){ gm.innerHTML='<span class="err">'+esc(e)+'</span>'; }
 btn.disabled=false;
}

/* ================= Marcas / triage ================= */
let MARK_FILTER='';
const MK_ESTADOS=['pendiente','TP','FP','descartado'];
const MK_LABEL={pendiente:'pending',TP:'TP',FP:'FP',descartado:'dismissed'};
function mkLbl(e){ return MK_LABEL[e]||e; }
async function markAddFromForm(){
 const id=parseInt(document.getElementById('mk_id').value,10);
 const msg=document.getElementById('mk_msg');
 if(!Number.isInteger(id)){ msg.innerHTML='<span class="err">Type a valid event #.</span>'; return; }
 const estado=document.getElementById('mk_estado').value;
 const nota=document.getElementById('mk_nota').value.trim()||null;
 try{
  const r=await fetch('/marks',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({event_id:id,estado,nota})});
  const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  document.getElementById('mk_id').value=''; document.getElementById('mk_nota').value='';
  msg.textContent=''; loadMarks();
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
async function markSetEstado(mid, estado){
 await fetch('/marks/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mid,estado})});
 loadMarks();
}
async function markEditNota(mid){
 const nota=prompt('Note for this mark:');
 if(nota===null) return;
 await fetch('/marks/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mid,nota})});
 loadMarks();
}
async function markDelete(mid){
 if(!confirm('Delete this mark?')) return;
 await fetch('/marks/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mid})});
 loadMarks();
}
function markFilter(e){ MARK_FILTER=e; loadMarks(); }
async function loadMarks(){
 const out=document.getElementById('mk_out'); const fbar=document.getElementById('mk_filters');
 try{
  const url='/marks'+(MARK_FILTER?('?estado='+encodeURIComponent(MARK_FILTER)):'');
  const r=await fetch(url); const j=await r.json();
  if(!r.ok){ out.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  const c=j.counts||{}; const tot=Object.values(c).reduce((a,b)=>a+b,0);
  let fb='<span class="mkfilt'+(MARK_FILTER===''?' active':'')+'" onclick="markFilter(\'\')">all ('+tot+')</span>';
  for(const e of MK_ESTADOS){ fb+=' <span class="mkfilt'+(MARK_FILTER===e?' active':'')+'" onclick="markFilter(\''+e+'\')">'+mkLbl(e)+' ('+(c[e]||0)+')</span>'; }
  fbar.innerHTML=fb;
  const msg=document.getElementById('mk_msg');
  if(msg) msg.textContent = j.persistent ? '' : '⚠ in-memory case: marks will not persist on close (load/save a .duckdb case).';
  if(!j.marks.length){ out.innerHTML='<p class="muted">No marks'+(MARK_FILTER?' with status '+esc(MK_LABEL[MARK_FILTER]||MARK_FILTER):'')+'.</p>'; return; }
  let h='';
  for(const m of j.marks){
   const det = (m.detalle && m.detalle.trim()) ? m.detalle
               : (m.event_id==null ? '(no event)'
                  : (m.ts ? ('('+(m.source||'event')+' '+(m.ts)+')')
                          : ('event #'+m.event_id+' — not in current data')));
   const meta=[m.seq!=null?('#'+m.seq):null, m.ts, m.source, m.user].filter(Boolean).map(esc).join(' · ');
   h+='<div class="mkitem"><span class="mkbadge mk-'+esc(m.estado)+'">'+esc(mkLbl(m.estado))+'</span>'
     +'<div class="mkmain">'
     +'<div class="mkdet" title="go to context" onclick="'+(m.event_id!=null?('sigmaGoto('+m.event_id+')'):'')+'">'+esc(det.slice(0,240))+(m.regla?'<span class="mkrule" title="rule that flagged it">'+esc(m.regla)+'</span>':'')+'</div>'
     +'<div class="mkmeta">'+(meta||'—')+' · marked '+esc(m.creado)+'</div>'
     +(m.nota?'<div class="mknota">📝 '+esc(m.nota)+'</div>':'')
     +(m.contexto?'<details class="mkctxd"><summary>frozen context ('+(m.contexto.split(String.fromCharCode(10)).length)+' events)</summary><pre class="mkctx">'+esc(m.contexto)+'</pre></details>':'')
     +'</div>'
     +'<div class="mkact">'
     +'<button class="xs" onclick="event.stopPropagation();showRaw('+m.event_id+')" '+(m.event_id==null?'disabled':'')+'>raw</button>'
     + MK_ESTADOS.filter(e=>e!==m.estado).map(e=>'<button class="xs" onclick="markSetEstado('+m.mid+',\''+e+'\')">'+mkLbl(e)+'</button>').join('')
     +'<button class="xs" onclick="markEditNota('+m.mid+')">note</button>'
     +'<button class="xs" onclick="markDelete('+m.mid+')">delete</button>'
     +'</div></div>';
  }
  out.innerHTML=h;
 }catch(e){ out.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}

loadAiCfg('ai');loadAiCfg('local');
buildColsPanel();applyCols();fillEx();init();gtfoStatus();
</script>
</body></html>"""
