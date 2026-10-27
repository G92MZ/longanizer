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
                     count_bytes)
from . import ai as ai_mod
from . import geoip as geo_mod
from . import report as report_mod

# Categorías LOL (cada una con su propia pestaña, carpeta de reglas y el campo
# por el que se agrupa su gráfica de indicadores).
LOL_CATS = {
    "lolbas":     {"label": "LOLBAS",     "indicator": "lower(regexp_extract(coalesce(image,original_filename,''),'([^\\\\/]+)$',1))", "ind_label": "binary"},
    "loldrivers": {"label": "LOLDrivers", "indicator": "lower(regexp_extract(coalesce(image_loaded,image,''),'([^\\\\/]+)$',1))",       "ind_label": "driver"},
    "lolrmm":     {"label": "LOLRMM",     "indicator": "lower(regexp_extract(coalesce(image,original_filename,''),'([^\\\\/]+)$',1))", "ind_label": "tool"},
    "hijacklibs": {"label": "HijackLibs", "indicator": "lower(regexp_extract(coalesce(image_loaded,''),'([^\\\\/]+)$',1))",             "ind_label": "DLL"},
    "lottunnels": {"label": "LOTTunnels", "indicator": "lower(regexp_extract(coalesce(image,original_filename,''),'([^\\\\/]+)$',1))", "ind_label": "tunnel tool"},
}

# pySigma es opcional: si no está, la pestaña Sigma se desactiva sin romper nada.
try:
    from . import sigma_engine
    SIGMA_AVAILABLE = True
    SIGMA_IMPORT_ERROR = None
except Exception as _e:  # noqa: BLE001
    sigma_engine = None
    SIGMA_AVAILABLE = False
    SIGMA_IMPORT_ERROR = str(_e)

SIGMA_DIR = os.environ.get("SIGMA_RULES_DIR", "rules")
# Conjuntos de reglas independientes: 'general' (pestaña Sigma) + una por LOL.
RULESETS: dict[str, list] = {"general": []}
RULE_INFO: dict[str, dict] = {}
for _c in LOL_CATS:
    RULESETS[_c] = []


def _valid_set(name: str) -> str:
    return name if name in RULESETS else "general"


# Binarios de sistema / muy comunes contra los que se detecta masquerading
# (cmd2.exe, svch0st.exe, scvhost.exe, lsass .exe, …) en la pestaña Lookalike.
_SYSTEM_BINS = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "svchost.exe", "lsass.exe",
    "services.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "explorer.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "certutil.exe", "schtasks.exe", "taskhostw.exe", "conhost.exe",
    "dllhost.exe", "spoolsv.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "bitsadmin.exe", "wmic.exe", "net.exe", "net1.exe",
    "whoami.exe", "ipconfig.exe", "tasklist.exe", "ping.exe", "curl.exe",
    "msiexec.exe", "notepad.exe", "calc.exe", "lsm.exe", "dwm.exe",
    "ctfmon.exe", "runtimebroker.exe", "searchindexer.exe", "fontdrvhost.exe",
]

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
    ts_from: Optional[str] = None   # ISO datetime UTC, p.ej. '2025-01-01'
    ts_to:   Optional[str] = None


class SearchReq(BaseModel):
    q: str
    regex: bool = False
    source: Optional[str] = None
    limit: int = 500
    offset: int = 0
    sort: Optional[str] = None
    desc: bool = False
    start: Optional[str] = None   # filtro temporal global (UTC)
    end: Optional[str] = None
    eid: Optional[str] = None     # filtro por EventID


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
    eid: Optional[str] = None
    limit: int = 20


class TimelineReq(BaseModel):
    source: Optional[str] = None
    limit: int = 2000
    offset: int = 0
    start: Optional[str] = None   # ts mínimo (UTC), ej. "2026-09-29" o "2026-09-29 08:00"
    end: Optional[str] = None     # ts máximo (UTC)
    sort: Optional[str] = None
    desc: bool = False
    eid: Optional[str] = None     # filtro por EventID


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
    regla: Optional[str] = None       # contexto de la regla si se marca desde una detección
    ctx_n: int = 10                   # nº de eventos de contexto a congelar


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


def _geo_enrich(result: dict, ip_fields=("src_ip", "dst_ip")) -> dict:
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
                                        req.offset, req.sort, req.desc, req.start,
                                        req.end, req.eid))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Search error: {e}")


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


@app.get("/iocs")
def iocs_extract_ep():
    """Descubre los IOCs presentes en los EVTX cargados, agrupados por tipo."""
    try:
        return STORE.extract_iocs()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"IOC extraction error: {e}")


def _facet_geo(req: "FacetReq") -> dict:
    """Facetas de asn/org: facetea src_ip/dst_ip y agrega por ASN u Org."""
    base = STORE.facet("src_ip", req.q, req.regex, req.source,
                       req.start, req.end, req.eid, 500)
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
                           req.start, req.end, req.eid, req.limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/network")
def network_ep(kind: Optional[str] = None, proto: Optional[str] = None,
               image: Optional[str] = None, ip: Optional[str] = None,
               port: Optional[str] = None):
    return {"rows": STORE.network(kind=kind, proto=proto, image=image,
                                  ip=ip, port=port)}


@app.get("/attack")
def attack_ep():
    return _attack_matrix()


@app.post("/attack/stream")
def attack_stream_ep():
    """Igual que /attack pero emite progreso por regla (NDJSON) acumulando el
    avance a través de todos los sets cargados; al final {done:True, matrix}."""
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=400, detail="pySigma not available")
    sets = [(name, rules) for name, rules in RULESETS.items() if rules]
    if not sets:
        raise HTTPException(status_code=400, detail="No Sigma rules loaded.")
    grand_total = sum(len(rules) for _n, rules in sets)

    def gen():
        done = 0
        all_findings: list[dict] = []
        try:
            for setname, rules in sets:
                for item in sigma_engine.iter_run(STORE, rules, limit_per_rule=50):
                    if item.get("done"):
                        for f in item.get("findings", []):
                            f["_set"] = setname
                        all_findings.extend(item.get("findings", []))
                    else:
                        cur = done + item.get("i", 0)
                        yield json.dumps({"i": cur, "total": grand_total,
                                          "found": len(all_findings) + item.get("found", 0)},
                                         ensure_ascii=False) + "\n"
                done += len(rules)
            yield json.dumps({"done": True, "matrix": _attack_build(all_findings),
                              "i": grand_total, "total": grand_total},
                             ensure_ascii=False, default=str) + "\n"
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
    """Agrega los hits de Sigma (todos los sets cargados) por técnica ATT&CK y
    los organiza por táctica (columnas), para una matriz de cobertura del caso."""
    if not SIGMA_AVAILABLE:
        return {"tactics": [], "total_findings": 0, "error": "pySigma not available"}
    all_findings: list[dict] = []
    for setname, rules in RULESETS.items():
        if not rules:
            continue
        try:
            res = sigma_engine.run(STORE, rules, limit_per_rule=50)
        except Exception:  # noqa: BLE001
            continue
        for f in res.get("findings", []):
            f["_set"] = setname
            all_findings.append(f)
    return _attack_build(all_findings)


def _attack_build(findings):
    """Construye la matriz ATT&CK a partir de findings (cada uno con '_set')."""
    import re as _re
    tac = {k: {"key": k, "label": lab, "techs": {}} for k, lab in _TACTICS}
    other = {"key": "other", "label": "(no tactic tag)", "techs": {}}
    nfind = 0
    for f in findings:
        setname = f.get("_set", "")
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
                    tech, {"tech": tech, "count": 0, "rules": [],
                           "level": None, "ids": []})
                e["count"] += f.get("count", 0)
                e["rules"].append({"title": f.get("title"), "count": f.get("count"),
                                   "level": f.get("level"), "set": setname})
                e["ids"] = (e["ids"] + sample_ids)[:10]
                e["level"] = _worst_level(e["level"], f.get("level"))
    cols = []
    for k, _lab in _TACTICS:
        b = tac[k]
        if b["techs"]:
            b = dict(b, techs=sorted(b["techs"].values(), key=lambda x: -x["count"]))
            cols.append(b)
    if other["techs"]:
        cols.append(dict(other, techs=sorted(other["techs"].values(),
                                             key=lambda x: -x["count"])))
    return {"tactics": cols, "total_findings": nfind}


@app.post("/timeline")
def timeline(req: TimelineReq):
    try:
        return _geo_enrich(STORE.timeline(req.source, req.limit, req.offset,
                                          req.start, req.end, req.sort, req.desc,
                                          req.eid))
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
        '    "loganalyzer-forense": {\n'
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
   <pre>claude mcp add loganalyzer-forense -e DUCKDB_PATH={db_show} -- python -m loganalyzer.mcp_server</pre>
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


def _need_sigma():
    if not SIGMA_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"pySigma not available: {SIGMA_IMPORT_ERROR}")


@app.get("/sigma/status")
def sigma_status(set: str = "general"):
    s = _valid_set(set)
    return {"available": SIGMA_AVAILABLE, "error": SIGMA_IMPORT_ERROR,
            "set": s, "loaded": len(RULESETS[s]), "info": RULE_INFO.get(s, {})}


def _reload_set(path: str, setname: str) -> dict:
    rules, errors = sigma_engine.load_rules_dir(path)
    RULESETS[setname] = rules
    pv = sigma_engine.preview(STORE, rules)
    RULE_INFO[setname] = {"loaded": len(rules), "errors": errors, "preview": pv,
                          "path": os.path.abspath(path), "set": setname}
    return RULE_INFO[setname]


@app.post("/sigma/load")
def sigma_load(req: SigmaLoadReq, set: str = "general"):
    _need_sigma()
    s = _valid_set(set)
    path = (req.path or SIGMA_DIR).strip()
    if not os.path.exists(path):
        raise HTTPException(status_code=404,
                            detail=f"Rules folder does not exist: {path}")
    try:
        return _reload_set(path, s)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Error loading rules: {e}")


@app.post("/sigma/load/stream")
def sigma_load_stream(req: SigmaLoadReq, set: str = "general"):
    """Carga reglas fichero a fichero emitiendo progreso (NDJSON), y al final
    intenta un load conjunto para recuperar correlaciones cruzadas."""
    _need_sigma()
    s = _valid_set(set)
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
            RULESETS[s] = final
            pv = sigma_engine.preview(STORE, final)
            RULE_INFO[s] = {"loaded": len(final), "errors": errors, "preview": pv,
                            "path": os.path.abspath(path), "set": s}
            yield json.dumps({"done": True, "loaded": len(final),
                              "errors": errors, "preview": pv,
                              "path": os.path.abspath(path), "set": s},
                             default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@app.get("/sigma/rules")
def sigma_rules_ep(set: str = "general"):
    _need_sigma()
    s = _valid_set(set)
    try:
        return {"rules": sigma_engine.list_rules(STORE, RULESETS[s])}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Error listing rules: {e}")


@app.post("/sigma/run")
def sigma_run_ep(set: str = "general"):
    _need_sigma()
    s = _valid_set(set)
    if not RULESETS[s]:
        raise HTTPException(status_code=400, detail="No rules loaded for this tab.")
    try:
        return sigma_engine.run(STORE, RULESETS[s], limit_per_rule=200)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Error running Sigma: {e}")


@app.post("/sigma/run/stream")
def sigma_run_stream_ep(set: str = "general"):
    """Ejecuta un conjunto emitiendo progreso por regla en NDJSON."""
    _need_sigma()
    s = _valid_set(set)
    if not RULESETS[s]:
        raise HTTPException(status_code=400, detail="No rules loaded for this tab.")

    def gen():
        try:
            for item in sigma_engine.iter_run(STORE, RULESETS[s], limit_per_rule=200):
                yield json.dumps(item, ensure_ascii=False, default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


# ---------------------------------------------------------------------------
# Pestañas LOL: ejecutar sus Sigma + gráfica "top indicador por eventos con hit"
# ---------------------------------------------------------------------------
def _lol_chart(cat: str) -> list[dict]:
    """Agrega los eventos que hacen hit (cualquier regla del set) por indicador."""
    rules = RULESETS.get(cat, [])
    combined, _applied = sigma_engine.compile_combined_where(STORE, rules)
    if not combined:
        return []
    ind = LOL_CATS[cat]["indicator"]
    try:
        rows = STORE.lol_chart(combined, ind, limit=15)
    except Exception:  # noqa: BLE001
        return []
    return [{"k": k, "n": n} for k, n in rows]


@app.post("/lol/run")
def lol_run_ep(cat: str):
    _need_sigma()
    if cat not in LOL_CATS:
        raise HTTPException(status_code=404, detail="Unknown LOL category.")
    if not RULESETS[cat]:
        raise HTTPException(status_code=400,
                            detail="No rules loaded for this tab. Pick a rules folder and load.")
    try:
        res = sigma_engine.run(STORE, RULESETS[cat], limit_per_rule=200)
        res["chart"] = _lol_chart(cat)
        res["indicator"] = LOL_CATS[cat]["ind_label"]
        return res
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Error running {cat}: {e}")


@app.post("/lol/run/stream")
def lol_run_stream_ep(cat: str):
    """Como /lol/run pero emitiendo progreso por regla (NDJSON); al 'done' le
    añade la gráfica del indicador para que la barra avance igual que en Sigma."""
    _need_sigma()
    if cat not in LOL_CATS:
        raise HTTPException(status_code=404, detail="Unknown LOL category.")
    if not RULESETS[cat]:
        raise HTTPException(status_code=400,
                            detail="No rules loaded for this tab. Pick a rules folder and load.")

    def gen():
        try:
            for item in sigma_engine.iter_run(STORE, RULESETS[cat], limit_per_rule=200):
                if item.get("done"):
                    item["chart"] = _lol_chart(cat)
                    item["indicator"] = LOL_CATS[cat]["ind_label"]
                yield json.dumps(item, ensure_ascii=False, default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


# ---------------------------------------------------------------------------
# Lookalike / masquerading (distancia de Levenshtein sobre nombres de binario)
# ---------------------------------------------------------------------------
@app.get("/lookalike")
def lookalike_ep(dist: int = 2, also_seen: int = 0):
    refs = _SYSTEM_BINS
    try:
        res = STORE.lookalike(refs, max_dist=max(1, min(int(dist), 5)),
                              also_seen=bool(also_seen))
        return {"matches": res, "refs": len(refs), "dist": dist}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Error: {e}")


# ---------------------------------------------------------------------------
# Resumen / Dashboard  (+ GeoIP de las top IPs)
# ---------------------------------------------------------------------------
@app.get("/dashboard")
def dashboard_ep():
    d = STORE.dashboard()
    # enriquece las top IPs (origen y destino) con interna/externa y país/ASN/ISP
    for key in ("top_src_ip", "top_dst_ip"):
        for row in d.get(key, []):
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
    for key in ("top_src_ip", "top_dst_ip"):
        for row in d.get(key, []):
            g = geo_mod.lookup(row["k"])
            row["private"] = g["private"]; row["country"] = g["country"]
            row["country_code"] = g["country_code"]; row["asn"] = g["asn"]; row["org"] = g["org"]
    sigma_res = None
    lol_res = {}
    if SIGMA_AVAILABLE:
        if RULESETS["general"]:
            try:
                sigma_res = sigma_engine.run(STORE, RULESETS["general"])
            except Exception:  # noqa: BLE001
                sigma_res = None
        for cat in LOL_CATS:
            if RULESETS[cat]:
                try:
                    r = sigma_engine.run(STORE, RULESETS[cat])
                    r["chart"] = _lol_chart(cat)
                    lol_res[cat] = r
                except Exception:  # noqa: BLE001
                    pass
    marks = STORE.mark_list()
    persist = STORE.persistence()
    logons = STORE.logons()
    case = None if (AUTO_PENDING or DB_PATH == ":memory:") else os.path.basename(DB_PATH)
    html_doc = report_mod.build(
        meta={"title": "WinHound — Windows forensic report",
              "generated": report_mod.generated_now(), "case": case},
        dashboard=d, sigma=sigma_res, lol=lol_res,
        lol_labels={c: LOL_CATS[c]["label"] for c in LOL_CATS}, marks=marks,
        persist=persist, logons=logons)
    headers = {}
    if download:
        fn = "winhound_report_" + time.strftime("%Y%m%d_%H%M", time.gmtime()) + ".html"
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
# Fase 2: vistas avanzadas Windows
# ---------------------------------------------------------------------------
@app.get("/proctree")
def proctree_ep(pid: Optional[str] = None, guid: Optional[str] = None,
                image: Optional[str] = None, node: Optional[str] = None):
    pid = (pid or "").strip() or None
    guid = (guid or "").strip() or None
    image = (image or "").strip() or None
    node = (node or "").strip() or None
    if not (pid or guid or image or node):
        return {"roots": [], "anchors": [], "need_anchor": True}
    # node (id de evento exacto) ancla un único proceso: sin lista de anchors
    if node:
        return {"roots": STORE.process_tree(node=node), "anchors": [],
                "need_anchor": False}
    anchors = STORE.proc_anchors(pid=pid, guid=guid, image=image)
    return {"roots": STORE.process_tree(pid=pid, guid=guid, image=image),
            "anchors": anchors, "need_anchor": False}


@app.get("/logons")
def logons_ep(user: Optional[str] = None, logon_type: Optional[str] = None,
              src_ip: Optional[str] = None, workstation: Optional[str] = None,
              auth: Optional[str] = None, host: Optional[str] = None):
    return {"logons": STORE.logons(user=user, logon_type=logon_type,
                                   src_ip=src_ip, workstation=workstation,
                                   auth=auth, host=host)}


@app.get("/persistence")
def persistence_ep():
    return {"items": STORE.persistence()}


@app.get("/powershell")
def powershell_ep(q: Optional[str] = None):
    return {"scripts": STORE.powershell(q=q), "q": (q or "").strip()}


@app.get("/rawevent")
def rawevent_ep(id: int):
    return STORE.raw_event(id)


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


def _parse_ts_filter(req):
    import datetime as _dt
    def _p(val):
        if not val: return None
        val = val.strip().replace(' ', 'T')
        for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
            try: return _dt.datetime.strptime(val, fmt).replace(tzinfo=_dt.timezone.utc)
            except ValueError: pass
        return None
    return _p(getattr(req, 'ts_from', None)), _p(getattr(req, 'ts_to', None))


@app.post("/ingest/path/stream")
def ingest_path_stream_ep(req: PathReq):
    """Ingesta EVTX de una ruta del servidor emitiendo el resultado de cada
    fichero en NDJSON (progreso en vivo). Primera línea: {"total": N}."""
    if not os.path.exists(req.path):
        raise HTTPException(status_code=404, detail=f"Does not exist: {req.path}")
    _ensure_persistent()

    ts_from, ts_to = _parse_ts_filter(req)
    def gen():
        yield json.dumps({"total": count_files(req.path),
                          "total_bytes": count_bytes(req.path)}) + "\n"
        byte_prog = [0]
        try:
            for item in iter_ingest_path(STORE, req.path, byte_prog=byte_prog,
                                         ts_from=ts_from, ts_to=ts_to):
                yield json.dumps(item, ensure_ascii=False, default=str) + "\n"
        except Exception as e:  # noqa: BLE001
            yield json.dumps({"fatal": str(e)}, ensure_ascii=False) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@app.post("/ingest/path")
def ingest_path_ep(req: PathReq):
    if not os.path.exists(req.path):
        raise HTTPException(status_code=404, detail=f"Does not exist: {req.path}")
    _ensure_persistent()
    ts_from, ts_to = _parse_ts_filter(req)
    try:
        res = ingest_path(STORE, req.path, ts_from=ts_from, ts_to=ts_to)
        return {"ingested": res, "stats": STORE.stats()}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/ingest/upload")
async def ingest_upload(
    files: list[UploadFile] = File(...),
    relpaths: list[str] = Form(default=[]),
    ts_from_str: Optional[str] = Form(None),
    ts_to_str:   Optional[str] = Form(None),
):
    _ensure_persistent()
    import datetime as _dt
    def _pf(v):
        if not v: return None
        v=v.strip().replace(' ','T')
        for fmt in ('%Y-%m-%dT%H:%M:%S','%Y-%m-%dT%H:%M','%Y-%m-%d'):
            try: return _dt.datetime.strptime(v,fmt).replace(tzinfo=_dt.timezone.utc)
            except ValueError: pass
        return None
    _ts_from = _pf(ts_from_str); _ts_to = _pf(ts_to_str)
    results = []
    for i, uf in enumerate(files):
        suffix = os.path.basename(uf.filename or "upload.evtx")
        label = relpaths[i] if i < len(relpaths) and relpaths[i] else suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix="_" + suffix) as tmp:
            tmp.write(await uf.read())
            tmp_path = tmp.name
        real = None
        try:
            real = os.path.join(os.path.dirname(tmp_path), suffix)
            os.replace(tmp_path, real)
            results.extend(ingest_path(STORE, real, label=label,
                                       ts_from=_ts_from, ts_to=_ts_to))
        except Exception as e:  # noqa: BLE001
            results.append({"file": label, "error": str(e)})
        finally:
            for p in (tmp_path, real):
                if p and os.path.exists(p):
                    os.unlink(p)
    return {"ingested": results, "stats": STORE.stats()}


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WinHound</title>
<link rel="icon" href="data:image/svg+xml,&lt;svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'&gt;&lt;text y='14' font-size='14'&gt;&#128269;&lt;/text&gt;&lt;/svg&gt;">
<style>
 :root{--bg:#132743;--panel:#1b3357;--panel2:#23416b;--border:#345681;--fg:#eaf1fb;--muted:#a3b6d4;--accent:#5fa3ff;--accent-hi:#83baff;--ink:#07192f;--hit:#4a3d12;--radius:12px;--shadow:0 2px 10px rgba(0,0,0,.28);--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,sans-serif;font-size:14px;line-height:1.55}
 header{padding:18px 28px;border-bottom:1px solid var(--border);display:flex;gap:20px;align-items:baseline;flex-wrap:wrap;background:linear-gradient(180deg,#1d3860,#132743)}
 h1{font-size:19px;margin:0;letter-spacing:.2px}
 .muted{color:var(--muted);font-size:12px}
 .qacwrap{position:relative}
 .qac{position:absolute;left:0;right:0;top:100%;z-index:40;background:var(--panel2);border:1px solid var(--border);border-top:0;border-radius:0 0 8px 8px;max-height:260px;overflow:auto;box-shadow:var(--shadow)}
 .qac.hidden{display:none}
 .qacit{padding:5px 10px;font-family:var(--mono);font-size:12px;cursor:pointer;color:var(--fg)}
 .qacit.on,.qacit:hover{background:var(--accent);color:var(--ink)}
 main{padding:28px;max-width:1500px;margin:0 auto}
 .tabs{display:flex;gap:6px;margin-bottom:26px;flex-wrap:wrap;border-bottom:1px solid var(--border)}
 .tab{background:transparent;color:var(--muted);border:1px solid transparent;border-bottom:0;border-radius:9px 9px 0 0;padding:11px 20px;cursor:pointer;font-weight:500;margin-bottom:-1px}
 .tab:hover{color:var(--fg);background:var(--panel)}
 .tab.active{background:var(--panel);color:var(--accent);border-color:var(--border);font-weight:600}
 /* sub-navegación (p.ej. agrupar Sigma + LOL + Lookalike bajo un padre) */
 .subnav{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:-18px 0 24px;padding:8px 10px;background:var(--panel);border:1px solid var(--border);border-radius:10px}
 .subnav .subcap{color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-right:4px}
 .subnav .subtab{color:var(--muted);padding:7px 15px;border-radius:7px;cursor:pointer;font-size:13px;font-weight:500}
 .subnav .subtab:hover{color:var(--fg);background:var(--panel2)}
 .subnav .subtab.active{background:var(--accent);color:var(--ink);font-weight:600}
 .tab.parent.active{color:var(--accent)}
 .panel{display:none}
 .panel.active{display:block}
 section.panel{padding-top:2px}
 textarea{width:100%;min-height:100px;background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;font-family:var(--mono);font-size:13px;resize:vertical;line-height:1.55}
 input[type=text],input[type=number],select{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
 input[type=text]:focus,input[type=number]:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(95,163,255,.22)}
 input[type=file]{color:var(--muted);font-size:12px;max-width:100%;vertical-align:middle;margin-left:6px}
 input[type=file]::file-selector-button{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:8px 14px;font-weight:600;font-family:inherit;font-size:12px;cursor:pointer;margin-right:10px;transition:background .12s}
 input[type=file]::file-selector-button:hover{background:var(--border)}
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
 /* Phase 2 */
 .ptree{font-family:var(--mono);font-size:12px}
 .ptnode,.ptleaf{margin:2px 0 2px 0}
 .ptree details{border:0;background:transparent;border-radius:0;margin:0;padding:0 0 0 16px;box-shadow:none}
 .ptree>.ptnode,.ptree>.ptleaf{padding-left:0}
 .ptree summary{list-style:none;padding:3px 0;cursor:pointer}
 .ptree summary::-webkit-details-marker{display:none}
 .ptree summary::before{content:"\25B6";color:var(--accent);font-size:9px;margin-right:6px;display:inline-block}
 .ptree details[open]>summary::before{transform:rotate(90deg)}
 .ptleaf{padding:3px 0 3px 14px}
 .ptbin{color:var(--accent);font-weight:700;cursor:pointer}
 .ptbin:hover{text-decoration:underline}
 .ptpid{color:var(--muted);margin-left:8px;font-size:11px}
 .ptcmd{color:var(--fg);margin-left:10px}
 .ptmeta{margin-left:10px}
 .ptrow.pthit{background:rgba(88,166,255,.16);border-radius:4px;padding:1px 4px;outline:1px solid rgba(88,166,255,.5)}
 .ptbin.pthit{color:#ffd166}
 tr.failrow td{background:rgba(248,81,73,.12)}
 tr.failrow td:first-child{border-left:3px solid #f85149}
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
 mark{background:#fde68a;color:#1e293b;padding:0 2px;border-radius:2px}
 details.ingsec{margin-top:14px}
 details.ingsec>summary{cursor:pointer;font-size:13px;font-weight:600;margin:4px 0 6px;user-select:none}
 .ptsrc{display:inline-block;font-size:10px;font-weight:600;padding:1px 6px;border-radius:9px;margin:0 6px;background:var(--chip,#1f3a5f);color:var(--muted);vertical-align:middle}
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
 /* ATT&CK matrix */
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
 /* IOC sweep */
 .iocard{border:1px solid var(--border);border-radius:10px;margin:12px 0;overflow:hidden}
 .iocard .iohead{padding:9px 12px;font-size:13px;background:var(--panel)}
 .iocard.ioc-hit .iohead{border-left:4px solid #f85149}
 .iocard.ioc-clean .iohead{border-left:4px solid #3fb950;color:var(--muted)}
 .iocard .iohead{border-left:4px solid var(--accent)}
 .iocard .iocxbody{display:none}
 .iocard.open .iocxbody{display:block}
 .iocxtoggle{cursor:pointer;user-select:none}
 .iocard .caret{display:inline-block;width:11px;color:var(--muted);transition:transform .15s}
 .iocard .caret::before{content:'\25B8'}
 .iocard.open .caret{transform:rotate(90deg)}
 .iocxchips{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
 .iocxchip{background:var(--panel2);border:1px solid var(--border);border-radius:14px;padding:3px 10px;font-size:12px;color:var(--fg);text-decoration:none}
 .iocxchip:hover{border-color:var(--accent)} .iocxchip b{color:var(--accent)}
 .iocxchip.active{background:var(--accent);color:var(--ink);border-color:var(--accent)}
 .iocxchip.active b{color:var(--ink)}
 #iocx_filters select{padding:4px 8px;background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px;font-size:13px}
 #iocx_filters input[type=search]{padding:4px 8px;background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px;font-size:13px;width:220px}
 .iocard.iocx-hidden{display:none}
 tr.iocx-hidden{display:none}
 td.iocval{font-family:var(--mono);cursor:pointer} td.iocval:hover{color:var(--accent)}
 .ioctag{display:inline-block;border-radius:6px;padding:0 6px;font-size:10px;margin-left:6px;vertical-align:1px}
 .ioctag-ext{background:#5a1d1d;color:#ff9b9b} .ioctag-int{background:#1d3a24;color:#8fe0a6} .ioctag-doc{background:#2b2b40;color:#b7b7d8}
 .psprev{margin-top:5px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--muted);white-space:pre-wrap;word-break:break-word;line-height:1.5}
 #ingested h3{margin:20px 0 6px;font-size:13px}
 td.prevcell{white-space:normal;max-width:520px}
 .prev{margin:0;font-family:var(--mono);font-size:11px;color:var(--muted);white-space:pre-wrap;max-height:90px;overflow:auto}
</style>
<style id="colstyle"></style></head>
<body>
<header>
 <h1>&#128302; WinHound</h1>
 <span class="muted">Windows EVTX (Sysmon/Security/PowerShell/…) &middot; DuckDB</span>
 <span id="stat" class="pill">loading&hellip;</span>
 <span id="dbpill" class="pill" title="Where this case is stored"></span>
</header>
<main>
 <div class="tabs">
  <div class="tab active" data-tab="landing" onclick="switchTab('landing')">Load</div>
  <div class="tab hidden" data-tab="dash" data-optional onclick="switchTab('dash')">Overview</div>
  <div class="tab hidden" data-tab="explorer" data-optional onclick="switchTab('explorer')">Explorer</div>
  <div class="tab hidden" data-tab="iocx" data-optional onclick="switchTab('iocx')">IOCs</div>
  <div class="tab hidden" data-tab="ioc" data-optional onclick="switchTab('ioc')">IOC sweep</div>
  <div class="tab hidden" data-tab="sql" data-optional onclick="switchTab('sql')">SQL</div>
  <div class="tab parent hidden" data-tab="__ai" data-optional onclick="openGroup('ai')">AI ▾</div>
  <div class="tab parent hidden" data-tab="__sigma" data-optional onclick="openGroup('sigma')">Sigma &amp; LOL ▾</div>
  <div class="tab parent hidden" data-tab="__hunt" data-optional onclick="openGroup('hunt')">Hunting ▾</div>
  <div class="tab hidden" data-tab="marks" data-optional onclick="switchTab('marks')">Marks</div>
  <div class="tab hidden" data-tab="help" data-optional onclick="switchTab('help')">Help</div>
 </div>
 <div id="subnav_ai" class="subnav hidden">
  <span class="subcap">AI</span>
  <div class="subtab" data-tab="ai" onclick="switchTab('ai')">AI (API)</div>
  <div class="subtab" data-tab="ailocal" onclick="switchTab('ailocal')">AI (local)</div>
  <div class="subtab" data-tab="mcp" onclick="switchTab('mcp')">MCP</div>
 </div>
 <div id="subnav_sigma" class="subnav hidden">
  <span class="subcap">Sigma &amp; LOL</span>
  <div class="subtab" data-tab="sigma" onclick="switchTab('sigma')">Sigma rules</div>
  <div class="subtab" data-tab="lol_lolbas" onclick="switchTab('lol_lolbas')">LOLBAS</div>
  <div class="subtab" data-tab="lol_loldrivers" onclick="switchTab('lol_loldrivers')">LOLDrivers</div>
  <div class="subtab" data-tab="lol_lolrmm" onclick="switchTab('lol_lolrmm')">LOLRMM</div>
  <div class="subtab" data-tab="lol_hijacklibs" onclick="switchTab('lol_hijacklibs')">HijackLibs</div>
  <div class="subtab" data-tab="lol_lottunnels" onclick="switchTab('lol_lottunnels')">LOTTunnels</div>
  <div class="subtab" data-tab="lookalike" onclick="switchTab('lookalike')">Lookalike</div>
  <div class="subtab" data-tab="attack" onclick="switchTab('attack')">ATT&amp;CK matrix</div>
 </div>
 <div id="subnav_hunt" class="subnav hidden">
  <span class="subcap">Hunting</span>
  <div class="subtab" data-tab="proctree" onclick="switchTab('proctree')">Proc tree</div>
  <div class="subtab" data-tab="logons" onclick="switchTab('logons')">Logons</div>
  <div class="subtab" data-tab="persist" onclick="switchTab('persist')">Persistence</div>
  <div class="subtab" data-tab="powershell" onclick="switchTab('powershell')">PowerShell</div>
  <div class="subtab" data-tab="network" onclick="switchTab('network')">Network</div>
 </div>

 <!-- ============ CARGAR (inicio) ============ -->
 <section id="landing" class="panel active">
  <div class="landing">
   <p>Load your Windows <b>EVTX</b> to start. Records are normalized into a single
   timeline (UTC) and, once done, the <b>Overview</b>, <b>Explorer</b>, <b>SQL</b>,
   <b>Sigma</b>, the <b>LOL</b> tabs and more become available.</p>
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
     <b style="font-size:13px">Load EVTX:</b>
     <label class="muted">files<input type="file" id="files" accept=".evtx,.zip,.gz,.tar,.tgz" multiple></label>
     <label class="muted">or folder<input type="file" id="folder" webkitdirectory multiple></label>
     <button class="bigbtn" onclick="uploadFiles()">Upload and load</button>
     <button class="sec" onclick="clearPicks()">Clear selection</button>
    </div>
    <div class="row" style="flex-wrap:wrap;gap:10px;margin-top:4px;align-items:center">
     <span style="font-size:12px;color:var(--muted)">Time filter (UTC, optional):</span>
     <label class="muted" style="gap:4px">From<input type="text" id="ts_from_up" placeholder="2025-01-01" style="width:130px" title="YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"></label>
     <label class="muted" style="gap:4px">To<input type="text" id="ts_to_up" placeholder="2025-12-31" style="width:130px" title="YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"></label>
     <select id="ts_preset_up" onchange="applyTsPreset('up',this.value)" style="font-size:12px;padding:3px 6px;background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px">
      <option value="">— quick range —</option>
      <option value="1">Last 24 h</option>
      <option value="3">Last 3 days</option>
      <option value="7">Last 7 days</option>
      <option value="30">Last 30 days</option>
      <option value="90">Last 90 days</option>
     </select>
    </div>
    <div class="row">
     <progress id="prog" value="0" max="100" style="width:220px;display:none"></progress>
     <span id="ingmsg" class="muted"></span>
    </div>
    <div class="muted">With <b>folder</b> you pick a directory and it uploads <b>the whole tree</b> (subfolders included); with <b>files</b>, loose <code>.evtx</code> or a <code>.zip</code>/<code>.tar.gz</code> (auto-extracted, <code>.evtx</code> found recursively). Non-EVTX files are skipped. EVTX timestamps are already UTC.</div>
   </div>

   <div class="drop" style="margin-top:12px">
    <div class="row">
     <b style="font-size:13px">Or a path on the server:</b>
     <input type="text" id="spath" placeholder="E:\path\to\triage  (folder, .evtx or .zip/.tar.gz)" style="flex:1;min-width:280px">
     <button class="bigbtn" onclick="ingestPath()">Load from path</button>
    </div>
    <div class="row" style="flex-wrap:wrap;gap:10px;margin-top:4px;align-items:center">
     <span style="font-size:12px;color:var(--muted)">Time filter (UTC, optional):</span>
     <label class="muted" style="gap:4px">From<input type="text" id="ts_from_path" placeholder="2025-01-01" style="width:130px" title="YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"></label>
     <label class="muted" style="gap:4px">To<input type="text" id="ts_to_path" placeholder="2025-12-31" style="width:130px" title="YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"></label>
     <select id="ts_preset_path" onchange="applyTsPreset('path',this.value)" style="font-size:12px;padding:3px 6px;background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:6px">
      <option value="">— quick range —</option>
      <option value="1">Last 24 h</option>
      <option value="3">Last 3 days</option>
      <option value="7">Last 7 days</option>
      <option value="30">Last 30 days</option>
      <option value="90">Last 90 days</option>
     </select>
    </div>
    <div class="muted">Faster when the EVTX are already <b>on this machine</b>: the server reads them straight from disk, without uploading through the browser, and you get <b>live progress</b> (files and events). Supports folders with subfolders and archives. The path is on the machine running the server.</div>
   </div>

   <div class="muted" style="margin-top:12px">💡 <b>Sample data:</b> 562 attack EVTX ship with WinHound in <code>samples/evtx-attack-samples.zip</code>. Unzip it and load the <code>evtx-attack-samples/</code> folder, or point either loader straight at the <code>.zip</code>.</div>

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
      <input type="text" id="q" placeholder="mimikatz  image:powershell  -user:SYSTEM" autofocus autocomplete="off">
      <div id="qac" class="qac hidden"></div>
     </div>
     <div class="fld">
      <label for="src">Channel</label>
      <select id="src"><option>(all)</option></select>
     </div>
     <div class="fld">
      <label for="eid">EventID</label>
      <select id="eid"><option>(all)</option></select>
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
       <tr><td><code>mimikatz lsass</code></td><td>free text; several words = <b>AND</b> (all must appear)</td></tr>
       <tr><td><code>image:powershell</code></td><td>field <b>contains</b> (case-insensitive). Also <code>command_line:enc</code>, <code>user:admin</code>, <code>src_ip:10.</code></td></tr>
       <tr><td><code>image&nbsp;contains&nbsp;powershell</code></td><td>same thing, written with the word <code>contains</code></td></tr>
       <tr><td><code>eid=4688</code></td><td>field <b>exactly</b> equals (<code>=</code>). Handy for EventID, logon_type…</td></tr>
       <tr><td><code>user!=SYSTEM</code></td><td>field is <b>not</b> that value</td></tr>
       <tr><td><code>-SYSTEM</code> &nbsp; <code>-eid:4624</code></td><td><b>exclude</b> (NOT): drop events with that text / field value. Several allowed</td></tr>
       <tr><td><code>x:TargetObject:Run</code></td><td>a key of the <code>extra</code> JSON (EventData, <b>PascalCase</b>). Also <code>extra.TargetObject:Run</code></td></tr>
       <tr><td><code>/regex/</code></td><td>regex over the raw record, e.g. <code>/mimikatz|sekurlsa/</code>. Combine with fields &amp; NOT</td></tr>
       <tr><td><code>command_line:/-enc\s+\w+/</code></td><td>regex on a single field. Quote if it has spaces: <code>"command_line:/a b/"</code></td></tr>
       <tr><td><code>logon_type:*</code></td><td>the field <b>exists</b> / has a value. <code>-logon_type:*</code> (or <code>logon_type:-</code>) = <b>empty or missing</b></td></tr>
       <tr><td><code>command_line:"-enc AB"</code></td><td>use quotes for values with spaces</td></tr>
      </table>
      <p class="hintlbl">Mix freely: <code>image:powershell -user:SYSTEM eid=1</code>. Fields: ts, source(channel), host, eid, user, sid, src_ip, dst_ip, image, command_line, parent_image, hashes, target_filename, logon_type, message (aliases: ip, id, cmd, img, parent…). The <b>regex</b> checkbox treats the WHOLE box as one regex; the <code>/…/</code> form works token-by-token without it.</p>
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
        <option value="eid">eid</option><option value="source">channel</option>
        <option value="user">user</option><option value="src_ip">src_ip</option>
        <option value="dst_ip">dst_ip</option><option value="image">image</option>
        <option value="parent_image">parent_image</option><option value="logon_type">logon_type</option>
        <option value="level">level</option><option value="host">host</option>
        <option value="asn">asn</option><option value="org">org</option>
       </optgroup>
       <optgroup label="high cardinality">
        <option value="command_line">command_line</option><option value="target_filename">target_filename</option>
        <option value="hashes">hashes</option><option value="message">message</option>
       </optgroup>
       <optgroup label="extra (EventData)" id="facextra"></optgroup>
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
   <p>Run your <b>Sigma</b> rules (Windows taxonomy) over the loaded EVTX. The
   logsource maps to channels/EventIDs (e.g. <code>process_creation</code> →
   Sysmon EID1 or Security 4688); rules that filter by <code>Channel</code>/
   <code>EventID</code> directly also work. Each rule is translated to SQL over the
   <code>events</code> table. This tab is for your <b>general</b> ruleset (no chart).</p>
  </div>
  <div class="aicfg">
   <label class="wide">rules folder on the server<input type="text" id="sg_path" placeholder="path to your general Sigma rules folder"></label>
   <button class="bigbtn" onclick="sigmaLoad()">Load rules</button>
  </div>
  <div class="row">
   <button onclick="sigmaRun()" id="sg_runbtn" disabled>Run rules</button>
   <button class="sec" onclick="sigmaListRules()" id="sg_listbtn" disabled>View applicable rules (SQL)</button>
   <button class="sec" onclick="sigmaExportCsv()" id="sg_csvbtn" disabled style="margin-left:4px">&#8615; CSV</button>
   <progress id="sg_prog" max="100" value="0" style="display:none;width:180px;vertical-align:middle"></progress>
   <span id="sg_msg" class="muted"></span>
  </div>
  <div id="sg_out"></div>
 </section>

 <!-- ============ LOL TABS (one per category) ============ -->
 <section id="lol_lolbas" class="panel"></section>
 <section id="lol_loldrivers" class="panel"></section>
 <section id="lol_lolrmm" class="panel"></section>
 <section id="lol_hijacklibs" class="panel"></section>
 <section id="lol_lottunnels" class="panel"></section>

 <!-- ============ LOOKALIKE (Levenshtein) ============ -->
 <section id="lookalike" class="panel">
  <div class="help">
   <p>Find executed binaries whose name is <b>suspiciously close</b> to a legitimate
   Windows/LOLBAS binary (e.g. <code>cmd2.exe</code>, <code>svch0st.exe</code>,
   <code>scvhost.exe</code>) by <b>Levenshtein distance</b>. Exact matches (the real
   ones) are excluded. Optionally also compare the seen binaries against each other.</p>
  </div>
  <div class="toolbar">
   <div class="tbgroup"><div class="tbglabel">Lookalike search</div>
    <div class="tbrow">
     <div class="fld"><label for="lk_dist">Max distance</label>
      <select id="lk_dist"><option>1</option><option selected>2</option><option>3</option></select></div>
     <div class="fld fld-chk"><label>Mode</label>
      <label class="chk"><input type="checkbox" id="lk_seen"> also compare seen vs seen</label></div>
     <button class="bigbtn" onclick="lkRun()">Search lookalikes</button>
     <span id="lk_msg" class="muted"></span>
    </div>
   </div>
  </div>
  <div id="lk_out"></div>
 </section>

 <!-- ============ PHASE 2: advanced Windows views ============ -->
 <section id="proctree" class="panel">
  <div class="help"><p>Process tree for Sigma <b>process_creation</b> — Sysmon <b>EID1</b>
  <i>and</i> Security <b>4688</b>. Linked by <code>ProcessGuid</code>/<code>ParentProcessGuid</code>
  when present (Sysmon), otherwise by <b>PID</b> within the same host and time order (4688).
  <b>Anchored on a process you choose</b>: enter a <b>PID</b>, a <b>ProcessGuid</b> or an
  <b>image name</b> and the tree is built from there (descendants plus the chain of ancestors),
  instead of loading every process. Each node shows its source (<span class="ptsrc">sysmon</span>/<span class="ptsrc">4688</span>);
  click a node to jump to its event context.</p></div>
  <div class="row">
   <input id="pt_pid" placeholder="PID — e.g. 3388" style="width:140px"
     onkeydown="if(event.key==='Enter')loadProctree()">
   <input id="pt_img" placeholder="image — e.g. mimikatz.exe" style="width:200px"
     onkeydown="if(event.key==='Enter')loadProctree()">
   <input id="pt_guid" placeholder="ProcessGuid (optional, most precise)" style="width:290px"
     onkeydown="if(event.key==='Enter')loadProctree()">
   <button class="bigbtn" onclick="loadProctree()">Build tree</button>
   <button class="sec" onclick="ptAll(1)">Expand all</button>
   <button class="sec" onclick="ptAll(0)">Collapse all</button>
   <span id="pt_msg" class="muted"></span></div>
  <div id="pt_anchors"></div>
  <div id="pt_out"></div>
 </section>

 <section id="logons" class="panel">
  <div class="help"><p>Authentication activity (Sigma-style, across channels):
  <b>Security</b> logons (4624/4625/4634/4647/4648/4672), <b>Kerberos</b> (4768/4769/4771),
  <b>NTLM</b> (4776) and <b>RDP</b> (4778/4779, TerminalServices 1149 &amp; 21/22/24/25) — with
  logon type, source IP, workstation and auth package normalized per source. Failed
  auth (4625/4771) is highlighted. Filter by user, type, source IP, workstation, auth
  or host (substring; type is exact).</p></div>
  <div class="row">
   <input id="lo_user" placeholder="user" style="width:130px"
     onkeydown="if(event.key==='Enter')loadLogons()">
   <input id="lo_type" placeholder="type (2,3,10…)" style="width:120px"
     onkeydown="if(event.key==='Enter')loadLogons()">
   <input id="lo_src" placeholder="source IP" style="width:130px"
     onkeydown="if(event.key==='Enter')loadLogons()">
   <input id="lo_ws" placeholder="workstation" style="width:140px"
     onkeydown="if(event.key==='Enter')loadLogons()">
   <input id="lo_auth" placeholder="auth (NTLM/Kerberos…)" style="width:170px"
     onkeydown="if(event.key==='Enter')loadLogons()">
   <input id="lo_host" placeholder="host" style="width:150px"
     onkeydown="if(event.key==='Enter')loadLogons()">
   <button class="bigbtn" onclick="loadLogons()">Search</button>
   <button class="sec" onclick="clearLogons()">Clear</button>
   <span id="lo_msg" class="muted"></span></div>
  <div id="lo_out"></div>
 </section>

 <section id="persist" class="panel">
  <div class="help"><p>Persistence signals (ASEP) from <b>Sysmon</b> and <b>native Windows
  logs</b>: registry autostart in ~30 locations (Sysmon 12/13/14 — Run keys, Winlogon,
  IFEO, AppInit/AppCert, services, COM/CLSID, LSA, screensaver, Active Setup…), the
  <b>Startup folder</b> (Sysmon 11), <b>service</b> installs &amp; start-type changes
  (7045/4697/7040), <b>scheduled tasks</b> (4698–4702, TaskScheduler 106/140/141/200/201),
  <b>WMI</b> subscriptions (Sysmon 19/20/21 and WMI-Activity 5861), <b>account</b> creation
  and privileged <b>group</b> additions (4720/4722/4728/4732/4738/4756) and <b>BITS</b> jobs
  (Bits-Client 3).</p></div>
  <div class="row"><button class="bigbtn" onclick="loadPersist()">Refresh</button>
   <input id="pe_filter" placeholder="filter type / detail…" style="width:220px"
     oninput="renderPersist()">
   <span id="pe_msg" class="muted"></span></div>
  <div id="pe_out"></div>
 </section>

 <section id="powershell" class="panel">
  <div class="help"><p>PowerShell <b>script blocks</b> (Operational <b>4104</b>),
  reassembled when logged in multiple parts. Type a string to find only the scripts
  that contain it (searches the whole reassembled script, so you don't have to read
  them all). Click a row to expand the script; click the script to jump to its event
  context. Needs PowerShell script-block logging enabled in the source host.</p></div>
  <div class="row">
   <input id="ps_q" placeholder="find text in script — e.g. DownloadString, -enc, Invoke-" style="width:360px"
     onkeydown="if(event.key==='Enter')loadPS()">
   <button class="bigbtn" onclick="loadPS()">Search</button>
   <button class="sec" onclick="document.getElementById('ps_q').value='';loadPS()">Clear</button>
   <span id="ps_msg" class="muted"></span></div>
  <div id="ps_out"></div>
 </section>

 <!-- ============ IOC EXTRACTOR ============ -->
 <section id="iocx" class="panel">
  <div class="help"><p>Automatically <b>extracts the IOCs present in the loaded EVTX</b> — IPv4/IPv6, domains, URLs, emails, user agents, hashes (MD5/SHA1/SHA256/imphash), file paths, registry keys, named pipes, services and scheduled tasks — grouped by type, with how many events each one appears in. Public IPs are tagged with their class and <b>ASN · Org</b>. Click any value to jump to its first event; export the lot as CSV or JSON. <i>(This is the reverse of <b>IOC sweep</b>, where you paste your own IOCs.)</i></p></div>
  <div class="row">
   <button class="bigbtn" onclick="loadIocx()" id="iocx_btn">Extract IOCs</button>
   <button class="sec" onclick="iocxExport('csv')" id="iocx_csv" disabled>Download CSV</button>
   <button class="sec" onclick="iocxExport('json')" id="iocx_json" disabled>Download JSON</button>
   <span id="iocx_msg" class="muted"></span>
  </div>
  <div class="row" id="iocx_filters" style="display:none;gap:8px;margin-top:4px;flex-wrap:wrap;align-items:center">
   <select id="iocx_type" onchange="iocxFilter()">
    <option value="">All types</option>
   </select>
   <input id="iocx_search" type="search" placeholder="filter values…" oninput="iocxFilter()">
   <button class="sec" style="font-size:12px;padding:3px 10px" onclick="iocxFilterReset()">Reset</button>
   <span id="iocx_filtermsg" class="muted" style="font-size:12px"></span>
  </div>
  <div id="iocx_out"></div>
 </section>

 <!-- ============ IOC SWEEP ============ -->
 <section id="ioc" class="panel">
  <div class="help"><p>Paste a list of <b>IOCs</b> — IPs, hashes, file names, domains, user names — one per line (or comma/semicolon separated) and sweep the whole dataset at once. Each IOC shows its hit count and a sample; the match looks across the relevant fields <i>and</i> the raw event, so the indicator is found wherever it appears. Click a row for its context, or &#10697; to copy the full event.</p></div>
  <div class="row" style="align-items:flex-start">
   <textarea id="ioc_in" placeholder="8.8.8.8&#10;mimikatz.exe&#10;e3b0c44298fc1c14...&#10;evil-domain.com&#10;IEUser" style="min-height:130px;width:380px"></textarea>
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
  <div class="help"><p>Network connectivity — Sysmon <b>EID3</b> (connections) and <b>22</b> (DNS) plus <b>native Windows</b> events: Filtering Platform <b>5156/5157</b> (allow/block) and <b>5158</b> (bind). Protocol and direction are normalized per source. Filter by IP/host, port, protocol, process or kind.</p></div>
  <div class="row">
   <input id="nw_ip" placeholder="IP / host / query" style="width:170px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <input id="nw_port" placeholder="port" style="width:90px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <input id="nw_proto" placeholder="proto (TCP/UDP)" style="width:140px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <input id="nw_img" placeholder="process" style="width:160px" onkeydown="if(event.key==='Enter')loadNetwork()">
   <select id="nw_kind"><option value="">any kind</option><option value="conn">conn</option><option value="dns">dns</option><option value="bind">bind</option><option value="blocked">blocked</option></select>
   <button class="bigbtn" onclick="loadNetwork()">Search</button>
   <button class="sec" onclick="clearNet()">Clear</button>
   <span id="nw_msg" class="muted"></span>
  </div>
  <div id="nw_out"></div>
 </section>

 <!-- ============ ATT&CK MATRIX ============ -->
 <section id="attack" class="panel">
  <div class="help"><p><b>ATT&amp;CK coverage</b> of this case, built from your matched <b>Sigma</b> rules across every loaded tab (Sigma + the LOL sets). Techniques are grouped by tactic; the number is the count of matching events, and the color is the worst rule level. Load your rules first, then build. Click a technique to jump to a sample event.</p></div>
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
   <p>EVTX records are normalized into one <code>events</code> table in <b>UTC</b>
   (System fields to columns, EventData promoted or kept in <code>extra</code>, full
   record in <code>raw</code>). For a full walkthrough see the separate user guide.</p>

   <h3>Load</h3>
   <ul>
    <li>Upload <code>.evtx</code>, a whole folder, or a <code>.zip</code>/<code>.tar.gz</code> (EVTX found recursively), or give a server path (live progress). EVTX timestamps are already UTC.</li>
    <li>Everything persists in a <code>.duckdb</code> case under <code>casos/</code>; reopen it later without re-ingesting.</li>
    <li>When reading from a <b>server path</b>, the progress bar advances <b>by bytes</b> (reading X / Y MB · %), so it moves <i>within</i> a single large <code>.evtx</code>, not just file by file. Records are inserted in batches as the file is read.</li>
   </ul>

   <h3>Explorer, Time range &amp; SQL</h3>
   <ul>
    <li>Search any text (IOC, IP, hash, command, Image). Multiple words = AND. Toggle <b>regex</b>. The <b>Channel</b> dropdown filters by source, and next to it the <b>EventID</b> dropdown filters by event ID (both default to <b>(all)</b>, are populated from what's loaded, and apply to <i>both</i> the search and the timeline).</li>
    <li><b>Filter by a field's content</b> with <code>field:value</code> (contains), e.g. <code>image:powershell</code>, <code>command_line:enc</code>, <code>src_ip:10.</code> (word form <code>image contains powershell</code> works too). <code>field=value</code> is an <b>exact</b> match (<code>eid=4688</code>), <code>field!=value</code> is <b>not equal</b>. <b>Exclude (NOT)</b> with a leading <code>-</code>: <code>-SYSTEM</code>, <code>-eid:4624</code>. Reach an EventData key with <code>x:TargetObject:Run</code> (PascalCase). <b>Regex per token</b>: <code>/regex/</code> over the raw record and <code>field:/regex/</code> on one field (e.g. <code>command_line:/-enc\s+\w+/</code>), combinable with fields and NOT. <b>Field exists / empty</b>: <code>field:*</code> = that field has a value (e.g. <code>logon_type:*</code>), <code>-field:*</code> (or <code>field:-</code>) = empty or missing. Mix freely: <code>image:powershell -user:SYSTEM eid=1</code>. A <b>«How to filter»</b> cheatsheet sits under the search box, which also <b>autocompletes field names</b>; the <b>regex</b> checkbox treats the whole box as one regex.</li>
    <li><b>Facets</b>: pick a field and click <b>Top values</b> for its most frequent values over the current results — click one to add it to the search (categorical fields like eid, user, image, src_ip, asn, org are the useful ones). The list is scrollable and has a <b>✕ hide</b>; it follows the <b>current view</b> — the <b>timeline</b> facets over everything (its channel/time filters), a <b>search</b> over its matches. <b>Recent &amp; saved searches</b> keeps your last queries and named ones (in this browser).</li>
    <li><b>Time range</b> (From / To, UTC) applies to <i>both</i> search and the full timeline, to scope a window.</li>
    <li>Click a row for its <b>context</b> (±N events). The <b>&#10697;</b> button on every row — and in the context header — copies the <b>full event JSON</b> to the clipboard; the <b>Structured event</b> modal shows the whole record to read and copy in full.</li>
    <li>The <b>Columns</b> panel shows first-class columns plus every <code>extra</code> (EventData) key — use its <b>filter</b> box. <b>EventID</b> and <b>Channel</b> are shown by default (key triage fields, EventID placed next to Channel). Two GeoIP columns — <b>ASN</b> (e.g. <code>AS3352</code>) and <b>Org/ISP</b> — are filled from the row's IP (SourceIp, else DestinationIp); they need the <b>ASN database</b> downloaded (Overview → <b>Update GeoIP database</b>) and only fill for public IPs. Only visible columns are rendered (fast with many events), and long cells are truncated (full value on hover). <b>&#8615; CSV</b> exports the loaded rows.</li>
    <li>SQL runs over <code>events</code>; reach EventData with <code>extra-&gt;&gt;'FieldName'</code>.</li>
   </ul>

   <h3>IOCs <span class="hintlbl">· extractor (discovered indicators)</span></h3>
   <ul>
    <li><b>Extracts the IOCs present in the loaded EVTX</b> — IPv4/IPv6, domains, URLs, emails, user agents, hashes (MD5/SHA1/SHA256/imphash), file paths, registry keys, named pipes, services and scheduled tasks — grouped by type, each with the number of events it appears in. Registry/pipe/service/task come from the parsed EventData fields; strict validation keeps the rest clean. Public IPs are tagged with their class and <b>ASN · Org</b>. Click a value to jump to its first event; export everything as CSV or JSON. It's the <b>reverse of IOC sweep</b>: the app discovers them for you.</li>
   </ul>

   <h3>IOC sweep</h3>
   <ul>
    <li>Paste a list of IOCs (one per line) — IPs, hashes, file names, domains, users — and sweep the whole dataset at once. Each IOC shows its hit count and a sample; the match covers the relevant fields <i>and</i> the raw event. IP IOCs are tagged <b>internal</b> or with their <b>ASN · Org/ISP</b>. Export the summary as CSV.</li>
   </ul>

   <h3>Sigma &amp; LOL (grouped under “Sigma &amp; LOL ▾”)</h3>
   <ul>
    <li><b>Sigma</b> runs your <i>general</i> ruleset. Windows taxonomy: <code>process_creation</code> → Sysmon EID1 + Security 4688; rules that filter by <code>Channel</code>/<code>EventID</code> work too. Rule <b>loading shows a progress bar</b> (file by file), and running shows per-rule progress.</li>
    <li><b>Expand a detection</b> to see the <b>full rule (YAML)</b> that fired and the <b>structured raw log</b> of the matching event. Every finding carries the triage buttons (<b>⎘ copy</b>, <b>view structured</b>, <b>mark</b>) and an <b>add to review</b> action — the same across the LOL tabs. On the <b>ATT&amp;CK</b> matrix each technique tile has a <b>&#43;</b> to send a sample of that technique to review. <b>Lookalike</b> aggregates by binary, so its mark button sends a <b>sample event</b> of that binary to review (clicking the row still pivots to the Explorer).</li>
    <li>Each <b>LOL</b> tab (LOLBAS/LOLDrivers/LOLRMM/HijackLibs/LOTTunnels) loads <b>its own rules folder</b> and shows findings + a chart of the top indicator by events that hit. <i>You provide the rules.</i></li>
    <li><b>ATT&amp;CK matrix</b>: coverage of the case built from your matched Sigma rules across every loaded set — techniques grouped by tactic, colored by level, click to jump to a sample event (rules need <code>attack.*</code> tags).</li>
    <li><b>Lookalike</b>: binaries within a Levenshtein distance of a legit one (cmd2.exe, svch0st.exe…), across <i>all</i> sources (Sysmon Image and Security 4688).</li>
   </ul>

   <h3>Hunting (grouped under “Hunting ▾”)</h3>
   <ul>
    <li><b>Proc tree</b> — Sigma <code>process_creation</code> (Sysmon EID1 <i>and</i> Security 4688), anchored on a PID / ProcessGuid / image; linked by GUID when present, else by PID.</li>
    <li><b>Logons</b> — the authentication family: Security logons, Kerberos (4768/4769/4771), NTLM (4776), RDP (4778/4779, TerminalServices 1149/21-25). Filter by user/type/source IP/workstation/auth/host.</li>
    <li><b>Persistence</b> — ~65 ASEP registry locations (Sysmon 12/13/14 and Security 4657), Startup &amp; dropped task XML (Sysmon 11), services (7045/4697/7040), scheduled tasks, WMI, accounts/groups, BITS.</li>
    <li><b>PowerShell</b> — 4104 script blocks, reassembled; type a string to find only the scripts that contain it, with the match highlighted.</li>
    <li><b>Network</b> — Sysmon EID3 + DNS 22 plus native Windows Filtering Platform (5156/5157 allow/block, 5158 bind); filter by IP/host, port, protocol, process or kind.</li>
   </ul>

   <h3>AI (grouped under “AI ▾”), Overview, Marks &amp; Report</h3>
   <ul>
    <li><b>AI (API)</b>, <b>AI (local)</b> and <b>MCP</b> are grouped under the AI parent tab.</li>
    <li><b>Overview</b>: tops (EventID, Image, host, user, logon type), source/destination IPs with GeoIP (internal/external, country · ASN · Org/ISP with DB-IP Lite). On startup GeoIP <b>auto-updates in the background</b> only if the base is missing or older than 30 days (silent without network).</li>
    <li><b>Marks</b>: triage events (pending/TP/FP/dismissed) saved in the case <code>.duckdb</code>. The <b>mark buttons appear in every detection view</b> (Sigma, LOL, Lookalike, ATT&amp;CK, Network, Logons, Persistence, Proc tree, IOC sweep); each mark from a detection <b>freezes a context of the 10 surrounding events</b> plus the rule/source, and marks can be <b>deleted with confirmation</b>. <b>Report</b>: self-contained HTML of the whole case.</li>
   </ul>

   <h3>SQL examples</h3>
   <pre>-- process creations with a suspicious parent
SELECT ts, host, image, command_line FROM events
WHERE eid=1 AND source LIKE '%Sysmon%'
  AND lower(parent_image) LIKE '%\\winword.exe' ORDER BY ts;

-- failed logons by source IP
SELECT src_ip, count(*) n FROM events
WHERE source='Security' AND eid=4625 GROUP BY src_ip ORDER BY n DESC;

-- a value from EventData (extra)
SELECT ts, image, extra-&gt;&gt;'TargetObject' AS target
FROM events WHERE eid=13 ORDER BY ts;</pre>
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
 &#128302; WinHound &middot; made by <b style="color:var(--accent)">gmzpt</b>
</footer>
<script>
function esc(v){if(v===null||v===undefined)return '<span class=muted>&#8709;</span>';return String(v).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
/* Celda truncada: muchas columnas (extra JSON, command_line, hashes) son muy
   largas; renderizarlas enteras x miles de filas satura el DOM y ralentiza la
   UI. Mostramos ~240 chars y dejamos el resto en el tooltip (title, ~4000). */
const CELL_MAX=240, CELL_TITLE_MAX=4000;
function tdCell(v,cls){
 const ca=cls?(' class="'+cls+'"'):'';
 if(v===null||v===undefined)return '<td'+ca+'><span class=muted>&#8709;</span></td>';
 const s=String(v);
 const disp=s.length>CELL_MAX?esc(s.slice(0,CELL_MAX))+'<span class="muted">…</span>':esc(s);
 const title=esc(s.length>CELL_TITLE_MAX?s.slice(0,CELL_TITLE_MAX)+'…':s);
 return '<td'+ca+' title="'+title+'">'+disp+'</td>';
}
/* Pestañas agrupadas: un padre en la barra superior abre una sub-barra con sus
   hijos, para que la barra no quede tan larga. */
const GROUPS={ai:['ai','ailocal','mcp'],
              sigma:['sigma','lol_lolbas','lol_loldrivers','lol_lolrmm','lol_hijacklibs','lol_lottunnels','lookalike','attack'],
              hunt:['proctree','logons','persist','powershell','network']};
let GROUP_LAST={ai:'ai', sigma:'sigma', hunt:'proctree'};
function groupOf(t){ for(const g in GROUPS){ if(GROUPS[g].includes(t)) return g; } return null; }
function openGroup(g){ switchTab(GROUP_LAST[g]||GROUPS[g][0]); }
function switchTab(t){
 const g=groupOf(t);
 if(g) GROUP_LAST[g]=t;
 document.querySelectorAll('.tab').forEach(x=>{
  const dt=x.dataset.tab;
  if(dt==='__ai') x.classList.toggle('active', g==='ai');
  else if(dt==='__sigma') x.classList.toggle('active', g==='sigma');
  else if(dt==='__hunt') x.classList.toggle('active', g==='hunt');
  else x.classList.toggle('active', dt===t);
 });
 document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('active',x.id===t));
 const sa=document.getElementById('subnav_ai'), sg=document.getElementById('subnav_sigma'), sh=document.getElementById('subnav_hunt');
 if(sa) sa.classList.toggle('hidden', g!=='ai');
 if(sg) sg.classList.toggle('hidden', g!=='sigma');
 if(sh) sh.classList.toggle('hidden', g!=='hunt');
 document.querySelectorAll('.subtab').forEach(x=>x.classList.toggle('active',x.dataset.tab===t));
 if(t==='mcp')loadMcpHelp();
 if(t==='sigma')sigmaInit();
 if(t==='dash' && !DASH_LOADED){ DASH_LOADED=true; loadDash(); geoStatus(); }
 if(t==='marks') loadMarks();
 if(t.indexOf('lol_')===0) buildLolTab(t.slice(4));
 if(t==='proctree' && !document.getElementById('pt_out').innerHTML) loadProctree();
 if(t==='logons' && !document.getElementById('lo_out').innerHTML) loadLogons();
 if(t==='persist' && !document.getElementById('pe_out').innerHTML) loadPersist();
 if(t==='powershell' && !document.getElementById('ps_out').innerHTML) loadPS();
 if(t==='network' && !document.getElementById('nw_out').innerHTML) loadNetwork();
 if(t==='attack' && !document.getElementById('at_out').innerHTML) loadAttack();
 if(t==='iocx' && !document.getElementById('iocx_out').innerHTML) loadIocx();
}
/* autocompletado de campos para la caja de búsqueda (sintaxis campo:valor) */
const QFIELDS=['source','host','eid','user','sid','src_ip','dst_ip','image','command_line','parent_image','original_filename','hashes','target_filename','image_loaded','logon_type','asn','org','level','message','ts'];
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
 const ee=document.getElementById('eid');
 // sigue la vista activa: en el timeline completo se ignora la caja (como el timeline)
 const qv=(LASTVIEW==='timeline')?'':document.getElementById('q').value.trim();
 const body={field, q:qv,
   regex:document.getElementById('rgx').checked,
   source:document.getElementById('src').value,
   eid:(ee&&ee.value&&ee.value!=='(all)')?ee.value:null,
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
  const esel=document.getElementById('eid');
  if(esel){ const ec=esel.value;
   esel.innerHTML='<option>(all)</option>'+(j.by_eid||[]).map(x=>'<option value="'+x.eid+'">'+x.eid+' ('+x.count+')</option>').join('');
   esel.value=ec; }
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
function uploadChunk(files,tz,onprog,opts){
 return new Promise((resolve,reject)=>{
  const xhr=new XMLHttpRequest();
  xhr.open('POST','/ingest/upload');
  xhr.upload.onprogress=e=>{ if(e.lengthComputable) onprog(e.loaded/e.total); };
  xhr.onload=()=>{ try{const j=JSON.parse(xhr.responseText); xhr.status<400?resolve(j):reject(j.detail||'error');}catch(_){reject('invalid response');} };
  xhr.onerror=()=>reject('network error');
  const fd=new FormData();
  for(const f of files){ fd.append('files',f); fd.append('relpaths', f.webkitRelativePath || f.name); }
  if(opts&&opts.ts_from) fd.append('ts_from_str',opts.ts_from);
  if(opts&&opts.ts_to)   fd.append('ts_to_str',opts.ts_to);
  xhr.send(fd);
 });
}
function clearPicks(){
 document.getElementById('files').value='';
 document.getElementById('folder').value='';
 document.getElementById('ingmsg').textContent='selection cleared';
}
function applyTsPreset(sfx,days){
 if(!days){document.getElementById('ts_from_'+sfx).value='';document.getElementById('ts_to_'+sfx).value='';return;}
 const now=new Date(),from=new Date(now-parseInt(days)*86400000);
 const fmt=d=>d.toISOString().slice(0,10);
 document.getElementById('ts_from_'+sfx).value=fmt(from);
 document.getElementById('ts_to_'+sfx).value=fmt(now);
 document.getElementById('ts_preset_'+sfx).value='';
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
 const t0=Date.now();
 msg.textContent='reading from disk: '+path+' … · started '+_clock(t0);
 prog.style.display=''; prog.value=0;
 let total=0, done=0, ev=0, ok=0, skip=0, err=0, totalBytes=0, bytesDone=0;
 const hb=n=>n>=1048576?(n/1048576).toFixed(1)+' MB':(n>=1024?(n/1024).toFixed(0)+' KB':n+' B');
 try{
  const tsFrom=(document.getElementById('ts_from_path')||{}).value||undefined;
  const tsTo=(document.getElementById('ts_to_path')||{}).value||undefined;
  const r=await fetch('/ingest/path/stream',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({path,ts_from:tsFrom,ts_to:tsTo})});
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
    if(x.progress_bytes!=null){ // progreso POR BYTES (incl. dentro de un .evtx)
     bytesDone=x.progress_bytes;
     if(totalBytes>0){ const p=Math.min(99,Math.round(bytesDone/totalBytes*100)); prog.value=p;
       msg.textContent='reading '+hb(bytesDone)+' / '+hb(totalBytes)+' · '+p+'% · '+ev+' events · '+ingClock(t0,bytesDone/totalBytes,true); }
     continue;
    }
    if(x.fatal){ INGESTED.push({file:path,error:x.fatal}); err++; done++; continue; }
    if(x.archive && x.events==null && x.error==null){ continue; } // contenedor: no cuenta
    INGESTED.push(x);
    if(x.events!=null){ok++; ev+=x.events; done++;}
    else if(x.skipped){skip++; done++;}
    else if(x.error){err++; done++;}
    let pct=null;
    if(totalBytes>0) pct=Math.min(99,Math.round(bytesDone/totalBytes*100));
    else if(total>0) pct=Math.min(99,Math.round(done/total*100));
    if(pct!=null) prog.value=pct;
    const denom=(total>0 && done<=total)?('/≈'+total):'';
    const fr=(totalBytes>0)?(bytesDone/totalBytes):(total>0?done/total:0);
    msg.textContent='processing '+done+denom+' files'+(pct!=null?' · '+pct+'%':'')+' · '+ev+' events · '+ingClock(t0,fr,true);
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
 const tz='0';
 const total=picks.length;
 const t0=Date.now();
 let done=0, ev=0, ok=0, skip=0, err=0;
 prog.style.display=''; prog.value=0;
 for(let i=0;i<picks.length;i+=UP_CHUNK){
  const chunk=picks.slice(i,i+UP_CHUNK);
  msg.textContent='uploading '+(done+1)+'-'+(done+chunk.length)+' / '+total+' files · '+ingClock(t0,done/total,false);
  try{
   const uTsFrom=(document.getElementById('ts_from_up')||{}).value||null;
  const uTsTo=(document.getElementById('ts_to_up')||{}).value||null;
  const j=await uploadChunk(chunk,tz,frac=>{ const f=(done+frac*chunk.length)/total; prog.value=Math.round(f*100);
     msg.textContent='uploading '+(done+1)+'-'+(done+chunk.length)+' / '+total+' files · '+Math.round(f*100)+'% · '+ingClock(t0,f,false); },{ts_from:uTsFrom,ts_to:uTsTo});
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
 const archived=INGESTED.filter(x=>x.archive && !x.error);
 // "No ingestado" = saltados (no .evtx, etc.) + con error de parseo
 const notIng =INGESTED.filter(x=>x.skipped!=null || x.error!=null);
 const totalEv=loaded.reduce((a,x)=>a+(x.events||0),0);
 let h='<div class="count">'+loaded.length+' loaded · '+totalEv.toLocaleString()+' events · '
      +notIng.length+' not ingested'+(archived.length?' · '+archived.length+' archives':'')+'</div>';
 // Cargados: colapsable (con 562 ficheros no debe dominar la vista)
 if(loaded.length){
  const open=loaded.length<=40?' open':'';
  h+='<details class="ingsec"'+open+'><summary class="st-ok">✓ Loaded ('+loaded.length+')</summary>'
    +'<div class="wrap"><table><thead><tr><th>file</th><th>events</th></tr></thead><tbody>';
  for(const x of loaded) h+='<tr><td title="'+esc(x.file)+'">'+esc(x.file)+'</td><td>'+esc(x.events)+'</td></tr>';
  h+='</tbody></table></div></details>';
 }
 if(archived.length){
  h+='<details class="ingsec"><summary class="st-arc">📦 Extracted archives ('+archived.length+')</summary>'
    +'<div class="wrap"><table><thead><tr><th>file</th></tr></thead><tbody>';
  for(const x of archived) h+='<tr><td>'+esc(x.archive)+'</td></tr>';
  h+='</tbody></table></div></details>';
 }
 // Tabla de NO ingestados, siempre al final (con el motivo por fichero)
 h+=secNotIngested(notIng);
 box.innerHTML=h;
}
function secNotIngested(list){
 if(!list.length) return '<h3 class="st-ok" style="margin-top:18px">Not ingested (0)</h3>'
   +'<p class="muted">Every file was ingested — nothing skipped or failed.</p>';
 let h='<h3 class="st-err" style="margin-top:18px">Not ingested ('+list.length+')</h3>'
   +'<div class="muted" style="margin-bottom:6px">Files that were skipped or failed to parse, with the reason for each.</div>'
   +'<div class="wrap"><table><thead><tr><th>file</th><th>status</th><th>reason</th></tr></thead><tbody>';
 for(const x of list){
  const name=x.file||x.archive||'';
  const isErr=x.error!=null;
  const reason=isErr?x.error:x.skipped;
  h+='<tr><td title="'+esc(name)+'">'+esc(name)+'</td>'
    +'<td><span class="'+(isErr?'st-err':'st-skip')+'">'+(isErr?'error':'skipped')+'</span></td>'
    +'<td title="'+esc(reason)+'">'+esc(reason)+'</td></tr>';
 }
 return h+'</tbody></table></div>';
}

/* Columnas mostradas en las tablas de resultados/timeline/contexto */
const BASECOLS=['seq','ts','source','eid','host','program','event','level','user','sid','src_ip','dst_ip','asn','org','image','command_line','parent_image','original_filename','hashes','target_filename','image_loaded','logon_type','record_id','message','extra','src_file'];
const LABELS={seq:'#',src_file:'file',src_ip:'SourceIp',dst_ip:'DestinationIp',asn:'ASN',org:'Org/ISP',command_line:'CommandLine',parent_image:'ParentImage',original_filename:'OriginalFileName',target_filename:'TargetFilename',image_loaded:'ImageLoaded',logon_type:'LogonType',record_id:'EventRecordID',eid:'EventID',source:'Channel',program:'Provider',image:'Image',hashes:'Hashes'};
function pageSize(){ const n=parseInt(document.getElementById('pagesize').value,10); return (Number.isInteger(n)&&n>0)?n:500; }
/* ---- columnas: orden + mostrar/ocultar (persistido en localStorage) ----
   Cada columna es un campo base (p.ej. 'status') o una clave dinámica de
   `extra` con prefijo 'x:' (p.ej. 'x:widget'), auto-descubierta de logs
   desconocidos (logfmt). Se pueden reordenar y ocultar. */
let COLS=loadOrder();
let XKEYS=[];                 // claves de extra ya descubiertas
let HIDDEN=loadHidden();
/* claves de localStorage propias de WinHound (no compartir con la app de Linux,
   que corre en el mismo 127.0.0.1 y pisaría el orden de columnas) */
function loadOrder(){ try{const a=JSON.parse(localStorage.getItem('winhound_colorder')||'null');
  if(Array.isArray(a)&&a.length){ for(const c of BASECOLS){ if(!a.includes(c)) a.push(c); } return a; }
 }catch(_){} return BASECOLS.slice(); }
function saveOrder(){ try{localStorage.setItem('winhound_colorder',JSON.stringify(COLS));}catch(_){} }
function loadHidden(){ try{return new Set(JSON.parse(localStorage.getItem('winhound_hidden')||'[]'));}catch(_){return new Set();} }
function saveHidden(){ try{localStorage.setItem('winhound_hidden',JSON.stringify([...HIDDEN]));}catch(_){} }
function isX(c){ return c.indexOf('x:')===0; }
function colLabel(c){ return isX(c)?c.slice(2):(LABELS[c]||c); }
function colClass(c){ return 'c-'+c.replace(/[^\w-]/g,'_'); }  // c-status / c-x_widget
/* Columnas que se RENDERIZAN como <td>: las base siempre (toggle vía CSS,
   instantáneo), y las dinámicas (x:) solo cuando están visibles. Antes se
   pintaban TODAS (incl. ~580 claves de extra ocultas) y se escondían por CSS:
   con muchos logs eran cientos de miles de <td> vacíos -> la UI iba lentísima.
   Ahora una fila típica pinta ~24 celdas en vez de ~600. */
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
   return '<div class="colchip '+(on?'on':'off')+'" data-n="'+esc(colLabel(c).toLowerCase())+'" onclick="clickCol(\''+c+'\')" title="'+(on?'hide':'show')+' '+lb+'">'
     +'<span class="coldot"></span><span class="collbl">'+lb+'</span>'+tag
     +'<span class="colmv">'+up+dn+'</span></div>';
 }).join('');
 p.innerHTML='<div class="colbtns">'
   +'<button class="sec" onclick="allCols(true)">Show all</button>'
   +'<button class="sec" onclick="allCols(false)">Hide all</button>'
   +'<button class="sec" onclick="hideEmptyCols()">Hide empty</button>'
   +'<button class="sec" onclick="resetCols()">Original order</button>'
   +'<input type="text" id="colsearch" placeholder="filter columns…" oninput="colFilter()" value="'+esc(COLQ)+'" style="min-width:160px">'
   +'<span class="colcount">'+shown+' of '+COLS.length+' columns visible</span></div>'
   +'<div class="colhint">Click a column to show or hide it · use &#9664; &#9654; to reorder · those tagged <span class="xtag">extra</span> come from the <code>extra</code> JSON (EVTX EventData). Use the filter — Windows has many keys.</div>'
   +'<div class="colgrid">'+chips+'</div>';
 if(COLQ) colFilter();
}
let COLQ='';
function colFilter(){
 const el=document.getElementById('colsearch'); if(el) COLQ=el.value;
 const q=(COLQ||'').toLowerCase();
 document.querySelectorAll('#colspanel .colchip').forEach(c=>{ c.style.display = c.dataset.n.includes(q)?'':'none'; });
}
function clickCol(c){ toggleCol(c, HIDDEN.has(c)); buildColsPanel(); }
/* oculta las columnas que están vacías en los resultados mostrados ahora */
function hideEmptyCols(){
 const rows=document.querySelectorAll('#hits table tbody tr');
 if(!rows.length)return;
 const cols=renderCols();           // sólo las visibles están pintadas
 cols.forEach((c,ci)=>{
  if(c==='seq'||c==='ts')return;
  let hasData=false;
  rows.forEach(tr=>{const td=tr.children[ci+1]; if(td){const t=td.textContent.trim(); if(t && t!=='∅') hasData=true;}});  // +1: celda de copiar
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
/* valor de una celda: campo base o clave de extra (x:) */
function cellVal(row,idx,c,xobj){ return isX(c) ? (xobj&&xobj[c.slice(2)]!=null?xobj[c.slice(2)]:'') : row[idx[c]]; }
function parseExtra(row,idx){ try{ return row[idx.extra]?JSON.parse(row[idx.extra]):null; }catch(_){ return null; } }
function rowCells(row,idx){
 const cols=renderCols();
 const needX=cols.some(isX); const xobj=needX?parseExtra(row,idx):null;
 return actCell(row[idx.id])+cols.map(c=>tdCell(cellVal(row,idx,c,xobj), colClass(c))).join('');
}
/* portapapeles robusto (clipboard API con fallback execCommand para http) */
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
/* añadir evento a revisar (marca 'pendiente' en Marks) desde cualquier vista;
   congela ~10 eventos de contexto, y la regla si se marcó desde una detección */
async function addReview(id,btn){
 const regla=(btn&&btn.dataset&&btn.dataset.regla)?btn.dataset.regla:null;
 try{ const r=await fetch('/marks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({event_id:id,estado:'pendiente',regla:regla,ctx_n:10})});
  flashBtn(btn, r.ok?'✓':'✗');
 }catch(e){ flashBtn(btn,'✗'); }
}
/* ver el evento ESTRUCTURADO en una ventana modal (funciona en tablas y fuera) */
async function showRaw(id){
 const ov=document.getElementById('rawmodal'); const pre=document.getElementById('rawmodalpre');
 pre.textContent='loading…'; ov.classList.remove('hidden'); ov.dataset.id=id;
 try{ const j=await (await fetch('/rawevent?id='+id)).json(); pre.textContent=(j.pretty||j.raw||'(no raw stored)'); }catch(e){ pre.textContent='error'; }
}
function closeRaw(){ document.getElementById('rawmodal').classList.add('hidden'); }
async function copyRawModal(btn){ const t=document.getElementById('rawmodalpre').textContent||''; flashBtn(btn,(await copyText(t))?'✓ copied':'✗'); }
/* botones de acción (copiar · revisar · ver evento). `regla` opcional para marcar con contexto de detección */
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
function csvTable(cols,rows,name){ if(!rows||!rows.length){return;} const text=[cols.map(csvCell).join(',')].concat(rows.map(r=>r.map(csvCell).join(','))).join('\n'); dlCSV(name||'export.csv',text); }
function csvObjs(headers,objs,name){ const text=[headers.map(csvCell).join(',')].concat(objs.map(o=>headers.map(k=>csvCell(o[k])).join(','))).join('\n'); dlCSV(name,text); }

/* ================= IOC extractor (discovered IOCs) ================= */
let IOCX=null;
async function loadIocx(){
 const out=document.getElementById('iocx_out'), msg=document.getElementById('iocx_msg'), btn=document.getElementById('iocx_btn');
 msg.textContent='extracting\u2026'; btn.disabled=true;
 // reset filtros al extraer de nuevo
 document.getElementById('iocx_type').value='';
 document.getElementById('iocx_search').value='';
 document.getElementById('iocx_filtermsg').textContent='';
 try{
  const r=await fetch('/iocs'); const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; btn.disabled=false; return; }
  IOCX=j; msg.textContent='';
  document.getElementById('iocx_csv').disabled=false; document.getElementById('iocx_json').disabled=false;
  if(!j.groups||!j.groups.length){ out.innerHTML='<p class="muted">No IOCs found in the loaded data.</p>'; btn.disabled=false; return; }
  // poblar el <select> con los tipos presentes
  const sel=document.getElementById('iocx_type');
  sel.innerHTML='<option value="">All types</option>';
  j.groups.forEach(g=>{ const o=document.createElement('option'); o.value=g.type; o.textContent=g.label+' ('+g.total+')'; sel.appendChild(o); });
  document.getElementById('iocx_filters').style.display='';
  let h='<div class="count">'+j.total+' distinct IOC(s) across '+j.groups.length+' type(s)</div>';
  h+='<div class="iocxchips">'+j.groups.map(g=>'<a class="iocxchip" href="#iocx_'+g.type+'" onclick="iocxOpen(event,\''+g.type+'\')">'+esc(g.label)+' <b>'+g.total+'</b></a>').join('')+'</div>';
  h+='<div class="row" style="margin:2px 0 6px"><button class="sec" onclick="iocxAll(1)">Expand all</button> <button class="sec" onclick="iocxAll(0)">Collapse all</button></div>';
  j.groups.forEach(function(g,gi){
   h+='<div class="iocard'+(gi===0?' open':'')+'" id="iocx_'+g.type+'" data-ioctype="'+g.type+'">'
     +'<div class="iohead iocxtoggle" onclick="this.parentNode.classList.toggle(\'open\')">'
     +'<span class="caret"></span> <b>'+esc(g.label)+'</b> '
     +'<span class="muted">\u00b7 <span class="iocx_count_'+g.type+'">'+g.total+'</span>'+(g.total>g.items.length?(' (showing '+g.items.length+')'):'')+'</span></div>';
   h+='<div class="iocxbody"><div class="wrap"><table><thead><tr><th class="acts"></th><th>value</th><th>events</th><th></th></tr></thead><tbody>';
   for(const it of g.items){
    let tag='';
    if(it.klass){ const cls=(it.klass==='external'?'ioctag-ext':(it.klass==='internal'?'ioctag-int':'ioctag-doc'));
      tag='<span class="ioctag '+cls+'">'+esc(it.klass)+'</span>'+(it.asn?(' <span class="muted">'+esc(it.asn)+(it.org?(' \u00b7 '+esc(it.org)):'')+(it.country?(' \u00b7 '+esc(it.country)):'')+'</span>'):''); }
    const safeVal=it.value.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    h+='<tr class="hitrow" data-iocval="'+esc(it.value).toLowerCase()+'">'
      +'<td class="acts"><button class="copybtn" title="copy value" onclick="event.stopPropagation();copyText(\''+safeVal+'\')">&#10697;</button></td>'
      +'<td class="iocval" onclick="iocxGoto('+it.id+')" title="jump to first event">'+esc(it.value)+' '+tag+'</td>'
      +'<td>'+it.count+'</td>'
      +'<td><button class="revbtn" title="add first event to review" onclick="event.stopPropagation();addReview('+it.id+',this)" data-regla="'+esc('IOC '+g.label+': '+it.value)+'">&#43;</button></td></tr>';
   }
   h+='</tbody></table></div></div></div>';
  });
  out.innerHTML=h;
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
 btn.disabled=false;
}
function iocxGoto(id){ switchTab('explorer'); openCtx(id); }
function iocxFilter(){
 if(!IOCX) return;
 const type=document.getElementById('iocx_type').value;
 const q=(document.getElementById('iocx_search').value||'').toLowerCase().trim();
 let visCards=0, visRows=0;
 document.querySelectorAll('#iocx_out .iocard[data-ioctype]').forEach(card=>{
  const ct=card.dataset.ioctype;
  const typeMatch=(!type||ct===type);
  if(!typeMatch){ card.classList.add('iocx-hidden'); return; }
  card.classList.remove('iocx-hidden');
  if(q){
   let rowsVisible=0;
   card.querySelectorAll('tbody tr').forEach(tr=>{
    const val=tr.dataset.iocval||'';
    if(val.includes(q)){ tr.classList.remove('iocx-hidden'); rowsVisible++; }
    else tr.classList.add('iocx-hidden');
   });
   if(rowsVisible===0){ card.classList.add('iocx-hidden'); return; }
   visRows+=rowsVisible;
  } else {
   card.querySelectorAll('tbody tr').forEach(tr=>tr.classList.remove('iocx-hidden'));
  }
  visCards++;
 });
 // actualizar chips activos
 document.querySelectorAll('.iocxchip').forEach(chip=>{
  const t=chip.getAttribute('href').replace('#iocx_','');
  chip.classList.toggle('active', !!type && t===type);
 });
 // mensaje de estado
 const fmsg=document.getElementById('iocx_filtermsg');
 if(!type && !q){ fmsg.textContent=''; return; }
 fmsg.textContent=visCards+' type(s)'+(q?' · '+visRows+' value(s)':'')+' matching';
}
function iocxFilterReset(){
 document.getElementById('iocx_type').value='';
 document.getElementById('iocx_search').value='';
 iocxFilter();
}
function iocxAll(open){ document.querySelectorAll('#iocx_out .iocard').forEach(c=>c.classList.toggle('open',!!open)); }
function iocxOpen(ev,type){ if(ev)ev.preventDefault(); const c=document.getElementById('iocx_'+type); if(c){ c.classList.add('open'); c.scrollIntoView({block:'start'}); } }
function iocxExport(fmt){
 if(!IOCX) return;
 if(fmt==='json'){ dlBlob('iocs.json', JSON.stringify(IOCX,null,2), 'application/json'); return; }
 let rows=[['type','value','events','class','asn','org','country','first_event_id','first_ts']];
 for(const g of IOCX.groups) for(const it of g.items)
   rows.push([g.type,it.value,it.count,it.klass||'',it.asn||'',it.org||'',it.country||'',it.id,it.ts||'']);
 const csv=rows.map(r=>r.map(c=>{c=String(c==null?'':c); return /[",\n]/.test(c)?('"'+c.replace(/"/g,'""')+'"'):c;}).join(',')).join('\n');
 dlBlob('iocs.csv', csv, 'text/csv');
}
function dlBlob(name,data,type){ try{ const b=new Blob([data],{type}); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(u),1500);}catch(e){} }

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
    h+='<div class="wrap"><table><thead><tr><th class="acts"></th><th>ts</th><th>eid</th><th>source</th><th>host</th><th>user</th><th>detail</th></tr></thead><tbody>';
    for(const x of r.hits){ h+='<tr class="hitrow" onclick="sigmaGoto('+x.id+')">'+actCell(x.id)+'<td>'+esc(x.ts)+'</td><td>'+esc(x.eid)+'</td><td>'+esc(x.source)+'</td><td>'+esc(x.host)+'</td><td>'+esc(x.user)+'</td><td class="sgmatch">'+esc((x.detail||'').slice(0,220))+'</td></tr>'; }
    h+='</tbody></table></div>';
    if(r.count>r.hits.length) h+='<div class="muted" style="padding:4px 2px">… '+(r.count-r.hits.length)+' more (showing first '+r.hits.length+')</div>';
   }
   h+='</div>';
  }
  out.innerHTML=h;
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}

/* ================= Network ================= */
let NET_ROWS=[];
function clearNet(){ for(const id of ['nw_ip','nw_port','nw_proto','nw_img']) document.getElementById(id).value=''; document.getElementById('nw_kind').value=''; loadNetwork(); }
async function loadNetwork(){
 const out=document.getElementById('nw_out'), msg=document.getElementById('nw_msg');
 const qs=new URLSearchParams();
 const m={ip:'nw_ip',port:'nw_port',proto:'nw_proto',image:'nw_img',kind:'nw_kind'};
 for(const k in m){ const el=document.getElementById(m[k]); const v=el?el.value.trim():''; if(v) qs.set(k,v); }
 msg.textContent='loading…';
 try{ const j=await (await fetch('/network'+(qs.toString()?'?'+qs:''))).json(); msg.textContent=''; NET_ROWS=j.rows||[];
  if(!NET_ROWS.length){ out.innerHTML='<p class="muted">No network events match.</p>'; return; }
  let h='<div class="count">'+NET_ROWS.length+' connection(s) '
    +'<button class="sec xcsv" onclick="csvObjs([\'ts\',\'kind\',\'eid\',\'proto\',\'direction\',\'src_ip\',\'src_port\',\'dst_ip\',\'dst_port\',\'hostname\',\'dns_result\',\'app\',\'host\',\'user\'],NET_ROWS,\'network.csv\')">&#8615; CSV</button></div>';
  h+='<div class="wrap wide"><table><thead><tr><th class="acts"></th><th>ts</th><th>kind</th><th>eid</th><th>proto</th><th>dir</th><th>src IP</th><th>sport</th><th>dst IP</th><th>dport</th><th>hostname / query</th><th>process</th><th>host</th><th>user</th></tr></thead><tbody>';
  for(const n of NET_ROWS){ h+='<tr class="hitrow'+(n.kind==='blocked'?' failrow':'')+'" onclick="sigmaGoto('+n.id+')">'+actCell(n.id)+'<td>'+esc(n.ts)+'</td><td>'+esc(n.kind)+'</td><td>'+esc(n.eid)+'</td><td>'+esc(n.proto)+'</td><td>'+esc(n.direction)+'</td><td>'+esc(n.src_ip)+'</td><td>'+esc(n.src_port)+'</td><td>'+esc(n.dst_ip)+'</td><td>'+esc(n.dst_port)+'</td><td>'+esc(n.hostname||n.dns_result)+'</td><td title="'+esc(n.app)+'">'+esc(base(n.app))+'</td><td>'+esc(n.host)+'</td><td>'+esc(n.user)+'</td></tr>'; }
  out.innerHTML=h+'</tbody></table></div>';
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}

/* ================= ATT&CK matrix ================= */
async function loadAttack(){
 const out=document.getElementById('at_out'), msg=document.getElementById('at_msg'),
       prog=document.getElementById('at_prog'), btn=document.getElementById('at_btn');
 msg.textContent='running Sigma across loaded rule sets…'; if(prog){prog.style.display='';prog.value=0;} if(btn)btn.disabled=true;
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
  if(!j.tactics||!j.tactics.length){ out.innerHTML='<p class="muted">No ATT&CK-tagged Sigma hits yet. Load rules in the <b>Sigma</b> / <b>LOL</b> tabs first — techniques come from the <code>attack.*</code> tags on each rule.</p>'; return; }
  let h='<div class="count">'+j.total_findings+' matched rule(s) across loaded sets · click a technique to jump to a sample event</div>';
  h+='<div class="attgrid">';
  for(const col of j.tactics){
   h+='<div class="attcol"><div class="atthead">'+esc(col.label)+' <span class="muted">('+col.techs.length+')</span></div>';
   for(const t of col.techs){
    const lv=t.level||'info';
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

/* rango temporal global (aplica a búsqueda y timeline) */
function trStart(){ return (document.getElementById('tstart')||{}).value?document.getElementById('tstart').value.trim():''; }
function trEnd(){ return (document.getElementById('tend')||{}).value?document.getElementById('tend').value.trim():''; }
function eidVal(){ const e=document.getElementById('eid'); const v=e?e.value:''; return (v&&v!=='(all)')?v:''; }
/* ---------- Explorador: búsqueda paginada ---------- */
let SE={q:'',regex:false,source:'',offset:0,total:0,start:'',end:'',cols:[],rows:[]};
/* ---------- Historial y búsquedas guardadas (localStorage namespaced) ---------- */
const QHIST_KEY='winhound_qhistory', QSAVED_KEY='winhound_qsaved';
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
 SE={q, regex:document.getElementById('rgx').checked, source:document.getElementById('src').value, eid:eidVal(), offset:0, total:0, start:trStart(), end:trEnd(), cols:[], rows:[]};
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
   body:JSON.stringify({q:SE.q,regex:SE.regex,source:SE.source,eid:SE.eid||null,limit:pageSize(),offset,sort:SORT.col,desc:SORT.desc,start:SE.start||null,end:SE.end||null})});
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
 TL={source:document.getElementById('src').value, eid:eidVal(), offset:0, total:0,
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
   body:JSON.stringify({source:TL.source,eid:TL.eid||null,limit:pageSize(),offset,start:TL.start||null,end:TL.end||null,sort:SORT.col,desc:SORT.desc})});
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
    +'<button class="sec" onclick="copyEvent('+id+',this)">&#10697; Copy event JSON</button>'
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
  for(const row of j.rows){h+='<tr>';for(const v of row)h+=tdCell(v,'');h+='</tr>'}
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
  msg.textContent='Enter the folder with your general Sigma rules and click Load.';
 }catch(e){ SIGMA_INIT=false; }
}
function sigmaSummary(info){
 const p=info.preview||{};
 let h='<div class="count">'+info.loaded+' rules loaded · <b>'+(p.aplicables||0)+' applicable</b>'
  +(p.correlacion?' ('+p.correlacion+' correlation)':'')
  +' · '+(p.sin_datos||0)+' no logsource data · '+(p.no_linux||0)+' non-Windows product (skipped)'
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
/* Carga de reglas en streaming con barra de progreso (reutilizable: Sigma y LOL).
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
  SIGMA_LAST=j;
  document.getElementById('sg_csvbtn').disabled=!j.findings.length;
  let h='<div class="count">'+j.findings.length+' rules with findings · '+j.total_hits+' events · '
   +j.applied+' rules run of '+j.rules_total+'</div>';
  if(!j.findings.length){ h+='<p class="muted">No findings. (Rules ran but no match.)</p>'; }
  else { h+=sgToggleBar(); h+=fcards(j); }
  out.innerHTML=h;
 }catch(e){ prog.style.display='none'; btn.disabled=false; msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
let SIGMA_LAST=null;
function sigmaExportCsv(){
 if(!SIGMA_LAST||!SIGMA_LAST.findings) return;
 // Cabecera del CSV
 const cols=[
  'rule_title','rule_id','rule_level','rule_tags','rule_logsource',
  'seq','event_id','ts','channel','provider','detail','src_file','what_matched','rule_yaml'
 ];
 const rows=[cols];
 for(const f of SIGMA_LAST.findings){
  const rtitle=f.title||'';
  const rid=f.id||'';
  const rlevel=f.level||'';
  const rtags=(f.tags||[]).join(' | ');
  const rls=f.logsource||'';
  const ryaml=f.yaml||'';
  if(f.correlation){
   // regla de correlación: columnas dinámicas — volcamos como JSON en 'detail'
   for(const row of f.hits){
    const sid=row[row.length-1];
    rows.push([rtitle,rid,rlevel,rtags,rls,
     '',''+sid,'','','',
     JSON.stringify(Object.fromEntries(f.columns.map((c,i)=>[c,row[i]]))),
     '','',ryaml]);
   }
  } else {
   // regla normal: row = [seq, id, ts, channel, provider, detail, src_file, what_matched]
   for(const row of f.hits){
    rows.push([rtitle,rid,rlevel,rtags,rls,
     ''+row[0],''+row[1],row[2]||'',row[3]||'',row[4]||'',
     row[5]||'',row[6]||'',row[7]||'',ryaml]);
   }
  }
 }
 const csv=rows.map(r=>r.map(c=>{
  c=String(c==null?'':c);
  return /[,"\n\r]/.test(c)?('"'+c.replace(/"/g,'""')+'"'):c;
 }).join(',')).join('\r\n');
 dlBlob('sigma_findings.csv','\uFEFF'+csv,'text/csv;charset=utf-8');
}
function hlKw(text, kws){
 let h=esc(text);
 for(const k of (kws||[])){ if(!k)continue; try{ const rx=new RegExp('('+k.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','ig'); h=h.replace(rx,'<mark>$1</mark>'); }catch(_){}}
 return h;
}
function sgExpandAll(){ document.querySelectorAll('#sg_out .sghits').forEach(e=>e.classList.remove('hidden')); }
function sgCollapseAll(){ document.querySelectorAll('#sg_out .sghits').forEach(e=>e.classList.add('hidden')); }
function sgToggleBar(){ return '<div class="row" style="margin:4px 0 8px"><button class="sec" onclick="sgExpandAll()">Expand all</button> <button class="sec" onclick="sgCollapseAll()">Collapse all</button></div>'; }
function sigmaGoto(id){ switchTab('explorer'); openCtx(id); }

/* ================= LOL tabs ================= */
const LOL_LABELS={lolbas:'LOLBAS',loldrivers:'LOLDrivers',lolrmm:'LOLRMM',hijacklibs:'HijackLibs',lottunnels:'LOTTunnels'};
const LOL_IND={lolbas:'binary',loldrivers:'driver',lolrmm:'tool',hijacklibs:'DLL',lottunnels:'tunnel tool'};
const LOL_BUILT={};
function buildLolTab(cat){
 if(LOL_BUILT[cat])return; LOL_BUILT[cat]=true;
 const lbl=LOL_LABELS[cat];
 document.getElementById('lol_'+cat).innerHTML=
  '<div class="help"><p>Load your <b>'+lbl+'</b> Sigma rules (your own folder) and run them. Findings show like the Sigma tab, plus a chart of the top '+LOL_IND[cat]+' by number of events that hit.</p></div>'
  +'<div class="aicfg"><label class="wide">rules folder on the server<input type="text" id="lol_'+cat+'_path" placeholder="path to your '+lbl+' Sigma rules"></label>'
  +'<button class="bigbtn" onclick="lolLoad(\''+cat+'\')">Load rules</button></div>'
  +'<div class="row"><button onclick="lolRun(\''+cat+'\')" id="lol_'+cat+'_runbtn" disabled>Run</button>'
  +'<progress id="lol_'+cat+'_prog" max="100" value="0" style="display:none;width:180px;vertical-align:middle"></progress>'
  +'<span id="lol_'+cat+'_msg" class="muted"></span></div>'
  +'<div id="lol_'+cat+'_chart"></div><div id="lol_'+cat+'_out"></div>';
}
async function lolLoad(cat){
 const path=document.getElementById('lol_'+cat+'_path').value.trim();
 if(!path){ document.getElementById('lol_'+cat+'_msg').innerHTML='<span class="err">Enter a rules folder.</span>'; return; }
 await streamRuleLoad('/sigma/load/stream?set='+cat, path, 'lol_'+cat+'_msg', 'lol_'+cat+'_prog', function(j){
  document.getElementById('lol_'+cat+'_runbtn').disabled=!(j.loaded>0);
  const pv=j.preview||{};
  document.getElementById('lol_'+cat+'_msg').textContent=j.loaded+' rules loaded · '+(pv.aplicables||0)+' applicable'+(j.errors&&j.errors.length?' · '+j.errors.length+' file errors':'');
 });
}
async function lolRun(cat){
 const msg=document.getElementById('lol_'+cat+'_msg'),out=document.getElementById('lol_'+cat+'_out'),chart=document.getElementById('lol_'+cat+'_chart'),btn=document.getElementById('lol_'+cat+'_runbtn'),prog=document.getElementById('lol_'+cat+'_prog');
 msg.textContent='running rules…'; if(prog){prog.style.display='';prog.value=0;} btn.disabled=true;
 let j=null;
 try{
  const r=await fetch('/lol/run/stream?cat='+cat,{method:'POST'});
  if(!r.ok){ let d=''; try{d=(await r.json()).detail;}catch(_){}
    if(prog)prog.style.display='none'; btn.disabled=false;
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
    if(x.fatal){ if(prog)prog.style.display='none'; btn.disabled=false;
      msg.innerHTML='<span class="err">'+esc(x.fatal)+'</span>'; return; }
    if(x.done){ j=x; continue; }
    if(prog&&x.total>0) prog.value=Math.round(x.i/x.total*100);
    msg.textContent='running rule '+x.i+'/'+x.total+' · '+x.found+' with findings…';
   }
  }
  if(prog){prog.value=100;prog.style.display='none';} btn.disabled=false;
  if(!j){ msg.innerHTML='<span class="err">incomplete response</span>'; return; }
  msg.textContent='';
  chart.innerHTML=lolChart(j.chart,j.indicator||LOL_IND[cat]);
  let h='<div class="count">'+j.findings.length+' rules with findings · '+j.total_hits+' events · '+j.applied+' rules run of '+j.rules_total+'</div>';
  if(!j.findings.length) h+='<p class="muted">No findings.</p>';
  else h+='<div class="row" style="margin:4px 0 8px"><button class="sec" onclick="lolExpand(\''+cat+'\',1)">Expand all</button> <button class="sec" onclick="lolExpand(\''+cat+'\',0)">Collapse all</button></div>';
  h+=fcards(j); out.innerHTML=h;
 }catch(e){ if(prog)prog.style.display='none'; btn.disabled=false; msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
function lolChart(chart,label){
 if(!chart||!chart.length) return '<p class="muted">No indicator hits.</p>';
 const max=Math.max.apply(null,chart.map(x=>x.n))||1;
 let h='<div class="dcard"><h3>Top '+esc(label)+' (events that hit)</h3>';
 for(const c of chart){ const pct=Math.max(2,Math.round(c.n/max*100));
  h+='<div class="dbar" style="cursor:default"><span class="dbk">'+esc(c.k)+'</span><span class="dbtrack"><span class="dbfill" style="width:'+pct+'%"></span></span><span class="dbn">'+c.n+'</span></div>'; }
 return h+'</div>';
}
function lolExpand(cat,open){ document.querySelectorAll('#lol_'+cat+'_out .sghits').forEach(e=>e.classList.toggle('hidden',!open)); }
function ruleYamlBlock(f){ return f.yaml ? '<details class="ruleyaml"><summary>&#9776; rule content (YAML)</summary><pre class="rawpre">'+esc(f.yaml)+'</pre></details>' : ''; }
function ruleLabel(f){ return (f.title||'rule')+(f.id?(' ['+f.id+']'):'')+(f.tags&&f.tags.length?(' · '+f.tags.join(' ')):''); }
function fcards(j){
 let h='';
 for(const f of j.findings){
  const sv=SEVCLASS[f.level]||'sev-info'; const rl=ruleLabel(f);
  h+='<div class="sgfind"><div class="sghead '+sv+'" onclick="this.parentNode.querySelector(\'.sghits\').classList.toggle(\'hidden\')">'
    +'<span class="sgsev">'+esc((f.level||'?').toUpperCase())+'</span> '+esc(f.title)
    +' <span class="muted">· '+esc(f.logsource)+' · ×'+f.count+(f.tags&&f.tags.length?' · '+f.tags.map(esc).join(' '):'')+'</span></div>';
  h+='<div class="sghits hidden">'+ruleYamlBlock(f)+'<div class="wrap"><table>';
  if(f.correlation){
   const nc=f.columns.length;
   h+='<thead><tr><th class="acts"></th>'+f.columns.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>';
   for(const row of f.hits){ const sid=row[row.length-1];
    h+='<tr class="hitrow" onclick="sigmaGoto('+sid+')">'+actCell(sid,rl)+row.slice(0,nc).map(v=>'<td>'+esc(v)+'</td>').join('')+'</tr>'; }
  }else{
   h+='<thead><tr><th class="acts"></th><th>#</th><th>ts</th><th>channel</th><th>provider</th><th>detail</th><th>what matched</th></tr></thead><tbody>';
   for(const row of f.hits){
    h+='<tr class="hitrow" onclick="sigmaGoto('+row[1]+')">'+actCell(row[1],rl)+'<td>'+esc(row[0])+'</td><td>'+esc(row[2])+'</td><td>'+esc(row[3])+'</td><td>'+esc(row[4])+'</td><td title="'+esc(row[5])+'">'+hlKw(row[5],f.keywords)+'</td><td class="sgmatch" title="'+esc(row[7]||'')+'">'+esc(row[7]||'')+'</td></tr>'; }
   if(f.count>f.hits.length) h+='<tr><td colspan="7" class="muted">… '+(f.count-f.hits.length)+' more (sample limited)</td></tr>';
  }
  h+='</tbody></table></div></div></div>';
 }
 return h;
}
/* ================= Lookalike (Levenshtein) ================= */
async function lkRun(){
 const msg=document.getElementById('lk_msg'),out=document.getElementById('lk_out');
 const dist=document.getElementById('lk_dist').value, seen=document.getElementById('lk_seen').checked?1:0;
 msg.textContent='searching…';
 try{
  const r=await fetch('/lookalike?dist='+dist+'&also_seen='+seen); const j=await r.json();
  if(!r.ok){ msg.innerHTML='<span class="err">'+esc(j.detail||'error')+'</span>'; return; }
  msg.textContent='';
  if(!j.matches.length){ out.innerHTML='<p class="muted">No lookalike binaries within distance '+esc(dist)+' (checked against '+j.refs+' reference binaries).</p>'; return; }
  let h='<div class="count">'+j.matches.length+' lookalike candidate(s) · distance ≤ '+esc(dist)+' · '+j.refs+' reference binaries</div>';
  h+='<div class="wrap"><table><thead><tr><th class="acts"></th><th>suspicious binary</th><th>events</th><th>looks like</th><th>distance</th><th>source</th></tr></thead><tbody>';
  for(const m of j.matches){
   const act=(m.id!=null)?actCell(m.id,'Lookalike '+m.name+' ~ '+m.ref):'<td class="acts"></td>';
   h+='<tr class="hitrow" data-n="'+esc(m.name)+'" onclick="goExplore(this.dataset.n)">'+act+'<td class="sgmatch">'+esc(m.name)+'</td><td>'+m.count+'</td><td>'+esc(m.ref)+'</td><td>'+m.dist+'</td><td class="muted">'+(m.kind==='seen'?'seen vs seen':'reference')+'</td></tr>'; }
  h+='</tbody></table></div>'; out.innerHTML=h;
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}

/* ================= Phase 2: advanced views ================= */
function base(s){ return (s||'').split(/[\\\/]/).pop(); }
let PT_HL={};
function ptHit(n){ return (PT_HL.guid&&n.guid===PT_HL.guid)
  ||(PT_HL.pid&&String(n.pid)===String(PT_HL.pid))
  ||(PT_HL.img&&(n.image||'').toLowerCase().indexOf(PT_HL.img.toLowerCase())>=0); }
async function loadProctree(anchorGuid){
 const out=document.getElementById('pt_out'), msg=document.getElementById('pt_msg');
 const an=document.getElementById('pt_anchors');
 const pid=document.getElementById('pt_pid').value.trim();
 const img=document.getElementById('pt_img').value.trim();
 let guid=document.getElementById('pt_guid').value.trim();
 if(anchorGuid){ guid=anchorGuid; document.getElementById('pt_guid').value=anchorGuid; }
 const qs=new URLSearchParams();
 if(guid) qs.set('guid',guid);
 else if(pid) qs.set('pid',pid);
 else if(img) qs.set('image',img);
 if(!Array.from(qs.keys()).length){
  an.innerHTML=''; out.innerHTML='<p class="muted">Enter a <b>PID</b>, <b>ProcessGuid</b> or <b>image name</b> above, then &laquo;Build tree&raquo;.</p>'; return; }
 PT_HL={guid:guid||'', pid:guid?'':pid, img:guid?'':img};
 msg.textContent='loading…';
 try{ const j=await (await fetch('/proctree?'+qs.toString())).json(); msg.textContent='';
  // anchor picker when a PID/image matches several distinct processes
  if(!guid && j.anchors && j.anchors.length>1){
   an.innerHTML='<div class="count">'+j.anchors.length+' processes match — «pin» one for just its tree, or scroll down for the combined view:</div>'
     +'<div class="wrap"><table><thead><tr><th>ts</th><th>image</th><th>pid</th><th>user</th><th>host</th><th></th></tr></thead><tbody>'
     +j.anchors.map(a=>'<tr class="hitrow"><td>'+esc(a.ts)+'</td><td>'+esc(base(a.image))+' <span class="ptsrc">'+(a.eid===1?'sysmon':a.eid)+'</span></td><td>'+esc(a.pid)+'</td><td>'+esc(a.user)+'</td><td>'+esc(a.host)+'</td>'
        +'<td><button class="sec" onclick="pinProc('+a.id+')">pin this</button></td></tr>').join('')
     +'</tbody></table></div>';
  } else { an.innerHTML=''; }
  if(!j.roots.length){ out.innerHTML='<p class="muted">No process matches that anchor (Sysmon EID1 or Security 4688).</p>'; return; }
  out.innerHTML='<div class="ptree">'+j.roots.map(ptNode).join('')+'</div>';
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
async function pinProc(id){
 const out=document.getElementById('pt_out'), msg=document.getElementById('pt_msg'), an=document.getElementById('pt_anchors');
 msg.textContent='loading…';
 try{ const j=await (await fetch('/proctree?node='+encodeURIComponent(id))).json(); msg.textContent='';
  an.innerHTML='<div class="count">Pinned process #'+esc(id)+' — <a href="#" onclick="loadProctree();return false">back to all matches</a></div>';
  if(!j.roots.length){ out.innerHTML='<p class="muted">That process has no tree.</p>'; return; }
  out.innerHTML='<div class="ptree">'+j.roots.map(ptNode).join('')+'</div>';
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
function ptNode(n){
 const kids=n.children&&n.children.length;
 const hl=ptHit(n)?' pthit':'';
 const src=n.eid===1?'sysmon':(n.eid===4688?'4688':(n.eid||''));
 const head='<span class="ptrow'+hl+'">'+actInline(n.id)+'<span class="ptbin'+hl+'" onclick="event.stopPropagation();sigmaGoto('+n.id+')" title="go to context">'+esc(base(n.image)||'?')+'</span>'
   +(src?'<span class="ptsrc">'+esc(src)+'</span>':'')
   +'<span class="ptpid">pid '+esc(n.pid||'?')+'</span>'
   +'<span class="ptcmd">'+esc((n.cmd||'').slice(0,160))+'</span>'
   +'<span class="muted ptmeta">'+esc(n.user||'')+(n.ts?' · '+esc(n.ts):'')+'</span></span>';
 if(kids) return '<details open class="ptnode"><summary>'+head+' <span class="muted">('+kids+')</span></summary>'+n.children.map(ptNode).join('')+'</details>';
 return '<div class="ptleaf">'+head+'</div>';
}
function ptAll(open){ document.querySelectorAll('#pt_out details').forEach(d=>d.open=!!open); }
function clearLogons(){ for(const id of ['lo_user','lo_type','lo_src','lo_ws','lo_auth','lo_host']) document.getElementById(id).value=''; loadLogons(); }
async function loadLogons(){
 const out=document.getElementById('lo_out'), msg=document.getElementById('lo_msg');
 const qs=new URLSearchParams();
 const map={user:'lo_user',logon_type:'lo_type',src_ip:'lo_src',workstation:'lo_ws',auth:'lo_auth',host:'lo_host'};
 for(const k in map){ const v=document.getElementById(map[k]).value.trim(); if(v) qs.set(k,v); }
 const filtered=Array.from(qs.keys()).length>0;
 msg.textContent='loading…';
 try{ const j=await (await fetch('/logons'+(filtered?'?'+qs.toString():''))).json(); msg.textContent='';
  if(!j.logons.length){ out.innerHTML='<p class="muted">No logon/auth events match'+(filtered?' those filters.':' (Security 4624/4625/Kerberos/NTLM/RDP).')+'</p>'; return; }
  let h='<div class="count">'+j.logons.length+' logon/auth events'+(filtered?' (filtered)':'')+'</div><div class="wrap"><table><thead><tr><th class="acts"></th><th>ts</th><th>eid</th><th>action</th><th>user</th><th>type</th><th>source IP</th><th>workstation</th><th>auth</th><th>host</th></tr></thead><tbody>';
  for(const l of j.logons){ h+='<tr class="hitrow'+(l.failed?' failrow':'')+'" onclick="sigmaGoto('+l.id+')">'+actCell(l.id)+'<td>'+esc(l.ts)+'</td><td>'+esc(l.eid)+'</td><td>'+esc(l.action)+'</td><td>'+esc(l.user)+'</td><td>'+esc(l.logon_type)+'</td><td>'+esc(l.src_ip)+'</td><td>'+esc(l.workstation)+'</td><td>'+esc(l.auth_pkg)+'</td><td>'+esc(l.host)+'</td></tr>'; }
  out.innerHTML=h+'</tbody></table></div>';
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
let PERSIST_ITEMS=[];
async function loadPersist(){
 const out=document.getElementById('pe_out'), msg=document.getElementById('pe_msg');
 msg.textContent='loading…';
 try{ const j=await (await fetch('/persistence')).json(); msg.textContent='';
  PERSIST_ITEMS=j.items||[]; renderPersist();
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
}
function renderPersist(){
 const out=document.getElementById('pe_out');
 const fEl=document.getElementById('pe_filter'); const f=(fEl?fEl.value.trim().toLowerCase():'');
 let items=PERSIST_ITEMS;
 if(f) items=items.filter(i=>((i.ptype||'')+' '+(i.detail||'')+' '+(i.actor||'')+' '+(i.user||'')+' '+(i.eid||'')).toLowerCase().indexOf(f)>=0);
 if(!PERSIST_ITEMS.length){ out.innerHTML='<p class="muted">No persistence signals found.</p>'; return; }
 if(!items.length){ out.innerHTML='<p class="muted">No persistence signals match that filter.</p>'; return; }
 let h='<div class="count">'+items.length+' persistence signal(s)'+(f?' (filtered of '+PERSIST_ITEMS.length+')':'')+'</div><div class="wrap"><table><thead><tr><th class="acts"></th><th>ts</th><th>type</th><th>eid</th><th>detail</th><th>actor</th><th>user</th><th>host</th></tr></thead><tbody>';
 for(const i of items){ h+='<tr class="hitrow" onclick="sigmaGoto('+i.id+')">'+actCell(i.id)+'<td>'+esc(i.ts)+'</td><td><b>'+esc(i.ptype)+'</b></td><td>'+esc(i.eid)+'</td><td class="sgmatch">'+esc(i.detail)+'</td><td>'+esc(base(i.actor))+'</td><td>'+esc(i.user)+'</td><td>'+esc(i.host)+'</td></tr>'; }
 out.innerHTML=h+'</tbody></table></div>';
}
/* resalta las apariciones (literal, case-insensitive) de q en el texto, escapando HTML */
function hlMark(text,q){
 const t=String(text||''); if(!q) return esc(t);
 const lt=t.toLowerCase(), lq=q.toLowerCase(); let i=0,pos,h='';
 while((pos=lt.indexOf(lq,i))>=0){ h+=esc(t.slice(i,pos))+'<mark>'+esc(t.slice(pos,pos+lq.length))+'</mark>'; i=pos+lq.length; }
 return h+esc(t.slice(i));
}
/* fragmento alrededor de la 1ª aparición de q, con la coincidencia resaltada */
function psSnippet(text,q){
 const t=String(text||''); const lt=t.toLowerCase(), lq=q.toLowerCase();
 const pos=lt.indexOf(lq); if(pos<0) return esc(t.slice(0,160))+(t.length>160?'…':'');
 const a=Math.max(0,pos-60), b=Math.min(t.length,pos+lq.length+90);
 return (a>0?'…':'')+esc(t.slice(a,pos))+'<mark>'+esc(t.slice(pos,pos+lq.length))+'</mark>'+esc(t.slice(pos+lq.length,b))+(b<t.length?'…':'');
}
async function loadPS(){
 const out=document.getElementById('ps_out'), msg=document.getElementById('ps_msg');
 const q=(document.getElementById('ps_q').value||'').trim();
 msg.textContent='loading…';
 try{
  const j=await (await fetch('/powershell'+(q?('?q='+encodeURIComponent(q)):''))).json();
  msg.textContent='';
  if(!j.scripts.length){ out.innerHTML='<p class="muted">'+(q?('No script blocks contain “'+esc(q)+'”.'):'No PowerShell 4104 script blocks (script-block logging not present in this data).')+'</p>'; return; }
  let h='<div class="count">'+j.scripts.length+' script block(s)'+(q?(' matching “'+esc(q)+'”'):'')+'</div>';
  for(const s of j.scripts){
   const txt=s.text||'';
   const prev = q ? psSnippet(txt,q) : (esc(txt.slice(0,160))+(txt.length>160?'…':''));
   h+='<div class="sgfind"><div class="sghead sev-info" onclick="this.parentNode.querySelector(\'.sghits\').classList.toggle(\'hidden\')">'
     +actInline(s.id)+'<span class="muted">'+esc(s.ts||'')+' · '+esc(s.host||'')+' · '+esc(s.user||'')+' · '+esc(base(s.path)||'script')+(s.parts>1?' · '+s.parts+' parts':'')+'</span>'
     +'<div class="psprev">'+prev+'</div></div>'
     +'<div class="sghits'+(q?'':' hidden')+'"><pre class="sgsql" title="click to open event context" onclick="sigmaGoto('+s.id+')">'+hlMark(txt,q)+'</pre></div></div>';
  }
  out.innerHTML=h;
 }catch(e){ msg.innerHTML='<span class="err">'+esc(e)+'</span>'; }
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
   +'<div class="dtile"><div class="v">'+(d.source||0)+'</div><div class="l">channels</div></div>'
   +'<div class="dtile"><div class="v">'+(d.host||0)+'</div><div class="l">hosts</div></div>'
   +'<div class="dtile"><div class="v">'+(d.user||0)+'</div><div class="l">users</div></div>'
   +'<div class="dtile"><div class="v">'+(d.ip||0)+'</div><div class="l">distinct IPs</div></div>'
   +'<div class="dtile" style="flex:2;min-width:240px"><div class="l">time range (UTC)</div><div class="sub">'+esc(rango)+'</div></div>'
   +'</div>';
  h+=dHist(j.hist);
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Top EventIDs</h3>'+dBars(j.top_eid)+'</div>'
   +'<div class="dcard"><h3>Top images</h3>'+dBars(j.top_image)+'</div></div>';
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Top users</h3>'+dBars(j.top_user)+'</div>'
   +'<div class="dcard"><h3>Top hosts</h3>'+dBars(j.top_host)+'</div></div>';
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Top destination IPs</h3>'+dBars(j.top_dst_ip,'ip')+'</div>'
   +'<div class="dcard"><h3>Top source IPs</h3>'+dBars(j.top_src_ip,'ip')+'</div></div>';
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Top ISP / operator</h3>'+dBars(j.top_isp,null,false)+'</div>'
   +'<div class="dcard"><h3>Top countries</h3>'+dBars(j.top_country,null,false)+'</div></div>';
  h+='<div class="dcols">'
   +'<div class="dcard"><h3>Events by channel</h3>'+dBars(j.by_source)+'</div>'
   +'<div class="dcard"><h3>Logon types</h3>'+dBars(j.top_logon)+'</div></div>';
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
buildColsPanel();applyCols();fillEx();init();
</script>
</body></html>"""
