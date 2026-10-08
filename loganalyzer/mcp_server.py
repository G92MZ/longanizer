"""Servidor MCP para LogAnalyzer forense.

Expone los logs cargados como herramientas MCP de SOLO LECTURA, para que un
cliente MCP (Claude Desktop, Claude Code, u otro) pueda consultarlos en
lenguaje natural sin pasar por la API web.

Uso (stdio, lo habitual para Claude Desktop/Code):

    DUCKDB_PATH=/ruta/al/caso.duckdb python -m loganalyzer.mcp_server

Comparte el MISMO almacén DuckDB que la web mediante la variable de entorno
`DUCKDB_PATH`. Si usas `:memory:` (por defecto) cada proceso tiene sus propios
datos; para analizar un caso con MCP, arranca la web/ingesta con un fichero
.duckdb y apunta el servidor MCP a ese mismo fichero.

Herramientas:
  - buscar_logs(q, regex?, source?, limit?)
  - consulta_sql(sql)            # solo lectura (SELECT/WITH/…)
  - contexto(seq?/id?, before?, after?, unit?)
  - estadisticas()
  - ver_timeline(source?, start?, end?, limit?)
"""
from __future__ import annotations

import os
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .store import EventStore

_DB = os.environ.get("DUCKDB_PATH", ":memory:")
STORE = EventStore(_DB)
MAX_ROWS = 200

mcp = FastMCP("longanizer")


def _trim(res: dict) -> dict:
    rows = res.get("rows", [])
    out = {"columns": res.get("columns", []), "rows": rows[:MAX_ROWS],
           "rowcount": res.get("rowcount", len(rows))}
    if res.get("total") is not None:
        out["total"] = res["total"]
    if len(rows) > MAX_ROWS:
        out["note"] = f"Mostrando {MAX_ROWS} de {len(rows)} filas."
    elif res.get("note"):
        out["note"] = res["note"]
    return out


@mcp.tool()
def buscar_logs(q: str, regex: bool = False, source: Optional[str] = None,
                limit: int = 100) -> dict:
    """Busca eventos por texto (substring/IOC) o regex en los logs cargados.

    q: texto o patrón; regex: tratar q como expresión regular;
    source: filtrar por origen (auth, access, auditd, syslog, weberror, logfmt…).
    """
    return _trim(STORE.search(q, regex=regex, source=source or None,
                              limit=min(int(limit), MAX_ROWS), offset=0))


@mcp.tool()
def consulta_sql(sql: str) -> dict:
    """Ejecuta SQL de SOLO LECTURA (SELECT/WITH/DESCRIBE/SUMMARIZE) sobre la
    tabla `events` (DuckDB). La columna `extra` es JSON: usa (extra->>'clave')."""
    return _trim(STORE.query(sql, limit=MAX_ROWS))


@mcp.tool()
def contexto(seq: Optional[int] = None, id: Optional[int] = None,
             before: float = 5, after: float = 5, unit: str = "lines") -> dict:
    """Líneas alrededor de un evento. Ancla por seq (posición en la timeline,
    1=más antiguo) o por id interno. unit: 'lines' | 'minutes' | 'seconds'."""
    return _trim(STORE.context(row_id=id, seq=seq, before=before, after=after,
                               unit=unit))


@mcp.tool()
def estadisticas() -> dict:
    """Resumen: total de eventos, por origen (con rango temporal) y claves
    dinámicas presentes en `extra`."""
    return STORE.stats()


@mcp.tool()
def ver_timeline(source: Optional[str] = None, start: Optional[str] = None,
                 end: Optional[str] = None, limit: int = 100) -> dict:
    """Eventos en orden cronológico (con su seq). Filtros opcionales por origen
    y rango temporal UTC (start/end, 'YYYY-MM-DD HH:MM:SS')."""
    return _trim(STORE.timeline(source=source or None, start=start or None,
                                end=end or None,
                                limit=min(int(limit), MAX_ROWS), offset=0))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
