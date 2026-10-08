"""CLI para ingesta rápida y consola SQL sin levantar la web.

  python -m loganalyzer.cli ingest /ruta/logs --db caso.duckdb
  python -m loganalyzer.cli ingest auth.log --type auth --year 2026
  python -m loganalyzer.cli sql "SELECT ..." --db caso.duckdb
  python -m loganalyzer.cli shell --db caso.duckdb   # consola interactiva
"""
from __future__ import annotations

import argparse
import json
import sys

from .store import EventStore
from .ingest import ingest_path
from .detect import detect_by_name, sniff_content, detect_type


def main(argv=None):
    p = argparse.ArgumentParser(prog="loganalyzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ingest", help="Cargar fichero o carpeta de logs")
    pi.add_argument("path")
    pi.add_argument("--type", default=None, help="fuerza tipo (auth, syslog, kern, cron, access, auditd, weberror, logfmt, applog, bash_history)")
    pi.add_argument("--year", type=int, default=None, help="año base para logs syslog sin año")
    pi.add_argument("--user", default=None, help="usuario para bash_history")
    pi.add_argument("--tz", type=int, default=0, metavar="MIN",
                    help="offset en minutos de la zona de la máquina para logs syslog (ej. 120 para CEST)")
    pi.add_argument("--db", default=":memory:")

    pq = sub.add_parser("sql", help="Ejecutar una consulta")
    pq.add_argument("query")
    pq.add_argument("--db", default=":memory:")
    pq.add_argument("--limit", type=int, default=100)

    ps = sub.add_parser("shell", help="Consola SQL interactiva")
    ps.add_argument("--db", default=":memory:")

    st = sub.add_parser("stats", help="Resumen de lo cargado")
    st.add_argument("--db", default=":memory:")

    pd = sub.add_parser("detect", help="Mostrar el tipo detectado por fichero (sin ingestar)")
    pd.add_argument("path")

    pm = sub.add_parser("mcp", help="Arrancar el servidor MCP (stdio) sobre --db")
    pm.add_argument("--db", default=":memory:")

    args = p.parse_args(argv)

    if args.cmd == "detect":
        _detect(args.path)
        return

    if args.cmd == "mcp":
        import os
        os.environ["DUCKDB_PATH"] = args.db
        from . import mcp_server
        mcp_server.main()
        return

    store = EventStore(args.db)

    if args.cmd == "ingest":
        res = ingest_path(store, args.path, args.type, args.year, args.user, args.tz)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        print(json.dumps(store.stats(), indent=2, ensure_ascii=False, default=str))
    elif args.cmd == "sql":
        r = store.query(args.query, limit=args.limit)
        _print_table(r)
    elif args.cmd == "stats":
        print(json.dumps(store.stats(), indent=2, ensure_ascii=False, default=str))
    elif args.cmd == "shell":
        _shell(store)


def _detect(path):
    import os
    files = []
    if os.path.isdir(path):
        for root, _, fns in os.walk(path):
            files.extend(os.path.join(root, f) for f in sorted(fns))
    else:
        files = [path]
    print(f"{'fichero':30} {'por_nombre':13} {'por_contenido':14} {'final'}")
    print("-" * 72)
    for fp in files:
        name = detect_by_name(fp) or "-"
        content = sniff_content(fp) or "-"
        final = detect_type(fp) or "??? (usa --type)"
        print(f"{os.path.basename(fp):30} {name:13} {content:14} {final}")


def _print_table(r):
    cols = r["columns"]
    print(" | ".join(cols))
    print("-" * 60)
    for row in r["rows"]:
        print(" | ".join("∅" if v is None else str(v) for v in row))
    print(f"({r['rowcount']} filas)")


def _shell(store):
    print("Consola SQL DuckDB (tabla: events). Vacío o 'exit' para salir.")
    while True:
        try:
            q = input("sql> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not q or q.lower() in ("exit", "quit", "\\q"):
            break
        try:
            _print_table(store.query(q, limit=200))
        except Exception as e:  # noqa: BLE001
            print(f"error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
