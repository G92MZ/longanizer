#!/usr/bin/env python3
"""Arranca el servicio web.

  python run.py                         # en memoria, http://127.0.0.1:8000
  python run.py --port 8001             # otro puerto (p.ej. 2 apps a la vez)
  python run.py --host 0.0.0.0 --port 9000
  python run.py --db caso.duckdb        # persiste el caso en fichero

También valen las variables de entorno HOST, PORT y DUCKDB_PATH (los
argumentos tienen prioridad). Para cargar logs al arrancar sin tocar la API,
usa el CLI: python -m loganalyzer.cli
"""
import argparse
import os

import uvicorn

if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="run.py", description="Servicio web Longanizer")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"),
                    help="interfaz de escucha (por defecto 127.0.0.1)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")),
                    help="puerto (por defecto 8000; cámbialo para tener varias apps a la vez)")
    ap.add_argument("--db", default=None,
                    help="ruta del caso DuckDB (por defecto en memoria); equivale a DUCKDB_PATH")
    args = ap.parse_args()

    if args.db:
        os.environ["DUCKDB_PATH"] = args.db

    uvicorn.run(
        "loganalyzer.app:app",
        host=args.host,
        port=args.port,
        reload=False,
    )
