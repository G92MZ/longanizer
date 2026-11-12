#!/usr/bin/env python3
"""Arranca el servicio web.

  python run.py                         # en memoria, accesible desde la red (puerto 8000)
  python run.py --port 8001             # otro puerto (p.ej. 2 apps a la vez)
  python run.py --host 127.0.0.1        # solo accesible desde este equipo
  python run.py --db caso.duckdb        # persiste el caso en fichero
  python run.py --no-update             # no comprobar actualizaciones al arrancar

Al arrancar comprueba si hay una versión más nueva en GitHub y, si la hay, te
pregunta si quieres instalarla (usa update.py por debajo). Con --yes se instala
sin preguntar; con --no-update ni se comprueba. Tus datos (casos/, geoip_data/)
nunca se tocan.

También valen las variables de entorno HOST, PORT y DUCKDB_PATH (los
argumentos tienen prioridad). Para cargar logs al arrancar sin tocar la API,
usa el CLI: python -m loganalyzer.cli
"""
import argparse
import os
import sys

import uvicorn


def _lan_ip() -> str:
    """IP de este equipo en la red local (sin enviar tráfico)."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return ""


def _print_urls(host: str, port: int) -> None:
    """Dice dónde abrir la app (uvicorn muestra 0.0.0.0, que no sirve en el navegador)."""
    if host in ("0.0.0.0", "::", ""):
        ip = _lan_ip()
        print(f"[run] Abre http://127.0.0.1:{port} en este equipo"
              + (f" o http://{ip}:{port} desde otro equipo de la red" if ip else ""),
              file=sys.stderr)
    else:
        print(f"[run] Abre http://{host}:{port}", file=sys.stderr)


def _check_updates(auto_yes: bool) -> None:
    """Comprueba GitHub y, si hay versión nueva, ofrece actualizar. Nunca aborta
    el arranque: cualquier fallo (sin red, repo privado…) se avisa y sigue."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import update as upd
    except Exception:
        return  # sin updater disponible: arrancamos sin más
    try:
        loc = upd.local_version()
        rem = upd.remote_version()
    except Exception as e:  # noqa: BLE001
        print(f"[run] No se pudo comprobar actualizaciones: {e}", file=sys.stderr)
        return
    if not upd.is_newer(rem, loc):
        print(f"[run] Longanizer {loc} — al día.", file=sys.stderr)
        return

    print(f"[run] Hay una actualización disponible: {loc} -> {rem}.", file=sys.stderr)
    do_it = auto_yes
    if not auto_yes:
        if not sys.stdin.isatty():
            print("[run] Ejecuta 'python update.py' para instalarla.", file=sys.stderr)
            return
        try:
            ans = input(f"      ¿Actualizar a {rem} ahora? [y/N] ").strip().lower()
        except EOFError:
            return
        do_it = ans in ("y", "yes", "s", "si", "sí")
    if not do_it:
        print("[run] Continuando con la versión actual.", file=sys.stderr)
        return
    try:
        n = upd.apply_update()
        print(f"[run] Actualizado a {rem} ({n} ficheros). Arrancando la nueva versión…",
              file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"[run] Falló la actualización: {e}. Continuando con la versión actual.",
              file=sys.stderr)


def _ensure_gtfobins() -> None:
    """El catálogo GTFOBins (GPL-3.0) no viaja en el repo: se descarga del repo
    oficial en la instalación, es decir, en el primer arranque. Sin red no
    bloquea: se avisa y se puede bajar luego con «Update catalog»."""
    try:
        from loganalyzer import gtfobins
    except Exception:  # noqa: BLE001
        return
    if gtfobins.load():
        return
    import threading
    print("[run] Descargando el catálogo GTFOBins (primer arranque)…", file=sys.stderr)
    res: dict = {}

    def work() -> None:
        try:
            res["ok"] = gtfobins.refresh()
        except Exception as e:  # noqa: BLE001
            res["err"] = e

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(150)
    if "ok" in res:
        print(f"[run] GTFOBins: {res['ok'].get('count')} binarios.", file=sys.stderr)
    elif t.is_alive():
        print("[run] GTFOBins sigue descargándose en segundo plano.", file=sys.stderr)
    else:
        print(f"[run] No se pudo descargar GTFOBins ({str(res.get('err'))[:120]}). "
              "Pulsa «Update catalog» en la pestaña GTFOBins cuando haya red.",
              file=sys.stderr)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="run.py", description="Servicio web Longanizer")
    ap.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"),
                    help="interfaz de escucha (por defecto 0.0.0.0 = todas; 127.0.0.1 = solo este equipo)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")),
                    help="puerto (por defecto 8000; cámbialo para tener varias apps a la vez)")
    ap.add_argument("--db", default=None,
                    help="ruta del caso DuckDB (por defecto en memoria); equivale a DUCKDB_PATH")
    ap.add_argument("--no-update", action="store_true",
                    help="no comprobar actualizaciones al arrancar")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="si hay actualización, instalarla sin preguntar")
    args = ap.parse_args()

    if not args.no_update:
        _check_updates(args.yes)

    _ensure_gtfobins()

    if args.db:
        os.environ["DUCKDB_PATH"] = args.db

    _print_urls(args.host, args.port)
    uvicorn.run(
        "loganalyzer.app:app",
        host=args.host,
        port=args.port,
        reload=False,
    )
