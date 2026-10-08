"""Catálogo GTFOBins: binarios Unix legítimos y las invocaciones con las que se
abusa de ellos (shell, reverse-shell, suid, sudo, file-read/write, etc.).

El dato se trae del repo oficial (clonado con git) y se normaliza a un JSON
plano en `gtfobins_data/gtfobins.json`, que es lo que consume la app. Se
actualiza bajo demanda desde la pestaña GTFOBins (botón «Actualizar»).

Formato del repo: `_gtfobins/<binario>` (sin extensión) con YAML frontmatter
entre `---`, clave `functions: {tecnica: [{code, comment, contexts}]}`.
"""
from __future__ import annotations

import glob
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from typing import Any, Optional

import yaml

REPO = "https://github.com/GTFOBins/GTFOBins.github.io"
# tarballs (orden de intento) para la vía sin git
TARBALLS = [
    "https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master",
    "https://github.com/GTFOBins/GTFOBins.github.io/archive/refs/heads/master.tar.gz",
    "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/tarball/master",
]
_ROOT = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(_ROOT, "gtfobins_data")
JSON_PATH = os.path.join(DATA_DIR, "gtfobins.json")


def _parse_frontmatter(text: str) -> Optional[dict]:
    """Devuelve el YAML del frontmatter. Los ficheros GTFOBins son un documento
    YAML que empieza en `---` y termina en `...` (a veces con markdown después)."""
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception:  # noqa: BLE001
        return None
    for d in docs:
        if isinstance(d, dict) and "functions" in d:
            return d
    return docs[0] if docs and isinstance(docs[0], dict) else None


def _normalize(data: dict) -> dict:
    """{functions: {tecnica: [{code, comment, contexts[]}]}} depurado."""
    funcs: dict[str, list] = {}
    for fname, entries in (data.get("functions") or {}).items():
        out: list[dict] = []
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            code = (e.get("code") or "").strip()
            if not code:
                continue
            ctx = e.get("contexts")
            contexts = list(ctx.keys()) if isinstance(ctx, dict) else (
                [str(ctx)] if ctx else [])
            comment = (e.get("comment") or "").strip() or None
            out.append({"code": code, "comment": comment, "contexts": contexts})
        if out:
            funcs[str(fname)] = out
    return {"functions": funcs}


def _build_from_dir(gdir: str) -> dict[str, dict]:
    """Parsea todos los ficheros de un directorio `_gtfobins` → {bin: {...}}."""
    binaries: dict[str, dict] = {}
    for fp in sorted(glob.glob(os.path.join(gdir, "*"))):
        if not os.path.isfile(fp):
            continue
        name = os.path.basename(fp)
        try:
            text = open(fp, encoding="utf-8").read()
        except Exception:  # noqa: BLE001
            continue
        data = _parse_frontmatter(text)
        if not isinstance(data, dict):
            continue
        norm = _normalize(data)
        if norm["functions"]:
            binaries[name] = norm
    return binaries


def _find_gtfobins_dir(root: str) -> Optional[str]:
    """Busca el directorio `_gtfobins` bajo `root` (el tar trae un prefijo)."""
    direct = os.path.join(root, "_gtfobins")
    if os.path.isdir(direct):
        return direct
    for entry in os.listdir(root):
        cand = os.path.join(root, entry, "_gtfobins")
        if os.path.isdir(cand):
            return cand
    return None


def _fetch_git(dest: str) -> None:
    subprocess.run(["git", "clone", "--depth", "1", REPO, dest],
                   check=True, capture_output=True, text=True, timeout=240)


def _fetch_tarball(dest: str) -> None:
    """Descarga el repo como tar.gz (sin git) y lo extrae en `dest`."""
    last = None
    for url in TARBALLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "loganalyzer"})
            data = urllib.request.urlopen(req, timeout=120).read()
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                tf.extractall(dest)
            return
        except Exception as e:  # noqa: BLE001
            last = e
            continue
    raise RuntimeError(f"descarga del tarball fallida: {last}")


def refresh() -> dict:
    """Actualiza el catálogo. Intenta `git clone`; si no hay git o falla, descarga
    el repo como tar.gz con Python (sin git). Guarda el JSON y devuelve el status."""
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="gtfo_")
    try:
        errors: list[str] = []
        got = False
        try:
            _fetch_git(tmp)
            got = True
        except FileNotFoundError:
            errors.append("git no instalado")
        except Exception as e:  # noqa: BLE001
            errors.append(f"git: {getattr(e, 'stderr', None) or e}")
        if not got:
            try:
                _fetch_tarball(tmp)
                got = True
            except Exception as e:  # noqa: BLE001
                errors.append(f"descarga: {e}")
        if not got:
            raise RuntimeError("; ".join(str(x)[:160] for x in errors)
                               or "no se pudo obtener el repo")

        gdir = _find_gtfobins_dir(tmp)
        if not gdir:
            raise RuntimeError("no se encontró el directorio _gtfobins en el repo")
        binaries = _build_from_dir(gdir)
        payload = {
            "updated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
            "count": len(binaries),
            "binaries": binaries,
        }
        with open(JSON_PATH, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        return {"loaded": True, "count": payload["count"],
                "updated": payload["updated"]}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def load() -> Optional[dict]:
    if not os.path.exists(JSON_PATH):
        return None
    try:
        with open(JSON_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return None


def status() -> dict:
    d = load()
    if not d:
        return {"loaded": False}
    return {"loaded": True, "count": d.get("count"), "updated": d.get("updated")}
