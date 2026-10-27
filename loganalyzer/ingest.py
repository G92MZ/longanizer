"""Ingesta de EVTX: fichero .evtx, carpeta (recursiva) o comprimido.

Recorre carpetas y descomprime archivos (.zip/.tar.gz/…) buscando `.evtx`
recursivamente. Cada .evtx se parsea con la librería Rust y se inserta en bloque.
Emite un dict de resultado por fichero para mostrar progreso en vivo.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from typing import Iterator, Optional

from . import compress
from .evtx_parse import iter_evtx
from .store import EventStore

_MAX_DEPTH = 8
_BATCH = 5000


def _is_evtx(path: str) -> bool:
    return path.lower().endswith(".evtx")


def ingest_file(store: EventStore, path: str,
                label: Optional[str] = None) -> dict:
    """Ingesta un único .evtx. Devuelve {file, events} o {file, error}."""
    display = label or os.path.basename(path)
    if not _is_evtx(path):
        return {"file": display, "skipped": "not an .evtx"}
    try:
        n = _insert_evtx(store, path)
        return {"file": display, "events": n}
    except Exception as exc:  # noqa: BLE001
        return {"file": display, "error": str(exc)}


def _insert_evtx(store: EventStore, path: str,
                 ts_from=None, ts_to=None) -> int:
    batch: list[tuple] = []
    total = 0
    for ev in iter_evtx(path):
        batch.append(ev.as_row())
        if len(batch) >= _BATCH:
            total += store.insert_events(batch, ts_from=ts_from, ts_to=ts_to)
            batch = []
    if batch:
        total += store.insert_events(batch, ts_from=ts_from, ts_to=ts_to)
    return total


# tamaño medio aproximado de un registro EVTX (para estimar progreso intra-fichero
# sin una segunda pasada de conteo).
_AVG_REC_BYTES = 1400


def _insert_evtx_streaming(store, path, label, bytes_done, filesize,
                            ts_from=None, ts_to=None):
    """Generador: inserta un .evtx por lotes emitiendo progreso POR BYTES
    (estimado por nº de registros vs tamaño) para que la barra se mueva también
    dentro de un único .evtx grande. Emite {progress_bytes} y, al final,
    {file, events}."""
    est = max(1, filesize // _AVG_REC_BYTES)
    batch: list[tuple] = []
    total = 0
    last_emit = 0
    for ev in iter_evtx(path):
        batch.append(ev.as_row())
        if len(batch) >= _BATCH:
            inserted = store.insert_events(batch, ts_from=ts_from, ts_to=ts_to)
            total += inserted
            batch = []
            if total - last_emit >= _BATCH:
                last_emit = total
                frac = min(0.98, total / est)
                yield {"progress_bytes": bytes_done + int(filesize * frac)}
    if batch:
        total += store.insert_events(batch, ts_from=ts_from, ts_to=ts_to)
    yield {"file": label, "events": total}


def ingest_path(store: EventStore, path: str,
                label: Optional[str] = None,
                ts_from=None, ts_to=None) -> list[dict]:
    return list(iter_ingest_path(store, path, label,
                                 ts_from=ts_from, ts_to=ts_to))


def iter_ingest_path(store: EventStore, path: str,
                     label: Optional[str] = None,
                     byte_prog: Optional[list] = None,
                     ts_from=None, ts_to=None) -> Iterator[dict]:
    base = label if label is not None else os.path.basename(path.rstrip("/\\"))
    single = os.path.isfile(path) and not compress.is_archive(path)
    yield from _iter_recursive(store, path, single, 0, base, byte_prog,
                               ts_from=ts_from, ts_to=ts_to)


def count_files(path: str) -> int:
    """Nº aproximado de .evtx bajo `path` (denominador de progreso; no expande
    comprimidos)."""
    if os.path.isfile(path):
        return 1 if _is_evtx(path) or compress.is_archive(path) else 0
    total = 0
    for _root, _dirs, files in os.walk(path):
        total += sum(1 for f in files if _is_evtx(f) or compress.is_archive(f))
    return total


def count_bytes(path: str) -> int:
    """Suma de tamaños en disco de los .evtx/archivos bajo `path` (denominador
    de progreso por bytes; no expande comprimidos)."""
    def _ok(f):
        return _is_evtx(f) or compress.is_archive(f)
    if os.path.isfile(path):
        if _ok(path):
            try:
                return os.path.getsize(path)
            except OSError:
                return 0
        return 0
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            if _ok(f):
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    return total


def _iter_recursive(store, path, single, depth, label,
                    byte_prog=None, ts_from=None, ts_to=None) -> Iterator[dict]:
    if depth > _MAX_DEPTH:
        yield {"file": label, "skipped": "nesting too deep"}
        return

    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            child = (label + "/" + name) if label else name
            yield from _iter_recursive(
                store, os.path.join(path, name), False, depth, child,
                byte_prog, ts_from=ts_from, ts_to=ts_to)
        return

    if compress.is_archive(path):
        arc_size = 0
        try:
            arc_size = os.path.getsize(path)
        except OSError:
            pass
        tmp = tempfile.mkdtemp(prefix="winhound_")
        try:
            compress.extract_archive(path, tmp)
            yield {"archive": label}
            # el contenido del archivo no está en el denominador: sin progreso
            # por bytes dentro; cuenta por su tamaño en disco una vez, al acabar.
            yield from _iter_recursive(store, tmp, False, depth + 1,
                                       label + "!", None,
                                       ts_from=ts_from, ts_to=ts_to)
        except Exception as exc:  # noqa: BLE001
            yield {"archive": label, "error": str(exc)}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            if byte_prog is not None:
                byte_prog[0] += arc_size
                yield {"progress_bytes": byte_prog[0]}
        return

    if _is_evtx(path):
        if byte_prog is not None:
            try:
                filesize = os.path.getsize(path)
            except OSError:
                filesize = 0
            try:
                yield from _insert_evtx_streaming(
                    store, path, label, byte_prog[0], filesize,
                    ts_from=ts_from, ts_to=ts_to)
            except Exception as exc:  # noqa: BLE001
                yield {"file": label, "error": str(exc)}
            finally:
                byte_prog[0] += filesize
                yield {"progress_bytes": byte_prog[0]}
            return
        try:
            n = _insert_evtx(store, path, ts_from=ts_from, ts_to=ts_to)
            yield {"file": label, "events": n}
        except Exception as exc:  # noqa: BLE001
            yield {"file": label, "error": str(exc)}
    elif single:
        yield {"file": label, "error": "not an .evtx file"}
    else:
        if byte_prog is not None:
            try:
                byte_prog[0] += os.path.getsize(path)
                yield {"progress_bytes": byte_prog[0]}
            except OSError:
                pass
        yield {"file": label, "skipped": "not .evtx"}
