"""Ingesta de ficheros de log: detección de tipo, descompresión y volcado.

Acepta ficheros sueltos, carpetas (recursivo) y archivos comprimidos
(.gz/.bz2/.xz sueltos y contenedores .tar*/.zip, que se extraen a un
temporal y se recorren). Los tipos no reconocidos se saltan avisando.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime
from typing import Optional

from .parsers import TEXT_PARSERS
from .store import EventStore
from .detect import detect_type, detect_by_name, sniff_content  # noqa: F401 (reexport)
from .sigma_map import classify as _classify_sigma
from . import compress

_MAX_DEPTH = 8  # tope de anidamiento de archivos dentro de archivos


def _preview(path: str, n: int = 4, maxlen: int = 300) -> str:
    """Primeras n líneas del fichero (para diagnosticar los que fallan)."""
    try:
        if compress.looks_binary(path):
            return "(contenido binario)"
        out = []
        for line in compress.open_text_lines(path):
            out.append(line.rstrip("\n")[:maxlen])
            if len(out) >= n:
                break
        return "\n".join(out)
    except Exception:  # noqa: BLE001
        return ""


def ingest_file(
    store: EventStore,
    path: str,
    log_type: Optional[str] = None,
    base_year: Optional[int] = None,
    user: Optional[str] = None,
    tz_offset_minutes: int = 0,
    src_name: Optional[str] = None,
) -> dict:
    """Ingesta un único fichero de log (texto, posiblemente .gz/.bz2/.xz).

    log_type: fuerza el tipo; si None se autodetecta por nombre/contenido.
    base_year: año base para logs syslog sin año; si None, el año del mtime.
    tz_offset_minutes: zona de la máquina para logs syslog/weberror (se resta).
    src_name: ruta lógica a guardar como origen (por defecto, el nombre del fichero).
    """
    display = src_name or os.path.basename(path)
    log_type = log_type or detect_type(path)
    if log_type is None:
        raise ValueError(
            f"Could not detect the type of '{os.path.basename(path)}'. "
            f"Specify it explicitly (types: {', '.join(TEXT_PARSERS)})."
        )
    if log_type not in TEXT_PARSERS:
        raise ValueError(f"Unknown type '{log_type}'. Valid: {', '.join(TEXT_PARSERS)}")

    if base_year is None:
        base_year = datetime.fromtimestamp(os.path.getmtime(path)).year

    if compress.looks_binary(path):
        raise ValueError(
            f"'{os.path.basename(path)}' parece un fichero binario; "
            f"solo se admiten logs de texto (tipos: {', '.join(TEXT_PARSERS)})."
        )

    lines = compress.open_text_lines(path)
    parser = TEXT_PARSERS[log_type]
    events = parser(
        lines, base_year=base_year,
        src_file=display, user=user,
        tz_offset_minutes=tz_offset_minutes,
    )
    rows = []
    for e in events:
        # clasificación Sigma por evento (flag de prune + etiqueta de logsource)
        e.sigma_ok, e.sigma_logsource = _classify_sigma(e.source, e.event, e.program)
        rows.append(e.as_row())
    n = store.insert_events(rows)
    return {
        "file": display,
        "type": log_type,
        "base_year": base_year,
        "events": n,
    }


def ingest_path(
    store: EventStore,
    path: str,
    log_type: Optional[str] = None,
    base_year: Optional[int] = None,
    user: Optional[str] = None,
    tz_offset_minutes: int = 0,
    skip_unknown: bool = False,
    label: Optional[str] = None,
    catch_all: bool = False,
) -> list[dict]:
    """Ingesta un fichero, carpeta (recursiva) o archivo comprimido.

    Carpetas y archivos contenedor se recorren enteros; los ficheros de tipo
    no reconocido se saltan (quedan reflejados como 'skipped' en el resumen).
    skip_unknown=True fuerza esa semántica también para un único fichero suelto
    (útil al subir por la web, donde un no-log se marca 'saltado' en vez de error).
    label: ruta lógica de origen que se mostrará (por defecto, el nombre del path);
    al recorrer carpetas/archivos se le añade la ruta relativa de cada fichero.
    """
    return list(iter_ingest_path(
        store, path, log_type, base_year, user, tz_offset_minutes,
        skip_unknown=skip_unknown, label=label, catch_all=catch_all))


def iter_ingest_path(
    store: EventStore,
    path: str,
    log_type: Optional[str] = None,
    base_year: Optional[int] = None,
    user: Optional[str] = None,
    tz_offset_minutes: int = 0,
    skip_unknown: bool = False,
    label: Optional[str] = None,
    catch_all: bool = False,
    byte_prog: Optional[list] = None,
):
    """Como ingest_path pero GENERADOR: va emitiendo el dict de cada fichero a
    medida que lo procesa (para mostrar progreso en vivo mientras se ingesta).

    catch_all=True ingesta como 'raw' (línea completa) lo que no se reconozca y
    no sea clave=valor, para que ninguna línea se pierda (más ruido).
    byte_prog: lista mutable [bytes_acumulados]; si se pasa, además se emiten
    dicts {progress_bytes} con progreso POR BYTES (incl. dentro de un fichero)."""
    top_is_single = (os.path.isfile(path) and not compress.is_archive(path)
                     and not skip_unknown)
    base_label = label if label is not None else os.path.basename(path.rstrip("/\\"))
    yield from _iter_ingest_recursive(store, path, top_is_single, log_type,
                                      base_year, user, tz_offset_minutes, 0,
                                      base_label, catch_all, byte_prog)


def count_files(path: str) -> int:
    """Nº aproximado de ficheros bajo `path` (para un denominador de progreso).
    No expande archivos comprimidos, así que con .zip/.tar dentro será menor que
    el real; el cliente lo trata como estimación."""
    if os.path.isfile(path):
        return 1
    total = 0
    for _root, _dirs, files in os.walk(path):
        total += len(files)
    return total


def count_bytes(path: str) -> int:
    """Suma de tamaños en disco bajo `path` (denominador de progreso por bytes).
    No expande archivos comprimidos (misma estimación que count_files)."""
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


# inserción por lotes + emisión de progreso por bytes mientras se lee un fichero
_BATCH_ROWS = 20000
_PROGRESS_EVERY_BYTES = 1_000_000  # ~1 MB entre eventos de progreso


def _ingest_file_streaming(store, path, typ, base_year, user, tz, label,
                           bytes_done, filesize):
    """Generador: ingesta un fichero insertando por lotes y emitiendo progreso
    POR BYTES a medida que lo lee. Emite dicts {progress_bytes: ...} durante la
    lectura y, al final, el dict resultado {file,type,events}. Así la barra se
    mueve también dentro de un único fichero grande."""
    if base_year is None:
        try:
            base_year = datetime.fromtimestamp(os.path.getmtime(path)).year
        except OSError:
            base_year = datetime.now().year

    cnt = [0]  # bytes (aprox, por longitud de línea) leídos de este fichero

    def _wrapped():
        for line in compress.open_text_lines(path):
            cnt[0] += len(line)
            yield line

    parser = TEXT_PARSERS[typ]
    events = parser(_wrapped(), base_year=base_year, src_file=label,
                    user=user, tz_offset_minutes=tz)
    rows = []
    total_events = 0
    last_emit = 0
    for e in events:
        e.sigma_ok, e.sigma_logsource = _classify_sigma(e.source, e.event, e.program)
        rows.append(e.as_row())
        if len(rows) >= _BATCH_ROWS:
            total_events += store.insert_events(rows)
            rows = []
        if cnt[0] - last_emit >= _PROGRESS_EVERY_BYTES:
            last_emit = cnt[0]
            # clamp al tamaño del fichero (bytes sin comprimir ≈ disco en texto plano)
            yield {"progress_bytes": bytes_done + min(cnt[0], filesize)}
    if rows:
        total_events += store.insert_events(rows)
    yield {"file": label, "type": typ, "base_year": base_year,
           "events": total_events}


def _iter_ingest_recursive(store, path, single, log_type,
                           base_year, user, tz, depth, label, catch_all=False,
                           byte_prog=None):
    if depth > _MAX_DEPTH:
        yield {"file": label, "skipped": "nesting too deep"}
        return

    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            child = (label + "/" + name) if label else name
            yield from _iter_ingest_recursive(
                store, os.path.join(path, name), False,
                log_type, base_year, user, tz, depth, child, catch_all,
                byte_prog)
        return

    # contenedor tar*/zip -> extraer a temporal y recorrer (ruta: archivo!/interno)
    if compress.is_archive(path):
        arc_size = 0
        try:
            arc_size = os.path.getsize(path)
        except OSError:
            pass
        tmp = tempfile.mkdtemp(prefix="loganalyzer_")
        try:
            compress.extract_archive(path, tmp)
            yield {"archive": label, "extracted_to": "(temporal)"}
            # el contenido del archivo no está en el denominador de bytes, así
            # que no emitimos progreso por bytes dentro (byte_prog=None); el
            # archivo cuenta por su tamaño en disco una vez, al terminar.
            yield from _iter_ingest_recursive(
                store, tmp, False, log_type, base_year, user, tz,
                depth + 1, label + "!", catch_all, None)
        except Exception as exc:  # noqa: BLE001
            yield {"archive": label, "error": str(exc)}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            if byte_prog is not None:
                byte_prog[0] += arc_size
                yield {"progress_bytes": byte_prog[0]}
        return

    # fichero normal (o .gz/.bz2/.xz suelto)
    typ = log_type or detect_type(path)
    if typ is None:
        if catch_all:
            # modo catch-all: ingerir como 'raw' (línea completa) en vez de saltar
            typ = "raw"
        elif single:
            # fichero único pedido explícitamente: error claro
            raise ValueError(
                f"Could not detect the type of '{os.path.basename(path)}'. "
                f"Specify it explicitly (types: {', '.join(TEXT_PARSERS)})."
            )
        else:
            # aun saltándolo, su tamaño cuenta para el progreso por bytes
            if byte_prog is not None:
                try:
                    byte_prog[0] += os.path.getsize(path)
                except OSError:
                    pass
            yield {"file": label, "skipped": "unrecognized type",
                   "preview": _preview(path)}
            return
    if byte_prog is not None:
        # ingesta en streaming por lotes, con progreso por bytes intra-fichero
        try:
            filesize = os.path.getsize(path)
        except OSError:
            filesize = 0
        try:
            yield from _ingest_file_streaming(
                store, path, typ, base_year, user, tz, label,
                byte_prog[0], filesize)
        except Exception as exc:  # noqa: BLE001
            yield {"file": label, "error": str(exc), "preview": _preview(path)}
        finally:
            byte_prog[0] += filesize
            yield {"progress_bytes": byte_prog[0]}
        return
    try:
        yield ingest_file(store, path, typ, base_year, user, tz, src_name=label)
    except Exception as exc:  # noqa: BLE001
        yield {"file": label, "error": str(exc), "preview": _preview(path)}
