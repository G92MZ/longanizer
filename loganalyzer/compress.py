"""Lectura transparente de logs comprimidos y extracción de archivos.

- Ficheros sueltos comprimidos: .gz, .bz2, .xz  -> se leen descomprimidos.
- Archivos contenedor: .tar, .tar.gz/.tgz, .tar.bz2, .tar.xz, .zip
  -> se extraen a un directorio temporal para recorrerlos.

La extracción es defensiva contra path traversal (zip/tar slip).
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import os
import tarfile
import zipfile
from typing import IO, Iterator

_SINGLE_SUFFIXES = (".gz", ".bz2", ".xz")


def strip_comp_suffix(name: str) -> str:
    """Quita el sufijo de compresión de un nombre para detectar por nombre."""
    low = name.lower()
    for s in _SINGLE_SUFFIXES:
        if low.endswith(s):
            return name[: -len(s)]
    return name


def is_archive(path: str) -> bool:
    """¿Es un contenedor (tar*/zip) que hay que extraer?"""
    try:
        if tarfile.is_tarfile(path):  # cubre .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz
            return True
    except (OSError, tarfile.TarError):
        pass
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def _raw_open(path: str) -> IO[bytes]:
    low = path.lower()
    if low.endswith(".gz"):
        return gzip.open(path, "rb")
    if low.endswith(".bz2"):
        return bz2.open(path, "rb")
    if low.endswith(".xz"):
        return lzma.open(path, "rb")
    return open(path, "rb")


def open_text_lines(path: str) -> Iterator[str]:
    """Itera líneas de texto, descomprimiendo .gz/.bz2/.xz al vuelo."""
    with _raw_open(path) as fb:
        for raw in fb:
            yield raw.decode("utf-8", errors="replace")


def read_head_bytes(path: str, n: int = 4096) -> bytes:
    try:
        with _raw_open(path) as fb:
            return fb.read(n)
    except OSError:
        return b""


def looks_binary(path: str) -> bool:
    """Heurística de binario: NUL en la cabecera (ya descomprimida)."""
    return b"\x00" in read_head_bytes(path, 4096)


def _safe_join(base: str, *parts: str) -> str:
    target = os.path.realpath(os.path.join(base, *parts))
    if not target.startswith(os.path.realpath(base) + os.sep):
        raise ValueError(f"ruta insegura en el archivo: {parts!r}")
    return target


def extract_archive(path: str, dest: str) -> None:
    """Extrae un tar*/zip a `dest`, ignorando miembros peligrosos.

    Extracción manual (sin extractall) para ser segura e independiente de la
    versión de Python: solo ficheros regulares, sin rutas absolutas ni `..`.
    """
    os.makedirs(dest, exist_ok=True)
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue  # nada de symlinks/devices/hardlinks
                try:
                    out = _safe_join(dest, m.name)
                except ValueError:
                    continue
                os.makedirs(os.path.dirname(out), exist_ok=True)
                src = tf.extractfile(m)
                if src is None:
                    continue
                with src, open(out, "wb") as dst:
                    dst.write(src.read())
        return
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    out = _safe_join(dest, info.filename)
                except ValueError:
                    continue
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with zf.open(info) as src, open(out, "wb") as dst:
                    dst.write(src.read())
        return
    raise ValueError(f"no es un archivo soportado: {path}")
