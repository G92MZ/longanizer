#!/usr/bin/env python3
"""Self-updater for Longanizer.

Checks GitHub for a newer version and, if there is one, downloads the latest
code from the default branch and updates the app files in place — no git
required, using only the Python standard library (works on Windows and Linux).

Your data is preserved: the cases folder (casos/) and the GeoIP databases
(geoip_data/) are never overwritten.

  python update.py            # check, then ask before updating
  python update.py --check    # only check, change nothing
  python update.py --yes      # update without asking

Private repo? Set a token in the environment first:
  GITHUB_TOKEN=ghp_xxx python update.py
"""
from __future__ import annotations

import argparse
import io
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile

OWNER = "G92MZ"
REPO = "longanizer"
BRANCH = "main"

# Top-level folders that are NEVER overwritten (your data).
PROTECTED = {"casos", "geoip_data"}

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _request(url: str, accept: str | None = None):
    headers = {"User-Agent": f"{REPO}-updater"}
    if accept:
        headers["Accept"] = accept
    if TOKEN:
        headers["Authorization"] = f"token {TOKEN}"
    return urllib.request.Request(url, headers=headers)


def _get(url: str, accept: str | None = None, timeout: int = 60) -> bytes:
    with urllib.request.urlopen(_request(url, accept), timeout=timeout) as r:
        return r.read()


def local_version() -> str:
    try:
        with open(os.path.join(HERE, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "0.0.0"


def remote_version() -> str:
    if TOKEN:
        url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/VERSION?ref={BRANCH}"
        return _get(url, accept="application/vnd.github.raw").decode("utf-8", "replace").strip()
    url = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/VERSION"
    return _get(url).decode("utf-8", "replace").strip()


def _vtuple(v: str) -> tuple:
    out = []
    for part in v.strip().lstrip("vV").replace("-", ".").split("."):
        out.append(int(part) if part.isdigit() else 0)
    return tuple(out)


def is_newer(remote: str, local: str) -> bool:
    return _vtuple(remote) > _vtuple(local)


def _download_zip() -> bytes:
    if TOKEN:
        url = f"https://api.github.com/repos/{OWNER}/{REPO}/zipball/{BRANCH}"
    else:
        url = f"https://github.com/{OWNER}/{REPO}/archive/refs/heads/{BRANCH}.zip"
    return _get(url, timeout=180)


def apply_update() -> int:
    """Download the latest code and copy it over the install dir. Returns the
    number of files written. Protected data folders are left untouched."""
    zf = zipfile.ZipFile(io.BytesIO(_download_zip()))
    names = [n for n in zf.namelist() if n.strip()]
    if not names:
        raise RuntimeError("empty archive")
    root = names[0].split("/")[0]          # e.g. "longanizer-main" or a commit hash
    tmp = tempfile.mkdtemp(prefix=f"{REPO}_upd_")
    try:
        zf.extractall(tmp)
        src = os.path.join(tmp, root)
        copied = 0
        for dirpath, dirnames, filenames in os.walk(src):
            rel = os.path.relpath(dirpath, src)
            top = "" if rel == "." else rel.split(os.sep)[0]
            if top in PROTECTED:
                dirnames[:] = []
                continue
            dest_dir = HERE if rel == "." else os.path.join(HERE, rel)
            os.makedirs(dest_dir, exist_ok=True)
            for fn in filenames:
                shutil.copy2(os.path.join(dirpath, fn), os.path.join(dest_dir, fn))
                copied += 1
        return copied
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser(prog="update.py", description=f"Update {REPO} to the latest version.")
    ap.add_argument("--check", action="store_true", help="only check, do not change anything")
    ap.add_argument("--yes", "-y", action="store_true", help="update without asking")
    args = ap.parse_args()

    loc = local_version()
    try:
        rem = remote_version()
    except Exception as e:  # noqa: BLE001
        print(f"Could not check for updates: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"Installed: {loc}   Latest: {rem}")
    if not is_newer(rem, loc):
        print("Already up to date.")
        return
    if args.check:
        print("An update is available. Run without --check to install.")
        return
    if not args.yes:
        ans = input(f"Update {loc} -> {rem}? [y/N] ").strip().lower()
        if ans not in ("y", "yes", "s", "si", "sí"):
            print("Cancelled.")
            return
    try:
        n = apply_update()
    except Exception as e:  # noqa: BLE001
        print(f"Update failed: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Updated to {rem} ({n} files). Restart the app:  python run.py")


if __name__ == "__main__":
    main()
