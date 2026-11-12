#!/usr/bin/env python3
"""Screenshots for the documentation site (docs/assets/shots/**.webp).

Starts Longanizer on a throw-away case built from the bundled sample incident
(sample_logs/: SSH brute force → web shell → download & run → sudo), loads the
example Sigma rules in reglas_sigma/, drives the UI with Playwright and saves
each view as WebP.

    pip install playwright pillow      # Chromium: python -m playwright install chromium
    python scripts/docs_screenshots.py           # all shots
    python scripts/docs_screenshots.py explorer  # only shots whose name starts with it

Nothing from a real case is ever used.
"""
from __future__ import annotations

import io
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "shots"
SAMPLES = ROOT / "sample_logs"
W, H, DPR = 1440, 900, 1.25


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def post(base: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)


def save(png: bytes, name: str) -> None:
    dest = OUT / f"{name}.webp"
    dest.parent.mkdir(parents=True, exist_ok=True)
    Image.open(io.BytesIO(png)).save(dest, "WEBP", quality=82, method=6)
    print(f"  {dest.relative_to(ROOT)}  ({dest.stat().st_size // 1024} KB)")


class Shooter:
    def __init__(self, page):
        self.pg = page

    def js(self, code: str, wait: float = 0.6):
        self.pg.evaluate(f"(async()=>{{ {code} }})()")
        time.sleep(wait)

    def tab(self, t: str, wait: float = 1.2):
        self.js(f"switchTab('{t}')", wait)

    def shot(self, name: str, sel: str = "section.panel.active", max_h: int = H,
             top: bool = False, pad: int = 8):
        """top=True: from the tab bar down (tabs + start of the panel)."""
        if top:
            self.pg.evaluate("window.scrollTo(0,0)")
            time.sleep(0.3)
            y = self.pg.evaluate("document.querySelector('.tabs').getBoundingClientRect().top+scrollY") - 6
            clip = {"x": 0, "y": max(0, y), "width": W, "height": max_h}
        else:
            self.pg.locator(sel).first.scroll_into_view_if_needed()
            time.sleep(0.3)
            b = self.pg.evaluate(
                "(s)=>{const r=document.querySelector(s).getBoundingClientRect();"
                "return {x:r.x+scrollX,y:r.y+scrollY,w:r.width,h:r.height}}", sel)
            clip = {"x": max(0, b["x"] - pad), "y": max(0, b["y"] - pad),
                    "width": min(W, b["w"] + 2 * pad), "height": min(max_h, b["h"] + 2 * pad)}
        save(self.pg.screenshot(clip=clip, full_page=True), name)


def main(only: str = "") -> None:
    tmp = Path(tempfile.mkdtemp(prefix="longanizer-docs-"))
    try:
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        srv = subprocess.Popen([sys.executable, "run.py", "--host", "127.0.0.1", "--port", str(port),
                                "--no-update", "--db", str(tmp / "case.duckdb")],
                               cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(120):
                try:
                    urllib.request.urlopen(base + "/", timeout=2)
                    break
                except OSError:
                    time.sleep(0.5)
            print("ingesting sample_logs…")
            post(base, "/ingest/path", {"path": str(SAMPLES)})
            shoot(base, only)
        finally:
            srv.terminate()
            srv.wait(timeout=20)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def shoot(base: str, only: str) -> None:
    def want(name: str) -> bool:
        return name.startswith(only)

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        pg = browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=DPR)
        pg.goto(base + "/", wait_until="networkidle")
        time.sleep(1.5)
        s = Shooter(pg)

        if want("start"):
            s.tab("landing")
            s.shot("start/load", top=True, max_h=900)

        if want("explorer") or want("home"):
            s.tab("explorer")
            s.js("showTimeline()", 2.5)
            s.shot("explorer/toolbar", top=True, max_h=1000)
            s.shot("home/explorer", "#hits", max_h=700)
            s.shot("explorer/timeline", "#hits", max_h=700)
            pg.fill("#q", "(Failed OR Accepted) user=root")
            s.js("doSearch()", 2)
            s.js("document.querySelector('details.qhelp').open=true", 0.4)
            s.shot("explorer/query-cheatsheet", ".toolbar", max_h=1100)
            s.js("document.querySelector('details.qhelp').open=false", 0.3)
            pg.fill("#q", "status>=400")
            s.js("doSearch()", 2)
            td = pg.locator("#serows tr.hitrow >> nth=0 >> td.c-src_ip")
            td.scroll_into_view_if_needed()
            td.hover()
            time.sleep(0.5)
            box = pg.locator("#hits").bounding_box()
            save(pg.screenshot(clip={"x": 0, "y": box["y"] + pg.evaluate("scrollY") - 10, "width": W, "height": 260},
                               full_page=True), "explorer/cell-filter")
            s.js("document.getElementById('facfield').value='src_ip'; loadFacets()", 1.5)
            s.shot("explorer/facets", "div:has(> #fac_out)", max_h=560)
            first = pg.evaluate("ROWMAP && Object.keys(ROWMAP)[0]")
            s.js(f"openCtx({first})", 2)
            s.shot("explorer/context", "#gotoout", max_h=640)
            s.js("toggleColsPanel()", 0.8)
            s.shot("explorer/columns", "#colspanel", max_h=560)
            s.js("toggleColsPanel()", 0.4)

        if want("overview"):
            s.tab("dash")
            s.js("loadDash()", 3)
            s.shot("overview/overview", top=True, max_h=900)

        if want("iocs"):
            s.tab("iocx", 4)
            pg.wait_for_selector("#iocx_out .iocard", timeout=60000)
            time.sleep(0.5)
            s.shot("iocs/extractor", top=True, max_h=900)
            s.tab("ioc")
            pg.fill("#ioc_in", "203.0.113.55\n198.51.100.23\n/tmp/.x/payload.sh\nwget\nwww-data\n192.0.2.200")
            s.js("runIoc()", 3)
            s.shot("iocs/sweep", top=True, max_h=820)

        if want("network"):
            s.tab("network", 3)
            s.shot("network/network", top=True, max_h=820)

        if want("sql"):
            s.tab("sql")
            pg.fill("#sqltext", "-- SSH brute force by source IP\n"
                    "SELECT src_ip, count(*) AS n FROM events\n"
                    "WHERE source='auth' AND message ILIKE '%failed password%'\n"
                    "GROUP BY src_ip ORDER BY n DESC;")
            s.js("runSql()", 2.5)
            s.shot("sql/sql", top=True, max_h=820)

        if want("detect"):
            s.tab("sigma", 1.5)
            pg.fill("#sg_path", "reglas_sigma")   # relative to the app folder
            s.js("await sigmaLoad()", 2)
            s.js("await sigmaRun()", 2)
            pg.wait_for_selector("#sg_out details, #sg_out .sghits", timeout=60000, state="attached")
            s.shot("detect/sigma", top=True, max_h=1000)
            s.tab("attack", 3)
            s.shot("detect/attack", top=True, max_h=820)
            s.tab("gtfo", 1)
            s.js("await gtfoCheck()", 3)
            s.shot("detect/gtfobins", top=True, max_h=1000)

        if want("marks"):
            ids = pg.evaluate("fetch('/query',{method:'POST',headers:{'Content-Type':'application/json'},"
                              "body:JSON.stringify({sql:\"SELECT id FROM events WHERE source IN ('auth','access') "
                              "ORDER BY ts LIMIT 40\"})}).then(r=>r.json()).then(j=>j.rows.map(r=>r[0]))")
            for i, (st, note) in zip(ids[::13], [("TP", "Brute force from the scanner IP"),
                                                ("pendiente", None), ("FP", "Health-check probe")]):
                post(base, "/marks", {"event_id": i, "estado": st, "nota": note})
            s.tab("marks", 2)
            s.shot("marks/marks", top=True, max_h=760)
            pg.goto(base + "/report", wait_until="networkidle")
            time.sleep(1)
            pg.evaluate("document.querySelectorAll('details').forEach((d,i)=>d.open=i<2)")
            save(pg.screenshot(clip={"x": 0, "y": 0, "width": W, "height": 900}, full_page=True), "marks/report")
            pg.goto(base + "/", wait_until="networkidle")
            time.sleep(1.5)

        if want("ai"):
            s.tab("ai", 1)
            s.shot("ai/ai", top=True, max_h=760)
            s.tab("mcp", 1.5)
            s.shot("ai/mcp", top=True, max_h=760)

        browser.close()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
