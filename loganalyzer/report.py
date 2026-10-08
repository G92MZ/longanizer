"""Self-contained HTML case report for LogAnalyzer.

Builds a single static HTML document (embedded CSS, no external assets) from the
data already computed by the app: case summary, Sigma detections (collapsible,
with per-finding matches), abused GTFOBins binaries, top source IPs with GeoIP,
and triage marks. Sections use native <details> so everything is collapsible and
the page does not look overwhelming at first glance.
"""
from __future__ import annotations

import html
import time
from typing import Any, Optional

_SEV = {"critical": "#f85149", "high": "#db6d28", "medium": "#e3b341",
        "low": "#3fb950", "informational": "#58a6ff"}


def _e(v: Any) -> str:
    if v is None:
        return "&empty;"
    return html.escape(str(v))


def _tile(value: Any, label: str) -> str:
    return f'<div class="tile"><div class="v">{_e(value)}</div><div class="l">{_e(label)}</div></div>'


def _sigma_section(sigma: Optional[dict]) -> str:
    if sigma is None:
        return ('<details><summary>Sigma detections <span class="muted">'
                '(rules not loaded)</span></summary><p class="muted">Load Sigma '
                'rules and run them to include detections here.</p></details>')
    findings = sigma.get("findings", [])
    head = (f'Sigma detections <span class="pill">{len(findings)} findings · '
            f'{sigma.get("total_hits", 0)} hits · {sigma.get("applied", 0)} rules run</span>')
    if not findings:
        return f'<details open><summary>{head}</summary><p class="muted">No matches.</p></details>'
    body = []
    for f in findings:
        lvl = (f.get("level") or "info")
        col = _SEV.get(lvl, "#58a6ff")
        cols = f.get("columns", [])
        rows = []
        for hit in f.get("hits", []):
            tds = "".join(f"<td>{_e(c)}</td>" for c in hit)
            rows.append(f"<tr>{tds}</tr>")
        more = ""
        if f.get("count", 0) > len(f.get("hits", [])):
            more = (f'<tr><td colspan="{len(cols)}" class="muted">… '
                    f'{f["count"] - len(f["hits"])} more</td></tr>')
        thead = "".join(f"<th>{_e(c)}</th>" for c in cols)
        tags = " ".join(_e(t) for t in f.get("tags", []))
        body.append(
            f'<details class="finding"><summary>'
            f'<span class="sev" style="background:{col}">{_e(lvl.upper())}</span> '
            f'{_e(f.get("title"))} <span class="muted">· {_e(f.get("logsource"))} '
            f'· ×{f.get("count", 0)} {("· " + tags) if tags else ""}</span></summary>'
            f'<div class="tblwrap"><table><thead><tr>{thead}</tr></thead>'
            f'<tbody>{"".join(rows)}{more}</tbody></table></div></details>')
    return f'<details open><summary>{head}</summary>{"".join(body)}</details>'


def _priv_label(p: dict) -> str:
    out = []
    if p.get("via_sudo"):
        out.append('<span class="danger">via sudo</span>')
    if p.get("escalation"):
        out.append('<span class="danger">&#9888; privilege escalation (auid '
                   + _e(",".join(p.get("login_users", []))) + ")</span>")
    elif p.get("as_root"):
        out.append('<span class="danger">as root</span>')
    if not out:
        out.append('<span class="muted">normal user</span>')
    return " ".join(out)


def _gtfo_section(gtfo: Optional[dict]) -> str:
    if gtfo is None:
        return ('<details><summary>GTFOBins — abused binaries '
                '<span class="muted">(catalog not loaded)</span></summary>'
                '<p class="muted">Update the GTFOBins catalog and run the check '
                'to include this.</p></details>')
    matched = gtfo.get("matched", [])
    ndanger = sum(1 for m in matched if m.get("danger"))
    head = (f'GTFOBins — abused binaries executed <span class="pill">'
            f'{len(matched)} binaries · {ndanger} privileged</span>')
    if not matched:
        return f'<details open><summary>{head}</summary><p class="muted">None found.</p></details>'
    body = []
    for b in matched:
        fns = " ".join(f'<span class="fn">{_e(k)}</span>'
                       for k in b.get("functions", {}).keys())
        secs = []
        for fname, entries in b.get("functions", {}).items():
            codes = []
            for ent in entries:
                cm = f'<div class="muted">{_e(ent.get("comment"))}</div>' if ent.get("comment") else ""
                ctx = " ".join(f'<span class="ctx">{_e(c)}</span>'
                               for c in ent.get("contexts", []))
                codes.append(f'{cm}<pre class="code">{_e(ent.get("code"))}</pre>'
                             f'<div>{ctx}</div>')
            secs.append(f'<div class="fnsec"><div class="fnh">{_e(fname)}</div>'
                        f'{"".join(codes)}</div>')
        samples = ""
        if b.get("samples"):
            rows = "".join(
                f'<tr><td>{_e(s.get("ts"))}</td><td>{_e(s.get("source"))}</td>'
                f'<td>{_e(s.get("user"))}</td><td>{_e(s.get("detalle"))}</td></tr>'
                for s in b["samples"])
            samples = (f'<div class="subh">Where it ran</div><div class="tblwrap">'
                       f'<table><thead><tr><th>ts</th><th>source</th><th>user</th>'
                       f'<th>detail</th></tr></thead><tbody>{rows}</tbody></table></div>')
        cls = " danger" if b.get("danger") else ""
        body.append(
            f'<details class="finding{cls}"><summary><b class="bin">{_e(b["bin"])}</b> '
            f'<span class="muted">×{b.get("count", 0)}</span> {_priv_label(b.get("privilege", {}))} '
            f'<span class="fns">{fns}</span></summary>{"".join(secs)}{samples}</details>')
    return f'<details open><summary>{head}</summary>{"".join(body)}</details>'


def _ip_section(top_ip: list[dict]) -> str:
    if not top_ip:
        return ""
    rows = []
    for x in top_ip:
        if x.get("private") is True:
            loc = '<span class="tag int">internal</span>'
        elif x.get("private") is False:
            geo = " · ".join(str(v) for v in
                             [x.get("country"), f"AS{x['asn']}" if x.get("asn") else None,
                              x.get("org")] if v)
            loc = f'<span class="tag ext">external</span> {_e(geo)}'
        else:
            loc = ""
        rows.append(f'<tr><td class="mono">{_e(x.get("k"))}</td>'
                    f'<td class="mono">{x.get("n")}</td><td>{loc}</td></tr>')
    return (f'<details open><summary>Top source IPs</summary><div class="tblwrap">'
            f'<table><thead><tr><th>IP</th><th>events</th><th>location</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></details>')


def _marks_section(marks: list[dict]) -> str:
    if not marks:
        return ('<details><summary>Triage marks</summary>'
                '<p class="muted">No marks.</p></details>')
    from collections import Counter
    lbl = {"pendiente": "pending", "descartado": "dismissed",
           "TP": "TP", "FP": "FP"}
    c = Counter(lbl.get(m["estado"], m["estado"]) for m in marks)
    counts = " · ".join(f"{k}: {v}" for k, v in c.items())
    rows = []
    for m in marks:
        meta = " · ".join(str(v) for v in
                          [f"#{m['seq']}" if m.get("seq") is not None else None,
                           m.get("ts"), m.get("source"), m.get("user")] if v)
        note = f'<div class="note">{_e(m.get("nota"))}</div>' if m.get("nota") else ""
        rows.append(f'<div class="mk"><span class="badge badge-{_e(m["estado"])}">'
                    f'{_e(lbl.get(m["estado"], m["estado"]))}</span><div><div class="mono">'
                    f'{_e(m.get("detalle") or "(no event)")}</div>'
                    f'<div class="muted small">{_e(meta)}</div>{note}</div></div>')
    return (f'<details open><summary>Triage marks <span class="pill">{_e(counts)}'
            f'</span></summary>{"".join(rows)}</details>')


_CSS = """
:root{--bg:#132743;--panel:#1b3357;--panel2:#23416b;--border:#345681;--fg:#eaf1fb;
--muted:#a3b6d4;--accent:#5fa3ff;--ink:#07192f;--mono:ui-monospace,Menlo,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,sans-serif;padding:0 0 40px}
header{padding:22px 28px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,#1d3860,#132743)}
h1{margin:0;font-size:20px}
.sub{color:var(--muted);font-size:12px;margin-top:4px;font-family:var(--mono)}
main{max-width:1100px;margin:0 auto;padding:24px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:22px}
.tile{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.tile .v{font-size:22px;font-weight:700;color:var(--accent);font-family:var(--mono)}
.tile .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
details{background:var(--panel);border:1px solid var(--border);border-radius:12px;margin:12px 0;padding:4px 14px}
details>summary{cursor:pointer;padding:10px 4px;font-size:14px;font-weight:600;list-style:none}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"\\25B6";color:var(--accent);font-size:10px;margin-right:9px;display:inline-block;transition:transform .12s}
details[open]>summary::before{transform:rotate(90deg)}
details.finding{background:var(--bg);margin:8px 0}
details.finding.danger{border-color:#f85149}
.sev{font-family:var(--mono);font-size:10px;font-weight:700;color:var(--ink);padding:2px 7px;border-radius:4px}
.pill{font-weight:400;font-size:12px;color:var(--muted);font-family:var(--mono)}
.muted{color:var(--muted)}.small{font-size:11px}
.mono{font-family:var(--mono);font-size:12px}
.tblwrap{overflow:auto;border:1px solid var(--border);border-radius:8px;margin:8px 0;max-height:420px}
table{border-collapse:collapse;width:100%;font-family:var(--mono);font-size:12px}
th,td{border:1px solid var(--border);padding:6px 10px;text-align:left;white-space:nowrap;
max-width:460px;overflow:hidden;text-overflow:ellipsis}
th{background:var(--panel2);position:sticky;top:0}
.fn,.fns .fn{font-family:var(--mono);font-size:10px;background:var(--panel2);border:1px solid var(--border);
border-radius:4px;padding:1px 6px;margin-left:4px}
.fns{float:right}
.bin{font-family:var(--mono);color:var(--accent);font-size:15px}
.danger,.tag.ext{color:#ff7b72}
.fnsec{margin:6px 0 12px}.fnh{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--accent);margin:6px 0}
.code{background:#0d1b30;border:1px solid var(--border);border-radius:6px;padding:9px 11px;
font-family:var(--mono);font-size:12px;white-space:pre-wrap;overflow:auto;margin:4px 0}
.ctx{font-family:var(--mono);font-size:9px;border:1px solid var(--border);border-radius:4px;padding:0 5px;color:var(--muted)}
.subh{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:10px 0 2px}
.tag{font-family:var(--mono);font-size:10px;border:1px solid var(--border);border-radius:4px;padding:1px 6px}
.tag.int{color:#56d364;border-color:#3fb950}.tag.ext{border-color:#f85149}
.mk{display:flex;gap:12px;align-items:flex-start;border-bottom:1px solid var(--border);padding:9px 0}
.badge{font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;border:1px solid var(--border);white-space:nowrap}
.badge-pendiente{color:#e3b341;border-color:#e3b341}.badge-TP{color:#ff7b72;border-color:#f85149}
.badge-FP{color:#56d364;border-color:#3fb950}.badge-descartado{color:var(--muted)}
.note{font-size:12px;margin-top:3px}
footer{max-width:1100px;margin:30px auto 0;padding:16px 24px;border-top:1px solid var(--border);
color:var(--muted);font-size:12px;text-align:center}
footer b{color:var(--accent)}
@media print{body{background:#fff;color:#000}details{break-inside:avoid}}
"""


def build(meta: dict, dashboard: dict, sigma: Optional[dict],
          gtfo: Optional[dict], marks: list[dict]) -> str:
    dist = dashboard.get("distinct", {})
    rng = (f'{dashboard.get("ts_min")} → {dashboard.get("ts_max")}'
           if dashboard.get("ts_min") else "no timestamps")
    nmarks = len(marks)
    ndanger = (sum(1 for m in gtfo["matched"] if m.get("danger")) if gtfo else 0)
    nfind = len(sigma["findings"]) if sigma else 0
    tiles = "".join([
        _tile(dashboard.get("total", 0), "events"),
        _tile(dist.get("source", 0), "sources"),
        _tile(dist.get("ip", 0), "distinct IPs"),
        _tile(nfind, "Sigma findings"),
        _tile(ndanger, "privileged GTFOBins"),
        _tile(nmarks, "triage marks"),
    ])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(meta.get('title', 'Longanizer report'))}</title><style>{_CSS}</style></head>
<body>
<header><h1><svg viewBox="0 0 24 24" width="1.2em" height="1.2em" style="vertical-align:-.26em" aria-label="chorizo"><path d="M18.7 5.8 L20.9 3.9 M18.7 5.8 L20.3 7.9" fill="none" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#141414" stroke-width="7.8" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#e0485a" stroke-width="5.6" stroke-linecap="round"/><path d="M7.4 16.8 C10 18.6 15.4 17.6 16.8 8" fill="none" stroke="#f58a95" stroke-width="1.6" stroke-linecap="round" opacity=".85"/><path d="M10.6 19.9 l1.3 -2.4" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M14.8 19.2 l1.2 -2.3" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M3.7 20.2 L6.4 18.2 L5.9 21.2 Z" fill="#e0485a" stroke="#141414" stroke-width="1.1" stroke-linejoin="round"/></svg> Longanizer — forensic case report</h1>
<div class="sub">generated {_e(meta.get('generated'))} · case: {_e(meta.get('case') or 'in-memory')}
 · time range (UTC): {_e(rng)}</div></header>
<main>
<div class="tiles">{tiles}</div>
{_sigma_section(sigma)}
{_gtfo_section(gtfo)}
{_ip_section(dashboard.get('top_ip', []))}
{_marks_section(marks)}
</main>
<footer><svg viewBox="0 0 24 24" width="1.2em" height="1.2em" style="vertical-align:-.26em" aria-label="chorizo"><path d="M18.7 5.8 L20.9 3.9 M18.7 5.8 L20.3 7.9" fill="none" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#141414" stroke-width="7.8" stroke-linecap="round"/><path d="M6.2 18.4 C10 21.2 17.4 19.6 18.6 6.6" fill="none" stroke="#e0485a" stroke-width="5.6" stroke-linecap="round"/><path d="M7.4 16.8 C10 18.6 15.4 17.6 16.8 8" fill="none" stroke="#f58a95" stroke-width="1.6" stroke-linecap="round" opacity=".85"/><path d="M10.6 19.9 l1.3 -2.4" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M14.8 19.2 l1.2 -2.3" stroke="#141414" stroke-width="1.6" stroke-linecap="round"/><path d="M3.7 20.2 L6.4 18.2 L5.9 21.2 Z" fill="#e0485a" stroke="#141414" stroke-width="1.1" stroke-linejoin="round"/></svg> Longanizer · report made by <b>gmzpt</b><br>
<span class="small">GTFOBins data &copy; GTFOBins · IP Geolocation by DB-IP (https://db-ip.com)</span></footer>
</body></html>"""


def generated_now() -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
