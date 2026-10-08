<div align="center">

# 🌭 Longanizer

**Forensic Linux log analyzer — parse once, query with SQL, hunt with Sigma.**

Drop in the logs you pulled from a box, open the browser, and investigate:
timeline, full‑text + field search, Sigma detections, GTFOBins, IOC sweep,
GeoIP and a one‑click case report. Runs **100% offline**.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-DuckDB-009688)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

</div>

---

## 🚀 Quickstart

```bash
pip install -r requirements.txt
python run.py                 # open http://127.0.0.1:8000
```

```bash
python run.py --port 8001     # run next to EVTXray on another port
python run.py --db case.duckdb  # keep the case in a file instead of memory
```

## 🧭 How you use it

1. **📥 Load** — point it at a folder or drop files (`.zip`/`.tar.gz` auto‑extract). It auto‑detects each log type.
2. **🔎 Explore** — browse the timeline or search. Words = AND, `field:value` filters, `-term` excludes, `/regex/` for power users. The box autocompletes field names.
3. **🛡️ Hunt** — run your **Sigma** rules over everything, see what matched, pivot to context.
4. **📌 Triage** — mark events as pending / TP / FP with a note (saved inside the case file).
5. **📄 Report** — export a self‑contained HTML case report to share.

## ✨ What's inside

| | |
|---|---|
| 🧩 **Many log types** | auth · syslog/kern/cron · access · auditd · web error · bash_history · logfmt · CSV · dmesg · apt/dpkg · fontconfig · udev |
| 🔎 **Smart search** | `field:value` / `=exact` / `!=` / `-NOT` / `/regex/` / `field:*` exists · field autocomplete · facets |
| 🛡️ **Sigma engine** | Linux & webserver rules, correlation, ATT&CK matrix, "what matched" per hit |
| 🧬 **auditd enrichment** | EXECVE stitched into full command lines, hex & `saddr` decoded (decoded values shown *in italics*) |
| 🪤 **GTFOBins** | cross‑references binaries actually executed (incl. BSD appliance shell logs) with the catalog |
| 🌐 **GeoIP / ASN** | public IPs tagged with country + Org/ISP (offline DB‑IP Lite) |
| 🎯 **IOC sweep** | paste IPs/hashes/paths/users and sweep every log at once, export CSV |
| ⏱️ **Live ingest** | progress by bytes with start / elapsed / ETA |
| 🤖 **AI & MCP** | optional AI tab and an MCP server to query the case from Claude |

## 📝 Notes

- Everything runs locally — no cloud, no outbound calls except the optional GeoIP database download.
- Cases are DuckDB files under `casos/` (git‑ignored). Use `--db` to pin one.
- The Python package/module is named `loganalyzer`; the app is branded **Longanizer**.

## 📜 License

Licensed under the **Apache License 2.0** — free to use, modify and distribute
(including commercially); just keep the copyright and `NOTICE`, and state your
changes. See [`LICENSE`](LICENSE).

© 2026 Gregorio Moreno (**gmzpt**)
