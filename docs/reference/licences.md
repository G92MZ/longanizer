# Licences and data

Longanizer is licensed under the **Apache License 2.0** — free to use, modify and distribute
(including commercially); keep the copyright and `NOTICE`, and state your changes.
© 2026 Gregorio Moreno (gmzpt).

## Libraries

| Library | Used for | Licence |
|---|---|---|
| [DuckDB](https://duckdb.org) | the case database | MIT |
| [FastAPI](https://fastapi.tiangolo.com) · [Uvicorn](https://www.uvicorn.org) | the web service | MIT · BSD-3-Clause |
| [pySigma](https://github.com/SigmaHQ/pySigma) *(optional)* | the Sigma tab | LGPL-2.1 |
| [maxminddb](https://github.com/maxmind/MaxMind-DB-Reader-python) *(optional)* | reading GeoIP databases | Apache-2.0 |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) *(optional)* | the MCP server | MIT |

Optional packages are installed by you with `pip`, not shipped in the repository.

## Data

- **GTFOBins** — the catalogue © [GTFOBins](https://gtfobins.github.io) (GPL-3.0). It is **not
  shipped** with Longanizer: the first start downloads it from the official repository into
  `gtfobins_data/` (git-ignored), and **Update catalog** refreshes it.
- **GeoIP** — IP geolocation by [DB-IP](https://db-ip.com) (DB-IP Lite, CC BY 4.0), downloaded
  on demand into `geoip_data/`.
- **Sample incident** — `sample_logs/` is synthetic, with documentation IP ranges.
- **Sigma rules** — the six examples in `reglas_sigma/` are part of the project; add your own.
