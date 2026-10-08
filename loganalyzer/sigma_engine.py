"""Motor Sigma -> SQL (DuckDB) para LogAnalyzer.

Usa pySigma SOLO para parsear las reglas (YAML, logsource, modificadores y la
gramática de `condition`), y traduce el árbol de condición ya resuelto a una
cláusula WHERE sobre la tabla `events`, con el mapeo de campos de `sigma_map`.

Detección histórica (retro-hunting): cada regla -> un SELECT. Las reglas que no
aplican a datos Linux/web, o cuyo logsource no está cargado, o que usan algo no
soportado, se SALTAN con motivo (nunca se traducen mal en silencio).

pySigma es dependencia opcional: si no está instalado, importar este módulo
lanza ImportError y la app desactiva la pestaña Sigma, sin romper el resto.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any, Optional

import yaml

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND, ConditionOR, ConditionNOT,
    ConditionFieldEqualsValueExpression, ConditionValueExpression,
)
from sigma.types import (
    SigmaString, SigmaNumber, SigmaNull, SigmaRegularExpression,
    SigmaCIDRExpression, SigmaCompareExpression, SigmaExpansion, SpecialChars,
    SigmaBool, SigmaFieldReference, SigmaExists,
)

from .sigma_map import (
    LOGSOURCE_PREDICATES, rule_logsource_key, resolve_field,
)


class Unsupported(Exception):
    """La regla usa algo que el backend aún no traduce; se salta."""


# ---------------------------------------------------------------------------
# Carga de reglas
# ---------------------------------------------------------------------------
def list_rule_files(path: str) -> list[str]:
    """Lista los .yml/.yaml bajo `path` (o el propio fichero)."""
    if os.path.isfile(path):
        return [path]
    files: list[str] = []
    for root, _dirs, fns in os.walk(path):
        for fn in sorted(fns):
            if fn.lower().endswith((".yml", ".yaml")):
                files.append(os.path.join(root, fn))
    return files


def load_one_file(fp: str) -> tuple[list, list[dict]]:
    """Carga un único fichero de reglas. Devuelve (reglas, errores)."""
    try:
        col = SigmaCollection.from_yaml(open(fp, encoding="utf-8").read())
        return list(col.rules), []
    except Exception as e:  # noqa: BLE001
        return [], [{"file": os.path.basename(fp), "error": str(e)[:300]}]


def try_bulk_load(files: list[str]):
    """Intenta cargar todo junto (resuelve correlaciones cruzadas). None si falla."""
    try:
        return list(SigmaCollection.load_ruleset(files).rules)
    except Exception:  # noqa: BLE001
        return None


def load_rules_dir(path: str) -> tuple[list, list[dict]]:
    """Carga todos los .yml/.yaml bajo `path`. Devuelve (reglas, errores).

    Primero intenta cargar TODO junto (resuelve referencias cruzadas de las
    reglas de correlación entre ficheros); si falla, cae a fichero-a-fichero
    aislando el que da error (perdiendo correlaciones entre ficheros)."""
    files: list[str] = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, _dirs, fns in os.walk(path):
            for fn in sorted(fns):
                if fn.lower().endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, fn))
    if not files:
        return [], []
    try:
        col = SigmaCollection.load_ruleset(files)
        return list(col.rules), []
    except Exception:  # noqa: BLE001 - un fichero rompe el lote -> por fichero
        pass
    rules: list = []
    errors: list[dict] = []
    for fp in files:
        try:
            col = SigmaCollection.from_yaml(open(fp, encoding="utf-8").read())
            rules.extend(col.rules)
        except Exception as e:  # noqa: BLE001
            errors.append({"file": os.path.basename(fp), "error": str(e)[:300]})
    return rules, errors


# ---------------------------------------------------------------------------
# Traducción de valores a SQL
# ---------------------------------------------------------------------------
def _q(s: str) -> str:
    """Literal SQL con comillas simples escapadas."""
    return "'" + str(s).replace("'", "''") + "'"


def _like_from_string(v: SigmaString) -> tuple[str, bool]:
    """SigmaString -> patrón LIKE (., %, _) y si lleva comodín."""
    out: list[str] = []
    wild = False
    for part in v.s:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append("%"); wild = True
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append("_"); wild = True
        else:
            t = str(part).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            out.append(t)
    return "".join(out), wild


def _regex_text(v: SigmaRegularExpression) -> str:
    r = v.regexp
    if isinstance(r, str):
        pat = r
    else:  # SigmaString con */? parseados: reconstruir como literales de regex
        buf = []
        for part in r.s:
            if part is SpecialChars.WILDCARD_MULTI:
                buf.append("*")
            elif part is SpecialChars.WILDCARD_SINGLE:
                buf.append("?")
            else:
                buf.append(str(part))
        pat = "".join(buf)
    flags = getattr(v, "flags", set()) or set()
    if any(getattr(f, "name", "").upper() == "IGNORECASE" for f in flags) \
            and not pat.startswith("(?i)"):
        pat = "(?i)" + pat
    return pat


_CMP = {"LT": "<", "LTE": "<=", "GT": ">", "GTE": ">="}


def _cidr_sql(fx_text: str, v: SigmaCIDRExpression) -> str:
    """Match CIDR genérico (IPv4 e IPv6, cualquier prefijo) vía la UDF
    sigma_ip_in_cidr registrada en la conexión. Los valores no-IP dan FALSE."""
    net = v.network
    return (f"COALESCE(sigma_ip_in_cidr({fx_text}, {_q(str(net))}), FALSE)")


def _value_sql(fx: str, value: Any) -> str:
    fx_text = f"CAST({fx} AS VARCHAR)"
    if isinstance(value, SigmaExpansion):
        # base64offset/windash/etc.: pySigma expande a varias alternativas (OR)
        return "(" + " OR ".join(_value_sql(fx, v) for v in value.values) + ")"
    if isinstance(value, SigmaNull):
        return f"{fx} IS NULL"
    if isinstance(value, SigmaExists):
        return f"{fx} IS NOT NULL" if value.exists else f"{fx} IS NULL"
    if isinstance(value, SigmaBool):
        truthy = f"lower({fx_text}) IN ('true','1','yes','enabled')"
        return truthy if value.boolean else f"NOT ({truthy})"
    if isinstance(value, SigmaCompareExpression):
        op = _CMP.get(getattr(value.op, "name", ""), None)
        if not op:
            raise Unsupported("comparador numérico")
        return f"TRY_CAST({fx} AS DOUBLE) {op} {value.number.number}"
    if isinstance(value, SigmaNumber):
        return f"{fx_text} = {_q(str(value.number))}"
    if isinstance(value, SigmaString):
        pat, _wild = _like_from_string(value)
        return f"{fx_text} ILIKE {_q(pat)} ESCAPE '\\'"
    if isinstance(value, SigmaRegularExpression):
        return f"regexp_matches({fx_text}, {_q(_regex_text(value))})"
    if isinstance(value, SigmaCIDRExpression):
        return _cidr_sql(fx_text, value)
    raise Unsupported(f"valor {type(value).__name__}")


_RAW = "CAST(COALESCE(ev.raw, ev.message, '') AS VARCHAR)"


def _keyword_sql(value: Any) -> str:
    if isinstance(value, SigmaNull):
        # keyword nulo (p.ej. un bloque `fields:` vacío usado con `and fields`):
        # no aporta filtro -> cláusula neutra verdadera.
        return "1=1"
    if isinstance(value, SigmaString):
        pat, wild = _like_from_string(value)
        if not wild:
            pat = "%" + pat + "%"
        return f"{_RAW} ILIKE {_q(pat)} ESCAPE '\\'"
    if isinstance(value, SigmaNumber):
        return f"{_RAW} ILIKE {_q('%' + str(value.number) + '%')} ESCAPE '\\'"
    if isinstance(value, SigmaRegularExpression):
        return f"regexp_matches({_RAW}, {_q(_regex_text(value))})"
    raise Unsupported(f"keyword {type(value).__name__}")


def _keyword_text(value: Any) -> Optional[str]:
    """Texto llano de un keyword (para resaltarlo en el detalle del hit)."""
    if isinstance(value, SigmaString):
        txt = "".join(str(p) for p in value.s if not isinstance(p, SpecialChars))
        return txt or None
    if isinstance(value, SigmaNumber):
        return str(value.number)
    return None


def _walk(node: Any, lskey: str, acc: dict) -> str:
    if isinstance(node, ConditionAND):
        return "(" + " AND ".join(_walk(a, lskey, acc) for a in node.args) + ")"
    if isinstance(node, ConditionOR):
        return "(" + " OR ".join(_walk(a, lskey, acc) for a in node.args) + ")"
    if isinstance(node, ConditionNOT):
        return "(NOT " + _walk(node.args[0], lskey, acc) + ")"
    if isinstance(node, ConditionFieldEqualsValueExpression):
        if node.field not in acc["fields"] and len(acc["fields"]) < 8:
            acc["fields"][node.field] = resolve_field(lskey, node.field)
        if isinstance(node.value, SigmaFieldReference):
            # comparación campo==campo (|fieldref), con variantes de subcadena
            a = f"CAST({resolve_field(lskey, node.field)} AS VARCHAR)"
            b = f"CAST({resolve_field(lskey, node.value.field)} AS VARCHAR)"
            sw = getattr(node.value, "starts_with", False)
            ew = getattr(node.value, "ends_with", False)
            if sw and ew:
                return f"contains({a}, {b})"
            if sw:
                return f"starts_with({a}, {b})"
            if ew:
                return f"ends_with({a}, {b})"
            return f"{a} = {b}"
        return _value_sql(resolve_field(lskey, node.field), node.value)
    if isinstance(node, ConditionValueExpression):
        kw = _keyword_text(node.value)
        if kw and kw not in acc["keywords"]:
            acc["keywords"].append(kw)
        return _keyword_sql(node.value)
    raise Unsupported(f"condición {type(node).__name__}")


def _detection_sql(rule, lskey: str) -> tuple[str, dict]:
    acc = {"fields": {}, "keywords": []}  # fields: label->expr (orden de inserción)
    parts = [_walk(pc.parse(), lskey, acc) for pc in rule.detection.parsed_condition]
    if not parts:
        raise Unsupported("sin condición")
    sql = "(" + " OR ".join(parts) + ")" if len(parts) > 1 else parts[0]
    return sql, acc


_LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_CORR_OP = {"GTE": ">=", "GT": ">", "LTE": "<=", "LT": "<", "EQ": "="}


def _correlation_sql(corr):
    """Construye el SQL de una correlación sin ejecutarlo.
    Devuelve (sql, lskey, group_by, error)."""
    base_rules = [getattr(r, "rule", None) for r in corr.rules]
    base_rules = [b for b in base_rules if b is not None]
    if not base_rules:
        return None, None, [], "no base rules resolved (missing 'name'?)"
    typ = getattr(corr.type, "name", str(corr.type)).lower()
    gb = list(corr.group_by or [])
    lskey = None
    selects = []
    for i, br in enumerate(base_rules):
        k = rule_logsource_key(br.logsource.product, br.logsource.category,
                               br.logsource.service)
        if k is None or k not in LOGSOURCE_PREDICATES:
            return None, None, gb, f"non-Linux base rule: {getattr(br,'title','?')}"
        lskey = lskey or k
        try:
            det, _acc = _detection_sql(br, k)
        except Unsupported as e:
            return None, None, gb, f"unsupported base rule: {e}"
        gcols = "".join(f", {resolve_field(k, f)} AS g{j}" for j, f in enumerate(gb))
        fref = ""
        if typ == "value_count" and corr.condition.fieldref:
            fref = f", CAST({resolve_field(k, corr.condition.fieldref)} AS VARCHAR) AS fref"
        selects.append(
            f"SELECT ev.ts AS ts, ev.id AS id, {i} AS tag{gcols}{fref} "
            f"FROM events ev WHERE ev.sigma_ok=1 AND ({LOGSOURCE_PREDICATES[k]}) "
            f"AND ({det}) AND ev.ts IS NOT NULL")
    base = "\nUNION ALL\n".join(selects)
    secs = int(corr.timespan.seconds) or 60
    op = _CORR_OP.get(getattr(corr.condition.op, "name", "GTE"), ">=")
    cnt = int(corr.condition.count or 1)
    if typ == "event_count":
        agg = "count(*)"
    elif typ == "value_count":
        agg = "count(DISTINCT fref)"
    elif typ in ("temporal", "temporal_ordered"):
        agg, cnt, op = "count(DISTINCT tag)", len(base_rules), ">="
    else:
        return None, None, gb, f"unsupported correlation type: {typ}"
    gsel = "".join(f"g{j}, " for j in range(len(gb)))
    sql = (f"WITH base AS (\n{base}\n)\n"
           f"SELECT {gsel}floor(epoch(ts)/{secs}) AS bucket, {agg} AS c, "
           f"min(ts) AS tmin, max(ts) AS tmax, min(id) AS sample_id "
           f"FROM base GROUP BY {gsel}bucket HAVING {agg} {op} {cnt} "
           f"ORDER BY c DESC LIMIT 200")
    return sql, lskey, gb, None


def _run_correlation(store, corr):
    """Ejecuta una regla de correlación Sigma (event_count/value_count/temporal)
    como una agregación con ventanas de tiempo (tumbling, aprox.).
    Devuelve (finding|None, error|None)."""
    sql, lskey, gb, err = _correlation_sql(corr)
    if err:
        return None, err
    try:
        res = store.sigma_select(sql)
    except Exception as e:  # noqa: BLE001
        return None, f"correlation SQL error: {str(e)[:160]}"
    hits = []
    n = len(gb)
    for row in res["rows"]:
        gvals = [("" if v is None else str(v)) for v in row[:n]]
        c, tmin, tmax, sid = row[n + 1], row[n + 2], row[n + 3], row[n + 4]
        hits.append(gvals + [f"{tmin} → {tmax}", c, sid])
    if not hits:
        return None, None  # aplicada pero sin grupos que cumplan
    return {
        "id": str(corr.id) if corr.id else None,
        "title": getattr(corr, "title", "(correlation)"),
        "level": str(corr.level).lower() if getattr(corr, "level", None) else None,
        "tags": [str(t) for t in getattr(corr, "tags", [])],
        "logsource": (lskey or "linux") + " · correlation",
        "count": sum(h[-2] for h in hits),
        "correlation": True,
        "columns": gb + ["window (UTC)", "events"],
        "hits": hits,
        "keywords": [],
        "yaml": _rule_full_yaml(corr),
    }, None


# ---------------------------------------------------------------------------
# Ejecución de un ruleset
# ---------------------------------------------------------------------------
def preview(store, rules: list) -> dict:
    """Resumen de aplicabilidad sin ejecutar: cuántas aplican, cuántas no son
    Linux/web y cuántas no tienen datos cargados."""
    from collections import Counter
    aplic = no_linux = sin_datos = corr = 0
    by: Counter = Counter()
    present: dict[str, bool] = {}
    for rule in rules:
        if type(rule).__name__ == "SigmaCorrelationRule":
            corr += 1
            aplic += 1
            continue
        key = rule_logsource_key(rule.logsource.product, rule.logsource.category,
                                 rule.logsource.service)
        if key is None or key not in LOGSOURCE_PREDICATES:
            no_linux += 1
            continue
        if key not in present:
            present[key] = store.logsource_present(LOGSOURCE_PREDICATES[key])
        if present[key]:
            aplic += 1
            by[key] += 1
        else:
            sin_datos += 1
    return {"aplicables": aplic, "no_linux": no_linux, "sin_datos": sin_datos,
            "correlacion": corr, "por_logsource": dict(by)}


def _run_one(store, rule, present: dict, limit_per_rule: int):
    """Ejecuta UNA regla. Devuelve (finding|None, skip|None, applied_bool)."""
    title = getattr(rule, "title", "(sin título)")
    if type(rule).__name__ == "SigmaCorrelationRule":
        f, err = _run_correlation(store, rule)
        if err:
            return None, {"title": title, "reason": err}, False
        return f, None, True
    key = rule_logsource_key(rule.logsource.product, rule.logsource.category,
                             rule.logsource.service)
    if key is None or key not in LOGSOURCE_PREDICATES:
        return None, {"title": title, "reason": "non-Linux/unmapped logsource"}, False
    pred = LOGSOURCE_PREDICATES[key]
    if key not in present:
        present[key] = store.logsource_present(pred)
    if not present[key]:
        return None, {"title": title, "reason": f"no data for {key}"}, False
    try:
        where_det, acc = _detection_sql(rule, key)
    except Unsupported as e:
        return None, {"title": title, "reason": f"unsupported: {e}"}, False
    except Exception as e:  # noqa: BLE001
        return None, {"title": title, "reason": f"translation error: {str(e)[:150]}"}, False
    where = f"ev.sigma_ok=1 AND ({pred}) AND ({where_det})"
    # columnas extra = los campos que la regla referencia (para "qué hizo match")
    labels = list(acc["fields"].keys())
    extra_sel = [(f"m{n}", acc["fields"][lab]) for n, lab in enumerate(labels)]
    try:
        res = store.sigma_run(where, limit_per_rule, extra_sel)
    except Exception as e:  # noqa: BLE001
        return None, {"title": title, "reason": f"SQL error: {str(e)[:150]}"}, False
    if res["total"] == 0:
        return None, None, True  # ejecutada, sin hallazgos
    base_n = 7  # seq,id,ts,source,program,detalle,src_file
    hits = []
    for row in res["rows"]:
        base, vals = row[:base_n], row[base_n:]
        match = " · ".join(f"{lab}={v}" for lab, v in zip(labels, vals)
                           if v not in (None, ""))
        hits.append(base + [match])
    finding = {
        "id": str(rule.id) if rule.id else None,
        "title": title,
        "level": str(rule.level).lower() if rule.level else None,
        "tags": [str(t) for t in rule.tags],
        "logsource": key,
        "count": res["total"],
        "columns": res["columns"][:base_n] + ["match"],
        "hits": hits,
        "keywords": acc["keywords"],
        "yaml": _rule_full_yaml(rule),
    }
    return finding, None, True


def iter_run(store, rules: list, limit_per_rule: int = 200):
    """Generador: ejecuta las reglas una a una emitiendo progreso.

    Emite por cada regla un dict {"i", "total", "title", "applied", "found",
    "hits"} y, al final, {"done": True, ...} con el mismo payload que run()."""
    findings: list[dict] = []
    skipped: list[dict] = []
    applied = 0
    present: dict[str, bool] = {}
    total = len(rules)
    for i, rule in enumerate(rules, 1):
        title = getattr(rule, "title", "(sin título)")
        finding, skip, was_applied = _run_one(store, rule, present, limit_per_rule)
        if was_applied:
            applied += 1
        if skip:
            skipped.append(skip)
        if finding:
            findings.append(finding)
        yield {"i": i, "total": total, "title": title, "applied": applied,
               "found": len(findings),
               "hits": finding["count"] if finding else 0}
    findings.sort(key=lambda f: (_LEVEL_RANK.get(f["level"], 5), -f["count"]))
    yield {"done": True, "findings": findings, "applied": applied,
           "skipped": skipped, "rules_total": total,
           "total_hits": sum(f["count"] for f in findings)}


def run(store, rules: list, limit_per_rule: int = 200) -> dict:
    """Ejecuta todas las reglas y devuelve el resultado completo (sin streaming)."""
    final: dict = {}
    for item in iter_run(store, rules, limit_per_rule):
        if item.get("done"):
            final = {k: v for k, v in item.items() if k != "done"}
    return final


# ---------------------------------------------------------------------------
# Listado de reglas con su SQL equivalente (para auditar qué hace cada una)
# ---------------------------------------------------------------------------
def _select_from_where(where: str) -> str:
    return ('SELECT ts, source, program, "user", src_ip, '
            'coalesce(message, raw) AS detalle\n'
            'FROM events ev\n'
            f'WHERE {where}\n'
            'ORDER BY ts NULLS LAST, id')


def _compile_normal(rule):
    """-> (key, where_sql, reason). where_sql=None si no se puede compilar."""
    key = rule_logsource_key(rule.logsource.product, rule.logsource.category,
                             rule.logsource.service)
    if key is None or key not in LOGSOURCE_PREDICATES:
        return None, None, "logsource no-Linux/no-mapeado"
    try:
        det, _acc = _detection_sql(rule, key)
    except Unsupported as e:
        return key, None, f"unsupported: {e}"
    except Exception as e:  # noqa: BLE001
        return key, None, f"translation error: {str(e)[:150]}"
    where = f"ev.sigma_ok=1 AND ({LOGSOURCE_PREDICATES[key]}) AND ({det})"
    return key, where, None


def _rule_full_yaml(rule) -> Optional[str]:
    """YAML completo de la regla (para mostrarla al desplegar sus hallazgos)."""
    try:
        d = rule.to_dict()
        ls = d.get("logsource")
        if isinstance(ls, dict):   # to_dict() inyecta la ruta del fichero: fuera
            d["logsource"] = {k: v for k, v in ls.items()
                              if k in ("product", "category", "service", "definition")}
        return yaml.safe_dump(d, sort_keys=False, allow_unicode=True,
                              default_flow_style=False)
    except Exception:  # noqa: BLE001
        return None


def _rule_yaml(rule) -> Optional[str]:
    """Reserializa el YAML equivalente (logsource + detection, o correlation)."""
    try:
        d = rule.to_dict()
        snip = {k: d[k] for k in ("logsource", "detection", "correlation") if k in d}
        if not snip:
            return None
        # to_dict() inyecta la ruta del fichero en logsource.source: fuera
        if isinstance(snip.get("logsource"), dict):
            snip["logsource"] = {k: v for k, v in snip["logsource"].items()
                                 if k in ("product", "category", "service", "definition")}
        return yaml.safe_dump(snip, sort_keys=False, allow_unicode=True,
                              default_flow_style=False)
    except Exception:  # noqa: BLE001
        return None


def list_rules(store, rules: list) -> list[dict]:
    """Cada regla con su título, logsource, si es aplicable y su SQL equivalente.
    Las aplicables primero (por nivel); las no aplicables, con su motivo."""
    out: list[dict] = []
    present: dict[str, bool] = {}
    for rule in rules:
        base = {"title": getattr(rule, "title", "(sin título)"),
                "id": str(rule.id) if getattr(rule, "id", None) else None,
                "level": (str(rule.level).lower()
                          if getattr(rule, "level", None) else None),
                "tags": [str(t) for t in getattr(rule, "tags", [])],
                "yaml": _rule_yaml(rule)}
        if type(rule).__name__ == "SigmaCorrelationRule":
            sql, lskey, _gb, err = _correlation_sql(rule)
            base.update({"type": "correlation",
                         "logsource": (lskey or "linux") + " · correlation",
                         "applicable": err is None, "reason": err, "sql": sql})
            out.append(base)
            continue
        key, where, reason = _compile_normal(rule)
        base.update({"type": "regla", "logsource": key})
        if where is None:
            base.update({"applicable": False, "reason": reason, "sql": None})
        else:
            if key not in present:
                present[key] = store.logsource_present(LOGSOURCE_PREDICATES[key])
            if not present[key]:
                base.update({"applicable": False,
                             "reason": f"no data for {key}", "sql": None})
            else:
                base.update({"applicable": True, "reason": None,
                             "sql": _select_from_where(where)})
        out.append(base)
    out.sort(key=lambda r: (0 if r["applicable"] else 1,
                            _LEVEL_RANK.get(r["level"], 5), r["title"].lower()))
    return out
