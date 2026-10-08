"""Asistente IA sobre los logs (function-calling compatible con OpenAI).

Permite preguntar en lenguaje natural ("¿hubo fuerza bruta SSH?") y que el
modelo use las herramientas de SOLO LECTURA de esta app (buscar, SQL,
contexto, stats, timeline) para responder con datos reales de los logs
cargados.

Funciona con cualquier endpoint compatible con la API de OpenAI
(`/chat/completions` + `tools`):
  - API remota: el proxy LiteLLM de tu empresa, la API de un proveedor, etc.
    (base_url + api_key [+ cabeceras/usuario extra que pida tu LiteLLM]).
  - API local: una app de IA que corras en tu máquina y exponga API
    compatible con OpenAI (Ollama con /v1, LM Studio, llama.cpp server…).

No guarda ni envía nada por su cuenta: solo llama al endpoint que tú indicas
cuando tú lanzas una pregunta. Las herramientas no pueden modificar los datos.
"""
from __future__ import annotations

import json
from typing import Any, Optional

import httpx

MAX_TOOL_ROWS = 60          # filas que se le devuelven al modelo por llamada
MAX_ITERS = 6               # tope de rondas de herramientas por pregunta
TIMEOUT = 120.0

SYSTEM_PROMPT = (
    "Eres un analista forense (DFIR) que responde preguntas sobre logs ya "
    "cargados en una base DuckDB (tabla `events`, normalizada a UTC). "
    "Usa SIEMPRE las herramientas para consultar datos reales; no inventes "
    "resultados. La columna `extra` es JSON: filtra con (extra->>'clave') "
    "entre paréntesis. El campo `seq` es la posición en la timeline (1 = más "
    "antiguo). Responde en español, de forma concisa, citando datos concretos "
    "(IPs, usuarios, timestamps, nº de eventos) y, cuando aporte, la query SQL "
    "que usaste. Si no hay datos que respalden algo, dilo."
)

# --- definición de herramientas (esquema function-calling de OpenAI) ---
TOOLS = [
    {"type": "function", "function": {
        "name": "buscar_logs",
        "description": "Busca eventos por texto (substring/IOC) o regex en los "
                       "logs. Devuelve columnas y filas coincidentes.",
        "parameters": {"type": "object", "properties": {
            "q": {"type": "string", "description": "Texto o patrón a buscar."},
            "regex": {"type": "boolean", "description": "True para tratar q como regex."},
            "source": {"type": "string", "description": "Filtrar por origen (auth, access, auditd, syslog, weberror, logfmt…). Vacío = todos."},
            "limit": {"type": "integer", "description": "Máx. filas (por defecto 50)."},
        }, "required": ["q"]},
    }},
    {"type": "function", "function": {
        "name": "consulta_sql",
        "description": "Ejecuta SQL de SOLO LECTURA (SELECT/WITH) sobre la tabla "
                       "`events` en DuckDB y devuelve el resultado. Útil para "
                       "agregaciones, correlaciones y filtros temporales.",
        "parameters": {"type": "object", "properties": {
            "sql": {"type": "string", "description": "Consulta SELECT/WITH."},
        }, "required": ["sql"]},
    }},
    {"type": "function", "function": {
        "name": "contexto",
        "description": "Devuelve las líneas alrededor de un evento, por nº de "
                       "líneas o por ventana temporal (minutos/segundos).",
        "parameters": {"type": "object", "properties": {
            "seq": {"type": "integer", "description": "Posición en la timeline (1=más antiguo)."},
            "id": {"type": "integer", "description": "Id interno del evento (alternativa a seq)."},
            "before": {"type": "number", "description": "Cantidad antes (por defecto 5)."},
            "after": {"type": "number", "description": "Cantidad después (por defecto 5)."},
            "unit": {"type": "string", "enum": ["lines", "minutes", "seconds"], "description": "Unidad de la ventana."},
        }},
    }},
    {"type": "function", "function": {
        "name": "estadisticas",
        "description": "Resumen de lo cargado: total de eventos, por origen "
                       "(con rango temporal) y claves dinámicas de `extra`.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "ver_timeline",
        "description": "Eventos en orden cronológico (con su seq), opcionalmente "
                       "por origen y rango temporal UTC (start/end 'YYYY-MM-DD HH:MM:SS').",
        "parameters": {"type": "object", "properties": {
            "source": {"type": "string"},
            "start": {"type": "string"},
            "end": {"type": "string"},
            "limit": {"type": "integer", "description": "Máx. filas (por defecto 50)."},
        }},
    }},
]


def _trim(res: dict[str, Any]) -> dict[str, Any]:
    """Recorta un resultado {columns, rows} para no saturar el contexto."""
    rows = res.get("rows", [])
    out = {"columns": res.get("columns", []), "rows": rows[:MAX_TOOL_ROWS]}
    total = res.get("total", res.get("rowcount", len(rows)))
    out["rowcount"] = res.get("rowcount", len(rows))
    if total is not None:
        out["total"] = total
    if len(rows) > MAX_TOOL_ROWS:
        out["note"] = f"Mostrando {MAX_TOOL_ROWS} de {len(rows)} filas devueltas."
    if res.get("note"):
        out["note"] = res["note"]
    return out


def run_tool(store, name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Ejecuta una herramienta (solo lectura) contra el store."""
    try:
        if name == "buscar_logs":
            return _trim(store.search(
                args["q"], regex=bool(args.get("regex")),
                source=args.get("source") or None,
                limit=int(args.get("limit") or 50), offset=0))
        if name == "consulta_sql":
            return _trim(store.query(args["sql"], limit=MAX_TOOL_ROWS))
        if name == "contexto":
            return _trim(store.context(
                row_id=args.get("id"), seq=args.get("seq"),
                before=args.get("before", 5), after=args.get("after", 5),
                unit=args.get("unit", "lines")))
        if name == "estadisticas":
            return store.stats()
        if name == "ver_timeline":
            return _trim(store.timeline(
                source=args.get("source") or None,
                start=args.get("start") or None, end=args.get("end") or None,
                limit=int(args.get("limit") or 50), offset=0))
        return {"error": f"herramienta desconocida: {name}"}
    except Exception as e:  # noqa: BLE001 - se lo devolvemos al modelo
        return {"error": str(e)}


def _headers(cfg: dict[str, Any]) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    key = (cfg.get("api_key") or "").strip()
    if key:
        h["Authorization"] = f"Bearer {key}"
    extra = cfg.get("extra_headers")
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k and v is not None:
                h[str(k)] = str(v)
    return h


def chat(store, user_message: str, cfg: dict[str, Any],
         history: Optional[list[dict]] = None) -> dict[str, Any]:
    """Una ronda de conversación con bucle de herramientas.

    cfg: base_url, model, api_key?, user?, extra_headers?.
    Devuelve {reply, tool_trace, model}.
    """
    base = (cfg.get("base_url") or "").rstrip("/")
    if not base:
        raise ValueError("Falta base_url del endpoint de IA.")
    model = cfg.get("model") or ""
    if not model:
        raise ValueError("Falta el nombre del modelo.")
    url = base + "/chat/completions"

    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": user_message})

    trace: list[dict[str, Any]] = []
    with httpx.Client(timeout=TIMEOUT) as client:
        for _ in range(MAX_ITERS):
            payload: dict[str, Any] = {
                "model": model, "messages": messages,
                "tools": TOOLS, "tool_choice": "auto",
                "temperature": cfg.get("temperature", 0),
            }
            if cfg.get("user"):
                payload["user"] = cfg["user"]
            r = client.post(url, headers=_headers(cfg), json=payload)
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}: {r.text[:500]}")
            data = r.json()
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                return {"reply": msg.get("content") or "", "tool_trace": trace,
                        "model": data.get("model", model)}
            # añade el turno del asistente (con las tool_calls) y resuelve cada una
            messages.append({"role": "assistant",
                             "content": msg.get("content") or "",
                             "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = (tc.get("function") or {})
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = run_tool(store, name, args)
                trace.append({"tool": name, "args": args,
                              "rowcount": result.get("rowcount"),
                              "error": result.get("error")})
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                                 "name": name,
                                 "content": json.dumps(result, ensure_ascii=False)})
    return {"reply": "(Se alcanzó el límite de pasos de herramientas sin una "
                     "respuesta final. Prueba a reformular la pregunta.)",
            "tool_trace": trace, "model": model}
