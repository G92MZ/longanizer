"""Lenguaje de consulta del Explorer (común a Longanizer y WinHound).

Sintaxis (estilo KQL/Lucene, sin mayúsculas en nombres ni valores):

  palabra                 texto libre: el evento CONTIENE la palabra
  "frase con espacios"    texto libre literal (también protege AND/OR/NOT)
  campo:valor             campo coincide con valor   (':' y '=' son lo mismo)
  campo = valor           se admiten espacios alrededor del operador
  campo==valor            exacto y literal (sin comodines ni listas), también en texto
  campo!=valor            NO coincide (igual que -campo:valor)
  campo>N  >=  <  <=      comparación (números y fechas: ts>=2026-10-01)
  campo:a,b,c             lista (cualquiera de los valores)
  campo:*valor*           comodines * y ? (anclados: image:*\\cmd.exe)
  campo:/regex/  /regex/  expresión regular (en el campo / en el texto)
  campo:*   campo:-       el campo tiene valor / está vacío
  a b  ·  a AND b         AND (implícito)
  a OR b                  OR
  NOT a  ·  -a            negación
  ( ... )                 agrupar

Coincidencia de 'campo:valor' según el tipo de campo:
  numérico / código (eid, pid, status, logon_type…)  -> exacto (eid:6 ≠ 4661)
  fecha (ts)                                          -> prefijo (ts:2026-10-01)
  texto                                               -> contiene
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

KW_AND = {"and", "&&"}
KW_OR = {"or", "||"}
KW_NOT = {"not", "!"}
OPS = ("==", "!=", ">=", "<=", "=", ":", ">", "<")
_ATOM_RE = re.compile(r"^((?:x:|extra\.))?([A-Za-z_@][\w.\-@]*?)(==|!=|>=|<=|=|:|>|<)(.*)$", re.S)
_IDENT_RE = re.compile(r"^(?:x:|extra\.)?[A-Za-z_@][\w.\-@]*$")


class QueryError(ValueError):
    """Consulta mal formada (se muestra tal cual al usuario)."""


def norm_field(name: str) -> str:
    """Normaliza un nombre de campo para comparar: sin mayúsculas, _ - . @"""
    return re.sub(r"[_\-.@\s]", "", (name or "").lower())


def like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _glob_to_like(s: str) -> str:
    out = []
    for c in s:
        if c == "*":
            out.append("%")
        elif c == "?":
            out.append("_")
        elif c in "\\%_":
            out.append("\\" + c)
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------------------
# Tokenizador
# ---------------------------------------------------------------------------
class Tok:
    """kind: 'W' (palabra), '(' o ')'. lit: era una cadena entre comillas
    (texto literal, nunca operador ni palabra clave). neg: llevaba un '-'
    delante, fuera de comillas."""
    __slots__ = ("kind", "text", "lit", "neg")

    def __init__(self, kind: str, text: str = "", lit: bool = False, neg: bool = False):
        self.kind, self.text, self.lit, self.neg = kind, text, lit, neg

    def __repr__(self):  # pragma: no cover - depuración
        return f"Tok({self.kind},{self.text!r},lit={self.lit},neg={self.neg})"


def tokenize(q: str) -> list[Tok]:
    """Separa por espacios respetando comillas y SIN tocar las barras
    invertidas (las regex /\\s+/ y las rutas C:\\ llegan intactas).
    '(' al inicio de un término y ')' al final son paréntesis de agrupación."""
    toks: list[Tok] = []
    cur, quote, lit, neg, started, in_regex = "", None, False, False, False, False
    i, n = 0, len(q)

    def flush():
        nonlocal cur, lit, neg, started, in_regex
        if started:
            if neg and not cur and not lit:
                toks.append(Tok("W", "-"))           # un '-' suelto es texto
            else:
                toks.append(Tok("W", cur, lit, neg))
        cur, lit, neg, started, in_regex = "", False, False, False, False

    while i < n:
        c = q[i]
        if quote:
            if c == quote:
                quote = None
            else:
                cur += c
        elif c in "\"'":
            if not cur:
                lit = True                           # "frase" -> literal
            quote, started = c, True
        elif c.isspace():
            flush()
        elif c == "(" and not started:
            toks.append(Tok("("))
        elif c == ")" and not in_regex and (i + 1 == n or q[i + 1].isspace() or q[i + 1] == ")"):
            flush()
            toks.append(Tok(")"))
        elif c == "-" and not started:
            neg = started = True
        else:
            started = True
            lit = False                              # "a"b ya no es literal
            cur += c
            if c == "/" and (cur == "/" or re.search(r"(:|=)/$", cur)):
                in_regex = True
            elif c == "/" and in_regex and len(cur) > 1:
                in_regex = False
        i += 1
    if quote:
        raise QueryError("Unclosed quote (\" or ') in the query.")
    flush()
    return toks


def _merge_spaced(toks: list[Tok], is_field: Callable[[str], bool]) -> list[Tok]:
    """Une 'campo = valor', 'campo: valor', 'campo :valor' y la forma con
    palabra 'campo contains valor' en un solo término campo:valor."""
    out: list[Tok] = []
    i = 0
    W = lambda t: t is not None and t.kind == "W"
    while i < len(toks):
        t = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        nxt2 = toks[i + 2] if i + 2 < len(toks) else None
        if W(t) and not t.lit:
            core = t.text
            ident = bool(_IDENT_RE.match(core))
            # campo  OP  valor
            if (ident and W(nxt) and not nxt.lit and not nxt.neg and nxt.text in OPS
                    and W(nxt2) and is_field(core)):
                out.append(Tok("W", core + nxt.text + nxt2.text, False, t.neg))
                i += 3
                continue
            # campo contains valor
            if (ident and W(nxt) and not nxt.lit and nxt.text.lower() == "contains" and W(nxt2)):
                out.append(Tok("W", core + ":" + nxt2.text, False, t.neg))
                i += 3
                continue
            # campo:  valor   /  campo=  valor
            m = re.match(r"^(.*?)(==|!=|>=|<=|=|:|>|<)$", core)
            if (m and W(nxt) and not nxt.neg and _IDENT_RE.match(m.group(1))
                    and is_field(m.group(1))):
                out.append(Tok("W", core + nxt.text, False, t.neg))
                i += 2
                continue
            # campo  :valor   /  campo  =valor
            if (ident and W(nxt) and not nxt.lit and not nxt.neg and is_field(core)
                    and re.match(r"^(==|!=|>=|<=|=|:|>|<)\S", nxt.text)):
                out.append(Tok("W", core + nxt.text, False, t.neg))
                i += 2
                continue
        out.append(t)
        i += 1
    return out


# ---------------------------------------------------------------------------
# Compilador a SQL
# ---------------------------------------------------------------------------
class Compiler:
    """Convierte la consulta en (sql, params, warnings).

    resolve(name, prefix) -> (expr_sql, kind) o None; kind in
    {'num', 'code', 'ts', 'text'}. prefix es 'x:'/'extra.' o ''."""

    def __init__(self, resolve: Callable[[str, str], Optional[tuple[str, str]]],
                 text_expr: str, regex_expr: str):
        self.resolve = resolve
        self.text_expr = text_expr
        self.regex_expr = regex_expr
        self.warnings: list[str] = []

    # -- entrada ------------------------------------------------------------
    def compile(self, q: str) -> tuple[str, list[Any], list[str]]:
        q = (q or "").strip()
        if not q:
            raise QueryError("Empty query.")
        toks = tokenize(q)
        toks = _merge_spaced(toks, lambda f: self._is_field(f))
        self.toks, self.pos = toks, 0
        if not toks:
            raise QueryError("Empty query.")
        sql, params = self._or()
        if self.pos < len(self.toks):
            t = self.toks[self.pos]
            raise QueryError("Unexpected ')' in the query." if t.kind == ")"
                             else f"Unexpected {t.text!r} in the query.")
        return sql, params, self.warnings

    def _is_field(self, name: str) -> bool:
        pre = ""
        if name.startswith("x:"):
            pre, name = "x:", name[2:]
        elif name.startswith("extra."):
            pre, name = "extra.", name[6:]
        return self.resolve(name, pre) is not None

    # -- gramática: or := and (OR and)* ; and := not (AND? not)* ------------
    def _peek(self) -> Optional[Tok]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _is_kw(self, t: Optional[Tok], kws: set) -> bool:
        return bool(t and t.kind == "W" and not t.lit and not t.neg and t.text.lower() in kws)

    def _or(self):
        parts = [self._and()]
        while self._is_kw(self._peek(), KW_OR):
            self.pos += 1
            if self._peek() is None or self._peek().kind == ")":
                raise QueryError("OR needs something on both sides.")
            parts.append(self._and())
        if len(parts) == 1:
            return parts[0]
        return "(" + " OR ".join(p[0] for p in parts) + ")", [x for p in parts for x in p[1]]

    def _and(self):
        parts = [self._not()]
        while True:
            t = self._peek()
            if t is None or t.kind == ")" or self._is_kw(t, KW_OR):
                break
            if self._is_kw(t, KW_AND):
                self.pos += 1
                if self._peek() is None or self._peek().kind == ")":
                    raise QueryError("AND needs something on both sides.")
                continue
            parts.append(self._not())
        if len(parts) == 1:
            return parts[0]
        return "(" + " AND ".join(p[0] for p in parts) + ")", [x for p in parts for x in p[1]]

    def _not(self):
        t = self._peek()
        if self._is_kw(t, KW_NOT):
            self.pos += 1
            if self._peek() is None:
                raise QueryError("NOT needs something after it.")
            s, p = self._not()
            return f"NOT coalesce({s}, FALSE)", p
        return self._primary()

    def _primary(self):
        t = self._peek()
        if t is None:
            raise QueryError("Incomplete query.")
        if t.kind == "(":
            self.pos += 1
            if self._peek() is not None and self._peek().kind == ")":
                raise QueryError("Empty parentheses ().")
            s, p = self._or()
            if self._peek() is None or self._peek().kind != ")":
                raise QueryError("Missing closing parenthesis ')'.")
            self.pos += 1
            return s, p
        if t.kind == ")":
            raise QueryError("Unexpected ')' in the query.")
        if self._is_kw(t, KW_AND | KW_OR):
            raise QueryError(f"{t.text.upper()} needs something on both sides.")
        self.pos += 1
        return self._atom(t)

    # -- términos -----------------------------------------------------------
    def _atom(self, t: Tok):
        frag, params = self._free_text(t.text) if t.lit else self._term(t.text)
        if t.neg:
            frag = f"NOT coalesce({frag}, FALSE)"
        return frag, params

    def _free_text(self, s: str):
        if len(s) > 2 and s.startswith("/") and s.endswith("/"):
            return f"regexp_matches({self.regex_expr}, ?, 'i')", [s[1:-1]]
        core = s.strip("*")
        if core and ("*" in core or "?" in core):
            return f"{self.text_expr} ILIKE ? ESCAPE '\\'", ["%" + _glob_to_like(core) + "%"]
        return f"{self.text_expr} ILIKE ? ESCAPE '\\'", [f"%{like_escape(core or s)}%"]

    def _term(self, s: str):
        m = _ATOM_RE.match(s)
        if not m:
            return self._free_text(s)
        pre, name, op, val = m.group(1) or "", m.group(2), m.group(3), m.group(4)
        res = self.resolve(name, pre)
        if res is None:
            # Rutas (C:\...), URLs (http://...) y similares: texto libre sin aviso
            plain = len(name) == 1 or val.startswith(("\\", "/")) or (op == ":" and not val)
            if not plain:
                self.warnings.append(
                    f"Unknown field '{name}' — searched as plain text. "
                    f"Check the field list (autocomplete) or use x:Key for EventData/extra keys.")
            return self._free_text(s)
        expr, kind = res
        return self._field_clause(name, expr, kind, op, val)

    def _field_clause(self, name: str, expr: str, kind: str, op: str, val: str):
        sval = f"CAST({expr} AS VARCHAR)"
        if op == "!=":
            f, p = self._field_clause(name, expr, kind, ":", val)
            return f"NOT coalesce({f}, FALSE)", p
        if val == "" and op in (":", "=", "=="):
            raise QueryError(f"'{name}{op}' has no value. Use {name}:* (has a value) or {name}:- (empty).")
        if op in (":", "=") and val == "*":
            return f"({expr} IS NOT NULL AND {sval} <> '')", []
        if op in (":", "=") and val == "-":
            return f"({expr} IS NULL OR {sval} = '')", []
        if op in (":", "=") and len(val) > 2 and val.startswith("/") and val.endswith("/"):
            return f"regexp_matches({sval}, ?, 'i')", [val[1:-1]]

        if op in (">", ">=", "<", "<="):
            if kind == "num":
                try:
                    num = float(val) if "." in val else int(val)
                except ValueError:
                    raise QueryError(f"'{name}' is numeric: {name}{op}{val} needs a number.")
                return f"{expr} {op} ?", [num]
            if kind == "ts":
                return f"{expr} {op} CAST(? AS TIMESTAMP)", [val.replace("T", " ").rstrip("Z")]
            return f"lower({sval}) {op} lower(?)", [val]

        literal = op == "=="                 # '==' = valor literal: sin comodines ni listas
        exact = literal or kind in ("num", "code")
        vals = ([v.strip() for v in val.split(",")]
                if kind in ("num", "code") and not literal else [val])
        vals = [v for v in vals if v != ""] or [val]

        if kind == "num":
            ints, bad = [], []
            for v in vals:
                (ints if re.fullmatch(r"-?\d+", v) else bad).append(v)
            notnum = [v for v in bad if "*" not in v and "?" not in v]
            if notnum:
                self.warnings.append(f"'{name}' is numeric; '{', '.join(notnum)}' is not a number.")
            frags, params = [], []
            if ints:
                if len(ints) == 1:
                    frags.append(f"{expr} = ?")
                else:
                    frags.append(f"{expr} IN ({', '.join('?' * len(ints))})")
                params.extend(int(v) for v in ints)
            for v in bad:
                if ("*" in v or "?" in v) and not literal:
                    frags.append(f"{sval} ILIKE ? ESCAPE '\\'")
                    params.append(_glob_to_like(v))
                else:
                    frags.append(f"{sval} = ?")
                    params.append(v)
            return ("(" + " OR ".join(frags) + ")" if len(frags) > 1 else frags[0]), params

        if kind == "ts" and op != "==":
            return f"{sval} LIKE ? ESCAPE '\\'", [like_escape(val.replace("T", " ")) + "%"]

        frags, params = [], []
        for v in vals:
            if ("*" in v or "?" in v) and not literal:
                frags.append(f"{sval} ILIKE ? ESCAPE '\\'")
                params.append(_glob_to_like(v))
            elif exact:
                frags.append(f"lower({sval}) = lower(?)")
                params.append(v)
            else:
                frags.append(f"{sval} ILIKE ? ESCAPE '\\'")
                params.append(f"%{like_escape(v)}%")
        return ("(" + " OR ".join(frags) + ")" if len(frags) > 1 else frags[0]), params


def compile_query(q: str, resolve, text_expr: str, regex_expr: str):
    """Atajo: devuelve (sql, params, warnings)."""
    return Compiler(resolve, text_expr, regex_expr).compile(q)
