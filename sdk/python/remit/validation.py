import base64
import math
import re
from datetime import date

from . import core


def schema_type(s):
    if not isinstance(s, dict) or not any(k in s for k in ("type", "$schema", "anyOf", "oneOf")):
        return s
    alternatives = s.get("anyOf", s.get("oneOf"))
    if alternatives is not None:
        inner = [x for x in alternatives if x.get("type") != "null"]
        if len(alternatives) != 2 or len(inner) != 1:
            raise ValueError("unsupported union")
        return {"optional": schema_type(inner[0])}
    kind = s.get("type")
    if isinstance(kind, list):
        if len(kind) != 2 or "null" not in kind:
            raise ValueError("unsupported union")
        return {"optional": schema_type({**s, "type": next(k for k in kind if k != "null")})}
    if "enum" in s:
        return {"enum": s["enum"]}
    if "const" in s:
        return {"enum": [s["const"]]}
    if kind == "boolean":
        return "bool"
    if kind in ("integer", "number"):
        body = {"min": s.get("minimum", s.get("x-remit-minimum")), "max": s.get("maximum", s.get("x-remit-maximum"))}
        if kind == "number":
            body["precision"] = s.get("x-remit-precision", s.get("multipleOf"))
        return {"int" if kind == "integer" else "float": body}
    if kind == "string":
        fmt = s.get("format")
        if fmt in ("decimal", "date", "date-time"):
            body = {"min": s.get("x-remit-minimum", s.get("formatMinimum")), "max": s.get("x-remit-maximum", s.get("formatMaximum"))}
            if fmt == "decimal":
                body["scale"] = s["x-remit-scale"]
            elif "x-remit-granularity" in s:
                body["granularity"] = s["x-remit-granularity"]
            return {"timestamp" if fmt == "date-time" else fmt: body}
        if s.get("contentEncoding") == "base64":
            return {"bytes": {"max_len": s["x-remit-maxBytes"]}}
        body = {"max_len": s["maxLength"], "charset": s.get("x-remit-charset", "unicode")}
        if "pattern" in s:
            body["pattern"] = s["pattern"]
        return {"string": body}
    if kind == "array":
        table = s.get("x-remit-table", False)
        return {"table" if table else "list": {"max_rows" if table else "max": s["maxItems"], "of": schema_type(s["items"])}}
    if kind == "object":
        fields = {}
        for name, value in s.get("properties", {}).items():
            inner = schema_type(value)
            fields[name] = inner if name in s.get("required", []) or isinstance(inner, dict) and "optional" in inner else {"optional": inner}
        return {"struct": fields}
    raise ValueError("unsupported result schema")


def validate(returns, params, value):
    rt = schema_type(returns)
    core.capacity(rt, params)

    def walk(t, v, depth=0):
        if depth > 128:
            raise ValueError("result nesting exceeds limit")
        kind, body = ("bool", None) if t == "bool" else next(iter(t.items()))

        def bound(name, default=None):
            x = body.get(name, default)
            return params[x[1:]] if isinstance(x, str) and x.startswith("$") else x

        valid = False
        if kind == "optional":
            if v is not None:
                walk(body, v, depth + 1)
            return
        if kind == "bool":
            valid = isinstance(v, bool)
        elif kind in ("int", "float", "decimal"):
            if isinstance(v, bool) or not isinstance(v, (int, float, str)) or isinstance(v, str) and kind != "decimal":
                raise ValueError("expected numeric result")
            n = v if kind == "int" else float(v)
            lo, hi = bound("min"), bound("max")
            valid = math.isfinite(n) and lo <= n <= hi
            if valid and kind == "int":
                valid = isinstance(n, int) or n.is_integer()
            elif valid and kind == "float" and bound("precision") is not None:
                step = bound("precision")
                index = (n - lo) / step
                valid = abs(index - round(index)) <= 1e-6 and round(index) <= math.floor((hi - lo) / step + 1e-9)
            elif valid and kind == "decimal":
                valid = isinstance(v, str) and v == f"{n + 0.0:.{body['scale']}f}"
        elif kind == "enum":
            valid = isinstance(v, str) and v in (body if isinstance(body, list) else body["values"])
        elif kind == "string":
            valid = isinstance(v, str) and len(v) <= bound("max_len")
            if valid:
                charsets = {"digits": r"[0-9]*", "hex": r"[0-9a-fA-F]*", "alpha": r"[a-zA-Z]*", "alnum": r"[a-zA-Z0-9]*", "base64": r"[a-zA-Z0-9+/=_-]*", "ascii": r"[ -~]*", "unicode": r"[^\ud800-\udfff]*"}
                valid = re.fullmatch(charsets[body.get("charset", "unicode")], v) is not None
                if "pattern" in body:
                    valid = valid and re.fullmatch(body["pattern"], v) is not None
        elif kind == "bytes":
            if isinstance(v, str):
                raw = base64.b64decode(v, validate=True)
                valid = len(raw) <= bound("max_len") and base64.b64encode(raw).decode() == v
        elif kind in ("timestamp", "date"):
            if isinstance(v, str):
                if kind == "date":
                    n, lo, hi = (date.fromisoformat(x).toordinal() for x in (v, bound("min"), bound("max")))
                    step = core._dur(bound("granularity", "1d")) // 86_400_000
                else:
                    n, lo, hi = (core._ts_ms(x) for x in (v, bound("min"), bound("max")))
                    step = core._dur(bound("granularity"))
                valid = lo <= n <= hi and (n - lo) % step == 0
        elif kind in ("list", "table"):
            valid = isinstance(v, list) and len(v) <= bound("max" if kind == "list" else "max_rows")
            if valid:
                for item in v:
                    walk(body["of"], item, depth + 1)
        elif kind == "struct":
            valid = isinstance(v, dict) and v.keys() <= body.keys()
            if valid:
                for name, inner in body.items():
                    if name not in v and not (isinstance(inner, dict) and "optional" in inner):
                        raise ValueError(f"missing field {name}")
                    walk(inner, v.get(name), depth + 1)
        if not valid:
            raise ValueError(f"result does not inhabit {kind}")

    walk(rt, value)
