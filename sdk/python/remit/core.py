"""JCS, identities, DSSE, Remit Types and capacity (mirrors the Rust/TS rules)."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from typing import Any

from . import _ed25519

# ------------------------------------------------------------------ JCS

def _num(x: float | int) -> str:
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        if abs(x) <= 2**53:
            return str(x)
        # Outside ±2^53 an integer is canonical only if it is its double's ES form.
        lit, f = str(x), float(x)
        if _num(f) != lit:
            raise ValueError(f"integer {lit} is outside the I-JSON safe range")
        return lit
    if not math.isfinite(x):
        raise ValueError("non-finite number")
    if x == 0:
        return "0"
    # ECMAScript Number::toString: shortest round-trip digits.
    r = repr(x)
    m, _, e = r.partition("e")
    if not e:
        return r[:-2] if r.endswith(".0") else r
    exp = int(e)
    digits = m.replace(".", "").replace("-", "").lstrip("0") or "0"
    neg = x < 0
    n = exp + 1  # position of decimal point relative to first digit
    if -6 < n <= 21:
        if n <= 0:
            s = "0." + "0" * (-n) + digits
        elif n >= len(digits):
            s = digits + "0" * (n - len(digits))
        else:
            s = digits[:n] + "." + digits[n:]
    else:
        s = digits[0] + ("." + digits[1:] if len(digits) > 1 else "") + "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
    return ("-" if neg else "") + s


def canonicalize(v: Any) -> str:
    """RFC 8785 canonical JSON."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonicalize(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonicalize(v[k]) for k in keys) + "}"
    if isinstance(v, datetime):
        return json.dumps(iso(v))
    raise TypeError(f"cannot canonicalize {type(v)}")


def sha256_hex(b: bytes | str) -> str:
    return hashlib.sha256(b.encode() if isinstance(b, str) else b).hexdigest()


def iso(d: datetime) -> str:
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if d.microsecond == 0 else d.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

# ------------------------------------------------------------- identity

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def unb58(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + out


def did_key(pk: bytes) -> str:
    return "did:key:z" + b58(b"\xed\x01" + pk)


def public_key_from_did_key(i: str) -> bytes | None:
    base = i.split("#")[0]
    if not base.startswith("did:key:z"):
        return None
    b = unb58(base[9:])
    if len(b) == 34 and b[:2] == b"\xed\x01":
        return b[2:]
    if len(b) == 35 and b[:2] == b"\x80\x24":  # P-256, compressed
        return b[2:]
    return None


class Identity:
    """Ed25519 signing identity; file format compatible with `remit keygen`."""

    def __init__(self, seed: bytes, id: str | None = None):
        self._seed = seed
        self.public_key = _ed25519.public_key(seed)
        dk = did_key(self.public_key)
        self.id = id or dk
        self.key_id = self.id if self.id.startswith("did:key:") else f"{self.id}#{dk[len('did:key:'):]}"

    @classmethod
    def generate(cls, id: str | None = None) -> "Identity":
        return cls(secrets.token_bytes(32), id)

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path) as f:
            d = json.load(f)
        return cls(base64.b64decode(d["secret_key"]), d["id"])

    @classmethod
    def from_env(cls) -> "Identity":
        if os.environ.get("REMIT_IDENTITY"):
            return cls.load(os.environ["REMIT_IDENTITY"])
        if os.environ.get("REMIT_SECRET_KEY"):
            return cls(base64.b64decode(os.environ["REMIT_SECRET_KEY"]), os.environ.get("REMIT_ID"))
        raise RuntimeError("set REMIT_IDENTITY (path to `remit keygen` output) or REMIT_SECRET_KEY")

    @property
    def did_key(self) -> str:
        return did_key(self.public_key)

    def sign(self, msg: bytes) -> bytes:
        return _ed25519.sign(self._seed, msg)

    def to_json(self) -> dict:
        return {"id": self.id, "key_id": self.key_id, "secret_key": base64.b64encode(self._seed).decode(), "public_key": self.did_key}


MANIFEST_TYPE = "application/vnd.remit.manifest+json"
RECEIPT_TYPE = "application/vnd.remit.receipt+json"
CATALOG_TYPE = "application/vnd.remit.catalog+json"


def pae(t: str, body: bytes) -> bytes:
    tb = t.encode()
    return b"DSSEv1 " + str(len(tb)).encode() + b" " + tb + b" " + str(len(body)).encode() + b" " + body


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Ed25519 (32-byte key) or P-256 / ES256 (33-byte compressed key; needs `cryptography`)."""
    if len(pk) == 32:
        return _ed25519.verify(pk, msg, sig)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(sig) != 64:
        return False
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
    try:
        key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def sign_envelope(t: str, body: bytes, ident: Identity) -> dict:
    return {"payloadType": t, "payload": base64.b64encode(body).decode(), "signatures": [{"keyid": ident.key_id, "sig": base64.b64encode(ident.sign(pae(t, body))).decode()}]}


def open_envelope(env: dict, t: str, key: bytes) -> bytes:
    if env.get("payloadType") != t:
        raise ValueError(f"payloadType must be {t}")
    body = base64.b64decode(env["payload"])
    if not any(verify(key, pae(t, body), base64.b64decode(s["sig"])) for s in env.get("signatures", [])):
        raise ValueError("envelope signature does not verify")
    return body

# ------------------------------------------------------------ manifest

def remit_id(m: dict) -> str:
    code = m.get("code")
    if code is not None:
        code = {"lang": code["lang"], "entry": code.get("entry", "main"), "source_sha256": code["source_sha256"].removeprefix("sha256:").lower()}
    reads = {}
    for k, r in m["reads"].items():
        rr = {"sql": r["sql"], "max_rows": r["max_rows"], "max_calls": r.get("max_calls", 1)}
        if r.get("params"):
            rr["params"] = r["params"]
        reads[k] = rr
    limits = {k: v for k, v in (m.get("limits") or {}).items() if v is not None}
    return "sha256:" + sha256_hex(canonicalize({"remit": m["remit"], "mode": m["mode"], "purpose": m["purpose"], "reads": reads, "code": code, "limits": limits, "returns": m["returns"]}))


def params_sha256(m: dict) -> str:
    return "sha256:" + sha256_hex(canonicalize(m.get("params") or {}))


def wire_params(p: dict) -> dict:
    return {k: iso(v) if isinstance(v, datetime) else v for k, v in p.items()}


def bind(m: dict, ident: Identity, ttl: int = 300) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    out = dict(m)
    out.update(remit=m.get("remit", "0.1"), sender=ident.id, issued_at=iso(now), expires_at=iso(now + timedelta(seconds=ttl)), nonce=secrets.token_hex(16))
    out.setdefault("limits", {})
    for r in out["reads"].values():
        r.setdefault("max_calls", 1)
        if "params" in r and not r["params"]:
            del r["params"]
    return out


def sign_manifest(m: dict, ident: Identity) -> dict:
    return sign_envelope(MANIFEST_TYPE, canonicalize(m).encode(), ident)

# ------------------------------------------------------------- types

class t:
    """Builders for bounded Remit Types (RT JSON)."""

    @staticmethod
    def bool():
        return "bool"

    @staticmethod
    def int(min, max):
        return {"int": {"min": min, "max": max}}

    @staticmethod
    def float(min, max, precision=None):
        b = {"min": min, "max": max}
        if precision is not None:
            b["precision"] = precision
        return {"float": b}

    @staticmethod
    def enum(*values):
        return {"enum": [str(v) for v in values]}

    @staticmethod
    def string(max_len, charset=None, pattern=None):
        b: dict = {"max_len": max_len}
        if charset:
            b["charset"] = charset
        if pattern:
            b["pattern"] = pattern
        return {"string": b}

    @staticmethod
    def timestamp(granularity, min="$from", max="$until"):
        return {"timestamp": {"min": iso(min) if isinstance(min, datetime) else min, "max": iso(max) if isinstance(max, datetime) else max, "granularity": granularity}}

    @staticmethod
    def list(of, max):
        return {"list": {"max": max, "of": of}}

    @staticmethod
    def table(of, max_rows):
        return {"table": {"max_rows": max_rows, "of": of}}

    @staticmethod
    def struct(**fields):
        return {"struct": fields}

    @staticmethod
    def optional(of):
        return {"optional": of}


STATUS_SET = ["ok", "limit_exceeded", "type_violation", "denied", "internal"]
STATUS_BITS = math.ceil(math.log2(len(STATUS_SET)))
_CHARSET = {"digits": 10, "hex": 22, "alpha": 52, "alnum": 62, "base64": 67, "ascii": 95, "unicode": 1_112_064}


class RemitTypeError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        super().__init__(f"{code} at {path}: {message}")
        self.code, self.path = code, path


def _dur(s) -> int:
    if isinstance(s, (int, float)):
        return int(s)
    total, pos = 0, 0
    for m in re.finditer(r"(\d+(?:\.\d+)?)(ms|s|min|m|h|d|w)", s):
        if m.start() != pos:
            raise RemitTypeError("RMT-E0107", "/", f"bad duration {s}")
        total += float(m.group(1)) * {"ms": 1, "s": 1e3, "m": 6e4, "min": 6e4, "h": 36e5, "d": 864e5, "w": 6048e5}[m.group(2)]
        pos = m.end()
    if pos != len(s) or pos == 0:
        raise RemitTypeError("RMT-E0107", "/", f"bad duration {s}")
    return math.floor(total + 0.5)


def _ts_ms(v) -> float:
    if isinstance(v, datetime):
        return v.timestamp() * 1000
    if isinstance(v, (int, float)):
        return v
    parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp() * 1000


def _log2c(n: float) -> float:
    return 0.0 if n <= 1 else math.log2(n)


_MAX_TIME, _MAX_LEN = 8_640_000_000_000_000, 1 << 24
_BODY = ("int", "float", "decimal", "string", "timestamp", "date", "bytes", "list", "table", "struct")


def _strict(k: str, b, p: str, r) -> None:
    """Reject what the Rust implementation rejects, before any arithmetic."""

    def bad(code, f, msg):
        raise RemitTypeError(code, f"{p}/{f}" if f else p, msg)

    def number(f, integer=False):
        v = r(f)
        ok = isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and (not integer or (float(v).is_integer() and abs(v) <= 2**63))
        if not ok:
            bad("RMT-E0103", f, "must be an integer" if integer else "must be a finite number")
        return v

    def length(f):
        v = number(f, True)
        if v < 0:
            bad("RMT-E0103", f, "must be non-negative")
        if v > _MAX_LEN:
            bad("RMT-E0106", f, f"exceeds {_MAX_LEN}")

    def duration(f):
        v = r(f)
        ms = _dur(v) if isinstance(v, str) else v
        if isinstance(ms, bool) or not isinstance(ms, (int, float)) or ms != int(ms) or not 0 < ms <= _MAX_TIME:
            bad("RMT-E0107", f, "must be a positive duration")
        return ms

    def moment(f):
        v = r(f)
        try:
            t = _ts_ms(v)
            if isinstance(v, bool) or (isinstance(v, (int, float)) and v != int(v)) or abs(t) > _MAX_TIME:
                raise ValueError
            return t
        except (ValueError, TypeError, AttributeError, OverflowError):
            bad("RMT-E0103", f, "must be an RFC 3339 timestamp or epoch ms")

    def span(lo, hi):
        if lo > hi:
            raise RemitTypeError("RMT-E0105", p.rsplit("/", 1)[0] or "/", "empty range")

    if k in _BODY and not isinstance(b, dict):
        bad("RMT-E0103", "", f"`{k}` expects an object of constraints")
    if k in ("int", "float", "decimal"):
        if k == "decimal" and not (isinstance(b.get("scale"), int) and 0 <= b["scale"] <= 18):
            bad("RMT-E0101", "scale", "`scale` (0..=18) is required")
        span(number("min", k == "int"), number("max", k == "int"))
        if k == "float" and b.get("precision") is not None and number("precision") <= 0:
            bad("RMT-E0103", "precision", "must be > 0")
    elif k == "enum":
        vals = b if isinstance(b, list) else b.get("values") if isinstance(b, dict) else None
        if not isinstance(vals, list):
            bad("RMT-E0101", "", "`enum` needs a list of values")
        if any(not isinstance(v, str) for v in vals) or len(set(vals)) != len(vals):
            bad("RMT-E0103", "", "enum values must be distinct strings")
        if not 1 <= len(vals) <= 65536:
            bad("RMT-E0106", "", "enum must have 1..=65536 values")
    elif k == "string":
        if b.get("charset", "unicode") not in _CHARSET:
            bad("RMT-E0103", "charset", "unknown charset")
        length("max_len")
    elif k == "bytes":
        length("max_len")
    elif k == "timestamp":
        span(moment("min"), moment("max"))
        duration("granularity")
    elif k == "date":
        for f in ("min", "max"):
            v = r(f)
            if not isinstance(v, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d", v):
                bad("RMT-E0103", f, "must be YYYY-MM-DD")
        span(moment("min"), moment("max"))
        if b.get("granularity") is not None and duration("granularity") % 86_400_000:
            bad("RMT-E0107", "granularity", "date granularity must be whole days")
    elif k in ("list", "table"):
        if "of" not in b:
            bad("RMT-E0101", "of", f"`{k}` needs `of`")
        if k == "table" and not (isinstance(b["of"], dict) and "struct" in b["of"]):
            bad("RMT-E0103", "of", "`table` rows must be a struct")
        length("max" if k == "list" else "max_rows")
    elif k == "struct" and any(not 1 <= len(f.encode()) <= 128 for f in b):
        bad("RMT-E0103", "", "struct field names must be 1..=128 bytes")


def capacity(rt, params: dict | None = None, path: str = "") -> float:
    """Capacity in bits (must agree with the Rust normative implementation)."""
    params = params or {}
    if rt == "bool":
        return 1.0
    if isinstance(rt, str):
        raise RemitTypeError("RMT-E0101" if rt in ("int", "float", "string", "list", "timestamp", "bytes", "decimal", "date") else "RMT-E0102", path or "/", f"type `{rt}` needs constraints")
    if not isinstance(rt, dict) or len(rt) != 1:
        raise RemitTypeError("RMT-E0102", path or "/", "a type is \"bool\" or a single-key object")
    (k, b), = rt.items()
    p = f"{path}/{k}"

    def r(f):
        v = b.get(f) if isinstance(b, dict) else None
        if v is None:
            raise RemitTypeError("RMT-E0101", f"{p}/{f}", f"`{f}` is required: every Remit Type must be bounded")
        if isinstance(v, str) and v.startswith("$"):
            if v[1:] not in params:
                raise RemitTypeError("RMT-E0104", f"{p}/{f}", f"bound references param `{v}`, which is not provided")
            return params[v[1:]]
        return v

    _strict(k, b, p, r)
    if k == "bool":
        return 1.0
    if k == "int":
        lo, hi = r("min"), r("max")
        if lo > hi:
            raise RemitTypeError("RMT-E0105", path or "/", "empty range")
        return _log2c(hi - lo + 1)
    if k == "float":
        lo, hi = r("min"), r("max")
        if b.get("precision") is None:
            return 64.0
        return _log2c(math.floor((hi - lo) / r("precision") + 1e-9) + 1)
    if k == "decimal":
        return _log2c(math.floor((r("max") - r("min")) * 10 ** b["scale"] + 0.5) + 1)
    if k == "enum":
        return _log2c(len(b if isinstance(b, list) else b["values"]))
    if k == "string":
        n = r("max_len")
        return n * math.log2(_CHARSET[b.get("charset", "unicode")]) + math.log2(n + 1)
    if k == "timestamp":
        lo, hi, g = _ts_ms(r("min")), _ts_ms(r("max")), _dur(r("granularity"))
        return _log2c(math.trunc((hi - lo) / g) + 1)
    if k == "date":
        days = (date.fromisoformat(r("max")) - date.fromisoformat(r("min"))).days
        g = _dur(r("granularity")) / 864e5 if b.get("granularity") is not None else 1
        return _log2c(math.trunc(days / g) + 1)
    if k == "bytes":
        n = r("max_len")
        return 8 * n + math.log2(n + 1)
    if k in ("list", "table"):
        m = r("max" if k == "list" else "max_rows")
        return math.log2(m + 1) + m * capacity(b["of"], params, f"{p}/of")
    if k == "struct":
        return sum(capacity(ft, params, f"{p}/{f}") for f, ft in b.items())
    if k == "optional":
        c = capacity(b, params, p)
        return c + math.log2(1 + 2 ** -c)
    raise RemitTypeError("RMT-E0102", path or "/", f"unknown type `{k}`")


def capacity_ceil(bits: float) -> int:
    return max(0, math.ceil(bits - 1e-9))


class Untrusted:
    """A string from another agent's data: data, never instructions."""

    __slots__ = ("value", "holder")

    def __init__(self, value: str, holder: str):
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "holder", holder)

    def __setattr__(self, *_):
        raise AttributeError("Untrusted is immutable")

    def unwrap(self) -> str:
        return self.value

    def __repr__(self):
        return f"Untrusted(from={self.holder!r})"

    __str__ = __repr__


def revive(rt, v, holder: str):
    if v is None:
        return None
    if rt == "bool":
        return v
    if "$schema" in rt or "type" in rt or "anyOf" in rt or "enum" in rt and "struct" not in rt:
        return _revive_schema(rt, v, holder)
    (k, b), = rt.items()
    if k in ("timestamp", "date"):
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    if k == "string":
        return Untrusted(v, holder)
    if k in ("list", "table"):
        return [revive(b["of"], x, holder) for x in v]
    if k == "optional":
        return revive(b, v, holder)
    if k == "struct":
        return {f: revive(ft, v.get(f), holder) for f, ft in b.items()}
    return v


def _revive_schema(s: dict, v, holder: str):
    """Revive a value described by the JSON Schema profile."""
    if v is None:
        return None
    if "anyOf" in s:
        inner = [x for x in s["anyOf"] if x.get("type") != "null"]
        return _revive_schema(inner[0], v, holder) if len(inner) == 1 else v
    if "enum" in s or "const" in s:
        return v
    ty = s.get("type")
    if ty == "array":
        return [_revive_schema(s.get("items", {}), x, holder) for x in v]
    if ty == "object":
        return {k: _revive_schema(p, v.get(k), holder) for k, p in s.get("properties", {}).items()}
    if ty == "string":
        if s.get("format") in ("date-time", "date"):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return Untrusted(v, holder)
    return v
