"""Sender client: sync (`Remit`) and async (`AsyncRemit`), stdlib HTTP."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from . import core
from .core import Identity

try:
    import remit_native as _native  # the Holder's verifier (PyO3)
except ImportError:
    _native = None


class RemitError(Exception):
    def __init__(self, decision: str, diagnostics: list, response: Any):
        msg = "; ".join(f"{d.get('code')} {d.get('path')}: {d.get('message')}" for d in diagnostics) or (response or {}).get("status", "failed")
        super().__init__(f"{decision}: {msg}")
        self.decision, self.diagnostics, self.response = decision, diagnostics, response


@dataclass
class Receipt:
    """A verified receipt body; `verify()` re-checks the signature."""

    body: dict
    envelope: dict
    holder_key: bytes

    def verify(self) -> bool:
        return json.loads(core.open_envelope(self.envelope, core.RECEIPT_TYPE, self.holder_key)) == self.body

    def __getitem__(self, k: str) -> Any:
        return self.body[k]

    def get(self, k: str, default: Any = None) -> Any:
        return self.body.get(k, default)


@dataclass
class Result:
    value: Any
    status: str
    labels: list
    terms: dict
    provenance: dict
    receipt: Receipt
    usage: dict
    cached: bool


def _http(method: str, url: str, body: bytes | None = None, headers: dict | None = None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:  # 4xx carry structured bodies
        return e.code, dict(e.headers), e.read()


def sign_request(ident: Identity, method: str, url: str, body: bytes, now: int | None = None, ttl: int = 60) -> dict[str, str]:
    """RFC 9421 HTTP message signature headers (with RFC 9530 Content-Digest)."""
    import hashlib

    u = urlsplit(url)
    created = int(now if now is not None else time.time())
    digest = f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"
    comps = [("@method", method.upper()), ("@authority", u.netloc.lower()), ("@path", u.path or "/"), ("content-digest", digest)]
    if u.query:
        comps.append(("@query", "?" + u.query))
    names = " ".join('"' + n + '"' for n, _ in comps)
    params = f'({names});created={created};expires={created + ttl};nonce="{secrets.token_hex(12)}";alg="ed25519";keyid="{ident.key_id}";tag="remit"'
    base = "\n".join([f'"{n}": {v}' for n, v in comps] + [f'"@signature-params": {params}'])
    return {"content-digest": digest, "signature-input": "sig1=" + params, "signature": "sig1=:" + base64.b64encode(ident.sign(base.encode())).decode() + ":"}


def _infer(v) -> str:
    if isinstance(v, datetime):
        return "timestamp"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str) and re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d", v):
        return "timestamp"
    return "string"


def _returns(rt) -> Any:
    """RT JSON, a `t.*` type, a JSON Schema dict, or a Pydantic model / TypeAdapter."""
    if isinstance(rt, (dict, str)):
        return rt
    schema = rt.model_json_schema() if hasattr(rt, "model_json_schema") else rt.json_schema() if hasattr(rt, "json_schema") else None
    if schema is None:
        raise TypeError("returns must be RT JSON, a t.* type, JSON Schema, or a Pydantic model / TypeAdapter")
    return _inline_refs(schema)


def _inline_refs(s: dict) -> dict:
    """Resolve local `$ref`s: the JSON Schema profile has no references."""
    defs = s.get("$defs", {})

    def walk(x, depth=0):
        if depth > 32:
            raise TypeError("recursive result types are unbounded")
        if isinstance(x, dict):
            if "$ref" in x:
                return walk(defs[x["$ref"].rsplit("/", 1)[-1]], depth + 1)
            return {k: walk(v, depth + 1) for k, v in x.items() if k not in ("$defs", "title", "description", "default")}
        return [walk(v, depth + 1) for v in x] if isinstance(x, list) else x

    out = walk(s)
    out.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
    return out


class Holder:
    def __init__(self, remit: "Remit", url: str, catalog: dict):
        self.remit, self.url, self.catalog = remit, url.rstrip("/"), catalog
        self.id = catalog["holder"]
        self.holder_key = core.public_key_from_did_key(catalog["keys"][0]["did_key"])

    def enums(self, path: str) -> list[str]:
        *prefix, col = path.split(".")
        pre = ".".join(prefix)
        for r in self.catalog.get("resources", []):
            if r["name"] == pre or r["name"].startswith(pre + "."):
                for c in r.get("columns", []):
                    if c["name"] == col and c.get("enum"):
                        return c["enum"]
        raise KeyError(f"no published enum for {path}")

    def _submit(self, action: str, m: dict) -> dict:
        url = f"{self.url}/remit/v1/{action}"
        body = json.dumps(core.sign_manifest(m, self.remit.identity)).encode()
        headers = {"content-type": "application/vnd.remit.envelope+json"}
        if self.remit.sign_requests:
            headers |= sign_request(self.remit.identity, "POST", url, body)
        status, rh, out = _http("POST", url, body, headers)
        v = json.loads(out)
        if status == 429:
            v.setdefault("retry_after_s", float(next((x for k, x in rh.items() if k.lower() == "retry-after"), 1)))
        return v

    def put_blob(self, source: str) -> str:
        sha = core.sha256_hex(source)
        status, _, _ = _http("PUT", f"{self.url}/remit/v1/blobs/{sha}", source.encode())
        if status >= 300:
            raise RuntimeError(f"blob upload failed: {status}")
        return sha

    def _manifest(self, mode, reads, params, returns, limits, purpose, code=None, authority=None) -> dict:
        m = {"holder": self.id, "purpose": purpose or (self.catalog.get("purposes") or ["unspecified"])[0], "mode": mode, "reads": reads,
             "params": core.wire_params(params or {}), "limits": limits or {}, "returns": returns}
        if code:
            m["code"] = code
        if authority:
            m["authority"] = authority
        return m

    def local_check(self, m: dict) -> list[dict]:
        """The Holder's verifier, offline (needs `remit_native` for SQL binding)."""
        d = []
        if _native is not None:
            for name, r in m["reads"].items():
                v = json.loads(_native.bind_sql(r["sql"], json.dumps(self.catalog)))
                if not v["ok"]:
                    d.append({**v["error"], "path": f"/reads/{name}/sql"})
            v = json.loads(_native.capacity(json.dumps(m["returns"]), json.dumps(m.get("params") or {})))
            if not v["ok"]:
                d.append(v["error"])
        elif not (isinstance(m["returns"], dict) and ("$schema" in m["returns"] or "type" in m["returns"])):
            try:
                core.capacity(m["returns"], m.get("params"))
            except core.RemitTypeError as e:
                d.append({"code": e.code, "path": "/returns" + e.path, "message": str(e)})
        return d

    def check(self, m: dict) -> dict:
        return self._submit("check", m if "nonce" in m else core.bind(m, self.remit.identity))

    def _acceptable(self, patch: list) -> bool:
        floors = self.remit.auto_accept
        return floors is not None and all(op["path"].startswith("/limits/") and op["value"] >= floors.get(op["path"][8:], 0) for op in patch)

    def _run(self, body: dict) -> Result:
        local = self.local_check(body)
        if local:
            raise RemitError("rejected_locally", local, None)
        code = body.get("code")
        if code and len(code.get("source", "").encode()) > self.remit.inline_code_bytes:
            self.put_blob(code["source"])
            body = {**body, "code": {k: v for k, v in code.items() if k != "source"}}
        offers, busy = 0, 0
        while True:
            m = core.bind(body, self.remit.identity)
            resp = self._submit("run", m)
            dec = resp.get("decision")
            if dec == "busy" and busy < self.remit.retries:
                busy += 1
                time.sleep(resp.get("retry_after_s", 1))
                continue
            if dec == "counter_offer" and offers == 0:
                patch = resp["counter_offer"]["json_patch"]
                if self._acceptable(patch):
                    offers += 1
                    body = {**body, "limits": {**body["limits"], **{op["path"][8:]: op["value"] for op in patch}}}
                    continue
            break
        if dec and dec != "admitted":
            raise RemitError(dec, resp.get("diagnostics", []), resp)
        receipt = json.loads(core.open_envelope(resp["receipt"], core.RECEIPT_TYPE, self.holder_key))
        if resp.get("status") != "ok":
            raise RemitError(resp.get("status", "failed"), [], resp)
        if receipt.get("status") != "ok" or receipt.get("decision") != "admitted":
            raise RemitError("receipt_mismatch", [], resp)
        if receipt["remit_id"] != core.remit_id(m) or receipt["params_sha256"] != core.params_sha256(m) or receipt["holder"] != self.id or receipt["sender"] != self.remit.identity.id:
            raise RemitError("receipt_mismatch", [], resp)
        if receipt.get("result_sha256") != "sha256:" + core.sha256_hex(core.canonicalize(resp["result"])):
            raise RemitError("result_mismatch", [], resp)
        if _native is not None:  # the Holder is not trusted to honor the type
            v = json.loads(_native.validate(json.dumps(m["returns"]), json.dumps(m.get("params") or {}), json.dumps(resp["result"])))
            if not v["ok"]:
                raise RemitError("result_type", [{"code": "RMT-E0120", "path": "/returns", "message": v["error"]}], resp)
        else:
            from .validation import validate
            try:
                validate(m["returns"], m.get("params") or {}, resp["result"])
            except (ValueError, TypeError, KeyError, OverflowError) as e:
                raise RemitError("result_type", [{"code": "RMT-E0120", "path": "/returns", "message": str(e)}], resp) from e
        value = core.revive(m["returns"], resp["result"], self.id)
        return Result(value, resp["status"], receipt["labels"], receipt["terms"], resp["provenance"], Receipt(receipt, resp["receipt"], self.holder_key),
                      resp.get("usage", {}), resp.get("cached", False))

    def query(self, sql: str, returns, params: dict | None = None, limits: dict | None = None, purpose: str | None = None, max_rows: int | None = None, authority: list | None = None) -> Result:
        params = params or {}
        ptypes = {p: _infer(params.get(p)) for p in re.findall(r"\$([A-Za-z_]\w*)", sql)}
        rt = _returns(returns)
        mr = max_rows or (rt.get("list", {}).get("max") or rt.get("table", {}).get("max_rows") or rt.get("maxItems") if isinstance(rt, dict) else None) or 1000
        read = {"sql": sql, "max_rows": mr, "max_calls": 1}
        if ptypes:
            read["params"] = ptypes
        return self._run(self._manifest("query", {"q": read}, params, rt, limits, purpose, None, authority))

    def kernel(self, reads: dict, source: str, returns, params: dict | None = None, limits: dict | None = None, purpose: str | None = None, entry: str = "main",
               lang: str = "js/es2023", authority: list | None = None) -> Result:
        """`lang`: `js/es2023` or `python/monty`."""
        reads = {k: {"max_rows": 1000, "max_calls": 1, **({"sql": r} if isinstance(r, str) else r)} for k, r in reads.items()}
        code = {"lang": lang, "entry": entry, "source": source, "source_sha256": core.sha256_hex(source)}
        return self._run(self._manifest("kernel", reads, params, _returns(returns), limits, purpose, code, authority))


class Remit:
    """Sender client. `auto_accept` maps limit names to the lowest value accepted in a counter-offer (`None` refuses them)."""

    def __init__(self, identity: Identity, auto_accept: dict | None = {}, sign_requests: bool = True, retries: int = 3, inline_code_bytes: int = 32 * 1024):
        self.identity, self.sign_requests, self.retries, self.inline_code_bytes = identity, sign_requests, retries, inline_code_bytes
        # A private copy: the default must not be shared between clients.
        self.auto_accept = None if auto_accept is None else dict(auto_accept)

    @classmethod
    def from_env(cls) -> "Remit":
        return cls(Identity.from_env())

    def holder(self, url: str, pin: str | None = None, scoped: bool = False) -> Holder:
        headers = {}
        catalog = self._catalog(url, pin, headers)
        if scoped:
            body = core.canonicalize({"holder": catalog["holder"], "principal": self.identity.id, "ts": int(time.time() * 1000)}).encode()
            env = core.sign_envelope("application/vnd.remit.catalog-request+json", body, self.identity)
            catalog = self._catalog(url, catalog["keys"][0]["did_key"], {"remit-proof": base64.b64encode(json.dumps(env).encode()).decode()})
        return Holder(self, url, catalog)

    def _catalog(self, url: str, pin: str | None, headers: dict) -> dict:
        status, rh, body = _http("GET", f"{url.rstrip('/')}/.well-known/remit", None, headers)
        if status != 200:
            raise RuntimeError(f"catalog fetch failed: {status}")
        catalog = json.loads(body)
        sig_h = next((v for k, v in rh.items() if k.lower() == "remit-signature"), "")
        m = re.search(r'sig="([^"]+)"', sig_h)
        dk = catalog["keys"][0]["did_key"]
        if pin and pin != dk:
            raise RuntimeError("catalog key does not match the pinned key")
        pk = core.public_key_from_did_key(dk)
        if not m or pk is None or not core.verify(pk, core.pae(core.CATALOG_TYPE, core.canonicalize(catalog).encode()), base64.b64decode(m.group(1))):
            raise RuntimeError("catalog signature does not verify")
        return catalog


class AsyncHolder:
    """Async view of a `Holder` (requests run on worker threads)."""

    def __init__(self, inner: Holder):
        self.sync = inner

    def __getattr__(self, name: str):
        return getattr(self.sync, name)

    async def query(self, *a, **k) -> Result:
        return await asyncio.to_thread(self.sync.query, *a, **k)

    async def kernel(self, *a, **k) -> Result:
        return await asyncio.to_thread(self.sync.kernel, *a, **k)

    async def check(self, m: dict) -> dict:
        return await asyncio.to_thread(self.sync.check, m)


class AsyncRemit:
    def __init__(self, identity: Identity, **kw):
        self.sync = Remit(identity, **kw)

    @classmethod
    def from_env(cls) -> "AsyncRemit":
        return cls(Identity.from_env())

    async def holder(self, url: str, pin: str | None = None, scoped: bool = False) -> AsyncHolder:
        return AsyncHolder(await asyncio.to_thread(self.sync.holder, url, pin, scoped))
