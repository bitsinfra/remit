"""Python Holder bindings: expose in-process data as Remit resources.

Each resource is a callable returning rows (dicts). `EmbeddedHolder` snapshots
them, supervises a `remit serve` sidecar (the trusted Rust Holder) and refreshes
on demand::

    with EmbeddedHolder("did:web:me.example", ident, {"app.orders": lambda: ORDERS}) as h:
        print(h.url)
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from .core import Identity, iso


def _toml(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {_toml(x)}" for k, x in v.items() if x is not None) + " }"
    return json.dumps(str(v))


def _default(o: Any):
    if isinstance(o, datetime):
        return iso(o)
    if isinstance(o, date):
        return o.isoformat()
    raise TypeError(f"cannot expose {type(o).__name__}")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EmbeddedHolder:
    def __init__(self, id: str, identity: Identity, resources: dict[str, Callable[[], Iterable[dict]]], *, config: dict[str, dict] | None = None,
                 presets: list[str] | None = None, policy: str | None = None, principals: list[dict] | None = None, budgets: dict | None = None,
                 bin: str | None = None, engine: str | None = None, isolation: str = "process", listen: str | None = None):
        self.id, self.resources, self.config = id, resources, config or {}
        self._listen = listen or f"127.0.0.1:{_free_port()}"
        self.url = f"http://{self._listen}"
        self._token = secrets.token_hex(16)
        self._dir = Path(tempfile.mkdtemp(prefix="remit-embedded-"))
        self._proc: subprocess.Popen | None = None
        self._bin = bin or os.environ.get("REMIT_BIN", "remit")
        try:
            self._snapshot()
            f = self._dir / "identity.json"
            f.touch(mode=0o600)
            f.write_text(json.dumps({**identity.to_json(), "id": id}))
            t = f"[holder]\nid = {_toml(id)}\nlisten = {_toml(self._listen)}\nisolation = {_toml(isolation)}\nidentity = \"identity.json\"\nadmin_token = {_toml(self._token)}\n\n"
            if policy:
                (self._dir / "policy.cedar").write_text(policy)
            t += f"[policy]\npresets = {_toml(presets or ['personal-vault'])}\nfiles = {_toml(['policy.cedar'] if policy else [])}\n\n"
            if budgets:
                t += "[budgets]\n" + "".join(f"{k} = {_toml(v)}\n" for k, v in budgets.items()) + "\n"
            if engine:
                t += f"[runtime]\nengine = {_toml(engine)}\n\n"
            for name in resources:
                src, _, table = name.partition(".")
                if not table:
                    raise ValueError(f"resource names are source.table, got {name}")
                t += f"[[source]]\nname = {_toml(src)}\nkind = \"json\"\npath = {_toml(f'data/{name}.ndjson')}\ntable = {_toml(table)}\n\n"
                if self.config.get(name):
                    t += f"[catalog.{_toml(name)}]\n" + "".join(f"{k} = {_toml(v)}\n" for k, v in self.config[name].items()) + "\n"
            for p in principals or []:
                t += "[[principal]]\n" + "".join(f"{k} = {_toml(v)}\n" for k, v in p.items()) + "\n"
            (self._dir / "remit.toml").write_text(t)
            self._start()
        except BaseException:
            self.stop()
            raise

    def _snapshot(self) -> None:
        data = self._dir / "data"
        data.mkdir(exist_ok=True)
        for name, rows in self.resources.items():
            lines = [json.dumps(r, default=_default) for r in rows()]
            if not lines:
                raise ValueError(f"resource {name} returned no rows (its schema cannot be inferred)")
            tmp = data / f"{name}.ndjson.tmp"
            tmp.write_text("\n".join(lines) + "\n")
            tmp.replace(data / f"{name}.ndjson")

    def _start(self) -> None:
        log = (self._dir / "log").open("w")
        self._proc = subprocess.Popen([self._bin, "serve", "--config", str(self._dir / "remit.toml")], stdout=log, stderr=log)
        for _ in range(600):
            if self._proc.poll() is not None:
                break
            try:
                with urllib.request.urlopen(f"{self.url}/healthz", timeout=1):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("remit serve did not become ready:\n" + (self._dir / "log").read_text()[-4000:])

    def refresh(self) -> None:
        """Re-read every resource and pin a new snapshot."""
        self._snapshot()
        req = urllib.request.Request(f"{self.url}/admin/refresh", data=b"", method="POST", headers={"authorization": f"Bearer {self._token}"})
        urllib.request.urlopen(req, timeout=60).read()

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        shutil.rmtree(self._dir, ignore_errors=True)

    def __enter__(self) -> "EmbeddedHolder":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
