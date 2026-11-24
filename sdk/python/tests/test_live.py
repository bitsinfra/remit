"""Live: embed a Holder over in-process data and query it (needs REMIT_BIN)."""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import remit
from remit import t

ROOT = Path(__file__).resolve().parents[3]
BIN = os.environ.get("REMIT_BIN")
ENGINE = str(ROOT / "engines/js/dist/remit_engine_js.wasm")


def orders(n):
    return [{"id": i, "region": ["EMEA", "AMER"][i % 2], "total": 10.0 * i, "at": datetime(2026, 11, 1 + i, tzinfo=timezone.utc), "card": "4242"} for i in range(n)]


def main():
    rows = orders(10)
    sender = remit.Identity.generate("did:web:agent.example")
    with remit.EmbeddedHolder(
        "did:web:me.example", remit.Identity.generate(), {"app.orders": lambda: rows}, bin=BIN, engine=ENGINE,
        config={"app.orders": {"columns": {"card": {"expose": False}, "at": {"type": "timestamp"}, "region": {"enum": True}}}},
        principals=[{"id": sender.id, "keys": [sender.did_key], "groups": ["verified-agents"], "verified": True}],
    ) as h:
        c = remit.Remit(sender).holder(h.url, scoped=True)
        assert c.enums("app.orders.region") == ["AMER", "EMEA"]
        r = c.query("SELECT region, SUM(total) AS total FROM app.orders GROUP BY region ORDER BY region",
                    returns=t.list(t.struct(region=t.enum(*c.enums("app.region")), total=t.float(min=0, max=1e6, precision=1)), max=5))
        assert r.value == [{"region": "AMER", "total": 250}, {"region": "EMEA", "total": 200}], r.value
        assert r.receipt.verify() and r.receipt["sender"] == sender.id
        # Pydantic-style JSON Schema, with references.
        class Model:
            @staticmethod
            def model_json_schema():
                return {"type": "array", "maxItems": 3, "items": {"$ref": "#/$defs/Row"}, "$defs": {"Row": {"type": "object", "title": "Row", "properties": {"id": {"type": "integer", "minimum": 0, "maximum": 100}, "at": {"type": "string", "format": "date-time", "x-remit-minimum": "2026-11-01T00:00:00Z", "x-remit-maximum": "2026-12-01T00:00:00Z", "x-remit-granularity": "1d"}}, "required": ["id", "at"]}}}
        r = c.query("SELECT id, at FROM app.orders WHERE at >= $from ORDER BY id LIMIT 3", returns=Model, params={"from": datetime(2026, 11, 8, tzinfo=timezone.utc)})
        assert [x["id"] for x in r.value] == [7, 8, 9] and r.value[0]["at"].day == 8, r.value
        # Kernel, counter-offer (limits clamped), large code by hash, async.
        src = "export default function main({ o }, p) { return o({}).rows().filter(r => r.total >= p.min).length; }\n//" + "x" * 40_000
        async def go():
            a = await remit.AsyncRemit(sender).holder(h.url)
            return await a.kernel({"o": "SELECT total FROM app.orders"}, src, t.int(min=0, max=100), params={"min": 50}, limits={"wall_ms": 999_999})
        r = asyncio.run(go())
        assert r.value == 5
        # Hidden columns do not exist.
        try:
            c.query("SELECT card FROM app.orders", returns=t.list(t.struct(card=t.string(max_len=8)), max=20))
            raise SystemExit("card must be hidden")
        except remit.RemitError as e:
            assert e.diagnostics[0]["code"] in ("RMT-E0301", "RMT-E0213"), e
        # Refresh pins a new snapshot.
        rows = orders(12)
        h.resources["app.orders"] = lambda: rows
        h.refresh()
        assert c.query("SELECT COUNT(*) AS n FROM app.orders", returns=t.int(min=0, max=100)).value == 12
        # Tampered results are refused.
        real = c._submit
        c._submit = lambda action, m: {**real(action, m), "result": 13}
        try:
            c.query("SELECT COUNT(*) AS n FROM app.orders", returns=t.int(min=0, max=100))
            raise SystemExit("tampering must be detected")
        except remit.RemitError as e:
            assert e.decision == "result_mismatch"
    print("ok live")


if __name__ == "__main__":
    if not BIN:
        print("skipping: REMIT_BIN not set")
        sys.exit(0)
    main()
