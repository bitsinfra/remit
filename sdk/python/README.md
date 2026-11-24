# remit (Python SDK)

The Python Sender SDK for [Remit](https://github.com/bitsinfra/remit): agents
exchange programs, not messages. Write SQL queries or kernels against a Holder's
typed catalog, check them locally, sign and submit them, and get back typed
results with verified receipts.

```bash
pip install remit
```

Python ≥ 3.10, no required dependencies. `pip install "remit[fast]"` adds
`cryptography` for P-256 identities and faster Ed25519, and
`pip install "remit[native]"` adds `remit-native`, the Rust verifier core the
Holder itself runs (offline SQL binding and result validation).

## Query mode

```python
import remit
from remit import t

client = remit.Remit.from_env()               # REMIT_IDENTITY=keys/agent.json
crm = client.holder("https://crm.example.com")  # fetches and verifies the signed catalog

r = crm.query(
    "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region",
    returns=t.list(t.struct(region=t.enum(*crm.enums("crm.accounts.region")),
                            arr=t.float(min=0, max=1e10, precision=1000)), max=20),
)
r.value             # typed values; strings come back as Untrusted
r.receipt.verify()  # the signed receipt binds the result, program and parties
```

`returns` also accepts JSON Schema, including Pydantic models (anything with
`model_json_schema()`); every type must be bounded.

## Kernel mode

```python
r = vault.kernel(
    reads={"busy": {"sql": "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from",
                    "params": {"from": "timestamp", "until": "timestamp"}, "max_rows": 500}},
    source=open("free_slots.js").read(),
    returns=t.list(t.struct(start=t.timestamp("15m"), end=t.timestamp("15m")), max=3),
    params={"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z"},
    purpose="scheduling",
)
```

Pass `lang="python/monty"` to send a Python kernel to Holders that enable it.

## More

- `AsyncRemit` / `AsyncHolder` mirror the sync API for asyncio.
- `RemitError` carries structured diagnostics and counter-offers; `auto_accept`
  on `Remit` sets the lowest limits you accept automatically.
- `EmbeddedHolder` serves in-process data (callables returning rows) through a
  supervised `remit serve` sidecar.

## License

Apache-2.0
