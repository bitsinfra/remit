# Choose the result type

Every remit declares what can come back. A useful result type states both the shape of the answer and a finite bound on its capacity.

## Express the answer you need

With the TypeScript SDK’s `t` builders:

```ts
import { capacity, t } from "remit-protocol";

const count = t.int({ min: 0, max: 100 });
const region = t.enum("AMER", "APAC", "EMEA", "LATAM");
const revenue = t.float({ min: 0, max: 1e10, precision: 1000 });
const answer = t.list(t.struct({ region, revenue }), { max: 4 });

console.log(capacity(answer));
```

Use an enum for a known category, an integer range for a count, and a finite precision for a numeric measure. Lists need a maximum length; strings and byte sequences need a maximum length too. Unbounded strings and arrays are rejected.

The SDK also accepts bounded Zod, Standard Schema and JSON Schema representations. Python supports JSON Schema and Pydantic models through `model_json_schema()`.

## Capacity is a bound, not a measurement

The type’s capacity bounds how many bits the declared answer can encode. It is computed before execution, not from the size of the particular JSON response. The status channel adds three bits to protocol accounting.

The holder checks the request against resource and budget limits. Quantization and other trusted output transforms run on the holder side. A result that does not fit the declared type is not released as a successful answer.

This accounting is one part of the privacy model. It does not prove that an arbitrary sequence of questions is harmless. Read the [threat model](../spec/threat-model.md) and [status accounting](../spec/status.md) when choosing budgets.

## Bound time explicitly

Timestamp ranges can reference input parameters:

```ts
const slots = t.list(t.struct({
  start: t.timestamp({ min: "$from", max: "$until", granularity: "15m" }),
  end: t.timestamp({ min: "$from", max: "$until", granularity: "15m" }),
}), { max: 3 });
```

The remit must supply `from` and `until`. This example permits three time slots on a 15-minute grid, without needing a free-form description of the calendar.

The [Remit Types specification](../spec/rt.md) defines each type, the capacity formulas, parameter binding and validation.
