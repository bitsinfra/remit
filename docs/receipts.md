# Use the result and receipt

A successful exchange returns more than a value. Keep the receipt and handling terms alongside the answer so later work can identify its origin and constraints.

```ts
const value = answer.value;
const receipt = answer.receipt;
const labels = answer.labels;
const terms = answer.terms;
```

This continues the result from the [TypeScript quickstart](quickstart-typescript.md).

## What verification establishes

The SDK verifies the holder’s signature, the request and parameter hashes, the parties, the returned result hash and the declared type. The receipt records the policy hash, catalog hash, data versions, status and budget charges.

A valid signature establishes origin and integrity. It does not establish the truth of a business record, nor turn returned text into instructions the agent should follow.

## Carry restrictions into derived work

Restriction labels accumulate across inputs. Retention uses the shortest applicable period. Forwarding is permitted only when every contributing input allows it; `no-forward` forbids forwarding.

Keep those terms when building an agent’s brief, storing a result, or passing it to another holder. They are obligations your application must enforce after receipt. Remit does not remotely control the sender’s storage or model context.

## Verify a receipt log

The holder writes a hash-chained `receipts.jsonl` under its data directory. For a log you have retained locally:

```bash
./target/debug/remit receipts verify path/to/receipts.jsonl \
  --holder-key did:key:YOUR_EXPECTED_HOLDER_KEY
```

Replace the filename with the retained log and the key with the holder key you trust independently. The example placeholder is not an identity to use as-is. Verification checks the chain and signatures. Inclusion proofs and signed tree heads support transparency checks across observations.

## Replay a recorded run

Use `remit replay --config ... --envelope ... --receipt ...` on the holder side with the recorded envelope, receipt and matching data versions. Replay compares result hashes. Kernel receipts preserve the execution context needed for deterministic replay. Differentially private answers have separate replay semantics.

See the [receipt specification](../spec/receipts.md) for the wire format, log hashing, transparency proofs and attestation support.
