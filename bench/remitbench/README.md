# RemitBench

Each task is answered two ways against the same data:

- **(a) MCP-tools baseline** — the Holder exposes sensible tools that return
  records (`list_events`, `list_accounts`, `list_deals`, `list_customers`); the
  Sender computes the answer from what comes back.
- **(b) Remit** — the Sender submits one remit; only the typed result returns.

`run.ts` executes scripted reference solutions for both arms, checks both
answers against ground truth computed independently from the CSVs, and
reports per task: correctness, round trips, bytes crossing the boundary, an
LLM-token estimate (bytes / 4), and Remit's maximum leakage in bits.

```bash
# start the three example Holders (or pass --spawn to let run.ts do it)
node bench/remitbench/run.ts --spawn
```

`author.ts` is the **authoring-study harness**: it gives an external author
command (any LLM wrapper reading a prompt on stdin and printing a program JSON
on stdout) the catalog, generated types and task text, submits the result to
`/check` + `/run`, feeds structured diagnostics back for up to two repairs, and
reports first-try admission, correctness, and admission within 2 repairs.

```bash
node bench/remitbench/author.ts --author "my-llm-wrapper --model …" --spawn
```

`adversarial.ts` is the adversarial track: injection strings planted in Holder
data, exfiltration attempts against the declared capacity, and a bit-budget
campaign. More adversarial cases live in the Rust test suites (see
[spec/threat-model.md](../../spec/threat-model.md)).
