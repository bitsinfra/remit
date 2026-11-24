# Set access policy and budgets

The holder derives facts from a program and evaluates those facts against its policy. A sender’s description of why a program is safe is not part of admission.

## Permit a specific kind of work

The enterprise example admits aggregate questions from principals in the `partners` group:

```cedar
permit (
  principal in Remit::Group::"partners",
  action == Remit::Action::"aggregate",
  resource in Remit::Dataset::"crm"
)
when {
  context.aggregate_only && context.min_group_size >= 20
};
```

This policy assumes the CRM resources declare `aggregate_only = true`, `k = 20`, and a privacy-unit column, as shown in the [holder guide](holders.md). The holder’s planner enforces the threshold; the request cannot merely claim it used 20 accounts.

Load policy files through `[policy] files`. Every resource and requested action must be allowed. A kernel needs permission to run a kernel as well as permission for its declared reads.

## Bound repeated questions

```toml
[budgets]
bits_per_principal_per_day = 16384
bits_global_per_day = 262144
```

These are rolling budgets. The holder reserves budget before execution and persists reservations to its ledger. A narrow result type reduces the answer’s capacity; per-principal and global budgets bound repeated requests.

Resource `max_bits`, runtime ceilings and global budgets serve different purposes. A request can fit one and fail another. Read the [admission specification](../spec/admission.md#budgets) for accounting, caching and privacy-loss composition.

## Apply protections at the holder

Use hidden columns, masks, row filters and owner filters to control what reads can see. Use aggregate-only rules and minimum group sizes where rows must not leave. For differential privacy, declare contribution and value bounds and a privacy budget on the resource. Trusted holder code adds the noise; sender code cannot turn it off.

The reference holder supports these policies. The [Cloudflare edge profile](../backends/cloudflare/README.md) does not offer the same k-threshold or differential-privacy machinery; choose the backend to match the policy you need.

## Inspect policy changes

From the checkout root:

```bash
./target/debug/remit policy lint \
  --config examples/enterprise-analytics/remit.toml
```

Policy linting uses Cedar validation and, for solver-backed analysis, Z3. `remit policy diff` compares decisions for two files. Neither operation is permission to deploy a policy change.

Resource approvals can bind a program hash, principal, parameter constraints and expiry. A changed program needs a new approval. Counter-offers are proposed changes to the request; inspect them and re-sign only the constraints your application accepts.
