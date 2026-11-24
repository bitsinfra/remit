# Security policy

Remit runs untrusted programs next to sensitive data, so security reports are
treated as the highest-priority work in this project.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
[private vulnerability reporting](https://github.com/bitsinfra/remit/security/advisories/new)
("Report a vulnerability" on the Security tab). Include the affected component and
version, a description of the impact, and a reproducer if you have one (a remit, a
Holder config, a fuzz input).

You will get an acknowledgement within three working days. Fixes are developed in
a private fork, released with an advisory, and credited to the reporter unless you
ask otherwise.

## What counts

Anything that breaks a guarantee in the [threat model](spec/threat-model.md), for
example:

- a kernel reaching anything beyond the `remit:kernel` imports (network, files,
  clocks, another trust domain's data), or escaping a worker sandbox;
- a result that carries more information than its declared capacity, or a value
  that does not inhabit the declared type;
- reading a hidden column, a hidden row, or a resource the principal cannot see,
  or getting an exact answer where a k-threshold or differential privacy applies;
- spending bits, ε or fuel without being charged, or overdrawing a budget;
- admitting a remit that policy, authority, freshness or replay checks should
  refuse;
- forging, altering or truncating receipts or the receipt log without detection;
- disagreement between the Rust verifier and an SDK that lets a Sender be misled
  about what a Holder will release.

Denial of service through a single remit that stays within its declared limits is
in scope when the limits fail to bound it.

## Supported versions

Security fixes are made on the latest release line. The wire format is versioned
separately (see [spec/VERSIONING.md](spec/VERSIONING.md)).

## Deployment notes

- Remit has not yet had an independent security audit.
- Use `isolation = "process"` (the default) or `"microvm"` for Senders you do not
  trust. `inprocess` is for development and trusted networks.
- The production target for hostile code is x86-64 Linux; aarch64 and macOS are
  for development and trusted deployments.
- Pin the engine components with `[runtime] engine_sha256` and build them with
  `scripts/build-engine.sh` or take them from a signed release.
- The keys under `examples/*/keys/` are public demo keys. Generate your own with
  `remit keygen`.
