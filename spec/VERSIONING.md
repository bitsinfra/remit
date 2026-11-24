# Versioning and upgrade paths

The current specification and wire version are `0.1`. Implementation and SDK
packages use the semantic version `0.1.0`.

- **Wire version** (`manifest.remit`): `MAJOR.MINOR`. Holders accept the versions
  they list in the catalog and reject others (`RMT-E0003`). A minor version only
  adds optional fields; `remit_id` never changes meaning within a major version.
- **Spec and crates** follow semver. A change to canonicalization, capacity,
  `remit_id`, the status set, or the meaning of a diagnostic code is breaking.
- **Diagnostic codes** are never reused. Messages and hints may improve.
- **WIT worlds** are versioned by package (`remit:kernel@0.1.0`). A Holder may
  serve several worlds at once; engine components name the world they target, and
  the engine hash in receipts says which one ran.
- **MSRV**: Rust 1.98 (checked in CI). Raising it is a minor change.
