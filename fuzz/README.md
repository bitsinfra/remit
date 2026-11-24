# Fuzzing

`cargo +nightly fuzz run <target>` from this directory. Targets cover every
parser and the host boundary: manifests, envelopes, RFC 9421 / JWT, JCS, RT
parsing and validation, Remit SQL (profile and binder), JS early errors, guest
CBOR, Biscuit tokens, Cedar policies, attestation evidence, RPC messages, and
`wasm-smith` components against the structural limits and restricted engine.

* CI runs each target briefly on x86-64 **and aarch64** (upstream Wasmtime has no
  continuous aarch64 fuzzing, so Remit runs its own), plus a nightly long run.
* `oss-fuzz/` is the OSS-Fuzz project; enrolment is a pull request to
  google/oss-fuzz by a maintainer.
