# Isolation

| Level | Where kernels run | Status |
|---|---|---|
| `inprocess` | Wasmtime inside the Holder process | Dev / trusted networks |
| `process` (default) | Worker processes pooled per **trust domain** | Production |
| `microvm` | One KVM guest per trust domain (QEMU), running the same worker | Linux with `/dev/kvm`; configured by `[runtime.microvm]` |

## MicroVMs

At level `microvm` each trust domain gets a diskless, networkless KVM guest whose
only program is the kernel worker (`remit-guest` as PID 1, booted from an initramfs
the Holder builds). It speaks the same worker protocol over a single virtio serial
port, so fuel metering, determinism and results are identical to level `process`.
The guest has no disk, network or host file access: those devices do not exist.
`[runtime.microvm]` names the guest `kernel` (with virtio-console, virtio-mmio and
devtmpfs built in) and optionally the `worker` binary, the `vmm` (default
`qemu-system-<arch>`) and `memory_mib`. A guest boots once per worker, so the
start-up cost is paid when a worker spawns, not per remit.

## Process model

- The trusted main process owns connectors, credentials, keys, the read plane,
  admission and the emit plane.
- Workers (`remit kernel-worker`) are spawned with a cleared environment, cwd
  `/`, stdin/stdout as the only channels, and are pooled per trust domain
  (`[[principal]] trust_domain`, else the principal's first group, else the
  principal itself; unregistered `did:key` senders get a domain of their own).
- A worker receives only post-policy Arrow batches for the reads of the remit it
  is running: CBOR control frames over the pipe, Arrow IPC through a shared-memory
  ring the worker maps read-only (sealed memfd on Linux). Spectre
  inside a worker can therefore reach only data that remit was already allowed to
  read, or another remit of the same trust domain.
- Hardening after the engine loads: `RLIMIT_CORE = 0`, `RLIMIT_NOFILE = 64`;
  macOS: a deny-by-default `sandbox_init` profile (no network, files, exec, IPC);
  Linux: spawned in a fresh user + network namespace, then `PR_SET_NO_NEW_PRIVS`,
  a Landlock ruleset granting no filesystem access, and a seccomp-bpf filter
  failing sockets, file opens, exec, ptrace, namespaces, mounts, BPF, perf,
  keyrings, userfaultfd and io_uring with `EPERM` (arch mismatch kills).
- Linux workers are pinned to a core. `remit worker-selftest` hardens itself and
  then tries to read, write, connect, spawn and ptrace; every attempt must fail.
- Sender-built components are compiled in a separate **compile worker** with CPU,
  address-space and wall limits; kernel workers only load its output.
- Workers are recycled after 1000 jobs, killed on wall-deadline overrun or
  protocol errors, and respawned on demand.

## Wasmtime hygiene

- Wasmtime 48 LTS (48.0.10), Cranelift; pooling allocator with
  copy-on-write images, `InstancePre`, `linear_memory_keep_resident`.
- Features off: threads, relaxed SIMD, memory64, GC, function references, wide
  arithmetic, component-model async. NaN canonicalization on.
- Fuel only, async yields every `yield_interval` fuel; no epochs.
- Only Holder-trusted bytes are compiled; compiled artifacts are cached under the
  Holder's data dir keyed by H(wasm) ‖ Wasmtime version ‖ engine config ‖ arch.
  `.cwasm` is never accepted from outside. Unknown-import stubbing is never
  enabled; exactly the `remit:kernel` imports plus deterministic WASI stubs are
  linked (no sockets, no HTTP, no preopened directories).
- Production target for hostile code: x86-64 Linux. aarch64 (incl. macOS) is for
  development and trusted deployments.
