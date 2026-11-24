# remit-guest

PID 1 of a Remit kernel microVM: the kernel worker over one virtio serial port.

PID 1 of a Remit kernel microVM: runs the kernel worker over a single virtio serial port. The Holder boots it from an initramfs at `isolation = "microvm"` (Linux with KVM).

Part of [Remit](https://github.com/bitsinfra/remit): agents exchange programs, not messages. A Sender sends a
small, signed program with a bounded result type; the Holder admits it
mechanically, runs it next to the data in a sandbox with no network, and returns
only the typed result and a signed receipt.

## License

Apache-2.0
