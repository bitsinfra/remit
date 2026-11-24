//! `/init` of the `microvm` isolation level. The guest has no disk, no network
//! device and no shell: an initramfs with this program, the pinned engine and
//! its Holder-compiled cache, and one virtio serial port to the Holder. Inside,
//! the worker applies the same Landlock + seccomp hardening as at level
//! `process`, unprivileged, so a Wasm escape still has to break the guest
//! kernel and then the hypervisor.

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use std::os::fd::AsRawFd;
    // SAFETY: plain syscalls on our own process with valid NUL-terminated paths.
    unsafe {
        ensure!(
            libc::getpid() == 1,
            "remit-guest is the init of a Remit microVM"
        );
        libc::mkdir(c"/dev".as_ptr(), 0o755);
        libc::mount(
            c"dev".as_ptr(),
            c"/dev".as_ptr(),
            c"devtmpfs".as_ptr(),
            0,
            std::ptr::null(),
        );
    }
    let mut port = None;
    for _ in 0..500 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vport0p1")
        {
            Ok(f) => {
                port = Some(f);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    let port = port.context("no virtio serial port")?;
    let cfg = serde_json::from_slice(&std::fs::read("/remit.json")?)?;
    unsafe {
        ensure!(
            libc::dup2(port.as_raw_fd(), 0) == 0 && libc::dup2(port.as_raw_fd(), 1) == 1,
            "dup2"
        );
    }
    drop(port);
    unsafe {
        ensure!(
            libc::setgroups(0, std::ptr::null()) == 0
                && libc::setgid(65534) == 0
                && libc::setuid(65534) == 0,
            "drop privileges"
        );
    }
    // Returning from PID 1 panics the guest, which ends the VM (`panic=-1`).
    remit_kernel::worker::serve_stdio(cfg)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("remit-guest runs only as the init of a Linux microVM");
    std::process::exit(1);
}
