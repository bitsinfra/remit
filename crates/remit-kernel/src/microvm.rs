//! Isolation level `microvm`: the kernel worker as the only program of a KVM
//! guest, one guest per trust domain.
//!
//! The guest boots a stock kernel from an initramfs built here and talks the
//! worker protocol over a single virtio serial port bound to the VMM's
//! stdin/stdout, so [`crate::WorkerPool`] drives it like any worker process.
//! There is no disk, network, clock-sharing or host file access to configure
//! away: none of those devices exist. The worker, its fuel metering and its
//! determinism are the same code as at level `process`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

use crate::EngineConfig;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MicroVmConfig {
    /// Guest kernel image (needs virtio-console, virtio-mmio, devtmpfs built in).
    pub kernel: PathBuf,
    /// The `remit-guest` binary (default: next to the running executable).
    #[serde(default)]
    pub worker: Option<PathBuf>,
    /// QEMU binary (default: `qemu-system-<arch>`).
    #[serde(default)]
    pub vmm: Option<PathBuf>,
    /// Guest memory (default: kernel memory limit + 768 MiB).
    #[serde(default)]
    pub memory_mib: Option<u64>,
}

/// SVR4 ("newc") cpio writer for the initramfs.
struct Cpio {
    out: Vec<u8>,
    ino: u32,
    dirs: std::collections::BTreeSet<String>,
}

impl Cpio {
    fn new() -> Self {
        Cpio {
            out: Vec::new(),
            ino: 0,
            dirs: Default::default(),
        }
    }
    fn entry(&mut self, name: &str, mode: u32, data: &[u8]) {
        self.ino += 1;
        let h = [
            self.ino,
            mode,
            0,
            0,
            1,
            0,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ];
        self.out.extend_from_slice(b"070701");
        for v in h {
            self.out.extend_from_slice(format!("{v:08x}").as_bytes());
        }
        self.out.extend_from_slice(name.as_bytes());
        self.out.push(0);
        self.pad();
        self.out.extend_from_slice(data);
        self.pad();
    }
    fn pad(&mut self) {
        while !self.out.len().is_multiple_of(4) {
            self.out.push(0);
        }
    }
    fn file(&mut self, path: &str, exec: bool, data: &[u8]) {
        let path = path.trim_start_matches('/');
        let mut at = String::new();
        for part in path
            .split('/')
            .collect::<Vec<_>>()
            .split_last()
            .map(|(_, d)| d)
            .unwrap_or_default()
        {
            at = if at.is_empty() {
                part.to_string()
            } else {
                format!("{at}/{part}")
            };
            if self.dirs.insert(at.clone()) {
                self.entry(&at, 0o040755, b"");
            }
        }
        self.entry(path, if exec { 0o100755 } else { 0o100644 }, data);
    }
    fn finish(mut self) -> Vec<u8> {
        self.entry("TRAILER!!!", 0, b"");
        while !self.out.len().is_multiple_of(512) {
            self.out.push(0);
        }
        self.out
    }
}

/// Shared libraries of a dynamic executable, by the path its loader expects.
fn libraries(bin: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let out = Command::new("ldd").arg(bin).output().context("ldd")?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let p = l.split("=>").last()?.trim().split(" (").next()?.trim();
            p.starts_with('/').then(|| PathBuf::from(p))
        })
        .collect())
}

/// Build the initramfs for one engine. `cache` holds the Holder-compiled
/// artifacts, so guests start without compiling.
pub fn initramfs(worker: &Path, engine: &EngineConfig, cache: &Path) -> anyhow::Result<Vec<u8>> {
    let mut c = Cpio::new();
    c.file(
        "init",
        true,
        &std::fs::read(worker).with_context(|| format!("microVM worker {}", worker.display()))?,
    );
    for lib in libraries(worker)? {
        c.file(&lib.to_string_lossy(), true, &std::fs::read(&lib)?);
    }
    c.file("engine.wasm", false, &std::fs::read(&engine.component)?);
    for e in std::fs::read_dir(cache)?
        .flatten()
        .filter(|e| e.path().is_file())
    {
        c.file(
            &format!("cache/{}", e.file_name().to_string_lossy()),
            false,
            &std::fs::read(e.path())?,
        );
    }
    let guest = EngineConfig {
        component: "/engine.wasm".into(),
        cache_dir: Some("/cache".into()),
        ..engine.clone()
    };
    c.file("remit.json", false, &serde_json::to_vec(&guest)?);
    Ok(c.finish())
}

/// Compile the engine for guests, write the initramfs under `dir`, and return
/// the VMM command that boots it.
pub async fn prepare(
    cfg: &MicroVmConfig,
    engine: EngineConfig,
    dir: &Path,
) -> anyhow::Result<(PathBuf, Vec<String>)> {
    anyhow::ensure!(
        cfg!(target_os = "linux"),
        "isolation `microvm` needs a Linux host with KVM"
    );
    anyhow::ensure!(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok(),
        "isolation `microvm` needs read-write access to /dev/kvm"
    );
    let kernel = std::fs::canonicalize(&cfg.kernel)
        .with_context(|| format!("guest kernel {}", cfg.kernel.display()))?;
    let worker = match &cfg.worker {
        Some(w) => w.clone(),
        None => std::env::current_exe()?.with_file_name("remit-guest"),
    };
    let vmm = cfg
        .vmm
        .clone()
        .unwrap_or_else(|| format!("qemu-system-{}", std::env::consts::ARCH).into());
    let vmm = if vmm.components().count() > 1 {
        vmm
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|d| d.join(&vmm))
            .find(|p| p.is_file())
            .ok_or_else(|| anyhow!("{} is not installed", vmm.display()))?
    };
    // A cache directory per engine, holding only what guests need.
    let tag: String = engine
        .lang
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let cache = dir.join(format!("microvm-cache-{tag}"));
    let engine = EngineConfig {
        pool_instances: 8,
        warm_instances: 2,
        baseline_cpu: true,
        cache_dir: Some(cache.clone()),
        ..engine
    };
    drop(crate::KernelEngine::new(engine.clone()).await?);
    let image = initramfs(&worker, &engine, &cache)?;
    let path = dir.join(format!("microvm-{tag}.cpio"));
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&image)?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    let path = std::fs::canonicalize(path)?;
    let mib = cfg
        .memory_mib
        .unwrap_or((engine.max_memory_bytes >> 20) + 768);
    Ok((vmm, vmm_args(&kernel, &path, mib)))
}

fn vmm_args(kernel: &Path, initrd: &Path, mib: u64) -> Vec<String> {
    let machine: &[&str] = if cfg!(target_arch = "aarch64") {
        &["-M", "virt,gic-version=host"]
    } else {
        &["-M", "microvm,acpi=off,rtc=off"]
    };
    let mut a: Vec<String> = machine.iter().map(|s| s.to_string()).collect();
    for s in [
        "-accel",
        "kvm",
        "-cpu",
        "host",
        "-smp",
        "1",
        "-m",
        &mib.to_string(),
        // Nothing that was not asked for: no default devices, config files, display or monitor.
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "none",
        "-no-reboot",
        "-sandbox",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-kernel",
        &kernel.to_string_lossy(),
        "-initrd",
        &initrd.to_string_lossy(),
        "-append",
        "quiet loglevel=0 panic=-1 reboot=t oops=panic random.trust_cpu=on",
        "-chardev",
        "stdio,id=w,signal=off",
        "-device",
        "virtio-serial-device",
        "-device",
        "virtserialport,chardev=w,name=remit",
    ] {
        a.push(s.to_string());
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpio_is_well_formed() {
        let mut c = Cpio::new();
        c.file("/usr/lib/a.so", true, b"abc");
        c.file("usr/lib/b", false, b"");
        let b = c.finish();
        assert_eq!(b.len() % 512, 0);
        let (mut at, mut names) = (0, vec![]);
        loop {
            assert_eq!(&b[at..at + 6], b"070701");
            let f = |i: usize| {
                usize::from_str_radix(
                    std::str::from_utf8(&b[at + 6 + 8 * i..at + 14 + 8 * i]).unwrap(),
                    16,
                )
                .unwrap()
            };
            let (size, n) = (f(6), f(11));
            let name = std::str::from_utf8(&b[at + 110..at + 110 + n - 1])
                .unwrap()
                .to_string();
            at = (at + 110 + n).next_multiple_of(4) + size;
            at = at.next_multiple_of(4);
            if name == "TRAILER!!!" {
                break;
            }
            names.push(name);
        }
        assert_eq!(names, ["usr", "usr/lib", "usr/lib/a.so", "usr/lib/b"]);
    }

    #[test]
    fn guests_get_no_devices_but_the_port() {
        let a = vmm_args(Path::new("/k"), Path::new("/i"), 512).join(" ");
        assert!(a.contains("-nodefaults"));
        for d in [
            "-net",
            "-nic",
            "-drive",
            "-blockdev",
            "-hda",
            "-virtfs",
            "vhost",
            "-usb",
            "-vga",
            "-fsdev",
        ] {
            assert!(!a.contains(d), "{d}");
        }
        assert_eq!(a.matches(" -device ").count(), 2);
    }
}
