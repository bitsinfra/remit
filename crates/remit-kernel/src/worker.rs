//! Isolation level `process`: kernels run in worker processes pooled per
//! trust domain. A worker holds no keys and no connectors; it receives only
//! post-policy Arrow batches for the remit it is running, proxied from the
//! trusted main process: control messages are CBOR frames over a pipe, data
//! arrives over a shared-memory ring the worker maps read-only (`shm.rs`).
//!
//! Sender-built components are compiled in a *separate* compile worker with
//! CPU, memory and wall limits; only its output reaches a kernel worker.
//!
//! Hardening applied in the worker after the engine is loaded:
//! * environment cleared, cwd `/`, stdin/stdout are the only channels;
//! * `RLIMIT_NOFILE` lowered, core dumps disabled;
//! * macOS: `sandbox_init` profile denying network and file writes/reads of
//!   user data;
//! * Linux: fresh user + network namespace (spawn), no-new-privs, Landlock
//!   (no filesystem access) and a seccomp-bpf denylist (see `linux.rs`).

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::shm::SharedMem;
use crate::{
    ByteBuf, EngineConfig, HostTable, KernelEngine, KernelJob, KernelOutcome, ReadErr, ReadHost,
    Status,
};

#[derive(Serialize, Deserialize, Debug)]
enum Chunk {
    Shm { off: u64, len: u64 },
    Inline(ByteBuf),
}

#[derive(Serialize, Deserialize, Debug)]
struct WireTable {
    schema: Chunk,
    batches: Vec<Chunk>,
    rows: u64,
    bytes: u64,
}

fn pack(t: HostTable, ring: &mut Option<SharedMem>) -> WireTable {
    if let Some(r) = ring.as_mut() {
        r.rewind();
    }
    let mut chunk = |b: Vec<u8>| match ring.as_mut().and_then(|r| r.put(&b)) {
        Some(off) => Chunk::Shm {
            off,
            len: b.len() as u64,
        },
        None => Chunk::Inline(ByteBuf(b)),
    };
    WireTable {
        schema: chunk(t.schema_ipc),
        batches: t.batches_ipc.into_iter().map(|b| chunk(b.0)).collect(),
        rows: t.rows,
        bytes: t.bytes,
    }
}

fn unpack(t: WireTable, ring: &Option<SharedMem>) -> Option<HostTable> {
    let take = |c: Chunk| match c {
        Chunk::Inline(b) => Some(b.0),
        Chunk::Shm { off, len } => ring.as_ref()?.get(off, len),
    };
    Some(HostTable {
        schema_ipc: take(t.schema)?,
        batches_ipc: t
            .batches
            .into_iter()
            .map(|b| take(b).map(ByteBuf))
            .collect::<Option<_>>()?,
        rows: t.rows,
        bytes: t.bytes,
    })
}

#[derive(Serialize, Deserialize, Debug)]
enum ToWorker {
    Run {
        job: KernelJob,
        declared: Vec<String>,
        fn_prices: BTreeMap<String, u64>,
    },
    ReadResult {
        ok: Option<WireTable>,
        err: Option<ReadErr>,
    },
    FnResult {
        ok: Option<Value>,
        err: Option<ReadErr>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
enum FromWorker {
    Ready {
        engine_sha256: String,
        baseline_load_fuel: u64,
    },
    Read {
        name: String,
        params: serde_json::Map<String, Value>,
    },
    Fn {
        name: String,
        args: Value,
    },
    Done {
        outcome: KernelOutcome,
    },
}

const MAX_FRAME: usize = 256 << 20;
/// Shared-memory ring per worker.
const RING_BYTES: usize = 16 << 20;
/// Descriptor number the ring is inherited on.
const RING_FD: i32 = 3;
const RING_ENV: &str = "REMIT_RING";

async fn write_frame<W: AsyncWriteExt + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> anyhow::Result<()> {
    let mut b = vec![0u8; 4];
    ciborium::into_writer(msg, &mut b)?;
    let n = (b.len() - 4) as u32;
    b[..4].copy_from_slice(&n.to_le_bytes());
    w.write_all(&b).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> anyhow::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(anyhow!("frame too large"));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    // Bounded recursion: a worker cannot make the parent overflow its stack.
    Ok(ciborium::de::from_reader_with_recursion_limit(
        b.as_slice(),
        128,
    )?)
}

// ------------------------------------------------------------- worker side

/// Entry point for `remit kernel-worker`: load the engine, harden the
/// process, then serve jobs over stdin/stdout until EOF.
///
/// Must be called from a process with no other threads: on Linux, Landlock
/// binds the calling thread and those it creates, so the engine is loaded on a
/// throw-away single-threaded runtime and the serving runtime starts only once
/// the process is confined.
pub fn serve_stdio(cfg: EngineConfig) -> anyhow::Result<()> {
    let ring = match std::env::var(RING_ENV)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        Some(len) => Some(SharedMem::open(RING_FD, len).context("shared-memory ring")?),
        None => None,
    };
    let ring = Arc::new(ring);
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(KernelEngine::new(cfg))?;
    harden()?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(serve(engine, ring))
}

async fn serve(engine: Arc<KernelEngine>, ring: Arc<Option<SharedMem>>) -> anyhow::Result<()> {
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    write_frame(
        &mut *stdout.lock().await,
        &FromWorker::Ready {
            engine_sha256: engine.engine_sha256().to_string(),
            baseline_load_fuel: engine.baseline_load_fuel(),
        },
    )
    .await?;
    // One reader owns stdin for the life of the process.
    let (tx, rx) = tokio::sync::mpsc::channel::<ToWorker>(4);
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        while let Ok(m) = read_frame::<_, ToWorker>(&mut stdin).await {
            if tx.send(m).await.is_err() {
                break;
            }
        }
    });
    let rx = Arc::new(Mutex::new(rx));
    loop {
        let msg = rx.lock().await.recv().await;
        let Some(msg) = msg else { return Ok(()) }; // parent closed the pipe
        let ToWorker::Run {
            job,
            declared,
            fn_prices,
        } = msg
        else {
            continue;
        };
        let proxy = RemoteReads {
            declared,
            fn_prices,
            ring: ring.clone(),
            out: stdout.clone(),
            replies: rx.clone(),
        };
        let outcome = engine.run(&job, Box::new(proxy)).await;
        write_frame(&mut *stdout.lock().await, &FromWorker::Done { outcome }).await?;
    }
}

struct RemoteReads {
    declared: Vec<String>,
    fn_prices: BTreeMap<String, u64>,
    ring: Arc<Option<SharedMem>>,
    out: Arc<Mutex<tokio::io::Stdout>>,
    replies: Arc<Mutex<tokio::sync::mpsc::Receiver<ToWorker>>>,
}

#[async_trait::async_trait]
impl ReadHost for RemoteReads {
    fn declared(&self) -> Vec<String> {
        self.declared.clone()
    }
    async fn call(
        &mut self,
        name: &str,
        params: serde_json::Map<String, Value>,
    ) -> Result<HostTable, ReadErr> {
        write_frame(
            &mut *self.out.lock().await,
            &FromWorker::Read {
                name: name.into(),
                params,
            },
        )
        .await
        .map_err(|_| ReadErr::Internal)?;
        match self.replies.lock().await.recv().await {
            Some(ToWorker::ReadResult { ok: Some(t), .. }) => {
                unpack(t, &self.ring).ok_or(ReadErr::Internal)
            }
            Some(ToWorker::ReadResult { err: Some(e), .. }) => Err(e),
            _ => Err(ReadErr::Internal),
        }
    }
    async fn holder_fn(&mut self, name: &str, args: Value) -> Result<Value, ReadErr> {
        write_frame(
            &mut *self.out.lock().await,
            &FromWorker::Fn {
                name: name.into(),
                args,
            },
        )
        .await
        .map_err(|_| ReadErr::Internal)?;
        match self.replies.lock().await.recv().await {
            Some(ToWorker::FnResult { ok: Some(v), .. }) => Ok(v),
            Some(ToWorker::FnResult { err: Some(e), .. }) => Err(e),
            _ => Err(ReadErr::Internal),
        }
    }
    fn fn_price(&self, name: &str) -> Option<u64> {
        self.fn_prices.get(name).copied()
    }
}

/// Entry point for `remit compile-worker`: one Sender component on stdin, the
/// Holder-compiled artifact on stdout. Limits are applied before any input is
/// read; the process exits after one compile.
pub fn compile_stdio(max_memory_bytes: u64) -> anyhow::Result<()> {
    use std::io::{Read as _, Write as _};
    unsafe {
        let cpu = libc::rlimit {
            rlim_cur: COMPILE_CPU_S,
            rlim_max: COMPILE_CPU_S,
        };
        libc::setrlimit(libc::RLIMIT_CPU, &cpu);
        #[cfg(target_os = "linux")]
        {
            let mem = libc::rlimit {
                rlim_cur: COMPILE_AS_BYTES,
                rlim_max: COMPILE_AS_BYTES,
            };
            libc::setrlimit(libc::RLIMIT_AS, &mem);
        }
    }
    let engine = crate::sender::restricted_engine(max_memory_bytes)?;
    harden()?;
    let mut bytes = Vec::new();
    std::io::stdin().take(64 << 20).read_to_end(&mut bytes)?;
    crate::sender::validate_structure(&bytes, &Default::default()).map_err(|e| anyhow!(e))?;
    let c = wasmtime::component::Component::new(&engine, &bytes)?;
    std::io::stdout().write_all(&c.serialize()?)?;
    Ok(())
}

const COMPILE_CPU_S: u64 = 20;
#[cfg(target_os = "linux")]
const COMPILE_AS_BYTES: u64 = 4 << 30;

/// OS hardening of the worker process. Fails closed: a worker that cannot be
/// confined must not read Sender input.
pub fn harden() -> anyhow::Result<()> {
    // SAFETY: plain setrlimit calls on our own process.
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
        let lim = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
    }
    #[cfg(target_os = "linux")]
    crate::linux::harden()?;
    #[cfg(target_os = "macos")]
    macos_sandbox()?;
    Ok(())
}

/// What a hardened worker can still do. Every field must be `false`
/// (`remit worker-selftest`, run by the test suite on each platform).
#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct Escapes {
    pub read_file: bool,
    pub write_file: bool,
    pub tcp_connect: bool,
    pub unix_socket: bool,
    pub spawn_process: bool,
    pub read_other_process: bool,
    /// A thread that already existed when the sandbox was applied.
    pub sibling_thread: bool,
    pub signal_other_process: bool,
    /// `fork` without exec.
    pub fork: bool,
    /// The sandbox could not be applied at all.
    pub unconfined: bool,
}

/// Harden this process, then try to break out of it.
pub fn selftest(secret_file: &std::path::Path) -> Escapes {
    let parent = unsafe { libc::getppid() };
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let path = secret_file.to_path_buf();
    let sibling = std::thread::spawn(move || {
        let _ = wait.recv();
        std::fs::read(path).is_ok()
            || std::net::UdpSocket::bind("127.0.0.1:0")
                .is_ok_and(|s| s.send_to(b"x", "127.0.0.1:9").is_ok())
    });
    let unconfined = harden().is_err();
    let _ = go.send(());
    let tmp = std::env::temp_dir().join(format!("remit-escape-{}", std::process::id()));
    Escapes {
        read_file: std::fs::read(secret_file).is_ok(),
        write_file: std::fs::write(&tmp, b"x").is_ok(),
        tcp_connect: std::net::TcpStream::connect_timeout(
            &"127.0.0.1:1".parse().expect("addr"),
            Duration::from_millis(200),
        )
        .is_ok()
            || std::net::TcpListener::bind("127.0.0.1:0").is_ok()
            || std::net::UdpSocket::bind("127.0.0.1:0")
                .is_ok_and(|s| s.send_to(b"x", "127.0.0.1:9").is_ok()),
        unix_socket: std::os::unix::net::UnixListener::bind(tmp.with_extension("sock")).is_ok()
            || std::os::unix::net::UnixStream::pair().is_ok_and(|_| cfg!(target_os = "linux")),
        spawn_process: std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("true")
            .status()
            .is_ok(),
        read_other_process: {
            #[cfg(target_os = "linux")]
            {
                std::fs::read(format!("/proc/{parent}/environ")).is_ok()
                    || unsafe { libc::ptrace(libc::PTRACE_ATTACH, parent, 0, 0) } == 0
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        },
        sibling_thread: sibling.join().unwrap_or(true),
        signal_other_process: unsafe { libc::kill(parent, 0) } == 0,
        fork: unsafe {
            match libc::fork() {
                0 => libc::_exit(0),
                pid => pid > 0,
            }
        },
        unconfined,
    }
}

#[cfg(target_os = "macos")]
fn macos_sandbox() -> anyhow::Result<()> {
    use std::ffi::{CStr, CString};
    extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            errorbuf: *mut *mut libc::c_char,
        ) -> libc::c_int;
    }
    // Deny by default: no network, no file writes, no exec/fork, no IPC, and
    // reads only of the OS libraries the process already maps.
    let profile = CString::new(
        "(version 1)(deny default)(allow sysctl-read)(allow process-info* (target self))(allow signal (target self))(allow file-read* (subpath \"/usr/lib\") (subpath \"/System/Library\") (literal \"/dev/urandom\") (literal \"/dev/null\"))(allow file-read-metadata)",
    )
    .unwrap();
    let mut err: *mut libc::c_char = std::ptr::null_mut();
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut err) };
    if rc != 0 {
        let msg = if err.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(err) }.to_string_lossy().to_string()
        };
        return Err(anyhow!("sandbox_init failed: {msg}"));
    }
    Ok(())
}

// ------------------------------------------------------------- parent side

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    ring: Option<SharedMem>,
    jobs: u64,
}

/// Pool of worker processes keyed by trust domain.
pub struct WorkerPool {
    program: PathBuf,
    args: Vec<String>,
    per_domain: usize,
    max_jobs_per_worker: u64,
    domains: Mutex<HashMap<String, Vec<Arc<Mutex<Option<Worker>>>>>>,
    /// Compile-worker command (defaults to `<program> compile-worker`).
    compile: Option<(PathBuf, Vec<String>)>,
    /// Hand data over in shared memory (not across a VM boundary).
    shared_memory: bool,
    compiled: Mutex<lru::LruCache<String, Arc<Vec<u8>>>>,
}

impl WorkerPool {
    /// `program args…` must start a process that calls [`serve_stdio`].
    pub fn new(program: PathBuf, args: Vec<String>, per_domain: usize) -> Arc<Self> {
        Self::with_compiler(program, args, per_domain, None)
    }

    /// `compile` must start a process that calls [`compile_stdio`]; without
    /// it, Sender components are compiled inside their kernel worker.
    pub fn with_compiler(
        program: PathBuf,
        args: Vec<String>,
        per_domain: usize,
        compile: Option<(PathBuf, Vec<String>)>,
    ) -> Arc<Self> {
        Self::build(program, args, per_domain, compile, true)
    }

    /// Workers behind a VM boundary: `program args…` is a VMM whose stdin and
    /// stdout reach a guest running [`serve_stdio`] (see [`crate::microvm`]).
    pub fn microvm(program: PathBuf, args: Vec<String>, per_domain: usize) -> Arc<Self> {
        Self::build(program, args, per_domain, None, false)
    }

    fn build(
        program: PathBuf,
        args: Vec<String>,
        per_domain: usize,
        compile: Option<(PathBuf, Vec<String>)>,
        shared_memory: bool,
    ) -> Arc<Self> {
        Arc::new(WorkerPool {
            program,
            args,
            per_domain: per_domain.max(1),
            max_jobs_per_worker: 1000,
            domains: Mutex::new(HashMap::new()),
            compile,
            shared_memory,
            compiled: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(64).expect("nonzero"),
            )),
        })
    }

    /// Compile a Sender component in a resource-limited process, cached by hash.
    async fn compile(&self, b64: &str) -> anyhow::Result<Option<Arc<Vec<u8>>>> {
        let Some((prog, args)) = &self.compile else {
            return Ok(None);
        };
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
            .map_err(|_| anyhow!("component is not base64"))?;
        let sha = remit_wire::sha256_hex(&bytes);
        if let Some(c) = self.compiled.lock().await.get(&sha) {
            return Ok(Some(c.clone()));
        }
        let mut cmd = Command::new(prog);
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(crate::linux::isolate_namespaces);
        }
        let mut child = cmd
            .args(args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().expect("piped");
        let mut stdout = child.stdout.take().expect("piped");
        let work = async {
            let feed = async move {
                let _ = stdin.write_all(&bytes).await;
                drop(stdin);
            };
            let mut out = Vec::new();
            let read = async { (&mut stdout).take(256 << 20).read_to_end(&mut out).await };
            let (_, r) = tokio::join!(feed, read);
            r?;
            let st = child.wait().await?;
            anyhow::ensure!(
                st.success() && !out.is_empty(),
                "compile worker failed ({st})"
            );
            Ok::<_, anyhow::Error>(out)
        };
        let out = tokio::time::timeout(crate::sender::COMPILE_TIMEOUT * 2, work)
            .await
            .map_err(|_| anyhow!("compile timeout"))??;
        let out = Arc::new(out);
        self.compiled.lock().await.put(sha, out.clone());
        Ok(Some(out))
    }

    async fn spawn(&self) -> anyhow::Result<Worker> {
        let (ring, ring_fd) = match if self.shared_memory {
            SharedMem::create(RING_BYTES)
        } else {
            Err(std::io::ErrorKind::Unsupported.into())
        } {
            Err(_) if !self.shared_memory => (None, None),
            Ok((m, fd)) => (Some(m), Some(fd)),
            Err(e) => {
                tracing::warn!("no shared-memory ring, sending data inline: {e}");
                (None, None)
            }
        };
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args).env_clear();
        if let Some(fd) = &ring_fd {
            use std::os::fd::AsRawFd;
            let raw = fd.as_raw_fd();
            cmd.env(RING_ENV, RING_BYTES.to_string());
            // SAFETY: dup2/fcntl are async-signal-safe.
            unsafe {
                cmd.pre_exec(move || {
                    if raw == RING_FD {
                        libc::fcntl(raw, libc::F_SETFD, 0);
                    } else if libc::dup2(raw, RING_FD) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        #[cfg(target_os = "linux")]
        {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            let cpu = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % cpus;
            unsafe {
                cmd.pre_exec(move || {
                    crate::linux::pin(cpu);
                    Ok(())
                });
            }
        }
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(crate::linux::isolate_namespaces);
        }
        let mut child = cmd
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn worker {}", self.program.display()))?;
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let ready: FromWorker =
            tokio::time::timeout(Duration::from_secs(120), read_frame(&mut stdout))
                .await
                .map_err(|_| anyhow!("worker did not become ready"))??;
        if !matches!(ready, FromWorker::Ready { .. }) {
            return Err(anyhow!("unexpected worker greeting"));
        }
        drop(ring_fd);
        Ok(Worker {
            child,
            stdin,
            stdout,
            ring,
            jobs: 0,
        })
    }

    async fn slot(&self, domain: &str) -> Arc<Mutex<Option<Worker>>> {
        let mut d = self.domains.lock().await;
        let slots = d.entry(domain.to_string()).or_insert_with(|| {
            (0..self.per_domain)
                .map(|_| Arc::new(Mutex::new(None)))
                .collect()
        });
        // Prefer an idle slot; otherwise pick by round-robin hash.
        for s in slots.iter() {
            if s.try_lock().is_ok() {
                return s.clone();
            }
        }
        slots[(rand::random::<u32>() as usize) % slots.len()].clone()
    }

    /// OS process id of a trust domain's first live worker.
    pub async fn worker_pid(&self, domain: &str) -> Option<u32> {
        let slots = self.domains.lock().await.get(domain).cloned()?;
        for s in slots {
            if let Some(w) = s.lock().await.as_ref() {
                return w.child.id();
            }
        }
        None
    }

    /// Pre-spawn a worker for a trust domain.
    pub async fn warm(&self, domain: &str) -> anyhow::Result<()> {
        let slot = self.slot(domain).await;
        let mut g = slot.lock().await;
        if g.is_none() {
            *g = Some(self.spawn().await?);
        }
        Ok(())
    }

    pub async fn run(
        &self,
        domain: &str,
        job: &KernelJob,
        mut host: Box<dyn ReadHost>,
    ) -> KernelOutcome {
        let mut owned;
        let mut job = job;
        if job.component {
            match self.compile(&job.source).await {
                Ok(Some(c)) => {
                    owned = job.clone();
                    owned.source = String::new();
                    owned.compiled = Some(ByteBuf(c.as_ref().clone()));
                    job = &owned;
                }
                Ok(None) => {}
                Err(e) => return failed(format!("compile: {e}")),
            }
        }
        let slot = self.slot(domain).await;
        let mut g = slot.lock().await;
        if g.is_none() {
            match self.spawn().await {
                Ok(w) => *g = Some(w),
                Err(e) => return failed(format!("worker spawn: {e}")),
            }
        }
        let w = g.as_mut().unwrap();
        let deadline = Duration::from_millis(job.limits.wall_ms + 2_000);
        let res = tokio::time::timeout(deadline, drive(w, job, host.as_mut())).await;
        let outcome = match res {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                *g = None; // protocol error: discard worker
                return failed(format!("worker: {e}"));
            }
            Err(_) => {
                if let Some(mut w) = g.take() {
                    let _ = w.child.start_kill();
                }
                let mut o = failed("worker exceeded wall deadline".into());
                o.status = Status::LimitExceeded;
                return o;
            }
        };
        w.jobs += 1;
        if w.jobs >= self.max_jobs_per_worker {
            *g = None;
        }
        outcome
    }
}

async fn drive(
    w: &mut Worker,
    job: &KernelJob,
    host: &mut dyn ReadHost,
) -> anyhow::Result<KernelOutcome> {
    write_frame(
        &mut w.stdin,
        &ToWorker::Run {
            job: job.clone(),
            declared: host.declared(),
            fn_prices: host.fn_prices(),
        },
    )
    .await?;
    loop {
        let msg: FromWorker = read_frame(&mut w.stdout).await?;
        match msg {
            FromWorker::Read { name, params } => {
                let r = host.call(&name, params).await;
                let reply = match r {
                    Ok(t) => ToWorker::ReadResult {
                        ok: Some(pack(t, &mut w.ring)),
                        err: None,
                    },
                    Err(e) => ToWorker::ReadResult {
                        ok: None,
                        err: Some(e),
                    },
                };
                write_frame(&mut w.stdin, &reply).await?;
            }
            FromWorker::Fn { name, args } => {
                let r = host.holder_fn(&name, args).await;
                let reply = match r {
                    Ok(v) => ToWorker::FnResult {
                        ok: Some(v),
                        err: None,
                    },
                    Err(e) => ToWorker::FnResult {
                        ok: None,
                        err: Some(e),
                    },
                };
                write_frame(&mut w.stdin, &reply).await?;
            }
            FromWorker::Done { outcome } => return Ok(outcome),
            FromWorker::Ready { .. } => {}
        }
    }
}

fn failed(log: String) -> KernelOutcome {
    KernelOutcome {
        status: Status::Internal,
        result_cbor: vec![],
        fuel_used: 0,
        host_fuel: 0,
        wall_us: 0,
        instantiate_us: 0,
        log,
    }
}
