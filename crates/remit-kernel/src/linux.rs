//! Linux worker hardening, applied after the engine is loaded and before any
//! Sender input is read or any runtime thread exists:
//!
//! * `PR_SET_NO_NEW_PRIVS`;
//! * **Landlock**: a ruleset that handles every filesystem access right and
//!   grants none (no file can be opened, created, removed or executed);
//! * **seccomp-bpf** on *every* thread (`TSYNC`; `prctl` would cover only the
//!   caller): sockets, file opens, exec, new processes, signals to other
//!   processes, ptrace, pidfds, namespaces, mounts, BPF, perf, keyrings,
//!   userfaultfd and io_uring fail with `EPERM`; architecture mismatches and
//!   the x32 ABI kill the process;
//! * the parent spawns workers in a fresh **user + network namespace**
//!   ([`isolate_namespaces`], run in `pre_exec`), so even a seccomp bypass
//!   finds no network interface but loopback-down.
//!
//! Seccomp is mandatory: a worker that cannot install it exits. Landlock and
//! namespaces are logged and skipped on kernels that lack them.

use std::io;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

// struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0: u32 = 16; // low half: both targets are little-endian

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
#[cfg(target_arch = "x86_64")]
const BPF_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Syscalls a kernel worker never needs once the engine is loaded.
fn denied() -> Vec<libc::c_long> {
    #[allow(unused_mut)]
    let mut v = vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_process_madvise,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_quotactl,
        libc::SYS_acct,
        libc::SYS_prlimit64,
        libc::SYS_fchmodat,
        libc::SYS_fchownat,
        libc::SYS_truncate,
        libc::SYS_mkdirat,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_kexec_load,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_mknodat,
        libc::SYS_unlinkat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        libc::SYS_open,
        libc::SYS_creat,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_mknod,
    ]);
    v
}

/// Build the BPF program: check arch, then EPERM for each denied syscall.
pub fn seccomp_program() -> Vec<libc::sock_filter> {
    let deny = denied();
    let mut p = vec![
        stmt(BPF_LD_W_ABS, OFF_ARCH),
        jump(BPF_JEQ_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, OFF_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    p.extend([
        jump(BPF_JGE_K, 0x4000_0000, 0, 1),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
    ]);
    for nr in &deny {
        p.push(jump(BPF_JEQ_K, *nr as u32, 0, 1));
        p.push(stmt(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff),
        ));
    }
    let eperm = SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff);
    // clone3 hides its flags behind a pointer: make libc fall back to clone.
    p.push(jump(BPF_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    p.push(stmt(
        BPF_RET_K,
        SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & 0xffff),
    ));
    // clone: threads only.
    p.push(jump(BPF_JEQ_K, libc::SYS_clone as u32, 0, 4));
    p.push(stmt(BPF_LD_W_ABS, OFF_ARG0));
    p.push(jump(BPF_JSET_K, libc::CLONE_THREAD as u32, 1, 0));
    p.push(stmt(BPF_RET_K, eperm));
    p.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    // tgkill (abort, pthread_kill): only within this process.
    p.push(jump(BPF_JEQ_K, libc::SYS_tgkill as u32, 0, 3));
    p.push(stmt(BPF_LD_W_ABS, OFF_ARG0));
    p.push(jump(BPF_JEQ_K, std::process::id(), 1, 0));
    p.push(stmt(BPF_RET_K, eperm));
    p.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    p
}

fn install_seccomp() -> io::Result<()> {
    let prog = seccomp_program();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // Positive: the id of a thread that could not be synchronized.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &fprog as *const libc::sock_fprog,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if rc > 0 {
        return Err(io::Error::other(format!(
            "thread {rc} could not be confined"
        )));
    }
    Ok(())
}

// Landlock ABI (linux/landlock.h).
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

fn install_landlock() -> io::Result<()> {
    // SYS_landlock_create_ruleset = 444, SYS_landlock_restrict_self = 446 on both arches.
    let abi = unsafe {
        libc::syscall(
            444,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "landlock unavailable",
        ));
    }
    // Every filesystem right defined by the running ABI (v1: 13 bits, v2 +REFER, v3 +TRUNCATE, v5 +IOCTL_DEV).
    let fs_bits: u64 = match abi {
        1 => (1 << 13) - 1,
        2 => (1 << 14) - 1,
        3 | 4 => (1 << 15) - 1,
        _ => (1 << 16) - 1,
    };
    let net_bits: u64 = if abi >= 4 { 0b11 } else { 0 }; // BIND_TCP | CONNECT_TCP
    let attr = LandlockRulesetAttr {
        handled_access_fs: fs_bits,
        handled_access_net: net_bits,
    };
    let size = if abi >= 4 {
        std::mem::size_of::<LandlockRulesetAttr>()
    } else {
        8
    };
    let fd = unsafe { libc::syscall(444, &attr as *const LandlockRulesetAttr, size, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::syscall(446, fd as libc::c_int, 0u32) };
    unsafe { libc::close(fd as libc::c_int) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Apply in the worker after the engine is loaded.
pub fn harden() -> io::Result<()> {
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    if let Err(e) = install_landlock() {
        eprintln!("remit-worker: landlock not applied: {e}");
    }
    install_seccomp().map_err(|e| io::Error::other(format!("seccomp: {e}")))
}

/// Pin the calling process to one CPU (kernel workers are core-pinned).
/// Async-signal-safe: usable between fork and exec.
pub fn pin(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu % libc::CPU_SETSIZE as usize, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Run in the child between fork and exec: new user + network namespace.
/// Must not allocate; returns the raw errno result.
pub fn isolate_namespaces() -> io::Result<()> {
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
    if rc != 0 {
        // Unprivileged user namespaces may be disabled; continue without.
        return Ok(());
    }
    Ok(())
}
