//! Shared-memory handoff from the trusted main process to a worker: the parent
//! maps it read-write, the worker read-only. Post-policy Arrow batches are
//! written into a ring; the worker copies them out before it can make another
//! request (strict request/response), so a wrapped region is always free.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub struct SharedMem {
    ptr: *mut u8,
    len: usize,
    head: usize,
    writable: bool,
}

// SAFETY: the mapping is owned by this value; access goes through &mut / &self.
unsafe impl Send for SharedMem {}
unsafe impl Sync for SharedMem {}

impl Drop for SharedMem {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

fn map(fd: RawFd, len: usize, writable: bool) -> io::Result<SharedMem> {
    let prot = if writable {
        libc::PROT_READ | libc::PROT_WRITE
    } else {
        libc::PROT_READ
    };
    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, libc::MAP_SHARED, fd, 0) };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(SharedMem {
        ptr: ptr.cast(),
        len,
        head: 0,
        writable,
    })
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

impl SharedMem {
    /// Create a region. Returns the writable mapping and a read-only
    /// descriptor for the worker.
    pub fn create(len: usize) -> io::Result<(SharedMem, OwnedFd)> {
        #[cfg(target_os = "linux")]
        unsafe {
            let rw = OwnedFd::from_raw_fd(check(libc::memfd_create(
                c"remit-ring".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            ))?);
            check(libc::ftruncate(rw.as_raw_fd(), len as libc::off_t))?;
            let m = map(rw.as_raw_fd(), len, true)?;
            // No new writable mappings, no resizing (best effort on old kernels).
            const F_SEAL_FUTURE_WRITE: libc::c_int = 0x0010;
            libc::fcntl(
                rw.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | F_SEAL_FUTURE_WRITE,
            );
            let path =
                std::ffi::CString::new(format!("/proc/self/fd/{}", rw.as_raw_fd())).expect("path");
            let ro = OwnedFd::from_raw_fd(check(libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            ))?);
            Ok((m, ro))
        }
        #[cfg(not(target_os = "linux"))]
        unsafe {
            let name = std::ffi::CString::new(format!("/rmt{:016x}", rand::random::<u64>()))
                .expect("name");
            let rw = OwnedFd::from_raw_fd(check(libc::shm_open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600 as libc::c_uint,
            ))?);
            let ro = check(libc::shm_open(
                name.as_ptr(),
                libc::O_RDONLY,
                0 as libc::c_uint,
            ));
            libc::shm_unlink(name.as_ptr());
            let ro = OwnedFd::from_raw_fd(ro?);
            check(libc::ftruncate(rw.as_raw_fd(), len as libc::off_t))?;
            libc::fcntl(ro.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
            Ok((map(rw.as_raw_fd(), len, true)?, ro))
        }
    }

    /// Map a descriptor inherited from the parent, read-only, and close it.
    pub fn open(fd: RawFd, len: usize) -> io::Result<SharedMem> {
        // SAFETY: the parent dedicated this descriptor to us.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        map(fd.as_raw_fd(), len, false)
    }

    /// Write into the ring; `None` when it does not fit (send it inline).
    pub fn put(&mut self, b: &[u8]) -> Option<u64> {
        if !self.writable || b.len() > self.len {
            return None;
        }
        if self.head + b.len() > self.len {
            return None;
        }
        // SAFETY: bounds checked above; we hold &mut self.
        unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), self.ptr.add(self.head), b.len()) };
        let at = self.head;
        self.head += b.len();
        Some(at as u64)
    }

    /// Start a new message (everything previously written has been consumed).
    pub fn rewind(&mut self) {
        self.head = 0;
    }

    pub fn get(&self, off: u64, len: u64) -> Option<Vec<u8>> {
        let (off, len) = (usize::try_from(off).ok()?, usize::try_from(len).ok()?);
        if off.checked_add(len)? > self.len {
            return None;
        }
        // SAFETY: bounds checked; the parent does not write while we read.
        Some(unsafe { std::slice::from_raw_parts(self.ptr.add(off), len) }.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    #[test]
    fn ring_roundtrip_is_read_only_for_the_reader() {
        let (mut w, fd) = SharedMem::create(1 << 16).unwrap();
        let a = w.put(b"hello").unwrap();
        let b = w.put(&[7u8; 1000]).unwrap();
        // A writable mapping through the worker's descriptor is refused.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                1 << 16,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        assert_eq!(p, libc::MAP_FAILED);
        let mut r = SharedMem::open(fd.into_raw_fd(), 1 << 16).unwrap();
        assert_eq!(r.get(a, 5).unwrap(), b"hello");
        assert_eq!(r.get(b, 1000).unwrap(), vec![7u8; 1000]);
        assert!(r.get(1 << 16, 1).is_none() && r.get(u64::MAX, 2).is_none());
        assert!(r.put(b"x").is_none(), "read-only");
        assert!(w.put(&vec![0; 1 << 17]).is_none());
        w.rewind();
        assert_eq!(w.put(b"again").unwrap(), 0);
        assert_eq!(r.get(0, 5).unwrap(), b"again");
    }
}
