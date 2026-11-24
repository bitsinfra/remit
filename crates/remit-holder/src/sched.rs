//! Weighted fair queuing of execution slots per principal.
//!
//! Start-time fair queuing: every request gets a virtual finish tag
//! `max(V, last[principal]) + cost / weight`; free slots go to the smallest
//! tag. A principal that floods the queue only delays itself. Queues are
//! bounded (globally and per principal); a full queue is backpressure
//! (`429` + `Retry-After`).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::oneshot;

#[derive(Debug)]
pub struct Full;

#[derive(PartialEq, PartialOrd)]
struct Tag(f64, u64);
impl Eq for Tag {}
#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for Tag {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&o.0).then(self.1.cmp(&o.1))
    }
}

struct Waiter {
    principal: String,
    tx: oneshot::Sender<Permit>,
}

#[derive(Default)]
struct Inner {
    running: usize,
    v: f64,
    seq: u64,
    last: HashMap<String, f64>,
    heap: BinaryHeap<Reverse<Tag>>,
    waiters: HashMap<u64, Waiter>,
    per_principal: HashMap<String, usize>,
}

pub struct Scheduler {
    inner: Mutex<Inner>,
    capacity: usize,
    max_queue: usize,
    max_queue_per_principal: usize,
}

/// An execution slot, released on drop.
pub struct Permit(Option<Arc<Scheduler>>);

/// A granted or queued slot.
pub enum Slot {
    Ready(Permit),
    Queued(oneshot::Receiver<Permit>),
}

impl Slot {
    pub async fn wait(self) -> Option<Permit> {
        match self {
            Slot::Ready(p) => Some(p),
            Slot::Queued(rx) => rx.await.ok(),
        }
    }
}

impl Scheduler {
    pub fn new(capacity: usize, max_queue: usize) -> Arc<Self> {
        Arc::new(Scheduler {
            inner: Mutex::new(Inner::default()),
            capacity: capacity.max(1),
            max_queue,
            max_queue_per_principal: (max_queue / 4).max(1),
        })
    }

    pub fn enqueue(
        self: &Arc<Self>,
        principal: &str,
        weight: u32,
        cost: f64,
    ) -> Result<Slot, Full> {
        let mut st = self.inner.lock();
        let start = st.last.get(principal).copied().unwrap_or(0.0).max(st.v);
        let finish = start + cost.max(1e-6) / weight.max(1) as f64;
        if st.running < self.capacity && st.waiters.is_empty() {
            st.running += 1;
            st.v = start;
            st.last.insert(principal.to_string(), finish);
            return Ok(Slot::Ready(Permit(Some(self.clone()))));
        }
        let mine = st.per_principal.get(principal).copied().unwrap_or(0);
        if st.waiters.len() >= self.max_queue || mine >= self.max_queue_per_principal {
            return Err(Full);
        }
        st.last.insert(principal.to_string(), finish);
        st.seq += 1;
        let seq = st.seq;
        let (tx, rx) = oneshot::channel();
        st.heap.push(Reverse(Tag(finish, seq)));
        st.waiters.insert(
            seq,
            Waiter {
                principal: principal.to_string(),
                tx,
            },
        );
        *st.per_principal.entry(principal.to_string()).or_default() += 1;
        Ok(Slot::Queued(rx))
    }

    pub fn queued(&self) -> usize {
        self.inner.lock().waiters.len()
    }

    pub fn running(&self) -> usize {
        self.inner.lock().running
    }

    fn release(self: Arc<Self>) {
        loop {
            let waiter = {
                let mut st = self.inner.lock();
                match st.heap.pop() {
                    None => {
                        st.running -= 1;
                        if st.running == 0 && st.waiters.is_empty() {
                            // Idle: forget history so tags do not grow forever.
                            st.last.clear();
                            st.v = 0.0;
                        }
                        return;
                    }
                    Some(Reverse(Tag(f, seq))) => {
                        st.v = st.v.max(f);
                        let w = st.waiters.remove(&seq).expect("queued waiter");
                        if let Some(n) = st.per_principal.get_mut(&w.principal) {
                            *n -= 1;
                            if *n == 0 {
                                st.per_principal.remove(&w.principal);
                            }
                        }
                        w
                    }
                }
            };
            // Hand the slot over; a waiter that went away is skipped.
            match waiter.tx.send(Permit(Some(self.clone()))) {
                Ok(()) => return,
                Err(mut p) => {
                    p.0 = None;
                }
            }
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            s.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_flood_only_delays_itself() {
        let s = Scheduler::new(1, 1000);
        let Slot::Ready(first) = s.enqueue("flood", 1, 1.0).unwrap() else {
            panic!()
        };
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut hs = Vec::new();
        let mut add = |who: &'static str, weight| {
            let slot = s.enqueue(who, weight, 1.0).unwrap();
            let o = order.clone();
            hs.push(tokio::spawn(async move {
                let p = slot.wait().await.unwrap();
                o.lock().push(who);
                tokio::task::yield_now().await;
                drop(p);
            }));
        };
        for _ in 0..20 {
            add("flood", 1);
        }
        add("polite", 1);
        add("heavy", 4);
        add("heavy", 4);
        drop(first);
        for h in hs {
            h.await.unwrap();
        }
        let o = order.lock();
        let pos = |w: &str| o.iter().position(|x| *x == w).unwrap();
        assert!(pos("polite") < 3, "{o:?}");
        assert!(o.iter().rposition(|x| *x == "heavy").unwrap() < 4, "{o:?}");
        assert_eq!(s.running(), 0);
    }

    #[tokio::test]
    async fn bounded_queues_and_dropped_waiters() {
        let s = Scheduler::new(1, 8);
        let p = match s.enqueue("a", 1, 1.0).unwrap() {
            Slot::Ready(p) => p,
            _ => panic!(),
        };
        let q1 = s.enqueue("a", 1, 1.0).unwrap();
        let _q2 = s.enqueue("a", 1, 1.0).unwrap();
        assert!(s.enqueue("a", 1, 1.0).is_err(), "per-principal bound");
        let q3 = s.enqueue("b", 1, 1.0).unwrap();
        drop(q1);
        drop(p); // skips the dropped waiter
        drop(_q2); // granted or queued, then abandoned: the slot must come back
        let _p3 = q3.wait().await.unwrap();
        assert_eq!(s.running(), 1);
        drop(_p3);
        assert_eq!((s.running(), s.queued()), (0, 0));
    }
}
