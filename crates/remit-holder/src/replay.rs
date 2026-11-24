//! Nonce replay cache: sharded, TTL = the remit's remaining validity, bounded,
//! and persisted so a restart does not reopen the replay window.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use parking_lot::Mutex;

const SHARDS: usize = 16;
const BUCKET_MS: i64 = 60_000;
const MAX_PER_SHARD: usize = 100_000;

#[derive(Default)]
struct Shard {
    seen: HashMap<[u8; 16], i64>,
    by_expiry: BTreeMap<i64, Vec<[u8; 16]>>,
}

#[derive(Debug, PartialEq)]
pub enum Seen {
    Fresh,
    Replayed,
    /// The cache is full of unexpired nonces: shed load instead of forgetting.
    Full,
}

pub struct ReplayCache {
    shards: Vec<Mutex<Shard>>,
    log: Option<Mutex<File>>,
}

fn key(sender: &str, nonce: &str) -> [u8; 16] {
    let mut k = [0; 16];
    k.copy_from_slice(
        &remit_wire::sha256(format!("{}:{sender}|{nonce}", sender.len()).as_bytes())[..16],
    );
    k
}

impl ReplayCache {
    pub fn open(path: Option<&Path>, now_ms: i64) -> std::io::Result<Self> {
        let mut c = ReplayCache {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            log: None,
        };
        let Some(p) = path else { return Ok(c) };
        if let Ok(f) = File::open(p) {
            for l in BufReader::new(f).lines().map_while(Result::ok) {
                let Some((k, e)) = l.split_once(' ') else {
                    continue;
                };
                let (Some(k), Ok(e)) = (parse(k), e.parse::<i64>()) else {
                    continue;
                };
                if e > now_ms {
                    c.put(k, e);
                }
            }
        }
        // Compact on open.
        let tmp = p.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            for s in &c.shards {
                for (k, e) in &s.lock().seen {
                    writeln!(f, "{} {e}", hexs(k))?;
                }
            }
        }
        std::fs::rename(&tmp, p)?;
        c.log = Some(Mutex::new(OpenOptions::new().append(true).open(p)?));
        Ok(c)
    }

    fn put(&self, k: [u8; 16], exp: i64) {
        let mut s = self.shards[k[0] as usize % SHARDS].lock();
        s.seen.insert(k, exp);
        s.by_expiry
            .entry(exp.div_euclid(BUCKET_MS))
            .or_default()
            .push(k);
    }

    /// Record a nonce until `exp_ms`.
    pub fn check(&self, sender: &str, nonce: &str, exp_ms: i64, now_ms: i64) -> Seen {
        let k = key(sender, nonce);
        {
            let mut s = self.shards[k[0] as usize % SHARDS].lock();
            let nowb = now_ms.div_euclid(BUCKET_MS);
            while let Some((&b, _)) = s.by_expiry.first_key_value() {
                if b >= nowb {
                    break;
                }
                let (_, ks) = s.by_expiry.pop_first().expect("first");
                for x in ks {
                    if s.seen.get(&x).is_some_and(|e| *e < now_ms) {
                        s.seen.remove(&x);
                    }
                }
            }
            if s.seen.get(&k).is_some_and(|e| *e > now_ms) {
                return Seen::Replayed;
            }
            if s.seen.len() >= MAX_PER_SHARD {
                return Seen::Full;
            }
            s.seen.insert(k, exp_ms);
            s.by_expiry
                .entry(exp_ms.div_euclid(BUCKET_MS))
                .or_default()
                .push(k);
        }
        if let Some(l) = &self.log {
            let line = format!("{} {exp_ms}\n", hexs(&k));
            if l.lock().write_all(line.as_bytes()).is_err() {
                self.forget(sender, nonce);
                return Seen::Full;
            }
        }
        Seen::Fresh
    }

    /// Give a nonce back (the remit was shed before anything ran).
    pub fn forget(&self, sender: &str, nonce: &str) {
        let k = key(sender, nonce);
        self.shards[k[0] as usize % SHARDS].lock().seen.remove(&k);
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().seen.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn hexs(k: &[u8; 16]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut k = [0; 16];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_expiry_and_restart() {
        let p = std::env::temp_dir().join(format!("remit-nonces-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let t = 1_000_000_000;
        let c = ReplayCache::open(Some(&p), t).unwrap();
        assert_eq!(c.check("a", "n1", t + 300_000, t), Seen::Fresh);
        assert_eq!(c.check("a", "n1", t + 300_000, t + 1), Seen::Replayed);
        assert_eq!(c.check("b", "n1", t + 300_000, t), Seen::Fresh);
        // Restart: still a replay. (Ambiguous concatenations do not collide.)
        drop(c);
        let c = ReplayCache::open(Some(&p), t + 10).unwrap();
        assert_eq!(c.check("a", "n1", t + 300_000, t + 10), Seen::Replayed);
        assert_eq!(c.check("a|n", "1", t + 300_000, t), Seen::Fresh);
        // Given back, then expired entries are collected.
        c.forget("a", "n1");
        assert_eq!(c.check("a", "n1", t + 300_000, t + 10), Seen::Fresh);
        assert_eq!(
            c.check("z", "z", t + 10_000_000, t + 9_000_000),
            Seen::Fresh
        );
        assert_eq!(
            c.check("a", "n1", t + 10_000_000, t + 9_000_000),
            Seen::Fresh
        );
    }
}
