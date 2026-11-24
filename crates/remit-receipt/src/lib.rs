//! Receipts: every terminal state produces a DSSE-signed receipt, appended
//! to a hash-chained, append-only local log (each entry commits to the
//! previous one, so truncation or rewriting is detectable). [`merkle`] adds
//! RFC 6962 tree heads and inclusion proofs over the same entries.

pub mod attest;
pub mod merkle;

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use remit_wire::{jcs, sha256_hex, Envelope, Signer, RECEIPT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Terms {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retain_days: Option<u64>,
    pub forward: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Charged {
    pub bits: u64,
    pub epsilon: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Runtime {
    pub remit: String,
    pub wasmtime: String,
    /// Kernel engine used, `lang@sha256:…`.
    #[serde(skip_serializing_if = "Option::is_none", alias = "js_engine")]
    pub engine: Option<String>,
    pub isolation: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ExecutionContext {
    pub issued_at: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    pub run_id: String,
    pub remit_id: String,
    pub params_sha256: String,
    pub sender: String,
    pub holder: String,
    /// admitted | rejected | pending_approval | counter_offer
    pub decision: String,
    pub policy_sha256: String,
    pub catalog_sha256: String,
    pub data_versions: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_sha256: Option<String>,
    pub result_bits_max: u64,
    /// ok | limit_exceeded | type_violation | denied | internal
    pub status: String,
    pub labels: Vec<String>,
    pub terms: Terms,
    /// Bucketed usage (never exact counts).
    pub usage: BTreeMap<String, String>,
    pub charged: Charged,
    pub runtime: Runtime,
    #[serde(default)]
    pub cached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionContext>,
    pub attestation: Option<Value>,
    pub ts: String,
}

/// Labels and terms of a result: the *meet* of its inputs. Restriction
/// labels accumulate (union); retention is the minimum; forwarding is
/// allowed only if every input allows it.
pub fn meet<'a, I>(inputs: I) -> (Vec<String>, Terms)
where
    I: IntoIterator<Item = (&'a [String], Option<u64>, Option<bool>)>,
{
    let mut labels: Vec<String> = Vec::new();
    let mut retain: Option<u64> = None;
    let mut forward = true;
    for (ls, r, f) in inputs {
        for l in ls {
            if !labels.contains(l) {
                labels.push(l.clone());
            }
        }
        if let Some(r) = r {
            retain = Some(retain.map_or(r, |x| x.min(r)));
        }
        if f == Some(false) || ls.iter().any(|l| l == "no-forward") {
            forward = false;
        }
    }
    labels.sort();
    (
        labels,
        Terms {
            retain_days: retain,
            forward,
        },
    )
}

impl Receipt {
    pub fn sign(&self, signer: &Signer) -> Envelope {
        let body =
            jcs::canonical_bytes(&serde_json::to_value(self).expect("receipt")).expect("canonical");
        Envelope::sign(RECEIPT_TYPE, &body, signer)
    }

    /// Verify a receipt envelope against the Holder's key.
    pub fn verify(
        env: &Envelope,
        holder_key: &remit_wire::PublicKey,
    ) -> Result<Receipt, remit_wire::WireError> {
        let (body, _) = env.verify_with(RECEIPT_TYPE, |_| Some(*holder_key))?;
        serde_json::from_slice(&body).map_err(|e| remit_wire::WireError::Decode(e.to_string()))
    }
}

#[derive(Serialize, Deserialize)]
struct LogEntry {
    seq: u64,
    prev: String,
    hash: String,
    envelope: Envelope,
}

/// Hash-chained append-only receipt log (JSONL).
pub struct ReceiptLog {
    path: Option<PathBuf>,
    inner: Mutex<LogState>,
}

struct LogState {
    file: Option<File>,
    failed: bool,
    seq: u64,
    last: String,
    /// run_id → envelope (bounded in memory for `GET /receipts/{id}`).
    recent: BTreeMap<String, Envelope>,
    order: std::collections::VecDeque<String>,
    /// Merkle leaves (one per entry) and run_id → index.
    leaves: Vec<[u8; 32]>,
    index: BTreeMap<String, u64>,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn entry_hash(prev: &str, env: &Envelope) -> String {
    let v = serde_json::to_value(env).expect("env");
    let mut b = prev.as_bytes().to_vec();
    b.extend(jcs::canonical_bytes(&v).expect("canonical"));
    sha256_hex(&b)
}

impl ReceiptLog {
    pub fn open(path: Option<&Path>) -> std::io::Result<Self> {
        let mut seq = 0;
        let mut last = GENESIS.to_string();
        let mut recent = BTreeMap::new();
        let mut order = std::collections::VecDeque::new();
        let mut leaves = Vec::new();
        let mut index = BTreeMap::new();
        if let Some(p) = path {
            match File::open(p) {
                Ok(f) => {
                    for line in BufReader::new(f).lines() {
                        let e: LogEntry = serde_json::from_str(&line?)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        if e.seq != seq + 1
                            || e.prev != last
                            || entry_hash(&last, &e.envelope) != e.hash
                        {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid receipt chain",
                            ));
                        }
                        let body = e.envelope.payload_bytes().map_err(std::io::Error::other)?;
                        let r: Receipt = serde_json::from_slice(&body)?;
                        seq = e.seq;
                        last = e.hash.clone();
                        leaves.push(merkle::leaf_hash(&e.envelope));
                        index.insert(r.run_id.clone(), leaves.len() as u64 - 1);
                        order.push_back(r.run_id.clone());
                        recent.insert(r.run_id, e.envelope);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d)?;
            }
        }
        let file = match path {
            Some(p) => Some(OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        Ok(ReceiptLog {
            path: path.map(Path::to_path_buf),
            inner: Mutex::new(LogState {
                file,
                failed: false,
                seq,
                last,
                recent,
                order,
                leaves,
                index,
            }),
        })
    }

    pub fn append(&self, run_id: &str, env: &Envelope) -> std::io::Result<u64> {
        let mut st = self.inner.lock();
        if st.failed {
            return Err(std::io::Error::other("receipt log is unavailable"));
        }
        let hash = entry_hash(&st.last, env);
        let e = LogEntry {
            seq: st.seq + 1,
            prev: st.last.clone(),
            hash: hash.clone(),
            envelope: env.clone(),
        };
        let mut bytes = serde_json::to_vec(&e)?;
        bytes.push(b'\n');
        if let Some(f) = st.file.as_mut() {
            if let Err(error) = f.write_all(&bytes).and_then(|()| f.sync_data()) {
                st.failed = true;
                return Err(error);
            }
        }
        st.seq = e.seq;
        st.last = hash;
        let leaf = merkle::leaf_hash(env);
        st.leaves.push(leaf);
        let ix = st.leaves.len() as u64 - 1;
        st.index.insert(run_id.to_string(), ix);
        st.recent.insert(run_id.to_string(), env.clone());
        st.order.push_back(run_id.to_string());
        while st.order.len() > 100_000 {
            if let Some(old) = st.order.pop_front() {
                st.recent.remove(&old);
            }
        }
        Ok(st.seq)
    }

    pub fn get(&self, run_id: &str) -> Option<Envelope> {
        self.inner.lock().recent.get(run_id).cloned()
    }

    pub fn head(&self) -> (u64, String) {
        let st = self.inner.lock();
        (st.seq, st.last.clone())
    }

    /// Current signed-tree-head body (size, Merkle root).
    pub fn tree_head(&self, holder: &str) -> merkle::TreeHead {
        let st = self.inner.lock();
        merkle::TreeHead {
            holder: holder.to_string(),
            size: st.leaves.len() as u64,
            root: hex::encode(merkle::root(&st.leaves)),
            ts: String::new(),
        }
    }

    /// Inclusion proof for a run's receipt against the current tree.
    pub fn inclusion(&self, run_id: &str) -> Option<merkle::InclusionProof> {
        let st = self.inner.lock();
        let ix = *st.index.get(run_id)?;
        let path = merkle::inclusion_proof(&st.leaves, ix as usize)
            .iter()
            .map(hex::encode)
            .collect();
        Some(merkle::InclusionProof {
            index: ix,
            size: st.leaves.len() as u64,
            leaf: hex::encode(st.leaves[ix as usize]),
            path,
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ChainError {
    #[error("line {0}: malformed entry")]
    Malformed(usize),
    #[error("entry {0}: broken chain (prev does not match)")]
    Broken(u64),
    #[error("entry {0}: hash mismatch (entry was modified)")]
    Modified(u64),
    #[error("entry {0}: bad signature")]
    Signature(u64),
}

/// Verify a log file end to end: chain integrity and (optionally) signatures.
pub fn verify_log(
    path: &Path,
    holder_key: Option<&remit_wire::PublicKey>,
) -> Result<u64, ChainError> {
    let f = File::open(path).map_err(|_| ChainError::Malformed(0))?;
    let mut prev = GENESIS.to_string();
    let mut n = 0;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|_| ChainError::Malformed(i + 1))?;
        let e: LogEntry = serde_json::from_str(&line).map_err(|_| ChainError::Malformed(i + 1))?;
        if e.prev != prev {
            return Err(ChainError::Broken(e.seq));
        }
        if entry_hash(&prev, &e.envelope) != e.hash {
            return Err(ChainError::Modified(e.seq));
        }
        if let Some(k) = holder_key {
            Receipt::verify(&e.envelope, k).map_err(|_| ChainError::Signature(e.seq))?;
        }
        prev = e.hash;
        n = e.seq;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(id: &str) -> Receipt {
        Receipt {
            run_id: id.into(),
            remit_id: "sha256:ab".into(),
            status: "ok".into(),
            decision: "admitted".into(),
            ts: "2026-11-21T10:00:00Z".into(),
            ..Default::default()
        }
    }

    #[test]
    fn sign_verify_and_chain() {
        let s = Signer::generate(Some("did:web:alice.vault.example".into()));
        let dir = std::env::temp_dir().join(format!("remit-receipts-{}", std::process::id()));
        let p = dir.join("receipts.jsonl");
        let _ = std::fs::remove_file(&p);
        let log = ReceiptLog::open(Some(&p)).unwrap();
        for i in 0..5 {
            let r = receipt(&format!("run{i}"));
            let env = r.sign(&s);
            assert_eq!(Receipt::verify(&env, &s.public_key()).unwrap(), r);
            log.append(&r.run_id, &env).unwrap();
        }
        assert!(log.get("run3").is_some());
        assert_eq!(verify_log(&p, Some(&s.public_key())).unwrap(), 5);
        // Reopen continues the chain.
        drop(log);
        let log = ReceiptLog::open(Some(&p)).unwrap();
        log.append("run5", &receipt("run5").sign(&s)).unwrap();
        assert_eq!(verify_log(&p, Some(&s.public_key())).unwrap(), 6);
        // Tamper with an entry.
        let text = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        lines.remove(2);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(matches!(verify_log(&p, None), Err(ChainError::Broken(_))));
        // Wrong key.
        let other = Signer::generate(None);
        assert!(Receipt::verify(&receipt("x").sign(&s), &other.public_key()).is_err());
    }

    #[test]
    fn label_meet() {
        let a = vec!["personal".to_string()];
        let b = vec!["no-forward".to_string(), "personal".to_string()];
        let (l, t) = meet([
            (a.as_slice(), Some(30), None),
            (b.as_slice(), Some(7), Some(true)),
        ]);
        assert_eq!(l, vec!["no-forward", "personal"]);
        assert_eq!(
            t,
            Terms {
                retain_days: Some(7),
                forward: false
            }
        );
        let (_, t) = meet([(a.as_slice(), None, None)]);
        assert!(t.forward);
    }
    #[test]
    fn log_rejects_corruption_and_write_failure() {
        let path = std::env::temp_dir().join(format!("remit-log-errors-{}", std::process::id()));
        std::fs::write(&path, b"broken\n").unwrap();
        assert!(ReceiptLog::open(Some(&path)).is_err());
        std::fs::write(&path, b"").unwrap();
        let log = ReceiptLog::open(Some(&path)).unwrap();
        log.inner.lock().file = Some(File::open(&path).unwrap());
        let signer = Signer::generate(None);
        assert!(log.append("a", &receipt("a").sign(&signer)).is_err());
        assert_eq!(log.inner.lock().seq, 0);
        assert!(log.get("a").is_none());
        assert!(log.append("b", &receipt("b").sign(&signer)).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}
