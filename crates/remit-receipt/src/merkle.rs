//! RFC 6962-style Merkle tree over receipt envelopes: signed tree heads
//! (STH) and inclusion proofs, so Senders can check that their receipt is in
//! the same log every other Sender sees (equivocation becomes detectable once
//! STHs are gossiped or witnessed).

use remit_wire::{jcs, Envelope, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STH_TYPE: &str = "application/vnd.remit.tree-head+json";

pub fn leaf_hash(env: &Envelope) -> [u8; 32] {
    let v = serde_json::to_value(env).expect("env");
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(jcs::canonical_bytes(&v).expect("canonical"));
    h.finalize().into()
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn split(n: usize) -> usize {
    // Largest power of two strictly less than n.
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle tree hash of `leaves` (RFC 6962 §2.1).
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path for leaf `m` (RFC 6962 §2.1.1).
pub fn inclusion_proof(leaves: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = split(n);
    if m < k {
        let mut p = inclusion_proof(&leaves[..k], m);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof(&leaves[k..], m - k);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Verify an audit path (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(
    leaf: &[u8; 32],
    index: u64,
    size: u64,
    proof: &[[u8; 32]],
    root_hash: &[u8; 32],
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == root_hash
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TreeHead {
    pub holder: String,
    pub size: u64,
    pub root: String,
    pub ts: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InclusionProof {
    pub index: u64,
    pub size: u64,
    pub leaf: String,
    pub path: Vec<String>,
}

pub fn sign_head(h: &TreeHead, s: &Signer) -> Envelope {
    Envelope::sign(
        STH_TYPE,
        &jcs::canonical_bytes(&serde_json::to_value(h).unwrap()).unwrap(),
        s,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_and_size() {
        let leaves: Vec<[u8; 32]> = (0..37u8).map(|i| Sha256::digest([i]).into()).collect();
        for n in 1..=leaves.len() {
            let r = root(&leaves[..n]);
            for m in 0..n {
                let p = inclusion_proof(&leaves[..n], m);
                assert!(
                    verify_inclusion(&leaves[m], m as u64, n as u64, &p, &r),
                    "n={n} m={m}"
                );
                if n > 1 {
                    assert!(!verify_inclusion(
                        &leaves[(m + 1) % n],
                        m as u64,
                        n as u64,
                        &p,
                        &r
                    ));
                }
            }
        }
    }
}
