//! Attested receipts (TEE mode): evidence that a *measured Remit runtime* signed
//! this receipt. The evidence is bound to the receipt (user data = hash of the
//! receipt body without its attestation) and to the remit (nonce).
//!
//! Verified here: **AWS Nitro Enclaves** attestation documents (COSE_Sign1 with
//! ES384, X.509 chain to a pinned root, PCR measurements). Evidence from other
//! TEEs (TDX, SEV-SNP) is carried opaquely with its format name; verifying it
//! needs that vendor's verifier, and this module refuses to call it verified.
//!
//! Attestation proves *which code ran*, not that the data is genuine.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ciborium::Value as C;
use p384::ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

use crate::Receipt;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AttestError {
    #[error("attestation is malformed: {0}")]
    Malformed(String),
    #[error("attestation does not verify: {0}")]
    Invalid(String),
    #[error("no verifier for evidence format `{0}`")]
    Unsupported(String),
    #[error("the receipt carries no attestation")]
    Missing,
}

fn mal(e: impl std::fmt::Display) -> AttestError {
    AttestError::Malformed(e.to_string())
}

fn inv(e: impl std::fmt::Display) -> AttestError {
    AttestError::Invalid(e.to_string())
}

/// Produces evidence for `(user_data, nonce)`; implemented by the Holder's TEE
/// adapter (NSM device, or an external command).
pub trait Attester: Send + Sync {
    fn format(&self) -> &str;
    fn attest(&self, user_data: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, String>;
}

/// Runs a command with the binding in its environment
/// (`REMIT_ATTEST_USER_DATA`, `REMIT_ATTEST_NONCE`, hex) and reads the raw
/// evidence from its stdout. Works with `nitro-cli`-style helpers, configfs-tsm
/// wrappers for TDX / SEV-SNP, or vTPM tooling.
pub struct CommandAttester {
    pub format: String,
    pub command: Vec<String>,
}

impl Attester for CommandAttester {
    fn format(&self) -> &str {
        &self.format
    }
    fn attest(&self, user_data: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, String> {
        let (prog, args) = self
            .command
            .split_first()
            .ok_or("empty attestation command")?;
        let out = std::process::Command::new(prog)
            .args(args)
            .env("REMIT_ATTEST_USER_DATA", hex::encode(user_data))
            .env("REMIT_ATTEST_NONCE", hex::encode(nonce))
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err(format!("attestation command failed ({})", out.status));
        }
        Ok(out.stdout)
    }
}

/// What the evidence must bind: the receipt body with `attestation: null`.
pub fn binding(r: &Receipt) -> [u8; 32] {
    let mut v = serde_json::to_value(r).expect("receipt");
    v["attestation"] = Value::Null;
    remit_wire::sha256(&remit_wire::jcs::canonical_bytes(&v).expect("canonical"))
}

fn nonce_of(r: &Receipt) -> Vec<u8> {
    remit_wire::sha256(format!("{}|{}", r.remit_id, r.run_id).as_bytes()).to_vec()
}

/// Attach evidence to a receipt (before it is signed).
pub fn attach(r: &mut Receipt, a: &dyn Attester) -> Result<(), String> {
    r.attestation = None;
    let doc = a.attest(&binding(r), &nonce_of(r))?;
    r.attestation = Some(json!({"format": a.format(), "evidence": STANDARD.encode(doc)}));
    Ok(())
}

/// What a Sender requires of a high-stakes answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Expectation {
    /// PEM or DER (base64) of the pinned root certificate.
    pub root: String,
    /// Required PCR values (index → hex). PCR0–2 measure the runtime image.
    pub pcrs: BTreeMap<u64, String>,
    /// Maximum age of the document.
    pub max_age_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Verified {
    pub module_id: String,
    pub timestamp_ms: i64,
    pub pcrs: BTreeMap<u64, String>,
}

/// Verify a receipt's attestation: signature, chain, freshness, measurements,
/// and that it is bound to this very receipt.
pub fn verify(r: &Receipt, want: &Expectation, now_ms: i64) -> Result<Verified, AttestError> {
    let a = r.attestation.as_ref().ok_or(AttestError::Missing)?;
    match a["format"].as_str() {
        Some("nitro") => {}
        other => return Err(AttestError::Unsupported(other.unwrap_or("").to_string())),
    }
    let doc = STANDARD
        .decode(a["evidence"].as_str().unwrap_or(""))
        .map_err(mal)?;
    let (v, user_data, nonce) = verify_nitro(&doc, &want.root, now_ms)?;
    if user_data.as_deref() != Some(&binding(r)[..]) {
        return Err(inv("evidence is bound to a different receipt"));
    }
    if nonce.as_deref() != Some(&nonce_of(r)[..]) {
        return Err(inv("evidence nonce mismatch"));
    }
    if now_ms - v.timestamp_ms > want.max_age_ms || v.timestamp_ms > now_ms + 60_000 {
        return Err(inv("evidence is stale"));
    }
    if want.pcrs.is_empty() {
        return Err(inv("no expected measurements were given"));
    }
    for (i, want) in &want.pcrs {
        if v.pcrs.get(i).map(|x| x.eq_ignore_ascii_case(want)) != Some(true) {
            return Err(inv(format!("PCR{i} does not match")));
        }
    }
    Ok(v)
}

fn parse_cert(s: &[u8]) -> Result<Certificate, AttestError> {
    Certificate::from_der(s).map_err(mal)
}

fn root_der(s: &str) -> Result<Vec<u8>, AttestError> {
    let body: String = if s.contains("BEGIN CERTIFICATE") {
        s.lines().filter(|l| !l.starts_with("-----")).collect()
    } else {
        s.split_whitespace().collect()
    };
    STANDARD.decode(body).map_err(mal)
}

fn p384_key(c: &Certificate) -> Result<p384::ecdsa::VerifyingKey, AttestError> {
    let spki = &c.tbs_certificate.subject_public_key_info;
    p384::ecdsa::VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|_| inv("certificate key is not P-384"))
}

fn check_issued(child: &Certificate, issuer: &Certificate, now_s: u64) -> Result<(), AttestError> {
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(inv("certificate chain is broken"));
    }
    let v = &child.tbs_certificate.validity;
    if now_s < v.not_before.to_unix_duration().as_secs()
        || now_s > v.not_after.to_unix_duration().as_secs()
    {
        return Err(inv("certificate is outside its validity period"));
    }
    let sig = p384::ecdsa::DerSignature::try_from(child.signature.raw_bytes())
        .map_err(|_| inv("certificate signature is not ES384"))?;
    p384_key(issuer)?
        .verify(&child.tbs_certificate.to_der().map_err(mal)?, &sig)
        .map_err(|_| inv("certificate signature"))
}

fn is_ca(c: &Certificate) -> bool {
    use x509_cert::ext::pkix::BasicConstraints;
    c.tbs_certificate
        .get::<BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, b)| b.ca)
}

type Nitro = (Verified, Option<Vec<u8>>, Option<Vec<u8>>);

fn verify_nitro(doc: &[u8], root: &str, now_ms: i64) -> Result<Nitro, AttestError> {
    if doc.len() > 64 * 1024 {
        return Err(mal("document too large"));
    }
    let v: C = ciborium::de::from_reader_with_recursion_limit(doc, 32).map_err(mal)?;
    let v = match v {
        C::Tag(18, x) => *x,
        x => x,
    };
    let C::Array(parts) = v else {
        return Err(mal("not COSE_Sign1"));
    };
    let [C::Bytes(protected), _, C::Bytes(payload), C::Bytes(sig)] = parts.as_slice() else {
        return Err(mal("not COSE_Sign1"));
    };
    let hdr: C = ciborium::from_reader(protected.as_slice()).map_err(mal)?;
    let alg = hdr
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| *k == C::Integer(1.into())))
        .map(|(_, v)| v.clone());
    if alg != Some(C::Integer((-35).into())) {
        return Err(inv("algorithm must be ES384"));
    }
    let body: C =
        ciborium::de::from_reader_with_recursion_limit(payload.as_slice(), 32).map_err(mal)?;
    let m = body.as_map().ok_or_else(|| mal("payload is not a map"))?;
    let get = |k: &str| {
        m.iter()
            .find(|(n, _)| n.as_text() == Some(k))
            .map(|(_, v)| v)
    };
    let bytes = |k: &str| get(k).and_then(C::as_bytes).cloned();
    let leaf = parse_cert(&bytes("certificate").ok_or_else(|| mal("no certificate"))?)?;
    let bundle: Vec<Certificate> = get("cabundle")
        .and_then(C::as_array)
        .ok_or_else(|| mal("no cabundle"))?
        .iter()
        .map(|c| {
            c.as_bytes()
                .ok_or_else(|| mal("cabundle"))
                .and_then(|b| parse_cert(b))
        })
        .collect::<Result<_, _>>()?;
    let root_der = root_der(root)?;
    // The bundle goes root → … → issuer of the leaf, and must start at our pin.
    let first = bundle.first().ok_or_else(|| mal("empty cabundle"))?;
    if first.to_der().map_err(mal)? != root_der {
        return Err(inv("chain does not start at the pinned root"));
    }
    if bundle.len() > 8 || !bundle.iter().all(is_ca) {
        return Err(inv("cabundle contains a non-CA certificate"));
    }
    let now_s = (now_ms / 1000).max(0) as u64;
    check_issued(first, first, now_s)?;
    for w in bundle.windows(2) {
        check_issued(&w[1], &w[0], now_s)?;
    }
    check_issued(&leaf, bundle.last().expect("non-empty"), now_s)?;
    let tbs = C::Array(vec![
        C::Text("Signature1".into()),
        C::Bytes(protected.clone()),
        C::Bytes(vec![]),
        C::Bytes(payload.clone()),
    ]);
    let mut msg = Vec::new();
    ciborium::into_writer(&tbs, &mut msg).map_err(mal)?;
    let sig = p384::ecdsa::Signature::from_slice(sig).map_err(|_| inv("signature encoding"))?;
    p384_key(&leaf)?
        .verify(&msg, &sig)
        .map_err(|_| inv("document signature"))?;
    let pcrs = get("pcrs")
        .and_then(C::as_map)
        .ok_or_else(|| mal("no pcrs"))?
        .iter()
        .filter_map(|(k, v)| {
            Some((
                u64::try_from(i128::from(k.as_integer()?)).ok()?,
                hex::encode(v.as_bytes()?),
            ))
        })
        .collect();
    let ts = get("timestamp")
        .and_then(C::as_integer)
        .and_then(|i| i64::try_from(i128::from(i)).ok())
        .ok_or_else(|| mal("no timestamp"))?;
    let module_id = get("module_id")
        .and_then(C::as_text)
        .unwrap_or("")
        .to_string();
    Ok((
        Verified {
            module_id,
            timestamp_ms: ts,
            pcrs,
        },
        bytes("user_data"),
        bytes("nonce"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::signature::Signer as _;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P384_SHA384,
    };

    struct Tee {
        root: Vec<u8>,
        bundle: Vec<Vec<u8>>,
        leaf: Vec<u8>,
        key: p384::ecdsa::SigningKey,
        ts: i64,
        pcr0: Vec<u8>,
    }

    fn params(cn: &str, ca: bool) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = if ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::NoCa
        };
        p
    }

    fn tee(now: i64, ca_intermediate: bool) -> Tee {
        let kp = || KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let (rk, ik, lk) = (kp(), kp(), kp());
        let rp = params("root", true);
        let root = rp.self_signed(&rk).unwrap();
        let ri = Issuer::from_params(&rp, &rk);
        let ip = params("intermediate", ca_intermediate);
        let inter = ip.signed_by(&ik, &ri).unwrap();
        let ii = Issuer::from_params(&ip, &ik);
        let leaf = params("enclave", false).signed_by(&lk, &ii).unwrap();
        use p384::pkcs8::DecodePrivateKey;
        Tee {
            root: root.der().to_vec(),
            bundle: vec![root.der().to_vec(), inter.der().to_vec()],
            leaf: leaf.der().to_vec(),
            key: p384::ecdsa::SigningKey::from_pkcs8_der(&lk.serialize_der()).unwrap(),
            ts: now,
            pcr0: vec![7; 48],
        }
    }

    impl Attester for Tee {
        fn format(&self) -> &str {
            "nitro"
        }
        fn attest(&self, user_data: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, String> {
            let t = |s: &str| C::Text(s.into());
            let payload = C::Map(vec![
                (t("module_id"), t("i-test")),
                (t("digest"), t("SHA384")),
                (t("timestamp"), C::Integer(self.ts.into())),
                (
                    t("pcrs"),
                    C::Map(vec![(C::Integer(0.into()), C::Bytes(self.pcr0.clone()))]),
                ),
                (t("certificate"), C::Bytes(self.leaf.clone())),
                (
                    t("cabundle"),
                    C::Array(self.bundle.iter().map(|b| C::Bytes(b.clone())).collect()),
                ),
                (t("user_data"), C::Bytes(user_data.to_vec())),
                (t("nonce"), C::Bytes(nonce.to_vec())),
            ]);
            let enc = |v: &C| {
                let mut b = Vec::new();
                ciborium::into_writer(v, &mut b).unwrap();
                b
            };
            let protected = enc(&C::Map(vec![(
                C::Integer(1.into()),
                C::Integer((-35).into()),
            )]));
            let payload = enc(&payload);
            let tbs = enc(&C::Array(vec![
                t("Signature1"),
                C::Bytes(protected.clone()),
                C::Bytes(vec![]),
                C::Bytes(payload.clone()),
            ]));
            let sig: p384::ecdsa::Signature = self.key.sign(&tbs);
            Ok(enc(&C::Array(vec![
                C::Bytes(protected),
                C::Map(vec![]),
                C::Bytes(payload),
                C::Bytes(sig.to_bytes().to_vec()),
            ])))
        }
    }

    fn receipt() -> Receipt {
        Receipt {
            run_id: "run_1".into(),
            remit_id: "sha256:ab".into(),
            status: "ok".into(),
            result_sha256: Some("sha256:cd".into()),
            ..Default::default()
        }
    }

    #[test]
    fn nitro_attested_receipts() {
        let now = chrono::Utc::now().timestamp_millis();
        let t = tee(now, true);
        let mut r = receipt();
        attach(&mut r, &t).unwrap();
        let want = Expectation {
            root: STANDARD.encode(&t.root),
            pcrs: [(0, hex::encode([7u8; 48]))].into(),
            max_age_ms: 300_000,
        };
        let v = verify(&r, &want, now).unwrap();
        assert_eq!(v.module_id, "i-test");
        // Bound to this receipt: changing the result, status or run breaks it.
        for f in [
            |r: &mut Receipt| r.result_sha256 = Some("sha256:ff".into()),
            |r: &mut Receipt| r.status = "denied".into(),
            |r: &mut Receipt| r.run_id = "run_2".into(),
        ] {
            let mut x = r.clone();
            f(&mut x);
            assert!(matches!(
                verify(&x, &want, now),
                Err(AttestError::Invalid(_))
            ));
        }
        // Wrong measurement, stale, no expectations, wrong root.
        assert!(verify(
            &r,
            &Expectation {
                pcrs: [(0, "00".into())].into(),
                ..want.clone()
            },
            now
        )
        .is_err());
        assert!(verify(
            &r,
            &Expectation {
                pcrs: Default::default(),
                ..want.clone()
            },
            now
        )
        .is_err());
        assert!(verify(&r, &want, now + 3_600_000).is_err());
        assert!(verify(
            &r,
            &Expectation {
                root: STANDARD.encode(tee(now, true).root),
                ..want.clone()
            },
            now
        )
        .is_err());
        // A non-CA intermediate cannot issue enclave certificates.
        let bad = tee(now, false);
        let mut x = receipt();
        attach(&mut x, &bad).unwrap();
        assert!(verify(
            &x,
            &Expectation {
                root: STANDARD.encode(&bad.root),
                ..want.clone()
            },
            now
        )
        .is_err());
        // Any flipped bit in the evidence is caught (or malformed), never a panic.
        let doc = STANDARD
            .decode(
                r.attestation.as_ref().unwrap()["evidence"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        for i in (0..doc.len()).step_by(17) {
            let mut d = doc.clone();
            d[i] ^= 1;
            let mut x = r.clone();
            x.attestation = Some(json!({"format": "nitro", "evidence": STANDARD.encode(d)}));
            assert!(verify(&x, &want, now).is_err(), "byte {i}");
        }
        // Other TEEs are carried, never called verified.
        let mut x = r.clone();
        x.attestation = Some(json!({"format": "sev-snp", "evidence": ""}));
        assert_eq!(
            verify(&x, &want, now),
            Err(AttestError::Unsupported("sev-snp".into()))
        );
        x.attestation = None;
        assert_eq!(verify(&x, &want, now), Err(AttestError::Missing));
    }

    #[test]
    fn command_adapter() {
        let a = CommandAttester {
            format: "test".into(),
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf %s \"$REMIT_ATTEST_USER_DATA\"".into(),
            ],
        };
        assert_eq!(
            a.attest(&[0xab; 32], b"n").unwrap(),
            "ab".repeat(32).into_bytes()
        );
        assert!(CommandAttester {
            format: "x".into(),
            command: vec!["/bin/false".into()]
        }
        .attest(&[0; 32], b"")
        .is_err());
    }
}
