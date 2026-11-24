//! Remit wire format: manifest, JCS canonicalization, DSSE, identities.

#[cfg(feature = "crypto")]
pub mod dsse;
#[cfg(feature = "crypto")]
pub mod httpsig;
#[cfg(feature = "crypto")]
pub mod identity;
pub mod jcs;
#[cfg(feature = "crypto")]
pub mod jwt;
pub mod manifest;

#[cfg(feature = "crypto")]
pub use dsse::{Envelope, CATALOG_TYPE, MANIFEST_TYPE, RECEIPT_TYPE};
#[cfg(feature = "crypto")]
pub use identity::{did_key, public_key_from_did_key, PublicKey, Signer};
pub use manifest::{Code, Limits, Manifest, Mode, ParamType, ReadTemplate, REMIT_VERSION};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum WireError {
    #[error("decode: {0}")]
    Decode(String),
    #[error("{0} exceeds {1} bytes")]
    TooLarge(&'static str, usize),
    #[error("{0}: {1}")]
    Invalid(&'static str, String),
    #[error("authentication: {0}")]
    Auth(String),
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Sign a manifest: JCS-canonicalize and wrap in a DSSE envelope.
#[cfg(feature = "crypto")]
pub fn sign_manifest(m: &Manifest, signer: &Signer) -> Envelope {
    let body = jcs::canonical_bytes(&m.to_value()).expect("canonical manifest");
    Envelope::sign(MANIFEST_TYPE, &body, signer)
}

/// Verify an envelope and decode the manifest. The payload must be canonical
/// JCS (so every party hashes identical bytes) and the signing key must
/// belong to `manifest.sender`.
#[cfg(feature = "crypto")]
pub fn open_manifest<F>(env: &Envelope, resolve: F) -> Result<(Manifest, String), WireError>
where
    F: Fn(&str) -> Option<PublicKey>,
{
    let (body, keyid) = env.verify_with(MANIFEST_TYPE, &resolve)?;
    if body.len() > manifest::MANIFEST_MAX_BYTES + manifest::INLINE_CODE_MAX_BYTES {
        return Err(WireError::TooLarge(
            "manifest",
            manifest::MANIFEST_MAX_BYTES,
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| WireError::Decode(e.to_string()))?;
    let canon = jcs::canonical_bytes(&v).map_err(|e| WireError::Decode(e.to_string()))?;
    if canon != body {
        return Err(WireError::Decode(
            "manifest payload is not JCS-canonical".into(),
        ));
    }
    let m = Manifest::from_value(v)?;
    let sender_base = m.sender.split('#').next().unwrap_or("");
    let key_base = keyid.split('#').next().unwrap_or("");
    if key_base != sender_base
        && !(m.sender.starts_with("did:key:") && keyid.starts_with(&m.sender))
    {
        return Err(WireError::Auth(format!(
            "key `{keyid}` does not belong to sender `{}`",
            m.sender
        )));
    }
    Ok((m, keyid))
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;
    use serde_json::json;

    pub fn sample(signer: &Signer) -> Manifest {
        Manifest::from_value(json!({
            "remit": "0.1",
            "sender": signer.id(),
            "holder": "did:web:alice.vault.example",
            "issued_at": "2026-11-21T10:00:00Z",
            "expires_at": "2026-11-21T10:05:00Z",
            "nonce": "q3V0aaaaaaaa",
            "purpose": "scheduling",
            "mode": "query",
            "reads": {"r": {"sql": "SELECT 1", "max_rows": 1}},
            "params": {},
            "returns": "bool"
        }))
        .unwrap()
    }

    #[test]
    fn sign_open_roundtrip() {
        let s = Signer::generate(None);
        let m = sample(&s);
        let env = sign_manifest(&m, &s);
        let (m2, kid) = open_manifest(&env, public_key_from_did_key).unwrap();
        assert_eq!(m2, m);
        // The resolver is authoritative: refusing a did:key refuses the envelope.
        assert!(matches!(
            open_manifest(&env, |_| None),
            Err(WireError::Auth(_))
        ));
        assert_eq!(kid, s.key_id());
        // Tamper with the payload.
        let mut bad = env.clone();
        let mut body = bad.payload_bytes().unwrap();
        let i = body.len() - 3;
        body[i] ^= 1;
        bad.payload = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &body);
        assert!(open_manifest(&bad, public_key_from_did_key).is_err());
        // Wrong sender.
        let other = Signer::generate(None);
        let env2 = sign_manifest(&m, &other);
        assert!(matches!(
            open_manifest(&env2, public_key_from_did_key),
            Err(WireError::Auth(_))
        ));
    }

    #[test]
    fn did_web_with_registry() {
        let s = Signer::generate(Some("did:web:travel-agent.example".into()));
        assert!(s.key_id().starts_with("did:web:travel-agent.example#z"));
        let m = sample(&s);
        let env = sign_manifest(&m, &s);
        assert!(open_manifest(&env, |_| None).is_err());
        let pk = s.public_key();
        let (m2, _) = open_manifest(&env, |k| (k == s.key_id()).then_some(pk)).unwrap();
        assert_eq!(m2.sender, "did:web:travel-agent.example");
    }

    #[test]
    fn remit_id_excludes_binding_fields() {
        let s = Signer::generate(None);
        let a = sample(&s);
        let mut b = a.clone();
        b.nonce = "different-nonce".into();
        b.sender = "did:web:x".into();
        b.params = Some(json!({"x": 1}).as_object().unwrap().clone());
        assert_eq!(a.remit_id(), b.remit_id());
        assert_ne!(a.params_sha256(), b.params_sha256());
        b.returns = json!({"int": {"min": 0, "max": 1}});
        assert_ne!(a.remit_id(), b.remit_id());
    }

    #[test]
    fn did_key_roundtrip() {
        let s = Signer::generate(None);
        assert_eq!(public_key_from_did_key(&s.did_key()), Some(s.public_key()));
        assert!(s.did_key().starts_with("did:key:z6Mk"));
        let p = Signer::generate_p256(None);
        assert!(p.did_key().starts_with("did:key:zDn"));
        assert_eq!(public_key_from_did_key(&p.did_key()), Some(p.public_key()));
        let m = sample(&p);
        let (m2, _) = open_manifest(&sign_manifest(&m, &p), public_key_from_did_key).unwrap();
        assert_eq!(m2.sender, p.did_key());
        let back = Signer::from_file(&p.to_file()).unwrap();
        assert_eq!(back.public_key(), p.public_key());
    }
    #[test]
    #[cfg(unix)]
    fn identity_files_are_private_and_exclusive() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("remit-key-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let signer = Signer::generate(None);
        signer.save_new(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(Signer::generate(None).save_new(&path).is_err());
        assert_eq!(
            Signer::load(&path).unwrap().public_key(),
            signer.public_key()
        );
        std::fs::remove_file(path).unwrap();
    }
}
