//! Identities and signing keys. `did:key` (Ed25519 or P-256) is
//! self-certifying; `did:web`, Web Bot Auth and WIMSE ids are mapped to keys
//! by the verifier (registry, allowlisted resolution, or a verified token).
//!
//! Ed25519 is the default; P-256 (ES256) is allowed for HSM and KMS keys.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use p256::ecdsa as es;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::WireError;

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];

/// A verification key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    /// SEC1 compressed point.
    P256([u8; 33]),
}

impl From<[u8; 32]> for PublicKey {
    fn from(b: [u8; 32]) -> Self {
        PublicKey::Ed25519(b)
    }
}

impl PublicKey {
    /// JOSE / catalog algorithm name.
    pub fn alg(&self) -> &'static str {
        match self {
            PublicKey::Ed25519(_) => "Ed25519",
            PublicKey::P256(_) => "ES256",
        }
    }

    /// RFC 9421 signature algorithm name.
    pub fn httpsig_alg(&self) -> &'static str {
        match self {
            PublicKey::Ed25519(_) => "ed25519",
            PublicKey::P256(_) => "ecdsa-p256-sha256",
        }
    }

    pub fn did_key(&self) -> String {
        let mut b = Vec::with_capacity(35);
        match self {
            PublicKey::Ed25519(k) => {
                b.extend_from_slice(&ED25519_MULTICODEC);
                b.extend_from_slice(k);
            }
            PublicKey::P256(k) => {
                b.extend_from_slice(&P256_MULTICODEC);
                b.extend_from_slice(k);
            }
        }
        format!("did:key:z{}", bs58::encode(b).into_string())
    }

    /// `z…` multibase key (the fragment used in key ids and Multikey documents).
    pub fn multibase(&self) -> String {
        self.did_key()["did:key:".len()..].to_string()
    }

    pub fn from_multibase(z: &str) -> Option<PublicKey> {
        public_key_from_did_key(&format!("did:key:{z}"))
    }

    /// Public JWK (RFC 7517 / 8037).
    pub fn jwk(&self) -> Value {
        match self {
            PublicKey::Ed25519(k) => {
                json!({"kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(k)})
            }
            PublicKey::P256(k) => {
                let p = es::VerifyingKey::from_sec1_bytes(k)
                    .expect("validated point")
                    .to_sec1_point(false);
                json!({"kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(p.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(p.y().unwrap())})
            }
        }
    }

    pub fn from_jwk(j: &Value) -> Option<PublicKey> {
        let f = |k: &str| j.get(k).and_then(Value::as_str);
        let b = |k: &str| f(k).and_then(|s| URL_SAFE_NO_PAD.decode(s).ok());
        match (f("kty")?, f("crv")?) {
            ("OKP", "Ed25519") => Some(PublicKey::Ed25519(b("x")?.try_into().ok()?)),
            ("EC", "P-256") => {
                let (x, y) = (b("x")?, b("y")?);
                if x.len() != 32 || y.len() != 32 {
                    return None;
                }
                let mut pt = vec![4u8];
                pt.extend(x);
                pt.extend(y);
                let vk = es::VerifyingKey::from_sec1_bytes(&pt).ok()?;
                Some(PublicKey::P256(
                    vk.to_sec1_point(true).as_bytes().try_into().ok()?,
                ))
            }
            _ => None,
        }
    }

    /// RFC 7638 JWK thumbprint (Web Bot Auth key ids).
    pub fn thumbprint(&self) -> String {
        let j = self.jwk();
        let members: &[&str] = match self {
            PublicKey::Ed25519(_) => &["crv", "kty", "x"],
            PublicKey::P256(_) => &["crv", "kty", "x", "y"],
        };
        let body: Vec<String> = members
            .iter()
            .map(|m| format!("\"{m}\":{}", j[*m]))
            .collect();
        URL_SAFE_NO_PAD.encode(crate::sha256(format!("{{{}}}", body.join(",")).as_bytes()))
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Ed25519(k) => {
                let Ok(vk) = VerifyingKey::from_bytes(k) else {
                    return false;
                };
                let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else {
                    return false;
                };
                vk.verify(msg, &sig).is_ok()
            }
            PublicKey::P256(k) => {
                use es::signature::Verifier as _;
                let Ok(vk) = es::VerifyingKey::from_sec1_bytes(k) else {
                    return false;
                };
                let Ok(sig) = es::Signature::from_slice(sig) else {
                    return false;
                };
                vk.verify(msg, &sig).is_ok()
            }
        }
    }
}

/// `did:key:z…` for an Ed25519 public key.
pub fn did_key(pk: &[u8; 32]) -> String {
    PublicKey::Ed25519(*pk).did_key()
}

/// Extract the key from a `did:key` (optionally with `#fragment`).
pub fn public_key_from_did_key(id: &str) -> Option<PublicKey> {
    let id = id.split('#').next()?;
    let z = id.strip_prefix("did:key:z")?;
    let b = bs58::decode(z).into_vec().ok()?;
    if b.len() == 34 && b[..2] == ED25519_MULTICODEC {
        return Some(PublicKey::Ed25519(b[2..].try_into().ok()?));
    }
    if b.len() == 35 && b[..2] == P256_MULTICODEC {
        // Reject points that are not on the curve.
        es::VerifyingKey::from_sec1_bytes(&b[2..]).ok()?;
        return Some(PublicKey::P256(b[2..].try_into().ok()?));
    }
    None
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &[u8]) -> bool {
    pk.verify(msg, sig)
}

#[derive(Clone)]
enum SecretKey {
    Ed25519(SigningKey),
    P256(es::SigningKey),
}

/// A signing identity: an id (DID, SPIFFE id, …) plus a key.
#[derive(Clone)]
pub struct Signer {
    id: String,
    key_id: String,
    key: SecretKey,
}

/// On-disk identity format (`remit keygen`).
#[derive(Serialize, Deserialize)]
pub struct IdentityFile {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// `Ed25519` (default) or `ES256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Base64 private seed/scalar (32 bytes).
    pub secret_key: String,
    pub public_key: String,
}

impl Signer {
    pub fn generate(id: Option<String>) -> Signer {
        Self::from_key(
            SecretKey::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng)),
            id,
        )
    }

    /// A P-256 (ES256) identity.
    pub fn generate_p256(id: Option<String>) -> Signer {
        let key = loop {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            if let Ok(key) = es::SigningKey::from_slice(&bytes) {
                break key;
            }
        };
        Self::from_key(SecretKey::P256(key), id)
    }

    pub fn from_seed(seed: [u8; 32], id: Option<String>) -> Signer {
        Self::from_key(SecretKey::Ed25519(SigningKey::from_bytes(&seed)), id)
    }

    fn from_key(key: SecretKey, id: Option<String>) -> Signer {
        let pk = public(&key);
        let dk = pk.did_key();
        let id = id.unwrap_or_else(|| dk.clone());
        let key_id = if id.starts_with("did:key:") {
            id.clone()
        } else {
            format!("{id}#{}", pk.multibase())
        };
        Signer { id, key_id, key }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn did_key(&self) -> String {
        self.public_key().did_key()
    }
    pub fn public_key(&self) -> PublicKey {
        public(&self.key)
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match &self.key {
            SecretKey::Ed25519(k) => k.sign(msg).to_bytes().to_vec(),
            SecretKey::P256(k) => {
                use es::signature::Signer as _;
                let s: es::Signature = k.sign(msg);
                s.to_bytes().to_vec()
            }
        }
    }

    pub fn save_new(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec_pretty(&self.to_file())?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()
    }

    pub fn to_file(&self) -> IdentityFile {
        let (alg, secret) = match &self.key {
            SecretKey::Ed25519(k) => (None, k.to_bytes().to_vec()),
            SecretKey::P256(k) => (Some("ES256".to_string()), k.to_bytes().to_vec()),
        };
        IdentityFile {
            id: self.id.clone(),
            key_id: Some(self.key_id.clone()),
            alg,
            secret_key: STANDARD.encode(secret),
            public_key: self.did_key(),
        }
    }

    pub fn from_file(f: &IdentityFile) -> Result<Signer, WireError> {
        let seed: [u8; 32] = STANDARD
            .decode(&f.secret_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                WireError::Decode("identity secret_key must be 32 base64 bytes".into())
            })?;
        let key = match f.alg.as_deref() {
            None | Some("Ed25519") => SecretKey::Ed25519(SigningKey::from_bytes(&seed)),
            Some("ES256") => SecretKey::P256(
                es::SigningKey::from_slice(&seed)
                    .map_err(|_| WireError::Decode("invalid P-256 scalar".into()))?,
            ),
            Some(other) => {
                return Err(WireError::Decode(format!(
                    "unknown key algorithm `{other}` (Ed25519 | ES256)"
                )))
            }
        };
        let mut s = Signer::from_key(key, Some(f.id.clone()));
        if let Some(k) = &f.key_id {
            s.key_id = k.clone();
        }
        Ok(s)
    }

    pub fn from_json(s: &str) -> Result<Signer, WireError> {
        let f: IdentityFile =
            serde_json::from_str(s).map_err(|e| WireError::Decode(e.to_string()))?;
        Signer::from_file(&f)
    }

    pub fn load(path: &std::path::Path) -> Result<Signer, WireError> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| WireError::Decode(format!("{}: {e}", path.display())))?;
        Self::from_json(&s)
    }
}

fn public(k: &SecretKey) -> PublicKey {
    match k {
        SecretKey::Ed25519(k) => PublicKey::Ed25519(k.verifying_key().to_bytes()),
        SecretKey::P256(k) => PublicKey::P256(
            k.verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .expect("compressed point"),
        ),
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("id", &self.id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}
