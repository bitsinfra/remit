//! DSSE envelopes (Dead Simple Signing Envelope) with Ed25519 or P-256.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::identity::{PublicKey, Signer};
use crate::WireError;

pub const MANIFEST_TYPE: &str = "application/vnd.remit.manifest+json";
pub const RECEIPT_TYPE: &str = "application/vnd.remit.receipt+json";
pub const CATALOG_TYPE: &str = "application/vnd.remit.catalog+json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub payload_type: String,
    /// Base64 (standard) payload bytes.
    pub payload: String,
    pub signatures: Vec<Signature>,
}

/// DSSE pre-authentication encoding.
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(body);
    out
}

impl Envelope {
    pub fn sign(payload_type: &str, body: &[u8], signer: &Signer) -> Envelope {
        let sig = signer.sign(&pae(payload_type, body));
        Envelope {
            payload_type: payload_type.to_string(),
            payload: STANDARD.encode(body),
            signatures: vec![Signature {
                keyid: signer.key_id().to_string(),
                sig: STANDARD.encode(sig),
            }],
        }
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>, WireError> {
        STANDARD
            .decode(&self.payload)
            .map_err(|_| WireError::Decode("envelope payload is not base64".into()))
    }

    /// Verify the first signature whose key the resolver knows. The resolver is
    /// authoritative: a key it refuses is never trusted (pass
    /// [`crate::public_key_from_did_key`] to accept self-certifying ids).
    /// Returns the payload bytes and the verified key id.
    pub fn verify_with<F>(
        &self,
        expected_type: &str,
        resolve: F,
    ) -> Result<(Vec<u8>, String), WireError>
    where
        F: Fn(&str) -> Option<PublicKey>,
    {
        if self.payload_type != expected_type {
            return Err(WireError::Auth(format!(
                "payloadType must be `{expected_type}`"
            )));
        }
        let body = self.payload_bytes()?;
        let msg = pae(&self.payload_type, &body);
        for s in &self.signatures {
            let key = match resolve(&s.keyid) {
                Some(k) => k,
                None => continue,
            };
            let sig = STANDARD
                .decode(&s.sig)
                .map_err(|_| WireError::Auth("signature is not base64".into()))?;
            if crate::identity::verify(&key, &msg, &sig) {
                return Ok((body, s.keyid.clone()));
            }
            return Err(WireError::Auth(format!(
                "bad signature for key `{}`",
                s.keyid
            )));
        }
        Err(WireError::Auth("no signature from a known key".into()))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("envelope serializes")
    }
}
