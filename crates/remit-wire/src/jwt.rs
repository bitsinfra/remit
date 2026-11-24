//! Compact JWS verification (EdDSA, ES256) and the WIMSE profile:
//! Workload Identity Token (WIT) + Workload Proof Token (WPT), and OAuth
//! transaction tokens. Only asymmetric algorithms exist here, so there is no
//! `alg: none` and no key-confusion path.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

use crate::identity::{PublicKey, Signer};
use crate::WireError;

fn auth(m: impl Into<String>) -> WireError {
    WireError::Auth(m.into())
}

#[derive(Clone, Debug, PartialEq)]
pub struct Jwt {
    pub header: Value,
    pub claims: Value,
}

/// Sign a JWT (used by tests, `remit` tooling and the Sender helpers).
pub fn sign(typ: &str, claims: &Value, signer: &Signer) -> String {
    let alg = match signer.public_key() {
        PublicKey::Ed25519(_) => "EdDSA",
        PublicKey::P256(_) => "ES256",
    };
    let h = URL_SAFE_NO_PAD.encode(
        json!({"typ": typ, "alg": alg, "kid": signer.public_key().thumbprint()}).to_string(),
    );
    let c = URL_SAFE_NO_PAD.encode(claims.to_string());
    let sig = signer.sign(format!("{h}.{c}").as_bytes());
    format!("{h}.{c}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// Verify signature, `typ`, `alg` and `exp` / `nbf`. `keys` are candidates for
/// the token's `kid` (or all of the issuer's keys).
pub fn verify(
    token: &str,
    typ: &str,
    now: i64,
    skew: i64,
    keys: &[PublicKey],
) -> Result<Jwt, WireError> {
    if token.len() > 16 * 1024 {
        return Err(auth("token too large"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [h, c, s] = parts.as_slice() else {
        return Err(auth("not a compact JWS"));
    };
    let dec = |p: &str| {
        URL_SAFE_NO_PAD
            .decode(p)
            .map_err(|_| auth("token is not base64url"))
    };
    let header: Value =
        serde_json::from_slice(&dec(h)?).map_err(|_| auth("token header is not JSON"))?;
    let claims: Value =
        serde_json::from_slice(&dec(c)?).map_err(|_| auth("token claims are not JSON"))?;
    let t = header["typ"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches("application/")
        .to_ascii_lowercase();
    if t != typ {
        return Err(auth(format!("token typ must be `{typ}`")));
    }
    if header.get("crit").is_some() {
        return Err(auth("token uses critical extensions"));
    }
    let want = header["alg"].as_str().unwrap_or("");
    let sig = dec(s)?;
    let msg = format!("{h}.{c}");
    let ok = keys.iter().any(|k| {
        let alg = match k {
            PublicKey::Ed25519(_) => "EdDSA",
            PublicKey::P256(_) => "ES256",
        };
        alg == want && k.verify(msg.as_bytes(), &sig)
    });
    if !ok {
        return Err(auth("bad token signature"));
    }
    let exp = claims["exp"]
        .as_i64()
        .ok_or_else(|| auth("token has no exp"))?;
    if exp + skew < now {
        return Err(auth("token has expired"));
    }
    if claims["nbf"].as_i64().is_some_and(|n| n > now + skew) {
        return Err(auth("token is not valid yet"));
    }
    Ok(Jwt { header, claims })
}

/// The unverified issuer claim (to select the issuer's keys).
pub fn peek_issuer(token: &str) -> Option<String> {
    let c = token.split('.').nth(1)?;
    let v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(c).ok()?).ok()?;
    v["iss"].as_str().map(String::from)
}

/// A verified workload identity.
#[derive(Clone, Debug, PartialEq)]
pub struct Workload {
    /// `spiffe://…` / `wimse://…` subject.
    pub sub: String,
    pub iss: String,
    /// The key bound by `cnf.jwk` (must also sign the DSSE envelope).
    pub key: PublicKey,
}

/// Verify a WIT and its WPT (proof of possession bound to `aud` and the WIT).
pub fn verify_workload(
    wit: &str,
    wpt: Option<&str>,
    aud: &str,
    now: i64,
    skew: i64,
    issuer_keys: &dyn Fn(&str) -> Vec<PublicKey>,
) -> Result<Workload, WireError> {
    let iss = peek_issuer(wit).ok_or_else(|| auth("WIT has no iss"))?;
    let j = verify(wit, "wit+jwt", now, skew, &issuer_keys(&iss))?;
    let sub = j.claims["sub"]
        .as_str()
        .filter(|s| s.contains("://"))
        .ok_or_else(|| auth("WIT sub must be a workload URI"))?
        .to_string();
    let key = PublicKey::from_jwk(&j.claims["cnf"]["jwk"])
        .ok_or_else(|| auth("WIT has no usable cnf.jwk"))?;
    if let Some(p) = wpt {
        let pj = verify(p, "wpt+jwt", now, skew, &[key])?;
        if pj.claims["aud"].as_str() != Some(aud) {
            return Err(auth("WPT audience mismatch"));
        }
        if pj.claims["wth"].as_str()
            != Some(
                URL_SAFE_NO_PAD
                    .encode(crate::sha256(wit.as_bytes()))
                    .as_str(),
            )
        {
            return Err(auth("WPT is not bound to this WIT"));
        }
    }
    Ok(Workload { sub, iss, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wimse_wit_wpt() {
        let issuer = Signer::generate(Some("https://wimse.example".into()));
        for wl in [
            Signer::generate(Some("spiffe://example.com/agent".into())),
            Signer::generate_p256(Some("spiffe://example.com/agent".into())),
        ] {
            let wit = sign(
                "wit+jwt",
                &json!({"iss": "https://wimse.example", "sub": "spiffe://example.com/agent", "exp": 2000, "cnf": {"jwk": wl.public_key().jwk()}}),
                &issuer,
            );
            let wth = URL_SAFE_NO_PAD.encode(crate::sha256(wit.as_bytes()));
            let wpt = sign(
                "wpt+jwt",
                &json!({"aud": "https://alice.example/remit/v1/run", "exp": 1100, "jti": "x", "wth": wth}),
                &wl,
            );
            let keys = |i: &str| {
                if i == "https://wimse.example" {
                    vec![issuer.public_key()]
                } else {
                    vec![]
                }
            };
            let w = verify_workload(
                &wit,
                Some(&wpt),
                "https://alice.example/remit/v1/run",
                1000,
                30,
                &keys,
            )
            .unwrap();
            assert_eq!(
                (w.sub.as_str(), w.key),
                ("spiffe://example.com/agent", wl.public_key())
            );
            assert!(verify_workload(&wit, Some(&wpt), "https://other", 1000, 30, &keys).is_err());
            assert!(verify_workload(
                &wit,
                Some(&wpt),
                "https://alice.example/remit/v1/run",
                5000,
                30,
                &keys
            )
            .is_err());
            let mallory = Signer::generate(None);
            let stolen = sign(
                "wpt+jwt",
                &json!({"aud": "https://alice.example/remit/v1/run", "exp": 1100, "wth": wth}),
                &mallory,
            );
            assert!(verify_workload(
                &wit,
                Some(&stolen),
                "https://alice.example/remit/v1/run",
                1000,
                30,
                &keys
            )
            .is_err());
            let forged = sign(
                "wit+jwt",
                &json!({"iss": "https://wimse.example", "sub": "spiffe://example.com/agent", "exp": 2000, "cnf": {"jwk": mallory.public_key().jwk()}}),
                &mallory,
            );
            assert!(verify_workload(&forged, None, "x", 1000, 30, &keys).is_err());
        }
        // No `alg: none`, no wrong typ.
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"typ":"wit+jwt","alg":"none"}"#),
            URL_SAFE_NO_PAD
                .encode(r#"{"iss":"https://wimse.example","sub":"spiffe://x/y","exp":9999}"#)
        );
        assert!(verify(&none, "wit+jwt", 0, 0, &[issuer.public_key()]).is_err());
        assert!(verify("a.b", "jwt", 0, 0, &[]).is_err());
    }

    #[test]
    fn jwk_roundtrip_and_thumbprint() {
        for s in [Signer::generate(None), Signer::generate_p256(None)] {
            let k = s.public_key();
            assert_eq!(PublicKey::from_jwk(&k.jwk()), Some(k));
            assert_eq!(PublicKey::from_multibase(&k.multibase()), Some(k));
        }
        // RFC 8037 A.3 thumbprint.
        let k = PublicKey::from_jwk(&json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})).unwrap();
        assert_eq!(
            k.thumbprint(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }
}
