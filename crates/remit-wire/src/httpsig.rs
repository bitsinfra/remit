//! HTTP Message Signatures (RFC 9421) with `Content-Digest` (RFC 9530):
//! the transport signature that binds an envelope to one HTTP request.
//! Also the wire half of Web Bot Auth (`Signature-Agent`, `tag`).

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::identity::{PublicKey, Signer};
use crate::WireError;

/// The parts of a request a signature can cover.
pub struct HttpRequest<'a> {
    pub method: &'a str,
    /// Lowercased `host[:port]`.
    pub authority: &'a str,
    pub path: &'a str,
    /// Without the leading `?`.
    pub query: Option<&'a str>,
    pub body: &'a [u8],
    /// Header lookup by lowercase name (multiple values joined with `", "`).
    pub header: &'a dyn Fn(&str) -> Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    pub keyid: String,
    pub key: PublicKey,
    pub tag: Option<String>,
    pub nonce: Option<String>,
    pub created: i64,
    pub covered: Vec<String>,
}

fn auth(m: impl Into<String>) -> WireError {
    WireError::Auth(m.into())
}

pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(crate::sha256(body)))
}

fn component(req: &HttpRequest, name: &str) -> Result<String, WireError> {
    Ok(match name {
        "@method" => req.method.to_ascii_uppercase(),
        "@authority" => req.authority.to_ascii_lowercase(),
        "@path" => {
            if req.path.is_empty() {
                "/".into()
            } else {
                req.path.to_string()
            }
        }
        "@query" => format!("?{}", req.query.unwrap_or("")),
        n if n.starts_with('@') => {
            return Err(auth(format!("unsupported signature component `{n}`")))
        }
        n => {
            let v =
                (req.header)(n).ok_or_else(|| auth(format!("signed header `{n}` is missing")))?;
            v.trim().to_string()
        }
    })
}

fn base(req: &HttpRequest, covered: &[String], params: &str) -> Result<String, WireError> {
    let mut s = String::new();
    for c in covered {
        s.push_str(&format!("\"{c}\": {}\n", component(req, c)?));
    }
    s.push_str(&format!("\"@signature-params\": {params}"));
    Ok(s)
}

/// Headers to add to a request signed by `signer`.
pub struct Signed {
    pub signature_input: String,
    pub signature: String,
    pub content_digest: String,
}

/// Sign a request. `headers` are extra covered header names (lowercase).
pub fn sign(
    req: &HttpRequest,
    signer: &Signer,
    created: i64,
    ttl_s: i64,
    nonce: &str,
    tag: &str,
    headers: &[&str],
) -> Result<Signed, WireError> {
    let digest = content_digest(req.body);
    let inner = |n: &str| {
        if n == "content-digest" {
            Some(digest.clone())
        } else {
            (req.header)(n)
        }
    };
    let req2 = HttpRequest {
        header: &inner,
        ..*req
    };
    let mut covered: Vec<String> = ["@method", "@authority", "@path", "content-digest"]
        .map(String::from)
        .to_vec();
    if req.query.is_some() {
        covered.push("@query".into());
    }
    covered.extend(headers.iter().map(|h| h.to_string()));
    let list = covered
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let params = format!(
        "({list});created={created};expires={};nonce=\"{nonce}\";alg=\"{}\";keyid=\"{}\";tag=\"{tag}\"",
        created + ttl_s,
        signer.public_key().httpsig_alg(),
        signer.key_id()
    );
    let sig = signer.sign(base(&req2, &covered, &params)?.as_bytes());
    Ok(Signed {
        signature_input: format!("sig1={params}"),
        signature: format!("sig1=:{}:", STANDARD.encode(sig)),
        content_digest: digest,
    })
}

struct Input {
    label: String,
    covered: Vec<String>,
    params: String,
    kv: Vec<(String, String)>,
}

/// Split a structured-field dictionary at top-level commas.
fn split_top(s: &str, sep: char) -> Vec<&str> {
    let (mut out, mut start, mut depth, mut quoted, mut esc) = (Vec::new(), 0, 0i32, false, false);
    for (i, c) in s.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' if quoted => esc = true,
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth -= 1,
            c if c == sep && !quoted && depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn parse_inputs(h: &str) -> Result<Vec<Input>, WireError> {
    let bad = || auth("malformed Signature-Input");
    if h.len() > 4096 {
        return Err(bad());
    }
    let mut out = Vec::new();
    for item in split_top(h, ',') {
        let (label, rest) = item.trim().split_once('=').ok_or_else(bad)?;
        let rest = rest.trim();
        let close = rest.find(')').ok_or_else(bad)?;
        let inner = rest
            .strip_prefix('(')
            .ok_or_else(bad)?
            .get(..close - 1)
            .ok_or_else(bad)?;
        let mut covered = Vec::new();
        for c in inner.split_ascii_whitespace() {
            // Component parameters (`;sf`, `;req`, …) are not in this profile.
            let n = c
                .strip_prefix('"')
                .and_then(|c| c.strip_suffix('"'))
                .ok_or_else(bad)?;
            if n.chars().any(|ch| ch.is_ascii_uppercase()) || covered.iter().any(|x| x == n) {
                return Err(bad());
            }
            covered.push(n.to_string());
        }
        let mut kv = Vec::new();
        for p in split_top(&rest[close + 1..], ';').into_iter().skip(1) {
            let (k, v) = p.trim().split_once('=').ok_or_else(bad)?;
            kv.push((k.to_string(), v.trim().trim_matches('"').to_string()));
        }
        out.push(Input {
            label: label.trim().to_string(),
            covered,
            params: rest.to_string(),
            kv,
        });
    }
    Ok(out)
}

/// Verify the request's signatures. Returns the first signature made by a key
/// `resolve` knows; `None` when the request carries no signature headers.
pub fn verify<F>(
    req: &HttpRequest,
    now: i64,
    max_age_s: i64,
    skew_s: i64,
    resolve: F,
) -> Result<Option<Verified>, WireError>
where
    F: Fn(&str) -> Option<PublicKey>,
{
    let (Some(input), Some(sigs)) = ((req.header)("signature-input"), (req.header)("signature"))
    else {
        return Ok(None);
    };
    let inputs = parse_inputs(&input)?;
    for i in &inputs {
        let get = |k: &str| i.kv.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let Some(keyid) = get("keyid") else { continue };
        let Some(key) = resolve(&keyid) else { continue };
        if get("alg").is_some_and(|a| a != key.httpsig_alg()) {
            return Err(auth("signature algorithm does not match the key"));
        }
        for need in ["@method", "@path"] {
            if !i.covered.iter().any(|c| c == need) {
                return Err(auth(format!("the signature must cover `{need}`")));
            }
        }
        if !i.covered.iter().any(|c| c == "@authority") {
            return Err(auth("the signature must cover `@authority`"));
        }
        if req.query.is_some() && !i.covered.iter().any(|c| c == "@query") {
            return Err(auth("the signature must cover `@query`"));
        }
        if !req.body.is_empty() {
            if !i.covered.iter().any(|c| c == "content-digest") {
                return Err(auth("the signature must cover `content-digest`"));
            }
            let d = (req.header)("content-digest").unwrap_or_default();
            if !split_top(&d, ',')
                .iter()
                .any(|x| x.trim() == content_digest(req.body))
            {
                return Err(auth("content-digest does not match the body"));
            }
        }
        let created: i64 = get("created")
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| auth("signature has no `created`"))?;
        if created > now + skew_s || now - created > max_age_s + skew_s {
            return Err(auth("signature is outside its validity window"));
        }
        if get("expires")
            .and_then(|e| e.parse::<i64>().ok())
            .is_some_and(|e| e + skew_s < now)
        {
            return Err(auth("signature has expired"));
        }
        let prefix = format!("{}=:", i.label);
        let sig = split_top(&sigs, ',')
            .into_iter()
            .find_map(|s| {
                s.trim()
                    .strip_prefix(&prefix)
                    .and_then(|s| s.strip_suffix(':'))
            })
            .and_then(|s| STANDARD.decode(s).ok())
            .ok_or_else(|| auth("no matching Signature"))?;
        if !key.verify(base(req, &i.covered, &i.params)?.as_bytes(), &sig) {
            return Err(auth("bad HTTP message signature"));
        }
        return Ok(Some(Verified {
            keyid,
            key,
            tag: get("tag"),
            nonce: get("nonce"),
            created,
            covered: i.covered.clone(),
        }));
    }
    Err(auth("no HTTP message signature from a known key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn req<'a>(body: &'a [u8], h: &'a dyn Fn(&str) -> Option<String>) -> HttpRequest<'a> {
        HttpRequest {
            method: "POST",
            authority: "alice.example",
            path: "/remit/v1/run",
            query: None,
            body,
            header: h,
        }
    }

    fn roundtrip(s: &Signer) {
        let none = |_: &str| None;
        let out = sign(&req(b"{}", &none), s, 1000, 60, "n-1", "remit", &[]).unwrap();
        let hs: BTreeMap<&str, String> = [
            ("signature-input", out.signature_input.clone()),
            ("signature", out.signature.clone()),
            ("content-digest", out.content_digest.clone()),
        ]
        .into_iter()
        .collect();
        let h = |n: &str| hs.get(n).cloned();
        let key = s.public_key();
        let v = verify(&req(b"{}", &h), 1010, 300, 30, |_| Some(key))
            .unwrap()
            .unwrap();
        assert_eq!(
            (v.keyid.as_str(), v.tag.as_deref(), v.nonce.as_deref()),
            (s.key_id(), Some("remit"), Some("n-1"))
        );
        // Body, path, method, key, age.
        assert!(verify(&req(b"{ }", &h), 1010, 300, 30, |_| Some(key)).is_err());
        let moved = HttpRequest {
            path: "/remit/v1/check",
            ..req(b"{}", &h)
        };
        assert!(verify(&moved, 1010, 300, 30, |_| Some(key)).is_err());
        let other_host = HttpRequest {
            authority: "mallory.example",
            ..req(b"{}", &h)
        };
        assert!(verify(&other_host, 1010, 300, 30, |_| Some(key)).is_err());
        assert!(verify(&req(b"{}", &h), 1010, 300, 30, |_| Some(
            Signer::generate(None).public_key()
        ))
        .is_err());
        assert!(verify(&req(b"{}", &h), 5000, 300, 30, |_| Some(key)).is_err());
        assert!(verify(&req(b"{}", &h), 1010, 300, 30, |_| None).is_err());
        assert!(verify(&req(b"{}", &none), 1010, 300, 30, |_| Some(key))
            .unwrap()
            .is_none());
    }

    #[test]
    fn sign_and_verify() {
        roundtrip(&Signer::generate(None));
        roundtrip(&Signer::generate_p256(Some("did:web:hsm.example".into())));
    }

    /// RFC 9421 Appendix B.2.6: ed25519 over the test request.
    #[test]
    fn rfc9421_b26_vector() {
        let pk: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
            .unwrap()
            .try_into()
            .unwrap();
        let hs: BTreeMap<&str, &str> = [
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            ("content-length", "18"),
        ]
        .into_iter()
        .collect();
        let h = |n: &str| hs.get(n).map(|s| s.to_string());
        let r = HttpRequest {
            method: "POST",
            authority: "example.com",
            path: "/foo",
            query: Some("param=Value&Pet=dog"),
            body: b"",
            header: &h,
        };
        let covered: Vec<String> = [
            "date",
            "@method",
            "@path",
            "@authority",
            "content-type",
            "content-length",
        ]
        .map(String::from)
        .to_vec();
        let params = "(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
        let sig = STANDARD.decode("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==").unwrap();
        assert!(PublicKey::Ed25519(pk).verify(base(&r, &covered, params).unwrap().as_bytes(), &sig));
    }

    #[test]
    fn malformed_inputs_never_panic() {
        for s in [
            "",
            "=",
            "sig1=",
            "sig1=(",
            "sig1=)",
            "sig1=()",
            "sig1=(\"a",
            "sig1=(\"@method\");created",
            "a=(\"A\")",
            ")(",
            "sig1=\"(\";)",
        ] {
            let h = |n: &str| match n {
                "signature-input" => Some(s.to_string()),
                "signature" => Some("sig1=:AA==:".to_string()),
                _ => None,
            };
            let _ = verify(&req(b"x", &h), 0, 1, 1, |_| {
                Some(PublicKey::Ed25519([0; 32]))
            });
        }
    }
}
