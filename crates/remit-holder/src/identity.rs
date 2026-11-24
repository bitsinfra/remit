//! Sender identity: the principal registry, allowlisted `did:web` and Web Bot
//! Auth resolution, WIMSE workload tokens, and RFC 9421 transport signatures.
//!
//! The Holder only ever dereferences hosts **it** allowlisted (`[[identity.web]]`),
//! over HTTPS, without redirects, with size and time caps. Nothing a Sender
//! sends selects a URL outside that list.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, Method, Uri};
use parking_lot::Mutex;
use remit_wire::httpsig::{self, HttpRequest};
use remit_wire::jwt::{self, Workload};
use remit_wire::{public_key_from_did_key, PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::Holder;

/// Attributes granted to principals matched by an identity rule.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Grant {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub trust_domain: Option<String>,
}

/// A host whose `did:web` documents and Web Bot Auth directories are trusted
/// to name keys for identities under that host.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WebRule {
    /// `example.com` or `*.example.com` (any subdomain, not the apex).
    pub host: String,
    #[serde(flatten)]
    pub grant: Grant,
}

/// A WIMSE / SPIFFE issuer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WimseRule {
    pub issuer: String,
    /// Subjects must start with this URI (`spiffe://example.com/`).
    pub subject_prefix: String,
    /// Issuer keys as `did:key:z…`.
    pub keys: Vec<String>,
    #[serde(flatten)]
    pub grant: Grant,
}

/// An OAuth transaction-token / token-exchange issuer for delegated authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenRule {
    pub issuer: String,
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// Refuse requests without a valid RFC 9421 signature by the sender's key.
    #[serde(default)]
    pub require_transport_signature: bool,
    /// Public `host[:port]` senders sign as `@authority` (default: the Host header).
    #[serde(default)]
    pub authority: Option<String>,
    #[serde(default)]
    pub web: Vec<WebRule>,
    #[serde(default)]
    pub wimse: Vec<WimseRule>,
    #[serde(default)]
    pub transaction_tokens: Vec<TokenRule>,
    /// Resolve `did:web:localhost%3A…` over plain HTTP (tests and dev only).
    #[serde(default)]
    pub insecure_loopback: bool,
}

/// What the transport proved about the caller.
#[derive(Clone, Debug, Default)]
pub struct Transport {
    /// Key id and key of a verified RFC 9421 signature.
    pub signed_by: Option<(String, PublicKey)>,
    pub workload: Option<Workload>,
}

const CACHE_TTL: Duration = Duration::from_secs(600);
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const MAX_DOC: usize = 64 * 1024;

#[derive(Default)]
pub struct KeyCache {
    docs: Mutex<HashMap<String, (Instant, Vec<PublicKey>)>>,
}

impl KeyCache {
    fn get(&self, id: &str) -> Option<Vec<PublicKey>> {
        let m = self.docs.lock();
        let (t, k) = m.get(id)?;
        (t.elapsed()
            < if k.is_empty() {
                NEGATIVE_TTL
            } else {
                CACHE_TTL
            })
        .then(|| k.clone())
    }
    fn put(&self, id: &str, k: Vec<PublicKey>) {
        let mut m = self.docs.lock();
        if m.len() > 10_000 {
            m.clear();
        }
        m.insert(id.to_string(), (Instant::now(), k));
    }
}

fn host_matches(rule: &str, host: &str) -> bool {
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    match rule.strip_prefix("*.") {
        Some(sfx) => {
            host.len() > sfx.len() + 1 && host.ends_with(&format!(".{}", sfx.to_ascii_lowercase()))
        }
        None => host == rule.to_ascii_lowercase(),
    }
}

/// Host of a `did:web` or `https://` identity.
pub fn web_host(id: &str) -> Option<String> {
    let base = id.split('#').next()?;
    if let Some(r) = base.strip_prefix("did:web:") {
        return Some(r.split(':').next()?.replace("%3A", ":").replace("%3a", ":"));
    }
    base.strip_prefix("https://")
        .map(|r| r.split('/').next().unwrap_or(r).to_string())
}

/// Document URL for an identity (did:web document or Web Bot Auth directory).
fn doc_url(id: &str, insecure_loopback: bool) -> Option<String> {
    let host = web_host(id)?;
    if host.contains(['/', '@', '?', '#', '%', ' ']) {
        return None;
    }
    let local = host.starts_with("localhost:") || host.starts_with("127.0.0.1:");
    let scheme = if local && insecure_loopback {
        "http"
    } else {
        "https"
    };
    if let Some(r) = id.strip_prefix("did:web:") {
        let path: Vec<&str> = r.split('#').next()?.split(':').skip(1).collect();
        if path
            .iter()
            .any(|p| p.is_empty() || p.contains(['/', '.', '%', '?', '@']))
        {
            return None;
        }
        return Some(if path.is_empty() {
            format!("{scheme}://{host}/.well-known/did.json")
        } else {
            format!("{scheme}://{host}/{}/did.json", path.join("/"))
        });
    }
    Some(format!(
        "{scheme}://{host}/.well-known/http-message-signatures-directory"
    ))
}

fn keys_in(doc: &Value) -> Vec<PublicKey> {
    let mut out = Vec::new();
    for vm in doc["verificationMethod"].as_array().into_iter().flatten() {
        if let Some(k) = vm["publicKeyMultibase"]
            .as_str()
            .and_then(PublicKey::from_multibase)
        {
            out.push(k);
        } else if let Some(k) = PublicKey::from_jwk(&vm["publicKeyJwk"]) {
            out.push(k);
        }
    }
    out.extend(
        doc["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(PublicKey::from_jwk),
    );
    out
}

impl Holder {
    /// The identity rule covering a web identity.
    pub fn web_rule(&self, id: &str) -> Option<&WebRule> {
        let host = web_host(id)?;
        self.cfg
            .identity
            .web
            .iter()
            .find(|r| host_matches(&r.host, &host))
    }

    /// Fetch (or reuse) the keys of every allowlisted web identity among the
    /// key ids, so the synchronous resolver can use them.
    pub async fn prefetch_keys(&self, ids: &[String]) {
        for kid in ids.iter().take(4) {
            let base = kid.split('#').next().unwrap_or(kid);
            if self
                .principals
                .get(base)
                .is_some_and(|p| !p.keys.is_empty())
                || self.web_rule(base).is_none()
                || self.keys.get(base).is_some()
            {
                continue;
            }
            let keys = match doc_url(base, self.cfg.identity.insecure_loopback) {
                Some(u) => fetch_keys(&u).await.unwrap_or_default(),
                None => vec![],
            };
            self.keys.put(base, keys);
        }
    }

    /// Resolve a signing key id to its key. `None` refuses the signature.
    pub fn resolve_key(&self, keyid: &str, t: &Transport) -> Option<PublicKey> {
        let (base, frag) = keyid.split_once('#').unwrap_or((keyid, ""));
        // WIMSE: the workload token binds the subject to exactly one key.
        if let Some(w) = &t.workload {
            if w.sub == base && (frag.is_empty() || frag == w.key.multibase()) {
                return Some(w.key);
            }
        }
        if base.starts_with("did:key:") {
            let pk = public_key_from_did_key(base)?;
            return (self.principals.contains_key(base) || self.cfg.holder.allow_did_key)
                .then_some(pk);
        }
        let named = PublicKey::from_multibase(frag);
        if self.cfg.holder.dev && !self.principals.contains_key(base) {
            // `remit dev`: synthetic data, no registry — accept the key the id names.
            return named;
        }
        if let Some(p) = self.principals.get(base) {
            if let Some(k) = named {
                let dk = k.did_key();
                if p.keys.iter().any(|x| x == &dk) {
                    return Some(k);
                }
            }
            if !p.keys.is_empty() {
                return None;
            }
        }
        self.web_rule(base)?;
        let keys = self.keys.get(base)?;
        match named {
            Some(k) => keys.contains(&k).then_some(k),
            // Web Bot Auth: the fragment is an RFC 7638 thumbprint.
            None => keys.into_iter().find(|k| k.thumbprint() == frag),
        }
    }

    /// Verify transport-level identity (RFC 9421 and WIMSE headers).
    pub async fn transport(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Transport, String> {
        let mut t = Transport::default();
        let now = self.now_ms() / 1000;
        let skew = self.cfg.holder.clock_skew_s;
        let get = |n: &str| -> Option<String> {
            let v: Vec<&str> = headers
                .get_all(n)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::trim)
                .collect();
            (!v.is_empty()).then(|| v.join(", "))
        };
        let authority = self
            .cfg
            .identity
            .authority
            .clone()
            .or_else(|| get("host"))
            .or_else(|| uri.authority().map(|a| a.to_string()))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if let Some(wit) = get("workload-identity-token") {
            let aud = format!("https://{authority}{}", uri.path());
            let keys = |iss: &str| -> Vec<PublicKey> {
                self.cfg
                    .identity
                    .wimse
                    .iter()
                    .filter(|r| r.issuer == iss)
                    .flat_map(|r| &r.keys)
                    .filter_map(|k| public_key_from_did_key(k))
                    .collect()
            };
            let w = jwt::verify_workload(
                &wit,
                get("workload-proof-token").as_deref(),
                &aud,
                now,
                skew,
                &keys,
            )
            .map_err(|e| e.to_string())?;
            if !self
                .cfg
                .identity
                .wimse
                .iter()
                .any(|r| r.issuer == w.iss && w.sub.starts_with(&r.subject_prefix))
            {
                return Err("authentication: the issuer may not assert this workload".into());
            }
            t.workload = Some(w);
        }
        if let Some(input) = get("signature-input") {
            // Prefetch only the key ids the header names (allowlisted hosts).
            let ids: Vec<String> = input
                .split("keyid=\"")
                .skip(1)
                .filter_map(|s| s.split('"').next())
                .map(String::from)
                .collect();
            let agent = get("signature-agent")
                .map(|a| a.trim_matches('"').to_string())
                .filter(|a| a.starts_with("https://"));
            let mut wanted = ids.clone();
            wanted.extend(agent.clone());
            self.prefetch_keys(&wanted).await;
            let req = HttpRequest {
                method: method.as_str(),
                authority: &authority,
                path: uri.path(),
                query: uri.query(),
                body,
                header: &get,
            };
            let v = httpsig::verify(&req, now, 300, skew, |k| {
                self.resolve_key(k, &t).or_else(|| {
                    // Web Bot Auth: keyid is a thumbprint in the agent's directory.
                    let a = agent.as_deref()?;
                    self.web_rule(a)?;
                    self.keys.get(a)?.into_iter().find(|x| x.thumbprint() == k)
                })
            })
            .map_err(|e| e.to_string())?;
            t.signed_by = v.map(|v| (v.keyid, v.key));
        }
        if self.cfg.identity.require_transport_signature && t.signed_by.is_none() {
            return Err(
                "authentication: this Holder requires an RFC 9421 HTTP message signature".into(),
            );
        }
        Ok(t)
    }

    /// Attributes for a sender that has no registry entry.
    pub fn grant_for(&self, sender: &str, t: &Transport) -> Option<Grant> {
        if let Some(w) = t.workload.as_ref().filter(|w| w.sub == sender) {
            return self
                .cfg
                .identity
                .wimse
                .iter()
                .find(|r| r.issuer == w.iss && w.sub.starts_with(&r.subject_prefix))
                .map(|r| r.grant.clone());
        }
        self.web_rule(sender).map(|r| r.grant.clone())
    }
}

async fn fetch_keys(url: &str) -> Option<Vec<PublicKey>> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
    let mut r = client
        .get(url)
        .header("accept", "application/json")
        .send()
        .await
        .ok()?;
    if !r.status().is_success() || r.content_length().is_some_and(|n| n as usize > MAX_DOC) {
        return None;
    }
    let mut buf = Vec::new();
    while let Ok(Some(c)) = r.chunk().await {
        buf.extend_from_slice(&c);
        if buf.len() > MAX_DOC {
            return None;
        }
    }
    Some(keys_in(&serde_json::from_slice(&buf).ok()?))
}

/// Verify a transaction token presented as delegated authority. Returns the
/// issuer. The token can only narrow: audience, purpose, resources, bits.
pub fn verify_transaction_token(
    h: &Holder,
    token: &str,
    sender: &str,
    facts: &remit_analyze::Facts,
    now: i64,
) -> Result<String, String> {
    let iss = jwt::peek_issuer(token).ok_or("transaction token has no issuer")?;
    let keys: Vec<PublicKey> = h
        .cfg
        .identity
        .transaction_tokens
        .iter()
        .filter(|r| r.issuer == iss)
        .flat_map(|r| &r.keys)
        .filter_map(|k| public_key_from_did_key(k))
        .collect();
    let j = jwt::verify(token, "txntoken+jwt", now, h.cfg.holder.clock_skew_s, &keys)
        .map_err(|e| e.to_string())?;
    let c = &j.claims;
    if c["aud"].as_str() != Some(h.id()) {
        return Err("transaction token is for another audience".into());
    }
    // `req_wl` names the requesting workload; `sub` the delegating subject.
    if c["req_wl"].as_str() != Some(sender) {
        return Err("transaction token was issued to another workload".into());
    }
    if let Some(p) = c["purp"].as_str().or(c["scope"].as_str()) {
        if !p.split(' ').any(|x| x == facts.purpose) {
            return Err("purpose is outside the transaction token".into());
        }
    }
    if let Some(rs) = c["tctx"]["resources"].as_array() {
        if let Some(r) = facts
            .resources
            .keys()
            .find(|r| !rs.iter().any(|x| x.as_str() == Some(r)))
        {
            return Err(format!("`{r}` is outside the transaction token"));
        }
    }
    if c["tctx"]["max_bits"]
        .as_u64()
        .is_some_and(|b| facts.result_bits > b)
    {
        return Err("result bits exceed the transaction token".into());
    }
    Ok(iss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_urls() {
        assert!(host_matches("example.com", "example.com:8443"));
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "evilexample.com"));
        assert_eq!(
            doc_url("did:web:a.example", false).unwrap(),
            "https://a.example/.well-known/did.json"
        );
        assert_eq!(
            doc_url("did:web:a.example:agents:x", false).unwrap(),
            "https://a.example/agents/x/did.json"
        );
        assert_eq!(
            doc_url("https://bot.example/anything", false).unwrap(),
            "https://bot.example/.well-known/http-message-signatures-directory"
        );
        // No path traversal, userinfo, or scheme downgrade.
        for bad in [
            "did:web:a.example:..:x",
            "did:web:a.example:%2e%2e",
            "did:web:user@host",
            "http://a.example",
            "file:///etc/passwd",
            "did:web:a.example%2Fx",
        ] {
            assert!(
                doc_url(bad, false).is_none() || !doc_url(bad, false).unwrap().contains(".."),
                "{bad}"
            );
        }
        assert!(doc_url("http://a.example", false).is_none());
        assert!(doc_url("did:web:user@host", false).is_none());
        assert!(doc_url("did:web:localhost%3A8080", false)
            .unwrap()
            .starts_with("https://"));
        assert!(doc_url("did:web:localhost%3A8080", true)
            .unwrap()
            .starts_with("http://"));
    }
}
