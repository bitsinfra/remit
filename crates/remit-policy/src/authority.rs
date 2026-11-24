//! Delegated, attenuable authority as Biscuit tokens.
//!
//! A token is issued by a key the Holder trusts (its own root, or an issuer
//! listed in config) and may be attenuated by every holder of it (blocks can
//! only add checks). At admission the authorizer injects the analyzer's
//! facts and the token's checks must all pass:
//!
//! ```datalog
//! // authority block (issuer)
//! right("calendar.events", "read");
//! check if principal($p), $p == "did:web:travel-agent.example";
//! // attenuation block (delegatee)
//! check if purpose("scheduling");
//! check if result_bits($b), $b <= 128;
//! check if time($t), $t <= 2026-12-01T00:00:00Z;
//! ```

use biscuit_auth::{builder::Fact, AuthorizerBuilder, Biscuit, PrivateKey, PublicKey};
use remit_analyze::Facts;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AuthorityError {
    #[error("token: {0}")]
    Token(String),
    #[error("authority does not cover this remit: {0}")]
    Denied(String),
}

/// Verify every token in `authority` against `root` and the facts.
/// Each requested (resource, action) must be covered by a `right` fact.
/// Returns the issuers (`biscuit:<root key>`) of the verified tokens.
pub fn verify(
    tokens: &[String],
    roots: &[PublicKey],
    principal: &str,
    facts: &Facts,
    now_unix: i64,
) -> Result<Vec<String>, AuthorityError> {
    let mut issuers = Vec::new();
    for t in tokens {
        let b64 = t.strip_prefix("biscuit:").unwrap_or(t);
        let mut last_err = None;
        let mut ok = false;
        for root in roots {
            match Biscuit::from_base64(b64, *root) {
                Ok(token) => {
                    authorize(&token, principal, facts, now_unix)?;
                    issuers.push(format!("biscuit:{root}"));
                    ok = true;
                    break;
                }
                Err(e) => last_err = Some(e.to_string()),
            }
        }
        if !ok {
            return Err(AuthorityError::Token(
                last_err.unwrap_or_else(|| "no trusted root".into()),
            ));
        }
    }
    Ok(issuers)
}

fn authorize(
    token: &Biscuit,
    principal: &str,
    facts: &Facts,
    now_unix: i64,
) -> Result<(), AuthorityError> {
    let e = |x: biscuit_auth::error::Token| AuthorityError::Token(x.to_string());
    let mut b = AuthorizerBuilder::new();
    let fact = |s: String| -> Result<Fact, AuthorityError> {
        s.as_str()
            .try_into()
            .map_err(|x: biscuit_auth::error::Token| AuthorityError::Token(x.to_string()))
    };
    b = b
        .fact(fact(format!("principal({})", q(principal)))?)
        .map_err(e)?;
    b = b
        .fact(fact(format!("purpose({})", q(&facts.purpose)))?)
        .map_err(e)?;
    b = b
        .fact(fact(format!("mode({})", q(&facts.mode)))?)
        .map_err(e)?;
    b = b
        .fact(fact(format!("result_bits({})", facts.result_bits))?)
        .map_err(e)?;
    b = b
        .fact(fact(format!("fuel({})", facts.fuel.min(i64::MAX as u64)))?)
        .map_err(e)?;
    b = b
        .fact(fact(format!("epsilon_milli({})", facts.epsilon_milli))?)
        .map_err(e)?;
    b = b
        .fact(fact(format!("aggregate_only({})", facts.aggregate_only))?)
        .map_err(e)?;
    let ts = chrono::DateTime::from_timestamp(now_unix, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default();
    b = b.fact(fact(format!("time({ts})"))?).map_err(e)?;
    let mut code = String::new();
    for (res, rf) in &facts.resources {
        b = b.fact(fact(format!("resource({})", q(res)))?).map_err(e)?;
        for c in &rf.columns {
            b = b
                .fact(fact(format!("column({}, {})", q(res), q(c)))?)
                .map_err(e)?;
        }
        // Every requested (resource, action) must be covered by a right.
        // `aggregate` is covered by a `read` right (it reveals strictly less).
        for a in &rf.actions {
            let (r, aa) = (q(res), q(a));
            if a == "aggregate" {
                code.push_str(&format!(
                    "check if right({r}, {aa}) or right({r}, \"read\") or right(\"*\", {aa}) or right(\"*\", \"read\");\n"
                ));
            } else {
                code.push_str(&format!(
                    "check if right({r}, {aa}) or right(\"*\", {aa});\n"
                ));
            }
        }
    }
    code.push_str("allow if true;\n");
    b = b.code(code).map_err(e)?;
    let mut az = b.build(token).map_err(e)?;
    az.authorize()
        .map_err(|x| AuthorityError::Denied(x.to_string()))?;
    Ok(())
}

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Issue a token (used by `remit authority issue` and tests).
pub fn issue(root: &PrivateKey, datalog: &str) -> Result<String, AuthorityError> {
    let t = Biscuit::builder()
        .code(datalog)
        .map_err(|e| AuthorityError::Token(e.to_string()))?
        .build(root)
        .map_err(|e| AuthorityError::Token(e.to_string()))?;
    t.to_base64()
        .map(|s| format!("biscuit:{s}"))
        .map_err(|e| AuthorityError::Token(e.to_string()))
}

/// Attenuate a token with an extra block of checks.
pub fn attenuate(token: &str, root: PublicKey, datalog: &str) -> Result<String, AuthorityError> {
    let t = Biscuit::from_base64(token.strip_prefix("biscuit:").unwrap_or(token), root)
        .map_err(|e| AuthorityError::Token(e.to_string()))?;
    let blk = biscuit_auth::builder::BlockBuilder::new()
        .code(datalog)
        .map_err(|e| AuthorityError::Token(e.to_string()))?;
    let t2 = t
        .append(blk)
        .map_err(|e| AuthorityError::Token(e.to_string()))?;
    t2.to_base64()
        .map(|s| format!("biscuit:{s}"))
        .map_err(|e| AuthorityError::Token(e.to_string()))
}
