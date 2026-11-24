//! Sender-side helpers: fill defaults, sign, submit, apply counter-offers,
//! offline lint with the Holder's own verifier code.

use std::path::Path;

use anyhow::anyhow;
use remit_wire::{Envelope, Manifest, Signer};
use serde_json::{json, Value};

/// Fill defaults (version, timestamps, nonce, sender, code hash) and sign.
pub fn sign(mut m: Value, s: &Signer, holder_id: Option<&str>) -> anyhow::Result<Envelope> {
    let o = m
        .as_object_mut()
        .ok_or_else(|| anyhow!("manifest must be a JSON object"))?;
    o.remove("remit_id");
    let now = chrono::Utc::now();
    o.entry("remit").or_insert(json!(remit_wire::REMIT_VERSION));
    o.insert("sender".into(), json!(s.id()));
    if let Some(h) = holder_id {
        o.insert("holder".into(), json!(h));
    }
    o.insert(
        "issued_at".into(),
        json!(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    );
    o.insert(
        "expires_at".into(),
        json!(
            (now + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
    );
    o.insert(
        "nonce".into(),
        json!(format!("{:032x}", rand::random::<u128>())),
    );
    o.entry("purpose").or_insert(json!("unspecified"));
    o.entry("limits").or_insert(json!({}));
    if let Some(code) = o.get_mut("code").and_then(Value::as_object_mut) {
        if let Some(src) = code.get("source").and_then(Value::as_str) {
            let h = remit_wire::sha256_hex(src.as_bytes());
            code.insert("source_sha256".into(), json!(h));
        }
        code.entry("lang").or_insert(json!("js/es2023"));
        code.entry("entry").or_insert(json!("main"));
    }
    let man = Manifest::from_value(m).map_err(|e| anyhow!("{e}"))?;
    Ok(remit_wire::sign_manifest(&man, s))
}

/// RFC 6902 subset: add / replace / remove.
pub fn apply_patch(doc: &mut Value, patch: &[Value]) -> anyhow::Result<()> {
    for op in patch {
        let path = op["path"]
            .as_str()
            .ok_or_else(|| anyhow!("patch op without path"))?;
        let parts: Vec<String> = path
            .split('/')
            .skip(1)
            .map(|p| p.replace("~1", "/").replace("~0", "~"))
            .collect();
        let (last, parents) = parts.split_last().ok_or_else(|| anyhow!("empty path"))?;
        let mut cur = &mut *doc;
        for p in parents {
            if !cur.get(p).is_some_and(|v| v.is_object()) {
                cur[p.as_str()] = json!({});
            }
            cur = cur.get_mut(p).unwrap();
        }
        match op["op"].as_str() {
            Some("add") | Some("replace") => {
                cur[last.as_str()] = op["value"].clone();
            }
            Some("remove") => {
                if let Some(o) = cur.as_object_mut() {
                    o.remove(last);
                }
            }
            other => return Err(anyhow!("unsupported patch op {other:?}")),
        }
    }
    Ok(())
}

async fn holder_catalog(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<(String, remit_wire::PublicKey)> {
    use base64::Engine as _;
    let response = client
        .get(format!("{}/.well-known/remit", url.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?;
    let header = response
        .headers()
        .get("remit-signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let catalog: Value = response.json().await?;
    let key = catalog["keys"][0]["did_key"]
        .as_str()
        .and_then(remit_wire::identity::public_key_from_did_key)
        .ok_or_else(|| anyhow!("catalog has no supported key"))?;
    let sig = header
        .split("sig=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or_else(|| anyhow!("catalog is unsigned"))?;
    let sig = base64::engine::general_purpose::STANDARD.decode(sig)?;
    let body = remit_wire::jcs::canonical_bytes(&catalog)?;
    anyhow::ensure!(
        key.verify(
            &remit_wire::dsse::pae(remit_wire::CATALOG_TYPE, &body),
            &sig
        ),
        "catalog signature does not verify"
    );
    let id = catalog["holder"]
        .as_str()
        .ok_or_else(|| anyhow!("catalog has no holder id"))?
        .to_string();
    Ok((id, key))
}

pub async fn submit(
    file: &Path,
    url: &str,
    identity: Option<&Path>,
    action: &str,
    accept: bool,
) -> anyhow::Result<Value> {
    let client = reqwest::Client::new();
    let (holder_id, holder_key) = holder_catalog(&client, url).await?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
    let (mut env, manifest, signer) = if v.get("payloadType").is_some() {
        (serde_json::from_value::<Envelope>(v)?, None, None)
    } else {
        let id = identity.ok_or_else(|| {
            anyhow!("--identity (or REMIT_IDENTITY) is required to sign a manifest")
        })?;
        let s = Signer::load(id).map_err(|e| anyhow!("{e}"))?;
        let mut m = v;
        let fields = m
            .as_object_mut()
            .ok_or_else(|| anyhow!("manifest must be a JSON object"))?;
        fields.entry("holder").or_insert_with(|| json!(holder_id));
        if action == "run" {
            fields.entry("params").or_insert_with(|| json!({}));
        }
        (sign(m.clone(), &s, None)?, Some(m), Some(s))
    };
    let endpoint = format!("{}/remit/v1/{action}", url.trim_end_matches('/'));
    let mut resp: Value = client
        .post(&endpoint)
        .header("content-type", "application/vnd.remit.envelope+json")
        .json(&env)
        .send()
        .await?
        .json()
        .await?;
    if accept && resp["decision"] == json!("counter_offer") {
        if let (Some(mut m), Some(s)) = (manifest, signer) {
            let patch = resp["counter_offer"]["json_patch"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            eprintln!("accepting counter-offer: {}", Value::Array(patch.clone()));
            apply_patch(&mut m, &patch)?;
            env = sign(m, &s, None)?;
            resp = client
                .post(&endpoint)
                .json(&env)
                .send()
                .await?
                .json()
                .await?;
        }
    }
    if action == "run" && resp["status"] == "ok" {
        let receipt: remit_wire::Envelope = serde_json::from_value(resp["receipt"].clone())?;
        let receipt = remit_receipt::Receipt::verify(&receipt, &holder_key)?;
        let manifest = Manifest::from_value(serde_json::from_slice(&env.payload_bytes()?)?)?;
        anyhow::ensure!(
            receipt.status == "ok" && receipt.decision == "admitted",
            "receipt does not record a successful run"
        );
        anyhow::ensure!(
            receipt.remit_id == manifest.remit_id()
                && receipt.params_sha256 == manifest.params_sha256(),
            "receipt does not match the submitted remit"
        );
        anyhow::ensure!(
            receipt.holder == holder_id
                && receipt.holder == manifest.holder
                && receipt.sender == manifest.sender,
            "receipt names different parties"
        );
        let digest = format!(
            "sha256:{}",
            remit_wire::sha256_hex(&remit_wire::jcs::canonical_bytes(&resp["result"])?)
        );
        anyhow::ensure!(
            receipt.result_sha256.as_ref() == Some(&digest),
            "result does not match the signed receipt"
        );
        let returns = &manifest.returns;
        let schema = returns.as_object().is_some_and(|o| {
            o.contains_key("type") || o.contains_key("$schema") || o.contains_key("anyOf")
        });
        let template = if schema {
            remit_types::RtTemplate::from_json_schema(returns)
        } else {
            remit_types::RtTemplate::from_json(returns)
        }?;
        let rt = template.bind(&manifest.params.unwrap_or_default())?;
        let normalized = rt.validate(&resp["result"])?;
        anyhow::ensure!(
            remit_wire::jcs::canonical_bytes(&normalized)?
                == remit_wire::jcs::canonical_bytes(&resp["result"])?,
            "result is not normalized to its declared type"
        );
        resp["labels"] = json!(receipt.labels);
        resp["terms"] = json!(receipt.terms);
    }
    Ok(resp)
}

/// Offline lint: structure, SQL profile, RT capacity, JS early errors.
pub fn lint(m: &Value) -> Value {
    let mut diags = Vec::new();
    let mut out = json!({});
    // Structure (fill throwaway binding fields so a bare program lints).
    let mut full = m.clone();
    if let Some(o) = full.as_object_mut() {
        o.remove("remit_id");
    }
    for (k, v) in [
        ("remit", json!("0.1")),
        ("sender", json!("did:key:lint")),
        ("holder", json!("did:web:lint")),
        ("issued_at", json!("2026-01-01T00:00:00Z")),
        ("expires_at", json!("2026-01-01T00:05:00Z")),
        ("nonce", json!("lint-nonce-0000")),
        ("purpose", json!("lint")),
    ] {
        if full.get(k).is_none() {
            full[k] = v;
        }
    }
    if let Some(src) = full
        .pointer("/code/source")
        .and_then(Value::as_str)
        .map(String::from)
    {
        full["code"]["source_sha256"] = json!(remit_wire::sha256_hex(src.as_bytes()));
        if full.pointer("/code/lang").is_none() {
            full["code"]["lang"] = json!("js/es2023");
        }
    }
    match Manifest::from_value(full) {
        Ok(man) => {
            out["remit_id"] = json!(man.remit_id());
            for (name, r) in &man.reads {
                if let Err(e) = remit_sql::check(&r.sql, &remit_sql::Profile::default()) {
                    diags.push(json!({"code": e.code, "path": format!("/reads/{name}/sql"), "span": e.span, "message": e.message, "hint": e.hint}));
                }
            }
            match remit_analyze::parse_returns(&man.returns) {
                Ok(t) => {
                    if let Some(p) = &man.params {
                        match t.bind(p) {
                            Ok(rt) => {
                                let capacity = rt.capacity_bits_ceil();
                                out["type"] = json!(rt.to_string());
                                if capacity == u64::MAX {
                                    diags.push(json!({"code": "RMT-E0130", "path": "/returns", "message": "result capacity exceeds the supported range"}));
                                } else {
                                    out["capacity_bits"] = json!((rt.capacity_bits() * 100.0).round() / 100.0);
                                    out["result_bits"] = json!(capacity + remit_types::status_bits() as u64);
                                }
                            }
                            Err(e) => diags.push(json!({"code": e.code(), "path": format!("/returns{}", e.path()), "message": e.message()})),
                        }
                    }
                }
                Err(d) => diags.push(json!(d)),
            }
            if let Some(c) = &man.code {
                if let Some(src) = &c.source {
                    for d in remit_analyze::check_js(src, &c.entry) {
                        diags.push(json!(d));
                    }
                }
            }
        }
        Err(e) => diags.push(json!({"code": "RMT-E0003", "path": "/", "message": e.to_string()})),
    }
    out["ok"] = json!(diags.is_empty());
    out["diagnostics"] = json!(diags);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_program_metadata_is_omitted_from_the_manifest() {
        let program = json!({
            "remit_id": "sha256:build-metadata",
            "mode": "query",
            "reads": {"q": {"sql": "SELECT 1 AS n", "max_rows": 1}},
            "params": {},
            "returns": {"int": {"min": 0, "max": 2}}
        });
        let holder = "did:web:example.com";
        let env = sign(program.clone(), &Signer::generate(None), Some(holder)).unwrap();
        let body: Value = serde_json::from_slice(&env.payload_bytes().unwrap()).unwrap();
        assert!(body.get("remit_id").is_none());
        assert_eq!(body["holder"], holder);
        assert_eq!(lint(&program)["ok"], true);
    }

    #[test]
    fn lint_rejects_result_capacity_above_the_supported_range() {
        let mut returns = json!("bool");
        for _ in 0..3 {
            returns = json!({"list": {"max": 16777216, "of": returns}});
        }
        let report = lint(&json!({
            "mode": "query",
            "reads": {"q": {"sql": "SELECT true AS b", "max_rows": 1}},
            "params": {},
            "returns": returns
        }));
        assert_eq!(report["ok"], false);
        assert_eq!(report["diagnostics"][0]["code"], "RMT-E0130");
    }
}
