//! Native HTTP API (v1).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

use crate::admission::{admit, AdmitOptions, Outcome};
use crate::identity::Transport;
use crate::run::{admission_receipt, new_run_id, run_admitted, spawn_async, RunResponse};
use crate::state::Holder;

pub const ENVELOPE_CT: &str = "application/vnd.remit.envelope+json";

pub const ARROW_CT: &str = "application/vnd.apache.arrow.stream";
pub const MAX_BLOB: usize = remit_wire::manifest::INLINE_CODE_MAX_BYTES * 4;

pub fn router(h: Arc<Holder>) -> Router {
    Router::new()
        .route("/.well-known/remit", get(catalog))
        .route("/.well-known/agent-card.json", get(agent_card))
        .route("/remit/v1/check", post(check))
        .route("/remit/v1/run", post(run))
        .route("/remit/v1/runs/{id}", get(get_run))
        .route("/remit/v1/blobs/{sha}", put(put_blob))
        .route("/remit/v1/receipts/{id}", get(get_receipt))
        .route("/remit/v1/log/head", get(log_head))
        .route("/remit/v1/log/proof/{id}", get(log_proof))
        .route("/mcp", post(crate::mcp::handle))
        .route("/a2a", post(crate::a2a::handle))
        .route(
            "/remit.v1.RemitService/{method}",
            post(crate::connect::handle),
        )
        .route("/admin/approvals", get(list_approvals))
        .route("/admin/approvals/{ticket}/approve", post(approve))
        .route("/admin/approvals/{ticket}/deny", post(deny))
        .route("/admin/refresh", post(refresh))
        .route("/metrics", get(metrics))
        .route(
            "/playground",
            get(|| async { axum::response::Html(include_str!("playground.html")) }),
        )
        .route("/playground/fonts/{font}", get(playground_font))
        .route("/.well-known/did.json", get(did_document))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BLOB + 4096))
        .with_state(h)
}

async fn playground_font(Path(font): Path<String>) -> Response {
    let bytes: &'static [u8] = match font.as_str() {
        "petrona-latin.woff2" => include_bytes!("fonts/petrona-latin.woff2"),
        "geist.woff2" => include_bytes!("fonts/geist.woff2"),
        "geist-mono.woff2" => include_bytes!("fonts/geist-mono.woff2"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
        .into_response()
}

/// Sign the catalog: detached DSSE signature over JCS(doc).
fn catalog_signature(h: &Holder, doc: &Value) -> String {
    let body = remit_wire::jcs::canonical_bytes(doc).unwrap_or_default();
    let sig = h
        .signer
        .sign(&remit_wire::dsse::pae(remit_wire::CATALOG_TYPE, &body));
    format!(
        "keyid=\"{}\", sig=\"{}\"",
        h.signer.key_id(),
        STANDARD.encode(sig)
    )
}

/// Groups for a scoped catalog request (`Remit-Proof` header), else public.
fn scope_from_headers(h: &Holder, headers: &HeaderMap) -> Vec<String> {
    let Some(proof) = headers.get("remit-proof").and_then(|v| v.to_str().ok()) else {
        return vec![];
    };
    let Ok(bytes) = STANDARD.decode(proof) else {
        return vec![];
    };
    let Ok(env) = serde_json::from_slice::<remit_wire::Envelope>(&bytes) else {
        return vec![];
    };
    let Ok((body, keyid)) = env.verify_with("application/vnd.remit.catalog-request+json", |k| {
        h.resolve_key(k, &Transport::default())
    }) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return vec![];
    };
    let principal = v["principal"].as_str().unwrap_or("");
    let ts = v["ts"].as_i64().unwrap_or(0);
    if v["holder"] != json!(h.id())
        || (h.now_ms() - ts).abs() > 300_000
        || keyid.split('#').next() != Some(principal.split('#').next().unwrap_or(""))
    {
        return vec![];
    }
    h.principal(principal, &Transport::default()).0.groups
}

async fn catalog(State(h): State<Arc<Holder>>, headers: HeaderMap) -> Response {
    let groups = scope_from_headers(&h, &headers);
    let (doc, sha) = h.catalog(&groups);
    let etag = format!("\"{sha}\"");
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let sig = catalog_signature(&h, &doc);
    let mut r = Json(doc).into_response();
    r.headers_mut()
        .insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    r.headers_mut()
        .insert("remit-signature", HeaderValue::from_str(&sig).unwrap());
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=60"),
    );
    r
}

/// `did:web` document for the Holder (resolvable at https://<host>/.well-known/did.json).
async fn did_document(State(h): State<Arc<Holder>>) -> Json<Value> {
    let dk = h.signer.did_key();
    let frag = dk.trim_start_matches("did:key:").to_string();
    Json(json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": h.id(),
        "verificationMethod": [{"id": format!("{}#{frag}", h.id()), "type": "Multikey", "controller": h.id(), "publicKeyMultibase": frag}],
        "authentication": [format!("{}#{frag}", h.id())],
        "assertionMethod": [format!("{}#{frag}", h.id())],
        "service": [{"id": format!("{}#remit", h.id()), "type": "RemitHolder", "serviceEndpoint": "/.well-known/remit"}],
    }))
}

async fn agent_card(State(h): State<Arc<Holder>>) -> Json<Value> {
    Json(json!({
        "name": h.id(),
        "description": "Remit Holder: send signed programs, receive typed results.",
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": {
            "extensions": [{
                "uri": "https://github.com/bitsinfra/remit/blob/main/spec/protocol.md#a2a-v10-extension",
                "description": "Remit method extension (remit/check, remit/run) and DataPart profile for envelopes, results and receipts",
                "required": false,
                "params": {"catalog": "/.well-known/remit", "envelope_media_type": ENVELOPE_CT},
            }]
        },
        "url": "/a2a",
        "defaultInputModes": [ENVELOPE_CT],
        "defaultOutputModes": ["application/json"],
        "skills": [{"id": "remit", "name": "Run a remit", "description": "Admit and run a signed Remit program against this Holder's catalog", "tags": ["remit"]}],
    }))
}

/// Shared rendering of admission outcomes that did not run.
pub fn outcome_json(h: &Holder, o: &Outcome) -> (StatusCode, Value) {
    match o {
        Outcome::Admitted(a) => (
            StatusCode::OK,
            json!({
                "decision": "admitted",
                "remit_id": a.manifest.remit_id(),
                "facts": {
                    "result_bits": a.analysis.facts.result_bits,
                    "capacity_bits": (a.analysis.facts.capacity_bits * 100.0).round() / 100.0,
                    "aggregate_only": a.analysis.facts.aggregate_only,
                    "min_group_size": a.analysis.facts.min_group_size,
                    "resources": a.analysis.facts.resources,
                    "ops": a.analysis.facts.ops,
                },
                "cost": if h.cfg.holder.explain { a.analysis.facts.cost.clone() } else { Value::Null },
                "limits": a.analysis.limits,
                "permitted_by": a.decision.permitted_by,
                "warnings": a.analysis.warnings,
                "access_card": remit_analyze::access_card(&a.manifest, &a.analysis),
                "plan_cache": a.plan_cache_hit,
                "trace": if h.cfg.holder.explain { json!(a.trace) } else { Value::Null },
            }),
        ),
        Outcome::Rejected {
            diagnostics,
            denied,
            trace,
            remit_id,
        } => (
            if *denied {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            },
            json!({"decision": "rejected", "status": "denied", "remit_id": remit_id, "diagnostics": diagnostics,
                   "trace": if h.cfg.holder.explain { json!(trace) } else { Value::Null }}),
        ),
        Outcome::PendingApproval { ticket, card, .. } => (
            StatusCode::ACCEPTED,
            json!({"decision": "pending_approval", "ticket": ticket, "access_card": card,
                   "message": "a Holder approver must approve this remit; resubmit (or poll /remit/v1/runs) after approval"}),
        ),
        Outcome::CounterOffer {
            patch, diagnostics, ..
        } => (
            StatusCode::CONFLICT,
            json!({"decision": "counter_offer", "counter_offer": {"json_patch": patch}, "diagnostics": diagnostics,
                   "message": "apply the JSON Patch to the manifest, re-sign and resubmit"}),
        ),
        Outcome::Busy {
            retry_after_s,
            message,
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            json!({"decision": "busy", "retry_after_s": retry_after_s, "message": message}),
        ),
    }
}

fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"decision": "rejected", "status": "denied", "diagnostics": [remit_analyze::Diagnostic::new("RMT-E0012", "/", msg)]}))).into_response()
}

async fn check(
    State(h): State<Arc<Holder>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let transport = match h.transport(&method, &uri, &headers, &body).await {
        Ok(t) => t,
        Err(e) => return unauthorized(&e),
    };
    let o = admit(
        &h,
        &body,
        AdmitOptions {
            dry: true,
            accept_clamps: false,
            transport,
        },
    )
    .await;
    if matches!(o, Outcome::Rejected { .. }) {
        h.metrics
            .rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let (code, v) = outcome_json(&h, &o);
    // /check always answers 200: the decision is in the body.
    let _ = code;
    Json(v).into_response()
}

fn busy(retry_after_s: u64, v: Value) -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, Json(v)).into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_s));
    r
}

/// Sync result rendering: Arrow IPC for `table<…>` when asked for, else JSON.
fn render(h: &Holder, r: &RunResponse, arrow: Option<Vec<(String, String)>>) -> Response {
    if let (Some(cols), Some(Value::Array(rows)), true) = (arrow, &r.result, r.status == "ok") {
        let b = remit_read::arrowconv::rows_to_batch(rows, &cols);
        let mut resp = remit_read::arrowconv::ipc_stream(&b.schema(), &[b]).into_response();
        let hm = resp.headers_mut();
        hm.insert(header::CONTENT_TYPE, HeaderValue::from_static(ARROW_CT));
        // Everything but the rows travels in one header, so the receipt still verifies.
        let mut meta = serde_json::to_value(r).unwrap_or(Value::Null);
        meta["result"] = Value::Null;
        if let Ok(v) = HeaderValue::from_str(&STANDARD.encode(meta.to_string())) {
            hm.insert("remit-response", v);
        }
        return resp;
    }
    let _ = h;
    Json(serde_json::to_value(r).unwrap_or(Value::Null)).into_response()
}

async fn run(
    State(h): State<Arc<Holder>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let transport = match h.transport(&method, &uri, &headers, &body).await {
        Ok(t) => t,
        Err(e) => return unauthorized(&e),
    };
    let prefer = headers
        .get("prefer")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let wants_arrow = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains(ARROW_CT));
    let o = admit(
        &h,
        &body,
        AdmitOptions {
            dry: false,
            accept_clamps: false,
            transport,
        },
    )
    .await;
    match o {
        Outcome::Admitted(a) => {
            let run_id = new_run_id();
            if prefer.contains("respond-async") {
                spawn_async(&h, *a, run_id.clone());
                let mut r = (StatusCode::ACCEPTED, Json(json!({"run_id": run_id, "status_url": format!("/remit/v1/runs/{run_id}"), "state": "running"}))).into_response();
                r.headers_mut().insert(
                    header::LOCATION,
                    HeaderValue::from_str(&format!("/remit/v1/runs/{run_id}")).unwrap(),
                );
                return r;
            }
            let cols = wants_arrow
                .then(|| a.analysis.rt.as_ref().and_then(remit_emit::table_layout))
                .flatten();
            match run_admitted(&h, *a, run_id.clone()).await {
                Some(r) => {
                    h.runs
                        .lock()
                        .put(&run_id, "done", serde_json::to_value(&r).ok(), h.now_ms());
                    render(&h, &r, cols)
                }
                None => busy(
                    1,
                    json!({"decision": "busy", "retry_after_s": 1, "message": "execution queue is full"}),
                ),
            }
        }
        other => {
            h.metrics
                .rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (code, mut v) = outcome_json(&h, &other);
            // Every terminal state is receipted.
            let decision = match &other {
                Outcome::Rejected {
                    remit_id: Some(rid),
                    ..
                } => Some(("rejected", rid.clone())),
                Outcome::PendingApproval { card, .. } => Some((
                    "pending_approval",
                    card["remit_id"].as_str().unwrap_or("").to_string(),
                )),
                Outcome::CounterOffer { remit_id, .. } => Some(("counter_offer", remit_id.clone())),
                _ => None,
            };
            if let Some((d, rid)) = decision {
                let sender = serde_json::from_slice::<remit_wire::Envelope>(&body)
                    .ok()
                    .and_then(|e| e.payload_bytes().ok())
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .and_then(|m| m["sender"].as_str().map(String::from))
                    .unwrap_or_default();
                v["receipt"] = json!(admission_receipt(&h, &rid, &sender, d));
            }
            match other {
                Outcome::Busy { retry_after_s, .. } => busy(retry_after_s, v),
                _ => (code, Json(v)).into_response(),
            }
        }
    }
}

async fn get_run(
    State(h): State<Arc<Holder>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"));
    if sse {
        let h2 = h.clone();
        let stream = async_stream(h2, id);
        return Sse::new(stream).into_response();
    }
    let rec = h.runs.lock().get(&id);
    match rec {
        Some(r) => Json(json!(r)).into_response(),
        None => match h.approvals.ticket(&id) {
            Some(t) => Json(json!({"run_id": id, "state": t.state, "ticket": t})).into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({"error": "unknown run"}))).into_response(),
        },
    }
}

fn async_stream(
    h: Arc<Holder>,
    id: String,
) -> impl futures::Stream<Item = Result<Event, std::convert::Infallible>> {
    futures::stream::unfold((h, id, 0u32, false), |(h, id, n, done)| async move {
        if done || n > 600 {
            return None;
        }
        let rec = h.runs.lock().get(&id);
        match rec {
            Some(r) if r.state == "done" => {
                let ev = Event::default()
                    .event("result")
                    .data(serde_json::to_string(&r.response).unwrap_or_default());
                Some((Ok(ev), (h, id, n + 1, true)))
            }
            Some(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let ev = Event::default()
                    .event("progress")
                    .data("{\"state\":\"running\"}");
                Some((Ok(ev), (h, id, n + 1, false)))
            }
            None => Some((
                Ok(Event::default()
                    .event("error")
                    .data("{\"error\":\"unknown run\"}")),
                (h, id, n + 1, true),
            )),
        }
    })
}

async fn put_blob(State(h): State<Arc<Holder>>, Path(sha): Path<String>, body: Bytes) -> Response {
    let sha = remit_wire::manifest::normalize_hash(&sha);
    if body.len() > MAX_BLOB {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "blob too large"})),
        )
            .into_response();
    }
    if remit_wire::sha256_hex(&body) != sha {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "sha256 does not match the body"})),
        )
            .into_response();
    }
    let Ok(text) = String::from_utf8(body.to_vec()) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "blobs are UTF-8 source"})),
        )
            .into_response();
    };
    h.blobs.lock().put(sha.clone(), text);
    (StatusCode::CREATED, Json(json!({"sha256": sha}))).into_response()
}

async fn get_receipt(State(h): State<Arc<Holder>>, Path(id): Path<String>) -> Response {
    match h.receipts.get(&id) {
        Some(e) => Json(json!(e)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown receipt"})),
        )
            .into_response(),
    }
}

fn signed_head(h: &Holder) -> (remit_receipt::merkle::TreeHead, remit_wire::Envelope) {
    let mut th = h.receipts.tree_head(h.id());
    th.ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let env = remit_receipt::merkle::sign_head(&th, &h.signer);
    (th, env)
}

async fn log_head(State(h): State<Arc<Holder>>) -> Json<Value> {
    let (th, env) = signed_head(&h);
    Json(json!({"tree_head": th, "signed": env}))
}

async fn log_proof(State(h): State<Arc<Holder>>, Path(id): Path<String>) -> Response {
    let Some(p) = h.receipts.inclusion(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown receipt"})),
        )
            .into_response();
    };
    let (th, env) = signed_head(&h);
    if th.size != p.size {
        // A receipt was appended concurrently: recompute against the new head.
        if let Some(p2) = h.receipts.inclusion(&id) {
            let (th2, env2) = signed_head(&h);
            return Json(json!({"proof": p2, "tree_head": th2, "signed": env2})).into_response();
        }
    }
    Json(json!({"proof": p, "tree_head": th, "signed": env})).into_response()
}

fn admin_ok(h: &Holder, headers: &HeaderMap) -> bool {
    let Some(tok) = crate::config::secret(&h.cfg.holder.admin_token).filter(|t| !t.is_empty())
    else {
        return false;
    };
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| {
            // Constant-time comparison.
            t.len() == tok.len()
                && t.bytes()
                    .zip(tok.bytes())
                    .fold(0u8, |a, (x, y)| a | (x ^ y))
                    == 0
        })
}

/// Load a fresh snapshot of every source now.
async fn refresh(State(h): State<Arc<Holder>>, headers: HeaderMap) -> Response {
    if !admin_ok(&h, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match h.refresh().await {
        Ok(()) => {
            Json(json!({"refreshed": true, "catalog_sha256": h.catalog(&[]).1})).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("{e:#}")})),
        )
            .into_response(),
    }
}

async fn list_approvals(State(h): State<Arc<Holder>>, headers: HeaderMap) -> Response {
    if !admin_ok(&h, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    Json(json!({"tickets": h.approvals.tickets(), "standing": h.approvals.standing()}))
        .into_response()
}

async fn approve(
    State(h): State<Arc<Holder>>,
    Path(t): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !admin_ok(&h, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let params = v
        .get("params")
        .and_then(|p| serde_json::from_value(p.clone()).ok());
    let all = v
        .get("all_principals")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let exp = v
        .get("expires_at")
        .and_then(Value::as_str)
        .map(String::from);
    match h.approvals.approve(&t, params, all, exp) {
        Some(a) => {
            h.analysis_cache.lock().clear();
            Json(json!({"approved": a})).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn deny(State(h): State<Arc<Holder>>, Path(t): Path<String>, headers: HeaderMap) -> Response {
    if !admin_ok(&h, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if h.approvals.deny(&t) {
        Json(json!({"denied": t})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// `/metrics`: OpenMetrics text when scraped (`Accept: text/plain` or
/// `application/openmetrics-text`), JSON otherwise.
async fn metrics(State(h): State<Arc<Holder>>, headers: HeaderMap) -> Response {
    let v = metrics_json(&h);
    if headers
        .get(header::ACCEPT)
        .and_then(|a| a.to_str().ok())
        .is_some_and(|a| a.contains("text/plain") || a.contains("openmetrics"))
    {
        let mut s = String::new();
        for (k, x) in v.as_object().into_iter().flatten() {
            if let Some(n) = x.as_u64() {
                let kind = if matches!(k.as_str(), "running" | "queued" | "nonces") {
                    "gauge"
                } else {
                    "counter"
                };
                let sfx = if kind == "counter" { "_total" } else { "" };
                s.push_str(&format!("# TYPE remit_{k} {kind}\nremit_{k}{sfx} {n}\n"));
            }
        }
        s.push_str("# EOF\n");
        return (
            [(
                header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            s,
        )
            .into_response();
    }
    Json(v).into_response()
}

pub fn metrics_json(h: &Holder) -> Value {
    use std::sync::atomic::Ordering::Relaxed;
    let m = &h.metrics;
    let (seq, head) = h.receipts.head();
    json!({
        "running": h.sched.running(), "queued": h.sched.queued(), "nonces": h.nonces.len(),
        "standing_admissions": m.standing.load(Relaxed),
        "admitted": m.admitted.load(Relaxed), "rejected": m.rejected.load(Relaxed),
        "runs_ok": m.runs_ok.load(Relaxed), "runs_failed": m.runs_failed.load(Relaxed),
        "plan_cache_hits": m.plan_cache_hits.load(Relaxed), "result_cache_hits": m.result_cache_hits.load(Relaxed),
        "receipts": {"seq": seq, "head": head},
    })
}
