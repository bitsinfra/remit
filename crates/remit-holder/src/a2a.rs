//! A2A v1.0 extension: a **method extension** (`remit/check`, `remit/run`)
//! and a **profile** constraining `DataPart`s in `message/send` to Remit
//! envelopes, results and receipts. Agent Cards advertise the catalog URL.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::admission::{admit, AdmitOptions, Outcome};
use crate::http::{outcome_json, ENVELOPE_CT};
use crate::identity::Transport;
use crate::run::{new_run_id, run_admitted};
use crate::state::Holder;

fn ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err(id: &Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

async fn run_envelope(h: &Arc<Holder>, env: &Value, dry: bool, t: &Transport) -> Value {
    let body = serde_json::to_vec(env).unwrap_or_default();
    let o = admit(
        h,
        &body,
        AdmitOptions {
            dry,
            accept_clamps: false,
            transport: t.clone(),
        },
    )
    .await;
    match o {
        Outcome::Admitted(a) if !dry => match run_admitted(h, *a, new_run_id()).await {
            Some(r) => serde_json::to_value(r).unwrap_or(Value::Null),
            None => {
                json!({"decision": "busy", "retry_after_s": 1, "message": "execution queue is full"})
            }
        },
        other => outcome_json(h, &other).1,
    }
}

pub async fn handle(
    State(h): State<Arc<Holder>>,
    http_method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let t = match h.transport(&http_method, &uri, &headers, &body).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(err(&Value::Null, -32001, &e)),
            )
                .into_response()
        }
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return Json(err(&Value::Null, -32700, "parse error")).into_response(),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let resp = match req.get("method").and_then(Value::as_str).unwrap_or("") {
        "remit/check" => match params.get("envelope") {
            Some(e) => ok(&id, run_envelope(&h, e, true, &t).await),
            None => err(&id, -32602, "params.envelope is required"),
        },
        "remit/run" => match params.get("envelope") {
            Some(e) => ok(&id, run_envelope(&h, e, false, &t).await),
            None => err(&id, -32602, "params.envelope is required"),
        },
        "message/send" => {
            // Profile: the first DataPart whose mediaType is the Remit envelope type.
            let parts = params
                .pointer("/message/parts")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let env = parts.iter().find_map(|p| {
                let is_data = p.get("kind").and_then(Value::as_str) == Some("data")
                    || p.get("data").is_some();
                let mt = p
                    .get("mediaType")
                    .or_else(|| p.pointer("/metadata/mediaType"))
                    .and_then(Value::as_str);
                (is_data && (mt.is_none() || mt == Some(ENVELOPE_CT)))
                    .then(|| p.get("data").cloned())
                    .flatten()
            });
            match env {
                Some(e) => {
                    let e = e.get("envelope").cloned().unwrap_or(e);
                    let res = run_envelope(&h, &e, false, &t).await;
                    let state = if res.get("status").and_then(Value::as_str) == Some("ok") {
                        "completed"
                    } else {
                        "failed"
                    };
                    ok(
                        &id,
                        json!({
                            "kind": "task",
                            "id": res.get("run_id").cloned().unwrap_or(json!(new_run_id())),
                            "status": {"state": state},
                            "artifacts": [{"artifactId": "result", "parts": [{"kind": "data", "data": res, "mediaType": "application/vnd.remit.result+json"}]}],
                        }),
                    )
                }
                None => err(
                    &id,
                    -32602,
                    "message must contain a DataPart with a Remit envelope",
                ),
            }
        }
        _ => err(&id, -32601, "method not found"),
    };
    Json(resp).into_response()
}
