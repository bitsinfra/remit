//! MCP extension `io.github.bitsinfra/remit` (targets the stateless 2026-07-28 spec).
//!
//! * resource `remit://catalog`;
//! * tools `remit_check`, `remit_run` (argument: a signed DSSE envelope);
//! * counter-offers are Multi Round-Trip Requests: `resultType:
//!   "input_required"` carries the JSON Patch; the client retries with a
//!   re-signed envelope;
//! * pending approvals and async runs use `io.modelcontextprotocol/tasks`
//!   (`tasks/get`);
//! * typed results travel in `structuredContent`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::admission::{admit, AdmitOptions, Outcome};
use crate::http::outcome_json;
use crate::identity::Transport;
use crate::run::{new_run_id, run_admitted, spawn_async};
use crate::state::Holder;

pub const EXTENSION_ID: &str = "io.github.bitsinfra/remit";
pub const PROTOCOL_VERSION: &str = "2026-07-28";
const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

fn ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err(id: &Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

fn tools() -> Value {
    let envelope = json!({
        "type": "object",
        "properties": {"envelope": {"type": "object", "description": "DSSE envelope (payloadType application/vnd.remit.manifest+json) carrying the JCS-canonical manifest"}},
        "required": ["envelope"]
    });
    json!([
        {"name": "remit_check", "title": "Check a remit",
         "description": "Admission only: returns decision, structured diagnostics (code, JSON pointer / SQL span, hint, fix), counter-offers, capacity in bits and coarse cost. Nothing runs.",
         "inputSchema": envelope, "annotations": {"readOnlyHint": true, "idempotentHint": true}},
        {"name": "remit_run", "title": "Run a remit",
         "description": "Admit and run a signed remit next to the data. Returns only the typed result (structuredContent), labels, terms and a signed receipt.",
         "inputSchema": envelope, "annotations": {"readOnlyHint": true, "openWorldHint": false}},
    ])
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
    // Gateways route on these headers without parsing bodies: they must agree.
    let hd = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    if let Some(m) = hd("mcp-method") {
        if req["method"].as_str() != Some(m) {
            return (
                StatusCode::BAD_REQUEST,
                Json(err(
                    &req["id"],
                    -32600,
                    "Mcp-Method header does not match the body",
                )),
            )
                .into_response();
        }
    }
    if let Some(n) = hd("mcp-name") {
        let body_name = req["params"]["name"]
            .as_str()
            .or(req["params"]["uri"].as_str());
        if body_name != Some(n) {
            return (
                StatusCode::BAD_REQUEST,
                Json(err(
                    &req["id"],
                    -32600,
                    "Mcp-Name header does not match the body",
                )),
            )
                .into_response();
        }
    }
    let legacy = hd("mcp-protocol-version") == Some(LEGACY_PROTOCOL_VERSION);
    if let Value::Array(batch) = req {
        let mut out = Vec::new();
        for r in batch {
            if let Some(v) = dispatch_version(&h, r, &t, legacy).await {
                out.push(v);
            }
        }
        return Json(Value::Array(out)).into_response();
    }
    match dispatch_version(&h, req, &t, legacy).await {
        Some(v) => Json(v).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

pub async fn dispatch(h: &Arc<Holder>, req: Value, t: &Transport) -> Option<Value> {
    dispatch_version(h, req, t, false).await
}

async fn dispatch_version(
    h: &Arc<Holder>,
    req: Value,
    t: &Transport,
    legacy: bool,
) -> Option<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!({}));
    req.get("id")?;
    Some(match method {
        "server/discover" | "initialize" => {
            let mut result = json!({
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {"name": "remit-holder", "version": env!("CARGO_PKG_VERSION"), "title": h.id()},
                "capabilities": {
                    "tools": {}, "resources": {},
                    "extensions": {
                        EXTENSION_ID: {"version": remit_wire::REMIT_VERSION, "catalog": "remit://catalog"},
                        "io.modelcontextprotocol/tasks": {}
                    }
                },
                "instructions": "Read remit://catalog, write a remit (SQL query or JS kernel over declared reads with a bounded `returns` type), sign it, then call remit_check / remit_run. Use the remit-mcp helper to sign and repair automatically."
            });
            if method == "initialize" {
                result["protocolVersion"] = json!(LEGACY_PROTOCOL_VERSION);
            } else {
                result["resultType"] = json!("complete");
                result["supportedVersions"] = json!([PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION]);
                result["_meta"] =
                    json!({"io.modelcontextprotocol/serverInfo": result["serverInfo"]});
            }
            ok(&id, result)
        }
        "ping" => ok(&id, json!({})),
        "tools/list" => ok(&id, json!({"tools": tools()})),
        "resources/list" => ok(
            &id,
            json!({"resources": [{"uri": "remit://catalog", "name": "catalog", "title": "Remit catalog", "mimeType": "application/json"}]}),
        ),
        "resources/read" => {
            if params.get("uri").and_then(Value::as_str) != Some("remit://catalog") {
                err(&id, -32602, "unknown resource")
            } else {
                let (doc, _) = h.catalog(&[]);
                ok(
                    &id,
                    json!({"contents": [{"uri": "remit://catalog", "mimeType": "application/json", "text": doc.to_string()}]}),
                )
            }
        }
        "tasks/get" => {
            let tid = params.get("taskId").and_then(Value::as_str).unwrap_or("");
            let run = h.runs.lock().get(tid);
            if let Some(r) = run {
                ok(
                    &id,
                    json!({"taskId": tid, "status": if r.state == "done" { "completed" } else { "working" }, "result": r.response}),
                )
            } else if let Some(t) = h.approvals.ticket(tid) {
                let status = match t.state.as_str() {
                    "approved" => "completed",
                    "denied" => "failed",
                    _ => "input_required",
                };
                ok(
                    &id,
                    json!({"taskId": tid, "status": status, "statusMessage": "awaiting Holder approval; resubmit the remit after approval", "accessCard": t.card}),
                )
            } else {
                err(&id, -32602, "unknown task")
            }
        }
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let Some(env) = params.get("arguments").and_then(|a| a.get("envelope")) else {
                return Some(err(&id, -32602, "arguments.envelope is required"));
            };
            let body = serde_json::to_vec(env).unwrap_or_default();
            match name {
                "remit_check" => {
                    let o = admit(
                        h,
                        &body,
                        AdmitOptions {
                            dry: true,
                            accept_clamps: false,
                            transport: t.clone(),
                        },
                    )
                    .await;
                    let (_, v) = outcome_json(h, &o);
                    ok(&id, tool_result(v, false))
                }
                "remit_run" => {
                    let o = admit(
                        h,
                        &body,
                        AdmitOptions {
                            dry: false,
                            accept_clamps: false,
                            transport: t.clone(),
                        },
                    )
                    .await;
                    if legacy
                        && matches!(
                            &o,
                            Outcome::CounterOffer { .. } | Outcome::PendingApproval { .. }
                        )
                    {
                        let (_, v) = outcome_json(h, &o);
                        return Some(ok(&id, tool_result(v, true)));
                    }
                    match o {
                        Outcome::Admitted(a) => {
                            let run_id = new_run_id();
                            // Task-augmented call: answer now, poll `tasks/get`.
                            if !legacy && params.get("task").is_some() {
                                spawn_async(h, *a, run_id.clone());
                                return Some(ok(
                                    &id,
                                    json!({"resultType": "task", "task": {"taskId": run_id, "status": "working", "pollInterval": 250}}),
                                ));
                            }
                            let Some(r) = run_admitted(h, *a, run_id).await else {
                                return Some(err(&id, -32000, "execution queue is full; retry"));
                            };
                            let is_err = r.status != "ok";
                            ok(
                                &id,
                                tool_result(
                                    serde_json::to_value(&r).unwrap_or(Value::Null),
                                    is_err,
                                ),
                            )
                        }
                        Outcome::CounterOffer {
                            patch, diagnostics, ..
                        } => ok(
                            &id,
                            json!({
                                "resultType": "input_required",
                                "inputRequests": {"counter_offer": {"method": "remit/counter_offer", "json_patch": patch, "diagnostics": diagnostics,
                                    "message": "apply the patch to the manifest, re-sign, and call remit_run again"}}
                            }),
                        ),
                        Outcome::PendingApproval { ticket, card, .. } => ok(
                            &id,
                            json!({"resultType": "task", "task": {"taskId": ticket, "status": "input_required", "statusMessage": "awaiting Holder approval"}, "_meta": {"accessCard": card}}),
                        ),
                        other => {
                            let (_, v) = outcome_json(h, &other);
                            ok(&id, tool_result(v, true))
                        }
                    }
                }
                _ => err(&id, -32602, "unknown tool"),
            }
        }
        _ => err(&id, -32601, "method not found"),
    })
}

fn tool_result(v: Value, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": v.to_string()}], "structuredContent": v, "isError": is_error})
}
