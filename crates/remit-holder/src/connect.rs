//! `remit.v1.RemitService` over the Connect protocol (unary; JSON and binary
//! protobuf codecs) and gRPC. One method table serves all three codecs.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::admission::{admit, AdmitOptions, Outcome};
use crate::grpc;
use crate::http::outcome_json;
use crate::identity::Transport;
use crate::run::{new_run_id, run_admitted, spawn_async};
use crate::state::Holder;

type Rpc = Result<Value, (&'static str, String)>;

fn connect_err(code: &str, message: &str) -> Response {
    let status = match code {
        "invalid_argument" => StatusCode::BAD_REQUEST,
        "unauthenticated" => StatusCode::UNAUTHORIZED,
        "not_found" => StatusCode::NOT_FOUND,
        "permission_denied" => StatusCode::FORBIDDEN,
        "resource_exhausted" => StatusCode::TOO_MANY_REQUESTS,
        "unimplemented" => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({"code": code, "message": message}))).into_response()
}

pub async fn handle(
    State(h): State<Arc<Holder>>,
    Path(method): Path<String>,
    http_method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let is_grpc = ct.starts_with("application/grpc");
    let is_proto = ct.starts_with("application/proto");
    if is_grpc && !matches!(ct.as_str(), "application/grpc" | "application/grpc+proto") {
        return grpc::grpc_response(Err((
            "unimplemented",
            "only application/grpc+proto is served".into(),
        )));
    }
    if !is_grpc && !is_proto && !ct.starts_with("application/json") {
        return connect_err(
            "invalid_argument",
            "use application/json, application/proto or application/grpc",
        );
    }
    let transport = h.transport(&http_method, &uri, &headers, &body).await;
    let req = if is_grpc {
        grpc::unframe(&body)
            .map_err(String::from)
            .and_then(|b| grpc::decode_request(&method, b))
    } else if is_proto {
        grpc::decode_request(&method, &body)
    } else if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(&body).map_err(|e| format!("invalid JSON: {e}"))
    };
    let out: Rpc = match (transport, req) {
        (Err(e), _) => Err(("unauthenticated", e)),
        (_, Err(e)) => Err(("invalid_argument", e)),
        (Ok(t), Ok(r)) => call(&h, &method, r, t).await,
    };
    if is_grpc {
        return grpc::grpc_response(out.map(|v| grpc::encode_response(&method, &v)));
    }
    match out {
        Err((code, msg)) => connect_err(code, &msg),
        Ok(v) if is_proto => {
            let mut r = grpc::encode_response(&method, &v).into_response();
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/proto"),
            );
            r
        }
        Ok(v) => Json(v).into_response(),
    }
}

async fn call(h: &Arc<Holder>, method: &str, req: Value, transport: Transport) -> Rpc {
    let field = |k: &str| req.get(k).cloned().unwrap_or(Value::Null);
    let run_id = || {
        field("runId")
            .as_str()
            .or(field("run_id").as_str())
            .unwrap_or("")
            .to_string()
    };
    match method {
        "GetCatalog" => Ok(h.catalog(&[]).0),
        "Check" | "Run" => {
            let env = field("envelope");
            if env.is_null() {
                return Err(("invalid_argument", "envelope is required".into()));
            }
            let bytes = serde_json::to_vec(&env).unwrap_or_default();
            let dry = method == "Check";
            match admit(
                h,
                &bytes,
                AdmitOptions {
                    dry,
                    accept_clamps: false,
                    transport,
                },
            )
            .await
            {
                Outcome::Admitted(a) if !dry => {
                    let run_id = new_run_id();
                    if req.get("async").and_then(Value::as_bool).unwrap_or(false) {
                        spawn_async(h, *a, run_id.clone());
                        return Ok(json!({"runId": run_id, "status": "running"}));
                    }
                    match run_admitted(h, *a, run_id).await {
                        Some(r) => Ok(serde_json::to_value(&r).unwrap_or(Value::Null)),
                        None => Err(("resource_exhausted", "execution queue is full".into())),
                    }
                }
                Outcome::Busy { message, .. } => Err(("resource_exhausted", message)),
                other => Ok(outcome_json(h, &other).1),
            }
        }
        "GetRun" => h
            .runs
            .lock()
            .get(&run_id())
            .map(|r| json!(r))
            .ok_or(("not_found", "unknown run".into())),
        "GetReceipt" => h
            .receipts
            .get(&run_id())
            .map(|e| json!(e))
            .ok_or(("not_found", "unknown receipt".into())),
        "GetLogProof" => h
            .receipts
            .inclusion(&run_id())
            .map(|p| json!({"proof": p, "treeHead": h.receipts.tree_head(h.id())}))
            .ok_or(("not_found", "unknown receipt".into())),
        "PutBlob" => {
            let sha = remit_wire::manifest::normalize_hash(field("sha256").as_str().unwrap_or(""));
            let src = field("source").as_str().unwrap_or("").to_string();
            if src.len() > crate::http::MAX_BLOB {
                return Err(("invalid_argument", "blob too large".into()));
            }
            if remit_wire::sha256_hex(src.as_bytes()) != sha {
                return Err(("invalid_argument", "sha256 does not match source".into()));
            }
            h.blobs.lock().put(sha.clone(), src);
            Ok(json!({"sha256": sha}))
        }
        _ => Err((
            "unimplemented",
            format!("unknown method remit.v1.RemitService/{method}"),
        )),
    }
}
