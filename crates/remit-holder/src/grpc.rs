//! `remit.v1.RemitService` messages (spec/proto) and the binary codecs:
//! gRPC over HTTP/2 (h2c or behind TLS termination) and Connect unary with
//! `application/proto`. The JSON codec lives in `connect.rs`; both call the
//! same method implementations, so the surface cannot drift.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use prost::Message;
use serde_json::{json, Map, Value};

// ------------------------------------------------ google.protobuf.Struct

#[derive(Clone, PartialEq, Message)]
pub struct PbStruct {
    #[prost(btree_map = "string, message", tag = "1")]
    pub fields: BTreeMap<String, PbValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbList {
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<PbValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PbValue {
    #[prost(oneof = "Kind", tags = "1, 2, 3, 4, 5, 6")]
    pub kind: Option<Kind>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Kind {
    #[prost(int32, tag = "1")]
    Null(i32),
    #[prost(double, tag = "2")]
    Number(f64),
    #[prost(string, tag = "3")]
    String(String),
    #[prost(bool, tag = "4")]
    Bool(bool),
    #[prost(message, tag = "5")]
    Struct(PbStruct),
    #[prost(message, tag = "6")]
    List(PbList),
}

pub fn to_pb(v: &Value) -> PbValue {
    PbValue {
        kind: Some(match v {
            Value::Null => Kind::Null(0),
            Value::Bool(b) => Kind::Bool(*b),
            Value::Number(n) => Kind::Number(n.as_f64().unwrap_or(0.0)),
            Value::String(s) => Kind::String(s.clone()),
            Value::Array(a) => Kind::List(PbList {
                values: a.iter().map(to_pb).collect(),
            }),
            Value::Object(o) => Kind::Struct(PbStruct {
                fields: o.iter().map(|(k, v)| (k.clone(), to_pb(v))).collect(),
            }),
        }),
    }
}

pub fn from_pb(v: &PbValue) -> Value {
    match &v.kind {
        None | Some(Kind::Null(_)) => Value::Null,
        Some(Kind::Bool(b)) => json!(b),
        Some(Kind::Number(n)) if n.fract() == 0.0 && n.abs() < 9e15 => json!(*n as i64),
        Some(Kind::Number(n)) => json!(n),
        Some(Kind::String(s)) => json!(s),
        Some(Kind::List(l)) => Value::Array(l.values.iter().map(from_pb).collect()),
        Some(Kind::Struct(s)) => Value::Object(
            s.fields
                .iter()
                .map(|(k, v)| (k.clone(), from_pb(v)))
                .collect::<Map<_, _>>(),
        ),
    }
}

fn pb_struct(v: &Value) -> Option<PbStruct> {
    match to_pb(v).kind {
        Some(Kind::Struct(s)) => Some(s),
        _ => None,
    }
}

fn pb_list(v: &Value) -> Option<PbList> {
    match to_pb(v).kind {
        Some(Kind::List(l)) => Some(l),
        _ => None,
    }
}

// ----------------------------------------------------------- messages

#[derive(Clone, PartialEq, Message)]
pub struct Signature {
    #[prost(string, tag = "1")]
    pub keyid: String,
    #[prost(string, tag = "2")]
    pub sig: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Envelope {
    #[prost(string, tag = "1")]
    pub payload_type: String,
    #[prost(string, tag = "2")]
    pub payload: String,
    #[prost(message, repeated, tag = "3")]
    pub signatures: Vec<Signature>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Diagnostic {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub path: String,
    #[prost(uint64, repeated, tag = "3")]
    pub span: Vec<u64>,
    #[prost(string, tag = "4")]
    pub message: String,
    #[prost(string, tag = "5")]
    pub hint: String,
    #[prost(string, tag = "6")]
    pub docs: String,
    #[prost(message, optional, tag = "7")]
    pub fix: Option<PbList>,
}

/// `CheckRequest` and `RunRequest` (the latter adds `async`).
#[derive(Clone, PartialEq, Message)]
pub struct RunRequest {
    #[prost(message, optional, tag = "1")]
    pub envelope: Option<Envelope>,
    #[prost(bool, tag = "2")]
    pub r#async: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct CheckResponse {
    #[prost(string, tag = "1")]
    pub decision: String,
    #[prost(string, tag = "2")]
    pub remit_id: String,
    #[prost(message, repeated, tag = "3")]
    pub diagnostics: Vec<Diagnostic>,
    #[prost(message, optional, tag = "4")]
    pub facts: Option<PbStruct>,
    #[prost(message, optional, tag = "5")]
    pub access_card: Option<PbStruct>,
    #[prost(message, optional, tag = "6")]
    pub counter_offer: Option<PbStruct>,
    #[prost(message, optional, tag = "7")]
    pub cost: Option<PbStruct>,
    #[prost(message, optional, tag = "8")]
    pub trace: Option<PbList>,
    #[prost(string, tag = "9")]
    pub ticket: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RunResponse {
    #[prost(string, tag = "1")]
    pub run_id: String,
    #[prost(string, tag = "2")]
    pub status: String,
    #[prost(message, optional, tag = "3")]
    pub result: Option<PbValue>,
    #[prost(string, repeated, tag = "4")]
    pub labels: Vec<String>,
    #[prost(message, optional, tag = "5")]
    pub terms: Option<PbStruct>,
    #[prost(message, optional, tag = "6")]
    pub provenance: Option<PbStruct>,
    #[prost(message, optional, tag = "7")]
    pub receipt: Option<Envelope>,
    #[prost(btree_map = "string, string", tag = "8")]
    pub usage: BTreeMap<String, String>,
    #[prost(bool, tag = "9")]
    pub cached: bool,
    #[prost(string, tag = "10")]
    pub decision: String,
    #[prost(message, repeated, tag = "11")]
    pub diagnostics: Vec<Diagnostic>,
    #[prost(message, optional, tag = "12")]
    pub counter_offer: Option<PbStruct>,
    #[prost(string, tag = "13")]
    pub ticket: String,
}

/// `GetRunRequest`, `GetReceiptRequest`, `GetLogProofRequest`.
#[derive(Clone, PartialEq, Message)]
pub struct RunIdRequest {
    #[prost(string, tag = "1")]
    pub run_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct PutBlob {
    #[prost(string, tag = "1")]
    pub sha256: String,
    #[prost(string, tag = "2")]
    pub source: String,
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}

fn env_pb(v: &Value) -> Option<Envelope> {
    v.is_object().then(|| Envelope {
        payload_type: s(v, "payloadType"),
        payload: s(v, "payload"),
        signatures: v["signatures"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|x| Signature {
                keyid: s(x, "keyid"),
                sig: s(x, "sig"),
            })
            .collect(),
    })
}

fn env_json(e: &Envelope) -> Value {
    json!({"payloadType": e.payload_type, "payload": e.payload, "signatures": e.signatures.iter().map(|x| json!({"keyid": x.keyid, "sig": x.sig})).collect::<Vec<_>>()})
}

fn diags(v: &Value) -> Vec<Diagnostic> {
    v["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|d| Diagnostic {
            code: s(d, "code"),
            path: s(d, "path"),
            span: d["span"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_u64)
                .collect(),
            message: s(d, "message"),
            hint: s(d, "hint"),
            docs: s(d, "docs"),
            fix: pb_list(&d["fix"]),
        })
        .collect()
}

/// Binary request → the JSON shape the method implementations take.
pub fn decode_request(method: &str, b: &[u8]) -> Result<Value, String> {
    let e = |e: prost::DecodeError| e.to_string();
    Ok(match method {
        "Check" | "Run" => {
            let r = RunRequest::decode(b).map_err(e)?;
            json!({"envelope": r.envelope.as_ref().map(env_json), "async": r.r#async})
        }
        "GetRun" | "GetReceipt" | "GetLogProof" => {
            json!({"runId": RunIdRequest::decode(b).map_err(e)?.run_id})
        }
        "PutBlob" => {
            let r = PutBlob::decode(b).map_err(e)?;
            json!({"sha256": r.sha256, "source": r.source})
        }
        _ => json!({}),
    })
}

/// JSON response → binary.
pub fn encode_response(method: &str, v: &Value) -> Vec<u8> {
    match method {
        "Check" => CheckResponse {
            decision: s(v, "decision"),
            remit_id: s(v, "remit_id"),
            diagnostics: diags(v),
            facts: pb_struct(&v["facts"]),
            access_card: pb_struct(&v["access_card"]),
            counter_offer: pb_struct(&v["counter_offer"]),
            cost: pb_struct(&v["cost"]),
            trace: pb_list(&v["trace"]),
            ticket: s(v, "ticket"),
        }
        .encode_to_vec(),
        "Run" => RunResponse {
            run_id: if v["run_id"].is_string() {
                s(v, "run_id")
            } else {
                s(v, "runId")
            },
            status: s(v, "status"),
            result: (!v["result"].is_null()).then(|| to_pb(&v["result"])),
            labels: v["labels"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            terms: pb_struct(&v["terms"]),
            provenance: pb_struct(&v["provenance"]),
            receipt: env_pb(&v["receipt"]),
            usage: v["usage"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string()))
                .collect(),
            cached: v["cached"].as_bool().unwrap_or(false),
            decision: s(v, "decision"),
            diagnostics: diags(v),
            counter_offer: pb_struct(&v["counter_offer"]),
            ticket: s(v, "ticket"),
        }
        .encode_to_vec(),
        "GetReceipt" => env_pb(v).unwrap_or_default().encode_to_vec(),
        "PutBlob" => PutBlob {
            sha256: s(v, "sha256"),
            source: String::new(),
        }
        .encode_to_vec(),
        _ => pb_struct(v).unwrap_or_default().encode_to_vec(),
    }
}

// --------------------------------------------------------- gRPC framing

/// Connect code → gRPC status number.
pub fn grpc_code(code: &str) -> u32 {
    match code {
        "invalid_argument" => 3,
        "not_found" => 5,
        "permission_denied" => 7,
        "resource_exhausted" => 8,
        "unimplemented" => 12,
        "internal" => 13,
        "unauthenticated" => 16,
        _ => 2,
    }
}

/// Unwrap one length-prefixed, uncompressed gRPC message.
pub fn unframe(b: &[u8]) -> Result<&[u8], &'static str> {
    if b.len() < 5 {
        return Err("truncated gRPC frame");
    }
    if b[0] != 0 {
        return Err("compressed gRPC messages are not supported");
    }
    let n = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
    if b.len() != 5 + n {
        return Err("expected exactly one gRPC message");
    }
    Ok(&b[5..])
}

/// A unary gRPC response body: one data frame, then trailers.
struct GrpcBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl http_body::Body for GrpcBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if let Some(d) = self.data.take() {
            return Poll::Ready(Some(Ok(http_body::Frame::data(d))));
        }
        Poll::Ready(
            self.trailers
                .take()
                .map(|t| Ok(http_body::Frame::trailers(t))),
        )
    }
}

pub fn grpc_response(r: Result<Vec<u8>, (&str, String)>) -> Response {
    let mut trailers = HeaderMap::new();
    let data = match r {
        Ok(b) => {
            let mut f = vec![0u8];
            f.extend((b.len() as u32).to_be_bytes());
            f.extend(b);
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            Some(Bytes::from(f))
        }
        Err((code, msg)) => {
            trailers.insert(
                "grpc-status",
                HeaderValue::from_str(&grpc_code(code).to_string()).expect("digits"),
            );
            let enc: String = msg
                .bytes()
                .map(|b| {
                    if (0x20..0x7f).contains(&b) && b != b'%' {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            if let Ok(v) = HeaderValue::from_str(&enc) {
                trailers.insert("grpc-message", v);
            }
            None
        }
    };
    let mut resp = (
        StatusCode::OK,
        Body::new(GrpcBody {
            data,
            trailers: Some(trailers),
        }),
    )
        .into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc+proto"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_roundtrip() {
        let v = json!({"a": [1, 2.5, "x", null, true], "b": {"c": {}}});
        assert_eq!(
            from_pb(&PbValue::decode(to_pb(&v).encode_to_vec().as_slice()).unwrap()),
            v
        );
    }

    #[test]
    fn frames() {
        assert_eq!(unframe(&[0, 0, 0, 0, 2, 9, 8]).unwrap(), &[9, 8]);
        for bad in [
            &[][..],
            &[0, 0, 0, 0],
            &[1, 0, 0, 0, 0],
            &[0, 0, 0, 0, 2, 9],
            &[0, 0, 0, 0, 0, 1],
            &[0, 255, 255, 255, 255],
        ] {
            assert!(unframe(bad).is_err());
        }
        // Arbitrary bytes never panic the decoders.
        for m in ["Check", "Run", "GetRun", "PutBlob", "GetCatalog"] {
            for i in 0..=255u8 {
                let _ = decode_request(m, &[i, i.wrapping_mul(7), 0xff, i]);
            }
        }
    }
}
