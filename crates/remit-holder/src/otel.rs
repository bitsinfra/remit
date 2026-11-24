//! OpenTelemetry export: one trace per remit with a span per admission stage
//! plus the execution span, sent as OTLP/HTTP JSON to
//! `[holder] otlp_endpoint` (e.g. `http://127.0.0.1:4318`). Fire-and-forget;
//! attributes are bucketed and never include params or results.

use serde_json::{json, Value};

use crate::admission::Stage;

fn hex(n: usize) -> String {
    (0..n)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

fn attr(k: &str, v: &str) -> Value {
    json!({"key": k, "value": {"stringValue": v}})
}

/// Build an OTLP `ExportTraceServiceRequest` (JSON encoding).
pub fn trace_request(
    holder: &str,
    remit_id: &str,
    status: &str,
    trace: &[Stage],
    exec_start_ns: u128,
    exec_end_ns: u128,
) -> Value {
    let trace_id = hex(16);
    let root = hex(8);
    let total: u64 = trace.iter().map(|s| s.us).sum();
    let start = exec_start_ns.saturating_sub(total as u128 * 1000);
    let mut spans = vec![json!({
        "traceId": trace_id, "spanId": root, "name": "remit", "kind": 2,
        "startTimeUnixNano": start.to_string(), "endTimeUnixNano": exec_end_ns.to_string(),
        "attributes": [attr("remit.id", remit_id), attr("remit.status", status)],
        "status": {"code": if status == "ok" { 1 } else { 2 }},
    })];
    let mut t = start;
    for s in trace {
        let end = t + s.us as u128 * 1000;
        spans.push(json!({"traceId": trace_id, "spanId": hex(8), "parentSpanId": root, "name": format!("admission.{}", s.stage),
            "kind": 1, "startTimeUnixNano": t.to_string(), "endTimeUnixNano": end.to_string()}));
        t = end;
    }
    spans.push(json!({"traceId": trace_id, "spanId": hex(8), "parentSpanId": root, "name": "execute", "kind": 1,
        "startTimeUnixNano": exec_start_ns.to_string(), "endTimeUnixNano": exec_end_ns.to_string()}));
    json!({"resourceSpans": [{
        "resource": {"attributes": [attr("service.name", "remit-holder"), attr("remit.holder", holder)]},
        "scopeSpans": [{"scope": {"name": "remit", "version": env!("CARGO_PKG_VERSION")}, "spans": spans}],
    }]})
}

pub fn export(endpoint: &str, body: Value) {
    let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        if let Err(e) = client
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            tracing::debug!("otlp export failed: {e}");
        }
    });
}

pub fn now_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// OTLP metrics (`/v1/metrics`): monotonic counters and gauges, no per-Sender
/// dimensions.
pub fn metrics_request(holder: &str, m: &Value, start_ns: u128, now: u128) -> Value {
    let mut metrics = Vec::new();
    for (k, v) in m.as_object().into_iter().flatten() {
        let Some(n) = v.as_u64() else { continue };
        let point = json!([{"asInt": n.to_string(), "startTimeUnixNano": start_ns.to_string(), "timeUnixNano": now.to_string()}]);
        metrics.push(if matches!(k.as_str(), "running" | "queued" | "nonces") {
            json!({"name": format!("remit.{k}"), "gauge": {"dataPoints": point}})
        } else {
            json!({"name": format!("remit.{k}"), "sum": {"aggregationTemporality": 2, "isMonotonic": true, "dataPoints": point}})
        });
    }
    json!({"resourceMetrics": [{
        "resource": {"attributes": [attr("service.name", "remit-holder"), attr("remit.holder", holder)]},
        "scopeMetrics": [{"scope": {"name": "remit", "version": env!("CARGO_PKG_VERSION")}, "metrics": metrics}],
    }]})
}

/// Export metrics periodically while the Holder lives.
pub fn start_metrics(h: &std::sync::Arc<crate::state::Holder>) {
    let Some(ep) = h.cfg.holder.otlp_endpoint.clone() else {
        return;
    };
    let weak = std::sync::Arc::downgrade(h);
    let start = now_ns();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let url = format!("{}/v1/metrics", ep.trim_end_matches('/'));
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let Some(h) = weak.upgrade() else { return };
            let body = metrics_request(h.id(), &crate::http::metrics_json(&h), start, now_ns());
            drop(h);
            let _ = client
                .post(&url)
                .json(&body)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_shape() {
        let v = metrics_request(
            "did:web:h",
            &json!({"admitted": 3, "queued": 1, "receipts": {"seq": 1}}),
            1,
            2,
        );
        let m = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        assert_eq!(m.len(), 2);
        assert!(m
            .iter()
            .any(|x| x["name"] == "remit.admitted" && x["sum"]["isMonotonic"] == true));
        assert!(m
            .iter()
            .any(|x| x["name"] == "remit.queued" && x["gauge"].is_object()));
    }
}
