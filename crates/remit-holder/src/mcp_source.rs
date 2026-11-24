//! Sidecar mode: front an existing MCP server's data. Each configured tool is
//! called once per snapshot over MCP's HTTP transport and its rows become a
//! policy-protected table; Senders never reach the MCP server itself.

use std::time::Duration;

use anyhow::{anyhow, Context as _};
use remit_read::{SourceConfig, Store};
use serde_json::{json, Value};

const MAX_BYTES: usize = 64 << 20;

fn find_rows(v: &Value) -> Option<Vec<Value>> {
    match v {
        Value::Array(a) if a.iter().all(Value::is_object) => Some(a.clone()),
        Value::Object(o) => o.values().find_map(find_rows),
        _ => None,
    }
}

/// Rows of a `tools/call` result.
pub fn rows_of(result: &Value, pointer: Option<&str>) -> Option<Vec<Value>> {
    let sc = result.get("structuredContent").cloned().or_else(|| {
        let t = result["content"]
            .as_array()?
            .iter()
            .find_map(|c| c["text"].as_str())?;
        serde_json::from_str(t).ok()
    })?;
    match pointer {
        Some(p) => sc.pointer(p).and_then(find_rows),
        None => find_rows(&sc),
    }
}

pub async fn load(src: &SourceConfig, store: &mut Store) -> anyhow::Result<()> {
    let url = src
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("source `{}` needs `url`", src.name))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    for (i, (table, t)) in src.tools.iter().enumerate() {
        let req = json!({"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": {"name": t.tool, "arguments": t.arguments}});
        let mut resp = client
            .post(url)
            .header("accept", "application/json")
            .header("mcp-method", "tools/call")
            .header("mcp-name", &t.tool)
            .json(&req)
            .send()
            .await
            .with_context(|| format!("mcp source `{}`", src.name))?;
        let mut buf = Vec::new();
        while let Some(c) = resp.chunk().await? {
            buf.extend_from_slice(&c);
            anyhow::ensure!(
                buf.len() <= MAX_BYTES,
                "mcp source `{}`: response too large",
                src.name
            );
        }
        let v: Value = serde_json::from_slice(&buf)?;
        anyhow::ensure!(
            v.get("error").is_none() && v["result"]["isError"] != json!(true),
            "mcp source `{}`: tool `{}` failed",
            src.name,
            t.tool
        );
        let rows = rows_of(&v["result"], t.rows.as_deref()).ok_or_else(|| {
            anyhow!(
                "mcp source `{}`: tool `{}` returned no rows",
                src.name,
                t.tool
            )
        })?;
        store
            .insert_json(&format!("{}.{}", src.name, table), &rows)
            .map_err(|e| anyhow!("{e}"))?;
    }
    Ok(())
}
