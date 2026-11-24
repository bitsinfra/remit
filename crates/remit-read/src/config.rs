//! Holder-side resource configuration (the `[[source]]` and `[catalog."x.y"]`
//! sections of `remit.toml`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub name: String,
    /// csv | parquet | json | sqlite | postgres | mysql | duckdb | delta | iceberg | memory
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    /// For file sources: the table name (default: file stem).
    #[serde(default)]
    pub table: Option<String>,
    /// For sqlite / postgres: tables to load (default: all for sqlite).
    #[serde(default)]
    pub tables: Vec<String>,
    /// For postgres / mysql: connection string (`env:NAME` reads an env var).
    #[serde(default)]
    pub dsn: Option<String>,
    /// For mcp: the server's HTTP endpoint.
    #[serde(default)]
    pub url: Option<String>,
    /// For mcp: table name → tool call that returns its rows.
    #[serde(default)]
    pub tools: BTreeMap<String, McpTool>,
    /// For delta / iceberg: pin a table version / snapshot id (default: latest).
    #[serde(default)]
    pub snapshot: Option<i64>,
    /// For `s3://` / `gs://` / `az://` paths: refuse a source larger than this
    /// (default 4 GiB).
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Reload the source this often (each load is a new pinned snapshot).
    #[serde(default)]
    pub refresh_s: Option<u64>,
}

/// A read-only tool on an existing MCP server whose result is a table.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpTool {
    pub tool: String,
    #[serde(default)]
    pub arguments: serde_json::Map<String, serde_json::Value>,
    /// JSON pointer to the row array inside `structuredContent` (default: auto).
    #[serde(default)]
    pub rows: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ColumnConfig {
    /// Hidden columns do not exist for Senders.
    #[serde(default = "yes")]
    pub expose: bool,
    /// hash | null | redact | trunc:<unit> (date_trunc unit)
    #[serde(default)]
    pub mask: Option<String>,
    /// Cast on read: timestamp | date | int | float | string | bool
    #[serde(rename = "type", default)]
    pub ty: Option<String>,
    /// Publish the column's distinct values in the catalog as an enum.
    #[serde(rename = "enum", default)]
    pub publish_enum: bool,
    #[serde(default)]
    pub description: Option<String>,
    /// Clamp bounds for DP sums (dp-governed tables).
    #[serde(default)]
    pub bounds: Option<[f64; 2]>,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DpConfig {
    /// ε budget per day (global per dataset).
    pub epsilon_per_day: f64,
    /// Max ε a single remit may spend.
    #[serde(default)]
    pub max_epsilon_per_remit: Option<f64>,
    /// Rows one privacy unit may contribute to an answer (contribution bound).
    #[serde(default = "one")]
    pub max_contributions: u64,
    /// δ per remit for τ-thresholding of group keys (and Gaussian noise).
    #[serde(default = "d_delta")]
    pub delta: f64,
    /// laplace (pure ε) | gaussian (zCDP)
    #[serde(default = "d_mech")]
    pub mechanism: String,
    /// ε for the lifetime of the dataset (never resets).
    #[serde(default)]
    pub epsilon_lifetime: Option<f64>,
}

fn one() -> u64 {
    1
}

fn d_delta() -> f64 {
    1e-6
}

fn d_mech() -> String {
    "laplace".into()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    /// low | medium | high
    #[serde(default)]
    pub sensitivity: Option<String>,
    /// Allowed operations: read, aggregate, search, call (default: read, aggregate).
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub purposes: Vec<String>,
    /// Bit cap per remit (policy hint + Cedar resource attribute).
    #[serde(default)]
    pub max_bits: Option<u64>,
    #[serde(default)]
    pub aggregate_only: bool,
    /// k-threshold enforced in the plan.
    #[serde(default)]
    pub k: Option<u64>,
    /// Column identifying the privacy unit (k counts distinct units).
    #[serde(default)]
    pub privacy_unit: Option<String>,
    /// SQL predicate over raw columns, always applied.
    #[serde(default)]
    pub row_filter: Option<String>,
    /// Owner-rows-only: rows where this column equals the principal id.
    #[serde(default)]
    pub owner_column: Option<String>,
    /// Groups allowed to see the resource (empty: everyone).
    #[serde(default)]
    pub visible_to: Vec<String>,
    /// required | first-use | never
    #[serde(default)]
    pub approval: Option<String>,
    #[serde(default)]
    pub retain_days: Option<u64>,
    #[serde(default)]
    pub forward: Option<bool>,
    /// Pad responses touching this resource to a fixed latency class (ms).
    #[serde(default)]
    pub pad_ms: Option<u64>,
    #[serde(default)]
    pub dp: Option<DpConfig>,
    #[serde(default)]
    pub columns: BTreeMap<String, ColumnConfig>,
}

impl ResourceConfig {
    pub fn operations(&self) -> Vec<String> {
        if self.operations.is_empty() {
            vec!["read".into(), "aggregate".into()]
        } else {
            self.operations.clone()
        }
    }
    pub fn column(&self, name: &str) -> ColumnConfig {
        self.columns.get(name).cloned().unwrap_or(ColumnConfig {
            expose: true,
            ..Default::default()
        })
    }
    pub fn visible_to_groups(&self, groups: &[String]) -> bool {
        self.visible_to.is_empty() || self.visible_to.iter().any(|g| groups.contains(g))
    }
}
