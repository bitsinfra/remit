//! Remit read plane (trusted, main process).
//!
//! * Each resource is exposed through a **policy view**: hidden columns do not
//!   exist, masks/casts/clamps are applied, row filters and owner filters are
//!   always on. Views are inlined into the Sender's plan before optimization,
//!   so policy is enforced *in the plan*, whatever the Sender's SQL says.
//! * k-thresholds are injected into every aggregate over a protected table.
//! * Scans are metered (rows/bytes) per remit, memory is capped per remit by a
//!   DataFusion memory pool, and reads are pinned to immutable snapshots.

pub mod arrowconv;
pub mod config;
pub mod dp;
#[cfg(feature = "duckdb")]
pub mod duck;
pub mod lakehouse;
#[cfg(feature = "lance")]
pub mod lance_db;
#[cfg(feature = "mysql")]
pub mod mysql;
pub mod plane;
pub mod postgres;
#[cfg(feature = "object-store")]
mod remote;
pub mod search;
pub mod store;
#[cfg(feature = "tantivy")]
mod tantivy_index;

pub use config::{ColumnConfig, DpConfig, ResourceConfig, SourceConfig};
pub use dp::{DpOut, DpShape};
pub use plane::{
    OutputKind, PlanFacts, Principal, ReadLimits, ReadOutput, ReadPlane, ScanCounter, TableFacts,
};
pub use search::IndexConfig;
pub use store::{RawTable, Store};

use datafusion::error::DataFusionError;

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("configuration: {0}")]
    Config(String),
    /// Planning/binding failure, phrased in visible-catalog terms.
    #[error("{0}")]
    Plan(String),
    #[error("{0}")]
    Param(String),
    #[error(
        "`{0}` is aggregate-only: every read of it must go through GROUP BY / aggregate functions"
    )]
    AggregateOnly(String),
    #[error("aggregations over `{0}` must keep `{1}` available to the aggregate (the k-threshold counts distinct `{1}`)")]
    PrivacyUnit(String, String),
    #[error("{0}")]
    Dp(String),
    #[error("row cap exceeded")]
    RowCap,
    #[error("scan cap exceeded")]
    ScanCap,
    #[error("memory limit exceeded")]
    Memory,
    #[error("wall-time limit exceeded")]
    Timeout,
    #[error("internal: {0}")]
    Internal(String),
}

impl ReadError {
    pub fn code(&self) -> &'static str {
        match self {
            ReadError::Config(_) => "RMT-E0300",
            ReadError::Plan(_) => "RMT-E0301",
            ReadError::Param(_) => "RMT-E0305",
            ReadError::AggregateOnly(_) => "RMT-E0304",
            ReadError::PrivacyUnit(_, _) => "RMT-E0306",
            ReadError::Dp(_) => "RMT-E0161",
            ReadError::RowCap | ReadError::ScanCap | ReadError::Memory | ReadError::Timeout => {
                "RMT-E0400"
            }
            ReadError::Internal(_) => "RMT-E0500",
        }
    }

    /// True for runtime limit hits (reported as `limit_exceeded`).
    pub fn is_limit(&self) -> bool {
        matches!(
            self,
            ReadError::RowCap | ReadError::ScanCap | ReadError::Memory | ReadError::Timeout
        )
    }

    pub(crate) fn plan(e: DataFusionError) -> Self {
        let e = e.find_root().to_string();
        ReadError::Plan(clean_message(&e))
    }

    pub(crate) fn exec(e: DataFusionError) -> Self {
        let s = e.to_string();
        if s.contains(plane::SCAN_CAP_MSG) {
            ReadError::ScanCap
        } else if matches!(e.find_root(), DataFusionError::ResourcesExhausted(_))
            || s.contains("Resources exhausted")
        {
            ReadError::Memory
        } else {
            ReadError::Internal(s)
        }
    }
}

impl From<DataFusionError> for ReadError {
    fn from(e: DataFusionError) -> Self {
        ReadError::plan(e)
    }
}

/// Strip DataFusion internals (catalog prefixes, raw scan aliases) from messages.
fn clean_message(s: &str) -> String {
    let s = s
        .replace("Error during planning: ", "")
        .replace("Schema error: ", "")
        .replace("SQL error: ", "")
        .replace("datafusion.", "");
    let s = regex_lite_replace(&s, "__raw_", "");
    if s.contains("table '") && s.contains("not found") {
        if let Some(start) = s.find("table '") {
            let rest = &s[start + 7..];
            if let Some(end) = rest.find('\'') {
                return format!("relation `{}` does not exist", &rest[..end]);
            }
        }
    }
    s
}

fn regex_lite_replace(s: &str, pat: &str, with: &str) -> String {
    s.replace(pat, with)
}

#[cfg(test)]
mod tests;
