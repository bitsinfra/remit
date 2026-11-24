//! The remit manifest (spec/manifest.md).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{jcs, sha256_hex, WireError};

pub const REMIT_VERSION: &str = "0.1";
pub const MANIFEST_MAX_BYTES: usize = 64 * 1024;
pub const INLINE_CODE_MAX_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Query,
    Kernel,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Query => "query",
            Mode::Kernel => "kernel",
        }
    }
}

/// Declared type of a read-template param.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    Timestamp,
    Date,
    Int,
    Float,
    String,
    Bool,
}

impl ParamType {
    pub fn as_str(self) -> &'static str {
        match self {
            ParamType::Timestamp => "timestamp",
            ParamType::Date => "date",
            ParamType::Int => "int",
            ParamType::Float => "float",
            ParamType::String => "string",
            ParamType::Bool => "bool",
        }
    }
}

fn one() -> u32 {
    1
}

/// A declared, typed, parameterized read template.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadTemplate {
    pub sql: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ParamType>,
    pub max_rows: u64,
    #[serde(default = "one")]
    pub max_calls: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub lang: String,
    #[serde(default = "default_entry")]
    pub entry: String,
    pub source_sha256: String,
    /// Inline source; absent when uploaded via `PUT /remit/v1/blobs/{sha256}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

fn default_entry() -> String {
    "main".into()
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_rows: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epsilon: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<f64>,
    /// Sender pre-commitment below the type capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub remit: String,
    pub sender: String,
    pub holder: String,
    pub issued_at: String,
    pub expires_at: String,
    pub nonce: String,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority: Vec<String>,
    pub mode: Mode,
    pub reads: BTreeMap<String, ReadTemplate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// Absent for a template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Map<String, Value>>,
    #[serde(default)]
    pub limits: Limits,
    /// RT JSON, or a JSON Schema 2020-12 document (detected by `$schema` or `type`).
    pub returns: Value,
}

impl Manifest {
    /// Parse and structurally validate a manifest from JSON bytes.
    pub fn from_slice(b: &[u8]) -> Result<Self, WireError> {
        if b.len() > MANIFEST_MAX_BYTES + INLINE_CODE_MAX_BYTES {
            return Err(WireError::TooLarge(
                "manifest",
                MANIFEST_MAX_BYTES + INLINE_CODE_MAX_BYTES,
            ));
        }
        let m: Manifest =
            serde_json::from_slice(b).map_err(|e| WireError::Decode(e.to_string()))?;
        m.check_structure()?;
        Ok(m)
    }

    pub fn from_value(v: Value) -> Result<Self, WireError> {
        let m: Manifest =
            serde_json::from_value(v).map_err(|e| WireError::Decode(e.to_string()))?;
        m.check_structure()?;
        Ok(m)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("manifest serializes")
    }

    /// Structural checks that do not need the catalog.
    pub fn check_structure(&self) -> Result<(), WireError> {
        if self.remit != REMIT_VERSION && !self.remit.starts_with("0.1.") {
            return Err(WireError::Invalid(
                "/remit",
                format!("unsupported remit version `{}`", self.remit),
            ));
        }
        if self.nonce.len() < 8 || self.nonce.len() > 128 {
            return Err(WireError::Invalid(
                "/nonce",
                "nonce must be 8..=128 characters".into(),
            ));
        }
        // The purpose is a vocabulary token, never prose: it reaches policy,
        // access cards and logs.
        if !is_token(&self.purpose) {
            return Err(WireError::Invalid(
                "/purpose",
                "purpose must be 1..=64 characters of [A-Za-z0-9_.:-]".into(),
            ));
        }
        if self.reads.is_empty() {
            return Err(WireError::Invalid(
                "/reads",
                "at least one read template is required".into(),
            ));
        }
        for (name, r) in &self.reads {
            if !is_ident(name) {
                return Err(WireError::Invalid(
                    "/reads",
                    format!("read name `{name}` must be an identifier"),
                ));
            }
            if r.max_rows == 0 {
                return Err(WireError::Invalid(
                    "/reads",
                    format!("`{name}.max_rows` must be ≥ 1"),
                ));
            }
            if r.max_calls == 0 {
                return Err(WireError::Invalid(
                    "/reads",
                    format!("`{name}.max_calls` must be ≥ 1"),
                ));
            }
        }
        match self.mode {
            Mode::Query => {
                if self.code.is_some() {
                    return Err(WireError::Invalid("/code", "query mode has no code".into()));
                }
                if self.reads.len() != 1 {
                    return Err(WireError::Invalid(
                        "/reads",
                        "query mode takes exactly one root read".into(),
                    ));
                }
            }
            Mode::Kernel => {
                let c = self.code.as_ref().ok_or(WireError::Invalid(
                    "/code",
                    "kernel mode requires code".into(),
                ))?;
                if let Some(src) = &c.source {
                    if src.len() > INLINE_CODE_MAX_BYTES {
                        return Err(WireError::TooLarge("inline code", INLINE_CODE_MAX_BYTES));
                    }
                    let h = sha256_hex(src.as_bytes());
                    if !eq_hash(&c.source_sha256, &h) {
                        return Err(WireError::Invalid(
                            "/code/source_sha256",
                            "does not match the inline source".into(),
                        ));
                    }
                }
                if !is_ident(&c.entry) {
                    return Err(WireError::Invalid(
                        "/code/entry",
                        "entry must be an identifier".into(),
                    ));
                }
            }
        }
        chrono::DateTime::parse_from_rfc3339(&self.issued_at)
            .map_err(|_| WireError::Invalid("/issued_at", "must be RFC 3339".into()))?;
        chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| WireError::Invalid("/expires_at", "must be RFC 3339".into()))?;
        Ok(())
    }

    /// The program's identity: hash over `{remit, mode, purpose, reads, code, limits, returns}`.
    /// Excludes sender, holder, authority, params, nonce and timestamps. Inline
    /// source is excluded (it is bound by `source_sha256`).
    pub fn remit_id(&self) -> String {
        let mut code = self.code.clone();
        if let Some(c) = code.as_mut() {
            c.source = None;
            c.source_sha256 = normalize_hash(&c.source_sha256);
        }
        let v = json!({
            "remit": self.remit,
            "mode": self.mode,
            "purpose": self.purpose,
            "reads": self.reads,
            "code": code,
            "limits": self.limits,
            "returns": self.returns,
        });
        format!(
            "sha256:{}",
            sha256_hex(&jcs::canonical_bytes(&v).expect("manifest is canonicalizable"))
        )
    }

    /// Hash of the params (empty object for templates).
    pub fn params_sha256(&self) -> String {
        let p = self
            .params
            .clone()
            .map(Value::Object)
            .unwrap_or_else(|| json!({}));
        format!(
            "sha256:{}",
            sha256_hex(&jcs::canonical_bytes(&p).unwrap_or_default())
        )
    }

    pub fn is_template(&self) -> bool {
        self.params.is_none()
    }

    pub fn issued_at_ms(&self) -> i64 {
        chrono::DateTime::parse_from_rfc3339(&self.issued_at)
            .map(|d| d.timestamp_millis())
            .unwrap_or(0)
    }

    pub fn expires_at_ms(&self) -> i64 {
        chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|d| d.timestamp_millis())
            .unwrap_or(0)
    }

    /// Type of each top-level param, inferred from the read templates that
    /// declare a param of the same name (spec/manifest.md §params).
    pub fn param_types(&self) -> BTreeMap<String, ParamType> {
        let mut out = BTreeMap::new();
        for r in self.reads.values() {
            for (k, t) in &r.params {
                out.entry(k.clone()).or_insert(*t);
            }
        }
        out
    }
}

pub fn normalize_hash(h: &str) -> String {
    h.strip_prefix("sha256:").unwrap_or(h).to_ascii_lowercase()
}

pub fn eq_hash(a: &str, b: &str) -> bool {
    normalize_hash(a) == normalize_hash(b)
}

/// A vocabulary token (purposes, labels).
pub fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

pub fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && s.len() <= 64
}
