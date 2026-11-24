//! `remit.toml`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use remit_analyze::HolderLimits;
use remit_policy::{BudgetConfig, PrincipalInfo};
use remit_read::{ResourceConfig, SourceConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderSection {
    pub id: String,
    #[serde(default = "d_listen")]
    pub listen: String,
    /// inprocess | process | microvm (Linux + KVM; see `[runtime.microvm]`)
    #[serde(default = "d_isolation")]
    pub isolation: String,
    /// Path to the Holder identity file (`remit keygen`). Relative to the config.
    #[serde(default)]
    pub identity: Option<String>,
    /// Receipts, ledger WAL, blobs, engine cache.
    #[serde(default = "d_data_dir")]
    pub data_dir: String,
    /// Salt for `mask = "hash"` columns (`env:NAME` reads an env var).
    #[serde(default)]
    pub mask_salt: Option<String>,
    /// Allow `explain` (cost buckets) in /check responses.
    #[serde(default = "yes")]
    pub explain: bool,
    /// Accept self-certifying `did:key` Senders that are not registered.
    #[serde(default = "yes")]
    pub allow_did_key: bool,
    /// Max manifest validity window.
    #[serde(default = "d_validity")]
    pub max_validity_s: i64,
    /// Allowed clock skew for `issued_at`.
    #[serde(default = "d_skew")]
    pub clock_skew_s: i64,
    /// Admin token for `/admin/*` (approvals). `env:NAME` reads an env var.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// TEE evidence embedded in receipts (`[holder.attestation]`).
    #[serde(default)]
    pub attestation: Option<AttestationSection>,
    /// Dev mode: synthetic data; kernel logs are returned to Senders.
    #[serde(default)]
    pub dev: bool,
    /// OTLP/HTTP collector base URL (spans per remit), e.g. `http://127.0.0.1:4318`.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
}

/// Attested receipts: a command that turns `(user data, nonce)` into evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSection {
    /// `nitro` (verifiable by `remit receipts verify --attestation`), `tdx`, `sev-snp`, …
    pub format: String,
    pub command: Vec<String>,
    /// Refuse to answer when evidence cannot be produced.
    #[serde(default = "yes")]
    pub required: bool,
}

fn d_listen() -> String {
    "127.0.0.1:8443".into()
}
fn d_isolation() -> String {
    "process".into()
}
fn d_data_dir() -> String {
    ".remit-holder".into()
}
fn d_validity() -> i64 {
    900
}
fn d_skew() -> i64 {
    120
}
fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilesSection {
    #[serde(default)]
    pub enabled: bool,
    /// One-time ε for published stats profiles.
    #[serde(default = "d_eps")]
    pub epsilon: f64,
}

fn d_eps() -> f64 {
    0.1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeSection {
    #[serde(default = "d_engine")]
    pub engine: String,
    #[serde(default)]
    pub engine_sha256: Option<String>,
    /// Python (Monty) engine component; enables `lang = "python/monty"`.
    #[serde(default)]
    pub python_engine: Option<String>,
    #[serde(default)]
    pub python_engine_sha256: Option<String>,
    #[serde(default = "d_workers")]
    pub workers_per_domain: usize,
    #[serde(default = "d_pool")]
    pub pool_instances: u32,
    /// Concurrent executions (0: one per CPU); the rest queue fairly.
    #[serde(default)]
    pub max_parallel: usize,
    /// Queued executions before the Holder answers 429.
    #[serde(default = "d_queue")]
    pub max_queue: usize,
    /// Total bytes of uploaded code blobs kept.
    #[serde(default = "d_blobs")]
    pub max_blob_bytes: usize,
    /// Guest kernel and VMM for `isolation = "microvm"`.
    #[serde(default)]
    pub microvm: Option<remit_kernel::microvm::MicroVmConfig>,
    #[serde(flatten)]
    pub limits: HolderLimits,
}

fn d_engine() -> String {
    "engines/js/dist/remit_engine_js.wasm".into()
}
fn d_workers() -> usize {
    2
}
fn d_pool() -> u32 {
    64
}
fn d_queue() -> usize {
    1024
}
fn d_blobs() -> usize {
    64 << 20
}

impl Default for RuntimeSection {
    fn default() -> Self {
        RuntimeSection {
            engine: d_engine(),
            engine_sha256: None,
            python_engine: None,
            python_engine_sha256: None,
            workers_per_domain: d_workers(),
            pool_instances: d_pool(),
            max_parallel: 0,
            max_queue: d_queue(),
            max_blob_bytes: d_blobs(),
            microvm: None,
            limits: HolderLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSection {
    pub id: String,
    /// `did:key:z…` public keys allowed to sign for this id.
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Worker-process trust domain (default: first group, else the id).
    #[serde(default)]
    pub trust_domain: Option<String>,
}

impl PrincipalSection {
    pub fn info(&self) -> PrincipalInfo {
        PrincipalInfo {
            id: self.id.clone(),
            groups: self.groups.clone(),
            org: self.org.clone(),
            verified: self.verified,
            tags: self.tags.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySection {
    /// Trusted Biscuit root public keys (`ed25519/<hex>`).
    #[serde(default)]
    pub roots: Vec<String>,
}

/// A standing approval: `(remit_id, principal constraint, param constraint)`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSection {
    pub remit_id: String,
    /// Exact principal id, `group:<name>`, or `*`.
    #[serde(default = "star")]
    pub principal: String,
    /// Param constraints, e.g. `{ max_span = { from = "from", until = "until", max = "31d" } }`.
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

fn star() -> String {
    "*".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleSection {
    pub title: String,
    /// Path to an example manifest (JSON) relative to the config.
    pub file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub holder: HolderSection,
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceConfig>,
    /// `[catalog."source.table"]` resource configs plus `[catalog.profiles]`.
    #[serde(default)]
    pub catalog: BTreeMap<String, Value>,
    #[serde(default)]
    pub policy: PolicySection,
    #[serde(default)]
    pub budgets: BudgetConfig,
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default, rename = "principal")]
    pub principals: Vec<PrincipalSection>,
    #[serde(default)]
    pub authority: AuthoritySection,
    #[serde(default, rename = "approval")]
    pub approvals: Vec<ApprovalSection>,
    #[serde(default, rename = "example")]
    pub examples: Vec<ExampleSection>,
    /// `[identity]` sender identity resolution and transport signatures.
    #[serde(default)]
    pub identity: crate::identity::IdentitySection,
    /// `[[index]]` search indexes (`fts` / `knn` table functions).
    #[serde(default, rename = "index")]
    pub indexes: Vec<remit_read::IndexConfig>,
    /// Directory the config was loaded from (resolves relative paths).
    #[serde(skip)]
    pub base: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let mut c: Config =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        c.base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        if c.base.as_os_str().is_empty() {
            c.base = PathBuf::from(".");
        }
        Ok(c)
    }

    pub fn from_str(text: &str, base: &Path) -> anyhow::Result<Config> {
        let mut c: Config = toml::from_str(text)?;
        c.base = base.to_path_buf();
        Ok(c)
    }

    pub fn resolve(&self, p: &str) -> PathBuf {
        let p = Path::new(p);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base.join(p)
        }
    }

    pub fn resources(&self) -> anyhow::Result<BTreeMap<String, ResourceConfig>> {
        let mut out = BTreeMap::new();
        for (k, v) in &self.catalog {
            if k == "profiles" {
                continue;
            }
            let r: ResourceConfig = serde_json::from_value(v.clone())
                .map_err(|e| anyhow::anyhow!("catalog `{k}`: {e}"))?;
            out.insert(k.to_lowercase(), r);
        }
        Ok(out)
    }

    pub fn profiles(&self) -> ProfilesSection {
        self.catalog
            .get("profiles")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }
}

/// Resolve `env:NAME` indirections.
pub fn secret(v: &Option<String>) -> Option<String> {
    v.as_ref().map(|s| match s.strip_prefix("env:") {
        Some(name) => std::env::var(name).unwrap_or_default(),
        None => s.clone(),
    })
}
