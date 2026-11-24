//! Holder state: everything the admission pipeline and planes share.

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context as _};
use lru::LruCache;
use parking_lot::Mutex;
use remit_analyze::Analysis;
use remit_kernel::{EngineConfig, KernelEngine, WorkerPool};
use remit_policy::{
    presets, Actual, Ask, BudgetError, Ledger, PolicyEngine, PrincipalInfo, Reservation,
};
use remit_read::{ReadPlane, ResourceConfig, Store};
use remit_receipt::ReceiptLog;
use remit_wire::Signer;
use serde_json::{json, Value};

use crate::approvals::Approvals;
use crate::config::{secret, Config, PrincipalSection};
use crate::identity::{KeyCache, Transport};

#[derive(Clone, Debug)]
pub struct CachedResult {
    pub value: Value,
    pub result_sha256: String,
    pub execution: Option<remit_receipt::ExecutionContext>,
    /// Principals that already paid for (and received) this answer.
    pub seen_by: std::collections::HashSet<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RunRecord {
    pub run_id: String,
    pub state: String,
    pub response: Option<Value>,
    #[serde(skip)]
    pub at_ms: i64,
}

/// Recent runs (bounded in number and age).
#[derive(Default)]
pub struct Runs(
    HashMap<String, RunRecord>,
    std::collections::VecDeque<String>,
);

impl Runs {
    const MAX: usize = 10_000;
    const TTL_MS: i64 = 3_600_000;

    pub fn put(&mut self, run_id: &str, state: &str, response: Option<Value>, now_ms: i64) {
        if self
            .0
            .insert(
                run_id.to_string(),
                RunRecord {
                    run_id: run_id.into(),
                    state: state.into(),
                    response,
                    at_ms: now_ms,
                },
            )
            .is_none()
        {
            self.1.push_back(run_id.to_string());
        }
        while self.1.len() > Self::MAX
            || self
                .1
                .front()
                .and_then(|f| self.0.get(f))
                .is_some_and(|r| r.at_ms + Self::TTL_MS < now_ms)
        {
            if let Some(old) = self.1.pop_front() {
                self.0.remove(&old);
            }
        }
    }
    pub fn get(&self, id: &str) -> Option<RunRecord> {
        self.0.get(id).cloned()
    }
}

/// Uploaded code, content-addressed, bounded by total size (oldest first out).
#[derive(Default)]
pub struct Blobs {
    map: HashMap<String, String>,
    order: std::collections::VecDeque<String>,
    bytes: usize,
    max: usize,
    dir: PathBuf,
}

impl Blobs {
    fn open(dir: PathBuf, max: usize) -> Blobs {
        let mut b = Blobs {
            dir,
            max,
            ..Default::default()
        };
        if let Ok(rd) = std::fs::read_dir(&b.dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Ok(s) = std::fs::read_to_string(e.path()) {
                    if remit_wire::sha256_hex(s.as_bytes()) == name {
                        b.insert(name, s);
                    }
                }
            }
        }
        b
    }
    fn insert(&mut self, sha: String, text: String) {
        self.bytes += text.len();
        if let Some(old) = self.map.insert(sha.clone(), text) {
            self.bytes -= old.len();
        } else {
            self.order.push_back(sha);
        }
        while self.bytes > self.max && self.order.len() > 1 {
            if let Some(o) = self.order.pop_front() {
                if let Some(t) = self.map.remove(&o) {
                    self.bytes -= t.len();
                }
                let _ = std::fs::remove_file(self.dir.join(&o));
            }
        }
    }
    /// Store a blob under its hash (the caller checked the hash).
    pub fn put(&mut self, sha: String, text: String) {
        if !self.map.contains_key(&sha) {
            let _ = std::fs::create_dir_all(&self.dir);
            let _ = std::fs::write(self.dir.join(&sha), &text);
        }
        self.insert(sha, text);
    }
    pub fn get(&self, sha: &str) -> Option<&String> {
        self.map.get(sha)
    }
}

#[derive(Default, Debug)]
pub struct Metrics {
    pub admitted: std::sync::atomic::AtomicU64,
    /// Admissions covered by a standing approval (an adoption metric).
    pub standing: std::sync::atomic::AtomicU64,
    pub rejected: std::sync::atomic::AtomicU64,
    pub runs_ok: std::sync::atomic::AtomicU64,
    pub runs_failed: std::sync::atomic::AtomicU64,
    pub plan_cache_hits: std::sync::atomic::AtomicU64,
    pub result_cache_hits: std::sync::atomic::AtomicU64,
}

/// Budget ledger: local (WAL) or shared by replicas (Postgres).
pub enum Budgets {
    Local(Box<Ledger>),
    Shared(Box<remit_policy::shared::SharedLedger>),
}

impl Budgets {
    pub async fn reserve(&self, ask: &Ask, now: i64) -> Result<Reservation, BudgetError> {
        match self {
            Budgets::Local(l) => l.reserve(ask, now),
            Budgets::Shared(s) => s.reserve(ask, now).await.map_err(|e| match e {
                remit_policy::shared::SharedError::Budget(b) => b,
                remit_policy::shared::SharedError::Db(m) => {
                    tracing::error!("shared ledger: {m}");
                    BudgetError::Unavailable
                }
            }),
        }
    }
    pub async fn settle(&self, r: &Reservation, a: Actual) {
        match self {
            Budgets::Local(l) => l.settle(r, a),
            Budgets::Shared(s) => {
                if let Err(e) = s.settle(r, a).await {
                    tracing::error!("shared ledger settle failed: {e}");
                }
            }
        }
    }
}

pub enum EngineHandle {
    InProcess(Arc<KernelEngine>),
    Process {
        pool: Arc<WorkerPool>,
        engine_sha256: String,
    },
}

impl EngineHandle {
    pub fn sha256(&self) -> String {
        match self {
            EngineHandle::InProcess(e) => e.engine_sha256().to_string(),
            EngineHandle::Process { engine_sha256, .. } => engine_sha256.clone(),
        }
    }
}

pub enum Isolation {
    /// Kernel engines by language (`js/es2023`, `python/monty`).
    Engines(std::collections::BTreeMap<String, EngineHandle>),
    /// Query-mode only Holder (no engine configured).
    None,
}

/// Canonical kernel language name (`js` → `js/es2023`).
pub fn canonical_lang(l: &str) -> &str {
    match l {
        "js" | "javascript" | "ts" | "typescript" => "js/es2023",
        "python" | "py" => "python/monty",
        other => other,
    }
}

pub struct Holder {
    pub cfg: Config,
    pub signer: Signer,
    plane: parking_lot::RwLock<Arc<ReadPlane>>,
    pub functions: Arc<crate::functions::Functions>,
    pub resources: BTreeMap<String, ResourceConfig>,
    pub policy: PolicyEngine,
    pub ledger: Budgets,
    pub receipts: ReceiptLog,
    pub isolation: Isolation,
    pub principals: HashMap<String, PrincipalSection>,
    pub biscuit_roots: Vec<biscuit_auth::PublicKey>,
    pub nonces: crate::replay::ReplayCache,
    pub keys: KeyCache,
    pub sched: Arc<crate::sched::Scheduler>,
    /// Aliases for identity resolution live in `cfg.identity`.
    pub started_ms: i64,
    pub analysis_cache: Mutex<LruCache<String, Arc<Analysis>>>,
    pub result_cache: Mutex<LruCache<String, CachedResult>>,
    pub runs: Mutex<Runs>,
    pub blobs: Mutex<Blobs>,
    pub approvals: Approvals,
    pub examples: Vec<Value>,
    pub stats: parking_lot::RwLock<Value>,
    pub catalog_cache: Mutex<HashMap<Vec<String>, (Value, String)>>,
    pub metrics: Metrics,
    pub data_dir: PathBuf,
    /// Builder-supplied tables (kept across refreshes).
    base_store: Store,
}

impl std::fmt::Debug for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Holder")
            .field("id", &self.cfg.holder.id)
            .finish()
    }
}

async fn load_sources(cfg: &Config, store: &mut Store) -> anyhow::Result<()> {
    for s in &cfg.sources {
        if s.kind == "mcp" {
            crate::mcp_source::load(s, store).await?;
        } else {
            store
                .load_source(s, &cfg.base)
                .await
                .map_err(|e| anyhow!("{e}"))?;
        }
    }
    Ok(())
}

/// Extra in-memory data supplied by the Rust builder API.
#[derive(Default)]
pub struct ExtraData {
    pub store: Option<Store>,
    pub signer: Option<Signer>,
    /// Override the worker command for `process` isolation.
    pub worker_command: Option<(PathBuf, Vec<String>)>,
    pub engine_path: Option<PathBuf>,
    pub functions: crate::functions::Functions,
}

impl Holder {
    pub async fn from_config(cfg: Config) -> anyhow::Result<Arc<Holder>> {
        Self::build(cfg, ExtraData::default()).await
    }

    pub async fn build(cfg: Config, extra: ExtraData) -> anyhow::Result<Arc<Holder>> {
        let data_dir = cfg.resolve(&cfg.holder.data_dir);
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("data dir {}", data_dir.display()))?;
        let data_dir = std::fs::canonicalize(&data_dir).unwrap_or(data_dir);
        // Identity.
        let signer = match (extra.signer, &cfg.holder.identity) {
            (Some(s), _) => s,
            (None, Some(p)) => {
                Signer::load(&cfg.resolve(p)).map_err(|e| anyhow!("holder identity: {e}"))?
            }
            (None, None) => {
                let p = data_dir.join("holder-identity.json");
                if p.exists() {
                    Signer::load(&p).map_err(|e| anyhow!("{e}"))?
                } else {
                    let s = Signer::generate(Some(cfg.holder.id.clone()));
                    s.save_new(&p)?;
                    s
                }
            }
        };
        if signer.id() != cfg.holder.id {
            return Err(anyhow!(
                "identity id `{}` does not match holder.id `{}`",
                signer.id(),
                cfg.holder.id
            ));
        }
        // Data.
        let base_store = extra.store.unwrap_or_default();
        let mut store = base_store.clone();
        load_sources(&cfg, &mut store).await?;
        let resources = cfg.resources()?;
        for r in resources.keys() {
            if store.get(r).is_none() {
                return Err(anyhow!("catalog entry `{r}` has no matching source table"));
            }
        }
        let salt = Self::mask_salt(&cfg, &signer);
        let plane = Arc::new(
            ReadPlane::new(&store, &resources, &salt)
                .and_then(|p| p.with_indexes(&cfg.indexes, &store))
                .map_err(|e| anyhow!("{e}"))?,
        );
        // Effective resources: every exposed table, with defaults for unconfigured ones.
        let mut all_res = BTreeMap::new();
        for (name, _) in store.tables() {
            if let Some(r) = plane.resource(name) {
                all_res.insert(name.clone(), r.clone());
            }
        }
        // Policy.
        let mut files = Vec::new();
        for pat in &cfg.policy.files {
            let full = cfg.resolve(pat);
            let mut paths: Vec<PathBuf> = glob::glob(&full.to_string_lossy())
                .map_err(|e| anyhow!("{e}"))?
                .filter_map(Result::ok)
                .collect();
            paths.sort();
            if paths.is_empty() && !pat.contains('*') {
                return Err(anyhow!("policy file {} not found", full.display()));
            }
            for p in paths {
                files.push((p.display().to_string(), std::fs::read_to_string(&p)?));
            }
        }
        let text = presets::assemble(&cfg.policy.presets, &files).map_err(|e| anyhow!(e))?;
        let mut groups: Vec<String> = cfg
            .principals
            .iter()
            .flat_map(|p| p.groups.clone())
            .collect();
        groups.extend(["verified-agents".to_string(), "internal".to_string()]);
        groups.sort();
        groups.dedup();
        let policy = PolicyEngine::new(&text, &all_res, &groups).map_err(|e| anyhow!("{e}"))?;
        // Budgets.
        let mut bcfg = cfg.budgets.clone();
        for (name, r) in &all_res {
            if let Some(dp) = &r.dp {
                let ds = name.split('.').next().unwrap_or(name).to_string();
                if remit_emit::dp::Mechanism::parse(&dp.mechanism).is_none() {
                    return Err(anyhow!(
                        "catalog `{name}`: unknown DP mechanism `{}` (laplace | gaussian)",
                        dp.mechanism
                    ));
                }
                // One budget per dataset: the strictest resource governs.
                let cap = bcfg
                    .epsilon_global_per_day
                    .entry(ds.clone())
                    .or_insert(dp.epsilon_per_day);
                *cap = cap.min(dp.epsilon_per_day);
                if let Some(l) = dp.epsilon_lifetime {
                    let cap = bcfg.epsilon_global_lifetime.entry(ds).or_insert(l);
                    *cap = cap.min(l);
                }
            }
        }
        let ledger = match crate::config::secret(&bcfg.shared_dsn).filter(|d| !d.is_empty()) {
            Some(dsn) => Budgets::Shared(Box::new(
                remit_policy::shared::SharedLedger::connect(&dsn, bcfg)
                    .await
                    .map_err(|e| anyhow!("{e}"))?,
            )),
            None => Budgets::Local(Box::new(Ledger::open(
                bcfg,
                Some(&data_dir.join("ledger.wal")),
            )?)),
        };
        let receipts = ReceiptLog::open(Some(&data_dir.join("receipts.jsonl")))?;
        // Compute plane: one engine (or worker pool) per kernel language.
        let mut cfg = cfg;
        let mut wanted: Vec<(String, PathBuf, Option<String>)> = vec![(
            "js/es2023".into(),
            extra
                .engine_path
                .clone()
                .unwrap_or_else(|| cfg.resolve(&cfg.runtime.engine)),
            cfg.runtime.engine_sha256.clone(),
        )];
        if let Some(p) = &cfg.runtime.python_engine {
            wanted.push((
                "python/monty".into(),
                cfg.resolve(p),
                cfg.runtime.python_engine_sha256.clone(),
            ));
        }
        let kernel_enabled = cfg.runtime.limits.modes.iter().any(|m| m == "kernel");
        let mut engines = std::collections::BTreeMap::new();
        if kernel_enabled {
            for (lang, path, expect) in wanted {
                if !path.exists() {
                    tracing::warn!(
                        "engine component {} not found: `{lang}` kernels disabled",
                        path.display()
                    );
                    continue;
                }
                // Workers run with cwd `/`: pass absolute paths.
                let path = std::fs::canonicalize(&path).unwrap_or(path);
                let sha = remit_wire::sha256_hex(&std::fs::read(&path)?);
                if let Some(exp) = &expect {
                    if !remit_wire::manifest::eq_hash(exp, &sha) {
                        return Err(anyhow!("engine component hash mismatch for `{lang}`"));
                    }
                }
                let handle = match cfg.holder.isolation.as_str() {
                    "inprocess" => EngineHandle::InProcess(
                        KernelEngine::new(EngineConfig {
                            component: path.clone(),
                            sha256: Some(sha.clone()),
                            cache_dir: Some(data_dir.join("engine-cache")),
                            pool_instances: cfg.runtime.pool_instances,
                            max_memory_bytes: cfg.runtime.limits.max_memory_bytes.max(64 << 20),
                            lang: lang.clone(),
                            ..Default::default()
                        })
                        .await?,
                    ),
                    "process" => {
                        let (prog, mut args) = extra.worker_command.clone().unwrap_or_else(|| {
                            (
                                std::env::current_exe().unwrap_or_else(|_| "remit".into()),
                                vec!["kernel-worker".into()],
                            )
                        });
                        args.extend([
                            "--engine".into(),
                            path.display().to_string(),
                            "--sha256".into(),
                            sha.clone(),
                            "--lang".into(),
                            lang.clone(),
                        ]);
                        args.extend([
                            "--cache-dir".into(),
                            data_dir.join("engine-cache").display().to_string(),
                        ]);
                        let compile = extra.worker_command.is_none().then(|| {
                            (
                                prog.clone(),
                                vec![
                                    "compile-worker".to_string(),
                                    "--max-memory-bytes".into(),
                                    cfg.runtime
                                        .limits
                                        .max_memory_bytes
                                        .max(64 << 20)
                                        .to_string(),
                                ],
                            )
                        });
                        args.extend([
                            "--max-memory-bytes".into(),
                            cfg.runtime
                                .limits
                                .max_memory_bytes
                                .max(64 << 20)
                                .to_string(),
                        ]);
                        EngineHandle::Process {
                            pool: WorkerPool::with_compiler(
                                prog,
                                args,
                                cfg.runtime.workers_per_domain,
                                compile,
                            ),
                            engine_sha256: sha,
                        }
                    }
                    "microvm" => {
                        let vm = cfg.runtime.microvm.clone().ok_or_else(|| anyhow!("isolation `microvm` needs a [runtime.microvm] section with a guest `kernel`"))?;
                        let engine = EngineConfig {
                            component: path.clone(),
                            sha256: Some(sha.clone()),
                            max_memory_bytes: cfg.runtime.limits.max_memory_bytes.max(64 << 20),
                            lang: lang.clone(),
                            ..Default::default()
                        };
                        let (prog, args) =
                            remit_kernel::microvm::prepare(&vm, engine, &data_dir).await?;
                        EngineHandle::Process {
                            pool: WorkerPool::microvm(prog, args, cfg.runtime.workers_per_domain),
                            engine_sha256: sha,
                        }
                    }
                    other => {
                        return Err(anyhow!(
                            "unknown isolation `{other}` (inprocess | process | microvm)"
                        ))
                    }
                };
                engines.insert(lang, handle);
            }
        }
        cfg.runtime.limits.languages = engines.keys().cloned().collect();
        if engines.contains_key("js/es2023") {
            // Sender-built components run on the JS engine's restricted twin.
            cfg.runtime.limits.languages.push("wasm/component".into());
        }
        if engines.is_empty() {
            cfg.runtime.limits.modes.retain(|m| m != "kernel");
        }
        let isolation = if engines.is_empty() {
            Isolation::None
        } else {
            Isolation::Engines(engines)
        };
        let mut principals = HashMap::new();
        for p in &cfg.principals {
            principals.insert(p.id.clone(), p.clone());
        }
        let mut biscuit_roots = Vec::new();
        for r in &cfg.authority.roots {
            biscuit_roots.push(
                biscuit_auth::PublicKey::from_str(r)
                    .map_err(|e| anyhow!("authority root `{r}`: {e}"))?,
            );
        }
        let mut examples = Vec::new();
        for e in &cfg.examples {
            let p = cfg.resolve(&e.file);
            let v: Value = serde_json::from_str(
                &std::fs::read_to_string(&p).with_context(|| p.display().to_string())?,
            )?;
            examples.push(json!({"title": e.title, "manifest": v}));
        }
        let profiles = cfg.profiles();
        let stats = if profiles.enabled {
            crate::stats::load_or_compute(
                &data_dir.join("stats.json"),
                &plane,
                &all_res,
                profiles.epsilon,
            )?
        } else {
            json!({})
        };
        let approvals = Approvals::new(cfg.approvals.clone());
        let blobs = Blobs::open(data_dir.join("blobs"), cfg.runtime.max_blob_bytes);
        let started_ms = chrono::Utc::now().timestamp_millis();
        let nonces =
            crate::replay::ReplayCache::open(Some(&data_dir.join("nonces.log")), started_ms)?;
        let parallel = match cfg.runtime.max_parallel {
            0 => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            n => n,
        };
        let sched = crate::sched::Scheduler::new(parallel, cfg.runtime.max_queue);
        Ok(Arc::new(Holder {
            cfg,
            signer,
            plane: parking_lot::RwLock::new(plane),
            functions: Arc::new(extra.functions),
            resources: all_res,
            policy,
            ledger,
            receipts,
            isolation,
            principals,
            biscuit_roots,
            nonces,
            keys: KeyCache::default(),
            sched,
            started_ms,
            analysis_cache: Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap())),
            result_cache: Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap())),
            runs: Mutex::new(Runs::default()),
            blobs: Mutex::new(blobs),
            approvals,
            examples,
            stats: parking_lot::RwLock::new(stats),
            catalog_cache: Mutex::new(HashMap::new()),
            metrics: Metrics::default(),
            data_dir,
            base_store,
        }))
    }

    /// The current data snapshot.
    pub fn plane(&self) -> Arc<ReadPlane> {
        self.plane.read().clone()
    }

    fn mask_salt(cfg: &Config, signer: &Signer) -> String {
        secret(&cfg.holder.mask_salt).unwrap_or_else(|| {
            remit_wire::sha256_hex(&signer.sign(b"remit:mask-salt"))[..32].to_string()
        })
    }

    /// Reload sources into a new pinned snapshot (in-flight runs keep theirs).
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let mut store = self.base_store.clone();
        load_sources(&self.cfg, &mut store).await?;
        let resources = self.cfg.resources()?;
        let plane = ReadPlane::new(
            &store,
            &resources,
            &Self::mask_salt(&self.cfg, &self.signer),
        )
        .and_then(|p| p.with_indexes(&self.cfg.indexes, &store))
        .map_err(|e| anyhow!("{e}"))?;
        for r in self.resources.keys() {
            if plane.resource(r).is_none() {
                return Err(anyhow!("refresh: `{r}` disappeared"));
            }
        }
        *self.plane.write() = Arc::new(plane);
        self.catalog_cache.lock().clear();
        self.analysis_cache.lock().clear();
        Ok(())
    }

    /// Refresh on the shortest configured `refresh_s`. Published statistics
    /// profiles are *not* recomputed (their ε is a one-time spend).
    pub fn start_refresh(self: &Arc<Self>) {
        let Some(s) = self.cfg.sources.iter().filter_map(|s| s.refresh_s).min() else {
            return;
        };
        let h = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(s.max(1))).await;
                let Some(h) = h.upgrade() else { return };
                if let Err(e) = h.refresh().await {
                    tracing::warn!("source refresh failed, keeping the previous snapshot: {e:#}");
                }
            }
        });
    }

    pub fn id(&self) -> &str {
        &self.cfg.holder.id
    }

    pub fn engine(&self, lang: &str) -> Option<&EngineHandle> {
        match &self.isolation {
            Isolation::Engines(m) => {
                let l = canonical_lang(lang);
                m.get(if l == "wasm/component" {
                    "js/es2023"
                } else {
                    l
                })
            }
            Isolation::None => None,
        }
    }

    /// `lang@sha256:…` for receipts and the catalog.
    pub fn engine_id(&self, lang: &str) -> Option<String> {
        let l = canonical_lang(lang);
        // A Sender-built component is identified by its own hash (code.source_sha256
        // in remit_id); the Holder-side "engine" is the restricted Wasmtime config.
        if l == "wasm/component" {
            return self.engine(lang).map(|_| {
                format!(
                    "wasm/component@wasmtime-{}+restricted",
                    remit_kernel::wasmtime_version()
                )
            });
        }
        self.engine(lang)
            .map(|e| format!("{}@sha256:{}", l, e.sha256()))
    }

    /// Principal attributes and trust domain for an authenticated sender id.
    pub fn principal(&self, sender: &str, t: &Transport) -> (PrincipalInfo, String) {
        match self.principals.get(sender) {
            Some(p) => {
                let domain = p
                    .trust_domain
                    .clone()
                    .or_else(|| p.groups.first().cloned())
                    .unwrap_or_else(|| p.id.clone());
                (p.info(), domain)
            }
            None => match self.grant_for(sender, t) {
                Some(g) => {
                    let domain = g
                        .trust_domain
                        .clone()
                        .or_else(|| g.groups.first().cloned())
                        .unwrap_or_else(|| sender.to_string());
                    (
                        PrincipalInfo {
                            id: sender.into(),
                            groups: g.groups,
                            org: g.org,
                            verified: g.verified,
                            tags: g.tags,
                        },
                        domain,
                    )
                }
                None => (
                    PrincipalInfo {
                        id: sender.into(),
                        ..Default::default()
                    },
                    format!("anon:{sender}"),
                ),
            },
        }
    }

    /// Fair-queuing weight of a principal (the largest of its groups').
    pub fn weight(&self, p: &PrincipalInfo) -> u32 {
        p.groups
            .iter()
            .filter_map(|g| self.cfg.budgets.weights.get(g))
            .copied()
            .max()
            .unwrap_or(1)
    }

    /// The catalog document scoped to `groups` (hidden equals nonexistent).
    pub fn catalog(&self, groups: &[String]) -> (Value, String) {
        let mut key = groups.to_vec();
        key.sort();
        if let Some(c) = self.catalog_cache.lock().get(&key) {
            return c.clone();
        }
        let doc = crate::catalog::build(self, groups);
        let sha = format!(
            "sha256:{}",
            remit_wire::sha256_hex(&remit_wire::jcs::canonical_bytes(&doc).unwrap_or_default())
        );
        let mut doc = doc;
        doc["catalog_sha256"] = json!(sha);
        self.catalog_cache
            .lock()
            .insert(key, (doc.clone(), sha.clone()));
        (doc, sha)
    }

    pub fn now_ms(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
}
