//! Remit Holder: the data owner's side.
//!
//! ```ignore
//! let holder = remit_holder::Holder::builder("did:web:alice.vault.example")
//!     .source_batches("crm.accounts", schema, batches)
//!     .resource("crm.accounts", ResourceConfig { aggregate_only: true, k: Some(20), ..Default::default() })
//!     .presets(["aggregate-only"])
//!     .build().await?;
//! axum::serve(listener, remit_holder::router(holder)).await?;
//! ```

pub mod a2a;
pub mod admission;
pub mod approvals;
pub mod catalog;
pub mod config;
pub mod connect;
pub mod functions;
pub mod grpc;
pub mod http;
pub mod identity;
pub mod mcp;
pub mod mcp_source;
pub mod otel;
pub mod replay;
pub mod run;
pub mod sched;
pub mod state;
pub mod stats;

use std::path::PathBuf;
use std::sync::Arc;

pub use config::Config;
pub use http::router;
pub use state::{ExtraData, Holder};

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use remit_read::{ResourceConfig, Store};
use remit_wire::Signer;

/// Rust builder API for embedding a Holder.
pub struct HolderBuilder {
    cfg: Config,
    store: Store,
    signer: Option<Signer>,
    worker: Option<(PathBuf, Vec<String>)>,
    engine: Option<PathBuf>,
    functions: functions::Functions,
}

impl Holder {
    pub fn builder(id: &str) -> HolderBuilder {
        let cfg = Config::from_str(
            &format!("[holder]\nid = {:?}\nisolation = \"inprocess\"\n", id),
            &std::env::current_dir().unwrap_or_default(),
        )
        .expect("minimal config");
        HolderBuilder {
            cfg,
            store: Store::new(),
            signer: None,
            worker: None,
            engine: None,
            functions: Default::default(),
        }
    }
}

impl HolderBuilder {
    pub fn config(mut self, f: impl FnOnce(&mut Config)) -> Self {
        f(&mut self.cfg);
        self
    }
    pub fn identity(mut self, s: Signer) -> Self {
        self.signer = Some(s);
        self
    }
    /// In-memory Arrow data (the `memory` connector), exposed as `name`.
    pub fn source_batches(
        mut self,
        name: &str,
        schema: SchemaRef,
        batches: Vec<RecordBatch>,
    ) -> Self {
        self.store.insert_batches(name, schema, batches);
        self
    }
    pub fn resource(mut self, name: &str, r: ResourceConfig) -> Self {
        self.cfg
            .catalog
            .insert(name.to_string(), serde_json::to_value(r).expect("resource"));
        self
    }
    /// Any DataFusion `TableProvider`, read into a pinned snapshot at build time.
    pub async fn resource_provider(
        mut self,
        name: &str,
        provider: Arc<dyn datafusion::catalog::TableProvider>,
        r: ResourceConfig,
    ) -> anyhow::Result<Self> {
        let batches = datafusion::prelude::SessionContext::new()
            .read_table(provider.clone())?
            .collect()
            .await?;
        self.store.insert_batches(name, provider.schema(), batches);
        Ok(self.resource(name, r))
    }
    /// A Holder function offered to kernels (pure; priced in fuel).
    pub fn function(
        mut self,
        name: &str,
        description: &str,
        fuel: u64,
        f: impl functions::HolderFunction + 'static,
    ) -> Self {
        self.functions.insert(
            name,
            functions::FunctionDef {
                description: description.into(),
                fuel,
                visible_to: vec![],
                f: Arc::new(f),
            },
        );
        self
    }
    pub fn policy_dir(mut self, dir: &std::path::Path) -> Self {
        self.cfg
            .policy
            .files
            .push(dir.join("*.cedar").display().to_string());
        self
    }
    pub fn index(mut self, ix: remit_read::IndexConfig) -> Self {
        self.cfg.indexes.push(ix);
        self
    }
    pub fn presets<I: IntoIterator<Item = S>, S: Into<String>>(mut self, p: I) -> Self {
        self.cfg
            .policy
            .presets
            .extend(p.into_iter().map(Into::into));
        self
    }
    pub fn engine(mut self, path: PathBuf) -> Self {
        self.engine = Some(path);
        self
    }
    pub fn worker_command(mut self, prog: PathBuf, args: Vec<String>) -> Self {
        self.worker = Some((prog, args));
        self
    }
    pub async fn build(self) -> anyhow::Result<Arc<Holder>> {
        Holder::build(
            self.cfg,
            ExtraData {
                store: Some(self.store),
                signer: self.signer,
                worker_command: self.worker,
                engine_path: self.engine,
                functions: self.functions,
            },
        )
        .await
    }
}

/// Serve the Holder on its configured address.
pub async fn serve(h: Arc<Holder>) -> anyhow::Result<()> {
    let addr = h.cfg.holder.listen.clone();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(holder = h.id(), %addr, "remit holder listening");
    h.start_refresh();
    otel::start_metrics(&h);
    axum::serve(listener, router(h)).await?;
    Ok(())
}
