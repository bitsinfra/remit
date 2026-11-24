//! The read plane: policy views, plan analysis (lineage), k-threshold
//! rewrites, limits, execution.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::memory::MemorySchemaProvider;
use datafusion::catalog::streaming::StreamingTable;
use datafusion::catalog::MemoryCatalogProvider;
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{DFSchema, ParamValues, TableReference};
use datafusion::datasource::empty::EmptyTable;
use datafusion::datasource::provider_as_source;
use datafusion::datasource::ViewTable;
use datafusion::error::DataFusionError;
use datafusion::execution::context::{SQLOptions, SessionState};
use datafusion::execution::memory_pool::GreedyMemoryPool;
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{
    col, lit, utils::conjunction, Aggregate, Expr, ExprSchemable, LogicalPlan, LogicalPlanBuilder,
};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::streaming::PartitionStream;
use datafusion::physical_plan::SendableRecordBatchStream;
use datafusion::prelude::{DataFrame, SessionConfig, SessionContext};
use futures::StreamExt;
use parking_lot::Mutex;
use remit_wire::ParamType;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::arrowconv::{param_placeholder, param_scalar};
use crate::config::ResourceConfig;
use crate::dp::DpShape;
use crate::store::{RawTable, Store};
use crate::ReadError;

/// The authenticated principal a remit runs for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Principal {
    pub id: String,
    pub groups: Vec<String>,
}

/// Per-remit read limits.
#[derive(Clone, Debug)]
pub struct ReadLimits {
    pub max_rows: u64,
    pub scan_rows: u64,
    pub scan_bytes: u64,
    pub memory_bytes: u64,
    pub timeout: Duration,
}

impl Default for ReadLimits {
    fn default() -> Self {
        ReadLimits {
            max_rows: 10_000,
            scan_rows: 10_000_000,
            scan_bytes: 1 << 30,
            memory_bytes: 256 << 20,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Shared scan counter for one remit (all reads and calls).
#[derive(Debug, Default)]
pub struct ScanCounter {
    pub rows: AtomicU64,
    pub bytes: AtomicU64,
    pub max_rows: AtomicU64,
    pub max_bytes: AtomicU64,
}

impl ScanCounter {
    pub fn new(max_rows: u64, max_bytes: u64) -> Arc<Self> {
        Arc::new(ScanCounter {
            rows: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            max_rows: AtomicU64::new(max_rows),
            max_bytes: AtomicU64::new(max_bytes),
        })
    }
}

/// Facts about one resource touched by a read.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct TableFacts {
    pub columns: BTreeSet<String>,
    /// Every scan of this table sits under an aggregate.
    pub aggregated: bool,
}

/// Facts derived from planning a read against the principal's views.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct PlanFacts {
    pub tables: BTreeMap<String, TableFacts>,
    pub aggregate_only: bool,
    /// Output columns and their kinds (bool/int/float/timestamp/date/string/bytes).
    pub output: Vec<(String, String)>,
    /// Upper bound on rows scanned (sum of snapshot row counts of scanned tables).
    pub scan_rows_bound: u64,
    /// Minimum k enforced across scanned tables when every one is k-protected.
    pub min_group_size: Option<u64>,
    /// Any scanned table is DP-governed.
    pub dp: bool,
    /// How each output column is derived.
    pub output_kinds: BTreeMap<String, OutputKind>,
}

/// Derivation of a root output column.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputKind {
    GroupKey,
    Aggregate { func: String, arg: Option<String> },
    Other,
}

/// Output of one read execution.
#[derive(Debug)]
pub struct ReadOutput {
    pub schema: SchemaRef,
    pub batches: Vec<RecordBatch>,
    pub rows: u64,
}

struct ViewDef {
    raw: RawTable,
    cfg: ResourceConfig,
    /// Projection over the raw scan (casts, masks, clamps), aliased to column names.
    projection: Vec<Expr>,
    filter: Option<Expr>,
    /// Exposed schema (what Senders see).
    schema: SchemaRef,
}

/// The trusted read plane.
pub struct ReadPlane {
    views: BTreeMap<String, ViewDef>,
    base_state: SessionState,
    analysis_cache: Mutex<HashMap<Vec<String>, SessionContext>>,
    /// Lineage is param-independent: cache by (sql, scope, param types).
    lineage_cache: Mutex<HashMap<(String, Vec<String>, String), PlanFacts>>,
    indexes: BTreeMap<String, Arc<crate::search::SearchIndex>>,
}

impl fmt::Debug for ReadPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadPlane")
            .field("tables", &self.views.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn session_config() -> SessionConfig {
    let mut c = SessionConfig::new()
        .with_target_partitions(1)
        .with_information_schema(false)
        .with_create_default_catalog_and_schema(true);
    c.options_mut().sql_parser.dialect = datafusion::config::Dialect::PostgreSQL;
    c.options_mut().sql_parser.enable_ident_normalization = true;
    c
}

fn sql_options() -> SQLOptions {
    SQLOptions::new()
        .with_allow_ddl(false)
        .with_allow_dml(false)
        .with_allow_statements(false)
}

fn check_projected_subqueries(plan: &LogicalPlan) -> Result<(), ReadError> {
    plan.apply_with_subqueries(|node| {
        if let LogicalPlan::Projection(projection) = node {
            for expr in &projection.expr {
                if expr.exists(|e| Ok(matches!(e, Expr::Exists(_) | Expr::InSubquery(_))))? {
                    return Err(DataFusionError::Plan(
                        "IN and EXISTS subqueries are unsupported in SELECT expressions. Use a filter or a COUNT(*) comparison instead.".into(),
                    ));
                }
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .map_err(ReadError::plan)?;
    Ok(())
}

/// Normalize timestamps to ms UTC so params compare uniformly.
fn ts_ms() -> DataType {
    DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()))
}

impl ReadPlane {
    /// Build views for every configured resource present in the store.
    pub fn new(
        store: &Store,
        resources: &BTreeMap<String, ResourceConfig>,
        mask_salt: &str,
    ) -> Result<Self, ReadError> {
        let base_state = SessionStateBuilder::new()
            .with_config(session_config())
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(base_state.clone());
        let mut views = BTreeMap::new();
        for (name, raw) in store.tables() {
            let cfg = resources.get(name).cloned().unwrap_or_default();
            for c in cfg.columns.keys() {
                if raw.schema.field_with_name(c).is_err() {
                    return Err(ReadError::Config(format!(
                        "catalog `{name}`: column `{c}` does not exist in the source"
                    )));
                }
            }
            let df_schema = DFSchema::try_from(raw.schema.as_ref().clone())
                .map_err(|e| ReadError::Config(e.to_string()))?;
            let parse = |sql: &str| -> Result<Expr, ReadError> {
                ctx.parse_sql_expr(sql, &df_schema)
                    .map_err(|e| ReadError::Config(format!("catalog `{name}`: `{sql}`: {e}")))
            };
            let mut projection = Vec::new();
            for f in raw.schema.fields() {
                let c = cfg.column(f.name());
                if !c.expose {
                    continue;
                }
                let base = col(datafusion::common::Column::new_unqualified(f.name()));
                let mut e = match c.ty.as_deref() {
                    Some("timestamp") => base
                        .cast_to(&ts_ms(), &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                    Some("date") => base
                        .cast_to(&DataType::Date32, &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                    Some("int") => base
                        .cast_to(&DataType::Int64, &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                    Some("float") => base
                        .cast_to(&DataType::Float64, &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                    Some("string") => base
                        .cast_to(&DataType::Utf8, &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                    Some("bool") => base
                        .cast_to(&DataType::Boolean, &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                    Some(other) => {
                        return Err(ReadError::Config(format!(
                            "catalog `{name}.{}`: unknown type `{other}`",
                            f.name()
                        )))
                    }
                    None if matches!(f.data_type(), DataType::Timestamp(_, _)) => base
                        .cast_to(&ts_ms(), &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                    None => base,
                };
                let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
                if let Some(m) = &c.mask {
                    e = match m.as_str() {
                        "hash" => parse(&format!(
                            "encode(sha256(concat('{}', CAST({} AS VARCHAR))), 'hex')",
                            mask_salt.replace('\'', "''"),
                            q(f.name())
                        ))?,
                        "null" => Expr::Literal(
                            datafusion::scalar::ScalarValue::try_from(f.data_type())
                                .map_err(|e| ReadError::Config(e.to_string()))?,
                            None,
                        ),
                        "redact" => lit("***"),
                        t if t.starts_with("trunc:") => parse(&format!(
                            "date_trunc('{}', {})",
                            t[6..].replace('\'', ""),
                            q(f.name())
                        ))?
                        .cast_to(&ts_ms(), &df_schema)
                        .map_err(|e| ReadError::Config(e.to_string()))?,
                        other => {
                            return Err(ReadError::Config(format!(
                                "catalog `{name}.{}`: unknown mask `{other}`",
                                f.name()
                            )))
                        }
                    };
                }
                if let (Some(_), Some([lo, hi])) = (&cfg.dp, c.bounds) {
                    // DP-governed columns are clamped in the view (bounded sensitivity).
                    let x = format!("CAST({} AS DOUBLE)", q(f.name()));
                    e = parse(&format!("CASE WHEN {x} IS NULL OR isnan({x}) THEN NULL WHEN {x} < {lo} THEN {lo}e0 WHEN {x} > {hi} THEN {hi}e0 ELSE {x} END"))?;
                }
                projection.push(e.alias(f.name()));
            }
            if projection.is_empty() {
                continue; // nothing exposed: the resource does not exist for Senders
            }
            let filter = cfg.row_filter.as_deref().map(parse).transpose()?;
            // Compute the exposed schema by planning the view once.
            let plan = LogicalPlanBuilder::scan(
                "__raw",
                provider_as_source(Arc::new(EmptyTable::new(raw.schema.clone()))),
                None,
            )
            .and_then(|b| b.project(projection.clone()))
            .and_then(|b| b.build())
            .map_err(|e| ReadError::Config(format!("catalog `{name}`: {e}")))?;
            let schema: SchemaRef = Arc::new(Schema::new(
                plan.schema()
                    .fields()
                    .iter()
                    .map(|f| Field::new(f.name(), f.data_type().clone(), true))
                    .collect::<Vec<_>>(),
            ));
            views.insert(
                name.clone(),
                ViewDef {
                    raw: raw.clone(),
                    cfg,
                    projection,
                    filter,
                    schema,
                },
            );
        }
        Ok(ReadPlane {
            views,
            base_state,
            analysis_cache: Mutex::new(HashMap::new()),
            lineage_cache: Mutex::new(HashMap::new()),
            indexes: BTreeMap::new(),
        })
    }

    /// Build search indexes (`fts` / `knn`) over exposed, unmasked columns.
    pub fn with_indexes(
        mut self,
        cfgs: &[crate::search::IndexConfig],
        store: &Store,
    ) -> Result<Self, ReadError> {
        for c in cfgs {
            let v = self.views.get(&c.table).ok_or_else(|| {
                ReadError::Config(format!("index `{}`: unknown table `{}`", c.name, c.table))
            })?;
            for col in [
                Some(&c.id_column),
                c.text_column.as_ref(),
                c.vector_column.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                let cc = v.cfg.column(col);
                if !cc.expose || cc.mask.is_some() {
                    return Err(ReadError::Config(format!(
                        "index `{}`: column `{col}` must be exposed and unmasked",
                        c.name
                    )));
                }
            }
            if !v.cfg.operations().iter().any(|o| o == "search") {
                return Err(ReadError::Config(format!(
                    "index `{}`: add \"search\" to `{}`.operations",
                    c.name, c.table
                )));
            }
            let raw = store.get(&c.table).ok_or_else(|| {
                ReadError::Config(format!("index `{}`: no data for `{}`", c.name, c.table))
            })?;
            self.indexes.insert(
                c.name.clone(),
                Arc::new(crate::search::SearchIndex::build(c, raw)?),
            );
        }
        Ok(self)
    }

    pub fn index(&self, name: &str) -> Option<&crate::search::IndexConfig> {
        self.indexes.get(name).map(|i| &i.cfg)
    }

    pub fn indexes(&self) -> impl Iterator<Item = &crate::search::IndexConfig> {
        self.indexes.values().map(|i| &i.cfg)
    }

    /// The SQL profile for this Holder (its table functions).
    pub fn sql_profile(&self) -> remit_sql::Profile {
        let mut p = remit_sql::Profile::default();
        if !self.indexes.is_empty() {
            p.table_functions.insert("fts".into());
            p.table_functions.insert("knn".into());
        }
        p
    }

    /// Map a scan name to its view: views are inlined by the SQL planner, so
    /// execution-time scans are named `__raw_<source>_<table>`.
    fn canonical<'a>(&'a self, scan: &'a str) -> &'a str {
        if let Some(rest) = scan.strip_prefix("__raw_") {
            for k in self.views.keys() {
                if k.replace('.', "_") == rest {
                    return k.as_str();
                }
            }
        }
        scan
    }

    /// Tables visible to the principal.
    pub fn visible_tables(&self, p: &Principal) -> Vec<String> {
        self.views
            .iter()
            .filter(|(_, v)| v.cfg.visible_to_groups(&p.groups))
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn exposed_schema(&self, table: &str) -> Option<SchemaRef> {
        self.views.get(table).map(|v| v.schema.clone())
    }

    pub fn resource(&self, table: &str) -> Option<&ResourceConfig> {
        self.views.get(table).map(|v| &v.cfg)
    }

    pub fn data_version(&self, table: &str) -> Option<String> {
        self.views.get(table).map(|v| v.raw.version.clone())
    }

    pub fn row_count(&self, table: &str) -> Option<u64> {
        self.views.get(table).map(|v| v.raw.rows)
    }

    /// The raw snapshot behind a view (trusted code only: stats profiles).
    pub fn raw_batches(&self, table: &str) -> Option<Arc<Vec<RecordBatch>>> {
        self.views.get(table).map(|v| v.raw.batches.clone())
    }

    fn view_plan(
        &self,
        name: &str,
        v: &ViewDef,
        p: &Principal,
        counter: Option<Arc<ScanCounter>>,
    ) -> Result<LogicalPlan, ReadError> {
        let source: Arc<dyn datafusion::catalog::TableProvider> = match counter {
            Some(c) => Arc::new(
                StreamingTable::try_new(
                    v.raw.schema.clone(),
                    vec![Arc::new(CountingPartition {
                        schema: v.raw.schema.clone(),
                        batches: v.raw.batches.clone(),
                        counter: c,
                    })],
                )
                .map_err(ReadError::from)?,
            ),
            None => Arc::new(EmptyTable::new(v.raw.schema.clone())),
        };
        let mut b = LogicalPlanBuilder::scan(
            format!("__raw_{}", name.replace('.', "_")),
            provider_as_source(source),
            None,
        )?;
        let mut preds = Vec::new();
        if let Some(f) = &v.filter {
            preds.push(f.clone());
        }
        if let Some(owner) = &v.cfg.owner_column {
            preds.push(
                col(datafusion::common::Column::new_unqualified(owner)).eq(lit(p.id.clone())),
            );
        }
        if let Some(pred) = conjunction(preds) {
            b = b.filter(pred)?;
        }
        Ok(b.project(v.projection.clone())?.build()?)
    }

    fn register(
        &self,
        ctx: &SessionContext,
        p: &Principal,
        counter: Option<Arc<ScanCounter>>,
        analysis: bool,
        allowed: crate::search::Allowed,
    ) -> Result<(), ReadError> {
        let catalog = ctx
            .catalog("datafusion")
            .ok_or_else(|| ReadError::Internal("no catalog".into()))?;
        for (name, v) in self
            .views
            .iter()
            .filter(|(_, v)| v.cfg.visible_to_groups(&p.groups))
        {
            let (src, table) = name.split_once('.').unwrap_or(("default", name.as_str()));
            if catalog.schema(src).is_none() {
                catalog.register_schema(src, Arc::new(MemorySchemaProvider::new()))?;
            }
            let provider: Arc<dyn datafusion::catalog::TableProvider> = if analysis {
                Arc::new(EmptyTable::new(v.schema.clone()))
            } else {
                Arc::new(ViewTable::new(
                    self.view_plan(name, v, p, counter.clone())?,
                    None,
                ))
            };
            ctx.register_table(TableReference::partial(src, table), provider)?;
        }
        if !self.indexes.is_empty() {
            let visible: BTreeMap<String, Arc<crate::search::SearchIndex>> = self
                .indexes
                .iter()
                .filter(|(_, i)| {
                    self.views
                        .get(&i.cfg.table)
                        .is_some_and(|v| v.cfg.visible_to_groups(&p.groups))
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            ctx.register_udtf(
                "fts",
                Arc::new(crate::search::SearchFn {
                    kind: crate::search::SearchKind::Fts,
                    indexes: visible.clone(),
                    allowed: allowed.clone(),
                }),
            );
            ctx.register_udtf(
                "knn",
                Arc::new(crate::search::SearchFn {
                    kind: crate::search::SearchKind::Knn,
                    indexes: visible,
                    allowed,
                }),
            );
        }
        Ok(())
    }

    fn analysis_ctx(&self, p: &Principal) -> Result<SessionContext, ReadError> {
        let key = {
            let mut g = p.groups.clone();
            g.sort();
            g
        };
        if let Some(c) = self.analysis_cache.lock().get(&key) {
            return Ok(c.clone());
        }
        let state = SessionStateBuilder::new_from_existing(self.base_state.clone())
            .with_catalog_list(Arc::new(
                datafusion::catalog::MemoryCatalogProviderList::new(),
            ))
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("datafusion", Arc::new(MemoryCatalogProvider::new()));
        self.register(&ctx, p, None, true, Default::default())?;
        let mut cache = self.analysis_cache.lock();
        if cache.len() > 1024 {
            cache.clear();
        }
        cache.insert(key, ctx.clone());
        Ok(ctx)
    }

    /// Plan `sql` against the principal's views and derive lineage facts.
    pub async fn analyze(
        &self,
        sql: &str,
        p: &Principal,
        param_types: &BTreeMap<String, ParamType>,
    ) -> Result<PlanFacts, ReadError> {
        let mut groups = p.groups.clone();
        groups.sort();
        let key = (sql.to_string(), groups, format!("{param_types:?}"));
        if let Some(f) = self.lineage_cache.lock().get(&key) {
            return Ok(f.clone());
        }
        let f = self.analyze_uncached(sql, p, param_types).await?;
        let mut c = self.lineage_cache.lock();
        if c.len() > 4096 {
            c.clear();
        }
        c.insert(key, f.clone());
        Ok(f)
    }

    async fn analyze_uncached(
        &self,
        sql: &str,
        p: &Principal,
        param_types: &BTreeMap<String, ParamType>,
    ) -> Result<PlanFacts, ReadError> {
        let ctx = self.analysis_ctx(p)?;
        let df = ctx
            .sql_with_options(sql, sql_options())
            .await
            .map_err(ReadError::plan)?;
        let (state, plan) = df.into_parts();
        check_projected_subqueries(&plan)?;
        // Bind typed NULL placeholders so types resolve without constant
        // folding real values (lineage must not depend on param values).
        let plan = bind_params(plan, &Map::new(), param_types, true)?;
        let optimized = state.optimize(&plan).map_err(ReadError::plan)?;
        let mut tables: BTreeMap<String, TableFacts> = BTreeMap::new();
        let mut seen_unaggregated: BTreeSet<String> = BTreeSet::new();
        let is_view = |n: &str| self.views.contains_key(self.canonical(n));
        walk_scans(&optimized, false, &mut |name, cols, under| {
            if !is_view(name) {
                return;
            }
            let t = tables.entry(name.to_string()).or_insert(TableFacts {
                columns: BTreeSet::new(),
                aggregated: true,
            });
            t.columns.extend(cols);
            if !under {
                seen_unaggregated.insert(name.to_string());
            }
        })?;
        // Unoptimized plan: count every scan (optimizer may prune some).
        walk_scans(&plan, false, &mut |name, _, under| {
            if !is_view(name) {
                return;
            }
            tables.entry(name.to_string()).or_insert(TableFacts {
                columns: BTreeSet::new(),
                aggregated: true,
            });
            if !under {
                seen_unaggregated.insert(name.to_string());
            }
        })?;
        for (n, t) in tables.iter_mut() {
            t.aggregated = !seen_unaggregated.contains(n);
        }
        let aggregate_only = !tables.is_empty() && tables.values().all(|t| t.aggregated);
        let output = plan
            .schema()
            .fields()
            .iter()
            .map(|f| {
                (
                    f.name().clone(),
                    crate::arrowconv::kind_of(f.data_type()).to_string(),
                )
            })
            .collect();
        let scan_rows_bound = tables.keys().filter_map(|t| self.row_count(t)).sum();
        let min_group_size = if aggregate_only {
            tables
                .keys()
                .map(|t| self.views.get(t).and_then(|v| v.cfg.k))
                .collect::<Option<Vec<u64>>>()
                .and_then(|ks| ks.into_iter().min())
        } else {
            None
        };
        if std::env::var_os("REMIT_DEBUG_PLAN").is_some() {
            eprintln!("{}", plan.display_indent_schema());
        }
        let output_kinds = output_kinds(&plan);
        let dp = tables
            .keys()
            .any(|t| self.views.get(t).is_some_and(|v| v.cfg.dp.is_some()));
        Ok(PlanFacts {
            dp,
            tables,
            aggregate_only,
            output,
            scan_rows_bound,
            min_group_size,
            output_kinds,
        })
    }

    /// Execute `sql` with policy views, k-thresholds and limits.
    pub async fn execute(
        &self,
        sql: &str,
        p: &Principal,
        params: &Map<String, Value>,
        param_types: &BTreeMap<String, ParamType>,
        limits: &ReadLimits,
        counter: Arc<ScanCounter>,
    ) -> Result<ReadOutput, ReadError> {
        let (state, plan) = self
            .plan_for(sql, p, params, param_types, limits, counter)
            .await?;
        if self.scans_dp(&plan)? {
            return Err(ReadError::Dp(
                "this resource is DP-governed: read it through a DP query".into(),
            ));
        }
        self.enforce_aggregate_only(&plan)?;
        let plan = self.enforce_k(plan)?;
        let plan = bind_params(plan, params, param_types, false)?;
        let out = collect(state, plan, limits.max_rows, limits.timeout).await?;
        if out.rows > limits.max_rows {
            return Err(ReadError::RowCap);
        }
        Ok(out)
    }

    /// Derive the DP treatment of a query at admission (data-independent).
    pub async fn dp_shape(
        &self,
        sql: &str,
        p: &Principal,
        param_types: &BTreeMap<String, ParamType>,
    ) -> Result<DpShape, ReadError> {
        let ctx = self.analysis_ctx(p)?;
        let df = ctx
            .sql_with_options(sql, sql_options())
            .await
            .map_err(ReadError::plan)?;
        let (_, plan) = df.into_parts();
        let plan = bind_params(plan, &Map::new(), param_types, true)?;
        crate::dp::shape(&plan, self)
    }

    /// Execute the *exact* (clamped, contribution-bounded) aggregates of a DP
    /// query. The caller must add noise before anything leaves the Holder.
    pub async fn execute_dp(
        &self,
        sql: &str,
        p: &Principal,
        params: &Map<String, Value>,
        param_types: &BTreeMap<String, ParamType>,
        limits: &ReadLimits,
        counter: Arc<ScanCounter>,
    ) -> Result<(DpShape, Vec<Value>), ReadError> {
        let (state, plan) = self
            .plan_for(sql, p, params, param_types, limits, counter)
            .await?;
        let plan = bind_params(plan, params, param_types, false)?;
        let shape = crate::dp::shape(&plan, self)?;
        let plan = crate::dp::rewrite(&plan, self, &shape)?;
        let out = collect(state, plan, DP_MAX_GROUPS, limits.timeout).await?;
        if out.rows > DP_MAX_GROUPS {
            return Err(ReadError::RowCap);
        }
        Ok((shape, crate::arrowconv::batches_to_rows(&out.batches)))
    }

    /// True when any scanned resource is DP-governed.
    fn scans_dp(&self, plan: &LogicalPlan) -> Result<bool, ReadError> {
        let mut hit = false;
        walk_scans(plan, false, &mut |name, _, _| {
            hit |= self
                .views
                .get(self.canonical(name))
                .is_some_and(|v| v.cfg.dp.is_some());
        })?;
        Ok(hit)
    }

    async fn plan_for(
        &self,
        sql: &str,
        p: &Principal,
        params: &Map<String, Value>,
        param_types: &BTreeMap<String, ParamType>,
        limits: &ReadLimits,
        counter: Arc<ScanCounter>,
    ) -> Result<(SessionState, LogicalPlan), ReadError> {
        let searches = !self.indexes.is_empty() && (sql.contains("fts(") || sql.contains("knn("));
        let allowed = if searches {
            self.allowed_ids(p).await?
        } else {
            Default::default()
        };
        let ctx = self.exec_ctx(p, Some(limits.memory_bytes), Some(counter), allowed)?;
        // Table-function arguments are evaluated at planning time: bind them as
        // literals, in one pass over the tokenized SQL.
        let bound;
        let sql = if searches {
            bound = bind_literals(sql, params, param_types)?;
            bound.as_str()
        } else {
            sql
        };
        let df = ctx
            .sql_with_options(sql, sql_options())
            .await
            .map_err(ReadError::plan)?;
        let (state, plan) = df.into_parts();
        check_projected_subqueries(&plan)?;
        Ok((state, plan))
    }

    fn exec_ctx(
        &self,
        p: &Principal,
        memory: Option<u64>,
        counter: Option<Arc<ScanCounter>>,
        allowed: crate::search::Allowed,
    ) -> Result<SessionContext, ReadError> {
        let mut b = SessionStateBuilder::new_from_existing(self.base_state.clone())
            .with_catalog_list(Arc::new(
                datafusion::catalog::MemoryCatalogProviderList::new(),
            ));
        if let Some(m) = memory {
            b = b.with_runtime_env(
                RuntimeEnvBuilder::new()
                    .with_memory_pool(Arc::new(GreedyMemoryPool::new(m as usize)))
                    .build_arc()?,
            );
        }
        let ctx = SessionContext::new_with_state(b.build());
        ctx.register_catalog("datafusion", Arc::new(MemoryCatalogProvider::new()));
        self.register(&ctx, p, counter, false, allowed)?;
        Ok(ctx)
    }

    /// Ids a principal may see per indexed table whose view filters rows, so a
    /// search can never act as an oracle over hidden rows.
    async fn allowed_ids(&self, p: &Principal) -> Result<crate::search::Allowed, ReadError> {
        let mut out = BTreeMap::new();
        for ix in self.indexes.values() {
            let Some(v) = self.views.get(&ix.cfg.table) else {
                continue;
            };
            if v.filter.is_none() && v.cfg.owner_column.is_none() {
                continue;
            }
            let ctx = self.exec_ctx(
                p,
                None,
                Some(ScanCounter::new(u64::MAX, u64::MAX)),
                Default::default(),
            )?;
            let Some((s, t)) = ix.cfg.table.split_once('.') else {
                continue;
            };
            let q = format!(
                "SELECT \"{}\" AS id FROM \"{s}\".\"{t}\"",
                ix.cfg.id_column.replace('"', "\"\"")
            );
            let batches = ctx
                .sql(&q)
                .await
                .map_err(ReadError::plan)?
                .collect()
                .await
                .map_err(ReadError::exec)?;
            let ids = crate::arrowconv::batches_to_rows(&batches)
                .into_iter()
                .filter_map(|r| match &r["id"] {
                    Value::Null => None,
                    Value::String(s) => Some(s.clone()),
                    v => Some(v.to_string()),
                })
                .collect();
            out.insert(ix.cfg.name.clone(), Arc::new(ids));
        }
        Ok(out)
    }

    fn enforce_aggregate_only(&self, plan: &LogicalPlan) -> Result<(), ReadError> {
        let mut bad = None;
        walk_scans(plan, false, &mut |name, _, under| {
            let name = self.canonical(name);
            if !under && self.views.get(name).is_some_and(|v| v.cfg.aggregate_only) {
                bad = Some(name.to_string());
            }
        })?;
        match bad {
            Some(t) => Err(ReadError::AggregateOnly(t)),
            None => Ok(()),
        }
    }

    /// Inject k-thresholds: every aggregate over a k-protected table keeps only
    /// groups with at least k (distinct privacy units | rows).
    fn enforce_k(&self, plan: LogicalPlan) -> Result<LogicalPlan, ReadError> {
        let mut error: Option<ReadError> = None;
        let out = plan
            .transform_up_with_subqueries(|node| {
                let LogicalPlan::Aggregate(agg) = &node else {
                    return Ok(Transformed::no(node));
                };
                let mut protected: BTreeMap<String, (u64, Option<String>)> = BTreeMap::new();
                let _ = agg.input.apply_with_subqueries(|n| {
                    if let LogicalPlan::TableScan(ts) = n {
                        let raw = ts.table_name.to_string().to_lowercase();
                        let name = self.canonical(&raw).to_string();
                        if let Some(v) = self.views.get(&name) {
                            if let Some(k) = v.cfg.k {
                                protected.insert(name, (k, v.cfg.privacy_unit.clone()));
                            }
                        }
                    }
                    Ok(TreeNodeRecursion::Continue)
                });
                if protected.is_empty() {
                    return Ok(Transformed::no(node));
                }
                let mut extra = Vec::new();
                let mut preds = Vec::new();
                let mut n = 0usize;
                for (t, (k, pu)) in protected.iter() {
                    // Every candidate privacy-unit column must reach k (sound for joins).
                    let exprs: Vec<Expr> = match pu {
                        Some(pu) => {
                            let cols: Vec<_> = agg
                                .input
                                .schema()
                                .columns()
                                .into_iter()
                                .filter(|c| &c.name == pu)
                                .collect();
                            if cols.is_empty() {
                                error = Some(ReadError::PrivacyUnit(t.clone(), pu.clone()));
                                return Ok(Transformed::no(node));
                            }
                            cols.into_iter()
                                .map(|c| {
                                    datafusion::functions_aggregate::expr_fn::count_distinct(
                                        Expr::Column(c),
                                    )
                                })
                                .collect()
                        }
                        None => vec![datafusion::functions_aggregate::expr_fn::count(lit(1i64))],
                    };
                    for cexpr in exprs {
                        let alias = format!("__remit_k{n}");
                        n += 1;
                        extra.push(cexpr.alias(&alias));
                        preds.push(col(alias).gt_eq(lit(*k as i64)));
                    }
                }
                let orig: Vec<Expr> = agg.schema.columns().into_iter().map(Expr::Column).collect();
                let mut aggr = agg.aggr_expr.clone();
                aggr.extend(extra);
                let new = Aggregate::try_new(agg.input.clone(), agg.group_expr.clone(), aggr)?;
                let b = LogicalPlanBuilder::from(LogicalPlan::Aggregate(new))
                    .filter(conjunction(preds).expect("non-empty"))?
                    .project(orig)?
                    .build()?;
                Ok(Transformed::yes(b))
            })
            .map(|t| t.data)
            .map_err(ReadError::plan)?;
        match error {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }
}

/// Group-count ceiling for DP queries (before thresholding).
const DP_MAX_GROUPS: u64 = 1_000_000;

async fn collect(
    state: SessionState,
    plan: LogicalPlan,
    max_rows: u64,
    timeout: Duration,
) -> Result<ReadOutput, ReadError> {
    let df = DataFrame::new(state, plan).limit(0, Some((max_rows as usize).saturating_add(1)))?;
    let schema: SchemaRef = Arc::new(df.schema().as_arrow().clone());
    let batches = match tokio::time::timeout(timeout, df.collect()).await {
        Err(_) => return Err(ReadError::Timeout),
        Ok(r) => r.map_err(ReadError::exec)?,
    };
    let rows = batches.iter().map(|b| b.num_rows() as u64).sum();
    Ok(ReadOutput {
        schema,
        batches,
        rows,
    })
}

impl crate::dp::Catalog for ReadPlane {
    fn resource(&self, name: &str) -> Option<(String, &ResourceConfig)> {
        let n = self.canonical(name);
        self.views
            .get_key_value(n)
            .map(|(k, v)| (k.clone(), &v.cfg))
    }
}

/// Bind `$params` as literals using the SQL tokenizer: one pass, so a param's
/// *value* is never re-scanned for placeholders, and placeholders inside
/// string literals or comments are never substituted.
fn bind_literals(
    sql: &str,
    params: &Map<String, Value>,
    types: &BTreeMap<String, ParamType>,
) -> Result<String, ReadError> {
    use datafusion::sql::sqlparser::dialect::PostgreSqlDialect;
    use datafusion::sql::sqlparser::tokenizer::{Token, Tokenizer};
    let toks = Tokenizer::new(&PostgreSqlDialect {}, sql)
        .with_unescape(false)
        .tokenize()
        .map_err(|e| ReadError::Plan(e.to_string()))?;
    let mut out = String::with_capacity(sql.len());
    for t in toks {
        match t {
            Token::Placeholder(p) => {
                let n = p.trim_start_matches('$');
                let ty = *types.get(n).ok_or_else(|| {
                    ReadError::Param(format!("param `${n}` is not declared in the read template"))
                })?;
                let v = params
                    .get(n)
                    .ok_or_else(|| ReadError::Param(format!("param `${n}` is missing")))?;
                let lit = crate::search::sql_literal(v, ty).ok_or_else(|| {
                    ReadError::Param(format!("param `${n}` is not a valid {}", ty.as_str()))
                })?;
                out.push_str(&lit);
            }
            t => out.push_str(&t.to_string()),
        }
    }
    Ok(out)
}

/// Classify root output columns: group keys, direct aggregates, or other.
fn output_kinds(plan: &LogicalPlan) -> BTreeMap<String, OutputKind> {
    let mut out = BTreeMap::new();
    let mut node = plan;
    loop {
        match node {
            LogicalPlan::Sort(s) => node = &s.input,
            LogicalPlan::Limit(l) => node = &l.input,
            LogicalPlan::Filter(f) => node = &f.input,
            LogicalPlan::SubqueryAlias(a) => node = &a.input,
            _ => break,
        }
    }
    let LogicalPlan::Projection(proj) = node else {
        for f in plan.schema().fields() {
            out.insert(f.name().clone(), OutputKind::Other);
        }
        return out;
    };
    let mut input = proj.input.as_ref();
    while let LogicalPlan::Filter(f) = input {
        input = &f.input;
    }
    let agg = match input {
        LogicalPlan::Aggregate(a) => Some(a),
        _ => None,
    };
    for (i, e) in proj.expr.iter().enumerate() {
        let name = proj.schema.field(i).name().clone();
        let mut inner = e;
        while let Expr::Alias(a) = inner {
            inner = a.expr.as_ref();
        }
        let kind = match (inner, agg) {
            (Expr::Column(c), Some(a)) => {
                let idx = a.schema.columns().iter().position(|x| x.name == c.name);
                match idx {
                    Some(ix) if ix < a.group_expr.len() => OutputKind::GroupKey,
                    Some(ix) => {
                        let ae = &a.aggr_expr[ix - a.group_expr.len()];
                        let mut ae = ae;
                        while let Expr::Alias(x) = ae {
                            ae = x.expr.as_ref();
                        }
                        match ae {
                            Expr::AggregateFunction(af) if af.params.filter.is_none() => {
                                let arg = af.params.args.first().and_then(|x| match x {
                                    Expr::Column(c) => Some(c.name.clone()),
                                    _ => None,
                                });
                                OutputKind::Aggregate {
                                    func: af.func.name().to_lowercase(),
                                    arg,
                                }
                            }
                            _ => OutputKind::Other,
                        }
                    }
                    None => OutputKind::Other,
                }
            }
            _ => OutputKind::Other,
        };
        out.insert(name, kind);
    }
    out
}

/// Replace placeholders with typed values (or typed NULLs for analysis).
fn bind_params(
    plan: LogicalPlan,
    params: &Map<String, Value>,
    types: &BTreeMap<String, ParamType>,
    placeholders: bool,
) -> Result<LogicalPlan, ReadError> {
    let names = plan.get_parameter_names().map_err(ReadError::plan)?;
    if names.is_empty() {
        return Ok(plan);
    }
    let inferred = plan.get_parameter_types().map_err(ReadError::plan)?;
    let mut map: HashMap<String, datafusion::scalar::ScalarValue> = HashMap::new();
    for n in names {
        let name = n.trim_start_matches('$').to_string();
        let t = *types.get(&name).ok_or_else(|| {
            ReadError::Param(format!(
                "param `${name}` is not declared in the read template"
            ))
        })?;
        let mut v = if placeholders {
            param_placeholder(t)
        } else {
            let raw = params
                .get(&name)
                .ok_or_else(|| ReadError::Param(format!("param `${name}` is missing")))?;
            param_scalar(raw, t).ok_or_else(|| {
                ReadError::Param(format!("param `${name}` is not a valid {}", t.as_str()))
            })?
        };
        if let Some(Some(dt)) = inferred.get(&n) {
            if &v.data_type() != dt {
                v = v.cast_to(dt).map_err(|_| {
                    ReadError::Param(format!("param `${name}` cannot be used as {dt}"))
                })?;
            }
        }
        map.insert(name, v);
    }
    plan.replace_params_with_values(&ParamValues::from(map))
        .map_err(ReadError::plan)
}

/// Visit every TableScan with its projected columns and whether it sits under an Aggregate.
fn walk_scans(
    plan: &LogicalPlan,
    under: bool,
    f: &mut dyn FnMut(&str, Vec<String>, bool),
) -> Result<(), ReadError> {
    let under_here = under || matches!(plan, LogicalPlan::Aggregate(_));
    if let LogicalPlan::TableScan(ts) = plan {
        let schema = ts.source.schema();
        let cols: Vec<String> = match &ts.projection {
            Some(p) => p.iter().map(|i| schema.field(*i).name().clone()).collect(),
            None => schema.fields().iter().map(|f| f.name().clone()).collect(),
        };
        f(&ts.table_name.to_string().to_lowercase(), cols, under);
    }
    for input in plan.inputs() {
        walk_scans(input, under_here, f)?;
    }
    let mut subs = Vec::new();
    plan.apply_subqueries(|sq| {
        subs.push(sq.clone());
        Ok(TreeNodeRecursion::Jump)
    })
    .map_err(ReadError::plan)?;
    for sq in subs {
        walk_scans(&sq, false, f)?;
    }
    Ok(())
}

/// Streams a snapshot's batches while charging the remit's scan counter.
struct CountingPartition {
    schema: SchemaRef,
    batches: Arc<Vec<RecordBatch>>,
    counter: Arc<ScanCounter>,
}

impl fmt::Debug for CountingPartition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CountingPartition")
    }
}

pub const SCAN_CAP_MSG: &str = "remit:scan_cap";

impl PartitionStream for CountingPartition {
    fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    fn execute(&self, _ctx: Arc<TaskContext>) -> SendableRecordBatchStream {
        let batches = self.batches.clone();
        let counter = self.counter.clone();
        let stream = futures::stream::iter((0..batches.len()).map(move |i| {
            let b = batches[i].clone();
            let rows = counter
                .rows
                .fetch_add(b.num_rows() as u64, Ordering::Relaxed)
                + b.num_rows() as u64;
            let bytes = counter
                .bytes
                .fetch_add(b.get_array_memory_size() as u64, Ordering::Relaxed)
                + b.get_array_memory_size() as u64;
            if rows > counter.max_rows.load(Ordering::Relaxed)
                || bytes > counter.max_bytes.load(Ordering::Relaxed)
            {
                Err(DataFusionError::ResourcesExhausted(SCAN_CAP_MSG.into()))
            } else {
                Ok(b)
            }
        }))
        .boxed();
        Box::pin(RecordBatchStreamAdapter::new(self.schema.clone(), stream))
    }
}

#[allow(dead_code)]
fn _assert_any(_: &dyn Any) {}
