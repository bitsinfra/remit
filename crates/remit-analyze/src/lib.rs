//! Remit analyzer. Turns a manifest + the principal's catalog view into
//! **facts** (what policy decides on) and **diagnostics** (stable codes,
//! JSON pointers / SQL spans, hints) phrased only in visible-catalog terms.

mod js;

use std::collections::{BTreeMap, BTreeSet};

use remit_read::{PlanFacts, Principal, ReadPlane};
use remit_types::{status_bits, Rt, RtTemplate};
use remit_wire::{Manifest, Mode, ParamType};
use serde::Serialize;
use serde_json::{json, Map, Value};

pub use js::check_js;

/// One structured, LLM-actionable diagnostic.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Diagnostic {
    pub code: String,
    /// JSON pointer into the manifest.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<(u64, u64)>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    pub docs: String,
    /// Machine-applicable fix (RFC 6902 JSON Patch), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Value>,
}

impl Diagnostic {
    pub fn new(code: &str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Diagnostic {
            code: code.to_string(),
            path: path.into(),
            span: None,
            message: message.into(),
            hint: None,
            docs: format!(
                "https://github.com/bitsinfra/remit/blob/main/spec/diagnostics.md#{}",
                code.to_lowercase()
            ),
            fix: None,
        }
    }
    pub fn hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }
    pub fn span(mut self, s: Option<(u64, u64)>) -> Self {
        self.span = s;
        self
    }
    pub fn fix(mut self, f: Value) -> Self {
        self.fix = Some(f);
        self
    }
}

/// Per-resource facts.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct ResourceFacts {
    pub columns: BTreeSet<String>,
    pub aggregate_only: bool,
    /// Cedar actions requested on this resource.
    pub actions: BTreeSet<String>,
    pub max_rows_total: u64,
}

/// The analyzer's facts: the Cedar context.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Facts {
    pub mode: String,
    pub purpose: String,
    pub resources: BTreeMap<String, ResourceFacts>,
    pub ops: BTreeSet<String>,
    pub aggregate_only: bool,
    pub min_group_size: Option<u64>,
    /// ⌈capacity⌉ + status bits.
    pub result_bits: u64,
    pub capacity_bits: f64,
    pub fuel: u64,
    pub memory_bytes: u64,
    pub wall_ms: u64,
    pub scan_rows: u64,
    pub output_bytes: u64,
    pub max_rows_total: u64,
    pub epsilon_milli: u64,
    pub standing_approval: bool,
    /// Issuers of verified delegated authority (`biscuit:ed25519/…`, `txn:<iss>`).
    pub authority: BTreeSet<String>,
    /// Coarse cost buckets (never exact).
    pub cost: Value,
}

impl Facts {
    /// Cedar context for one resource.
    pub fn cedar_context(&self, resource: &str) -> Value {
        let r = self.resources.get(resource).cloned().unwrap_or_default();
        json!({
            "mode": self.mode,
            "purpose": self.purpose,
            "columns": r.columns,
            "ops": self.ops,
            "aggregate_only": r.aggregate_only && self.aggregate_only_for(resource),
            "min_group_size": self.min_group_size.unwrap_or(0) as i64,
            "result_bits": self.result_bits as i64,
            "fuel": self.fuel.min(i64::MAX as u64) as i64,
            "memory_bytes": self.memory_bytes as i64,
            "wall_ms": self.wall_ms as i64,
            "max_rows_total": r.max_rows_total.min(i64::MAX as u64) as i64,
            "epsilon_milli": self.epsilon_milli as i64,
            "standing_approval": self.standing_approval,
            "authority": self.authority,
        })
    }

    fn aggregate_only_for(&self, resource: &str) -> bool {
        self.resources
            .get(resource)
            .is_some_and(|r| r.aggregate_only)
    }
}

/// Holder-wide limit ceilings and defaults (from `remit.toml [runtime]`).
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HolderLimits {
    pub max_fuel: u64,
    pub max_memory_bytes: u64,
    pub max_wall_ms: u64,
    pub max_scan_rows: u64,
    pub max_scan_bytes: u64,
    pub max_output_bytes: u64,
    pub max_rows_per_read: u64,
    pub max_calls_per_read: u32,
    pub default_fuel: u64,
    pub default_memory_bytes: u64,
    pub default_wall_ms: u64,
    pub default_output_bytes: u64,
    pub modes: Vec<String>,
    pub languages: Vec<String>,
}

impl Default for HolderLimits {
    fn default() -> Self {
        HolderLimits {
            max_fuel: 2_000_000_000,
            max_memory_bytes: 256 << 20,
            max_wall_ms: 10_000,
            max_scan_rows: 50_000_000,
            max_scan_bytes: 4 << 30,
            max_output_bytes: 1 << 20,
            max_rows_per_read: 1_000_000,
            max_calls_per_read: 1_000,
            default_fuel: 50_000_000,
            default_memory_bytes: 32 << 20,
            default_wall_ms: 1_000,
            default_output_bytes: 64 << 10,
            modes: vec!["query".into(), "kernel".into()],
            languages: vec!["js/es2023".into()],
        }
    }
}

/// Effective limits after defaults (and clamps, if a counter-offer was accepted).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct EffectiveLimits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub wall_ms: u64,
    pub scan_rows: u64,
    pub scan_bytes: u64,
    pub output_bytes: u64,
    pub epsilon: f64,
}

/// Result of analyzing a manifest.
#[derive(Clone, Debug)]
pub struct Analysis {
    pub facts: Facts,
    /// Bound result type (None for a template without params).
    pub rt: Option<Rt>,
    pub rt_template: RtTemplate,
    pub limits: EffectiveLimits,
    pub plans: BTreeMap<String, PlanFacts>,
    /// DP treatment per read over DP-governed resources.
    pub dp: BTreeMap<String, remit_read::DpShape>,
    pub param_types: BTreeMap<String, ParamType>,
    /// Limits the Holder would clamp (counter-offer), as JSON Patch ops.
    pub clamps: Vec<Value>,
    /// Non-fatal notes (e.g. unquantized floats).
    pub warnings: Vec<Diagnostic>,
}

pub const E_PARAM_UNDECLARED: &str = "RMT-E0110";
pub const E_PARAM_MISSING: &str = "RMT-E0111";
pub const E_SHAPE: &str = "RMT-E0120";
pub const E_BITS: &str = "RMT-E0130";
pub const E_LIMIT: &str = "RMT-E0140";
pub const E_MODE: &str = "RMT-E0150";
pub const E_LANG: &str = "RMT-E0151";

/// Parse `returns`: RT JSON, or JSON Schema 2020-12 (detected by `$schema`/`type`).
pub fn parse_returns(v: &Value) -> Result<RtTemplate, Diagnostic> {
    let is_schema = v.as_object().is_some_and(|o| {
        o.contains_key("$schema") || o.contains_key("type") || o.contains_key("anyOf")
    });
    let r = if is_schema {
        RtTemplate::from_json_schema(v)
    } else {
        RtTemplate::from_json(v)
    };
    r.map_err(|e| {
        let mut d = Diagnostic::new(e.code(), format!("/returns{}", if e.path() == "/" { "" } else { e.path() }), e.message().to_string());
        if e.code() == "RMT-E0101" {
            d = d.hint("bound every type: lists need `max`, strings `max_len`, numbers `min`/`max`, timestamps `min`/`max`/`granularity`");
        }
        d
    })
}

/// Analyze a manifest for `principal`. Returns facts or diagnostics.
pub async fn analyze(
    m: &Manifest,
    plane: &ReadPlane,
    principal: &Principal,
    hl: &HolderLimits,
) -> Result<Analysis, Vec<Diagnostic>> {
    let mut diags = Vec::new();
    let mut warnings = Vec::new();

    if !hl.modes.iter().any(|x| x == m.mode.as_str()) {
        diags.push(Diagnostic::new(
            E_MODE,
            "/mode",
            format!("mode `{}` is not offered by this Holder", m.mode.as_str()),
        ));
    }

    // ---- returns
    let rt_template = match parse_returns(&m.returns) {
        Ok(t) => Some(t),
        Err(d) => {
            diags.push(d);
            None
        }
    };
    let params = m.params.clone();
    let rt = match (&rt_template, &params) {
        (Some(t), Some(p)) => match t.bind(p) {
            Ok(rt) => Some(rt),
            Err(e) => {
                diags.push(Diagnostic::new(
                    e.code(),
                    format!("/returns{}", if e.path() == "/" { "" } else { e.path() }),
                    e.message().to_string(),
                ));
                None
            }
        },
        _ => None,
    };
    if let (Some(t), Some(p)) = (&rt_template, &params) {
        for name in t.params() {
            if !p.contains_key(&name) {
                diags.push(Diagnostic::new(
                    E_PARAM_MISSING,
                    "/params",
                    format!("`returns` references `${name}` but params has no `{name}`"),
                ));
            }
        }
    }

    // ---- reads
    let param_types = m.param_types();
    let mut plans = BTreeMap::new();
    let mut ops: BTreeSet<String> = BTreeSet::new();
    let mut resources: BTreeMap<String, ResourceFacts> = BTreeMap::new();
    let mut max_rows_total = 0u64;
    let mut dp: BTreeMap<String, remit_read::DpShape> = BTreeMap::new();
    for (name, r) in &m.reads {
        let path = format!("/reads/{name}/sql");
        if r.max_rows > hl.max_rows_per_read {
            diags.push(
                Diagnostic::new(E_LIMIT, format!("/reads/{name}/max_rows"), format!("max_rows {} exceeds the Holder maximum {}", r.max_rows, hl.max_rows_per_read))
                    .fix(json!([{"op": "replace", "path": format!("/reads/{name}/max_rows"), "value": hl.max_rows_per_read}])),
            );
        }
        if r.max_calls > hl.max_calls_per_read {
            diags.push(Diagnostic::new(
                E_LIMIT,
                format!("/reads/{name}/max_calls"),
                format!(
                    "max_calls exceeds the Holder maximum {}",
                    hl.max_calls_per_read
                ),
            ));
        }
        if m.mode == Mode::Query && r.max_calls != 1 {
            diags.push(Diagnostic::new(E_LIMIT, format!("/reads/{name}/max_calls"), "query mode runs its root read exactly once").fix(json!([{"op": "replace", "path": format!("/reads/{name}/max_calls"), "value": 1}])));
        }
        let sqlf = match remit_sql::check(&r.sql, &plane.sql_profile()) {
            Ok(f) => f,
            Err(e) => {
                let mut d = Diagnostic::new(e.code, path.clone(), e.message.clone()).span(e.span);
                if let Some(h) = e.hint {
                    d = d.hint(h);
                }
                diags.push(d);
                continue;
            }
        };
        for p in &sqlf.params {
            if !r.params.contains_key(p) {
                diags.push(
                    Diagnostic::new(E_PARAM_UNDECLARED, format!("/reads/{name}/params"), format!("SQL uses `${p}` but the template does not declare it"))
                        .hint("declare its type, e.g. \"params\": {\"from\": \"timestamp\"}")
                        .fix(json!([{"op": "add", "path": format!("/reads/{name}/params/{p}"), "value": "string"}])),
                );
            }
        }
        if m.mode == Mode::Query {
            if let Some(p) = &params {
                for k in sqlf.params.iter() {
                    if !p.contains_key(k) {
                        diags.push(Diagnostic::new(
                            E_PARAM_MISSING,
                            "/params",
                            format!("query param `{k}` is missing"),
                        ));
                    }
                }
            }
        }
        ops.extend(sqlf.ops.iter().cloned());
        let pf = match plane.analyze(&r.sql, principal, &r.params).await {
            Ok(pf) => pf,
            Err(e) => {
                diags.push(Diagnostic::new(e.code(), path.clone(), e.to_string()));
                continue;
            }
        };
        let rows = r.max_rows.saturating_mul(r.max_calls as u64);
        max_rows_total = max_rows_total.saturating_add(rows);
        // Search functions read their index's table: `search` + indexed columns.
        for (f, idx) in &sqlf.table_function_calls {
            let Some(ix) = idx.as_deref().and_then(|i| plane.index(i)) else {
                diags.push(Diagnostic::new(
                    "RMT-E0211",
                    path.clone(),
                    format!("{f}(): the first argument must name an index (string literal)"),
                ));
                continue;
            };
            let rf = resources
                .entry(ix.table.clone())
                .or_insert_with(|| ResourceFacts {
                    aggregate_only: true,
                    ..Default::default()
                });
            rf.columns.insert(ix.id_column.clone());
            if let Some(c) = ix.text_column.as_ref().or(ix.vector_column.as_ref()) {
                rf.columns.insert(c.clone());
            }
            rf.actions.insert("search".into());
            rf.aggregate_only = false;
            // Search returns row ids and scores: row-level by construction.
            if plane
                .resource(&ix.table)
                .is_some_and(|c| c.aggregate_only || c.dp.is_some())
            {
                diags.push(Diagnostic::new(
                    "RMT-E0304",
                    path.clone(),
                    format!(
                        "`{}` is aggregate-only: search over it would reveal individual rows",
                        ix.table
                    ),
                ));
            }
            rf.max_rows_total = rf.max_rows_total.saturating_add(rows);
        }
        for (t, tf) in &pf.tables {
            let rf = resources.entry(t.clone()).or_insert_with(|| ResourceFacts {
                aggregate_only: true,
                ..Default::default()
            });
            rf.columns.extend(tf.columns.iter().cloned());
            rf.aggregate_only &= tf.aggregated && !sqlf.ops.contains("collect");
            rf.actions
                .insert(if tf.aggregated && !sqlf.ops.contains("collect") {
                    "aggregate".into()
                } else {
                    "read".into()
                });
            if m.mode == Mode::Kernel {
                rf.actions.insert("run_kernel".into());
            }
            rf.max_rows_total = rf.max_rows_total.saturating_add(rows);
            if let Some(cfg) = plane.resource(t) {
                if cfg.aggregate_only && !(tf.aggregated && !sqlf.ops.contains("collect")) {
                    diags.push(
                        Diagnostic::new("RMT-E0304", path.clone(), format!("`{t}` is aggregate-only: every read of it must aggregate (GROUP BY / COUNT / SUM …)"))
                            .hint("aggregate in SQL; raw rows from this resource never reach kernels"),
                    );
                }
                if cfg.dp.is_some() && m.limits.epsilon.unwrap_or(0.0) <= 0.0 {
                    diags.push(
                        Diagnostic::new(
                            "RMT-E0160",
                            "/limits/epsilon",
                            format!("`{t}` is DP-governed: declare `limits.epsilon` (> 0)"),
                        )
                        .fix(json!([{"op": "add", "path": "/limits/epsilon", "value": 0.1}])),
                    );
                }
            }
        }
        if pf.dp {
            match plane.dp_shape(&r.sql, principal, &r.params).await {
                Ok(s) => {
                    dp.insert(name.clone(), s);
                }
                Err(e) => diags.push(
                    Diagnostic::new(e.code(), path.clone(), e.to_string())
                        .hint("e.g. SELECT region, COUNT(*) AS n, SUM(arr) AS total FROM crm.accounts GROUP BY region"),
                ),
            }
        }
        if m.mode == Mode::Query {
            if let (Some(rt), true) = (&rt, diags.is_empty()) {
                if let Err(d) = check_query_shape(rt, &pf) {
                    diags.push(d);
                }
            }
        }
        plans.insert(name.clone(), pf);
    }

    // ---- code
    if m.mode == Mode::Kernel {
        if let Some(c) = &m.code {
            let is_js = c.lang == "js" || c.lang.starts_with("js/");
            if !hl.languages.iter().any(|l| {
                l == &c.lang
                    || (c.lang == "js" && l.starts_with("js/"))
                    || (c.lang == "python" && l.starts_with("python/"))
            }) {
                diags.push(Diagnostic::new(
                    E_LANG,
                    "/code/lang",
                    format!(
                        "language `{}` is not offered (available: {})",
                        c.lang,
                        hl.languages.join(", ")
                    ),
                ));
            } else if let (true, Some(src)) = (is_js, &c.source) {
                diags.extend(check_js(src, &c.entry));
            }
            ops.insert("kernel".into());
        }
    }

    // ---- limits
    let l = &m.limits;
    let mut clamps = Vec::new();
    let mut lim = |v: Option<u64>, def: u64, max: u64, field: &str| -> u64 {
        let x = v.unwrap_or(def);
        if x > max {
            clamps.push(json!({"op": "replace", "path": format!("/limits/{field}"), "value": max}));
            max
        } else {
            x
        }
    };
    let limits = EffectiveLimits {
        fuel: lim(l.fuel, hl.default_fuel, hl.max_fuel, "fuel"),
        memory_bytes: lim(
            l.memory_bytes,
            hl.default_memory_bytes,
            hl.max_memory_bytes,
            "memory_bytes",
        ),
        wall_ms: lim(l.wall_ms, hl.default_wall_ms, hl.max_wall_ms, "wall_ms"),
        scan_rows: lim(l.scan_rows, hl.max_scan_rows, hl.max_scan_rows, "scan_rows"),
        scan_bytes: lim(
            l.scan_bytes,
            hl.max_scan_bytes,
            hl.max_scan_bytes,
            "scan_bytes",
        ),
        output_bytes: lim(
            l.output_bytes,
            hl.default_output_bytes,
            hl.max_output_bytes,
            "output_bytes",
        ),
        epsilon: l.epsilon.unwrap_or(0.0),
    };

    // ---- bits
    let (capacity_bits, result_bits) = match &rt {
        Some(rt) => {
            let c = rt.capacity_bits();
            if rt.capacity_bits_ceil() == u64::MAX {
                diags.push(Diagnostic::new(
                    E_BITS,
                    "/returns",
                    "result type capacity is unbounded",
                ));
            }
            (
                c,
                rt.capacity_bits_ceil().saturating_add(status_bits() as u64),
            )
        }
        None => (0.0, 0),
    };
    if let (Some(b), Some(rt)) = (l.bits, &rt) {
        if rt.capacity_bits_ceil() > b {
            diags.push(
                Diagnostic::new(E_BITS, "/limits/bits", format!("result type can carry {} bits, above the declared pre-commitment of {b}", rt.capacity_bits_ceil()))
                    .hint("tighten the type (smaller list max, coarser granularity/precision) or raise `limits.bits`"),
            );
        }
    }
    if let Some(rt) = &rt {
        if has_unquantized_float(rt) {
            warnings.push(
                Diagnostic::new(
                    "RMT-W0101",
                    "/returns",
                    "unquantized float carries 64 bits; add `precision`",
                )
                .hint("e.g. {\"float\": {\"min\": 0, \"max\": 1e9, \"precision\": 1}}"),
            );
        }
        let max_json_bytes = rt.max_json_bytes();
        if max_json_bytes > limits.output_bytes {
            warnings.push(Diagnostic::new(
                "RMT-W0102",
                "/limits/output_bytes",
                format!("worst-case encoded result ({max_json_bytes} bytes) exceeds output_bytes ({}); large results will be rejected", limits.output_bytes),
            ));
        }
    }

    if !diags.is_empty() {
        return Err(diags);
    }
    let aggregate_only = !resources.is_empty() && resources.values().all(|r| r.aggregate_only);
    // DP reads enforce k on the *noisy* unit count, so no exact k is claimed.
    let min_group_size = if aggregate_only && dp.is_empty() {
        plans
            .values()
            .map(|p| p.min_group_size)
            .collect::<Option<Vec<_>>>()
            .and_then(|v| v.into_iter().min())
    } else {
        None
    };
    let scan_bound: u64 = plans.values().map(|p| p.scan_rows_bound).sum();
    let cost = json!({
        "scan_rows": bucket(scan_bound),
        "fuel": bucket(limits.fuel),
        "result_bits": result_bits,
    });
    let facts = Facts {
        mode: m.mode.as_str().into(),
        purpose: m.purpose.clone(),
        resources,
        ops,
        aggregate_only,
        min_group_size,
        result_bits,
        capacity_bits,
        fuel: limits.fuel,
        memory_bytes: limits.memory_bytes,
        wall_ms: limits.wall_ms,
        scan_rows: limits.scan_rows,
        output_bytes: limits.output_bytes,
        max_rows_total,
        epsilon_milli: (limits.epsilon * 1000.0).round() as u64,
        standing_approval: false,
        authority: BTreeSet::new(),
        cost,
    };
    Ok(Analysis {
        facts,
        rt,
        rt_template: rt_template.expect("no diagnostics"),
        limits,
        plans,
        dp,
        param_types,
        clamps,
        warnings,
    })
}

/// Coarse bucket string for a count (`≤20M`).
pub fn bucket(n: u64) -> String {
    const STEPS: [(u64, &str); 10] = [
        (1_000, "≤1K"),
        (10_000, "≤10K"),
        (100_000, "≤100K"),
        (1_000_000, "≤1M"),
        (5_000_000, "≤5M"),
        (20_000_000, "≤20M"),
        (100_000_000, "≤100M"),
        (500_000_000, "≤500M"),
        (2_000_000_000, "≤2G"),
        (u64::MAX, ">2G"),
    ];
    STEPS
        .iter()
        .find(|(s, _)| n <= *s)
        .map(|(_, b)| b.to_string())
        .unwrap_or_default()
}

/// Bucket for durations (`≤50ms`).
pub fn bucket_ms(us: u64) -> String {
    const STEPS: [(u64, &str); 8] = [
        (1_000, "≤1ms"),
        (10_000, "≤10ms"),
        (50_000, "≤50ms"),
        (250_000, "≤250ms"),
        (1_000_000, "≤1s"),
        (5_000_000, "≤5s"),
        (30_000_000, "≤30s"),
        (u64::MAX, ">30s"),
    ];
    STEPS
        .iter()
        .find(|(s, _)| us <= *s)
        .map(|(_, b)| b.to_string())
        .unwrap_or_default()
}

fn has_unquantized_float(rt: &Rt) -> bool {
    match rt {
        Rt::Float {
            precision: None, ..
        } => true,
        Rt::List { of, .. } | Rt::Table { of, .. } | Rt::Optional(of) => has_unquantized_float(of),
        Rt::Struct { fields } => fields.iter().any(|(_, t)| has_unquantized_float(t)),
        _ => false,
    }
}

/// Query mode: the root query *is* the result. Check its columns against
/// the declared type.
fn check_query_shape(rt: &Rt, pf: &PlanFacts) -> Result<(), Diagnostic> {
    let cols: Vec<&(String, String)> = pf.output.iter().collect();
    let row = match rt {
        Rt::List { of, .. } | Rt::Table { of, .. } => of.as_ref(),
        Rt::Struct { .. } => rt,
        scalar => {
            if cols.len() != 1 {
                return Err(Diagnostic::new(
                    E_SHAPE,
                    "/returns",
                    format!(
                        "a scalar result needs exactly one output column; the query returns {}",
                        cols.len()
                    ),
                ));
            }
            return compat(scalar, &cols[0].1, &cols[0].0);
        }
    };
    let Rt::Struct { fields } = row else {
        if cols.len() == 1 {
            return compat(row, &cols[0].1, &cols[0].0);
        }
        return Err(Diagnostic::new(
            E_SHAPE,
            "/returns",
            "list items must be a struct whose fields match the query's output columns",
        ));
    };
    for (name, kind) in &pf.output {
        let Some((_, t)) = fields.iter().find(|(f, _)| f == name) else {
            return Err(Diagnostic::new(
                E_SHAPE,
                "/returns",
                format!("output column `{name}` is not declared in `returns`"),
            )
            .hint("alias columns to match field names, or add the field to the struct"));
        };
        compat(t, kind, name)?;
    }
    for (f, t) in fields {
        if !matches!(t, Rt::Optional(_)) && !pf.output.iter().any(|(c, _)| c == f) {
            return Err(Diagnostic::new(
                E_SHAPE,
                "/returns",
                format!("declared field `{f}` is not an output column of the query"),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::match_like_matches_macro)] // one line per type pair reads better
fn compat(t: &Rt, kind: &str, col: &str) -> Result<(), Diagnostic> {
    let t = match t {
        Rt::Optional(i) => i.as_ref(),
        t => t,
    };
    let ok = match (t, kind) {
        (Rt::Bool, "bool") => true,
        (Rt::Int { .. }, "int") => true,
        (Rt::Float { .. } | Rt::Decimal { .. }, "float" | "int") => true,
        (Rt::Enum { .. } | Rt::String { .. }, "string") => true,
        (Rt::Timestamp { .. }, "timestamp") => true,
        (Rt::Date { .. }, "date") => true,
        (Rt::Bytes { .. }, "bytes") => true,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(Diagnostic::new(
            E_SHAPE,
            "/returns",
            format!("column `{col}` is {kind}, but `returns` declares {t}"),
        ))
    }
}

/// Render an access card (for approvers and reviewer agents): reads,
/// columns, output type, bits, budgets, purpose — never raw Sender text.
pub fn access_card(m: &Manifest, a: &Analysis) -> Value {
    let reads: Vec<Value> = m
        .reads
        .iter()
        .map(|(n, r)| {
            let pf = a.plans.get(n);
            json!({
                "name": n,
                "resources": pf.map(|p| p.tables.iter().map(|(t, f)| json!({"resource": t, "columns": f.columns, "aggregated": f.aggregated})).collect::<Vec<_>>()).unwrap_or_default(),
                "max_rows": r.max_rows,
                "max_calls": r.max_calls,
            })
        })
        .collect();
    json!({
        "remit_id": m.remit_id(),
        "sender": m.sender,
        "purpose": m.purpose,
        "mode": m.mode.as_str(),
        "reads": reads,
        "returns": a.rt.as_ref().map(|r| r.to_string()).unwrap_or_else(|| "(template)".into()),
        "result_bits_max": a.facts.result_bits,
        "aggregate_only": a.facts.aggregate_only,
        "min_group_size": a.facts.min_group_size,
        "limits": a.limits,
        "ops": a.facts.ops,
        "dp": a.dp,
    })
}

/// Convenience: param map, or empty.
pub fn params_or_empty(m: &Manifest) -> Map<String, Value> {
    m.params.clone().unwrap_or_default()
}

#[cfg(test)]
mod tests;
