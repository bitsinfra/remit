//! Differentially private rewriting of Query-mode aggregates (Qrlew-style):
//! a relational rewrite that tracks **row ownership** (which privacy unit
//! owns each row) and **value bounds**, and refuses every plan shape whose
//! sensitivity it cannot bound.
//!
//! Accepted shape: `[Limit] [Sort] Projection(Aggregate(rows))`, where `rows`
//! is any row-level pipeline (filters, projections, derived tables, inner
//! joins on the privacy unit, joins to non-DP tables) built from total
//! expressions. No HAVING, window, DISTINCT, nested aggregate or subquery
//! predicate reaches the data un-noised. `ORDER BY`/`LIMIT` are applied to the
//! *noisy* answer.
//!
//! Rewrite, in the plan: keep at most `m` rows per privacy unit; clamp every
//! summed expression to its derived bounds; replace AVG by SUM and COUNT; add
//! a hidden unit count used for τ-thresholding of group keys. The noise itself
//! is added by `remit-emit::dp` (OpenDP), never here and never by the Sender.

use std::collections::BTreeMap;

use datafusion::common::{Column, DFSchema, TableReference};
use datafusion::logical_expr::expr::AggregateFunction;
use datafusion::logical_expr::{
    col, lit, Aggregate, Expr, ExprFunctionExt, ExprSchemable, JoinType, LogicalPlan,
    LogicalPlanBuilder, Operator, SortExpr,
};
use datafusion::scalar::ScalarValue;
use serde::Serialize;

use crate::config::ResourceConfig;
use crate::ReadError;

/// One output column of a DP query.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DpOut {
    /// Group key (released only for groups that pass the τ-threshold).
    Key,
    Count,
    /// COUNT(DISTINCT privacy unit).
    CountUnits,
    Sum {
        lo: f64,
        hi: f64,
        /// The SQL type is an integer: round the noisy value.
        int: bool,
    },
    /// Noisy centered sum / noisy count.
    Avg {
        lo: f64,
        hi: f64,
    },
}

/// The DP treatment of a query.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DpShape {
    /// Output columns in order: name, treatment, output is an integer.
    pub columns: Vec<(String, DpOut)>,
    /// Max rows one privacy unit contributes (over all groups).
    pub m: u64,
    /// Every privacy unit is one row (no unit column declared).
    pub row_level: bool,
    pub grouped: bool,
    /// Policy floor for released groups (from `k`).
    pub min_units: u64,
    /// Post-noise ordering: (output column, ascending, nulls first).
    pub order_by: Vec<(String, bool, bool)>,
    pub limit: Option<u64>,
    /// DP-governed tables.
    pub tables: Vec<String>,
}

/// Alias of the hidden unit count.
pub const UNITS: &str = "__remit_units";

fn no(msg: impl Into<String>) -> ReadError {
    ReadError::Dp(msg.into())
}

/// Resolves scan / view names to catalog resources.
pub trait Catalog {
    fn resource(&self, name: &str) -> Option<(String, &ResourceConfig)>;
}

struct Parsed<'a> {
    agg: &'a Aggregate,
    /// Output (name, index into the aggregate's schema).
    out: Vec<(String, usize)>,
    order: Vec<(String, bool, bool)>,
    limit: Option<u64>,
}

fn strip(e: &Expr) -> &Expr {
    match e {
        Expr::Alias(a) => strip(&a.expr),
        e => e,
    }
}

/// Root shape: `[Limit] [Sort] Projection(Aggregate(..))`.
fn parse(plan: &LogicalPlan) -> Result<Parsed<'_>, ReadError> {
    let mut node = plan;
    let mut limit = None;
    let mut sorts: Vec<&SortExpr> = vec![];
    loop {
        match node {
            LogicalPlan::Limit(l) => {
                if l.skip.is_some() {
                    return Err(no("OFFSET is not available on DP-governed resources"));
                }
                match l.fetch.as_deref().map(strip) {
                    Some(Expr::Literal(ScalarValue::Int64(Some(n)), _)) if *n >= 0 => {
                        limit = Some(*n as u64)
                    }
                    _ => return Err(no("LIMIT must be an integer literal")),
                }
                node = &l.input;
            }
            LogicalPlan::Sort(s) => {
                sorts = s.expr.iter().collect();
                node = &s.input;
            }
            LogicalPlan::SubqueryAlias(a) => node = &a.input,
            _ => break,
        }
    }
    let LogicalPlan::Projection(p) = node else {
        return Err(no(
            "a DP query is one SELECT with aggregates (COUNT, SUM, AVG) and an optional GROUP BY",
        ));
    };
    let agg = match p.input.as_ref() {
        LogicalPlan::Aggregate(a) => a,
        LogicalPlan::Filter(f) if matches!(f.input.as_ref(), LogicalPlan::Aggregate(_)) => {
            return Err(no(
                "HAVING compares exact aggregates; filter the noisy answer instead",
            ))
        }
        _ => return Err(no(
            "a DP query is one SELECT with aggregates (COUNT, SUM, AVG) and an optional GROUP BY",
        )),
    };
    let mut out = Vec::new();
    for (i, e) in p.expr.iter().enumerate() {
        let name = p.schema.field(i).name().clone();
        let Expr::Column(c) = strip(e) else {
            return Err(no(format!("output `{name}` must be a group key or a plain aggregate (compute on the noisy answer instead)")));
        };
        let ix = agg
            .schema
            .index_of_column(c)
            .map_err(|_| no(format!("output `{name}` is not a group key or aggregate")))?;
        out.push((name, ix));
    }
    let mut order = Vec::new();
    for s in sorts {
        let Expr::Column(c) = strip(&s.expr) else {
            return Err(no("ORDER BY must name an output column"));
        };
        if !out.iter().any(|(n, _)| n == &c.name) {
            return Err(no("ORDER BY must name an output column"));
        }
        order.push((c.name.clone(), s.asc, s.nulls_first));
    }
    Ok(Parsed {
        agg,
        out,
        order,
        limit,
    })
}

/// Row-level nodes only; collects the tables underneath.
fn check_rows(
    plan: &LogicalPlan,
    cat: &dyn Catalog,
    tables: &mut BTreeMap<String, ResourceConfig>,
) -> Result<(), ReadError> {
    if let Some((name, cfg)) = view_boundary(plan, cat) {
        tables.insert(name, cfg.clone());
        return Ok(());
    }
    match plan {
        LogicalPlan::Projection(p) => {
            for e in &p.expr {
                total(e, p.input.schema())?;
            }
            check_rows(&p.input, cat, tables)
        }
        LogicalPlan::Filter(f) => {
            total(&f.predicate, f.input.schema())?;
            check_rows(&f.input, cat, tables)
        }
        LogicalPlan::SubqueryAlias(a) => check_rows(&a.input, cat, tables),
        LogicalPlan::Join(j) => {
            if !matches!(j.join_type, JoinType::Inner | JoinType::Left) {
                return Err(no(
                    "only inner and left joins are available on DP-governed resources",
                ));
            }
            for (l, r) in &j.on {
                total(l, j.left.schema())?;
                total(r, j.right.schema())?;
            }
            if let Some(f) = &j.filter {
                total(f, &j.schema)?;
            }
            check_rows(&j.left, cat, tables)?;
            check_rows(&j.right, cat, tables)
        }
        LogicalPlan::Aggregate(_) | LogicalPlan::Distinct(_) => Err(no(
            "nested aggregation is not available on DP-governed resources",
        )),
        LogicalPlan::Window(_) => Err(no(
            "window functions are not available on DP-governed resources",
        )),
        LogicalPlan::Limit(_) | LogicalPlan::Sort(_) => Err(no(
            "ORDER BY / LIMIT inside a derived table is not available on DP-governed resources",
        )),
        _ => Err(no(
            "this query shape is not available on DP-governed resources",
        )),
    }
}

/// Total expressions: they never raise a data-dependent error, so the status
/// channel carries nothing about individual rows.
fn total(e: &Expr, schema: &DFSchema) -> Result<(), ReadError> {
    const FUNCS: &[&str] = &[
        "abs",
        "ceil",
        "ceiling",
        "floor",
        "round",
        "greatest",
        "least",
        "coalesce",
        "nullif",
        "lower",
        "upper",
        "length",
        "char_length",
        "character_length",
        "trim",
        "btrim",
        "ltrim",
        "rtrim",
        "starts_with",
        "ends_with",
        "strpos",
        "left",
        "right",
        "concat",
        "date_trunc",
        "date_part",
        "isnan",
    ];
    let bad = |what: &str| {
        no(format!(
            "{what} can fail on data and is not available on DP-governed resources"
        ))
    };
    match e {
        Expr::Column(_) | Expr::Literal(..) | Expr::Placeholder(_) => Ok(()),
        Expr::Alias(a) => total(&a.expr, schema),
        Expr::Not(x)
        | Expr::IsNull(x)
        | Expr::IsNotNull(x)
        | Expr::IsTrue(x)
        | Expr::IsFalse(x)
        | Expr::IsUnknown(x)
        | Expr::IsNotTrue(x)
        | Expr::IsNotFalse(x)
        | Expr::IsNotUnknown(x)
        | Expr::Negative(x) => total(x, schema),
        Expr::BinaryExpr(b) => {
            match b.op {
                Operator::Eq
                | Operator::NotEq
                | Operator::Lt
                | Operator::LtEq
                | Operator::Gt
                | Operator::GtEq
                | Operator::And
                | Operator::Or
                | Operator::IsDistinctFrom
                | Operator::IsNotDistinctFrom
                | Operator::Plus
                | Operator::Minus
                | Operator::Multiply => {}
                op => return Err(bad(&format!("operator `{op}`"))),
            }
            total(&b.left, schema)?;
            total(&b.right, schema)
        }
        Expr::Between(b) => {
            total(&b.expr, schema)?;
            total(&b.low, schema)?;
            total(&b.high, schema)
        }
        Expr::InList(l) => {
            total(&l.expr, schema)?;
            l.list.iter().try_for_each(|x| total(x, schema))
        }
        Expr::Like(l) => {
            total(&l.expr, schema)?;
            match l.pattern.as_ref() {
                Expr::Literal(..) | Expr::Placeholder(_) => Ok(()),
                _ => Err(bad("LIKE with a non-constant pattern")),
            }
        }
        Expr::Case(c) => {
            if let Some(x) = &c.expr {
                total(x, schema)?;
            }
            for (w, t) in &c.when_then_expr {
                total(w, schema)?;
                total(t, schema)?;
            }
            c.else_expr.as_ref().map_or(Ok(()), |x| total(x, schema))
        }
        Expr::TryCast(c) => total(&c.expr, schema),
        Expr::Cast(c) => {
            // Widening casts only (a parse failure would be data-dependent).
            let from = c.expr.get_type(schema).map_err(ReadError::plan)?;
            let to = e.get_type(schema).map_err(ReadError::plan)?;
            let ok = matches!(c.expr.as_ref(), Expr::Literal(..) | Expr::Placeholder(_))
                || from == to
                || (from.is_numeric() && to.is_floating())
                || (from.is_integer() && to.is_integer())
                || matches!((&from, &to), (f, t) if f.is_temporal() && t.is_temporal())
                || (is_text(&from) && is_text(&to));
            if !ok {
                return Err(bad(&format!("CAST from {from} to {to}")));
            }
            total(&c.expr, schema)
        }
        Expr::ScalarFunction(f) => {
            if !FUNCS.contains(&f.func.name()) {
                return Err(bad(&format!("function `{}`", f.func.name())));
            }
            f.args.iter().try_for_each(|x| total(x, schema))
        }
        Expr::ScalarSubquery(_) | Expr::InSubquery(_) | Expr::Exists(_) => {
            Err(no("subqueries are not available on DP-governed resources"))
        }
        _ => Err(bad("this expression")),
    }
}

fn is_text(t: &datafusion::arrow::datatypes::DataType) -> bool {
    use datafusion::arrow::datatypes::DataType as D;
    matches!(t, D::Utf8 | D::LargeUtf8 | D::Utf8View)
}

/// The catalog resource whose (inlined) policy view or scan this node is.
/// Sender aliases are bare identifiers; view boundaries are `source.table`.
fn view_boundary<'a>(
    plan: &LogicalPlan,
    cat: &'a dyn Catalog,
) -> Option<(String, &'a ResourceConfig)> {
    match plan {
        LogicalPlan::TableScan(t) => cat.resource(&t.table_name.to_string().to_lowercase()),
        LogicalPlan::SubqueryAlias(a) => match &a.alias {
            TableReference::Partial { schema, table } => {
                cat.resource(&format!("{schema}.{table}").to_lowercase())
            }
            TableReference::Full { schema, table, .. } => {
                cat.resource(&format!("{schema}.{table}").to_lowercase())
            }
            TableReference::Bare { .. } => None,
        },
        _ => None,
    }
}

/// Trace a column to the catalog column it renames, through renames only
/// (an expression aliased to a unit column's name is *not* that unit).
fn trace(plan: &LogicalPlan, c: &Column, cat: &dyn Catalog) -> Option<(String, String)> {
    if let Some((name, _)) = view_boundary(plan, cat) {
        return Some((name, c.name.clone()));
    }
    let ix = plan.schema().index_of_column(c).ok()?;
    match plan {
        LogicalPlan::Projection(p) => match strip(&p.expr[ix]) {
            Expr::Column(c2) => trace(&p.input, c2, cat),
            _ => None,
        },
        LogicalPlan::Filter(f) => trace(&f.input, c, cat),
        LogicalPlan::SubqueryAlias(a) => {
            let (q, f) = a.input.schema().qualified_field(ix);
            trace(&a.input, &Column::new(q.cloned(), f.name()), cat)
        }
        LogicalPlan::Join(j) => {
            let n = j.left.schema().fields().len();
            let (side, i) = if ix < n {
                (&j.left, ix)
            } else {
                (&j.right, ix - n)
            };
            let (q, f) = side.schema().qualified_field(i);
            trace(side, &Column::new(q.cloned(), f.name()), cat)
        }
        _ => None,
    }
}

/// Every DP table in a join must be joined on its privacy unit to another DP
/// table, so each joined row belongs to exactly one unit.
fn check_join_units(
    plan: &LogicalPlan,
    cat: &dyn Catalog,
    dp: &BTreeMap<String, String>,
) -> Result<(), ReadError> {
    if view_boundary(plan, cat).is_some() {
        return Ok(());
    }
    if let LogicalPlan::Join(j) = plan {
        let dp_in = |p: &LogicalPlan| -> Result<bool, ReadError> {
            let mut t = BTreeMap::new();
            check_rows(p, cat, &mut t)?;
            Ok(t.keys().any(|k| dp.contains_key(k)))
        };
        let (l, r) = (dp_in(&j.left)?, dp_in(&j.right)?);
        if l && r {
            let is_unit = |p: &LogicalPlan, e: &Expr| match strip(e) {
                Expr::Column(c) => {
                    trace(p, c, cat).is_some_and(|(t, col)| dp.get(&t) == Some(&col))
                }
                _ => false,
            };
            // Before optimization the planner keeps ON equalities in `filter`.
            let mut eqs: Vec<(&Expr, &Expr)> = j.on.iter().map(|(a, b)| (a, b)).collect();
            if let Some(f) = &j.filter {
                for c in datafusion::logical_expr::utils::split_conjunction(f) {
                    if let Expr::BinaryExpr(b) = c {
                        if b.op == Operator::Eq {
                            eqs.push((&b.left, &b.right));
                        }
                    }
                }
            }
            if !eqs.iter().any(|(a, b)| {
                (is_unit(&j.left, a) && is_unit(&j.right, b))
                    || (is_unit(&j.left, b) && is_unit(&j.right, a))
            }) {
                return Err(no(
                    "joins between DP-governed resources must equate their privacy units",
                ));
            }
        }
        if j.join_type == JoinType::Left && r && !l {
            return Err(no(
                "the DP-governed resource must be on the preserved side of a LEFT JOIN",
            ));
        }
    }
    for i in plan.inputs() {
        check_join_units(i, cat, dp)?;
    }
    Ok(())
}

/// Bounds of a numeric row expression, from declared column bounds.
fn interval(e: &Expr, plan: &LogicalPlan, cat: &dyn Catalog) -> Option<(f64, f64)> {
    match e {
        Expr::Alias(a) => interval(&a.expr, plan, cat),
        Expr::Column(c) => column_interval(plan, c, cat),
        Expr::Literal(v, _) => {
            let x = match v {
                ScalarValue::Int64(Some(x)) => *x as f64,
                ScalarValue::Float64(Some(x)) => *x,
                ScalarValue::Int32(Some(x)) => *x as f64,
                ScalarValue::UInt64(Some(x)) => *x as f64,
                ScalarValue::Null => 0.0,
                _ => return None,
            };
            x.is_finite().then_some((x, x))
        }
        Expr::Cast(c) => interval(&c.expr, plan, cat),
        Expr::TryCast(c) => interval(&c.expr, plan, cat),
        Expr::Negative(x) => interval(x, plan, cat).map(|(a, b)| (-b, -a)),
        Expr::BinaryExpr(b) => {
            let ((a, c), (d, f)) = (
                interval(&b.left, plan, cat)?,
                interval(&b.right, plan, cat)?,
            );
            match b.op {
                Operator::Plus => Some((a + d, c + f)),
                Operator::Minus => Some((a - f, c - d)),
                Operator::Multiply => {
                    let p = [a * d, a * f, c * d, c * f];
                    Some((
                        p.iter().copied().fold(f64::INFINITY, f64::min),
                        p.iter().copied().fold(f64::NEG_INFINITY, f64::max),
                    ))
                }
                _ => None,
            }
        }
        Expr::Case(c) => {
            let mut lo = f64::INFINITY;
            let mut hi = f64::NEG_INFINITY;
            for x in c
                .when_then_expr
                .iter()
                .map(|(_, t)| t)
                .chain(c.else_expr.iter())
            {
                let (a, b) = interval(x, plan, cat)?;
                lo = lo.min(a);
                hi = hi.max(b);
            }
            Some((lo, hi))
        }
        Expr::ScalarFunction(f)
            if f.func.name() == "coalesce"
                || f.func.name() == "greatest"
                || f.func.name() == "least" =>
        {
            let v: Vec<(f64, f64)> = f
                .args
                .iter()
                .map(|x| interval(x, plan, cat))
                .collect::<Option<_>>()?;
            Some((
                v.iter().map(|x| x.0).fold(f64::INFINITY, f64::min),
                v.iter().map(|x| x.1).fold(f64::NEG_INFINITY, f64::max),
            ))
        }
        Expr::ScalarFunction(f) if f.func.name() == "abs" => {
            interval(f.args.first()?, plan, cat).map(|(a, b)| (0.0, a.abs().max(b.abs())))
        }
        _ => None,
    }
}

fn column_interval(plan: &LogicalPlan, c: &Column, cat: &dyn Catalog) -> Option<(f64, f64)> {
    if let Some((_, cfg)) = view_boundary(plan, cat) {
        return cfg
            .columns
            .get(&c.name)
            .and_then(|c| c.bounds)
            .map(|[a, b]| (a, b));
    }
    let ix = plan.schema().index_of_column(c).ok()?;
    match plan {
        LogicalPlan::Projection(p) => interval(&p.expr[ix], &p.input, cat),
        LogicalPlan::Filter(f) => column_interval(&f.input, c, cat),
        LogicalPlan::SubqueryAlias(a) => {
            let (q, f) = a.input.schema().qualified_field(ix);
            column_interval(&a.input, &Column::new(q.cloned(), f.name()), cat)
        }
        LogicalPlan::Join(j) => {
            let n = j.left.schema().fields().len();
            let (side, i) = if ix < n {
                (&j.left, ix)
            } else {
                (&j.right, ix - n)
            };
            let (q, f) = side.schema().qualified_field(i);
            column_interval(side, &Column::new(q.cloned(), f.name()), cat)
        }
        _ => None,
    }
}

fn agg_fn(e: &Expr) -> Option<&AggregateFunction> {
    match strip(e) {
        Expr::AggregateFunction(a) => Some(a),
        _ => None,
    }
}

/// Derive the DP treatment, or explain why the plan is not admissible.
pub fn shape(plan: &LogicalPlan, cat: &dyn Catalog) -> Result<DpShape, ReadError> {
    let p = parse(plan)?;
    let input = p.agg.input.as_ref();
    let mut tables = BTreeMap::new();
    check_rows(input, cat, &mut tables)?;
    for g in &p.agg.group_expr {
        if matches!(strip(g), Expr::GroupingSet(_)) {
            return Err(no(
                "GROUPING SETS / ROLLUP / CUBE are not available on DP-governed resources",
            ));
        }
        total(g, input.schema())?;
    }
    let dp: Vec<(&String, &ResourceConfig)> =
        tables.iter().filter(|(_, c)| c.dp.is_some()).collect();
    if dp.is_empty() {
        return Err(no("no DP-governed resource in this query"));
    }
    let units: BTreeMap<String, String> = dp
        .iter()
        .filter_map(|(n, c)| c.privacy_unit.clone().map(|u| ((*n).clone(), u)))
        .collect();
    let row_level = units.is_empty();
    let has_join = count_scans(input, cat) > 1;
    if row_level && has_join {
        return Err(no(
            "joins over a DP-governed resource need its privacy unit declared by the Holder",
        ));
    }
    if !row_level && units.len() != dp.len() {
        return Err(no(
            "every DP-governed resource in a join must declare a privacy unit",
        ));
    }
    check_join_units(input, cat, &units)?;
    if !row_level {
        unit_column(input, cat, &units)?;
    }
    let mut columns = Vec::new();
    let ng = p.agg.group_expr.len();
    for (name, ix) in &p.out {
        if *ix < ng {
            columns.push((name.clone(), DpOut::Key));
            continue;
        }
        let Some(af) = agg_fn(&p.agg.aggr_expr[*ix - ng]) else {
            return Err(no(format!("output `{name}` is not a plain aggregate")));
        };
        if let Some(f) = &af.params.filter {
            total(f, input.schema())?;
        }
        for a in &af.params.args {
            total(a, input.schema())?;
        }
        let bounds = || -> Result<(f64, f64), ReadError> {
            let arg = af
                .params
                .args
                .first()
                .ok_or_else(|| no("missing argument"))?;
            let (lo, hi) = interval(arg, input, cat).ok_or_else(|| no(format!("`{name}`: the Holder declares no bounds for this expression, so its sensitivity is unbounded")))?;
            if !lo.is_finite() || !hi.is_finite() || lo > hi {
                return Err(no(format!("`{name}`: unbounded expression")));
            }
            Ok((lo, hi))
        };
        let out = match (af.func.name().to_lowercase().as_str(), af.params.distinct) {
            ("count", false) => DpOut::Count,
            ("count", true) => {
                let is_unit = af.params.args.len() == 1
                    && matches!(strip(&af.params.args[0]), Expr::Column(c) if trace(input, c, cat).is_some_and(|(t, col)| units.get(&t) == Some(&col)));
                if !is_unit {
                    return Err(no(format!(
                        "`{name}`: COUNT(DISTINCT …) is available on the privacy unit only"
                    )));
                }
                DpOut::CountUnits
            }
            ("sum", false) => {
                let (lo, hi) = bounds()?;
                DpOut::Sum {
                    lo,
                    hi,
                    int: p.agg.schema.field(*ix).data_type().is_integer(),
                }
            }
            ("avg" | "mean", false) => {
                let (lo, hi) = bounds()?;
                DpOut::Avg { lo, hi }
            }
            (f, _) => {
                return Err(no(format!(
                "aggregate `{f}` is not available on DP-governed resources (COUNT, SUM, AVG are)"
            )))
            }
        };
        columns.push((name.clone(), out));
    }
    let m = if row_level {
        1
    } else {
        dp.iter()
            .filter_map(|(_, c)| c.dp.as_ref().map(|d| d.max_contributions.max(1)))
            .min()
            .unwrap_or(1)
    };
    Ok(DpShape {
        columns,
        m,
        row_level,
        grouped: ng > 0,
        min_units: tables.values().filter_map(|c| c.k).max().unwrap_or(0),
        order_by: p.order,
        limit: p.limit,
        tables: dp.iter().map(|(n, _)| (*n).clone()).collect(),
    })
}

fn count_scans(plan: &LogicalPlan, cat: &dyn Catalog) -> usize {
    if view_boundary(plan, cat).is_some() {
        return 1;
    }
    plan.inputs().into_iter().map(|p| count_scans(p, cat)).sum()
}

/// A column of `plan` that is (a rename of) a DP table's privacy unit.
fn unit_column(
    plan: &LogicalPlan,
    cat: &dyn Catalog,
    units: &BTreeMap<String, String>,
) -> Result<Column, ReadError> {
    plan.schema()
        .columns()
        .into_iter()
        .find(|c| trace(plan, c, cat).is_some_and(|(t, col)| units.get(&t) == Some(&col)))
        .ok_or_else(|| {
            let (t, u) = units.iter().next().expect("non-empty");
            no(format!(
                "keep `{u}` of `{t}` available to the aggregate (it identifies the privacy unit)"
            ))
        })
}

/// Rewrite for execution: contribution bounding, clamping, AVG splitting and
/// the hidden unit count. Output columns: `k{i}` for keys, `a{i}` (and `b{i}`
/// for AVG counts) for aggregates, and [`UNITS`].
pub fn rewrite(
    plan: &LogicalPlan,
    cat: &dyn Catalog,
    shape: &DpShape,
) -> Result<LogicalPlan, ReadError> {
    use datafusion::functions_aggregate::expr_fn::{count, count_distinct, sum};
    let p = parse(plan)?;
    let mut tables = BTreeMap::new();
    check_rows(&p.agg.input, cat, &mut tables)?;
    let units: BTreeMap<String, String> = tables
        .iter()
        .filter(|(_, c)| c.dp.is_some())
        .filter_map(|(n, c)| c.privacy_unit.clone().map(|u| (n.clone(), u)))
        .collect();
    let mut b = LogicalPlanBuilder::from(p.agg.input.as_ref().clone());
    let unit = if shape.row_level {
        None
    } else {
        let u = unit_column(&p.agg.input, cat, &units)?;
        let cols: Vec<Expr> = p
            .agg
            .input
            .schema()
            .columns()
            .into_iter()
            .map(Expr::Column)
            .collect();
        let rn = datafusion::functions_window::expr_fn::row_number()
            .partition_by(vec![Expr::Column(u.clone())])
            .build()?;
        let rn_name = rn.schema_name().to_string();
        b = b
            .window(vec![rn])?
            .filter(col(Column::new_unqualified(rn_name)).lt_eq(lit(shape.m)))?
            .project(cols)?;
        Some(u)
    };
    let clamp = |e: &Expr, lo: f64, hi: f64, center: f64| -> Result<Expr, ReadError> {
        use datafusion::arrow::datatypes::DataType;
        let x = e
            .clone()
            .cast_to(&DataType::Float64, p.agg.input.schema())?;
        let nan = datafusion::functions::expr_fn::isnan(x.clone());
        let inner = datafusion::logical_expr::when(x.clone().lt(lit(lo)), lit(lo))
            .when(x.clone().gt(lit(hi)), lit(hi))
            .otherwise(x.clone())?;
        Ok(
            datafusion::logical_expr::when(x.is_null().or(nan), lit(ScalarValue::Float64(None)))
                .otherwise(inner - lit(center))?,
        )
    };
    let ng = p.agg.group_expr.len();
    let mut aggs = Vec::new();
    let mut proj = Vec::new();
    for (i, ((_, ix), (_, kind))) in p.out.iter().zip(&shape.columns).enumerate() {
        if matches!(kind, DpOut::Key) {
            proj.push(Expr::Column(p.agg.schema.columns()[*ix].clone()).alias(format!("k{i}")));
            continue;
        }
        let af = agg_fn(&p.agg.aggr_expr[*ix - ng]).ok_or_else(|| no("aggregate"))?;
        let filtered = |e: Expr| -> Result<Expr, ReadError> {
            Ok(match &af.params.filter {
                Some(f) => e.filter(f.as_ref().clone()).build()?,
                None => e,
            })
        };
        match kind {
            DpOut::Count => aggs.push(
                filtered(count(af.params.args.first().cloned().unwrap_or(lit(1i64))))?
                    .alias(format!("a{i}")),
            ),
            DpOut::CountUnits => aggs
                .push(filtered(count_distinct(af.params.args[0].clone()))?.alias(format!("a{i}"))),
            DpOut::Sum { lo, hi, .. } => aggs.push(
                filtered(sum(clamp(&af.params.args[0], *lo, *hi, 0.0)?))?.alias(format!("a{i}")),
            ),
            DpOut::Avg { lo, hi } => {
                let x = clamp(&af.params.args[0], *lo, *hi, (lo + hi) / 2.0)?;
                aggs.push(filtered(sum(x.clone()))?.alias(format!("a{i}")));
                aggs.push(filtered(count(x))?.alias(format!("b{i}")));
                proj.push(col(format!("b{i}")));
            }
            DpOut::Key => unreachable!(),
        }
        proj.push(col(format!("a{i}")));
    }
    aggs.push(match &unit {
        Some(u) => count_distinct(Expr::Column(u.clone())).alias(UNITS),
        None => count(lit(1i64)).alias(UNITS),
    });
    proj.push(col(UNITS));
    Ok(b.aggregate(p.agg.group_expr.clone(), aggs)?
        .project(proj)?
        .build()?)
}
