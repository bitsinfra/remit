//! Binder and lineage over a *catalog document* (no engine, no data): resolves
//! relations and columns, infers output columns, and reports what each read
//! touches. This is what SDKs run locally so an LLM's repair loop converges
//! offline. The Holder's plan-based analysis stays authoritative; this binder
//! is conservative (it never accepts an unknown relation or column).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use serde::Serialize;
use serde_json::Value;
use sqlparser::ast::{
    visit_expressions, DataType, Expr, FunctionArg, FunctionArgExpr, FunctionArguments,
    GroupByExpr, Query, SelectItem, SelectItemQualifiedWildcardKind, SetExpr, Spanned, Statement,
    TableFactor, Value as Lit,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::{check, obj_name, Profile, SqlError, AGGREGATE_FUNCTIONS};

pub const E_RELATION: &str = "RMT-E0212";
pub const E_COLUMN: &str = "RMT-E0213";

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutCol {
    pub name: String,
    /// bool | int | float | string | timestamp | date | bytes | unknown
    #[serde(rename = "type")]
    pub ty: String,
    pub nullable: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Bound {
    pub columns: Vec<OutCol>,
    /// Catalog columns read, per resource.
    pub reads: BTreeMap<String, BTreeSet<String>>,
    /// Every scanned resource is under an aggregate.
    pub aggregate_only: bool,
}

#[derive(Clone)]
struct Col {
    name: String,
    ty: String,
    nullable: bool,
    /// Catalog column this one renames, if any.
    origin: Option<(String, String)>,
}

#[derive(Clone)]
struct Rel {
    alias: String,
    cols: Vec<Col>,
}

struct Binder {
    catalog: BTreeMap<String, Vec<Col>>,
    reads: BTreeMap<String, BTreeSet<String>>,
    raw_scan: bool,
}

type R<T> = Result<T, SqlError>;

fn err(
    code: &'static str,
    message: String,
    span: Option<(u64, u64)>,
    hint: Option<String>,
) -> SqlError {
    SqlError {
        code,
        message,
        span,
        hint,
    }
}

fn at(e: &impl Spanned) -> Option<(u64, u64)> {
    let s = e.span();
    (s.start.line > 0).then_some((s.start.line, s.start.column))
}

/// Closest name by edit distance, for hints.
fn closest<'a>(name: &str, names: impl Iterator<Item = &'a String>) -> Option<String> {
    let dist = |a: &str, b: &str| {
        let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
        let mut row: Vec<usize> = (0..=b.len()).collect();
        for i in 1..=a.len() {
            let mut prev = row[0];
            row[0] = i;
            for j in 1..=b.len() {
                let cur = row[j];
                row[j] = (prev + (a[i - 1] != b[j - 1]) as usize)
                    .min(cur + 1)
                    .min(row[j - 1] + 1);
                prev = cur;
            }
        }
        row[b.len()]
    };
    names
        .map(|n| (dist(name, n), n))
        .min_by_key(|x| x.0)
        .filter(|(d, n)| *d <= 1 + n.len() / 3)
        .map(|(_, n)| n.clone())
}

/// Bind `sql` against a catalog document's `resources`.
pub fn bind(sql: &str, catalog: &Value, profile: &Profile) -> R<Bound> {
    check(sql, profile)?;
    let stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .map_err(|e| err(crate::E_PARSE, e.to_string(), None, None))?;
    let Some(Statement::Query(q)) = stmts.first() else {
        return Err(err(
            crate::E_NOT_QUERY,
            "only SELECT queries are allowed".into(),
            None,
            None,
        ));
    };
    let mut cat = BTreeMap::new();
    for r in catalog["resources"].as_array().into_iter().flatten() {
        let name = r["name"].as_str().unwrap_or("").to_lowercase();
        let cols = r["columns"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| {
                let n = c["name"].as_str()?.to_string();
                Some(Col {
                    ty: c["type"].as_str().unwrap_or("unknown").into(),
                    nullable: c["nullable"].as_bool().unwrap_or(true),
                    origin: Some((name.clone(), n.clone())),
                    name: n,
                })
            })
            .collect();
        cat.insert(name, cols);
    }
    let mut b = Binder {
        catalog: cat,
        reads: BTreeMap::new(),
        raw_scan: false,
    };
    let cols = b.query(q, &BTreeMap::new(), &[], false)?;
    Ok(Bound {
        columns: cols
            .into_iter()
            .map(|c| OutCol {
                name: c.name,
                ty: c.ty,
                nullable: c.nullable,
            })
            .collect(),
        aggregate_only: !b.reads.is_empty() && !b.raw_scan,
        reads: b.reads,
    })
}

impl Binder {
    fn query(
        &mut self,
        q: &Query,
        ctes: &BTreeMap<String, Vec<Col>>,
        outer: &[Rel],
        under: bool,
    ) -> R<Vec<Col>> {
        let mut ctes = ctes.clone();
        if let Some(w) = &q.with {
            for c in &w.cte_tables {
                let mut cols = self.query(&c.query, &ctes, outer, under)?;
                for (i, a) in c.alias.columns.iter().enumerate() {
                    if let Some(x) = cols.get_mut(i) {
                        x.name = a.name.value.to_lowercase();
                    }
                }
                ctes.insert(c.alias.name.value.to_lowercase(), cols);
            }
        }
        match q.body.as_ref() {
            SetExpr::Query(q) => self.query(q, &ctes, outer, under),
            SetExpr::Select(s) => {
                let is_agg = !matches!(&s.group_by, GroupByExpr::Expressions(e, _) if e.is_empty())
                    || s.projection.iter().any(has_aggregate)
                    || s.having.as_ref().is_some_and(expr_has_aggregate);
                let mut scope = Vec::new();
                for twj in &s.from {
                    scope.push(self.relation(&twj.relation, &ctes, outer, under || is_agg)?);
                    for j in &twj.joins {
                        let left = matches!(
                            j.join_operator,
                            sqlparser::ast::JoinOperator::Left(_)
                                | sqlparser::ast::JoinOperator::LeftOuter(_)
                        );
                        let mut r = self.relation(&j.relation, &ctes, outer, under || is_agg)?;
                        if left {
                            r.cols.iter_mut().for_each(|c| c.nullable = true);
                        }
                        scope.push(r);
                        use sqlparser::ast::{JoinConstraint, JoinOperator as J};
                        if let J::Join(JoinConstraint::On(e))
                        | J::Inner(JoinConstraint::On(e))
                        | J::Left(JoinConstraint::On(e))
                        | J::LeftOuter(JoinConstraint::On(e)) = &j.join_operator
                        {
                            self.expr(e, &scope, outer, &ctes)?;
                        }
                    }
                }
                let mut out = Vec::new();
                for item in &s.projection {
                    match item {
                        SelectItem::UnnamedExpr(e) => {
                            out.push(self.item(e, None, &scope, outer, &ctes)?)
                        }
                        SelectItem::ExprWithAlias { expr, alias } => out.push(self.item(
                            expr,
                            Some(alias.value.clone()),
                            &scope,
                            outer,
                            &ctes,
                        )?),
                        SelectItem::Wildcard(_) => {
                            for c in scope.iter().flat_map(|r| r.cols.clone()) {
                                self.note(&c);
                                out.push(c);
                            }
                        }
                        SelectItem::QualifiedWildcard(
                            SelectItemQualifiedWildcardKind::ObjectName(n),
                            _,
                        ) => {
                            let n = obj_name(n);
                            let r = scope
                                .iter()
                                .find(|r| {
                                    r.alias == n || r.alias.rsplit('.').next() == Some(n.as_str())
                                })
                                .cloned()
                                .ok_or_else(|| {
                                    err(
                                        E_RELATION,
                                        format!("relation `{n}` is not in FROM"),
                                        at(item),
                                        None,
                                    )
                                })?;
                            for c in r.cols {
                                self.note(&c);
                                out.push(c);
                            }
                        }
                        _ => {}
                    }
                }
                for e in s.selection.iter().chain(s.having.iter()) {
                    self.expr(e, &scope, outer, &ctes)?;
                }
                // GROUP BY / ORDER BY may also name output columns or positions.
                let mut with_out = scope.clone();
                with_out.push(Rel {
                    alias: String::new(),
                    cols: out.clone(),
                });
                if let GroupByExpr::Expressions(es, _) = &s.group_by {
                    for e in es {
                        self.expr(e, &with_out, outer, &ctes)?;
                    }
                }
                if let Some(sqlparser::ast::OrderBy {
                    kind: sqlparser::ast::OrderByKind::Expressions(es),
                    ..
                }) = &q.order_by
                {
                    for o in es {
                        self.expr(&o.expr, &with_out, outer, &ctes)?;
                    }
                }
                Ok(out)
            }
            _ => Err(err(
                crate::E_NOT_QUERY,
                "only SELECT bodies are allowed".into(),
                None,
                None,
            )),
        }
    }

    fn relation(
        &mut self,
        t: &TableFactor,
        ctes: &BTreeMap<String, Vec<Col>>,
        outer: &[Rel],
        under: bool,
    ) -> R<Rel> {
        match t {
            TableFactor::Table {
                name, alias, args, ..
            } => {
                let n = obj_name(name);
                let a = alias
                    .as_ref()
                    .map(|a| a.name.value.to_lowercase())
                    .unwrap_or_else(|| n.clone());
                if args.is_some() {
                    let mk = |n: &str, ty: &str| Col {
                        name: n.into(),
                        ty: ty.into(),
                        nullable: false,
                        origin: None,
                    };
                    self.raw_scan = true;
                    return Ok(Rel {
                        alias: a,
                        cols: vec![mk("id", "string"), mk("score", "float")],
                    });
                }
                if let Some(c) = ctes.get(&n) {
                    return Ok(Rel {
                        alias: a,
                        cols: c.clone(),
                    });
                }
                let cols = self.catalog.get(&n).cloned().ok_or_else(|| {
                    let h = closest(&n, self.catalog.keys())
                        .map(|c| format!("did you mean `{c}`?"))
                        .unwrap_or_else(|| {
                            format!(
                                "visible: {}",
                                self.catalog.keys().cloned().collect::<Vec<_>>().join(", ")
                            )
                        });
                    err(
                        E_RELATION,
                        format!("relation `{n}` does not exist"),
                        at(t),
                        Some(h),
                    )
                })?;
                self.reads.entry(n).or_default();
                self.raw_scan |= !under;
                Ok(Rel { alias: a, cols })
            }
            TableFactor::Derived {
                subquery, alias, ..
            } => {
                let cols = self.query(subquery, ctes, outer, under)?;
                Ok(Rel {
                    alias: alias
                        .as_ref()
                        .map(|a| a.name.value.to_lowercase())
                        .unwrap_or_default(),
                    cols,
                })
            }
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                let mut cols = self
                    .relation(&table_with_joins.relation, ctes, outer, under)?
                    .cols;
                for j in &table_with_joins.joins {
                    cols.extend(self.relation(&j.relation, ctes, outer, under)?.cols);
                }
                Ok(Rel {
                    alias: String::new(),
                    cols,
                })
            }
            _ => Err(err(
                crate::E_CLAUSE,
                "this FROM item is not in the Remit SQL profile".into(),
                at(t),
                None,
            )),
        }
    }

    fn note(&mut self, c: &Col) {
        if let Some((t, n)) = &c.origin {
            self.reads.entry(t.clone()).or_default().insert(n.clone());
        }
    }

    fn item(
        &mut self,
        e: &Expr,
        alias: Option<String>,
        scope: &[Rel],
        outer: &[Rel],
        ctes: &BTreeMap<String, Vec<Col>>,
    ) -> R<Col> {
        let mut c = self.expr(e, scope, outer, ctes)?;
        if let Some(a) = alias {
            c.name = a.to_lowercase();
        }
        Ok(c)
    }

    fn lookup(
        &mut self,
        qual: Option<&str>,
        name: &str,
        e: &Expr,
        scope: &[Rel],
        outer: &[Rel],
    ) -> R<Col> {
        for rels in [scope, outer] {
            for r in rels {
                if let Some(q) = qual {
                    if r.alias != q && r.alias.rsplit('.').next() != Some(q) {
                        continue;
                    }
                }
                if let Some(c) = r.cols.iter().find(|c| c.name.eq_ignore_ascii_case(name)) {
                    let c = c.clone();
                    self.note(&c);
                    return Ok(c);
                }
            }
        }
        let names: Vec<String> = scope
            .iter()
            .flat_map(|r| r.cols.iter().map(|c| c.name.clone()))
            .collect();
        let h = closest(name, names.iter())
            .map(|c| format!("did you mean `{c}`?"))
            .unwrap_or_else(|| format!("available: {}", names.join(", ")));
        Err(err(
            E_COLUMN,
            format!("column `{name}` does not exist"),
            at(e),
            Some(h),
        ))
    }

    /// Type (and, for plain columns, origin) of an expression; binds every
    /// column inside it.
    fn expr(
        &mut self,
        e: &Expr,
        scope: &[Rel],
        outer: &[Rel],
        ctes: &BTreeMap<String, Vec<Col>>,
    ) -> R<Col> {
        let anon = |ty: &str, nullable: bool| Col {
            name: "?column?".into(),
            ty: ty.into(),
            nullable,
            origin: None,
        };
        use sqlparser::ast::BinaryOperator as B;
        Ok(match e {
            Expr::Identifier(i) => self.lookup(None, &i.value, e, scope, outer)?,
            Expr::CompoundIdentifier(p) if p.len() >= 2 => {
                let q = p[..p.len() - 1]
                    .iter()
                    .map(|x| x.value.to_lowercase())
                    .collect::<Vec<_>>()
                    .join(".");
                self.lookup(Some(&q), &p[p.len() - 1].value, e, scope, outer)?
            }
            Expr::Value(v) => match &v.value {
                Lit::Number(n, _) if n.contains(['.', 'e', 'E']) => anon("float", false),
                Lit::Number(..) => anon("int", false),
                Lit::Boolean(_) => anon("bool", false),
                Lit::Null => anon("unknown", true),
                Lit::Placeholder(_) => anon("unknown", false),
                _ => anon("string", false),
            },
            Expr::Nested(x) => self.expr(x, scope, outer, ctes)?,
            Expr::UnaryOp { expr, op } => {
                let c = self.expr(expr, scope, outer, ctes)?;
                if matches!(op, sqlparser::ast::UnaryOperator::Not) {
                    anon("bool", c.nullable)
                } else {
                    anon(&c.ty, c.nullable)
                }
            }
            Expr::BinaryOp { left, op, right } => {
                let (l, r) = (
                    self.expr(left, scope, outer, ctes)?,
                    self.expr(right, scope, outer, ctes)?,
                );
                let n = l.nullable || r.nullable;
                match op {
                    B::Plus | B::Minus | B::Multiply | B::Divide | B::Modulo => {
                        let t = if l.ty == "int" && r.ty == "int" {
                            "int"
                        } else if l.ty == "timestamp" || l.ty == "date" {
                            l.ty.as_str()
                        } else {
                            "float"
                        };
                        anon(t, n)
                    }
                    B::StringConcat => anon("string", n),
                    _ => anon("bool", n),
                }
            }
            Expr::IsNull(x)
            | Expr::IsNotNull(x)
            | Expr::IsTrue(x)
            | Expr::IsFalse(x)
            | Expr::IsNotTrue(x)
            | Expr::IsNotFalse(x) => {
                self.expr(x, scope, outer, ctes)?;
                anon("bool", false)
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                for x in [expr, low, high] {
                    self.expr(x, scope, outer, ctes)?;
                }
                anon("bool", true)
            }
            Expr::InList { expr, list, .. } => {
                self.expr(expr, scope, outer, ctes)?;
                for x in list {
                    self.expr(x, scope, outer, ctes)?;
                }
                anon("bool", true)
            }
            Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => {
                self.expr(expr, scope, outer, ctes)?;
                self.expr(pattern, scope, outer, ctes)?;
                anon("bool", true)
            }
            Expr::Cast {
                expr, data_type, ..
            } => {
                let c = self.expr(expr, scope, outer, ctes)?;
                anon(type_name(data_type), c.nullable)
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                if let Some(o) = operand {
                    self.expr(o, scope, outer, ctes)?;
                }
                let mut ty = "unknown".to_string();
                for c in conditions {
                    self.expr(&c.condition, scope, outer, ctes)?;
                    let t = self.expr(&c.result, scope, outer, ctes)?;
                    if ty == "unknown" || (ty == "int" && t.ty == "float") {
                        ty = t.ty;
                    }
                }
                if let Some(x) = else_result {
                    let t = self.expr(x, scope, outer, ctes)?;
                    if ty == "unknown" || (ty == "int" && t.ty == "float") {
                        ty = t.ty;
                    }
                }
                anon(&ty, true)
            }
            Expr::Extract { expr, .. } => {
                self.expr(expr, scope, outer, ctes)?;
                anon("float", true)
            }
            Expr::Ceil { expr, .. } | Expr::Floor { expr, .. } => {
                let c = self.expr(expr, scope, outer, ctes)?;
                anon(if c.ty == "int" { "int" } else { "float" }, c.nullable)
            }
            Expr::Substring { expr, .. } | Expr::Trim { expr, .. } => {
                let c = self.expr(expr, scope, outer, ctes)?;
                anon("string", c.nullable)
            }
            Expr::Position { expr, r#in } => {
                self.expr(expr, scope, outer, ctes)?;
                self.expr(r#in, scope, outer, ctes)?;
                anon("int", true)
            }
            Expr::Interval(_) => anon("unknown", false),
            Expr::TypedString(t) => anon(type_name(&t.data_type), false),
            Expr::Subquery(q) => {
                let outer2: Vec<Rel> = scope.iter().chain(outer).cloned().collect();
                let cols = self.query(q, ctes, &outer2, false)?;
                cols.into_iter()
                    .next()
                    .map(|c| Col {
                        nullable: true,
                        ..c
                    })
                    .unwrap_or_else(|| anon("unknown", true))
            }
            Expr::InSubquery { expr, subquery, .. } => {
                self.expr(expr, scope, outer, ctes)?;
                let outer2: Vec<Rel> = scope.iter().chain(outer).cloned().collect();
                self.query(subquery, ctes, &outer2, false)?;
                anon("bool", true)
            }
            Expr::Exists { subquery, .. } => {
                let outer2: Vec<Rel> = scope.iter().chain(outer).cloned().collect();
                self.query(subquery, ctes, &outer2, false)?;
                anon("bool", false)
            }
            Expr::Function(f) => {
                let name = f
                    .name
                    .0
                    .last()
                    .map(|p| p.to_string().trim_matches('"').to_lowercase())
                    .unwrap_or_default();
                let mut args = Vec::new();
                if let FunctionArguments::List(l) = &f.args {
                    for a in &l.args {
                        if let FunctionArg::Unnamed(FunctionArgExpr::Expr(x)) = a {
                            args.push(self.expr(x, scope, outer, ctes)?);
                        }
                    }
                }
                if let Some(x) = &f.filter {
                    self.expr(x, scope, outer, ctes)?;
                }
                if let Some(sqlparser::ast::WindowType::WindowSpec(w)) = &f.over {
                    for x in w
                        .partition_by
                        .iter()
                        .chain(w.order_by.iter().map(|o| &o.expr))
                    {
                        self.expr(x, scope, outer, ctes)?;
                    }
                }
                let first = args.first().map(|c| c.ty.as_str()).unwrap_or("unknown");
                let (ty, nullable) = match name.as_str() {
                    "count" | "row_number" | "rank" | "dense_rank" | "ntile" => ("int", false),
                    "sum" if first == "int" => ("int", true),
                    "sum" | "avg" | "mean" | "median" | "stddev" | "stddev_pop" | "stddev_samp"
                    | "var" | "variance" | "var_pop" | "var_samp" | "corr" | "covar"
                    | "covar_pop" | "covar_samp" | "regr_slope" | "regr_intercept"
                    | "percent_rank" | "cume_dist" | "sqrt" | "cbrt" | "exp" | "ln" | "log"
                    | "log2" | "log10" | "power" | "pow" | "date_part" => ("float", true),
                    "min" | "max" | "coalesce" | "nullif" | "greatest" | "least" | "abs"
                    | "round" | "ceil" | "ceiling" | "floor" | "trunc" | "mod" | "lag" | "lead"
                    | "first_value" | "last_value" | "nth_value" | "sign" => {
                        (first, name != "coalesce" || args.iter().all(|c| c.nullable))
                    }
                    "bool_and" | "bool_or" | "starts_with" | "ends_with" | "regexp_like"
                    | "isnan" | "iszero" => ("bool", true),
                    "length" | "char_length" | "character_length" | "octet_length" | "strpos"
                    | "ascii" | "array_length" | "cardinality" => ("int", true),
                    "date_trunc"
                    | "date_bin"
                    | "to_timestamp"
                    | "to_timestamp_millis"
                    | "to_timestamp_seconds"
                    | "from_unixtime" => ("timestamp", true),
                    "to_date" | "make_date" => ("date", true),
                    "sha256" | "digest" => ("bytes", true),
                    _ => ("string", true),
                };
                Col {
                    name,
                    ty: ty.to_string(),
                    nullable,
                    origin: None,
                }
            }
            other => {
                // Anything else: bind the columns inside it.
                let mut found = Vec::new();
                let _ = visit_expressions(other, |x| {
                    if matches!(x, Expr::Identifier(_) | Expr::CompoundIdentifier(_)) {
                        found.push(x.clone());
                    }
                    ControlFlow::<()>::Continue(())
                });
                for x in found {
                    self.expr(&x, scope, outer, ctes)?;
                }
                anon("unknown", true)
            }
        })
    }
}

fn type_name(t: &DataType) -> &'static str {
    let s = t.to_string().to_uppercase();
    if s.contains("INT") {
        "int"
    } else if s.starts_with("BOOL") {
        "bool"
    } else if s.starts_with("TIMESTAMP") || s.starts_with("DATETIME") {
        "timestamp"
    } else if s == "DATE" {
        "date"
    } else if ["FLOAT", "DOUBLE", "REAL", "NUMERIC", "DECIMAL"]
        .iter()
        .any(|p| s.starts_with(p))
    {
        "float"
    } else if s.starts_with("BYTEA") || s.starts_with("BLOB") {
        "bytes"
    } else {
        "string"
    }
}

fn expr_has_aggregate(e: &Expr) -> bool {
    visit_expressions(e, |x| {
        if let Expr::Function(f) = x {
            let n = f
                .name
                .0
                .last()
                .map(|p| p.to_string().to_lowercase())
                .unwrap_or_default();
            if f.over.is_none() && AGGREGATE_FUNCTIONS.contains(&n.as_str()) {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    })
    .is_break()
}

fn has_aggregate(i: &SelectItem) -> bool {
    match i {
        SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => {
            expr_has_aggregate(e)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cat() -> Value {
        json!({"resources": [
            {"name": "crm.accounts", "columns": [{"name": "id", "type": "string", "nullable": false}, {"name": "region", "type": "string", "nullable": false}, {"name": "arr", "type": "float"}, {"name": "seats", "type": "int"}]},
            {"name": "crm.deals", "columns": [{"name": "account_id", "type": "string"}, {"name": "won", "type": "bool"}, {"name": "closed_at", "type": "timestamp"}]}]})
    }
    fn ok(sql: &str) -> Bound {
        bind(sql, &cat(), &Profile::default()).unwrap_or_else(|e| panic!("{sql}: {e}"))
    }
    fn sig(b: &Bound) -> String {
        b.columns
            .iter()
            .map(|c| format!("{}:{}{}", c.name, c.ty, if c.nullable { "?" } else { "" }))
            .collect::<Vec<_>>()
            .join(",")
    }

    #[test]
    fn infers_outputs_and_lineage() {
        let b = ok("SELECT region, SUM(arr) AS arr, COUNT(*) AS n, SUM(seats) AS seats FROM crm.accounts WHERE id <> $x GROUP BY region ORDER BY arr DESC");
        assert_eq!(sig(&b), "region:string,arr:float?,n:int,seats:int?");
        assert!(b.aggregate_only);
        assert_eq!(
            b.reads["crm.accounts"]
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
            "arr,id,region,seats"
        );
        let b = ok("WITH w AS (SELECT account_id, MAX(closed_at) AS last FROM crm.deals WHERE won GROUP BY account_id) SELECT a.region, w.last, a.seats + 1 AS s, CASE WHEN a.arr > 5 THEN 1 ELSE 2.5 END AS c FROM crm.accounts a LEFT JOIN w ON w.account_id = a.id");
        assert_eq!(sig(&b), "region:string,last:timestamp?,s:int?,c:float?");
        assert!(!b.aggregate_only);
        assert_eq!(
            sig(&ok("SELECT * FROM crm.deals")),
            "account_id:string?,won:bool?,closed_at:timestamp?"
        );
        assert_eq!(
            sig(&ok(
                "SELECT COUNT(*) AS n FROM (SELECT DISTINCT region FROM crm.accounts) t"
            )),
            "n:int"
        );
        assert_eq!(sig(&ok("SELECT CAST(seats AS DOUBLE) AS d FROM crm.accounts a WHERE EXISTS (SELECT 1 FROM crm.deals d WHERE d.account_id = a.id)")), "d:float?");
    }

    #[test]
    fn errors_are_located_with_hints() {
        let e = bind(
            "SELECT regoin FROM crm.accounts",
            &cat(),
            &Profile::default(),
        )
        .unwrap_err();
        assert_eq!(
            (e.code, e.hint.as_deref(), e.span),
            (E_COLUMN, Some("did you mean `region`?"), Some((1, 8)))
        );
        let e = bind("SELECT 1 FROM crm.account", &cat(), &Profile::default()).unwrap_err();
        assert_eq!(
            (e.code, e.hint.as_deref()),
            (E_RELATION, Some("did you mean `crm.accounts`?"))
        );
        assert!(bind(
            "SELECT x.id FROM crm.accounts a",
            &cat(),
            &Profile::default()
        )
        .is_err());
        assert!(bind(
            "SELECT won FROM crm.accounts WHERE id IN (SELECT nope FROM crm.deals)",
            &cat(),
            &Profile::default()
        )
        .is_err());
        assert_eq!(
            bind("SELECT now()", &cat(), &Profile::default())
                .unwrap_err()
                .code,
            crate::E_FUNCTION
        );
    }
}
