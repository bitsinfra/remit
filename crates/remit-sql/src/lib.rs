//! Remit SQL: a strict, deterministic dialect profile over `sqlparser-rs`.
//!
//! The reference parser is shared by the Holder and all SDKs (compiled to
//! Wasm in `remit-verify-wasm`). It checks the *profile* only; binding and
//! column lineage happen against the catalog in the read plane.
//!
//! Allowed: `SELECT`, `WHERE`, inner/left `JOIN`, `GROUP BY`, `HAVING`,
//! `ORDER BY`, `LIMIT`/`OFFSET`, non-recursive CTEs, derived tables and
//! subqueries, allowlisted deterministic functions, Holder table functions.
//! Excluded: DDL/DML, recursive CTEs, set operations, `now()`, `random()`,
//! UDFs, locking clauses, `SELECT INTO`, positional params.

pub mod bind;

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use serde::Serialize;
use sqlparser::ast::{
    Expr, JoinOperator, ObjectName, Query, Select, SetExpr, Spanned, Statement, TableFactor, Value,
    ValueWithSpan, Visit, Visitor,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

pub use sqlparser;

pub const MAX_SQL_BYTES: usize = 16 * 1024;
/// Nested calls (`f(g(…))`, `NOT (…)`, `CAST(…)`, `[…]`).
pub const MAX_CALL_NESTING: usize = 8;
/// Nested parentheses of any kind.
pub const MAX_NESTING: usize = 32;

/// Deterministic scalar functions.
pub const SCALAR_FUNCTIONS: &[&str] = &[
    "abs",
    "ceil",
    "ceiling",
    "floor",
    "round",
    "trunc",
    "sign",
    "sqrt",
    "cbrt",
    "power",
    "pow",
    "exp",
    "ln",
    "log",
    "log2",
    "log10",
    "mod",
    "greatest",
    "least",
    "coalesce",
    "nullif",
    "lower",
    "upper",
    "length",
    "char_length",
    "character_length",
    "octet_length",
    "substr",
    "substring",
    "trim",
    "btrim",
    "ltrim",
    "rtrim",
    "concat",
    "concat_ws",
    "replace",
    "starts_with",
    "ends_with",
    "strpos",
    "left",
    "right",
    "lpad",
    "rpad",
    "reverse",
    "split_part",
    "regexp_like",
    "regexp_replace",
    "date_trunc",
    "date_part",
    "date_bin",
    "extract",
    "to_timestamp",
    "to_timestamp_millis",
    "to_timestamp_seconds",
    "to_date",
    "make_date",
    "to_char",
    "from_unixtime",
    "md5",
    "sha256",
    "digest",
    "isnan",
    "iszero",
    "nanvl",
    "to_hex",
    "ascii",
    "chr",
    "initcap",
    "repeat",
    "translate",
    "array_length",
    "cardinality",
];

/// Aggregate functions.
pub const AGGREGATE_FUNCTIONS: &[&str] = &[
    "count",
    "sum",
    "avg",
    "mean",
    "min",
    "max",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "var",
    "variance",
    "var_pop",
    "var_samp",
    "median",
    "bool_and",
    "bool_or",
    "corr",
    "covar",
    "covar_pop",
    "covar_samp",
    "regr_slope",
    "regr_intercept",
    "string_agg",
    "array_agg",
];

/// Aggregates that emit raw member values (never "aggregate-only").
pub const COLLECTING_AGGREGATES: &[&str] = &["string_agg", "array_agg"];

/// Window-only functions.
pub const WINDOW_FUNCTIONS: &[&str] = &[
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    "nth_value",
];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SqlError {
    /// Stable diagnostic code, e.g. `RMT-E0201`.
    pub code: &'static str,
    pub message: String,
    /// 1-based (line, column) when known.
    pub span: Option<(u64, u64)>,
    pub hint: Option<String>,
}

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some((l, c)) = self.span {
            write!(f, " (line {l}, column {c})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SqlError {}

pub const E_PARSE: &str = "RMT-E0201";
pub const E_NOT_QUERY: &str = "RMT-E0202";
pub const E_RECURSIVE: &str = "RMT-E0203";
pub const E_SET_OP: &str = "RMT-E0204";
pub const E_FUNCTION: &str = "RMT-E0205";
pub const E_JOIN: &str = "RMT-E0206";
pub const E_CLAUSE: &str = "RMT-E0207";
pub const E_PARAM: &str = "RMT-E0208";
pub const E_TABLE: &str = "RMT-E0209";
pub const E_SIZE: &str = "RMT-E0210";

fn err(
    code: &'static str,
    message: impl Into<String>,
    span: Option<(u64, u64)>,
    hint: Option<&str>,
) -> SqlError {
    SqlError {
        code,
        message: message.into(),
        span,
        hint: hint.map(String::from),
    }
}

fn loc<T: Spanned>(node: &T) -> Option<(u64, u64)> {
    let s = node.span();
    (s.start.line > 0).then_some((s.start.line, s.start.column))
}

/// Profile facts about a statement that passed the profile.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct SqlFacts {
    /// Referenced catalog relations (lowercased, as written: `source.table`).
    pub tables: BTreeSet<String>,
    /// Named params (`$from` → `from`).
    pub params: BTreeSet<String>,
    /// Operations: join, left_join, group_by, having, order_by, limit, window,
    /// distinct, subquery, cte, aggregate, collect, search.
    pub ops: BTreeSet<String>,
    pub functions: BTreeSet<String>,
    pub table_functions: BTreeSet<String>,
    /// (function, first string-literal argument = index name).
    pub table_function_calls: Vec<(String, Option<String>)>,
    pub wildcard: bool,
}

/// Options for checking (Holder table functions allowed by the catalog).
#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub table_functions: BTreeSet<String>,
}

/// Parse and check a statement against the Remit SQL profile.
pub fn check(sql: &str, profile: &Profile) -> Result<SqlFacts, SqlError> {
    if sql.len() > MAX_SQL_BYTES {
        return Err(err(
            E_SIZE,
            format!("SQL exceeds {MAX_SQL_BYTES} bytes"),
            None,
            None,
        ));
    }
    guard_nesting(sql)?;
    let dialect = PostgreSqlDialect {};
    let stmts = Parser::new(&dialect)
        .with_recursion_limit(64)
        .try_with_sql(sql)
        .and_then(|mut p| p.parse_statements())
        .map_err(|e| {
            let msg = e.to_string();
            let span = parse_location(&msg);
            err(
                E_PARSE,
                msg.trim_start_matches("sql parser error: ").to_string(),
                span,
                None,
            )
        })?;
    if stmts.len() != 1 {
        return Err(err(
            E_NOT_QUERY,
            "exactly one statement is required",
            None,
            None,
        ));
    }
    let stmt = &stmts[0];
    let Statement::Query(_) = stmt else {
        return Err(err(
            E_NOT_QUERY,
            "only SELECT queries are allowed (no DDL, DML or utility statements)",
            loc(stmt),
            None,
        ));
    };
    let mut c = Checker {
        facts: SqlFacts::default(),
        ctes: BTreeSet::new(),
        profile,
    };
    match stmt.visit(&mut c) {
        ControlFlow::Break(e) => Err(e),
        ControlFlow::Continue(()) => {
            let ctes = c.ctes.clone();
            c.facts.tables.retain(|t| !ctes.contains(t));
            Ok(c.facts)
        }
    }
}

/// Linear pre-parse guard. The parser re-parses speculatively at every nested
/// call, so a *failing* input costs up to 3^depth; its recursion limit does not
/// bound that. Capping call nesting before parsing does.
fn guard_nesting(sql: &str) -> Result<(), SqlError> {
    use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};
    // Keywords whose parenthesis is not a speculative call site.
    const STRUCTURAL: &[&str] = &[
        "IN", "EXISTS", "FROM", "JOIN", "AS", "ON", "AND", "OR", "WHERE", "SELECT", "BY", "THEN",
        "ELSE", "WHEN", "HAVING", "LIKE", "ILIKE", "BETWEEN", "DISTINCT", "OVER", "FILTER",
        "LIMIT", "OFFSET", "USING", "UNION", "ALL", "ANY", "SOME",
    ];
    let toks = Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize_with_location()
        .map_err(|e| {
            err(
                E_PARSE,
                e.message.clone(),
                Some((e.location.line, e.location.column)),
                None,
            )
        })?;
    let mut stack: Vec<bool> = Vec::new();
    let (mut calls, mut prev_word) = (0usize, false);
    for t in &toks {
        match &t.token {
            Token::Whitespace(
                Whitespace::Space
                | Whitespace::Newline
                | Whitespace::Tab
                | Whitespace::SingleLineComment { .. }
                | Whitespace::MultiLineComment(_),
            ) => continue,
            Token::LParen | Token::LBracket => {
                let call = prev_word || matches!(t.token, Token::LBracket);
                calls += call as usize;
                stack.push(call);
                if calls > MAX_CALL_NESTING || stack.len() > MAX_NESTING {
                    let at = t.span.start;
                    return Err(err(
                        E_SIZE,
                        format!("expressions may nest at most {MAX_CALL_NESTING} calls and {MAX_NESTING} parentheses deep"),
                        Some((at.line, at.column)),
                        Some("compute intermediate values in a CTE or derived table"),
                    ));
                }
                prev_word = false;
            }
            Token::RParen | Token::RBracket => {
                if stack.pop() == Some(true) {
                    calls -= 1;
                }
                prev_word = false;
            }
            Token::Word(w) => {
                prev_word = w.quote_style.is_some()
                    || !STRUCTURAL.contains(&w.value.to_ascii_uppercase().as_str())
            }
            _ => prev_word = false,
        }
    }
    Ok(())
}

fn parse_location(msg: &str) -> Option<(u64, u64)> {
    let l = msg.find("Line: ")?;
    let rest = &msg[l + 6..];
    let line: u64 = rest.split(',').next()?.trim().parse().ok()?;
    let c = rest.find("Column: ")?;
    let col: u64 = rest[c + 8..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()?;
    Some((line, col))
}

struct Checker<'a> {
    facts: SqlFacts,
    ctes: BTreeSet<String>,
    profile: &'a Profile,
}

pub(crate) fn obj_name(n: &ObjectName) -> String {
    n.0.iter()
        .map(|p| p.to_string().trim_matches('"').to_lowercase())
        .collect::<Vec<_>>()
        .join(".")
}

impl Visitor for Checker<'_> {
    type Break = SqlError;

    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<SqlError> {
        if let Some(w) = &q.with {
            if w.recursive {
                return ControlFlow::Break(err(
                    E_RECURSIVE,
                    "recursive CTEs are not allowed",
                    loc(q),
                    Some(
                        "unroll the recursion into a bounded number of joins or kernel read calls",
                    ),
                ));
            }
            self.facts.ops.insert("cte".into());
            for cte in &w.cte_tables {
                self.ctes.insert(cte.alias.name.value.to_lowercase());
            }
        }
        if !q.locks.is_empty()
            || q.for_clause.is_some()
            || q.settings.is_some()
            || q.format_clause.is_some()
            || !q.pipe_operators.is_empty()
        {
            return ControlFlow::Break(err(
                E_CLAUSE,
                "locking, FOR, SETTINGS, FORMAT and pipe clauses are not allowed",
                loc(q),
                None,
            ));
        }
        if q.order_by.is_some() {
            self.facts.ops.insert("order_by".into());
        }
        if q.limit_clause.is_some() || q.fetch.is_some() {
            self.facts.ops.insert("limit".into());
        }
        if let Err(e) = check_set_expr(&q.body) {
            return ControlFlow::Break(e);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, s: &Select) -> ControlFlow<SqlError> {
        if s.into.is_some() {
            return ControlFlow::Break(err(E_CLAUSE, "SELECT INTO is not allowed", loc(s), None));
        }
        if s.top.is_some()
            || !s.lateral_views.is_empty()
            || s.prewhere.is_some()
            || !s.connect_by.is_empty()
            || !s.cluster_by.is_empty()
            || !s.distribute_by.is_empty()
            || !s.sort_by.is_empty()
            || s.qualify.is_some()
            || s.value_table_mode.is_some()
        {
            return ControlFlow::Break(err(
                E_CLAUSE,
                "dialect-specific SELECT clauses are not in the Remit SQL profile",
                loc(s),
                None,
            ));
        }
        if s.distinct.is_some() {
            self.facts.ops.insert("distinct".into());
        }
        if s.having.is_some() {
            self.facts.ops.insert("having".into());
        }
        if !matches!(&s.group_by, sqlparser::ast::GroupByExpr::Expressions(e, _) if e.is_empty()) {
            self.facts.ops.insert("group_by".into());
        }
        if !s.named_window.is_empty() {
            self.facts.ops.insert("window".into());
        }
        for item in &s.projection {
            if matches!(
                item,
                sqlparser::ast::SelectItem::Wildcard(_)
                    | sqlparser::ast::SelectItem::QualifiedWildcard(_, _)
            ) {
                self.facts.wildcard = true;
            }
        }
        for twj in &s.from {
            for j in &twj.joins {
                match &j.join_operator {
                    JoinOperator::Join(_) | JoinOperator::Inner(_) => {
                        self.facts.ops.insert("join".into());
                    }
                    JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => {
                        self.facts.ops.insert("join".into());
                        self.facts.ops.insert("left_join".into());
                    }
                    other => {
                        return ControlFlow::Break(err(
                            E_JOIN,
                            format!(
                                "join kind `{}` is not allowed; only inner and left joins",
                                join_name(other)
                            ),
                            loc(&j.relation),
                            Some("rewrite as an INNER or LEFT JOIN"),
                        ))
                    }
                }
            }
        }
        if s.from.len() > 1 {
            self.facts.ops.insert("join".into());
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<SqlError> {
        match tf {
            TableFactor::Table {
                name,
                args,
                with_hints,
                version,
                partitions,
                json_path,
                sample,
                index_hints,
                ..
            } => {
                if !with_hints.is_empty()
                    || version.is_some()
                    || !partitions.is_empty()
                    || json_path.is_some()
                    || sample.is_some()
                    || !index_hints.is_empty()
                {
                    return ControlFlow::Break(err(
                        E_CLAUSE,
                        "table hints, time travel, partitions and sampling are not allowed",
                        loc(tf),
                        Some("time always comes from params; snapshots are pinned by the Holder"),
                    ));
                }
                if args.is_some() {
                    let n = obj_name(name);
                    if !self.profile.table_functions.contains(&n) {
                        return ControlFlow::Break(err(
                            E_FUNCTION,
                            format!("table function `{n}` is not provided by this Holder"),
                            loc(tf),
                            None,
                        ));
                    }
                    let first = args
                        .as_ref()
                        .and_then(|a| a.args.first())
                        .and_then(|a| match a {
                            sqlparser::ast::FunctionArg::Unnamed(
                                sqlparser::ast::FunctionArgExpr::Expr(Expr::Value(v)),
                            ) => match &v.value {
                                Value::SingleQuotedString(s) => Some(s.clone()),
                                _ => None,
                            },
                            _ => None,
                        });
                    self.facts.table_function_calls.push((n.clone(), first));
                    self.facts.table_functions.insert(n);
                    self.facts.ops.insert("search".into());
                }
                ControlFlow::Continue(())
            }
            TableFactor::Derived { lateral, .. } => {
                if *lateral {
                    return ControlFlow::Break(err(
                        E_CLAUSE,
                        "LATERAL is not allowed",
                        loc(tf),
                        None,
                    ));
                }
                self.facts.ops.insert("subquery".into());
                ControlFlow::Continue(())
            }
            TableFactor::NestedJoin { .. } => ControlFlow::Continue(()),
            _ => ControlFlow::Break(err(
                E_CLAUSE,
                "this FROM item is not in the Remit SQL profile (UNNEST, PIVOT, table functions)",
                loc(tf),
                None,
            )),
        }
    }

    fn pre_visit_relation(&mut self, r: &ObjectName) -> ControlFlow<SqlError> {
        let n = obj_name(r);
        if n.split('.').count() > 2 {
            return ControlFlow::Break(err(
                E_TABLE,
                format!("relation `{n}` must be `source.table`"),
                None,
                None,
            ));
        }
        if !self.profile.table_functions.contains(&n) {
            self.facts.tables.insert(n);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, e: &Expr) -> ControlFlow<SqlError> {
        match e {
            Expr::Function(f) => {
                let name = f
                    .name
                    .0
                    .last()
                    .map(|p| p.to_string().trim_matches('"').to_lowercase())
                    .unwrap_or_default();
                if f.name.0.len() > 1 {
                    return ControlFlow::Break(err(
                        E_FUNCTION,
                        format!("qualified function `{}` is not allowed", f.name),
                        loc(e),
                        None,
                    ));
                }
                let is_agg = AGGREGATE_FUNCTIONS.contains(&name.as_str());
                let is_win = WINDOW_FUNCTIONS.contains(&name.as_str());
                if !(SCALAR_FUNCTIONS.contains(&name.as_str()) || is_agg || is_win) {
                    let hint = match name.as_str() {
                        "now" | "current_timestamp" | "current_date" | "current_time" | "localtimestamp" | "localtime" => {
                            Some("time always comes from params: compare against `$from`/`$until` instead")
                        }
                        "random" | "uuid" | "gen_random_uuid" | "setseed" => Some("remits are deterministic; randomness is not available in SQL"),
                        _ => None,
                    };
                    return ControlFlow::Break(err(
                        E_FUNCTION,
                        format!("function `{name}` is not in the Remit SQL allowlist"),
                        loc(e),
                        hint,
                    ));
                }
                if f.over.is_some() || is_win {
                    self.facts.ops.insert("window".into());
                } else if is_agg {
                    self.facts.ops.insert("aggregate".into());
                    if COLLECTING_AGGREGATES.contains(&name.as_str()) {
                        self.facts.ops.insert("collect".into());
                    }
                }
                self.facts.functions.insert(name);
            }
            Expr::Subquery(_) | Expr::InSubquery { .. } | Expr::Exists { .. } => {
                self.facts.ops.insert("subquery".into());
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_statement(&mut self, s: &Statement) -> ControlFlow<SqlError> {
        if !matches!(s, Statement::Query(_)) {
            return ControlFlow::Break(err(
                E_NOT_QUERY,
                "nested statements are not allowed",
                loc(s),
                None,
            ));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_value(&mut self, v: &ValueWithSpan) -> ControlFlow<SqlError> {
        if let Value::Placeholder(p) = &v.value {
            let name = p.trim_start_matches(['$', ':', '@']);
            if !p.starts_with('$')
                || name.is_empty()
                || name.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                return ControlFlow::Break(err(
                    E_PARAM,
                    format!("placeholder `{p}` is not allowed; use named params like `$from`"),
                    (v.span.start.line > 0).then_some((v.span.start.line, v.span.start.column)),
                    None,
                ));
            }
            self.facts.params.insert(name.to_string());
        }
        ControlFlow::Continue(())
    }
}

fn check_set_expr(s: &SetExpr) -> Result<(), SqlError> {
    match s {
        SetExpr::Select(_) => Ok(()),
        SetExpr::Query(q) => check_set_expr(&q.body),
        SetExpr::SetOperation { .. } => Err(err(
            E_SET_OP,
            "UNION/INTERSECT/EXCEPT are not in the Remit SQL profile",
            None,
            Some("declare a second read template instead"),
        )),
        SetExpr::Values(_) => Err(err(E_CLAUSE, "VALUES is not allowed", None, None)),
        _ => Err(err(
            E_NOT_QUERY,
            "only SELECT bodies are allowed",
            None,
            None,
        )),
    }
}

fn join_name(j: &JoinOperator) -> &'static str {
    match j {
        JoinOperator::Right(_) | JoinOperator::RightOuter(_) => "RIGHT",
        JoinOperator::FullOuter(_) => "FULL OUTER",
        JoinOperator::CrossJoin(_) => "CROSS",
        JoinOperator::Semi(_) | JoinOperator::LeftSemi(_) | JoinOperator::RightSemi(_) => "SEMI",
        JoinOperator::Anti(_) | JoinOperator::LeftAnti(_) | JoinOperator::RightAnti(_) => "ANTI",
        JoinOperator::CrossApply | JoinOperator::OuterApply => "APPLY",
        _ => "this",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(sql: &str) -> SqlFacts {
        check(sql, &Profile::default()).unwrap_or_else(|e| panic!("{sql}: {e}"))
    }
    fn bad(sql: &str) -> SqlError {
        check(sql, &Profile::default()).expect_err(sql)
    }

    #[test]
    fn plan_example() {
        let f = ok("SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'");
        assert_eq!(f.tables.iter().collect::<Vec<_>>(), vec!["calendar.events"]);
        assert_eq!(
            f.params.iter().cloned().collect::<Vec<_>>(),
            vec!["from", "until"]
        );
    }

    #[test]
    fn aggregates_and_ctes() {
        let f = ok("WITH r AS (SELECT region, arr FROM crm.accounts) SELECT region, SUM(arr) AS arr FROM r GROUP BY region HAVING COUNT(*) > 5 ORDER BY 2 DESC LIMIT 10");
        assert!(f.ops.contains("aggregate") && f.ops.contains("group_by") && f.ops.contains("cte"));
        assert_eq!(f.tables.len(), 1);
        let f = ok("SELECT a.id FROM crm.accounts a LEFT JOIN crm.deals d ON a.id = d.account_id");
        assert!(f.ops.contains("left_join"));
        assert!(ok("SELECT string_agg(name, ',') FROM crm.accounts")
            .ops
            .contains("collect"));
    }

    #[test]
    fn rejections() {
        assert_eq!(bad("DELETE FROM crm.accounts").code, E_NOT_QUERY);
        assert_eq!(bad("DROP TABLE crm.accounts").code, E_NOT_QUERY);
        assert_eq!(bad("SELECT 1; SELECT 2").code, E_NOT_QUERY);
        assert_eq!(
            bad("WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t) SELECT * FROM t")
                .code,
            E_RECURSIVE
        );
        assert_eq!(
            bad("SELECT a FROM x.t UNION SELECT a FROM x.u").code,
            E_SET_OP
        );
        let e = bad("SELECT * FROM calendar.events WHERE start_at < now()");
        assert_eq!(e.code, E_FUNCTION);
        assert!(e.hint.unwrap().contains("params"));
        assert!(e.span.is_some());
        assert_eq!(bad("SELECT random()").code, E_FUNCTION);
        assert_eq!(bad("SELECT my_udf(x) FROM a.b").code, E_FUNCTION);
        assert_eq!(
            bad("SELECT * FROM a.b FULL OUTER JOIN a.c ON true").code,
            E_JOIN
        );
        assert_eq!(bad("SELECT * FROM a.b CROSS JOIN a.c").code, E_JOIN);
        assert_eq!(bad("SELECT * FROM a.b WHERE x = $1").code, E_PARAM);
        assert_eq!(bad("SELECT * FROM a.b FOR UPDATE").code, E_CLAUSE);
        assert_eq!(bad("SELEC 1").code, E_PARSE);
        assert_eq!(bad("SELECT * INTO a.c FROM a.b").code, E_CLAUSE);
    }

    /// Regression (found by fuzzing): short inputs that made the parser
    /// exponential are refused in linear time.
    #[test]
    fn pathological_nesting_is_refused_quickly() {
        let t = std::time::Instant::now();
        for p in [
            "IF(F(",
            "F(",
            "ABS(-",
            "COALESCE(1,",
            "NOT (",
            "CAST(",
            "SUBSTRING(",
            "INTERVAL (",
            "ARRAY[",
            "ROW(",
            "a.b(",
            "ABS(x,(",
            "\"q\"(",
            "IF/**/(",
            "COUNT(DISTINCT (",
        ] {
            for n in [9, 20, 200] {
                assert_eq!(
                    bad(&format!("SELECT {}", p.repeat(n))).code,
                    E_SIZE,
                    "{p} x{n}"
                );
            }
            // Below the limit it is still the parser's verdict, and cheap.
            let _ = check(&format!("SELECT {}", p.repeat(4)), &Profile::default());
        }
        for p in ["(", "(SELECT * FROM ", "1 IN (", "EXISTS ("] {
            assert!(check(&format!("SELECT {}", p.repeat(300)), &Profile::default()).is_err());
        }
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            t.elapsed()
        );
        // Realistic nesting is unaffected.
        ok("SELECT ROUND(COALESCE(SUM(CASE WHEN ABS(x) > 1 THEN LEAST(GREATEST(y, 0), 10) ELSE 0 END), 0), 2) AS v FROM a.b WHERE id IN (SELECT id FROM a.c WHERE EXISTS (SELECT 1 FROM a.d)) GROUP BY LOWER(TRIM(z))");
    }

    #[test]
    fn table_functions() {
        let mut p = Profile::default();
        assert!(check("SELECT * FROM search('docs', $q, 5)", &p).is_err());
        p.table_functions.insert("search".into());
        let f = check("SELECT * FROM search('docs', $q, 5)", &p).unwrap();
        assert!(f.table_functions.contains("search"));
        assert!(f.tables.is_empty());
    }
}
