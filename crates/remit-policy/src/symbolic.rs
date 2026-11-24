//! SMT-backed policy analysis (Cedar Analysis style) for Remit's fixed schema.
//!
//! Policies are translated from Cedar's JSON form to SMT-LIB and decided by Z3
//! over **every** possible principal, action and fact context; resources range
//! over the Holder's catalog. Results are proofs, not samples: `unsat` means no
//! request exists. Policies using something outside the translated subset
//! (extension types, integer arithmetic that could overflow) are reported as
//! `Unsupported` and handled by the sampling lattice in `lint.rs`.
//!
//! The solver binary is `$REMIT_SMT` or `z3` on `PATH`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};

use cedar_policy::{Effect, PolicySet};
use remit_read::ResourceConfig;
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub enum SymError {
    Unsupported(String),
    Solver(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    Unsat,
    Sat(Value),
    Unknown,
}

const ACTIONS: [&str; 5] = ["read", "aggregate", "search", "call", "run_kernel"];
/// `action in Action::"x"` includes x's descendants.
fn action_closure(a: &str) -> Vec<&str> {
    match a {
        "read" => vec!["read", "aggregate", "search"],
        a => vec![a],
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum T {
    Bool,
    Int,
    Str,
    Set,
    Principal,
    Action,
    Resource,
    Context,
}

fn bad<X>(m: impl Into<String>) -> Result<X, SymError> {
    Err(SymError::Unsupported(m.into()))
}

/// SMT-LIB string literal.
fn lit(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\"\""),
            '\\' => o.push_str("\\u{5c}"),
            ' '..='~' => o.push(c),
            c => o.push_str(&format!("\\u{{{:x}}}", c as u32)),
        }
    }
    o.push('"');
    o
}

fn set_lit(items: &[String]) -> String {
    let mut s = "((as const (Array String Bool)) false)".to_string();
    for i in items {
        s = format!("(store {s} {i} true)");
    }
    s
}

const CTX: &[(&str, T)] = &[
    ("mode", T::Str),
    ("purpose", T::Str),
    ("columns", T::Set),
    ("ops", T::Set),
    ("aggregate_only", T::Bool),
    ("min_group_size", T::Int),
    ("result_bits", T::Int),
    ("fuel", T::Int),
    ("memory_bytes", T::Int),
    ("wall_ms", T::Int),
    ("max_rows_total", T::Int),
    ("epsilon_milli", T::Int),
    ("standing_approval", T::Bool),
    ("authority", T::Set),
];
const RES: &[(&str, T)] = &[
    ("labels", T::Set),
    ("sensitivity", T::Str),
    ("purposes", T::Set),
    ("operations", T::Set),
    ("max_bits", T::Int),
    ("aggregate_only", T::Bool),
    ("k", T::Int),
    ("dp", T::Bool),
    ("owner_scoped", T::Bool),
];
const PRI: &[(&str, T)] = &[("org", T::Str), ("verified", T::Bool), ("tags", T::Set)];

fn sort(t: T) -> &'static str {
    match t {
        T::Bool => "Bool",
        T::Int => "Int",
        T::Str => "String",
        T::Set => "(Array String Bool)",
        _ => unreachable!("entity sorts are encoded as strings"),
    }
}

/// Declarations and well-formedness constraints of every request.
fn prelude(resources: &BTreeMap<String, ResourceConfig>) -> String {
    let mut s = String::from("(set-option :timeout 10000)\n(declare-const pid String)\n(declare-const pgroups (Array String Bool))\n(declare-const act String)\n(declare-const rid String)\n(declare-const rds String)\n");
    for (pfx, attrs) in [("c_", CTX), ("r_", RES), ("p_", PRI)] {
        for (n, t) in attrs {
            s.push_str(&format!("(declare-const {pfx}{n} {})\n", sort(*t)));
        }
    }
    s.push_str(&format!(
        "(assert (or {}))\n",
        ACTIONS
            .iter()
            .map(|a| format!("(= act {})", lit(a)))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    s.push_str("(assert (or (= c_mode \"query\") (= c_mode \"kernel\")))\n");
    s.push_str("(assert (=> (= act \"run_kernel\") (= c_mode \"kernel\")))\n");
    for n in [
        "min_group_size",
        "result_bits",
        "fuel",
        "memory_bytes",
        "wall_ms",
        "max_rows_total",
        "epsilon_milli",
    ] {
        s.push_str(&format!(
            "(assert (and (>= c_{n} 0) (<= c_{n} 9223372036854775807)))\n"
        ));
    }
    let mut alts = Vec::new();
    for (name, r) in resources {
        let e = crate::table_entity(name, r);
        let a = &e["attrs"];
        let mut cs = vec![
            format!("(= rid {})", lit(name)),
            format!("(= rds {})", lit(name.split('.').next().unwrap_or(name))),
        ];
        for (n, t) in RES {
            let v = &a[*n];
            let x = match t {
                T::Bool => v.as_bool().unwrap_or(false).to_string(),
                T::Int => v.as_i64().unwrap_or(0).to_string(),
                T::Str => lit(v.as_str().unwrap_or("")),
                _ => set_lit(
                    &v.as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.as_str().map(lit))
                        .collect::<Vec<_>>(),
                ),
            };
            cs.push(format!("(= r_{n} {x})"));
        }
        alts.push(format!("(and {})", cs.join(" ")));
    }
    s.push_str(&format!("(assert (or false {}))\n", alts.join(" ")));
    s
}

fn uid(v: &Value) -> Option<(String, String)> {
    let e = v.get("__entity").unwrap_or(v);
    Some((
        e.get("type")?.as_str()?.to_string(),
        e.get("id")?.as_str()?.to_string(),
    ))
}

/// `var in/== entity` for a scope variable.
fn member(var: T, e: &(String, String), eq: bool) -> Result<String, SymError> {
    let (ty, id) = (e.0.as_str(), e.1.as_str());
    Ok(match (var, ty) {
        (T::Principal, "Remit::Agent") => format!("(= pid {})", lit(id)),
        (T::Principal, "Remit::Group") if !eq => format!("(select pgroups {})", lit(id)),
        (T::Resource, "Remit::Table") => format!("(= rid {})", lit(id)),
        (T::Resource, "Remit::Dataset") if !eq => format!("(= rds {})", lit(id)),
        (T::Action, "Remit::Action") if eq => format!("(= act {})", lit(id)),
        (T::Action, "Remit::Action") => format!(
            "(or false {})",
            action_closure(id)
                .iter()
                .map(|a| format!("(= act {})", lit(a)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        // Distinct entity types are never equal / never ancestors.
        _ => "false".into(),
    })
}

fn scope(var: T, s: &Value) -> Result<String, SymError> {
    match s["op"].as_str() {
        Some("All") => Ok("true".into()),
        Some(op @ ("==" | "in")) => {
            if let Some(es) = s.get("entities").and_then(Value::as_array) {
                let parts = es
                    .iter()
                    .map(|e| {
                        uid(e)
                            .ok_or(SymError::Unsupported("scope".into()))
                            .and_then(|u| member(var, &u, false))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(format!("(or false {})", parts.join(" ")));
            }
            let e = s
                .get("entity")
                .and_then(uid)
                .ok_or(SymError::Unsupported("template slots".into()))?;
            member(var, &e, op == "==")
        }
        Some("is") => {
            let t = match var {
                T::Principal => "Remit::Agent",
                T::Resource => "Remit::Table",
                _ => "Remit::Action",
            };
            let base = (s["entity_type"].as_str() == Some(t)).to_string();
            match s.get("in") {
                Some(i) => Ok(format!(
                    "(and {base} {})",
                    member(
                        var,
                        &uid(&i["entity"]).ok_or(SymError::Unsupported("scope".into()))?,
                        false
                    )?
                )),
                None => Ok(base),
            }
        }
        _ => bad("scope operator"),
    }
}

fn expr(v: &Value) -> Result<(String, T), SymError> {
    let Some((op, a)) = v.as_object().and_then(|o| o.iter().next()) else {
        return bad("expression");
    };
    let l = || expr(&a["left"]);
    let r = || expr(&a["right"]);
    let bools = |x: &(String, T)| {
        if x.1 == T::Bool {
            Ok(x.0.clone())
        } else {
            bad("boolean expected")
        }
    };
    let ints = |x: &(String, T)| {
        if x.1 == T::Int {
            Ok(x.0.clone())
        } else {
            bad("integer expected")
        }
    };
    Ok(match op.as_str() {
        "Value" => match a {
            Value::Bool(b) => (b.to_string(), T::Bool),
            Value::Number(n) => {
                let i = n.as_i64().ok_or(SymError::Unsupported("number".into()))?;
                (
                    if i < 0 {
                        format!("(- {})", i.unsigned_abs())
                    } else {
                        i.to_string()
                    },
                    T::Int,
                )
            }
            Value::String(s) => (lit(s), T::Str),
            _ => return bad("literal"),
        },
        "Var" => match a.as_str() {
            Some("principal") => ("pid".into(), T::Principal),
            Some("action") => ("act".into(), T::Action),
            Some("resource") => ("rid".into(), T::Resource),
            Some("context") => ("".into(), T::Context),
            _ => return bad("variable"),
        },
        "!" => (format!("(not {})", bools(&expr(&a["arg"])?)?), T::Bool),
        "&&" => (
            format!("(and {} {})", bools(&l()?)?, bools(&r()?)?),
            T::Bool,
        ),
        "||" => (format!("(or {} {})", bools(&l()?)?, bools(&r()?)?), T::Bool),
        "==" | "!=" => {
            let x = match (uid(&a["left"]["Value"]), uid(&a["right"]["Value"])) {
                (None, Some(e)) => member(l()?.1, &e, true)?,
                (Some(e), None) => member(r()?.1, &e, true)?,
                (Some(x), Some(y)) => (x == y).to_string(),
                (None, None) => {
                    let (x, y) = (l()?, r()?);
                    if x.1 == T::Context || y.1 == T::Context {
                        return bad("record equality");
                    }
                    if x.1 == y.1 {
                        format!("(= {} {})", x.0, y.0)
                    } else {
                        "false".into()
                    }
                }
            };
            (if op == "==" { x } else { format!("(not {x})") }, T::Bool)
        }
        "in" => {
            let lhs = l()?;
            let parts: Vec<String> = match a["right"].get("Set").and_then(Value::as_array) {
                Some(es) => es
                    .iter()
                    .map(|e| {
                        uid(&e["Value"])
                            .ok_or(SymError::Unsupported("in".into()))
                            .and_then(|u| member(lhs.1, &u, false))
                    })
                    .collect::<Result<_, _>>()?,
                None => vec![member(
                    lhs.1,
                    &uid(&a["right"]["Value"]).ok_or(SymError::Unsupported("in".into()))?,
                    false,
                )?],
            };
            (format!("(or false {})", parts.join(" ")), T::Bool)
        }
        "<" | "<=" | ">" | ">=" => (format!("({op} {} {})", ints(&l()?)?, ints(&r()?)?), T::Bool),
        "." => {
            let attr = a["attr"].as_str().unwrap_or("");
            let (pfx, table) = match l()?.1 {
                T::Context => ("c_", CTX),
                T::Resource => ("r_", RES),
                T::Principal => ("p_", PRI),
                _ => return bad("attribute access"),
            };
            let (n, t) = table
                .iter()
                .find(|(n, _)| *n == attr)
                .ok_or(SymError::Unsupported(format!("attribute `{attr}`")))?;
            (format!("{pfx}{n}"), *t)
        }
        "has" => {
            let attr = a["attr"].as_str().unwrap_or("");
            let table = match l()?.1 {
                T::Context => CTX,
                T::Resource => RES,
                T::Principal => PRI,
                _ => return bad("has"),
            };
            (table.iter().any(|(n, _)| *n == attr).to_string(), T::Bool)
        }
        "Set" => {
            let items = a
                .as_array()
                .into_iter()
                .flatten()
                .map(expr)
                .collect::<Result<Vec<_>, _>>()?;
            if items.iter().any(|x| x.1 != T::Str) {
                return bad("sets of non-strings");
            }
            (
                set_lit(&items.into_iter().map(|x| x.0).collect::<Vec<_>>()),
                T::Set,
            )
        }
        "contains" => match (l()?, r()?) {
            ((s, T::Set), (e, T::Str)) => (format!("(select {s} {e})"), T::Bool),
            _ => return bad("contains"),
        },
        "containsAll" | "containsAny" => match (l()?, r()?) {
            ((x, T::Set), (y, T::Set)) => {
                let empty = "((as const (Array String Bool)) false)";
                if op == "containsAll" {
                    (
                        format!("(= ((_ map and) {y} ((_ map not) {x})) {empty})"),
                        T::Bool,
                    )
                } else {
                    (format!("(not (= ((_ map and) {x} {y}) {empty}))"), T::Bool)
                }
            }
            _ => return bad(op.as_str()),
        },
        "isEmpty" => match expr(&a["arg"])? {
            (s, T::Set) => (
                format!("(= {s} ((as const (Array String Bool)) false))"),
                T::Bool,
            ),
            _ => return bad("isEmpty"),
        },
        "like" => {
            let (s, T::Str) = l()? else {
                return bad("like");
            };
            let mut parts = vec!["(str.to_re \"\")".to_string()];
            for p in a["pattern"].as_array().into_iter().flatten() {
                match p {
                    Value::String(w) if w == "Wildcard" => parts.push("re.all".into()),
                    p => parts.push(format!(
                        "(str.to_re {})",
                        lit(p["Literal"].as_str().unwrap_or(""))
                    )),
                }
            }
            (
                format!(
                    "(str.in_re {s} (re.++ {} (str.to_re \"\")))",
                    parts.join(" ")
                ),
                T::Bool,
            )
        }
        "if-then-else" => {
            let (c, t, e) = (expr(&a["if"])?, expr(&a["then"])?, expr(&a["else"])?);
            if t.1 != e.1 {
                return bad("if-then-else types");
            }
            (format!("(ite {} {} {})", bools(&c)?, t.0, e.0), t.1)
        }
        "is" => {
            let t = match l()?.1 {
                T::Principal => "Remit::Agent",
                T::Resource => "Remit::Table",
                T::Action => "Remit::Action",
                _ => return bad("is"),
            };
            ((a["entity_type"].as_str() == Some(t)).to_string(), T::Bool)
        }
        other => return bad(format!("operator `{other}`")),
    })
}

/// One policy as a formula over the request variables.
fn formula(p: &cedar_policy::Policy) -> Result<String, SymError> {
    let j = p
        .to_json()
        .map_err(|e| SymError::Unsupported(e.to_string()))?;
    let mut cs = vec![
        scope(T::Principal, &j["principal"])?,
        scope(T::Action, &j["action"])?,
        scope(T::Resource, &j["resource"])?,
    ];
    for c in j["conditions"].as_array().into_iter().flatten() {
        let (x, T::Bool) = expr(&c["body"])? else {
            return bad("condition");
        };
        cs.push(if c["kind"] == "unless" {
            format!("(not {x})")
        } else {
            x
        });
    }
    Ok(format!("(and {})", cs.join(" ")))
}

/// A translated policy set.
pub struct Model {
    prelude: String,
    /// (id, is_permit, formula)
    pub policies: Vec<(String, bool, String)>,
}

pub fn available() -> bool {
    Command::new(solver())
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn solver() -> String {
    std::env::var("REMIT_SMT").unwrap_or_else(|_| "z3".into())
}

impl Model {
    pub fn new(
        set: &PolicySet,
        resources: &BTreeMap<String, ResourceConfig>,
    ) -> Result<Model, SymError> {
        let mut policies = Vec::new();
        for p in set.policies() {
            policies.push((
                p.id().to_string(),
                p.effect() == Effect::Permit,
                formula(p)?,
            ));
        }
        Ok(Model {
            prelude: prelude(resources),
            policies,
        })
    }

    /// The decision formula of the whole set.
    pub fn allow(&self) -> String {
        let any = |permit: bool| {
            self.policies
                .iter()
                .filter(|p| p.1 == permit)
                .map(|p| p.2.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        format!(
            "(and (or false {}) (not (or false {})))",
            any(true),
            any(false)
        )
    }

    pub fn forbidden(&self) -> String {
        format!(
            "(or false {})",
            self.policies
                .iter()
                .filter(|p| !p.1)
                .map(|p| p.2.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    /// Is there a request satisfying `f`?
    pub fn check(&self, f: &str) -> Result<Answer, SymError> {
        let vals = [
            "pid",
            "act",
            "rid",
            "c_mode",
            "c_purpose",
            "c_aggregate_only",
            "c_min_group_size",
            "c_result_bits",
            "c_max_rows_total",
            "c_epsilon_milli",
            "c_standing_approval",
            "p_verified",
        ];
        let q = format!(
            "{}(assert {f})\n(check-sat)\n(get-value ({}))\n",
            self.prelude,
            vals.join(" ")
        );
        let e = |x: std::io::Error| SymError::Solver(x.to_string());
        let mut c = Command::new(solver())
            .args(["-in", "-T:20"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(e)?;
        c.stdin
            .take()
            .expect("piped")
            .write_all(q.as_bytes())
            .map_err(e)?;
        let out = c.wait_with_output().map_err(e)?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let mut lines = text.lines();
        match lines.next().map(str::trim) {
            Some("unsat") => Ok(Answer::Unsat),
            Some("sat") => Ok(Answer::Sat(model_values(
                &lines.collect::<Vec<_>>().join(" "),
            ))),
            Some("unknown" | "timeout") => Ok(Answer::Unknown),
            other => Err(SymError::Solver(other.unwrap_or("no output").to_string())),
        }
    }
}

/// Parse `((name value) …)` into a readable example request.
fn model_values(s: &str) -> Value {
    let mut o = serde_json::Map::new();
    for part in s
        .split("((")
        .flat_map(|x| x.split(") ("))
        .flat_map(|x| x.split(")  ("))
    {
        let part = part
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim();
        if let Some((k, v)) = part.split_once(' ') {
            let k = k.trim_start_matches("c_");
            let k = match k {
                "pid" => "principal",
                "act" => "action",
                "rid" => "resource",
                "p_verified" => "verified",
                k => k,
            };
            let v = v.trim().trim_end_matches(')');
            let val = match v {
                "true" => json!(true),
                "false" => json!(false),
                v if v.starts_with('"') => json!(v.trim_matches('"')),
                v => v
                    .parse::<i64>()
                    .map(|n| json!(n))
                    .unwrap_or_else(|_| json!(v)),
            };
            o.insert(k.to_string(), val);
        }
    }
    Value::Object(o)
}
