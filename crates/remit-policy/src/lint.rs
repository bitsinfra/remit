//! `remit policy lint` / `remit policy diff`.
//!
//! Cedar's strict schema validator, then SMT-backed analysis over *every*
//! request (`symbolic.rs`). Without a solver, or for policies outside the
//! translated subset, exhaustive evaluation over a finite request lattice
//! (principals × resources × actions × a grid of fact values derived from the
//! catalog's thresholds) is used instead, and the findings say so.

use std::collections::BTreeMap;

use cedar_policy::{
    Authorizer, Context, Decision, Effect, Entities, EntityUid, PolicySet, Request,
};
use remit_read::ResourceConfig;
use serde::Serialize;
use serde_json::{json, Value};

use crate::{parse_policies, schema, table_entity, PrincipalInfo};

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Finding {
    pub level: String,
    pub policy: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffEntry {
    pub principal: String,
    pub resource: String,
    pub action: String,
    pub context: Value,
    pub before: String,
    pub after: String,
}

const ACTIONS: [&str; 4] = ["read", "aggregate", "run_kernel", "search"];

struct Space {
    entities: Entities,
    requests: Vec<(String, String, String, Value, Request)>,
}

fn space(
    resources: &BTreeMap<String, ResourceConfig>,
    principals: &[PrincipalInfo],
) -> Result<Space, String> {
    let schema = schema();
    let mut ents: Vec<Value> = resources.iter().map(|(n, r)| table_entity(n, r)).collect();
    let mut groups: Vec<String> = principals.iter().flat_map(|p| p.groups.clone()).collect();
    groups.extend(["verified-agents".to_string(), "internal".to_string()]);
    groups.sort();
    groups.dedup();
    for g in &groups {
        ents.push(json!({"uid": {"type": "Remit::Group", "id": g}, "attrs": {}, "parents": []}));
    }
    let mut ds: Vec<&str> = resources
        .keys()
        .map(|n| n.split('.').next().unwrap_or(n))
        .collect();
    ds.sort();
    ds.dedup();
    for d in ds {
        ents.push(json!({"uid": {"type": "Remit::Dataset", "id": d}, "attrs": {}, "parents": []}));
    }
    let mut ps = principals.to_vec();
    ps.push(PrincipalInfo {
        id: "did:key:anonymous".into(),
        ..Default::default()
    });
    for p in &ps {
        ents.push(json!({"uid": {"type": "Remit::Agent", "id": p.id}, "attrs": {"org": p.org, "verified": p.verified, "tags": p.tags},
            "parents": p.groups.iter().map(|g| json!({"type": "Remit::Group", "id": g})).collect::<Vec<_>>()}));
    }
    let entities =
        Entities::from_json_value(Value::Array(ents), Some(&schema)).map_err(|e| e.to_string())?;
    // Fact grid: thresholds around each catalog bound.
    let mut bits = vec![1i64, 64, 128, 4096, 1 << 20];
    let mut ks = vec![0i64, 5, 20, 100];
    let mut purposes = vec![
        "analytics".to_string(),
        "scheduling".to_string(),
        "other".to_string(),
    ];
    for r in resources.values() {
        if let Some(b) = r.max_bits {
            bits.extend([b as i64, b as i64 + 1]);
        }
        if let Some(k) = r.k {
            ks.extend([k as i64 - 1, k as i64]);
        }
        purposes.extend(r.purposes.iter().cloned());
    }
    bits.sort();
    bits.dedup();
    ks.sort();
    ks.dedup();
    purposes.sort();
    purposes.dedup();
    let mut requests = Vec::new();
    for p in &ps {
        for res in resources.keys() {
            for a in ACTIONS {
                for &b in &bits {
                    for &k in &ks {
                        for agg in [true, false] {
                            for eps in [0i64, 100] {
                                for purpose in &purposes {
                                    for standing in [false, true] {
                                        let ctx = json!({"mode": if a == "run_kernel" {"kernel"} else {"query"}, "purpose": purpose,
                                        "columns": [], "ops": [], "aggregate_only": agg, "min_group_size": k, "result_bits": b,
                                        "fuel": 1000000, "memory_bytes": 1 << 24, "wall_ms": 100, "max_rows_total": 500,
                                        "epsilon_milli": eps, "standing_approval": standing, "authority": []});
                                        let au = EntityUid::from_type_name_and_id(
                                            "Remit::Action".parse().unwrap(),
                                            a.parse().unwrap(),
                                        );
                                        let c = Context::from_json_value(
                                            ctx.clone(),
                                            Some((&schema, &au)),
                                        )
                                        .map_err(|e| e.to_string())?;
                                        let req = Request::new(
                                            EntityUid::from_type_name_and_id(
                                                "Remit::Agent".parse().unwrap(),
                                                p.id.parse().unwrap(),
                                            ),
                                            au,
                                            EntityUid::from_type_name_and_id(
                                                "Remit::Table".parse().unwrap(),
                                                res.parse().unwrap(),
                                            ),
                                            c,
                                            Some(&schema),
                                        )
                                        .map_err(|e| e.to_string())?;
                                        requests.push((
                                            p.id.clone(),
                                            res.clone(),
                                            a.to_string(),
                                            ctx,
                                            req,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(Space { entities, requests })
}

/// Lint a policy set against the catalog.
pub fn lint(
    text: &str,
    resources: &BTreeMap<String, ResourceConfig>,
    principals: &[PrincipalInfo],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let pset = match parse_policies(text) {
        Ok(p) => p,
        Err(e) => {
            return vec![Finding {
                level: "error".into(),
                policy: None,
                message: e.to_string(),
            }]
        }
    };
    let v = cedar_policy::Validator::new(schema())
        .validate(&pset, cedar_policy::ValidationMode::Strict);
    for e in v.validation_errors() {
        out.push(Finding {
            level: "error".into(),
            policy: Some(e.policy_id().to_string()),
            message: e.to_string(),
        });
    }
    for w in v.validation_warnings() {
        out.push(Finding {
            level: "warning".into(),
            policy: Some(w.policy_id().to_string()),
            message: w.to_string(),
        });
    }
    if out.iter().any(|f| f.level == "error") {
        return out;
    }
    match prove(&pset, resources) {
        Ok(f) => {
            out.extend(f);
            return out;
        }
        Err(e) => out.push(Finding {
            level: "info".into(),
            policy: None,
            message: format!("sampled, not proved: {e}"),
        }),
    }
    let sp = match space(resources, principals) {
        Ok(s) => s,
        Err(e) => {
            out.push(Finding {
                level: "error".into(),
                policy: None,
                message: e,
            });
            return out;
        }
    };
    let az = Authorizer::new();
    let mut contributed: BTreeMap<String, usize> = BTreeMap::new();
    let mut allowed_anon = 0usize;
    let mut total_anon = 0usize;
    // Per-permit: requests it matches in isolation vs. in the full set.
    for p in pset.policies() {
        let id = p.id().to_string();
        let mut solo = PolicySet::new();
        solo.add(p.clone()).ok();
        let mut matched = 0usize;
        let mut effective = 0usize;
        for (_, _, _, _, req) in &sp.requests {
            let r = az.is_authorized(req, &solo, &sp.entities);
            if r.diagnostics().reason().next().is_some() {
                matched += 1;
                if p.effect() == Effect::Permit
                    && az.is_authorized(req, &pset, &sp.entities).decision() == Decision::Allow
                {
                    effective += 1;
                }
            }
        }
        contributed.insert(id.clone(), matched);
        // Base guard rails are expected to be dormant for well-formed catalogs.
        if id.starts_with("base:") {
            continue;
        }
        if matched == 0 {
            out.push(Finding {
                level: "warning".into(),
                policy: Some(id.clone()),
                message: "never satisfiable over the catalog's request space".into(),
            });
        } else if p.effect() == Effect::Permit && effective == 0 {
            out.push(Finding {
                level: "warning".into(),
                policy: Some(id.clone()),
                message: "shadowed: every request it permits is forbidden by another policy".into(),
            });
        } else if p.effect() == Effect::Permit && matched == sp.requests.len() {
            out.push(Finding {
                level: "warning".into(),
                policy: Some(id.clone()),
                message: "always-allow: permits every request in the space".into(),
            });
        }
    }
    for (pid, _, _, _, req) in &sp.requests {
        if pid == "did:key:anonymous" {
            total_anon += 1;
            if az.is_authorized(req, &pset, &sp.entities).decision() == Decision::Allow {
                allowed_anon += 1;
            }
        }
    }
    if allowed_anon > 0 {
        out.push(Finding {
            level: "warning".into(),
            policy: None,
            message: format!("unregistered (anonymous did:key) agents are allowed {allowed_anon}/{total_anon} sampled requests"),
        });
    }
    out
}

/// SMT proofs of never-satisfiable, shadowed, redundant and always-allow rules.
fn prove(
    pset: &PolicySet,
    resources: &BTreeMap<String, ResourceConfig>,
) -> Result<Vec<Finding>, String> {
    use crate::symbolic::{available, Answer, Model};
    if !available() {
        return Err("no SMT solver (install z3 or set REMIT_SMT)".into());
    }
    let m = Model::new(pset, resources).map_err(|e| format!("{e:?}"))?;
    let q = |f: &str| m.check(f).map_err(|e| format!("{e:?}"));
    let mut out = Vec::new();
    let warn = |id: &str, msg: &str| Finding {
        level: "warning".into(),
        policy: Some(id.to_string()),
        message: msg.to_string(),
    };
    let forbidden = m.forbidden();
    for (id, permit, f) in &m.policies {
        // Base guard rails are expected to be dormant for well-formed catalogs.
        if id.starts_with("base:") {
            continue;
        }
        match q(f)? {
            Answer::Unsat => {
                out.push(warn(
                    id,
                    "never satisfiable: no request over this catalog matches it (proved)",
                ));
                continue;
            }
            Answer::Unknown => return Err(format!("solver gave up on `{id}`")),
            Answer::Sat(_) => {}
        }
        if !permit {
            continue;
        }
        if q(&format!("(and {f} (not {forbidden}))"))? == Answer::Unsat {
            out.push(warn(
                id,
                "shadowed: every request it permits is forbidden by another policy (proved)",
            ));
            continue;
        }
        if q(&format!("(not {f})"))? == Answer::Unsat {
            out.push(warn(id, "always-allow: permits every request (proved)"));
        }
        let others = m
            .policies
            .iter()
            .filter(|(i, p, _)| *p && i != id)
            .map(|x| x.2.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if q(&format!("(and {f} (not (or false {others})))"))? == Answer::Unsat {
            out.push(Finding {
                level: "info".into(),
                policy: Some(id.clone()),
                message: "redundant: other permits already cover every request it matches (proved)"
                    .into(),
            });
        }
    }
    // Can a Sender with no group and no verified identity get anything?
    let anon = format!("(and {} (= pgroups ((as const (Array String Bool)) false)) (not p_verified) (= p_tags ((as const (Array String Bool)) false)) (= c_authority ((as const (Array String Bool)) false)))", m.allow());
    if let Answer::Sat(ex) = q(&anon)? {
        out.push(Finding {
            level: "warning".into(),
            policy: None,
            message: format!(
                "unregistered (anonymous did:key) agents are allowed some requests, e.g. {ex}"
            ),
        });
    }
    Ok(out)
}

/// Prove two policy sets equivalent, or return a distinguishing request.
pub fn prove_equivalent(
    before: &str,
    after: &str,
    resources: &BTreeMap<String, ResourceConfig>,
) -> Result<Option<Value>, String> {
    use crate::symbolic::{available, Answer, Model};
    if !available() {
        return Err("no SMT solver (install z3 or set REMIT_SMT)".into());
    }
    let a = Model::new(
        &parse_policies(before).map_err(|e| e.to_string())?,
        resources,
    )
    .map_err(|e| format!("{e:?}"))?;
    let b = Model::new(
        &parse_policies(after).map_err(|e| e.to_string())?,
        resources,
    )
    .map_err(|e| format!("{e:?}"))?;
    match a
        .check(&format!("(xor {} {})", a.allow(), b.allow()))
        .map_err(|e| format!("{e:?}"))?
    {
        Answer::Unsat => Ok(None),
        Answer::Sat(mut ex) => {
            let was = a
                .check(&format!("(and {} (not {}))", a.allow(), b.allow()))
                .map_err(|e| format!("{e:?}"))?;
            ex["change"] = json!(if matches!(was, Answer::Sat(_)) {
                "allow → deny (and possibly more)"
            } else {
                "deny → allow"
            });
            Ok(Some(ex))
        }
        Answer::Unknown => Err("solver gave up".into()),
    }
}

/// Decisions that differ between two policy sets over the request space.
pub fn diff(
    before: &str,
    after: &str,
    resources: &BTreeMap<String, ResourceConfig>,
    principals: &[PrincipalInfo],
) -> Result<Vec<DiffEntry>, String> {
    let a = parse_policies(before).map_err(|e| e.to_string())?;
    let b = parse_policies(after).map_err(|e| e.to_string())?;
    let sp = space(resources, principals)?;
    let az = Authorizer::new();
    let mut out = Vec::new();
    for (p, r, act, ctx, req) in &sp.requests {
        let da = az.is_authorized(req, &a, &sp.entities).decision();
        let db = az.is_authorized(req, &b, &sp.entities).decision();
        if da != db {
            out.push(DiffEntry {
                principal: p.clone(),
                resource: r.clone(),
                action: act.clone(),
                context: ctx.clone(),
                before: format!("{da:?}"),
                after: format!("{db:?}"),
            });
        }
    }
    Ok(out)
}
