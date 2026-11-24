//! Remit policy: **analysis produces facts; Cedar decides on facts.**
//! Delegated, attenuable authority travels as Biscuit tokens. LLMs never
//! write the Holder's policy.

pub mod authority;
pub mod budget;
pub mod lint;
pub mod presets;
pub mod shared;
pub mod symbolic;

use std::collections::BTreeMap;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CDecision, Entities, EntityUid, PolicySet, Request, Schema,
};
use remit_analyze::Facts;
use remit_read::ResourceConfig;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub use budget::{Actual, Ask, BudgetConfig, BudgetError, Ledger, Privacy, Reservation};

/// The Cedar schema for Remit entities, actions and the facts context.
pub const SCHEMA: &str = r#"
namespace Remit {
  entity Group;
  entity Agent in [Group] = {
    "org": String,
    "verified": Bool,
    "tags": Set<String>,
  };
  entity Dataset;
  entity Table in [Dataset] = {
    "labels": Set<String>,
    "sensitivity": String,
    "purposes": Set<String>,
    "operations": Set<String>,
    "max_bits": Long,
    "aggregate_only": Bool,
    "k": Long,
    "dp": Bool,
    "owner_scoped": Bool,
  };
  type Facts = {
    "mode": String,
    "purpose": String,
    "columns": Set<String>,
    "ops": Set<String>,
    "aggregate_only": Bool,
    "min_group_size": Long,
    "result_bits": Long,
    "fuel": Long,
    "memory_bytes": Long,
    "wall_ms": Long,
    "max_rows_total": Long,
    "epsilon_milli": Long,
    "standing_approval": Bool,
    "authority": Set<String>,
  };
  action "read" appliesTo { principal: [Agent], resource: [Table], context: Facts };
  action "aggregate" in ["read"] appliesTo { principal: [Agent], resource: [Table], context: Facts };
  action "search" in ["read"] appliesTo { principal: [Agent], resource: [Table], context: Facts };
  action "call" appliesTo { principal: [Agent], resource: [Table], context: Facts };
  action "run_kernel" appliesTo { principal: [Agent], resource: [Table], context: Facts };
}
"#;

/// Principal attributes known to the Holder.
#[derive(Clone, Debug, Default, Serialize, serde::Deserialize, PartialEq)]
pub struct PrincipalInfo {
    pub id: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Denial {
    pub resource: String,
    pub action: String,
    /// Policy ids that forbade (empty: no permit matched).
    pub forbidden_by: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub permitted_by: Vec<String>,
    pub denials: Vec<Denial>,
    pub errors: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy parse: {0}")]
    Parse(String),
    #[error("policy validation: {0}")]
    Validation(String),
    #[error("entities: {0}")]
    Entities(String),
}

pub struct PolicyEngine {
    schema: Schema,
    policies: PolicySet,
    static_entities: Entities,
    authorizer: Authorizer,
    policy_sha256: String,
    source: String,
    /// Static entities + one principal, per distinct principal (hot path).
    with_agent: parking_lot::Mutex<std::collections::HashMap<String, std::sync::Arc<Entities>>>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("policy_sha256", &self.policy_sha256)
            .finish()
    }
}

/// Parse policy text; `@id("…")` annotations become policy ids.
pub fn parse_policies(text: &str) -> Result<PolicySet, PolicyError> {
    let raw = PolicySet::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
    let mut out = PolicySet::new();
    for p in raw.policies() {
        let p = match p.annotation("id") {
            Some(id) => p.new_id(cedar_policy::PolicyId::new(id)),
            None => p.clone(),
        };
        out.add(p).map_err(|e| PolicyError::Parse(e.to_string()))?;
    }
    Ok(out)
}

pub fn schema() -> Schema {
    Schema::from_cedarschema_str(SCHEMA)
        .expect("valid schema")
        .0
}

/// Cedar entity JSON for a catalog resource.
pub fn table_entity(name: &str, r: &ResourceConfig) -> Value {
    let dataset = name.split('.').next().unwrap_or(name);
    json!({
        "uid": {"type": "Remit::Table", "id": name},
        "attrs": {
            "labels": r.labels,
            "sensitivity": r.sensitivity.clone().unwrap_or_else(|| "medium".into()),
            "purposes": r.purposes,
            "operations": r.operations(),
            "max_bits": r.max_bits.unwrap_or(1 << 40) as i64,
            "aggregate_only": r.aggregate_only,
            "k": r.k.unwrap_or(0) as i64,
            "dp": r.dp.is_some(),
            "owner_scoped": r.owner_column.is_some(),
        },
        "parents": [{"type": "Remit::Dataset", "id": dataset}],
    })
}

fn agent_entity(p: &PrincipalInfo) -> Value {
    json!({
        "uid": {"type": "Remit::Agent", "id": p.id},
        "attrs": {"org": p.org, "verified": p.verified, "tags": p.tags},
        "parents": p.groups.iter().map(|g| json!({"type": "Remit::Group", "id": g})).collect::<Vec<_>>(),
    })
}

impl PolicyEngine {
    /// Build from Cedar policy text (presets already expanded) and the catalog.
    pub fn new(
        policy_text: &str,
        resources: &BTreeMap<String, ResourceConfig>,
        groups: &[String],
    ) -> Result<Self, PolicyError> {
        let schema = schema();
        let policies = parse_policies(policy_text)?;
        let v = cedar_policy::Validator::new(schema.clone())
            .validate(&policies, cedar_policy::ValidationMode::Strict);
        if !v.validation_passed() {
            let errs: Vec<String> = v.validation_errors().map(|e| e.to_string()).collect();
            return Err(PolicyError::Validation(errs.join("; ")));
        }
        let mut ents: Vec<Value> = resources.iter().map(|(n, r)| table_entity(n, r)).collect();
        let mut datasets: Vec<&str> = resources
            .keys()
            .map(|n| n.split('.').next().unwrap_or(n))
            .collect();
        datasets.sort();
        datasets.dedup();
        for d in datasets {
            ents.push(
                json!({"uid": {"type": "Remit::Dataset", "id": d}, "attrs": {}, "parents": []}),
            );
        }
        for g in groups {
            ents.push(
                json!({"uid": {"type": "Remit::Group", "id": g}, "attrs": {}, "parents": []}),
            );
        }
        let static_entities = Entities::from_json_value(Value::Array(ents), Some(&schema))
            .map_err(|e| PolicyError::Entities(e.to_string()))?;
        let policy_sha256 = hex::encode(Sha256::digest(policy_text.as_bytes()));
        Ok(PolicyEngine {
            schema,
            policies,
            static_entities,
            authorizer: Authorizer::new(),
            policy_sha256,
            source: policy_text.to_string(),
            with_agent: Default::default(),
        })
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }

    /// Decide on every (resource, action) the facts request. All must allow.
    pub fn decide(&self, p: &PrincipalInfo, facts: &Facts) -> Decision {
        let mut out = Decision {
            allowed: true,
            permitted_by: vec![],
            denials: vec![],
            errors: vec![],
        };
        let entities = match self.entities_for(p) {
            Ok(e) => e,
            Err(e) => {
                out.allowed = false;
                out.errors.push(e);
                return out;
            }
        };
        let principal = EntityUid::from_type_name_and_id(
            "Remit::Agent".parse().unwrap(),
            p.id.parse().unwrap(),
        );
        for (res, rf) in &facts.resources {
            let resource = EntityUid::from_type_name_and_id(
                "Remit::Table".parse().unwrap(),
                res.parse().unwrap(),
            );
            for action in &rf.actions {
                let a = EntityUid::from_type_name_and_id(
                    "Remit::Action".parse().unwrap(),
                    action.parse().unwrap(),
                );
                let ctx = match Context::from_json_value(
                    facts.cedar_context(res),
                    Some((&self.schema, &a)),
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        out.allowed = false;
                        out.errors.push(format!("context: {e}"));
                        continue;
                    }
                };
                let req = match Request::new(
                    principal.clone(),
                    a.clone(),
                    resource.clone(),
                    ctx,
                    Some(&self.schema),
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        out.allowed = false;
                        out.errors.push(format!("request: {e}"));
                        continue;
                    }
                };
                let resp = self
                    .authorizer
                    .is_authorized(&req, &self.policies, entities.as_ref());
                let reasons: Vec<String> =
                    resp.diagnostics().reason().map(|r| r.to_string()).collect();
                for e in resp.diagnostics().errors() {
                    out.errors.push(e.to_string());
                }
                if resp.decision() == CDecision::Allow {
                    for r in reasons {
                        if !out.permitted_by.contains(&r) {
                            out.permitted_by.push(r);
                        }
                    }
                } else {
                    out.allowed = false;
                    let forbidden_by = reasons
                        .into_iter()
                        .filter(|id| self.is_forbid(id))
                        .collect();
                    out.denials.push(Denial {
                        resource: res.clone(),
                        action: action.clone(),
                        forbidden_by,
                    });
                }
            }
        }
        if facts.resources.is_empty() {
            out.allowed = false;
        }
        out
    }

    /// The entity store for a principal (cached; keyed by *all* its attributes).
    fn entities_for(&self, p: &PrincipalInfo) -> Result<std::sync::Arc<Entities>, String> {
        let key = serde_json::to_string(p).map_err(|e| e.to_string())?;
        if let Some(e) = self.with_agent.lock().get(&key) {
            return Ok(e.clone());
        }
        let agent = Entities::from_json_value(json!([agent_entity(p)]), Some(&self.schema))
            .map_err(|e| format!("principal: {e}"))?;
        let e = self
            .static_entities
            .clone()
            .add_entities(
                agent.iter().cloned().collect::<Vec<_>>(),
                Some(&self.schema),
            )
            .map_err(|e| e.to_string())?;
        let e = std::sync::Arc::new(e);
        let mut c = self.with_agent.lock();
        if c.len() >= 4096 {
            c.clear();
        }
        c.insert(key, e.clone());
        Ok(e)
    }

    fn is_forbid(&self, id: &str) -> bool {
        self.policies
            .policies()
            .any(|p| p.id().to_string() == id && p.effect() == cedar_policy::Effect::Forbid)
    }
}

#[cfg(test)]
mod tests;
