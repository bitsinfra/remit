//! Standing approvals, approval tickets and param constraints.

use std::collections::HashMap;

use parking_lot::Mutex;
use remit_policy::PrincipalInfo;
use remit_types::{parse_duration_ms, parse_timestamp_ms};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::ApprovalSection;

#[derive(Clone, Debug, Serialize)]
pub struct Ticket {
    pub ticket: String,
    pub remit_id: String,
    pub principal: String,
    pub card: Value,
    pub created_at: String,
    pub state: String,
}

#[derive(Default)]
pub struct Approvals {
    standing: Mutex<Vec<ApprovalSection>>,
    tickets: Mutex<HashMap<String, Ticket>>,
}

impl Approvals {
    pub fn new(initial: Vec<ApprovalSection>) -> Self {
        Approvals {
            standing: Mutex::new(initial),
            tickets: Mutex::new(HashMap::new()),
        }
    }

    /// Does a standing approval cover this (remit, principal, params)?
    pub fn covers(
        &self,
        remit_id: &str,
        p: &PrincipalInfo,
        params: &Map<String, Value>,
        now_ms: i64,
    ) -> bool {
        self.standing.lock().iter().any(|a| {
            remit_wire::manifest::eq_hash(&a.remit_id, remit_id)
                && principal_matches(&a.principal, p)
                && a.expires_at
                    .as_deref()
                    .and_then(parse_timestamp_ms)
                    .is_none_or(|e| e > now_ms)
                && params_satisfy(&a.params, params)
        })
    }

    /// Has this principal ever been approved for this remit (first-use)?
    pub fn seen(&self, remit_id: &str, p: &PrincipalInfo) -> bool {
        self.standing.lock().iter().any(|a| {
            remit_wire::manifest::eq_hash(&a.remit_id, remit_id)
                && principal_matches(&a.principal, p)
        })
    }

    pub fn open_ticket(&self, remit_id: &str, p: &PrincipalInfo, card: Value) -> Ticket {
        let mut t = self.tickets.lock();
        if let Some(existing) = t
            .values()
            .find(|x| x.remit_id == remit_id && x.principal == p.id && x.state == "pending")
        {
            return existing.clone();
        }
        let id = format!(
            "apr_{}",
            &remit_wire::sha256_hex(
                format!("{remit_id}{}{}", p.id, rand::random::<u64>()).as_bytes()
            )[..16]
        );
        let tk = Ticket {
            ticket: id.clone(),
            remit_id: remit_id.into(),
            principal: p.id.clone(),
            card,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            state: "pending".into(),
        };
        t.insert(id, tk.clone());
        tk
    }

    pub fn tickets(&self) -> Vec<Ticket> {
        let mut v: Vec<Ticket> = self.tickets.lock().values().cloned().collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        v
    }

    pub fn ticket(&self, id: &str) -> Option<Ticket> {
        self.tickets.lock().get(id).cloned()
    }

    /// Approve a ticket, creating a standing approval.
    pub fn approve(
        &self,
        id: &str,
        params: Option<std::collections::BTreeMap<String, Value>>,
        all_principals: bool,
        expires_at: Option<String>,
    ) -> Option<ApprovalSection> {
        let mut t = self.tickets.lock();
        let tk = t.get_mut(id)?;
        tk.state = "approved".into();
        let a = ApprovalSection {
            remit_id: tk.remit_id.clone(),
            principal: if all_principals {
                "*".into()
            } else {
                tk.principal.clone()
            },
            params: params.unwrap_or_default(),
            expires_at,
        };
        self.standing.lock().push(a.clone());
        Some(a)
    }

    pub fn deny(&self, id: &str) -> bool {
        match self.tickets.lock().get_mut(id) {
            Some(t) => {
                t.state = "denied".into();
                true
            }
            None => false,
        }
    }

    pub fn standing(&self) -> Vec<ApprovalSection> {
        self.standing.lock().clone()
    }
}

fn principal_matches(c: &str, p: &PrincipalInfo) -> bool {
    c == "*"
        || c == p.id
        || c.strip_prefix("group:")
            .is_some_and(|g| p.groups.iter().any(|x| x == g))
}

/// Param constraint DSL:
/// * `max_span = { from = "from", until = "until", max = "31d" }`
/// * `<param> = { eq = …, in = […], min = n, max = n, max_len = n }`
pub fn params_satisfy(
    cons: &std::collections::BTreeMap<String, Value>,
    params: &Map<String, Value>,
) -> bool {
    for (k, c) in cons {
        if k == "max_span" {
            let get = |f: &str| {
                c.get(f)
                    .and_then(Value::as_str)
                    .and_then(|n| params.get(n))
                    .and_then(Value::as_str)
                    .and_then(parse_timestamp_ms)
            };
            let max = c
                .get("max")
                .and_then(Value::as_str)
                .and_then(parse_duration_ms);
            match (get("from"), get("until"), max) {
                (Some(a), Some(b), Some(m)) if b >= a && b - a <= m => continue,
                _ => return false,
            }
        }
        let Some(v) = params.get(k) else { return false };
        if let Some(eq) = c.get("eq") {
            if eq != v {
                return false;
            }
        }
        if let Some(Value::Array(opts)) = c.get("in") {
            if !opts.contains(v) {
                return false;
            }
        }
        if let Some(min) = c.get("min").and_then(Value::as_f64) {
            if v.as_f64().is_none_or(|x| x < min) {
                return false;
            }
        }
        if let Some(max) = c.get("max").and_then(Value::as_f64) {
            if v.as_f64().is_none_or(|x| x > max) {
                return false;
            }
        }
        if let Some(ml) = c.get("max_len").and_then(Value::as_u64) {
            if v.as_str().is_none_or(|s| s.chars().count() as u64 > ml) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn constraints() {
        let c: std::collections::BTreeMap<String, Value> = serde_json::from_value(json!({
            "max_span": {"from": "from", "until": "until", "max": "31d"},
            "minutes": {"max": 240, "min": 15}
        }))
        .unwrap();
        let ok = json!({"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z", "minutes": 120});
        assert!(params_satisfy(&c, ok.as_object().unwrap()));
        let long = json!({"from": "2026-01-01T00:00:00Z", "until": "2026-12-08T00:00:00Z", "minutes": 120});
        assert!(!params_satisfy(&c, long.as_object().unwrap()));
        let big = json!({"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z", "minutes": 600});
        assert!(!params_satisfy(&c, big.as_object().unwrap()));
    }

    #[test]
    fn tickets_become_standing() {
        let a = Approvals::new(vec![]);
        let p = PrincipalInfo {
            id: "did:web:a".into(),
            groups: vec!["g".into()],
            ..Default::default()
        };
        let params = Map::new();
        assert!(!a.covers("sha256:aa", &p, &params, 0));
        let t = a.open_ticket("sha256:aa", &p, json!({}));
        assert_eq!(
            a.open_ticket("sha256:aa", &p, json!({})).ticket,
            t.ticket,
            "deduplicated"
        );
        a.approve(&t.ticket, None, false, None).unwrap();
        assert!(a.covers("aa", &p, &params, 0));
        let other = PrincipalInfo {
            id: "did:web:b".into(),
            ..Default::default()
        };
        assert!(!a.covers("aa", &other, &params, 0));
    }
}
