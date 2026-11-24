//! Admission: decode → authN → freshness/replay → plan cache → analyze →
//! authority (Biscuit) → decide (Cedar) → approvals → reserve budgets.
//! Every step is mechanical: nothing reads Sender-authored prose.

use std::sync::Arc;
use std::time::Instant;

use remit_analyze::{access_card, Analysis, Diagnostic};
use remit_policy::{Ask, Decision, PrincipalInfo, Privacy, Reservation};
use remit_read::Principal;
use remit_wire::{open_manifest, Envelope, Manifest, Mode};
use serde::Serialize;
use serde_json::{json, Value};

use crate::identity::Transport;
use crate::replay::Seen;
use crate::state::Holder;

#[derive(Debug, Clone, Serialize)]
pub struct Stage {
    pub stage: &'static str,
    pub us: u64,
}

pub struct Admitted {
    pub manifest: Manifest,
    pub principal: PrincipalInfo,
    pub trust_domain: String,
    pub analysis: Arc<Analysis>,
    pub decision: Decision,
    pub reservation: Option<Reservation>,
    pub source: Option<String>,
    pub datasets: Vec<String>,
    pub trace: Vec<Stage>,
    pub dp: Option<remit_emit::dp::DpParams>,
    pub weight: u32,
    /// Answer already released for this exact program, params and snapshot.
    pub cached: Option<crate::state::CachedResult>,
    pub cache_key: String,
    pub plane: std::sync::Arc<remit_read::ReadPlane>,
    pub plan_cache_hit: bool,
}

pub enum Outcome {
    Admitted(Box<Admitted>),
    Rejected {
        diagnostics: Vec<Diagnostic>,
        denied: bool,
        trace: Vec<Stage>,
        remit_id: Option<String>,
    },
    PendingApproval {
        ticket: String,
        card: Value,
        trace: Vec<Stage>,
    },
    CounterOffer {
        patch: Vec<Value>,
        diagnostics: Vec<Diagnostic>,
        trace: Vec<Stage>,
        remit_id: String,
    },
    Busy {
        retry_after_s: u64,
        message: String,
    },
}

fn diag(code: &str, path: &str, msg: impl Into<String>) -> Diagnostic {
    Diagnostic::new(code, path, msg)
}

struct Timer {
    t: Instant,
    trace: Vec<Stage>,
}

impl Timer {
    fn new() -> Self {
        Timer {
            t: Instant::now(),
            trace: Vec::new(),
        }
    }
    fn mark(&mut self, stage: &'static str) {
        let now = Instant::now();
        self.trace.push(Stage {
            stage,
            us: now.duration_since(self.t).as_micros() as u64,
        });
        self.t = now;
    }
}

pub const MAX_ENVELOPE_BYTES: usize = 512 * 1024;

#[derive(Default)]
pub struct AdmitOptions {
    /// Transport-level identity (RFC 9421, WIMSE).
    pub transport: Transport,
    /// `check` mode: no nonce consumption, no reservation.
    pub dry: bool,
    /// Sender-configured auto-accept of counter-offers is done client-side;
    /// the Holder only reports clamps.
    pub accept_clamps: bool,
}

/// Run the admission pipeline on raw envelope JSON bytes.
pub async fn admit(h: &Holder, body: &[u8], opts: AdmitOptions) -> Outcome {
    let mut tm = Timer::new();
    // 1. Decode.
    if body.len() > MAX_ENVELOPE_BYTES {
        return reject(
            vec![diag(
                "RMT-E0001",
                "/",
                format!("envelope exceeds {MAX_ENVELOPE_BYTES} bytes"),
            )],
            false,
            tm.trace,
            None,
        );
    }
    let env: Envelope = match serde_json::from_slice(body) {
        Ok(e) => e,
        Err(e) => {
            return reject(
                vec![diag("RMT-E0002", "/", format!("not a DSSE envelope: {e}"))],
                false,
                tm.trace,
                None,
            )
        }
    };
    tm.mark("decode");
    // 2. AuthN.
    let keyids: Vec<String> = env.signatures.iter().map(|s| s.keyid.clone()).collect();
    h.prefetch_keys(&keyids).await;
    let (mut m, _keyid) = match open_manifest(&env, |k| h.resolve_key(k, &opts.transport)) {
        Ok(x) => x,
        Err(remit_wire::WireError::Auth(msg)) => {
            return reject(
                vec![diag("RMT-E0010", "/signatures", msg)],
                true,
                tm.trace,
                None,
            )
        }
        Err(e) => {
            return reject(
                vec![diag("RMT-E0003", "/", e.to_string())],
                false,
                tm.trace,
                None,
            )
        }
    };
    let remit_id = m.remit_id();
    // A transport signature must come from the sender it carries.
    if let Some((kid, _)) = &opts.transport.signed_by {
        if kid.split('#').next() != m.sender.split('#').next() {
            return reject(
                vec![diag(
                    "RMT-E0011",
                    "/sender",
                    "the HTTP message signature was made by a different identity",
                )],
                true,
                tm.trace,
                Some(remit_id),
            );
        }
    }
    tm.mark("authn");
    // 3. Freshness and replay.
    let now = h.now_ms();
    if m.holder != h.id() {
        return reject(
            vec![diag(
                "RMT-E0020",
                "/holder",
                format!(
                    "this remit is addressed to `{}`, not `{}`",
                    m.holder,
                    h.id()
                ),
            )],
            false,
            tm.trace,
            Some(remit_id),
        );
    }
    let (iat, exp) = (m.issued_at_ms(), m.expires_at_ms());
    let skew = h.cfg.holder.clock_skew_s * 1000;
    if exp <= now {
        return reject(
            vec![diag("RMT-E0021", "/expires_at", "the remit has expired")
                .hint("re-sign with a fresh expires_at")],
            false,
            tm.trace,
            Some(remit_id),
        );
    }
    if iat > now + skew {
        return reject(
            vec![diag(
                "RMT-E0022",
                "/issued_at",
                "issued_at is in the future",
            )],
            false,
            tm.trace,
            Some(remit_id),
        );
    }
    if exp - iat > h.cfg.holder.max_validity_s * 1000 {
        return reject(
            vec![diag(
                "RMT-E0023",
                "/expires_at",
                format!("validity window exceeds {} s", h.cfg.holder.max_validity_s),
            )],
            false,
            tm.trace,
            Some(remit_id),
        );
    }
    if !opts.dry {
        match h.nonces.check(&m.sender, &m.nonce, exp + skew, now) {
            Seen::Fresh => {}
            Seen::Replayed => {
                return reject(
                    vec![diag("RMT-E0024", "/nonce", "replayed nonce")],
                    false,
                    tm.trace,
                    Some(remit_id),
                )
            }
            Seen::Full => {
                return Outcome::Busy {
                    retry_after_s: 5,
                    message: "replay cache is full".into(),
                }
            }
        }
    }
    tm.mark("freshness");
    // Resolve code from blobs when not inline.
    let source = match resolve_source(h, &m) {
        Ok(source) => source,
        Err(e) => {
            return reject(
                vec![diag("RMT-E0030", "/code/source_sha256", e.to_string())],
                false,
                tm.trace,
                Some(remit_id),
            )
        }
    };
    if let (Some(c), Some(src)) = (m.code.as_mut(), &source) {
        c.source = Some(src.clone());
    }
    let (principal, domain) = h.principal(&m.sender, &opts.transport);
    let rp = Principal {
        id: principal.id.clone(),
        groups: principal.groups.clone(),
    };
    // 4. Plan cache.
    let (_, catalog_sha) = h.catalog(&principal.groups);
    let mut groups = principal.groups.clone();
    groups.sort();
    let cache_key = format!(
        "{remit_id}|{catalog_sha}|{}|{}|{}|{}",
        h.policy.policy_sha256(),
        groups.join(","),
        principal.id,
        m.params_sha256()
    );
    let cached = h.analysis_cache.lock().get(&cache_key).cloned();
    let plan_cache_hit = cached.is_some();
    tm.mark("plan_cache");
    // 5. Analyze.
    let analysis = match cached {
        Some(a) => {
            h.metrics
                .plan_cache_hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            a
        }
        None => match remit_analyze::analyze(&m, &h.plane(), &rp, &h.cfg.runtime.limits).await {
            Ok(a) => {
                let a = Arc::new(a);
                h.analysis_cache.lock().put(cache_key, a.clone());
                a
            }
            Err(d) => return reject(d, false, tm.trace, Some(remit_id)),
        },
    };
    if let (Some(c), Some(src)) = (m.code.as_ref(), source.as_ref()) {
        if c.lang == "wasm/component" {
            use base64::Engine as _;
            let bytes = match base64::engine::general_purpose::STANDARD.decode(src.trim()) {
                Ok(b) => b,
                Err(_) => {
                    return reject(
                        vec![diag(
                            "RMT-E0604",
                            "/code/source",
                            "a wasm/component source is the base64 component bytes",
                        )],
                        false,
                        tm.trace,
                        Some(remit_id),
                    )
                }
            };
            if let Err(e) = remit_kernel::sender::validate_structure(&bytes, &Default::default()) {
                return reject(vec![diag("RMT-E0604", "/code/source", e).hint("Sender components target the remit:kernel `sender-kernel` world; precompiled artifacts are never accepted")], false, tm.trace, Some(remit_id));
            }
        }
    }
    if m.mode == Mode::Kernel && m.code.as_ref().is_some_and(|c| h.engine(&c.lang).is_none()) {
        return reject(
            vec![diag(
                "RMT-E0151",
                "/code/lang",
                format!(
                    "no engine for this language here (available: {})",
                    h.cfg.runtime.limits.languages.join(", ")
                ),
            )],
            false,
            tm.trace,
            Some(remit_id),
        );
    }
    if m.is_template() && !opts.dry {
        return reject(
            vec![diag(
                "RMT-E0111",
                "/params",
                "templates (no params) can be checked but not run",
            )
            .hint("bind params to run")],
            false,
            tm.trace,
            Some(remit_id),
        );
    }
    // DP parameters: the strictest of the DP-governed resources.
    let mut dp = None;
    let dp_cfgs: Vec<&remit_read::DpConfig> = analysis
        .facts
        .resources
        .keys()
        .filter_map(|t| h.resources.get(t).and_then(|r| r.dp.as_ref()))
        .collect();
    if !dp_cfgs.is_empty() {
        let max_eps = dp_cfgs
            .iter()
            .filter_map(|d| d.max_epsilon_per_remit)
            .fold(f64::INFINITY, f64::min);
        let eps = analysis.limits.epsilon;
        if !eps.is_finite() || eps <= 0.0 {
            return reject(
                vec![diag(
                    "RMT-E0160",
                    "/limits/epsilon",
                    "DP-governed: declare limits.epsilon > 0",
                )
                .fix(json!([{"op": "add", "path": "/limits/epsilon", "value": 0.1}]))],
                false,
                tm.trace,
                Some(remit_id),
            );
        }
        if eps > max_eps {
            return reject(
                vec![diag(
                    "RMT-E0162",
                    "/limits/epsilon",
                    format!("ε {eps} exceeds the per-remit maximum {max_eps}"),
                )
                .fix(json!([{"op": "replace", "path": "/limits/epsilon", "value": max_eps}]))],
                false,
                tm.trace,
                Some(remit_id),
            );
        }
        let max_delta = dp_cfgs
            .iter()
            .map(|d| d.delta)
            .fold(f64::INFINITY, f64::min);
        let delta = m.limits.delta.unwrap_or(max_delta);
        if !(delta > 0.0 && delta <= max_delta) {
            return reject(
                vec![diag(
                    "RMT-E0163",
                    "/limits/delta",
                    format!("δ must be in (0, {max_delta}]"),
                )
                .fix(json!([{"op": "replace", "path": "/limits/delta", "value": max_delta}]))],
                false,
                tm.trace,
                Some(remit_id),
            );
        }
        let gaussian = dp_cfgs.iter().any(|d| d.mechanism == "gaussian");
        let mechanism = if gaussian {
            remit_emit::dp::Mechanism::Gaussian
        } else {
            remit_emit::dp::Mechanism::Laplace
        };
        dp = Some(remit_emit::dp::DpParams {
            epsilon: eps,
            delta,
            mechanism,
        });
    }
    tm.mark("analyze");
    // 6. Authority.
    let mut issuers = std::collections::BTreeSet::new();
    if !m.authority.is_empty() {
        let (txn, biscuits): (Vec<String>, Vec<String>) = m
            .authority
            .iter()
            .cloned()
            .partition(|t| t.starts_with("txn:"));
        if (!biscuits.is_empty() && h.biscuit_roots.is_empty())
            || (!txn.is_empty() && h.cfg.identity.transaction_tokens.is_empty())
        {
            return reject(
                vec![diag(
                    "RMT-E0040",
                    "/authority",
                    "this Holder does not accept delegated authority tokens",
                )],
                true,
                tm.trace,
                Some(remit_id),
            );
        }
        match remit_policy::authority::verify(
            &biscuits,
            &h.biscuit_roots,
            &principal.id,
            &analysis.facts,
            now / 1000,
        ) {
            Ok(i) => issuers.extend(i),
            Err(e) => {
                return reject(
                    vec![diag("RMT-E0041", "/authority", e.to_string())],
                    true,
                    tm.trace,
                    Some(remit_id),
                )
            }
        }
        for t in &txn {
            match crate::identity::verify_transaction_token(
                h,
                &t["txn:".len()..],
                &principal.id,
                &analysis.facts,
                now / 1000,
            ) {
                Ok(i) => {
                    issuers.insert(format!("txn:{i}"));
                }
                Err(e) => {
                    return reject(
                        vec![diag("RMT-E0042", "/authority", e)],
                        true,
                        tm.trace,
                        Some(remit_id),
                    )
                }
            }
        }
    }
    tm.mark("authority");
    // Standing approvals feed the facts.
    let params = m.params.clone().unwrap_or_default();
    let standing = h.approvals.covers(&remit_id, &principal, &params, now);
    let mut facts = analysis.facts.clone();
    facts.standing_approval = standing;
    facts.authority = issuers;
    // 7. Decide.
    let decision = h.policy.decide(&principal, &facts);
    tm.mark("decide");
    if !decision.allowed {
        let mut d: Vec<Diagnostic> = decision
            .denials
            .iter()
            .map(|x| {
                let why = if x.forbidden_by.is_empty() {
                    "no policy permits it".to_string()
                } else {
                    format!("forbidden by {}", x.forbidden_by.join(", "))
                };
                diag(
                    "RMT-E0050",
                    "/reads",
                    format!("`{}` on `{}` is not allowed: {why}", x.action, x.resource),
                )
                .hint("compare against the catalog's policy_hints")
            })
            .collect();
        if d.is_empty() {
            d.push(diag("RMT-E0050", "/", "denied by policy"));
        }
        return reject(d, true, tm.trace, Some(remit_id));
    }
    // Counter-offer when limits were clamped.
    if !analysis.clamps.is_empty() && !opts.accept_clamps {
        let d = analysis
            .clamps
            .iter()
            .map(|c| {
                diag(
                    "RMT-E0140",
                    c["path"].as_str().unwrap_or("/limits"),
                    format!("the Holder caps this at {}", c["value"]),
                )
                .fix(json!([c]))
            })
            .collect();
        return Outcome::CounterOffer {
            patch: analysis.clamps.clone(),
            diagnostics: d,
            trace: tm.trace,
            remit_id,
        };
    }
    // Approvals required by resources.
    let needs = facts
        .resources
        .keys()
        .filter_map(|t| h.resources.get(t).and_then(|r| r.approval.clone()))
        .collect::<Vec<_>>();
    let need_required = needs.iter().any(|a| a == "required");
    let need_first = needs.iter().any(|a| a == "first-use");
    if (need_required && !standing)
        || (need_first && !standing && !h.approvals.seen(&remit_id, &principal))
    {
        let card = access_card(&m, &analysis);
        let t = h.approvals.open_ticket(&remit_id, &principal, card.clone());
        return Outcome::PendingApproval {
            ticket: t.ticket,
            card,
            trace: tm.trace,
        };
    }
    // 8. Reserve.
    let mut datasets: Vec<String> = facts
        .resources
        .keys()
        .map(|t| t.split('.').next().unwrap_or(t).to_string())
        .collect();
    datasets.sort();
    datasets.dedup();
    let plane = h.plane();
    let cache_key = crate::run::result_cache_key(h, &plane, &m, &principal, &facts);
    let cached = h.result_cache.lock().get(&cache_key).cloned();
    let paid = cached
        .as_ref()
        .is_some_and(|c| c.seen_by.contains(&principal.id));
    let reservation = if opts.dry {
        None
    } else {
        let ask = Ask {
            principal: principal.id.clone(),
            verified: principal.verified
                || principal
                    .groups
                    .iter()
                    .any(|g| g == "verified-agents" || g == "internal"),
            datasets: datasets.clone(),
            bits: if paid { 0 } else { facts.result_bits },
            cached: cached.is_some(),
            fuel: analysis.limits.fuel,
            privacy: dp
                .filter(|_| !paid)
                .map(|d| privacy_of(&d))
                .unwrap_or(Privacy::ZERO),
        };
        match h.ledger.reserve(&ask, now).await {
            Ok(r) => Some(r),
            Err(e) if e.retryable() => {
                // Nothing ran: the same envelope may be retried after Retry-After.
                h.nonces.forget(&m.sender, &m.nonce);
                return Outcome::Busy {
                    retry_after_s: 1,
                    message: e.to_string(),
                };
            }
            Err(e) => {
                return reject(
                    vec![diag("RMT-E0060", "/limits", e.to_string())
                        .hint("budgets reset daily; tighten the result type to spend fewer bits")],
                    true,
                    tm.trace,
                    Some(remit_id),
                )
            }
        }
    };
    tm.mark("reserve");
    h.metrics
        .admitted
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if facts.standing_approval {
        h.metrics
            .standing
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let weight = h.weight(&principal);
    Outcome::Admitted(Box::new(Admitted {
        manifest: m,
        weight,
        cached,
        cache_key,
        plane,
        principal,
        trust_domain: domain,
        analysis,
        decision,
        reservation,
        source,
        datasets,
        trace: tm.trace,
        dp,
        plan_cache_hit,
    }))
}

fn reject(
    diagnostics: Vec<Diagnostic>,
    denied: bool,
    trace: Vec<Stage>,
    remit_id: Option<String>,
) -> Outcome {
    Outcome::Rejected {
        diagnostics,
        denied,
        trace,
        remit_id,
    }
}

/// Ledger cost of a DP release at these parameters.
pub fn privacy_of(d: &remit_emit::dp::DpParams) -> Privacy {
    match d.mechanism {
        remit_emit::dp::Mechanism::Laplace => Privacy::pure(d.epsilon),
        remit_emit::dp::Mechanism::Gaussian => {
            Privacy::zcdp(remit_emit::dp::rho_for(d.epsilon, d.delta))
        }
    }
}

pub fn resolve_source(h: &Holder, m: &remit_wire::Manifest) -> anyhow::Result<Option<String>> {
    let Some(code) = &m.code else { return Ok(None) };
    let hash = remit_wire::manifest::normalize_hash(&code.source_sha256);
    let source = code
        .source
        .clone()
        .or_else(|| h.blobs.lock().get(&hash).cloned())
        .ok_or_else(|| anyhow::anyhow!("code blob not found"))?;
    anyhow::ensure!(
        remit_wire::sha256_hex(source.as_bytes()) == hash,
        "code hash does not match source"
    );
    Ok(Some(source))
}
