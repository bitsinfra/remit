//! Budget ledgers: per principal (fairness, DoS isolation) **and** global per
//! dataset (soundness under adaptivity). Reservations happen at admission
//! and settle at completion, over **rolling** windows (1 minute, 1 day).
//!
//! * Privacy loss is tracked both as pure ε and as zCDP ρ; a cap is compared
//!   with the tighter sound bound (see [`Privacy`]).
//! * Global budgets are a *scheduled* resource: principals without a verified
//!   group share at most `unverified_global_share` of each global budget, so
//!   Sybil depletion cannot starve verified agents.
//! * Backed by a write-ahead log: a reservation is durable before anything
//!   runs. Reservations that never settled (crash) stay charged in full.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    #[serde(default = "d_bits_p")]
    pub bits_per_principal_per_day: u64,
    #[serde(default = "d_bits_g")]
    pub bits_global_per_day: u64,
    #[serde(default = "d_fuel_min")]
    pub fuel_per_principal_per_minute: u64,
    #[serde(default = "d_fuel_day")]
    pub fuel_per_principal_per_day: u64,
    #[serde(default = "d_eps_p")]
    pub epsilon_per_principal_per_day: f64,
    #[serde(default = "d_conc")]
    pub concurrency_per_principal: u32,
    #[serde(default = "d_conc_g")]
    pub concurrency_global: u32,
    /// Per-dataset global ε per day (from catalog dp config).
    #[serde(default)]
    pub epsilon_global_per_day: HashMap<String, f64>,
    /// Per-dataset lifetime ε (never resets), when the policy needs one.
    #[serde(default)]
    pub epsilon_global_lifetime: HashMap<String, f64>,
    /// δ used to convert accumulated zCDP ρ to (ε, δ).
    #[serde(default = "d_delta")]
    pub privacy_delta: f64,
    /// Share of every global budget available to unverified principals together.
    #[serde(default = "d_share")]
    pub unverified_global_share: f64,
    /// Refuse privacy-budget spending by unverified principals altogether.
    #[serde(default)]
    pub epsilon_requires_verified: bool,
    /// fsync the WAL on every reservation (default: OS-buffered writes).
    #[serde(default)]
    pub wal_sync: bool,
    /// Weighted fair queuing: weight per principal group (default 1).
    #[serde(default)]
    pub weights: HashMap<String, u32>,
    /// Postgres DSN for a ledger shared by Holder replicas (`env:NAME` reads an env var).
    #[serde(default)]
    pub shared_dsn: Option<String>,
}

fn d_bits_p() -> u64 {
    4096
}
fn d_bits_g() -> u64 {
    65536
}
fn d_fuel_min() -> u64 {
    2_000_000_000
}
fn d_fuel_day() -> u64 {
    200_000_000_000
}
fn d_eps_p() -> f64 {
    1.0
}
fn d_conc() -> u32 {
    8
}
fn d_conc_g() -> u32 {
    256
}
fn d_delta() -> f64 {
    1e-6
}
fn d_share() -> f64 {
    0.5
}

impl Default for BudgetConfig {
    fn default() -> Self {
        serde_json::from_value(serde_json::json!({})).expect("defaults")
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error, Serialize)]
pub enum BudgetError {
    #[error("bit budget exhausted ({scope})")]
    Bits { scope: String },
    #[error("fuel budget exhausted ({scope})")]
    Fuel { scope: String },
    #[error("privacy budget exhausted ({scope})")]
    Epsilon { scope: String },
    #[error("too many in-flight remits ({scope})")]
    Concurrency { scope: String },
    #[error("budget ledger unavailable")]
    Unavailable,
}

impl BudgetError {
    /// Retryable errors become 429; others are denials until the window rolls.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            BudgetError::Concurrency { .. } | BudgetError::Unavailable
        )
    }
}

/// Privacy cost of one release.
///
/// Laplace-type (pure ε-DP) mechanisms compose additively in ε *and*, because
/// ε-DP implies ε²/2-zCDP, in ρ. Gaussian mechanisms only have ρ. The
/// accumulated loss is the tighter valid bound: Σε (when nothing Gaussian was
/// released) or ρ + 2·√(ρ·ln(1/δ)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Privacy {
    #[serde(default)]
    pub eps: f64,
    #[serde(default)]
    pub rho_pure: f64,
    #[serde(default)]
    pub rho_gauss: f64,
}

impl Privacy {
    pub const ZERO: Privacy = Privacy {
        eps: 0.0,
        rho_pure: 0.0,
        rho_gauss: 0.0,
    };
    pub fn pure(eps: f64) -> Privacy {
        Privacy {
            eps,
            rho_pure: eps * eps / 2.0,
            rho_gauss: 0.0,
        }
    }
    pub fn zcdp(rho: f64) -> Privacy {
        Privacy {
            eps: 0.0,
            rho_pure: 0.0,
            rho_gauss: rho,
        }
    }
    pub fn is_zero(&self) -> bool {
        self.eps <= 0.0 && self.rho_gauss <= 0.0
    }
    pub fn add(self, o: Privacy) -> Privacy {
        Privacy {
            eps: self.eps + o.eps,
            rho_pure: self.rho_pure + o.rho_pure,
            rho_gauss: self.rho_gauss + o.rho_gauss,
        }
    }
    fn sub(self, o: Privacy) -> Privacy {
        Privacy {
            eps: (self.eps - o.eps).max(0.0),
            rho_pure: (self.rho_pure - o.rho_pure).max(0.0),
            rho_gauss: (self.rho_gauss - o.rho_gauss).max(0.0),
        }
    }
    fn min(self, o: Privacy) -> Privacy {
        Privacy {
            eps: self.eps.min(o.eps),
            rho_pure: self.rho_pure.min(o.rho_pure),
            rho_gauss: self.rho_gauss.min(o.rho_gauss),
        }
    }
    /// Total ε at `delta`.
    pub fn epsilon(&self, delta: f64) -> f64 {
        let rho = self.rho_pure + self.rho_gauss;
        let z = if rho <= 0.0 {
            0.0
        } else {
            rho + 2.0 * (rho * (1.0 / delta).ln()).sqrt()
        };
        if self.rho_gauss > 0.0 {
            z
        } else {
            self.eps.min(z)
        }
    }
}

/// What a remit asks for at admission (worst case).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Ask {
    pub principal: String,
    /// Member of a verified group (or marked verified).
    #[serde(default)]
    pub verified: bool,
    pub datasets: Vec<String>,
    pub bits: u64,
    pub fuel: u64,
    #[serde(default)]
    pub privacy: Privacy,
    /// The answer is already released and cached: only the asking principal is
    /// charged, the global ledgers are untouched.
    #[serde(default)]
    pub cached: bool,
}

/// What it actually used. Cached answers charge the asking principal (they
/// learn the bits) but not the global ledgers (nothing new was released).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Actual {
    pub fuel: u64,
    pub bits: u64,
    pub global_bits: u64,
    pub privacy: Privacy,
    pub global_privacy: Privacy,
}

impl Actual {
    /// The reservation itself: everything asked for was used.
    pub fn worst(ask: &Ask) -> Actual {
        if ask.cached {
            return Actual {
                fuel: ask.fuel,
                bits: ask.bits,
                global_bits: 0,
                privacy: ask.privacy,
                global_privacy: Privacy::ZERO,
            };
        }
        Actual::used(ask.fuel, ask.bits, ask.privacy)
    }
    pub fn used(fuel: u64, bits: u64, privacy: Privacy) -> Actual {
        Actual {
            fuel,
            bits,
            global_bits: bits,
            privacy,
            global_privacy: privacy,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reservation {
    pub id: u64,
    pub ask: Ask,
    pub ts_ms: i64,
}

pub const DAY_SLOT_MS: i64 = 15 * 60_000;
pub const DAY_SLOTS: i64 = 96;
pub const MIN_SLOT_MS: i64 = 1_000;
pub const MIN_SLOTS: i64 = 60;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Acct {
    bits: u64,
    fuel: u64,
    privacy: Privacy,
}

/// Rolling window made of slots; a slot expires only once *all* of it is older
/// than the window (conservative by at most one slot).
#[derive(Debug, Default)]
struct Window {
    q: VecDeque<(i64, Acct)>,
}

impl Window {
    fn expire(&mut self, slot: i64, slots: i64) {
        while self.q.front().is_some_and(|(s, _)| *s < slot - slots) {
            self.q.pop_front();
        }
    }
    fn sum(&self, slot: i64, slots: i64) -> Acct {
        let mut a = Acct::default();
        for (s, x) in &self.q {
            if *s >= slot - slots {
                a.bits = a.bits.saturating_add(x.bits);
                a.fuel = a.fuel.saturating_add(x.fuel);
                a.privacy = a.privacy.add(x.privacy);
            }
        }
        a
    }
    fn add(&mut self, slot: i64, x: Acct) {
        match self.q.iter_mut().find(|(s, _)| *s == slot) {
            Some((_, a)) => {
                a.bits = a.bits.saturating_add(x.bits);
                a.fuel = a.fuel.saturating_add(x.fuel);
                a.privacy = a.privacy.add(x.privacy);
            }
            None => {
                let at = self
                    .q
                    .iter()
                    .position(|(s, _)| *s > slot)
                    .unwrap_or(self.q.len());
                self.q.insert(at, (slot, x));
            }
        }
    }
    fn sub(&mut self, slot: i64, x: Acct) {
        if let Some((_, a)) = self.q.iter_mut().find(|(s, _)| *s == slot) {
            a.bits = a.bits.saturating_sub(x.bits);
            a.fuel = a.fuel.saturating_sub(x.fuel);
            a.privacy = a.privacy.sub(x.privacy);
        }
    }
}

#[derive(Default, Debug)]
struct State {
    next_id: u64,
    principal_day: HashMap<String, Window>,
    principal_minute: HashMap<String, Window>,
    global_day: HashMap<String, Window>,
    /// The part of `global_day` spent by unverified principals.
    unverified_day: HashMap<String, Window>,
    lifetime: HashMap<String, Privacy>,
    in_flight: HashMap<String, u32>,
    in_flight_total: u32,
    /// Reservations not yet settled: a second settle must not refund again.
    open: std::collections::HashSet<u64>,
    ops: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Wal {
    Reserve {
        r: Reservation,
    },
    Settle {
        r: Reservation,
        a: Actual,
    },
    /// Lifetime totals carried over a compaction.
    Lifetime {
        dataset: String,
        privacy: Privacy,
    },
}

pub struct Ledger {
    cfg: BudgetConfig,
    state: Mutex<State>,
    wal: Option<Mutex<File>>,
    wal_path: Option<PathBuf>,
}

impl std::fmt::Debug for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger")
            .field("wal", &self.wal_path)
            .finish()
    }
}

/// Check one ask against one scope's totals; shared by both ledgers.
pub(crate) fn over_principal(
    cfg: &BudgetConfig,
    bits: u64,
    fuel: u64,
    p: Privacy,
    ask: &Ask,
) -> Option<BudgetError> {
    let scope = || "principal/day".to_string();
    if bits.saturating_add(ask.bits) > cfg.bits_per_principal_per_day {
        return Some(BudgetError::Bits { scope: scope() });
    }
    if fuel.saturating_add(ask.fuel) > cfg.fuel_per_principal_per_day {
        return Some(BudgetError::Fuel { scope: scope() });
    }
    if !ask.privacy.is_zero() {
        if cfg.epsilon_requires_verified && !ask.verified {
            return Some(BudgetError::Epsilon {
                scope: "unverified principals have no privacy budget".into(),
            });
        }
        if p.add(ask.privacy).epsilon(cfg.privacy_delta) > cfg.epsilon_per_principal_per_day + 1e-9
        {
            return Some(BudgetError::Epsilon { scope: scope() });
        }
    }
    None
}

pub(crate) fn over_global(
    cfg: &BudgetConfig,
    d: &str,
    share: f64,
    bits: u64,
    p: Privacy,
    ask: &Ask,
) -> Option<BudgetError> {
    let scope = || {
        if share < 1.0 {
            format!("global/{d}/day (unverified share)")
        } else {
            format!("global/{d}/day")
        }
    };
    if bits.saturating_add(ask.bits) as f64 > cfg.bits_global_per_day as f64 * share {
        return Some(BudgetError::Bits { scope: scope() });
    }
    if !ask.privacy.is_zero() {
        let cap = cfg.epsilon_global_per_day.get(d).copied().unwrap_or(0.0) * share;
        if p.add(ask.privacy).epsilon(cfg.privacy_delta) > cap + 1e-9 {
            return Some(BudgetError::Epsilon { scope: scope() });
        }
    }
    None
}

impl Ledger {
    /// Open a ledger, replaying (and compacting) the WAL. `now_ms` bounds what
    /// is still inside a window; pass the current time.
    pub fn open(cfg: BudgetConfig, wal: Option<&Path>) -> std::io::Result<Self> {
        let mut st = State::default();
        let mut pending: HashMap<(u64, i64, String), Reservation> = HashMap::new();
        let mut settled: Vec<(Reservation, Actual)> = Vec::new();
        let mut max_ts = 0i64;
        if let Some(p) = wal {
            if let Ok(f) = File::open(p) {
                for line in BufReader::new(f).lines().map_while(Result::ok) {
                    match serde_json::from_str(&line) {
                        Ok(Wal::Reserve { r }) => {
                            max_ts = max_ts.max(r.ts_ms);
                            st.next_id = st.next_id.max(r.id);
                            pending.insert((r.id, r.ts_ms, r.ask.principal.clone()), r);
                        }
                        Ok(Wal::Settle { r, a }) => {
                            pending.remove(&(r.id, r.ts_ms, r.ask.principal.clone()));
                            max_ts = max_ts.max(r.ts_ms);
                            settled.push((r, a));
                        }
                        Ok(Wal::Lifetime { dataset, privacy }) => {
                            let e = st.lifetime.entry(dataset).or_default();
                            *e = e.add(privacy);
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        // Unsettled reservations stay charged in full (conservative on crash).
        for r in pending.into_values() {
            let a = Actual::worst(&r.ask);
            settled.push((r, a));
        }
        for (r, a) in &settled {
            charge(&mut st, r, a);
        }
        let file = match wal {
            Some(p) => {
                if let Some(d) = p.parent() {
                    std::fs::create_dir_all(d)?;
                }
                // Compact: keep only what is still inside a window.
                let tmp = p.with_extension("wal.tmp");
                {
                    let mut f = File::create(&tmp)?;
                    let keep_from = max_ts - (DAY_SLOTS + 1) * DAY_SLOT_MS;
                    let mut dropped: HashMap<String, Privacy> = st.lifetime.clone();
                    for (r, a) in &settled {
                        if r.ts_ms >= keep_from {
                            writeln!(
                                f,
                                "{}",
                                serde_json::to_string(&Wal::Settle {
                                    r: r.clone(),
                                    a: *a
                                })?
                            )?;
                            for d in &r.ask.datasets {
                                let e = dropped.entry(d.clone()).or_default();
                                *e = e.sub(a.global_privacy);
                            }
                        }
                    }
                    for (dataset, privacy) in dropped {
                        if !privacy.is_zero() {
                            writeln!(
                                f,
                                "{}",
                                serde_json::to_string(&Wal::Lifetime { dataset, privacy })?
                            )?;
                        }
                    }
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, p)?;
                Some(Mutex::new(
                    OpenOptions::new().create(true).append(true).open(p)?,
                ))
            }
            None => None,
        };
        Ok(Ledger {
            cfg,
            state: Mutex::new(st),
            wal: file,
            wal_path: wal.map(Path::to_path_buf),
        })
    }

    pub fn config(&self) -> &BudgetConfig {
        &self.cfg
    }

    fn log(&self, rec: &Wal) -> std::io::Result<()> {
        let Some(w) = &self.wal else { return Ok(()) };
        let mut line = serde_json::to_string(rec)?;
        line.push('\n');
        let mut f = w.lock();
        f.write_all(line.as_bytes())?;
        if self.cfg.wal_sync {
            f.sync_data()?;
        }
        Ok(())
    }

    /// Atomically reserve worst-case usage for a remit.
    pub fn reserve(&self, ask: &Ask, now_ms: i64) -> Result<Reservation, BudgetError> {
        let (day, minute) = (
            now_ms.div_euclid(DAY_SLOT_MS),
            now_ms.div_euclid(MIN_SLOT_MS),
        );
        let mut st = self.state.lock();
        let p = ask.principal.as_str();
        if *st.in_flight.get(p).unwrap_or(&0) >= self.cfg.concurrency_per_principal {
            return Err(BudgetError::Concurrency {
                scope: "principal".into(),
            });
        }
        if st.in_flight_total >= self.cfg.concurrency_global {
            return Err(BudgetError::Concurrency {
                scope: "global".into(),
            });
        }
        let pd = st
            .principal_day
            .get(p)
            .map(|w| w.sum(day, DAY_SLOTS))
            .unwrap_or_default();
        if let Some(e) = over_principal(&self.cfg, pd.bits, pd.fuel, pd.privacy, ask) {
            return Err(e);
        }
        let pm = st
            .principal_minute
            .get(p)
            .map(|w| w.sum(minute, MIN_SLOTS))
            .unwrap_or_default();
        if pm.fuel.saturating_add(ask.fuel) > self.cfg.fuel_per_principal_per_minute {
            return Err(BudgetError::Fuel {
                scope: "principal/minute".into(),
            });
        }
        for d in ask.datasets.iter().filter(|_| !ask.cached) {
            let g = st
                .global_day
                .get(d)
                .map(|w| w.sum(day, DAY_SLOTS))
                .unwrap_or_default();
            if let Some(e) = over_global(&self.cfg, d, 1.0, g.bits, g.privacy, ask) {
                return Err(e);
            }
            if !ask.verified && self.cfg.unverified_global_share < 1.0 {
                let u = st
                    .unverified_day
                    .get(d)
                    .map(|w| w.sum(day, DAY_SLOTS))
                    .unwrap_or_default();
                if let Some(e) = over_global(
                    &self.cfg,
                    d,
                    self.cfg.unverified_global_share,
                    u.bits,
                    u.privacy,
                    ask,
                ) {
                    return Err(e);
                }
            }
            if let (Some(cap), false) = (
                self.cfg.epsilon_global_lifetime.get(d),
                ask.privacy.is_zero(),
            ) {
                let l = st.lifetime.get(d).copied().unwrap_or_default();
                if l.add(ask.privacy).epsilon(self.cfg.privacy_delta) > cap + 1e-9 {
                    return Err(BudgetError::Epsilon {
                        scope: format!("global/{d}/lifetime"),
                    });
                }
            }
        }
        st.next_id += 1;
        let r = Reservation {
            id: st.next_id,
            ask: ask.clone(),
            ts_ms: now_ms,
        };
        // Durable before anything runs: fail closed if the WAL cannot be written.
        if self.log(&Wal::Reserve { r: r.clone() }).is_err() {
            return Err(BudgetError::Unavailable);
        }
        charge(&mut st, &r, &Actual::worst(ask));
        *st.in_flight.entry(p.to_string()).or_default() += 1;
        st.in_flight_total += 1;
        st.open.insert(r.id);
        st.ops += 1;
        if st.ops.is_multiple_of(4096) {
            sweep(&mut st, day, minute);
        }
        Ok(r)
    }

    /// Settle: refund the difference between reserved and actual usage.
    pub fn settle(&self, r: &Reservation, a: Actual) {
        let a = Actual {
            fuel: a.fuel.min(r.ask.fuel),
            bits: a.bits.min(r.ask.bits),
            global_bits: a.global_bits.min(r.ask.bits),
            privacy: a.privacy.min(r.ask.privacy),
            global_privacy: a.global_privacy.min(r.ask.privacy),
        };
        let mut st = self.state.lock();
        if !st.open.remove(&r.id) {
            return;
        }
        refund(&mut st, r, &a);
        let gone = match st.in_flight.get_mut(&r.ask.principal) {
            Some(n) => {
                *n = n.saturating_sub(1);
                *n == 0
            }
            None => false,
        };
        if gone {
            st.in_flight.remove(&r.ask.principal);
        }
        st.in_flight_total = st.in_flight_total.saturating_sub(1);
        // A lost settle record only over-charges after a restart.
        let _ = self.log(&Wal::Settle { r: r.clone(), a });
    }

    /// Release a reservation that never ran (full refund).
    pub fn release(&self, r: &Reservation) {
        self.settle(r, Actual::default())
    }

    /// Remaining bits for a principal in the rolling day.
    pub fn remaining_bits(&self, principal: &str, now_ms: i64) -> u64 {
        let st = self.state.lock();
        let used = st
            .principal_day
            .get(principal)
            .map(|w| w.sum(now_ms.div_euclid(DAY_SLOT_MS), DAY_SLOTS).bits)
            .unwrap_or(0);
        self.cfg.bits_per_principal_per_day.saturating_sub(used)
    }

    /// Spent ε for a dataset in the rolling day.
    pub fn spent_epsilon(&self, dataset: &str, now_ms: i64) -> f64 {
        let st = self.state.lock();
        st.global_day
            .get(dataset)
            .map(|w| {
                w.sum(now_ms.div_euclid(DAY_SLOT_MS), DAY_SLOTS)
                    .privacy
                    .epsilon(self.cfg.privacy_delta)
            })
            .unwrap_or(0.0)
    }

    pub fn in_flight(&self) -> u32 {
        self.state.lock().in_flight_total
    }
}

fn charge(st: &mut State, r: &Reservation, a: &Actual) {
    let (day, minute) = (
        r.ts_ms.div_euclid(DAY_SLOT_MS),
        r.ts_ms.div_euclid(MIN_SLOT_MS),
    );
    let p = Acct {
        bits: a.bits,
        fuel: a.fuel,
        privacy: a.privacy,
    };
    let g = Acct {
        bits: a.global_bits,
        fuel: a.fuel,
        privacy: a.global_privacy,
    };
    st.principal_day
        .entry(r.ask.principal.clone())
        .or_default()
        .add(day, p);
    st.principal_minute
        .entry(r.ask.principal.clone())
        .or_default()
        .add(minute, p);
    for d in &r.ask.datasets {
        st.global_day.entry(d.clone()).or_default().add(day, g);
        if !r.ask.verified {
            st.unverified_day.entry(d.clone()).or_default().add(day, g);
        }
        if !a.global_privacy.is_zero() {
            let e = st.lifetime.entry(d.clone()).or_default();
            *e = e.add(a.global_privacy);
        }
    }
}

fn refund(st: &mut State, r: &Reservation, a: &Actual) {
    let (day, minute) = (
        r.ts_ms.div_euclid(DAY_SLOT_MS),
        r.ts_ms.div_euclid(MIN_SLOT_MS),
    );
    let fuel = r.ask.fuel - a.fuel;
    let p = Acct {
        bits: r.ask.bits - a.bits,
        fuel,
        privacy: r.ask.privacy.sub(a.privacy),
    };
    let held = Actual::worst(&r.ask);
    let g = Acct {
        bits: held.global_bits.saturating_sub(a.global_bits),
        fuel,
        privacy: held.global_privacy.sub(a.global_privacy),
    };
    if let Some(w) = st.principal_day.get_mut(&r.ask.principal) {
        w.sub(day, p);
    }
    if let Some(w) = st.principal_minute.get_mut(&r.ask.principal) {
        w.sub(minute, p);
    }
    for d in &r.ask.datasets {
        if let Some(w) = st.global_day.get_mut(d) {
            w.sub(day, g);
        }
        if !r.ask.verified {
            if let Some(w) = st.unverified_day.get_mut(d) {
                w.sub(day, g);
            }
        }
        if let Some(l) = st.lifetime.get_mut(d) {
            *l = l.sub(g.privacy);
        }
    }
}

fn sweep(st: &mut State, day: i64, minute: i64) {
    let clean = |m: &mut HashMap<String, Window>, slot: i64, slots: i64| {
        m.retain(|_, w| {
            w.expire(slot, slots);
            !w.q.is_empty()
        });
    };
    clean(&mut st.principal_day, day, DAY_SLOTS);
    clean(&mut st.principal_minute, minute, MIN_SLOTS);
    clean(&mut st.global_day, day, DAY_SLOTS);
    clean(&mut st.unverified_day, day, DAY_SLOTS);
}
