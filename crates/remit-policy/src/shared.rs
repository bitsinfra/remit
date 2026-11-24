//! Clustered budget ledger: the same accounting as [`crate::budget::Ledger`],
//! stored in Postgres so every Holder replica reserves against one global
//! state (global per-dataset budgets stay sound when a Holder scales out).
//!
//! Each reservation is one transaction that row-locks every scope it touches
//! in a fixed order, so concurrent replicas cannot deadlock. In-flight
//! reservations are leases: a crashed replica's slots expire, and its
//! unsettled charges stay (conservative).

use serde::Serialize;
use tokio_postgres::{Client, NoTls};

use crate::budget::{
    over_global, over_principal, Actual, Ask, BudgetConfig, BudgetError, Privacy, Reservation,
    DAY_SLOTS, DAY_SLOT_MS, MIN_SLOTS, MIN_SLOT_MS,
};

pub struct SharedLedger {
    cfg: BudgetConfig,
    client: tokio::sync::Mutex<Client>,
}

#[derive(Debug, thiserror::Error, Serialize)]
pub enum SharedError {
    #[error("{0}")]
    Budget(BudgetError),
    #[error("ledger database: {0}")]
    Db(String),
}

impl From<tokio_postgres::Error> for SharedError {
    fn from(e: tokio_postgres::Error) -> Self {
        SharedError::Db(e.to_string())
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS remit_scope (scope TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS remit_usage (
  scope TEXT NOT NULL, slot BIGINT NOT NULL,
  bits BIGINT NOT NULL DEFAULT 0, fuel BIGINT NOT NULL DEFAULT 0,
  eps DOUBLE PRECISION NOT NULL DEFAULT 0, rho_pure DOUBLE PRECISION NOT NULL DEFAULT 0, rho_gauss DOUBLE PRECISION NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, slot));
CREATE TABLE IF NOT EXISTS remit_lease (id BIGSERIAL PRIMARY KEY, principal TEXT NOT NULL, expires_ms BIGINT NOT NULL);
";

/// In-flight lease: longer than any admissible `wall_ms` plus padding.
const LEASE_MS: i64 = 120_000;

fn i(x: u64) -> i64 {
    x.min(i64::MAX as u64) as i64
}

#[derive(Clone)]
struct Scope {
    key: String,
    slot: i64,
    slots: i64,
    kind: Kind,
}

#[derive(Clone)]
enum Kind {
    PrincipalDay,
    PrincipalMinute,
    Global(String),
    Unverified(String),
    Lifetime(String),
}

impl SharedLedger {
    pub async fn connect(dsn: &str, cfg: BudgetConfig) -> Result<Self, SharedError> {
        let (client, conn) = tokio_postgres::connect(dsn, NoTls).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        // Serialize concurrent schema creation across replicas.
        client
            .batch_execute(&format!(
                "BEGIN; SELECT pg_advisory_xact_lock(7237418); {SCHEMA} COMMIT;"
            ))
            .await?;
        Ok(SharedLedger {
            cfg,
            client: tokio::sync::Mutex::new(client),
        })
    }

    pub fn config(&self) -> &BudgetConfig {
        &self.cfg
    }

    fn scopes(&self, ask: &Ask, ts: i64) -> Vec<Scope> {
        let (day, minute) = (ts.div_euclid(DAY_SLOT_MS), ts.div_euclid(MIN_SLOT_MS));
        let mut v = vec![
            Scope {
                key: format!("p:{}", ask.principal),
                slot: day,
                slots: DAY_SLOTS,
                kind: Kind::PrincipalDay,
            },
            Scope {
                key: format!("pm:{}", ask.principal),
                slot: minute,
                slots: MIN_SLOTS,
                kind: Kind::PrincipalMinute,
            },
        ];
        for d in ask.datasets.iter().filter(|_| !ask.cached) {
            v.push(Scope {
                key: format!("g:{d}"),
                slot: day,
                slots: DAY_SLOTS,
                kind: Kind::Global(d.clone()),
            });
            if !ask.verified {
                v.push(Scope {
                    key: format!("u:{d}"),
                    slot: day,
                    slots: DAY_SLOTS,
                    kind: Kind::Unverified(d.clone()),
                });
            }
            if self.cfg.epsilon_global_lifetime.contains_key(d) {
                v.push(Scope {
                    key: format!("l:{d}"),
                    slot: 0,
                    slots: 0,
                    kind: Kind::Lifetime(d.clone()),
                });
            }
        }
        v.sort_by(|a, b| a.key.cmp(&b.key));
        v
    }

    pub async fn reserve(&self, ask: &Ask, now_ms: i64) -> Result<Reservation, SharedError> {
        let scopes = self.scopes(ask, now_ms);
        let mut c = self.client.lock().await;
        let tx = c.transaction().await?;
        // Lock every scope row in key order ("!" sorts first and guards leases).
        for k in
            std::iter::once("!inflight".to_string()).chain(scopes.iter().map(|s| s.key.clone()))
        {
            tx.execute(
                "INSERT INTO remit_scope (scope) VALUES ($1) ON CONFLICT DO NOTHING",
                &[&k],
            )
            .await?;
            tx.query_one(
                "SELECT scope FROM remit_scope WHERE scope = $1 FOR UPDATE",
                &[&k],
            )
            .await?;
        }
        tx.execute("DELETE FROM remit_lease WHERE expires_ms < $1", &[&now_ms])
            .await?;
        let pi: i64 = tx
            .query_one(
                "SELECT count(*) FROM remit_lease WHERE principal = $1",
                &[&ask.principal],
            )
            .await?
            .get(0);
        let gi: i64 = tx
            .query_one("SELECT count(*) FROM remit_lease", &[])
            .await?
            .get(0);
        if pi >= self.cfg.concurrency_per_principal as i64 {
            return Err(SharedError::Budget(BudgetError::Concurrency {
                scope: "principal".into(),
            }));
        }
        if gi >= self.cfg.concurrency_global as i64 {
            return Err(SharedError::Budget(BudgetError::Concurrency {
                scope: "global".into(),
            }));
        }
        for s in &scopes {
            let r = tx
                .query_one(
                    "SELECT COALESCE(sum(bits),0)::bigint, COALESCE(sum(fuel),0)::bigint, COALESCE(sum(eps),0), COALESCE(sum(rho_pure),0), COALESCE(sum(rho_gauss),0)
                     FROM remit_usage WHERE scope = $1 AND slot >= $2",
                    &[&s.key, &(s.slot - s.slots)],
                )
                .await?;
            let (b, f) = (r.get::<_, i64>(0) as u64, r.get::<_, i64>(1) as u64);
            let p = Privacy {
                eps: r.get(2),
                rho_pure: r.get(3),
                rho_gauss: r.get(4),
            };
            let over = match &s.kind {
                Kind::PrincipalDay => over_principal(&self.cfg, b, f, p, ask),
                Kind::PrincipalMinute => (f.saturating_add(ask.fuel)
                    > self.cfg.fuel_per_principal_per_minute)
                    .then(|| BudgetError::Fuel {
                        scope: "principal/minute".into(),
                    }),
                Kind::Global(d) => over_global(&self.cfg, d, 1.0, b, p, ask),
                Kind::Unverified(d) if self.cfg.unverified_global_share < 1.0 => {
                    over_global(&self.cfg, d, self.cfg.unverified_global_share, b, p, ask)
                }
                Kind::Unverified(_) => None,
                Kind::Lifetime(d) => {
                    let cap = self
                        .cfg
                        .epsilon_global_lifetime
                        .get(d)
                        .copied()
                        .unwrap_or(0.0);
                    (!ask.privacy.is_zero()
                        && p.add(ask.privacy).epsilon(self.cfg.privacy_delta) > cap + 1e-9)
                        .then(|| BudgetError::Epsilon {
                            scope: format!("global/{d}/lifetime"),
                        })
                }
            };
            if let Some(e) = over {
                return Err(SharedError::Budget(e));
            }
        }
        for s in &scopes {
            let p = ask.privacy;
            tx.execute(
                "INSERT INTO remit_usage (scope, slot, bits, fuel, eps, rho_pure, rho_gauss) VALUES ($1,$2,$3,$4,$5,$6,$7)
                 ON CONFLICT (scope, slot) DO UPDATE SET bits = remit_usage.bits + $3, fuel = remit_usage.fuel + $4, eps = remit_usage.eps + $5,
                   rho_pure = remit_usage.rho_pure + $6, rho_gauss = remit_usage.rho_gauss + $7",
                &[&s.key, &s.slot, &i(ask.bits), &i(ask.fuel), &p.eps, &p.rho_pure, &p.rho_gauss],
            )
            .await?;
        }
        let id: i64 = tx
            .query_one(
                "INSERT INTO remit_lease (principal, expires_ms) VALUES ($1,$2) RETURNING id",
                &[&ask.principal, &(now_ms + LEASE_MS)],
            )
            .await?
            .get(0);
        tx.commit().await?;
        Ok(Reservation {
            id: id as u64,
            ask: ask.clone(),
            ts_ms: now_ms,
        })
    }

    pub async fn settle(&self, r: &Reservation, a: Actual) -> Result<(), SharedError> {
        let scopes = self.scopes(&r.ask, r.ts_ms);
        let mut c = self.client.lock().await;
        let tx = c.transaction().await?;
        // The lease settles once. An expired lease keeps its worst-case charge.
        if tx
            .execute("DELETE FROM remit_lease WHERE id = $1", &[&(r.id as i64)])
            .await?
            == 0
        {
            return Ok(());
        }
        for s in &scopes {
            let global = !matches!(s.kind, Kind::PrincipalDay | Kind::PrincipalMinute);
            let (bits, p) = if global {
                (a.global_bits, a.global_privacy)
            } else {
                (a.bits, a.privacy)
            };
            tx.execute(
                "UPDATE remit_usage SET bits = GREATEST(bits - $3, 0), fuel = GREATEST(fuel - $4, 0), eps = GREATEST(eps - $5, 0),
                   rho_pure = GREATEST(rho_pure - $6, 0), rho_gauss = GREATEST(rho_gauss - $7, 0) WHERE scope = $1 AND slot = $2",
                &[
                    &s.key,
                    &s.slot,
                    &i(r.ask.bits.saturating_sub(bits)),
                    &i(r.ask.fuel.saturating_sub(a.fuel)),
                    &(r.ask.privacy.eps - p.eps).max(0.0),
                    &(r.ask.privacy.rho_pure - p.rho_pure).max(0.0),
                    &(r.ask.privacy.rho_gauss - p.rho_gauss).max(0.0),
                ],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn remaining_bits(&self, principal: &str, now_ms: i64) -> Result<u64, SharedError> {
        let c = self.client.lock().await;
        let slot = now_ms.div_euclid(DAY_SLOT_MS) - DAY_SLOTS;
        let used: i64 = c.query_one("SELECT COALESCE(sum(bits),0)::bigint FROM remit_usage WHERE scope = $1 AND slot >= $2", &[&format!("p:{principal}"), &slot]).await?.get(0);
        Ok(self
            .cfg
            .bits_per_principal_per_day
            .saturating_sub(used as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two "replicas" share one ledger. Runs when REMIT_TEST_PG_DSN is set.
    #[tokio::test]
    async fn replicas_share_global_budgets() {
        let Ok(dsn) = std::env::var("REMIT_TEST_PG_DSN") else {
            eprintln!("skipping: REMIT_TEST_PG_DSN not set");
            return;
        };
        let cfg = BudgetConfig {
            bits_per_principal_per_day: 100,
            bits_global_per_day: 150,
            concurrency_per_principal: 4,
            ..Default::default()
        };
        let a = SharedLedger::connect(&dsn, cfg.clone()).await.unwrap();
        let b = SharedLedger::connect(&dsn, cfg).await.unwrap();
        a.client
            .lock()
            .await
            .batch_execute("DELETE FROM remit_usage; DELETE FROM remit_lease;")
            .await
            .unwrap();
        let now = 1_795_000_000_000;
        let ask = |p: &str| Ask {
            principal: p.into(),
            verified: true,
            datasets: vec!["cal".into()],
            bits: 60,
            fuel: 10,
            ..Default::default()
        };
        let r1 = a.reserve(&ask("alice"), now).await.unwrap();
        // Replica B sees A's reservation: the global cap (150) is shared.
        let r2 = b.reserve(&ask("bob"), now).await.unwrap();
        assert!(matches!(
            b.reserve(&ask("carol"), now).await,
            Err(SharedError::Budget(BudgetError::Bits { .. }))
        ));
        a.settle(&r1, Actual::used(5, 60, Privacy::ZERO))
            .await
            .unwrap();
        b.settle(&r2, Actual::default()).await.unwrap(); // released
        assert_eq!(b.remaining_bits("alice", now).await.unwrap(), 40);
        assert!(a.reserve(&ask("carol"), now).await.is_ok());
        // Concurrent reservations from both replicas never exceed the cap.
        a.client
            .lock()
            .await
            .batch_execute("DELETE FROM remit_usage; DELETE FROM remit_lease;")
            .await
            .unwrap();
        let (a, b) = (std::sync::Arc::new(a), std::sync::Arc::new(b));
        let mut hs = Vec::new();
        for n in 0..12 {
            let (l, q) = (
                if n % 2 == 0 { a.clone() } else { b.clone() },
                ask(&format!("p{n}")),
            );
            hs.push(tokio::spawn(
                async move { l.reserve(&q, now).await.is_ok() },
            ));
        }
        let mut ok = 0;
        for h in hs {
            ok += h.await.unwrap() as u32;
        }
        assert_eq!(ok, 2, "2 × 60 ≤ 150 < 3 × 60");
    }
}
