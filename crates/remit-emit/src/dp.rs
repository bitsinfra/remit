//! Differential privacy noise (trusted code only), calibrated through
//! OpenDP's Rust core.
//!
//! The read plane's DP rewrite (`remit_read::dp`) bounds sensitivity in the
//! plan (contribution bounding, clamping) and hands over *exact* aggregates;
//! this module noises them, thresholds group keys, and reports the privacy
//! loss. The budget of a remit is split evenly over its noised quantities.

use opendp::domains::AtomDomain;
use opendp::measurements::{make_gaussian, make_laplace};
use opendp::measures::{MaxDivergence, ZeroConcentratedDivergence};
use opendp::metrics::AbsoluteDistance;
use remit_read::dp::{DpOut, DpShape, UNITS};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mechanism {
    /// Discrete/continuous Laplace: pure ε-DP.
    Laplace,
    /// Gaussian: ρ-zCDP, with ρ chosen so that (ε, δ) holds.
    Gaussian,
}

impl Mechanism {
    pub fn parse(s: &str) -> Option<Mechanism> {
        match s {
            "laplace" => Some(Mechanism::Laplace),
            "gaussian" => Some(Mechanism::Gaussian),
            _ => None,
        }
    }
}

/// Privacy parameters of one release.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DpParams {
    pub epsilon: f64,
    pub delta: f64,
    pub mechanism: Mechanism,
}

/// Privacy loss of a release: pure ε, or zCDP ρ.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Loss {
    pub epsilon: f64,
    pub rho: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum DpError {
    #[error("opendp: {0}")]
    OpenDp(String),
    #[error("invalid privacy parameters")]
    Params,
}

fn od(e: opendp::error::Error) -> DpError {
    DpError::OpenDp(e.to_string())
}

pub fn noise_i64(v: i64, sensitivity: f64, epsilon: f64) -> Result<i64, DpError> {
    let m = make_laplace::<_, _, MaxDivergence>(
        AtomDomain::<i64>::default(),
        AbsoluteDistance::<i64>::default(),
        sensitivity / epsilon,
        None,
    )
    .map_err(od)?;
    m.invoke(&v).map_err(od)
}

pub fn noise_f64(v: f64, sensitivity: f64, epsilon: f64) -> Result<f64, DpError> {
    let m = make_laplace::<_, _, MaxDivergence>(
        AtomDomain::<f64>::new_non_nan(),
        AbsoluteDistance::<f64>::default(),
        sensitivity / epsilon,
        None,
    )
    .map_err(od)?;
    m.invoke(&v).map_err(od)
}

fn gauss_i64(v: i64, sigma: f64) -> Result<i64, DpError> {
    let m = make_gaussian::<_, _, ZeroConcentratedDivergence>(
        AtomDomain::<i64>::default(),
        AbsoluteDistance::<i64>::default(),
        sigma,
        None,
    )
    .map_err(od)?;
    m.invoke(&v).map_err(od)
}

fn gauss_f64(v: f64, sigma: f64) -> Result<f64, DpError> {
    let m = make_gaussian::<_, _, ZeroConcentratedDivergence>(
        AtomDomain::<f64>::new_non_nan(),
        AbsoluteDistance::<f64>::default(),
        sigma,
        None,
    )
    .map_err(od)?;
    m.invoke(&v).map_err(od)
}

/// Largest ρ with ρ + 2·√(ρ·ln(1/δ)) ≤ ε.
pub fn rho_for(epsilon: f64, delta: f64) -> f64 {
    let l = (1.0 / delta).ln();
    let r = (l + epsilon).sqrt() - l.sqrt();
    r * r
}

/// One noised quantity's share of the budget.
struct Share {
    mech: Mechanism,
    /// ε share (Laplace) or ρ share (Gaussian).
    v: f64,
}

impl Share {
    fn int(&self, x: i64, sens: f64) -> Result<i64, DpError> {
        match self.mech {
            Mechanism::Laplace => noise_i64(x, sens, self.v),
            Mechanism::Gaussian => gauss_i64(x, sens / (2.0 * self.v).sqrt()),
        }
    }
    fn real(&self, x: f64, sens: f64) -> Result<f64, DpError> {
        if sens == 0.0 {
            return Ok(x);
        }
        match self.mech {
            Mechanism::Laplace => noise_f64(x, sens, self.v),
            Mechanism::Gaussian => gauss_f64(x, sens / (2.0 * self.v).sqrt()),
        }
    }
    /// Noise level exceeded with probability ≤ p.
    fn tail(&self, sens: f64, p: f64) -> f64 {
        match self.mech {
            Mechanism::Laplace => sens / self.v * (1.0 / (2.0 * p)).ln().max(0.0),
            Mechanism::Gaussian => sens / (2.0 * self.v).sqrt() * (2.0 * (1.0 / p).ln()).sqrt(),
        }
    }
}

/// Noise the exact aggregates of a DP query. Returns the released rows and the
/// privacy loss actually incurred.
pub fn release(shape: &DpShape, raw: &[Value], p: DpParams) -> Result<(Vec<Value>, Loss), DpError> {
    if !(p.epsilon.is_finite() && p.epsilon > 0.0 && p.delta > 0.0 && p.delta < 0.1) {
        return Err(DpError::Params);
    }
    let n: usize = shape
        .columns
        .iter()
        .map(|(_, c)| match c {
            DpOut::Key => 0,
            DpOut::Avg { .. } => 2,
            _ => 1,
        })
        .sum::<usize>()
        + shape.grouped as usize;
    if n == 0 {
        return Err(DpError::Params);
    }
    let (share, loss) = match p.mechanism {
        Mechanism::Laplace => (
            Share {
                mech: p.mechanism,
                v: p.epsilon / n as f64,
            },
            Loss {
                epsilon: p.epsilon,
                rho: 0.0,
            },
        ),
        Mechanism::Gaussian => {
            let rho = rho_for(p.epsilon, p.delta);
            (
                Share {
                    mech: p.mechanism,
                    v: rho / n as f64,
                },
                Loss { epsilon: 0.0, rho },
            )
        }
    };
    let m = shape.m as f64;
    // Stability-based key release: a group owned by a single unit passes with
    // probability ≤ δ/m, and a unit touches at most m groups.
    let tau = (1.0 + share.tail(m, p.delta / m)).max(shape.min_units as f64);
    let mut out = Vec::new();
    for r in raw {
        let i64_of = |k: &str| r.get(k).and_then(Value::as_i64).unwrap_or(0);
        let f64_of = |k: &str| r.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        if shape.grouped && (share.int(i64_of(UNITS), m)? as f64) < tau {
            continue;
        }
        let mut o = Map::new();
        for (i, (name, kind)) in shape.columns.iter().enumerate() {
            let a = format!("a{i}");
            let v = match kind {
                DpOut::Key => r.get(format!("k{i}")).cloned().unwrap_or(Value::Null),
                DpOut::Count => Value::from(share.int(i64_of(&a), m)?.max(0)),
                DpOut::CountUnits => Value::from(
                    share
                        .int(i64_of(&a), if shape.grouped { m } else { 1.0 })?
                        .max(0),
                ),
                DpOut::Sum { lo, hi, int } => {
                    let x = share.real(f64_of(&a), m * lo.abs().max(hi.abs()))?;
                    number(if *int { x.round() } else { x }, *int)
                }
                DpOut::Avg { lo, hi } => {
                    let s = share.real(f64_of(&a), m * (hi - lo) / 2.0)?;
                    let c = share.int(i64_of(&format!("b{i}")), m)?.max(1) as f64;
                    number(((lo + hi) / 2.0 + s / c).clamp(*lo, *hi), false)
                }
            };
            o.insert(name.clone(), v);
        }
        out.push(Value::Object(o));
    }
    // Ordering and limits apply to the noisy answer; the default order is by
    // key so the physical row order reveals nothing.
    let keys: Vec<&String> = shape
        .columns
        .iter()
        .filter(|(_, c)| *c == DpOut::Key)
        .map(|(n, _)| n)
        .collect();
    out.sort_by(|a, b| {
        for (c, asc, nulls_first) in &shape.order_by {
            let o = cmp(&a[c.as_str()], &b[c.as_str()], *asc, *nulls_first);
            if o.is_ne() {
                return o;
            }
        }
        for k in &keys {
            let o = cmp(&a[k.as_str()], &b[k.as_str()], true, false);
            if o.is_ne() {
                return o;
            }
        }
        std::cmp::Ordering::Equal
    });
    if let Some(l) = shape.limit {
        out.truncate(l as usize);
    }
    Ok((out, loss))
}

fn number(x: f64, int: bool) -> Value {
    if int && x.abs() < 9e15 {
        return Value::from(x as i64);
    }
    serde_json::Number::from_f64(x)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn cmp(a: &Value, b: &Value, asc: bool, nulls_first: bool) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let o = match (a.is_null(), b.is_null()) {
        (true, true) => return Equal,
        (true, false) => return if nulls_first { Less } else { Greater },
        (false, true) => return if nulls_first { Greater } else { Less },
        _ => match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                x.as_f64().partial_cmp(&y.as_f64()).unwrap_or(Equal)
            }
            (Value::String(x), Value::String(y)) => x.cmp(y),
            (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
            _ => a.to_string().cmp(&b.to_string()),
        },
    };
    if asc {
        o
    } else {
        o.reverse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn shape(grouped: bool, cols: Vec<(&str, DpOut)>) -> DpShape {
        DpShape {
            columns: cols.into_iter().map(|(n, c)| (n.to_string(), c)).collect(),
            m: 1,
            row_level: true,
            grouped,
            min_units: 0,
            order_by: vec![],
            limit: None,
            tables: vec!["t".into()],
        }
    }

    #[test]
    fn unbiased_for_both_mechanisms() {
        for mechanism in [Mechanism::Laplace, Mechanism::Gaussian] {
            let s = shape(
                false,
                vec![
                    ("n", DpOut::Count),
                    ("avg", DpOut::Avg { lo: 0.0, hi: 10.0 }),
                    (
                        "sum",
                        DpOut::Sum {
                            lo: 0.0,
                            hi: 10.0,
                            int: true,
                        },
                    ),
                ],
            );
            let raw = [json!({"a0": 1000, "a1": -1000.0, "b1": 1000, "a2": 4000.0, UNITS: 1000})];
            let (mut n, mut avg, mut sum) = (0.0, 0.0, 0.0);
            let trials = 300;
            for _ in 0..trials {
                let (rows, loss) = release(
                    &s,
                    &raw,
                    DpParams {
                        epsilon: 4.0,
                        delta: 1e-6,
                        mechanism,
                    },
                )
                .unwrap();
                assert_eq!(loss.epsilon > 0.0, mechanism == Mechanism::Laplace);
                n += rows[0]["n"].as_f64().unwrap();
                avg += rows[0]["avg"].as_f64().unwrap();
                sum += rows[0]["sum"].as_i64().unwrap() as f64;
            }
            let t = trials as f64;
            assert!((n / t - 1000.0).abs() < 3.0, "{}", n / t);
            assert!((avg / t - 4.0).abs() < 0.1, "{}", avg / t);
            assert!((sum / t - 4000.0).abs() < 25.0, "{}", sum / t);
        }
    }

    #[test]
    fn small_groups_are_suppressed_and_order_is_post_noise() {
        let mut s = shape(true, vec![("region", DpOut::Key), ("n", DpOut::Count)]);
        s.order_by = vec![("n".into(), false, false)];
        s.limit = Some(2);
        let raw = [
            json!({"k0": "A", "a1": 500, UNITS: 500}),
            json!({"k0": "B", "a1": 1, UNITS: 1}),
            json!({"k0": "C", "a1": 5000, UNITS: 5000}),
            json!({"k0": "D", "a1": 900, UNITS: 900}),
        ];
        for _ in 0..50 {
            let (rows, _) = release(
                &s,
                &raw,
                DpParams {
                    epsilon: 2.0,
                    delta: 1e-9,
                    mechanism: Mechanism::Laplace,
                },
            )
            .unwrap();
            assert_eq!(
                rows.iter()
                    .map(|r| r["region"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                vec!["C", "D"]
            );
        }
        // The k floor applies to the noisy unit count.
        s.min_units = 700;
        let (rows, _) = release(
            &s,
            &raw,
            DpParams {
                epsilon: 10.0,
                delta: 1e-9,
                mechanism: Mechanism::Laplace,
            },
        )
        .unwrap();
        assert!(rows.iter().all(|r| r["region"] != "A"));
    }

    /// Empirical ε audit: on neighbouring inputs the likelihood ratio of every
    /// well-populated output bucket stays below e^ε (with sampling slack).
    #[test]
    fn empirical_privacy_audit() {
        let s = shape(false, vec![("n", DpOut::Count)]);
        let p = DpParams {
            epsilon: 1.0,
            delta: 1e-6,
            mechanism: Mechanism::Laplace,
        };
        let hist = |n: i64| {
            let mut h = std::collections::HashMap::new();
            for _ in 0..20_000 {
                let (r, _) = release(&s, &[json!({"a0": n, UNITS: n})], p).unwrap();
                *h.entry(r[0]["n"].as_i64().unwrap()).or_insert(0u32) += 1;
            }
            h
        };
        let (a, b) = (hist(100), hist(101));
        for (k, x) in &a {
            let y = *b.get(k).unwrap_or(&0);
            if *x > 400 && y > 400 {
                let ratio = (*x as f64 / y as f64).ln().abs();
                assert!(ratio < 1.0 + 0.2, "bucket {k}: ln ratio {ratio}");
            }
        }
    }

    #[test]
    fn rho_conversion() {
        for eps in [0.1, 0.5, 1.0, 3.0] {
            let r = rho_for(eps, 1e-6);
            let back = r + 2.0 * (r * 1e6f64.ln()).sqrt();
            assert!((back - eps).abs() < 1e-9, "{back}");
        }
        let s = shape(false, vec![("n", DpOut::Count)]);
        for e in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(release(
                &s,
                &[],
                DpParams {
                    epsilon: e,
                    delta: 1e-6,
                    mechanism: Mechanism::Laplace
                }
            )
            .is_err());
        }
    }
}
