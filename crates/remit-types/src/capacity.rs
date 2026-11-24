//! Capacity: the maximum number of bits a value of a type can carry.
//!
//! Capacity is `log2(|inhabitants|)` (or a sound upper bound on it). It is a
//! worst-case cap valid for *arbitrary* producing code, which is why it can
//! be computed before running anything.

use crate::Rt;

/// The fixed status set returned to Senders (spec/status.md).
pub const STATUS_SET: [&str; 5] = [
    "ok",
    "limit_exceeded",
    "type_violation",
    "denied",
    "internal",
];

/// Bits carried by the status channel: ⌈log2 |STATUS_SET|⌉.
pub fn status_bits() -> u32 {
    (STATUS_SET.len() as f64).log2().ceil() as u32
}

fn log2_count(n: f64) -> f64 {
    if n <= 1.0 {
        0.0
    } else {
        n.log2()
    }
}

impl Rt {
    /// Number of distinct values this type admits, as a log2 (bits).
    pub fn capacity_bits(&self) -> f64 {
        match self {
            Rt::Bool => 1.0,
            Rt::Int { min, max } => log2_count((*max as f64) - (*min as f64) + 1.0),
            Rt::Float {
                min,
                max,
                precision,
            } => match precision {
                Some(p) => log2_count(((max - min) / p + 1e-9).floor() + 1.0),
                None => 64.0,
            },
            Rt::Decimal { scale, min, max } => {
                log2_count(((max - min) * 10f64.powi(*scale as i32)).round() + 1.0)
            }
            Rt::Enum { values } => log2_count(values.len() as f64),
            Rt::String {
                max_len, charset, ..
            } => {
                let l = *max_len as f64;
                l * charset.size().log2() + (l + 1.0).log2()
            }
            Rt::Timestamp {
                min,
                max,
                granularity_ms,
            } => log2_count(
                ((*max as i128 - *min as i128) / (*granularity_ms).max(1) as i128) as f64 + 1.0,
            ),
            Rt::Date {
                min,
                max,
                granularity_days,
            } => log2_count(
                ((*max as i64 - *min as i64) / (*granularity_days).max(1) as i64) as f64 + 1.0,
            ),
            Rt::Bytes { max_len } => {
                let l = *max_len as f64;
                8.0 * l + (l + 1.0).log2()
            }
            Rt::List { max, of } | Rt::Table { max_rows: max, of } => {
                let m = *max as f64;
                (m + 1.0).log2() + m * of.capacity_bits()
            }
            Rt::Struct { fields } => fields.iter().map(|(_, t)| t.capacity_bits()).sum(),
            Rt::Optional(t) => {
                let c = t.capacity_bits();
                // log2(2^c + 1), computed stably.
                c + (1.0 + (-c).exp2()).log2()
            }
        }
    }

    /// Capacity rounded up to whole bits, as charged against budgets.
    pub fn capacity_bits_ceil(&self) -> u64 {
        let c = self.capacity_bits();
        if !c.is_finite() || c > 1e18 {
            u64::MAX
        } else {
            // Guard against float noise (e.g. 2.0000000000000004).
            (c - 1e-9).ceil().max(0.0) as u64
        }
    }

    /// Worst-case encoded JSON size in bytes (used to sanity-check `output_bytes`).
    pub fn max_json_bytes(&self) -> u64 {
        match self {
            Rt::Bool => 5,
            Rt::Int { min, max } => min.to_string().len().max(max.to_string().len()) as u64,
            Rt::Float { .. } | Rt::Decimal { .. } => 24,
            Rt::Enum { values } => values
                .iter()
                .map(|v| v.len() as u64 * 6 + 2)
                .max()
                .unwrap_or(2),
            Rt::String { max_len, .. } => *max_len as u64 * 6 + 2,
            Rt::Timestamp { .. } => 26,
            Rt::Date { .. } => 12,
            Rt::Bytes { max_len } => (*max_len as u64).div_ceil(3) * 4 + 2,
            Rt::List { max, of } | Rt::Table { max_rows: max, of } => (*max as u64)
                .saturating_mul(of.max_json_bytes().saturating_add(1))
                .saturating_add(2),
            Rt::Struct { fields } => fields.iter().fold(2u64, |total, (name, field)| {
                total
                    .saturating_add(name.len() as u64 + 4)
                    .saturating_add(field.max_json_bytes())
            }),
            Rt::Optional(t) => t.max_json_bytes().max(4),
        }
    }
}
