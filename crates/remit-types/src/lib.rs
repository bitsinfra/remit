//! Remit Types (RT): a small, bounded type system for remit results.
//!
//! * [`RtTemplate`] is the wire form; bounds may reference params (`"$from"`).
//! * [`RtTemplate::bind`] resolves params into a concrete [`Rt`].
//! * [`Rt::capacity_bits`] is a sound worst-case cap on the information the
//!   result can carry (spec/rt.md).
//! * [`Rt::validate`] checks an actual output and applies the trusted
//!   transforms (quantize to precision / granularity) before encoding.

mod capacity;
mod duration;
mod parse;
mod schema;
mod validate;

pub use capacity::{status_bits, STATUS_SET};
pub use duration::{format_duration_ms, parse_duration_ms};
pub use parse::{format_date_days, format_timestamp_ms, parse_date_days, parse_timestamp_ms};
pub use validate::Violation;

use std::fmt;

/// A bound that is either a literal or a reference to a param (`"$name"`).
#[derive(Clone, Debug, PartialEq)]
pub enum Bound {
    Lit(serde_json::Value),
    Param(String),
}

/// Wire form of a Remit Type. Mirrors [`Rt`] but bounds may be params.
#[derive(Clone, Debug, PartialEq)]
pub enum RtTemplate {
    Bool,
    Int {
        min: Bound,
        max: Bound,
    },
    Float {
        min: Bound,
        max: Bound,
        precision: Option<Bound>,
    },
    Decimal {
        scale: u32,
        min: Bound,
        max: Bound,
    },
    Enum {
        values: Vec<String>,
    },
    String {
        max_len: Bound,
        charset: Charset,
        pattern: Option<String>,
    },
    Timestamp {
        min: Bound,
        max: Bound,
        granularity: Bound,
    },
    Date {
        min: Bound,
        max: Bound,
        granularity: Option<Bound>,
    },
    Bytes {
        max_len: Bound,
    },
    List {
        max: Bound,
        of: Box<RtTemplate>,
    },
    Struct {
        fields: Vec<(String, RtTemplate)>,
    },
    Optional(Box<RtTemplate>),
    Table {
        max_rows: Bound,
        of: Box<RtTemplate>,
    },
}

/// Concrete, fully bounded Remit Type.
#[derive(Clone, Debug, PartialEq)]
pub enum Rt {
    Bool,
    Int {
        min: i64,
        max: i64,
    },
    /// `precision: None` means unquantized (capacity 64, policy-discouraged).
    Float {
        min: f64,
        max: f64,
        precision: Option<f64>,
    },
    Decimal {
        scale: u32,
        min: f64,
        max: f64,
    },
    Enum {
        values: Vec<String>,
    },
    String {
        max_len: u32,
        charset: Charset,
        pattern: Option<String>,
    },
    /// Epoch milliseconds, UTC.
    Timestamp {
        min: i64,
        max: i64,
        granularity_ms: i64,
    },
    /// Days since 1970-01-01.
    Date {
        min: i32,
        max: i32,
        granularity_days: i32,
    },
    Bytes {
        max_len: u32,
    },
    List {
        max: u32,
        of: Box<Rt>,
    },
    Struct {
        fields: Vec<(String, Rt)>,
    },
    Optional(Box<Rt>),
    /// Returned as Arrow IPC when requested; JSON array of objects otherwise.
    Table {
        max_rows: u32,
        of: Box<Rt>,
    },
}

/// Character classes for bounded strings. Capacity uses `log2(|charset|)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    Digits,
    Hex,
    Alpha,
    Alnum,
    Base64,
    /// Printable ASCII 0x20..=0x7e (95 symbols).
    Ascii,
    /// Any Unicode scalar value (1,112,064 symbols).
    Unicode,
}

impl Charset {
    pub fn size(self) -> f64 {
        match self {
            Charset::Digits => 10.0,
            Charset::Hex => 22.0,
            Charset::Alpha => 52.0,
            Charset::Alnum => 62.0,
            Charset::Base64 => 67.0,
            Charset::Ascii => 95.0,
            Charset::Unicode => 1_112_064.0,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Charset::Digits => "digits",
            Charset::Hex => "hex",
            Charset::Alpha => "alpha",
            Charset::Alnum => "alnum",
            Charset::Base64 => "base64",
            Charset::Ascii => "ascii",
            Charset::Unicode => "unicode",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "digits" => Charset::Digits,
            "hex" => Charset::Hex,
            "alpha" => Charset::Alpha,
            "alnum" => Charset::Alnum,
            "base64" => Charset::Base64,
            "ascii" => Charset::Ascii,
            "unicode" | "utf8" => Charset::Unicode,
            _ => return None,
        })
    }
    pub fn contains(self, c: char) -> bool {
        match self {
            Charset::Digits => c.is_ascii_digit(),
            Charset::Hex => c.is_ascii_hexdigit(),
            Charset::Alpha => c.is_ascii_alphabetic(),
            Charset::Alnum => c.is_ascii_alphanumeric(),
            Charset::Base64 => {
                c.is_ascii_alphanumeric()
                    || c == '+'
                    || c == '/'
                    || c == '='
                    || c == '-'
                    || c == '_'
            }
            Charset::Ascii => (' '..='~').contains(&c),
            Charset::Unicode => true,
        }
    }
}

/// Errors in a type declaration (as opposed to violations by a value).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TypeError {
    #[error("{path}: {msg}")]
    Invalid {
        path: String,
        msg: String,
        code: &'static str,
    },
}

impl TypeError {
    pub(crate) fn new(path: &str, code: &'static str, msg: impl Into<String>) -> Self {
        TypeError::Invalid {
            path: if path.is_empty() {
                "/".into()
            } else {
                path.into()
            },
            msg: msg.into(),
            code,
        }
    }
    pub fn path(&self) -> &str {
        match self {
            TypeError::Invalid { path, .. } => path,
        }
    }
    pub fn code(&self) -> &'static str {
        match self {
            TypeError::Invalid { code, .. } => code,
        }
    }
    pub fn message(&self) -> &str {
        match self {
            TypeError::Invalid { msg, .. } => msg,
        }
    }
}

/// Maximum enum cardinality (2^16).
pub const MAX_ENUM: usize = 65_536;
/// Largest |epoch ms| in a timestamp bound or granularity (±100M days).
pub const MAX_TIME_MS: u64 = 8_640_000_000_000_000;
/// Maximum list / table length accepted in a type.
pub const MAX_LIST: u64 = 1 << 24;
/// Maximum string / bytes length accepted in a type.
pub const MAX_LEN: u64 = 1 << 24;

impl fmt::Display for Rt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rt::Bool => write!(f, "bool"),
            Rt::Int { min, max } => write!(f, "int[{min}..{max}]"),
            Rt::Float {
                min,
                max,
                precision,
            } => match precision {
                Some(p) => write!(f, "float[{min}..{max} step {p}]"),
                None => write!(f, "float[{min}..{max}]"),
            },
            Rt::Decimal { scale, min, max } => write!(f, "decimal({scale})[{min}..{max}]"),
            Rt::Enum { values } => write!(f, "enum({})", values.join("|")),
            Rt::String {
                max_len, charset, ..
            } => write!(f, "string<{}>[≤{max_len}]", charset.name()),
            Rt::Timestamp {
                min,
                max,
                granularity_ms,
            } => write!(
                f,
                "timestamp[{}..{} step {}]",
                format_timestamp_ms(*min),
                format_timestamp_ms(*max),
                format_duration_ms(*granularity_ms)
            ),
            Rt::Date {
                min,
                max,
                granularity_days,
            } => {
                write!(
                    f,
                    "date[{}..{} step {granularity_days}d]",
                    format_date_days(*min),
                    format_date_days(*max)
                )
            }
            Rt::Bytes { max_len } => write!(f, "bytes[≤{max_len}]"),
            Rt::List { max, of } => write!(f, "list<{of}>[≤{max}]"),
            Rt::Struct { fields } => {
                write!(f, "{{")?;
                for (i, (k, t)) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{k}: {t}")?;
                }
                write!(f, "}}")
            }
            Rt::Optional(t) => write!(f, "{t}?"),
            Rt::Table { max_rows, of } => write!(f, "table<{of}>[≤{max_rows}]"),
        }
    }
}

#[cfg(test)]
mod tests;
