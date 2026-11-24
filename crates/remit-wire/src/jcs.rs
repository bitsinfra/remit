//! JSON Canonicalization Scheme (RFC 8785).
//!
//! * Object keys sorted by UTF-16 code units.
//! * Numbers serialized as ECMAScript `Number.prototype.toString` (via ryu-js).
//! * Strings escaped minimally (`"`, `\`, control chars).
//! * No insignificant whitespace.

use serde_json::Value;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum JcsError {
    #[error("non-finite number cannot be canonicalized")]
    NonFinite,
    #[error("integer {0} is outside the I-JSON safe range (±2^53)")]
    Unsafe(String),
}

/// Canonicalize a JSON value to its RFC 8785 string.
pub fn canonicalize(v: &Value) -> Result<String, JcsError> {
    let mut out = String::with_capacity(256);
    write(v, &mut out)?;
    Ok(out)
}

/// Canonicalize to bytes.
pub fn canonical_bytes(v: &Value) -> Result<Vec<u8>, JcsError> {
    canonicalize(v).map(String::into_bytes)
}

const SAFE: f64 = 9_007_199_254_740_992.0;

fn write(v: &Value, out: &mut String) -> Result<(), JcsError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                // Integers in the safe range format identically under ES rules.
                push_int(i as f64, i.to_string(), out)?;
            } else if let Some(u) = n.as_u64() {
                push_int(u as f64, u.to_string(), out)?;
            } else {
                let f = n.as_f64().ok_or(JcsError::NonFinite)?;
                if !f.is_finite() {
                    return Err(JcsError::NonFinite);
                }
                if f == 0.0 {
                    out.push('0');
                } else {
                    let mut buf = ryu_js::Buffer::new();
                    out.push_str(buf.format_finite(f));
                }
            }
        }
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out)?;
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(k, out);
                out.push(':');
                write(&o[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Outside ±2^53 an integer is canonical only if it is exactly the ECMAScript
/// form of its double; any other literal would change value in other languages.
/// (This keeps canonicalization idempotent: large doubles print as integers.)
fn push_int(f: f64, lit: String, out: &mut String) -> Result<(), JcsError> {
    if f.abs() >= SAFE && ryu_js::Buffer::new().format_finite(f) != lit {
        return Err(JcsError::Unsafe(lit));
    }
    out.push_str(&lit);
    Ok(())
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn idempotent_for_large_numbers() {
        // Found by fuzzing: a large double prints as an integer literal.
        for lit in [
            "444444444444444444.444444444",
            "9007199254740992",
            "1e18",
            "123456789012345680000",
            "-9e18",
            "18446744073709551615.0",
        ] {
            let v: Value = serde_json::from_str(lit).unwrap();
            let c = canonicalize(&v).unwrap();
            let back: Value = serde_json::from_str(&c).unwrap();
            assert_eq!(canonicalize(&back).unwrap(), c, "{lit}");
        }
        for lit in [
            "9007199254740993",
            "-9007199254740993",
            "18446744073709551615",
        ] {
            let v: Value = serde_json::from_str(lit).unwrap();
            assert!(
                matches!(canonicalize(&v), Err(JcsError::Unsafe(_))),
                "{lit} is not a double"
            );
        }
    }

    #[test]
    fn rfc8785_examples() {
        // RFC 8785 §3.2.2 number samples.
        let cases = [
            (json!(1e30), "1e+30"),
            (json!(4.5), "4.5"),
            (json!(0.002), "0.002"),
            (json!(1e-27), "1e-27"),
            (json!(-0.0), "0"),
            (json!(333_333_333.333_333_3), "333333333.3333333"),
            (json!(100), "100"),
        ];
        for (v, s) in cases {
            assert_eq!(canonicalize(&v).unwrap(), s);
        }
        let v = json!({"b": [1, "\u{20ac}\n"], "a": {"z": null, "\u{e9}": true, "A": false}});
        assert_eq!(
            canonicalize(&v).unwrap(),
            "{\"a\":{\"A\":false,\"z\":null,\"é\":true},\"b\":[1,\"€\\n\"]}"
        );
        // UTF-16 ordering: U+1F600 (surrogates D83D…) sorts before U+FB01.
        let v = json!({"\u{fb01}": 1, "\u{1f600}": 2});
        assert_eq!(
            canonicalize(&v).unwrap(),
            "{\"\u{1f600}\":2,\"\u{fb01}\":1}"
        );
        assert_eq!(canonicalize(&json!("\u{1f}")).unwrap(), "\"\\u001f\"");
    }
}
