/// Parse a duration like `"15m"`, `"250ms"`, `"1h30m"`, `"2d"`, `"1w"` into ms.
pub fn parse_duration_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut total: i64 = 0;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if start == i {
            return None;
        }
        let num: f64 = s[start..i].parse().ok()?;
        let ustart = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let mult: f64 = match &s[ustart..i] {
            "ms" => 1.0,
            "s" => 1_000.0,
            "m" | "min" => 60_000.0,
            "h" => 3_600_000.0,
            "d" => 86_400_000.0,
            "w" => 604_800_000.0,
            _ => return None,
        };
        let v = num * mult;
        if !v.is_finite() || v < 0.0 || v > 1e15 {
            return None;
        }
        total = total.checked_add(v.round() as i64)?;
    }
    Some(total)
}

/// Format ms as the shortest exact unit string (`900000` → `"15m"`).
pub fn format_duration_ms(ms: i64) -> String {
    const UNITS: [(i64, &str); 6] = [
        (604_800_000, "w"),
        (86_400_000, "d"),
        (3_600_000, "h"),
        (60_000, "m"),
        (1_000, "s"),
        (1, "ms"),
    ];
    if ms == 0 {
        return "0ms".into();
    }
    for (u, name) in UNITS {
        if ms % u == 0 {
            return format!("{}{}", ms / u, name);
        }
    }
    format!("{ms}ms")
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn durations() {
        assert_eq!(parse_duration_ms("15m"), Some(900_000));
        assert_eq!(parse_duration_ms("250ms"), Some(250));
        assert_eq!(parse_duration_ms("1h30m"), Some(5_400_000));
        assert_eq!(parse_duration_ms("1d"), Some(86_400_000));
        assert_eq!(parse_duration_ms("x"), None);
        assert_eq!(parse_duration_ms("10"), None);
        assert_eq!(format_duration_ms(900_000), "15m");
        assert_eq!(format_duration_ms(86_400_000), "1d");
        assert_eq!(format_duration_ms(1500), "1500ms");
    }
}
