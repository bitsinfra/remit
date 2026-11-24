use std::collections::BTreeSet;

use proptest::prelude::*;
use serde_json::{json, Map, Value};

use crate::*;

fn params() -> Map<String, Value> {
    json!({"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z", "minutes": 120})
        .as_object()
        .unwrap()
        .clone()
}

fn slots_type() -> Value {
    json!({"list": {"max": 3, "of": {"struct": {
        "start": {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}},
        "end":   {"timestamp": {"min": "$from", "max": "$until", "granularity": "15m"}}
    }}}})
}

#[test]
fn plan_example_capacity() {
    let t = RtTemplate::from_json(&slots_type()).unwrap();
    assert_eq!(t.params(), vec!["from".to_string(), "until".to_string()]);
    let rt = t.bind(&params()).unwrap();
    let c = rt.capacity_bits();
    // 1345 values per timestamp → 10.39 bits; 3 slots × 2 + log2(4).
    assert!((c - 64.35).abs() < 0.1, "capacity {c}");
    assert_eq!(rt.capacity_bits_ceil(), 65);
    assert_eq!(status_bits(), 3);
}

#[test]
fn unbounded_rejected() {
    let e = RtTemplate::from_json(&json!({"string": {}})).unwrap_err();
    assert_eq!(e.code(), "RMT-E0101");
    assert_eq!(e.path(), "/string/max_len");
    let e = RtTemplate::from_json(&json!({"list": {"of": "bool"}})).unwrap_err();
    assert_eq!(e.code(), "RMT-E0101");
    assert_eq!(
        RtTemplate::from_json(&json!("int")).unwrap_err().code(),
        "RMT-E0101"
    );
    assert_eq!(
        RtTemplate::from_json(&json!({"wat": {}}))
            .unwrap_err()
            .code(),
        "RMT-E0102"
    );
}

#[test]
fn unresolved_param() {
    let t = RtTemplate::from_json(&slots_type()).unwrap();
    let e = t.bind(&Map::new()).unwrap_err();
    assert_eq!(e.code(), "RMT-E0104");
}

#[test]
fn validate_and_quantize() {
    let rt = RtTemplate::from_json(&slots_type())
        .unwrap()
        .bind(&params())
        .unwrap();
    let ok = rt
        .validate(&json!([{"start": "2026-11-24T09:07:00Z", "end": "2026-11-24T11:00:00.000Z"}]))
        .unwrap();
    assert_eq!(
        ok,
        json!([{"start": "2026-11-24T09:00:00Z", "end": "2026-11-24T11:00:00Z"}])
    );
    assert!(rt
        .validate(&json!([{"start": "2026-11-24T09:00:00Z"}]))
        .is_err());
    assert!(rt
        .validate(
            &json!([{"start": "2026-11-24T09:00:00Z", "end": "2026-11-24T09:00:00Z", "title": "x"}])
        )
        .is_err());
    assert!(rt
        .validate(&json!([{"start": "2027-01-01T00:00:00Z", "end": "2026-11-24T09:00:00Z"}]))
        .is_err());
    let four = Value::Array(vec![
        json!({"start": "2026-11-24T09:00:00Z", "end": "2026-11-24T09:00:00Z"});
        4
    ]);
    assert!(rt.validate(&four).is_err());

    let f = Rt::from_json(&json!({"float": {"min": 0, "max": 1, "precision": 0.1}})).unwrap();
    assert_eq!(f.validate(&json!(0.33)).unwrap(), json!(0.3));
    assert!((f.capacity_bits() - 11f64.log2()).abs() < 1e-9);
    let s = Rt::from_json(&json!({"string": {"max_len": 4, "charset": "digits"}})).unwrap();
    assert!(s.validate(&json!("12a")).is_err());
    assert!(s.validate(&json!("12345")).is_err());
    assert!(s.validate(&json!("1234")).is_ok());
    let o = Rt::from_json(&json!({"struct": {"a": {"optional": "bool"}}})).unwrap();
    assert_eq!(o.validate(&json!({})).unwrap(), json!({"a": null}));
}

#[test]
fn string_capacity_covers_the_validator_alphabet() {
    for (charset, max_len) in [("hex", 24), ("base64", 512)] {
        let rt =
            Rt::from_json(&json!({"string": {"charset": charset, "max_len": max_len}})).unwrap();
        let alphabet = (0u8..=127)
            .map(|c| json!(char::from(c).to_string().repeat(max_len)))
            .filter(|s| rt.validate(s).as_ref() == Ok(s))
            .count() as f64;
        let required = (max_len as f64 * alphabet.log2()).ceil() as u64;
        assert!(rt.capacity_bits_ceil() >= required, "{charset}");
    }
}

#[test]
fn nested_result_size_saturates_at_the_largest_estimate() {
    let mut rt = Rt::Bool;
    for _ in 0..3 {
        rt = Rt::List {
            max: MAX_LEN as u32,
            of: Box::new(rt),
        };
    }
    assert_eq!(rt.max_json_bytes(), u64::MAX);
    let nested = Rt::Struct {
        fields: vec![("nested".to_owned(), rt)],
    };
    assert_eq!(nested.max_json_bytes(), u64::MAX);
}

#[test]
fn json_schema_roundtrip() {
    let t = RtTemplate::from_json(&slots_type()).unwrap();
    let s = t.to_json_schema();
    let back = RtTemplate::from_json_schema(&s).unwrap();
    assert_eq!(back, t);
    // zod-style output
    let zod = json!({"type": "array", "maxItems": 20, "items": {"type": "object",
        "properties": {"region": {"type": "string", "enum": ["EMEA", "AMER", "APAC"]},
                       "arr": {"type": "number", "minimum": 0, "maximum": 1e9, "multipleOf": 1000}},
        "required": ["region", "arr"], "additionalProperties": false}});
    let rt = RtTemplate::from_json_schema(&zod)
        .unwrap()
        .bind(&Map::new())
        .unwrap();
    assert!(rt.capacity_bits() > 0.0);
    assert!(RtTemplate::from_json_schema(&json!({"type": "string"})).is_err());
}

#[test]
fn ts_render() {
    let rt = RtTemplate::from_json(&slots_type())
        .unwrap()
        .bind(&params())
        .unwrap();
    assert_eq!(rt.to_ts(), "Array<{ start: Date; end: Date }>");
}

// ---------- property tests ----------

fn small_rt() -> impl Strategy<Value = Rt> {
    let leaf = prop_oneof![
        Just(Rt::Bool),
        (-4i64..4, 0i64..6).prop_map(|(lo, w)| Rt::Int {
            min: lo,
            max: lo + w
        }),
        (1usize..4).prop_map(|n| Rt::Enum {
            values: (0..n).map(|i| format!("v{i}")).collect()
        }),
        (0u32..3).prop_map(|l| Rt::String {
            max_len: l,
            charset: Charset::Digits,
            pattern: None
        }),
        (0i64..4, 1i64..3).prop_map(|(w, g)| Rt::Timestamp {
            min: 0,
            max: w * g * 1000,
            granularity_ms: g * 1000
        }),
        (0u32..5).prop_map(|k| Rt::Float {
            min: 0.0,
            max: k as f64 * 0.5,
            precision: Some(0.5)
        }),
    ];
    leaf.prop_recursive(2, 6, 3, |inner| {
        prop_oneof![
            (0u32..3, inner.clone()).prop_map(|(m, t)| Rt::List {
                max: m,
                of: Box::new(t)
            }),
            prop::collection::vec(inner.clone(), 1..3).prop_map(|ts| Rt::Struct {
                fields: ts
                    .into_iter()
                    .enumerate()
                    .map(|(i, t)| (format!("f{i}"), t))
                    .collect()
            }),
            inner.prop_map(|t| Rt::Optional(Box::new(t))),
        ]
    })
}

const ENUMERATION_LIMIT: usize = 20_000;

/// Enumerate every normalized inhabitant, or reject a type before a Cartesian
/// product would exceed the test's memory budget.
fn inhabitants(rt: &Rt) -> Option<Vec<Value>> {
    Some(match rt {
        Rt::Bool => vec![json!(false), json!(true)],
        Rt::Int { min, max } => (*min..=*max).map(Value::from).collect(),
        Rt::Enum { values } => values.iter().map(|v| json!(v)).collect(),
        Rt::String { max_len, .. } => {
            let mut out = vec![String::new()];
            let mut frontier = vec![String::new()];
            for _ in 0..*max_len {
                let mut next = Vec::new();
                for s in &frontier {
                    for d in '0'..='9' {
                        let mut t = s.clone();
                        t.push(d);
                        next.push(t);
                    }
                }
                out.extend(next.iter().cloned());
                frontier = next;
            }
            out.into_iter().map(Value::from).collect()
        }
        Rt::Timestamp {
            min,
            max,
            granularity_ms,
        } => {
            let mut v = Vec::new();
            let mut t = *min;
            while t <= *max {
                v.push(json!(format_timestamp_ms(t)));
                t += granularity_ms;
            }
            v
        }
        Rt::Float {
            min,
            max,
            precision: Some(p),
        } => {
            let mut v = Vec::new();
            let mut k = 0.0;
            while min + k * p <= *max + 1e-12 {
                v.push(json!(min + k * p));
                k += 1.0;
            }
            v
        }
        Rt::Optional(t) => {
            let mut v = vec![Value::Null];
            v.extend(inhabitants(t)?);
            if v.len() >= ENUMERATION_LIMIT {
                return None;
            }
            v
        }
        Rt::Struct { fields } => {
            let mut acc: Vec<Map<String, Value>> = vec![Map::new()];
            for (k, t) in fields {
                let vals = inhabitants(t)?;
                if acc.len().saturating_mul(vals.len()) >= ENUMERATION_LIMIT {
                    return None;
                }
                let mut next = Vec::new();
                for m in &acc {
                    for x in &vals {
                        let mut m2 = m.clone();
                        m2.insert(k.clone(), x.clone());
                        next.push(m2);
                    }
                }
                acc = next;
            }
            acc.into_iter().map(Value::Object).collect()
        }
        Rt::List { max, of } => {
            let vals = inhabitants(of)?;
            let mut out: Vec<Vec<Value>> = vec![vec![]];
            let mut frontier: Vec<Vec<Value>> = vec![vec![]];
            for _ in 0..*max {
                if out
                    .len()
                    .saturating_add(frontier.len().saturating_mul(vals.len()))
                    >= ENUMERATION_LIMIT
                {
                    return None;
                }
                let mut next = Vec::new();
                for l in &frontier {
                    for x in &vals {
                        let mut l2 = l.clone();
                        l2.push(x.clone());
                        next.push(l2);
                    }
                }
                out.extend(next.iter().cloned());
                frontier = next;
            }
            out.into_iter().map(Value::Array).collect()
        }
        _ => vec![],
    })
}

#[test]
fn exhaustive_capacity_check_bounds_cartesian_products() {
    let strings = Rt::String {
        max_len: 2,
        charset: Charset::Digits,
        pattern: None,
    };
    let lists = Rt::List {
        max: 2,
        of: Box::new(strings),
    };
    assert_eq!(inhabitants(&lists).unwrap().len(), 12_433);
    assert!(inhabitants(&Rt::List {
        max: 2,
        of: Box::new(lists.clone())
    })
    .is_none());
    assert!(inhabitants(&Rt::Struct {
        fields: vec![("a".into(), lists.clone()), ("b".into(), lists)],
    })
    .is_none());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 300, .. ProptestConfig::default() })]

    /// Canonical wire form round-trips through the parser.
    #[test]
    fn wire_roundtrip(rt in small_rt()) {
        let back = Rt::from_json(&rt.to_json()).unwrap();
        prop_assert_eq!(back.to_json(), rt.to_json());
        let viaschema = RtTemplate::from_json_schema(&RtTemplate::from_json(&rt.to_json()).unwrap().to_json_schema())
            .unwrap().bind(&Map::new()).unwrap();
        prop_assert_eq!(viaschema.to_json(), rt.to_json());
    }

    /// Soundness of capacity: the number of distinct normalized values the
    /// validator can emit never exceeds 2^capacity.
    #[test]
    fn capacity_is_sound(rt in small_rt()) {
        let all = inhabitants(&rt);
        prop_assume!(all.is_some());
        let all = all.unwrap();
        let mut distinct = BTreeSet::new();
        for x in &all {
            let n = rt.validate(x).expect("inhabitant must validate");
            // Normalization is idempotent.
            prop_assert_eq!(rt.validate(&n).unwrap(), n.clone());
            distinct.insert(n.to_string());
        }
        let bound = rt.capacity_bits().exp2();
        prop_assert!((distinct.len() as f64) <= bound * (1.0 + 1e-9) + 1e-9,
            "{} distinct > 2^{} for {}", distinct.len(), rt.capacity_bits(), rt);
    }

    /// Capacity is monotone under subtyping (narrowing a bound never raises it).
    #[test]
    fn capacity_monotone(lo in -100i64..100, w in 0i64..1000, shrink in 0i64..1000, max in 0u32..10, smax in 0u32..10) {
        let wide = Rt::Int { min: lo, max: lo + w };
        let narrow = Rt::Int { min: lo, max: lo + (w - shrink.min(w)) };
        prop_assert!(narrow.capacity_bits() <= wide.capacity_bits());
        let l1 = Rt::List { max, of: Box::new(wide.clone()) };
        let l2 = Rt::List { max: max.min(smax), of: Box::new(narrow) };
        prop_assert!(l2.capacity_bits() <= l1.capacity_bits() + 1e-9);
        prop_assert!(Rt::Optional(Box::new(wide.clone())).capacity_bits() >= wide.capacity_bits());
    }

    /// The validator never accepts a value outside the type: anything it
    /// returns re-validates, and arbitrary JSON either fails or normalizes.
    #[test]
    fn validator_total(rt in small_rt(), x in arb_json()) {
        if let Ok(n) = rt.validate(&x) {
            prop_assert!(rt.validate(&n).is_ok());
        }
    }
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        (-10i64..10).prop_map(Value::from),
        (-10.0f64..10.0).prop_map(|f| json!(f)),
        "[0-9a-z]{0,4}".prop_map(Value::from),
    ];
    leaf.prop_recursive(3, 12, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("f[0-2]", inner, 0..3)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// Regression: a range that overflows i64 must not be admitted as 0 bits.
#[test]
fn extreme_bounds_never_lose_capacity() {
    for (min, max) in [
        (i64::MIN, i64::MAX),
        (-9_000_000_000_000_000_000, 9_000_000_000_000_000_000),
        (i64::MIN + 1, 0),
    ] {
        let ts = serde_json::json!({"timestamp": {"min": min, "max": max, "granularity": 1}});
        assert!(Rt::from_json(&ts).is_err(), "{ts}");
        let int = serde_json::json!({"int": {"min": min, "max": max}});
        assert!(Rt::from_json(&int).unwrap().capacity_bits() > 60.0, "{int}");
    }
    let t = Rt::from_json(&serde_json::json!({"timestamp": {"min": -8_640_000_000_000_000i64, "max": 8_640_000_000_000_000i64, "granularity": 1}})).unwrap();
    assert!(t.capacity_bits() > 53.0);
    // Even a hand-built type cannot wrap.
    assert!(
        Rt::Timestamp {
            min: i64::MIN,
            max: i64::MAX,
            granularity_ms: 1
        }
        .capacity_bits()
            > 63.0
    );
    assert!(
        Rt::Date {
            min: i32::MIN,
            max: i32::MAX,
            granularity_days: 1
        }
        .capacity_bits()
            > 31.0
    );
    for g in [0i64, -5, i64::MAX, 9_000_000_000_000_000_000] {
        assert!(Rt::from_json(
            &serde_json::json!({"timestamp": {"min": 0, "max": 10, "granularity": g}})
        )
        .is_err());
        assert!(Rt::from_json(&serde_json::json!({"date": {"min": "2026-01-01", "max": "2026-02-01", "granularity": g}})).is_err());
    }
}

/// Every value the validator releases for arbitrary raw numbers, including
/// ranges whose ends are off the grid.
fn released(rt: &Rt, lo: f64, hi: f64) -> BTreeSet<String> {
    let n = 4000;
    let mut raw: Vec<f64> = (0..=n)
        .map(|i| lo + (hi - lo) * i as f64 / n as f64)
        .collect();
    raw.extend([lo, hi, 0.0, -0.0]);
    raw.into_iter()
        .filter_map(|x| rt.validate(&json!(x)).ok())
        .map(|v| remit_canon(&v))
        .collect()
}

/// JSON text with negative zero folded, as JCS does for numbers.
fn remit_canon(v: &Value) -> String {
    match v.as_f64() {
        Some(0.0) => "0".into(),
        _ => v.to_string(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, .. ProptestConfig::default() })]

    /// Regression: an off-grid `max` used to be released in addition to every
    /// grid point, one value more than the declared capacity.
    #[test]
    fn quantized_numbers_never_exceed_capacity(lo in -3.0f64..3.0, w in 0.0f64..4.0, p in prop_oneof![Just(0.1), Just(0.25), Just(0.4), Just(1.0), 0.05f64..3.0], scale in 0u32..2) {
        for rt in [Rt::Float { min: lo, max: lo + w, precision: Some(p) }, Rt::Decimal { scale, min: lo, max: lo + w }] {
            let out = released(&rt, lo, lo + w);
            prop_assert!(out.len() as f64 <= rt.capacity_bits().exp2() * (1.0 + 1e-9), "{rt}: {out:?}");
            for v in &out {
                let v: Value = serde_json::from_str(v).unwrap();
                let again = rt.validate(&v);
                prop_assert!(again.is_ok(), "{rt}: released {v} is outside its own type");
                prop_assert_eq!(remit_canon(&again.unwrap()), remit_canon(&v));
            }
        }
    }
}

#[test]
fn zero_capacity_numbers_have_one_value() {
    for t in [
        json!({"float": {"min": 0.0, "max": 0.9, "precision": 1}}),
        json!({"decimal": {"scale": 0, "min": 0.4, "max": 0.6}}),
        json!({"decimal": {"scale": 0, "min": -0.4, "max": 0.0}}),
    ] {
        let rt = Rt::from_json(&t).unwrap();
        assert_eq!(rt.capacity_bits(), 0.0, "{t}");
        assert!(released(&rt, -1.0, 1.0).len() <= 1, "{t}");
    }
}
