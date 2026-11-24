//! Differential test against the proved Lean model (`formal/lean`).
//! Build it with `cd formal/lean && lake build`; without it the test is skipped
//! unless `REMIT_REQUIRE_LEAN` is set.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use remit_types::{parse_timestamp_ms, Charset, Rt};
use serde_json::{json, Value};

/// Numbers are sixty-fourths, so every bound is exact in `f64`.
const U: f64 = 64.0;

fn rt() -> impl Strategy<Value = Rt> {
    let leaf = prop_oneof![
        Just(Rt::Bool),
        (-50i64..50, 0i64..40).prop_map(|(lo, w)| Rt::Int {
            min: lo,
            max: lo + w
        }),
        (-300i64..300, 0i64..300, 1i64..200).prop_map(|(lo, w, p)| Rt::Float {
            min: lo as f64 / U,
            max: (lo + w) as f64 / U,
            precision: Some(p as f64 / U)
        }),
        (0i64..5_000, 0i64..90_000, 1i64..40_000).prop_map(|(lo, w, g)| Rt::Timestamp {
            min: lo,
            max: lo + w,
            granularity_ms: g
        }),
        (1usize..6).prop_map(|n| Rt::Enum {
            values: (0..n).map(|i| format!("v{i}")).collect()
        }),
        (0u32..5).prop_map(|l| Rt::String {
            max_len: l,
            charset: Charset::Digits,
            pattern: None
        }),
    ];
    leaf.prop_recursive(3, 10, 3, |inner| {
        prop_oneof![
            (0u32..4, inner.clone()).prop_map(|(m, t)| Rt::List {
                max: m,
                of: Box::new(t)
            }),
            prop::collection::vec(inner.clone(), 0..4).prop_map(|ts| Rt::Struct {
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

fn ty(t: &Rt) -> Value {
    let u = |f: f64| (f * U) as i64;
    match t {
        Rt::Bool => json!(["bool"]),
        Rt::Int { min, max } => json!(["int", min, max]),
        Rt::Float {
            min,
            max,
            precision,
        } => json!(["quant", u(*min), u(*max), u(precision.unwrap())]),
        Rt::Timestamp {
            min,
            max,
            granularity_ms,
        } => json!(["grid", min, max, granularity_ms]),
        Rt::Enum { values } => json!(["enum", values.len()]),
        Rt::String { max_len, .. } => json!(["str", max_len, 10]),
        Rt::List { max, of } => json!(["list", max, ty(of)]),
        Rt::Struct { fields } => fields
            .iter()
            .rev()
            .fold(json!(["unit"]), |acc, (_, t)| json!(["pair", ty(t), acc])),
        Rt::Optional(t) => json!(["opt", ty(t)]),
        _ => unreachable!(),
    }
}

/// A raw value for `t`: usually the right shape, often out of range, sometimes
/// the wrong type. Returns the Rust and the Lean encoding.
fn raw(t: &Rt, r: &mut impl FnMut(i64) -> i64) -> (Value, Value) {
    if r(40) == 0 {
        return match r(3) {
            0 => (Value::Null, json!(["null"])),
            1 => (json!(true), json!(["bool", true])),
            _ => (json!([]), json!(["arr", []])),
        };
    }
    match t {
        Rt::Bool => {
            let b = r(2) == 0;
            (json!(b), json!(["bool", b]))
        }
        Rt::Int { min, max } => {
            let x = min - 1 + r(max - min + 3);
            (json!(x), json!(["num", x]))
        }
        Rt::Float { min, max, .. } => {
            let x = (min * U) as i64 - 1 + r(((max - min) * U) as i64 + 3);
            (json!(x as f64 / U), json!(["num", x]))
        }
        Rt::Timestamp { min, max, .. } => {
            let x = min - 1 + r(max - min + 3);
            (json!(x), json!(["num", x]))
        }
        Rt::Enum { values } => {
            let k = r(values.len() as i64 + 1);
            (json!(format!("v{k}")), json!(["sym", k]))
        }
        Rt::String { max_len, .. } => {
            let cs: Vec<i64> = (0..r(*max_len as i64 + 2))
                .map(|_| if r(30) == 0 { 10 } else { r(10) })
                .collect();
            (
                json!(cs
                    .iter()
                    .map(|d| if *d == 10 {
                        'x'
                    } else {
                        (b'0' + *d as u8) as char
                    })
                    .collect::<String>()),
                json!(["str", cs]),
            )
        }
        Rt::List { max, of } => {
            let (a, b): (Vec<_>, Vec<_>) = (0..r(*max as i64 + 2)).map(|_| raw(of, r)).unzip();
            (json!(a), json!(["arr", b]))
        }
        Rt::Struct { fields } => {
            let vs: Vec<_> = fields.iter().map(|(k, t)| (k, raw(t, r))).collect();
            let obj: Value = vs
                .iter()
                .map(|(k, v)| ((*k).clone(), v.0.clone()))
                .collect::<serde_json::Map<_, _>>()
                .into();
            (
                obj,
                vs.iter()
                    .rev()
                    .fold(json!(["unit"]), |acc, (_, v)| json!(["pair", v.1, acc])),
            )
        }
        Rt::Optional(t) => match r(4) {
            0 => (Value::Null, json!(["null"])),
            _ => raw(t, r),
        },
        _ => unreachable!(),
    }
}

/// Does a released Rust value equal the model's?
fn same(t: &Rt, v: &Value, m: &Value) -> bool {
    match t {
        Rt::Optional(t) => {
            if v.is_null() || m[0] == "null" {
                v.is_null() && m[0] == "null"
            } else {
                same(t, v, m)
            }
        }
        Rt::Bool => m[0] == "bool" && m[1] == *v,
        Rt::Int { .. } => m[0] == "num" && m[1] == *v,
        Rt::Float { precision, .. } => {
            m[0] == "num"
                && (m[1].as_f64().unwrap() / U - v.as_f64().unwrap()).abs()
                    <= precision.unwrap() * 1e-5
        }
        Rt::Timestamp { .. } => {
            m[0] == "num" && m[1].as_i64() == parse_timestamp_ms(v.as_str().unwrap())
        }
        Rt::Enum { .. } => m[0] == "sym" && format!("v{}", m[1]) == v.as_str().unwrap(),
        Rt::String { .. } => {
            m[0] == "str"
                && m[1]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| d.to_string())
                    .collect::<String>()
                    == v.as_str().unwrap()
        }
        Rt::List { of, .. } => {
            let (a, b) = (v.as_array().unwrap(), m[1].as_array().unwrap());
            m[0] == "arr" && a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(of, x, y))
        }
        Rt::Struct { fields } => {
            let mut m = m;
            for (k, t) in fields {
                if m[0] != "pair" || !same(t, &v[k], &m[1]) {
                    return false;
                }
                m = &m[2];
            }
            m[0] == "unit"
        }
        _ => unreachable!(),
    }
}

#[test]
fn validator_and_capacity_match_the_lean_model() {
    let bin = std::env::var("REMIT_LEAN_ORACLE").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../formal/lean/.lake/build/bin/oracle"
        )
        .into()
    });
    let Ok(mut child) = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    else {
        assert!(
            std::env::var_os("REMIT_REQUIRE_LEAN").is_none(),
            "no Lean oracle at {bin}"
        );
        eprintln!("skipped: no Lean oracle at {bin}");
        return;
    };
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut runner = TestRunner::default();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut r = move |n: i64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed >> 1) as i64 % n.max(1)
    };
    let (mut accepted, mut refused) = (0, 0);
    for _ in 0..2000 {
        let t = rt().new_tree(&mut runner).unwrap().current();
        let vs: Vec<_> = (0..10).map(|_| raw(&t, &mut r)).collect();
        writeln!(stdin, "{}", json!({"op": "type", "type": ty(&t), "values": vs.iter().map(|v| &v.1).collect::<Vec<_>>()})).unwrap();
        stdin.flush().unwrap();
        let reply: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
        let card: f64 = reply["card"]
            .as_str()
            .unwrap_or_else(|| panic!("{reply}"))
            .parse()
            .unwrap();
        if card.is_finite() {
            assert!(
                (t.capacity_bits() - card.log2()).abs() < 1e-6,
                "{t}: {} bits, model {}",
                t.capacity_bits(),
                card.log2()
            );
        }
        for ((v, _), m) in vs.iter().zip(reply["out"].as_array().unwrap()) {
            match t.validate(v) {
                Ok(n) => {
                    assert!(
                        !m.is_null() && same(&t, &n, m),
                        "{t}: {v} -> {n}, model {m}"
                    );
                    accepted += 1;
                }
                Err(e) => {
                    assert!(m.is_null(), "{t}: {v} refused ({e:?}), model {m}");
                    refused += 1;
                }
            }
        }
    }
    assert!(
        accepted > 1000 && refused > 1000,
        "{accepted} accepted, {refused} refused"
    );
    drop(stdin);
    child.wait().unwrap();
}
