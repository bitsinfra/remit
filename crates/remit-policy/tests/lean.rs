//! Differential test of the ledger against the proved Lean model
//! (`formal/lean`); see `remit-types/tests/lean.rs` for how it is found.

use std::io::Write;
use std::process::{Command, Stdio};

use remit_policy::budget::{Actual, Ask, BudgetConfig, BudgetError, Ledger, Privacy};
use serde_json::{json, Value};

#[test]
fn ledger_matches_the_lean_model() {
    let bin = std::env::var("REMIT_LEAN_ORACLE").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../formal/lean/.lake/build/bin/oracle"
        )
        .into()
    });
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut r = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let (mut input, mut expected) = (String::new(), Vec::new());
    let mut seen = std::collections::BTreeMap::new();
    for _ in 0..300 {
        let (cap, conc) = (r(300) + 1, r(6) + 1);
        let cfg = BudgetConfig {
            bits_per_principal_per_day: cap,
            concurrency_per_principal: conc as u32,
            unverified_global_share: 1.0,
            bits_global_per_day: u64::MAX >> 12,
            ..Default::default()
        };
        let l = Ledger::open(cfg, None).unwrap();
        // Newest first, as in the model.
        let (mut open, mut done, mut events, mut want) = (vec![], vec![], vec![], vec![]);
        for nonce in 0..60u64 {
            let o = match r(5) {
                0 | 1 if !open.is_empty() => {
                    let i = r(open.len() as u64) as usize;
                    let a = r(120);
                    let res = open.remove(i);
                    l.settle(
                        &res,
                        Actual {
                            bits: a,
                            ..Default::default()
                        },
                    );
                    done.push(res);
                    events.push(json!({"settle": [i, a]}));
                    "settled"
                }
                2 if !done.is_empty() => {
                    // Settling twice is a no-op; the model has no such event.
                    let i = r(done.len() as u64) as usize;
                    l.settle(&done[i], Actual::default());
                    continue;
                }
                _ => {
                    let bits = r(90);
                    let ask = Ask {
                        principal: "p".into(),
                        verified: true,
                        datasets: vec!["d".into()],
                        bits,
                        fuel: 0,
                        privacy: Privacy::ZERO,
                        cached: false,
                    };
                    events.push(json!({"submit": {"decodes": true, "signed": true, "addressed": true, "unexpired": true, "notFuture": true, "shortLived": true, "nonce": nonce, "analyzes": true, "authority": true, "permitted": true, "withinClamps": true, "approved": true, "bits": bits}}));
                    match l.reserve(&ask, 1_000_000) {
                        Ok(res) => {
                            open.insert(0, res);
                            "admitted"
                        }
                        Err(BudgetError::Concurrency { .. }) => "busy",
                        Err(BudgetError::Bits { .. }) => "RMT-E0060",
                        Err(e) => panic!("{e}"),
                    }
                }
            };
            *seen.entry(o).or_insert(0) += 1;
            want.push(json!([o, cap - l.remaining_bits("p", 1_000_000)]));
        }
        input.push_str(&format!(
            "{}\n",
            json!({"op": "ledger", "cap": cap, "concurrency": conc, "events": events})
        ));
        expected.push(Value::from(want));
    }
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
    let w = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let out = child.wait_with_output().unwrap();
    w.join().unwrap();
    let got: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(got.len(), expected.len());
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert!(
        ["admitted", "busy", "RMT-E0060", "settled"]
            .iter()
            .all(|k| seen.get(k).copied().unwrap_or(0) > 50),
        "{seen:?}"
    );
}
