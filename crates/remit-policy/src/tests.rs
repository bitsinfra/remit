use std::collections::{BTreeMap, BTreeSet};

use remit_analyze::{Facts, ResourceFacts};
use remit_read::ResourceConfig;
use serde_json::json;

use crate::*;

fn resources() -> BTreeMap<String, ResourceConfig> {
    let mut m = BTreeMap::new();
    m.insert(
        "calendar.events".into(),
        ResourceConfig {
            purposes: vec!["scheduling".into()],
            max_bits: Some(128),
            ..Default::default()
        },
    );
    m.insert(
        "crm.accounts".into(),
        ResourceConfig {
            aggregate_only: true,
            k: Some(20),
            ..Default::default()
        },
    );
    m.insert("hr.salaries".into(), ResourceConfig::default());
    m
}

fn facts(
    res: &str,
    actions: &[&str],
    bits: u64,
    agg: bool,
    k: Option<u64>,
    purpose: &str,
) -> Facts {
    let mut resources = BTreeMap::new();
    resources.insert(
        res.to_string(),
        ResourceFacts {
            columns: ["start_at", "end_at", "status"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            aggregate_only: agg,
            actions: actions.iter().map(|s| s.to_string()).collect(),
            max_rows_total: 500,
        },
    );
    Facts {
        mode: "kernel".into(),
        purpose: purpose.into(),
        resources,
        ops: BTreeSet::new(),
        aggregate_only: agg,
        min_group_size: k,
        result_bits: bits,
        capacity_bits: bits as f64,
        fuel: 20_000_000,
        memory_bytes: 1 << 24,
        wall_ms: 250,
        scan_rows: 1000,
        output_bytes: 1024,
        max_rows_total: 500,
        epsilon_milli: 0,
        standing_approval: false,
        authority: BTreeSet::new(),
        cost: json!({}),
    }
}

const SAMPLE_POLICY: &str = r#"
@id("alice:calendar")
permit (
  principal in Remit::Group::"verified-agents",
  action in [Remit::Action::"read", Remit::Action::"run_kernel"],
  resource == Remit::Table::"calendar.events"
) when {
  ["start_at", "end_at", "status"].containsAll(context.columns) &&
  context.purpose == "scheduling" &&
  context.result_bits <= 128 &&
  context.max_rows_total <= 1000
};

@id("crm:partners")
permit (principal in Remit::Group::"partners", action == Remit::Action::"aggregate", resource in Remit::Dataset::"crm")
when { context.aggregate_only && (context.min_group_size >= 20 || context.epsilon_milli > 0) };

@id("hr:fence")
forbid (principal, action, resource in Remit::Dataset::"hr")
unless { principal in Remit::Group::"hr-agents" };
"#;

fn engine() -> PolicyEngine {
    let text = presets::assemble(&[], &[("sample.cedar".into(), SAMPLE_POLICY.into())]).unwrap();
    PolicyEngine::new(
        &text,
        &resources(),
        &[
            "verified-agents".into(),
            "partners".into(),
            "hr-agents".into(),
        ],
    )
    .unwrap()
}

fn agent(groups: &[&str]) -> PrincipalInfo {
    PrincipalInfo {
        id: "did:web:travel-agent.example".into(),
        groups: groups.iter().map(|s| s.to_string()).collect(),
        verified: true,
        ..Default::default()
    }
}

#[test]
fn plan_policies() {
    let e = engine();
    let ok = e.decide(
        &agent(&["verified-agents"]),
        &facts(
            "calendar.events",
            &["read", "run_kernel"],
            68,
            false,
            None,
            "scheduling",
        ),
    );
    assert!(ok.allowed, "{ok:?}");
    assert!(ok.permitted_by.contains(&"alice:calendar".to_string()));
    let d = e.decide(
        &agent(&[]),
        &facts(
            "calendar.events",
            &["read", "run_kernel"],
            68,
            false,
            None,
            "scheduling",
        ),
    );
    assert!(!d.allowed);
    let d = e.decide(
        &agent(&["verified-agents"]),
        &facts("calendar.events", &["read"], 200, false, None, "scheduling"),
    );
    assert!(!d.allowed, "bits over the resource cap");
    assert!(d.denials[0].forbidden_by.contains(&"base:bits".to_string()));
    let d = e.decide(
        &agent(&["verified-agents"]),
        &facts("calendar.events", &["read"], 68, false, None, "marketing"),
    );
    assert!(!d.allowed, "purpose");
    let ok = e.decide(
        &agent(&["partners"]),
        &facts(
            "crm.accounts",
            &["aggregate"],
            500,
            true,
            Some(20),
            "analytics",
        ),
    );
    assert!(ok.allowed, "{ok:?}");
    let d = e.decide(
        &agent(&["partners"]),
        &facts(
            "crm.accounts",
            &["aggregate"],
            500,
            true,
            Some(5),
            "analytics",
        ),
    );
    assert!(!d.allowed);
    let d = e.decide(
        &agent(&["partners"]),
        &facts("crm.accounts", &["read"], 500, false, None, "analytics"),
    );
    assert!(!d.allowed);
    assert!(d.denials[0]
        .forbidden_by
        .contains(&"base:aggregate-only".to_string()));
    let d = e.decide(
        &agent(&["verified-agents"]),
        &facts("hr.salaries", &["read"], 8, false, None, "x"),
    );
    assert!(!d.allowed);
}

#[test]
fn presets_parse_and_validate() {
    let all: Vec<String> = presets::PRESETS.iter().map(|s| s.to_string()).collect();
    let text = presets::assemble(&all, &[]).unwrap();
    let e = PolicyEngine::new(
        &text,
        &resources(),
        &["verified-agents".into(), "internal".into()],
    )
    .unwrap();
    let ok = e.decide(
        &agent(&["verified-agents"]),
        &facts(
            "calendar.events",
            &["read", "run_kernel"],
            68,
            false,
            None,
            "scheduling",
        ),
    );
    assert!(ok.allowed, "{ok:?}");
    let ok = e.decide(
        &agent(&[]),
        &facts(
            "crm.accounts",
            &["aggregate"],
            68,
            true,
            Some(20),
            "analytics",
        ),
    );
    assert!(ok.allowed, "{ok:?}");
    assert!(presets::assemble(&["nope".into()], &[]).is_err());
}

#[test]
fn lint_finds_problems() {
    let bad = r#"
@id("open")
permit (principal, action, resource);
@id("never")
permit (principal, action, resource) when { context.result_bits < 0 };
@id("shadowed")
permit (principal, action == Remit::Action::"read", resource in Remit::Dataset::"hr");
@id("fence")
forbid (principal, action, resource in Remit::Dataset::"hr");
"#;
    let f = lint::lint(bad, &resources(), &[agent(&["verified-agents"])]);
    let msg = |id: &str| {
        f.iter()
            .find(|x| x.policy.as_deref() == Some(id))
            .map(|x| x.message.clone())
            .unwrap_or_default()
    };
    assert!(msg("open").contains("always-allow"), "{f:?}");
    assert!(msg("never").contains("never satisfiable"), "{f:?}");
    assert!(msg("shadowed").contains("shadowed"), "{f:?}");
    let d = lint::diff(
        SAMPLE_POLICY,
        bad,
        &resources(),
        &[agent(&["verified-agents"])],
    )
    .unwrap();
    assert!(!d.is_empty());
    assert!(lint::lint(
        "permit (principal, action, resource) when { context.nope };",
        &resources(),
        &[]
    )
    .iter()
    .any(|x| x.level == "error"));
}

fn ask(p: &str, ds: &[&str], bits: u64, fuel: u64) -> Ask {
    Ask {
        principal: p.into(),
        verified: true,
        datasets: ds.iter().map(|s| s.to_string()).collect(),
        bits,
        fuel,
        ..Default::default()
    }
}

/// Differential test: the SMT translation agrees with Cedar's evaluator.
#[test]
fn symbolic_analysis_agrees_with_cedar() {
    if !symbolic::available() {
        eprintln!("skipping: no SMT solver");
        return;
    }
    let res = resources();
    let all: Vec<String> = presets::PRESETS.iter().map(|s| s.to_string()).collect();
    let text = presets::assemble(&all, &[("sample".into(), SAMPLE_POLICY.into())]).unwrap();
    let set = parse_policies(&text).unwrap();
    let m = symbolic::Model::new(&set, &res).unwrap();
    let e = PolicyEngine::new(
        &text,
        &res,
        &[
            "verified-agents".into(),
            "partners".into(),
            "hr-agents".into(),
            "internal".into(),
        ],
    )
    .unwrap();
    let mut n = 0;
    for (r, bits, agg, k, purpose, groups) in [
        (
            "calendar.events",
            68,
            false,
            None,
            "scheduling",
            vec!["verified-agents"],
        ),
        (
            "calendar.events",
            129,
            false,
            None,
            "scheduling",
            vec!["verified-agents"],
        ),
        (
            "calendar.events",
            68,
            false,
            None,
            "marketing",
            vec!["verified-agents"],
        ),
        ("crm.accounts", 68, true, Some(20), "a", vec!["partners"]),
        ("crm.accounts", 68, true, Some(19), "a", vec![]),
        ("crm.accounts", 68, false, Some(20), "a", vec!["partners"]),
        ("hr.salaries", 8, false, None, "x", vec!["verified-agents"]),
        (
            "hr.salaries",
            8,
            false,
            None,
            "x",
            vec!["hr-agents", "verified-agents"],
        ),
        (
            "hr.salaries",
            8,
            true,
            None,
            "x",
            vec!["hr-agents", "internal"],
        ),
    ] {
        for action in ["read", "aggregate", "search", "run_kernel"] {
            let mut f = facts(r, &[action], bits, agg, k, purpose);
            f.mode = "kernel".into();
            let mut p = agent(&groups);
            p.id = "did:web:x".into();
            let cedar = e.decide(&p, &f).allowed;
            let gs = groups.iter().fold(
                "((as const (Array String Bool)) false)".to_string(),
                |s, g| format!("(store {s} \"{g}\" true)"),
            );
            let cols = ["start_at", "end_at", "status"].iter().fold(
                "((as const (Array String Bool)) false)".to_string(),
                |s, g| format!("(store {s} \"{g}\" true)"),
            );
            let empty = "((as const (Array String Bool)) false)";
            let pin = format!(
                "(and (= pid \"did:web:x\") (= pgroups {gs}) (= act \"{action}\") (= rid \"{r}\") (= c_mode \"kernel\") (= c_purpose \"{purpose}\") (= c_columns {cols}) (= c_ops {empty}) (= c_aggregate_only {agg}) (= c_min_group_size {}) (= c_result_bits {bits}) (= c_fuel 20000000) (= c_memory_bytes {}) (= c_wall_ms 250) (= c_max_rows_total 500) (= c_epsilon_milli 0) (= c_standing_approval false) (= c_authority {empty}) (= p_org \"\") p_verified (= p_tags {empty}))",
                k.unwrap_or(0), 1 << 24
            );
            let sym = matches!(
                m.check(&format!("(and {pin} {})", m.allow())).unwrap(),
                symbolic::Answer::Sat(_)
            );
            assert_eq!(
                cedar, sym,
                "{r} {action} {bits} {agg} {k:?} {purpose} {groups:?}"
            );
            n += 1;
        }
    }
    assert_eq!(n, 36);
    // Equivalence: reordering and double negation are equivalent; a widened bound is not.
    let a = r#"permit (principal, action, resource) when { context.result_bits <= 128 && context.aggregate_only };"#;
    let b = r#"permit (principal, action, resource) when { !(!context.aggregate_only || context.result_bits > 128) };"#;
    let c = r#"permit (principal, action, resource) when { context.result_bits <= 129 && context.aggregate_only };"#;
    assert_eq!(lint::prove_equivalent(a, b, &res).unwrap(), None);
    let ex = lint::prove_equivalent(a, c, &res).unwrap().unwrap();
    assert_eq!(
        (ex["result_bits"].clone(), ex["change"].clone()),
        (json!(129), json!("deny → allow")),
        "{ex}"
    );
    // Proved findings a sampling lattice can miss.
    let f = lint::lint(
        r#"@id("gap") permit (principal, action, resource) when { context.result_bits > 777 && context.result_bits < 779 && context.result_bits != 778 };
        @id("like") permit (principal, action, resource) when { context.purpose like "a*" && context.purpose == "b" };"#,
        &res,
        &[],
    );
    assert!(
        f.iter()
            .filter(|x| x.message.contains("never satisfiable"))
            .count()
            == 2,
        "{f:?}"
    );
}

#[test]
fn budgets() {
    let dir = std::env::temp_dir().join(format!("remit-ledger-{}", std::process::id()));
    let wal = dir.join("ledger.wal");
    let _ = std::fs::remove_file(&wal);
    let cfg = BudgetConfig {
        bits_per_principal_per_day: 100,
        bits_global_per_day: 150,
        concurrency_per_principal: 2,
        ..Default::default()
    };
    let now = 1_795_000_000_000;
    let l = Ledger::open(cfg.clone(), Some(&wal)).unwrap();
    let cal = ["calendar"];
    let r1 = l.reserve(&ask("a", &cal, 60, 1000), now).unwrap();
    assert!(matches!(
        l.reserve(&ask("a", &cal, 60, 1000), now),
        Err(BudgetError::Bits { .. })
    ));
    let r2 = l.reserve(&ask("b", &cal, 60, 1000), now).unwrap();
    assert!(
        matches!(
            l.reserve(&ask("c", &cal, 60, 1000), now),
            Err(BudgetError::Bits { .. })
        ),
        "global cap is shared (Sybil)"
    );
    l.settle(&r1, Actual::used(10, 60, Privacy::ZERO));
    l.release(&r2);
    assert_eq!(l.remaining_bits("a", now), 40);
    assert_eq!(l.remaining_bits("b", now), 100);
    // Rolling day: still charged across midnight and at +23 h, free after it rolls off.
    assert!(l
        .reserve(&ask("a", &cal, 60, 1000), now + 23 * 3_600_000)
        .is_err());
    assert_eq!(l.remaining_bits("a", now + 25 * 3_600_000), 100);
    // An unsettled reservation survives a crash, charged in full.
    let _crashed = l.reserve(&ask("d", &cal, 30, 1000), now).unwrap();
    drop(l);
    let l2 = Ledger::open(cfg.clone(), Some(&wal)).unwrap();
    assert_eq!(l2.remaining_bits("a", now), 40);
    assert_eq!(l2.remaining_bits("b", now), 100);
    assert_eq!(l2.remaining_bits("d", now), 70);
    // Compaction is idempotent.
    drop(l2);
    let l2 = Ledger::open(cfg, Some(&wal)).unwrap();
    assert_eq!(
        (l2.remaining_bits("a", now), l2.remaining_bits("d", now)),
        (40, 70)
    );
    // Concurrency.
    let x = l2.reserve(&ask("z", &[], 1, 1), now).unwrap();
    let _y = l2.reserve(&ask("z", &[], 1, 1), now).unwrap();
    assert!(matches!(
        l2.reserve(&ask("z", &[], 1, 1), now),
        Err(BudgetError::Concurrency { .. })
    ));
    l2.settle(&x, Actual::used(1, 1, Privacy::ZERO));
    assert!(l2.reserve(&ask("z", &[], 1, 1), now).is_ok());
    // ε needs a global dataset budget.
    let e = Ask {
        privacy: Privacy::pure(0.1),
        ..ask("e", &["crm"], 1, 1)
    };
    assert!(matches!(
        l2.reserve(&e, now),
        Err(BudgetError::Epsilon { .. })
    ));
}

#[test]
fn privacy_accounting_is_the_tighter_sound_bound() {
    let d = 1e-6;
    // Few large releases: pure composition. Many small: zCDP wins.
    assert_eq!(Privacy::pure(0.5).epsilon(d), 0.5);
    let many = (0..1000).fold(Privacy::ZERO, |a, _| a.add(Privacy::pure(0.01)));
    assert!(
        many.epsilon(d) < 2.0 && many.epsilon(d) < many.eps,
        "{}",
        many.epsilon(d)
    );
    // Gaussian releases have no pure ε, so only the zCDP bound applies.
    let g = Privacy::zcdp(0.01).add(Privacy::pure(0.1));
    assert!(g.epsilon(d) > 0.1);
    // Monotone under composition.
    let mut p = Privacy::ZERO;
    for i in 0..200 {
        let q = p.add(if i % 3 == 0 {
            Privacy::zcdp(0.001)
        } else {
            Privacy::pure(0.02)
        });
        assert!(q.epsilon(d) >= p.epsilon(d));
        p = q;
    }
}

#[test]
fn epsilon_global_lifetime_and_unverified_share() {
    let mut cfg = BudgetConfig {
        epsilon_per_principal_per_day: 10.0,
        unverified_global_share: 0.25,
        bits_global_per_day: 400,
        ..Default::default()
    };
    cfg.epsilon_global_per_day.insert("crm".into(), 1.0);
    cfg.epsilon_global_lifetime.insert("crm".into(), 1.5);
    let l = Ledger::open(cfg.clone(), None).unwrap();
    let now = 1_795_000_000_000;
    let ask_e = |p: &str, e: f64| Ask {
        privacy: Privacy::pure(e),
        ..ask(p, &["crm"], 1, 1)
    };
    let r = l.reserve(&ask_e("a", 0.7), now).unwrap();
    assert!(
        l.reserve(&ask_e("b", 0.7), now).is_err(),
        "global ε is shared across principals"
    );
    // A cached answer charges the asker, not the dataset.
    l.settle(
        &r,
        Actual {
            fuel: 0,
            bits: 1,
            global_bits: 0,
            privacy: Privacy::pure(0.7),
            global_privacy: Privacy::ZERO,
        },
    );
    assert_eq!(l.spent_epsilon("crm", now), 0.0);
    for i in 0..2 {
        let t = now + i * 26 * 3_600_000;
        let r = l.reserve(&ask_e("a", 0.7), t).unwrap();
        l.settle(&r, Actual::used(0, 1, Privacy::pure(0.7)));
    }
    assert!(
        matches!(l.reserve(&ask_e("a", 0.7), now + 3 * 26 * 3_600_000), Err(BudgetError::Epsilon { scope }) if scope.contains("lifetime"))
    );
    // Sybils: unverified principals together get a quarter of the global bits.
    let l = Ledger::open(cfg, None).unwrap();
    let mut spent = 0;
    for i in 0..100 {
        let a = Ask {
            verified: false,
            ..ask(&format!("sybil{i}"), &["crm"], 10, 1)
        };
        spent += l.reserve(&a, now).is_ok() as u64 * 10;
    }
    assert_eq!(spent, 100);
    assert!(
        l.reserve(&ask("verified", &["crm"], 300, 1), now).is_ok(),
        "verified agents keep their share"
    );
}

#[test]
fn biscuit_authority() {
    let root = biscuit_auth::PrivateKey::new();
    let tok = authority::issue(&root, r#"right("calendar.events", "read"); right("calendar.events", "run_kernel"); check if principal("did:web:travel-agent.example");"#).unwrap();
    let f = facts(
        "calendar.events",
        &["read", "run_kernel"],
        68,
        false,
        None,
        "scheduling",
    );
    let now = 1_795_000_000;
    authority::verify(
        std::slice::from_ref(&tok),
        &[root.public()],
        "did:web:travel-agent.example",
        &f,
        now,
    )
    .unwrap();
    // Wrong principal.
    assert!(authority::verify(
        std::slice::from_ref(&tok),
        &[root.public()],
        "did:web:evil",
        &f,
        now
    )
    .is_err());
    // Attenuation narrows: purpose + bits.
    let att = authority::attenuate(
        &tok,
        root.public(),
        r#"check if purpose("scheduling"); check if result_bits($b), $b <= 64;"#,
    )
    .unwrap();
    assert!(
        authority::verify(
            std::slice::from_ref(&att),
            &[root.public()],
            "did:web:travel-agent.example",
            &f,
            now
        )
        .is_err(),
        "68 bits > 64"
    );
    let f2 = facts(
        "calendar.events",
        &["read", "run_kernel"],
        60,
        false,
        None,
        "scheduling",
    );
    authority::verify(
        std::slice::from_ref(&att),
        &[root.public()],
        "did:web:travel-agent.example",
        &f2,
        now,
    )
    .unwrap();
    // An attenuation block cannot add rights.
    let widened =
        authority::attenuate(&tok, root.public(), r#"right("hr.salaries", "read");"#).unwrap();
    let f3 = facts("hr.salaries", &["read"], 8, false, None, "x");
    assert!(authority::verify(
        &[widened],
        &[root.public()],
        "did:web:travel-agent.example",
        &f3,
        now
    )
    .is_err());
    // Untrusted root.
    let other = biscuit_auth::PrivateKey::new();
    assert!(authority::verify(
        &[tok],
        &[other.public()],
        "did:web:travel-agent.example",
        &f,
        now
    )
    .is_err());
}
