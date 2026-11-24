#![no_main]
// Arbitrary tokens and Datalog must never crash admission or grant authority.
use std::collections::{BTreeMap, BTreeSet};
fn facts() -> remit_analyze::Facts {
    let mut resources = BTreeMap::new();
    resources.insert("a.b".to_string(), remit_analyze::ResourceFacts { actions: BTreeSet::from(["read".to_string()]), ..Default::default() });
    remit_analyze::Facts { mode: "query".into(), purpose: "p".into(), resources, ops: Default::default(), aggregate_only: false, min_group_size: None, result_bits: 8, capacity_bits: 5.0, fuel: 1, memory_bytes: 1, wall_ms: 1, scan_rows: 1, output_bytes: 1, max_rows_total: 1, epsilon_milli: 0, standing_approval: false, authority: Default::default(), cost: serde_json::Value::Null }
}
libfuzzer_sys::fuzz_target!(|data: &str| {
    static ROOT: std::sync::OnceLock<biscuit_auth::PrivateKey> = std::sync::OnceLock::new();
    let root = ROOT.get_or_init(biscuit_auth::PrivateKey::new);
    assert!(remit_policy::authority::verify(&[data.to_string()], &[root.public()], "did:web:x", &facts(), 0).is_err(), "unsigned token accepted");
    // A correctly signed token with fuzzed Datalog may or may not authorize; it must not panic.
    if let Ok(t) = remit_policy::authority::issue(root, data) {
        let _ = remit_policy::authority::verify(&[t], &[root.public()], "did:web:x", &facts(), 0);
    }
});
