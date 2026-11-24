#![no_main]
// Attestation evidence is attacker-controlled on the Sender side.
use base64::Engine as _;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let r = remit_receipt::Receipt { attestation: Some(serde_json::json!({"format": "nitro", "evidence": b64})), ..Default::default() };
    let want = remit_receipt::attest::Expectation { root: "AAAA".into(), pcrs: [(0, "00".into())].into(), max_age_ms: i64::MAX };
    assert!(remit_receipt::attest::verify(&r, &want, 0).is_err());
});
