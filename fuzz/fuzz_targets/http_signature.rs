#![no_main]
// RFC 9421 headers and JWTs come from the network, before authentication.
libfuzzer_sys::fuzz_target!(|data: (String, String, String)| {
    let (input, sig, tok) = data;
    let h = |n: &str| match n { "signature-input" => Some(input.clone()), "signature" => Some(sig.clone()), "content-digest" => Some(tok.clone()), _ => None };
    let req = remit_wire::httpsig::HttpRequest { method: "POST", authority: "h", path: "/", query: None, body: b"x", header: &h };
    let key = remit_wire::PublicKey::Ed25519([7; 32]);
    assert!(!matches!(remit_wire::httpsig::verify(&req, 0, 1, 1, |_| Some(key)), Ok(Some(_))), "forged signature accepted");
    assert!(remit_wire::jwt::verify(&tok, "wit+jwt", 0, 0, &[key]).is_err(), "forged token accepted");
});
