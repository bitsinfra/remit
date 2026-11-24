#![no_main]
// Binary request decoding for every RPC, and gRPC framing.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = remit_holder::grpc::unframe(data);
    for m in ["Check", "Run", "GetRun", "GetReceipt", "PutBlob", "GetLogProof", "GetCatalog"] {
        if let Ok(v) = remit_holder::grpc::decode_request(m, data) {
            let _ = remit_holder::grpc::encode_response(m, &v);
        }
    }
});
