#![no_main]
// wasm-smith kernels against the structural limits and the restricted engine:
// anything that validates must compile or be refused, and never crash the host.
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(m) = wasm_smith::Module::arbitrary(&mut u) else { return };
    let bytes = m.to_bytes();
    // Bare core modules are not components: always refused.
    assert!(remit_kernel::sender::validate_structure(&bytes, &Default::default()).is_err());
    // Wrapped as a component with that core module.
    let mut c = wasm_encoder::Component::new();
    c.section(&wasm_encoder::RawSection { id: wasm_encoder::ComponentSectionId::CoreModule.into(), data: &bytes });
    let c = c.finish();
    if remit_kernel::sender::validate_structure(&c, &Default::default()).is_ok() {
        static ENGINE: std::sync::OnceLock<wasmtime::Engine> = std::sync::OnceLock::new();
        let e = ENGINE.get_or_init(|| remit_kernel::sender::restricted_engine(64 << 20).expect("engine"));
        let _ = wasmtime::component::Component::new(e, &c);
    }
});
