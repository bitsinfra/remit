//! Test fixture: a Sender-built kernel component (sender-kernel world) that
//! returns the number of rows a declared read `busy` yields.
wit_bindgen::generate!({ path: "../../../../../spec/wit", world: "sender-kernel" });

use remit::kernel::data;

struct K;

impl Guest for K {
    fn run(_params: Vec<u8>) -> Result<Vec<u8>, u32> {
        let r = data::bind("busy").ok_or(3u32)?;
        let mut p = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(vec![]), &mut p).map_err(|_| 4u32)?;
        let t = r.call(&p).map_err(|_| 1u32)?;
        let n = t.num_rows();
        let mut out = Vec::new();
        ciborium::into_writer(&ciborium::Value::Integer(n.into()), &mut out).map_err(|_| 4u32)?;
        Ok(out)
    }
}

export!(K);
