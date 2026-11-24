//! `remit_native`: the Holder's verifier core for Python (same Rust code the
//! Holder runs; JSON strings in and out). Build: `maturin develop -m crates/remit-py/Cargo.toml`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
fn canonicalize(json: &str) -> PyResult<String> {
    remit_verify_wasm::canonicalize(json).map_err(PyValueError::new_err)
}

#[pyfunction]
fn remit_id(manifest: &str) -> PyResult<String> {
    remit_verify_wasm::remit_id(manifest).map_err(PyValueError::new_err)
}

#[pyfunction]
fn capacity(returns: &str, params: &str) -> String {
    remit_verify_wasm::capacity(returns, params)
}

#[pyfunction]
fn validate(returns: &str, params: &str, value: &str) -> String {
    remit_verify_wasm::validate(returns, params, value)
}

#[pyfunction]
fn check_sql(sql: &str) -> String {
    remit_verify_wasm::check_sql(sql)
}

#[pyfunction]
fn bind_sql(sql: &str, catalog: &str) -> String {
    remit_verify_wasm::bind_sql(sql, catalog)
}

#[pymodule]
fn remit_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonicalize, m)?)?;
    m.add_function(wrap_pyfunction!(remit_id, m)?)?;
    m.add_function(wrap_pyfunction!(capacity, m)?)?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    m.add_function(wrap_pyfunction!(check_sql, m)?)?;
    m.add_function(wrap_pyfunction!(bind_sql, m)?)?;
    Ok(())
}
