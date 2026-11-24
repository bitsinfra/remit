//! Holder functions: pure, deterministic functions a Holder offers to kernels
//! (`embed`, `geocode`, `fx-rate`, …). They run in the trusted plane, are
//! priced in fuel, scoped per principal group, and size-capped.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use remit_kernel::ReadErr;
use serde_json::Value;

/// Implemented by the Holder for each function it offers.
#[async_trait::async_trait]
pub trait HolderFunction: Send + Sync {
    /// Must be pure: same args, same answer (results are cacheable and replayable).
    async fn call(&self, args: Value) -> Result<Value, String>;
}

#[async_trait::async_trait]
impl<F> HolderFunction for F
where
    F: Fn(Value) -> Result<Value, String> + Send + Sync,
{
    async fn call(&self, args: Value) -> Result<Value, String> {
        self(args)
    }
}

#[derive(Clone)]
pub struct FunctionDef {
    pub description: String,
    /// Fuel charged per call (on top of the per-byte price of the result).
    pub fuel: u64,
    /// Groups that may call it (empty: everyone).
    pub visible_to: Vec<String>,
    pub f: Arc<dyn HolderFunction>,
}

/// Cap on encoded arguments and results.
pub const MAX_BYTES: usize = 256 * 1024;

#[derive(Default, Clone)]
pub struct Functions(BTreeMap<String, FunctionDef>);

impl std::fmt::Debug for Functions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl Functions {
    pub fn insert(&mut self, name: &str, def: FunctionDef) {
        self.0.insert(name.to_string(), def);
    }

    pub fn get(&self, name: &str) -> Option<&FunctionDef> {
        self.0.get(name)
    }

    pub fn visible(&self, groups: &[String]) -> BTreeSet<String> {
        self.0
            .iter()
            .filter(|(_, d)| {
                d.visible_to.is_empty() || d.visible_to.iter().any(|g| groups.contains(g))
            })
            .map(|(n, _)| n.clone())
            .collect()
    }

    pub fn price(&self, name: &str) -> Option<u64> {
        self.0.get(name).map(|d| d.fuel)
    }

    pub async fn call(&self, name: &str, args: Value) -> Result<Value, ReadErr> {
        let d = self.0.get(name).ok_or(ReadErr::Denied)?;
        if args.to_string().len() > MAX_BYTES {
            return Err(ReadErr::ParamType);
        }
        // Error details stay on the Holder side.
        let out = d.f.call(args).await.map_err(|e| {
            tracing::warn!(function = name, "holder function failed: {e}");
            ReadErr::Internal
        })?;
        if out.to_string().len() > MAX_BYTES {
            return Err(ReadErr::RowCap);
        }
        Ok(out)
    }
}
