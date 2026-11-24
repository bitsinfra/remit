//! Policy presets, so most Holders never write Cedar from scratch.

/// Always-on guard rails (defense in depth on top of the read plane).
pub const BASE: &str = r#"
@id("base:aggregate-only")
forbid (principal, action, resource)
when { resource.aggregate_only && !context.aggregate_only };

@id("base:operations")
forbid (principal, action == Remit::Action::"aggregate", resource)
when { !resource.operations.contains("aggregate") && !resource.operations.contains("read") };

@id("base:read-op")
forbid (principal, action == Remit::Action::"read", resource)
when { !resource.operations.contains("read") };

@id("base:search-op")
forbid (principal, action == Remit::Action::"search", resource)
when { !resource.operations.contains("search") };

@id("base:bits")
forbid (principal, action, resource)
when { context.result_bits > resource.max_bits };

@id("base:purpose")
forbid (principal, action, resource)
when { !resource.purposes.isEmpty() && !resource.purposes.contains(context.purpose) };
"#;

pub fn preset(name: &str) -> Option<&'static str> {
    Some(match name {
        // Verified agents may see what the catalog exposes, for a declared
        // purpose, under the resource's bit cap.
        "personal-vault" => {
            r#"
@id("preset:personal-vault")
permit (
  principal in Remit::Group::"verified-agents",
  action in [Remit::Action::"read", Remit::Action::"run_kernel"],
  resource
) when {
  context.result_bits <= resource.max_bits &&
  context.max_rows_total <= 10000
};
"#
        }
        // Aggregates only, and only when the planner enforces k (or DP).
        "aggregate-only" => {
            r#"
@id("preset:aggregate-only")
permit (principal, action == Remit::Action::"aggregate", resource)
when {
  context.aggregate_only &&
  ((resource.k > 0 && context.min_group_size >= resource.k) || context.epsilon_milli > 0)
};

@id("preset:aggregate-only-kernel")
permit (principal, action == Remit::Action::"run_kernel", resource)
when { context.aggregate_only && resource.k > 0 && context.min_group_size >= resource.k };
"#
        }
        "dp-analytics" => {
            r#"
@id("preset:dp-analytics")
permit (principal, action == Remit::Action::"aggregate", resource)
when { resource.dp && context.aggregate_only && context.epsilon_milli > 0 && context.epsilon_milli <= 1000 };
"#
        }
        "owner-rows-only" => {
            r#"
@id("preset:owner-rows-only")
permit (principal, action in [Remit::Action::"read", Remit::Action::"run_kernel"], resource)
when { resource.owner_scoped };
"#
        }
        "internal-trusted" => {
            r#"
@id("preset:internal-trusted")
permit (principal in Remit::Group::"internal", action, resource);
"#
        }
        _ => return None,
    })
}

pub const PRESETS: [&str; 5] = [
    "personal-vault",
    "aggregate-only",
    "dp-analytics",
    "owner-rows-only",
    "internal-trusted",
];

/// Assemble the effective policy text: base + presets + Holder files.
pub fn assemble(presets: &[String], files: &[(String, String)]) -> Result<String, String> {
    let mut out = String::from(BASE);
    for p in presets {
        out.push_str(preset(p).ok_or_else(|| {
            format!(
                "unknown policy preset `{p}` (available: {})",
                PRESETS.join(", ")
            )
        })?);
    }
    for (name, text) in files {
        out.push_str(&format!("\n// ---- {name}\n"));
        out.push_str(text);
        out.push('\n');
    }
    Ok(out)
}
