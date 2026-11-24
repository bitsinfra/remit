// CRM: partners get aggregates only, and only when the planner enforces k >= 20 (or DP).
@id("crm:partners")
permit (principal in Remit::Group::"partners", action == Remit::Action::"aggregate", resource in Remit::Dataset::"crm")
when { context.aggregate_only && (context.min_group_size >= 20 || context.epsilon_milli > 0) };

// Kernels may post-process aggregates (growth rates, ratios) for partners.
@id("crm:partner-kernels")
permit (principal in Remit::Group::"partners", action == Remit::Action::"run_kernel", resource in Remit::Dataset::"crm")
when { context.aggregate_only && context.min_group_size >= 20 && context.result_bits <= 1024 };

// HR data never leaves to anyone but HR agents (no such resource here; shown for the preset pattern).
@id("hr:fence")
forbid (principal, action, resource in Remit::Dataset::"hr")
unless { principal in Remit::Group::"hr-agents" };

@id("finance:partners")
permit (principal in Remit::Group::"partners", action == Remit::Action::"aggregate", resource in Remit::Dataset::"finance")
when { resource.dp && context.aggregate_only && context.epsilon_milli > 0 && context.epsilon_milli <= 1000 };
