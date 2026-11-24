// Alice's vault: verified scheduling agents may see busy intervals, nothing else.
@id("alice:calendar")
permit (
  principal in Remit::Group::"verified-agents",
  action in [Remit::Action::"read", Remit::Action::"run_kernel"],
  resource == Remit::Table::"calendar.events"
) when {
  ["start_at", "end_at", "status"].containsAll(context.columns) &&
  context.purpose == "scheduling" &&
  context.result_bits <= 128 &&
  context.max_rows_total <= 1000
};

// Health: weekly aggregates only, for coaching agents Alice approved.
@id("alice:health")
permit (principal in Remit::Group::"verified-agents", action == Remit::Action::"aggregate", resource == Remit::Table::"health.steps")
when { context.aggregate_only && context.min_group_size >= 7 && context.standing_approval };
