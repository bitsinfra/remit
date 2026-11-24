// Partners may run overlap kernels: they see hashed emails inside the
// sandbox, but only a ≤ 32-bit answer leaves.
@id("overlap:partners")
permit (principal in Remit::Group::"partners", action in [Remit::Action::"read", Remit::Action::"run_kernel"], resource == Remit::Table::"crm.customers")
when {
  context.mode == "kernel" &&
  context.purpose == "overlap" &&
  context.result_bits <= 32 &&
  ["email_sha256", "country"].containsAll(context.columns)
};
