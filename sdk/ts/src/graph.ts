// Sender-orchestrated multi-Holder graphs: run remits across Holders where
// later steps take earlier *typed* results as params. The combined result
// carries the meet of every step's labels/terms and the chain of verified
// receipts, so provenance survives composition. (Holder-to-Holder
// pipelining, where results never return to the Sender, is a research item.)

import type { Holder, RemitResult } from "./client.ts";

export interface GraphStep<C> {
  name: string;
  holder: Holder;
  /** Build and run this step from earlier step values. */
  run: (h: Holder, ctx: C) => Promise<RemitResult<unknown>>;
}

export interface GraphResult<C> {
  values: C;
  labels: string[];
  terms: { retain_days?: number; forward: boolean };
  provenance: { step: string; holder: string; remit_id: string; run_id: string; result_sha256?: string }[];
}

/** Run steps in order (each sees the typed values of the steps before it). */
export async function runGraph<C extends Record<string, unknown>>(steps: GraphStep<C>[]): Promise<GraphResult<C>> {
  const values: Record<string, unknown> = {};
  const labels = new Set<string>();
  let retain: number | undefined;
  let forward = true;
  const provenance: GraphResult<C>["provenance"] = [];
  for (const s of steps) {
    const r = await s.run(s.holder, values as C);
    values[s.name] = r.value;
    for (const l of r.labels) labels.add(l);
    if (r.terms.retain_days !== undefined) retain = retain === undefined ? r.terms.retain_days : Math.min(retain, r.terms.retain_days);
    forward &&= r.terms.forward;
    provenance.push({ step: s.name, holder: s.holder.id, remit_id: r.receipt.remit_id, run_id: r.receipt.run_id, result_sha256: r.receipt.result_sha256 });
  }
  return { values: values as C, labels: [...labels].sort(), terms: { ...(retain !== undefined ? { retain_days: retain } : {}), forward }, provenance };
}
