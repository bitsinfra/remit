// Search then fetch, in one remit: BM25 over the KB, join back through the
// policy view, and return at most three short passages.
import { Remit, t } from "../../sdk/ts/src/index.ts";

const remit = new Remit({ identity: await Remit.identity.fromEnv() });
const kb = await remit.holder(process.env.HOLDER ?? "http://127.0.0.1:8446");
console.log("indexes:", kb.catalog.indexes);
const r = await kb.kernel<{ doc: string; text: { unwrap(): string } }[]>({
  reads: {
    hits: kb.sql`SELECT c.doc AS doc, c.body AS body, s.score AS score
                 FROM fts('kb', ${t.param("q", "string")}, 5) s JOIN docs.chunks c ON c.chunk_id = s.id
                 ORDER BY s.score DESC`.maxRows(5),
  },
  params: { q: "refund annual plan" },
  source: `export default function main({ hits }, p) {
    return hits({ q: p.q }).rows().slice(0, 3).map(r => ({ doc: r.doc, text: r.body.slice(0, 160) }));
  }`,
  returns: t.list(t.struct({ doc: t.enum(...kb.enums("docs.chunks.doc")), text: t.string({ max_len: 160, charset: "ascii" }) }), { max: 3 }),
  purpose: "support",
});
for (const p of r.value) console.log(`[${p.doc}] ${p.text.unwrap()}`);
console.log("≤", r.receipt.result_bits_max, "bits; labels", r.labels);
