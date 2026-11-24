// Find up to three free slots of `minutes` length between 09:00 and 18:00 UTC.
// Build: `remit-ts build kernels/free-slots.ts` → free-slots.remit.json
type Row = { start_at: Date; end_at: Date };
type Reads = { busy: (p: { from: Date; until: Date }) => { rows(): Row[] } };
type Params = { from: Date; until: Date; minutes: number };
type Result = { start: Date; end: Date }[];

export const remit = {
  purpose: "scheduling",
  reads: {
    busy: {
      sql: "SELECT start_at, end_at FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'",
      params: { from: "timestamp", until: "timestamp" },
      max_rows: 500,
    },
  },
  limits: { wall: "250ms", memory: "16MiB", fuel: 50_000_000, output: "1KiB" },
  returns: {
    list: { max: 3, of: { struct: {
      start: { timestamp: { min: "$from", max: "$until", granularity: "15m" } },
      end: { timestamp: { min: "$from", max: "$until", granularity: "15m" } },
    } } },
  },
};

export default function main({ busy }: Reads, p: Params): Result {
  const H = 3_600_000, need = p.minutes * 60_000, step = 15 * 60_000;
  const taken = busy(p).rows().map((r) => [+r.start_at, +r.end_at]).sort((a, b) => a[0] - b[0]);
  const out: Result = [];
  for (let day = +p.from; day < +p.until && out.length < 3; day += 24 * H) {
    let t = day + 9 * H;
    const close = day + 18 * H;
    for (const [s, e] of taken) {
      if (e <= t || s >= close) continue;
      if (s - t >= need && out.length < 3) out.push({ start: new Date(t), end: new Date(t + need) });
      t = Math.max(t, Math.ceil(e / step) * step);
    }
    if (out.length < 3 && close - t >= need) out.push({ start: new Date(t), end: new Date(t + need) });
  }
  return out;
}
