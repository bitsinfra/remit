// Count how many of `mine` (SHA-256 of normalized emails) are B's customers,
// optionally per country. Answers below 10 are suppressed to 0 by the Sender's
// own kernel (the Holder's bit budget bounds repeated probing).
export default function main({ customers }, p) {
  const theirs = new Set(customers({}).col("email_sha256"));
  let n = 0;
  for (const h of p.mine) if (theirs.has(h)) n++;
  return n < 10 ? 0 : n;
}
