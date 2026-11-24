// GBNF grammar for constrained decoding of Remit SQL against one catalog:
// relations and columns come from the catalog, functions from the profile.
// Optional: for self-hosted models that support grammar-constrained sampling.

const lit = (s: string) => JSON.stringify(s);
const alt = (xs: string[]) => (xs.length ? xs.map(lit).join(" | ") : '""');

export function sqlGrammar(catalog: any): string {
  const tables: string[] = (catalog.resources ?? []).map((r: any) => r.name);
  const cols = [...new Set<string>((catalog.resources ?? []).flatMap((r: any) => (r.columns ?? []).map((c: any) => c.name)))];
  const enums = [...new Set<string>((catalog.resources ?? []).flatMap((r: any) => (r.columns ?? []).flatMap((c: any) => c.enum ?? [])))];
  return `# Remit SQL for ${catalog.holder} (${catalog.catalog_sha256}); generated, do not edit.
root ::= "SELECT " ("DISTINCT ")? items " FROM " from where? group? having? order? limit?
items ::= item (", " item)*
item ::= expr (" AS " ident)?
from ::= table (" " ident)? (join)*
join ::= (" JOIN " | " LEFT JOIN ") table (" " ident)? " ON " cond
table ::= ${alt(tables)}
where ::= " WHERE " cond
group ::= " GROUP BY " expr (", " expr)*
having ::= " HAVING " cond
order ::= " ORDER BY " expr (" DESC" | " ASC")? (", " expr (" DESC" | " ASC")?)*
limit ::= " LIMIT " [0-9]+
cond ::= pred ((" AND " | " OR ") pred)*
pred ::= "(" cond ")" | "NOT " pred | expr cmp expr | expr " IS NULL" | expr " IS NOT NULL" | expr " BETWEEN " expr " AND " expr | expr " IN (" value (", " value)* ")" | expr " LIKE " string
cmp ::= " = " | " <> " | " < " | " <= " | " > " | " >= "
expr ::= term ((" + " | " - " | " * " | " / ") term)*
term ::= agg | func | "CASE WHEN " cond " THEN " expr " ELSE " expr " END" | column | param | value | "(" expr ")"
agg ::= "COUNT(*)" | ("COUNT" | "SUM" | "AVG" | "MIN" | "MAX" | "MEDIAN" | "STDDEV") "(" ("DISTINCT ")? expr ")"
func ::= ("ABS" | "ROUND" | "FLOOR" | "CEIL" | "COALESCE" | "LOWER" | "UPPER" | "LENGTH" | "DATE_TRUNC" | "DATE_PART" | "GREATEST" | "LEAST") "(" expr (", " expr)* ")"
column ::= (ident ".")? (${alt(cols)})
param ::= "$" ident
value ::= [0-9]+ ("." [0-9]+)? | string | "TRUE" | "FALSE"
string ::= ${enums.length ? `${alt(enums.map((e) => `'${e.replace(/'/g, "''")}'`))} | ` : ""}"'" [A-Za-z0-9 _%.:-]* "'"
ident ::= [a-z_] [a-z0-9_]*
`;
}
