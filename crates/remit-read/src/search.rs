//! Holder search resources: `fts(index, query, k)` (BM25 full-text) and
//! `knn(index, vector, k)` (cosine over a vector column) as DataFusion table
//! functions.
//!
//! **Policy stays in the plan.** A search function returns only `(id, score)`;
//! Senders join back through the resource's policy view to read columns, so
//! hidden columns, masks, row/owner filters and k-thresholds still apply.
//! Indexes are built from the trusted snapshot over columns that the view
//! exposes unmasked, and are visible only to principals who can see the table.
//! Using one requires the `search` operation (a Cedar action) on the table.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use datafusion::arrow::array::{Float64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::{TableFunctionArgs, TableFunctionImpl, TableProvider};
use datafusion::datasource::MemTable;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::logical_expr::Expr;
use datafusion::scalar::ScalarValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::RawTable;
use crate::ReadError;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IndexConfig {
    pub name: String,
    /// fulltext | vector
    pub kind: String,
    /// `source.table`
    pub table: String,
    pub id_column: String,
    #[serde(default)]
    pub text_column: Option<String>,
    /// Vector column: JSON array text (`"[0.1, 0.2]"`) or numbers.
    #[serde(default)]
    pub vector_column: Option<String>,
    /// Full-text engine: `builtin` (default) or `tantivy` (feature `tantivy`).
    #[serde(default)]
    pub engine: Option<String>,
}

pub const MAX_K: usize = 1000;

#[derive(Debug)]
pub struct SearchIndex {
    pub cfg: IndexConfig,
    ids: Vec<String>,
    tf: Vec<HashMap<String, u32>>,
    doc_len: Vec<u32>,
    df: HashMap<String, u32>,
    avgdl: f64,
    vectors: Vec<Vec<f32>>,
    #[cfg(feature = "tantivy")]
    tantivy: Option<crate::tantivy_index::TantivyIndex>,
}

pub fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| stem(&t.to_lowercase()))
        .collect()
}

/// Light English suffix stripping (deterministic, dependency-free).
fn stem(t: &str) -> String {
    for suf in ["ing", "ed", "es", "s"] {
        if t.len() > suf.len() + 3 && t.ends_with(suf) {
            return t[..t.len() - suf.len()].to_string();
        }
    }
    t.to_string()
}

impl SearchIndex {
    pub fn build(cfg: &IndexConfig, raw: &RawTable) -> Result<Self, ReadError> {
        let col = |name: &str| -> Result<usize, ReadError> {
            raw.schema.index_of(name).map_err(|_| {
                ReadError::Config(format!(
                    "index `{}`: column `{name}` not in `{}`",
                    cfg.name, cfg.table
                ))
            })
        };
        let id_ix = col(&cfg.id_column)?;
        let (mut ids, mut tf, mut doc_len, mut vectors) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut df: HashMap<String, u32> = HashMap::new();
        let text_ix = cfg.text_column.as_deref().map(col).transpose()?;
        let vec_ix = cfg.vector_column.as_deref().map(col).transpose()?;
        match cfg.kind.as_str() {
            "fulltext" if text_ix.is_none() => {
                return Err(ReadError::Config(format!(
                    "index `{}`: fulltext needs `text_column`",
                    cfg.name
                )))
            }
            "vector" if vec_ix.is_none() => {
                return Err(ReadError::Config(format!(
                    "index `{}`: vector needs `vector_column`",
                    cfg.name
                )))
            }
            "fulltext" | "vector" => {}
            k => {
                return Err(ReadError::Config(format!(
                    "index `{}`: unknown kind `{k}` (fulltext | vector)",
                    cfg.name
                )))
            }
        }
        for b in raw.batches.iter() {
            for r in 0..b.num_rows() {
                let id = crate::arrowconv::cell(b.column(id_ix).as_ref(), r);
                let id = match id {
                    Value::String(s) => s,
                    Value::Null => continue,
                    v => v.to_string(),
                };
                ids.push(id);
                if let Some(ti) = text_ix {
                    let text = crate::arrowconv::cell(b.column(ti).as_ref(), r);
                    let toks = tokenize(text.as_str().unwrap_or(""));
                    let mut m: HashMap<String, u32> = HashMap::new();
                    for t in &toks {
                        *m.entry(t.clone()).or_default() += 1;
                    }
                    for t in m.keys() {
                        *df.entry(t.clone()).or_default() += 1;
                    }
                    doc_len.push(toks.len() as u32);
                    tf.push(m);
                }
                if let Some(vi) = vec_ix {
                    let v = match crate::arrowconv::cell(b.column(vi).as_ref(), r) {
                        Value::String(s) => {
                            serde_json::from_str::<Vec<f32>>(&s).unwrap_or_default()
                        }
                        Value::Array(a) => a
                            .iter()
                            .filter_map(|x| x.as_f64().map(|f| f as f32))
                            .collect(),
                        _ => vec![],
                    };
                    vectors.push(v);
                }
            }
        }
        match cfg.engine.as_deref() {
            None | Some("builtin") => {}
            Some("tantivy") if cfg!(feature = "tantivy") && cfg.kind == "fulltext" => {}
            Some(e) => {
                return Err(ReadError::Config(format!(
                    "index `{}`: engine `{e}` is not available for {} indexes in this build",
                    cfg.name, cfg.kind
                )))
            }
        }
        #[cfg(feature = "tantivy")]
        let tantivy = match (cfg.engine.as_deref(), text_ix) {
            (Some("tantivy"), Some(ti)) => {
                let texts = raw.batches.iter().flat_map(|b| {
                    (0..b.num_rows())
                        .filter(|r| !crate::arrowconv::cell(b.column(id_ix).as_ref(), *r).is_null())
                        .map(|r| {
                            crate::arrowconv::cell(b.column(ti).as_ref(), r)
                                .as_str()
                                .unwrap_or("")
                                .to_string()
                        })
                        .collect::<Vec<_>>()
                });
                Some(
                    crate::tantivy_index::TantivyIndex::build(texts)
                        .map_err(|e| ReadError::Config(format!("index `{}`: {e}", cfg.name)))?,
                )
            }
            _ => None,
        };
        let avgdl = if doc_len.is_empty() {
            0.0
        } else {
            doc_len.iter().map(|x| *x as f64).sum::<f64>() / doc_len.len() as f64
        };
        Ok(SearchIndex {
            #[cfg(feature = "tantivy")]
            tantivy,
            cfg: cfg.clone(),
            ids,
            tf,
            doc_len,
            df,
            avgdl,
            vectors,
        })
    }

    /// BM25 (k1 = 1.2, b = 0.75).
    ///
    /// With `allowed`, only those documents exist: corpus statistics (N, df,
    /// average length) are computed over them too, so scores reveal nothing
    /// about hidden documents.
    pub fn bm25(
        &self,
        query: &str,
        k: usize,
        allowed: Option<&HashSet<String>>,
    ) -> Vec<(String, f64)> {
        // Tantivy scores with corpus-wide statistics, so it only answers for
        // principals who may see every document; anyone else gets the built-in
        // scorer over their own documents.
        #[cfg(feature = "tantivy")]
        if let (Some(t), None) = (&self.tantivy, allowed) {
            return t
                .search(query, k.min(MAX_K))
                .into_iter()
                .map(|(d, s)| (self.ids[d].clone(), s))
                .collect();
        }
        let q = tokenize(query);
        let docs: Vec<usize> = match allowed {
            Some(a) => (0..self.ids.len())
                .filter(|d| a.contains(&self.ids[*d]))
                .collect(),
            None => (0..self.ids.len()).collect(),
        };
        let n = docs.len() as f64;
        let (dfs, avgdl): (HashMap<&String, f64>, f64) = match allowed {
            Some(_) => (
                q.iter()
                    .map(|t| {
                        (
                            t,
                            docs.iter().filter(|d| self.tf[**d].contains_key(t)).count() as f64,
                        )
                    })
                    .collect(),
                docs.iter().map(|d| self.doc_len[*d] as f64).sum::<f64>() / n.max(1.0),
            ),
            None => (
                q.iter()
                    .map(|t| (t, *self.df.get(t).unwrap_or(&0) as f64))
                    .collect(),
                self.avgdl,
            ),
        };
        let mut scores: Vec<(usize, f64)> = Vec::new();
        for d in docs {
            let m = &self.tf[d];
            let mut s = 0.0;
            for t in &q {
                if let Some(f) = m.get(t) {
                    let df = dfs.get(t).copied().unwrap_or(0.0);
                    let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                    let f = *f as f64;
                    let dl = self.doc_len[d] as f64;
                    s += idf * f * 2.2 / (f + 1.2 * (1.0 - 0.75 + 0.75 * dl / avgdl.max(1e-9)));
                }
            }
            if s > 0.0 {
                scores.push((d, s));
            }
        }
        top(scores, k)
            .into_iter()
            .map(|(d, s)| (self.ids[d].clone(), s))
            .collect()
    }

    pub fn knn(
        &self,
        qv: &[f32],
        k: usize,
        allowed: Option<&HashSet<String>>,
    ) -> Vec<(String, f64)> {
        let qn = qv.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
        let mut scores = Vec::new();
        for (d, v) in self.vectors.iter().enumerate() {
            if v.len() != qv.len()
                || qn == 0.0
                || allowed.is_some_and(|a| !a.contains(&self.ids[d]))
            {
                continue;
            }
            let dot: f64 = v.iter().zip(qv).map(|(a, b)| *a as f64 * *b as f64).sum();
            let vn = v.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
            if vn > 0.0 {
                scores.push((d, dot / (qn * vn)));
            }
        }
        top(scores, k)
            .into_iter()
            .map(|(d, s)| (self.ids[d].clone(), s))
            .collect()
    }
}

fn top(mut v: Vec<(usize, f64)>, k: usize) -> Vec<(usize, f64)> {
    // Deterministic: score desc, then document order.
    v.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    v.truncate(k.min(MAX_K));
    v
}

pub fn result_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("score", DataType::Float64, false),
    ]))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchKind {
    Fts,
    Knn,
}

/// The table function bound to the indexes one principal may see.
#[derive(Debug)]
pub struct SearchFn {
    pub kind: SearchKind,
    pub indexes: BTreeMap<String, Arc<SearchIndex>>,
    pub allowed: Allowed,
}

/// Index name → ids the principal may see (absent: every row of the table).
pub type Allowed = BTreeMap<String, Arc<HashSet<String>>>;

fn lit_str(e: &Expr) -> Option<String> {
    match e {
        Expr::Literal(
            ScalarValue::Utf8(Some(s))
            | ScalarValue::LargeUtf8(Some(s))
            | ScalarValue::Utf8View(Some(s)),
            _,
        ) => Some(s.clone()),
        Expr::Cast(c) => lit_str(&c.expr),
        _ => None,
    }
}

fn lit_int(e: &Expr) -> Option<i64> {
    match e {
        Expr::Literal(v, _) => match v {
            ScalarValue::Int64(Some(x)) => Some(*x),
            ScalarValue::Int32(Some(x)) => Some(*x as i64),
            ScalarValue::UInt64(Some(x)) => Some(*x as i64),
            _ => None,
        },
        Expr::Cast(c) => lit_int(&c.expr),
        _ => None,
    }
}

impl TableFunctionImpl for SearchFn {
    fn call_with_args(&self, args: TableFunctionArgs) -> DfResult<Arc<dyn TableProvider>> {
        let ex = args.exprs();
        let fname = if self.kind == SearchKind::Fts {
            "fts"
        } else {
            "knn"
        };
        if ex.len() != 3 {
            return Err(DataFusionError::Plan(format!(
                "{fname}(index, query, k) takes 3 arguments"
            )));
        }
        let name = lit_str(&ex[0]).ok_or_else(|| {
            DataFusionError::Plan(format!("{fname}: the index name must be a string literal"))
        })?;
        let idx = self
            .indexes
            .get(&name)
            .ok_or_else(|| DataFusionError::Plan(format!("index `{name}` does not exist")))?;
        let want = if self.kind == SearchKind::Fts {
            "fulltext"
        } else {
            "vector"
        };
        if idx.cfg.kind != want {
            return Err(DataFusionError::Plan(format!(
                "index `{name}` is a {} index; use {}",
                idx.cfg.kind,
                if want == "fulltext" { "knn" } else { "fts" }
            )));
        }
        // During analysis params are placeholders: return the (empty) shape.
        let rows = match (lit_str(&ex[1]), lit_int(&ex[2])) {
            (Some(q), Some(k)) if k >= 0 => match self.kind {
                SearchKind::Fts => {
                    idx.bm25(&q, k as usize, self.allowed.get(&name).map(Arc::as_ref))
                }
                SearchKind::Knn => idx.knn(
                    &serde_json::from_str::<Vec<f32>>(&q).unwrap_or_default(),
                    k as usize,
                    self.allowed.get(&name).map(Arc::as_ref),
                ),
            },
            _ => vec![],
        };
        let schema = result_schema();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.0.clone()).collect::<Vec<_>>(),
                )),
                Arc::new(Float64Array::from(
                    rows.iter()
                        .map(|r| (r.1 * 1e6).round() / 1e6)
                        .collect::<Vec<_>>(),
                )),
            ],
        )?;
        Ok(Arc::new(MemTable::try_new(schema, vec![vec![batch]])?))
    }
}

/// Render a typed param as a SQL literal (used to bind table-function
/// arguments, which DataFusion evaluates at planning time). Values are typed
/// scalars validated by `param_scalar`; strings are quote-escaped.
pub fn sql_literal(v: &Value, t: remit_wire::ParamType) -> Option<String> {
    use remit_wire::ParamType as P;
    crate::arrowconv::param_scalar(v, t)?;
    Some(match t {
        P::String => format!("'{}'", v.as_str()?.replace('\'', "''")),
        P::Int | P::Float => serde_json::to_string(v).ok()?,
        P::Bool => v.as_bool()?.to_string(),
        P::Timestamp => format!("TIMESTAMP '{}'", v.as_str()?.replace('\'', "")),
        P::Date => format!("DATE '{}'", v.as_str()?.replace('\'', "")),
    })
}
