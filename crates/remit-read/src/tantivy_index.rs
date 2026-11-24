//! Tantivy full-text scoring over a pinned snapshot (in-memory index).

use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, FAST, STORED,
};
use tantivy::tokenizer::{LowerCaser, SimpleTokenizer, Stemmer, TextAnalyzer};
use tantivy::{doc, Index, IndexReader, TantivyDocument, Term};

pub struct TantivyIndex {
    reader: IndexReader,
    body: Field,
    ord: Field,
    analyzer: TextAnalyzer,
}

impl std::fmt::Debug for TantivyIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TantivyIndex")
    }
}

fn analyzer() -> TextAnalyzer {
    TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .filter(Stemmer::default())
        .build()
}

impl TantivyIndex {
    pub fn build(texts: impl Iterator<Item = String>) -> tantivy::Result<Self> {
        let mut sb = Schema::builder();
        let opts = TextOptions::default().set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("remit_en")
                .set_index_option(IndexRecordOption::WithFreqs),
        );
        let body = sb.add_text_field("body", opts);
        let ord = sb.add_u64_field("ord", STORED | FAST);
        let index = Index::create_in_ram(sb.build());
        index.tokenizers().register("remit_en", analyzer());
        // One thread, one segment order: deterministic across builds.
        let mut w = index.writer_with_num_threads(1, 20_000_000)?;
        for (i, t) in texts.enumerate() {
            w.add_document(doc!(body => t, ord => i as u64))?;
        }
        w.commit()?;
        Ok(TantivyIndex {
            reader: index.reader()?,
            body,
            ord,
            analyzer: analyzer(),
        })
    }

    /// Top documents by BM25. The query is a bag of terms: no query language is
    /// exposed to Senders.
    pub fn search(&self, query: &str, k: usize) -> Vec<(usize, f64)> {
        let mut terms: Vec<String> = Vec::new();
        let mut a = self.analyzer.clone();
        let mut ts = a.token_stream(query);
        while ts.advance() {
            terms.push(ts.token().text.clone());
        }
        if terms.is_empty() || k == 0 {
            return vec![];
        }
        terms.truncate(64);
        let clauses: Vec<(Occur, Box<dyn Query>)> = terms
            .iter()
            .map(|t| {
                (
                    Occur::Should,
                    Box::new(TermQuery::new(
                        Term::from_field_text(self.body, t),
                        IndexRecordOption::WithFreqs,
                    )) as Box<dyn Query>,
                )
            })
            .collect();
        let s = self.reader.searcher();
        let Ok(hits) = s.search(
            &BooleanQuery::new(clauses),
            &TopDocs::with_limit(k).order_by_score(),
        ) else {
            return vec![];
        };
        let mut out: Vec<(usize, f64)> = hits
            .into_iter()
            .filter_map(|(sc, a)| {
                Some((
                    s.doc::<TantivyDocument>(a)
                        .ok()?
                        .get_first(self.ord)?
                        .as_u64()? as usize,
                    sc as f64,
                ))
            })
            .collect();
        out.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}
