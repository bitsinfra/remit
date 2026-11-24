//! Early JS checks at admission (oxc): syntax errors with locations, no
//! imports, an exported entry function. The engine is the final authority;
//! this gives Senders located diagnostics before anything runs.

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

use crate::Diagnostic;

pub const E_SYNTAX: &str = "RMT-E0601";
pub const E_IMPORT: &str = "RMT-E0602";
pub const E_ENTRY: &str = "RMT-E0603";

fn line_col(src: &str, offset: usize) -> (u64, u64) {
    let before = &src[..offset.min(src.len())];
    let line = before.matches('\n').count() as u64 + 1;
    let col = before
        .rsplit('\n')
        .next()
        .map(|l| l.chars().count())
        .unwrap_or(0) as u64
        + 1;
    (line, col)
}

/// Check kernel source. Returns diagnostics (empty when OK).
pub fn check_js(src: &str, entry: &str) -> Vec<Diagnostic> {
    let alloc = Allocator::default();
    let ret = Parser::new(&alloc, src, SourceType::mjs()).parse();
    let mut out = Vec::new();
    for d in ret.diagnostics.iter() {
        let span = d.labels.first().map(|l| line_col(src, l.offset() as usize));
        out.push(
            Diagnostic::new(
                E_SYNTAX,
                "/code/source",
                format!("SyntaxError: {}", d.message),
            )
            .span(span),
        );
        if out.len() >= 5 {
            break;
        }
    }
    if !out.is_empty() {
        return out;
    }
    let mr = &ret.module_record;
    if !mr.requested_modules.is_empty() || !mr.import_entries.is_empty() {
        out.push(
            Diagnostic::new(E_IMPORT, "/code/source", "imports are not available in kernels")
                .hint("kernels are single, self-contained modules; inline helpers instead of importing them"),
        );
    }
    if let Some(d) = mr.dynamic_imports.first() {
        out.push(
            Diagnostic::new(
                E_IMPORT,
                "/code/source",
                "dynamic import() is not available in kernels",
            )
            .span(Some(line_col(src, d.span.start as usize))),
        );
    }
    let exported: Vec<String> = mr
        .local_export_entries
        .iter()
        .filter_map(|e| match &e.export_name {
            oxc_syntax::module_record::ExportExportName::Name(n) => Some(n.name.to_string()),
            oxc_syntax::module_record::ExportExportName::Default(_) => Some("default".to_string()),
            _ => None,
        })
        .collect();
    let has_entry = if entry == "main" || entry.is_empty() {
        exported.iter().any(|n| n == "default" || n == "main")
    } else {
        exported.iter().any(|n| n == entry)
    };
    if !has_entry {
        out.push(
            Diagnostic::new(
                E_ENTRY,
                "/code/entry",
                format!(
                    "the module does not export `{}`",
                    if entry.is_empty() { "main" } else { entry }
                ),
            )
            .hint("write `export default function main(reads, params) { … }`"),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn js_checks() {
        assert!(check_js("export default function main(r, p) { return 1 }", "main").is_empty());
        assert!(check_js("export function main(r, p) { return 1 }", "main").is_empty());
        let d = check_js("export default function main( {", "main");
        assert_eq!(d[0].code, E_SYNTAX);
        assert_eq!(d[0].span.unwrap().0, 1);
        let d = check_js(
            "import x from 'fs';\nexport default function main() {}",
            "main",
        );
        assert_eq!(d[0].code, E_IMPORT);
        let d = check_js(
            "export default async function main() { await import('x') }",
            "main",
        );
        assert_eq!(d[0].code, E_IMPORT);
        let d = check_js("function main() {}", "main");
        assert_eq!(d[0].code, E_ENTRY);
    }
}
