import { statSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { visit } from 'unist-util-visit';
import { externalPages, pageId } from './navigation.mjs';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const repoUrl = 'https://github.com/bitsinfra/remit';

export function resolveLink(original, href, markdown = false) {
  if (/^(?:[a-z][a-z0-9+.-]*:|[/#?])/i.test(href)) return href;
  const [, path, suffix] = /^([^?#]+)(.*)$/.exec(href);
  const destination = resolve(repo, dirname(original), decodeURIComponent(path));
  const source = relative(repo, destination);
  if ((source.startsWith('docs/') && /\.mdx?$/.test(source)) || externalPages[source]) {
    const id = pageId(source);
    return (markdown ? `/${id}.md` : id === 'index' ? '/' : `/${id}/`) + suffix;
  }
  if (/^spec\/.*\.(json|wit|proto)$/.test(source)) return `/${source}${suffix}`;
  const kind = statSync(destination, { throwIfNoEntry: false })?.isDirectory() ? 'tree' : 'blob';
  return `${repoUrl}/${kind}/main/${source}${suffix}`;
}

export function repositoryMarkdown() {
  return (tree, file) => {
    const heading = tree.children.findIndex((node) => node.type === 'heading' && node.depth === 1);
    if (heading !== -1) tree.children.splice(heading, 1);

    // Cedar's policy/schema grammars are not bundled with the shared highlighter.
    visit(tree, 'code', (node) => {
      if (node.lang === 'cedar' || node.lang === 'cedarschema') node.lang = 'text';
    });

    // Resolve Markdown links from their source files, including READMEs outside docs/.
    visit(tree, ['link', 'definition'], (node) => {
      const original = relative(resolve(repo, 'docs/.content'), file.path);
      node.url = resolveLink(original, node.url);
    });
  };
}
