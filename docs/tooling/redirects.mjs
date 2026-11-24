import { copyFile, glob, mkdir, readdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { externalPages, pageId, sidebar } from './navigation.mjs';
import { readMarkdown } from './content.mjs';
import { resolveLink } from './markdown.mjs';

// Serve /<page>.html beside /<page>/, so links written either way keep working.
const output = resolve('out');
for await (const file of glob('**/index.html', { cwd: output })) {
  const id = file.split('/').slice(0, -1).join('/');
  if (!id || id === '404' || id === '_not-found') continue;
  const url = `/${id}/`;
  const html = `<!doctype html><html lang="en"><meta charset="utf-8">
<title>Page moved · Remit Docs</title><meta name="robots" content="noindex">
<script>location.replace(${JSON.stringify(url)} + location.search + location.hash)</script>
<meta http-equiv="refresh" content="0;url=${url}"><a href="${url}">Open the documentation</a></html>`;
  await writeFile(resolve(output, id + '.html'), html);
}

const repo = resolve('..');
const paths = [...Object.keys(externalPages), ...(await readdir('.')).filter(p => /\.mdx?$/.test(p)).map(p => 'docs/' + p)];
const pages = paths.map(path => {
  const markdown = readMarkdown(path).replace(/(\[[^\]\n]+\]\()([^\s)]+)(\))/g,
    (_, start, url, end) => start + resolveLink(path, url, true) + end);
  return { path, id: pageId(path), markdown, title: markdown.match(/^# (.+)$/m)?.[1] };
});
for (const page of pages) {
  const target = resolve(output, page.id + '.md');
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, page.markdown);
}
const index = ['# Remit documentation', '', '> An agent-to-agent protocol: signed programs, typed results and signed receipts.', '',
  'Research preview. Specification 0.1; wire version 0.1.',
  'Start with installation and a first exchange. SDK and specification pages are built from their repository sources.', '',
  '[Complete documentation](https://remit.bitsinfra.com/llms-full.txt)', ''];
for (const group of sidebar) {
  index.push('## ' + group.label, '');
  for (const item of group.items) {
    const id = typeof item === 'string' ? item : item.slug;
    const page = pages.find(p => p.id === id);
    index.push(`- [${typeof item === 'string' ? page.title : item.label}](https://remit.bitsinfra.com/${id}.md)`);
  }
  index.push('');
}
await writeFile(resolve(output, 'llms.txt'), index.join('\n'));
await writeFile(resolve(output, 'llms-full.txt'), pages.map(p => `<!-- source: ${p.path} -->\n\n${p.markdown}`).join('\n\n---\n\n'));
for await (const file of glob('spec/**/*.{json,wit,proto}', { cwd: repo })) {
  const target = resolve(output, file);
  await mkdir(dirname(target), { recursive: true });
  await copyFile(resolve(repo, file), target);
}
console.log(`Exported ${pages.length} Markdown pages, llms.txt, llms-full.txt and protocol artifacts.`);
