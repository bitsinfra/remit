import { readFile, stat, glob } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

// Check the actual static export, including search, scripts, images and deep links.
const output = resolve('out');
const errors = new Set();
let pages = 0;
const exists = async path => { try { return (await stat(path)).isFile(); } catch { return false; } };
for await (const file of glob('**/*.html', { cwd: output })) {
  pages++;
  const html = await readFile(resolve(output, file), 'utf8');
  for (const match of html.matchAll(/(?:href|src)="([^"<>]+)"/g)) {
    const href = match[1].replaceAll('&amp;', '&');
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#|\?)/i.test(href)) continue;
    const path = decodeURIComponent(href.split(/[?#]/)[0]);
    if (!path) continue;
    const target = path.startsWith('/') ? resolve(output, '.' + path) : resolve(output, dirname(file), path);
    if (!(await exists(target)) && !(await exists(resolve(target, 'index.html')))) errors.add(`${file}: ${href}`);
  }
}
for (const path of ['index.html','search-index.json','llms.txt','llms-full.txt','spec/schema/manifest.schema.json','quickstart-typescript/index.html','sdks/python/index.html']) {
  if (!(await exists(resolve(output,path)))) errors.add(`Missing required output: ${path}`);
}
if (errors.size) { console.error([...errors].join('\n')); process.exit(1); }
console.log(`Checked ${pages} HTML files: all local page and asset links resolve.`);
