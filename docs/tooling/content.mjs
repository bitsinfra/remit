import { globSync, mkdirSync, readFileSync, readdirSync, unlinkSync, watch, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { externalPages } from './navigation.mjs';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const content = join(repo, 'docs/.content');
const guideDirs = ['docs'];

export function prepareContent(watchChanges = false) {
  // Keep one source of truth for the guides and SDK READMEs while restricting
  // the Next.js build and Fumadocs watcher to the documentation project.
  function sync() {
    const paths = new Set(Object.keys(externalPages));
    for (const dir of guideDirs) {
      for (const name of readdirSync(join(repo, dir))) {
        if (/\.mdx?$/.test(name)) paths.add(join(dir, name));
      }
    }
    for (const path of paths) {
      const target = join(content, path);
      const markdown = readMarkdown(path);
      const title = markdown.match(/^# (.+)$/m)?.[1];
      if (!title) throw new Error(`Missing page title in ${path}`);
      const page = `---\ntitle: ${JSON.stringify(title)}\n---\n\n${markdown}`;
      mkdirSync(dirname(target), { recursive: true });
      try {
        if (readFileSync(target, 'utf8') === page) continue;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      writeFileSync(target, page);
    }
    for (const old of globSync('**/*.{md,mdx}', { cwd: content })) {
      if (!paths.has(old)) unlinkSync(join(content, old));
    }
  }
  sync();
  if (watchChanges) {
    const dirs = new Set([...guideDirs, ...Object.keys(externalPages).map(dirname)]);
    let timer;
    for (const dir of dirs) {
      watch(join(repo, dir), { persistent: false }, (_, name) => {
        if (!name || /\.(?:mdx?|ts|py)$/.test(name)) {
          clearTimeout(timer);
          timer = setTimeout(sync, 60);
        }
      });
    }
  }
}

// Runnable examples are printed from the files readers execute, not maintained twice.
export function readMarkdown(path) {
  return readFileSync(join(repo, path), 'utf8').replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').replace(
    /<!-- example: (examples\/[\w/.-]+) -->/g,
    (_, example) => {
      const language = example.endsWith('.py') ? 'python' : example.endsWith('.ts') ? 'ts' : 'text';
      return '```' + language + '\n' + readFileSync(join(repo, example), 'utf8').trimEnd() + '\n```';
    },
  );
}
