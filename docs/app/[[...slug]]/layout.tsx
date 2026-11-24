import type { ReactNode } from 'react';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { tree } from '../../lib/source';

export default function GuideLayout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={tree}
      nav={{ url: '/', title: <><img src="/remit.svg" width="22" height="22" alt="" /> Remit Docs</> }}
      githubUrl="https://github.com/bitsinfra/remit"
    >
      {children}
    </DocsLayout>
  );
}
