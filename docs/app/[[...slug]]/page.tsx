import type { AnchorHTMLAttributes } from 'react';
import { notFound } from 'next/navigation';
import { DocsBody, DocsPage, DocsTitle } from 'fumadocs-ui/page';
import defaultComponents from 'fumadocs-ui/mdx';
import { Tab, Tabs } from 'fumadocs-ui/components/tabs';
import { source } from '../../lib/source';

type Props = { params: Promise<{ slug?: string[] }> };

export function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata({ params }: Props) {
  const page = source.getPage((await params).slug);
  if (!page) notFound();
  return { title: page.data.title, description: page.data.description };
}

function GuideLink(props: AnchorHTMLAttributes<HTMLAnchorElement>) {
  // Machine-readable exports and standalone references are files, not app routes.
  if (props.href?.startsWith('/') && /\.(?:md|txt|json|wit|proto)(?:[?#]|$)/.test(props.href)) return <a {...props} />;
  if (props.href?.startsWith('/api/') && props.href.endsWith('.html')) return <a {...props} />;
  return <defaultComponents.a {...props} />;
}

export default async function Page({ params }: Props) {
  const page = source.getPage((await params).slug);
  if (!page) notFound();
  const { body: Content, title, toc } = page.data;

  return (
    <DocsPage toc={toc}>
      <DocsTitle>{title}</DocsTitle>
      <DocsBody>
        <Content components={{ ...defaultComponents, a: GuideLink, Tabs, Tab }} />
      </DocsBody>
    </DocsPage>
  );
}
