import type { MetadataRoute } from 'next';
import { source } from '../lib/source';
import { site } from '../lib/site';

export const dynamic = 'force-static';

export default function sitemap(): MetadataRoute.Sitemap {
  // Pages are served with a trailing slash; list the canonical form.
  return source.getPages().map((page) => ({ url: site + page.url.replace(/\/?$/, '/') }));
}
