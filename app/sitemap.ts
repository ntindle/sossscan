import type { MetadataRoute } from 'next';
import { PAGES, SITE } from '@/lib/pages.ts';

/**
 * /sitemap.xml (https://www.sitemaps.org/protocol.html): the home page and every text page. Each has a <lastmod> when
 * git could date its content as the site was built (PAGE_DATES in next.config.ts, which hands them over as
 * SITEMAP_LASTMOD), and none otherwise. The Markdown twins aren't listed: they name their page as canonical.
 * Next.js serves this as application/xml and prerenders it when the site builds.
 */
export default function sitemap(): MetadataRoute.Sitemap {
  const dates: Record<string, string> = JSON.parse(process.env.SITEMAP_LASTMOD || '{}');
  return ['/', ...PAGES.map((page) => page.path)].map((path) =>
    dates[path] ? { url: `${SITE}${path}`, lastModified: dates[path] } : { url: `${SITE}${path}` },
  );
}
