import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/about.md as Markdown, at /about.md and for requests to /about that ask for Markdown (proxy.ts).
 * It's the same for everyone, so it's prerendered at build time.
 */
export const dynamic = 'force-static';
export const GET = markdownRoute('/about');
