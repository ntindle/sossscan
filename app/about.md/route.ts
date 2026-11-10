import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/about.md as Markdown, at /about.md and for requests to /about that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/about');
