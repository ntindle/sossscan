import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/terms.md as Markdown, at /terms.md and for requests to /terms that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/terms');
