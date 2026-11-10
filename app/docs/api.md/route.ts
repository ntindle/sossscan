import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/docs/api.md as Markdown, at /docs/api.md and for requests to /docs/api that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/docs/api');
