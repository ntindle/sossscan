import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/docs/cli.md as Markdown, at /docs/cli.md and for requests to /docs/cli that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/docs/cli');
