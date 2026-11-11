import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/docs/mcp.md as Markdown, at /docs/mcp.md and for requests to /docs/mcp that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/docs/mcp');
