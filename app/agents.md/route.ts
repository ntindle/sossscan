import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/agents.md as Markdown, at /agents.md and for requests to /agents that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/agents');
