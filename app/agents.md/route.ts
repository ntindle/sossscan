import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/agents.md as Markdown, at /agents.md and for requests to /agents that ask for Markdown (proxy.ts).
 * It's the same for everyone, so it's prerendered at build time.
 */
export const dynamic = 'force-static';
export const GET = markdownRoute('/agents');
