import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/docs/cli.md as Markdown, at /docs/cli.md and for requests to /docs/cli that ask for Markdown (proxy.ts).
 * It's the same for everyone, so it's prerendered at build time.
 */
export const dynamic = 'force-static';
export const GET = markdownRoute('/docs/cli');
