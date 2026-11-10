import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/privacy.md as Markdown, at /privacy.md and for requests to /privacy that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/privacy');
