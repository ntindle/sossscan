import { markdownRoute } from '@/lib/pages.ts';

/**
 * The home page as Markdown (lib/home.ts), at /index.md and for requests to / that ask for Markdown (proxy.ts). It
 * renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/');
