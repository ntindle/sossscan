import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/contact.md as Markdown, at /contact.md and for requests to /contact that ask for Markdown (proxy.ts).
 * It renders per request, from a copy kept in memory, so that Vercel keeps its Vary: Accept (lib/pages.ts).
 */
export const dynamic = 'force-dynamic';
export const GET = markdownRoute('/contact');
