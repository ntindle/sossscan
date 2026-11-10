import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/contact.md as Markdown, at /contact.md and for requests to /contact that ask for Markdown (proxy.ts).
 * It's the same for everyone, so it's prerendered at build time.
 */
export const dynamic = 'force-static';
export const GET = markdownRoute('/contact');
