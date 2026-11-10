import { markdownRoute } from '@/lib/pages.ts';

/**
 * content/privacy.md as Markdown, at /privacy.md and for requests to /privacy that ask for Markdown (proxy.ts).
 * It's the same for everyone, so it's prerendered at build time.
 */
export const dynamic = 'force-static';
export const GET = markdownRoute('/privacy');
