import { markdownRoute } from '@/lib/pages.ts';

/**
 * The home page as Markdown (lib/home.ts): its Markdown twin, and what / sends to requests that ask for Markdown
 * (proxy.ts). It's the same for everyone, so it's prerendered at build time.
 */
export const dynamic = 'force-static';
export const GET = markdownRoute('/');
