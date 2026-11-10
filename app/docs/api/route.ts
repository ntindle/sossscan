import { pageRoute } from '@/lib/pages.ts';

/**
 * content/docs/api.md as a web page (lib/pages.ts). It renders per request, from a copy kept in memory, so that Vercel
 * keeps its Vary: Accept; a prerendered route would lose it. The CDN still keeps each answer for a day.
 */
export const dynamic = 'force-dynamic';
export const GET = pageRoute('/docs/api');
