import { pageRoute } from '@/lib/pages.ts';

/** content/docs/cli.md as a web page (lib/pages.ts). It's the same for everyone, so it's prerendered at build time. */
export const dynamic = 'force-static';
export const GET = pageRoute('/docs/cli');
