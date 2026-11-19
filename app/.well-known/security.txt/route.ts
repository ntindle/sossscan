import { securityTxt } from '@/lib/security-txt.ts';

/**
 * /.well-known/security.txt (lib/security-txt.ts). Next.js prerenders it when the site builds, so its Expires date
 * counts from the build: every deploy renews it, and a site nobody has deployed for a year says its details may be
 * out of date.
 */
export const dynamic = 'force-static';

export function GET(): Response {
  return new Response(securityTxt(new Date()), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
