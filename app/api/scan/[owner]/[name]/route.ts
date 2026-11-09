import { type NextRequest, NextResponse } from 'next/server';
import { HttpError, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { parseRepo, SCAN_TTL, scanOr404 } from '@/lib/public-scan.ts';

export const maxDuration = 300;

/**
 * The same scan at an address a CDN can cache: Vercel keeps each repo's result for 6 hours, so repeat visits don't
 * reach the server or spend its GitHub quota. Errors aren't cached.
 */
export const GET = route(async (req: NextRequest, ctx: { params: Promise<{ owner: string; name: string }> }) => {
  const limited = rateLimit(req, 'scan');
  if (limited) return limited;
  const { owner, name } = await ctx.params;
  if (owner.length > 39 || name.length > 100) throw new HttpError(422, 'Expected OWNER/REPO or a github.com URL');
  const rep = await scanOr404(parseRepo(`${owner}/${name}`), false);
  return NextResponse.json(rep, {
    headers: { 'Cache-Control': `public, max-age=0, s-maxage=${SCAN_TTL}, stale-while-revalidate=600` },
  });
});
