import { type NextRequest, NextResponse } from 'next/server';
import { count, fromBrowser } from '@/lib/counts.ts';
import { otherMethods, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import {
  cacheable,
  invalidRepo,
  NAME_MAX,
  OWNER_MAX,
  parseRepo,
  SCAN_CACHE_CONTROL,
  scanOr404,
} from '@/lib/public-scan.ts';

export const maxDuration = 300;

/**
 * The same scan at an address a CDN can cache: Vercel keeps each repo's result for 6 hours, so repeat visits don't
 * reach the server or spend its GitHub quota. Errors aren't cached, and neither is a scan GitHub rate-limited, whose
 * answers may be wrong. A program's scan is counted when it reaches the server; the page counts its own.
 */
export const GET = route(async (req: NextRequest, ctx: { params: Promise<{ owner: string; name: string }> }) => {
  const limited = rateLimit(req, 'scan');
  if (limited) return limited;
  const { owner, name } = await ctx.params;
  if (owner.length > OWNER_MAX || name.length > NAME_MAX) throw invalidRepo();
  const rep = await scanOr404(parseRepo(`${owner}/${name}`), false);
  if (!fromBrowser(req.headers)) count(req, 'api_scan', { refresh: false });
  return NextResponse.json(rep, { headers: { 'Cache-Control': cacheable(rep) ? SCAN_CACHE_CONTROL : 'no-store' } });
});

export const { POST, PUT, PATCH, DELETE, OPTIONS } = otherMethods('GET');
