import { type NextRequest, NextResponse } from 'next/server';
import { count, fromBrowser } from '@/lib/counts.ts';
import { field, jsonBody, otherMethods, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { parseRepo, REPO_LENGTH, scanOr404 } from '@/lib/public-scan.ts';

export const maxDuration = 300;

/**
 * Scan a public repo. With refresh, ignore every cache; the page's Rescan button uses this. A scan a program asks for
 * is counted here; the page counts its own (lib/counts.ts).
 */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'scan');
  if (limited) return limited;
  const body = await jsonBody(req);
  const refresh = body.refresh === true;
  const rep = await scanOr404(parseRepo(field(body, 'repo', REPO_LENGTH)), refresh);
  if (!fromBrowser(req.headers)) count(req, 'api_scan', { refresh });
  return NextResponse.json(rep, { headers: { 'Cache-Control': 'no-store' } });
});

export const { GET, PUT, PATCH, DELETE, OPTIONS } = otherMethods('POST');
