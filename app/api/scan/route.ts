import { type NextRequest, NextResponse } from 'next/server';
import { field, jsonBody, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { parseRepo, scanOr404 } from '@/lib/public-scan.ts';

export const maxDuration = 300;

/** Scan a public repo. With refresh, ignore every cache; the page's Rescan button uses this. */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'scan');
  if (limited) return limited;
  const body = await jsonBody(req);
  const rep = await scanOr404(parseRepo(field(body, 'repo', { min: 3, max: 200 })), body.refresh === true);
  return NextResponse.json(rep, { headers: { 'Cache-Control': 'no-store' } });
});
