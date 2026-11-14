import type { NextRequest } from 'next/server';
import { count, pageEvent } from '@/lib/counts.ts';
import { csrf, HttpError, jsonBody, otherMethods, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

export const dynamic = 'force-dynamic';

/** An event is a few short fields: anything longer isn't one the page sent. */
const MAX_BODY_BYTES = 2048;

/**
 * Where the page reports what it counts (lib/counts.ts): one event per request, which the server passes on to PostHog
 * with nothing about who sent it. Only the page's own script sends these (it sets X-Requested-With, like the app's
 * requests), and the answer is always empty, whether or not the event was counted.
 */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'count');
  if (limited) return limited;
  csrf(req);
  const text = await req.text();
  if (Buffer.byteLength(text) > MAX_BODY_BYTES) {
    throw new HttpError(
      422,
      'invalid_request',
      `The request body is over ${MAX_BODY_BYTES / 1024} KiB.`,
      "Send one event, as the site's page does.",
    );
  }
  const [event, details] = pageEvent(await jsonBody(new Response(text)));
  count(req, event, details);
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
});

export const { GET, PUT, PATCH, DELETE, OPTIONS } = otherMethods('POST');
