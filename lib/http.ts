/** Small helpers for the route handlers: errors with a status, JSON bodies, query values and the CSRF check. */
import { NextResponse } from 'next/server';

/** Why a request can't go ahead, in words for the person who made it. Routes answer with {"detail": message}. */
export class HttpError extends Error {
  readonly status: number;
  readonly headers: Record<string, string>;
  constructor(status: number, detail: string, headers: Record<string, string> = {}) {
    super(detail);
    this.status = status;
    this.headers = headers;
  }
}

export function errorResponse(e: unknown): NextResponse {
  if (e instanceof HttpError) return NextResponse.json({ detail: e.message }, { status: e.status, headers: e.headers });
  console.error(e);
  return NextResponse.json({ detail: 'Something went wrong on the server. Try again in a minute.' }, { status: 500 });
}

/** Wrap a route handler so an HttpError (or a crash) becomes a JSON error response. */
export function route<A extends unknown[]>(fn: (...args: A) => Promise<Response> | Response) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (e) {
      return errorResponse(e);
    }
  };
}

/** JSON for one signed-in person (or about them): never cached anywhere. */
export function privateJson(data: unknown, status = 200): NextResponse {
  return NextResponse.json(data, { status, headers: { 'Cache-Control': 'private, no-store' } });
}

/** A redirect with the Location exactly as given: a site-relative path stays relative, like the old server sent. */
export function redirect(location: string, status = 303): NextResponse {
  return new NextResponse(null, { status, headers: { Location: location } });
}

/** Requests that change something must come from the page's own script, which sets this header. */
export function csrf(req: Request): void {
  if (req.headers.get('x-requested-with') !== 'sosf') throw new HttpError(400, 'Missing X-Requested-With header');
}

export async function jsonBody(req: Request): Promise<Record<string, unknown>> {
  let data: unknown;
  try {
    data = await req.json();
  } catch {
    throw new HttpError(422, 'Expected a JSON body');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new HttpError(422, 'Expected a JSON object');
  return data as Record<string, unknown>;
}

/** A required string field of a JSON body, with a length check. */
export function field(
  data: Record<string, unknown>,
  key: string,
  { min = 0, max }: { min?: number; max: number },
): string {
  const v = data[key];
  if (typeof v !== 'string') throw new HttpError(422, `${key} is required`);
  if (v.length < min || v.length > max) throw new HttpError(422, `${key} must be ${min} to ${max} characters long`);
  return v;
}

/** An optional query value, with a length check and an optional pattern. */
export function queryValue(url: URL, key: string, { max, pattern }: { max: number; pattern?: RegExp }): string | null {
  const v = url.searchParams.get(key);
  if (v === null) return null;
  if (v.length > max || (pattern && !pattern.test(v))) throw new HttpError(422, `${key} isn't valid`);
  return v;
}

/** Python's urllib.parse.quote: percent-encode everything except letters, digits, "_.-~" and the `safe` characters. */
export function quote(s: string, safe = '/'): string {
  return encodeURIComponent(s)
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%2F/gi, (m) => (safe.includes('/') ? '/' : m));
}
