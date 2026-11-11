/** Small helpers for the route handlers: the API's errors, JSON bodies, query values and the CSRF check. */
import { NextResponse } from 'next/server';

/**
 * What went wrong, as a code a program can branch on, with what it means. A code keeps its meaning, and a new kind of
 * error gets a new code. The first group is what the public API returns (lib/openapi.ts lists them in its Error
 * schema); the rest come from the GitHub App's endpoints under /api/app/, which only the site's page calls.
 */
export const ERROR_CODES = {
  invalid_request: "The request body isn't a JSON object, or a field in it is missing or the wrong length.",
  invalid_repo: "The repository isn't given as OWNER/REPO or a github.com URL.",
  not_found: 'No API endpoint has this address.',
  method_not_allowed: "The endpoint doesn't take this HTTP method. The Allow header lists the ones it takes.",
  repo_not_found:
    'GitHub has no public repository by this name. A private repository gets the same answer, so the API never shows whether one exists.',
  scan_failed: "The scan has no results: GitHub refused or rate-limited its first request, or didn't answer it.",
  rate_limited: 'Too many requests from your IP address. The Retry-After header says how many seconds to wait.',
  internal_error: 'Something went wrong on the server.',
  scanner_busy: 'The scans this server instance runs at once were all busy for the 2 minutes the request waited.',

  missing_header: "The X-Requested-With header that the site's page sends is missing.",
  sign_in_required: "There's no GitHub sign-in, or it has expired.",
  not_admin: 'The signed-in person is not an admin of the repository.',
  app_not_configured: 'This copy of the site has no GitHub App, so sign-in is off.',
  app_not_installed: "The GitHub App isn't installed on the repository.",
  app_permission_missing: "The GitHub App doesn't have a permission the fix needs.",
  preview_expired: 'The pull request preview is more than 15 minutes old, or someone else made it.',
  fix_failed: "The fix can't be made on the repository as it is now, or the AI agent didn't finish it.",
  ai_limit_reached: "Today's AI fixes for this person, or the site's monthly budget for them, are used up.",
  ai_unavailable: "AI fixes aren't set up on this site, or the AI service didn't answer.",
  github_error: "GitHub didn't answer, or refused a request the server made.",
  server_misconfigured: 'The site is missing SOSF_SECRET, so sign-in is off.',
} as const satisfies Record<string, string>;
export type ErrorCode = keyof typeof ERROR_CODES;

/**
 * Why a request can't go ahead: a code for programs, the message (what went wrong) and the hint (what to do next) for
 * people. Routes answer with errorBody().
 */
export class HttpError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly hint: string;
  readonly headers: Record<string, string>;
  constructor(status: number, code: ErrorCode, message: string, hint: string, headers: Record<string, string> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.hint = hint;
    this.headers = headers;
  }
}

/**
 * The body of every error the API sends. `detail` repeats the message: clients written before `error` existed read it,
 * and so does the site's page from an older copy.
 */
export function errorBody(e: HttpError): {
  error: { code: ErrorCode; message: string; hint: string };
  detail: string;
} {
  return { error: { code: e.code, message: e.message, hint: e.hint }, detail: e.message };
}

/** An error as a response. Nothing may keep it: a cache would hand one person's refusal to the next. */
export function errorJson(e: HttpError): NextResponse {
  return NextResponse.json(errorBody(e), { status: e.status, headers: { 'Cache-Control': 'no-store', ...e.headers } });
}

/** A crash: what every route answers when something throws that isn't an HttpError. */
export function internalError(): HttpError {
  return new HttpError(
    500,
    'internal_error',
    'Something went wrong on the server.',
    'Try again in a minute. If it keeps happening, open an issue at https://github.com/ntindle/sossscan/issues.',
  );
}

export function errorResponse(e: unknown): NextResponse {
  if (e instanceof HttpError) return errorJson(e);
  console.error(e);
  return errorJson(internalError());
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

/** An address under /api/ that no endpoint has (app/api/[[...path]]/route.ts). */
export function noEndpoint(): HttpError {
  return new HttpError(
    404,
    'not_found',
    "There's no API endpoint at this address.",
    'Use one of the endpoints listed at /openapi.json.',
  );
}

/** Every method Next.js hands to a route's handlers (next/dist/server/web/http.js). */
export const METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;
export type Method = (typeof METHODS)[number];

/** What an endpoint answers with Allow: its methods, HEAD with GET (Next.js runs GET for it), and OPTIONS. */
export function allowHeader(taken: readonly ('GET' | 'POST')[]): string {
  return [...taken, ...(taken.includes('GET') ? ['HEAD'] : []), 'OPTIONS'].sort().join(', ');
}

export function methodNotAllowed(method: string, taken: readonly ('GET' | 'POST')[]): HttpError {
  return new HttpError(
    405,
    'method_not_allowed',
    `This endpoint doesn't take ${method} requests.`,
    `Send a ${taken.join(' or ')} request instead.`,
    { Allow: allowHeader(taken) },
  );
}

/**
 * Handlers for the methods an API route doesn't take, to export beside its own: `export const { POST, PUT, PATCH,
 * DELETE, OPTIONS } = otherMethods('GET');`. Without them Next.js answers an empty 405; these send the API's error,
 * with Allow, and OPTIONS answers 204 with the same Allow, as Next.js's own would.
 */
export function otherMethods(...taken: ('GET' | 'POST')[]): Record<Method, () => Response> {
  const refuse = (method: Method) => () => errorJson(methodNotAllowed(method, taken));
  return {
    GET: refuse('GET'),
    HEAD: refuse('HEAD'),
    POST: refuse('POST'),
    PUT: refuse('PUT'),
    DELETE: refuse('DELETE'),
    PATCH: refuse('PATCH'),
    OPTIONS: () => new Response(null, { status: 204, headers: { Allow: allowHeader(taken) } }),
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
  if (req.headers.get('x-requested-with') !== 'sosf') {
    throw new HttpError(
      400,
      'missing_header',
      'The X-Requested-With header is missing.',
      'Send the header X-Requested-With: sosf.',
    );
  }
}

export async function jsonBody(req: Request): Promise<Record<string, unknown>> {
  let data: unknown;
  try {
    data = await req.json();
  } catch {
    throw new HttpError(
      422,
      'invalid_request',
      "The request body isn't valid JSON.",
      'Send a JSON object as the request body.',
    );
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(
      422,
      'invalid_request',
      'The request body is JSON, but not an object.',
      'Send a JSON object as the request body.',
    );
  }
  return data as Record<string, unknown>;
}

/** A required string field of a JSON body, with a length check. */
export function field(
  data: Record<string, unknown>,
  key: string,
  { min = 0, max }: { min?: number; max: number },
): string {
  const v = data[key];
  const range = min > 0 ? `${min} to ${max}` : `up to ${max}`;
  if (typeof v !== 'string') {
    throw new HttpError(
      422,
      'invalid_request',
      `${key} is missing, or isn't a string.`,
      `Send "${key}" in the JSON body, as a string of ${range} characters.`,
    );
  }
  if (v.length < min || v.length > max) {
    throw new HttpError(
      422,
      'invalid_request',
      `${key} is ${v.length} characters long.`,
      `Send a ${key} of ${range} characters.`,
    );
  }
  return v;
}

/**
 * An optional query value, with a length check and an optional pattern. Only the sign-in routes read them, from links
 * the page or GitHub made.
 */
export function queryValue(url: URL, key: string, { max, pattern }: { max: number; pattern?: RegExp }): string | null {
  const v = url.searchParams.get(key);
  if (v === null) return null;
  if (v.length > max || (pattern && !pattern.test(v))) {
    throw new HttpError(
      422,
      'invalid_request',
      `The ${key} parameter isn't valid.`,
      "Start again from the site's page.",
    );
  }
  return v;
}

/** Python's urllib.parse.quote: percent-encode everything except letters, digits, "_.-~" and the `safe` characters. */
export function quote(s: string, safe = '/'): string {
  return encodeURIComponent(s)
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%2F/gi, (m) => (safe.includes('/') ? '/' : m));
}
