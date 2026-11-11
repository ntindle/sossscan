import { errorJson, noEndpoint } from '@/lib/http.ts';

/**
 * Every address under /api/, and /api itself, that no other route answers, whatever the method: a 404 in the API's
 * error format, for programs that can't read the site's 404 page (app/[...path]/route.ts). Next.js tries this after the
 * API's own routes, so it never shadows them, and the methods those don't take get their own 405 (otherMethods).
 */
export const dynamic = 'force-dynamic';

function notFound(): Response {
  return errorJson(noEndpoint());
}

export const GET = notFound;
export const POST = notFound;
export const PUT = notFound;
export const PATCH = notFound;
export const DELETE = notFound;
export const OPTIONS = notFound;
