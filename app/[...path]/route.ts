import { notFound } from '@/lib/pages.ts';

/**
 * Every address that no file in public/ and no other route answers: a 404, as Markdown for requests that ask for it and
 * as a page in the site's style otherwise (lib/pages.ts). Next.js tries this catch-all last, after public/ and every
 * other route, so it never shadows them. It reads the Accept header, so it runs per request and isn't cached.
 */
export const dynamic = 'force-dynamic';
export const GET = notFound;
export const POST = notFound;
export const PUT = notFound;
export const PATCH = notFound;
export const DELETE = notFound;
export const OPTIONS = notFound;
