import { NextResponse, type NextRequest } from 'next/server';
import { markdownPath, negotiate, NOT_ACCEPTABLE } from './lib/negotiate.ts';

/**
 * Markdown content negotiation (https://acceptmarkdown.com) for the home page and the text pages, the only paths this
 * runs on (config.matcher). A GET or HEAD whose Accept header prefers Markdown is rewritten to the page's Markdown
 * twin, /index.md for the home page and /about.md for /about. One that rules out both HTML and Markdown gets 406.
 * Everything else, HTML requests included, goes on to the page as before.
 *
 * Why a rewrite to a separate address: the home page's HTML is a file in public/, which can't read the request, and
 * with each representation at its own address behind the scenes, a cache keyed on that address can't mix them. On
 * Vercel this runs before the CDN cache, whose key also includes the Accept header
 * (https://vercel.com/docs/caching/cdn-cache). Browsers and other caches only see the page's own address, so every
 * answer there carries Vary: Accept: the routes set it themselves (lib/pages.ts), next.config.ts adds it to the home
 * page's file, and the 406 below sets its own.
 */
export function proxy(request: NextRequest): Response {
  const { pathname } = request.nextUrl;
  const page = config.matcher.includes(pathname);
  if (!page || (request.method !== 'GET' && request.method !== 'HEAD')) return NextResponse.next();
  const chosen = negotiate(request.headers.get('accept'));
  if (chosen === 'html') return NextResponse.next();
  if (chosen === 'markdown') {
    const url = request.nextUrl.clone();
    url.pathname = markdownPath(pathname);
    return NextResponse.rewrite(url);
  }
  return new NextResponse(request.method === 'HEAD' ? null : NOT_ACCEPTABLE, {
    status: 406,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', Vary: 'Accept' },
  });
}

/** The home page and every page in PAGES (lib/pages.ts); a test keeps them in step. Next.js needs a literal list. */
export const config = {
  matcher: ['/', '/about', '/contact', '/privacy', '/docs', '/docs/api', '/docs/cli', '/agents'],
};
