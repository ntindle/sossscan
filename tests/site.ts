/**
 * The whole site in-process: serve() answers a request the way the server puts the answer together
 * (node_modules/next/dist/docs/01-app/03-api-reference/03-file-conventions/proxy.md, "Execution order"):
 * 1. headers from next.config.ts, matched against the address that was asked for;
 * 2. redirects;
 * 3. proxy.ts, when its matcher matches: an answer of its own, a rewrite, or on to the page;
 * 4. beforeFiles rewrites (/ is /index.html);
 * 5. a file in public/, then /sitemap.xml and the routes in app/ (routeFor in helpers.ts, the catch-all last).
 * HEAD runs GET and sends no body, as Next.js does for a route without its own HEAD handler.
 *
 * `host` picks whose rules join the headers, each one checked with curl against a real server:
 * - 'next' (next dev, next start): the config's headers, then the Vary Next.js adds to every answer from app/
 *   (setVaryHeader in next/dist/server/base-server.js), then the route's own. Vary is appended; any other header of the
 *   route's is added only if the config hasn't set it (next/dist/server/send-response.js).
 * - 'next-loopback' (next start --hostname 127.0.0.1, as the local service runs): the same, except a rewrite from the
 *   proxy. Next.js writes loopback hosts as localhost in the proxy's URLs (next/dist/server/web/next-url.js), so the
 *   rewrite no longer matches the server's own address and counts as external (router-utils/resolve-routes.js). The
 *   server fetches the new address as a request of its own (router-utils/proxy-request.js), and that answer's headers
 *   replace the ones set so far.
 * - 'vercel': rewrites stay internal and the config's headers are matched against the address asked for, but Vary
 *   comes from the answer itself. A file in public/ keeps the config's. A prerendered route is sent with the Vary
 *   Next.js gives it, in place of the config's and the route's. A route that renders per request keeps the Vary it
 *   sets, without Next.js's, and nothing here relies on the config's reaching it. (Seen on the live site: the home
 *   page's file had Vary: Accept, prerendered pages only Next.js's list, and the 404 route only its own Vary: Accept.)
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import fs from 'node:fs';
import path from 'node:path';
import { resolveSitemap } from 'next/dist/build/webpack/loaders/metadata/resolve-route-data.js';
import { getPathMatch } from 'next/dist/shared/lib/router/utils/path-match.js';
import { NextRequest, type NextResponse } from 'next/server';
import config from '@/next.config.ts';
import { config as proxyConfig, proxy } from '@/proxy.ts';
import { routeFor } from './helpers.ts';

// Next's testing helpers load its request storage, which expects the global Next.js sets up when it runs.
(globalThis as { AsyncLocalStorage?: unknown }).AsyncLocalStorage ??= AsyncLocalStorage;
const testing = await import('next/experimental/testing/server');

/** What Next.js sends a file in public/ as. */
const FILE_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=UTF-8',
  '.txt': 'text/plain; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.mjs': 'application/javascript; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.md': 'text/markdown; charset=UTF-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

/** The Vary Next.js gives every answer from app/ (setVaryHeader), and a prerendered one on Vercel. */
export const APP_VARY = 'rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch';

export type Host = 'next' | 'next-loopback' | 'vercel';
/** Where an answer comes from: a file in public/, a route that renders per request, a prerendered route, the proxy. */
type Source = 'file' | 'route' | 'prerendered' | 'proxy';

const matches = (source: string, pathname: string) => getPathMatch(source)(pathname) !== false;

/** Whether the proxy runs for this address, by Next's own matcher logic. */
export function proxyRuns(target: string): boolean {
  return testing.unstable_doesMiddlewareMatch({ config: proxyConfig, url: target, nextConfig: config });
}

export async function serve(
  target: string,
  {
    method = 'GET',
    headers = {},
    body,
    host = 'next',
  }: { method?: string; headers?: Record<string, string>; body?: BodyInit; host?: Host } = {},
): Promise<Response> {
  const url = new URL(target, 'http://127.0.0.1:3340');
  let pathname = url.pathname;

  const fromConfig = new Headers();
  for (const rule of await config.headers!()) {
    if (matches(rule.source, pathname)) for (const { key, value } of rule.headers) fromConfig.set(key, value);
  }
  const answer = (res: Response, source: Source): Response => {
    const out = new Headers(fromConfig);
    // Vary is a list Next.js adds values to, skipping one that's already there (appendHeader in
    // next/dist/server/base-http/node.js).
    let vary = fromConfig.has('vary') && !(host === 'vercel' && source !== 'file') ? [fromConfig.get('vary')!] : [];
    const addVary = (value: string) => {
      if (!vary.includes(value)) vary.push(value);
    };
    if (host !== 'vercel' && (source === 'route' || source === 'prerendered')) addVary(APP_VARY);
    res.headers.forEach((value, name) => {
      if (name.startsWith('x-middleware-')) return;
      if (name === 'vary') addVary(value);
      else if (!out.has(name)) out.set(name, value);
    });
    if (host === 'vercel' && source === 'prerendered') vary = [APP_VARY];
    out.delete('vary');
    if (vary.length) out.set('vary', vary.join(', '));
    return new Response(method === 'HEAD' ? null : res.body, { status: res.status, headers: out });
  };

  for (const rule of await config.redirects!()) {
    if (matches(rule.source, pathname)) {
      const status = 'statusCode' in rule && rule.statusCode ? rule.statusCode : 307;
      return answer(new Response(null, { status, headers: { Location: rule.destination } }), 'proxy');
    }
  }

  if (proxyRuns(url.pathname + url.search)) {
    const res = proxy(new NextRequest(url, { method, headers })) as NextResponse;
    if (testing.isRewrite(res)) {
      const to = new URL(testing.getRewrittenUrl(res)!);
      if (host === 'next-loopback') {
        const fetched = await serve(to.pathname + to.search, { method, headers, body, host });
        const out = new Headers(fromConfig);
        fetched.headers.forEach((value, name) => out.set(name, value));
        return new Response(fetched.body, { status: fetched.status, headers: out });
      }
      pathname = to.pathname;
    } else if (!res.headers.has('x-middleware-next')) {
      return answer(res, 'proxy');
    }
  }

  const { beforeFiles = [] } = (await config.rewrites!()) as {
    beforeFiles?: { source: string; destination: string }[];
  };
  for (const rule of beforeFiles) if (matches(rule.source, pathname)) pathname = rule.destination;

  const file = path.join(process.cwd(), 'public', pathname);
  if ((method === 'GET' || method === 'HEAD') && fs.existsSync(file) && fs.statSync(file).isFile()) {
    const type = FILE_TYPES[path.extname(file)] ?? 'application/octet-stream';
    return answer(new Response(fs.readFileSync(file), { headers: { 'Content-Type': type } }), 'file');
  }

  if (pathname === '/sitemap.xml') {
    const { default: sitemap } = await import('@/app/sitemap.ts');
    const xml = new Response(resolveSitemap(sitemap()), { headers: { 'Content-Type': 'application/xml' } });
    return answer(xml, 'prerendered');
  }

  const [pattern, load] = routeFor(pathname)!;
  const route = await load();
  const source: Source = route.dynamic === 'force-static' ? 'prerendered' : 'route';
  const handler = route[method] ?? (method === 'HEAD' ? route.GET : undefined);
  if (!handler) return answer(new Response(null, { status: 405 }), source);
  const request = new NextRequest(new URL(pathname + url.search, url), { method, headers, body });
  const [, owner = '', name = ''] = pattern.exec(pathname)!;
  return answer(await handler(request, { params: Promise.resolve({ owner, name }) }), source);
}
