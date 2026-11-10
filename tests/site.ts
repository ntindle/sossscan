/**
 * The whole site in-process: serve() answers a request the way Next.js puts the answer together
 * (node_modules/next/dist/docs/01-app/03-api-reference/03-file-conventions/proxy.md, "Execution order"):
 * 1. headers from next.config.ts, matched against the address that was asked for;
 * 2. redirects;
 * 3. proxy.ts, when its matcher matches: an answer of its own, a rewrite, or on to the page;
 * 4. beforeFiles rewrites (/ is /index.html);
 * 5. a file in public/, then /sitemap.xml and the routes in app/ (routeFor in helpers.ts, the catch-all last).
 * A route's headers join the config's as Next's server joins them (next/dist/server/send-response.js): Vary is
 * appended, and any other header is added only if the config hasn't set it. HEAD runs GET and sends no body, as Next
 * does for a route without its own HEAD handler. The dev server answers the same (curl against next dev).
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

const matches = (source: string, pathname: string) => getPathMatch(source)(pathname) !== false;

/** Whether the proxy runs for this address, by Next's own matcher logic. */
export function proxyRuns(target: string): boolean {
  return testing.unstable_doesMiddlewareMatch({ config: proxyConfig, url: target, nextConfig: config });
}

export async function serve(
  target: string,
  { method = 'GET', headers = {} }: { method?: string; headers?: Record<string, string> } = {},
): Promise<Response> {
  const url = new URL(target, 'http://127.0.0.1:3340');
  let pathname = url.pathname;

  const fromConfig = new Headers();
  for (const rule of await config.headers!()) {
    if (matches(rule.source, pathname)) for (const { key, value } of rule.headers) fromConfig.set(key, value);
  }
  const answer = (res: Response): Response => {
    const out = new Headers(fromConfig);
    res.headers.forEach((value, name) => {
      if (name.startsWith('x-middleware-')) return;
      if (name === 'vary') out.append(name, value);
      else if (!out.has(name)) out.set(name, value);
    });
    return new Response(method === 'HEAD' ? null : res.body, { status: res.status, headers: out });
  };

  for (const rule of await config.redirects!()) {
    if (matches(rule.source, pathname)) {
      const status = 'statusCode' in rule && rule.statusCode ? rule.statusCode : 307;
      return answer(new Response(null, { status, headers: { Location: rule.destination } }));
    }
  }

  if (proxyRuns(url.pathname + url.search)) {
    const res = proxy(new NextRequest(url, { method, headers })) as NextResponse;
    if (testing.isRewrite(res)) pathname = new URL(testing.getRewrittenUrl(res)!).pathname;
    else if (!res.headers.has('x-middleware-next')) return answer(res);
  }

  const { beforeFiles = [] } = (await config.rewrites!()) as {
    beforeFiles?: { source: string; destination: string }[];
  };
  for (const rule of beforeFiles) if (matches(rule.source, pathname)) pathname = rule.destination;

  const file = path.join(process.cwd(), 'public', pathname);
  if ((method === 'GET' || method === 'HEAD') && fs.existsSync(file) && fs.statSync(file).isFile()) {
    const type = FILE_TYPES[path.extname(file)] ?? 'application/octet-stream';
    return answer(new Response(fs.readFileSync(file), { headers: { 'Content-Type': type } }));
  }

  if (pathname === '/sitemap.xml') {
    const { default: sitemap } = await import('@/app/sitemap.ts');
    return answer(new Response(resolveSitemap(sitemap()), { headers: { 'Content-Type': 'application/xml' } }));
  }

  const [pattern, load] = routeFor(pathname)!;
  const route = await load();
  const handler = route[method] ?? (method === 'HEAD' ? route.GET : undefined);
  if (!handler) return answer(new Response(null, { status: 405 }));
  const request = new NextRequest(new URL(pathname + url.search, url), { method, headers });
  const [, owner = '', name = ''] = pattern.exec(pathname)!;
  return answer(await handler(request, { params: Promise.resolve({ owner, name }) }));
}
