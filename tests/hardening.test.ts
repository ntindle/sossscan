/** The public site's hardening: security headers, per-address rate limits, input checks and retired pages. */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import config, { CSP, RETIRED } from '@/next.config.ts';
import { HttpError } from '@/lib/http.ts';
import { clientIp } from '@/lib/limits.ts';
import { parseRepo } from '@/lib/public-scan.ts';
import { Browser, useTestEnv } from './helpers.ts';

vi.mock('@/lib/public-scan.ts', async (original) => ({
  ...(await original<typeof import('@/lib/public-scan.ts')>()),
  scanOr404: async (repo: string) => ({ repo, results: { x: {} }, cached: false }),
}));

useTestEnv();

const PUBLIC = path.join(process.cwd(), 'public');

it('gives every page and file the security headers', async () => {
  const rules = await config.headers!();
  const all = rules.find((r) => r.source === '/:path*')!;
  const h = Object.fromEntries(all.headers.map((x) => [x.key, x.value]));
  expect(h['Content-Security-Policy']).toBe(CSP);
  expect(CSP).toContain("script-src 'self' 'sha256-");
  expect(CSP).toContain("frame-ancestors 'none'");
  expect(CSP).not.toContain('unsafe-eval');
  expect(h['X-Frame-Options']).toBe('DENY');
  expect(h['X-Content-Type-Options']).toBe('nosniff');
});

it('allows every inline script by its hash, and no others', () => {
  const pages = fs
    .readdirSync(PUBLIC, { recursive: true, encoding: 'utf8' })
    .filter((f) => f.endsWith('.html'))
    .map((f) => fs.readFileSync(path.join(PUBLIC, f), 'utf8'));
  const inline = pages.reduce((n, p) => n + (p.split('<script>').length - 1), 0);
  expect(inline).toBeGreaterThanOrEqual(1);
  expect(CSP.split("'sha256-").length - 1).toBe(inline);
});

it('rate-limits public scans per address', async () => {
  const c = new Browser();
  const codes = [];
  for (let i = 0; i < 7; i++) codes.push((await c.post('/api/scan', { repo: 'octo/demo' }, {})).status);
  expect(codes).toEqual([200, 200, 200, 200, 200, 200, 429]);
  const r = await c.post('/api/scan', { repo: 'octo/demo' }, {});
  expect(r.status).toBe(429);
  expect(Number(r.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  expect(r.headers.get('cache-control')).toBe('no-store'); // a CDN must never keep a refusal
  expect((await c.get('/api/scan/octo/demo')).status).toBe(429); // the cacheable address counts too
});

it('lets a CDN cache GET scans, but not POST ones', async () => {
  const c = new Browser();
  const got = await c.get('/api/scan/octo/demo');
  expect(got.status).toBe(200);
  expect(got.headers.get('cache-control')).toBe('public, max-age=0, s-maxage=21600, stale-while-revalidate=600');
  const posted = await c.post('/api/scan', { repo: 'https://github.com/octo/demo.git', refresh: true }, {});
  expect(posted.headers.get('cache-control')).toBe('no-store');
  expect((await posted.json()).repo).toBe('octo/demo');
  expect((await c.post('/api/scan', { repo: 'not a repo' }, {})).status).toBe(422);
  expect((await c.post('/api/scan', { nope: 1 }, {})).status).toBe(422);
});

it('only trusts proxy headers when told to', () => {
  const headers = new Headers({ 'fly-client-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.1, 10.0.0.1' });
  expect(clientIp(headers)).toBe('direct'); // anyone can send these, so they don't count
  process.env.TRUST_PROXY_HEADERS = '1';
  expect(clientIp(headers)).toBe('203.0.113.9');
  expect(clientIp(new Headers({ 'x-forwarded-for': '198.51.100.1, 10.0.0.1' }))).toBe('198.51.100.1');
  delete process.env.TRUST_PROXY_HEADERS;
  process.env.VERCEL = '1';
  expect(clientIp(new Headers({ 'x-vercel-forwarded-for': '192.0.2.4', 'x-forwarded-for': '198.51.100.1' }))).toBe(
    '192.0.2.4',
  );
});

describe('parseRepo', () => {
  it.each([
    ['octo/demo', 'octo/demo'],
    [' https://github.com/octo/demo ', 'octo/demo'],
    ['github.com/octo/demo.git', 'octo/demo'],
    ['https://www.github.com/octo/demo/tree/main/src', 'octo/demo'],
    ['octo/demo.js', 'octo/demo.js'],
  ])('accepts %j', (raw, repo) => expect(parseRepo(raw)).toBe(repo));

  it.each([
    'octo',
    'octo/..',
    '-octo/demo',
    'https://evil.example/octo/demo',
    'octo/demo extra',
    `${'a'.repeat(40)}/x`,
  ])('refuses %j', (raw) => expect(() => parseRepo(raw)).toThrow(HttpError));
});

it('sends retired pages to the home page, keeping their query', async () => {
  const redirects = await config.redirects!();
  expect(redirects.map((r) => r.source)).toEqual(RETIRED);
  for (const r of redirects) expect(r).toMatchObject({ destination: '/', statusCode: 302 });
  const rewrites = (await config.rewrites!()) as { beforeFiles: { source: string; destination: string }[] };
  expect(rewrites.beforeFiles).toContainEqual({ source: '/', destination: '/index.html' });
});

it("never bundles a server's own secrets or caches into a deployment", () => {
  // The code reads .cache/ at run time, so without these excludes the build's file tracer copies whatever the building
  // machine has there. The server no longer reads .secrets/, but an old copy may linger (a local `vercel build` once
  // picked up the GitHub App's private key from it).
  const excludes = Object.values(config.outputFileTracingExcludes || {}).flat();
  expect(excludes).toEqual(expect.arrayContaining(['.secrets/**', '.cache/**']));
  expect(Object.keys(config.outputFileTracingExcludes || {})).toContain('**');
});

it('serves the pipeline map as the home page', () => {
  const page = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');
  expect(page).toContain('<script type="module" src="/pipeline/pipeline.js">');
  expect(page).not.toContain('Report card');
});
