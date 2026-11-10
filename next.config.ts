import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { NextConfig } from 'next';

const PUBLIC = path.join(process.cwd(), 'public');

/** CSP hashes for the pages' few inline scripts, so no other inline script can run. Computed at build time. */
function scriptHashes(): string {
  const found = new Set<string>();
  for (const file of readdirSync(PUBLIC, { recursive: true, encoding: 'utf8' })) {
    if (!file.endsWith('.html')) continue;
    const text = readFileSync(path.join(PUBLIC, file), 'utf8');
    for (const m of text.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)) {
      found.add(`'sha256-${createHash('sha256').update(m[1]).digest('base64')}'`);
    }
  }
  return [...found].sort().join(' ');
}

export const CSP =
  `default-src 'self'; script-src 'self' ${scriptHashes()}; style-src 'self' 'unsafe-inline'; ` +
  "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; " +
  "frame-ancestors 'none'; form-action 'self'";

export const SECURITY_HEADERS = [
  { key: 'Content-Security-Policy', value: CSP },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  ...((process.env.SITE_BASE_URL || '').startsWith('https://')
    ? [{ key: 'Strict-Transport-Security', value: 'max-age=31536000' }]
    : []),
];

/**
 * Retired pages: the ten original designs (2026-11-04), then the report card and the guided wizard (2026-11-05).
 * The pipeline map is now the home page. Old links land on it, keeping their ?repo=.
 */
export const RETIRED = ['/ui/:path+', '/variants', '/variants/:path+', '/wizard', '/wizard/:path+', '/pipeline'];

/** The text pages (lib/pages.ts PAGES), whose route handlers read their Markdown from content/. */
export const TEXT_PAGES = ['/about', '/contact', '/privacy', '/docs', '/docs/api', '/docs/cli'];

const config: NextConfig = {
  poweredByHeader: false,
  // The page is plain files in public/; the server is route handlers only.
  async rewrites() {
    return { beforeFiles: [{ source: '/', destination: '/index.html' }] };
  },
  async redirects() {
    return RETIRED.map((source) => ({ source, destination: '/', statusCode: 302 as const }));
  },
  // These reach the CDN's copies of public/ on Vercel too, so every page and file gets them.
  async headers() {
    return [{ source: '/:path*', headers: SECURITY_HEADERS }];
  },
  // Pull request fixes read the guide's templates at run time. The text pages are prerendered when the site builds,
  // but if one ever renders per request, it reads its Markdown then.
  outputFileTracingIncludes: {
    '/api/app/pr/preview': ['./public/data/guide.json'],
    ...Object.fromEntries(TEXT_PAGES.map((page) => [page, ['./content/**/*.md']])),
  },
  // A machine's own files must never be bundled into a deployment: the code reads .cache at run time, so the tracer
  // could otherwise copy whatever the building machine has there, or in an old .secrets folder (a private key, say).
  outputFileTracingExcludes: { '**': ['.secrets/**', '.cache/**', '.vercel/**', '.venv/**'] },
};

export default config;
