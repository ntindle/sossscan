import { execFileSync } from 'node:child_process';
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
export const TEXT_PAGES = ['/about', '/contact', '/privacy', '/docs', '/docs/api', '/docs/cli', '/agents'];

const SITE = 'https://sossscan.ntindle.com';

/** Each page that comes as HTML and as Markdown (proxy.ts), with its Markdown twin (markdownPath in lib/negotiate.ts). */
export const NEGOTIATED = ['/', ...TEXT_PAGES].map((page) => ({
  page,
  markdown: page === '/' ? '/index.md' : `${page}.md`,
}));

/**
 * Headers for the pages that come in two representations, and for their Markdown twins. These rules are matched against
 * the address that was asked for.
 * - Vary: Accept, here for the home page only. Every answer at a page's address needs it, so that a browser or shared
 *   cache keeps the HTML and the Markdown apart, but only the home page's HTML gets it from here: it's a file in public/,
 *   and Vercel keeps these headers on files. The routes set their own (lib/pages.ts), because Vercel sends a prerendered
 *   route with the Vary Next.js gives it, in place of this one, and a rule here would only repeat theirs.
 * - Link: on a page, where its Markdown twin is and the llms.txt that describes the site (https://llmstxt.org). On a
 *   twin, its page as canonical, so search engines index the page, not the twin.
 */
export const NEGOTIATION_HEADERS = NEGOTIATED.flatMap(({ page, markdown }) => [
  {
    source: page,
    headers: [
      ...(page === '/' ? [{ key: 'Vary', value: 'Accept' }] : []),
      { key: 'Link', value: `<${markdown}>; rel="alternate"; type="text/markdown", </llms.txt>; rel="describedby"` },
    ],
  },
  {
    source: markdown,
    headers: [{ key: 'Link', value: `<${SITE}${page}>; rel="canonical", </llms.txt>; rel="describedby"` }],
  },
]);

/*
 * When each page's content last changed, for the sitemap's <lastmod> (app/sitemap.ts): the last commit that touched
 * the files it comes from. git runs here, when the site builds, and the dates reach the prerendered sitemap through
 * `env`, so the server's own code never starts a process (tests/attack-surface.test.ts).
 *
 * Builds often have only part of the history: Vercel clones 10 commits deep, CI checks out 1, and a Docker build has no
 * git. Where a clone's history stops, git reports its oldest commit as the change to every older file, and that date
 * moves forward with each deployment. So a date only counts when the commit's parents are there too. Vercel's clone
 * isn't always marked shallow, so this looks for the parents rather than trusting the mark. A page git can't date gets
 * no <lastmod>, rather than a wrong one. VERCEL_DEEP_CLONE=true gives Vercel builds the whole history (DEPLOY.md).
 */

function git(args: string[], cwd: string): string | null {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000 });
  } catch {
    return null; // no git, not a repository, or an object that isn't there
  }
}

/** Whether the history this clone has stops at this commit: it's marked shallow, or its parents are missing. */
export function historyStopsAt(sha: string, cwd = process.cwd()): boolean {
  const shallow = git(['rev-parse', '--git-path', 'shallow'], cwd)?.trim();
  try {
    if (shallow && readFileSync(path.resolve(cwd, shallow), 'utf8').split('\n').includes(sha)) return true;
  } catch {
    // a complete clone has no such file
  }
  const commit = git(['cat-file', '-p', sha], cwd);
  if (commit === null) return true;
  const parents = [...commit.matchAll(/^parent ([0-9a-f]+)$/gm)].map((m) => m[1]);
  return parents.some((parent) => git(['cat-file', '-e', `${parent}^{commit}`], cwd) === null);
}

/**
 * When these files (relative to cwd, the repository) last changed, as a W3C datetime in UTC, or undefined when git
 * can't say: no git, files never committed, or a change older than the history this clone has.
 */
export function lastModified(files: readonly string[], cwd = process.cwd()): string | undefined {
  const log = git(['log', '-1', '--format=commit %H %cI', '--', ...files], cwd) ?? '';
  // Only the line in this format: a setting such as log.showSignature can print more.
  const m = /^commit ([0-9a-f]{40,64}) (\S+)$/m.exec(log);
  if (!m || historyStopsAt(m[1], cwd)) return undefined;
  return new Date(m[2]).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** The files each page's content comes from. The home page is its HTML, its Markdown and the guide it shows. */
export const PAGE_SOURCES: Record<string, string[]> = {
  '/': ['public/index.html', 'content/index.md', 'public/data/guide.json'],
  ...Object.fromEntries(TEXT_PAGES.map((page) => [page, [`content${page}.md`]])),
};

/** Each page's date, where git has one. */
export const PAGE_DATES: Record<string, string> = Object.fromEntries(
  Object.entries(PAGE_SOURCES).flatMap(([page, files]) => {
    const date = lastModified(files);
    return date ? [[page, date]] : [];
  }),
);

const config: NextConfig = {
  poweredByHeader: false,
  // Built into the server's code when the site builds: app/sitemap.ts reads it.
  env: { SITEMAP_LASTMOD: JSON.stringify(PAGE_DATES) },
  // The page is plain files in public/; the server is route handlers only.
  async rewrites() {
    return { beforeFiles: [{ source: '/', destination: '/index.html' }] };
  },
  async redirects() {
    return RETIRED.map((source) => ({ source, destination: '/', statusCode: 302 as const }));
  },
  // These reach the CDN's copies of public/ on Vercel too, so every page and file gets them.
  async headers() {
    return [{ source: '/:path*', headers: SECURITY_HEADERS }, ...NEGOTIATION_HEADERS];
  },
  // Files the server reads at run time, which the deployment must include: the guide's templates for pull request
  // fixes, and the Markdown each text page and twin renders from on its first request (the home page's Markdown also
  // lists the guide's checks).
  outputFileTracingIncludes: {
    '/api/app/pr/preview': ['./public/data/guide.json'],
    ...Object.fromEntries(TEXT_PAGES.map((page) => [page, ['./content/**/*.md']])),
    ...Object.fromEntries(
      NEGOTIATED.map(({ page, markdown }) => [
        markdown,
        page === '/' ? ['./content/**/*.md', './public/data/guide.json'] : ['./content/**/*.md'],
      ]),
    ),
  },
  // A machine's own files must never be bundled into a deployment: the code reads .cache at run time, so the tracer
  // could otherwise copy whatever the building machine has there, or in an old .secrets folder (a private key, say).
  outputFileTracingExcludes: { '**': ['.secrets/**', '.cache/**', '.vercel/**', '.venv/**'] },
};

export default config;
