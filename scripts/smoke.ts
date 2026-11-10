/**
 * Smoke-test a running site (after `npm run build`): the page and its files with their headers, the text pages,
 * retired-page redirects, the scanner download, and the API answering. Nothing here scans a repo or touches GitHub.
 *   node scripts/smoke.ts [base URL, default http://127.0.0.1:3340]
 */
export {};

const BASE = (process.argv[2] || 'http://127.0.0.1:3340').replace(/\/+$/, '');
let failed = 0;

function check(what: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${ok || !detail ? '' : `: ${detail}`}`);
  if (!ok) failed += 1;
}

async function get(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(BASE + path, { redirect: 'manual', ...init });
}

/** Follow redirects by hand (up to 3), returning each status and the final location. */
async function chase(path: string): Promise<{ statuses: number[]; location: string }> {
  const statuses: number[] = [];
  let location = path;
  for (let i = 0; i < 3; i++) {
    const r = await get(location);
    statuses.push(r.status);
    if (r.status < 300 || r.status >= 400) break;
    const next = new URL(r.headers.get('location')!, BASE + location);
    location = next.pathname + next.search;
  }
  return { statuses, location };
}

const home = await get('/');
const page = await home.text();
const csp = home.headers.get('content-security-policy') || '';
check(
  '/ is the pipeline map',
  home.status === 200 && page.includes('src="/pipeline/pipeline.js"'),
  String(home.status),
);
check(
  '/ has a CSP with script hashes',
  /script-src 'self' 'sha256-/.test(csp) && csp.includes("frame-ancestors 'none'"),
  csp,
);
check(
  '/ has the other security headers',
  home.headers.get('x-frame-options') === 'DENY' && home.headers.get('x-content-type-options') === 'nosniff',
);
check(
  '/ is HTML',
  (home.headers.get('content-type') || '').startsWith('text/html'),
  home.headers.get('content-type') || '',
);
check('/index.html has the same CSP', (await get('/index.html')).headers.get('content-security-policy') === csp);
check('no X-Powered-By header', !home.headers.has('x-powered-by'));
check(
  '/ has the site links in its footer and JSON-LD in its head',
  page.includes('<a href="/docs">Docs</a>') && page.includes('<script type="application/ld+json">'),
);
for (const path of ['/about', '/contact', '/privacy', '/docs', '/docs/api', '/docs/cli']) {
  const r = await get(path);
  const html = await r.text();
  check(
    `${path} is a page with the site's footer`,
    r.status === 200 &&
      (r.headers.get('content-type') || '').startsWith('text/html') &&
      html.includes('<a href="/privacy"'),
    `${r.status} ${r.headers.get('content-type')}`,
  );
  check(`${path} has the same CSP`, r.headers.get('content-security-policy') === csp);
}

const files = await Promise.all(Array.from({ length: 30 }, () => get('/pipeline/pipeline.js')));
check(
  'the page files are never rate limited',
  files.every((r) => r.status === 200),
  files.map((r) => r.status).join(','),
);
check('pipeline.js has the security headers', files[0].headers.get('x-content-type-options') === 'nosniff');
const guide = await get('/data/guide.json');
check('guide.json is served', guide.status === 200 && Array.isArray((await guide.json()).items));

for (const old of [
  '/pipeline',
  '/pipeline/',
  '/wizard/',
  '/wizard/app.js',
  '/ui/03-report-card/',
  '/variants/',
  '/variants',
]) {
  const { statuses, location } = await chase(`${old}?repo=octo/demo`);
  const params = new URLSearchParams(location.split('?')[1] || '');
  check(
    `${old} lands on / with its ?repo=`,
    location.startsWith('/?') && params.get('repo') === 'octo/demo',
    `${statuses} ${location}`,
  );
}

const cli = await get('/download/sosf-scan.mjs');
const cliText = await cli.text();
check('the scanner downloads', cli.status === 200 && cliText.startsWith('#!/usr/bin/env node'), String(cli.status));
const health = await get('/api/health');
const h = health.status === 200 ? await health.json() : {};
check(
  '/api/health answers, and says nothing else',
  h.ok === true && typeof h.scanner_version === 'string' && Object.keys(h).sort().join() === 'ok,scanner_version',
  JSON.stringify(h),
);
check('/api/health has the CSP too', health.headers.get('content-security-policy') === csp);
check("/ can't post forms to another site", /(?:^|;\s*)form-action 'self'(?:;|$)/.test(csp), csp);
const status = await get('/api/app/status');
check('/api/app/status answers', status.status === 200 && 'configured' in (await status.json()));
for (const gone of ['/app/register', '/app/manifest-callback']) {
  const r = await get(gone);
  check(`${gone} is gone: the site can't make or replace its GitHub App`, r.status === 404, String(r.status));
}
const noHeader = await get('/api/app/repo', {
  method: 'POST',
  body: '{"repo":"octo/demo"}',
  headers: { 'content-type': 'application/json' },
});
check('app requests need X-Requested-With', noHeader.status === 400, String(noHeader.status));
check('unknown paths are 404', (await get('/no-such-page')).status === 404);

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
