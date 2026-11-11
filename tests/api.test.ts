/**
 * The API's contract with programs and agents:
 * - every error under /api/ is JSON with a code, a message and a hint (lib/http.ts), for addresses and methods no
 *   endpoint has too, while the rest of the site keeps its HTML and Markdown 404s;
 * - the site's page still reads those errors and says the same as before.
 * GitHub is faked (tests/helpers.ts), and serve() (tests/site.ts) answers the way Next.js does.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { ERROR_CODES, errorBody, internalError, route } from '@/lib/http.ts';
import { HTML_TYPE, MARKDOWN_TYPE } from '@/lib/negotiate.ts';
import { NAME_MAX, NOT_FOUND, OWNER_MAX, scannerBusy } from '@/lib/public-scan.ts';
import { RATE_LIMITED } from '@/lib/scanner/index.ts';
import { SECURITY_HEADERS } from '@/next.config.ts';
// The page's browser module (allowJs lets TypeScript read it; it isn't type-checked).
import * as sg from '../public/shared/core.js';
import { Browser, configure, READER, signIn, useTestEnv } from './helpers.ts';
import { serve } from './site.ts';

const env = useTestEnv();
const ROOT = process.cwd();

type Json = Record<string, any>;

/**
 * Check that an answer is the API's error, with this status and code, that nothing may keep, and return its body.
 * HEAD answers have no body, so only their status and headers are checked.
 */
async function apiError(res: Response, status: number, code: string): Promise<Json> {
  expect(res.status).toBe(status);
  expect(res.headers.get('content-type')).toBe('application/json');
  expect(res.headers.get('cache-control')).toContain('no-store');
  const text = await res.text();
  if (!text) return {};
  const body = JSON.parse(text);
  expect(Object.keys(body)).toEqual(['error', 'detail']);
  expect(Object.keys(body.error)).toEqual(['code', 'message', 'hint']);
  expect(body.error.code).toBe(code);
  expect(Object.keys(ERROR_CODES)).toContain(code);
  expect(body.error.message.length).toBeGreaterThan(10);
  expect(body.error.hint).toMatch(/^[A-Z].{8,}\.$/); // a sentence that says what to do
  expect(body.detail).toBe(body.error.message); // what clients written before `error` read
  return body;
}

/** Every route under app/api/ except the catch-all, at an address it answers, with the method it takes. */
const ENDPOINTS: [string, 'GET' | 'POST'][] = [
  ['/api/scan/octo/demo', 'GET'],
  ['/api/scan', 'POST'],
  ['/api/health', 'GET'],
  ['/api/app/status', 'GET'],
  ['/api/app/repo', 'POST'],
  ['/api/app/check', 'POST'],
  ['/api/app/fix', 'POST'],
  ['/api/app/pr/preview', 'POST'],
  ['/api/app/pr', 'POST'],
];

/** The route files under app/api/, as addresses with {param} templates. */
function apiRoutes(): string[] {
  return fs
    .readdirSync(path.join(ROOT, 'app/api'), { recursive: true, encoding: 'utf8' })
    .filter((f) => f.endsWith('route.ts'))
    .map((f) => `/api/${path.dirname(f).split(path.sep).join('/')}`.replace(/\[(\w+)\]/g, '{$1}'))
    .sort();
}

// ------------------------------------------------------------------------------------- errors under /api/
describe('errors under /api/', () => {
  const NOWHERE = ['/api', '/api/nope', '/api/scan/octo', '/api/scan/octo/demo/extra', '/api/app', '/api/health/now'];

  it.each(NOWHERE)('answers %s, which no endpoint has, with a JSON 404 whatever the method or Accept', async (to) => {
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']) {
      for (const accept of ['text/markdown', 'text/html', 'application/json']) {
        const res = await serve(to, { method, headers: { accept } });
        const body = await apiError(res, 404, 'not_found');
        if (method === 'HEAD') expect(body).toEqual({});
        else expect(body.error.hint).toContain('/docs/api');
      }
    }
  });

  it('leaves the 404 pages outside /api/ as they were: HTML, or Markdown when asked for', async () => {
    for (const to of ['/apis', '/api.md', '/application']) {
      expect((await serve(to)).headers.get('content-type')).toBe(HTML_TYPE);
      const md = await serve(to, { headers: { accept: 'text/markdown' } });
      expect([md.status, md.headers.get('content-type')]).toEqual([404, MARKDOWN_TYPE]);
    }
  });

  it('has a route for each endpoint listed here, and nothing else under app/api/ besides the catch-all', () => {
    const listed = ENDPOINTS.map(([to]) => to.replace('/octo/demo', '/{owner}/{name}')).sort();
    expect(apiRoutes()).toEqual([...listed, '/api/[[...path]]'].sort());
  });

  it.each(ENDPOINTS)('answers a method %s does not take with a JSON 405 and Allow', async (to, taken) => {
    const allow = taken === 'GET' ? 'GET, HEAD, OPTIONS' : 'OPTIONS, POST';
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].filter((m) => m !== taken)) {
      const res = await serve(to, { method });
      expect(res.headers.get('allow'), method).toBe(allow);
      const body = await apiError(res, 405, 'method_not_allowed');
      expect(body.error.message).toBe(`This endpoint doesn't take ${method} requests.`);
      expect(body.error.hint).toBe(`Send a ${taken} request instead.`);
    }
    const options = await serve(to, { method: 'OPTIONS' });
    expect([options.status, options.headers.get('allow'), await options.text()]).toEqual([204, allow, '']);
    const head = await serve(to, { method: 'HEAD' });
    if (taken === 'POST') {
      expect([head.status, head.headers.get('allow'), await head.text()]).toEqual([405, allow, '']);
    } else {
      expect(head.status).not.toBe(405); // Next.js answers HEAD with the GET handler
    }
  });

  it('answers 422 invalid_repo for a repository name GitHub would not allow', async () => {
    const c = new Browser();
    await apiError(await c.get('/api/scan/-octo/demo'), 422, 'invalid_repo');
    await apiError(await c.get(`/api/scan/octo/${'a'.repeat(NAME_MAX + 1)}`), 422, 'invalid_repo');
    await apiError(await c.get(`/api/scan/${'a'.repeat(OWNER_MAX + 1)}/demo`), 422, 'invalid_repo');
    const bad = await apiError(await c.post('/api/scan', { repo: 'not a repo' }, {}), 422, 'invalid_repo');
    expect(bad.error.message).toBe('Expected OWNER/REPO or a github.com URL.');
  });

  it('answers 422 invalid_request for a body that is not what the endpoint reads', async () => {
    const c = new Browser();
    const post = (body: string) =>
      c.request('POST', '/api/scan', { body, headers: { 'content-type': 'application/json' } });
    expect((await apiError(await post('{"repo": '), 422, 'invalid_request')).error.message).toBe(
      "The request body isn't valid JSON.",
    );
    await apiError(await post('["octo/demo"]'), 422, 'invalid_request');
    const missing = await apiError(await c.post('/api/scan', { refresh: true }, {}), 422, 'invalid_request');
    expect(missing.error.hint).toBe('Send "repo" in the JSON body, as a string of 3 to 200 characters.');
    const short = await apiError(await c.post('/api/scan', { repo: 'ab' }, {}), 422, 'invalid_request');
    expect([short.error.message, short.error.hint]).toEqual([
      'repo is 2 characters long.',
      'Send a repo of 3 to 200 characters.',
    ]);
  });

  it('answers 404 scan_failed, with the scanner’s words, when GitHub never answered the scan', async () => {
    // The fake GitHub answers no request made with the server's own token, so the scan stops at its first.
    const res = await new Browser().get('/api/scan/octo/demo');
    const body = await apiError(res, 404, 'scan_failed');
    expect(body.error.message).toBe('repo lookup failed: HTTP 0');
    expect(body.error.hint).toBe('Try again in a few minutes.');
  });

  it('answers 429 rate_limited with Retry-After, the limit in its message and the wait in its hint', async () => {
    const c = new Browser();
    for (let i = 0; i < 6; i++) expect((await c.post('/api/scan', { repo: 'octo/demo' }, {})).status).toBe(404);
    const res = await c.post('/api/scan', { repo: 'octo/demo' }, {});
    const wait = Number(res.headers.get('retry-after'));
    const body = await apiError(res, 429, 'rate_limited');
    expect(wait).toBeGreaterThanOrEqual(1);
    expect(body.error.message).toBe(
      'Too many requests from your IP address, which can make 6 scan requests a minute and 40 an hour.',
    );
    expect(body.error.hint).toBe(`Try again in ${wait} seconds.`);
    // The app's routes count on their own.
    for (let i = 0; i < 90; i++) await c.get('/api/app/status');
    const app = await apiError(await c.get('/api/app/status'), 429, 'rate_limited');
    expect(app.error.message).toContain('90 sign-in and app requests a minute');
  });

  it('answers 503 scanner_busy when every scan slot stays taken for the 2 minutes a request waits', async () => {
    const held: ((res: Response) => void)[] = [];
    vi.stubGlobal('fetch', () => new Promise<Response>((resolve) => held.push(resolve)));
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const tick = () => new Promise((resolve) => setImmediate(resolve));
    const c = new Browser();
    const scans = ['octo/a', 'octo/b', 'octo/c'].map((repo) => c.get(`/api/scan/${repo}`));
    for (let i = 0; i < 100 && held.length < 3; i++) await tick();
    expect(held).toHaveLength(3); // three scans wait on GitHub: every slot is taken
    const busy = c.get('/api/scan/octo/d');
    for (let i = 0; i < 20; i++) await tick();
    await vi.advanceTimersByTimeAsync(120_000);
    await apiError(await busy, 503, 'scanner_busy');
    // GitHub answers at last, and the three scans finish.
    for (const answer of held.splice(0)) answer(new Response('{"message": "Not Found"}', { status: 404 }));
    for (const res of await Promise.all(scans)) await apiError(res, 404, 'repo_not_found');
  });

  it('answers 500 internal_error when a route crashes, without saying what went wrong inside', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await route(() => {
      throw new Error('a secret detail');
    })();
    const body = await apiError(res, 500, 'internal_error');
    expect(JSON.stringify(body)).not.toContain('secret');
    expect(logged).toHaveBeenCalledOnce(); // the server's log has it
  });

  it("answers the GitHub App's errors in the same format, and never lets anything keep them", async () => {
    const c = new Browser();
    const fix = { repo: 'octo/demo', fix_id: 'enable-private-reporting' };
    const preview = { repo: 'octo/demo', item_id: 'disc-security-md' };
    await apiError(await c.post('/api/app/repo', { repo: 'octo/demo' }, {}), 400, 'missing_header');
    await apiError(await c.post('/api/app/repo', { repo: 'octo/demo' }), 404, 'app_not_configured');
    configure();
    await apiError(await c.post('/api/app/repo', { repo: 'octo/demo' }), 401, 'sign_in_required');
    c.cookies.set('sosf_session', 'not-a-sealed-value');
    delete process.env.SOSF_SECRET;
    await apiError(await c.post('/api/app/repo', { repo: 'octo/demo' }), 503, 'server_misconfigured');
    process.env.SOSF_SECRET = 'test-secret-0123456789abcdef-0123456789';
    await signIn(c, { token: READER, login: 'eve' });
    const notAdmin = await apiError(await c.post('/api/app/fix', fix), 403, 'not_admin');
    expect(notAdmin.error.message).toBe('@eve is not an admin of octo/demo.');
    await signIn(c);
    await apiError(await c.post('/api/app/fix', { ...fix, fix_id: 'nope' }), 422, 'invalid_request');
    await apiError(await c.post('/api/app/pr', { plan: 'x'.repeat(40) }), 410, 'preview_expired');
    env.world().installed = false;
    const notInstalled = await apiError(await c.post('/api/app/pr/preview', preview), 404, 'app_not_installed');
    expect(notInstalled.error.hint).toContain('https://github.com/apps/secure-oss-guide-test/installations/new');
    env.world().installed = true;
    env.world().perms = { contents: 'read', metadata: 'read' };
    await apiError(await c.post('/api/app/pr/preview', preview), 403, 'app_permission_missing');
    env.world().perms = { contents: 'write', pull_requests: 'write', metadata: 'read' };
    env.world().tokenStatus = 500;
    await apiError(await c.post('/api/app/pr/preview', preview), 502, 'github_error');
    env.world().tokenStatus = 201;
    env
      .world()
      .repo.set('GET /repos/octo/demo', [
        200,
        { full_name: 'octo/demo', default_branch: 'main', private: false, archived: true, owner: { login: 'octo' } },
      ]);
    const archived = await apiError(await c.post('/api/app/pr/preview', preview), 409, 'fix_failed');
    expect([archived.error.message, archived.error.hint]).toEqual([
      "octo/demo is archived, so it can't take pull requests.",
      'Unarchive it on GitHub first.',
    ]);
  });

  it('sends the security headers with every API answer', async () => {
    for (const [to, init] of [
      ['/api/nope', {}],
      ['/api/health', {}],
      ['/api/health', { method: 'POST' }],
      ['/api/scan', { method: 'GET' }],
      ['/api/scan/-octo/demo', {}],
    ] as const) {
      const res = await serve(to, init);
      for (const { key, value } of SECURITY_HEADERS) expect(res.headers.get(key), `${key} on ${to}`).toBe(value);
    }
  });
});

// ------------------------------------------------------------------------------------------ the page
describe("the site's page", () => {
  /** fetch as the page has it: its own API in-process, and everything else (GitHub) from the fake world. */
  function pageFetch(c: Browser) {
    const world = env.world().fetch;
    return async (input: string | URL | Request, init: RequestInit = {}) => {
      if (typeof input !== 'string' || !input.startsWith('/')) return world(input, init);
      const headers = Object.fromEntries(new Headers(init.headers));
      return c.request(init.method || 'GET', input, { body: init.body as string | undefined, headers });
    };
  }

  /** What scanPublic throws for a repo. */
  async function scanError(repo: string, refresh = false): Promise<Error & { code: string; detail: string }> {
    try {
      await sg.scanPublic(repo, { refresh });
    } catch (e) {
      return e as Error & { code: string; detail: string };
    }
    throw new Error('expected the scan to fail');
  }

  it('says a missing or private repository is not a public one, from the 404 it gets', async () => {
    configure();
    delete process.env.GITHUB_TOKEN; // the app's token, which the fake GitHub answers
    vi.stubGlobal('fetch', pageFetch(new Browser()));
    const missing = await scanError('octo/missing');
    expect([missing.code, missing.detail]).toEqual(['repo_not_found', NOT_FOUND]);
    expect(missing.message.startsWith(`${NOT_FOUND} Check the spelling`)).toBe(true);
    expect(sg.scanTrouble('octo/missing', missing)).toEqual([
      'GitHub has no public repository called octo/missing.',
      'Check the spelling of the owner and the name. If the repository is private, use the private scan.',
    ]);
    // GitHub shows the app's token its owner's private repo (tests/scan-token.test.ts).
    const hiddenRepo = { full_name: 'octo/Demo', name: 'Demo', default_branch: 'main', private: true };
    env.world().repo.set('GET /repos/octo/demo', [200, { ...hiddenRepo, owner: { login: 'octo', type: 'User' } }]);
    const hidden = await scanError('octo/demo', true);
    expect(sg.scanTrouble('octo/demo', hidden)[0]).toBe('GitHub has no public repository called octo/demo.');
  });

  it('says GitHub is limiting requests when it refused the repo lookup', async () => {
    configure();
    delete process.env.GITHUB_TOKEN;
    env.world().repo.set('GET /repos/octo/demo', [403, { message: 'API rate limit exceeded for installation ID 5.' }]);
    vi.stubGlobal('fetch', pageFetch(new Browser()));
    const err = await scanError('octo/demo');
    expect([err.code, err.detail]).toEqual(['scan_failed', `repo lookup failed: HTTP 403; ${RATE_LIMITED}`]);
    expect(sg.scanTrouble('octo/demo', err)).toEqual([
      'GitHub is limiting requests right now, so octo/demo wasn’t scanned.',
      'Try again in a few minutes.',
    ]);
  });

  it('passes on what the API says to do when the site itself refuses the scan', async () => {
    const c = new Browser();
    vi.stubGlobal('fetch', pageFetch(c));
    for (let i = 0; i < 6; i++) await scanError('octo/demo', true);
    const limited = await scanError('octo/demo', true);
    expect(limited.code).toBe('rate_limited');
    const [title, next] = sg.scanTrouble('octo/demo', limited);
    expect(title).toBe('Couldn’t scan octo/demo.');
    expect(next).toMatch(
      /^The scanner said: Too many requests from your IP address, which can make 6 scan requests a minute and 40 an hour\. Try again in \d+ seconds\.$/,
    );
    // An answer this server sends but can't easily be made to here: a busy scanner.
    vi.stubGlobal('fetch', async () => Response.json(errorBody(scannerBusy()), { status: 503 }));
    expect(sg.scanTrouble('octo/demo', await scanError('octo/demo'))).toEqual([
      'The scanner is busy with other scans.',
      'Try again in a minute.',
    ]);
    vi.stubGlobal('fetch', async () => Response.json(errorBody(internalError()), { status: 500 }));
    expect(sg.scanTrouble('octo/demo', await scanError('octo/demo'))[1]).toBe(
      `The scanner said: ${internalError().message} ${internalError().hint}`,
    );
  });

  it('still reads an error with only `detail`, or no JSON at all', async () => {
    vi.stubGlobal('fetch', async () =>
      Response.json({ detail: 'Expected OWNER/REPO or a github.com URL' }, { status: 422 }),
    );
    const old = await scanError('octo/demo');
    expect([old.message, old.code, old.detail]).toEqual([
      'Expected OWNER/REPO or a github.com URL',
      '',
      'Expected OWNER/REPO or a github.com URL',
    ]);
    vi.stubGlobal('fetch', async () => new Response('<html>Bad gateway</html>', { status: 502 }));
    expect((await scanError('octo/demo')).message).toBe('Scan failed (502)');
  });

  it("shows the GitHub App's errors with what to do next", async () => {
    configure();
    vi.stubGlobal('fetch', pageFetch(new Browser()));
    let err: (Error & { code?: string }) | null = null;
    try {
      await sg.app.fix('octo/demo', 'enable-private-reporting');
    } catch (e) {
      err = e as Error & { code?: string };
    }
    expect(err?.code).toBe('sign_in_required');
    expect(err?.message).toBe(
      "You aren't signed in with GitHub, or your sign-in has expired. Sign in with GitHub, then try again.",
    );
    expect(await sg.app.repo('octo/demo')).toEqual({ error: err?.message });
  });
});
