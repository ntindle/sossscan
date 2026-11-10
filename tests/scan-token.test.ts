/**
 * Public scans' token: GITHUB_TOKEN or GH_TOKEN, else the site's GitHub App (a metadata-only installation token,
 * cached until shortly before it expires), else none. Never the gh CLI's. And a private repo, which the app's token
 * can see, gets exactly the answer a missing one gets, while a scan GitHub rate-limited is kept nowhere and isn't
 * mistaken for one. GitHub is faked (tests/helpers.ts).
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpError } from '@/lib/http.ts';
import { NOT_FOUND, runPublicScan, scanOr404 } from '@/lib/public-scan.ts';
import { publicScanToken } from '@/lib/scan-token.ts';
import { RATE_LIMITED } from '@/lib/scanner/index.ts';
// The page's browser module (allowJs lets TypeScript read it; it isn't type-checked).
import * as sg from '../public/shared/core.js';
import { Browser, CFG, configure, useTestEnv } from './helpers.ts';

// The only command anything here could run is `gh auth token` (the scanner CLI's findToken): record it, never run it.
const commands = vi.hoisted(() => [] as string[][]);
vi.mock('node:child_process', async (original) => ({
  ...(await original<typeof import('node:child_process')>()),
  execFileSync: (file: string, args: string[] = []) => {
    commands.push([file, ...args]);
    throw new Error('tests run no commands');
  },
}));

const env = useTestEnv();
let logs: string[];

beforeEach(() => {
  delete process.env.GITHUB_TOKEN; // helpers.ts sets one for the other test files
  commands.length = 0;
  logs = [];
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    logs.push(args.join(' '));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  expect(commands).toEqual([]); // whatever happened, the server never asked the gh CLI for a token
});

/** The error a promise rejects with, or a failure if it resolves. */
async function rejection(p: Promise<unknown>): Promise<HttpError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(HttpError);
    return e as HttpError;
  }
  throw new Error('expected a rejection');
}

// ----------------------------------------------------------------------------------------------- the order
describe('the token for public scans', () => {
  it('is GITHUB_TOKEN or GH_TOKEN when one is set, before the app', async () => {
    configure();
    process.env.GH_TOKEN = 'from-gh-token';
    expect(await publicScanToken()).toBe('from-gh-token');
    process.env.GITHUB_TOKEN = 'server-token';
    expect(await publicScanToken()).toBe('server-token');
    expect(env.world().installationLists + env.world().tokenRequests.length).toBe(0); // the app wasn't asked
  });

  it("is the app's next: a metadata-only token for the installation on the owner's account", async () => {
    configure();
    expect(await publicScanToken()).toBe('inst-token');
    expect(env.world().tokenRequests).toEqual([{ permissions: { metadata: 'read' } }]);
    expect(logs).toEqual([]);
  });

  it("is null without either: the server never borrows the gh CLI's token", async () => {
    expect(await publicScanToken()).toBeNull();
    expect(env.world().installationLists).toBe(0);
    expect(logs).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------- the app's token
describe("the app's token", () => {
  it.each([
    [
      "the owner's, in any letter case",
      [
        { id: 7, account: { login: 'someone' } },
        { id: 5, account: { login: 'OCTO' } },
      ],
    ],
    [
      'the first one, when the owner has none',
      [
        { id: 5, account: { login: 'someone' } },
        { id: 7, account: { login: 'someone-else' } },
      ],
    ],
    [
      "a working one, not the owner's suspended one",
      [
        { id: 7, account: { login: 'octo' }, suspended_at: '2026-11-01T00:00:00Z' },
        { id: 5, account: { login: 'someone' } },
      ],
    ],
  ])('comes from %s installation', async (_, list) => {
    configure();
    env.world().installations = [200, list];
    expect(await publicScanToken()).toBe('inst-token'); // only installation 5 hands out tokens
    expect(env.world().tokenRequests).toEqual([{ permissions: { metadata: 'read' } }]);
  });

  it('is cached, with the installation, and minted again 5 minutes before GitHub expires it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-11-08T12:00:00Z')); // the fake GitHub's token expires at 13:00
    configure();
    const world = env.world();
    expect(await publicScanToken()).toBe('inst-token');
    vi.setSystemTime(new Date('2026-11-08T12:54:59Z'));
    expect(await publicScanToken()).toBe('inst-token');
    expect(world.tokenRequests).toHaveLength(1);
    vi.setSystemTime(new Date('2026-11-08T12:55:00Z'));
    expect(await publicScanToken()).toBe('inst-token');
    expect(world.tokenRequests).toHaveLength(2);
    expect(world.installationLists).toBe(1); // the installation is remembered
  });

  it('is minted once for scans that start together', async () => {
    configure();
    expect(await Promise.all([publicScanToken(), publicScanToken(), publicScanToken()])).toEqual([
      'inst-token',
      'inst-token',
      'inst-token',
    ]);
    expect(env.world().tokenRequests).toHaveLength(1);
    expect(env.world().installationLists).toBe(1);
  });

  it("starts over when the app's settings change", async () => {
    configure();
    await publicScanToken();
    configure({ ...CFG, id: 12 });
    await publicScanToken();
    expect(env.world().installationLists).toBe(2);
    expect(env.world().tokenRequests).toHaveLength(2);
  });

  it('is dropped once GitHub stops accepting it, so the next scan gets a new one', async () => {
    configure();
    const world = env.world();
    world.repo.set('GET /repos/octo/demo', [401, { message: 'Bad credentials' }]); // the app was uninstalled, say
    const err = await rejection(scanOr404('octo/demo', false));
    expect([err.status, err.message]).toEqual([404, 'repo lookup failed: HTTP 401']);
    expect(await publicScanToken()).toBe('inst-token');
    expect(world.tokenRequests).toHaveLength(2);
    expect(world.installationLists).toBe(2);
  });
});

// ------------------------------------------------------------------------------------------ falling through
describe('when the app has no token to give, public scans go on without one', () => {
  beforeEach(() => {
    configure();
  });

  /** One short line in the log, which never quotes a token, a key or a secret. */
  function expectOneLogLine(about: RegExp): void {
    expect(logs).toHaveLength(1);
    expect(logs[0]).toMatch(/^public scans: no GitHub App token \(.+\), scanning without a token$/);
    expect(logs[0]).toMatch(about);
    expect(logs[0]).not.toMatch(/PRIVATE KEY|inst-token/);
  }

  it('when listing the installations fails', async () => {
    env.world().installations = [500, { message: 'boom' }];
    expect(await publicScanToken()).toBeNull();
    expectOneLogLine(/HTTP 500 listing/);
  });

  it('when the app is installed nowhere', async () => {
    env.world().installations = [200, []];
    expect(await publicScanToken()).toBeNull();
    expectOneLogLine(/not installed anywhere/);
  });

  it('when GitHub refuses a token, and looks for the installation again next time', async () => {
    env.world().tokenStatus = 404;
    expect(await publicScanToken()).toBeNull();
    expectOneLogLine(/HTTP 404 minting/);
    env.world().tokenStatus = 201;
    expect(await publicScanToken()).toBe('inst-token');
    expect(env.world().installationLists).toBe(2);
  });

  it("when GitHub doesn't answer", async () => {
    const world = env.world();
    vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).startsWith('https://api.github.com/app/')) throw new TypeError('fetch failed');
      return world.fetch(input, init);
    });
    expect(await publicScanToken()).toBeNull();
    expectOneLogLine(/GitHub didn't answer/);
  });

  it('with a broken private key, without quoting it', async () => {
    configure({ ...CFG, pem: '-----BEGIN PRIVATE KEY-----\nnot-really-a-key\n-----END PRIVATE KEY-----\n' });
    expect(await publicScanToken()).toBeNull();
    expectOneLogLine(/\(\w+\)/);
    expect(logs[0]).not.toContain('not-really-a-key');
  });
});

// ----------------------------------------------------------------------------------------- private repos
describe('a private repo', () => {
  /** GitHub shows the app's token its owner's private repo, under GitHub's own spelling of the name. */
  const PRIVATE = {
    full_name: 'octo/Demo',
    name: 'Demo',
    default_branch: 'main',
    private: true,
    owner: { login: 'octo', type: 'User' },
  };

  beforeEach(() => {
    configure();
    env.world().repo.set('GET /repos/octo/demo', [200, PRIVATE]);
  });

  it('gets the 404 a missing repo gets, and nothing keeps it', async () => {
    const world = env.world();
    const lookups = () => world.repo.calls.filter(([m, p]) => m === 'GET' && p === '/repos/octo/demo').length;
    for (const repo of ['octo/demo', 'octo/missing']) {
      const err = await rejection(scanOr404(repo, false));
      expect([err.status, err.message, err.headers]).toEqual([404, NOT_FOUND, { 'Cache-Control': 'no-store' }]);
    }
    expect(lookups()).toBe(1);
    await rejection(scanOr404('octo/demo', false));
    expect(lookups()).toBe(2); // not cached: GitHub is asked again
    expect(fs.existsSync(path.join(env.dataDir(), '.cache', 'scans'))).toBe(false);
    expect(NOT_FOUND).toBe('repo lookup failed: HTTP 404 (private repo? pass a token)'); // the scanner's own words
  });

  it("leaves no trace in the report: not even GitHub's spelling of its name", async () => {
    const hidden = await runPublicScan('octo/demo');
    const missing = await runPublicScan('octo/missing');
    expect(hidden.repo).toBe('octo/demo');
    const rest = <T extends { repo: string; scanned_at: string }>({ repo: _repo, scanned_at: _at, ...others }: T) =>
      others;
    expect(rest(hidden)).toEqual(rest(missing));
    expect(missing.errors).toEqual([NOT_FOUND]);
  });

  it('gets the same answer as a missing repo from every scan route', async () => {
    const c = new Browser();
    const answers = [];
    for (const r of [
      await c.get('/api/scan/octo/demo'),
      await c.get('/api/scan/octo/missing'),
      await c.post('/api/scan', { repo: 'octo/demo', refresh: true }, {}),
      await c.post('/api/scan', { repo: 'octo/missing' }, {}),
    ]) {
      answers.push({ status: r.status, cache: r.headers.get('cache-control'), body: await r.json() });
    }
    expect(answers).toEqual(Array(4).fill({ status: 404, cache: 'no-store', body: { detail: NOT_FOUND } }));
  });
});

it("scans a public repo with the app's token, and caches the report", async () => {
  configure();
  const first = await scanOr404('octo/demo', false); // the fake GitHub only answers repo calls for the app's token
  expect(first.cached).toBe(false);
  expect(Object.keys(first.results).length).toBeGreaterThan(0);
  expect((await scanOr404('octo/demo', false)).cached).toBe(true);
  expect(env.world().tokenRequests).toEqual([{ permissions: { metadata: 'read' } }]);
});

it('keeps no copy of a scan GitHub rate-limited, here or at the CDN: some of its answers may be wrong', async () => {
  configure();
  const world = env.world();
  const branch = 'GET /repos/octo/demo/branches/main';
  world.repo.set(branch, [403, { message: 'API rate limit exceeded for installation ID 5.' }]);
  const c = new Browser();
  const limited = await c.get('/api/scan/octo/demo');
  const rep = await limited.json();
  expect([limited.status, limited.headers.get('cache-control')]).toEqual([200, 'no-store']);
  expect(Object.keys(rep.results).length).toBeGreaterThan(0);
  expect(rep.errors).toContain(RATE_LIMITED);
  expect(fs.existsSync(path.join(env.dataDir(), '.cache', 'scans'))).toBe(false);
  // Nothing kept it, so the next scan asks GitHub again, and a scan GitHub answered in full is kept as before.
  world.repo.routes.delete(branch);
  const again = await c.get('/api/scan/octo/demo');
  expect([(await again.json()).cached, again.headers.get('cache-control')]).toEqual([
    false,
    'public, max-age=0, s-maxage=21600, stale-while-revalidate=600',
  ]);
  expect((await scanOr404('octo/demo', false)).cached).toBe(true);
});

it('has the page say GitHub is limiting requests, not that the repo is missing, when the repo lookup was refused', async () => {
  configure();
  env.world().repo.set('GET /repos/octo/demo', [403, { message: 'API rate limit exceeded for installation ID 5.' }]);
  const c = new Browser();
  const r = await c.get('/api/scan/octo/demo');
  const { detail } = await r.json();
  expect([r.status, r.headers.get('cache-control'), detail]).toEqual([
    404,
    'no-store',
    `repo lookup failed: HTTP 403; ${RATE_LIMITED}`,
  ]);
  // The page's words for it (scanPublic throws the detail).
  expect(sg.scanTrouble('octo/demo', new Error(detail))).toEqual([
    'GitHub is limiting requests right now, so octo/demo wasn’t scanned.',
    'Try again in a few minutes.',
  ]);
  // A repository GitHub doesn't have is still called that.
  const missing = await (await c.get('/api/scan/octo/missing')).json();
  expect(sg.scanTrouble('octo/missing', new Error(missing.detail))[0]).toBe(
    'GitHub has no public repository called octo/missing.',
  );
});
