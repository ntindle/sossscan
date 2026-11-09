/**
 * The owner's rule for this site: "Remove the ability to replace the app. We already made the app — use it. Don't
 * leave open room for attacks. Reduce the attack surface." These tests keep it that way:
 * - nothing can create or replace the GitHub App, and its credentials come only from the environment;
 * - the server never makes up, saves or borrows a secret (no generated key, no gh CLI token);
 * - its cookies can't be planted from another subdomain, its pages can't post forms elsewhere, and its health check
 *   says nothing about how it's set up.
 */
import fs from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { appConfig, sessionCookie, stateCookie } from '@/lib/github-app.ts';
import { HttpError } from '@/lib/http.ts';
import { VERSION } from '@/lib/scanner/index.ts';
import { seal, unseal } from '@/lib/sealed.ts';
import { CSP } from '@/next.config.ts';
import { Browser, CFG, configure, PEM, setCookie, setCookieLine, signIn, startedState, useTestEnv } from './helpers.ts';

const env = useTestEnv();
const SITE = process.cwd();

// ------------------------------------------------------------------------- no way to make or replace the app
it('has no route, module or script that creates or replaces the GitHub App', () => {
  for (const gone of [
    'app/app/register',
    'app/app/manifest-callback',
    'lib/app-manifest.ts',
    'scripts/register-github-app.ts',
    'tests/register-app.test.ts',
  ]) {
    expect(fs.existsSync(path.join(SITE, gone)), gone).toBe(false);
  }
  // The app's setup URL on GitHub stays: it only sends people back to the page.
  expect(fs.existsSync(path.join(SITE, 'app/app/installed/route.ts'))).toBe(true);
});

/** The server's code: every source file in app/ and lib/, except the scanner CLI's own folder (lib/scanner/). */
function serverSources(): [string, string][] {
  const scanner = path.join('lib', 'scanner') + path.sep;
  return ['app', 'lib']
    .flatMap((dir) =>
      fs
        .readdirSync(path.join(SITE, dir), { recursive: true, encoding: 'utf8' })
        .filter((f) => /\.(?:ts|tsx|js|mjs)$/.test(f))
        .map((f) => path.join(dir, f)),
    )
    .filter((f) => !f.startsWith(scanner))
    .map((f) => [f, fs.readFileSync(path.join(SITE, f), 'utf8')]);
}

it.each(['app-manifests', 'APP_SETUP_TOKEN', 'execFileSync', 'writeSecret', 'findToken', '.secrets'])(
  'has no %s in the server',
  (word) => {
    const files = serverSources();
    expect(files.length).toBeGreaterThan(20);
    expect(files.filter(([, text]) => text.includes(word)).map(([f]) => f)).toEqual([]);
  },
);

// ------------------------------------------------------------------------------ the app: environment only
/** A complete set of the app's settings (made up, apart from the slug). */
const APP_ENV = {
  GITHUB_APP_ID: '5677633',
  GITHUB_APP_SLUG: 'sossscan',
  GITHUB_APP_CLIENT_ID: 'Iv23.example',
  GITHUB_APP_CLIENT_SECRET: 'not-a-real-secret',
  GITHUB_APP_PRIVATE_KEY: PEM,
};

describe('appConfig', () => {
  it('ignores a credentials file in the data folder: the environment is the only source', () => {
    const secrets = path.join(env.dataDir(), '.secrets');
    fs.mkdirSync(secrets);
    fs.writeFileSync(path.join(secrets, 'github_app.json'), JSON.stringify({ ...CFG, id: 99 }));
    expect(appConfig()).toBeNull();
    Object.assign(process.env, APP_ENV);
    expect(appConfig()).toMatchObject({ id: 5677633, slug: 'sossscan' });
  });

  it.each([
    'GITHUB_APP_ID',
    'GITHUB_APP_SLUG',
    'GITHUB_APP_CLIENT_ID',
    'GITHUB_APP_CLIENT_SECRET',
    'GITHUB_APP_PRIVATE_KEY',
  ])('is null without %s, and the site carries on without sign-in', async (name) => {
    Object.assign(process.env, APP_ENV);
    expect(appConfig()).not.toBeNull();
    process.env[name] = '  ';
    expect(appConfig()).toBeNull();
    delete process.env[name];
    expect(appConfig()).toBeNull();
    const c = new Browser();
    expect(await (await c.get('/api/app/status')).json()).toMatchObject({ configured: false, user: null });
    const login = await c.get('/app/login');
    expect(login.status).toBe(404);
    expect((await login.json()).detail).toBe("Sign in with GitHub isn't available on this copy of the site.");
  });

  it.each(['0', '-1', '007', '12abc', '1.5', '1e3', '0x10', 'abc', '99999999999999999999'])(
    'is null for the app id %j',
    (id) => {
      Object.assign(process.env, APP_ENV, { GITHUB_APP_ID: id });
      expect(appConfig()).toBeNull();
    },
  );

  it.each(['a/b', 'a b', '../x', '-x', 'x?y', 'x#y'])(
    'is null for the slug %j, which would go into its links',
    (slug) => {
      Object.assign(process.env, APP_ENV, { GITHUB_APP_SLUG: slug });
      expect(appConfig()).toBeNull();
    },
  );
});

// ------------------------------------------------------------------------------------------ SOSF_SECRET
describe('SOSF_SECRET', () => {
  /** The error a call throws, or a failure if it doesn't throw. */
  function thrown(fn: () => unknown): HttpError {
    try {
      fn();
    } catch (e) {
      expect(e).toBeInstanceOf(HttpError);
      return e as HttpError;
    }
    throw new Error('expected an error');
  }

  it.each([
    ['missing', undefined],
    ['empty', ''],
    ['31 characters long', 'x'.repeat(31)],
  ])('stops sealing when it is %s, on any host, and nothing is made up or saved instead', (_, secret) => {
    const sealed = seal('session', { a: 1 }); // with the tests' own secret
    for (const vercel of [false, true]) {
      if (secret === undefined) delete process.env.SOSF_SECRET;
      else process.env.SOSF_SECRET = secret;
      if (vercel) process.env.VERCEL = '1';
      else delete process.env.VERCEL;
      for (const call of [() => seal('session', { a: 1 }), () => unseal('session', sealed, 60)]) {
        const err = thrown(call);
        expect([err.status, err.message]).toEqual([
          503,
          "This site isn't fully set up: SOSF_SECRET is missing or too short.",
        ]);
      }
    }
    expect(fs.readdirSync(env.dataDir())).toEqual([]); // no key file
  });

  it('works from 32 characters', () => {
    process.env.SOSF_SECRET = 'x'.repeat(32);
    expect(unseal('session', seal('session', { a: 1 }), 60)).toEqual({ a: 1 });
  });

  it("isn't needed for public scans, for the status of someone who never signed in, or for the health check", async () => {
    delete process.env.SOSF_SECRET;
    delete process.env.GITHUB_TOKEN; // scan with the app's token: the only one the fake GitHub answers repo calls for
    configure();
    const c = new Browser();
    const scanned = await c.get('/api/scan/octo/demo');
    expect(scanned.status).toBe(200);
    expect(Object.keys((await scanned.json()).results).length).toBeGreaterThan(0);
    expect((await c.post('/api/scan', { repo: 'octo/demo', refresh: true }, {})).status).toBe(200);
    const status = await c.get('/api/app/status');
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ configured: true, user: null });
    expect((await c.get('/api/health')).status).toBe(200);
    // Signing in is what needs it, and it says so rather than pretending to work.
    const login = await c.get('/app/login');
    expect(login.status).toBe(503);
    expect(login.headers.getSetCookie()).toEqual([]);
    expect(fs.readdirSync(env.dataDir())).toEqual(['.cache']); // scan results, and nothing else
  });
});

// ---------------------------------------------------------------------------------------------- cookies
/** Check a Set-Cookie line: HttpOnly, SameSite=Lax, Path=/ and never a Domain, plus Secure when asked. */
function expectCookieLine(line: string | null, { secure, cleared }: { secure: boolean; cleared: boolean }): void {
  expect(line).not.toBeNull();
  const [pair, ...attrs] = line!.split(/;\s*/);
  const a = attrs.map((x) => x.toLowerCase());
  expect(a).toContain('path=/');
  expect(a).toContain('httponly');
  expect(a).toContain('samesite=lax');
  expect(a.some((x) => x.startsWith('domain='))).toBe(false);
  expect(a.includes('secure')).toBe(secure);
  const maxAge = Number(a.find((x) => x.startsWith('max-age='))?.slice('max-age='.length));
  if (cleared) {
    expect(pair.endsWith('=')).toBe(true);
    expect(maxAge).toBe(0);
  } else {
    expect(maxAge).toBeGreaterThan(0);
  }
}

describe('cookies over https', () => {
  beforeEach(() => {
    process.env.SITE_BASE_URL = 'https://sossscan.example';
    configure();
  });

  it('are __Host- cookies: Secure, Path=/ and no Domain, from sign-in to sign-out', async () => {
    expect([sessionCookie(), stateCookie()]).toEqual(['__Host-sosf_session', '__Host-sosf_state']);
    const c = new Browser();
    const login = await c.get('/app/login', { next: '/?repo=octo/demo' });
    expectCookieLine(setCookieLine(login, '__Host-sosf_state'), { secure: true, cleared: false });
    const state = new URL(login.headers.get('location')!).searchParams.get('state')!;

    const back = await c.get('/app/oauth-callback', { code: 'x', state });
    expect(back.headers.get('location')).toBe('/?repo=octo%2Fdemo&app=signed-in');
    expectCookieLine(setCookieLine(back, '__Host-sosf_session'), { secure: true, cleared: false });
    expectCookieLine(setCookieLine(back, '__Host-sosf_state'), { secure: true, cleared: true }); // used up
    expect(unseal('session', setCookie(back, '__Host-sosf_session'), 60)).toMatchObject({ login: 'octo' });
    expect((await (await c.get('/api/app/status')).json()).user).toBe('octo');

    const out = await c.get('/app/logout');
    expectCookieLine(setCookieLine(out, '__Host-sosf_session'), { secure: true, cleared: true });
    expect(c.cookies.size).toBe(0);
    expect((await (await c.get('/api/app/status')).json()).user).toBeNull();
    for (const r of [login, back, out]) {
      expect(r.headers.getSetCookie().every((line) => line.startsWith('__Host-'))).toBe(true);
    }
  });

  it('ignore plain-named cookies, which another subdomain of the same domain could plant', async () => {
    const c = new Browser();
    const session = await signIn(c); // a genuine sign-in...
    c.cookies.clear();
    c.cookies.set('sosf_session', session); // ...under the name a sibling subdomain can set
    expect((await (await c.get('/api/app/status')).json()).user).toBeNull();
    const state = await startedState(c);
    const nonce = c.cookies.get('__Host-sosf_state')!;
    c.cookies.clear();
    c.cookies.set('sosf_state', nonce);
    const r = await c.get('/app/oauth-callback', { code: 'x', state });
    expect(r.headers.get('location')).toBe('/?app=signin-expired');
  });
});

it('keeps the plain cookie names, without Secure, over plain http (a local test site)', async () => {
  configure();
  expect([sessionCookie(), stateCookie()]).toEqual(['sosf_session', 'sosf_state']);
  const c = new Browser();
  const login = await c.get('/app/login');
  expectCookieLine(setCookieLine(login, 'sosf_state'), { secure: false, cleared: false });
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
  const back = await c.get('/app/oauth-callback', { code: 'x', state });
  expectCookieLine(setCookieLine(back, 'sosf_session'), { secure: false, cleared: false });
  expectCookieLine(setCookieLine(back, 'sosf_state'), { secure: false, cleared: true });
  const out = await c.get('/app/logout');
  expectCookieLine(setCookieLine(out, 'sosf_session'), { secure: false, cleared: true });
  for (const r of [login, back, out]) expect(r.headers.getSetCookie().join('\n')).not.toContain('__Host-');
  process.env.SITE_BASE_URL = 'https://sossscan.example'; // the names follow the setting at once
  expect(sessionCookie()).toBe('__Host-sosf_session');
});

// ------------------------------------------------------------------------------------ the page and health
it('lets the page post forms only to this site', () => {
  const directives = CSP.split(';').map((d) => d.trim());
  expect(directives.filter((d) => d.startsWith('form-action'))).toEqual(["form-action 'self'"]);
  expect(CSP).not.toContain('github.com');
});

it('says only that the site is up, and which scanner it runs, at /api/health', async () => {
  configure(); // even with an app and a token, nothing about them
  process.env.GITHUB_TOKEN = 'server-token';
  const r = await new Browser().get('/api/health');
  expect(r.status).toBe(200);
  expect(r.headers.get('cache-control')).toBe('no-store');
  expect(await r.json()).toEqual({ ok: true, scanner_version: VERSION });
});
