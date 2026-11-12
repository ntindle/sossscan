/**
 * Test helpers: a fake GitHub (for lib/fixes.ts directly, and behind a fake fetch for the routes), a fake AI model,
 * and a "browser" that calls the route handlers in-process with a cookie jar. Nothing leaves the machine.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, vi } from 'vitest';
import type { GhAnswer } from '@/lib/github.ts';

export const SHA_A = 'a'.repeat(40);
export const SHA_B = 'b'.repeat(40);
export const SHA_C = 'c'.repeat(40);

type Answer = [number, unknown] | ((path: string, body: any) => [number, unknown]);

/** Routes (method, path regex) to canned answers and records every call. */
export class FakeGitHub {
  routes: Map<string, Answer>;
  calls: [string, string, any][] = [];
  constructor(routes: Record<string, Answer> = {}) {
    this.routes = new Map(Object.entries(routes));
  }
  /** `method path-regex` keys, like "GET /repos/octo/demo". The regex matches the path without its query. */
  set(key: string, answer: Answer): void {
    this.routes.set(key, answer);
  }
  call = async (method: string, apiPath: string, body?: unknown): Promise<GhAnswer> => {
    this.calls.push([method, apiPath, body]);
    for (const [key, answer] of this.routes) {
      const [m, pattern] = [key.slice(0, key.indexOf(' ')), key.slice(key.indexOf(' ') + 1)];
      const target = pattern.includes('?') ? apiPath : apiPath.split('?')[0];
      if (m === method && new RegExp(`^(?:${pattern})$`).test(target)) {
        const [status, data] = typeof answer === 'function' ? answer(apiPath, body) : answer;
        return { status, data };
      }
    }
    return { status: 404, data: { message: 'Not Found' } };
  };
  made(method: string, prefix: string): [string, string, any][] {
    return this.calls.filter((c) => c[0] === method && c[1].startsWith(prefix));
  }
}

export function repoRoutes({
  isPrivate = false,
  ownerType = 'User',
  tree = [] as string[],
  truncated = false,
  archived = false,
} = {}): Record<string, Answer> {
  return {
    'GET /repos/octo/demo': [
      200,
      {
        full_name: 'octo/demo',
        name: 'demo',
        default_branch: 'main',
        private: isPrivate,
        archived,
        owner: { login: 'octo', type: ownerType },
      },
    ],
    'GET /repos/octo/demo/pulls': [200, []],
    'GET /repos/octo/demo/git/ref/heads/main': [200, { object: { sha: SHA_A } }],
    [`GET /repos/octo/demo/git/commits/${SHA_A}`]: [200, { tree: { sha: SHA_B } }],
    [`GET /repos/octo/demo/git/trees/${SHA_B}`]: [
      200,
      { tree: tree.map((p) => ({ path: p, type: 'blob', mode: '100644' })), truncated },
    ],
  };
}

// ------------------------------------------------------------------------------------------- the app
export const PEM = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
}).privateKey;

export const CFG = {
  id: 11,
  slug: 'secure-oss-guide-test',
  client_id: 'Iv1.test',
  client_secret: 's',
  pem: PEM,
  html_url: 'https://github.com/apps/secure-oss-guide-test',
  owner: 'octo',
  public: false,
};
/** The fix app's settings: no client ID or secret, since it signs no one in. Its installation on octo/demo is 7. */
export const FIX_CFG = { id: 12, slug: 'secure-oss-fix-test', pem: PEM };
export const ADMIN = 'user-admin';
export const READER = 'user-reader';
export const ALL_WRITE: Record<string, string | null> = {
  administration: 'write',
  contents: 'write',
  pull_requests: 'write',
  workflows: 'write',
  metadata: 'read',
};
/** The live main app's permissions before the split (gh api apps/sossscan): reads, and five that write. */
export const BEFORE_SPLIT: Record<string, string> = {
  actions: 'read',
  administration: 'write',
  contents: 'write',
  environments: 'read',
  members: 'read',
  metadata: 'read',
  organization_administration: 'read',
  pull_requests: 'write',
  repository_advisories: 'read',
  secret_scanning_alerts: 'read',
  secrets: 'read',
  security_events: 'write',
  vulnerability_alerts: 'read',
  workflows: 'write',
};
/** The main app's permissions after the split (DEPLOY.md): read only, and no security advisories. */
export const MAIN_READ: Record<string, string> = {
  actions: 'read',
  administration: 'read',
  contents: 'read',
  members: 'read',
  metadata: 'read',
  organization_administration: 'read',
  pull_requests: 'read',
  secret_scanning_alerts: 'read',
  secrets: 'read',
  security_events: 'read',
  vulnerability_alerts: 'read',
};
/** The fix app's permissions (DEPLOY.md). */
export const FIX_PERMS: Record<string, string> = {
  administration: 'write',
  contents: 'write',
  metadata: 'read',
  pull_requests: 'write',
  repository_advisories: 'read',
  workflows: 'write',
};
export const H = { 'x-requested-with': 'sosf' };

/** Stands in for the AI service: answers each chat request with the next scripted reply and keeps what it was sent. */
export class FakeModel {
  replies: unknown[];
  sent: any[][] = [];
  constructor(...replies: unknown[]) {
    this.replies = replies;
  }
}

/** Which app signed a JWT: the fix app (by its ID, FIX_CFG) or the main app (by its client ID). */
function jwtApp(headers: Headers): 'main' | 'fix' {
  const jwt = (headers.get('authorization') || '').replace(/^Bearer /, '');
  try {
    const iss = JSON.parse(Buffer.from(jwt.split('.')[1] || '', 'base64url').toString()).iss;
    return iss === String(FIX_CFG.id) ? 'fix' : 'main';
  } catch {
    return 'main';
  }
}

/** Everything outside the server: GitHub's API as each token sees it, GitHub's sign-in pages, and the AI service. */
export class FakeWorld {
  /** The main app's installation on octo/demo (5): is it there, and with which permissions. */
  installed = true;
  perms: Record<string, string | null> = { ...ALL_WRITE };
  /** The fix app's (7). */
  fixInstalled = true;
  fixPerms: Record<string, string | null> = { ...FIX_PERMS };
  /** The account both are installed on. */
  account = { login: 'octo', type: 'User' };
  repo = new FakeGitHub({
    ...repoRoutes({ tree: ['README.md'] }),
    'GET /repos/octo/demo/private-vulnerability-reporting': [200, { enabled: true }],
  });
  /** GET /app/installations, as the app. */
  installations: [number, unknown] = [200, [{ id: 5, account: { login: 'octo', type: 'User' } }]];
  installationLists = 0;
  /** Bodies of the token requests for installation 5, which answers with tokenStatus. */
  tokenRequests: any[] = [];
  /** Bodies of the token requests for the fix app's installation, 7. */
  fixTokenRequests: any[] = [];
  tokenStatus = 201;
  /** Name each token apart (inst-token-1, fix-token-2…), so a test can tell which one made a call. */
  distinctTokens = false;
  /** Every token handed out: its installation and the permissions it holds. */
  issued = new Map<string, { installation: number; permissions: Record<string, string> }>();
  /** Every API call a token made: [token, method, path]. */
  used: [string, string, string][] = [];
  oauthAnswer: [number, unknown] = [200, { access_token: ADMIN }];
  model: FakeModel | null = null;
  aiAnswer: ((body: any) => Response) | null = null;

  /** The calls one token made, as "METHOD path". */
  callsBy(token: string): string[] {
    return this.used.filter(([t]) => t === token).map(([, m, p]) => `${m} ${p}`);
  }

  /** The tokens handed out for one installation, in order. */
  tokensOf(installation: number): string[] {
    return [...this.issued].filter(([, v]) => v.installation === installation).map(([k]) => k);
  }

  fetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const method = (init.method || 'GET').toUpperCase();
    const headers = new Headers(init.headers);
    const body = typeof init.body === 'string' ? safeJson(init.body) : init.body;
    const reply = (status: number, data: unknown) =>
      new Response(status === 204 ? null : typeof data === 'string' ? data : JSON.stringify(data), { status });
    if (url.origin === 'https://ai.example') {
      if (this.aiAnswer) return this.aiAnswer(body);
      if (!this.model) throw new Error('no model scripted');
      this.model.sent.push(JSON.parse(JSON.stringify((body as any).messages)));
      if (!this.model.replies.length) throw new Error('the model ran out of replies');
      return reply(200, this.model.replies.shift());
    }
    if (url.href === 'https://github.com/login/oauth/access_token') return reply(...this.oauthAnswer);
    if (url.origin !== 'https://api.github.com') throw new Error(`unexpected fetch ${method} ${url.href}`);
    const apiPath = url.pathname + url.search;
    const token = (headers.get('authorization') || '').replace(/^Bearer /, '');
    if (token === ADMIN || token === READER) {
      if (url.pathname === '/user') return reply(200, { login: token === ADMIN ? 'octo' : 'eve' });
      if (url.pathname === '/repos/octo/demo') return reply(200, { permissions: { admin: token === ADMIN } });
    }
    if (url.pathname === '/repos/octo/demo/installation') {
      // Each app sees its own installation.
      const fix = jwtApp(headers) === 'fix';
      if (!(fix ? this.fixInstalled : this.installed)) return reply(404, { message: 'Not Found' });
      return reply(200, { id: fix ? 7 : 5, permissions: fix ? this.fixPerms : this.perms, account: this.account });
    }
    if (url.pathname === '/app/installations') {
      this.installationLists += 1;
      return reply(...this.installations);
    }
    const minting = /^\/app\/installations\/(5|7)\/access_tokens$/.exec(url.pathname);
    if (minting) {
      const id = Number(minting[1]);
      // An app can only mint tokens for its own installations.
      if ((id === 7) !== (jwtApp(headers) === 'fix')) return reply(404, { message: 'Not Found' });
      (id === 7 ? this.fixTokenRequests : this.tokenRequests).push(body);
      if (this.tokenStatus !== 201) return reply(this.tokenStatus, { message: 'Not Found' });
      // GitHub's tokens last an hour, and it says until when (no milliseconds), and what the token may do: what the
      // request asked for, or all the installation has.
      const expires = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
      const permissions =
        (body as { permissions?: unknown } | null)?.permissions ?? (id === 7 ? this.fixPerms : this.perms);
      const kind = id === 7 ? 'fix-token' : 'inst-token';
      const name = this.distinctTokens ? `${kind}-${this.issued.size + 1}` : kind;
      this.issued.set(name, { installation: id, permissions: permissions as Record<string, string> });
      return reply(201, { token: name, expires_at: expires, permissions });
    }
    if (!this.issued.has(token) && token !== 'inst-token') {
      throw new Error(`unexpected call ${method} ${apiPath} with ${token}`);
    }
    this.used.push([token, method, apiPath]);
    const { status, data } = await this.repo.call(method, apiPath, body);
    return reply(status, data);
  };
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}

// ---------------------------------------------------------------------------------- calling routes
const ROUTES: [RegExp, () => Promise<Record<string, any>>][] = [
  [/^\/api\/health$/, () => import('@/app/api/health/route.ts')],
  [/^\/api\/scan$/, () => import('@/app/api/scan/route.ts')],
  [/^\/api\/scan\/([^/]+)\/([^/]+)$/, () => import('@/app/api/scan/[owner]/[name]/route.ts')],
  [/^\/api\/app\/status$/, () => import('@/app/api/app/status/route.ts')],
  [/^\/api\/app\/repo$/, () => import('@/app/api/app/repo/route.ts')],
  [/^\/api\/app\/check$/, () => import('@/app/api/app/check/route.ts')],
  [/^\/api\/app\/fix$/, () => import('@/app/api/app/fix/route.ts')],
  [/^\/api\/app\/pr\/preview$/, () => import('@/app/api/app/pr/preview/route.ts')],
  [/^\/api\/app\/pr$/, () => import('@/app/api/app/pr/route.ts')],
  [/^\/app\/installed$/, () => import('@/app/app/installed/route.ts')],
  [/^\/app\/login$/, () => import('@/app/app/login/route.ts')],
  [/^\/app\/oauth-callback$/, () => import('@/app/app/oauth-callback/route.ts')],
  [/^\/app\/logout$/, () => import('@/app/app/logout/route.ts')],
  [/^\/about$/, () => import('@/app/about/route.ts')],
  [/^\/contact$/, () => import('@/app/contact/route.ts')],
  [/^\/privacy$/, () => import('@/app/privacy/route.ts')],
  [/^\/docs$/, () => import('@/app/docs/route.ts')],
  [/^\/docs\/api$/, () => import('@/app/docs/api/route.ts')],
  [/^\/docs\/cli$/, () => import('@/app/docs/cli/route.ts')],
  [/^\/docs\/mcp$/, () => import('@/app/docs/mcp/route.ts')],
  [/^\/agents$/, () => import('@/app/agents/route.ts')],
  [/^\/index\.md$/, () => import('@/app/index.md/route.ts')],
  [/^\/about\.md$/, () => import('@/app/about.md/route.ts')],
  [/^\/contact\.md$/, () => import('@/app/contact.md/route.ts')],
  [/^\/privacy\.md$/, () => import('@/app/privacy.md/route.ts')],
  [/^\/docs\.md$/, () => import('@/app/docs.md/route.ts')],
  [/^\/docs\/api\.md$/, () => import('@/app/docs/api.md/route.ts')],
  [/^\/docs\/cli\.md$/, () => import('@/app/docs/cli.md/route.ts')],
  [/^\/docs\/mcp\.md$/, () => import('@/app/docs/mcp.md/route.ts')],
  [/^\/agents\.md$/, () => import('@/app/agents.md/route.ts')],
  [/^\/openapi\.json$/, () => import('@/app/openapi.json/route.ts')],
  [/^\/mcp$/, () => import('@/app/mcp/route.ts')],
  [/^\/mcp\/server-card$/, () => import('@/app/mcp/server-card/route.ts')],
  [/^\/\.well-known\/ai-catalog\.json$/, () => import('@/app/.well-known/ai-catalog.json/route.ts')],
  // After the API's own routes: every other address under /api/, and /api itself.
  [/^\/api(?:\/.*)?$/, () => import('@/app/api/[[...path]]/route.ts')],
  // Last, as in Next.js: every address no file in public/ and no other route answers.
  [/^\/.+$/, () => import('@/app/[...path]/route.ts')],
];

/** The route module for an address, as the Browser and serve() find it. */
export function routeFor(pathname: string): [RegExp, () => Promise<Record<string, any>>] | undefined {
  return ROUTES.find(([re]) => re.test(pathname));
}

/** A browser with a cookie jar that calls the route handlers directly, the way Next.js would. */
export class Browser {
  cookies = new Map<string, string>();
  headers: Record<string, string>;
  constructor(headers: Record<string, string> = {}) {
    this.headers = headers;
  }

  async request(
    method: string,
    target: string,
    {
      json,
      body,
      headers = {},
      query,
    }: { json?: unknown; body?: string; headers?: Record<string, string>; query?: Record<string, string> } = {},
  ): Promise<Response> {
    const url = new URL(target, 'http://127.0.0.1:3340');
    for (const [k, v] of Object.entries(query || {})) url.searchParams.set(k, v);
    const h = new Headers({ ...this.headers, ...headers });
    if (this.cookies.size) h.set('cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    if (json !== undefined) {
      body = JSON.stringify(json);
      h.set('content-type', 'application/json');
    }
    const found = routeFor(url.pathname);
    if (!found) throw new Error(`no route for ${url.pathname}`);
    const mod = await found[1]();
    const handler = mod[method];
    if (!handler) return new Response(null, { status: 405 });
    const m = found[0].exec(url.pathname)!;
    const ctx = {
      params: Promise.resolve({ owner: decodeURIComponent(m[1] || ''), name: decodeURIComponent(m[2] || '') }),
    };
    const res: Response = await handler(new NextRequest(url, { method, headers: h, body }), ctx);
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';');
      const name = pair.slice(0, pair.indexOf('='));
      const value = pair.slice(pair.indexOf('=') + 1);
      const gone = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a) || /^\s*expires=thu, 01 jan 1970/i.test(a));
      if (gone || !value) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }

  get(target: string, query?: Record<string, string>) {
    return this.request('GET', target, { query });
  }

  post(target: string, json: unknown, headers: Record<string, string> = H) {
    return this.request('POST', target, { json, headers });
  }
}

/** The parsed Set-Cookie value for one cookie on a response, or null. */
export function setCookie(res: Response, name: string): string | null {
  for (const line of res.headers.getSetCookie()) {
    const pair = line.split(';')[0];
    if (pair.startsWith(`${name}=`)) return pair.slice(name.length + 1) || null;
  }
  return null;
}

// ------------------------------------------------------------------------------------ test setup
const ENV_KEYS =
  /^(SOSF_|GITHUB_APP_|GITHUB_FIX_APP_|AGENT_|VERCEL$|SITE_BASE_URL$|TRUST_PROXY_HEADERS$|GITHUB_TOKEN$|GH_TOKEN$)/;

/** SOSF_SECRET for the tests: long enough (32 characters or more) for lib/sealed.ts to use. */
export const TEST_SECRET = 'test-secret-0123456789abcdef-0123456789';

/** A clean environment for each test: a fresh data folder, a test secret, no app, no AI service, a fake world. */
export function useTestEnv(): { world: () => FakeWorld; dataDir: () => string } {
  let world: FakeWorld;
  let dir: string;
  const saved = { ...process.env };
  beforeEach(async () => {
    for (const k of Object.keys(process.env)) if (ENV_KEYS.test(k)) delete process.env[k];
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sosf-test-'));
    process.env.SOSF_DATA_DIR = dir;
    process.env.SOSF_SECRET = TEST_SECRET;
    process.env.GITHUB_TOKEN = 'server-token';
    world = new FakeWorld();
    vi.stubGlobal('fetch', world.fetch);
    const [{ repoCache }, { clearRefCache }, { resetLimits }, { clearScanCache }, { resetScanToken }] =
      await Promise.all([
        import('@/lib/github-app.ts'),
        import('@/lib/fixes.ts'),
        import('@/lib/limits.ts'),
        import('@/lib/public-scan.ts'),
        import('@/lib/scan-token.ts'),
      ]);
    repoCache.clear();
    clearRefCache();
    resetLimits();
    clearScanCache();
    resetScanToken();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
    for (const k of Object.keys(process.env)) if (ENV_KEYS.test(k)) delete process.env[k];
    Object.assign(process.env, Object.fromEntries(Object.entries(saved).filter(([k]) => ENV_KEYS.test(k))));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { world: () => world, dataDir: () => dir };
}

/** Configure the site's GitHub App the only way there is: its GITHUB_APP_* settings (useTestEnv clears them). */
export function configure(cfg: Omit<typeof CFG, 'html_url'> = CFG): void {
  Object.assign(process.env, {
    GITHUB_APP_ID: String(cfg.id),
    GITHUB_APP_SLUG: cfg.slug,
    GITHUB_APP_CLIENT_ID: cfg.client_id,
    GITHUB_APP_CLIENT_SECRET: cfg.client_secret,
    GITHUB_APP_PRIVATE_KEY: cfg.pem,
    GITHUB_APP_OWNER: cfg.owner,
    GITHUB_APP_PUBLIC: String(cfg.public),
  });
}

/** Configure the fix app, the same way: its three GITHUB_FIX_APP_* settings. */
export function configureFix(cfg: typeof FIX_CFG = FIX_CFG): void {
  Object.assign(process.env, {
    GITHUB_FIX_APP_ID: String(cfg.id),
    GITHUB_FIX_APP_SLUG: cfg.slug,
    GITHUB_FIX_APP_PRIVATE_KEY: cfg.pem,
  });
}

/** Give the browser a sign-in cookie, as the OAuth callback would, under the name this site uses now. */
export async function signIn(
  b: Browser,
  { token = ADMIN, login = 'octo', appId = CFG.id, exp, ...extra }: Record<string, any> = {},
): Promise<string> {
  const { seal } = await import('@/lib/sealed.ts');
  const { sessionCookie } = await import('@/lib/github-app.ts');
  const cookie = seal('session', { login, token, app_id: appId, exp: exp ?? Date.now() / 1000 + 3600, ...extra });
  b.cookies.set(sessionCookie(), cookie);
  return cookie;
}

/** A sealed state for a GitHub round trip, with its nonce cookie set on the browser like /app/login does. */
export async function startedState(b: Browser, next = '/'): Promise<string> {
  const { newState, stateCookie } = await import('@/lib/github-app.ts');
  const [state, nonce] = newState(next);
  b.cookies.set(stateCookie(), nonce);
  return state;
}

/** The whole Set-Cookie line for one cookie on a response, or null. */
export function setCookieLine(res: Response, name: string): string | null {
  return res.headers.getSetCookie().find((line) => line.startsWith(`${name}=`)) ?? null;
}

/** Routes for opening a pull request on the fake repo. */
export function openPrRoutes(world: FakeWorld, number = 3): void {
  world.repo.set('POST /repos/octo/demo/git/trees', [201, { sha: 't' }]);
  world.repo.set('POST /repos/octo/demo/git/commits', [201, { sha: 'c' }]);
  world.repo.set('POST /repos/octo/demo/git/refs', [201, {}]);
  world.repo.set('POST /repos/octo/demo/pulls', [
    201,
    { html_url: `https://github.com/octo/demo/pull/${number}`, number },
  ]);
}
