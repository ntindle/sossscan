/**
 * The GitHub App routes: sealed sign-ins and previews, and the pull request fixes. The app comes from the GITHUB_APP_*
 * settings only (tests/attack-surface.test.ts guards that). GitHub is faked (tests/helpers.ts); nothing leaves the
 * machine.
 */
import { describe, expect, it, vi } from 'vitest';
import { appConfig, newState, sessionCookie, stateCookie } from '@/lib/github-app.ts';
import { appJwt } from '@/lib/github.ts';
import { seal, unseal } from '@/lib/sealed.ts';
import {
  ADMIN,
  ALL_WRITE,
  Browser,
  CFG,
  configure,
  H,
  openPrRoutes,
  PEM,
  READER,
  setCookie,
  signIn,
  startedState,
  useTestEnv,
} from './helpers.ts';

const env = useTestEnv();

// ------------------------------------------------------------------------------------------ sealed data
describe('sealed values', () => {
  it('resist tampering, reuse and age', () => {
    const token = seal('plan', { repo: 'octo/demo' });
    expect(unseal('plan', token, 60)).toEqual({ repo: 'octo/demo' });
    expect(unseal('session', token, 60)).toBeNull(); // another purpose can't read it
    const at = token.length - 6;
    const flipped = token.slice(0, at) + (token[at] !== 'A' ? 'A' : 'B') + token.slice(at + 1);
    expect(unseal('plan', flipped, 60)).toBeNull();
    expect(unseal('plan', 'not-a-token', 60)).toBeNull();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() - 3600_000);
    const old = seal('plan', { x: 1 });
    vi.useRealTimers();
    expect(unseal('plan', old, 60)).toBeNull();
    expect(unseal('plan', old, 7200)).toEqual({ x: 1 });
    process.env.SOSF_SECRET = 'a-different-secret-and-just-as-long-as-the-first';
    expect(unseal('plan', token, 60)).toBeNull(); // a new secret signs everyone out
  });
});

it('takes the app credentials from the environment', () => {
  Object.assign(process.env, {
    GITHUB_APP_ID: '77',
    GITHUB_APP_SLUG: 'sossscan',
    GITHUB_APP_CLIENT_ID: 'Iv1.env',
    GITHUB_APP_CLIENT_SECRET: 'sec',
    GITHUB_APP_OWNER: 'octo',
    GITHUB_APP_PUBLIC: 'true',
    GITHUB_APP_PRIVATE_KEY: PEM.replaceAll('\n', '\\n'), // one line, the way some settings forms take it
  });
  const cfg = appConfig()!;
  expect(cfg).toEqual({
    id: 77,
    slug: 'sossscan',
    client_id: 'Iv1.env',
    client_secret: 'sec',
    pem: PEM,
    html_url: 'https://github.com/apps/sossscan',
    owner: 'octo',
    public: true,
  });
  const [, payload] = appJwt(cfg).split('.');
  expect(JSON.parse(Buffer.from(payload, 'base64url').toString()).iss).toBe('Iv1.env');
  delete process.env.GITHUB_APP_OWNER; // the two optional ones
  delete process.env.GITHUB_APP_PUBLIC;
  expect(appConfig()).toMatchObject({ id: 77, owner: '', public: false });
});

// ---------------------------------------------------------------------------------------------- status
it('lists the settings and pull request fixes', async () => {
  const c = new Browser();
  expect((await (await c.get('/api/app/status')).json()).configured).toBe(false);
  configure();
  await signIn(c);
  const st = await (await c.get('/api/app/status')).json();
  expect(st.user).toBe('octo');
  expect(st.owner).toBe('octo');
  expect(st.public).toBe(false);
  expect(st.pr_fixes).toHaveProperty('ci-pin-actions');
  expect(st.fixes).toHaveProperty('enable-private-reporting');
});

it('ignores stale or foreign sign-ins', async () => {
  configure();
  const c = new Browser();
  await signIn(c, { appId: 999 }); // made through another app: the settings have changed since
  expect((await (await c.get('/api/app/status')).json()).user).toBeNull();
  await signIn(c, { exp: Date.now() / 1000 - 1 }); // past its own expiry
  expect((await (await c.get('/api/app/status')).json()).user).toBeNull();
  c.cookies.set(sessionCookie(), 'forged');
  expect((await (await c.get('/api/app/status')).json()).user).toBeNull();
});

// ---------------------------------------------------------------------------------------------- sign-in
it('refuses a state from another browser', async () => {
  configure();
  const c = new Browser();
  const state = await startedState(c, '/somewhere');
  c.cookies.set(stateCookie(), 'someone-elses-nonce');
  const r = await c.get('/app/oauth-callback', { code: 'x', state });
  expect(r.headers.get('location')).toBe('/?app=signin-expired');
});

it('returns every sign-in outcome to the page, with a reason', async () => {
  configure();
  const c = new Browser();
  let state = await startedState(c, '/?repo=octo/demo#item-ci-pin-actions');
  let r = await c.get('/app/oauth-callback', { error: 'access_denied', state });
  expect(r.status).toBe(303);
  expect(r.headers.get('location')).toBe('/?repo=octo%2Fdemo&app=signin-cancelled#item-ci-pin-actions');
  expect((await c.get('/app/oauth-callback', { code: 'x', state: 'nope' })).headers.get('location')).toBe(
    '/?app=signin-expired',
  );

  state = await startedState(c, '/?repo=octo/demo');
  env.world().oauthAnswer = [200, { access_token: ADMIN }];
  r = await c.get('/app/oauth-callback', { code: 'x', state });
  expect(r.headers.get('location')).toBe('/?repo=octo%2Fdemo&app=signed-in');
  const sess = unseal('session', setCookie(r, 'sosf_session'), 60)!;
  expect(sess).toMatchObject({ login: 'octo', token: ADMIN, app_id: CFG.id });
  const line = r.headers.getSetCookie().find((l) => l.startsWith('sosf_session='))!;
  expect(line.toLowerCase()).toContain('httponly');
  expect(line.toLowerCase()).toContain('samesite=lax');
});

describe('login', () => {
  it.each(['//evil.example/', '/\\evil.example/', 'https://evil.example/', '/x\nLocation: //evil', 'evil'])(
    'refuses the off-site next %j',
    async (bad) => {
      configure();
      const r = await new Browser().get('/app/login', { next: bad });
      const state = new URL(r.headers.get('location')!).searchParams.get('state');
      expect(unseal('state', state, 60)!.next).toBe('/');
    },
  );

  it('keeps an on-site next', async () => {
    configure();
    const r = await new Browser().get('/app/login', { next: '/?repo=a/b#hop=ci' });
    const target = new URL(r.headers.get('location')!);
    expect(target.origin + target.pathname).toBe('https://github.com/login/oauth/authorize');
    expect(target.searchParams.get('redirect_uri')).toBe('http://127.0.0.1:3340/app/oauth-callback');
    expect(unseal('state', target.searchParams.get('state'), 60)!.next).toBe('/?repo=a/b#hop=ci');
    expect(setCookie(r, 'sosf_state')).toBeTruthy();
  });
});

it('signs out', async () => {
  configure();
  const c = new Browser();
  await signIn(c);
  const r = await c.get('/app/logout');
  expect(r.headers.get('location')).toBe('/?app=signed-out');
  expect(c.cookies.has('sosf_session')).toBe(false);
});

// ------------------------------------------------------------------------------------------- repo status
it('reports repo status for admins and others', async () => {
  configure();
  const c = new Browser();
  expect((await c.post('/api/app/repo', { repo: 'octo/demo' }, {})).status).toBe(400);
  expect((await c.post('/api/app/repo', { repo: 'octo/demo' })).status).toBe(401);
  await signIn(c, { token: READER, login: 'eve' });
  let st = await (await c.post('/api/app/repo', { repo: 'octo/demo' })).json();
  expect(st.admin).toBe(false);
  expect(st.installed).toBeNull();
  await signIn(c);
  const r = await c.post('/api/app/repo', { repo: 'octo/demo' });
  expect(r.headers.get('cache-control')).toBe('private, no-store');
  st = await r.json();
  expect(st).toMatchObject({ admin: true, installed: true, can_pr_workflows: true, can_settings: true });
  expect(st.manage_url).toBe('https://github.com/settings/installations/5');
});

it('asks GitHub again while the app is not installed, so an install shows up at once', async () => {
  configure();
  const c = new Browser();
  await signIn(c);
  const status = async () => (await c.post('/api/app/repo', { repo: 'octo/demo' })).json();
  env.world().installed = false;
  expect(await status()).toMatchObject({ admin: true, installed: false });
  // Deep scan or a fix sent the person to install the app, and GitHub sent them back within the minute.
  env.world().installed = true;
  expect(await status()).toMatchObject({ admin: true, installed: true });
  // An answer with the app installed is kept for that minute.
  env.world().installed = false;
  expect(await status()).toMatchObject({ installed: true });
});

it('runs a settings fix as the app, for an admin only', async () => {
  configure();
  const c = new Browser();
  await signIn(c, { token: READER, login: 'eve' });
  expect((await c.post('/api/app/fix', { repo: 'octo/demo', fix_id: 'enable-private-reporting' })).status).toBe(403);
  await signIn(c);
  expect((await c.post('/api/app/fix', { repo: 'octo/demo', fix_id: 'no-such-fix' })).status).toBe(422);
  env.world().repo.set('PUT /repos/octo/demo/private-vulnerability-reporting', [204, null]);
  const done = await (await c.post('/api/app/fix', { repo: 'octo/demo', fix_id: 'enable-private-reporting' })).json();
  expect(done).toMatchObject({ ok: true, status: 204, message: 'Done' });
  expect(env.world().repo.made('PUT', '/repos/octo/demo/private-vulnerability-reporting')).toHaveLength(1);
});

it("gives Deep scan the token's permissions, so a check whose permission the installation lacks says so", async () => {
  configure();
  const c = new Browser();
  await signIn(c, { token: READER, login: 'eve' });
  expect((await c.post('/api/app/check', { repo: 'octo/demo' })).status).toBe(403);
  await signIn(c);
  const w = env.world();
  // An installation that hasn't accepted Secrets or Repository security advisories: GitHub refuses the secrets and
  // lists no unpublished advisories, which the scan mustn't read as none.
  w.repo.set('GET /repos/octo/demo/actions/secrets', [403, { message: 'Resource not accessible by integration' }]);
  w.repo.set('GET /repos/octo/demo/security-advisories', [200, []]);
  const check = async () => {
    const r = await c.post('/api/app/check', { repo: 'octo/demo' });
    expect([r.status, r.headers.get('cache-control')]).toEqual([200, 'private, no-store']);
    const rep = await r.json();
    expect(rep.layer).toBe('app');
    return (id: string) => [rep.results[id]?.status, rep.results[id]?.summary];
  };
  let got = await check();
  expect(got('ci-secrets-hygiene')).toEqual([
    'unknown',
    "Couldn't read the names of Actions secrets: the GitHub App hasn't been given access to them on this " +
      "installation. An owner can approve the new permission in the installation's settings, or use the CLI with " +
      "an admin's token",
  ]);
  expect(got('disc-triage-sla')[1]).toMatch(/^Couldn't read the private vulnerability reports: the GitHub App hasn't/);
  // Once it accepts them.
  w.perms = { ...w.perms, secrets: 'read', repository_advisories: 'read' };
  w.repo.set('GET /repos/octo/demo/actions/secrets', [200, { total_count: 2, secrets: [{ name: 'PYPI_TOKEN' }] }]);
  got = await check();
  expect(got('ci-secrets-hygiene')).toEqual([
    'info',
    '2 repository Actions secret(s); prefer environment secrets and OIDC',
  ]);
  expect(got('disc-triage-sla')).toEqual(['info', 'No private vulnerability reports are waiting in triage']);
  // The token it scanned with was one for that repository alone, with all the installation's permissions.
  expect(w.tokenRequests.at(-1)).toEqual({ repositories: ['demo'] });
});

// ------------------------------------------------------------------------------------- pull request fixes
it('checks admin, install and permissions before a preview', async () => {
  configure();
  const c = new Browser();
  const body = { repo: 'octo/demo', item_id: 'disc-security-md' };
  expect((await c.post('/api/app/pr/preview', body)).status).toBe(401);
  await signIn(c, { token: READER, login: 'eve' });
  expect((await c.post('/api/app/pr/preview', body)).status).toBe(403);
  await signIn(c);
  expect((await c.post('/api/app/pr/preview', { ...body, item_id: 'acct-2fa-required' })).status).toBe(422);
  env.world().installed = false;
  expect((await c.post('/api/app/pr/preview', body)).status).toBe(404);
  env.world().installed = true;
  env.world().perms = { contents: 'read', metadata: 'read' };
  let r = await c.post('/api/app/pr/preview', body);
  expect(r.status).toBe(403);
  expect((await r.json()).detail).toContain('contents, pull requests');
  env.world().perms = { ...ALL_WRITE, workflows: null };
  r = await c.post('/api/app/pr/preview', { ...body, item_id: 'ci-pin-actions' });
  expect(r.status).toBe(403);
  expect((await r.json()).detail).toContain('workflows');
});

it('previews, then opens, and a replay gets the same pull request', async () => {
  configure();
  const world = env.world();
  const c = new Browser();
  await signIn(c);
  const view = await (await c.post('/api/app/pr/preview', { repo: 'octo/demo', item_id: 'disc-security-md' })).json();
  expect(view.files[0].path).toBe('SECURITY.md');
  expect(view.base).toBe('main');
  expect(view.plan.length).toBeGreaterThan(100);
  expect(view.plan).not.toContain('SECURITY.md'); // sealed: the browser carries it but can't read or change it
  expect(world.repo.made('POST', '/')).toHaveLength(0); // a preview never writes

  const other = new Browser();
  await signIn(other, { token: ADMIN, login: 'mallory' });
  expect((await other.post('/api/app/pr', { plan: view.plan })).status).toBe(410);
  expect((await c.post('/api/app/pr', { plan: `${view.plan.slice(0, -8)}AAAAAAAA` })).status).toBe(410);

  openPrRoutes(world);
  const r = await c.post('/api/app/pr', { plan: view.plan });
  expect(await r.json()).toEqual({
    ok: true,
    url: 'https://github.com/octo/demo/pull/3',
    number: 3,
    branch: 'sosf/disc-security-md',
  });
  expect(world.tokenRequests.at(-1)).toEqual({
    repositories: ['demo'],
    permissions: { contents: 'write', pull_requests: 'write', metadata: 'read' },
  });
  const [tree] = world.repo.made('POST', '/repos/octo/demo/git/trees');
  expect(tree[2].tree[0].path).toBe('SECURITY.md');
  expect(tree[2].tree[0].content).toContain('advisories/new');

  world.repo.set('GET /repos/octo/demo/pulls', [200, [{ html_url: 'https://github.com/octo/demo/pull/3', number: 3 }]]);
  const again = await (await c.post('/api/app/pr', { plan: view.plan })).json();
  expect(again.existing).toBe(true);
  expect(again.number).toBe(3);
  expect(world.repo.made('POST', '/repos/octo/demo/pulls')).toHaveLength(1);
});

it('refuses an old preview', async () => {
  configure();
  const c = new Browser();
  await signIn(c, { exp: Date.now() / 1000 + 7200 });
  const view = await (await c.post('/api/app/pr/preview', { repo: 'octo/demo', item_id: 'disc-security-md' })).json();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(Date.now() + 16 * 60_000);
  expect((await c.post('/api/app/pr', { plan: view.plan })).status).toBe(410);
});

it('reports a pull request that is already open', async () => {
  configure();
  const c = new Browser();
  await signIn(c);
  env
    .world()
    .repo.set('GET /repos/octo/demo/pulls', [200, [{ html_url: 'https://github.com/octo/demo/pull/2', number: 2 }]]);
  const r = await (await c.post('/api/app/pr/preview', { repo: 'octo/demo', item_id: 'disc-security-md' })).json();
  expect(r).toEqual({ existing: { url: 'https://github.com/octo/demo/pull/2', number: 2 } });
});

it('makes a state whose nonce the same browser must hold, and nothing else', () => {
  const [state, nonce] = newState('/x');
  expect(unseal('state', state, 60)).toEqual({ next: '/x', nonce });
  expect(H['x-requested-with']).toBe('sosf');
});
