/**
 * The GitHub App routes: sealed sign-ins and previews, and the pull request fixes. The app comes from the GITHUB_APP_*
 * settings only (tests/attack-surface.test.ts guards that). GitHub is faked (tests/helpers.ts); nothing leaves the
 * machine.
 */
import { describe, expect, it, vi } from 'vitest';
import skeleton from '@/build/skeleton.json';
import { appConfig, FIXES, newState, sessionCookie, SETTINGS_FIX_PERMISSIONS, stateCookie } from '@/lib/github-app.ts';
import { appJwt } from '@/lib/github.ts';
import { seal, unseal } from '@/lib/sealed.ts';
// The page's browser module (allowJs lets TypeScript read it; it isn't type-checked).
import * as core from '../public/shared/core.js';
import {
  ADMIN,
  ALL_WRITE,
  BEFORE_SPLIT,
  Browser,
  CFG,
  configure,
  configureFix,
  FIX_CFG,
  FIX_PERMS,
  H,
  MAIN_READ,
  openPrRoutes,
  PEM,
  READER,
  setCookie,
  signIn,
  startedState,
  useTestEnv,
} from './helpers.ts';

const env = useTestEnv();
const sg: any = core;

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
  // It scanned with a token for that repository alone that only reads, and read the advisories with another, which
  // holds nothing else.
  expect(w.tokenRequests.slice(-2)).toEqual([
    {
      repositories: ['demo'],
      permissions: {
        administration: 'read',
        contents: 'read',
        metadata: 'read',
        pull_requests: 'read',
        secrets: 'read',
      },
    },
    { repositories: ['demo'], permissions: { repository_advisories: 'read', metadata: 'read' } },
  ]);
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

// ---------------------------------------------------------------------------------------------- two apps
describe('two apps: the main app reads, and the fix app changes things', () => {
  const ADVISORIES = { repository_advisories: 'read', metadata: 'read' };
  const INSTALL_FIX = `https://github.com/apps/${FIX_CFG.slug}/installations/new`;
  /** What Deep scan's token holds on a personal account's installation: organization permissions aren't asked for. */
  const { members: _members, organization_administration: _orgAdmin, ...PERSONAL_READ } = MAIN_READ;

  /** A signed-in admin of octo/demo, in a world that names each token apart. */
  async function admin() {
    const w = env.world();
    w.distinctTokens = true;
    w.repo.set('GET /repos/octo/demo/security-advisories', [200, []]);
    const c = new Browser();
    await signIn(c);
    return { w, c };
  }

  it('gives Deep scan a token that only reads, even while the main app can still write', async () => {
    configure();
    const { w, c } = await admin();
    w.perms = { ...BEFORE_SPLIT };
    w.account = { login: 'octo', type: 'Organization' };
    const r = await c.post('/api/app/check', { repo: 'octo/demo' });
    expect(r.status).toBe(200);
    // Every read Deep scan uses, nothing that writes, and not the advisories: they get a token of their own.
    expect(w.tokenRequests).toEqual([
      { repositories: ['demo'], permissions: MAIN_READ },
      { repositories: ['demo'], permissions: ADVISORIES },
    ]);
    expect(Object.values(w.tokenRequests[0].permissions).every((v) => v === 'read')).toBe(true);
    const [scanToken, reportsToken] = w.tokensOf(5);
    expect(w.callsBy(scanToken).every((call) => call.startsWith('GET '))).toBe(true);
    expect(w.callsBy(scanToken).filter((call) => call.includes('/security-advisories'))).toEqual([]);
    // The advisories' token read the four lists, and nothing else.
    expect(w.callsBy(reportsToken).map((call) => /state=(\w+)/.exec(call)![1])).toEqual(
      expect.arrayContaining(['published', 'triage', 'closed', 'draft']),
    );
    expect(w.callsBy(reportsToken).every((call) => call.startsWith('GET /repos/octo/demo/security-advisories?'))).toBe(
      true,
    );
    expect((await r.json()).results['disc-triage-sla'].status).toBe('info');
  });

  it('with the fix app, fixes and reads the advisories through it, and Deep scans through the main app', async () => {
    configure();
    configureFix();
    const { w, c } = await admin();
    w.perms = { ...MAIN_READ };

    // Deep scan: the main app's token reads; the fix app's reads the advisories, and nothing else.
    const rep = await (await c.post('/api/app/check', { repo: 'octo/demo' })).json();
    expect(rep.results['disc-triage-sla'].status).toBe('info');
    expect(w.tokenRequests).toEqual([{ repositories: ['demo'], permissions: PERSONAL_READ }]);
    expect(w.fixTokenRequests).toEqual([{ repositories: ['demo'], permissions: ADVISORIES }]);
    const [reports] = w.tokensOf(7);
    expect(w.callsBy(reports)).toHaveLength(4);
    expect(w.callsBy(reports).every((call) => call.startsWith('GET /repos/octo/demo/security-advisories?'))).toBe(true);

    // A settings fix: a fix app token that holds only what that fix takes, and makes the one call.
    w.repo.set('PUT /repos/octo/demo/private-vulnerability-reporting', [204, null]);
    const done = await (await c.post('/api/app/fix', { repo: 'octo/demo', fix_id: 'enable-private-reporting' })).json();
    expect(done).toMatchObject({ ok: true, status: 204 });
    expect(w.fixTokenRequests.at(-1)).toEqual({
      repositories: ['demo'],
      permissions: { administration: 'write', metadata: 'read' },
    });
    expect(w.callsBy(w.tokensOf(7).at(-1)!)).toEqual(['PUT /repos/octo/demo/private-vulnerability-reporting']);
    expect(w.tokenRequests).toHaveLength(1); // the main app minted nothing for it

    // A pull request fix: the main app's read-only token builds the preview, and the fix app's opens it.
    const view = await (await c.post('/api/app/pr/preview', { repo: 'octo/demo', item_id: 'disc-security-md' })).json();
    expect(view.files[0].path).toBe('SECURITY.md');
    expect(w.tokenRequests.at(-1)).toEqual({
      repositories: ['demo'],
      permissions: { contents: 'read', pull_requests: 'read', metadata: 'read' },
    });
    expect(w.callsBy(w.tokensOf(5).at(-1)!).every((call) => call.startsWith('GET '))).toBe(true);
    openPrRoutes(w);
    expect((await (await c.post('/api/app/pr', { plan: view.plan })).json()).number).toBe(3);
    expect(w.fixTokenRequests.at(-1)).toEqual({
      repositories: ['demo'],
      permissions: { contents: 'write', pull_requests: 'write', metadata: 'read' },
    });
    expect(w.callsBy(w.tokensOf(7).at(-1)!).filter((call) => !call.startsWith('GET '))).toEqual([
      'POST /repos/octo/demo/git/trees',
      'POST /repos/octo/demo/git/commits',
      'POST /repos/octo/demo/git/refs',
      'POST /repos/octo/demo/pulls',
    ]);

    // What the page reads: the fix app's name and install page, and that it's installed here.
    const st = await (await c.get('/api/app/status')).json();
    expect(st.fix_app).toEqual({ configured: true, slug: FIX_CFG.slug, install_url: INSTALL_FIX });
    const info = await (await c.post('/api/app/repo', { repo: 'octo/demo' })).json();
    expect(info).toMatchObject({
      installed: true,
      can_settings: true,
      can_pr: true,
      can_pr_workflows: true,
      fix_app: {
        configured: true,
        installed: true,
        install_url: INSTALL_FIX,
        manage_url: 'https://github.com/settings/installations/7',
      },
    });
    expect(sg.fixerOn(st, info)).toMatchObject({ fix: true, name: FIX_CFG.slug, installed: true });
  });

  it('without the fix app, fixes go through the main app, each token cut down to its request', async () => {
    configure();
    const { w, c } = await admin();
    w.perms = { ...BEFORE_SPLIT };
    w.repo.set('PUT /repos/octo/demo/private-vulnerability-reporting', [204, null]);
    const done = await (await c.post('/api/app/fix', { repo: 'octo/demo', fix_id: 'enable-private-reporting' })).json();
    expect(done.ok).toBe(true);
    expect(w.tokenRequests.at(-1)).toEqual({
      repositories: ['demo'],
      permissions: { administration: 'write', metadata: 'read' },
    });
    const view = await (await c.post('/api/app/pr/preview', { repo: 'octo/demo', item_id: 'disc-security-md' })).json();
    expect(w.tokenRequests.at(-1)).toEqual({
      repositories: ['demo'],
      permissions: { contents: 'read', pull_requests: 'read', metadata: 'read' },
    });
    openPrRoutes(w);
    expect((await c.post('/api/app/pr', { plan: view.plan })).status).toBe(200);
    expect(w.tokenRequests.at(-1)).toEqual({
      repositories: ['demo'],
      permissions: { contents: 'write', pull_requests: 'write', metadata: 'read' },
    });
    expect(w.fixTokenRequests).toEqual([]);
    const st = await (await c.get('/api/app/status')).json();
    expect(st.fix_app).toEqual({ configured: false, slug: null, install_url: null });
    const info = await (await c.post('/api/app/repo', { repo: 'octo/demo' })).json();
    expect(info).toMatchObject({
      installed: true,
      can_settings: true,
      can_pr: true,
      fix_app: { configured: false, installed: null, install_url: null, manage_url: null },
    });
    // The page sends people to the main app, as before there were two.
    expect(sg.fixerOn(st, info)).toMatchObject({ fix: false, name: 'the GitHub App', installed: true });
  });

  it('asks for only the permission each settings fix takes', async () => {
    configure();
    configureFix();
    const { w, c } = await admin();
    // Every settings fix in the guide says what it takes, so none is left out of the ones offered.
    expect(Object.keys(FIXES).sort()).toEqual(Object.keys(skeleton.app_fixes).sort());
    for (const [id, fix] of Object.entries(FIXES)) {
      const path = fix.path.replace('{owner}', 'octo').replace('{repo}', 'demo');
      w.repo.set(`${fix.method} ${path}`, [204, null]);
      expect(await (await c.post('/api/app/fix', { repo: 'octo/demo', fix_id: id })).json(), id).toMatchObject({
        ok: true,
      });
      expect(w.fixTokenRequests.at(-1), id).toEqual({
        repositories: ['demo'],
        permissions: { ...SETTINGS_FIX_PERMISSIONS[id], metadata: 'read' },
      });
      expect(w.callsBy(w.tokensOf(7).at(-1)!), id).toEqual([`${fix.method} ${path}`]);
    }
    // GitHub lists all nine under Administration (write), CodeQL default setup included.
    expect(new Set(Object.values(SETTINGS_FIX_PERMISSIONS).map((p) => JSON.stringify(p)))).toEqual(
      new Set([JSON.stringify({ administration: 'write' })]),
    );
    // An installation without it gets no token, and a reason.
    w.fixPerms = { ...FIX_PERMS, administration: 'read' };
    const r = await c.post('/api/app/fix', { repo: 'octo/demo', fix_id: 'enable-private-reporting' });
    expect(r.status).toBe(403);
    expect((await r.json()).error.message).toBe(
      `The ${FIX_CFG.slug} app on octo/demo can't change settings yet. It needs write access to administration.`,
    );
  });

  it('says where the fix app is missing and offers its install, while Deep scan carries on', async () => {
    configure();
    configureFix();
    const { w, c } = await admin();
    w.perms = { ...MAIN_READ };
    w.fixInstalled = false;
    const st = await (await c.get('/api/app/status')).json();
    expect(st.fix_app).toEqual({ configured: true, slug: FIX_CFG.slug, install_url: INSTALL_FIX });
    const info = await (await c.post('/api/app/repo', { repo: 'octo/demo' })).json();
    expect(info).toMatchObject({
      admin: true,
      installed: true,
      can_settings: false,
      can_pr: false,
      can_pr_workflows: false,
      fix_app: { configured: true, installed: false, install_url: INSTALL_FIX, manage_url: null },
    });
    // The page asks for the fix app, by its name, with a link to install it (public/shared/core.js).
    expect(sg.fixerOn(st, info)).toEqual({
      fix: true,
      name: FIX_CFG.slug,
      slug: FIX_CFG.slug,
      installed: false,
      install_url: INSTALL_FIX,
      manage_url: null,
    });
    // Without its name in the status, the page calls it "the sossscan fix app".
    expect(sg.fixerOf({ fix_app: { configured: true } }).name).toBe('the sossscan fix app');
    // A fix says the same, and the main app isn't asked for a token instead.
    for (const [path, body] of [
      ['/api/app/fix', { repo: 'octo/demo', fix_id: 'enable-private-reporting' }],
      ['/api/app/pr/preview', { repo: 'octo/demo', item_id: 'disc-security-md' }],
    ] as const) {
      const r = await c.post(path, body);
      expect(r.status, path).toBe(404);
      expect((await r.json()).error, path).toEqual({
        code: 'app_not_installed',
        message: `The ${FIX_CFG.slug} app is not installed on octo/demo.`,
        hint: `Install it from ${INSTALL_FIX}, then try again.`,
      });
    }
    expect(w.tokenRequests).toEqual([]);
    // Deep scan works through the main app, and the private-report checks say what they need. Nothing reads them.
    const rep = await (await c.post('/api/app/check', { repo: 'octo/demo' })).json();
    expect(rep.results['disc-triage-sla']).toMatchObject({
      status: 'unknown',
      summary:
        `Couldn't read the private vulnerability reports: Deep scan reads them through ${FIX_CFG.slug}, the app ` +
        "for one-click fixes, which isn't installed on this repository. Install it if you want this check, or use " +
        "the CLI with an admin's token",
    });
    expect(w.fixTokenRequests).toEqual([]);
    expect(w.used.filter(([, , p]) => /security-advisories\?state=(?:triage|closed|draft)/.test(p))).toEqual([]);
    // The answer without it wasn't kept, so once it's installed the next one says so.
    w.fixInstalled = true;
    expect((await (await c.post('/api/app/repo', { repo: 'octo/demo' })).json()).fix_app.installed).toBe(true);
  });

  it("builds a preview with the fix app's read-only token where only the fix app is installed", async () => {
    configure();
    configureFix();
    const { w, c } = await admin();
    w.installed = false;
    const view = await (await c.post('/api/app/pr/preview', { repo: 'octo/demo', item_id: 'disc-security-md' })).json();
    expect(view.files[0].path).toBe('SECURITY.md');
    expect(w.tokenRequests).toEqual([]);
    expect(w.fixTokenRequests).toEqual([
      { repositories: ['demo'], permissions: { contents: 'read', pull_requests: 'read', metadata: 'read' } },
    ]);
    // Deep scan needs the main app.
    const r = await c.post('/api/app/check', { repo: 'octo/demo' });
    expect(r.status).toBe(404);
    expect((await r.json()).error.message).toBe(`The ${CFG.slug} app is not installed on octo/demo.`);
  });

  it("carries on with Deep scan when the advisories' token can't be had, and says why", async () => {
    configure();
    configureFix();
    const { w, c } = await admin();
    w.perms = { ...MAIN_READ };
    const summary = async () => {
      const r = await c.post('/api/app/check', { repo: 'octo/demo' });
      expect(r.status).toBe(200);
      return (await r.json()).results['disc-triage-sla'].summary;
    };
    // GitHub refuses the fix app's token: the rest of the scan goes on, and the check gives GitHub's answer.
    w.fixTokenStatus = 500;
    expect(await summary()).toBe(
      `Couldn't read the private vulnerability reports: GitHub didn't give the ${FIX_CFG.slug} app a token for ` +
        "octo/demo (HTTP 500). Run Deep scan again in a minute, or use the CLI with an admin's token",
    );
    // A fix app key that isn't one: the same, without quoting it.
    configureFix({ ...FIX_CFG, pem: '-----BEGIN PRIVATE KEY-----\nnot-really-a-key\n-----END PRIVATE KEY-----\n' });
    const said = await summary();
    expect(said).toBe(
      "Couldn't read the private vulnerability reports: the server couldn't make a token for them. Run Deep scan " +
        "again in a minute, or use the CLI with an admin's token",
    );
    expect(w.used.filter(([, , p]) => /security-advisories\?state=(?:triage|closed|draft)/.test(p))).toEqual([]);
  });

  it('reads the advisories through the main app while only it may, and otherwise says how to let the fix app', async () => {
    configure();
    configureFix();
    const { w, c } = await admin();
    w.perms = { ...BEFORE_SPLIT };
    w.fixPerms = { ...FIX_PERMS, repository_advisories: null };
    let rep = await (await c.post('/api/app/check', { repo: 'octo/demo' })).json();
    expect(rep.results['disc-triage-sla'].status).toBe('info');
    expect(w.tokenRequests.at(-1)).toEqual({ repositories: ['demo'], permissions: ADVISORIES });
    expect(w.fixTokenRequests).toEqual([]);
    w.perms = { ...MAIN_READ };
    rep = await (await c.post('/api/app/check', { repo: 'octo/demo' })).json();
    expect(rep.results['disc-triage-sla'].summary).toBe(
      `Couldn't read the private vulnerability reports: ${FIX_CFG.slug} hasn't been given access to security ` +
        "advisories on this installation. An owner can approve the new permission in the installation's settings, " +
        "or use the CLI with an admin's token",
    );
  });
});
