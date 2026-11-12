/**
 * Optional GitHub App layer: sign in, check admin settings, and fix things in one click.
 *
 * The site uses up to two apps, which already exist on GitHub; its operator configures them in the environment:
 * - the main app (GITHUB_APP_*): sign-in, Deep scan and public scans' token. It only needs to read.
 * - the fix app (GITHUB_FIX_APP_*), optional: one-click fixes, pull request fixes and the private-report checks, the
 *   only things that need write access or a repository's security advisories. People install it only if they want
 *   those. It signs no one in, so it has no client ID or secret. Without it, fixes go through the main app.
 * Each token covers one repository and asks for only what its request needs (the *_PERMISSIONS below), whatever the
 * app could do: Deep scan's never holds a write permission. A stolen token can do no more than that request could.
 * The site can't create, register or replace an app, and nothing here writes an app's credentials: changing an app is
 * an operator's change to those settings. Without the main app's there's no sign-in, and the site works without it.
 * There are two kinds of fix, both allow-listed and both only for a signed-in admin of the repository:
 * - settings: one API call each (FIXES, from app_fixes in build/skeleton.json);
 * - pull requests: a new branch plus a pull request that adds a file, pins actions or carries an AI agent's edit
 *   (lib/fixes.ts), shown to the person as a preview first. Nothing is merged and no existing branch is touched.
 *
 * The server keeps nothing between requests, so it runs on serverless hosts (Vercel) as well as on a plain server:
 * - a sign-in is a sealed cookie, and the sign-in handshake is a sealed value tied to a cookie in the same browser;
 * - a pull request preview goes back to the browser sealed (good only for the person who asked, for 15 minutes), and
 *   the browser sends it back to open the pull request.
 * lib/sealed.ts holds the key handling (SOSF_SECRET).
 */
import crypto from 'node:crypto';
import type { NextRequest, NextResponse } from 'next/server';
import skeleton from '../build/skeleton.json';
import { AgentError, config as agentConfig, usage } from './agent.ts';
import { secureCookies } from './env.ts';
import { available, neededPermissions } from './fixes.ts';
import { appJwt, ghRequest } from './github.ts';
import { HttpError } from './http.ts';
import type { AdvisoryAccess } from './scanner/index.ts';
import { seal, unseal } from './sealed.ts';

export const STATE_TTL = 900;
export const SESSION_TTL = 7 * 3600; // GitHub expires app user tokens after 8 hours
export const PLAN_TTL = 900;
const REPO_TTL = 60;

// ---------------------------------------------------------------------------------------- permissions
// What each token asks GitHub for. GitHub lists the permission every endpoint takes in "Permissions required for
// GitHub Apps" (docs.github.com/en/rest/authentication/permissions-required-for-github-apps).

/**
 * Deep scan's token: read access to everything the admin checks read (lib/scanner/private-layer.ts and scan.ts), and
 * nothing more, even while the main app still holds write access. Not the security advisories (ADVISORY_PERMISSIONS).
 */
export const DEEP_SCAN_PERMISSIONS: Record<string, string> = {
  actions: 'read', // the Actions settings, the workflows, and the deployment environments with their reviewers
  administration: 'read', // Dependabot, CodeQL default setup, the default token, fork approvals, branch protection,
  // immutable releases and the security configuration
  contents: 'read', // a private repository's files and releases
  metadata: 'read',
  pull_requests: 'read', // a private repository's open update pull requests (deps-refresh)
  secret_scanning_alerts: 'read',
  secrets: 'read', // how many Actions secrets there are: GitHub gives names and dates, never values
  security_events: 'read', // the open code scanning alerts
  vulnerability_alerts: 'read', // the open Dependabot alerts
  members: 'read', // an org's members without 2FA, or with SMS for it
  organization_administration: 'read', // an org's 2FA requirement and its default security configurations
};

/** The private-report checks' token: the security advisories, other people's unpublished reports among them. */
export const ADVISORY_PERMISSIONS: Record<string, string> = { repository_advisories: 'read', metadata: 'read' };

/** A pull request fix's preview only reads: the files, the open pull requests and an org's maintainers team. */
export const PREVIEW_PERMISSIONS: Record<string, string> = {
  contents: 'read',
  pull_requests: 'read',
  members: 'read',
  metadata: 'read',
};

/**
 * What each settings fix's one API call takes. GitHub lists all nine under Administration (write), CodeQL default
 * setup included. A fix in build/skeleton.json without an entry here isn't offered (a test checks there's none).
 */
export const SETTINGS_FIX_PERMISSIONS: Record<string, Record<string, string>> = {
  'enable-private-reporting': { administration: 'write' },
  'enable-dependabot-alerts': { administration: 'write' },
  'enable-dependabot-security-updates': { administration: 'write' },
  'enable-secret-scanning': { administration: 'write' },
  'enable-push-protection': { administration: 'write' },
  'workflow-permissions-read': { administration: 'write' },
  'fork-pr-approval': { administration: 'write' },
  'enable-codeql-default-setup': { administration: 'write' },
  'enable-immutable-releases': { administration: 'write' },
};

export type SettingsFix = { label: string; method: string; path: string; body?: unknown; note?: string };
/** One-click settings fixes, from build/skeleton.json: those SETTINGS_FIX_PERMISSIONS says what they take. */
export const FIXES: Record<string, SettingsFix> = Object.fromEntries(
  Object.entries(skeleton.app_fixes as Record<string, SettingsFix>).filter(([id]) =>
    Object.hasOwn(SETTINGS_FIX_PERMISSIONS, id),
  ),
);

// ---------------------------------------------------------------------------------------- credentials
export type AppConfig = {
  id: number;
  slug: string;
  client_id: string;
  client_secret: string;
  pem: string;
  html_url: string;
  owner: string;
  public: boolean;
};

/** The fix app's settings. It signs no one in, so it has no client ID or secret: only installation tokens. */
export type FixAppConfig = { id: number; slug: string; pem: string; html_url: string };

/** Either app, for what both do: find an installation and mint its tokens. */
export type TokenApp = AppConfig | FixAppConfig;

/** An app's ID (a positive integer), slug and private key (real line breaks or \n), checked; null if one isn't. */
function appKeys(
  rawId: string | undefined,
  rawSlug: string | undefined,
  rawPem: string | undefined,
): FixAppConfig | null {
  const id = (rawId || '').trim();
  const slug = (rawSlug || '').trim();
  const pem = (rawPem || '').replaceAll('\\n', '\n');
  if (!/^[1-9]\d*$/.test(id) || !Number.isSafeInteger(Number(id))) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(slug)) return null; // it becomes part of the app's links
  if (!pem.trim()) return null;
  return { id: Number(id), slug, pem, html_url: `https://github.com/apps/${slug}` };
}

/**
 * The site's main app, from the environment and nowhere else, or null when a setting is missing or invalid. Required:
 * GITHUB_APP_ID (a positive integer), _SLUG, _CLIENT_ID, _CLIENT_SECRET and _PRIVATE_KEY (real line breaks or \n).
 * _OWNER and _PUBLIC are optional.
 */
export function appConfig(): AppConfig | null {
  const env = process.env;
  const keys = appKeys(env.GITHUB_APP_ID, env.GITHUB_APP_SLUG, env.GITHUB_APP_PRIVATE_KEY);
  const clientId = (env.GITHUB_APP_CLIENT_ID || '').trim();
  const clientSecret = env.GITHUB_APP_CLIENT_SECRET || '';
  if (!keys || !clientId || !clientSecret.trim()) return null;
  return {
    id: keys.id,
    slug: keys.slug,
    client_id: clientId,
    client_secret: clientSecret,
    pem: keys.pem,
    html_url: keys.html_url,
    owner: (env.GITHUB_APP_OWNER || '').trim(),
    public: ['1', 'true', 'yes'].includes((env.GITHUB_APP_PUBLIC || '').trim().toLowerCase()),
  };
}

/**
 * The fix app, from the environment and nowhere else, or null when it isn't set up: GITHUB_FIX_APP_ID, _SLUG and
 * _PRIVATE_KEY, checked like the main app's. It only counts alongside the main app, which signs people in.
 */
export function fixAppConfig(): FixAppConfig | null {
  const env = process.env;
  return appKeys(env.GITHUB_FIX_APP_ID, env.GITHUB_FIX_APP_SLUG, env.GITHUB_FIX_APP_PRIVATE_KEY);
}

export function configOr404(): AppConfig {
  const cfg = appConfig();
  if (!cfg) {
    throw new HttpError(
      404,
      'app_not_configured',
      "Sign in with GitHub isn't available on this copy of the site.",
      "Use the public scan, or run the CLI with an admin's token for the admin-only checks.",
    );
  }
  return cfg;
}

// -------------------------------------------------------------------------------------------- cookies
/**
 * The site's two cookies. Over https their names carry the __Host- prefix: a browser only takes such a cookie from
 * this exact host, with Secure, Path=/ and no Domain, so another subdomain of the same domain can't plant or overwrite
 * it (cookie tossing). Plain http (a local test site) can't have them, so there they keep their plain names. Read at
 * every call, like the rest of the environment.
 */
export function sessionCookie(): string {
  return secureCookies() ? '__Host-sosf_session' : 'sosf_session';
}

export function stateCookie(): string {
  return secureCookies() ? '__Host-sosf_state' : 'sosf_state';
}

/** Every cookie this site sets: host-only (no Domain), for the whole site, out of scripts' reach, and Lax. */
function putCookie(res: NextResponse, name: string, value: string, maxAge: number): void {
  res.cookies.set(name, value, { httpOnly: true, secure: secureCookies(), sameSite: 'lax', path: '/', maxAge });
}

/**
 * Clear a cookie with the attributes it was set with. A browser ignores a __Host- cookie without Secure, deletions
 * included, so cookies.delete() (which sends no Secure) would leave it in place.
 */
function dropCookie(res: NextResponse, name: string): void {
  putCookie(res, name, '', 0);
}

// ----------------------------------------------------------------------------------------- handshakes
/** A path on this site, or "/". Browsers read "//host" and "/\host" as other sites, so neither is allowed. */
export function safeNext(url: string): string {
  if (
    !url.startsWith('/') ||
    url.startsWith('//') ||
    url.includes('\\') ||
    [...url].some((c) => c.charCodeAt(0) < 32)
  ) {
    return '/';
  }
  try {
    const parsed = new URL(url, 'http://site.invalid');
    return parsed.origin === 'http://site.invalid' ? url : '/';
  } catch {
    return '/';
  }
}

/** A sealed state value for a GitHub sign-in round trip, and the nonce the same browser must hold in a cookie. */
export function newState(next = '/'): [string, string] {
  const nonce = crypto.randomBytes(16).toString('base64url');
  return [seal('state', { next: safeNext(next), nonce }), nonce];
}

export function setStateCookie(res: NextResponse, nonce: string): void {
  putCookie(res, stateCookie(), nonce, STATE_TTL);
}

export function clearStateCookie(res: NextResponse): void {
  dropCookie(res, stateCookie());
}

/** The state, if it's genuine, recent and was started in this browser (so a link can't sign someone in as you). */
export function popState(req: NextRequest, state: string | null): Record<string, any> | null {
  const st = unseal('state', state, STATE_TTL);
  const nonce = req.cookies.get(stateCookie())?.value;
  if (!st || !nonce) return null;
  const want = Buffer.from(String(st.nonce ?? ''));
  const got = Buffer.from(nonce);
  return want.length === got.length && crypto.timingSafeEqual(want, got) ? st : null;
}

/** Add ?key=value to a site-relative URL, keeping its other parameters and its #fragment. */
export function withParam(url: string, key: string, value: string): string {
  const u = new URL(url, 'http://site.invalid');
  u.searchParams.delete(key);
  u.searchParams.append(key, value);
  return `${u.pathname || '/'}${u.search}${u.hash}`;
}

// ------------------------------------------------------------------------------------------- sessions
export type Session = {
  login: string;
  token: string;
  app_id: number;
  exp: number;
  fixes?: Record<string, number>; // AI fixes used today, {"2026-11-05": 2}
};

/** The request's sign-in, if it's genuine, unexpired and made through the app the site uses now. */
export function liveSession(req: NextRequest): Session | null {
  const s = unseal<Session>('session', req.cookies.get(sessionCookie())?.value, SESSION_TTL);
  const cfg = appConfig();
  if (!s || !cfg || s.app_id !== cfg.id || !(s.exp > Date.now() / 1000)) return null;
  return s;
}

export function sessionOf(req: NextRequest): Session {
  const s = liveSession(req);
  if (!s) {
    throw new HttpError(
      401,
      'sign_in_required',
      "You aren't signed in with GitHub, or your sign-in has expired.",
      'Sign in with GitHub, then try again.',
    );
  }
  return s;
}

/** (Re)write the sign-in cookie. It keeps the sign-in's own expiry, so updating it never extends a sign-in. */
export function setSession(res: NextResponse, sess: Session): void {
  putCookie(res, sessionCookie(), seal('session', sess), Math.max(Math.trunc(sess.exp - Date.now() / 1000), 0));
}

export function clearSession(res: NextResponse): void {
  dropCookie(res, sessionCookie());
}

// ---------------------------------------------------------------------------------------------- GitHub
export async function requireAdmin(sess: Session, repo: string): Promise<void> {
  const r = await ghRequest('GET', `/repos/${repo}`, sess.token);
  if (r.status !== 200 || !r.data?.permissions?.admin) {
    throw new HttpError(
      403,
      'not_admin',
      `@${sess.login} is not an admin of ${repo}.`,
      'Sign in as one of its admins, or ask one to do this.',
    );
  }
}

export type Installation = {
  id: number;
  permissions?: Record<string, string>;
  account?: { login?: string; type?: string };
};

export async function installation(app: TokenApp, repo: string): Promise<Installation | null> {
  const r = await ghRequest('GET', `/repos/${repo}/installation`, appJwt(app));
  return r.status === 200 ? r.data : null;
}

/** The app's installation on the repo, or a 404 that says where to install it. */
export async function installed(app: TokenApp, repo: string): Promise<Installation> {
  const inst = await installation(app, repo);
  if (!inst) throw notInstalled(app, repo);
  return inst;
}

function notInstalled(app: TokenApp, repo: string): HttpError {
  return new HttpError(
    404,
    'app_not_installed',
    `The ${app.slug} app is not installed on ${repo}.`,
    `Install it from ${app.html_url}/installations/new, then try again.`,
  );
}

/** Organization permissions, which a token asks for only on an organization's installation. */
const ORG_PERMISSIONS = new Set(['members', 'organization_administration']);
const LEVEL: Record<string, number> = { read: 1, write: 2, admin: 3 };
const holds = (inst: Installation, name: string, level: string) =>
  (LEVEL[inst.permissions?.[name] ?? ''] ?? 0) >= (LEVEL[level] ?? 9);

/**
 * The part of `wanted` an installation holds, to ask a token for: GitHub gives no token to a request that names a
 * permission the installation lacks, so each check whose permission is missing says so instead (Deep scan passes the
 * scanner the permissions GitHub gave). Organization permissions only on an organization's installation.
 */
export function grantable(wanted: Record<string, string>, inst: Installation): Record<string, string> {
  const org = inst.account?.type === 'Organization';
  const out: Record<string, string> = {};
  for (const [name, level] of Object.entries(wanted)) {
    if ((org || !ORG_PERMISSIONS.has(name)) && holds(inst, name, level)) out[name] = level;
  }
  return { ...out, metadata: 'read' }; // every installation has it
}

/** Stop with a 403 unless the installation holds all of `need`. `doing` finishes "can't …", as "open pull requests". */
export function requirePermissions(
  app: TokenApp,
  inst: Installation,
  repo: string,
  need: Record<string, string>,
  doing: string,
): void {
  const missing = Object.entries(need)
    .filter(([name, level]) => !holds(inst, name, level))
    .map(([name]) => name.replaceAll('_', ' '));
  if (missing.length) {
    throw new HttpError(
      403,
      'app_permission_missing',
      `The ${app.slug} app on ${repo} can't ${doing} yet. It needs write access to ${missing.join(', ')}.`,
      "The app's owner can add that in the app's settings, then accept it on the installation.",
    );
  }
}

export async function installationToken(
  app: TokenApp,
  repo: string,
  opts: { permissions?: Record<string, string>; inst?: Installation | null } = {},
): Promise<string> {
  return (await installationAccess(app, repo, opts)).token;
}

/**
 * A token of the app's installation for one repo, and the permissions GitHub gave it (null if it didn't say). Deep
 * scan passes them to the scanner, so a check whose permission an installation hasn't accepted says so.
 */
export async function installationAccess(
  app: TokenApp,
  repo: string,
  { permissions, inst }: { permissions?: Record<string, string>; inst?: Installation | null } = {},
): Promise<{ token: string; permissions: Record<string, string> | null }> {
  const found = inst || (await installation(app, repo));
  if (!found) throw notInstalled(app, repo);
  const body: Record<string, unknown> = { repositories: [repo.split('/')[1]] };
  if (permissions) body.permissions = permissions; // a token that can only do what this request needs
  const r = await ghRequest('POST', `/app/installations/${found.id}/access_tokens`, appJwt(app), body);
  if (r.status !== 201) {
    throw new HttpError(
      502,
      'github_error',
      `GitHub didn't give the ${app.slug} app a token for ${repo} (HTTP ${r.status}).`,
      'Try again in a minute.',
    );
  }
  const given: unknown = r.data.permissions;
  const listed =
    given && typeof given === 'object' && !Array.isArray(given)
      ? Object.fromEntries(Object.entries(given).filter((e): e is [string, string] => typeof e[1] === 'string'))
      : null;
  return { token: r.data.token, permissions: listed };
}

/** What one signed-in person can do on one repo, cached for a minute (a speed-up only; per process, safe to lose). */
export const repoCache = new Map<string, { at: number; value: Record<string, unknown> }>();
export const REPO_CACHE_TTL = REPO_TTL;

/** The app that makes fixes: the fix app when the site has one, otherwise the main app, as before there were two. */
export function fixer(cfg: AppConfig): TokenApp {
  return fixAppConfig() ?? cfg;
}

/** An app and its installation on one repository. */
export type AppInstall = { app: TokenApp; inst: Installation };

/**
 * Check everything a pull request fix needs before touching GitHub: an admin, the app that makes fixes installed, and
 * its permissions. Returns that app's installation, which opens the pull request, and what the token needs.
 */
export async function prReady(
  cfg: AppConfig,
  sess: Session,
  repo: string,
  itemId: string,
): Promise<AppInstall & { need: Record<string, string> }> {
  if (!Object.hasOwn(available(), itemId)) {
    throw new HttpError(
      422,
      'invalid_request',
      "There's no one-click pull request for this check.",
      'Fix it with the steps in the guide, or copy the prompt for your own AI agent.',
    );
  }
  await requireAdmin(sess, repo);
  const app = fixer(cfg);
  const inst = await installed(app, repo);
  const need = neededPermissions(itemId);
  requirePermissions(app, inst, repo, need, 'open pull requests');
  return { app, inst, need };
}

/**
 * A read-only token for building a pull request's preview: from the main app's installation, or, on a repository
 * where only the fix app is installed, from that one (`writer`, which prReady found).
 */
export async function previewToken(cfg: AppConfig, repo: string, writer: AppInstall): Promise<string> {
  const main = writer.app === cfg ? writer.inst : await installation(cfg, repo);
  const reader: AppInstall = main ? { app: cfg, inst: main } : writer;
  return installationToken(reader.app, repo, {
    inst: reader.inst,
    permissions: grantable(PREVIEW_PERMISSIONS, reader.inst),
  });
}

/**
 * What Deep scan reads the security advisories with (the private-report checks): a token that may read them and
 * nothing else, from the fix app's installation when the site has one that can; otherwise from the main app's while it
 * still can (an installation from before there were two apps). Otherwise no token, and why, which those checks say.
 * The rest of Deep scan doesn't need this token, so a failure to get one (a broken fix app key, say) only costs them.
 */
export async function advisoryAccess(cfg: AppConfig, repo: string, mainInst: Installation): Promise<AdvisoryAccess> {
  const fix = fixAppConfig();
  try {
    const fixInst = fix ? await installation(fix, repo) : null;
    const candidates: [TokenApp | null, Installation | null][] = [
      [fix, fixInst],
      [cfg, mainInst],
    ];
    for (const [app, inst] of candidates) {
      if (app && inst && holds(inst, 'repository_advisories', 'read')) {
        const { token, permissions } = await installationAccess(app, repo, { inst, permissions: ADVISORY_PERMISSIONS });
        return { token, grants: permissions };
      }
    }
    const approve =
      "An owner can approve the new permission in the installation's settings, or use the CLI with an admin's token";
    const why = !fix
      ? `the GitHub App hasn't been given access to security advisories on this installation. ${approve}`
      : !fixInst
        ? `Deep scan reads them through ${fix.slug}, the app for one-click fixes, which isn't installed on this ` +
          "repository. Install it if you want this check, or use the CLI with an admin's token"
        : `${fix.slug} hasn't been given access to security advisories on this installation. ${approve}`;
    return { token: null, why };
  } catch (e) {
    // Only an HttpError's words: an error about a bad private key can quote it.
    const what = e instanceof HttpError ? e.message.replace(/\.$/, '') : "the server couldn't make a token for them";
    return { token: null, why: `${what}. Run Deep scan again in a minute, or use the CLI with an admin's token` };
  }
}

/**
 * Count one AI fix against today's limit, which lives in the person's sign-in cookie, after checking the site's
 * monthly budget. Returns the updated sign-in for the caller to set on its response, whether the fix works or not:
 * a failed attempt cost tokens too.
 */
export function countAgentFix(sess: Session): Session {
  const c = agentConfig();
  const day = new Date().toISOString().slice(0, 10);
  const used = Math.trunc(Number(sess.fixes?.[day]) || 0);
  if (used >= c.per_day) {
    throw new HttpError(
      429,
      'ai_limit_reached',
      `You've used today's ${c.per_day} AI fixes.`,
      'Try again tomorrow, or copy the prompt and use your own agent.',
    );
  }
  try {
    usage().check();
  } catch (e) {
    if (e instanceof AgentError) throw new HttpError(e.status, e.code, e.message, e.hint);
    throw e;
  }
  return { ...sess, fixes: { [day]: used + 1 } };
}
