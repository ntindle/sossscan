/**
 * Optional GitHub App layer: sign in, check admin settings, and fix things in one click.
 *
 * The site uses one app, which already exists on GitHub; its operator configures it in the environment (GITHUB_APP_*).
 * The site can't create, register or replace an app, and nothing here writes the app's credentials: changing the app
 * is an operator's change to those settings. Without them there's no app, and the site works without sign-in.
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
import { seal, unseal } from './sealed.ts';

export const STATE_TTL = 900;
export const SESSION_TTL = 7 * 3600; // GitHub expires app user tokens after 8 hours
export const PLAN_TTL = 900;
const REPO_TTL = 60;

export type SettingsFix = { label: string; method: string; path: string; body?: unknown; note?: string };
/** One-click settings fixes, from build/skeleton.json. */
export const FIXES: Record<string, SettingsFix> = skeleton.app_fixes as Record<string, SettingsFix>;

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

/**
 * The site's app, from the environment and nowhere else, or null when a setting is missing or invalid. Required:
 * GITHUB_APP_ID (a positive integer), _SLUG, _CLIENT_ID, _CLIENT_SECRET and _PRIVATE_KEY (real line breaks or \n).
 * _OWNER and _PUBLIC are optional.
 */
export function appConfig(): AppConfig | null {
  const env = process.env;
  const id = (env.GITHUB_APP_ID || '').trim();
  const slug = (env.GITHUB_APP_SLUG || '').trim();
  const clientId = (env.GITHUB_APP_CLIENT_ID || '').trim();
  const clientSecret = env.GITHUB_APP_CLIENT_SECRET || '';
  const pem = (env.GITHUB_APP_PRIVATE_KEY || '').replaceAll('\\n', '\n');
  if (!/^[1-9]\d*$/.test(id) || !Number.isSafeInteger(Number(id))) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(slug)) return null; // it becomes part of the app's links
  if (!clientId || !clientSecret.trim() || !pem.trim()) return null;
  return {
    id: Number(id),
    slug,
    client_id: clientId,
    client_secret: clientSecret,
    pem,
    html_url: `https://github.com/apps/${slug}`,
    owner: (env.GITHUB_APP_OWNER || '').trim(),
    public: ['1', 'true', 'yes'].includes((env.GITHUB_APP_PUBLIC || '').trim().toLowerCase()),
  };
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

export async function installation(cfg: AppConfig, repo: string): Promise<Installation | null> {
  const r = await ghRequest('GET', `/repos/${repo}/installation`, appJwt(cfg));
  return r.status === 200 ? r.data : null;
}

function notInstalled(cfg: AppConfig, repo: string): HttpError {
  return new HttpError(
    404,
    'app_not_installed',
    `The app is not installed on ${repo}.`,
    `Install it from ${cfg.html_url}/installations/new, then try again.`,
  );
}

export async function installationToken(
  cfg: AppConfig,
  repo: string,
  opts: { permissions?: Record<string, string>; inst?: Installation | null } = {},
): Promise<string> {
  return (await installationAccess(cfg, repo, opts)).token;
}

/**
 * A token of the app's installation for one repo, and the permissions GitHub gave it (null if it didn't say). Deep
 * scan passes them to the scanner, so a check whose permission an installation hasn't accepted says so.
 */
export async function installationAccess(
  cfg: AppConfig,
  repo: string,
  { permissions, inst }: { permissions?: Record<string, string>; inst?: Installation | null } = {},
): Promise<{ token: string; permissions: Record<string, string> | null }> {
  const found = inst || (await installation(cfg, repo));
  if (!found) throw notInstalled(cfg, repo);
  const body: Record<string, unknown> = { repositories: [repo.split('/')[1]] };
  if (permissions) body.permissions = permissions; // a token that can only do what this request needs
  const r = await ghRequest('POST', `/app/installations/${found.id}/access_tokens`, appJwt(cfg), body);
  if (r.status !== 201) {
    throw new HttpError(
      502,
      'github_error',
      `GitHub didn't give the app a token for ${repo} (HTTP ${r.status}).`,
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

/** Check everything a pull request fix needs before touching GitHub: an admin, the app installed, the permissions. */
export async function prReady(
  cfg: AppConfig,
  sess: Session,
  repo: string,
  itemId: string,
): Promise<{ inst: Installation; need: Record<string, string> }> {
  if (!Object.hasOwn(available(), itemId)) {
    throw new HttpError(
      422,
      'invalid_request',
      "There's no one-click pull request for this check.",
      'Fix it with the steps in the guide, or copy the prompt for your own AI agent.',
    );
  }
  await requireAdmin(sess, repo);
  const inst = await installation(cfg, repo);
  if (!inst) throw notInstalled(cfg, repo);
  const need = neededPermissions(itemId);
  const have = inst.permissions || {};
  const missing = Object.entries(need)
    .filter(([k, v]) => have[k] !== v)
    .map(([k]) => k.replaceAll('_', ' '));
  if (missing.length) {
    throw new HttpError(
      403,
      'app_permission_missing',
      `The app on ${repo} can't open pull requests yet. It needs write access to ${missing.join(', ')}.`,
      "The app's owner can add that in the app's settings, then accept it on the installation.",
    );
  }
  return { inst, need };
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
