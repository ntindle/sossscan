/**
 * The token public scans use. The first of these that works:
 * 1. GITHUB_TOKEN or GH_TOKEN, when the operator set one;
 * 2. the site's GitHub App: a token for the installation on the app owner's account, cut down to reading metadata.
 *    That still reads every public repo the scanner looks at, with the installation's rate limit (about 12,500
 *    requests an hour) instead of the 60 an anonymous server gets;
 * 3. none: anonymous.
 * The server never borrows a personal token from the gh CLI. An app token can also see the owner's private repos, so
 * lib/public-scan.ts answers a private repo like a missing one.
 */
import { envToken } from './env.ts';
import { type AppConfig, appConfig } from './github-app.ts';
import { appJwt, ghRequest } from './github.ts';
import { HttpError } from './http.ts';

/** Mint a new token this long before GitHub expires the cached one, so a scan (up to 5 minutes) never outlives it. */
const REFRESH_BEFORE_MS = 5 * 60_000;

// Per process, for the configured app (by id, so different app settings start over). Safe to lose.
let installation: { appId: number; id: number } | null = null;
let cached: { appId: number; token: string; refreshAt: number } | null = null;
let minting: Promise<string | null> | null = null;

/** Why the app has no token for now. Its message goes to the log, so it never quotes a key or a secret. */
class NoAppToken extends Error {}

/** The token for the next public scan, or null to scan anonymously. It never throws. */
export async function publicScanToken(): Promise<string | null> {
  return envToken() ?? (await appToken());
}

/** Drop the cached app token if GitHub stopped accepting it (the app was uninstalled, say): the next scan starts over. */
export function forgetScanToken(token: string | null): void {
  if (token && cached?.token === token) {
    cached = null;
    installation = null;
  }
}

/** Forget the installation and the token, like a fresh server (for tests). */
export function resetScanToken(): void {
  installation = null;
  cached = null;
  minting = null;
}

async function appToken(): Promise<string | null> {
  const cfg: AppConfig | null = appConfig();
  if (!cfg) return null;
  if (cached?.appId === cfg.id && Date.now() < cached.refreshAt) return cached.token;
  // Scans that start together share one new token.
  minting ??= mint(cfg).finally(() => {
    minting = null;
  });
  return minting;
}

async function mint(cfg: AppConfig): Promise<string | null> {
  try {
    const jwt = appJwt(cfg);
    const id = installation?.appId === cfg.id ? installation.id : await findInstallation(cfg, jwt);
    const r = await ghRequest('POST', `/app/installations/${id}/access_tokens`, jwt, {
      permissions: { metadata: 'read' },
    });
    const token = r.data?.token;
    if (r.status !== 201 || typeof token !== 'string' || !token) {
      installation = null; // it may have been uninstalled or suspended: look again next time
      throw new NoAppToken(`HTTP ${r.status} minting a token`);
    }
    const expires = Date.parse(r.data.expires_at);
    cached = Number.isFinite(expires) ? { appId: cfg.id, token, refreshAt: expires - REFRESH_BEFORE_MS } : null;
    return token;
  } catch (e) {
    return noToken(reason(e));
  }
}

/** The installation on the app owner's account (any other one reads public repos just as well, but spends its quota). */
async function findInstallation(cfg: AppConfig, jwt: string): Promise<number> {
  const r = await ghRequest('GET', '/app/installations?per_page=100', jwt);
  if (r.status !== 200 || !Array.isArray(r.data)) {
    throw new NoAppToken(`HTTP ${r.status} listing the app's installations`);
  }
  const usable = r.data.filter((i: any) => Number.isInteger(i?.id) && !i.suspended_at);
  const owner = String(cfg.owner || '').toLowerCase();
  const pick = usable.find((i: any) => owner && String(i.account?.login || '').toLowerCase() === owner) ?? usable[0];
  if (!pick) throw new NoAppToken('the app is not installed anywhere');
  installation = { appId: cfg.id, id: pick.id };
  return pick.id;
}

function reason(e: unknown): string {
  if (e instanceof NoAppToken) return e.message;
  if (e instanceof HttpError) return "GitHub didn't answer"; // ghRequest's only error
  // Only the error's code or name: messages about a bad private key can quote it.
  return (e as { code?: string })?.code || (e as Error)?.name || 'unexpected error';
}

/** One short log line (never a secret): this scan goes ahead without a token. */
function noToken(why: string): null {
  console.log(`public scans: no GitHub App token (${why}), scanning without a token`);
  return null;
}
