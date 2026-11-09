/**
 * Public scans for anyone, with the server's own token (lib/scan-token.ts): public repositories only, and cached for
 * 6 hours (in memory and on disk here, and by the CDN in front of GET /api/scan/OWNER/REPO), so repeat visits don't
 * spend GitHub quota.
 */
import fs from 'node:fs';
import path from 'node:path';
import { cacheDir } from './env.ts';
import { HttpError } from './http.ts';
import { ossFuzzIndex, ossFuzzLookup } from './ossfuzz.ts';
import { forgetScanToken, publicScanToken } from './scan-token.ts';
import { scan, type Report } from './scanner/index.ts';

export const SCAN_TTL = 6 * 3600;
/** The scanner's words for a repo GitHub doesn't show the token: what every hidden repo gets (public/shared/core.js). */
export const NOT_FOUND = 'repo lookup failed: HTTP 404 (private repo? pass a token)';
/** How the scanner's refusal of a private repo starts (lib/scanner/scan.ts, with allowPrivate false). */
const PRIVATE_REFUSAL = 'This is a private repository.';
/** The scanner's words when GitHub rejects the token itself. */
const BAD_TOKEN = 'repo lookup failed: HTTP 401';
const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
const MAX_SCANS = 3; // at once, per server instance
const mem = new Map<string, { at: number; rep: Report }>();

/** Accept exactly OWNER/REPO or a github.com repo URL (optionally .git, a trailing slash, or a subpage). */
export function parseRepo(raw: string): string {
  const m =
    /^(?:(?:https?:\/\/)?(?:www\.)?github\.com\/)?([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:\/\S*)?$/.exec(
      raw.trim(),
    );
  const repo = m ? `${m[1]}/${m[2]}` : '';
  if (!REPO_RE.test(repo) || ['.', '..'].includes(repo.split('/')[1])) {
    throw new HttpError(422, 'Expected OWNER/REPO or a github.com URL');
  }
  return repo;
}

let running = 0;
const waiting: (() => void)[] = [];

function acquire(timeoutMs: number): Promise<boolean> {
  if (running < MAX_SCANS) {
    running += 1;
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    const grant = () => {
      clearTimeout(timer);
      running += 1;
      resolve(true);
    };
    const timer = setTimeout(() => {
      waiting.splice(waiting.indexOf(grant), 1);
      resolve(false);
    }, timeoutMs);
    waiting.push(grant);
  });
}

function release(): void {
  running -= 1;
  waiting.shift()?.();
}

export async function runPublicScan(repo: string, refresh = false): Promise<Report & { cached: boolean }> {
  const key = repo.toLowerCase();
  const disk = path.join(cacheDir(), 'scans', `${key.replaceAll('/', '__')}.json`);
  const now = Date.now() / 1000;
  if (!refresh) {
    const hit = mem.get(key);
    if (hit && now - hit.at < SCAN_TTL) return { ...hit.rep, cached: true };
    try {
      const at = fs.statSync(disk).mtimeMs / 1000;
      if (now - at < SCAN_TTL) {
        const rep = JSON.parse(fs.readFileSync(disk, 'utf8')) as Report;
        mem.set(key, { at, rep });
        return { ...rep, cached: true };
      }
    } catch {
      // not cached yet
    }
  }
  if (!(await acquire(120_000))) throw new HttpError(503, 'Scanner busy, try again in a minute');
  let rep: Report;
  let token: string | null = null;
  try {
    token = await publicScanToken();
    rep = await scan(repo, {
      token,
      layer: 'public',
      ossFuzzLookup: Object.keys(ossFuzzIndex()).length ? ossFuzzLookup : null,
      allowPrivate: false,
    });
  } finally {
    release();
  }
  if (rep.errors.includes(BAD_TOKEN)) forgetScanToken(token);
  // The server's token may see private repos (an app's token sees its owner's), and the scanner refuses them. Saying
  // so would tell anyone the repo exists: answer exactly as for a missing repo, and never cache it.
  if (rep.errors.some((e) => e.startsWith(PRIVATE_REFUSAL))) {
    return { ...rep, repo, meta: {}, results: {}, findings: [], errors: [NOT_FOUND], cached: false };
  }
  if (rep.results && Object.keys(rep.results).length) {
    mem.set(key, { at: now, rep });
    try {
      fs.mkdirSync(path.dirname(disk), { recursive: true });
      fs.writeFileSync(disk, JSON.stringify(rep));
    } catch (e) {
      console.log('scan cache write failed:', (e as Error).message); // the memory copy still helps
    }
  }
  return { ...rep, cached: false };
}

/**
 * A scan with results, or a 404 that says why there are none (no such public repo, GitHub's rate limit). Nothing may
 * keep the 404, so a missing repo and a hidden one are told apart neither by their words nor by how they're cached.
 */
export async function scanOr404(repo: string, refresh: boolean): Promise<Report & { cached: boolean }> {
  const rep = await runPublicScan(repo, refresh);
  if (!rep.results || !Object.keys(rep.results).length) {
    throw new HttpError(404, (rep.errors?.length ? rep.errors : ['scan failed']).join('; '), {
      'Cache-Control': 'no-store',
    });
  }
  return rep;
}

export function clearScanCache(): void {
  mem.clear();
}
