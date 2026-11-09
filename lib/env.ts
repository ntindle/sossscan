/**
 * Where the site runs and where it may write. Read on every call, so a test (or a changed environment) takes effect
 * without restarting anything. Every secret comes from the environment: the server never makes or saves one.
 */
import path from 'node:path';

/** The project root: Next.js and the tests both run from it. */
export const ROOT = process.cwd();

export function onVercel(): boolean {
  return Boolean(process.env.VERCEL);
}

/** Caches live here, and nothing else. Serverless hosts only allow writing under /tmp. */
export function dataDir(): string {
  return process.env.SOSF_DATA_DIR || (onVercel() ? '/tmp/sosf' : ROOT);
}

export function cacheDir(): string {
  return path.join(dataDir(), '.cache');
}

export function siteUrl(): string {
  return (process.env.SITE_BASE_URL || 'http://127.0.0.1:3340').replace(/\/+$/, '');
}

export function secureCookies(): boolean {
  return siteUrl().startsWith('https://');
}

/** GITHUB_TOKEN or GH_TOKEN, when the operator set one. The server never borrows anyone's gh CLI token. */
export function envToken(): string | null {
  return process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
}
