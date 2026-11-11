/**
 * Requests per visitor address, kept in memory. Public scans spend the server's GitHub quota, and the app's routes
 * spend the visitor's. The MCP server (lib/mcp.ts) counts every message it's sent, and a scan through it also counts as
 * a scan request. On a serverless host each instance counts on its own, so these are speed bumps, not hard caps.
 */
import type { NextResponse } from 'next/server';
import { onVercel } from './env.ts';
import { errorJson, HttpError } from './http.ts';

/** (window in seconds, allowed requests) per bucket. */
const LIMITS = {
  scan: [
    [60, 6],
    [3600, 40],
  ],
  app: [[60, 90]],
  mcp: [[60, 120]],
} as const;
export type Bucket = keyof typeof LIMITS;

/** What each bucket counts, in the words the docs use. */
const COUNTED: Record<Bucket, string> = {
  scan: 'scan requests',
  app: 'sign-in and app requests',
  mcp: 'MCP requests',
};
const PER: Record<number, string> = { 60: 'a minute', 3600: 'an hour' };

/** What one address may send, in words: "6 scan requests a minute and 40 an hour". */
export function allowance(bucket: Bucket): string {
  return LIMITS[bucket].map(([window, n], i) => `${n}${i ? '' : ` ${COUNTED[bucket]}`} ${PER[window]}`).join(' and ');
}

/** A wait in words: seconds up to two minutes, then minutes, rounded up. */
function inWords(seconds: number): string {
  if (seconds < 120) return seconds === 1 ? '1 second' : `${seconds} seconds`;
  return `${Math.ceil(seconds / 60)} minutes`;
}

/** The refusal for an address over its limit, which may try again in `wait` seconds. */
export function rateLimitError(bucket: Bucket, wait: number): HttpError {
  return new HttpError(
    429,
    'rate_limited',
    `Too many requests from your IP address, which can make ${allowance(bucket)}.`,
    `Try again in ${inWords(wait)}.`,
    { 'Retry-After': String(wait) },
  );
}

const hits = new Map<string, number[]>();

/** Behind a proxy (Vercel, Fly, Cloudflare) the visitor's address arrives in a header; only trust it when told to. */
export function trustProxy(): boolean {
  return process.env.TRUST_PROXY_HEADERS === '1' || onVercel();
}

/**
 * The visitor's address. Without a trusted proxy there's no reliable one (a visitor can send any X-Forwarded-For),
 * so everyone shares one count: the same as a server behind a local proxy that doesn't pass the address on.
 */
export function clientIp(headers: Headers): string {
  if (trustProxy()) {
    const ip =
      headers.get('x-vercel-forwarded-for') ||
      headers.get('x-real-ip') ||
      headers.get('fly-client-ip') ||
      headers.get('cf-connecting-ip') ||
      (headers.get('x-forwarded-for') || '').split(',')[0];
    if (ip.trim()) return ip.trim();
  }
  return 'direct';
}

/** Seconds to wait before this address may try again, or 0 when the request can go ahead (and is counted). */
export function limited(bucket: Bucket, ip: string, now = Date.now() / 1000): number {
  const rules = LIMITS[bucket];
  const longest = Math.max(...rules.map(([w]) => w));
  if (hits.size > 20_000) {
    for (const [k, q] of hits) if (!q.length || now - q[q.length - 1] > 3600) hits.delete(k); // forget quiet addresses
  }
  const key = `${bucket}\n${ip}`;
  let q = hits.get(key);
  if (!q) hits.set(key, (q = []));
  while (q.length && now - q[0] > longest) q.shift();
  for (const [window, allowed] of rules) {
    const recent = q.filter((t) => now - t <= window);
    if (recent.length >= allowed) return Math.max(1, Math.floor(window - (now - recent[0])) + 1);
  }
  q.push(now);
  return 0;
}

/** A 429 response when this request's address is over the limit, otherwise null. Nothing caches it (errorJson). */
export function rateLimit(req: Request, bucket: Bucket): NextResponse | null {
  const wait = limited(bucket, clientIp(req.headers));
  return wait ? errorJson(rateLimitError(bucket, wait)) : null;
}

export function resetLimits(): void {
  hits.clear();
}
