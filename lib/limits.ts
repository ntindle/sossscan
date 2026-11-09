/**
 * Requests per visitor address, kept in memory. Public scans spend the server's GitHub quota, and the app's routes
 * spend the visitor's. On a serverless host each instance counts on its own, so these are speed bumps, not hard caps.
 */
import { NextResponse } from 'next/server';
import { onVercel } from './env.ts';

/** (window in seconds, allowed requests) per bucket. */
const LIMITS = {
  scan: [
    [60, 6],
    [3600, 40],
  ],
  app: [[60, 90]],
} as const;
export type Bucket = keyof typeof LIMITS;

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

/** A 429 response when this request's address is over the limit, otherwise null. */
export function rateLimit(req: Request, bucket: Bucket): NextResponse | null {
  const wait = limited(bucket, clientIp(req.headers));
  if (!wait) return null;
  return NextResponse.json(
    { detail: 'Too many requests from your address. Try again in a minute.' },
    { status: 429, headers: { 'Retry-After': String(wait), 'Cache-Control': 'no-store' } },
  );
}

export function resetLimits(): void {
  hits.clear();
}
