/** Talking to GitHub's API as the app (a signed JWT), as an installation, or as a signed-in person. */
import crypto from 'node:crypto';
import { HttpError } from './http.ts';

export const API = 'https://api.github.com';
const JSON_ACCEPT = 'application/vnd.github+json';

export type GhAnswer = { status: number; data: any };
/** What lib/fixes.ts works through: (method, path, body?, accept?) -> {status, data}. Tests pass a fake one. */
export type Gh = (method: string, path: string, body?: unknown, accept?: string) => Promise<GhAnswer>;

export type GhResponse = { status: number; data: any; text: string };

/** One API call. `data` is the parsed JSON (null when there's none), `text` the raw body. */
export async function ghRequest(
  method: string,
  path: string,
  token: string | null,
  body?: unknown,
  accept = JSON_ACCEPT,
): Promise<GhResponse> {
  const headers: Record<string, string> = {
    Accept: accept,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'sosf-guide',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body != null) headers['Content-Type'] = 'application/json';
  let r: Response;
  try {
    r = await fetch(API + path, {
      method,
      headers,
      body: body == null ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new HttpError(502, "GitHub didn't answer. Try again in a minute.");
  }
  const text = await r.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  return { status: r.status, data, text };
}

/** The Gh callable for one token: JSON answers come back parsed, others (raw files, SHAs) as text. */
export function client(token: string): Gh {
  return async (method, path, body, accept) => {
    const r = await ghRequest(method, path, token, body, accept || JSON_ACCEPT);
    return { status: r.status, data: accept && !accept.includes('json') ? r.text : r.data };
  };
}

/** A JWT that proves a request comes from the app itself (RS256, valid for 9 minutes, back-dated a minute for clock drift). */
export function appJwt(cfg: { id: number; client_id?: string; pem: string }): string {
  const now = Math.floor(Date.now() / 1000);
  const part = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = `${part({ alg: 'RS256', typ: 'JWT' })}.${part({ iat: now - 60, exp: now + 540, iss: String(cfg.client_id || cfg.id) })}`;
  return `${unsigned}.${crypto.sign('RSA-SHA256', Buffer.from(unsigned), cfg.pem).toString('base64url')}`;
}
