// The scanner's only network code. It sends GET requests and nothing else, like the Python Http class it ports.
import { execFileSync } from 'node:child_process';
import { API, UA } from './constants.ts';
import { pyStrip } from './py.ts';

/** The only hosts that ever see the token. */
const TOKEN_HOSTS = new Set(['api.github.com', 'raw.githubusercontent.com']);
/** GitHub's hosts, whose refusals can mean GitHub rate-limited the scan (the dependents page is on github.com). */
const GITHUB_HOSTS = new Set([...TOKEN_HOSTS, 'github.com']);
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

interface Fetched {
  status: number;
  body: Uint8Array;
  headers: Record<string, string>;
}

/** bytes.decode("utf-8", errors="replace"): bad bytes become U+FFFD and a leading BOM is kept. */
export function decodeReplace(body: Uint8Array): string {
  return new TextDecoder('utf-8', { ignoreBOM: true }).decode(body);
}

/**
 * A text file's bytes as text: UTF-16 when it starts with a UTF-16 byte-order mark, or when every other byte is zero
 * (ASCII saved as UTF-16 by a Windows editor); otherwise UTF-8 as decodeReplace reads it. For security policies, which
 * people save in all sorts of ways.
 */
export function decodeText(body: Uint8Array): string {
  if (body.length >= 2 && body[0] === 0xff && body[1] === 0xfe)
    return new TextDecoder('utf-16le').decode(body.subarray(2));
  if (body.length >= 2 && body[0] === 0xfe && body[1] === 0xff)
    return new TextDecoder('utf-16be').decode(body.subarray(2));
  const n = Math.min(body.length, 4000) & ~1;
  if (n >= 8) {
    let even = 0;
    let odd = 0;
    for (let k = 0; k < n; k += 2) {
      if (body[k] === 0) even++;
      if (body[k + 1] === 0) odd++;
    }
    const pairs = n / 2;
    if (odd > pairs * 0.6 && even < pairs * 0.1)
      return new TextDecoder('utf-16le').decode(body.subarray(0, body.length & ~1));
    if (even > pairs * 0.6 && odd < pairs * 0.1)
      return new TextDecoder('utf-16be').decode(body.subarray(0, body.length & ~1));
  }
  return decodeReplace(body);
}

/** json.loads(body) on the bytes of a response: invalid UTF-8 or JSON gives null, and a UTF-8 BOM is skipped. */
function parseJson(body: Uint8Array): any {
  if (!body.length) return null;
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return null;
  }
}

/**
 * Whether GitHub refused a request for going over a rate limit: a 429 (too many requests, whatever else it says), or a
 * 403 that leaves no requests, asks to retry later or says so in its message. Other 403s refuse the request itself.
 */
function isRateLimit({ status, body, headers }: Fetched): boolean {
  if (status === 429) return true;
  if (status !== 403) return false;
  if (headers['x-ratelimit-remaining'] === '0' || 'retry-after' in headers) return true;
  const parsed = parseJson(body);
  return typeof parsed?.message === 'string' && /rate limit/i.test(parsed.message);
}

async function readBody(res: Response, touch: () => void): Promise<Uint8Array> {
  if (!res.body) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
    touch();
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export class Http {
  token: string | null;
  /** Seconds a request may sit idle (connecting, or between chunks of the body), like a Python socket timeout. */
  timeout: number;
  calls = 0;
  /** Set once GitHub refuses a request for going over a rate limit, so the scan can say its answers may be wrong. */
  rateLimited = false;

  constructor(token: string | null = null, timeout = 30) {
    this.token = token;
    this.timeout = timeout;
  }

  /** One GET, retried once on a 5xx or a network error. A network failure comes back as status 0. */
  async req(
    url: string,
    accept = 'application/vnd.github+json',
    auth = true,
  ): Promise<[number, Uint8Array, Record<string, string>]> {
    // Python's http.client refuses to send a URL with spaces, control or non-ASCII characters, and the
    // scanner doesn't catch that error, so neither does this.
    if (/[^\x21-\x7e]/.test(url)) throw new Error(`URL can't contain control, space or non-ASCII characters: ${url}`);
    const host = new URL(url).host;
    const headers: Record<string, string> = { 'User-Agent': UA, Accept: accept };
    if (this.token && auth && TOKEN_HOSTS.has(host)) headers.Authorization = `Bearer ${this.token}`;
    if (host === 'api.github.com') headers['X-GitHub-Api-Version'] = '2022-11-28';
    for (let attempt = 0; attempt < 2; attempt++) {
      this.calls += 1;
      let got: Fetched;
      try {
        got = await this.follow(url, headers);
      } catch (e) {
        if (attempt === 0) continue;
        return [0, new TextEncoder().encode(String(e)), {}];
      }
      if (got.status >= 500 && attempt === 0) continue;
      if (GITHUB_HOSTS.has(host) && isRateLimit(got)) this.rateLimited = true;
      return [got.status, got.body, got.headers];
    }
    return [0, new Uint8Array(), {}];
  }

  /**
   * GET url and follow redirects the way urllib does (at most 10 distinct URLs, each at most 4 times), except that
   * the token is dropped as soon as a redirect leaves api.github.com and raw.githubusercontent.com.
   */
  private async follow(url: string, headers: Record<string, string>): Promise<Fetched> {
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const touch = () => {
      clearTimeout(timer);
      timer = setTimeout(() => ctl.abort(new Error(`timed out after ${this.timeout}s`)), this.timeout * 1000);
    };
    const hdrs = { ...headers };
    const visited = new Map<string, number>();
    let current = url;
    try {
      for (;;) {
        touch();
        const res = await fetch(current, { headers: hdrs, redirect: 'manual', signal: ctl.signal });
        const location = res.headers.get('location') ?? res.headers.get('uri');
        if (REDIRECTS.has(res.status) && location !== null) {
          const next = new URL(location, current);
          const seen = visited.get(next.href) ?? 0;
          if ((next.protocol === 'http:' || next.protocol === 'https:') && visited.size < 10 && seen < 4) {
            visited.set(next.href, seen + 1);
            await res.body?.cancel();
            if (!TOKEN_HOSTS.has(next.host)) delete hdrs.Authorization;
            current = next.href;
            continue;
          }
        }
        const body = await readBody(res, touch);
        return { status: res.status, body, headers: Object.fromEntries(res.headers) };
      }
    } finally {
      clearTimeout(timer);
    }
  }

  /** GET JSON from an API path (or a full URL). The body is parsed whatever the status; null if it isn't JSON. */
  async json(
    pathOrUrl: string,
    opts: { accept?: string; auth?: boolean } = {},
  ): Promise<[number, any, Record<string, string>]> {
    const url = pathOrUrl.startsWith('http') ? pathOrUrl : API + pathOrUrl;
    const [status, body, headers] = await this.req(url, opts.accept, opts.auth);
    return [status, parseJson(body), headers];
  }

  /** GET text; null unless the status is 200. decode reads the bytes (as UTF-8, unless it says otherwise). */
  async text(
    url: string,
    opts: { auth?: boolean; decode?: (body: Uint8Array) => string } = {},
  ): Promise<[number, string | null]> {
    const [status, body] = await this.req(url, '*/*', opts.auth);
    return [status, status === 200 ? (opts.decode ?? decodeReplace)(body) : null];
  }
}

/** The token to use: --token, then $GITHUB_TOKEN, $GH_TOKEN, then `gh auth token`. */
export function findToken(explicit?: string | null): string | null {
  if (explicit) return explicit;
  for (const name of ['GITHUB_TOKEN', 'GH_TOKEN']) {
    const value = process.env[name];
    if (value) return value;
  }
  try {
    const out = execFileSync('gh', ['auth', 'token'], {
      encoding: 'utf8',
      timeout: 15_000,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    });
    return pyStrip(out) || null;
  } catch {
    // gh isn't installed, isn't logged in, or took too long.
    return null;
  }
}
