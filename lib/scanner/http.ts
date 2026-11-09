// The scanner's only network code. It sends GET requests and nothing else, like the Python Http class it ports.
import { execFileSync } from 'node:child_process';
import { API, UA } from './constants.ts';
import { pyStrip } from './py.ts';

/** The only hosts that ever see the token. */
const TOKEN_HOSTS = new Set(['api.github.com', 'raw.githubusercontent.com']);
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

/** json.loads(body) on the bytes of a response: invalid UTF-8 or JSON gives null, and a UTF-8 BOM is skipped. */
function parseJson(body: Uint8Array): any {
  if (!body.length) return null;
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return null;
  }
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

  /** GET text; null unless the status is 200. */
  async text(url: string, opts: { auth?: boolean } = {}): Promise<[number, string | null]> {
    const [status, body] = await this.req(url, '*/*', opts.auth);
    return [status, status === 200 ? decodeReplace(body) : null];
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
