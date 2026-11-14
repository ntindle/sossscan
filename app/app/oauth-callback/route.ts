import type { NextRequest } from 'next/server';
import { count } from '@/lib/counts.ts';
import { siteUrl } from '@/lib/env.ts';
import { ghRequest } from '@/lib/github.ts';
import { appConfig, clearStateCookie, popState, SESSION_TTL, setSession, withParam } from '@/lib/github-app.ts';
import { queryValue, redirect, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

async function exchange(cfg: { client_id: string; client_secret: string }, code: string): Promise<string | null> {
  try {
    const r = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'User-Agent': 'sosf-guide' },
      body: new URLSearchParams({
        client_id: cfg.client_id,
        client_secret: cfg.client_secret,
        code,
        redirect_uri: `${siteUrl()}/app/oauth-callback`,
      }),
      signal: AbortSignal.timeout(30_000),
    });
    if (r.status !== 200) return null;
    const token = (await r.json())?.access_token;
    return typeof token === 'string' && token ? token : null;
  } catch {
    return null;
  }
}

/** GitHub sends the person back here after sign-in. Every outcome returns to their page, with ?app= saying how it went. */
export const GET = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  const state = queryValue(req.nextUrl, 'state', { max: 2000 });
  const code = queryValue(req.nextUrl, 'code', { max: 100 });
  const error = queryValue(req.nextUrl, 'error', { max: 100 });
  const st = popState(req, state);
  const next: string = st ? st.next : '/';
  const cfg = appConfig();
  const back = (why: string) => {
    const res = redirect(withParam(next, 'app', why), 303);
    clearStateCookie(res);
    return res;
  };
  if (!st) return back('signin-expired');
  if (error || !code || !cfg) return back(error === 'access_denied' ? 'signin-cancelled' : 'signin-failed');
  const token = await exchange(cfg, code);
  const user = token ? await ghRequest('GET', '/user', token).catch(() => null) : null;
  if (!token || !user || user.status !== 200 || typeof user.data?.login !== 'string') return back('signin-failed');
  const res = back('signed-in');
  setSession(res, { login: user.data.login, token, app_id: cfg.id, exp: Date.now() / 1000 + SESSION_TTL });
  count(req, 'signed_in', {});
  return res;
});
