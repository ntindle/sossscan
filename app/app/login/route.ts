import type { NextRequest } from 'next/server';
import { siteUrl } from '@/lib/env.ts';
import { configOr404, newState, setStateCookie } from '@/lib/github-app.ts';
import { queryValue, redirect, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

/** Sign in with GitHub. `next` is where to come back to, on this site only. */
export const GET = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  const next = queryValue(req.nextUrl, 'next', { max: 300 }) ?? '/';
  const cfg = configOr404();
  const [state, nonce] = newState(next);
  const q = new URLSearchParams({ client_id: cfg.client_id, redirect_uri: `${siteUrl()}/app/oauth-callback`, state });
  const res = redirect(`https://github.com/login/oauth/authorize?${q}`, 303);
  setStateCookie(res, nonce);
  return res;
});
