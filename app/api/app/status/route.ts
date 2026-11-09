import type { NextRequest } from 'next/server';
import { available } from '@/lib/fixes.ts';
import { appConfig, FIXES, liveSession } from '@/lib/github-app.ts';
import { privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

/** Is there an app, who's signed in, and which fixes this site offers. */
export const GET = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  const cfg = appConfig();
  const s = cfg ? liveSession(req) : null; // without an app, a sign-in cookie isn't even opened
  return privateJson({
    configured: Boolean(cfg),
    slug: cfg?.slug ?? null,
    html_url: cfg?.html_url ?? null,
    install_url: cfg ? `${cfg.html_url}/installations/new` : null,
    public: Boolean(cfg?.public),
    owner: cfg?.owner ?? null,
    user: s ? s.login : null,
    fixes: Object.fromEntries(Object.entries(FIXES).map(([k, v]) => [k, { label: v.label, note: v.note ?? null }])),
    pr_fixes: Object.fromEntries(
      Object.entries(available()).map(([k, v]) => [
        k,
        { label: v.label, kind: v.kind, workflow: Boolean(v.workflow), public_only: Boolean(v.public_only) },
      ]),
    ),
  });
});
