import type { NextRequest } from 'next/server';
import { available } from '@/lib/fixes.ts';
import { appConfig, FIXES, fixAppConfig, liveSession } from '@/lib/github-app.ts';
import { otherMethods, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

/** Is there an app, and a fix app, who's signed in, and which fixes this site offers. */
export const GET = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  const cfg = appConfig();
  const s = cfg ? liveSession(req) : null; // without an app, a sign-in cookie isn't even opened
  const fix = cfg ? fixAppConfig() : null; // the fix app needs the main app's sign-in
  return privateJson({
    configured: Boolean(cfg),
    slug: cfg?.slug ?? null,
    html_url: cfg?.html_url ?? null,
    install_url: cfg ? `${cfg.html_url}/installations/new` : null,
    public: Boolean(cfg?.public),
    owner: cfg?.owner ?? null,
    user: s ? s.login : null,
    // The app for one-click fixes, pull request fixes and the private-report checks. Without it, the main app fixes.
    fix_app: {
      configured: Boolean(fix),
      slug: fix?.slug ?? null,
      install_url: fix ? `${fix.html_url}/installations/new` : null,
    },
    fixes: Object.fromEntries(Object.entries(FIXES).map(([k, v]) => [k, { label: v.label, note: v.note ?? null }])),
    pr_fixes: Object.fromEntries(
      Object.entries(available()).map(([k, v]) => [
        k,
        { label: v.label, kind: v.kind, workflow: Boolean(v.workflow), public_only: Boolean(v.public_only) },
      ]),
    ),
  });
});

export const { POST, PUT, PATCH, DELETE, OPTIONS } = otherMethods('GET');
