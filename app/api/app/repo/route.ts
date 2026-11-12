import type { NextRequest } from 'next/server';
import { ghRequest } from '@/lib/github.ts';
import {
  configOr404,
  fixAppConfig,
  type Installation,
  installation,
  REPO_CACHE_TTL,
  repoCache,
  sessionOf,
} from '@/lib/github-app.ts';
import { csrf, field, jsonBody, otherMethods, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { parseRepo, REPO_LENGTH } from '@/lib/public-scan.ts';

/** Where an installation's settings are on GitHub, for its account's owner. */
function manageUrl(inst: Installation | null): string | null {
  if (!inst) return null;
  const account = inst.account || {};
  return account.type === 'Organization'
    ? `https://github.com/organizations/${account.login}/settings/installations/${inst.id}`
    : `https://github.com/settings/installations/${inst.id}`;
}

/**
 * What the signed-in person can do on one repo: are they an admin, is the main app installed (Deep scan), is the fix
 * app (when the site has one), and what the app that makes fixes may do there (can_*: the fix app's installation when
 * the site has one, otherwise the main app's).
 */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  csrf(req);
  const body = await jsonBody(req);
  const cfg = configOr404();
  const sess = sessionOf(req);
  const repo = parseRepo(field(body, 'repo', REPO_LENGTH));
  const key = `${sess.login.toLowerCase()}\n${repo.toLowerCase()}`;
  const hit = repoCache.get(key);
  if (hit && Date.now() / 1000 - hit.at < REPO_CACHE_TTL) return privateJson(hit.value);
  const fix = fixAppConfig();
  const fixApp = {
    configured: Boolean(fix),
    installed: null as boolean | null,
    install_url: fix ? `${fix.html_url}/installations/new` : null,
    manage_url: null as string | null,
  };
  const out: Record<string, unknown> = {
    repo,
    user: sess.login,
    admin: false,
    installed: null,
    can_settings: false,
    can_pr: false,
    can_pr_workflows: false,
    install_url: `${cfg.html_url}/installations/new`,
    manage_url: null,
    fix_app: fixApp,
  };
  const r = await ghRequest('GET', `/repos/${repo}`, sess.token);
  out.admin = r.status === 200 && Boolean(r.data?.permissions?.admin);
  // Whether an app is installed is only shown to the repo's admins, who can see it on GitHub anyway.
  if (out.admin) {
    const [inst, fixInst] = await Promise.all([installation(cfg, repo), fix ? installation(fix, repo) : null]);
    const perms = (fix ? fixInst : inst)?.permissions || {};
    const prs = perms.contents === 'write' && perms.pull_requests === 'write';
    Object.assign(out, {
      installed: Boolean(inst),
      can_settings: perms.administration === 'write',
      can_pr: prs,
      can_pr_workflows: prs && perms.workflows === 'write',
      manage_url: manageUrl(inst),
    });
    if (fix) Object.assign(fixApp, { installed: Boolean(fixInst), manage_url: manageUrl(fixInst) });
  }
  // Only an answer with every app installed is kept. Until then the person may be installing one on GitHub right now,
  // and the page asks again when GitHub sends them back.
  if (out.installed && (!fix || fixApp.installed)) repoCache.set(key, { at: Date.now() / 1000, value: out });
  return privateJson(out);
});

export const { GET, PUT, PATCH, DELETE, OPTIONS } = otherMethods('POST');
