import type { NextRequest } from 'next/server';
import { count } from '@/lib/counts.ts';
import { ghRequest } from '@/lib/github.ts';
import {
  configOr404,
  FIXES,
  fixer,
  installationToken,
  installed,
  repoCache,
  requireAdmin,
  requirePermissions,
  sessionOf,
  SETTINGS_FIX_PERMISSIONS,
} from '@/lib/github-app.ts';
import { csrf, field, HttpError, jsonBody, otherMethods, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { parseRepo, REPO_LENGTH } from '@/lib/public-scan.ts';

/**
 * One allow-listed settings fix: a single API call for a signed-in admin of the repo, through the app that makes fixes
 * (the fix app when the site has one), with a token that holds only the permission that call takes.
 */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  csrf(req);
  const body = await jsonBody(req);
  const cfg = configOr404();
  const fixId = field(body, 'fix_id', { max: 60 });
  const fix = Object.hasOwn(FIXES, fixId) ? FIXES[fixId] : null;
  if (!fix) {
    throw new HttpError(
      422,
      'invalid_request',
      "There's no settings fix with that fix_id.",
      'Use one of the fix ids that /api/app/status lists under fixes.',
    );
  }
  const sess = sessionOf(req);
  const repo = parseRepo(field(body, 'repo', REPO_LENGTH));
  await requireAdmin(sess, repo);
  const [owner, name] = repo.split('/');
  const app = fixer(cfg);
  const inst = await installed(app, repo);
  const need = SETTINGS_FIX_PERMISSIONS[fixId];
  requirePermissions(app, inst, repo, need, 'change settings');
  const token = await installationToken(app, repo, { inst, permissions: { ...need, metadata: 'read' } });
  const r = await ghRequest(
    fix.method,
    fix.path.replaceAll('{owner}', owner).replaceAll('{repo}', name),
    token,
    fix.body,
  );
  const ok = [200, 201, 202, 204].includes(r.status);
  let message = 'Done';
  if (!ok) {
    message = (r.data && typeof r.data === 'object' && !Array.isArray(r.data) && r.data.message) || `HTTP ${r.status}`;
    if (r.status === 403 || r.status === 404) {
      message = `${message}. The ${app.slug} app may not have the permission this fix needs on ${repo}.`;
    }
  }
  repoCache.delete(`${sess.login.toLowerCase()}\n${repo.toLowerCase()}`);
  count(req, 'settings_fix', { ok });
  return privateJson({ ok, fix_id: fixId, status: r.status, label: fix.label, message });
});

export const { GET, PUT, PATCH, DELETE, OPTIONS } = otherMethods('POST');
