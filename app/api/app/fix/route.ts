import type { NextRequest } from 'next/server';
import { ghRequest } from '@/lib/github.ts';
import { configOr404, FIXES, installationToken, repoCache, requireAdmin, sessionOf } from '@/lib/github-app.ts';
import { csrf, field, HttpError, jsonBody, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { parseRepo } from '@/lib/public-scan.ts';

/** One allow-listed settings fix: a single API call through the app, for a signed-in admin of the repo. */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  csrf(req);
  const body = await jsonBody(req);
  const cfg = configOr404();
  const fixId = field(body, 'fix_id', { max: 60 });
  const fix = Object.hasOwn(FIXES, fixId) ? FIXES[fixId] : null;
  if (!fix) throw new HttpError(422, 'Unknown fix');
  const sess = sessionOf(req);
  const repo = parseRepo(field(body, 'repo', { min: 3, max: 200 }));
  await requireAdmin(sess, repo);
  const [owner, name] = repo.split('/');
  const token = await installationToken(cfg, repo);
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
      message = `${message}. The app may not have the permission this fix needs on ${repo}.`;
    }
  }
  repoCache.delete(`${sess.login.toLowerCase()}\n${repo.toLowerCase()}`);
  return privateJson({ ok, fix_id: fixId, status: r.status, label: fix.label, message });
});
