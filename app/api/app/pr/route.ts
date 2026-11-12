import type { NextRequest } from 'next/server';
import { apply, FixError, openPull, type Plan } from '@/lib/fixes.ts';
import { client } from '@/lib/github.ts';
import { configOr404, installationToken, PLAN_TTL, prReady, sessionOf } from '@/lib/github-app.ts';
import { csrf, field, HttpError, jsonBody, otherMethods, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { unseal } from '@/lib/sealed.ts';

export const maxDuration = 300;

/**
 * Open the pull request from a preview: only for the person who previewed it, within 15 minutes. Through the app that
 * makes fixes (the fix app when the site has one), with a token that holds only what this fix's files take.
 */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  csrf(req);
  const body = await jsonBody(req);
  const cfg = configOr404();
  const sess = sessionOf(req);
  const p = unseal<Plan & { login: string }>('plan', field(body, 'plan', { min: 20, max: 3_000_000 }), PLAN_TTL);
  if (!p || p.login !== sess.login.toLowerCase()) {
    throw new HttpError(410, 'preview_expired', 'This preview has expired.', 'Preview the fix again.');
  }
  const { app, inst, need } = await prReady(cfg, sess, p.repo, p.item_id);
  const token = await installationToken(app, p.repo, { permissions: { ...need, metadata: 'read' }, inst });
  const gh = client(token);
  // Opening the same preview twice gives back the pull request it already opened.
  const existing = await openPull(gh, p.repo, p.head);
  if (existing) return privateJson({ ok: true, existing: true, ...existing, branch: p.head });
  try {
    return privateJson({ ok: true, ...(await apply(gh, p)) });
  } catch (e) {
    if (e instanceof FixError) throw new HttpError(e.status, e.code, e.message, e.hint);
    throw e;
  }
});

export const { GET, PUT, PATCH, DELETE, OPTIONS } = otherMethods('POST');
