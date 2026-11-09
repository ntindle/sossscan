import type { NextRequest } from 'next/server';
import { configOr404, installationToken, requireAdmin, sessionOf } from '@/lib/github-app.ts';
import { csrf, field, jsonBody, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { ossFuzzLookup } from '@/lib/ossfuzz.ts';
import { parseRepo } from '@/lib/public-scan.ts';
import { scan } from '@/lib/scanner/index.ts';

export const maxDuration = 300;

/** The admin-only checks, through the app's installation: the settings a public scan can't see. */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  csrf(req);
  const body = await jsonBody(req);
  const cfg = configOr404();
  const sess = sessionOf(req);
  const repo = parseRepo(field(body, 'repo', { min: 3, max: 200 }));
  await requireAdmin(sess, repo);
  const token = await installationToken(cfg, repo);
  const rep = await scan(repo, { token, layer: 'private', assumeAdmin: true, ossFuzzLookup });
  return privateJson({ ...rep, layer: 'app' });
});
