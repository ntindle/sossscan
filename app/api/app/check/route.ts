import type { NextRequest } from 'next/server';
import {
  advisoryAccess,
  configOr404,
  DEEP_SCAN_PERMISSIONS,
  grantable,
  installationAccess,
  installed,
  requireAdmin,
  sessionOf,
} from '@/lib/github-app.ts';
import { csrf, field, jsonBody, otherMethods, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { ossFuzzLookup } from '@/lib/ossfuzz.ts';
import { parseRepo, REPO_LENGTH } from '@/lib/public-scan.ts';
import { scan } from '@/lib/scanner/index.ts';

export const maxDuration = 300;

/**
 * The admin-only checks, through the main app's installation: the settings a public scan can't see. Its token only
 * reads, whatever the app may do, and the security advisories have a token of their own (advisoryAccess).
 */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  csrf(req);
  const body = await jsonBody(req);
  const cfg = configOr404();
  const sess = sessionOf(req);
  const repo = parseRepo(field(body, 'repo', REPO_LENGTH));
  await requireAdmin(sess, repo);
  const inst = await installed(cfg, repo);
  // The scanner gets the token's permissions too: until an installation accepts one the app asks for, the check that
  // needs it says so, and an empty list GitHub gives such a token isn't read as an empty list.
  const { token, permissions } = await installationAccess(cfg, repo, {
    inst,
    permissions: grantable(DEEP_SCAN_PERMISSIONS, inst),
  });
  const advisories = await advisoryAccess(cfg, repo, inst);
  const rep = await scan(repo, {
    token,
    layer: 'private',
    assumeAdmin: true,
    ossFuzzLookup,
    grants: permissions,
    advisories,
  });
  return privateJson({ ...rep, layer: 'app' });
});

export const { GET, PUT, PATCH, DELETE, OPTIONS } = otherMethods('POST');
