import type { NextRequest, NextResponse } from 'next/server';
import { usage } from '@/lib/agent.ts';
import { available, FixError, plan, preview } from '@/lib/fixes.ts';
import { client } from '@/lib/github.ts';
import {
  configOr404,
  countAgentFix,
  installationToken,
  prReady,
  type Session,
  sessionOf,
  setSession,
} from '@/lib/github-app.ts';
import { csrf, errorResponse, field, HttpError, jsonBody, otherMethods, privateJson, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';
import { parseRepo, REPO_LENGTH } from '@/lib/public-scan.ts';
import { seal } from '@/lib/sealed.ts';

export const maxDuration = 300;

/**
 * Build the pull request without opening it. Returns what it will contain, and the sealed plan that opens it.
 * An AI agent fix runs here too, so this can take a minute or two.
 */
export const POST = route(async (req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  csrf(req);
  const body = await jsonBody(req);
  const cfg = configOr404();
  const sess = sessionOf(req);
  const repo = parseRepo(field(body, 'repo', REPO_LENGTH));
  const itemId = field(body, 'item_id', { max: 60 });
  const { inst } = await prReady(cfg, sess, repo, itemId);
  const isAgent = available()[itemId].kind === 'agent';
  // Today's AI fixes ride in the sign-in cookie, so every answer from here on carries the updated count.
  const counted: Session | null = isAgent ? countAgentFix(sess) : null;
  const answer = (res: NextResponse) => {
    if (counted) setSession(res, counted);
    return res;
  };
  try {
    const token = await installationToken(cfg, repo, { inst });
    let p;
    try {
      p = await plan(client(token), repo, itemId, sess.login);
    } catch (e) {
      if (!(e instanceof FixError)) throw e;
      if (isAgent) usage().record(e.usage);
      throw new HttpError(e.status, e.code, e.message, e.hint);
    }
    if ('existing' in p) return answer(privateJson({ existing: p.existing }));
    if (isAgent) usage().record(p.usage);
    const { changes: _changes, summary: _summary, ...rest } = p;
    const sealed = {
      ...rest,
      files: p.files.map((f) => ({ path: f.path, mode: f.mode, content: f.content })),
      login: sess.login.toLowerCase(),
    };
    return answer(privateJson({ plan: seal('plan', sealed), ...preview(p) }));
  } catch (e) {
    return answer(errorResponse(e));
  }
});

export const { GET, PUT, PATCH, DELETE, OPTIONS } = otherMethods('POST');
