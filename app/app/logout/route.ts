import type { NextRequest } from 'next/server';
import { clearSession } from '@/lib/github-app.ts';
import { redirect, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

export const dynamic = 'force-dynamic';

export const GET = route((req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  const res = redirect('/?app=signed-out', 303);
  clearSession(res);
  return res;
});
