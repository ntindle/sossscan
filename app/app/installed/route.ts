import type { NextRequest } from 'next/server';
import { count } from '@/lib/counts.ts';
import { redirect, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

export const dynamic = 'force-dynamic';

/** Where GitHub sends someone after they install the app. */
export const GET = route((req: NextRequest) => {
  const limited = rateLimit(req, 'app');
  if (limited) return limited;
  count(req, 'app_installed', {});
  return redirect('/?app=installed', 303);
});
