import type { NextRequest } from 'next/server';
import { redirect, route } from '@/lib/http.ts';
import { rateLimit } from '@/lib/limits.ts';

export const dynamic = 'force-dynamic';

/** Where GitHub sends someone after they install the app. */
export const GET = route((req: NextRequest) => rateLimit(req, 'app') || redirect('/?app=installed', 303));
