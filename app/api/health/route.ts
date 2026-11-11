import { NextResponse } from 'next/server';
import { otherMethods, route } from '@/lib/http.ts';
import { VERSION } from '@/lib/scanner/index.ts';

export const dynamic = 'force-dynamic';

/** Up or not, and which scanner. Nothing about the server's settings, tokens or app: anyone can read this. */
export const GET = route(() =>
  NextResponse.json({ ok: true, scanner_version: VERSION }, { headers: { 'Cache-Control': 'no-store' } }),
);

export const { POST, PUT, PATCH, DELETE, OPTIONS } = otherMethods('GET');
