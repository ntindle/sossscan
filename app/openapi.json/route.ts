import { openApiDocument } from '@/lib/openapi.ts';

/**
 * The API's description in OpenAPI 3.1 (lib/openapi.ts). It can only change with a deployment, so Next.js renders it
 * once, when the site builds, and serves it as a static file that the CDN keeps.
 */
export const dynamic = 'force-static';

export function GET(): Response {
  return new Response(`${JSON.stringify(openApiDocument(), null, 2)}\n`, {
    headers: { 'Content-Type': 'application/json' },
  });
}
