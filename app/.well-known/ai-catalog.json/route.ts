import { otherMethods } from '@/lib/http.ts';
import { AI_CATALOG, AI_CATALOG_TYPE, discoveryOptions, discoveryRoute } from '@/lib/mcp.ts';

/**
 * The site's AI Catalog (lib/mcp.ts), at the well-known address AI Catalog clients look for first. Its one entry is the
 * MCP server's Server Card.
 */
export const dynamic = 'force-dynamic';
export const GET = discoveryRoute(AI_CATALOG, AI_CATALOG_TYPE);
export const OPTIONS = discoveryOptions;
export const { POST, PUT, PATCH, DELETE } = otherMethods('GET');
