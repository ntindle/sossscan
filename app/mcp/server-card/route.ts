import { otherMethods } from '@/lib/http.ts';
import { discoveryOptions, discoveryRoute, SERVER_CARD, SERVER_CARD_TYPE } from '@/lib/mcp.ts';

/**
 * The MCP server's Server Card (lib/mcp.ts), at <the MCP endpoint>/server-card, the address the Server Card extension
 * reserves for it. /.well-known/ai-catalog.json points here.
 */
export const dynamic = 'force-dynamic';
export const GET = discoveryRoute(SERVER_CARD, SERVER_CARD_TYPE);
export const OPTIONS = discoveryOptions;
export const { POST, PUT, PATCH, DELETE } = otherMethods('GET');
