import { mcpMethodNotAllowed, mcpOptions, mcpPost } from '@/lib/mcp.ts';

/**
 * The MCP server (lib/mcp.ts): JSON-RPC messages over the Streamable HTTP transport, one POST each. It keeps no
 * sessions and no event stream, so the other methods get 405. A tool call can run a scan, which can take a while.
 */
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export const POST = mcpPost;
export const OPTIONS = mcpOptions;
export const GET = mcpMethodNotAllowed;
export const PUT = mcpMethodNotAllowed;
export const PATCH = mcpMethodNotAllowed;
export const DELETE = mcpMethodNotAllowed;
