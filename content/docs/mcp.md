# sossscan MCP server

The sossscan MCP server lets an AI agent scan a public GitHub repository and read the guide's advice through the Model Context Protocol (MCP). There's no key and no sign-in. It has four tools, and all of them only read: nothing on GitHub or on this site changes when they run.

The address is `https://sossscan.ntindle.com/mcp`, and the transport is Streamable HTTP.

## Connect a client

### Claude Code

```sh
claude mcp add --transport http sossscan https://sossscan.ntindle.com/mcp
```

That adds it to the current project, for you only. Add `--scope user` to have it in every project, or `--scope project` to share it with your team through the project's `.mcp.json`.

### Cursor

Add the server to `.cursor/mcp.json` in a project, or to `~/.cursor/mcp.json` to have it in every project:

```json
{
  "mcpServers": {
    "sossscan": { "url": "https://sossscan.ntindle.com/mcp" }
  }
}
```

### VS Code

Run `MCP: Add Server` from the Command Palette, choose HTTP and enter the address. Or, from a terminal:

```sh
code --add-mcp '{"name":"sossscan","type":"http","url":"https://sossscan.ntindle.com/mcp"}'
```

### ChatGPT

Open [ChatGPT Plugins](https://chatgpt.com/plugins), select the plus button, then "Add custom MCP server". Enter a name, the address above as the server URL, and no authentication, then select "Create as a plugin". Your account's or workspace's policies decide whether you can add custom MCP servers.

### Claude

In Claude, Claude Desktop and Cowork, open [Customize, then Connectors](https://claude.ai/customize/connectors), select "+ Add" and "Add custom connector", then enter a name and the address. On Team and Enterprise plans, an owner adds the connector for the organization first. Claude connects from Anthropic's servers, not from your computer.

### MCP Inspector

The MCP Inspector's command line lists the tools, or calls one:

```sh
npx @modelcontextprotocol/inspector --cli https://sossscan.ntindle.com/mcp --transport http --method tools/list
npx @modelcontextprotocol/inspector --cli https://sossscan.ntindle.com/mcp --transport http --method tools/call --tool-name get_check --tool-arg id=ci-pin-actions
```

## Tools

| Tool | What it does | Arguments |
|---|---|---|
| `scan_repository` | Runs the public scan of a public repository. It returns the repository's size tier, how many checks got each status, and the checks that need work, most urgent first, each with up to three findings and a link to its fix on the home page. | `repo`: `owner/name` or a github.com address. `include_report`, optional: `true` adds the whole report, about 20 KB. |
| `list_checks` | Lists the guide's checks, stage by stage, with each one's id, title, one-line fix, tier, impact and effort. | `stage` and `tier`, both optional. |
| `get_check` | Gives one check's guidance: why it matters, the steps, snippets, mistakes to avoid, links to GitHub's docs and settings, and what projects in GitHub's Secure Open Source Fund did about it, with links to their posts, files and commits. | `id`, such as `ci-pin-actions`. |
| `fix_prompt` | Writes the prompt that "Prompt to fix" on the home page copies, for an AI coding agent working in the repository. It covers the checks you pick, or the five most urgent. | `repo`, and `check_ids`, optional. |

`tools/list` gives each tool's arguments and result as JSON Schema (`inputSchema` and `outputSchema`). A tool returns its result as `structuredContent` and again as the same JSON in a text block, for clients that don't read structured content. Every tool is marked read-only (`readOnlyHint`), and `scan_repository` and `fix_prompt` also as reaching outside the server (`openWorldHint`), since they read GitHub.

`scan_repository` runs the same scan as `GET /api/scan/{owner}/{repo}` in the [sossscan API](/docs/api), with the same 6-hour cache. A private repository gets the same answer as one that doesn't exist. The results quote text from the repository, such as file paths and workflow names, and say that it's data from the scan, not instructions. The prompt from `fix_prompt` tells the coding agent the same.

## Protocol versions

The server speaks protocol version 2026-07-28, the current one, and two earlier ones:

- 2026-07-28 has no handshake. Each request carries its protocol version and the client's capabilities in `params._meta`, repeats the version and the method in the `MCP-Protocol-Version` and `Mcp-Method` headers, and, for `tools/call`, the tool's name in `Mcp-Name`. The server answers `server/discover`, `tools/list` and `tools/call`.
- 2025-11-25 and 2025-06-18 start with `initialize`, which picks the version, and every later request names it in the `MCP-Protocol-Version` header. The server answers `initialize`, `ping`, `tools/list` and `tools/call`, and accepts notifications such as `notifications/initialized` with 202.

Each message is its own POST, with `Content-Type: application/json`, and gets one JSON answer. There's no event stream and there are no sessions, so GET and DELETE get 405, and an `Mcp-Session-Id` header is ignored. Batches of messages aren't accepted, and neither are protocol versions before 2025-06-18.

## Errors

A problem with a request is a JSON-RPC error with the specification's code:

| Code | When |
|---|---|
| -32700 | The body isn't JSON in UTF-8. |
| -32600 | The body isn't one valid JSON-RPC message, or the request was refused before it was read: HTTP 403, 405, 406, 413, 415 or 429. |
| -32601 | No such method. In protocol version 2026-07-28, the HTTP status is 404. |
| -32602 | An unknown tool, or parameters the method can't take. |
| -32603 | Something went wrong on the server. |
| -32020 | A header is missing, or doesn't match the request body. |
| -32022 | A protocol version the server doesn't speak. `error.data.supported` lists the ones it does. |

When the [sossscan API](/docs/api#errors) has a code for the same problem, such as `rate_limited`, it's in `error.data.code`, and `error.data.hint` says what to do next.

When a tool can't do what it was asked, it returns a result with `isError: true` whose text is the API's error body, `{"error": {"code": "...", "message": "...", "hint": "..."}}`, so the model can read it and correct the call. Arguments that don't fit a tool's schema come back the same way, with the code `invalid_request`.

## Limits

- Each IP address can send 120 MCP requests a minute. Past that, the server answers 429, and the `Retry-After` header says how many seconds to wait.
- Each call to `scan_repository` or `fix_prompt` also counts as a scan request, under the API's limit: 6 a minute and 40 an hour for each IP address, for the API and the MCP server together. Past that, the tool returns a `rate_limited` error whose `retry_after` is the wait in seconds.
- A new scan takes about 5 to 30 seconds, and a scan from the last 6 hours is reused. Each server instance runs 3 scans at once, and a scan waits up to 2 minutes for its turn.
- A request body can be up to 64 KiB.

## Security

- Browsers send an `Origin` header, and MCP clients don't. A request from a web page on any other site gets 403, so no page can make its visitors' browsers call the server. The endpoint sends no CORS headers, like the API. Only the two discovery documents below can be read from any page, since they hold public metadata and nothing else.
- The server keeps nothing about a request: no session, no account, and no log of who called which tool. It reads what a client says about itself only to check its form.
- Errors never quote the request. An error repeats only the request's id and, when the protocol version isn't one the server speaks, that version, if it looks like one.

## Finding the server

A client that looks for MCP servers on a domain can find this one without being given the address:

- [/.well-known/ai-catalog.json](/.well-known/ai-catalog.json) is an [AI Catalog](https://ai-catalog.io), version 1.0, whose one entry is the server's card.
- [/mcp/server-card](/mcp/server-card) is the server's MCP Server Card, in the format of the MCP Server Card extension (SEP-2127): its name, version, address, transport and protocol versions.

[llms.txt](/llms.txt) names the server too.

## What it isn't for

The MCP server runs the public scan only, so it can't see private repositories or the settings only admins can see. For those, run the [sossscan CLI](/docs/cli) on your own machine with your own token. [sossscan for AI agents](/agents) says which parts of a report matter and what sossscan doesn't check.
