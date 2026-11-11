# sossscan docs

sossscan scans a GitHub repository for security gaps. Besides the [home page](/), there are three ways to use it from your own scripts, tools and AI agents.

## sossscan API

The [sossscan API](/docs/api) is a few HTTP endpoints on this site. One request scans a public repository and returns the report as JSON. Another tells you the service is up, and the guide's own data is a JSON file you can download. You don't need a key or an account.

## sossscan MCP server

The [sossscan MCP server](/docs/mcp) gives AI agents the public scan and the guide as tools, over the Model Context Protocol. Add its address, `https://sossscan.ntindle.com/mcp`, to Claude Code, Cursor, VS Code, ChatGPT or Claude. It needs no key either.

## sossscan CLI

The [sossscan CLI](/docs/cli) is the same scanner as one JavaScript file, which you run with Node.js on your own machine and your own GitHub token. It can scan private repositories and check the settings only admins can see, and the page can load its report.

## For AI agents

[sossscan for AI agents](/agents) says when an agent should use sossscan, which parts of a report matter and what the limits are. Every page also comes as Markdown, at its address with `.md` added, or at its own address for requests that send `Accept: text/markdown`. [llms.txt](/llms.txt) lists them.

## Which one to use

Use the API for a quick look at a public repository. It sees what anyone can see, and repeat scans of a repository within 6 hours come from a cache. Use the MCP server when an AI agent should run that scan and read the guide itself. Use the CLI for a private repository, for the admin-only checks, or when you'd rather your scan didn't go through this site.

The API and the CLI give you the same report, in the format the [API docs](/docs/api#the-report) describe, and the MCP server can return it too. The scanner's source code is in [lib/scanner](https://github.com/ntindle/sossscan/tree/main/lib/scanner) on GitHub.
