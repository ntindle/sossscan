# sossscan for AI agents

sossscan checks how a GitHub repository is set up for security: who can push and publish, branch and tag rules, CI workflows, dependency updates, releases, and how people report vulnerabilities. This page says when to use it, how to call it, what to read in its answer and where it stops.

## When to use it

Use sossscan when a person asks how well a GitHub repository is protected, or what to do about it:

- "How secure is this repository?" or "What should we fix first?" for a public repository on github.com.
- Whether one control is in place: actions pinned to commit SHAs, a read-only `GITHUB_TOKEN`, branch protection, a SECURITY.md, private vulnerability reporting, Dependabot, CodeQL, release signing or provenance, trusted publishing.
- Risky GitHub Actions workflows: untrusted input in `run:` steps, `pull_request_target`, a token left in `.git/config`.
- What a project of its size should add next. Each check has a tier, set by stars and dependents, so a one-person project isn't held to what critical infrastructure needs.
- How other open source projects closed the same gap. Most checks link to what projects in GitHub's Secure Open Source Fund wrote and to the commits that fixed it.

## How to call it

For a public repository, send one GET request. There's no key, account or sign-in.

```sh
curl https://sossscan.ntindle.com/api/scan/OWNER/REPO
```

The answer is the report as JSON. A new scan takes about 5 to 30 seconds. These fields matter most:

| Field | What to use it for |
|---|---|
| `summary` | How many checks got each status |
| `results` | One entry per check, keyed by its id, with a `status` (`pass`, `warn`, `fail`, `info`, `unknown` or `na`) and a one-sentence `summary`. The [home page's Markdown](/index.md) lists every id. |
| `findings` | Specific problems, each with the check's `item_id`, a `severity` (`high`, `medium` or `low`), a `title`, and the `path` and `line` when there is one |
| `tier` | The repository's size tier, `id` 0 to 7, with its `name` |
| `errors` | What the scan couldn't read, usually nothing |
| `scanned_at`, `cached` | When the scan ran, and whether the server answered from its cache |

A result is `unknown` when the scan couldn't settle it. When its summary says it needs the private scan, it's a setting only the repository's admins can see, so don't report it as missing. Self-checks, such as security training, aren't in the report at all.

To choose what to fix first, do what the web page does. Take the checks that are `fail` or `warn` and whose tier is at or below the repository's. A check with a `high` finding comes first, then one with a `medium` finding, then the one that loses the most impact (all of its `impact` for `fail`, half for `warn`), then the one with the least `effort`. Each check's `impact`, `effort`, `tier`, steps and snippets are in [guide.json](/data/guide.json), about 700 KB, under `items`.

When a request fails, the answer is JSON with `error.code`, such as `repo_not_found` or `rate_limited`, `error.message`, and `error.hint`, which says what to do next. [openapi.json](/openapi.json) describes the API in OpenAPI 3.1, with every code and the report's schema.

If you can use MCP servers, the [sossscan MCP server](/docs/mcp) at `https://sossscan.ntindle.com/mcp` has this scan as a tool. Its `scan_repository` returns the tier, the counts and the checks that need work, already in that order. `get_check` gives one check's steps and what Fund projects did, `list_checks` lists the checks, and `fix_prompt` writes a prompt for a coding agent that fixes the ones you pick. Scans through it count against the same limit.

To show a person the result with every fix, link to `https://sossscan.ntindle.com/?repo=OWNER/REPO`. The [API docs](/docs/api) describe the whole report, the other endpoints and the errors.

## Private repositories and admin settings

The API only scans public repositories. For a private one, or to check settings only admins can see, such as secret scanning, push protection, Dependabot alerts and rulesets, run the CLI on the person's machine with their GitHub token:

```sh
curl -fsSLO https://sossscan.ntindle.com/download/sosf-scan.mjs
node sosf-scan.mjs OWNER/REPO --out report.json --quiet
```

It needs Node.js 20 or newer, sends only GET requests, and takes its token from `--token`, `GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`, in that order. It writes a report in the same format and sends nothing to sossscan.ntindle.com. It exits with 0 when the scan produced results, 1 when it produced none, and 2 for wrong arguments. The [CLI docs](/docs/cli) have the details.

## Limits

- Each IP address can make 6 scan requests a minute and 40 an hour. Past that, the API answers 429, and the `Retry-After` header says how many seconds to wait. When requests go out through a shared service, other people's scans count against the same address.
- A scan is cached for 6 hours, by the server and by the CDN in front of it, so a report can be up to about 12 hours old. `scanned_at` says when it ran. A request the CDN answers doesn't count against the limit.
- To skip the cache, POST to `/api/scan` with `{"repo": "OWNER/REPO", "refresh": true}`. It counts against the same limit.
- Each server instance runs 3 scans at once. A request that waits 2 minutes for its turn gets a 503.
- The API sends no CORS headers, so a web page on another site can't read its answers.

## What it isn't for

- Finding bugs in source code. sossscan doesn't analyze a project's code. It reads repository settings, workflow files and files such as SECURITY.md and CODEOWNERS. It checks whether a project runs code scanning such as CodeQL, not what code scanning would find.
- Private repositories through the API. The API answers them with the same 404 as a repository that doesn't exist. Use the CLI.
- Repositories anywhere but github.com. GitLab, Bitbucket, Codeberg and self-hosted servers aren't supported.
- Certifying a project. The checks are heuristics that read file names and workflow text, so a finding is a lead to verify, and passing every check doesn't make a project safe.
