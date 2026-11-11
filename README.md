# sossscan

A security scanner and guide for open source maintainers, live at https://sossscan.ntindle.com.

Scan a GitHub repository to see where it has security gaps, from your accounts to your releases, and which one to fix first. Each check shows how projects in GitHub's Secure Open Source Fund handled it: what they wrote about it, the files they added and the commits that fixed it. You can fix a gap yourself, hand it to your AI coding agent with a ready-made prompt, or let the optional GitHub App change the setting or open a pull request.

## How a scan works

Type `owner/repo`, or open a link like `https://sossscan.ntindle.com/?repo=owner/repo`. There are three layers, and each one sees more:

1. **Public scan**, run by the site (`GET /api/scan/{owner}/{repo}`, or `POST /api/scan` to rescan; `/openapi.json` describes both). AI agents can run it through the [MCP server](#the-mcp-server).
   - It reads what anyone can see: files, workflows, public settings, and the OpenSSF Scorecard, Best Practices badge, OSS-Fuzz and OSS Scanner listings. It only reads.
   - It uses the first of these tokens (`lib/scan-token.ts`): `GITHUB_TOKEN` or `GH_TOKEN`; then a token of the site's GitHub App, once it's installed on its owner's account, limited to `metadata: read`; then none (60 requests an hour). It never borrows a `gh` CLI token.
   - It refuses private repos: a private repo gets exactly the answer a missing one gets (a 404 with the code `repo_not_found` and the message `repo lookup failed: HTTP 404 (private repo? pass a token)`), never cached, so a public scan doesn't even reveal that a private repo exists.
   - Results are cached for 6 hours.
2. **Private scan**, on your own machine, with the [scanner CLI](#the-scanner-cli) and your own token. An admin token unlocks the checks only admins can see. You load its JSON report into the page, which parses it in your browser and never uploads it. A report made with an admin token is kept in `sessionStorage`; one made without is marked as a public scan and kept in `localStorage`, like one.
3. **Deep scan**, through the [GitHub App](#the-github-app): the admin checks, run by the site for an admin of the repo. The Deep scan button signs them in with GitHub, asks them to install the app if it isn't on the repo yet, then runs the checks, all in the same tab.

Reports are sanitized on the way in: markup characters are neutralized and only http(s) links are kept.

The page then shows:
- a status for every check (pass, warn, fail, unknown, and so on) and specific findings with file and line;
- the one check to fix first: a high-severity finding, then medium, then the most impact lost, then the quickest fix;
- the repo's tier ("grows with you"; see [Tiers](#tiers)), and the gaps along the route from your keyboard to your users, worst first.

## Three ways to fix

Each check's fix panel offers:

1. **Do it yourself:** why it matters, steps and snippets, links to the right settings pages, a prefilled new file, the `gh` command and a tracking issue.
2. **Hand it to your AI agent:** a prompt to paste into Claude Code, Codex, Copilot or Cursor. It holds the scan's findings, the steps, real fix commits from Fund projects, and ground rules: a new branch, the smallest change, pinned actions, nothing weakened, ask instead of guessing, and no settings changed behind your back. Checks about accounts, people and process get no prompt, because nothing in the repo would change.
3. **Fix it for me**, with the GitHub App: a setting changes in one click, or the app opens a pull request that you preview first. [What the app does and never does](#the-github-app) is below.

After a scan, **Prompt to fix**, at the head of the results, hands several checks to your agent at once. You pick them, starting from the five most urgent, and it copies one prompt: the scan's result with a link back to it, then each fix with its evidence, the recommended fix and the current result, then the requirements. Settings stay yours: the agent lists each one with its `gh` command or settings page and asks first.

### AI agent fixes (optional, off by default)

Three workflow fixes need judgment but are well defined: moving untrusted `${{ }}` values out of `run:` steps, `persist-credentials: false` on checkouts, and least-privilege `permissions:` blocks. When the site is configured with an OpenAI-compatible chat API (`AGENT_BASE_URL` and `AGENT_MODEL`), these get a "Let an AI agent fix it" button (`lib/agent.ts`):

1. The model gets the problem, the scan's findings and the flagged workflow files, marked as data, never as instructions. It edits copies of them with three tools (`read_file`, `edit_file`, `finish`) and never talks to GitHub.
2. When it calls `finish`, the server checks the change itself: the YAML still parses, the scan no longer finds the problem, no action, URL, download, secret, trigger, runner or write-all permission was added, and the change stays small. A failed check goes back to the model, within its turn limit. After a passing `finish`, the files are frozen.
3. Only a change that passes becomes a preview, labeled as written by an AI model, with the model and the cost. It's opened like any other pull request fix: only when you confirm.

It's limited per fix (tokens and turns), per person per day, and per month. `DEPLOY.md` lists the settings.

## The scanner CLI

`lib/scanner/` is both the engine the server uses and a standalone CLI with no dependencies. It isn't minified, so you can read it before you run it.

```sh
curl -fsSLO https://sossscan.ntindle.com/download/sosf-scan.mjs
node sosf-scan.mjs OWNER/REPO [--out report.json] [--public] [--token TOKEN] [--quiet]
```

- It needs Node.js 20 or newer. Build it yourself with `npm run build:cli`, which writes `public/download/sosf-scan.mjs`.
- The token is optional: `--token`, `$GITHUB_TOKEN`, `$GH_TOKEN` or `gh auth token`.
- It sends only GET requests: to GitHub (api.github.com, raw.githubusercontent.com, github.com) and two public score services (api.securityscorecards.dev, www.bestpractices.dev). Private repos are never looked up in Scorecard, the Best Practices badge, OSS-Fuzz or OSS Scanner.
- With a token that has admin access, it also checks secret scanning, push protection, Dependabot alerts, Actions permissions, fork pull request approval, rulesets, immutable releases, environments, org 2FA and open alert backlogs.

## The MCP server

AI agents can use sossscan through its MCP server at `https://sossscan.ntindle.com/mcp`, with no key. [Its docs](https://sossscan.ntindle.com/docs/mcp) say how to add it to Claude Code, Cursor, VS Code, ChatGPT and Claude. It has four tools, all read-only:

- `scan_repository`: the public scan, through the same code, cache and per-address limit as `GET /api/scan/{owner}/{repo}`. It returns the tier, the counts and the checks that need work, most urgent first, with their findings, and the whole report when asked. A private repository gets the same answer as a missing one.
- `list_checks` and `get_check`: the guide's checks, and one check's guidance with what Fund projects did.
- `fix_prompt`: the page's "Prompt to fix", built by the page's own code (`public/shared/core.js`).

It speaks protocol version 2026-07-28, and 2025-11-25 and 2025-06-18 for clients that start with `initialize`, over the Streamable HTTP transport: one POST per message, one JSON answer, no sessions and no event stream. It's written for this site (`lib/mcp.ts`, `lib/mcp-tools.ts`) rather than built on the official TypeScript SDK, which has 17 dependencies of its own. A request from a web page on another site gets 403, each address can send 120 messages a minute, a body can be up to 64 KiB, and batches are refused. An [AI Catalog](https://ai-catalog.io) at `/.well-known/ai-catalog.json` points to the server's MCP Server Card at `/mcp/server-card`.

## The GitHub App

The site uses one GitHub App, [`sossscan`](https://github.com/apps/sossscan). It's optional: without it, the site works except for sign-in, Deep scan and "Fix it for me". The server holds the app's private key, so installing the app means trusting this server with the permissions below on the repositories you pick. This section describes what the code does with them. The code is `app/api/app/`, `app/app/`, `lib/github-app.ts` and `lib/fixes.ts`, and the settings fixes are listed under `app_fixes` in `build/skeleton.json`.

### What its permissions are used for

| Permission | Access | Used for |
|---|---|---|
| Administration | Read and write | The one-click settings fixes |
| Contents | Read and write | Pull request fixes: a new branch with one commit |
| Pull requests | Read and write | Opening that pull request |
| Workflows | Read and write | Pull requests that add or change files in `.github/workflows` |
| Code scanning alerts | Read and write | Turning on CodeQL default setup |
| Secret scanning alerts, Dependabot alerts, Actions, Environments | Read | The admin-settings check |
| Organization members, Organization administration | Read | The admin-settings check (org 2FA and org settings) |
| Metadata | Read | Always on. Public scans use only this. |

The admin-settings check uses only read access, including the read side of the write permissions.

### What it never does

- **It never merges.** Every change arrives as a pull request for you to review and merge, or close.
- **It never pushes to an existing branch.** A pull request fix creates a new branch, `sosf/<check>` (`-2` to `-5` if that name is taken), holding one commit on top of your default branch. The only branch it ever deletes is the one it just created, if GitHub refuses to open the pull request.
- **It opens a pull request only after you've seen a preview.**
  - The change is built on the server, never from text the browser sends: a file from the guide's own templates, your workflows with their actions pinned, or an AI agent's edit that passed the checks above.
  - You see the diff or the full new file first. It opens only when you confirm, within 15 minutes, as the person who asked for the preview, and only if your default branch hasn't moved since.
  - It won't add a file the repo already has, and it points to an already-open pull request instead of opening a second one.
- **It changes a setting only when you click.** Each settings fix is one allow-listed API call, made after a confirm dialog says what will change. There are nine: turning on private vulnerability reporting, Dependabot alerts, Dependabot security updates, secret scanning, push protection, CodeQL default setup and immutable releases; making the default `GITHUB_TOKEN` read-only; and requiring approval before first-time contributors' workflows run.
- **It acts only for a repo admin.** Every fix and admin check first confirms, with your own sign-in, that you're an admin of that repository.
- **It never acts on a repository on its own.** There are no webhooks and nothing scheduled: every change happens inside a request from a signed-in admin.
- **It keeps its tokens narrow.** The tokens it mints to check or fix a repository cover only that repository, and the one that opens a pull request has only the permissions that fix needs. Public scans use a token limited to `metadata: read`. Your own sign-in token is used for two reads (who you are, and whether you're an admin of the repo). It lives encrypted in your browser's cookie for 7 hours; the server stores nothing.

## Local development

You need Node.js 24 (Python 3.11 or newer only to [rebuild the guide data](#rebuilding-the-guide-data)).

```sh
npm ci                 # the locked versions, with no install scripts (.npmrc)
npm run dev            # http://localhost:3341 (builds the scanner download first)
npm test               # the server against a fake GitHub and a fake AI service, the scanner against recorded fixtures
npm run typecheck
npm run lint
npm run format:check   # npm run format fixes it
npm run build          # set SITE_BASE_URL to the public address for a real deployment
```

`npm run smoke -- http://localhost:3000` checks a running site after `npm run build && npm start`. Sign-in needs a GitHub App and `SOSF_SECRET` (below); public scans and the guide work without them. `DEPLOY.md` covers Vercel and the container alternative.

### Settings (environment)

- `SITE_BASE_URL`: the public address (default `http://127.0.0.1:3340`). `https` turns on secure `__Host-` cookies and HSTS. Security headers are fixed at build time, so set it when you build.
- `SOSF_SECRET`: the key for sign-in cookies, the sign-in handshake and sealed previews, at least 32 characters (`openssl rand -hex 32`). Sign-in needs it; the server never makes one up. Changing it signs everyone out.
- `GITHUB_APP_ID` (a number), `GITHUB_APP_SLUG`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET` and `GITHUB_APP_PRIVATE_KEY`: the GitHub App's credentials, and the only place they come from. All five are required; if one is missing or invalid, the site runs without sign-in. `GITHUB_APP_OWNER` and `GITHUB_APP_PUBLIC` are optional.
- `GITHUB_TOKEN` or `GH_TOKEN`: optional. When set, public scans use it instead of the app's token.
- `SOSF_DATA_DIR`: caches only, nothing secret (default: the project root; `/tmp/sosf` on Vercel).
- `TRUST_PROXY_HEADERS=1`: behind a proxy that sets the visitor's address, so rate limits count each visitor. Without it (and off Vercel), everyone shares one count, because anyone can send a fake `X-Forwarded-For`.
- `AGENT_*`: AI agent fixes (see `DEPLOY.md`).

## Layout

The page is plain files in `public/`; the server is Next.js route handlers in `app/` over the code in `lib/`. The text pages (About, Contact, Privacy, the docs and the page for AI agents) are route handlers too, rendered from Markdown. Every page also comes as Markdown, for agents: at its address with `.md` added (`/index.md` for the home page), and at its own address for requests that send `Accept: text/markdown`.

| Path | What |
|---|---|
| `app/api/scan/`, `app/api/health/` | The public scan API and a health check. |
| `lib/http.ts` | The route handlers' helpers. Every error under `/api/` is JSON with a code, a message and a hint (`ERROR_CODES`), and each route answers the methods it doesn't take with a JSON 405 and `Allow` (`otherMethods`). |
| `app/api/[[...path]]/` | Every address under `/api/` that no route answers: a 404 in the same JSON form, never the site's 404 page. |
| `app/openapi.json/`, `lib/openapi.ts` | `/openapi.json`, the API's description in OpenAPI 3.1, built when the site builds. It leaves out the GitHub App's endpoints. Its JSON Schemas (the report, the error, the scan request) are plain objects that other code can reuse. |
| `content/` | The text pages' Markdown, one file per page at its address: `/docs/api` is `content/docs/api.md`. `content/index.md` starts the home page's Markdown. |
| `lib/pages.ts`, `lib/markdown.ts` | Renders those pages in the site's header and footer, for `app/about/`, `app/contact/`, `app/privacy/`, `app/docs/` and `app/agents/`, and gives each page's Markdown as written. The renderer covers what the pages use: headings, paragraphs, lists, code blocks, tables, `code` and links. |
| `proxy.ts`, `lib/negotiate.ts` | Markdown content negotiation (acceptmarkdown.com) for the home page and the text pages: a request whose `Accept` header prefers Markdown is rewritten to the page's Markdown twin (`app/about.md/`, `app/index.md/` and the rest), and one that rules out both HTML and Markdown gets 406. Every answer carries `Vary: Accept`: the page and twin routes set it themselves and render per request, because Vercel replaces a prerendered route's `Vary` with its own, while `next.config.ts` adds it to the home page's HTML file. |
| `lib/home.ts` | The home page as Markdown: `content/index.md`, then every stage and check, listed from `public/data/guide.json`. |
| `app/[...path]/` | Every address nothing else answers: a 404, as Markdown for requests that ask for it and as a page in the site's style otherwise. Next.js tries it after every file and route, and after `app/api/[[...path]]/` for addresses under `/api/`. |
| `public/llms.txt`, `public/robots.txt`, `app/sitemap.ts` | For agents and crawlers: an index of the site in the llms.txt format, the crawl rules (crawlers stay out of `/api/` and `/app/`), and a sitemap dated by each page's last commit (`PAGE_DATES` in `next.config.ts`). |
| `app/api/app/`, `app/app/` | The optional GitHub App: sign-in, Deep scan (the admin-settings check), settings fixes and pull request fixes. Nothing here creates or replaces the app. |
| `next.config.ts` | Serves the page (`/` is `public/index.html`), sends the security headers on every response (the CSP's script hashes are computed from `public/` at build time), redirects retired pages, and dates each page from Git for the sitemap. |
| `lib/scanner/` | The scanner: the server's engine and the downloadable CLI. Read-only, no dependencies. |
| `lib/public-scan.ts`, `lib/scan-token.ts` | Public scans: which repo, the 6-hour cache, at most 3 at once, and which token. |
| `app/mcp/`, `lib/mcp.ts`, `lib/mcp-tools.ts` | The MCP server: the protocol and the transport, its tools, and its Server Card (`app/mcp/server-card/`). |
| `app/.well-known/ai-catalog.json/` | The AI Catalog, whose one entry is the MCP server's card. |
| `lib/github-app.ts`, `lib/sealed.ts`, `lib/github.ts` | The app's credentials (environment only), sealed sign-ins and previews, and GitHub API calls. |
| `lib/fixes.ts` | Pull request fixes: builds the change on the server, previews it, then opens it. |
| `lib/agent.ts` | AI agent fixes through any OpenAI-compatible chat API. Off until configured. |
| `lib/ossfuzz.ts`, `lib/ossfuzz.json` | Which repos have an OSS-Fuzz project. `npm run ossfuzz` refreshes the list. |
| `lib/limits.ts` | Rate limits per visitor address. |
| `public/index.html`, `public/pipeline/` | The page: the pipeline map. Its footer has the same links as the text pages' (`footerHtml` in `lib/pages.ts`; a test keeps them equal). Its HTML also lists the stages, for readers without JavaScript; a test keeps them equal to `guide.json`'s. |
| `public/shared/` | The engine the page runs on: the scan panel, the fix panel, the AI prompts and "Fix it for me". `public/shared/README.md` is its contract. Also the text pages' styles and theme script (`text.css`, `theme.js`). |
| `public/data/guide.json` | The guide data, built by `build/build_guide.py`. |
| `build/skeleton.json`, `build/content/*.json` | The guide's structure (tiers, stages, attacks, settings links, `gh` commands, file templates, the settings-fix allowlist) and its prose per check. |
| `tests/` | Vitest tests. No network. |
| `scripts/` | `build-cli.ts` (the scanner download), `ossfuzz-refresh.ts` and `smoke.ts`. |
| `DEPLOY.md`, `.vercelignore`, `Dockerfile`, `fly.toml` | Deployment: Vercel, or one container. |
| `.cache/` | Created at run time: public scan cache, a refreshed OSS-Fuzz list and AI-fix usage. Not committed. |

## Where the guide's data comes from

The guide is built from what the 193 projects in GitHub's Secure Open Source Fund wrote and changed:
- what they wrote: their blog posts and GitHub's write-ups about the program, read for what each team did, planned or recommends;
- what they changed: a scan of each project's repository (which controls it has, and whether they arrived during the program), and commits where teams fixed CI and supply chain risks.

The research corpus behind it is private, because it includes full copies of the original posts. What's published is the built output, `public/data/guide.json`: per check, short quotes attributed to their project with a link to the source, links to example files and fix commits in fund projects' repositories, and adoption by project size. The prose in `build/content/` was written for the guide from that evidence.

### Rebuilding the guide data

Rebuilding `public/data/guide.json` needs the private research data, so you can't do it from this repository alone. To suggest a change to a check's text or structure, open an issue or a pull request against `build/`, and the maintainer will rebuild the guide.

```sh
SOSF_RESEARCH_DIR=/path/to/research python3 -I build/build_guide.py
```

- `SOSF_RESEARCH_DIR` holds `data/changes/` and `data/posts_index.json` (default: `../sossscan-research`, next to this repo). The script stops with a list of what's missing.
- It uses the Python standard library only. Action pins (`{{pin:owner/repo}}` in templates and snippets) resolve to the newest release that is at least 7 days old, as a full commit SHA, using `GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`.
- File templates can use `{owner}`, `{repo}`, `{full}`, `{branch}`, `{maintainer}` (`@user`, or `@org/maintainers` for an organization), `{person}` and `{ecosystem_blocks}`. The page and the server fill them the same way (`fill` in `public/shared/core.js` and `lib/fixes.ts`, kept in step by a test).
- To give a check a pull request fix, add it to `PR_FIXES` in `lib/fixes.ts`. To change the kind of AI prompt it gets, edit the `PROMPT_*` sets in `public/shared/core.js`.

## Tiers

A repo's tier is the higher of its stars tier and its dependents tier. Dependents are repositories plus packages from GitHub's dependency graph, and they count more, because they measure real blast radius.

| Tier | Name | Stars ≥ | Dependents ≥ |
|---:|---|---:|---:|
| 0 | Just you | 0 | 0 |
| 1 | First fans | 1 | 1 |
| 2 | Getting noticed | 10 | 5 |
| 3 | Small community | 50 | 25 |
| 4 | Established | 250 | 100 |
| 5 | Widely used | 1,000 | 500 |
| 6 | Load-bearing | 5,000 | 2,500 |
| 7 | Critical infrastructure | 25,000 | 10,000 |

The thresholds live in two places that must match: `TIERS` in `lib/scanner/` and `tiers` in `build/skeleton.json`. Each check's `tier` in the skeleton is the point at which you should do it.

## Known limitations

- The public scan sees what anyone can see. Several checks stay `unknown` until a deep scan or the private scan checks them.
- Repo checks are heuristics (file names, workflow text). Treat `risk` findings as leads to verify.
- The OSS Scanner check (public repos with over 1,000 stars or 200 dependents) finds a project by matching folder names in anthropics/oss-scanner against the repo's name and owner, then confirms the `repo:` URL in its project.yaml. A project enrolled under an unrelated folder name shows as not enrolled.
- Peer adoption covers the 193 fund repos only, bucketed by stars.
- Fix commits are keyword-matched commit messages with false-positive filters, so expect some noise.
- Pull request fixes have been tested against a fake GitHub and, read-only, against real public repos (planning and previews), but not yet by opening a real pull request.
- AI agent fixes have been tested against a fake AI service, including one that tries to slip in a download; no real model has run them yet. How well they work depends on the model.
- Public scans are rate limited per address, but a visitor with many addresses can still use up the server's GitHub quota. The 6-hour cache softens that.
- On Vercel, rate limits and the monthly AI-fix budget are counted per instance, so they slow things down rather than cap them. The CDN cache and the AI provider's own spending limit are the real protection.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), not in public issues.

## License

The code is under the [MIT License](LICENSE). The Archivo font in `public/shared/fonts/` is under the SIL Open Font License (`OFL.txt` next to it). The quotes and commit messages in `public/data/guide.json` belong to their authors and are included with attribution and links.
