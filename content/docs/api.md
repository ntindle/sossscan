# sossscan API

The sossscan API is a few HTTP endpoints on this site, and the page itself uses the scan endpoints. There's no key and no sign-in: send a request and you get JSON back. An error comes back as JSON too, such as `{"detail": "Expected OWNER/REPO or a github.com URL"}`, with an HTTP status that says what kind of error it is.

The base address is `https://sossscan.ntindle.com`. The API sends no CORS headers, so a web page on another site can't read its answers. Call it from a script, a server or the command line. To scan from your own machine with your own token, use the [sossscan CLI](/docs/cli) instead.

## Scan a public repository

`GET /api/scan/{owner}/{repo}`

```sh
curl https://sossscan.ntindle.com/api/scan/ntindle/sossscan
```

This runs the public scan, which reads what anyone can see on GitHub, and returns the [report](#the-report). A scan takes about 5 to 30 seconds. The server reuses each result for 6 hours, and the CDN in front of it keeps each answer for 6 hours too, so asking again returns the same report without a new scan. `"cached": true` means the server answered from its cache. The CDN returns an answer exactly as it was first sent, and it may hold one the server took from its cache, so a report can be up to about 12 hours old. `scanned_at` says when the scan ran.

Private repositories are refused. They get the same 404 as a repository that doesn't exist, so the API never shows whether a private repository exists.

## Scan again without the cache

`POST /api/scan`

```sh
curl -X POST https://sossscan.ntindle.com/api/scan \
  -H 'content-type: application/json' \
  -d '{"repo": "ntindle/sossscan", "refresh": true}'
```

The body is a JSON object:

| Field | Type | What it does |
|---|---|---|
| `repo` | string, 3 to 200 characters | The repository: `owner/repo`, or a github.com address such as `https://github.com/owner/repo.git` or a page inside the repository. |
| `refresh` | boolean, optional | With `true`, the server skips its cache and scans again. Without it, a scan from the last 6 hours is reused. |

The answer is the same report, sent with `Cache-Control: no-store`, so the CDN doesn't keep it. The server does save the new scan in its own cache. The page's Rescan button uses this endpoint.

## Check that the service is up

`GET /api/health` returns `{"ok": true, "scanner_version": "0.4.3"}`. It says nothing else about the server, and it isn't rate limited.

## Download the guide's data

`GET /data/guide.json` is the whole guide as one JSON file of about 700 KB. Its `items` are the 81 checks, with their steps, snippets, settings links and what Fund projects did, and each check's `id` is its key in a report's `results`. The file also holds the stages, tiers and scan layers, the 193 Fund projects in `teams`, and the `counts` behind the guide. [public/shared/README.md](https://github.com/ntindle/sossscan/blob/main/public/shared/README.md) describes its fields.

## The report

Both scan endpoints return the report the scanner writes, in the format `sosf-scan/1`. These are its top-level fields:

| Field | What it holds |
|---|---|
| `schema` | `"sosf-scan/1"` |
| `tool` | The scanner's name and version |
| `repo` | `owner/repo`, spelled the way GitHub spells it |
| `scanned_at` | When the scan ran, in UTC |
| `layer` | `public` from the API. The CLI writes `private` when its token has admin access, and a GitHub App check is `app`. |
| `meta` | Facts about the repository: stars, forks, dependents, language, default branch, owner type, package ecosystems, the number of workflows, whether it publishes from CI, and a few more |
| `results` | One entry per check, keyed by the check's id |
| `findings` | Specific problems, with file and line |
| `errors` | What got in the scan's way, such as a file it couldn't read or GitHub's rate limit. Usually empty. |
| `scorecard` | The repository's OpenSSF Scorecard score and checks, or `null` when it has none |
| `tier` | The repository's size tier, such as `{"id": 0, "name": "Just you"}`. Tiers run from 0 to 7, "Critical infrastructure", and a repository's tier is the higher of its stars tier and its dependents tier. |
| `summary` | How many checks got each status |
| `api_calls` | How many requests the scan made |
| `cached` | From the API only: `true` when the server answered from its cache |

A scan that stopped early, for example because GitHub wouldn't show the repository, has no results, so the API answers it with a 404. In a report the CLI writes, such a scan has no `tier`, `summary` or `api_calls`.

Each entry in `results` has a `status`, a one-sentence `summary`, `evidence` (a list of `{label, url}` links), check-specific `details`, and the `layer` that produced it. The status is one of these:

| Status | Meaning | On the page |
|---|---|---|
| `pass` | The control is in place | Done |
| `warn` | It's partly in place | Partly done |
| `fail` | It's missing | Missing |
| `info` | A fact worth knowing, with no verdict | Info |
| `unknown` | This scan couldn't settle it: it needs admin access, or the scan couldn't read something | Needs a deeper scan, or Couldn't check when a read failed |
| `na` | It doesn't apply to this repository | Not applicable |

A finding names its check in `item_id` and has a `severity` (`high`, `medium` or `low`) and a `title`. Its `path`, `line`, `url` and `hint` can each be `null`.

Here's a report for this project's own repository, trimmed to two results:

```json
{
  "schema": "sosf-scan/1",
  "tool": { "name": "sosf-scan", "version": "0.4.3" },
  "repo": "ntindle/sossscan",
  "scanned_at": "2026-11-10T20:29:59Z",
  "layer": "public",
  "meta": {
    "stars": 0,
    "dependents_total": 0,
    "language": "TypeScript",
    "default_branch": "main",
    "private": false,
    "owner_type": "User",
    "ecosystems": ["npm"],
    "workflow_count": 4,
    "publishes_from_ci": false
  },
  "results": {
    "disc-security-md": {
      "status": "pass",
      "summary": "SECURITY.md found",
      "evidence": [{ "label": "SECURITY.md", "url": "https://github.com/ntindle/sossscan/blob/main/SECURITY.md" }],
      "details": { "path": "SECURITY.md", "length": 1293 },
      "layer": "public"
    },
    "plan-irp": {
      "status": "fail",
      "summary": "No incident response plan found in the repo",
      "evidence": [],
      "details": {},
      "layer": "public"
    }
  },
  "findings": [],
  "errors": [],
  "scorecard": null,
  "tier": { "id": 0, "name": "Just you" },
  "summary": { "pass": 17, "warn": 0, "fail": 5, "info": 7, "unknown": 9, "na": 6 },
  "api_calls": 20,
  "cached": false
}
```

A finding looks like this, with a placeholder repository and path:

```json
{
  "item_id": "ci-persist-credentials",
  "severity": "low",
  "title": "actions/checkout keeps the token in .git/config",
  "path": ".github/workflows/ci.yml",
  "line": 12,
  "url": "https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L12",
  "hint": "Add \"with: persist-credentials: false\""
}
```

## Errors

| Status | When |
|---|---|
| 404 | The scan has no results: the repository doesn't exist, it's private, or GitHub wouldn't show it. `detail` has the scanner's words, such as `repo lookup failed: HTTP 404 (private repo? pass a token)`. |
| 422 | The repository name or the request body isn't valid. `detail` says what's wrong, for example `Expected OWNER/REPO or a github.com URL`. |
| 429 | Too many requests from your IP address. The `Retry-After` header says how many seconds to wait. |
| 503 | The scanner is busy: the request waited two minutes for one of the three scans its server instance runs at once. Try again in a minute. |
| 500 | Something went wrong on the server. Try again in a minute. |

Error responses aren't cached, and neither are scans GitHub rate-limited. A scan with results is cached even when its `errors` lists something it couldn't read. To try again sooner, POST with `refresh`.

## Limits

Each IP address can make 6 scan requests a minute and 40 an hour. GET and POST count together, and so do requests the server answers from its cache, but a request the CDN answers doesn't reach the server, so it doesn't count. Each server instance runs at most 3 scans at once, and a scan waits up to two minutes for its turn before the 503. The site can run on several instances that each keep their own count, so the limits are approximate.

## The app endpoints

The endpoints under `/api/app/` and `/app/` serve the page's GitHub App features: sign-in, the admin check and the fixes. They work with the page's sign-in cookie, so they aren't meant for scripts.
