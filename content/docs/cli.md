# sossscan CLI

The sossscan CLI is the scanner the site runs, as a single JavaScript file that you run with Node.js on your own machine. Use it to scan a private repository, to run the checks only a repository's admins can see, or to scan without going through this site. It needs only Node.js 20 or newer.

## Download and run

```sh
curl -fsSLO https://sossscan.ntindle.com/download/sosf-scan.mjs
node sosf-scan.mjs OWNER/REPO
```

The file isn't minified, so you can read it before you run it. It only sends GET requests, so it can't change anything on GitHub. Instead of `OWNER/REPO` you can give a GitHub address, such as `https://github.com/OWNER/REPO.git` or `git@github.com:OWNER/REPO`.

## Options

| Option | What it does |
|---|---|
| `--token TOKEN` | The GitHub token to use. Without it, the CLI looks for one (see below). |
| `--public` | Runs only the checks anyone can see, with no token unless you also pass `--token`. |
| `--out FILE` | Where to write the JSON report. The default is `sosf-report-OWNER-REPO.json` in the current folder. |
| `--quiet` | Prints no progress, warnings or table. The report is still written. |
| `-h`, `--help` | Shows the usage and exits. |

A long option can be shortened to any prefix that isn't ambiguous, such as `--pub`.

## Tokens

The token is optional. Without `--token`, the CLI uses the first of these it finds:

1. the `GITHUB_TOKEN` environment variable;
2. the `GH_TOKEN` environment variable;
3. the output of `gh auth token`, if the GitHub CLI is installed and signed in.

With `--public` it skips all three. Without a token, GitHub allows only 60 requests an hour. The token goes only to api.github.com and raw.githubusercontent.com, and if GitHub redirects a request anywhere else, the CLI drops the token first.

## The admin checks

When the token belongs to an admin of the repository, the CLI also checks the settings only admins can see: secret scanning, push protection, Dependabot alerts, Actions permissions, approval for fork pull requests, rulesets, immutable releases, environments, the organization's two-factor requirement and its members who still use SMS for it, the organization's security configuration, and open alert backlogs. The report's `layer` is then `private`. Most settings the token can't read come back as `unknown`, usually with the HTTP status in the summary.

## What it contacts

The CLI talks to GitHub: api.github.com, raw.githubusercontent.com and github.com. For a public repository it also asks two OpenSSF services about it, the Scorecard API (api.securityscorecards.dev) and the Best Practices badge (www.bestpractices.dev). A private repository's name is never sent to them, and never looked up in OSS-Fuzz or OSS Scanner. Nothing is sent to sossscan.ntindle.com.

## Output

The report is JSON, in the same `sosf-scan/1` format the [API returns](/docs/api#the-report). Unless you pass `--quiet`, the CLI also prints one line per check, worst first, then the high-severity findings, then any warnings, such as files it couldn't read.

It exits with 0 when the scan produced results, even with warnings, and with 1 when it produced none, for example when the repository doesn't exist or the token can't see it. Wrong arguments exit with 2.

## Load the report into the page

On the [home page](/), open "Scan privately", choose "Load the report" and pick the JSON file. The page reads the file in your browser and checks that it's an `sosf-scan/1` report. It isn't uploaded. The map then shows its results, findings and fixes.

A report made with admin access (`layer` is `private`) joins a public scan of the same repository, if you ran one, and the page keeps it in sessionStorage for that tab. A report made without admin access is marked as a public scan, so it takes the place of the site's public scan of that repository and is kept in localStorage, like one.

## Build it yourself

The source is in [lib/scanner](https://github.com/ntindle/sossscan/tree/main/lib/scanner). In a clone of the repository, run `npm ci` and then `npm run build:cli`, which writes `public/download/sosf-scan.mjs`. Building needs Node.js 24, like the rest of the repository, and the file it writes runs on Node.js 20 or newer.
