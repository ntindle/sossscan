# Deploying sossscan

The live site, https://sossscan.ntindle.com, runs on **Vercel's free Hobby plan**: it's a Next.js app, so the page comes from Vercel's CDN and the server's route handlers (`app/`) run as Vercel Functions. Hobby is for non-commercial projects, and a free tool with no ads or payments qualifies.

## Why it needs no database
Vercel's functions don't remember anything between requests, so the server doesn't keep anything:
| What | Where it lives |
|---|---|
| Who's signed in | An encrypted, signed cookie in their browser (`SOSF_SECRET` is the key) |
| The GitHub sign-in handshake | An encrypted value, checked against a short-lived cookie in the same browser |
| A pull request preview, until you click Open | Sealed (encrypted) in the browser. It works only for the person who previewed it, for 15 minutes, and replaying it returns the pull request it already opened |
| The GitHub App's credentials | Environment variables (`GITHUB_APP_*`), and nowhere else |
| The token for public scans | Minted from the GitHub App's key when a scan needs one, and kept in memory (per instance) for up to an hour |
| Public scan results | Vercel's CDN, for 6 hours per repo. Rescan skips it |
| The OSS-Fuzz project list | A file shipped with the site (`lib/ossfuzz.json`) |
| An AI fix | It runs inside one request (up to 5 minutes), so there's no background job to track |
| AI fixes per person per day | In their sign-in cookie |

Two things are only per instance on Vercel, so treat them as speed bumps, not hard limits:
- **Rate limits per visitor address.** Repeat scans are mostly served by the CDN cache anyway.
- **The monthly AI-fix budget.** The hard cap is the spending limit you set on the AI provider's key.

## One-time setup
1. **Choose the site's address.** The live site uses `sossscan.ntindle.com`. Any domain you control works, or the `*.vercel.app` address Vercel assigns. It becomes `SITE_BASE_URL` (step 4), and the GitHub App's URLs must match it.
2. **Create the Vercel project.** At vercel.com/new, import the GitHub repo `ntindle/sossscan`.
   - Leave **Root Directory** at the repository root (`.`). Vercel detects Next.js from `package.json`.
   - Leave the build settings alone: `npm run build` builds the scanner download and the site, `package-lock.json` pins every dependency, and `engines` picks Node 24.
   - From the command line, the same is `npx vercel@65.9.0 link` from the repo root.
3. **Public scans need no token of yours.** Once the GitHub App (below) is installed on its owner's account, public scans use the app's own installation token:
   - It can't change anything. In the owner's private repositories it can only read metadata, such as their names; public repositories it reads like any token.
   - It allows about 12,500 GitHub requests an hour. A server with no token gets 60.
   - It can see that the owner's private repositories exist, so a public scan answers a private repo exactly like a missing one (a 404 that says `repo lookup failed: HTTP 404 (private repo? pass a token)`), and never caches that answer.
   - Until the app is installed, public scans run with no token. The server never uses anyone's `gh` CLI token.
   - A personal token still works if you prefer one: set `GITHUB_TOKEN` to a fine-grained token with repository access "Public repositories (read-only)" (github.com/settings/personal-access-tokens/new). When it's set, it wins over the app's.
4. **Set the environment variables** (Project, Settings, Environment Variables, for Production):
   | Name | Value |
   |---|---|
   | `SITE_BASE_URL` | The site's address: `https://sossscan.ntindle.com` today. The app's URLs on GitHub must match it. |
   | `GITHUB_TOKEN` | Optional, and best left out: see step 3 |
   | `SOSF_SECRET` | Required for sign-in: a random string of at least 32 characters, `openssl rand -hex 32`. Without it, sign-in says the site isn't fully set up (public scans still work). Changing it later signs everyone out. |
   | `GITHUB_APP_*` | The app's seven settings: see The GitHub App, below. |
   | `VERCEL_DEEP_CLONE` | Optional: `true`. Vercel then clones the whole Git history, not the last 10 commits, so `/sitemap.xml` can date every page. Without it, a page whose content hasn't changed in the last 10 commits is listed without a `<lastmod>`. Vercel's own docs don't list this setting; docs generators such as Zudoku tell you to set it for the same reason. |
5. **Deploy and add the domain.**
   - Deploy: a push to `main`, or `npx vercel@65.9.0 deploy --prod` from the repo root.
   - Under Project, Settings, Domains, add the site's domain, and add the DNS records Vercel shows you.
   - With Cloudflare DNS, set those records to **DNS only** (grey cloud), so Vercel can issue the certificate.
6. **Install the app.** From its page, install it on its owner's account (yours, or the organization's): public scans use that installation, and one repository is enough. Then install it on the repositories you want to fix.

## The GitHub App
The app already exists: [`sossscan`](https://github.com/apps/sossscan), public, owned by `ntindle`. The site uses it and nothing else:
- The site can't create, register or replace an app. There's no page or script for that, and the server never writes the app's credentials.
- Its seven `GITHUB_APP_*` settings live in Vercel (Project, Settings, Environment Variables), for **Production only**. Preview deployments don't get them, so they run without sign-in.
- Changing the app is an operator's change: edit those settings, then redeploy. A different app means everyone signs in again.

| Setting | What it is |
|---|---|
| `GITHUB_APP_ID` | The app's ID, a number (its settings page, under About) |
| `GITHUB_APP_SLUG` | `sossscan`, from its address `github.com/apps/sossscan` |
| `GITHUB_APP_CLIENT_ID` | Its client ID |
| `GITHUB_APP_CLIENT_SECRET` | A client secret, generated in its settings |
| `GITHUB_APP_PRIVATE_KEY` | A private key (the `.pem` file), generated in its settings. Real line breaks and `\n` both work. |
| `GITHUB_APP_OWNER` | `ntindle`. Optional: public scans use the installation on this account. |
| `GITHUB_APP_PUBLIC` | `true`. Optional. |

The first five are required. If one is missing or invalid, the site runs without sign-in, and public scans run without the app's token.

### Its settings on GitHub
In case it ever has to be made again by hand (github.com/settings/apps/new), these are its settings. A new app has a new name, ID and slug, so all seven settings change with it. The URLs follow `SITE_BASE_URL`: if the site moves to another domain, change them on GitHub too, then redeploy.
| Setting | Value |
|---|---|
| Description | Checks a repository's security settings and fixes them when you ask: one-click settings, or a pull request you review. |
| Homepage URL | `https://sossscan.ntindle.com` |
| Callback URL | `https://sossscan.ntindle.com/app/oauth-callback` |
| Expire user authorization tokens | On. A sign-in lasts 7 hours, inside a token's 8. |
| Request user authorization (OAuth) during installation | Off |
| Setup URL | `https://sossscan.ntindle.com/app/installed`, with **Redirect on update** on |
| Webhook | Off (**Active** unchecked), and no events |
| Where can it be installed | Any account (public) |

Its permissions. Write access is only used for a fix that a signed-in admin of the repo clicks: administration for the one-click settings, contents, pull requests and workflows for pull requests, and code scanning alerts to turn on CodeQL default setup. The rest are read-only, for the admin-settings check.
| Permission | Kind | API name | Access |
|---|---|---|---|
| Administration | Repository | `administration` | Read and write |
| Contents | Repository | `contents` | Read and write |
| Pull requests | Repository | `pull_requests` | Read and write |
| Workflows | Repository | `workflows` | Read and write |
| Code scanning alerts | Repository | `security_events` | Read and write |
| Secret scanning alerts | Repository | `secret_scanning_alerts` | Read-only |
| Dependabot alerts | Repository | `vulnerability_alerts` | Read-only |
| Actions | Repository | `actions` | Read-only |
| Environments | Repository | `environments` | Read-only |
| Metadata | Repository | `metadata` | Read-only (always on; public scans use only this) |
| Members | Organization | `members` | Read-only |
| Administration | Organization | `organization_administration` | Read-only |

### Rotating the private key
1. In the app's settings on GitHub (github.com/settings/apps/sossscan), under **Private keys**, click **Generate a private key**. GitHub downloads a `.pem` file.
2. In Vercel, replace `GITHUB_APP_PRIVATE_KEY` (Production) with that file's contents.
3. Redeploy, then check that sign-in and a public scan still work.
4. Delete the old key on GitHub. Delete the downloaded file too, or keep it somewhere safe: anyone with it can act as the app.

The client secret works the same way: generate a new one, replace `GITHUB_APP_CLIENT_SECRET`, redeploy, then delete the old one.

## AI fixes (optional)
They stay off until an OpenAI-compatible service is configured. Add these variables, then redeploy:
| Name | Example |
|---|---|
| `AGENT_BASE_URL` | `https://openrouter.ai/api/v1` |
| `AGENT_API_KEY` | The provider key. **Set a monthly spending limit on it with the provider**; that's the real cap. |
| `AGENT_MODEL` | The model id |
| `AGENT_PRICE_IN`, `AGENT_PRICE_OUT` | USD per million tokens, to show the cost in previews |
| `AGENT_FIXES_PER_DAY` | 5 (per signed-in person) |
| `AGENT_MONTHLY_TOKENS`, `AGENT_MONTHLY_USD` | Per-instance speed bumps on Vercel |
| `AGENT_MAX_TOKENS_PER_FIX`, `AGENT_MAX_TURNS` | 80,000 and 8 |

Only signed-in admins of a repo with the app installed can start one.

## Updating
- **Code:** a push to `main` deploys, if the project is connected to the repo. Otherwise run `npx vercel@65.9.0 deploy --prod` from the repo root.
- **Build check:** to test a build locally without an account, run `npx vercel@65.9.0 build`. It needs a linked project, or a placeholder `.vercel/project.json` with `{"projectId":"x","orgId":"x","settings":{"framework":"nextjs"}}`.
- **Dependencies:** `npm install <package>@<version>`, then commit `package.json` and `package-lock.json`. `.npmrc` keeps out anything published in the last 7 days and runs no install scripts.
- **The OSS-Fuzz list:** refresh it now and then with `npm run ossfuzz` (with `GITHUB_TOKEN` set, or `gh` signed in), and commit `lib/ossfuzz.json`.
- **An inline script in `public/index.html`:** its hash in the content security policy is computed when the site builds, so a deploy picks it up. A test (`tests/hardening.test.ts`) checks that every inline script has one.

## Free plan limits (November 2026)
- 1,000,000 function calls a month;
- 4 hours of active CPU;
- 100 GB of transfer;
- functions up to 5 minutes;
- non-commercial use only.

Page files and cached scans come from the CDN, so most visits never start the function.

## Alternative: one container on any server
`Dockerfile` (Node base image pinned by digest, dependencies installed exactly as locked) and `fly.toml` also work, for example on Fly.io at about $4 a month, or on your own hardware:
- The same environment variables apply, and every secret comes from them: `SOSF_SECRET` and the seven `GITHUB_APP_*` settings. `GITHUB_TOKEN` is optional here too: public scans use the app's token once it's installed.
- The volume mounted at `/data` holds caches only: scan results, a refreshed OSS-Fuzz list and the AI-fix usage count.

On Fly:
```sh
fly launch --no-deploy --copy-config --name sossscan
fly volumes create sosf_data --size 1 --region iad --yes
fly secrets set SOSF_SECRET=$(openssl rand -hex 32)
fly secrets set GITHUB_APP_ID=… GITHUB_APP_SLUG=… GITHUB_APP_CLIENT_ID=… GITHUB_APP_CLIENT_SECRET=… GITHUB_APP_OWNER=ntindle GITHUB_APP_PUBLIC=true
fly secrets set GITHUB_APP_PRIVATE_KEY="$(cat path/to/the-app.private-key.pem)"
fly deploy --ha=false
```
