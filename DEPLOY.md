# Deploying sossscan

The live site, https://sossscan.ntindle.com, runs on **Vercel's free Hobby plan**: it's a Next.js app, so the page comes from Vercel's CDN and the server's route handlers (`app/`) run as Vercel Functions. Hobby is for non-commercial projects, and a free tool with no ads or payments qualifies.

## Why it needs no database
Vercel's functions don't remember anything between requests, so the server doesn't keep anything:
| What | Where it lives |
|---|---|
| Who's signed in | An encrypted, signed cookie in their browser (`SOSF_SECRET` is the key) |
| The GitHub sign-in handshake | An encrypted value, checked against a short-lived cookie in the same browser |
| A pull request preview, until you click Open | Sealed (encrypted) in the browser. It works only for the person who previewed it, for 15 minutes, and replaying it returns the pull request it already opened |
| The GitHub Apps' credentials | Environment variables (`GITHUB_APP_*` and `GITHUB_FIX_APP_*`), and nowhere else |
| The token for public scans | Minted from the main app's key when a scan needs one, and kept in memory (per instance) for up to an hour |
| Public scan results | Vercel's CDN, for 6 hours per repo. Rescan skips it |
| The OSS-Fuzz project list | A file shipped with the site (`lib/ossfuzz.json`) |
| An AI fix | It runs inside one request (up to 5 minutes), so there's no background job to track |
| An MCP client's connection | Nowhere: the MCP server has no sessions, and each message stands alone |
| AI fixes per person per day | In their sign-in cookie |

Two things are only per instance on Vercel, so treat them as speed bumps, not hard limits:
- **Rate limits per visitor address.** Repeat scans are mostly served by the CDN cache anyway.
- **The monthly AI-fix budget.** The hard cap is the spending limit you set on the AI provider's key.

## One-time setup
1. **Choose the site's address.** The live site uses `sossscan.ntindle.com`. Any domain you control works, or the `*.vercel.app` address Vercel assigns. It becomes `SITE_BASE_URL` (step 4), and the GitHub Apps' URLs must match it.
2. **Create the Vercel project.** At vercel.com/new, import the GitHub repo `ntindle/sossscan`.
   - Leave **Root Directory** at the repository root (`.`). Vercel detects Next.js from `package.json`.
   - Leave the build settings alone: `npm run build` builds the scanner download and the site, `package-lock.json` pins every dependency, and `engines` picks Node 24.
   - From the command line, the same is `npx vercel@65.9.0 link` from the repo root.
3. **Public scans need no token of yours.** Once the main GitHub App (below) is installed on its owner's account, public scans use the app's own installation token:
   - It can't change anything. In the owner's private repositories it can only read metadata, such as their names; public repositories it reads like any token.
   - It allows about 12,500 GitHub requests an hour. A server with no token gets 60.
   - It can see that the owner's private repositories exist, so a public scan answers a private repo exactly like a missing one (a 404 that says `repo lookup failed: HTTP 404 (private repo? pass a token)`), and never caches that answer.
   - Until the app is installed, public scans run with no token. The server never uses anyone's `gh` CLI token.
   - A personal token still works if you prefer one: set `GITHUB_TOKEN` to a fine-grained token with repository access "Public repositories (read-only)" (github.com/settings/personal-access-tokens/new). When it's set, it wins over the app's.
4. **Set the environment variables** (Project, Settings, Environment Variables, for Production):
   | Name | Value |
   |---|---|
   | `SITE_BASE_URL` | The site's address: `https://sossscan.ntindle.com` today. The apps' URLs on GitHub must match it. |
   | `GITHUB_TOKEN` | Optional, and best left out: see step 3 |
   | `SOSF_SECRET` | Required for sign-in: a random string of at least 32 characters, `openssl rand -hex 32`. Without it, sign-in says the site isn't fully set up (public scans still work). Changing it later signs everyone out. |
   | `GITHUB_APP_*` | The main app's seven settings: see The GitHub Apps, below. |
   | `GITHUB_FIX_APP_*` | Optional: the fix app's three settings, below. Without them, the main app makes the fixes. |
   | `VERCEL_DEEP_CLONE` | Optional: `true`. Vercel then clones the whole Git history, not the last 10 commits, so `/sitemap.xml` can date every page. Without it, a page whose content hasn't changed in the last 10 commits is listed without a `<lastmod>`. Vercel's own docs don't list this setting; docs generators such as Zudoku tell you to set it for the same reason. |
5. **Deploy and add the domain.**
   - Deploy: a push to `main`, or `npx vercel@65.9.0 deploy --prod` from the repo root.
   - Under Project, Settings, Domains, add the site's domain, and add the DNS records Vercel shows you.
   - With Cloudflare DNS, set those records to **DNS only** (grey cloud), so Vercel can issue the certificate.
6. **Install the apps.** From the main app's page, install it on its owner's account (yours, or the organization's): public scans use that installation, and one repository is enough. Then install it on the repositories you want to Deep scan, and the fix app on the ones you want to fix.

## The GitHub Apps
The site uses two GitHub Apps, so that a stolen private key for the one most people install can't change anything:
- **The main app**, [`sossscan`](https://github.com/apps/sossscan), public, owned by `ntindle`: sign-in, Deep scan, and the token for public scans. It only reads.
- **The fix app**, optional: one-click settings fixes, pull request fixes, and Deep scan's private-report checks, which read security advisories (other people's unpublished vulnerability reports among them). It's the only app that can change a repository, so people install it only where they want those.

Without the fix app, the main app makes the fixes and reads the advisories, as it did before there were two, and then it needs those permissions back. Either way, every token the server mints covers one repository and asks only for what its request needs (`*_PERMISSIONS` in `lib/github-app.ts`): Deep scan's only reads, even from an app that could write, and the advisories get a token of their own.

The site uses these apps and nothing else:
- The site can't create, register or replace an app. There's no page or script for that, and the server never writes an app's credentials.
- Their settings live in Vercel (Project, Settings, Environment Variables), for **Production only**, each marked **Sensitive**. Preview deployments don't get them, so they run without sign-in.
- Changing an app is an operator's change: edit those settings, then redeploy. A different main app means everyone signs in again.

### The main app
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

#### Its settings on GitHub
In case it ever has to be made again by hand (github.com/settings/apps/new), these are its settings. A new app has a new name, ID and slug, so all seven settings change with it. The URLs follow `SITE_BASE_URL`: if the site moves to another domain, change them on GitHub too, then redeploy.
| Setting | Value |
|---|---|
| Description | Checks a repository's security settings, including the ones only admins can see. It only reads. |
| Homepage URL | `https://sossscan.ntindle.com` |
| Callback URL | `https://sossscan.ntindle.com/app/oauth-callback` |
| Expire user authorization tokens | On. A sign-in lasts 7 hours, inside a token's 8. |
| Request user authorization (OAuth) during installation | Off |
| Setup URL | `https://sossscan.ntindle.com/app/installed`, with **Redirect on update** on |
| Webhook | Off (**Active** unchecked), and no events |
| Where can it be installed | Any account (public) |

#### Its permissions
All read-only. Deep scan reads with each of them, and nothing writes.
| Permission | Kind | API name | Access | Used for |
|---|---|---|---|---|
| Actions | Repository | `actions` | Read-only | The Actions settings, the workflows, and the deployment environments with their required reviewers |
| Administration | Repository | `administration` | Read-only | Dependabot alerts and security updates, CodeQL default setup, the default `GITHUB_TOKEN`, fork pull request approval, branch protection, immutable releases and the security configuration |
| Code scanning alerts | Repository | `security_events` | Read-only | The open code scanning alerts |
| Contents | Repository | `contents` | Read-only | A private repository's files and releases, and the files a fix's preview reads |
| Dependabot alerts | Repository | `vulnerability_alerts` | Read-only | The open Dependabot alerts |
| Metadata | Repository | `metadata` | Read-only | Always on. Public scans use only this. |
| Pull requests | Repository | `pull_requests` | Read-only | A private repository's open update pull requests (`deps-refresh`), and whether a fix's pull request is already open |
| Secret scanning alerts | Repository | `secret_scanning_alerts` | Read-only | The open secret scanning alerts |
| Secrets | Repository | `secrets` | Read-only | How many Actions secrets the repository has (`ci-secrets-hygiene`). GitHub never returns a secret's value; it returns names and dates, and the scan reports only the count. |
| Members | Organization | `members` | Read-only | An org's members without 2FA, or with SMS for it, and its maintainers team, for a CODEOWNERS fix |
| Administration | Organization | `organization_administration` | Read-only | An org's 2FA requirement and its default security configurations |

Before the split it also had Environments and Repository security advisories. Neither is needed now: GitHub lists the environments and their reviewers under Actions (Environments covers environment secrets and variables, which the scan doesn't read), and the advisories go through the fix app.

The app doesn't ask for Issues. A public repository's issues can be read without it, so only in a Deep scan of a private repository does `repo-settings-review` say it couldn't read them; the CLI with an admin's token can.

### The fix app
| Setting | What it is |
|---|---|
| `GITHUB_FIX_APP_ID` | The app's ID, a number (its settings page, under About) |
| `GITHUB_FIX_APP_SLUG` | The last part of its address, `github.com/apps/<slug>`. The page calls the app by this name. |
| `GITHUB_FIX_APP_PRIVATE_KEY` | A private key (the `.pem` file), generated in its settings. Real line breaks and `\n` both work. |

All three are required, and they're checked like the main app's. If one is missing or invalid, the site runs as it would with one app. The fix app signs no one in, so it has no client ID or secret.

#### Its settings on GitHub
Register it by hand at github.com/settings/apps/new:
| Setting | Value |
|---|---|
| GitHub App name | Your choice, such as `sossscan-fix`. The page shows its slug, the name in its address. |
| Description | Fixes a repository's security settings and opens pull requests, only when an admin of the repository asks on sossscan.ntindle.com. Also reads security advisories for the private-report checks. |
| Homepage URL | `https://sossscan.ntindle.com` |
| Callback URL | None: leave it empty. Nobody signs in through this app. |
| Request user authorization (OAuth) during installation | Off |
| Setup URL | `https://sossscan.ntindle.com/app/installed`, with **Redirect on update** on |
| Webhook | Off (**Active** unchecked), and no events |
| Where can it be installed | Any account (public) |

#### Its permissions
| Permission | Kind | API name | Access | Used for |
|---|---|---|---|---|
| Administration | Repository | `administration` | Read and write | The nine one-click settings fixes. GitHub lists the API call of each under Administration (write), CodeQL default setup included. |
| Contents | Repository | `contents` | Read and write | Pull request fixes: a new branch with one commit |
| Pull requests | Repository | `pull_requests` | Read and write | Opening that pull request |
| Workflows | Repository | `workflows` | Read and write | Pull requests that add or change files in `.github/workflows` |
| Repository security advisories | Repository | `repository_advisories` | Read-only | The private-report checks. See below. |
| Metadata | Repository | `metadata` | Read-only | Always on |

It doesn't need Code scanning alerts, which the single app had for CodeQL default setup: turning that on is an Administration call.

Repository security advisories is the one to think about before asking for it: with it, a token can read every unpublished advisory in an installed repository, including private vulnerability reports other people sent. Deep scan reads three lists of one repository with a token that holds this permission and nothing else (the reports in triage, the drafts and the closed advisories), and the published advisories, which a public scan reads too. It keeps only these numbers and dates:
- the reports in triage: how many have waited over 14 days with no comment, and the age of the oldest (`disc-triage-sla`);
- the closed advisories: the date the latest one titled DRILL was closed (`plan-irp-exercise`);
- the drafts, closed and published advisories: how many brought in collaborators besides the reporter, or have a temporary private fork (`disc-coordinated-disclosure`).

Nothing else of an unpublished advisory is read into a result or stored: no title, description, reporter, identifier, severity or weakness. The server keeps nothing between requests, and a test (`tests/scanner.test.ts`, "keeps nothing of an unpublished advisory") fails if any other field reaches a report. Where the fix app isn't installed, Deep scan doesn't ask for them, and `disc-triage-sla` says that it reads them through the fix app.

### Splitting the app in two
In this order, so nothing stops working along the way:
1. **Register the fix app** by hand, with the settings and permissions above.
2. **Add it to the site.** In the fix app's settings, under **Private keys**, click **Generate a private key**. In Vercel, add `GITHUB_FIX_APP_ID`, `GITHUB_FIX_APP_SLUG` and `GITHUB_FIX_APP_PRIVATE_KEY` for Production, each marked **Sensitive**, then redeploy. From then on, the fixes and the private-report checks go through the fix app.
3. **Lower the main app's permissions** to the read-only list above. In its settings (github.com/settings/apps/sossscan), **Permissions & events**: set Administration, Contents, Pull requests and Code scanning alerts to **Read-only**, and Workflows, Environments and Repository security advisories to **No access**, then **Save changes**. Installations don't have to accept anything: GitHub's docs ("Modifying a GitHub App registration") say "If you remove permissions or webhooks from your GitHub App, the changes will take effect immediately", and only new permissions wait for each account to approve them. To check, open one installation's page (the account's settings, **GitHub Apps**, **Configure** next to sossscan) and see that it lists read access only.
4. **People who want fixes install the fix app**, on the repositories they choose. "Fix it for me" asks for it where it isn't installed, with a link to install it.

Until step 3 the main app still holds its old permissions, but the site doesn't use them: its tokens ask only for what each request needs.

### Adding a permission
1. In the app's settings on GitHub (github.com/settings/apps/sossscan for the main app), open **Permissions & events** and set the permission, for example **Secrets** to **Read-only**.
2. Under **Add a note to users**, say what it's for (the tables above have the words), then click **Save changes**.
3. GitHub emails the owner of each account the app is installed on. An installation keeps its old permissions until its owner approves the new ones on the installation's settings page: under the account's (or organization's) settings, **GitHub Apps**, then **Configure** next to the app.
4. Until then, Deep scan says the app hasn't been given that access: `ci-secrets-hygiene` does for the main app's Secrets, and `disc-triage-sla` (when SECURITY.md gives no response time) for the fix app's Repository security advisories. The drill and disclosure checks stay self-checks. The CLI with an admin's token checks all of them.

Removing a permission takes effect at once, without approval.

### Rotating a private key
1. In the app's settings on GitHub, under **Private keys**, click **Generate a private key**. GitHub downloads a `.pem` file.
2. In Vercel, replace `GITHUB_APP_PRIVATE_KEY` (the main app) or `GITHUB_FIX_APP_PRIVATE_KEY` (the fix app), for Production, with that file's contents.
3. Redeploy, then check that it still works: sign-in, a public scan and Deep scan for the main app; a one-click fix for the fix app.
4. Delete the old key on GitHub. Delete the downloaded file too, or keep it somewhere safe: anyone with it can act as the app.

The main app's client secret works the same way: generate a new one, replace `GITHUB_APP_CLIENT_SECRET`, redeploy, then delete the old one.

### If a key leaks
What someone can do with it depends on whose key it is, in every repository that has that app installed:
- **The main app's** (`GITHUB_APP_PRIVATE_KEY`), once its permissions are lowered (step 3 above), reads what Deep scan reads: repository settings, a private repository's code and pull requests, the open security alerts, the names of Actions secrets, and an org's members and 2FA settings. It can't change anything or read unpublished advisories.
- **The fix app's** (`GITHUB_FIX_APP_PRIVATE_KEY`) can change any repository setting (Administration also covers deleting a repository, adding collaborators and removing branch protection), push code and workflows to any branch, open pull requests, and read unpublished security advisories.

Then:
1. In that app's settings on GitHub, under **Private keys**, generate a new key first (GitHub won't delete an app's only key), then delete the leaked one. Nobody can make a token with it after that. A token made with it earlier lasts at most an hour, and GitHub's docs don't say whether deleting the key ends it sooner.
2. In Vercel, replace that app's `_PRIVATE_KEY` variable with the new key, and redeploy.
3. If the main app's client secret may be exposed too, generate a new one, replace `GITHUB_APP_CLIENT_SECRET`, redeploy, and delete the old one.
4. If `SOSF_SECRET` may be exposed, replace it with a new random value (`openssl rand -hex 32`) and redeploy. That ends every sign-in and every sealed pull request preview, so everyone signs in again. Someone with the old value and a person's sign-in cookie could read the GitHub token inside it.
5. Delete the downloaded `.pem` files, or keep them somewhere safe.

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

Only a signed-in admin of a repo can start one, where the app that makes fixes is installed: the fix app, when the site has one.

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
- The same environment variables apply, and every secret comes from them: `SOSF_SECRET`, the main app's seven `GITHUB_APP_*` settings and, optionally, the fix app's three `GITHUB_FIX_APP_*`. `GITHUB_TOKEN` is optional here too: public scans use the main app's token once it's installed.
- The volume mounted at `/data` holds caches only: scan results, a refreshed OSS-Fuzz list and the AI-fix usage count.

On Fly:
```sh
fly launch --no-deploy --copy-config --name sossscan
fly volumes create sosf_data --size 1 --region iad --yes
fly secrets set SOSF_SECRET=$(openssl rand -hex 32)
fly secrets set GITHUB_APP_ID=… GITHUB_APP_SLUG=… GITHUB_APP_CLIENT_ID=… GITHUB_APP_CLIENT_SECRET=… GITHUB_APP_OWNER=ntindle GITHUB_APP_PUBLIC=true
fly secrets set GITHUB_APP_PRIVATE_KEY="$(cat path/to/the-app.private-key.pem)"
fly secrets set GITHUB_FIX_APP_ID=… GITHUB_FIX_APP_SLUG=… GITHUB_FIX_APP_PRIVATE_KEY="$(cat path/to/the-fix-app.private-key.pem)"
fly deploy --ha=false
```
