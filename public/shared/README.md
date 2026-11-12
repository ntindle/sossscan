# The shared engine behind the page

The guide is one page, the pipeline map at `/` (`public/index.html`, with its script and styles in `public/pipeline/`). It runs on this module, one data file and the scanner API. Earlier there were more views of the same engine:
- ten design variants;
- then the report card and the guided wizard.

Those were retired and deleted.

Pages are static files under `public/`. You don't need to restart the server for HTML, CSS or JS changes.

The site's text pages (About, Contact, Privacy and the docs) don't use this engine. `lib/pages.ts` renders them from Markdown in `content/`, with `core.css`, `pipeline.css` and `text.css` for the look and `theme.js` for the theme, and no other script.

## How a view uses it
- Import the module with `<script type="module">import * as sg from '/shared/core.js'; …</script>`.
- Include `/shared/core.css` (the base styles for `sg-*` components), then override its CSS variables (`--sg-*`) so the components match the view. Set them on `body` if the view's own `:root` tokens must win.
- The Archivo font is self-hosted in `/shared/fonts/` (SIL Open Font License); declare it with `@font-face` and preload it.
- There is no build step: plain HTML, CSS and ES modules, with no third-party scripts or styles.

## Data: `/data/guide.json` (loaded by `sg.loadGuide()`)
`guide` has:
- `tiers[]`: `{id 0..7, name, stars, dependents, blurb}`. These are the "grow with you" levels. A repo's tier is the higher of its stars tier and its dependents tier; see `guide.tier_note`.
- `layers[]`: `public | private | app | manual`, each with `label` and `blurb`. These are the scan layers.
- `stages[]` (pipeline order: accounts → repo → code → ci → deps → release → disclosure → response → people).
- `attacks[]`: `{id, title, story}`, the threat scenarios.
- `sprint.weeks[]`: `W1, W2, W3, M6, M12`, each with `title` and `blurb`.
- `categories[]`: `{id, label}`.
- `app_fixes{}`: the one-click settings fixes the GitHub App can apply.
- `counts`: teams, repos scanned, posts, claims.
- `items[]`: the checklist, one entry per check. Each item has:
  - `id`, `title`, `short`, `why`, `steps[]`, `snippets[] {label, lang, code}`, `pitfalls[]`, `docs[] {label, url}`. The prose fields may be empty for a few items; always handle empty arrays and strings.
  - `category`, `category_label`, `stage`, `attacks[]`, `week`, `tags[]` (`actions`, `publishes`, `npm`, `org`, `ai`, `parses_input`, `multi_maintainer`).
  - `tier` (0–7: the tier at which you should do it), `effort` (1 = minutes … 5 = weeks), `impact` (1–5), `layer` (which scan layer can check it).
  - `links[] {label, url, when?}` (settings deep links with `{owner}`/`{repo}` placeholders), `cli` (a `gh` command), `app_fix[]`, `new_file {path, template}`.
  - For a self-check (layer `manual`), the lines of its "Check it yourself" block. They're empty (`recurs_months` is `null`) on the other checks:
    - `check`: how to check it yourself, in one or two sentences: where to look and what you should see there.
    - `no_result`: for a self-check the scan can sometimes settle, what the scan didn't find when it gave no result, naming what it looks for.
    - `habit`: for one whose convention the scan reads, how to do it so the scan sees it, such as a practice advisory titled DRILL.
    - `recurs_months`: how many months after it's marked done it comes due again, only where the item's own text gives a cadence.
    - `check` and `habit` may hold `[a link](https://…)` and `` `code` ``. A link with `{owner}` or `{repo}` in it needs the repository.
  - `stats`: `teams_did`, `teams_planned`, `teams_recommend`, `repo_present`, `repo_total`, `repo_added_in_window`, `window_commit_teams`, `repo_risk`.
  - `peer_adoption`: `{overall %, by_tier {tierId: %}}`. This is the share of the 193 Fund projects that have the control, by stars tier. It's `null` when the scan of the Fund's repositories didn't measure the control. For `secrets-scanning`, which a scan from outside can't see, it and `stats.repo_present` count a secret scanner (gitleaks or TruffleHog) in CI instead. `peerHave(item)` gives the words for what a check's count measures, to end "n% of the 193 Fund projects …": "have this", or for that check, "run a secret scanner (gitleaks or TruffleHog) in CI".
  - `from_teams[]`: `{team, status, detail, quote, source_url, source_title}`, what Fund teams wrote.
  - `repo_examples[]`: `{team, repo, label, url, timing, date, added_commit}`, real files in their repos.
  - `fix_commits[]`: `{team, repo, date, msg, url}`, commits where teams fixed it.
  - `tools[]`.
- `teams[]`: `{name, sessions, repo, stars, language, tier, scorecard, did[], planned[], present[], posts[] {title, url}, highlights[]}`.

## Scan reports (`sosf-scan/1`)
`report.results[itemId] = {status, summary, evidence[] {label, url}, details, layer}`:
- `status` is one of `pass`, `warn`, `fail`, `info`, `unknown`, `na`. A check gives `info`, not `warn`, for something it can't read: a security policy in a language or format it doesn't read, a file it points to that isn't there, a long policy whose first 256 KB give no way to report, or a versions table it can't parse. A file too large or too complex to read makes the checks that need it `unknown`.
- `details` depends on the check. For `disc-security-md` it has `path` and `length`, `account_default: true` for the account's policy, `report` (the ways to report it found, best first: `github`, `email`, `platform`, `form`, `chat`, `maintainer`, `page`) and `followed` (the one other file in the repository the scan read for it). For `rel-security-support` it has `target` (the release it compared with) and `supported` (the version cells marked supported), or `packages` when the releases are for several packages it couldn't tie to the table. From the admin checks, which read unpublished advisories for counts and dates only: `disc-triage-sla` has `waiting` (the reports that waited over 14 days with no comment, as a string that ends in `+` when there may be more) and `oldest_days`, or `in_triage`; `plan-irp-exercise` has `drill_closed` (YYYY-MM-DD); `disc-coordinated-disclosure` has `advisories` (the drafts, closed and published ones it read), `with_collaborators` (those that brought in someone besides the reporter) and `with_private_fork`, next to `credited` and `releases` from the public checks. `repo-settings-review` has `closed` (YYYY-MM-DD), the date the last issue labeled `settings-review` was closed, and `workflow`, the path of a scheduled workflow that opens them.
- `report.findings[]` holds specific problems: `{item_id, severity high|medium|low, title, path, line, url, hint}`.
- `report.meta` has `stars`, `dependents_total`, `ecosystems`, `owner_type`, `default_branch`, `language`, `publishes_from_ci`, `workflow_count` and `private`.
- Also on the report: `report.tier {id, name}`, `report.scorecard {score, checks, reasons}` (OpenSSF Scorecard, may be `null`), `report.layer` (`public | private | app`) and `report.repo`.

## `core.js` API (all exported)
**Booting and scanning**
- `boot({mountScan, render, compactScan, autoScan})` does everything for a typical page. With `autoScan`, a shared `?repo=` link that this browser has no scan of is scanned straight away, unless GitHub just sent the person back to the page (`?app=`). It loads the guide, mounts the standard scan panel into `mountScan`, and calls `render({guide, report, ctx, repo})` whenever a scan or report loads, or progress changes.
- `renderScanPanel({onReport, initialRepo, compact, autoScan})` is the standard scanner UI:
  1. the repo box, with Scan and Rescan (the public scan, through the API) and Deep scan (the checks only admins can see, through the GitHub App);
  2. a line under it: what Deep scan does, or who's signed in, with Sign out. Its two texts share one place, so it keeps its height when the app's status arrives;
  3. the status message;
  4. the private scan, `.sg-private`: download `sosf-scan.mjs`, run it with Node, then load the JSON report, which is parsed in the browser and never uploaded. A page can move it into a `<details>` of its own, as the map's "Scan privately" does. A message that points to it opens that `<details>`.

  How it behaves:
  - Deep scan asks `app.status()`, then `app.repo()` (afresh when someone presses it). Signed out, it saves an intent (below) and goes to `/app/login`, which comes back to the page with `?repo=`. For someone who isn't an admin of the repo, it says so and offers Sign out. Where the app isn't installed, it says the app is needed there and links to GitHub's install page in the same tab, saving the intent first. Otherwise it runs `app.check()` and merges the result, which is layer `app`. On a copy of the site without the app, it says Deep scan isn't available there and points to the private scan.
  - When GitHub sends the person back with `?app=signed-in` or `?app=installed`, the panel carries on with the intent once: a deep scan runs, or the check whose fix was open opens again (the panel puts `#fix=<id>` in the address before the page's first render). It never sends anyone to GitHub without a click.
  - While busy, the panel's root has `aria-busy="true"` and its status text starts with "Checking" (Deep scan checking access) or "Scanning". Buttons use `aria-disabled`, so keyboard focus stays put. When the panel starts a scan on its own as the page loads (a shared link, or a deep scan it carries on with), it's busy already at the page's first render.
  - Errors appear in `.sg-scan__msg.is-error`: what went wrong, then what to do next.
  - If a scan of a different repo fails, it calls `onReport(null, repo)`, so the old repo's results don't stay on screen under the new name.
  - It shows the `?app=` notice after a GitHub round trip.
- `scanPublic(repo, {refresh})`, `readReportFile(file)`, `mergeReports(...reports)`, `recallReports(repo)`, `initialRepo()` (reads `?repo=` and then the last repo used), `parseRepoInput(str)`.
- `scanTrouble(repo, err, where)` returns `[title, next step]` for a failed scan, in plain words.
- A failed API request, from `scanPublic` or the `app` calls, throws an Error whose message is the API's message and hint together. `err.code` is the API's error code (`lib/http.ts`), and `err.detail` the message alone, which `scanTrouble` reads.
- The `sg:report` document event, with detail `{report, item?}` or a bare report, adds a report to the scan panel (the app's re-check after a one-click fix uses it). The main page listens too, and reopens `item` after it redraws.

**Status and context**
- `ctxFromReport(report, repo)` returns `{owner, repo, full, branch, ecosystems, ownerType, stars, dependents, tier, publishes, hasActions, workflowCount}`. `workflowCount` is `null` unless the report counted the workflows. `tierFor(stars, dependents, guide.tiers)`.
- `itemStatus(item, report, repo, now)` returns `{status, summary, evidence, layer, source, self}`. Statuses also include `manual`, `done` (self-marked) and `todo` (not scanned). A self-check (layer `manual`) shows the scan's result when the report has one, which happens only on a sure sign; otherwise it's `manual`. `STATUS[status].label` / `.tone`.
  - A pass from the scan wins over a mark. A mark wins over any other result, until a self-check with `recurs_months` comes due again, that many calendar months after it was marked (`addMonths`; `now` defaults to the time). Then it's `manual` again, as before anyone marked it, with `due: true` and a summary that says when it was done, so the map lists it under "Still to check" and counts it as open.
  - `doneState(item, self, now)` is where a mark stands: `{done, at, due, overdue}` (dates, or `null`). `markText(item, mark)` is the line next to "Mark done": "Done on …, due again …", "Done on …. It’s due again.", or how often one repeats before it's marked. `dateText(date)` writes a date in the reader's language.
- `statusLabel(st)` is the label to show for one of those: `STATUS[status].label`, except for a check the scan couldn't read ("Could not read …"), which is "Couldn’t check, try again" from the public checks and "Couldn’t check" from the private layer, not "Needs a deeper scan".
- `findingsFor(item, report)`, `applies(item, ctx)`, `progress(items, report, repo)` (returns `{pass, warn, fail, open, total, pct}`).
- `checkRow(item, report, ctx, tierId)` is where one check stands, for a page that sorts and groups the checks: `{item, st, finds, bucket, lost, sev}`.
  - `bucket` is `done`, `todo` (no scan yet), `skip` (doesn't apply), `later` (it starts above the repo's tier), or the status: `fail`, `warn`, `info` or `open`. `NEEDS_WORK` holds `fail` and `warn`.
  - `lost` is the impact lost (all of it when missing, half when partly done), and `sev` the worst finding (`SEV_RANK`: high 2, medium 1, else 0).
  - Sort with `byUrgency` (a high, then medium, finding; then the most impact lost; then the quickest fix) or `byTier` (the order to add them: by tier, then impact, then effort).

**The fix**
- `renderRemediation(item, {guide, report, ctx, onChange})` is the full fix panel:
  - for a self-check the scan didn't pass (or find not applicable), "Check it yourself" in place of the status line: what the scan saw, how to check (`check`), how to make it count (`habit`), and "Mark done" with when it was done and when it's due again. Otherwise the status line;
  - why it matters, and the specific findings;
  - "Fix it for me";
  - settings deep links, a prefilled "Create file on GitHub" link, a prefilled tracking issue and "mark done";
  - "Hand it to an AI agent", the `gh` command, steps and snippets;
  - how other teams did it: quotes, their repo files and their fix commits.
- `selfCheckView(item, report, repo, now)` is what that block holds, or `null`: `{saw, check, habit, mark, when}`.
  - `saw` is the scan's own result (`kind: 'scan'`, with its `status`, `text` and `evidence`); otherwise, for a self-check the scan can sometimes settle, `no_result` (`kind: 'none'`); for one it never reads, `UNSEEN`, "The scan doesn’t check this." (`kind: 'unseen'`). Before any scan, one the scan can settle has no `saw`.
  - `richParts(text, ctx)` splits `check` and `habit` into text, `{code}` and `{text, url}` parts, filling in a link for the repository; until the page knows the repository, such a link stays text.
- `fixItForMe(item, {ctx, report, cls})` is the GitHub App block on its own, for a page that builds its own fix panel.
  - It covers one-click settings (`item.app_fix`) and pull request fixes (`pr_fixes` from `/api/app/status`).
  - It's hidden when the app can't fix the item or the item already passes. When it can't act, it says why: sign in, be an admin, install the app, or a missing permission.
  - Its sign-in and install links stay in the same tab and save an intent with the check's id (below), so the page opens this check again when GitHub sends the person back.
  - `cls = {btn, primary}` passes the page's own button classes.
- `promptBlock(item, {report, ctx, cls})`, `agentPrompt(item, {report, ctx})`, `promptKind(item)`:
  - `promptKind` is `'code'`, `'doc'`, `'setting'` or `null` (no prompt for accounts, people and process checks).
  - The prompts are plain Markdown text built from the guide and the scan.
- "Prompt to fix", one prompt for several checks, modeled on is-agentic.com's:
  - `promptChoices(rows)` takes a page's `checkRow` rows and returns what to offer: `missing` and `partly` (what needs work at the repo's size, most urgent first), `later` (missing or partly done checks for a bigger repo, by tier), `recommended` (the `PROMPT_PICKS`, 5, most urgent ids), `all` (every id offered), and `need: {fail, warn}`, which also counts the checks no agent can do (`outside`, not offered). It's `null` when nothing at the repo's size needs work an agent can do; then a page shows no button.
  - `fixPrompt(choices, pickedIds, {report, ctx, guide, tier, site})` is the prompt: the repository, the scan's result with a link back to `site`, the picked fixes (missing, then partly done, then later), each with its evidence, recommended fix and current result, then requirements. `null` when nothing is picked.
  - `promptDialog(choices, {…fixPrompt's options, opener})` opens the picker, a modal `<dialog>` with presets, a checklist per group and a live count, and copies the prompt. Escape, Cancel or a click outside closes it, and focus returns to `opener`.
- `confirmDialog({title, body, confirm, cancel, wide})` is a modal `<dialog>` that resolves `true` or `false` and returns focus afterwards.

**Links, storage and the app**
- Links: `settingsLinks(item, ctx)`, `newFileUrl(item, ctx)`, `issueForItem(item, ctx, report)`, `newIssueUrl(ctx, {title, body, labels})`, `cliFor(item, ctx)`, `fill(template, ctx)`.
  - `fill` replaces `{owner}`, `{repo}`, `{full}` and `{branch}`.
  - It also replaces `{maintainer}` (`@user`, or `@org/maintainers` for an organization), `{person}` (`@user`, or "(name a maintainer)" for an organization) and `{ecosystem_blocks}`.
  - When `ctx.workflowCount` is 0, the dependabot.yml template (the one with `{ecosystem_blocks}`) leaves out its github-actions entry, which Dependabot calls an error in a repository with no workflows.
  - `lib/fixes.ts` has a copy for pull requests, and a test keeps the two identical.
- `store.get(repo, id)`, `store.set(repo, id, {done, dismissed, note, pr, …})` (localStorage). This fires a `sg:progress` event. `pr` is `{url, number}` once the app has opened a pull request for the item. `at` is when the item was last marked done or not done; setting `pr` leaves it as it was. A self-check that repeats counts from it, so nothing else is stored for due dates.
- `app.status()` (one request per page load), `app.repo(repo, {fresh})` (admin? installed? permissions? Cached per page load unless `fresh`; a failure comes back as `{error, code}`), `app.check(repo)`, `app.fix(repo, fixId)`, `app.prPreview(repo, itemId)`, `app.prCreate(plan)`, `app.loginUrl()`.
  - `status().pr_fixes[itemId].kind` is `file`, `pin` or `agent`.
  - Agent fixes appear only when the site has an AI service configured. Their `prPreview` takes a minute or so, because the agent runs inside that request.
  - `prPreview` returns a sealed `plan` along with the preview. `prCreate(plan)` sends it back, and only the person who previewed it can use it, for 15 minutes.
  - `takeAppNotice()` returns `{key, text, error}` for the `?app=` parameter (`text` is null for a value it doesn't know) and removes the parameter from the address.
- A trip to GitHub and back. Before Deep scan or a fix panel sends someone to sign in or install the app, the page saves what they asked for in sessionStorage, under `INTENT_KEY` (`sg:intent`): `{repo, item, at}`, where `item` is the check whose fix was open, or null for Deep scan.
  - `saveIntent(repo, item)` writes it, and `backTo(repo)` is the page's address showing that repo, for `/app/login?next=`.
  - `readIntent(raw, now)` checks one: the repository with `parseRepoInput`, the check's id, and its age, under `INTENT_TTL` (15 minutes).
  - `resumeIntent(raw, {app, repo, now})` is the intent to carry on with: only after `?app=signed-in` or `?app=installed`, and only for the repository the page shows.
  - `takeIntent({app, repo})` takes it out of sessionStorage on every load, whether it carries on or not, so it's used once at most. The Back button, a cancelled sign-in or another repository leaves nothing to carry on with.

**DOM helpers**
- `el(tag, attrs, ...children)`: children are text, never HTML, and `javascript:` links are refused.
- `statusBadge(status, label)` (the label defaults to `STATUS[status].label`; pass `statusLabel(st)`), `codeBlock(code, lang)`, `copyButton(text, label, cls)`.
- `liveSay(text)` announces to screen readers.
- `EFFORT_LABEL`, `IMPACT_LABEL`, `LAYER_LABEL` (a report's layer: Public scan, Private scan, Deep scan) and `CHECKED_BY` (which scan can check an item, by the item's layer).

## Requirements for the page
1. **Repo in, scan out.** A visible repo input with all three scan layers. Results must change what the page shows: status per item, findings, and the tier from `report.tier` or `report.meta`. It must also work before any scan, as a browsable guide.
2. **Clear remediation for every item.** Show:
   - the why, the steps and the settings deep links;
   - the prefilled new-file link (when `new_file` exists), the tracking issue link and the CLI command;
   - "Fix it for me" and the AI prompt;
   - evidence from other projects: quotes, repo examples and fix commits.
   
   Linking a finding to "how other teams fixed it" is the heart of the product.
3. **Respect the data.** Never invent statistics. Everything shown comes from `guide.json` or the report.
4. **Works for maintainers.**
   - Light and dark mode; readable on a phone (≥360 px), with no horizontal page scroll.
   - Keyboard accessible, visible focus, semantic HTML, 0 axe-core violations.
   - Fast: no giant frameworks, and no layout jumps while things load.
5. **Verify it renders.**
   - With `npm run dev` running, `curl -s http://localhost:3341/` must return 200.
   - Load it in a browser: check for console errors, scan `goreleaser/goreleaser` and `etcd-io/etcd` (it has findings), and look at it at desktop and phone width.
