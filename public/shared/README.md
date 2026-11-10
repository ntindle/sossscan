# The shared engine behind the page

The guide is one page, the pipeline map at `/` (`public/index.html`, with its script and styles in `public/pipeline/`). It runs on this module, one data file and the scanner API. Earlier there were more views of the same engine:
- ten design variants;
- then the report card and the guided wizard.

Those were retired and deleted.

Pages are static files under `public/`. You don't need to restart the server for HTML, CSS or JS changes.

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
- `items[]`: the checklist (80 items). Each item has:
  - `id`, `title`, `short`, `why`, `steps[]`, `snippets[] {label, lang, code}`, `pitfalls[]`, `docs[] {label, url}`. The prose fields may be empty for a few items; always handle empty arrays and strings.
  - `category`, `category_label`, `stage`, `attacks[]`, `week`, `tags[]` (`actions`, `publishes`, `npm`, `org`, `ai`, `parses_input`, `multi_maintainer`).
  - `tier` (0–7: the tier at which you should do it), `effort` (1 = minutes … 5 = weeks), `impact` (1–5), `layer` (which scan layer can check it).
  - `links[] {label, url, when?}` (settings deep links with `{owner}`/`{repo}` placeholders), `cli` (a `gh` command), `app_fix[]`, `new_file {path, template}`.
  - `stats`: `teams_did`, `teams_planned`, `teams_recommend`, `repo_present`, `repo_total`, `repo_added_in_window`, `window_commit_teams`, `repo_risk`.
  - `peer_adoption`: `{overall %, by_tier {tierId: %}}`. This is the share of the 193 fund projects that have the control, by stars tier. It's `null` when no scanner can see the control.
  - `from_teams[]`: `{team, status, detail, quote, source_url, source_title}`, what fund teams wrote.
  - `repo_examples[]`: `{team, repo, label, url, timing, date, added_commit}`, real files in their repos.
  - `fix_commits[]`: `{team, repo, date, msg, url}`, commits where teams fixed it.
  - `tools[]`.
- `teams[]`: `{name, sessions, repo, stars, language, tier, scorecard, did[], planned[], present[], posts[] {title, url}, highlights[]}`.

## Scan reports (`sosf-scan/1`)
`report.results[itemId] = {status, summary, evidence[] {label, url}, details, layer}`:
- `status` is one of `pass`, `warn`, `fail`, `info`, `unknown`, `na`.
- `report.findings[]` holds specific problems: `{item_id, severity high|medium|low, title, path, line, url, hint}`.
- `report.meta` has `stars`, `dependents_total`, `ecosystems`, `owner_type`, `default_branch`, `language`, `publishes_from_ci`, `workflow_count` and `private`.
- Also on the report: `report.tier {id, name}`, `report.scorecard {score, checks, reasons}` (OpenSSF Scorecard, may be `null`), `report.layer` (`public | private | app`) and `report.repo`.

## `core.js` API (all exported)
**Booting and scanning**
- `boot({mountScan, render, compactScan, autoScan})` does everything for a typical page. With `autoScan`, a shared `?repo=` link that this browser has no scan of is scanned straight away. It loads the guide, mounts the standard scan panel into `mountScan`, and calls `render({guide, report, ctx, repo})` whenever a scan or report loads, or progress changes.
- `renderScanPanel({onReport, initialRepo, compact})` is the standard three-layer scanner UI:
  1. a public scan (calls the API);
  2. a private scan: download `sosf-scan.mjs`, run it with Node, then load the JSON report, which is parsed in the browser and never uploaded;
  3. the GitHub App: install, sign in, check settings.
  
  How it behaves:
  - Its layer headings are `h3`, so put it under an `h2`.
  - While busy, the panel's root has `aria-busy="true"` and its status text starts with "Scanning" or "Checking". Buttons use `aria-disabled`, so keyboard focus stays put.
  - Errors appear in `.sg-scan__msg.is-error`: what went wrong, then what to do next.
  - If a scan of a different repo fails, it calls `onReport(null, repo)`, so the old repo's results don't stay on screen under the new name.
  - It shows the `?app=` notice after a GitHub sign-in round trip.
- `scanPublic(repo, {refresh})`, `readReportFile(file)`, `mergeReports(...reports)`, `recallReports(repo)`, `initialRepo()` (reads `?repo=` and then the last repo used), `parseRepoInput(str)`.
- `scanTrouble(repo, err, where)` returns `[title, next step]` for a failed scan, in plain words.
- The `sg:report` document event, with detail `{report, item?}` or a bare report, adds a report to the scan panel (the app's re-check after a one-click fix uses it). The main page listens too, and reopens `item` after it redraws.

**Status and context**
- `ctxFromReport(report, repo)` returns `{owner, repo, full, branch, ecosystems, ownerType, stars, dependents, tier, publishes, hasActions, workflowCount}`. `workflowCount` is `null` unless the report counted the workflows. `tierFor(stars, dependents, guide.tiers)`.
- `itemStatus(item, report, repo)` returns `{status, summary, evidence, layer, source, self}`. Statuses also include `manual`, `done` (self-marked) and `todo` (not scanned). `STATUS[status].label` / `.tone`.
- `statusLabel(st)` is the label to show for one of those: `STATUS[status].label`, except for a check the scan couldn't read ("Could not read …"), which is "Couldn’t check, try again" from the public checks and "Couldn’t check" from the private layer, not "Needs a deeper scan".
- `findingsFor(item, report)`, `applies(item, ctx)`, `progress(items, report, repo)` (returns `{pass, warn, fail, open, total, pct}`).
- `checkRow(item, report, ctx, tierId)` is where one check stands, for a page that sorts and groups the checks: `{item, st, finds, bucket, lost, sev}`.
  - `bucket` is `done`, `todo` (no scan yet), `skip` (doesn't apply), `later` (it starts above the repo's tier), or the status: `fail`, `warn`, `info` or `open`. `NEEDS_WORK` holds `fail` and `warn`.
  - `lost` is the impact lost (all of it when missing, half when partly done), and `sev` the worst finding (`SEV_RANK`: high 2, medium 1, else 0).
  - Sort with `byUrgency` (a high, then medium, finding; then the most impact lost; then the quickest fix) or `byTier` (the order to add them: by tier, then impact, then effort).

**The fix**
- `renderRemediation(item, {guide, report, ctx, onChange})` is the full fix panel:
  - why it matters, the scan status and the specific findings;
  - "Fix it for me";
  - settings deep links, a prefilled "Create file on GitHub" link, a prefilled tracking issue and "mark done";
  - "Hand it to an AI agent", the `gh` command, steps and snippets;
  - how other teams did it: quotes, their repo files and their fix commits.
- `fixItForMe(item, {ctx, report, cls})` is the GitHub App block on its own, for a page that builds its own fix panel.
  - It covers one-click settings (`item.app_fix`) and pull request fixes (`pr_fixes` from `/api/app/status`).
  - It's hidden when the app can't fix the item or the item already passes. When it can't act, it says why: sign in, be an admin, install the app, or a missing permission.
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
- `store.get(repo, id)`, `store.set(repo, id, {done, dismissed, note, pr, …})` (localStorage). This fires a `sg:progress` event. `pr` is `{url, number}` once the app has opened a pull request for the item.
- `app.status()` (one request per page load), `app.repo(repo)` (admin? installed? permissions?), `app.check(repo)`, `app.fix(repo, fixId)`, `app.prPreview(repo, itemId)`, `app.prCreate(plan)`, `app.loginUrl()`.
  - `status().pr_fixes[itemId].kind` is `file`, `pin` or `agent`.
  - Agent fixes appear only when the site has an AI service configured. Their `prPreview` takes a minute or so, because the agent runs inside that request.
  - `prPreview` returns a sealed `plan` along with the preview. `prCreate(plan)` sends it back, and only the person who previewed it can use it, for 15 minutes.
  - `takeAppNotice()` returns the `?app=` notice and removes the parameter from the address.

**DOM helpers**
- `el(tag, attrs, ...children)`: children are text, never HTML, and `javascript:` links are refused.
- `statusBadge(status, label)` (the label defaults to `STATUS[status].label`; pass `statusLabel(st)`), `codeBlock(code, lang)`, `copyButton(text, label, cls)`.
- `liveSay(text)` announces to screen readers.
- `EFFORT_LABEL`, `IMPACT_LABEL`, `LAYER_LABEL`.

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
