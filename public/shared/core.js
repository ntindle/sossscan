// core.js — shared engine for every UI variant of the Secure Open Source guide.
// Plain ES module, no build step. Import from a UI page with:
//   import * as sg from '/shared/core.js';
// See /shared/README.md for the data contract and examples.

export const VERSION = '0.1.0';

// ------------------------------------------------------------------------------------------- data
let _guide = null;
export async function loadGuide() {
  if (_guide) return _guide;
  const res = await fetch('/data/guide.json');
  if (!res.ok) throw new Error(`Could not load guide data (${res.status})`);
  const g = await res.json();
  g.itemsById = Object.fromEntries(g.items.map((i) => [i.id, i]));
  g.attacksById = Object.fromEntries(g.attacks.map((a) => [a.id, a]));
  g.stagesById = Object.fromEntries(g.stages.map((s) => [s.id, s]));
  g.categoriesById = Object.fromEntries(g.categories.map((c) => [c.id, c]));
  g.tiersById = Object.fromEntries(g.tiers.map((t) => [t.id, t]));
  _guide = g;
  return g;
}

export const STATUS = {
  pass: { label: 'Done', tone: 'pass', rank: 5 },
  warn: { label: 'Partly done', tone: 'warn', rank: 2 },
  fail: { label: 'Missing', tone: 'fail', rank: 1 },
  info: { label: 'Info', tone: 'info', rank: 4 },
  unknown: { label: 'Needs a deeper scan', tone: 'unknown', rank: 3 },
  na: { label: 'Not applicable', tone: 'na', rank: 6 },
  manual: { label: 'Check yourself', tone: 'manual', rank: 3 },
  done: { label: 'Marked done', tone: 'pass', rank: 5 },
  todo: { label: 'Not scanned', tone: 'unknown', rank: 3 },
};
export const LAYER_LABEL = { public: 'Public scan', private: 'Private scan', app: 'GitHub App', manual: 'Self-check', self: 'Self-check' };
export const EFFORT_LABEL = { 1: 'Minutes', 2: 'An hour or two', 3: 'A day', 4: 'A few days', 5: 'Weeks' };
export const IMPACT_LABEL = { 1: 'Nice to have', 2: 'Helps', 3: 'Solid', 4: 'High', 5: 'Critical' };

// ------------------------------------------------------------------------------------- repo input
export function parseRepoInput(raw) {
  const m = String(raw || '').trim().match(/^(?:(?:https?:\/\/)?(?:www\.)?github\.com\/)?([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:\/\S*)?$/);
  return m && !['.', '..'].includes(m[2]) ? `${m[1]}/${m[2]}` : null;
}

export function initialRepo() {
  const fromUrl = parseRepoInput(new URLSearchParams(location.search).get('repo') || '');
  return fromUrl || safeGet(localStorage, 'sg:lastRepo') || '';
}

function safeGet(s, k) { try { return s.getItem(k); } catch { return null; } }
function safeSet(s, k, v) { try { v === null ? s.removeItem(k) : s.setItem(k, v); } catch { /* storage blocked */ } }

// ------------------------------------------------------------------------------------------ scans
// Reports contain text from third parties (file paths, workflow names) and may be loaded from files.
// Neutralize markup characters in every string and allow only http(s) URLs, so no UI can be tricked
// into rendering HTML or a javascript: link, however it renders.
const URL_KEYS = new Set(['url', 'html_url', 'added_commit']);
export function sanitizeReport(rep) {
  const walk = (v, key) => {
    if (typeof v === 'string') {
      if (URL_KEYS.has(key)) return /^https?:\/\//i.test(v.trim()) ? v.trim() : null;
      return v.replace(/</g, '‹').replace(/>/g, '›');
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, key));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x, k)]));
    return v;
  };
  return rep && typeof rep === 'object' ? walk(rep, '') : rep;
}

// A normal scan uses a GET address the host's CDN can cache for 6 hours; Rescan posts, which skips every cache.
export async function scanPublic(repo, { refresh = false } = {}) {
  const [owner, name] = repo.split('/');
  const res = refresh
    ? await fetch('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ repo, refresh: true }) })
    : await fetch(`/api/scan/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail ? String(data.detail) : `Scan failed (${res.status})`);
  const rep = sanitizeReport(data);
  remember(rep);
  return rep;
}

export async function readReportFile(file) {
  const text = await file.text();
  let rep;
  try { rep = JSON.parse(text); } catch { throw new Error('That file is not JSON'); }
  if (!rep || rep.schema !== 'sosf-scan/1' || !rep.results || typeof rep.repo !== 'string' || !parseRepoInput(rep.repo)) {
    throw new Error('Not an sosf-scan report (expected schema sosf-scan/1)');
  }
  if (!['public', 'private', 'app'].includes(rep.layer)) rep.layer = 'private';
  rep = sanitizeReport(rep);
  remember(rep);
  return rep;
}

// What went wrong with a scan, and what to do next: [title, next step]. `where` says where the private scan is (" below").
export function scanTrouble(repo, err, where = '') {
  const msg = String((err && err.message) || err || '');
  if (/private repositor/i.test(msg)) return [`${repo} is private, so the public scan can’t read it.`, `Use the private scan${where}. It runs on your machine with your own token, and its report stays in your browser.`];
  if (/\b404\b|not found|lookup failed/i.test(msg)) return [`GitHub has no public repository called ${repo}.`, `Check the spelling of the owner and the name. If the repository is private, use the private scan${where}.`];
  if (/\b(403|429)\b|rate limit/i.test(msg)) return [`GitHub is limiting requests right now, so ${repo} wasn’t scanned.`, 'Try again in a minute.'];
  if (/\b503\b|busy/i.test(msg)) return ['The scanner is busy with other scans.', 'Try again in a minute.'];
  if (/failed to fetch|network|load failed/i.test(msg)) return ['The scanner didn’t answer.', 'Check your connection, then press Scan again.'];
  return [`Couldn’t scan ${repo}.`, msg ? `The scanner said: ${msg}` : 'Press Scan to try again.'];
}

// Keep reports for the current tab: public in localStorage, private/app in sessionStorage only.
function remember(rep) {
  if (!rep || !rep.repo) return;
  safeSet(localStorage, 'sg:lastRepo', rep.repo);
  const store = rep.layer === 'public' ? localStorage : sessionStorage;
  safeSet(store, `sg:report:${rep.layer}:${rep.repo.toLowerCase()}`, JSON.stringify(rep));
}

export function recallReports(repo) {
  if (!repo) return [];
  const k = repo.toLowerCase();
  return ['public', 'private', 'app'].map((l) => {
    const raw = safeGet(l === 'public' ? localStorage : sessionStorage, `sg:report:${l}:${k}`);
    try { return raw ? sanitizeReport(JSON.parse(raw)) : null; } catch { return null; }
  }).filter(Boolean);
}

const LAYER_RANK = { public: 1, private: 2, app: 3 };
// Merge reports for one repo: deeper layers win per item, and meta is combined. An item's findings come from the report
// its result came from, so the two agree: a deeper scan reads settings a public one can only guess at (such as the token
// default a workflow without a permissions block gets), and the guess shouldn't stay next to the answer.
export function mergeReports(...reports) {
  const reps = reports.flat().filter(Boolean).sort((a, b) => (LAYER_RANK[a.layer] || 0) - (LAYER_RANK[b.layer] || 0));
  if (!reps.length) return null;
  const out = { ...reps[0], results: {}, findings: [], layers: [], meta: {} };
  const from = new Map();
  for (const r of reps) {
    out.layers.push(r.layer);
    Object.assign(out.meta, r.meta || {});
    for (const [id, res] of Object.entries(r.results || {})) {
      const prev = out.results[id];
      if (!prev || !(res.status === 'unknown' && prev.status !== 'unknown')) {
        out.results[id] = { ...res, layer: res.layer === 'private' ? r.layer : res.layer };
        from.set(id, r);
      }
    }
    out.tier = r.tier || out.tier;
    out.scorecard = r.scorecard || out.scorecard;
    out.layer = r.layer;
    out.scanned_at = r.scanned_at;
  }
  const seen = new Set();
  for (const r of reps) {
    for (const f of r.findings || []) {
      if (from.has(f.item_id) && from.get(f.item_id) !== r) continue;
      const key = `${f.item_id}|${f.path}|${f.line}|${f.title}`;
      if (!seen.has(key)) { seen.add(key); out.findings.push(f); }
    }
  }
  return out;
}

// --------------------------------------------------------------------------------------- context
// Fields we can't know without a scan are null (not false), so applies() doesn't hide items before a scan.
export function ctxFromReport(rep, repo) {
  const full = (rep && rep.repo) || repo || '';
  const [owner, name] = full.split('/');
  const known = !!(rep && rep.meta);
  const m = (rep && rep.meta) || {};
  return {
    owner, repo: name, full, branch: m.default_branch || 'main', ecosystems: m.ecosystems || [], ownerType: m.owner_type ?? null,
    stars: m.stars ?? null, dependents: m.dependents_total ?? null, tier: rep && rep.tier ? rep.tier.id : null,
    publishes: known ? !!m.publishes_from_ci : null, hasActions: known ? (m.workflow_count || 0) > 0 : null, language: m.language ?? null,
  };
}

export function tierFor(stars, dependents, tiers) {
  let best = tiers[0];
  for (const t of tiers) if ((stars || 0) >= t.stars || (dependents || 0) >= t.dependents) best = t;
  if (!stars && !dependents) best = tiers[0];
  return best;
}

const DEPENDABOT_ECO = { npm: 'npm', pypi: 'pip', go: 'gomod', cargo: 'cargo', maven: 'maven', rubygems: 'bundler', composer: 'composer', nuget: 'nuget', swift: 'swift' };
export function fill(template, ctx = {}) {
  if (!template) return template;
  const ecoBlocks = (ctx.ecosystems || []).filter((e) => DEPENDABOT_ECO[e]).map((e) =>
    `  - package-ecosystem: ${DEPENDABOT_ECO[e]}\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n`).join('');
  // An organization's handle isn't a person, and CODEOWNERS needs a team there: {maintainer} and {person} cover both cases.
  const org = ctx.ownerType === 'Organization';
  return template
    .replaceAll('{maintainer}', org ? `@${ctx.owner}/maintainers` : `@${ctx.owner || 'OWNER'}`)
    .replaceAll('{person}', org || !ctx.owner ? '(name a maintainer)' : `@${ctx.owner}`)
    .replaceAll('{owner}', ctx.owner || 'OWNER').replaceAll('{repo}', ctx.repo || 'REPO')
    .replaceAll('{full}', ctx.full || 'OWNER/REPO').replaceAll('{branch}', ctx.branch || 'main')
    .replaceAll('{ecosystem_blocks}', ecoBlocks);
}

// ------------------------------------------------------------------------------ status of an item
export function itemStatus(item, report, repo) {
  const self = store.get(repo || (report && report.repo), item.id);
  const r = report && report.results ? report.results[item.id] : null;
  if (self.done && (!r || r.status !== 'pass')) return { status: 'done', summary: 'You marked this done', evidence: [], layer: 'self', source: 'self', self };
  if (r) return { ...r, source: 'scan', self };
  if (item.layer === 'manual') return { status: 'manual', summary: 'No scanner can see this. Tick it off yourself.', evidence: [], layer: 'manual', source: 'none', self };
  if (!report) return { status: 'todo', summary: 'Scan your repo to check this', evidence: [], layer: item.layer, source: 'none', self };
  return { status: 'unknown', summary: `Needs the ${LAYER_LABEL[item.layer] || 'private scan'}`, evidence: [], layer: item.layer, source: 'none', self };
}

export function findingsFor(item, report) {
  return ((report && report.findings) || []).filter((f) => f.item_id === item.id);
}

// Applicability given what we know about the repo (wizard answers can extend ctx.answers).
export function applies(item, ctx = {}) {
  const tags = item.tags || [];
  const a = ctx.answers || {};
  if (tags.includes('npm') && ctx.ecosystems && ctx.ecosystems.length && !ctx.ecosystems.includes('npm')) return false;
  if (tags.includes('org') && ctx.ownerType === 'User' && a.org !== true) return false;
  if (tags.includes('ai') && a.ai === false) return false;
  if (tags.includes('publishes') && a.publishes === false) return false;
  if (tags.includes('parses_input') && a.parsesInput === false) return false;
  if (tags.includes('multi_maintainer') && a.maintainers === 1) return false;
  if (tags.includes('actions') && ctx.hasActions === false && a.actions !== true) return false;
  return true;
}

// Summary numbers for progress bars.
export function progress(items, report, repo) {
  const counts = { pass: 0, warn: 0, fail: 0, open: 0, total: 0 };
  for (const it of items) {
    const s = itemStatus(it, report, repo).status;
    if (s === 'na') continue;
    counts.total++;
    if (s === 'pass' || s === 'done') counts.pass++;
    else if (s === 'warn') counts.warn++;
    else if (s === 'fail') counts.fail++;
    else counts.open++;
  }
  counts.pct = counts.total ? Math.round((100 * (counts.pass + counts.warn * 0.5)) / counts.total) : 0;
  return counts;
}

// --------------------------------------------------------------------------- links and commands
// Links that need a repo ({owner}/{repo}) are dropped until we know the repo.
export function settingsLinks(item, ctx) {
  return (item.links || []).filter((l) => !l.when || (l.when === 'org' && ctx.ownerType === 'Organization'))
    .filter((l) => ctx.owner || !/\{(owner|repo)\}/.test(l.url))
    .map((l) => ({ label: l.label, url: fill(l.url, ctx) }));
}

export function newFileUrl(item, ctx) {
  if (!item.new_file || !ctx.owner) return null;
  const q = new URLSearchParams({ filename: item.new_file.path, value: fill(item.new_file.template, ctx) });
  return `https://github.com/${ctx.owner}/${ctx.repo}/new/${encodeURIComponent(ctx.branch || 'main')}?${q}`;
}

// GitHub rejects very long URLs; shrink the body until the whole URL fits.
const MAX_URL = 7800;
export function newIssueUrl(ctx, { title, body, labels = ['security'] }) {
  if (!ctx.owner) return null;
  const make = (b) => `https://github.com/${ctx.owner}/${ctx.repo}/issues/new?${new URLSearchParams({ title, body: b, labels: labels.join(',') })}`;
  let b = body;
  let url = make(b);
  while (url.length > MAX_URL && b.length > 200) {
    b = b.slice(0, Math.floor(b.length * 0.85)).replace(/\n[^\n]*$/, '') + '\n\n_(Truncated: the full checklist is in the Secure Open Source guide.)_';
    url = make(b);
  }
  return url;
}

export function issueForItem(item, ctx, report) {
  const st = itemStatus(item, report, ctx.full);
  const lines = [`**${item.title}**`, '', item.why || item.short || '', '', `Current status: ${STATUS[st.status].label}. ${st.summary || ''}`];
  if ((item.steps || []).length) lines.push('', '### Steps', ...item.steps.map((s, i) => `${i + 1}. ${s}`));
  const links = settingsLinks(item, ctx);
  if (links.length) lines.push('', '### Links', ...links.map((l) => `- [${l.label}](${l.url})`));
  const finds = findingsFor(item, report).slice(0, 20);
  if (finds.length) lines.push('', '### Findings');
  for (const f of finds) lines.push(`- [ ] ${f.title}${f.url ? ` ([${f.path}${f.line ? ':' + f.line : ''}](${f.url}))` : ''}`);
  const ex = (item.from_teams || []).slice(0, 2);
  if (ex.length) lines.push('', '### How other projects did it', ...ex.map((e) => `- ${e.team}: ${e.detail}${e.source_url ? ` ([source](${e.source_url}))` : ''}`));
  lines.push('', '_Generated by the Secure Open Source guide._');
  return newIssueUrl(ctx, { title: `Security: ${item.title}`, body: lines.join('\n') });
}

export function cliFor(item, ctx) { return item.cli ? fill(item.cli, ctx) : null; }

// ------------------------------------------------------------------------------------ AI prompts
// A prompt someone can paste into an AI coding agent (Claude Code, Codex, Copilot, Cursor…) running in their repository.
// What the agent can do differs by check: change code or config (the default), write a document, or change a repository
// setting with gh after asking. Checks about accounts, people and process get no prompt: there's nothing in the repo to change.
const PROMPT_DOC = new Set(['repo-codeowners', 'disc-security-md', 'disc-triage-sla', 'plan-threat-model', 'plan-irp', 'rel-security-support',
  'ai-threat-model', 'ai-contribution-policy', 'ai-agent-instructions', 'people-contributor-guidance', 'people-user-security-docs']);
const PROMPT_SETTING = new Set(['repo-branch-protection', 'repo-tag-release-protection', 'repo-signed-commits', 'disc-private-reporting',
  'ci-fork-pr-approval', 'sast-codeql', 'secrets-scanning', 'secrets-push-protection', 'deps-alerts']);
const PROMPT_NONE = new Set(['people-support-programs', 'acct-2fa-required', 'acct-phishing-resistant-2fa', 'acct-least-privilege', 'acct-registry-accounts', 'repo-org-security-config',
  'repo-settings-review', 'disc-advisories-cves', 'disc-coordinated-disclosure', 'plan-irp-exercise', 'plan-security-roadmap', 'plan-external-audit',
  'plan-postmortem', 'sast-autofix', 'secrets-rotate-leaked', 'deps-upstream-relationships', 'posture-best-practices-badge', 'ai-assisted-security',
  'people-security-owner', 'people-security-training', 'people-share-learnings']);
export function promptKind(item) {
  if (!item || PROMPT_NONE.has(item.id)) return null;
  if (PROMPT_DOC.has(item.id)) return 'doc';
  if (PROMPT_SETTING.has(item.id)) return 'setting';
  return 'code';
}

const ZIZMOR = 'Run zizmor on the workflows (`uvx zizmor .github/workflows`, or `pipx run zizmor .github/workflows`) and fix anything it reports about the lines you changed.';
const PROMPT_CHECK = {
  'ci-pin-actions': 'Check that every `uses:` line in .github/workflows points at a 40-character commit SHA with the version in a comment. Local actions (`./…`) and `docker://` images don’t need one.',
  'ci-script-injection': ZIZMOR, 'ci-dangerous-triggers': ZIZMOR, 'ci-token-permissions': ZIZMOR, 'ci-persist-credentials': ZIZMOR,
  'ci-workflow-audit': ZIZMOR, 'ci-runner-hardening': ZIZMOR, 'ci-untrusted-artifacts-caches': ZIZMOR, 'ci-oidc': ZIZMOR,
  'deps-lockfiles': 'Install from the lockfile the way CI does and make sure it still succeeds.',
  'fuzz-harnesses': 'Build each new fuzz target and run it for a minute. Tell me if it finds a crash; don’t silence one.',
  'test-security-tests': 'Run the test suite. Where you can, show the new test failing without the fix and passing with it.',
  'sast-oss-scanner': 'From the repository root, build the image (`docker build -f .oss-scanner/Dockerfile -t oss-scanner-test .`), then run the tests in it with no network (`docker run --rm --network none oss-scanner-test …`; the checkout is at /src). If a test needs the network, fetch what it needs in the Dockerfile or tell me; don’t skip the test.',
};
const PROMPT_RULES = {
  code: [
    'Work on a new branch. Keep the change to what this fix needs: no unrelated refactoring or reformatting.',
    'Pin any GitHub Action you add or change to a full 40-character commit SHA, with the version in a comment (`uses: owner/action@<sha> # v1.2.3`). Look the SHA up; never make one up.',
    'Never weaken an existing check, test or permission to make something pass.',
    'If the repository doesn’t match what this prompt describes, stop and ask me instead of guessing.',
    'Don’t change repository settings, secrets or anything else on GitHub itself. List what I need to do there instead.',
  ],
  doc: [
    'Don’t invent facts: no made-up email addresses, response times, supported versions, names or promises. Where the repository doesn’t tell you, leave a clear TODO for me.',
    'Keep it short and plain, and link to existing docs instead of repeating them.',
    'Work on a new branch and change only the files this needs.',
  ],
  setting: ['Change only this setting, and only after I say OK. Don’t touch other settings, secrets or files.'],
};
// Ground rules for one check, after the ones for its kind.
const PROMPT_ITEM_RULES = {
  'sast-oss-scanner': ['Don’t open the enrollment pull request to anthropics/oss-scanner, and don’t pick the contact address: a core maintainer does both. Draft project.yaml for me with a TODO for primary_contact.'],
};
const rulesFor = (item) => [...PROMPT_RULES[promptKind(item)], ...(PROMPT_ITEM_RULES[item.id] || [])];
const PROMPT_DONE = {
  code: 'When you’re done, show me the diff, explain each change in a sentence, and list anything I still need to do by hand.',
  doc: 'When you’re done, show me the file and list every TODO you left for me.',
  setting: 'When you’re done, tell me the setting’s new value and how to undo it.',
};
const LANG_OF = { md: 'markdown', yml: 'yaml', yaml: 'yaml', json: 'json' };
const langOf = (path) => LANG_OF[(path.split('.').pop() || '').toLowerCase()] || '';
const clipText = (t, n) => (t.length <= n ? t : `${t.slice(0, n).replace(/\s+\S*$/, '')}…`);
function fence(code, lang = '') {
  const ticks = code.includes('```') ? '~~~~' : '```';
  return `${ticks}${lang}\n${code.replace(/\n+$/, '')}\n${ticks}`;
}
function whereOf(ctx) { return ctx.full ? `the GitHub repository ${ctx.full} (default branch: ${ctx.branch || 'main'})` : 'my GitHub repository'; }

function promptSections(item, report, ctx, level) {
  const kind = promptKind(item);
  const H = (t) => `${'#'.repeat(level)} ${t}`;
  const out = [];
  const why = item.why || (item.short !== item.title ? item.short : '');
  if (why) out.push(H('Why it matters'), why);
  const st = report ? itemStatus(item, report, ctx.full) : null;
  if (st && st.source === 'scan') {
    const finds = findingsFor(item, report);
    const lines = [`Status from a scan of the repository: ${STATUS[st.status].label.toLowerCase()}.${st.summary ? ` ${st.summary}` : ''}`];
    for (const f of finds.slice(0, 15)) {
      lines.push(`- ${f.severity} severity: ${f.title}${f.path ? ` in \`${f.path}\`${f.line ? ` line ${f.line}` : ''}` : ''}${f.hint ? `. Hint: ${f.hint}` : ''}`);
    }
    if (finds.length > 15) lines.push(`- …and ${finds.length - 15} more like these. Find them all before you start.`);
    out.push(H('What a scan found'), lines.join('\n'));
  }
  if (kind === 'setting') {
    const cli = cliFor(item, ctx);
    if (cli) {
      out.push(H('Change it with the GitHub CLI'), fence(cli, 'sh'),
        'Before you run anything: check that `gh` is signed in as an admin of the repository (`gh auth status`), show me the exact command, say what it changes, and wait for my OK. Afterwards, read the setting back with `gh api` and tell me what it says now.');
    }
    const links = settingsLinks(item, ctx);
    if (links.length) out.push(`${cli ? 'Or I can' : 'I can'} change it myself on GitHub: ${links.map((l) => `${l.label}, ${l.url}`).join('; ')}.`);
  }
  if (kind === 'doc' && item.new_file) {
    const has = st && st.status === 'warn';
    out.push(H(has ? `What ${item.new_file.path} should cover` : `Start from this ${item.new_file.path}`), fence(fill(item.new_file.template, ctx), langOf(item.new_file.path)),
      has ? 'The repository already has a version of this file. Improve that one instead of replacing it: keep what’s accurate and add what’s missing.'
        : 'Adapt it to this repository. First read the README, CONTRIBUTING, the release notes or CHANGELOG, the existing docs and the git history, so it describes the project as it really is.');
  }
  if ((item.steps || []).length) out.push(H(kind === 'setting' ? 'The steps, for reference' : 'How to fix it'), item.steps.map((s, i) => `${i + 1}. ${s}`).join('\n'));
  if (kind !== 'setting') {
    const sn = (item.snippets || []).slice(0, 4);
    if (sn.length) out.push(H(sn.length === 1 ? 'Example' : 'Examples'), sn.map((x) => `${x.label ? `${x.label}:\n` : ''}${fence(fill(x.code, ctx), x.lang)}`).join('\n\n'));
    if (kind === 'code' && item.new_file) out.push(H(`If the repository has no ${item.new_file.path} yet, start from this`), fence(fill(item.new_file.template, ctx), langOf(item.new_file.path)));
  }
  const commits = (item.fix_commits || []).slice(0, 3);
  const ex = commits.length ? [] : (item.repo_examples || []).slice(0, 2);
  if (commits.length || ex.length) {
    out.push(H('How other open source projects did it'), [
      ...commits.map((c) => `- ${c.team}${c.repo ? ` (${c.repo})` : ''}: “${clipText(c.msg || '', 100)}” ${c.url}`),
      ...ex.map((r) => `- ${r.team}: ${r.label} ${r.url}`)].join('\n'));
  }
  if ((item.pitfalls || []).length) out.push(H('Watch out'), item.pitfalls.map((x) => `- ${x}`).join('\n'));
  if (PROMPT_CHECK[item.id]) out.push(H('Check your work'), PROMPT_CHECK[item.id]);
  return out;
}

// One check. Null when an agent can't help with it.
export function agentPrompt(item, { report = null, ctx = ctxFromReport(report) } = {}) {
  const kind = promptKind(item);
  if (!kind) return null;
  const lead = { code: `Fix a security problem in ${whereOf(ctx)}.`, doc: `Write a security document for ${whereOf(ctx)}.`, setting: `Change a security setting on ${whereOf(ctx)}.` }[kind];
  return `${[`# ${item.title}`, lead, ...promptSections(item, report, ctx, 2), '## Ground rules', rulesFor(item).map((r) => `- ${r}`).join('\n'), PROMPT_DONE[kind]].join('\n\n')}\n`;
}

// Several checks in one prompt, in the order given. Checks an agent can't help with are left out.
export function agentPromptMany(items, { report = null, ctx = ctxFromReport(report), title = '' } = {}) {
  const list = items.filter((it) => promptKind(it));
  if (list.length < 2) return list.length ? agentPrompt(list[0], { report, ctx }) : null;
  const parts = [
    `# ${title || `${list.length} security fixes`}`,
    `Fix these ${list.length} security problems in ${whereOf(ctx)}, one at a time and in this order. Make a separate commit for each one, and stop to ask me if one of them doesn’t fit this repository.`,
    list.map((it, i) => `${i + 1}. ${it.title}`).join('\n'),
  ];
  list.forEach((it, i) => {
    const kind = promptKind(it);
    parts.push(`## ${i + 1}. ${it.title}`);
    if (kind === 'setting') parts.push('This one is a repository setting, not a code change.');
    if (kind === 'doc') parts.push('This one is a document to write.');
    parts.push(...promptSections(it, report, ctx, 3));
  });
  const rules = [...new Set(list.flatMap(rulesFor))];
  parts.push('## Ground rules for all of them', rules.map((r) => `- ${r}`).join('\n'),
    'After each one, show me the diff or the result and explain it briefly. At the end, list anything I still need to do by hand.');
  return `${parts.join('\n\n')}\n`;
}

// ------------------------------------------------------------------------------- progress store
export const store = {
  _key(repo) { return `sg:progress:${(repo || '_').toLowerCase()}`; },
  all(repo) { try { return JSON.parse(safeGet(localStorage, this._key(repo)) || '{}'); } catch { return {}; } },
  get(repo, id) { return this.all(repo)[id] || {}; },
  set(repo, id, patch) {
    const all = this.all(repo);
    all[id] = { ...(all[id] || {}), ...patch, at: new Date().toISOString() };
    safeSet(localStorage, this._key(repo), JSON.stringify(all));
    document.dispatchEvent(new CustomEvent('sg:progress', { detail: { repo, id, value: all[id] } }));
    return all[id];
  },
};

// ---------------------------------------------------------------------------------- GitHub App
export const app = {
  // One status request per page load: every fix panel asks for it.
  _status: null,
  _statusValue: null, // the answer, once it has arrived
  status() {
    return (this._status ||= fetch('/api/app/status').then((r) => (r.ok ? r.json() : { configured: false })).catch(() => ({ configured: false }))
      .then((v) => (this._statusValue = v)));
  },
  loginUrl(next = location.pathname + location.search + location.hash) { return `/app/login?next=${encodeURIComponent(next)}`; },
  async _post(path, body) {
    const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-requested-with': 'sosf' }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail ? String(d.detail) : `Request failed (${r.status})`);
    return d;
  },
  async check(repo) { const rep = sanitizeReport(await this._post('/api/app/check', { repo })); remember(rep); return rep; },
  async fix(repo, fixId) { return this._post('/api/app/fix', { repo, fix_id: fixId }); },
  // What the signed-in person can fix on one repo (admin? app installed? which permissions?). Cached per page load.
  _repos: new Map(),
  _repoValues: new Map(),
  repo(repo) {
    const k = repo.toLowerCase();
    if (!this._repos.has(k)) {
      this._repos.set(k, this._post('/api/app/repo', { repo }).catch((e) => ({ error: e.message })).then((v) => { this._repoValues.set(k, v); return v; }));
    }
    return this._repos.get(k);
  },
  // Ask early, so fix panels opened later can draw "Fix it for me" at once instead of pushing the panel down.
  prefetch(repo) {
    if (repo) this.status().then((st) => { if (st.configured && st.user) this.repo(repo); });
  },
  async prPreview(repo, itemId) { return this._post('/api/app/pr/preview', { repo, item_id: itemId }); },
  // plan: the sealed plan the preview returned; only the person who previewed it can use it, for 15 minutes.
  async prCreate(plan) { return this._post('/api/app/pr', { plan }); },
};

// After GitHub sends someone back (?app=signed-in and so on): what to tell them. Removes the parameter from the address.
const APP_NOTICE = {
  installed: 'The GitHub App is installed. Sign in with GitHub to check admin settings and fix them in one click.',
  'signed-in': 'You’re signed in with GitHub. Fixes the app can make now have a button in their fix.',
  'signed-out': 'You’re signed out of GitHub on this site.',
  'signin-cancelled': 'GitHub sign-in was cancelled, so nothing changed.',
  'signin-failed': 'GitHub sign-in didn’t finish. Try again.',
  'signin-expired': 'That sign-in link had expired. Try again.',
};
export function takeAppNotice() {
  const q = new URLSearchParams(location.search);
  const k = q.get('app');
  if (!k) return null;
  q.delete('app');
  const rest = q.toString();
  try { history.replaceState(history.state, '', `${location.pathname}${rest ? `?${rest}` : ''}${location.hash}`); } catch { /* sandboxed */ }
  return APP_NOTICE[k] ? { text: APP_NOTICE[k], error: /failed|expired/.test(k) } : null;
}

// ------------------------------------------------------------------------------------- DOM helpers
const SCRIPT_URL = /^\s*(javascript|vbscript):/i;
export function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(n.style, v);
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else if (k === 'html') n.innerHTML = v;
    else if ((k === 'href' || k === 'src' || k === 'action') && SCRIPT_URL.test(String(v).replace(/[\u0000-\u001f]/g, ''))) n.setAttribute(k, '#');
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat(Infinity)) if (k !== null && k !== undefined && k !== false) n.append(k.nodeType ? k : String(k));
  return n;
}

// Say something to screen reader users without moving focus.
let _live = null;
export function liveSay(text) {
  if (!_live) { _live = el('p', { class: 'sg-sr', 'aria-live': 'polite' }); document.body.append(_live); }
  _live.textContent = '';
  requestAnimationFrame(() => { _live.textContent = text; });
}

// text may be a string or a function returning the current text (read at click time).
export function copyButton(text, label = 'Copy', cls = 'sg-btn sg-btn--small') {
  const b = el('button', { class: cls, type: 'button' }, label);
  b.addEventListener('click', async () => {
    const t = typeof text === 'function' ? text() : text;
    try { await navigator.clipboard.writeText(t); b.textContent = 'Copied'; liveSay('Copied to the clipboard.'); }
    catch { b.textContent = 'Select and copy'; liveSay('Couldn’t copy. Select the text and copy it yourself.'); }
    setTimeout(() => (b.textContent = label), 1500);
  });
  return b;
}

export function statusBadge(status) {
  const s = STATUS[status] || STATUS.unknown;
  return el('span', { class: `sg-badge sg-badge--${s.tone}` }, s.label);
}

export function codeBlock(code, lang = '') {
  // tabindex lets keyboard users scroll long lines; translate=no keeps code out of page translation.
  return el('div', { class: 'sg-code' }, el('div', { class: 'sg-code__bar' }, el('span', {}, lang), copyButton(code)), el('pre', { tabindex: '0' }, el('code', { translate: 'no' }, code)));
}

const TIMING = { 'during-program': 'added during the program', 'after-program': 'added after the program', 'before-program': 'already had it' };

// --------------------------------------------------------------------------- remediation panel
// Full "how do I fix this" panel for one item. opts: {guide, report, ctx, onChange, compact}
export function renderRemediation(item, opts = {}) {
  const { report = null, guide = _guide, onChange = () => {} } = opts;
  const ctx = opts.ctx || ctxFromReport(report);
  const st = itemStatus(item, report, ctx.full);
  const root = el('article', { class: 'sg-remedy', 'data-item': item.id });
  const tier = guide && guide.tiersById ? guide.tiersById[item.tier] : null;

  root.append(el('header', { class: 'sg-remedy__head' },
    el('div', { class: 'sg-remedy__title' }, el('h3', {}, item.title), statusBadge(st.status)),
    el('div', { class: 'sg-chips' },
      tier ? el('span', { class: 'sg-chip', title: tier.blurb }, `From tier ${tier.id}: ${tier.name}`) : null,
      el('span', { class: 'sg-chip' }, `Effort: ${EFFORT_LABEL[item.effort]}`),
      el('span', { class: 'sg-chip' }, `Impact: ${IMPACT_LABEL[item.impact]}`),
      el('span', { class: 'sg-chip' }, `Checked by: ${LAYER_LABEL[item.layer]}`))));

  if (st.summary) root.append(el('p', { class: `sg-remedy__status sg-tone--${STATUS[st.status].tone}` }, st.summary,
    ...(st.evidence || []).map((e) => [' ', el('a', { href: e.url, target: '_blank', rel: 'noopener' }, e.label)])));
  if (item.why) root.append(el('p', { class: 'sg-remedy__why' }, item.why));

  const finds = findingsFor(item, report);
  if (finds.length) {
    root.append(el('section', { class: 'sg-remedy__findings' }, el('h4', {}, `What the scan found (${finds.length})`),
      el('ul', {}, finds.slice(0, 25).map((f) => el('li', { class: `sg-sev--${f.severity}` },
        el('span', { class: 'sg-sev' }, f.severity), ' ', f.url ? el('a', { href: f.url, target: '_blank', rel: 'noopener' }, f.title) : f.title,
        f.path ? el('code', { translate: 'no' }, ` ${f.path}${f.line ? ':' + f.line : ''}`) : null, f.hint ? el('div', { class: 'sg-hint' }, f.hint) : null)))));
  }

  const fixit = fixItForMe(item, { ctx, report });
  if (fixit) root.append(fixit);

  // actions
  const actions = el('div', { class: 'sg-actions' });
  for (const l of settingsLinks(item, ctx)) actions.append(el('a', { class: 'sg-btn', href: l.url, target: '_blank', rel: 'noopener' }, `${l.label} ↗`));
  const nf = newFileUrl(item, ctx);
  if (nf) actions.append(el('a', { class: 'sg-btn sg-btn--primary', href: nf, target: '_blank', rel: 'noopener', title: 'Opens GitHub with the file prefilled. Review it, then commit to a branch and open a PR.' }, `Create ${item.new_file.path} on GitHub ↗`));
  if (ctx.owner) actions.append(el('a', { class: 'sg-btn', href: issueForItem(item, ctx, report), target: '_blank', rel: 'noopener' }, 'Open a tracking issue ↗'));
  const manualToggle = el('label', { class: 'sg-check' }, el('input', { type: 'checkbox', checked: st.self.done ? true : null,
    onchange: (e) => { store.set(ctx.full, item.id, { done: e.target.checked }); onChange(item); } }), ' Mark done');
  actions.append(manualToggle);
  root.append(actions);
  const prompt = promptBlock(item, { report, ctx });
  if (prompt) root.append(prompt);

  const cli = cliFor(item, ctx);
  if (cli) root.append(el('section', {}, el('h4', {}, 'Or with the GitHub CLI'), codeBlock(cli, 'sh')));
  if ((item.steps || []).length) root.append(el('section', {}, el('h4', {}, 'Steps'), el('ol', { class: 'sg-steps' }, item.steps.map((s) => el('li', {}, s)))));
  for (const sn of item.snippets || []) root.append(el('section', {}, el('h4', {}, sn.label || 'Example'), codeBlock(fill(sn.code, ctx), sn.lang)));
  if (nf) root.append(el('details', {}, el('summary', {}, `Preview ${item.new_file.path}`), codeBlock(fill(item.new_file.template, ctx), item.new_file.path)));
  if ((item.pitfalls || []).length) root.append(el('section', {}, el('h4', {}, 'Watch out'), el('ul', {}, item.pitfalls.map((p) => el('li', {}, p)))));

  // evidence from the fund's projects (never claim "0 have this" for things no scanner can see)
  const statsLine = evidenceSummary(item);
  if (statsLine) root.append(el('p', { class: 'sg-remedy__stats' }, statsLine));
  if ((item.from_teams || []).length) {
    root.append(el('section', { class: 'sg-remedy__teams' }, el('h4', {}, 'How other projects did it'),
      el('ul', {}, item.from_teams.map((t) => el('li', {},
        el('strong', {}, t.team), ' ', el('span', { class: `sg-chip sg-chip--${t.status}` }, t.status.replace('-', ' ')), ' ', t.detail,
        t.quote ? el('blockquote', { class: 'sg-quote' }, `“${t.quote}”`) : null,
        t.source_url ? el('a', { href: t.source_url, target: '_blank', rel: 'noopener', class: 'sg-src' }, t.source_title || 'source') : null)))));
  }
  if ((item.repo_examples || []).length) {
    root.append(el('section', {}, el('h4', {}, 'See it in their repos'),
      el('ul', { class: 'sg-examples' }, item.repo_examples.map((r) => el('li', {},
        el('a', { href: r.url, target: '_blank', rel: 'noopener' }, `${r.team}: ${r.label}`),
        r.timing ? el('span', { class: 'sg-muted' }, ` (${TIMING[r.timing] || r.timing}${r.date ? ', ' + r.date : ''})`) : null,
        r.added_commit ? [' ', el('a', { href: r.added_commit, target: '_blank', rel: 'noopener', class: 'sg-src' }, 'commit')] : null)))));
  }
  if ((item.fix_commits || []).length) {
    root.append(el('section', {}, el('h4', {}, 'Commits where teams fixed it'),
      el('ul', { class: 'sg-examples' }, item.fix_commits.map((c) => el('li', {},
        el('span', { class: 'sg-muted' }, `${c.date} `), el('strong', {}, c.team), ': ', el('a', { href: c.url, target: '_blank', rel: 'noopener' }, c.msg))))));
  }
  if ((item.docs || []).length) root.append(el('section', {}, el('h4', {}, 'Read more'), el('ul', {}, item.docs.map((d) => el('li', {}, el('a', { href: d.url, target: '_blank', rel: 'noopener' }, d.label))))));
  return root;
}

// One honest sentence about how the fund's projects handle this item.
export function evidenceSummary(item) {
  const s = item.stats || {};
  const wrote = s.teams_did ? `${s.teams_did} fund team${s.teams_did === 1 ? '' : 's'} wrote about doing this` : '';
  if (s.repo_risk && !s.repo_present) {
    return `The scan flagged this risk in ${s.repo_risk} of ${s.repo_total} fund projects' repos` + (wrote ? `; ${wrote}` : '') + '.';
  }
  if (!item.peer_adoption) return wrote ? `${wrote}. No scanner can see this from outside a repo.` : '';
  return `${s.repo_present ?? 0} of ${s.repo_total ?? 0} fund projects have this in their repo` +
    (s.repo_added_in_window ? `, ${s.repo_added_in_window} added it during the program` : '') + (wrote ? `; ${wrote}` : '') + '.';
}


// ------------------------------------------------------------------------------- confirm dialog
// A modal that says exactly what will happen before anything changes on GitHub. Resolves true or false.
export function confirmDialog({ title, body, confirm = 'Confirm', cancel = 'Cancel', wide = false }) {
  return new Promise((resolve) => {
    const id = `sg-dlg-${Math.random().toString(36).slice(2, 9)}`;
    const back = document.activeElement;
    const ok = el('button', { type: 'button', class: 'sg-btn sg-btn--primary' }, confirm);
    const no = el('button', { type: 'button', class: 'sg-btn' }, cancel);
    const d = el('dialog', { class: `sg-dialog${wide ? ' sg-dialog--wide' : ''}`, 'aria-labelledby': id },
      el('h2', { class: 'sg-dialog__title', id }, title),
      el('div', { class: 'sg-dialog__body' }, body),
      el('div', { class: 'sg-dialog__actions' }, no, ok));
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      if (d.open) d.close();
      d.remove();
      if (back && document.contains(back)) back.focus();
      resolve(v);
    };
    ok.addEventListener('click', () => finish(true));
    no.addEventListener('click', () => finish(false));
    d.addEventListener('cancel', (e) => { e.preventDefault(); finish(false); });
    document.body.append(d);
    d.showModal();
    ok.focus();
  });
}

// ------------------------------------------------------------------------- fix it for me (app)
// One-click fixes through the GitHub App for the repo on screen: a setting changed now, or a pull request opened after a
// preview. Says what's missing when it can't (sign-in, an admin, the app installed, a permission). Empty when the app
// can't fix this check at all. cls lets a page pass its own button classes.
export function fixItForMe(item, { ctx, report, cls = {} } = {}) {
  const B = { btn: cls.btn || 'sg-btn', primary: cls.primary || 'sg-btn sg-btn--primary' };
  const wrap = el('section', { class: 'sg-fixit', hidden: true, 'aria-label': `Fix it for me: ${item.title}` });
  if (!ctx || !ctx.owner) return wrap;
  const status = report ? itemStatus(item, report, ctx.full).status : null;
  if (status === 'pass' || status === 'na') return wrap;
  const note = el('p', { class: 'sg-fixit__note', role: 'status' });
  const show = (...kids) => { wrap.replaceChildren(el('h4', { class: 'sg-fixit__title' }, 'Fix it for me'), ...kids); wrap.hidden = false; };
  const link = (href, text, c = B.btn) => el('a', { class: c, href, target: '_blank', rel: 'noopener' }, text, el('span', { class: 'sg-sr' }, ' (opens in a new tab)'));
  // Returns false while it still needs to know what the app can do on this repo.
  const draw = (st, info) => {
    const pr = (st.pr_fixes || {})[item.id];
    const settings = (item.app_fix || []).filter((id) => (st.fixes || {})[id]);
    if (!st.configured || (!pr && !settings.length) || (pr && !settings.length && pr.public_only && report && report.meta && report.meta.private)) {
      wrap.hidden = true;
      return true;
    }
    const what = pr && settings.length ? 'change the setting or open a pull request' : pr ? 'open a pull request with the fix' : 'change the setting';
    if (!st.user) {
      show(el('p', {}, `The GitHub App can ${what} for you. You need to be an admin of ${ctx.full}.`),
        el('a', { class: B.primary, href: app.loginUrl() }, 'Sign in with GitHub'));
      return true;
    }
    if (!info) { show(el('p', { class: 'sg-fixit__note' }, `Checking what the GitHub App can do on ${ctx.full}…`)); return false; }
    if (info.error) { show(el('p', {}, `Couldn’t check the app on ${ctx.full}: ${info.error}`)); return true; }
    if (!info.admin) { show(el('p', {}, `Only an admin of ${ctx.full} can use these. You’re signed in as @${st.user}.`)); return true; }
    if (!info.installed) {
      show(el('p', {}, `The GitHub App can ${what} for you once it’s installed on ${ctx.full}.`),
        link(info.install_url, `Install the app on ${ctx.full}`, B.primary), el('p', { class: 'sg-fixit__note' }, 'Then reload this page.'));
      return true;
    }
    const buttons = el('div', { class: 'sg-fixit__buttons' });
    for (const id of settings) buttons.append(settingButton(item, id, st.fixes[id], info, ctx, B, note));
    if (pr && !(pr.public_only && report && report.meta && report.meta.private)) buttons.append(prButton(item, pr, st, info, ctx, B, note, link));
    const how = !pr || settings.length ? 'The app makes the change after you confirm.'
      : pr.kind === 'agent' ? 'An AI model drafts the change, this site checks it, and you see it before any pull request opens. It takes about a minute. Nothing is merged.'
        : 'The app builds the change on a new branch and shows it to you before it opens the pull request. Nothing is merged.';
    show(el('p', {}, how), buttons, note);
    return true;
  };
  const known = app._statusValue;
  if (known && draw(known, known.user ? app._repoValues.get(ctx.full.toLowerCase()) : null)) return wrap;
  app.status().then(async (st) => { if (!draw(st, null)) draw(st, await app.repo(ctx.full)); });
  return wrap;
}

function busy(b, text) { b.dataset.label = b.dataset.label || b.textContent; b.textContent = text; b.setAttribute('aria-disabled', 'true'); }
function unbusy(b) { b.textContent = b.dataset.label || b.textContent; b.removeAttribute('aria-disabled'); }
const isBusy = (b) => b.getAttribute('aria-disabled') === 'true';

function settingButton(item, id, f, info, ctx, B, note) {
  if (!info.can_settings) return el('p', { class: 'sg-fixit__note' }, `The app on ${ctx.full} can’t change settings: it doesn’t have the Administration permission there.`);
  const b = el('button', { type: 'button', class: B.primary }, f.label);
  b.addEventListener('click', async () => {
    if (isBusy(b)) return;
    const ok = await confirmDialog({
      title: `${f.label}?`,
      body: [el('p', {}, `This changes a setting on ${ctx.full} right away. You can change it back in the repository’s settings.`), f.note ? el('p', {}, f.note) : null],
      confirm: 'Make the change',
    });
    if (!ok) return;
    busy(b, 'Working…');
    try {
      const r = await app.fix(ctx.full, id);
      if (!r.ok) throw new Error(r.message);
      const done = el('p', { class: 'sg-fixit__done', tabindex: '-1' }, `Done: ${f.label.charAt(0).toLowerCase()}${f.label.slice(1)}.`);
      b.replaceWith(done);
      done.focus();
      note.textContent = 'Checking the repository again so the result here is current…';
      liveSay(`Done: ${f.label}.`);
      try {
        const rep = await app.check(ctx.full);
        note.textContent = '';
        // item: so the page can bring this check back into view after it redraws.
        document.dispatchEvent(new CustomEvent('sg:report', { detail: { report: rep, item: item.id } }));
      } catch { note.textContent = 'The change is made. Check the settings again to update the result here.'; }
    } catch (err) {
      unbusy(b);
      note.textContent = `That didn’t work: ${err.message}`;
    }
  });
  return b;
}

function prButton(item, pr, st, info, ctx, B, note, link) {
  const open = store.get(ctx.full, item.id).pr;
  const opened = (p, already) => el('p', { class: 'sg-fixit__done' }, already ? 'A pull request for this is already open: ' : 'Pull request opened: ',
    link(p.url, `#${p.number}`, 'sg-fixit__pr'), '. Review it and merge it on GitHub, then rescan.');
  if (open && open.url) return opened(open, true);
  if (!info.can_pr || (pr.workflow && !info.can_pr_workflows)) {
    const need = pr.workflow ? 'contents, pull requests and workflows' : 'contents and pull requests';
    const own = st.owner && st.user && st.owner.toLowerCase() === st.user.toLowerCase() && st.slug;
    return el('p', { class: 'sg-fixit__note' }, `The app on ${ctx.full} can’t open this pull request yet: it needs write access to ${need}. `,
      own ? [link(`https://github.com/settings/apps/${st.slug}/permissions`, 'Add the permissions'), ', then accept them on ', link(info.manage_url || `https://github.com/settings/installations`, 'the installation'), '.']
        : 'The app’s owner can add them.');
  }
  const b = el('button', { type: 'button', class: B.primary }, pr.label);
  b.addEventListener('click', async () => {
    if (isBusy(b)) return;
    busy(b, pr.kind === 'agent' ? 'The agent is working…' : 'Preparing the pull request…');
    note.textContent = '';
    let view;
    // An AI fix runs while this request waits, usually a minute or so: show that time is passing.
    const started = Date.now();
    const tick = pr.kind === 'agent' ? setInterval(() => {
      note.textContent = `The agent is reading the workflow and drafting the change (${Math.round((Date.now() - started) / 1000)} s). This site checks it before you see it.`;
    }, 1000) : null;
    try {
      view = await app.prPreview(ctx.full, item.id);
      note.textContent = '';
    } catch (err) { unbusy(b); note.textContent = `Couldn’t prepare it: ${err.message}`; return; }
    finally { if (tick) clearInterval(tick); }
    unbusy(b);
    if (view.existing) { store.set(ctx.full, item.id, { pr: view.existing }); settle(b, opened(view.existing, true)); return; }
    const ok = await confirmDialog({ title: `Open this pull request on ${view.repo}?`, body: prPreviewBody(view), confirm: 'Open the pull request', wide: true });
    if (!ok) return;
    busy(b, 'Opening the pull request…');
    try {
      const r = await app.prCreate(view.plan);
      store.set(ctx.full, item.id, { pr: { url: r.url, number: r.number } });
      settle(b, opened(r, false));
      liveSay(`Pull request ${r.number} opened.`);
    } catch (err) { unbusy(b); note.textContent = `The pull request wasn’t opened: ${err.message}`; }
  });
  return b;
}

// Swap a button for its result and keep keyboard focus there, on the link to the pull request.
function settle(button, result) {
  button.replaceWith(result);
  const a = result.querySelector('a');
  if (a) a.focus();
}

function diffEl(text) {
  return el('pre', { class: 'sg-diff', tabindex: '0' }, el('code', { translate: 'no' }, text.split('\n').map((line) =>
    el('span', { class: /^\+(?!\+\+)/.test(line) ? 'sg-diff__add' : /^-(?!--)/.test(line) ? 'sg-diff__del' : null }, `${line}\n`))));
}

function prPreviewBody(view) {
  const n = view.files.length;
  const u = view.usage;
  return [
    el('p', {}, el('strong', {}, view.title)),
    view.kind === 'agent' ? el('p', { class: 'sg-dialog__ai' }, `Written by an AI model (${u && u.model ? u.model : 'unknown'}). This site checked it: the YAML is valid, the problem is gone, and nothing new is downloaded, run or granted. Those checks don’t catch every wrong guess, so read every line.`,
      u && u.usd > 0 ? ` It cost about $${u.usd < 0.01 ? u.usd.toFixed(4) : u.usd.toFixed(2)} in AI usage.` : '') : null,
    el('p', {}, `It goes on a new branch, `, el('code', { translate: 'no' }, view.head), `, and changes ${n === 1 ? 'one file' : `${n} files`}. Nothing changes on `,
      el('code', { translate: 'no' }, view.base), ' until someone merges it.'),
    view.notes.length ? el('ul', { class: 'sg-dialog__notes' }, view.notes.map((x) => el('li', {}, x))) : null,
    view.files.map((f, i) => el('details', { class: 'sg-dialog__file', open: i === 0 ? true : null },
      el('summary', {}, `${f.change === 'add' ? 'New file' : 'Changes in'} `, el('code', { translate: 'no' }, f.path)),
      f.change === 'add' ? el('pre', { tabindex: '0' }, el('code', { translate: 'no' }, f.content)) : diffEl(f.diff))),
    el('details', { class: 'sg-dialog__file' }, el('summary', {}, 'The pull request’s description'), el('pre', { class: 'sg-wrap', tabindex: '0' }, el('code', {}, view.body))),
  ];
}

// --------------------------------------------------------------------------------- AI prompt block
// "Hand it to an AI agent": copy the prompt, or read it first. Null for checks an agent can't help with.
export function promptBlock(item, { report = null, ctx = ctxFromReport(report), cls = 'sg-btn', heading = 'h4' } = {}) {
  if (!promptKind(item)) return null;
  const now = report ? itemStatus(item, report, ctx.full).status : null;
  if (now === 'pass' || now === 'na') return null;
  const text = () => agentPrompt(item, { report, ctx });
  const code = el('code', { translate: 'no' });
  const see = el('details', { class: 'sg-prompt__see' }, el('summary', {}, 'Read the prompt first'), el('pre', { class: 'sg-wrap', tabindex: '0' }, code));
  see.addEventListener('toggle', () => { if (see.open) code.textContent = text(); });
  return el('section', { class: 'sg-prompt', 'aria-label': `AI agent prompt: ${item.title}` },
    el(heading, { class: 'sg-prompt__title' }, 'Hand it to an AI agent'),
    el('p', { class: 'sg-prompt__about' }, 'Paste this into an AI coding agent working in your repository, such as Claude Code, Codex, Copilot or Cursor. It explains the problem, what the scan found and how other projects fixed it. Review the change before you merge it.'),
    copyButton(text, 'Copy the prompt', cls), see);
}

// ------------------------------------------------------------------------------------ scan panel
// Repo input + the three scan layers. opts: {onReport(mergedReport), initialRepo, compact}
export function renderScanPanel(opts = {}) {
  const { onReport = () => {}, compact = false, autoScan = false } = opts;
  let repo = opts.initialRepo ?? initialRepo();
  const reports = new Map(recallReports(repo).map((r) => [r.layer, r]));
  const root = el('section', { class: `sg-scan${compact ? ' sg-scan--compact' : ''}`, 'aria-busy': 'false' });
  const input = el('input', { class: 'sg-input', type: 'text', name: 'repo', inputmode: 'url', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', translate: 'no',
    placeholder: 'owner/repo or a GitHub URL…', value: repo, 'aria-label': 'Repository' });
  const msg = el('div', { class: 'sg-scan__msg', role: 'status' });
  const say = (text) => { msg.classList.remove('is-error'); msg.replaceChildren(text); };
  // An error says what went wrong and what to do next.
  const sayError = (title, next) => { msg.classList.add('is-error'); msg.replaceChildren(...[el('p', { class: 'sg-err__title' }, title), next ? el('p', { class: 'sg-err__next' }, next) : null].filter(Boolean)); };
  const scanBtn = el('button', { class: 'sg-btn sg-btn--primary', type: 'submit' }, 'Scan');
  const rescanBtn = el('button', { class: 'sg-btn', type: 'submit', 'data-refresh': '1', title: 'Ignore the 6-hour cache' }, 'Rescan');
  // aria-disabled rather than disabled: a disabled button drops keyboard focus to the page body.
  let busy = false;
  const setBusy = (b) => {
    busy = b;
    root.setAttribute('aria-busy', String(b));
    for (const btn of [scanBtn, rescanBtn]) btn.setAttribute('aria-disabled', String(b));
    scanBtn.textContent = b ? 'Scanning…' : 'Scan';
  };
  const emit = () => onReport(mergeReports([...reports.values()]), repo);
  // Results for one repo never mix with another's: switching repos starts from what this tab already has for the new one.
  const switchTo = (r) => {
    if (r.toLowerCase() !== (repo || '').toLowerCase()) { reports.clear(); for (const x of recallReports(r)) reports.set(x.layer, x); }
    repo = r; input.value = r; safeSet(localStorage, 'sg:lastRepo', r);
  };
  const form = el('form', { class: 'sg-scan__form', onsubmit: async (e) => {
    e.preventDefault();
    if (busy) return;
    const r = parseRepoInput(input.value);
    if (!r) { sayError('Enter a repository as owner/repo, or paste its GitHub URL.'); input.focus(); return; }
    setBusy(true);
    say(`Scanning ${r}. This takes about 5 to 30 seconds.`);
    try {
      const rep = await scanPublic(r, { refresh: !!(e.submitter && e.submitter.dataset.refresh === '1') });
      switchTo(rep.repo);
      reports.set('public', rep);
      say(`Scanned ${rep.repo}.${rep.cached ? ' This public scan is from the last 6 hours; press Rescan for a fresh one.' : ''}`);
      updateCmd(); emit();
    } catch (err) {
      // Don't leave another repo's results on screen under the name that failed.
      if (r.toLowerCase() !== (repo || '').toLowerCase()) { reports.clear(); repo = r; updateCmd(); emit(); }
      sayError(...scanTrouble(r, err));
      input.focus();
    } finally { setBusy(false); }
  } }, input, scanBtn, rescanBtn);

  const cmd = el('code', { translate: 'no' });
  const updateCmd = () => { cmd.textContent = `node sosf-scan.mjs ${repo || 'OWNER/REPO'}`; };
  updateCmd();
  const file = el('input', { type: 'file', accept: 'application/json,.json', class: 'sg-file', onchange: async (e) => {
    const f = e.target.files[0]; if (!f) return;
    e.target.value = '';
    try {
      const rep = await readReportFile(f);
      switchTo(rep.repo);
      reports.set(rep.layer, rep);
      say(`Loaded the ${(LAYER_LABEL[rep.layer] || rep.layer).toLowerCase()} report for ${rep.repo}. It was read in your browser and not uploaded.`);
      updateCmd(); emit();
    } catch (err) { sayError('Couldn’t load that report.', `${err.message}. Load the JSON file that sosf-scan.mjs wrote, named like sosf-report-owner-repo.json.`); }
  } });

  // A hidden stand-in the size of the usual final box, so the layers don't grow when the answer arrives.
  const appBox = el('div', { class: 'sg-layer__body' }, el('p', { class: 'sg-sr' }, 'Checking the app…'),
    el('p', { class: 'sg-placeholder', 'aria-hidden': 'true' }, 'Install the app on your repo and sign in. It checks the admin-only settings and can fix them in one click, or open a pull request with the fix.'),
    el('span', { class: 'sg-btn sg-placeholder', 'aria-hidden': 'true' }, 'Install the app ↗'), el('span', { class: 'sg-btn sg-placeholder', 'aria-hidden': 'true' }, 'Sign in with GitHub'));
  app.status().then((st) => {
    appBox.replaceChildren();
    if (!st.configured) { appBox.append(el('p', {}, 'Sign in with GitHub isn’t available on this copy of the site.')); return; }
    appBox.append(el('p', {}, 'Install the app on your repo and sign in. It checks the admin-only settings and can fix them in one click, or open a pull request with the fix.'),
      el('a', { class: 'sg-btn', href: st.install_url, target: '_blank', rel: 'noopener' }, 'Install the app ↗'));
    if (!st.user) { appBox.append(el('a', { class: 'sg-btn', href: app.loginUrl() }, 'Sign in with GitHub')); return; }
    const b = el('button', { class: 'sg-btn sg-btn--primary', type: 'button' }, `Check settings as @${st.user}`);
    b.addEventListener('click', async () => {
      if (b.getAttribute('aria-disabled') === 'true') return;
      const r = parseRepoInput(input.value);
      if (!r) { sayError('Enter a repository first.'); input.focus(); return; }
      b.setAttribute('aria-disabled', 'true');
      say(`Checking ${r} through the GitHub App.`);
      try {
        const rep = await app.check(r);
        switchTo(rep.repo);
        reports.set('app', rep);
        say(`Checked ${rep.repo} through the GitHub App.`);
        updateCmd(); emit();
      } catch (err) {
        sayError('The GitHub App check didn’t finish.', `${err.message}. Check that the app is installed on this repository and that you’re signed in as one of its admins.`);
      } finally { b.removeAttribute('aria-disabled'); }
    });
    appBox.append(b, el('a', { href: '/app/logout', class: 'sg-muted' }, 'Sign out'));
  });

  // A report produced elsewhere on the page (for example the app's re-check after a one-click fix) joins this panel's set.
  document.addEventListener('sg:report', (e) => {
    const rep = e.detail && e.detail.report ? e.detail.report : e.detail;
    if (!rep || !rep.repo || !rep.layer) return;
    switchTo(rep.repo);
    reports.set(rep.layer, rep);
    updateCmd(); emit();
  });

  root.append(form, msg, el('div', { class: 'sg-layers' },
    el('div', { class: 'sg-layer' }, el('h3', {}, '1 · Public scan'), el('div', { class: 'sg-layer__body' },
      el('p', {}, 'Reads your files, workflows and public settings, the same things anyone can see. Use the box above.'))),
    el('div', { class: 'sg-layer' }, el('h3', {}, '2 · Private scan'), el('div', { class: 'sg-layer__body' },
      el('p', {}, 'Run it on your machine with your own token to check admin-only settings. It’s read-only and needs only Node.js 20 or newer; its report stays in your browser.'),
      el('a', { class: 'sg-btn', href: '/download/sosf-scan.mjs', download: 'sosf-scan.mjs' }, 'Download sosf-scan.mjs'),
      el('div', { class: 'sg-cmd' }, cmd, copyButton(() => cmd.textContent)),
      el('label', { class: 'sg-btn' }, 'Load the report', file))),
    el('div', { class: 'sg-layer' }, el('h3', {}, '3 · GitHub App'), appBox)));
  const notice = takeAppNotice();
  if (notice) (notice.error ? sayError(notice.text) : say(notice.text));
  if (reports.size) queueMicrotask(emit);
  // A shared link (?repo=owner/name) with no scan of that repo in this browser scans straight away.
  if (autoScan && !reports.has('public') && parseRepoInput(new URLSearchParams(location.search).get('repo') || '')) {
    queueMicrotask(() => form.requestSubmit());
  }
  return root;
}

// ------------------------------------------------------------------- convenience: boot a UI page
// Loads the guide, mounts the scan panel into `mountScan`, and calls render({guide, report, ctx}) on every change.
export async function boot({ mountScan, render, compactScan = false, autoScan = false }) {
  const guide = await loadGuide();
  let report = mergeReports(recallReports(initialRepo()));
  let repo = (report && report.repo) || initialRepo();
  const rerender = () => { app.prefetch(report && report.repo); render({ guide, report, ctx: ctxFromReport(report, repo), repo }); };
  if (mountScan) mountScan.replaceChildren(renderScanPanel({ compact: compactScan, autoScan, onReport: (rep, r) => { report = rep; repo = r || (rep && rep.repo); rerender(); } }));
  document.addEventListener('sg:progress', rerender);
  rerender();
  return { guide, get report() { return report; }, rerender };
}
