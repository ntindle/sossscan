// 09-pipeline, "Pipeline map": follow a change from a maintainer's keyboard to a user's machine, see after a
// scan which stages are exposed and what to fix first, and open the full fix for every check on the way.
import * as sg from '/shared/core.js';

const { el, NEEDS_WORK, byUrgency } = sg;
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const WIDE = matchMedia('(min-width: 1080px)');
// Held by reference: on narrow screens the panel moves into the selected stage's <li>, which drawLine() replaces.
const PANEL = $('#stage-panel');
const SLOT = $('#stage-slot');
const HEAD = $('#stage-head');
const LIST = $('#stage-list');
const READER = $('#reader');
const CALM = matchMedia('(prefers-reduced-motion: reduce)');

// The release line: six controls, in the order to add them, mapped onto checklist items.
const RELEASE_LINE = [
  { id: 'rel-trusted-publishing', name: 'Trusted publishing', what: 'CI proves who it is to the package registry with a short-lived OIDC token, so there is no long-lived publish token to steal.' },
  { id: 'rel-provenance', name: 'Provenance', what: 'A signed attestation records which repository, commit and workflow built each artifact.' },
  { id: 'rel-sbom', name: 'SBOM', what: 'A machine-readable list of everything inside the release, so users can check it against new advisories.' },
  { id: 'rel-signing', name: 'Signing', what: 'Users can verify that a file came from you and was not changed after you built it.' },
  { id: 'repo-tag-release-protection', name: 'Immutable releases', what: 'Once a release is published, nobody can move its tag or swap its files.' },
  { id: 'rel-gated-release', name: 'Gated environments', what: 'The publish job waits in a protected environment until a maintainer approves it.' },
];

const GLYPH = {
  check: '<svg viewBox="0 0 20 20"><path d="M5 10.4l3.3 3.3 6.9-6.9"/></svg>',
  bang: '<svg viewBox="0 0 20 20"><path d="M10 4.6v6.6"/><circle cx="10" cy="15" r="1.3"/></svg>',
  cross: '<svg viewBox="0 0 20 20"><path d="M6.2 6.2l7.6 7.6M13.8 6.2l-7.6 7.6"/></svg>',
  info: '<svg viewBox="0 0 20 20"><circle cx="10" cy="5.3" r="1.3"/><path d="M10 8.8v6.6"/></svg>',
  query: '<svg viewBox="0 0 20 20"><path d="M7.2 7.5a2.8 2.8 0 1 1 3.9 2.6c-.8.35-1.1.9-1.1 1.7v.3"/><circle cx="10" cy="15.2" r="1.2"/></svg>',
  dash: '<svg viewBox="0 0 20 20"><path d="M6 10h8"/></svg>',
};
const TERMINALS = {
  start: { name: 'Your keyboard', note: 'A change starts here',
    icon: '<svg viewBox="0 0 24 24"><rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M6.5 10h0M9.5 10h0M12.5 10h0M15.5 10h0M18 10h0M6.5 14h0M17.5 14h0M9.5 14h5"/></svg>' },
  users: { name: "Users' machines", note: 'Reports come back from here',
    icon: '<svg viewBox="0 0 24 24"><rect x="4.5" y="5" width="15" height="10.5" rx="1.5"/><path d="M2.5 19h19"/></svg>' },
};

const STATION_GLYPH = { fail: 'cross', warn: 'bang', pass: 'check', open: 'dash', todo: null };
const ITEM_TONE = { pass: 'pass', done: 'pass', warn: 'warn', fail: 'fail', info: 'info', unknown: 'open', manual: 'open', todo: 'todo', na: 'skip' };
const ITEM_GLYPH = { pass: 'check', done: 'check', warn: 'bang', fail: 'cross', info: 'info', unknown: 'query', manual: 'query', todo: null, na: 'dash' };
const BUCKET_ORDER = { fail: 0, warn: 1, info: 2, open: 3, todo: 3, done: 4, later: 5, skip: 6 };
// A check's worst finding (sg.SEV_RANK), in words.
const SEV_WORD = { 2: 'high', 1: 'medium' };
const GROUPS = [
  { id: 'work', title: 'Needs work', buckets: ['fail', 'warn'], open: true },
  { id: 'check', title: 'Still to check', buckets: ['info', 'open'], open: true,
    note: () => (deepScanned() ? 'The scans could not settle these. Check them yourself.' : ['The public scan could not settle these. ',
      el('button', { type: 'button', class: 'linkbtn', onclick: deepScan }, 'Run a deep scan'), ' or check them yourself.']) },
  { id: 'done', title: 'Done', buckets: ['done'], open: true },
  { id: 'later', title: 'Later, as you grow', buckets: ['later'], open: false },
  { id: 'skip', title: "Doesn't apply to this repo", buckets: ['skip'], open: false },
];
const LEGEND = [['fail', 'Missing'], ['warn', 'Partly done'], ['pass', 'All done'], ['open', 'No gaps found, more to check'], ['todo', 'Not scanned']];
const TICK_WORD = { fail: 'missing', warn: 'partly done', info: 'info', open: 'to check', todo: 'not scanned', done: 'done', later: 'for later' };
const WORDS = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten'];

const S = {
  guide: null, report: null, ctx: {}, repo: '', model: null,
  stage: null, item: null, key: null, first: true, pinned: false, collapsed: false,
  opener: null, readerSig: '', groupOpen: new Map(), threatsOpen: new Set(), switching: false, token: null, rerender: null,
  revealed: false, tokenWanted: false, keep: null,
};

const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const lc = (s) => (s ? s.charAt(0).toLowerCase() + s.slice(1) : '');
const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '');
const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
// Like replaceChildren, but skips empty slots (the DOM method would print "null").
const put = (node, ...kids) => node.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false));
const motion = () => (CALM.matches ? 'auto' : 'smooth');

function lamp(tone, size = 'sm', glyph = null) {
  const n = el('span', { class: `lamp lamp--${size} lamp--${tone}`, 'aria-hidden': 'true' });
  if (glyph && GLYPH[glyph]) n.innerHTML = GLYPH[glyph];
  return n;
}

// ------------------------------------------------------------------------------------------ boot
setupStatic();
sg.boot({ mountScan: $('#scan-mount'), render, autoScan: true })
  .then((b) => { S.rerender = b.rerender; })
  .catch((err) => {
    console.error(err);
    const where = $('#scan-mount .sg-scan') ? LIST : $('#scan-mount');
    where.replaceChildren(el('p', { class: 'load-error', role: 'alert' }, `The guide did not load (${err.message}). Reload the page to try again.`));
    reveal();
  });

function render({ guide, report, ctx, repo }) {
  const active = document.activeElement;
  const focusKey = active && active !== document.body ? active.dataset.fk : null;
  Object.assign(S, { guide, report, ctx: ctx || {}, repo: repo || '' });
  const key = report ? [report.repo, report.scanned_at, (report.layers || [report.layer]).join('+')].join('|') : '';
  const fresh = key !== S.key;
  const first = S.first;
  S.key = key;
  S.model = buildModel();

  if (first) {
    firstRun();
    const h = readHash();
    if (h.hop && S.model.byId[h.hop]) { S.stage = h.hop; S.pinned = true; }
    const linked = h.fix && guide.itemsById[h.fix];
    if (linked && S.model.byId[linked.stage]) { S.stage = linked.stage; S.item = linked.id; S.pinned = true; }
  }
  // A new scan: open the stage with the most urgent problem and select that check (on phones the sheet stays
  // closed until asked), unless the page was opened on a specific stage or fix, or the scan is the app's check after a
  // one-click fix, which keeps that fix open (S.keep, from sg:report).
  const kept = S.keep && guide.itemsById[S.keep];
  S.keep = null;
  if (fresh && report && kept && S.model.byId[kept.stage]) {
    S.stage = kept.stage; S.item = kept.id; S.collapsed = false;
  } else if (fresh && report && !(first && S.pinned)) {
    const top = S.model.fixFirst;
    if (top) { S.stage = top.stage.id; S.item = WIDE.matches ? top.row.item.id : null; S.collapsed = false; }
  }
  if (!S.model.byId[S.stage]) S.stage = S.model.stages[0].id;
  if (S.item && (!guide.itemsById[S.item] || guide.itemsById[S.item].stage !== S.stage)) S.item = null;
  if (!S.item && WIDE.matches) S.item = firstItem(S.stage);

  drawFirst();
  drawReadout();
  drawLine();
  drawStage();
  drawReader();
  writeHash();
  restoreFocus(active, focusKey);

  // A scan of another repo failed: the panel has said why, and the old repo's results are gone, so is their summary.
  if (fresh && !report) $('#announce').textContent = '';
  if (fresh && report) {
    announce(resultSentence(report));
    queueToken();
    // On narrow screens, keep the result of a scan in view: the "fix this first" box under the scan form,
    // or the readout when there is nothing to fix.
    if (!first && !WIDE.matches) {
      const box = $('#first');
      const out = $('#readout');
      if (!box.hidden) {
        const r = box.getBoundingClientRect();
        if (r.top < 0 || r.bottom > innerHeight) box.scrollIntoView({ block: 'nearest', behavior: motion() });
      } else if (out.getBoundingClientRect().top > innerHeight * 0.45) {
        out.scrollIntoView({ block: 'start', behavior: motion() });
      }
    }
  }
  S.first = false;
  // The scan box started a scan of its own as the page loaded: a shared link (?repo=) with no scan in this browser,
  // or a deep scan it carries on with after GitHub sent the person back. Show what's below the scan box once, with
  // the result, instead of drawing an empty map and pushing it down when the result lands.
  if (first && !report && $('#scan-mount .sg-scan[aria-busy="true"]')) {
    S.holdForScan = true;
    setTimeout(() => { if (S.holdForScan) { S.holdForScan = false; reveal(); } }, 15000);
  } else if (first) reveal();
  else if (S.holdForScan && report) { S.holdForScan = false; reveal(); }
}

function firstRun() {
  // The private scan goes under the repo box, in "Scan privately", which stays closed until someone opens it.
  const priv = $('#scan-mount .sg-private');
  const box = $('#private');
  if (priv) box.append(priv); else box.hidden = true;
  watchBusy();
  const c = S.guide.counts || {};
  // Above the site's links, which index.html has in its footer from the start.
  $('#foot').prepend(
    el('p', {}, `Built from what ${c.teams} projects in GitHub's Secure Open Source Fund changed: ${c.posts} posts by the teams, ${c.claims} quoted statements, and the files and commits in their ${c.repos_scanned} repos.`));
}

// Everything below the scan box waits for the first render (index.html starts with .is-booting), so nothing is
// drawn in one place and then pushed down. Nothing in the scan box changes size when the GitHub App's status arrives
// a moment later: the sign-in line keeps its space (core.css) and "Scan privately" starts closed. So the first render
// reveals the page at once, unless a scan is on its way (above).
function reveal() {
  if (S.revealed) return;
  S.revealed = true;
  document.documentElement.classList.remove('is-booting');
  if (S.tokenWanted) { S.tokenWanted = false; queueToken(); }
}

// ---------------------------------------------------------------------------------------- model
function buildModel() {
  const { guide, report } = S;
  const tier = report ? report.tier || (report.meta ? sg.tierFor(report.meta.stars, report.meta.dependents_total, guide.tiers) : null) : null;
  const tierId = tier ? tier.id : null;
  const releaseAt = guide.stages.findIndex((s) => s.id === 'release');
  const stages = guide.stages.map((stage, index) => {
    const rows = guide.items.filter((i) => i.stage === stage.id).map((item) => sg.checkRow(item, report, S.ctx, tierId)).sort(byPriority);
    const c = { fail: 0, warn: 0, info: 0, open: 0, todo: 0, done: 0, later: 0, skip: 0 };
    for (const r of rows) c[r.bucket] += 1;
    const due = rows.length - c.later - c.skip;
    let tone = 'open';
    if (!report) tone = 'todo';
    else if (c.fail) tone = 'fail';
    else if (c.warn) tone = 'warn';
    else if (due > 0 && c.done === due) tone = 'pass';
    const needs = rows.filter((r) => NEEDS_WORK.has(r.bucket)); // already most urgent first
    const s = { ...stage, index, rows, c, due, tone, finds: rows.reduce((n, r) => n + r.finds.length, 0),
      phase: releaseAt >= 0 && index > releaseAt ? 'return' : 'out',
      worst: needs[0] || null, lost: needs.reduce((n, r) => n + r.lost, 0), cue: severityCue(rows) };
    s.text = stageText(s);
    return s;
  });
  // Stages with gaps, worst first: by their most urgent check, then by how much impact the stage loses in all.
  const ranked = stages.filter((s) => s.worst).sort((a, b) => byUrgency(a.worst, b.worst) || b.lost - a.lost || a.index - b.index);
  return { tier, tierId, stages, byId: Object.fromEntries(stages.map((s) => [s.id, s])), ranked,
    fixFirst: ranked.length ? { stage: ranked[0], row: ranked[0].worst } : null,
    // What "Prompt to fix" offers; null hides the button.
    choices: report ? sg.promptChoices(stages.flatMap((s) => s.rows)) : null };
}

// Rows come from sg.checkRow: what needs work, most urgent first (sg.byUrgency); the rest by bucket, then in the order
// to add them (sg.byTier).
function byPriority(a, b) {
  if (NEEDS_WORK.has(a.bucket) && NEEDS_WORK.has(b.bucket)) return byUrgency(a, b);
  return BUCKET_ORDER[a.bucket] - BUCKET_ORDER[b.bucket] || sg.byTier(a, b);
}

// The worst finding severity at a stage and how many findings have it: {word: 'high', n: 1}, or null.
function severityCue(rows) {
  for (const word of ['high', 'medium']) {
    const n = rows.reduce((k, r) => k + r.finds.filter((f) => f.severity === word).length, 0);
    if (n) return { word, n };
  }
  return null;
}

function stageText(s) {
  const c = s.c;
  if (!S.report) return plural(s.rows.length, 'check');
  const bad = [c.fail ? `${c.fail} missing` : '', c.warn ? `${c.warn} partly done` : ''].filter(Boolean);
  if (bad.length) return bad.join(', ');
  if (s.tone === 'pass') return c.done === 1 ? 'Done' : `All ${c.done} done`;
  const toCheck = c.open + c.info;
  if (c.done && toCheck) return `${c.done} done, ${toCheck} to check`;
  if (toCheck) return `${toCheck} to check`;
  return 'Nothing due yet';
}

function stateSentence(s) {
  if (!S.report) return `${cap(plural(s.rows.length, 'check'))} at this stage. Scan a repo to see which ones it has.`;
  const c = s.c;
  return [
    c.fail && `${c.fail} missing`, c.warn && `${c.warn} partly done`, c.done && `${c.done} done`,
    (c.open + c.info) && `${c.open + c.info} to check`, c.later && `${c.later} for later`, c.skip && `${c.skip} not applicable`,
  ].filter(Boolean).join(', ');
}

// The bars under a stage: one per check (not the ones that don't apply), grouped by state, with words for them.
function ticksFor(s) {
  const rows = s.rows.filter((r) => r.bucket !== 'skip').sort((a, b) => BUCKET_ORDER[a.bucket] - BUCKET_ORDER[b.bucket]);
  const n = {};
  for (const r of rows) n[r.bucket] = (n[r.bucket] || 0) + 1;
  const words = ['fail', 'warn', 'info', 'open', 'todo', 'done', 'later'].filter((b) => n[b]).map((b) => `${n[b]} ${TICK_WORD[b]}`);
  return { rows, text: `One bar per check: ${words.join(', ') || 'none due'}` };
}

const firstItem = (stageId) => S.model.byId[stageId]?.rows[0]?.item.id || null;
const isFixFirst = (id) => !!(S.model.fixFirst && S.model.fixFirst.row.item.id === id);

function starsTier() {
  const stars = S.report && S.report.meta ? S.report.meta.stars : null;
  if (stars == null) return null;
  let best = null;
  for (const t of S.guide.tiers) if (stars >= t.stars) best = t;
  return best;
}

function resultSentence(r) {
  const top = S.model.fixFirst;
  const n = S.model.ranked.length;
  return `Map updated for ${r.repo}: ${n ? `gaps at ${plural(n, 'stage')}` : 'the scan found no gaps'}.`
    + (top ? ` Fix this first: ${top.row.item.title}, at ${top.stage.label}.` : '');
}

// ------------------------------------------------------------------------------- fix this first
// The one check to open after a scan, right under the scan result: what it is, why it comes first, and a way in.
function drawFirst() {
  const box = $('#first');
  const top = S.report ? S.model.fixFirst : null;
  box.hidden = !top;
  if (!top) { box.replaceChildren(); return; }
  const { stage, row } = top;
  const tone = row.bucket === 'fail' ? 'fail' : 'warn';
  box.className = `first first--${tone}`;
  const where = ` in ${stage.label} (stage ${stage.index + 1} of ${S.model.stages.length}).`;
  put(box,
    lamp(tone, 'md', STATION_GLYPH[tone]),
    el('div', {},
      el('h3', { class: 'first__h' }, el('span', { class: 'first__tag' }, 'Fix this first'), el('span', { class: 'vh' }, ': '), row.item.title),
      el('p', { class: 'first__why' }, row.sev
        ? [el('strong', { class: `sev--${SEV_WORD[row.sev]}` }, `${cap(SEV_WORD[row.sev])}-severity finding`), where]
        : `${sg.STATUS[row.st.status].label}, with ${lc(sg.IMPACT_LABEL[row.item.impact])} impact,${where}`)),
    el('div', { class: 'first__acts' },
      el('button', { type: 'button', class: 'sg-btn sg-btn--primary first__go', 'data-fk': 'first', onclick: jumpToFirst }, 'Show the fix')));
}

// "Prompt to fix": one prompt for an AI coding agent, covering the checks someone picks in its dialog (most urgent first
// to start with). Hidden when nothing needs work an agent can do. It's made once and kept across redraws, so the dialog
// can always hand focus back to it, even when a scan lands while it's open.
let promptBtn = null;
function promptButton() {
  if (!S.model.choices) return null;
  promptBtn ||= el('button', {
    type: 'button', class: 'sg-btn sg-btn--primary readout__prompt', 'data-fk': 'prompt', 'aria-haspopup': 'dialog',
    title: 'One prompt for an AI coding agent such as Claude Code, Codex, Copilot or Cursor, covering the checks you pick',
    onclick: () => sg.promptDialog(S.model.choices, { report: S.report, ctx: S.ctx, guide: S.guide, tier: S.model.tier, site: location.origin, opener: promptBtn }),
  }, 'Prompt to fix');
  return promptBtn;
}

// "Show the fix": open that stage and check. Wide screens move focus into the reader; phones open the sheet,
// whose Close button then returns to the check in the map.
function jumpToFirst() {
  const top = S.model && S.model.fixFirst;
  if (!top) return;
  const id = top.row.item.id;
  selectStage(top.stage.id);
  openItem(id, LIST.querySelector(`[data-item="${CSS.escape(id)}"]`));
  if (WIDE.matches) focusReader(true);
}

function focusReader(scroll) {
  if (scroll) PANEL.scrollIntoView({ block: 'start', behavior: motion() });
  READER.focus({ preventScroll: true });
}

// -------------------------------------------------------------------------------------- readout
function drawReadout() {
  const box = $('#readout');
  const r = S.report;
  if (!r) {
    put(box, el('p', { class: 'readout__empty' }, lamp('todo', 'sm'), el('span', {}, S.repo
      ? ['No scan results for ', el('span', { translate: 'no' }, S.repo), '. Until there are, use the map as a guide: pick any stage below.']
      : 'No repo scanned yet. Scan one to see its security gaps, or use the map as a guide: pick any stage below.')));
    return;
  }
  const m = r.meta || {};
  const t = S.model.tier;
  const num = (v) => Number(v).toLocaleString(undefined);
  const when = r.scanned_at ? new Date(r.scanned_at) : null;
  const facts = [
    t ? ['Tier', `${t.id}: ${t.name}`] : null,
    m.stars != null ? ['Stars', num(m.stars)] : null,
    m.dependents_total != null ? ['Dependents', num(m.dependents_total)] : null,
    r.scorecard && r.scorecard.score != null ? ['OpenSSF Scorecard', `${r.scorecard.score} of 10`] : null,
    ['Scanned', [(r.layers || [r.layer]).map((l) => sg.LAYER_LABEL[l] || l).join(', '),
      when && !Number.isNaN(when.getTime()) ? when.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '']
      .filter(Boolean).join(', ')],
  ].filter(Boolean);
  const blurb = t && S.guide.tiersById[t.id] ? S.guide.tiersById[t.id].blurb : '';
  const errors = (r.errors || []).map((e) => (typeof e === 'string' ? e : e.message || e.detail || JSON.stringify(e)));
  put(box,
    el('a', { class: 'readout__repo', href: m.html_url || `https://github.com/${r.repo}`, target: '_blank', rel: 'noopener', translate: 'no' }, r.repo),
    el('dl', { class: 'readout__facts' }, facts.map(([k, v]) => el('div', {}, el('dt', {}, k), el('dd', {}, v)))),
    promptButton(),
    blurb ? el('p', { class: 'readout__note' }, `Tier ${t.id}, ${t.name}: ${blurb}`) : null,
    nextSize(t, m, num),
    S.model.ranked.length
      ? el('div', { class: 'readout__weak' }, el('span', { class: 'readout__label' }, 'Gaps by stage, worst first:'), S.model.ranked.map(gapChip))
      : el('p', { class: 'readout__clean' }, 'The scan found nothing missing. The grey stages still have checks it could not see.'),
    issueForGaps(),
    errors.length ? el('p', { class: 'readout__note' }, `The scan reported ${plural(errors.length, 'problem')}: ${errors.slice(0, 3).join('; ')}`) : null,
  );
}

// Grows with you: the next size up, what gets a project there, and how many checks it adds.
function nextSize(t, m, num) {
  const next = t ? S.guide.tiersById[t.id + 1] : null;
  if (!t) return null;
  if (!next) return el('p', { class: 'readout__grow' }, 'This is the top tier, so every check in the guide applies.');
  const adds = S.guide.items.filter((i) => i.tier === next.id && sg.applies(i, S.ctx)).length;
  return el('p', { class: 'readout__grow' }, el('b', {}, 'Next tier: '),
    `${next.name}, at ${num(next.stars)} stars or ${num(next.dependents)} dependents (you have ${num(m.stars || 0)} and ${num(m.dependents_total || 0)}). It adds ${plural(adds, 'check')}, shown under “Later, as you grow” in each stage.`);
}

// One prefilled GitHub issue that lists every check that needs work, as tasks. Nothing is filed until it's submitted.
function issueForGaps() {
  const rows = S.model.stages.flatMap((s) => s.rows.filter((r) => NEEDS_WORK.has(r.bucket)).map((r) => ({ r, s }))).sort((a, b) => byUrgency(a.r, b.r));
  if (!rows.length || !S.ctx.owner) return null;
  const body = [
    `The Secure Open Source guide found ${plural(rows.length, 'check')} that ${rows.length === 1 ? 'needs' : 'need'} work in ${S.report.repo}, most urgent first:`, '',
    ...rows.map(({ r, s }) => `- [ ] **${r.item.title}** (${s.label}; ${sg.STATUS[r.st.status].label.toLowerCase()}${r.finds.length ? `, ${plural(r.finds.length, 'finding')}` : ''})`),
    '', `Each fix, with how Secure Open Source Fund projects did it: ${location.origin}/?repo=${S.report.repo}`,
  ].join('\n');
  const url = sg.newIssueUrl(S.ctx, { title: `Security: ${plural(rows.length, 'fix', 'fixes')} from the Secure Open Source guide`, body });
  return url ? el('a', { class: 'readout__issue', href: url, target: '_blank', rel: 'noopener', 'data-fk': 'issue' },
    `Open one GitHub issue for all ${rows.length}`, el('span', { class: 'vh' }, ' (opens in a new tab)')) : null;
}

// A stage with gaps: its light, its name, how many checks need work, and its worst finding severity.
function gapChip(s) {
  return el('button', { type: 'button', class: 'hopchip', 'data-fk': `weak:${s.id}`, onclick: () => selectStage(s.id, { focus: true, scroll: true }) },
    lamp(s.tone, 'xs', STATION_GLYPH[s.tone]),
    el('span', {}, s.label),
    el('span', { class: 'vh' }, ', '),
    el('span', { class: 'hopchip__n' }, `${s.c.fail + s.c.warn} to fix`),
    s.cue ? [el('span', { class: 'vh' }, ', '), el('span', { class: `hopchip__sev sev--${s.cue.word}` }, `${s.cue.n} ${s.cue.word}`)] : null);
}

// ----------------------------------------------------------------------------------------- line
function drawLine() {
  stopToken();
  const parts = [terminal('start')];
  let placed = false;
  for (const s of S.model.stages) {
    parts.push(station(s));
    if (s.id === 'release') { parts.push(terminal('users')); placed = true; }
  }
  if (!placed) parts.push(terminal('users'));
  $('#line').replaceChildren(...parts);
  placePanel();
}

function terminal(kind) {
  const t = TERMINALS[kind];
  const icon = el('span', { class: 'term__icon', 'aria-hidden': 'true' });
  icon.innerHTML = t.icon;
  return el('li', { class: `term term--${kind}`, 'data-kind': kind }, icon, el('span', { class: 'term__name' }, t.name), el('span', { class: 'term__note' }, t.note));
}

function station(s) {
  const selected = s.id === S.stage;
  const expanded = selected && !(S.collapsed && !WIDE.matches);
  const ticks = ticksFor(s);
  const btn = el('button', {
    type: 'button', class: 'st__btn', id: `st-${s.id}`, 'data-fk': `st:${s.id}`, 'data-stage': s.id,
    'aria-expanded': expanded ? 'true' : 'false', 'aria-controls': 'stage-panel', 'aria-describedby': `ticks-${s.id}`,
    tabindex: selected ? '0' : '-1',
    onclick: () => selectStage(s.id, { toggle: true, focus: true, keep: true }),
  },
  lamp(s.tone, 'lg', STATION_GLYPH[s.tone]),
  el('span', { class: 'st__name' }, s.label),
  el('span', { class: `st__state tone--${s.tone}` }, s.text),
  // The bars are a picture of the checks; the button is described by their words (and they show on hover).
  el('span', { class: 'ticks', id: `ticks-${s.id}`, 'aria-hidden': 'true', title: ticks.text },
    ticks.rows.map((r) => el('i', { 'data-b': r.bucket })), el('span', { class: 'vh' }, `${ticks.text}.`)),
  s.finds ? el('span', { class: 'st__finds' }, plural(s.finds, 'finding'),
    s.cue ? [', ', el('strong', { class: `sev--${s.cue.word}` }, `${s.cue.n} ${s.cue.word}`)] : null) : null);
  return el('li', { class: `st st--${s.tone}${selected ? ' is-selected' : ''}${s.phase === 'return' ? ' is-return' : ''}`, 'data-stage': s.id, style: `--i:${s.index}` }, btn);
}

function placePanel() {
  if (WIDE.matches) {
    PANEL.hidden = false;
    if (PANEL.parentElement !== SLOT) SLOT.append(PANEL);
    return;
  }
  const li = $(`#line > li[data-stage="${S.stage}"]`);
  PANEL.hidden = S.collapsed;
  if (li && PANEL.parentElement !== li) li.append(PANEL);
  else if (!li && PANEL.parentElement !== SLOT) SLOT.append(PANEL);
}

// toggle: tapping the open stage closes it (narrow screens). keep: hold the tapped header where it was on screen.
// focus: move focus to the stage's button. scroll: bring that button into view first.
function selectStage(id, { toggle = false, focus = false, scroll = false, keep = false } = {}) {
  if (!S.model || !S.model.byId[id]) return;
  const narrow = !WIDE.matches;
  const was = keep && narrow ? $(`#st-${id}`)?.getBoundingClientRect().top : null;
  if (toggle && narrow && id === S.stage) S.collapsed = !S.collapsed;
  else {
    if (id !== S.stage) S.item = null;
    S.stage = id;
    S.collapsed = false;
  }
  if (!S.item && WIDE.matches) S.item = firstItem(id);
  drawLine();
  drawStage();
  drawReader();
  writeHash();
  const btn = $(`#st-${id}`);
  if (!btn) return;
  if (was != null) holdPlace(btn, was);
  else if (scroll) btn.scrollIntoView({ block: narrow ? 'start' : 'nearest', behavior: motion() });
  if (focus) btn.focus({ preventScroll: true });
}

// On narrow screens the stage panel lives inside the selected stage, so a panel that closes above the tapped
// stage pulls its header up the page. Scroll by the same amount, so the header stays under the finger.
function holdPlace(btn, was) {
  const moved = btn.getBoundingClientRect().top - was;
  if (Math.abs(moved) >= 1) scrollBy({ top: moved, behavior: 'instant' });
  const top = btn.getBoundingClientRect().top;
  if (top < 0 || top > innerHeight - 48) btn.scrollIntoView({ block: 'start', behavior: 'instant' });
}

// ---------------------------------------------------------------------------------------- stage
function drawStage() {
  const s = S.model.byId[S.stage];
  put(HEAD, stageHead(s));
  put(LIST, stageList(s));
  placeSkip();
}

function stageHead(s) {
  const threats = threatsFor(s);
  return [
    el('div', {},
      el('h2', { class: 'stage__title', id: 'stage-title' }, el('span', { class: 'hopnum', 'aria-hidden': 'true' }, String(s.index + 1)), el('span', {}, s.label)),
      el('p', { class: 'stage__blurb' }, `${s.blurb ? `${s.blurb}. ` : ''}Stage ${s.index + 1} of ${S.model.stages.length}${s.phase === 'return' ? ', after the change reaches users' : ''}.`)),
    el('p', { class: 'stage__state' }, lamp(s.tone, 'md', STATION_GLYPH[s.tone]), el('span', {}, stateSentence(s))),
    threats.length ? el('details', {
      class: 'stage__threats', open: S.threatsOpen.has(s.id) ? true : null,
      ontoggle: (e) => { if (e.currentTarget.open) S.threatsOpen.add(s.id); else S.threatsOpen.delete(s.id); },
    }, el('summary', {}, `What can go wrong at this stage (${threats.length})`),
    el('ul', {}, threats.map((a) => el('li', {}, el('strong', {}, a.title), `. ${a.story}`)))) : null,
  ];
}

function threatsFor(s) {
  const seen = new Map();
  for (const r of s.rows) for (const a of r.item.attacks || []) seen.set(a, (seen.get(a) || 0) + 1);
  return [...seen.entries()].sort((a, b) => b[1] - a[1]).map(([id]) => S.guide.attacksById[id]).filter(Boolean);
}

function stageList(s) {
  const out = [];
  let rows = s.rows;
  if (s.id === 'release') {
    const line = releaseLine(s);
    if (line) {
      out.push(line);
      const ids = new Set(RELEASE_LINE.map((x) => x.id));
      rows = rows.filter((r) => !ids.has(r.item.id));
      if (rows.length && S.report) out.push(el('h3', { class: 'list__h' }, 'Also at this stage'));
    }
  }
  if (!rows.length) return out;
  if (!S.report) {
    out.push(group({ id: 'all', title: s.id === 'release' ? 'Also at this stage' : 'Checks at this stage', open: true,
      note: 'In the order to add them: by the tier where each one starts, then by impact. Scan a repo to see which ones it already has.' }, rows, s.id));
    return out;
  }
  for (const g of GROUPS) {
    const these = rows.filter((r) => g.buckets.includes(r.bucket));
    if (!these.length) continue;
    let def = g;
    if (g.id === 'later') def = { ...g, note: `These start above tier ${S.model.tierId}, this repo's tier. Come back to them as it grows.` };
    else if (g.id === 'work' && these.length > 1) def = { ...g, note: 'Most urgent first: high and medium findings, then the checks with the most impact.' };
    out.push(group(def, these, s.id));
  }
  return out;
}

function group(def, rows, stageId) {
  const key = `${stageId}:${def.id}`;
  const open = S.groupOpen.has(key) ? S.groupOpen.get(key) : def.open;
  return el('details', { class: 'group', open: open ? true : null, ontoggle: (e) => S.groupOpen.set(key, e.currentTarget.open) },
    el('summary', {}, el('h3', { class: 'group__h' }, def.title, el('span', { class: 'group__count' }, String(rows.length)))),
    def.note ? el('p', { class: 'group__note' }, typeof def.note === 'function' ? def.note() : def.note) : null,
    el('ul', { class: 'rows' }, rows.map(rowEl)));
}

// The "Fix this first" label on the most urgent check, wherever it is listed.
const firstTag = (id, cls) => (isFixFirst(id) ? [el('span', { class: cls }, 'Fix this first'), el('span', { class: 'vh' }, ': ')] : null);

function rowEl(r) {
  const { item, st, finds, bucket } = r;
  const current = item.id === S.item;
  const showLayer = !S.report || st.status === 'unknown' || st.status === 'manual';
  const btn = el('button', {
    type: 'button', class: 'row__btn', 'data-item': item.id, 'data-fk': `row:${item.id}`,
    'aria-current': current ? 'true' : null, 'aria-haspopup': WIDE.matches ? null : 'dialog',
    onclick: (e) => openItem(item.id, e.currentTarget),
  },
  lamp(ITEM_TONE[st.status] || 'open', 'sm', ITEM_GLYPH[st.status]),
  el('span', { class: 'row__title' }, firstTag(item.id, 'tag-first'), item.title),
  statusLine(r, 'span', 'row__status'),
  el('span', { class: 'row__meta' },
    el('span', {}, `From tier ${item.tier}`),
    el('span', {}, `Effort: ${lc(sg.EFFORT_LABEL[item.effort])}`),
    el('span', {}, `Impact: ${lc(sg.IMPACT_LABEL[item.impact])}`),
    showLayer ? el('span', {}, `Checked by: ${sg.CHECKED_BY[item.layer] || item.layer}`) : null));
  const li = el('li', { class: `row row--${bucket}${current ? ' is-current' : ''}` }, btn);
  if (finds.length) li.append(findsPreview(finds));
  return li;
}

// Status label plus the scan's own words; before a scan, the item's one-line summary instead.
function statusLine(r, tag, cls) {
  const { item, st } = r;
  if (!S.report && st.status !== 'done') {
    const short = item.short && norm(item.short) !== norm(item.title) ? item.short : '';
    return short ? el(tag, { class: 'row__short' }, short) : null;
  }
  const label = sg.statusLabel(st);
  const detail = st.source === 'scan' && st.summary ? st.summary : '';
  return el(tag, { class: cls }, el('strong', { class: `tone--${ITEM_TONE[st.status] || 'open'}` }, label), detail ? `: ${detail}` : '');
}

function findsPreview(finds) {
  const top = [...finds].sort((a, b) => (sg.SEV_RANK[b.severity] || 0) - (sg.SEV_RANK[a.severity] || 0)).slice(0, 2);
  return el('ul', { class: 'row__finds', 'aria-label': `What the scan found (${finds.length})` },
    top.map((f) => el('li', {},
      el('span', { class: `sev sev--${f.severity}` }, cap(f.severity)), ' ',
      f.url ? el('a', { href: f.url, target: '_blank', rel: 'noopener' }, f.title) : f.title,
      f.path ? [' ', el('code', { translate: 'no' }, `${f.path}${f.line ? `:${f.line}` : ''}`)] : null)),
    finds.length > top.length ? el('li', { class: 'row__more' }, `${finds.length - top.length} more in the fix panel`) : null);
}

// ------------------------------------------------------------------------------- the release line
function releaseLine(s) {
  const steps = RELEASE_LINE.map((step) => ({ step, row: s.rows.find((r) => r.item.id === step.id) })).filter((x) => x.row);
  if (!steps.length) return null;
  const counted = steps.filter((x) => x.row.bucket !== 'skip');
  const done = counted.filter((x) => x.row.bucket === 'done').length;
  const na = steps.length - counted.length;
  return el('section', { class: 'rl', 'aria-labelledby': 'rl-title' },
    el('h3', { class: 'rl__h', id: 'rl-title' }, 'The release line'),
    el('p', { class: 'rl__intro' }, `${WORDS[steps.length] || steps.length} controls stand between your build and your users. Add them in this order: each one makes a tampered release harder to ship or easier to catch.`),
    S.report ? el('p', { class: 'rl__score' },
      el('span', { class: 'meter', 'aria-hidden': 'true' }, steps.map((x) => el('i', { 'data-b': x.row.bucket }))),
      el('span', {}, `${done} of ${counted.length} done${na ? `, ${na} not applicable` : ''}`)) : null,
    el('ol', { class: 'rl__steps' }, steps.map(stepEl)));
}

function stepEl({ step, row }) {
  const { item, st, bucket, finds } = row;
  const current = item.id === S.item;
  const pa = item.peer_adoption;
  return el('li', { class: `rl__step rl__step--${bucket}${current ? ' is-current' : ''}` },
    lamp(ITEM_TONE[st.status] || 'open', 'md', ITEM_GLYPH[st.status]),
    el('div', { class: 'rl__body' },
      el('h4', { class: 'rl__h4' }, el('button', {
        type: 'button', class: 'rl__btn', 'data-item': item.id, 'data-fk': `step:${item.id}`,
        'aria-current': current ? 'true' : null, 'aria-haspopup': WIDE.matches ? null : 'dialog',
        onclick: (e) => openItem(item.id, e.currentTarget),
      }, el('span', { class: 'rl__name' }, firstTag(item.id, 'tag-first'), step.name), el('span', { class: 'rl__title' }, item.title))),
      S.report || st.status === 'done' ? statusLine(row, 'p', 'rl__status') : null,
      bucket === 'later' ? el('p', { class: 'rl__status' }, `This starts at tier ${item.tier}; the repo is tier ${S.model.tierId}.`) : null,
      el('p', { class: 'rl__what' }, step.what),
      pa && pa.overall != null ? el('p', { class: 'rl__peers' }, `${pa.overall}% of the ${S.guide.counts.repos_scanned} Fund projects ${sg.peerHave(item)}.`) : null,
      finds.length ? findsPreview(finds) : null));
}

// ------------------------------------------------------------------------------- reader and sheet
function openItem(id, opener) {
  S.item = id;
  S.opener = opener || null;
  markCurrent();
  drawReader();
  writeHash();
  if (WIDE.matches) announce(`Showing how to fix: ${S.guide.itemsById[id].title}`);
}

function markCurrent() {
  for (const b of $$('[data-item]', LIST)) {
    const on = b.dataset.item === S.item;
    if (on) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
    const holder = b.closest('.row, .rl__step');
    if (holder) holder.classList.toggle('is-current', on);
  }
  placeSkip();
}

// Wide screens: right after the selected check, a link that appears on focus and jumps over the rest of the
// list into its fix (the reader follows the whole list in the page order).
function placeSkip() {
  for (const n of $$('.skipto', LIST)) n.remove();
  if (!WIDE.matches || !S.item) return;
  const b = LIST.querySelector(`[data-item="${CSS.escape(S.item)}"]`);
  if (!b) return;
  (b.closest('.rl__h4') || b).after(el('a', { class: 'skipto', href: '#reader',
    onclick: (e) => { e.preventDefault(); focusReader(false); } }, 'Skip to the fix'));
}

function drawReader() {
  const item = S.item ? S.guide.itemsById[S.item] : null;
  const wide = WIDE.matches;
  const sig = [item ? item.id : '', S.key, S.ctx.full, item ? JSON.stringify(sg.store.get(S.ctx.full || S.repo, item.id)) : '', wide, isFixFirst(item && item.id)].join('|');
  const sameItem = S.readerSig.split('|')[0] === (item ? item.id : '');
  if (wide) {
    const box = READER;
    if (sig !== S.readerSig || !box.firstChild) {
      swap(box, item ? readerContent(item) : el('p', { class: 'reader__empty' }, 'Pick a check to see how to fix it.'), sameItem, box);
    }
    S.readerSig = sig;
    return;
  }
  const sheet = $('#sheet');
  if (!item) {
    S.readerSig = sig;
    if (sheet.open) { S.switching = true; sheet.close(); S.switching = false; }
    return;
  }
  if (sig !== S.readerSig || !$('#sheet-body').firstChild) {
    const stage = S.model.byId[item.stage];
    $('#sheet-title').textContent = stage ? `Stage ${stage.index + 1}: ${stage.label}` : 'How to fix';
    sheet.setAttribute('aria-label', `How to fix: ${item.title}`);
    swap($('#sheet-body'), readerContent(item), sameItem && sheet.open, sheet);
  }
  S.readerSig = sig;
  if (!sheet.open) sheet.showModal();
}

// Replace a panel's content, keeping its scroll position and the "Mark done" focus when it is the same item.
function swap(box, content, keep, scroller) {
  const top = keep ? scroller.scrollTop : 0;
  const refocus = box.contains(document.activeElement) && document.activeElement.matches('.sg-check input');
  box.replaceChildren(content);
  scroller.scrollTop = top;
  if (refocus) { const cb = box.querySelector('.sg-check input'); if (cb) cb.focus({ preventScroll: true }); }
}

function readerContent(item) {
  const stage = S.model.byId[item.stage];
  const rem = sg.renderRemediation(item, { guide: S.guide, report: S.report, ctx: S.ctx, onChange: () => { if (S.rerender) S.rerender(); } });
  const extra = readerExtra(item);
  if (extra) { const head = rem.querySelector('.sg-remedy__head'); if (head) head.after(extra); else rem.prepend(extra); }
  return el('div', { class: 'reader__inner' },
    WIDE.matches && stage ? el('p', { class: 'reader__crumb' }, lamp(stage.tone, 'xs', STATION_GLYPH[stage.tone]), `Stage ${stage.index + 1}: ${stage.label}`,
      isFixFirst(item.id) ? [el('span', { class: 'vh' }, '. '), el('span', { class: 'tag-first' }, 'Fix this first')] : null) : null,
    !WIDE.matches && isFixFirst(item.id) ? el('p', { class: 'reader__crumb' }, el('span', { class: 'tag-first' }, 'Fix this first')) : null,
    rem);
}

function readerExtra(item) {
  const bits = [];
  if (!item.why && item.short && norm(item.short) !== norm(item.title)) bits.push(el('p', { class: 'reader__short' }, item.short));
  const pa = item.peer_adoption;
  if (pa && pa.overall != null) {
    const t = starsTier();
    const near = t && pa.by_tier && pa.by_tier[t.id] != null ? pa.by_tier[t.id] : null;
    bits.push(el('p', { class: 'reader__peers' }, `${pa.overall}% of the ${S.guide.counts.repos_scanned} Fund projects ${sg.peerHave(item)}.`
      + (near != null ? ` Among those in this repo's star range (tier ${t.id}, ${t.name}): ${near}%.` : '')));
  }
  const attacks = (item.attacks || []).map((id) => S.guide.attacksById[id]).filter(Boolean);
  if (attacks.length) bits.push(el('div', { class: 'reader__stops' }, el('p', {}, 'Helps stop:'), el('ul', {}, attacks.map((a) => el('li', {}, a.title)))));
  return bits.length ? el('div', { class: 'reader__extra' }, bits) : null;
}

// ------------------------------------------------------------------------------- motion: the token
function queueToken() {
  if (!WIDE.matches || CALM.matches) return;
  if (!S.revealed) { S.tokenWanted = true; return; }
  requestAnimationFrame(() => requestAnimationFrame(runToken));
}

// A change travels the line from the keyboard, slowing into and pausing at every stage with gaps.
function runToken() {
  stopToken();
  if (!WIDE.matches || CALM.matches || !S.model) return;
  const map = $('#map');
  const tok = $('#token');
  const box = map.getBoundingClientRect();
  const stops = $$('#line > li').map((li) => {
    const mark = li.querySelector(':scope > .st__btn > .lamp, :scope > .term__icon');
    if (!mark) return null;
    const r = mark.getBoundingClientRect();
    const stage = li.dataset.stage ? S.model.byId[li.dataset.stage] : null;
    const hold = stage ? ({ fail: 650, warn: 450 }[stage.tone] || 0) : (li.dataset.kind === 'users' ? 350 : 0);
    return { x: r.left + r.width / 2 - box.left - map.clientLeft, y: r.top + r.height / 2 - box.top - map.clientTop, hold, stage: stage ? stage.id : null };
  }).filter(Boolean);
  if (stops.length < 2) return;
  const speed = 0.9; // px per ms
  const marks = [];
  const hits = [];
  let t = 200; // fade in at the keyboard
  stops.forEach((p, i) => {
    if (i) t += Math.hypot(p.x - stops[i - 1].x, p.y - stops[i - 1].y) / speed;
    marks.push({ t, p, arrive: !!p.hold });
    if (p.hold) {
      if (p.stage) hits.push({ at: t, id: p.stage });
      t += p.hold;
      marks.push({ t, p, leave: true });
    }
  });
  const total = t + 260;
  const at = (p) => `translate(${p.x.toFixed(1)}px, ${p.y.toFixed(1)}px)`;
  const frames = [{ transform: at(stops[0]), opacity: 0, offset: 0 }];
  marks.forEach((m, k) => {
    const next = marks[k + 1];
    const easing = m.leave ? 'ease-in' : next && next.arrive ? 'ease-out' : 'linear';
    frames.push({ transform: at(m.p), opacity: 1, offset: m.t / total, easing });
  });
  frames.push({ transform: at(stops[stops.length - 1]), opacity: 0, offset: 1 });
  tok.hidden = false;
  const anim = tok.animate(frames, { duration: total, fill: 'forwards' });
  const timers = hits.map((h) => setTimeout(() => {
    const li = $(`#line > li[data-stage="${h.id}"]`);
    if (!li) return;
    li.classList.add('is-hit');
    setTimeout(() => li.classList.remove('is-hit'), 1500);
  }, h.at));
  S.token = { anim, timers };
  anim.finished.then(() => { tok.hidden = true; S.token = null; }).catch(() => {});
}

function stopToken() {
  if (!S.token) return;
  const { anim, timers } = S.token;
  S.token = null;
  timers.forEach(clearTimeout);
  anim.cancel();
  $('#token').hidden = true;
  for (const li of $$('#line > li.is-hit')) li.classList.remove('is-hit');
}

// "Run a deep scan" (from "Still to check"): the scan box's Deep scan button, in view and pressed. It's the same flow,
// so with no sign-in yet it goes on to GitHub, which this click asked for.
function deepScan() {
  const btn = $('#scan-mount .sg-scan__deep');
  if (!btn) return;
  btn.scrollIntoView({ block: 'center', behavior: motion() });
  btn.focus({ preventScroll: true });
  btn.click();
}

// The report on screen has a scan with admin access: a deep scan, or a private scan's report.
const deepScanned = () => !!S.report && (S.report.layers || [S.report.layer]).some((l) => l !== 'public');

// ------------------------------------------------------------------------------------ plumbing
function setupStatic() {
  // index.html lists the stages in #line for readers without JavaScript. Empty it now: drawLine() draws the map there,
  // and if the guide doesn't load, the line stays empty.
  $('#line').replaceChildren();
  $('#legend').replaceChildren(...LEGEND.map(([tone, label]) => el('li', {}, lamp(tone, 'xs', STATION_GLYPH[tone]), label)),
    el('li', {}, el('span', { class: 'ticks ticks--key', 'aria-hidden': 'true' }, ['fail', 'warn', 'done', 'info', 'open'].map((b) => el('i', { 'data-b': b }))),
      'One bar per check (blue: info)'));
  setupTheme();
  $('#trace').addEventListener('click', () => runToken());

  // Arrow keys move between stages; Enter or Space opens one.
  $('#line').addEventListener('keydown', (e) => {
    const btn = e.target.closest && e.target.closest('.st__btn');
    if (!btn) return;
    const all = $$('#line .st__btn');
    const i = all.indexOf(btn);
    const to = { ArrowRight: i + 1, ArrowDown: i + 1, ArrowLeft: i - 1, ArrowUp: i - 1, Home: 0, End: all.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    const j = Math.max(0, Math.min(all.length - 1, to));
    all.forEach((b, k) => { b.tabIndex = k === j ? 0 : -1; });
    all[j].focus();
  });

  const sheet = $('#sheet');
  $('#sheet-close').addEventListener('click', () => sheet.close());
  sheet.addEventListener('click', (e) => { if (e.target === sheet) sheet.close(); });
  sheet.addEventListener('close', () => {
    if (S.switching) return;
    const id = S.item;
    S.item = null;
    markCurrent();
    writeHash();
    const back = (S.opener && document.contains(S.opener) && S.opener)
      || (id && LIST.querySelector(`[data-item="${CSS.escape(id)}"]`)) || $(`#st-${S.stage}`);
    if (back) back.focus();
  });

  WIDE.addEventListener('change', () => {
    if (!S.model) return;
    stopToken();
    if (WIDE.matches) {
      S.collapsed = false;
      if (sheet.open) { S.switching = true; sheet.close(); S.switching = false; }
      if (!S.item) S.item = firstItem(S.stage);
    } else {
      S.item = null;
    }
    S.readerSig = '';
    drawLine();
    drawStage();
    drawReader();
    writeHash();
  });
  CALM.addEventListener('change', stopToken);

  // Follow links that change the hash on this page (#hop=…&fix=…).
  addEventListener('hashchange', () => {
    if (!S.model) return;
    const h = readHash();
    const linked = h.fix && S.guide.itemsById[h.fix];
    const hop = linked ? linked.stage : h.hop;
    if (!hop || !S.model.byId[hop]) return;
    if (hop !== S.stage) selectStage(hop);
    if (linked && linked.id !== S.item) openItem(linked.id, null);
    else writeHash();
  });
  addEventListener('resize', stopToken);
  // After a one-click fix, the app checks the repository again and sends the result with the check's id. This runs
  // before the scan panel's own listener draws the result, so render() keeps that check open.
  document.addEventListener('sg:report', (e) => {
    const id = e.detail && e.detail.item;
    if (id && S.guide && S.guide.itemsById[id]) S.keep = id;
  });
}

function setupTheme() {
  const btn = $('#theme');
  const root = document.documentElement;
  let cur = ['light', 'dark'].includes(root.dataset.theme) ? root.dataset.theme : 'system';
  const paint = () => { btn.textContent = `Theme: ${cur}`; };
  btn.addEventListener('click', () => {
    cur = { system: 'light', light: 'dark', dark: 'system' }[cur];
    if (cur === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', cur);
    try { if (cur === 'system') localStorage.removeItem('pl:theme'); else localStorage.setItem('pl:theme', cur); } catch { /* storage blocked */ }
    paint();
  });
  paint();
}

// While a scan runs, the lamps run a "lamp test" and the map says so. The scan panel marks every scan with aria-busy
// (a public scan and a deep scan alike), and its message starts with "Checking" while a deep scan checks your access
// first, then "Scanning".
function watchBusy() {
  const scan = $('#scan-mount .sg-scan');
  if (!scan) return;
  const msg = $('.sg-scan__msg', scan);
  const sync = () => {
    const busy = scan.getAttribute('aria-busy') === 'true';
    // A scan the box started on its own ended without a result (it failed, or a deep scan needs a click first): show
    // the page anyway; the scan box says why.
    if (!busy && S.holdForScan && !S.report) { S.holdForScan = false; reveal(); }
    const checking = busy && !!msg && /^Checking\b/.test(msg.textContent.trim());
    if (busy) stopToken();
    $('#map').toggleAttribute('data-busy', busy);
    $('#busy').textContent = busy ? (checking ? 'Checking…' : 'Scanning…') : '';
  };
  const watch = new MutationObserver(sync);
  watch.observe(scan, { attributes: true, attributeFilter: ['aria-busy'] });
  if (msg) watch.observe(msg, { childList: true, characterData: true, subtree: true });
}

function readHash() {
  const old = location.hash.match(/^#item-([\w.-]+)$/); // links from the retired report card
  if (old) return { hop: null, fix: old[1] };
  const p = new URLSearchParams(location.hash.slice(1));
  return { hop: p.get('hop'), fix: p.get('fix') };
}

function writeHash() {
  const p = new URLSearchParams();
  if (S.stage) p.set('hop', S.stage);
  if (S.item) p.set('fix', S.item);
  const next = `#${p}`;
  if (next !== location.hash) history.replaceState(history.state, '', `${location.pathname}${location.search}${next}`);
}

function restoreFocus(prev, key) {
  if (!key || (prev && document.contains(prev))) return;
  const next = document.querySelector(`[data-fk="${CSS.escape(key)}"]`);
  if (next) next.focus({ preventScroll: true });
}

function announce(text) {
  const n = $('#announce');
  n.textContent = '';
  requestAnimationFrame(() => { n.textContent = text; });
}
