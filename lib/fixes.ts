/**
 * Click-to-fix pull requests for the GitHub App: allow-listed, built on the server, previewed before anything is opened.
 *
 * Three kinds of fix (PR_FIXES):
 * - file: add one file from the guide's template (SECURITY.md, CODEOWNERS, dependabot.yml, a few workflows) when the
 *   repo doesn't have it yet. The template comes from public/data/guide.json, where action pins are already resolved.
 * - pin: pin every GitHub Action in .github/workflows to the commit SHA of the ref it already uses. The code that runs
 *   stays the same; it just can't be swapped out under the same tag any more.
 * - agent: an AI model edits the workflows the scan flagged (lib/agent.ts), and the server checks its change before
 *   anyone sees it. Only offered when the site has an AI service configured.
 *
 * Each fix is a new branch plus a pull request; nothing is pushed to an existing branch and nothing is merged.
 * The functions here only talk to GitHub through a Gh callable (lib/github.ts), so tests can pass a fake one.
 */
import fs from 'node:fs';
import path from 'node:path';
import { structuredPatch } from 'diff';
import * as agent from './agent.ts';
import type { GuideItem, Spent } from './agent.ts';
import { ROOT } from './env.ts';
import type { Gh } from './github.ts';
import { quote } from './http.ts';
import { mapLimit } from './pool.ts';
import { ECOSYSTEM_FILES, parentKeys, splitLines } from './scanner/index.ts';

const SHA = /^[0-9a-f]{40}$/;
const RAW = 'application/vnd.github.raw';

/** Why a fix can't go ahead, in words for the person who asked. `status` is the HTTP status to answer with. */
export class FixError extends Error {
  status: number;
  usage?: Spent; // a failed AI fix still cost tokens
  constructor(message: string, status = 409) {
    super(message);
    this.status = status;
  }
}

export type PrFix = {
  kind: 'file' | 'pin' | 'agent';
  label: string;
  title?: string;
  alts?: string[]; // other places the same file counts as present
  workflow?: boolean; // the change touches .github/workflows, which needs the app's Workflows permission
  public_only?: boolean; // the file needs a public repo to work
};

export const PR_FIXES: Record<string, PrFix> = {
  'disc-security-md': {
    kind: 'file',
    label: 'Open a pull request that adds SECURITY.md',
    title: 'Add a security policy (SECURITY.md)',
    alts: ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'],
  },
  'repo-codeowners': {
    kind: 'file',
    label: 'Open a pull request that adds CODEOWNERS',
    title: "Require a maintainer's review for workflows and security docs (CODEOWNERS)",
    alts: ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS'],
  },
  'deps-update-automation': {
    kind: 'file',
    label: 'Open a pull request that adds dependabot.yml',
    title: 'Turn on Dependabot version updates, with a 7-day cooldown',
    alts: ['.github/dependabot.yml', '.github/dependabot.yaml'],
  },
  'ci-workflow-audit': {
    kind: 'file',
    label: 'Open a pull request that adds the zizmor workflow',
    title: 'Audit GitHub Actions workflows with zizmor',
    workflow: true,
  },
  'deps-review': {
    kind: 'file',
    label: 'Open a pull request that adds dependency review',
    title: 'Review new dependencies on pull requests',
    workflow: true,
    public_only: true,
  },
  'posture-scorecard': {
    kind: 'file',
    label: 'Open a pull request that adds the Scorecard workflow',
    title: 'Run OpenSSF Scorecard weekly',
    workflow: true,
    public_only: true,
  },
  'ci-pin-actions': { kind: 'pin', label: 'Open a pull request that pins your actions', workflow: true },
  ...Object.fromEntries(
    Object.entries(agent.FIXES).map(([id, spec]) => [
      id,
      { kind: 'agent', label: 'Let an AI agent fix it', title: spec.title, workflow: true } satisfies PrFix,
    ]),
  ),
};

/** The fixes this site can offer right now: agent fixes only when an AI service is configured. */
export function available(): Record<string, PrFix> {
  const on = agent.enabled();
  return Object.fromEntries(Object.entries(PR_FIXES).filter(([, v]) => v.kind !== 'agent' || on));
}

/** The installation permissions a pull request fix needs. */
export function neededPermissions(itemId: string): Record<string, string> {
  const need: Record<string, string> = { contents: 'write', pull_requests: 'write' };
  if (PR_FIXES[itemId]?.workflow) need.workflows = 'write';
  return need;
}

// ------------------------------------------------------------------------------------------- the guide
const GUIDE_FILE = path.join(ROOT, 'public', 'data', 'guide.json');
let guide: { mtime: number; items: Record<string, GuideItem> } = { mtime: 0, items: {} };

/** The guide's items by id, re-read when guide.json changes (a rebuild of the guide needs no restart). */
export function guideItems(): Record<string, GuideItem> {
  const mtime = fs.statSync(GUIDE_FILE).mtimeMs;
  if (mtime !== guide.mtime) {
    const items: GuideItem[] = JSON.parse(fs.readFileSync(GUIDE_FILE, 'utf8')).items;
    guide = { mtime, items: Object.fromEntries(items.map((i) => [i.id, i])) };
  }
  return guide.items;
}

// ------------------------------------------------------------------------------------------- templates
// fill() mirrors fill() in public/shared/core.js; tests/fixes.test.ts checks that both give the same text.
const DEPENDABOT_ECO: Record<string, string> = {
  npm: 'npm',
  pypi: 'pip',
  go: 'gomod',
  cargo: 'cargo',
  maven: 'maven',
  rubygems: 'bundler',
  composer: 'composer',
  nuget: 'nuget',
  swift: 'swift',
};
const ECO_TAIL = '    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n';

export type FillContext = {
  owner?: string;
  repo?: string;
  full?: string;
  branch?: string;
  ownerType?: string;
  ecosystems?: string[];
  maintainer?: string;
};

/**
 * Fill a guide template. ctx keys match core.js: owner, repo, full, branch, ownerType, ecosystems.
 * The server may pass a better `maintainer` and its own ecosystem blocks; core.js has neither.
 */
export function fill(template: string, ctx: FillContext, ecoBlocks?: string | null): string {
  if (!template) return template;
  const blocks =
    ecoBlocks ??
    (ctx.ecosystems || [])
      .filter((e) => Object.hasOwn(DEPENDABOT_ECO, e))
      .map((e) => `  - package-ecosystem: ${DEPENDABOT_ECO[e]}\n    directory: /\n${ECO_TAIL}`)
      .join('');
  const org = ctx.ownerType === 'Organization';
  const owner = ctx.owner;
  const maintainer = ctx.maintainer || (org ? `@${owner}/maintainers` : `@${owner || 'OWNER'}`);
  const person = org || !owner ? '(name a maintainer)' : `@${owner}`;
  return template
    .replaceAll('{maintainer}', maintainer)
    .replaceAll('{person}', person)
    .replaceAll('{owner}', owner || 'OWNER')
    .replaceAll('{repo}', ctx.repo || 'REPO')
    .replaceAll('{full}', ctx.full || 'OWNER/REPO')
    .replaceAll('{branch}', ctx.branch || 'main')
    .replaceAll('{ecosystem_blocks}', blocks);
}

/** Folders whose manifests are test data or vendored code, not dependencies to keep updated. */
const SKIP_DIR =
  /(^|\/)(node_modules|vendor|third_party|third-party|testdata|tests?|fixtures?|examples?|samples?)(\/|$)/i;

/** Dependabot ecosystem -> folders ("" is the root) that hold its manifests. */
export function ecosystemDirs(paths: string[]): Map<string, Set<string>> {
  const found = new Map<string, Set<string>>();
  for (const p of paths) {
    const folder = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '';
    if (folder && SKIP_DIR.test(folder)) continue;
    for (const [pattern, eco] of ECOSYSTEM_FILES) {
      if (!pattern.test(p)) continue;
      let kind: string | undefined = DEPENDABOT_ECO[eco];
      if (eco === 'maven' && /build\.gradle(\.kts)?$/.test(p)) kind = 'gradle';
      if (kind) {
        if (!found.has(kind)) found.set(kind, new Set());
        found.get(kind)!.add(folder);
      }
    }
  }
  return found;
}

const byCodePoint = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** One update entry per ecosystem: the root when it has a manifest there, otherwise the folders that do. */
export function dependabotBlocks(paths: string[]): string {
  const out: string[] = [];
  for (const [kind, folders] of [...ecosystemDirs(paths)].sort(([a], [b]) => byCodePoint(a, b))) {
    let where: string;
    if (folders.has('')) {
      where = '    directory: /\n';
    } else {
      const depth = (d: string) => d.split('/').length - 1;
      const shallow = [...folders].sort((a, b) => depth(a) - depth(b) || byCodePoint(a, b)).slice(0, 10);
      where = `    directories:\n${shallow.map((d) => `      - "/${d}"\n`).join('')}`;
    }
    out.push(`  - package-ecosystem: ${kind}\n${where}${ECO_TAIL}`);
  }
  return out.join('');
}

// ------------------------------------------------------------------------------------------------ pins
const USES = /^(?<pre>\s*(?:-\s+)?uses:\s*)(?<q>["']?)(?<name>[^\s"'#@]+)@(?<ref>[^\s"'#]+)\k<q>(?<post>\s*(?:#.*)?)$/;
// Refs that name a branch rather than a release: pinning them is still safer, but worth a note.
const BRANCH_REFS = new Set(['main', 'master', 'develop', 'dev', 'trunk', 'stable', 'latest', 'head']);

type UsesMatch = { pre: string; q: string; name: string; ref: string; post: string };

/** [line index, match] for every `uses:` that points at a tag or branch instead of a full commit SHA. */
export function unpinnedUses(text: string): [number, UsesMatch][] {
  const lines = splitLines(text);
  // All in one pass: parentKey() per line would walk back over a long script for each of its lines.
  const parents = parentKeys(lines);
  const hits: [number, UsesMatch][] = [];
  lines.forEach((line, i) => {
    const m = USES.exec(line)?.groups as UsesMatch | undefined;
    if (!m) return;
    if (m.name.startsWith('./') || m.name.startsWith('docker:') || !m.name.includes('/') || line.includes('${{'))
      return;
    if (SHA.test(m.ref)) return;
    // A `uses:` line inside a run: script is text, not a step.
    if (parents[i] === 'run' || parents[i] === 'script') return;
    hits.push([i, m]);
  });
  return hits;
}

export type PinChange = {
  line: number;
  action: string;
  ref: string;
  sha: string | null;
  branch: boolean;
  path?: string;
};

/** Rewrite `uses: owner/repo@ref` to `uses: owner/repo@<sha> # ref`, keeping quotes, indentation and line endings. */
export function pinText(
  text: string,
  resolve: (owner: string, repo: string, ref: string) => string | null | undefined,
): [string, PinChange[]] {
  const newline = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = splitLines(text);
  const changes: PinChange[] = [];
  for (const [i, m] of unpinnedUses(text)) {
    const [owner, repo] = m.name.split('/');
    const sha = resolve(owner, repo, m.ref) || null;
    changes.push({ line: i + 1, action: m.name, ref: m.ref, sha, branch: BRANCH_REFS.has(m.ref.toLowerCase()) });
    if (!sha) continue;
    const old = m.post.trim();
    lines[i] = `${m.pre}${m.q}${m.name}@${sha}${m.q} # ${m.ref}${old ? ` ${old}` : ''}`;
  }
  let out = lines.join(newline);
  if (text.endsWith('\n')) out += newline;
  return [out, changes];
}

const refCache = new Map<string, { at: number; sha: string | null }>();

export function clearRefCache(): void {
  refCache.clear();
}

/** owner, repo, ref -> the full commit SHA that ref points at (peeled through annotated tags), or null. */
export function resolver(gh: Gh): (owner: string, repo: string, ref: string) => Promise<string | null> {
  return async (owner, repo, ref) => {
    const key = `${owner.toLowerCase()}/${repo.toLowerCase()}@${ref}`;
    const hit = refCache.get(key);
    if (hit && Date.now() / 1000 - hit.at < (hit.sha ? 600 : 60)) return hit.sha;
    const { status, data } = await gh(
      'GET',
      `/repos/${quote(owner)}/${quote(repo)}/commits/${quote(ref, '')}`,
      undefined,
      'application/vnd.github.sha',
    );
    const text = typeof data === 'string' ? data.trim() : '';
    const sha = status === 200 && SHA.test(text) ? text : null;
    refCache.set(key, { at: Date.now() / 1000, sha });
    return sha;
  };
}

// ----------------------------------------------------------------------------------------------- plans
async function get(gh: Gh, apiPath: string, what: string): Promise<any> {
  const { status, data } = await gh('GET', apiPath);
  if (status !== 200 || data === null || data === undefined) {
    throw new FixError(`Couldn't read ${what} from GitHub (HTTP ${status}).`, 502);
  }
  return data;
}

async function exists(gh: Gh, full: string, file: string, ref: string): Promise<boolean> {
  const { status } = await gh('GET', `/repos/${full}/contents/${quote(file)}?ref=${quote(ref)}`, undefined, RAW);
  return status === 200;
}

export async function openPull(gh: Gh, full: string, head: string): Promise<{ url: string; number: number } | null> {
  const owner = full.split('/')[0];
  const { status, data } = await gh('GET', `/repos/${full}/pulls?state=open&head=${quote(owner)}:${quote(head)}`);
  if (status === 200 && Array.isArray(data) && data.length) return { url: data[0].html_url, number: data[0].number };
  return null;
}

export type PlanFile = { path: string; mode: string; before: string | null; content: string };
export type Plan = {
  repo: string;
  item_id: string;
  base_branch: string;
  base_sha: string;
  base_tree: string;
  head: string;
  notes: string[];
  kind: 'file' | 'pin' | 'agent';
  title: string;
  commit_message: string;
  why: string;
  files: PlanFile[];
  body: string;
  changes?: PinChange[];
  summary?: string;
  usage?: Spent;
};
type Entries = Record<string, { path: string; mode?: string; type?: string }>;
type Ctx = FillContext & { owner: string; repo: string; full: string; branch: string; ownerType: string };

/** Work out exactly what the pull request will contain. Reads only; nothing on GitHub changes. */
export async function plan(
  gh: Gh,
  repo: string,
  itemId: string,
  login: string,
  progress: (text: string) => void = () => {},
): Promise<Plan | { existing: { url: string; number: number } }> {
  const spec = available()[itemId];
  if (!spec) throw new FixError("There's no one-click pull request for this check.", 422);
  const meta = await get(gh, `/repos/${repo}`, repo);
  const full: string = meta.full_name;
  const base: string = meta.default_branch;
  if (meta.archived) throw new FixError(`${full} is archived, so it can't take pull requests.`);
  if (spec.public_only && meta.private) {
    throw new FixError(
      "This workflow needs a public repository (or GitHub Advanced Security), so it isn't offered for private ones.",
    );
  }
  const head = `sosf/${itemId}`;
  const existing = await openPull(gh, full, head);
  if (existing) return { existing };
  const baseSha: string = (await get(gh, `/repos/${full}/git/ref/heads/${quote(base)}`, 'the default branch')).object
    .sha;
  const baseTree: string = (await get(gh, `/repos/${full}/git/commits/${baseSha}`, 'the latest commit')).tree.sha;
  const tree = await get(gh, `/repos/${full}/git/trees/${baseTree}?recursive=1`, 'the file list');
  const entries: Entries = Object.fromEntries(
    (tree.tree || []).filter((t: any) => t.type === 'blob').map((t: any) => [t.path, t]),
  );
  const ctx: Ctx = { owner: meta.owner.login, repo: meta.name, full, branch: base, ownerType: meta.owner.type };
  const out = {
    repo: full,
    item_id: itemId,
    base_branch: base,
    base_sha: baseSha,
    base_tree: baseTree,
    head,
    notes: [] as string[],
  };
  const truncated = Boolean(tree.truncated);
  let part;
  if (spec.kind === 'file') part = await filePlan(gh, spec, itemId, ctx, entries, truncated, login);
  else if (spec.kind === 'pin') part = await pinPlan(gh, full, baseSha, entries, truncated);
  else part = await agentPlan(gh, full, baseSha, entries, truncated, itemId, progress);
  const p = { ...out, ...part } as Omit<Plan, 'body'>;
  return { ...p, body: prBody(p, login) };
}

async function filePlan(
  gh: Gh,
  spec: PrFix,
  itemId: string,
  ctx: Ctx,
  entries: Entries,
  truncated: boolean,
  login: string,
) {
  const item = guideItems()[itemId];
  const newFile = item.new_file!;
  const file = newFile.path;
  const full = ctx.full;
  const lower = new Map(Object.keys(entries).map((p) => [p.toLowerCase(), p]));
  for (const alt of spec.alts || [file]) {
    const have = lower.get(alt.toLowerCase()) || (truncated && (await exists(gh, full, alt, ctx.branch)) ? alt : null);
    if (have) {
      throw new FixError(
        `${full} already has ${have}. Edit that file instead; the steps in the guide say what it should cover.`,
      );
    }
  }
  const notes: string[] = [];
  let ecoBlocks: string | null = null;
  let fillCtx: FillContext = ctx;
  if (itemId === 'repo-codeowners' && ctx.ownerType === 'Organization') {
    const { status } = await gh('GET', `/orgs/${quote(ctx.owner)}/teams/maintainers`);
    if (status !== 200) {
      fillCtx = { ...ctx, maintainer: `@${login}` };
      notes.push(
        `There's no @${ctx.owner}/maintainers team, so the file names @${login}. Swap in the team that maintains this repository.`,
      );
    }
  }
  if (itemId === 'deps-update-automation') ecoBlocks = dependabotBlocks(Object.keys(entries));
  if (itemId === 'disc-security-md') {
    const { status, data } = await gh('GET', `/repos/${full}/private-vulnerability-reporting`);
    if (status === 200 && data && typeof data === 'object' && !data.enabled) {
      notes.push(
        "Private vulnerability reporting is off, so the report link in this file won't work yet. Turn it on too; the guide has a one-click fix for it.",
      );
    }
  }
  const content = `${fill(newFile.template, fillCtx, ecoBlocks).replace(/\n+$/, '')}\n`;
  return {
    kind: 'file' as const,
    title: spec.title || `Add ${file}`,
    commit_message: `Add ${file}\n\nFrom the Secure Open Source guide's template for: ${item.title}.`,
    why: item.why || item.short || '',
    files: [{ path: file, mode: '100644', before: null, content }],
    notes,
  };
}

/** Every workflow file's text at the base commit (null where it couldn't be read). */
async function readWorkflows(
  gh: Gh,
  full: string,
  baseSha: string,
  entries: Entries,
  truncated: boolean,
): Promise<Record<string, string | null>> {
  let paths = Object.keys(entries)
    .filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p))
    .sort(byCodePoint);
  if (truncated && !paths.length) {
    const { status, data } = await gh('GET', `/repos/${full}/contents/.github/workflows?ref=${baseSha}`);
    if (status === 200 && Array.isArray(data)) {
      paths = data
        .filter((f: any) => /^[^/]+\.ya?ml$/.test(f.name || ''))
        .map((f: any) => String(f.path))
        .sort(byCodePoint);
    }
  }
  if (!paths.length) throw new FixError(`${full} has no workflows in .github/workflows.`);
  const texts = await mapLimit(paths, 8, (p) => readText(gh, full, p, baseSha));
  return Object.fromEntries(paths.map((p, i) => [p, texts[i]]));
}

async function readText(gh: Gh, full: string, file: string, ref: string): Promise<string | null> {
  const { status, data } = await gh('GET', `/repos/${full}/contents/${quote(file)}?ref=${quote(ref)}`, undefined, RAW);
  return status === 200 && typeof data === 'string' ? data : null;
}

async function pinPlan(gh: Gh, full: string, baseSha: string, entries: Entries, truncated: boolean) {
  const texts = await readWorkflows(gh, full, baseSha, entries, truncated);
  const wanted = new Map<string, [string, string, string]>();
  for (const t of Object.values(texts)) {
    if (!t) continue;
    for (const [, m] of unpinnedUses(t)) {
      const [owner, repo] = m.name.split('/');
      wanted.set(`${owner}/${repo}@${m.ref}`, [owner, repo, m.ref]);
    }
  }
  const resolve = resolver(gh);
  const shas = new Map<string, string | null>();
  await mapLimit([...wanted], 8, async ([key, [owner, repo, ref]]) => {
    shas.set(key, await resolve(owner, repo, ref));
  });
  const files: PlanFile[] = [];
  const changes: PinChange[] = [];
  for (const [p, text] of Object.entries(texts)) {
    if (!text) continue;
    const [updated, ch] = pinText(text, (owner, repo, ref) => shas.get(`${owner}/${repo}@${ref}`));
    changes.push(...ch.map((c) => ({ ...c, path: p })));
    if (updated !== text) files.push({ path: p, mode: entries[p]?.mode || '100644', before: text, content: updated });
  }
  const pinned = changes.filter((c) => c.sha);
  const missed = changes.filter((c) => !c.sha);
  if (!changes.length) throw new FixError('Every action in .github/workflows is already pinned to a full commit SHA.');
  if (!pinned.length) {
    throw new FixError(
      'None of the action versions in your workflows could be looked up on GitHub, so nothing was pinned.',
    );
  }
  const notes: string[] = [];
  if (missed.length) {
    const names = [...new Set(missed.map((c) => `${c.action}@${c.ref}`))].sort(byCodePoint);
    notes.push(`Couldn't look up ${names.join(', ')}, so those lines are unchanged.`);
  }
  if (pinned.some((c) => c.branch)) {
    notes.push(
      "Some actions followed a branch (like main). They're pinned to today's commit; consider moving them to a release.",
    );
  }
  const n = new Set(pinned.map((c) => `${c.action}@${c.ref}`)).size;
  return {
    kind: 'pin' as const,
    title: `Pin ${n} GitHub ${n === 1 ? 'Action' : 'Actions'} to commit SHAs`,
    commit_message: `Pin GitHub Actions to full commit SHAs\n\nSame versions as before, now immutable. ${pinned.length} references in ${files.length} workflow files.`,
    why: "A tag like v4 can be moved to different code at any time, including by an attacker who takes over the action's repository. A commit SHA can't.",
    files,
    changes,
    notes,
  };
}

async function agentPlan(
  gh: Gh,
  full: string,
  baseSha: string,
  entries: Entries,
  truncated: boolean,
  itemId: string,
  progress: (text: string) => void,
) {
  const texts = await readWorkflows(gh, full, baseSha, entries, truncated);
  const found: Record<string, string[]> = {};
  for (const p of Object.keys(texts).sort(byCodePoint)) {
    const t = texts[p];
    if (!t) continue;
    const f = agent.findingsFor(itemId, p, t);
    if (f.length) found[p] = f;
  }
  const foundPaths = Object.keys(found);
  if (!foundPaths.length) throw new FixError("The scan doesn't find this problem in .github/workflows any more.");
  const targets = Object.fromEntries(foundPaths.slice(0, agent.MAX_FILES).map((p) => [p, found[p]]));
  const item = guideItems()[itemId];
  let result;
  try {
    result = await agent.run(
      itemId,
      item,
      full,
      targets,
      Object.fromEntries(Object.keys(targets).map((p) => [p, texts[p] as string])),
      (file) => readText(gh, full, file, baseSha),
      progress,
    );
  } catch (e) {
    if (!(e instanceof agent.AgentError)) throw e;
    const err = new FixError(e.message, e.status);
    err.usage = e.usage;
    throw err;
  }
  const notes = result.notes ? [result.notes] : [];
  const extra = foundPaths.length - Object.keys(targets).length;
  if (extra > 0) notes.push(`${extra} more workflow files need the same fix. Run it again after you merge this one.`);
  const u = result.usage;
  return {
    kind: 'agent' as const,
    title: agent.FIXES[itemId].title,
    commit_message: `${agent.FIXES[itemId].title}\n\nWritten by an AI model (${u.model}) with the Secure Open Source guide, checked automatically, and reviewed before merging.`,
    why: item.why || item.short || '',
    summary: result.summary,
    files: Object.keys(result.files)
      .sort(byCodePoint)
      .map((p) => ({ path: p, mode: entries[p]?.mode || '100644', before: texts[p], content: result.files[p] })),
    notes,
    usage: u,
  };
}

function prBody(p: Omit<Plan, 'body'>, login: string): string {
  const lines = [p.why, ''];
  if (p.kind === 'agent') {
    lines.push(
      p.summary || '',
      '',
      `This change was written by an AI model (${p.usage?.model}). Before this pull request was opened, the Secure Open Source guide checked that:`,
      '- the workflow files are still valid YAML;',
      '- the scan no longer finds the problem in the files that changed;',
      '- no action, URL, download, secret, trigger or write-all permission was added, and the change is small.',
      '',
      'Those checks catch mistakes and tampering, not every wrong guess. Read every line before you merge.',
    );
  } else if (p.kind === 'pin') {
    lines.push(
      "This pins every action in `.github/workflows` to the full commit SHA of the version it already uses. The code that runs doesn't change; it just can't be swapped out under the same tag any more.",
      '',
      '| Action | Was | Now |',
      '| --- | --- | --- |',
    );
    const seen = new Set<string>();
    for (const c of p.changes || []) {
      const key = `${c.action}@${c.ref}`;
      if (c.sha && !seen.has(key)) {
        seen.add(key);
        lines.push(`| \`${c.action}\` | \`${c.ref}\` | \`${c.sha.slice(0, 12)}\` |`);
      }
    }
    lines.push(
      '',
      'Dependabot keeps SHA pins and their version comments current when `.github/dependabot.yml` lists the `github-actions` ecosystem.',
    );
  } else {
    lines.push(
      `This adds \`${p.files[0].path}\` from the Secure Open Source guide's template, filled in for this repository. Read it before you merge: it's a starting point, and it should say what this project really does.`,
    );
  }
  if (p.notes.length) lines.push('', '**Notes**', ...p.notes.map((n) => `- ${n}`));
  lines.push(
    '',
    `_Opened at the request of @${login} with the Secure Open Source guide. Nothing changes until someone merges this._`,
  );
  return lines.join('\n');
}

/** A unified diff with no context lines, formatted like Python's difflib.unified_diff(n=0). */
export function unifiedDiff(before: string, after: string, fromFile: string, toFile: string): string {
  const patch = structuredPatch(fromFile, toFile, before, after, undefined, undefined, { context: 0 });
  if (!patch.hunks.length) return '';
  // difflib leaves out a length of 1, and an empty range names the line before it (jsdiff's start is one past that).
  const range = (start: number, length: number) =>
    length === 1 ? String(start) : `${length === 0 ? start - 1 : start},${length}`;
  let out = `--- ${fromFile}\n+++ ${toFile}\n`;
  for (const h of patch.hunks) {
    out += `@@ -${range(h.oldStart, h.oldLines)} +${range(h.newStart, h.newLines)} @@\n`;
    for (const line of h.lines) if (!line.startsWith('\\')) out += `${line}\n`;
  }
  return out;
}

/** What the person sees before they confirm: the title, the body and each file as a diff or as new content. */
export function preview(p: Plan) {
  return {
    repo: p.repo,
    kind: p.kind,
    usage: p.usage ?? null,
    title: p.title,
    body: p.body,
    base: p.base_branch,
    head: p.head,
    notes: p.notes,
    files: p.files.map((f) =>
      f.before === null
        ? { path: f.path, change: 'add' as const, content: f.content }
        : {
            path: f.path,
            change: 'edit' as const,
            diff: unifiedDiff(f.before, f.content, `a/${f.path}`, `b/${f.path}`),
          },
    ),
  };
}

// --------------------------------------------------------------------------------------------- applying
export function friendly(status: number, data: any, doing: string): FixError {
  const msg: string = data && typeof data === 'object' && !Array.isArray(data) ? String(data.message || '') : '';
  if (msg.toLowerCase().includes('workflow') && [403, 404, 422].includes(status)) {
    return new FixError(
      "The app isn't allowed to change workflow files on this repository. It needs the Workflows permission.",
      403,
    );
  }
  if (status === 403 || status === 404) {
    return new FixError(
      `The app isn't allowed to ${doing} on this repository. It needs write access to contents and pull requests.`,
      403,
    );
  }
  return new FixError(`GitHub refused to ${doing} (HTTP ${status}${msg ? `: ${msg}` : ''}).`, 502);
}

/** Create the branch, the commit and the pull request described by a plan from plan(). */
export async function apply(gh: Gh, p: Plan): Promise<{ url: string; number: number; branch: string }> {
  const full = p.repo;
  const base = p.base_branch;
  const now = await get(gh, `/repos/${full}/git/ref/heads/${quote(base)}`, 'the default branch');
  if (now.object.sha !== p.base_sha) {
    throw new FixError(
      `${base} has new commits since the preview. Preview the fix again so it's built on the latest code.`,
    );
  }
  const tree = await gh('POST', `/repos/${full}/git/trees`, {
    base_tree: p.base_tree,
    tree: p.files.map((f) => ({ path: f.path, mode: f.mode, type: 'blob', content: f.content })),
  });
  if (tree.status !== 201) throw friendly(tree.status, tree.data, 'add files');
  // No author or committer: GitHub signs commits that an app makes through the API, so they show as Verified.
  const commit = await gh('POST', `/repos/${full}/git/commits`, {
    message: p.commit_message,
    tree: tree.data.sha,
    parents: [p.base_sha],
  });
  if (commit.status !== 201) throw friendly(commit.status, commit.data, 'create a commit');
  let branch: string | null = null;
  for (let n = 1; n < 6; n++) {
    const name = n === 1 ? p.head : `${p.head}-${n}`;
    const ref = await gh('POST', `/repos/${full}/git/refs`, { ref: `refs/heads/${name}`, sha: commit.data.sha });
    if (ref.status === 201) {
      branch = name;
      break;
    }
    if (ref.status !== 422) throw friendly(ref.status, ref.data, 'create a branch');
  }
  if (!branch) throw new FixError(`Branches named ${p.head} already exist. Delete old ones and try again.`);
  const pr = await gh('POST', `/repos/${full}/pulls`, { title: p.title, head: branch, base, body: p.body });
  if (pr.status !== 201) {
    await gh('DELETE', `/repos/${full}/git/refs/heads/${quote(branch)}`);
    throw friendly(pr.status, pr.data, 'open a pull request');
  }
  return { url: pr.data.html_url, number: pr.data.number, branch };
}
