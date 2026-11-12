// ci-untrusted-artifacts-caches (new in 0.5.0): does a job that publishes, or a job that builds what it publishes,
// restore an Actions cache? A cache can be poisoned by any workflow that writes to it, so a release built from one
// can ship an attacker's files. The rule follows the research behind the guide: a publishing job (a publisher action,
// a publish command, one hop into a package.json script or a Makefile target, or OIDC plus a registry in a release
// workflow), the jobs whose artifacts it downloads (matched by name, directly or through one job in between), and
// zizmor's list of actions that restore caches.
import type { Finding, Status } from './types.ts';
import { actionMajor, actionName, grantsIdToken, readCompositeSteps, workflowOf } from './jobs.ts';
import type { Job, Step, Workflow } from './jobs.ts';
import { NPM_PUBLISH, SCRIPT_RUN, publishesToNpm } from './hops.ts';
import type { Hops } from './hops.ts';
import { finditer, re, search, splitLines } from './py.ts';
import { TooComplex } from './yaml-lite.ts';

/**
 * What follows a command on its line, up to the flag the command needs: at most 1000 characters, and never past the
 * same command again. Run from each start, a run that went on past the later ones took time squared on a line of the
 * command many times; stopping there finds the same commands, since the later start has the flag after it too.
 */
const upTo = (command: string) => String.raw`(?:(?!(?<=[\s;&|(/])${command})[^\n]){0,1000}`;
/**
 * A command that publishes a package, an image or a release. Dry runs and snapshot builds publish nothing: their flag
 * is looked for in the 200 characters after the command, so that each start looks at a few hundred characters.
 */
export const PUBLISH_RUN = re(
  String.raw`(?:^|[\s;&|(/])(?:(?:npm|pnpm)(?:\s+-[\w-]+(?:=\S+)?)*\s+(?:stage\s+)?publish\b|` +
    String.raw`yarn\s+npm\s+publish\b|twine\s+upload\b|` +
    String.raw`(?:uv|poetry|hatch|flit)\s+publish\b|maturin\s+(?:upload|publish)\b|cargo\s+publish\b|gem\s+push\b|` +
    String.raw`docker\s+(?:image\s+)?push\b|` +
    String.raw`docker\s+buildx\s+build\b${upTo(String.raw`docker\s+buildx\s+build\b`)}\s--push\b|` +
    String.raw`gh\s+release\s+(?:create|upload)\b|` +
    String.raw`goreleaser\s+release\b(?![^\n]{0,200}\s--(?:snapshot|skip-publish|skip[= ]publish))|` +
    String.raw`mvnw?\b${upTo(String.raw`mvnw?\b`)}(?<![\w.:-])deploy(?![\w.=-])|` +
    String.raw`gradlew?\b${upTo(String.raw`gradlew?\b`)}\bpublish(?!ToMavenLocal)\w*|` +
    String.raw`sbt\b${upTo(String.raw`sbt\b`)}(?:\bpublish(?!Local)\w*|\bci-release\b|\btlCiRelease\b)|semantic-release\b|` +
    String.raw`(?:dotnet\s+)?nuget\s+push\b)(?![^\n]{0,200}\s--dry-run\b)`,
);
/** A script file in the repository that a step runs (at the start of a command), which the scan doesn't read. */
const LOCAL_SCRIPT = re(
  String.raw`(?:^|[;&|(]|\b(?:then|do|exec))\s*(?:(?:bash|sh|zsh|node|python3?|ruby|perl|pwsh|tsx|bun|deno\s+run)\s+` +
    String.raw`(?:-\S+\s+)*)?(?:\./)?(?:[\w.-]+/)*[\w.-]+\.(?:sh|bash|js|mjs|cjs|ts|mts|py|rb|pl|ps1)\b`,
);
/** Script and target names that build or check, which don't publish when the scan can't read them. */
const NOT_PUBLISHING = new Set(
  ['install', 'test', 'tests', 'check', 'checks', 'lint', 'fmt', 'format', 'clean', 'typecheck', 'coverage'].concat([
    'bench',
    'benchmark',
    'build',
    'compile',
    'docs',
    'doc',
    'deps',
    'setup',
    'bootstrap',
    'dev',
    'prepare',
  ]),
);
/** A step condition that depends on what triggered the run (a tag, a release), so its cache may not run there. */
const RUNTIME_CONDITION = re(String.raw`ref_type|refs/tags|release|event_name`);
/** goreleaser-action arguments that build locally without publishing. */
const GORELEASER_LOCAL = re(String.raw`--snapshot|--skip[= ]?publish|^(?:build|check|healthcheck)\b`);

/** Publisher actions, by name in lower case. */
const PUBLISHERS = new Set([
  'pypa/gh-action-pypi-publish',
  'rubygems/release-gem',
  'jreleaser/release-action',
  'softprops/action-gh-release',
  'ncipollo/release-action',
  'googleapis/release-please-action',
  'google-github-actions/release-please-action',
  'redhat-actions/push-to-registry',
]);

/** A caching action that talks to the cache service itself, which may not honor cache-mode: none. */
const OWN_CACHE_CLIENT = new Set([
  'pyo3/maturin-action',
  'mozilla-actions/sccache-action',
  'determinatesystems/magic-nix-cache-action',
  'docker/build-push-action',
]);

/** An action input read as a switch: true, false, an expression (decided at run time), or missing. */
function flag(v: string | undefined): boolean | 'expr' | undefined {
  if (v === undefined) return undefined;
  const s = v.trim().toLowerCase();
  if (s.includes('${{')) return 'expr';
  if (['false', 'no', 'off', '0', '', 'null', '~'].includes(s)) return false;
  return true;
}

interface CacheUse {
  /** on: the step restores a cache; maybe: only in some cases (a default that depends on the project, a condition). */
  level: 'on' | 'maybe';
  what: string;
  step: Step;
}

/** Whether a step restores an Actions cache, and how sure that is (zizmor's list of cache-aware actions). */
export function cacheOf(step: Step, cacheModeNone = false): CacheUse | null {
  const name = actionName(step);
  if (!name) return null;
  const w = step.with;
  const set = (k: string) => w[k] !== undefined && w[k].trim() !== '';
  let level: 'on' | 'maybe' | null = null;
  let what = name;
  const pick = (f: boolean | 'expr' | undefined, dflt: boolean) => (f === 'expr' ? 'maybe' : (f ?? dflt) ? 'on' : null);
  switch (name) {
    case 'actions/cache':
    case 'actions/cache/restore':
    case 'swatinem/rust-cache':
      level = flag(w['lookup-only']) === true ? null : flag(w['lookup-only']) === 'expr' ? 'maybe' : 'on';
      break;
    case 'actions/setup-node':
      if (set('cache')) {
        level = flag(w.cache) === 'expr' ? 'maybe' : 'on';
        what = `actions/setup-node with cache: ${w.cache.trim()}`;
      } else if (flag(w['package-manager-cache']) !== false && !((actionMajor(step) ?? 99) < 5)) {
        // From v5, setup-node caches npm's packages unless told not to, when package.json names npm as its manager.
        level = 'maybe';
        what = 'actions/setup-node, which from v5 caches npm packages unless package-manager-cache is false';
      }
      break;
    case 'actions/setup-python':
    case 'actions/setup-java':
    case 'graalvm/setup-graalvm':
      if (set('cache')) {
        level = flag(w.cache) === 'expr' ? 'maybe' : 'on';
        what = `${name} with cache: ${w.cache.trim()}`;
      }
      break;
    case 'actions/setup-dotnet':
      level = pick(flag(w.cache), false);
      what = 'actions/setup-dotnet with cache: true';
      break;
    case 'actions/setup-go':
      level = pick(flag(w.cache), true);
      what = w.cache === undefined ? 'actions/setup-go, which caches by default' : 'actions/setup-go with cache on';
      break;
    case 'astral-sh/setup-uv': {
      const v = w['enable-cache']?.trim().toLowerCase();
      if (v === 'true') level = 'on';
      else if (v === undefined) level = (actionMajor(step) ?? 0) < 10 ? 'maybe' : null;
      else level = flag(v) === false ? null : 'maybe';
      what =
        level === 'on'
          ? 'astral-sh/setup-uv with enable-cache: true'
          : 'astral-sh/setup-uv, which caches on GitHub-hosted runners unless enable-cache is false';
      break;
    }
    case 'ruby/setup-ruby':
      level = pick(flag(w['bundler-cache']), false);
      what = 'ruby/setup-ruby with bundler-cache: true';
      break;
    case 'pyo3/maturin-action':
      level = pick(flag(w.sccache), false);
      what = 'PyO3/maturin-action with sccache: true';
      break;
    case 'mlugg/setup-zig':
      level = pick(flag(w['use-cache']), true);
      break;
    case 'oven-sh/setup-bun':
      level = flag(w['no-cache']) === true ? null : flag(w['no-cache']) === 'expr' ? 'maybe' : 'on';
      break;
    case 'pnpm/action-setup':
    case 'pnpm/setup':
      level = pick(flag(w.cache), false);
      what = `${name} with cache: true`;
      break;
    case 'determinatesystems/magic-nix-cache-action':
      level = pick(flag(w['use-gha-cache']), true);
      break;
    case 'gradle/actions/setup-gradle':
    case 'gradle/gradle-build-action':
      level = flag(w['cache-disabled']) === true ? null : flag(w['cache-disabled']) === 'expr' ? 'maybe' : 'on';
      break;
    case 'docker/setup-buildx-action':
      // It caches the buildx binary it downloads, which only happens for a pinned version.
      if (set('version')) level = pick(flag(w['cache-binary']), true);
      what = 'docker/setup-buildx-action, which caches the buildx binary';
      break;
    case 'actions-rust-lang/setup-rust-toolchain':
    case 'jdx/mise-action':
      level = pick(flag(w.cache), true);
      break;
    case 'mozilla-actions/sccache-action':
    case 'nix-community/cache-nix-action':
    case 'awalsh128/cache-apt-pkgs-action':
      level = 'on';
      break;
    case 'ramsey/composer-install':
      level = ['yes', 'true', '1'].includes((w['ignore-cache'] ?? '').trim().toLowerCase()) ? null : 'on';
      break;
    case 'docker/build-push-action':
      if ((w['cache-from'] ?? '').includes('type=gha')) level = 'on';
      what = 'docker/build-push-action with cache-from: type=gha';
      break;
  }
  if (!level) return null;
  if (cacheModeNone) {
    // cache-mode: none stops the cache toolkit; an action with its own cache client may not honor it.
    if (!OWN_CACHE_CLIENT.has(name)) return null;
    return { level: 'maybe', what: `${what}, which may ignore cache-mode: none`, step };
  }
  // A condition on the cache step itself, such as skipping it for tags, decides at run time.
  if (level === 'on' && step.if && search(RUNTIME_CONDITION, step.if)) level = 'maybe';
  return { level, what, step };
}

/** What a step does to publish, or null. */
export function publishOf(step: Step): string | null {
  const name = actionName(step);
  if (name) {
    if (PUBLISHERS.has(name)) return name;
    if (name === 'goreleaser/goreleaser-action') {
      return search(GORELEASER_LOCAL, (step.with.args ?? '').trim()) ? null : name;
    }
    if (name === 'docker/build-push-action') return flag(step.with.push) ? `${name} with push` : null;
    if (name === 'changesets/action') return step.with.publish?.trim() ? `${name} with publish` : null;
    if (name === 'pyo3/maturin-action') {
      const cmd = (step.with.command ?? '').trim().toLowerCase();
      return cmd === 'upload' || cmd === 'publish' ? `${name} with command: ${cmd}` : null;
    }
    return null;
  }
  for (const line of splitLines(step.run ?? '')) {
    if (line.trimStart().startsWith('#')) continue;
    const m = search(PUBLISH_RUN, line);
    if (m) return command(m[0]);
  }
  return null;
}

/** A matched command without the separator the pattern matched before it. */
function command(match: string): string {
  let t = match.trim();
  while (t && ';&|(/'.includes(t[0])) t = t.slice(1).trimStart();
  return t;
}

/** A local path ("./.github/actions/x/") as the tree lists it (".github/actions/x"). */
function localPath(uses: string): string {
  let p = uses.split('@')[0];
  if (p.startsWith('./')) p = p.slice(2);
  while (p.endsWith('/')) p = p.slice(0, -1);
  return p;
}

/**
 * A value with its ${{ env.NAME }} expressions replaced by the fixed values of an env (its entries without
 * expressions), one name after another. Only the names in the value are tried: a job can set thousands.
 */
function withEnv(value: string | undefined, fixed: [string, string][]): string | null {
  let v = value?.trim();
  if (!v) return null;
  if (!v.includes('env.')) return v;
  for (const [k, x] of fixed) {
    if (!v.includes(k)) continue;
    for (const form of [`\${{ env.${k} }}`, `\${{env.${k}}}`]) v = v.replaceAll(form, x);
  }
  return v;
}

/** An env's entries whose values hold no expression, in order. */
const fixedEntries = (env: Record<string, string>): [string, string][] =>
  Object.entries(env).filter(([, x]) => !x.includes('${{'));

/**
 * The artifacts a step uploads or downloads, with env (the workflow's and job's, as fixed: its fixedEntries) and the
 * step's own filled in to their names.
 */
function artifactsOf(
  step: Step,
  env: Record<string, string>,
  fixed = fixedEntries(env),
): { uploads: string[]; downloads: Download[] } {
  const name = actionName(step);
  const all = () => (Object.keys(step.env).length ? fixedEntries({ ...env, ...step.env }) : fixed);
  if (name === 'actions/upload-artifact') {
    return { uploads: [withEnv(step.with.name, all()) || 'artifact'], downloads: [] };
  }
  if (name === 'actions/download-artifact') {
    const w = step.with;
    const both = all();
    const other = ['run-id', 'github-token', 'repository'].some((k) => (w[k] ?? '').trim() !== '');
    return {
      uploads: [],
      downloads: [{ name: withEnv(w.name, both), pattern: withEnv(w.pattern, both), otherRun: other, step }],
    };
  }
  if (name === 'dawidd6/action-download-artifact') {
    return { uploads: [], downloads: [{ name: null, pattern: null, otherRun: true, step }] };
  }
  return { uploads: [], downloads: [] };
}

interface Download {
  name: string | null;
  pattern: string | null;
  otherRun: boolean;
  step: Step;
}

/** An artifact name for a summary: each ${{ }} expression as *. */
function shortName(name: string): string {
  let out = asGlob(name);
  while (out.includes('**')) out = out.replaceAll('**', '*');
  return out;
}

/**
 * A glob with * and ? against a name, with the usual two-pointer method: on a mismatch, the last * takes one more
 * character. At most the product of the lengths, where trying every split for each * took exponential time.
 */
export function globMatch(glob: string, name: string): boolean {
  let g = 0;
  let n = 0;
  let star = -1;
  let from = 0;
  while (n < name.length) {
    if (g < glob.length && glob[g] === '*') {
      star = g++;
      from = n;
    } else if (g < glob.length && (glob[g] === '?' || glob[g] === name[n])) {
      g++;
      n++;
    } else if (star >= 0) {
      g = star + 1;
      n = ++from;
    } else return false;
  }
  while (g < glob.length && glob[g] === '*') g++;
  return g === glob.length;
}

/** An artifact name with ${{ }} expressions read as wildcards. */
function asGlob(name: string): string {
  let out = '';
  for (let k = 0; k < name.length; k++) {
    if (name.startsWith('${{', k)) {
      const close = name.indexOf('}}', k);
      if (close < 0) return out + '*';
      out += '*';
      k = close + 1;
    } else out += name[k];
  }
  return out;
}

/**
 * Whether a download takes an upload: yes (by its name or pattern), all (a download without either takes every
 * artifact), no, or unknown (the download's name is decided at run time).
 */
function takes(d: Download, upload: string): 'yes' | 'all' | 'no' | 'unknown' {
  if (!d.name && !d.pattern) return 'all';
  const want = (d.name ?? d.pattern)!;
  if (want.includes('${{')) return asGlob(want) === asGlob(upload) ? 'yes' : 'unknown';
  if (upload.includes('${{')) {
    const filled = asGlob(upload).replaceAll('*', 'x');
    return globMatch(asGlob(upload), want) || (d.pattern !== null && globMatch(want, filled)) ? 'yes' : 'no';
  }
  return (d.pattern !== null ? globMatch(want, upload) : want === upload) ? 'yes' : 'no';
}

export interface CacheCheckInput {
  /** The workflows that could be read. */
  workflows: { path: string; text: string }[];
  /** Workflow files that couldn't be read, and why ("HTTP 500", "larger than 2 MB"). */
  unread: { path: string; why: string }[];
  /** Every file in the tree, for finding local actions, package.json and the Makefile. */
  files: string[];
  /** Whether the file tree could be listed at all. */
  treeRead: boolean;
  /** Read a file in the repository (null if it can't be read). */
  read: (path: string) => Promise<string | null>;
  /** One hop into package.json scripts and Makefile targets. */
  hops: Hops;
}

export interface CacheCheckResult {
  status: Status;
  summary: string;
  /** Files to link as evidence. */
  evidence: string[];
  details: Record<string, unknown>;
  findings: Omit<Finding, 'item_id' | 'url'>[];
}

/** A job in a run: a workflow's own, or one of a local reusable workflow it calls. */
interface Node {
  wf: Workflow;
  job: Job;
  /** The job that calls this one's workflow, for a job of a local reusable workflow. */
  via: Node | null;
  /** Its steps, with those of the local composite actions it uses once they've been read. */
  steps: Step[];
  expanded: boolean;
  /** Local actions in the job that the scan couldn't read. */
  opaque: string[];
}

interface Problem {
  level: 'fail' | 'warn';
  summary: string;
  finding: CacheCheckResult['findings'][number];
}

const MAX_ACTION_FILES = 10;
/** At most this many steps of local composite actions are read into the jobs that use them, in all. */
const MAX_ACTION_STEPS = 50_000;
/**
 * The work the check may do, in steps read, characters of scripts (16 to a unit), jobs waited for and artifacts
 * compared: about 20 times what the largest real repository needs, and a few hundred milliseconds. A hostile workflow (thousands of jobs that each need the last, or
 * upload and download thousands of artifacts) gets unknown instead of an hour of matching.
 */
const MAX_WORK = 4_000_000;
const CACHE_HINT =
  "Set cache-mode: none on the job and turn off the action's own cache input (for setup-node, package-manager-cache: false)";

export async function releaseCacheCheck(input: CacheCheckInput): Promise<CacheCheckResult> {
  const result = (
    status: Status,
    summary: string,
    evidence: string[] = [],
    details: Record<string, unknown> = {},
    findings: CacheCheckResult['findings'] = [],
  ): CacheCheckResult => ({ status, summary, evidence, details, findings });
  if (!input.treeRead) return result('unknown', "Could not list the repository's files, so the workflows weren't read");
  if (!input.workflows.length && !input.unread.length) return result('na', 'No GitHub Actions workflows');
  try {
    return await check(input, result);
  } catch (e) {
    if (!(e instanceof TooComplex)) throw e;
    return result('unknown', `Could not trace the release jobs: ${e.message}`);
  }
}

async function check(
  input: CacheCheckInput,
  result: (
    status: Status,
    summary: string,
    evidence?: string[],
    details?: Record<string, unknown>,
    findings?: CacheCheckResult['findings'],
  ) => CacheCheckResult,
): Promise<CacheCheckResult> {
  let work = MAX_WORK;
  const spend = (n: number) => {
    work -= n;
    if (work < 0) throw new TooComplex('the workflows have too many jobs, steps and artifacts to trace');
  };
  const wfs = input.workflows.map(workflowOf);
  const byPath = new Map(wfs.map((w) => [w.path, w]));
  const files = new Set(input.files);

  // ---- local composite actions, each read once, and at most MAX_ACTION_FILES of them
  const actionFiles = new Map<string, Promise<Step[] | null>>();
  const actionSteps = (uses: string): Promise<Step[] | null> => {
    const dir = localPath(uses);
    const file = [`${dir}/action.yml`, `${dir}/action.yaml`].find((p) => files.has(p));
    if (!file) return Promise.resolve(null);
    if (!actionFiles.has(file)) {
      if (actionFiles.size >= MAX_ACTION_FILES) return Promise.resolve(null);
      // An action file too deep or too big to read is one the scan couldn't read, like one it couldn't download.
      const steps = (body: string | null) => {
        try {
          return body === null ? null : readCompositeSteps(file, body);
        } catch (e) {
          if (e instanceof TooComplex) return null;
          throw e;
        }
      };
      actionFiles.set(file, input.read(file).then(steps));
    }
    return actionFiles.get(file)!;
  };
  /**
   * Steps with the steps of their local composite actions after them (two levels deep), and the actions not read.
   * Past MAX_ACTION_STEPS steps of actions in all, an action counts as one the scan couldn't read.
   */
  let actionStepsLeft = MAX_ACTION_STEPS;
  const expandSteps = async (steps: Step[], depth = 0): Promise<{ steps: Step[]; opaque: string[] }> => {
    const out: Step[] = [];
    const opaque: string[] = [];
    for (const s of steps) {
      out.push(s);
      if (!s.uses?.startsWith('./')) continue;
      const inner = depth < 2 ? await actionSteps(s.uses) : null;
      if (!inner || inner.length > actionStepsLeft) {
        opaque.push(s.uses);
        continue;
      }
      actionStepsLeft -= inner.length;
      spend(inner.length);
      const deeper = await expandSteps(inner, depth + 1);
      for (const x of deeper.steps) out.push(x);
      for (const x of deeper.opaque) opaque.push(x);
    }
    return { steps: out, opaque };
  };
  const expand = async (n: Node) => {
    if (n.expanded) return;
    n.expanded = true;
    const ex = await expandSteps(n.job.steps);
    n.steps = ex.steps;
    n.opaque = ex.opaque;
  };

  const hop = (tool: string, target: string) => input.hops.body(tool, target);
  /**
   * The publish command in the script or target a step runs, read once for each (a workflow can run one target
   * thousands of times). npm run publish (or pnpm's or yarn's) counts only when the script publishes to npm; any other
   * script counts when it runs a publish command.
   */
  const hopRuns = new Map<string, Promise<{ body: string | null | undefined; ran: RegExpExecArray | null }>>();
  const ranBy = (tool: string, target: string) => {
    const k = `${tool} ${target}`;
    if (!hopRuns.has(k)) {
      hopRuns.set(
        k,
        hop(tool, target).then((body) => {
          const npmScript = tool !== 'make' && target === 'publish';
          const ran =
            typeof body !== 'string'
              ? null
              : npmScript
                ? publishesToNpm(body)
                  ? search(NPM_PUBLISH, body)
                  : null
                : (search(PUBLISH_RUN, body) ?? search(NPM_PUBLISH, body));
          return { body, ran };
        }),
      );
    }
    return hopRuns.get(k)!;
  };

  /** Why a job publishes, or what it runs that the scan couldn't follow. */
  const publishing = async (n: Node): Promise<{ why: string | null; unresolved: string[] }> => {
    const unresolved: string[] = [];
    for (const s of n.steps) {
      spend(1 + ((s.run?.length ?? 0) >> 4));
      const why = publishOf(s);
      if (why) return { why, unresolved };
    }
    for (const s of n.steps) {
      spend(1 + ((s.run?.length ?? 0) >> 4));
      for (const line of splitLines(s.run ?? '')) {
        if (line.trimStart().startsWith('#')) continue;
        for (const m of finditer(SCRIPT_RUN, line)) {
          const tool = m[1].split(' ')[0];
          const { body, ran } = await ranBy(tool, m[2]);
          if (ran) return { why: `${m[1]} ${m[2]}, which runs ${command(ran[0])}`, unresolved };
          // A bare "pnpm X" or "yarn X" is often a built-in command, so only a named script counts.
          const named = (m[1].includes(' ') || tool === 'make') && !NOT_PUBLISHING.has(m[2].toLowerCase());
          if (body === undefined ? named : body === null && named) {
            unresolved.push(`runs ${m[1]} ${m[2]}, which the scan couldn't follow`);
          }
        }
        const script = search(LOCAL_SCRIPT, line);
        if (script) unresolved.push(`runs ${command(script[0])}, which the scan doesn't read`);
      }
    }
    // OIDC and a registry set up in a release workflow: trusted publishing, even when the command isn't recognized.
    const release = n.wf.triggers.includes('release') || n.wf.tagPush;
    const registry =
      n.steps.some((s) => actionName(s) === 'actions/setup-node' && (s.with['registry-url'] ?? '').trim() !== '') ||
      [n.job.env, n.wf.env, ...n.steps.map((s) => s.env)].some((e) => 'NPM_CONFIG_PROVENANCE' in e);
    if (release && registry && grantsIdToken(n.job, n.wf)) {
      return { why: 'id-token: write with a registry set up, in a release workflow', unresolved };
    }
    unresolved.push(...n.opaque.map((a) => `uses ${a}, which the scan couldn't read`));
    return { why: null, unresolved };
  };

  // ---- the runs: each workflow, with the jobs of the local reusable workflows it calls
  const callee = (j: Job) => (j.uses?.startsWith('./') ? byPath.get(localPath(j.uses)) : undefined);
  const calledLocally = new Set(wfs.flatMap((w) => w.jobs.map(callee)).filter((w) => w));
  const runs: Node[][] = [];
  for (const wf of wfs) {
    if (!wf.ok) continue;
    // A reusable workflow called from this repo is checked as part of each run that calls it.
    if (wf.triggers.every((t) => t === 'workflow_call') && calledLocally.has(wf)) continue;
    const nodes: Node[] = [];
    for (const job of wf.jobs) {
      const own: Node = { wf, job, via: null, steps: job.steps, expanded: false, opaque: [] };
      nodes.push(own);
      const sub = callee(job);
      if (sub && sub !== wf) {
        for (const cj of sub.jobs)
          nodes.push({ wf: sub, job: cj, via: own, steps: cj.steps, expanded: false, opaque: [] });
      }
    }
    runs.push(nodes);
  }

  const problems: Problem[] = [];
  const publishers: { node: Node; why: string }[] = [];
  /** What the scan couldn't see on a release path, each a sentence for an info result. */
  const unseen: string[] = [];
  /** Release workflows the scan read in full that it found no publishing in, and what they run that it can't read. */
  const quiet: string[] = [];
  const evidence = new Set<string>();
  const cacheModeNone = (n: Node) => (n.job.cacheMode ?? n.wf.cacheMode)?.trim().toLowerCase() === 'none';
  const label = (n: Node) => `${n.job.id} in ${n.wf.path}`;
  /** Each job's caches, worked out once (a job is asked about once for each publishing job it's on the way to). */
  const cached = new Map<Node, CacheUse[]>();
  const cachesOf = (n: Node) => {
    let got = cached.get(n);
    if (!got) {
      spend(n.steps.length);
      got = n.steps.map((s) => cacheOf(s, cacheModeNone(n))).filter((c): c is NonNullable<typeof c> => c !== null);
      cached.set(n, got);
    }
    return got;
  };

  for (const nodes of runs) {
    const wf = nodes[0]?.wf;
    if (!wf) continue;
    const releaseTriggered = wf.triggers.includes('release') || wf.tagPush;
    // Which jobs publish, and which jobs of a release workflow might, through something the scan can't follow.
    // Local actions are read for every job of a release workflow, and for publishing jobs.
    const found = new Map<Node, string>();
    const maybe = new Map<Node, string>();
    const remoteCalls: string[] = [];
    for (const n of nodes) {
      if (n.job.uses && !n.job.uses.startsWith('./')) {
        if (releaseTriggered) remoteCalls.push(n.job.uses);
        continue;
      }
      if (releaseTriggered) await expand(n);
      let p = await publishing(n);
      if (p.why && !n.expanded) {
        await expand(n);
        p = await publishing(n);
      }
      if (p.why) found.set(n, p.why);
      else if (releaseTriggered && p.unresolved.length) maybe.set(n, p.unresolved[0]);
    }
    // A remote reusable workflow may be where a release workflow publishes, unless a job the scan can read does.
    // When one does, the remote workflow matters only if it builds what that job publishes (checked below).
    if (!found.size && remoteCalls.length) {
      unseen.push(`release workflow ${wf.path} calls ${remoteCalls[0]}, which the scan can't read`);
      evidence.add(wf.path);
    }
    if (!found.size && !maybe.size) {
      if (releaseTriggered && !remoteCalls.length) {
        quiet.push(`release workflow ${wf.path} has no step the scan recognizes as publishing`);
        evidence.add(wf.path);
      }
      continue;
    }
    // Every job of the run, with its local actions, so artifacts uploaded there are seen too.
    for (const n of nodes) if (!n.job.uses) await expand(n);

    // ---- the run's job graph: what each job waits for, through local reusable workflows
    const key = (path: string, id: string, via: Node | null) => `${path}#${id}#${via ? via.job.id : ''}`;
    const index = new Map(nodes.map((n) => [key(n.wf.path, n.job.id, n.via), n]));
    const called = new Map<Node, Node[]>();
    for (const m of nodes) {
      if (!m.via) continue;
      const list = called.get(m.via);
      if (list) list.push(m);
      else called.set(m.via, [m]);
    }
    const needsOf = (n: Node): Node[] => {
      const out: Node[] = [];
      for (const id of n.job.needs) {
        const dep = index.get(key(n.wf.path, id, n.via));
        if (!dep) continue;
        out.push(dep);
        // Needing a job that calls a reusable workflow waits for all of that workflow's jobs.
        for (const m of called.get(dep) ?? []) out.push(m);
      }
      if (n.via) for (const m of needsOf(n.via)) out.push(m);
      spend(1 + out.length);
      return out;
    };
    // Every job n waits for, directly or not. Without recursion: a chain of jobs that each need the one before is as
    // deep as it is long. A job is added to the set before the jobs it waits for, as a recursive walk would.
    const ancestry = new Map<Node, Set<Node>>();
    const ancestors = (n: Node): Set<Node> => {
      if (ancestry.has(n)) return ancestry.get(n)!;
      ancestry.set(n, new Set());
      const stack = [{ node: n, deps: needsOf(n), next: 0, entered: false }];
      while (stack.length) {
        const top = stack[stack.length - 1];
        const got = ancestry.get(top.node)!;
        if (top.next >= top.deps.length) {
          stack.pop();
          continue;
        }
        const d = top.deps[top.next];
        if (!top.entered) {
          top.entered = true;
          got.add(d);
          if (!ancestry.has(d)) {
            ancestry.set(d, new Set());
            stack.push({ node: d, deps: needsOf(d), next: 0, entered: false });
            continue;
          }
        }
        const theirs = ancestry.get(d)!;
        spend(1 + theirs.size);
        for (const a of theirs) got.add(a);
        top.next++;
        top.entered = false;
      }
      return ancestry.get(n)!;
    };
    /** Each job's uploads and downloads, worked out once. */
    const ios = new Map<Node, { uploads: string[]; downloads: Download[] }>();
    const io = (n: Node) => {
      let got = ios.get(n);
      if (got) return got;
      got = { uploads: [], downloads: [] };
      const env = { ...n.wf.env, ...n.job.env };
      const fixed = fixedEntries(env);
      spend(1 + fixed.length);
      for (const s of n.steps) {
        // An upload or download fills its names in from the env, merged with the step's own (artifactsOf): a few
        // units for each name it merges or tries.
        const own = Object.keys(s.env).length;
        const tries = (x?: string) => (x?.includes('env.') ? fixed.length + own : 0);
        const artifact = actionName(s)?.endsWith('-artifact');
        spend(1 + (artifact ? (own ? 8 * (fixed.length + own) : 0) + tries(s.with.name) + tries(s.with.pattern) : 0));
        const a = artifactsOf(s, env, fixed);
        for (const x of a.uploads) got.uploads.push(x);
        for (const x of a.downloads) got.downloads.push(x);
      }
      ios.set(n, got);
      return got;
    };
    /** The jobs whose artifacts n downloads in its own run (strong: by name or pattern), and what it can't trace. */
    const fed = new Map<Node, ReturnType<typeof feedersOf>>();
    const feeders = (n: Node) => {
      let got = fed.get(n);
      if (!got) fed.set(n, (got = feedersOf(n)));
      return got;
    };
    const feedersOf = (n: Node) => {
      const out: { node: Node; strong: boolean; artifact: string }[] = [];
      const untraced: Download[] = [];
      for (const d of io(n).downloads) {
        if (d.otherRun) continue;
        let linked = false;
        const want = (d.name ?? d.pattern ?? '').length;
        for (const m of ancestors(n)) {
          for (const up of io(m).uploads) {
            // Matching a glob against a name takes at most the product of their lengths.
            spend(1 + ((want * up.length) >> 6));
            const t = takes(d, up);
            if (t === 'yes' || t === 'all') {
              out.push({ node: m, strong: t === 'yes', artifact: up });
              linked = true;
            }
          }
        }
        if (!linked) untraced.push(d);
      }
      return { out, untraced };
    };
    /**
     * The jobs that build what n uses, directly or through one job in between, each job, artifact and strength once:
     * what's said about a link depends on nothing else, and a hostile run repeats them many times over.
     */
    const chainOf = (n: Node) => {
      const first = feeders(n);
      const chain: { node: Node; strong: boolean; artifact: string }[] = [];
      const seen = new Map<Node, Set<string>>();
      const add = (node: Node, strong: boolean, artifact: string) => {
        spend(1);
        if (node === n) return;
        const k = `${strong} ${artifact}`;
        const got = seen.get(node);
        if (got?.has(k)) return;
        if (got) got.add(k);
        else seen.set(node, new Set([k]));
        chain.push({ node, strong, artifact });
      };
      for (const f of first.out) add(f.node, f.strong, f.artifact);
      // Through the same job, as strongly, the second step adds the same links again.
      const through = new Map<Node, Set<boolean>>();
      for (const f of first.out) {
        const got = through.get(f.node);
        if (got?.has(f.strong)) continue;
        if (got) got.add(f.strong);
        else through.set(f.node, new Set([f.strong]));
        for (const g of feeders(f.node).out) add(g.node, f.strong && g.strong, g.artifact);
      }
      return { chain, untraced: first.untraced };
    };

    // A job that may publish through a script the scan doesn't read matters only if a cache is on its path.
    for (const [n, what] of maybe) {
      const { chain } = chainOf(n);
      const cached = [...cachesOf(n), ...chain.flatMap((f) => cachesOf(f.node))][0];
      const opaque = [n, ...chain.map((f) => f.node)].find((m) => m.opaque.length);
      if (cached) {
        unseen.push(`job ${label(n)} ${what}, and a cache is restored on its way (${cached.what})`);
        evidence.add(n.wf.path);
      } else if (opaque) {
        unseen.push(`job ${label(opaque)} uses ${opaque.opaque[0]}, which the scan couldn't read`);
      } else {
        quiet.push(`release workflow ${n.wf.path} ${what}; no cache is restored on its way`);
        evidence.add(n.wf.path);
      }
    }

    for (const [p, why] of found) {
      publishers.push({ node: p, why });
      evidence.add(p.wf.path);
      if (p.opaque.length) unseen.push(`publishing job ${label(p)} uses ${p.opaque[0]}, which the scan couldn't read`);
      for (const c of cachesOf(p)) {
        const sure = c.level === 'on';
        problems.push({
          level: sure ? 'fail' : 'warn',
          summary: `publishing job ${label(p)} ${sure ? 'restores' : 'may restore'} a cache (${c.what})`,
          finding: {
            severity: sure ? 'medium' : 'low',
            title: `${sure ? 'Restores' : 'May restore'} a cache in publishing job ${p.job.id}: ${c.what}`,
            path: c.step.file,
            line: c.step.usesLine,
            hint: CACHE_HINT,
          },
        });
      }
      // Artifacts from another run were built where this run didn't look. workflow_run is ci-dangerous-triggers' job.
      if (!p.wf.triggers.includes('workflow_run')) {
        for (const d of io(p).downloads.filter((x) => x.otherRun)) {
          problems.push({
            level: 'warn',
            summary: `publishing job ${label(p)} downloads artifacts from another workflow run`,
            finding: {
              severity: 'low',
              title: `Publishing job ${p.job.id} downloads artifacts from another workflow run`,
              path: d.step.file,
              line: d.step.usesLine,
              hint: 'Build what you publish in the release workflow itself, from the tagged commit',
            },
          });
        }
      }
      const { chain, untraced } = chainOf(p);
      for (const f of chain) {
        evidence.add(f.node.wf.path);
        if (f.node.opaque.length)
          unseen.push(`job ${label(f.node)} uses ${f.node.opaque[0]}, which the scan couldn't read`);
        for (const c of cachesOf(f.node)) {
          const sure = c.level === 'on' && f.strong;
          problems.push({
            level: sure ? 'fail' : 'warn',
            summary:
              `job ${label(f.node)} ${c.level === 'on' ? 'restores' : 'may restore'} a cache (${c.what}) and builds ` +
              `artifact ${shortName(f.artifact)}, which goes into what ${p.job.id} publishes`,
            finding: {
              severity: sure ? 'medium' : 'low',
              title:
                `${c.level === 'on' ? 'Restores' : 'May restore'} a cache in job ${f.node.job.id}, whose artifact ` +
                `${shortName(f.artifact)} goes into what ${p.job.id} publishes: ${c.what}`,
              path: c.step.file,
              line: c.step.usesLine,
              hint: CACHE_HINT,
            },
          });
        }
      }
      // A download it couldn't trace to a job, in a run where another job restores a cache.
      if (untraced.length) {
        const other = nodes.filter((m) => m !== p).find((m) => cachesOf(m).length);
        const remote = [...ancestors(p)].find((m) => m.job.uses && !m.job.uses.startsWith('./'));
        if (other) {
          const d = untraced[0];
          problems.push({
            level: 'warn',
            summary:
              `publishing job ${label(p)} downloads an artifact the scan can't trace to a job, and ${other.job.id} ` +
              `in the same run restores a cache (${cachesOf(other)[0].what})`,
            finding: {
              severity: 'low',
              title: `Publishing job ${p.job.id} downloads an artifact the scan can't trace to the job that built it`,
              path: d.step.file,
              line: d.step.usesLine,
              hint: 'Name the artifacts you publish, and keep caches out of the jobs that build them',
            },
          });
        } else if (remote) {
          unseen.push(
            `publishing job ${label(p)} downloads artifacts that ${remote.job.uses} may build, which the scan can't read`,
          );
        }
      }
    }
  }

  const details = {
    publishing_jobs: publishers.map((x) => ({ workflow: x.node.wf.path, job: x.node.job.id, why: x.why })),
  };
  // One finding per step, however many publishing jobs it's on the way to: a composite action several jobs use is
  // one thing to fix. A step that fails for one job and only warns for another stays a failure.
  const seen = new Set<string>();
  const once = (xs: Problem[]) =>
    xs.filter((x) => {
      const k = `${x.finding.path}:${x.finding.line}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  const fails = once(problems.filter((x) => x.level === 'fail'));
  const warns = once(problems.filter((x) => x.level === 'warn'));
  const findings = [...fails, ...warns].map((x) => x.finding);
  const ev = [...evidence].slice(0, 5);
  const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
  const more = (n: number, what: string) => (n > 1 ? `; ${n - 1} more ${what}${n > 2 ? 's' : ''} in the findings` : '');
  if (fails.length) return result('fail', cap(fails[0].summary) + more(fails.length, 'cache'), ev, details, findings);
  if (warns.length) return result('warn', cap(warns[0].summary) + more(warns.length, 'risk'), ev, details, findings);
  // Nothing found so far; a workflow that couldn't be read may hold it.
  if (input.unread.length) {
    const u = input.unread[0];
    const others = input.unread.length - 1;
    return result(
      'unknown',
      `Could not read ${u.path} (${u.why})` +
        (others ? ` and ${others} more workflow file${others > 1 ? 's' : ''}` : ''),
      ev,
      details,
    );
  }
  if (unseen.length) {
    return result(
      'info',
      cap(unseen[0]) + (publishers.length ? '. The publishing jobs it can read restore no caches' : ''),
      ev,
      details,
    );
  }
  if (publishers.length) {
    const first = publishers[0].node;
    const none = publishers.every((x) => cacheModeNone(x.node));
    return result(
      'pass',
      (publishers.length === 1
        ? `Publishing job ${label(first)} restores no cache`
        : `${publishers.length} publishing jobs restore no caches, such as ${label(first)}`) +
        (none ? ' (cache-mode: none)' : ''),
      ev,
      details,
    );
  }
  if (quiet.length) return result('info', cap(quiet[0]), ev, details);
  return result('na', 'No publishing job or release workflow', [], details);
}
