// A workflow's jobs and steps, read with yaml-lite.ts: what the checks that look inside a job need (its triggers,
// needs, permissions, cache-mode, and each step's uses, with, env and run). New in 0.5.0.
import { splitLines } from './py.ts';
import { at, entry, list, readYaml, strings, text } from './yaml-lite.ts';
import type { YNode } from './yaml-lite.ts';

export interface Step {
  /** The file the step is in: the workflow, or a local composite action it uses. */
  file: string;
  /** 1-based lines: the step's first line, and those of its uses: and run: keys (or the first line otherwise). */
  line: number;
  usesLine: number;
  runLine: number;
  /** The 1-based line of the script's first line: the one after "run: |", or the run: line itself. */
  runFirst: number;
  /** The action, as written ("actions/setup-node@v5"), and the comment after it, such as "# v5.0.0". */
  uses: string | null;
  comment: string;
  with: Record<string, string>;
  env: Record<string, string>;
  run: string | null;
  shell: string | null;
  if: string | null;
  /** Every scalar in the step (its uses, with, env, run, shell and name), for references such as secrets.X. */
  all: string;
}

export interface Job {
  id: string;
  /** 1-based line of the job's key. */
  line: number;
  needs: string[];
  /** A reusable workflow the job calls instead of running steps, and its inputs. */
  uses: string | null;
  with: Record<string, string>;
  cacheMode: string | null;
  /** The job's permissions block, or null when it has none (it then gets the workflow's). */
  permissions: YNode | null;
  env: Record<string, string>;
  if: string | null;
  steps: Step[];
  /** Every scalar in the job outside its steps (strategy, matrix, runs-on...), as text. */
  extra: string;
}

export interface Workflow {
  path: string;
  /** False when the file isn't a mapping with jobs. */
  ok: boolean;
  triggers: string[];
  /** A push trigger with tags (or tags-ignore). */
  tagPush: boolean;
  cacheMode: string | null;
  permissions: YNode | null;
  env: Record<string, string>;
  jobs: Job[];
}

/**
 * Every scalar under a node, joined by newlines. readYaml() keeps a document's aliases from expanding past a few
 * times its size, and its depth under MAX_DEPTH, so this takes time in proportion to the file.
 */
export function flatten(node: YNode | null | undefined): string {
  if (!node) return '';
  if (node.kind === 'scalar') return node.text;
  if (node.kind === 'seq') return node.items.map(flatten).join('\n');
  return node.entries.map((e) => `${e.key}: ${flatten(e.value)}`).join('\n');
}

/** The comment on a line (what follows " #"), trimmed. */
function lineComment(lines: string[], i: number): string {
  const s = lines[i] ?? '';
  for (let k = 1; k < s.length; k++) {
    if (s[k] === '#' && (s[k - 1] === ' ' || s[k - 1] === '\t')) return s.slice(k + 1).trim();
  }
  return '';
}

/** Whether a key's value is a block scalar ("run: |", "run: >-"), whose text starts on the next line. */
function blockScalar(line: string): boolean {
  const colon = line.indexOf(':');
  const rest = colon < 0 ? '' : line.slice(colon + 1).trimStart();
  return rest[0] === '|' || rest[0] === '>';
}

/** The steps in a sequence node, as Steps of file. */
export function stepsOf(node: YNode | null, file: string, lines: string[]): Step[] {
  if (!node || node.kind !== 'seq') return [];
  return node.items
    .filter((s) => s.kind === 'map')
    .map((s) => {
      const uses = entry(s, 'uses');
      const run = entry(s, 'run');
      return {
        file,
        line: s.line + 1,
        usesLine: (uses?.line ?? s.line) + 1,
        runLine: (run?.line ?? s.line) + 1,
        runFirst: (run?.line ?? s.line) + 1 + (run && blockScalar(lines[run.line] ?? '') ? 1 : 0),
        uses: text(uses?.value),
        comment: uses ? lineComment(lines, uses.line) : '',
        with: strings(at(s, 'with')),
        env: strings(at(s, 'env')),
        run: text(run?.value),
        shell: text(at(s, 'shell')),
        if: text(at(s, 'if')),
        all: flatten(s),
      };
    });
}

/** The trigger names under on: (a name, a list of names, or a mapping of them). */
function triggersOf(on: YNode | null): string[] {
  if (!on) return [];
  if (on.kind === 'map') return on.entries.map((e) => e.key);
  return list(on);
}

/**
 * Read a workflow file. A file that isn't a mapping with jobs comes back with ok false and no jobs. Throws TooComplex
 * for a file that nests too deep, or is too big with its aliases expanded, to read.
 */
export function readWorkflow(path: string, source: string): Workflow {
  const doc = readYaml(source);
  const lines = splitLines(source);
  const on = at(doc, 'on');
  const push = on && on.kind === 'map' ? at(on, 'push') : null;
  const jobsNode = at(doc, 'jobs');
  const jobs: Job[] =
    jobsNode && jobsNode.kind === 'map'
      ? jobsNode.entries
          .filter((e) => e.value.kind === 'map')
          .map((e) => {
            const j = e.value;
            const needs = at(j, 'needs');
            const rest = j.kind === 'map' ? j.entries.filter((x) => x.key !== 'steps') : [];
            return {
              id: e.key,
              line: e.line + 1,
              needs: list(needs),
              uses: text(at(j, 'uses')),
              with: strings(at(j, 'with')),
              cacheMode: text(at(j, 'cache-mode')),
              permissions: at(j, 'permissions'),
              env: strings(at(j, 'env')),
              if: text(at(j, 'if')),
              steps: stepsOf(at(j, 'steps'), path, lines),
              extra: rest.map((x) => `${x.key}: ${flatten(x.value)}`).join('\n'),
            };
          })
      : [];
  return {
    path,
    ok: !!doc && doc.kind === 'map' && !!jobsNode && jobsNode.kind === 'map',
    triggers: triggersOf(on),
    tagPush: !!push && push.kind === 'map' && (!!at(push, 'tags') || !!at(push, 'tags-ignore')),
    cacheMode: text(at(doc, 'cache-mode')),
    permissions: at(doc, 'permissions'),
    env: strings(at(doc, 'env')),
    jobs,
  };
}

const parsed = new WeakMap<{ path: string; text: string }, Workflow>();

/** readWorkflow(w.path, w.text), once for each file the scan read: it hands the same objects to every check. */
export function workflowOf(w: { path: string; text: string }): Workflow {
  let wf = parsed.get(w);
  if (!wf) parsed.set(w, (wf = readWorkflow(w.path, w.text)));
  return wf;
}

/**
 * The steps of a local composite action (runs.using: composite), or null for any other action file. Throws
 * TooComplex, as readWorkflow does.
 */
export function readCompositeSteps(path: string, source: string): Step[] | null {
  const doc = readYaml(source);
  const runs = at(doc, 'runs');
  if (text(at(runs, 'using'))?.toLowerCase() !== 'composite') return null;
  return stepsOf(at(runs, 'steps'), path, splitLines(source));
}

/** Whether a permissions block (a job's, or else its workflow's) gives the token id-token: write. */
export function grantsIdToken(job: Job, wf: Workflow): boolean {
  const p = job.permissions ?? wf.permissions;
  if (!p) return false;
  if (p.kind === 'scalar') return p.text.trim() === 'write-all';
  return text(at(p, 'id-token'))?.trim() === 'write';
}

/** The action's name without its ref, in lower case ("actions/setup-node"), or null for a run step. */
export function actionName(step: Step): string | null {
  if (!step.uses) return null;
  const at = step.uses.indexOf('@');
  return (at < 0 ? step.uses : step.uses.slice(0, at)).toLowerCase();
}

/**
 * The action's major version, from its ref ("@v5", "@v5.1.0") or, for a commit pin, the version in the comment after
 * it ("# v5.0.0"). Null when neither says.
 */
export function actionMajor(step: Step): number | null {
  const ref = step.uses && step.uses.includes('@') ? step.uses.slice(step.uses.indexOf('@') + 1) : '';
  const isDigit = (c: string | undefined) => c !== undefined && c >= '0' && c <= '9';
  // The ref must be the version itself; the comment may name it anywhere ("# v5.0.0", "# tag=v5").
  for (const [s, anywhere] of [
    [ref, false],
    [step.comment, true],
  ] as const) {
    for (let start = 0; start < (anywhere ? s.length : 1); start++) {
      let k = start;
      if (s[k] === 'v' || s[k] === 'V') k++;
      if (!isDigit(s[k]) || (anywhere && k === start && start > 0 && s[start - 1] !== '=' && s[start - 1] !== ' ')) {
        continue;
      }
      let digits = '';
      while (isDigit(s[k])) digits += s[k++];
      // A commit SHA can start with digits too: a version is a short number ending at a dot, a space or the end.
      if (digits.length <= 4 && (k === s.length || s[k] === '.' || s[k] === ' ')) return Number(digits);
    }
  }
  return null;
}
