// Reading GitHub Actions workflow files line by line, without a YAML parser (as the Python scanner does).
import { RISKY_EXPR, TOOLS } from './constants.ts';
import { at, findall, finditer, LINE_SPACE as HS, match, pyLstrip, pyStrip, re, search, splitLines } from './py.ts';
import type { WorkflowAnalysis } from './types.ts';

// A workflow is a file anyone can write, read on our server, so these patterns take time in proportion to the text,
// and match what the Python scanner's did. A line's leading space is LINE_SPACE, not \s, which would run on into the
// lines below; "\s*-?\s*" is "\s*(?:-\s*)?", since two runs of \s* side by side take time squared.
const KEY = re(String.raw`^\s*(?:-\s*)?([\w-]+)\s*:`);
const STEP_DASH = re(String.raw`^(\s*)-\s`);
const WORDS = re(String.raw`[A-Za-z0-9]+`);
const TOP_PERMISSIONS = re(String.raw`(?m)^permissions\s*:`);
const WRITE_ALL = re(String.raw`(?m)^${HS}*permissions\s*:\s*write-all`);
const PRT_TRIGGER = re(String.raw`(?m)^${HS}*(?:-\s*)?pull_request_target\b`);
const PRT_ON_LINE = re(String.raw`(?m)^on:.*pull_request_target`);
// pull_request itself, as a key or list item under on:, or named on the on: line; \b keeps out pull_request_target.
const PR_TRIGGER = re(String.raw`(?m)^${HS}*(?:-\s*)?pull_request\b`);
const PR_ON_LINE = re(String.raw`(?m)^on:.*\bpull_request\b`);
const WORKFLOW_RUN = re(String.raw`(?m)^${HS}*workflow_run\s*:`);
const ID_TOKEN_WRITE = re(String.raw`id-token:\s*write`);
const UNSAFE_PR_CHECKOUT = re(String.raw`allow-unsafe-pr-checkout:\s*["\']?true`);
const JOB_KEY = re(String.raw`(?m)^  ([\w-]+):\s*$`);
const JOB_PERMISSIONS = re(String.raw`(?m)^    permissions\s*:`);
const USES = re(String.raw`^\s*(?:-\s*)?uses:\s*["\']?([^\s"\'#]+)`);
const PINNED = re(String.raw`@[0-9a-f]{40}$`);
const CHECKOUT = re(String.raw`actions/checkout@`);
const NO_PERSIST = re(String.raw`persist-credentials:\s*["\']?false`);
const PR_HEAD_REF = re(
  String.raw`ref:\s*\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)|refs/pull/`,
);
/**
 * CodeQL set to analyze actions: languages: "actions" or a list of names with actions in it, "- language: actions",
 * or "- actions". A languages: [...] list is LANGUAGES_LIST, read in code (see codeqlActions).
 */
const CODEQL_ACTIONS = re(
  String.raw`(?im)languages?\s*:\s*(?:["\'][\w, -]*|[\w,-][\w, -]*)?\bactions\b|` +
    String.raw`^${HS}*-\s*language\s*:\s*["\']?actions\b|^${HS}*-\s*["\']?actions["\']?\s*$`,
);
const LANGUAGES_LIST = re(String.raw`(?i)languages?\s*:\s*\[`);
const ACTIONS_WORD = re(String.raw`(?i)\bactions\b`);
const UNTRUSTED_ARTIFACTS = re(String.raw`actions/download-artifact|github\.event\.workflow_run\.head`);

/** The fix for one untrusted expression, using that expression: move it into env and quote the variable. */
export function envVarHint(expr: string): string {
  // The expression without its ${{ }} (trimmed in code: a pattern for it takes time squared on a run of spaces).
  let inner = expr;
  if (inner.startsWith('${{')) inner = inner.slice(3).trimStart();
  if (inner.endsWith('}}')) inner = inner.slice(0, -2).trimEnd();
  let words = findall(WORDS, inner).filter(
    (w) => !/^[0-9]+$/.test(w) && !['github', 'event'].includes(w.toLowerCase()),
  );
  if (!words.length) words = ['value'];
  const name = words.slice(-2).join('_').toUpperCase();
  return `Pass it through an env var: env: ${name}: \${{ ${inner} }} then use "$${name}" in the script`;
}

/** Python's _indent: how many whitespace characters the line starts with. */
function indent(line: string): number {
  return line.length - pyLstrip(line).length;
}

/** A line that isn't blank or a comment. */
function significant(line: string): boolean {
  return pyStrip(line) !== '' && !pyLstrip(line).startsWith('#');
}

/**
 * Nearest less-indented YAML key above line i (tells run: blocks apart from env: blocks), searched for all the way to
 * the top of the file. Python's _parent_key, without its limit of 119 lines (which missed lines deep in a long run:
 * script). A line that is itself a run: or script: key is its own parent.
 */
export function parentKey(lines: string[], i: number): string | null {
  let ind = indent(at(lines, i));
  let m = match(KEY, at(lines, i));
  if (m && (m[1] === 'run' || m[1] === 'script')) return m[1];
  for (let j = i - 1; j >= 0; j--) {
    const s = lines[j];
    if (!significant(s)) continue;
    if (indent(s) < ind) {
      m = match(KEY, s);
      if (m) return m[1];
      ind = indent(s);
    }
  }
  return null;
}

/**
 * parentKey() of every line, in one pass. Asking parentKey() line by line walks back over a whole long script for each
 * of its lines, which a hostile workflow could make take minutes; this takes time in proportion to the file's length.
 */
export function parentKeys(lines: string[]): (string | null)[] {
  // The lines above that the search could still stop at for a later line, each less indented than the next, with
  // what the search returns once it gets there: the line's own key, or for a line that isn't a key, its parent.
  const open: { ind: number; key: string | null }[] = [];
  return lines.map((line) => {
    const ind = indent(line);
    const own = pyStrip(line) ? (match(KEY, line)?.[1] ?? null) : null;
    // How many open lines are less indented than this one; the search stops at the nearest of them.
    let n = 0;
    for (let hi = open.length; n < hi;) {
      const mid = (n + hi) >> 1;
      if (open[mid].ind < ind) n = mid + 1;
      else hi = mid;
    }
    const parent = n ? open[n - 1].key : null;
    if (significant(line)) {
      // The open lines at least as indented as this one are now hidden behind it.
      open.length = n;
      open.push({ ind, key: own ?? parent });
    }
    return own === 'run' || own === 'script' ? own : parent;
  });
}

/** The lines of the step containing line i (from its '- ' line to the next sibling). Python's _step_block. */
export function stepBlock(lines: string[], i: number): string[] {
  let start = i;
  let dash: number | null = null;
  for (let j = i; j > Math.max(-1, i - 40); j--) {
    const m = match(STEP_DASH, at(lines, j));
    if (m && indent(lines[j]) <= indent(at(lines, i))) {
      start = j;
      dash = m[1].length;
      break;
    }
  }
  if (dash === null) return lines.slice(i, i + 1);
  let end = lines.length;
  for (let k = start + 1; k < lines.length; k++) {
    const s = lines[k];
    if (significant(s) && indent(s) <= dash) {
      end = k;
      break;
    }
  }
  return lines.slice(start, end);
}

/**
 * stepBlock() for every line of one file at once, as the first and last-plus-one lines of the step: each line's dash
 * and indentation are read once, and where each step ends comes from one pass. Asking stepBlock() for each uses: line
 * walked down to the end of its step every time, which steps nested ever deeper made take time squared.
 */
function stepRanges(lines: string[]): (i: number) => [number, number] {
  const n = lines.length;
  const indents = new Int32Array(n);
  const dashes = new Int32Array(n).fill(-1);
  // The next line that holds something and is at most as indented as line k, where a step that starts at k ends.
  const ends = new Int32Array(n).fill(n);
  const open: number[] = [];
  for (let k = 0; k < n; k++) {
    const l = lines[k];
    const ind = (indents[k] = indent(l));
    // A step's dash comes right after the line's indentation (STEP_DASH is run only where it can match).
    if (l[ind] === '-' && match(STEP_DASH, l)) dashes[k] = ind;
    // A line holds something, as significant() says, when it has more than its indentation and isn't a comment.
    if (ind >= l.length || l[ind] === '#') continue;
    while (open.length && indents[open[open.length - 1]] >= ind) ends[open.pop()!] = k;
    open.push(k);
  }
  return (i) => {
    for (let j = i; j > Math.max(-1, i - 40); j--) {
      if (dashes[j] >= 0 && indents[j] <= indents[i]) return [j, ends[j]];
    }
    return [i, i + 1];
  };
}

/**
 * Whether the text of lines from to to - 1, joined by newlines, matches rx, asked for many ranges of one file: rx runs
 * once over the file, from every place a match starts, and each question is a binary search. Exact for a pattern with
 * no anchors or lookarounds that has at most one match at any place, as NO_PERSIST and PR_HEAD_REF have.
 */
type Ranged = (from: number, to: number) => boolean;
/** A file's lines joined by newlines, and where each line starts in that text. */
interface Joined {
  text: string;
  offsets: ArrayLike<number>;
}
function joinLines(lines: string[]): Joined {
  const offsets = new Array<number>(lines.length);
  let at = 0;
  for (let k = 0; k < lines.length; k++) {
    offsets[k] = at;
    at += lines[k].length + 1;
  }
  return { text: lines.join('\n'), offsets };
}
function matchesIn(rx: RegExp, lines: string[], { text: joined, offsets }: Joined): Ranged {
  const starts: number[] = [];
  const ends: number[] = [];
  const g = new RegExp(rx.source, rx.flags + 'g');
  for (let m = g.exec(joined); m; m = g.exec(joined)) {
    starts.push(m.index);
    ends.push(m.index + m[0].length);
    g.lastIndex = m.index + 1;
  }
  // The nearest end of the matches from the k-th on.
  for (let k = ends.length - 2; k >= 0; k--) ends[k] = Math.min(ends[k], ends[k + 1]);
  return (from, to) => {
    const lo = offsets[from];
    const hi = to < lines.length ? offsets[to] - 1 : joined.length;
    let a = 0;
    let b = starts.length;
    while (a < b) {
      const mid = (a + b) >> 1;
      if (starts[mid] < lo) a = mid + 1;
      else b = mid;
    }
    return a < starts.length && ends[a] <= hi;
  };
}

/**
 * Whether a job runs on a self-hosted runner: what the Python scanner's runs-on:\s*\[?[^\n]*self-hosted found, read
 * line by line (the pattern took time squared on a long line). That is "self-hosted" after a runs-on: on its line, or
 * on the next line that isn't blank when only space follows a runs-on: (a list on the lines below).
 */
function selfHosted(text: string): boolean {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const at = lines[i].indexOf('runs-on:');
    if (at < 0) continue;
    if (lines[i].includes('self-hosted', at + 8)) return true;
    if (pyStrip(lines[i].slice(lines[i].lastIndexOf('runs-on:') + 8))) continue;
    let j = i + 1;
    while (j < lines.length && !pyStrip(lines[j])) j++;
    if (j < lines.length && lines[j].includes('self-hosted')) return true;
  }
  return false;
}

/**
 * Whether CodeQL is set to analyze actions (CODEQL_ACTIONS), or a languages: [...] list names it before its first ]:
 * what the Python scanner's languages?\s*:\s*\[[^\]]*\bactions\b[^\]]*\] found, read in one pass. That pattern ran
 * from each languages: [ to the first ], which many of them before one ] made take time squared.
 */
function codeqlActions(text: string): boolean {
  if (search(CODEQL_ACTIONS, text)) return true;
  const words = [...finditer(ACTIONS_WORD, text)].map((m) => m.index);
  let w = 0;
  let close = -1;
  for (const m of finditer(LANGUAGES_LIST, text)) {
    const from = m.index + m[0].length;
    if (close < from) close = text.indexOf(']', from);
    if (close < 0) return false;
    while (w < words.length && words[w] < from) w++;
    if (w < words.length && words[w] + 'actions'.length <= close) return true;
  }
  return false;
}

export function analyzeWorkflow(path: string, text: string): WorkflowAnalysis {
  const lines = splitLines(text);
  const out: WorkflowAnalysis = {
    path,
    uses: [],
    unpinned: [],
    checkouts: 0,
    checkouts_no_persist: [],
    risky_lines: [],
    top_permissions: search(TOP_PERMISSIONS, text) !== null,
    write_all: search(WRITE_ALL, text) !== null,
    prt: search(PRT_TRIGGER, text) !== null || search(PRT_ON_LINE, text) !== null,
    pull_request: search(PR_TRIGGER, text) !== null || search(PR_ON_LINE, text) !== null,
    workflow_run: search(WORKFLOW_RUN, text) !== null,
    id_token_write: search(ID_TOKEN_WRITE, text) !== null,
    unsafe_pr_checkout: search(UNSAFE_PR_CHECKOUT, text) !== null,
    self_hosted: selfHosted(text),
    tools: TOOLS.filter(([, p]) => search(p, text) !== null).map(([name]) => name),
  };
  // job-level permissions when there is no top-level block
  if (!out.top_permissions) {
    const jobsAt = text.indexOf('\njobs:');
    const jobs = jobsAt >= 0 ? findall(JOB_KEY, text.slice(jobsAt + '\njobs:'.length)) : [];
    const jobPerms = findall(JOB_PERMISSIONS, text).length;
    out.job_permissions_all = jobs.length > 0 && jobPerms >= jobs.length;
  }
  const parents = parentKeys(lines);
  // Worked out at the first checkout, since most workflows' other lines don't need them.
  let steps: { stepOf: (i: number) => [number, number]; noPersist: Ranged; prHeadRef: Ranged } | null = null;
  lines.forEach((ln, i) => {
    // Lines under run: or script: are a script's text. An expression there is spliced into the script; a uses:
    // line there is just text, not a step.
    const inScript = parents[i] === 'run' || parents[i] === 'script';
    const m = match(USES, ln);
    if (m && !inScript) {
      const ref = m[1];
      if (!ref.startsWith('./') && !ref.startsWith('docker://')) {
        out.uses.push(ref);
        if (!search(PINNED, ref)) out.unpinned.push({ line: i + 1, ref });
      }
      if (match(CHECKOUT, ref)) {
        out.checkouts += 1;
        // The step's text is stepBlock(lines, i).
        if (!steps) {
          const joined = joinLines(lines);
          steps = {
            stepOf: stepRanges(lines),
            noPersist: matchesIn(NO_PERSIST, lines, joined),
            prHeadRef: matchesIn(PR_HEAD_REF, lines, joined),
          };
        }
        const [from, to] = steps.stepOf(i);
        if (!steps.noPersist(from, to)) out.checkouts_no_persist.push(i + 1);
        if (out.prt && steps.prHeadRef(from, to)) (out.prt_checks_out_pr ??= []).push(i + 1);
      }
    }
    if (inScript) {
      // Each distinct expression on the line, once: the same one twice (even spaced differently) is one fix.
      const seen = new Set<string>();
      for (const risky of finditer(RISKY_EXPR, ln)) {
        if (seen.has(risky[1])) continue;
        seen.add(risky[1]);
        out.risky_lines.push({ line: i + 1, expr: risky[0] });
      }
    }
  });
  if (out.tools.includes('codeql')) out.codeql_actions = codeqlActions(text);
  // A workflow_run workflow that takes in the triggering run's artifacts or code. Its if: conditions don't count: they
  // only compare those values, and checking head_repository against github.repository is how one keeps forks out.
  const inCondition = (ln: string, i: number) => parents[i] === 'if' || match(KEY, ln)?.[1] === 'if';
  if (
    out.workflow_run &&
    lines.some((ln, i) => significant(ln) && !inCondition(ln, i) && search(UNTRUSTED_ARTIFACTS, ln) !== null)
  ) {
    out.workflow_run_untrusted = true;
  }
  return out;
}
