// Reading GitHub Actions workflow files line by line, without a YAML parser (as the Python scanner does).
import { RISKY_EXPR, TOOLS } from './constants.ts';
import { at, findall, finditer, match, pyLstrip, pyStrip, re, search, splitLines, sub } from './py.ts';
import type { WorkflowAnalysis } from './types.ts';

const KEY = re(String.raw`\s*-?\s*([\w-]+)\s*:`);
const STEP_DASH = re(String.raw`^(\s*)-\s`);
const EXPR_WRAPPER = re(String.raw`^\$\{\{\s*|\s*\}\}$`);
const WORDS = re(String.raw`[A-Za-z0-9]+`);
const TOP_PERMISSIONS = re(String.raw`(?m)^permissions\s*:`);
const WRITE_ALL = re(String.raw`(?m)^\s*permissions\s*:\s*write-all`);
const PRT_TRIGGER = re(String.raw`(?m)^\s*-?\s*pull_request_target\b`);
const PRT_ON_LINE = re(String.raw`(?m)^on:.*pull_request_target`);
// pull_request itself, as a key or list item under on:, or named on the on: line; \b keeps out pull_request_target.
const PR_TRIGGER = re(String.raw`(?m)^\s*-?\s*pull_request\b`);
const PR_ON_LINE = re(String.raw`(?m)^on:.*\bpull_request\b`);
const WORKFLOW_RUN = re(String.raw`(?m)^\s*workflow_run\s*:`);
const ID_TOKEN_WRITE = re(String.raw`id-token:\s*write`);
const UNSAFE_PR_CHECKOUT = re(String.raw`allow-unsafe-pr-checkout:\s*["\']?true`);
const SELF_HOSTED = re(String.raw`runs-on:\s*\[?[^\n]*self-hosted`);
const JOB_KEY = re(String.raw`(?m)^  ([\w-]+):\s*$`);
const JOB_PERMISSIONS = re(String.raw`(?m)^    permissions\s*:`);
const USES = re(String.raw`^\s*-?\s*uses:\s*["\']?([^\s"\'#]+)`);
const PINNED = re(String.raw`@[0-9a-f]{40}$`);
const CHECKOUT = re(String.raw`actions/checkout@`);
const NO_PERSIST = re(String.raw`persist-credentials:\s*["\']?false`);
const PR_HEAD_REF = re(
  String.raw`ref:\s*\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)|refs/pull/`,
);
const CODEQL_ACTIONS = re(
  String.raw`(?im)languages?\s*:\s*\[[^\]]*\bactions\b[^\]]*\]|languages?\s*:\s*["\']?[\w, -]*\bactions\b|` +
    String.raw`^\s*-\s*language\s*:\s*["\']?actions\b|^\s*-\s*["\']?actions["\']?\s*$`,
);
const UNTRUSTED_ARTIFACTS = re(String.raw`actions/download-artifact|github\.event\.workflow_run\.head`);

/** The fix for one untrusted expression, using that expression: move it into env and quote the variable. */
export function envVarHint(expr: string): string {
  const inner = sub(EXPR_WRAPPER, '', expr);
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
    self_hosted: search(SELF_HOSTED, text) !== null,
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
        const block = stepBlock(lines, i).join('\n');
        if (!search(NO_PERSIST, block)) out.checkouts_no_persist.push(i + 1);
        if (out.prt && search(PR_HEAD_REF, block)) (out.prt_checks_out_pr ??= []).push(i + 1);
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
  if (out.tools.includes('codeql')) out.codeql_actions = search(CODEQL_ACTIONS, text) !== null;
  if (out.workflow_run && search(UNTRUSTED_ARTIFACTS, text)) out.workflow_run_untrusted = true;
  return out;
}
