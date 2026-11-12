// Detections for checks that are otherwise self-checks (new in 0.5.0). Each one reports only on a definite sign and
// returns null otherwise, so the check stays one people tick off themselves: a missing sign is never a failure.
import { SCRIPT_RUN } from './hops.ts';
import type { Hops } from './hops.ts';
import { actionName, workflowOf } from './jobs.ts';
import type { Step, Workflow } from './jobs.ts';
import { finditer, isDict, re, search, splitLines } from './py.ts';
import type { Evidence, Status } from './types.ts';
import { at, list, parseYaml } from './yaml-lite.ts';
import type { YNode } from './yaml-lite.ts';

export interface Outcome {
  status: Status;
  summary: string;
  evidence: Evidence[];
  details: Record<string, unknown>;
}

// ------------------------------------------------------------------------------------------ memory safety
/** Source files in a language without memory safety: C and C++, Objective-C, Cython, CUDA, assembly, Fortran, Zig. */
export const NATIVE_FILE = re(
  String.raw`(?i)\.(?:c|h|cc|cpp|cxx|c\+\+|hh|hpp|hxx|h\+\+|ipp|tcc|inl|m|mm|s|asm|cu|cuh|pyx|pxd|pxi|f|f77|f90|f95|` +
    String.raw`f03|f08|for|zig)$`,
);
/** GitHub's names for those languages and the like (any assembly but WebAssembly counts too). */
const NATIVE_LANGUAGES = new Set(
  [
    'c',
    'c++',
    'objective-c',
    'objective-c++',
    'cython',
    'cuda',
    'fortran',
    'fortran free form',
    'zig',
    'd',
    'nim',
  ].concat(['odin', 'pascal', 'ada', 'opencl', 'metal', 'llvm', 'c3', 'hare']),
);

/**
 * code-memory-safety is na only when GitHub's language count has no native code, the tree (read in full) has no
 * native source file, and there are no submodules, which GitHub doesn't count. Otherwise there's no result.
 */
export function memorySafety(
  languages: unknown,
  files: string[],
  gitlinks: string[],
  treeComplete: boolean,
): Outcome | null {
  if (!treeComplete || !languages || typeof languages !== 'object' || Array.isArray(languages)) return null;
  const native = Object.entries(languages as Record<string, unknown>).filter(([name, bytes]) => {
    const n = name.toLowerCase();
    const isNative = NATIVE_LANGUAGES.has(n) || (n.includes('assembly') && n !== 'webassembly');
    return isNative && typeof bytes === 'number' && bytes > 0;
  });
  if (native.length || gitlinks.length || files.some((f) => search(NATIVE_FILE, f))) return null;
  return {
    status: 'na',
    summary: 'No C, C++ or other code without memory safety, and no submodules',
    evidence: [],
    details: { languages: Object.keys(languages as object) },
  };
}

// ------------------------------------------------------------------------------- secrets in traced steps
/** Shell tracing, which prints each command after expansion: set -x (or -ex, -o xtrace), or bash -x. */
export const XTRACE = re(
  String.raw`(?:^|[;&|(]|\bthen\b|\bdo\b)\s*set\s+(?:-[A-Za-z]*x[A-Za-z]*\b|-o\s+xtrace\b)|\b(?:ba|z|k)?sh\s+-[A-Za-z]*x[A-Za-z]*\b`,
);
/** A secret in an expression: ${{ secrets.NAME }} or ${{ secrets['NAME'] }}. */
export const SECRET_REF = re(String.raw`\$\{\{[^{}]*\bsecrets\s*[.\[]`);

/** The run steps that trace their commands while a secret is in the step: the step, and the line of the tracing. */
export function tracedSecrets(workflows: { path: string; text: string }[]): { step: Step; line: number }[] {
  const out: { step: Step; line: number }[] = [];
  for (const w of workflows) {
    for (const job of workflowOf(w).jobs) {
      for (const s of job.steps) {
        if (s.run === null || !search(SECRET_REF, s.all)) continue;
        if (s.shell && search(XTRACE, s.shell)) {
          out.push({ step: s, line: s.runLine });
          continue;
        }
        const lines = splitLines(s.run);
        const k = lines.findIndex((l) => !l.trimStart().startsWith('#') && search(XTRACE, l));
        if (k >= 0) out.push({ step: s, line: s.runFirst + k });
      }
    }
  }
  return out;
}

// ------------------------------------------------------------------------------------------- license gates
/**
 * A license check that fails on licenses outside an allow list. The flag is at most 1000 characters after the command
 * on its line, and before the command starts again (as in release-caches.ts' PUBLISH_RUN).
 */
const LICENSE_RUN = re(
  String.raw`\bgo-licenses\s+check\b|` +
    String.raw`\blicense-checker(?:-rseidelsohn)?\b(?:(?!\blicense-checker(?:-rseidelsohn)?\b)[^\n]){0,1000}\s--(?:onlyAllow|failOn)\b|` +
    String.raw`\blicense-compliance\b(?:(?!\blicense-compliance\b)[^\n]){0,1000}\s--allow\b`,
);
const CARGO_DENY = re(String.raw`\bcargo[- ]deny\b([^\n]*)`);
const DENY_CHECK = re(String.raw`\b(advisories|bans|licenses|sources)\b`);
const CARGO_ABOUT = re(String.raw`\bcargo[- ]about\s+generate\b`);
const DENY_CHECK_WORD = re(String.raw`\bcheck\b`);
const DENY_TOML = re(String.raw`(^|/)deny\.toml$`);
const ABOUT_TOML = re(String.raw`(^|/)about\.toml$`);
const TOML_SECTION = re(String.raw`^\s*\[([^\]]+)\]`);
const TOML_KEY = re(String.raw`^\s*([\w-]+)\s*=`);

/** Whether a TOML file has the key in the section ([licenses] allow, or the top-level accepted). */
function tomlHas(toml: string, section: string | null, key: string): boolean {
  let current: string | null = null;
  for (const line of splitLines(toml)) {
    const s = search(TOML_SECTION, line);
    if (s) {
      current = s[1].trim();
      continue;
    }
    const k = search(TOML_KEY, line);
    if (k && k[1] === key && current === section) return true;
  }
  return false;
}

/** Whether a cargo deny command line (what follows "cargo deny") checks licenses: all checks, or licenses named. */
function denyChecksLicenses(rest: string): boolean {
  const check = search(DENY_CHECK_WORD, rest);
  if (!check) return false;
  const names = finditer(DENY_CHECK, rest.slice(check.index)).map((m) => m[1]);
  return !names.length || names.includes('licenses');
}

export interface LicenseInput {
  workflows: { path: string; text: string }[];
  files: string[];
  read: (path: string) => Promise<string | null>;
  /** One hop into package.json scripts and Makefile targets. */
  hops: Hops;
}

/** deps-licenses passes when CI runs a license check with an allow or deny list. */
export async function licenseGate(input: LicenseInput): Promise<Outcome | null> {
  const files = new Set(input.files);
  const hopped = new Map<string, Promise<string | null>>();
  const pass = (summary: string, path: string): Outcome => ({
    status: 'pass',
    summary,
    evidence: [{ label: path, url: path }],
    details: {},
  });
  let denyToml: Promise<string | null> | null = null;
  let aboutToml: Promise<string | null> | null = null;
  // Each file read once, however many steps name it.
  const configs = new Map<string, Promise<string | null>>();
  const config = (path: string) => {
    if (!configs.has(path)) configs.set(path, input.read(path));
    return configs.get(path)!;
  };
  for (const w of input.workflows) {
    const wf = workflowOf(w);
    for (const job of wf.jobs) {
      for (const s of job.steps) {
        const name = actionName(s);
        if (name === 'actions/dependency-review-action') {
          if (['allow-licenses', 'deny-licenses'].some((k) => (s.with[k] ?? '').trim())) {
            return pass('Dependency review checks the licenses of new dependencies on pull requests', w.path);
          }
          const cfg = (s.with['config-file'] ?? '').trim();
          // A local config file (a remote one, OWNER/REPO/FILE@REF, isn't read).
          const local = cfg.startsWith('./') ? cfg.slice(2) : cfg && !cfg.includes('@') ? cfg : '';
          if (local && files.has(local)) {
            const body = await config(local);
            const doc = body === null ? null : parseYaml(body);
            if (['allow-licenses', 'deny-licenses'].some((k) => list(at(doc, k)).length)) {
              return pass(`Dependency review checks the licenses of new dependencies (${local})`, w.path);
            }
          }
        }
        // cargo-deny's action runs every check unless its command names some.
        if (name === 'embarkstudios/cargo-deny-action') {
          const cmd = `${s.with.command ?? 'check'} ${s.with.arguments ?? ''} ${s.with['command-arguments'] ?? ''}`;
          const matrix = cmd.includes('${{') ? job.extra : '';
          if ((denyChecksLicenses(cmd) || matrix.includes('licenses')) && (await denyAllows())) {
            return pass('cargo-deny checks dependency licenses in CI', w.path);
          }
        }
        const found = await stepChecks(s);
        if (found) return pass(found, w.path);
      }
    }
  }
  return null;

  /** The license check a script line runs, or null. */
  async function lineChecks(line: string): Promise<string | null> {
    const run = search(LICENSE_RUN, line);
    if (run) return `${run[0].split(' ')[0]} checks dependency licenses in CI`;
    const d = search(CARGO_DENY, line);
    if (d && denyChecksLicenses(d[1]) && (await denyAllows())) return 'cargo-deny checks dependency licenses in CI';
    if (search(CARGO_ABOUT, line) && (await aboutAccepts())) return 'cargo-about checks dependency licenses in CI';
    return null;
  }
  /**
   * The license check a step's script runs, in its own lines or in the body of a script or target it runs (one hop,
   * each read once: a workflow can run one target thousands of times).
   */
  async function stepChecks(s: Step): Promise<string | null> {
    const lines = splitLines(s.run ?? '').filter((l) => !l.trimStart().startsWith('#'));
    for (const l of lines) {
      const got = await lineChecks(l);
      if (got) return got;
    }
    for (const l of lines) {
      for (const m of finditer(SCRIPT_RUN, l)) {
        const got = await hopChecks(m[1].split(' ')[0], m[2]);
        if (got) return got;
      }
    }
    return null;
  }
  async function hopChecks(tool: string, target: string): Promise<string | null> {
    const k = `${tool} ${target}`;
    if (!hopped.has(k)) {
      hopped.set(
        k,
        input.hops.body(tool, target).then(async (body) => {
          if (typeof body !== 'string') return null;
          for (const line of splitLines(body)) {
            const got = await lineChecks(line);
            if (got) return got;
          }
          return null;
        }),
      );
    }
    return hopped.get(k)!;
  }
  async function denyAllows(): Promise<boolean> {
    const path = input.files.find((f) => search(DENY_TOML, f));
    if (!path) return false;
    const body = await (denyToml ??= input.read(path));
    return body !== null && tomlHas(body, 'licenses', 'allow');
  }
  async function aboutAccepts(): Promise<boolean> {
    const path = input.files.find((f) => search(ABOUT_TOML, f));
    if (!path) return false;
    const body = await (aboutToml ??= input.read(path));
    return body !== null && tomlHas(body, null, 'accepted');
  }
}

// ---------------------------------------------------------------------------------- custom CodeQL queries
export const QL_FILE = re(String.raw`\.qll?$`);
export const QL_PACK = re(String.raw`(?:^|/)(?:qlpack|codeql-pack)\.ya?ml$`);
const VENDORED = re(String.raw`(?:^|/)(?:vendor|vendored|node_modules|third_party|third-party|external)/`);
const PACK_NAME = re(String.raw`(?m)^name\s*:\s*["']?([\w.-]+/[\w.-]+)`);

/** The query packs and query files a CodeQL config or input names, split on commas and white space. */
function names(node: YNode | null): string[] {
  if (!node) return [];
  if (node.kind === 'scalar') return node.text.split(/[\s,]+/).filter(Boolean);
  if (node.kind === 'seq') return node.items.flatMap((i) => (i.kind === 'map' ? names(at(i, 'uses')) : names(i)));
  return node.entries.flatMap((e) => names(e.value));
}

export interface QueryInput {
  workflows: { path: string; text: string }[];
  files: string[];
  read: (path: string) => Promise<string | null>;
}

/**
 * sast-custom-queries passes when the repository has its own QL pack and CI runs it: a CodeQL config, the init
 * action's queries or packs, or a reusable workflow's queries or packs input names the pack or its files.
 */
export async function customQueries(input: QueryInput): Promise<Outcome | null> {
  const own = input.files.filter((f) => !search(VENDORED, f));
  const packs = own.filter((f) => search(QL_PACK, f));
  if (!packs.length || !own.some((f) => search(QL_FILE, f))) return null;
  const dirs = packs.map((p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : ''));
  const packNames = new Set<string>();
  for (const p of packs.slice(0, 3)) {
    const body = await input.read(p);
    const m = body === null ? null : search(PACK_NAME, body);
    if (m) packNames.add(m[1].toLowerCase());
  }
  /** A query, suite or pack this repository has: a local path into a pack's folder, or one of its pack names. */
  const isOwn = (token: string): boolean => {
    let t = token.trim();
    if (t.startsWith('+')) t = t.slice(1);
    t = t.replace(/^["']|["']$/g, '');
    if (t.startsWith('./')) {
      const path = t.slice(2).replace(/\/+$/, '');
      return dirs.some((d) => d === '' || path === d || path.startsWith(`${d}/`) || d.startsWith(`${path}/`));
    }
    const pack = t.split('@')[0].split(':')[0].toLowerCase();
    return packNames.has(pack);
  };
  const configs = new Map<string, Promise<YNode | null>>();
  const config = (path: string) => {
    if (!configs.has(path))
      configs.set(
        path,
        input.read(path).then((b) => (b === null ? null : parseYaml(b))),
      );
    return configs.get(path)!;
  };
  const fromConfig = (doc: YNode | null) => [...names(at(doc, 'queries')), ...names(at(doc, 'packs'))].find(isOwn);
  const files = new Set(input.files);
  for (const w of input.workflows) {
    const wf: Workflow = workflowOf(w);
    for (const job of wf.jobs) {
      const inputs: [string | undefined, string | undefined, string | undefined, string | undefined][] = [];
      // A reusable workflow called with queries or packs passes them to CodeQL itself.
      if (job.uses) inputs.push([job.with.queries, job.with.packs, undefined, job.with['config-file']]);
      for (const s of job.steps) {
        if (actionName(s) === 'github/codeql-action/init') {
          inputs.push([s.with.queries, s.with.packs, s.with.config, s.with['config-file']]);
        }
      }
      for (const [queries, packsIn, inline, file] of inputs) {
        const hit =
          [queries, packsIn].flatMap((v) => (v ? v.split(/[\s,]+/) : [])).find(isOwn) ??
          (inline ? fromConfig(parseYaml(inline)) : undefined);
        if (hit) return found(hit, w.path);
        const local = file?.trim().replace(/^\.\//, '');
        if (local && !local.includes('@') && files.has(local)) {
          const via = fromConfig(await config(local));
          if (via) return found(via, local);
        }
      }
    }
  }
  return null;

  function found(what: string, where: string): Outcome {
    return {
      status: 'pass',
      summary: `CI runs this repository's own CodeQL queries (${what.replace(/^\+/, '')})`,
      evidence: [{ label: where, url: where }],
      details: { packs },
    };
  }
}

// --------------------------------------------------------------------------------- AI review on every PR
/** ai-assisted-security passes when a ruleset on the default branch has Copilot review pull requests. */
export function copilotReview(rules: unknown): Outcome | null {
  if (!Array.isArray(rules)) return null;
  const rule = rules.find(
    (r) => r && typeof r === 'object' && (r as { type?: unknown }).type === 'copilot_code_review',
  );
  if (!rule) return null;
  return {
    status: 'pass',
    summary: 'A ruleset has Copilot review the pull requests to the default branch',
    evidence: [],
    details: { ruleset_id: (rule as { ruleset_id?: unknown }).ruleset_id ?? null },
  };
}

// ------------------------------------------------------------------------------------- dependency backlog
export const BOT_LOGINS = new Set(['dependabot[bot]', 'renovate[bot]']);
const DAY = 86_400_000;

/**
 * deps-refresh warns when the oldest open Dependabot or Renovate pull request is over 90 days old. pulls is the first
 * page of open pull requests, oldest first, so the first bot pull request in it is the oldest of all; a page with none
 * says nothing about the pull requests after it.
 */
export function refreshBacklog(pulls: unknown, now: Date = new Date()): Outcome | null {
  if (!Array.isArray(pulls)) return null;
  const oldest = pulls.find((p) => BOT_LOGINS.has(String(p?.user?.login ?? '')));
  if (!oldest) return null;
  const opened = Date.parse(String(oldest.created_at ?? ''));
  const days = Number.isNaN(opened) ? 0 : Math.floor((now.getTime() - opened) / DAY);
  if (days <= 90) return null;
  const who = oldest.user.login === 'renovate[bot]' ? 'Renovate' : 'Dependabot';
  return {
    status: 'warn',
    summary: `The oldest open ${who} pull request, #${oldest.number}, is ${days} days old`,
    evidence: typeof oldest.html_url === 'string' ? [{ label: `#${oldest.number}`, url: oldest.html_url }] : [],
    details: { oldest_days: days },
  };
}

// --------------------------------------------------------------------------------------- settings reviews
/** The label on the issues the guide's settings review workflow opens (.github/workflows/settings-review.yml). */
export const REVIEW_LABEL = 'settings-review';
/** How long a closed settings review counts, in months: the longer end of the guide's "every 3 to 6 months". */
export const REVIEW_MONTHS = 6;

/** Whether a character can be part of a label name next to the one looked for (settings-review-old isn't it). */
const inName = (c: string | undefined) =>
  c !== undefined &&
  (c === '-' || c === '_' || (c >= '0' && c <= '9') || (c.toLowerCase() >= 'a' && c.toLowerCase() <= 'z'));

/** Whether text names the label on its own, not as part of a longer name. */
function namesLabel(text: string): boolean {
  for (let i = text.indexOf(REVIEW_LABEL); i >= 0; i = text.indexOf(REVIEW_LABEL, i + 1)) {
    if (!inName(text[i - 1]) && !inName(text[i + REVIEW_LABEL.length])) return true;
  }
  return false;
}

/** The workflows that open settings review issues: a schedule trigger, and a step that names the label. */
export function reviewWorkflows(workflows: { path: string; text: string }[]): string[] {
  return workflows
    .filter((w) => {
      const wf = workflowOf(w);
      return wf.triggers.includes('schedule') && wf.jobs.some((j) => j.steps.some((s) => namesLabel(s.all)));
    })
    .map((w) => w.path);
}

/** How GitHub lists a workflow it turned off (the workflow list's state), in words. */
const TURNED_OFF: Record<string, string> = {
  disabled_inactivity: 'GitHub turned it off for inactivity',
  disabled_manually: "it's turned off",
  disabled_fork: "it's turned off in this fork",
};

/**
 * repo-settings-review (new in 0.5.3), from the closed issues labeled settings-review (the newest 5) and the
 * workflows that open them: pass for one closed in the last 6 months; info for such a workflow, or for an older
 * closed issue; unknown when GitHub didn't answer; otherwise null. Pull requests with the label don't count, nor do
 * issues closed as not planned or as duplicates: the review didn't happen. GitHub lists no issues, but answers, for a
 * repository with issues turned off.
 */
export function settingsReview(
  [status, body]: [number, unknown, Record<string, string>],
  workflows: { path: string; state: string | null }[],
  { repo, issuesOff = false, now = new Date() }: { repo: string; issuesOff?: boolean; now?: Date },
): Outcome | null {
  if (status !== 200 && status !== 404) {
    return {
      status: 'unknown',
      summary: `Could not read the closed issues labeled ${REVIEW_LABEL} (HTTP ${status})`,
      evidence: [],
      details: {},
    };
  }
  const closed = (Array.isArray(body) ? body : [])
    .filter(
      (i) => isDict(i) && !isDict(i.pull_request) && i.state_reason !== 'not_planned' && i.state_reason !== 'duplicate',
    )
    .map((i) => ({ at: Date.parse(String(i.closed_at ?? '')), number: i.number, url: i.html_url }))
    .filter((c) => !Number.isNaN(c.at) && c.at <= now.getTime());
  const last = closed.length ? closed.reduce((a, b) => (b.at > a.at ? b : a)) : null;
  const day = last ? new Date(last.at).toISOString().slice(0, 10) : null;
  const link: Evidence[] = last && typeof last.url === 'string' ? [{ label: `#${last.number}`, url: last.url }] : [];
  const since = new Date(now.getTime());
  since.setUTCMonth(since.getUTCMonth() - REVIEW_MONTHS);
  if (last && last.at >= since.getTime()) {
    return {
      status: 'pass',
      summary: `An issue labeled ${REVIEW_LABEL} was closed on ${day}, within the last ${REVIEW_MONTHS} months`,
      evidence: link,
      details: { closed: day },
    };
  }
  const [flow] = workflows;
  if (!flow && !last) return null;
  const parts: string[] = [];
  const evidence: Evidence[] = [];
  if (flow) {
    const off = flow.state && Object.hasOwn(TURNED_OFF, flow.state) ? TURNED_OFF[flow.state] : undefined;
    parts.push(
      `${flow.path} opens a settings review issue on a schedule` +
        (off ? `, but ${off}` : issuesOff ? ', but issues are turned off in this repository' : ''),
    );
    evidence.push({ label: flow.path, url: flow.path });
    if (off) {
      const file = flow.path.slice(flow.path.lastIndexOf('/') + 1);
      evidence.push({ label: 'Turn it on in Actions', url: `https://github.com/${repo}/actions/workflows/${file}` });
    }
  }
  parts.push(
    last
      ? `the last issue labeled ${REVIEW_LABEL} was closed on ${day}, over ${REVIEW_MONTHS} months ago`
      : `no issue labeled ${REVIEW_LABEL} was closed in the last ${REVIEW_MONTHS} months`,
  );
  const summary = parts.join('; ');
  return {
    status: 'info',
    summary: summary.charAt(0).toUpperCase() + summary.slice(1),
    evidence: [...evidence, ...link],
    details: { ...(flow ? { workflow: flow.path } : {}), ...(day ? { closed: day } : {}) },
  };
}
