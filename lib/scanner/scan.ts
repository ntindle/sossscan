// The scan itself, ported statement by statement from scan() in the Python scanner. The order of requests,
// reads, results and findings is the Python order, so the port gave the same report (and the same api_calls).
// Checks added since make their requests where they report.
import { mapLimit } from '../pool.ts';
import {
  API,
  CODEQL_ECOSYSTEMS,
  ECOSYSTEM_FILES,
  FUZZ_EXCLUDE,
  FUZZ_PATH,
  LOCKFILES,
  OTHER_SAST_NAMES,
  PUBLISH_TOOLS,
  REGISTRY_TOOLS,
  SCHEMA,
  TOOLS,
  TRUSTED_TOOLS,
  VERSION,
  codeqlSource,
  tierFor,
  updatableFile,
} from './constants.ts';
import { Http, decodeReplace } from './http.ts';
import { ossScannerCheck } from './oss-scanner.ts';
import { privateLayer } from './private-layer.ts';
import type { AddFinding, AddResult } from './private-layer.ts';
import {
  findall,
  findallTuples,
  get,
  isDict,
  item,
  pyIn,
  pyInt,
  pyIter,
  pyJoin,
  pyLen,
  pyOr,
  pyRepr,
  pySlice,
  pySorted,
  pyStr,
  quote,
  re,
  reEscape,
  search,
  truthy,
} from './py.ts';
import type { Evidence, Finding, Report, Result, ScanOptions, Status, WorkflowAnalysis } from './types.ts';
import { analyzeWorkflow, envVarHint } from './workflow.ts';

const STATUSES: Status[] = ['pass', 'warn', 'fail', 'info', 'unknown', 'na'];
/** The folders whose contents are listed when the full file tree is too big for one response. */
const TRUNCATED_DIRS = ['.github', 'docs', 'doc', 'fuzz', 'fuzzing', 'security', '.clusterfuzzlite', 'oss-fuzz'];
const NO_WORKFLOW_ITEMS = [
  'ci-token-permissions',
  'ci-pin-actions',
  'ci-persist-credentials',
  'ci-dangerous-triggers',
  'ci-script-injection',
  'ci-workflow-audit',
];
const NO_RELEASE_ITEMS = ['rel-sbom', 'rel-provenance', 'rel-signing', 'rel-trusted-publishing'];
const NEEDS_PRIVATE_LAYER: [string, string][] = [
  ['deps-alerts', 'Dependabot alerts'],
  ['ci-fork-pr-approval', 'Fork PR approval policy'],
  ['acct-2fa-required', 'Org 2FA requirement'],
  ['sast-fix-backlog', 'Open code scanning alerts'],
  ['secrets-rotate-leaked', 'Open secret scanning alerts'],
  ['rel-gated-release', 'Environment protection rules'],
];

const WORKFLOW_FILE = re(String.raw`^\.github/workflows/[^/]+\.ya?ml$`);
const DEPENDENTS = re(String.raw`(?s)([\d,]+)\s*(?:<[^>]+>\s*)*\s*(Repositories|Packages)\b`);
const SECURITY_MD = re(String.raw`(?i)^(\.github/|docs/)?security(\.md|\.rst|\.txt|\.adoc)?$`);
const HOW_TO_REPORT = re(
  // Any email address or bug bounty program counts too: both are ways to report privately.
  String.raw`(?i)advisor|privately|report a vulnerability|security@|mailto:|e-?mail|private vulnerability|` +
    String.raw`[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+|bug bounty|hackerone|bugcrowd|intigriti`,
);
const THREAT_MODEL = re(String.raw`(?i)threat[-_ ]?model`);
const INCIDENT_RESPONSE = re(String.raw`(?i)incident[-_ ]?response|(^|/)irp[-_.]|security[-_]incident`);
const CODEOWNERS = re(String.raw`^(\.github/|docs/)?CODEOWNERS$`);
const COVERS_WORKFLOWS = re(String.raw`(?m)^\s*(\*|/?\.github(/|\s)|/?\.github/workflows)`);
const OTHER_SAST = TOOLS.find(([t]) => t === 'other_sast')![1];
const ZIZMOR_CONFIG = re(String.raw`(?i)(^|/)\.?zizmor\.ya?ml$`);
const DEPENDABOT = re(String.raw`^\.github/dependabot\.ya?ml$`);
const RENOVATE = re(String.raw`(?i)^(\.github/)?(renovate\.json5?|\.renovaterc(\.json)?)$`);
const PACKAGE_ECOSYSTEM = re(String.raw`package-ecosystem:\s*["\']?([\w-]+)`);
const DEPENDABOT_COOLDOWN = re(String.raw`(?m)^\s*cooldown\s*:`);
const RENOVATE_COOLDOWN = re(String.raw`minimumReleaseAge|stabilityDays`);
const NPM_COOLDOWN = re(String.raw`min-release-age`);
const UV_COOLDOWN = re(String.raw`exclude-newer`);
const IGNORE_SCRIPTS = re(String.raw`(?m)^\s*ignore-scripts\s*=\s*true`);
const DENY_TOML = re(String.raw`(^|/)deny\.toml$`);
const GORELEASER = re(String.raw`^\.goreleaser\.ya?ml$`);
const GORELEASER_SBOMS = re(String.raw`(?m)^sboms\s*:`);
const GORELEASER_SIGNS = re(String.raw`(?m)^(signs|docker_signs|binary_signs)\s*:`);
const CLUSTERFUZZLITE = re(String.raw`^\.clusterfuzzlite/`);
const AGENT_FILES = re(
  String.raw`(?i)^(AGENTS\.md|CLAUDE\.md|\.github/copilot-instructions\.md|\.github/instructions/[^/]+\.md)$`,
);
const SECURITY_RULES = re(String.raw`(?i)secur|secret|vulnerab`);
/**
 * What a scan says in its errors when GitHub refused some of its requests for going over a rate limit. The server
 * matches it to keep such a scan out of its caches (lib/public-scan.ts).
 */
export const RATE_LIMITED = 'GitHub rate-limited this scan, so some checks may be wrong. Try again in a few minutes.';

type Got = Record<string, [number, any, Record<string, string>]>;

/**
 * GitHub's refusal of a feature the account's plan doesn't include, such as rulesets in a private repository on GitHub
 * Free. It's an answer (there are none), not a failure to read.
 */
function notInPlan(status: number, body: unknown): boolean {
  return (
    status === 403 && isDict(body) && typeof body.message === 'string' && /\bupgrade to github\b/i.test(body.message)
  );
}

/**
 * Scan OWNER/REPO. layer 'public' skips admin-only checks even if the token could see them. assumeAdmin runs the
 * private layer even though the token's permissions aren't reported (GitHub App installation tokens). allowPrivate
 * false refuses private repositories (the shared web server, whose token must not expose them).
 */
export async function scan(repoArg: string, opts: ScanOptions = {}): Promise<Report> {
  const { token = null, layer = 'private', ossFuzzLookup = null, assumeAdmin = false, allowPrivate = true } = opts;
  const log = opts.log || (() => {});
  const http = new Http(token);
  let repo = repoArg;
  if (!repo.includes('/')) throw new Error('not enough values to unpack (expected 2, got 1)');
  let owner = repo.slice(0, repo.indexOf('/'));
  let name = repo.slice(repo.indexOf('/') + 1);
  const rep: Report = {
    schema: SCHEMA,
    tool: { name: 'sosf-scan', version: VERSION },
    repo,
    scanned_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    layer: 'public',
    meta: {},
    results: {},
    findings: [],
    errors: [],
    scorecard: null,
  };
  const R = rep.results;
  let branch = '';

  const res: AddResult = (itemId, status, summary, evidence = null, details = null, lay = 'public') => {
    R[itemId] = {
      status,
      summary,
      evidence: truthy(evidence) ? evidence! : [],
      details: truthy(details) ? details! : {},
      layer: lay,
    } satisfies Result;
  };
  const finding: AddFinding = (itemId, severity, title, path = null, line = null, hint = null) => {
    const url = path ? `https://github.com/${repo}/blob/${branch}/${path}` + (line ? `#L${line}` : '') : null;
    const f: Finding = { item_id: itemId, severity, title, path, line, url, hint };
    rep.findings.push(f);
    return f;
  };

  const [st, meta] = await http.json(`/repos/${repo}`);
  if (st !== 200 || !truthy(meta)) {
    rep.errors.push(`repo lookup failed: HTTP ${st}` + (st === 404 ? ' (private repo? pass a token)' : ''));
    if (http.rateLimited) rep.errors.push(RATE_LIMITED);
    return rep;
  }
  [owner, name, repo] = [item(item(meta, 'owner'), 'login'), item(meta, 'name'), item(meta, 'full_name')];
  rep.repo = repo;
  if (truthy(get(meta, 'private')) && !allowPrivate) {
    rep.errors.push('This is a private repository. Scan it with the downloadable scanner and your own token instead.');
    return rep;
  }
  branch = item(meta, 'default_branch');
  const privateRepo = truthy(get(meta, 'private'));
  const admin = (truthy(get(pyOr(get(meta, 'permissions'), {}), 'admin')) || assumeAdmin) && layer !== 'public';
  rep.layer = admin ? 'private' : 'public';

  const blob = (p: string) => `https://github.com/${repo}/blob/${branch}/${p}`;
  const fileLink = (p: string): Evidence[] => [{ label: p, url: blob(p) }];

  log(`scanning ${repo} (${admin ? 'admin token: private layer' : 'public layer'})`);

  // ---- file tree (it lists folders as well as files)
  const [treeStatus, tree] = await http.json(`/repos/${repo}/git/trees/${quote(branch)}?recursive=1`);
  // Without the list, every check that looks for a file finds it missing. A 409 is GitHub's answer for an empty
  // repository, which has no files to list.
  if (treeStatus !== 200 && treeStatus !== 409) {
    rep.errors.push(`Could not read the repository's files (HTTP ${treeStatus}), so the file checks may be wrong`);
  }
  const entry = (t: any, prefix = '') => ({ path: prefix + item(t, 'path'), file: get(t, 'type') === 'blob' });
  let entries = pyIter(get(pyOr(tree, {}), 'tree', [])).map((t) => entry(t));
  // A truncated tree lists only some files, so no check may conclude from it that a kind of file is absent.
  let treeTruncated = false;
  if (truthy(tree) && truthy(get(tree, 'truncated'))) {
    treeTruncated = true;
    const [, root] = await http.json(`/repos/${repo}/git/trees/${quote(branch)}`);
    const top = pyIter(get(pyOr(root, {}), 'tree', []));
    entries = top.map((t) => entry(t));
    for (const t of top) {
      if (item(t, 'type') === 'tree' && TRUNCATED_DIRS.includes(item(t, 'path'))) {
        const [, subtree] = await http.json(`/repos/${repo}/git/trees/${item(t, 'sha')}?recursive=1`);
        entries.push(...pyIter(get(pyOr(subtree, {}), 'tree', [])).map((x) => entry(x, item(t, 'path') + '/')));
      }
    }
    rep.errors.push('file tree truncated: scanned root, .github and docs only');
  }
  const paths = entries.map((e) => e.path);
  const files = entries.filter((e) => e.file).map((e) => e.path);

  /** A file on the default branch: the HTTP status, and the text unless the status isn't 200. */
  const fetchFile = async (p: string): Promise<[number, string | null]> => {
    if (privateRepo) {
      const [s, body] = await http.req(
        `${API}/repos/${repo}/contents/${quote(p)}?ref=${quote(branch)}`,
        'application/vnd.github.raw',
      );
      return [s, s === 200 ? decodeReplace(body) : null];
    }
    return http.text(`https://raw.githubusercontent.com/${repo}/${quote(branch)}/${quote(p)}`);
  };
  /**
   * The files that couldn't be read, with the HTTP status. The tree lists each one, so a check must say it couldn't
   * read the file, never that the file is missing or empty.
   */
  const unread = new Map<string, number>();
  const read = async (p: string): Promise<string | null> => {
    const [s, text] = await fetchFile(p);
    if (text === null) unread.set(p, s);
    return text;
  };
  const couldNotRead = (p: string) => `Could not read ${p} (HTTP ${unread.get(p)})`;
  /**
   * A community health file the account provides for every repo without its own: GitHub takes it from the account's
   * .github repo, which must be public, looking in its .github/ folder, then its root, then docs/. Costs two API calls
   * and a read when there is one; null when there isn't (or this is that repo). A lookup GitHub didn't answer gives
   * its status instead, and a file that couldn't be read comes with a null body.
   */
  const accountDefault = async (
    rx: RegExp,
  ): Promise<{ label: string; url: string; body: string | null; status: number } | { failed: number } | null> => {
    if (name.toLowerCase() === '.github') return null;
    const [s, defaults] = await http.json(`/repos/${owner}/.github`);
    // 404: the account has no .github repo, so it has no defaults.
    if (s === 404) return null;
    if (s !== 200) return { failed: s };
    if (!isDict(defaults) || truthy(get(defaults, 'private'))) return null;
    const br = String(get(defaults, 'default_branch') || 'main');
    const [ts, t] = await http.json(`/repos/${owner}/.github/git/trees/${quote(br)}?recursive=1`);
    // An empty .github repo (409) has no files to provide.
    if (ts === 404 || ts === 409) return null;
    if (ts !== 200) return { failed: ts };
    const rank = (p: string) => (/^\.github\//i.test(p) ? 0 : /^docs\//i.test(p) ? 2 : 1);
    const hits = pyIter(get(pyOr(t, {}), 'tree', []))
      .filter((x) => get(x, 'type') === 'blob' && search(rx, String(item(x, 'path'))) !== null)
      .map((x) => String(item(x, 'path')))
      .sort((a, b) => rank(a) - rank(b));
    if (!hits.length) return null;
    const [bs, body] = await http.text(
      `https://raw.githubusercontent.com/${owner}/.github/${quote(br)}/${quote(hits[0])}`,
    );
    return {
      label: `${hits[0]} in ${owner}/.github`,
      url: `https://github.com/${owner}/.github/blob/${br}/${hits[0]}`,
      body,
      status: bs,
    };
  };
  /** The files whose path matches: what most checks look for (a folder named security/ is not a SECURITY.md). */
  const find = (rx: RegExp) => files.filter((p) => search(rx, p) !== null);
  /** The files and folders whose path matches, for the checks where a folder counts. */
  const findAny = (rx: RegExp) => paths.filter((p) => search(rx, p) !== null);

  const ecos = pySorted([...new Set(ECOSYSTEM_FILES.filter(([rx]) => find(rx).length).map(([, eco]) => eco))]);
  const wfPaths = find(WORKFLOW_FILE);
  const texts = await mapLimit(wfPaths, 8, read);
  // dict(zip(paths, texts)): one entry per path, in first-seen order.
  const wfText = new Map<string, string | null>();
  wfPaths.forEach((p, i) => wfText.set(p, texts[i]));
  const wfs: WorkflowAnalysis[] = [...wfText].filter(([, t]) => t).map(([p, t]) => analyzeWorkflow(p, t!));
  // A workflow that couldn't be read is left out of every check, like an empty one, though it may hold what they look
  // for: say so.
  const wfUnread = [...wfText.keys()].filter((p) => unread.has(p));
  if (wfUnread.length) {
    const one = wfUnread.length === 1;
    rep.errors.push(
      `Could not read ${one ? wfUnread[0] : `${wfUnread.length} workflow files, such as ${wfUnread[0]}`} ` +
        `(HTTP ${unread.get(wfUnread[0])}), so the checks skipped ${one ? 'it' : 'them'}`,
    );
  }
  const tools = new Map<string, string[]>();
  for (const w of wfs) {
    for (const t of w.tools) {
      if (!tools.has(t)) tools.set(t, []);
      tools.get(t)!.push(w.path);
    }
  }
  const publishes = PUBLISH_TOOLS.some((t) => tools.has(t));

  // ---- parallel public API lookups. OpenSSF Scorecard and the Best Practices badge cover public repositories only,
  // so a private repo's name is never sent to them (nor to OSS-Fuzz or OSS Scanner, below).
  const lookups: [string, string][] = [
    ['pvr', `/repos/${repo}/private-vulnerability-reporting`],
    ['branch', `/repos/${repo}/branches/${quote(branch)}`],
    ['rules', `/repos/${repo}/rules/branches/${quote(branch)}`],
    ['rulesets', `/repos/${repo}/rulesets?includes_parents=true`],
    ['release', `/repos/${repo}/releases/latest`],
    ['advisories', `/repos/${repo}/security-advisories?state=published&per_page=100`],
    ['workflows', `/repos/${repo}/actions/workflows?per_page=100`],
  ];
  if (!privateRepo) {
    lookups.push(
      ['scorecard', `https://api.securityscorecards.dev/projects/github.com/${repo}`],
      ['bestpractices', `https://www.bestpractices.dev/projects.json?url=${quote('https://github.com/' + repo)}`],
    );
  }
  const answers = await mapLimit(lookups, 8, ([, path]) => http.json(path));
  const got: Got = Object.fromEntries(lookups.map(([key], i) => [key, answers[i]]));
  /**
   * The HTTP status of a lookup GitHub didn't answer, or null when it did. A 404 answers that there's nothing there (no
   * such branch, no releases), and so does a feature the plan doesn't include. Anything else (a refusal, a rate limit,
   * a 5xx, or 0 for a network failure) leaves the checks that rely on the lookup unknown.
   */
  const failed = (key: string): number | null => {
    const [s, body] = got[key];
    return s === 200 || s === 404 || notInPlan(s, body) ? null : s;
  };
  const [, depPage] = await http.text(`https://github.com/${repo}/network/dependents`, { auth: false });

  let deps: { repositories: number; packages: number } | null = null;
  if (depPage) {
    const nums: Record<string, number> = {};
    for (const [v, k] of findallTuples(DEPENDENTS, depPage).slice(0, 2)) {
      nums[k.toLowerCase()] = pyInt(v.replaceAll(',', ''));
    }
    if (Object.keys(nums).length) {
      deps = { repositories: get(nums, 'repositories', 0), packages: get(nums, 'packages', 0) };
    }
  }
  const dependents = deps ? deps.repositories + deps.packages : null;
  rep.meta = {
    stars: get(meta, 'stargazers_count', 0),
    forks: get(meta, 'forks_count', 0),
    watchers: get(meta, 'subscribers_count'),
    dependents: deps,
    dependents_total: dependents,
    language: get(meta, 'language'),
    topics: get(meta, 'topics', []),
    default_branch: branch,
    archived: get(meta, 'archived'),
    private: privateRepo,
    owner_type: item(item(meta, 'owner'), 'type'),
    created_at: get(meta, 'created_at'),
    description: get(meta, 'description'),
    ecosystems: ecos,
    workflow_count: wfs.length,
    publishes_from_ci: publishes,
    html_url: get(meta, 'html_url'),
    has_security_tab: true,
    admin_token: admin,
  };
  rep.tier = tierFor(get(meta, 'stargazers_count', 0), dependents || 0);

  // ---- disclosure
  const sec = find(SECURITY_MD);
  if (sec.length) {
    const body = await read(sec[0]);
    if (body === null) {
      res('disc-security-md', 'unknown', couldNotRead(sec[0]), fileLink(sec[0]));
    } else {
      const how = search(HOW_TO_REPORT, body) !== null;
      res(
        'disc-security-md',
        how && pyLen(body) > 200 ? 'pass' : 'warn',
        `${sec[0]} found` + (how ? '' : ' but it does not clearly say how to report privately'),
        fileLink(sec[0]),
        { path: sec[0], length: pyLen(body) },
      );
    }
  } else {
    // GitHub shows the account's default, a SECURITY.md in its public .github repo, for any repo without its own.
    const inherited = await accountDefault(SECURITY_MD);
    if (inherited === null) {
      res('disc-security-md', 'fail', 'No SECURITY.md in the root, .github/ or docs/');
    } else if ('failed' in inherited) {
      res(
        'disc-security-md',
        'unknown',
        `No SECURITY.md in this repository, and the account's default couldn't be checked (HTTP ${inherited.failed})`,
      );
    } else if (inherited.body === null) {
      res(
        'disc-security-md',
        'unknown',
        `Could not read the account's default, ${inherited.label} (HTTP ${inherited.status})`,
        [{ label: inherited.label, url: inherited.url }],
      );
    } else {
      const how = search(HOW_TO_REPORT, inherited.body) !== null;
      res(
        'disc-security-md',
        how && pyLen(inherited.body) > 200 ? 'pass' : 'warn',
        `${inherited.label} found, the account's default for repos without their own` +
          (how ? '' : ' but it does not clearly say how to report privately'),
        [{ label: inherited.label, url: inherited.url }],
        { path: inherited.label, length: pyLen(inherited.body), account_default: true },
      );
    }
  }
  const pvr = got.pvr[0] === 200 ? got.pvr[1] : null;
  if (isDict(pvr) && Object.hasOwn(pvr, 'enabled')) {
    const on = truthy(pvr.enabled);
    res('disc-private-reporting', on ? 'pass' : 'fail', 'Private vulnerability reporting is ' + (on ? 'on' : 'off'), [
      { label: 'Security tab', url: `https://github.com/${repo}/security` },
    ]);
  } else {
    res('disc-private-reporting', 'unknown', 'Could not read the private vulnerability reporting setting');
  }
  const advs: any[] = got.advisories[0] === 200 && Array.isArray(got.advisories[1]) ? got.advisories[1] : [];
  // An advisory with no publication date (missing or null) still counts; it just can't be the newest.
  const published = advs.map((a) => get(a, 'published_at')).filter((d): d is string => typeof d === 'string' && !!d);
  const newest = published.length ? published.reduce((a, b) => (b > a ? b : a)) : null;
  const advisoriesLink = [{ label: 'Advisories', url: `https://github.com/${repo}/security/advisories` }];
  const advisoriesFailed = failed('advisories');
  if (advisoriesFailed !== null) {
    res(
      'disc-advisories-cves',
      'unknown',
      `Could not read the published security advisories (HTTP ${advisoriesFailed})`,
      advisoriesLink,
    );
  } else {
    res(
      'disc-advisories-cves',
      'info',
      `${advs.length} published security advisories` + (newest ? `, newest ${pySlice(newest, 0, 10)}` : ''),
      advisoriesLink,
      { count: advs.length, with_cve: advs.filter((a) => truthy(get(a, 'cve_id'))).length },
    );
  }

  // ---- planning docs. A threat-model/ or incident-response/ folder counts: it holds the documents, and a truncated
  // tree may list the folder without its files.
  const tm = findAny(THREAT_MODEL);
  res(
    'plan-threat-model',
    tm.length ? 'pass' : 'fail',
    tm.length ? `${tm[0]} found` : 'No threat model file found in the repo',
    tm.length ? fileLink(tm[0]) : [],
  );
  const irp = findAny(INCIDENT_RESPONSE);
  res(
    'plan-irp',
    irp.length ? 'pass' : 'fail',
    irp.length ? `${irp[0]} found` : 'No incident response plan found in the repo',
    irp.length ? fileLink(irp[0]) : [],
  );

  // ---- repository settings visible publicly
  const co = find(CODEOWNERS);
  if (co.length) {
    const body = await read(co[0]);
    if (body === null) {
      res('repo-codeowners', 'unknown', couldNotRead(co[0]), fileLink(co[0]));
    } else {
      const covers = search(COVERS_WORKFLOWS, body) !== null;
      res(
        'repo-codeowners',
        covers ? 'pass' : 'warn',
        `${co[0]} found` + (covers ? '' : ', but it does not cover .github/workflows'),
        fileLink(co[0]),
      );
      if (!covers) {
        finding(
          'repo-codeowners',
          'low',
          'CODEOWNERS does not cover .github/workflows',
          co[0],
          null,
          'Add a line such as "/.github/ @your-team"',
        );
      }
    }
  } else {
    res('repo-codeowners', 'fail', 'No CODEOWNERS file');
  }
  const rules: unknown[] =
    got.rules[0] === 200 && Array.isArray(got.rules[1]) ? got.rules[1].map((r: unknown) => get(r, 'type')) : [];
  const protectedBranch = got.branch[0] === 200 ? truthy(get(pyOr(got.branch[1], {}), 'protected')) : null;
  const ruleSet = new Set(rules);
  const strong = ruleSet.has('pull_request') && ruleSet.has('non_fast_forward');
  const rulesFailed = failed('rules');
  // The branch's protected flag counts rulesets as well as classic protection, so a branch GitHub says is unprotected
  // is. Without the flag, an empty list of ruleset rules leaves classic protection unknown.
  const protectionFailed = got.branch[0] === 200 ? null : (failed('branch') ?? rulesFailed);
  if (protectedBranch || rules.length) {
    res(
      'repo-branch-protection',
      strong || protectedBranch ? 'pass' : 'warn',
      'Default branch is protected' +
        (rules.length
          ? `; ruleset rules: ${pyJoin(', ', pySorted([...ruleSet]))}`
          : rulesFailed === null
            ? ' (classic protection)'
            : ''),
      [{ label: 'Rulesets', url: `https://github.com/${repo}/rules` }],
      { rules: pySorted([...ruleSet]), protected: protectedBranch },
    );
  } else if (protectionFailed !== null) {
    res(
      'repo-branch-protection',
      'unknown',
      `Could not read whether the default branch (${pyStr(branch)}) is protected (HTTP ${protectionFailed})`,
    );
  } else {
    res('repo-branch-protection', 'fail', `The default branch (${pyStr(branch)}) is not protected`);
  }
  const signed = rules.includes('required_signatures');
  if (!signed && rulesFailed !== null) {
    res('repo-signed-commits', 'unknown', `Could not read whether signed commits are required (HTTP ${rulesFailed})`);
  } else {
    res(
      'repo-signed-commits',
      signed ? 'pass' : 'info',
      signed ? 'Signed commits are required' : 'Signed commits are not required (optional)',
    );
  }
  const rulesets: any[] = got.rulesets[0] === 200 && Array.isArray(got.rulesets[1]) ? got.rulesets[1] : [];
  const tagRs = rulesets.filter((r) => get(r, 'target') === 'tag');
  const rel = got.release[0] === 200 ? got.release[1] : null;
  const immutable = truthy(get(pyOr(rel, {}), 'immutable'));
  // A 404 for the latest release means there are none. A release or ruleset list GitHub didn't send could have shown
  // the protection.
  const releaseFailed = failed('release');
  const rulesetsFailed = failed('rulesets');
  if (tagRs.length || immutable) {
    res(
      'repo-tag-release-protection',
      'pass',
      (immutable ? 'Releases are immutable' : '') +
        (immutable && tagRs.length ? ' / ' : '') +
        (tagRs.length ? `${tagRs.length} tag ruleset(s)` : ''),
      [{ label: 'Rulesets', url: `https://github.com/${repo}/rules` }],
    );
  } else if (releaseFailed !== null) {
    res('repo-tag-release-protection', 'unknown', `Could not read the latest release (HTTP ${releaseFailed})`);
  } else if (truthy(rel) && rulesetsFailed !== null) {
    res(
      'repo-tag-release-protection',
      'unknown',
      `Latest release ${pyStr(get(rel, 'tag_name'))} is not immutable, and the tag rulesets couldn't be checked ` +
        `(HTTP ${rulesetsFailed})`,
    );
  } else if (truthy(rel)) {
    res(
      'repo-tag-release-protection',
      'fail',
      `Latest release ${pyStr(get(rel, 'tag_name'))} is not immutable and no tag ruleset is visible`,
    );
  } else {
    res('repo-tag-release-protection', 'info', 'No GitHub releases; protect tags if you publish from tags');
  }

  // ---- GitHub Actions
  const n = wfs.length;
  // The findings for workflows without a permissions block. Their token gets the repository's default, which only an
  // admin can read, so here they say what a repository like this one gets; the private layer rewrites them with the
  // real default.
  const noBlock: Finding[] = [];
  if (n === 0) {
    for (const it of NO_WORKFLOW_ITEMS) res(it, 'na', 'No GitHub Actions workflows');
  } else {
    const declares = (w: WorkflowAnalysis) => w.top_permissions || truthy(w.job_permissions_all);
    const declared = wfs.filter(declares);
    const missing = wfs.filter((w) => !declares(w));
    const assumed = tokenDefault(rep.meta.owner_type, rep.meta.created_at);
    res(
      'ci-token-permissions',
      // Where the default is read-only, that's all a missing block gives away, however many workflows lack one.
      !missing.length ? 'pass' : assumed.readOnly || declared.length >= n / 2 ? 'warn' : 'fail',
      tokenSummary(missing.length, n),
      missing.slice(0, 5).map((w) => ({ label: w.path, url: blob(w.path) })),
      { missing: missing.map((w) => w.path) },
    );
    for (const w of missing) {
      noBlock.push(
        finding(
          'ci-token-permissions',
          assumed.severity,
          assumed.title,
          w.path,
          1,
          'Add "permissions: {}" at the top and grant per job, e.g. contents: read',
        ),
      );
    }
    for (const w of wfs) {
      if (w.write_all) {
        finding(
          'ci-token-permissions',
          'high',
          'permissions: write-all',
          w.path,
          null,
          'Replace write-all with the scopes each job needs, e.g. contents: read',
        );
      }
    }
    const uses = wfs.reduce((sum, w) => sum + w.uses.length, 0);
    const unpinned = wfs.flatMap((w) => w.unpinned.map((u) => [w.path, u] as const));
    const share = uses ? 1 - unpinned.length / uses : 1;
    res(
      'ci-pin-actions',
      !unpinned.length ? 'pass' : share >= 0.5 ? 'warn' : 'fail',
      `${uses - unpinned.length}/${uses} action references pinned to a full commit SHA`,
      [],
      { unpinned: unpinned.length, total: uses },
    );
    for (const [p, u] of unpinned.slice(0, 40)) {
      const firstParty = ['actions', 'github'].includes(u.ref.split('/')[0]);
      finding(
        'ci-pin-actions',
        firstParty ? 'low' : 'medium',
        `Unpinned action: ${u.ref}`,
        p,
        u.line,
        'Pin to a full commit SHA with a version comment (pinact, frizbee or ratchet can do this for you)',
      );
    }
    const checkouts = wfs.reduce((sum, w) => sum + w.checkouts, 0);
    const noPersist = wfs.flatMap((w) => w.checkouts_no_persist.map((ln) => [w.path, ln] as const));
    res(
      'ci-persist-credentials',
      checkouts && !noPersist.length ? 'pass' : !checkouts ? 'na' : 'warn',
      checkouts
        ? `${checkouts - noPersist.length}/${checkouts} checkout steps set persist-credentials: false`
        : 'No checkout steps',
    );
    for (const [p, ln] of noPersist.slice(0, 20)) {
      finding(
        'ci-persist-credentials',
        'low',
        'actions/checkout keeps the token in .git/config',
        p,
        ln,
        'Add "with: persist-credentials: false"',
      );
    }
    const prt = wfs.filter((w) => w.prt);
    const wr = wfs.filter((w) => w.workflow_run);
    // A workflow with both triggers is still one workflow: count it, list it and report its checkout once.
    const privileged = [...new Set([...prt, ...wr])];
    const bad = privileged.filter(
      (w) =>
        (w.prt && truthy(w.prt_checks_out_pr)) ||
        (w.workflow_run && w.workflow_run_untrusted === true) ||
        w.unsafe_pr_checkout,
    );
    for (const w of privileged) {
      if (w.unsafe_pr_checkout) {
        finding(
          'ci-dangerous-triggers',
          'high',
          'allow-unsafe-pr-checkout: true in a privileged workflow',
          w.path,
          null,
          "This opts out of actions/checkout's fork-PR protection. Remove it unless the checked-out code is never executed.",
        );
      }
    }
    if (bad.length) {
      res(
        'ci-dangerous-triggers',
        'fail',
        `${bad.length} privileged workflow(s) handle untrusted PR code or artifacts`,
        bad.map((w) => ({ label: w.path, url: blob(w.path) })),
      );
    } else if (privileged.length) {
      res(
        'ci-dangerous-triggers',
        'warn',
        `${privileged.length} privileged workflow(s) to review ` +
          `(pull_request_target: ${prt.length}, workflow_run: ${wr.length})`,
        privileged.slice(0, 5).map((w) => ({ label: w.path, url: blob(w.path) })),
      );
    } else {
      res('ci-dangerous-triggers', 'pass', 'No pull_request_target or workflow_run triggers');
    }
    for (const w of prt) {
      for (const ln of w.prt_checks_out_pr ?? []) {
        finding(
          'ci-dangerous-triggers',
          'high',
          'pull_request_target checks out the PR head (classic "pwn request")',
          w.path,
          ln,
          'Use pull_request instead, or split into an unprivileged build plus a privileged workflow that never runs PR code',
        );
      }
      if (!truthy(w.prt_checks_out_pr)) {
        finding(
          'ci-dangerous-triggers',
          'medium',
          'pull_request_target runs with secrets and a write token',
          w.path,
          null,
          'Make sure it never checks out or executes PR code; prefer pull_request',
        );
      }
    }
    for (const w of wr) {
      if (w.workflow_run_untrusted) {
        finding(
          'ci-dangerous-triggers',
          'medium',
          'workflow_run consumes artifacts or refs from PR runs',
          w.path,
          null,
          'Treat downloaded artifacts as untrusted data; never execute them',
        );
      }
    }
    const risky = wfs.flatMap((w) => w.risky_lines.map((r) => [w.path, r] as const));
    res(
      'ci-script-injection',
      risky.length ? 'fail' : 'pass',
      risky.length
        ? risky.length + ' untrusted ${{ }} expression(s) inside run steps'
        : 'No untrusted expressions inside run steps',
    );
    for (const [p, r] of risky.slice(0, 20)) {
      finding(
        'ci-script-injection',
        'high',
        `Script injection risk: ${r.expr} in a run step`,
        p,
        r.line,
        envVarHint(r.expr),
      );
    }
    for (const w of wfs) {
      // Fork PRs trigger pull_request and pull_request_target workflows, so a stranger's code can reach the runner.
      if (w.self_hosted && (w.prt || w.pull_request) && !privateRepo) {
        finding(
          'ci-runner-hardening',
          'medium',
          'Self-hosted runner in a public repo workflow',
          w.path,
          null,
          'Do not run untrusted PR code on persistent self-hosted runners',
        );
      }
    }
    const audit = tools.get('zizmor') || tools.get('actionlint');
    const zcfg = find(ZIZMOR_CONFIG);
    const auditOrConfig = audit || zcfg;
    res(
      'ci-workflow-audit',
      audit || zcfg.length ? 'pass' : 'fail',
      audit
        ? 'Workflows are linted in CI (' + ['zizmor', 'actionlint'].filter((t) => tools.has(t)).join(', ') + ')'
        : zcfg.length
          ? 'zizmor config present'
          : 'No zizmor/actionlint in CI',
      auditOrConfig.length ? fileLink(auditOrConfig[0]) : [],
    );
  }
  res(
    'ci-runner-hardening',
    tools.has('harden_runner') ? 'pass' : 'info',
    tools.has('harden_runner')
      ? 'harden-runner restricts runner egress'
      : 'No runner egress control (optional at most tiers)',
  );
  const oidc = wfs.some((w) => w.id_token_write);
  res(
    'ci-oidc',
    oidc ? 'info' : publishes ? 'fail' : 'na',
    oidc
      ? 'Workflows use OIDC (id-token: write)'
      : publishes
        ? 'Publishes from CI without OIDC: likely a long-lived token'
        : 'No publishing workflow detected',
  );

  // ---- code scanning
  const dyn = new Set(
    pyIter(got.workflows[0] === 200 ? get(pyOr(got.workflows[1], {}), 'workflows', []) : []).map((w) =>
      item(w, 'path'),
    ),
  );
  // The list shows CodeQL default setup and Dependabot's update runs, so without it neither can be ruled out.
  const dynFailed = failed('workflows');
  const codeqlDefault = dyn.has('dynamic/github-code-scanning/codeql');
  const codeql = tools.get('codeql');
  if (codeql || codeqlDefault) {
    res(
      'sast-codeql',
      'pass',
      'CodeQL ' + (codeql ? `workflow: ${codeql[0]}` : 'default setup is on'),
      codeql ? fileLink(codeql[0]) : [{ label: 'Actions', url: `https://github.com/${repo}/actions` }],
    );
  } else if (
    !treeTruncated &&
    !wfPaths.length &&
    !ecos.some((e) => CODEQL_ECOSYSTEMS.has(e)) &&
    !files.some(codeqlSource)
  ) {
    res('sast-codeql', 'na', 'No code in a language CodeQL analyzes, and no workflows');
  } else if (dynFailed !== null) {
    res(
      'sast-codeql',
      'unknown',
      `No CodeQL workflow, and CodeQL default setup couldn't be checked (HTTP ${dynFailed})`,
    );
  } else {
    res('sast-codeql', 'fail', 'No CodeQL code scanning found');
  }
  if (wfs.some((w) => w.codeql_actions)) {
    res('sast-codeql-actions', 'pass', "CodeQL scans the 'actions' language (your workflows)");
  } else if (!wfPaths.length) {
    res('sast-codeql-actions', 'na', 'No GitHub Actions workflows');
  } else if (codeqlDefault) {
    res('sast-codeql-actions', 'unknown', 'CodeQL default setup is on; its languages need the private layer');
  } else if (dynFailed !== null) {
    res(
      'sast-codeql-actions',
      'unknown',
      `No CodeQL workflow scans the 'actions' language, and CodeQL default setup couldn't be checked ` +
        `(HTTP ${dynFailed})`,
    );
  } else {
    res('sast-codeql-actions', 'fail', 'Workflows are not scanned by CodeQL');
  }
  // Name the tools found; the workflows that run them are the evidence, as for the other tools.
  const otherSast = tools.get('other_sast');
  const sastNames = new Set<string>();
  for (const p of otherSast ?? []) {
    for (const hit of findall(OTHER_SAST, wfText.get(p) ?? '')) {
      sastNames.add(OTHER_SAST_NAMES[hit.toLowerCase()] ?? hit);
    }
  }
  res(
    'sast-other-tools',
    'info',
    otherSast ? 'Other SAST in CI: ' + [...sastNames].join(', ') : 'No other SAST tools detected (optional)',
    otherSast ? otherSast.flatMap(fileLink) : [],
  );
  res(
    'secrets-scanning',
    tools.has('secret_scan') ? 'pass' : 'unknown',
    tools.has('secret_scan')
      ? 'gitleaks/trufflehog runs in CI'
      : 'GitHub secret scanning status needs the private layer',
  );
  res('secrets-push-protection', 'unknown', 'Push protection status needs the private layer');

  // ---- dependencies
  const dbot = find(DEPENDABOT);
  const reno = find(RENOVATE);
  const dynDbot = dyn.has('dynamic/dependabot/dependabot-updates');
  let cooldown = false;
  if (dbot.length) {
    const body = await read(dbot[0]);
    if (body === null) {
      res('deps-update-automation', 'unknown', couldNotRead(dbot[0]), fileLink(dbot[0]));
    } else {
      const ecosCfg = pySorted([...new Set(findall(PACKAGE_ECOSYSTEM, body))]);
      cooldown = search(DEPENDABOT_COOLDOWN, body) !== null;
      const gha = ecosCfg.includes('github-actions');
      res(
        'deps-update-automation',
        gha || n === 0 ? 'pass' : 'warn',
        `Dependabot updates: ${ecosCfg.join(', ') || '?'}` + (gha || n === 0 ? '' : ' (github-actions missing)'),
        fileLink(dbot[0]),
        { ecosystems: ecosCfg },
      );
      if (!gha && n) {
        finding(
          'deps-update-automation',
          'low',
          'Dependabot does not update GitHub Actions (pinned SHAs will go stale)',
          dbot[0],
          null,
          'Add a "package-ecosystem: github-actions" entry',
        );
      }
    }
  } else if (reno.length) {
    const body = (await read(reno[0])) || '';
    cooldown = search(RENOVATE_COOLDOWN, body) !== null;
    res('deps-update-automation', 'pass', `Renovate config: ${reno[0]}`, fileLink(reno[0]));
  } else if (dynDbot) {
    res('deps-update-automation', 'pass', 'Dependabot version updates are active');
  } else if (!treeTruncated && !ecos.length && !wfPaths.length && !files.some(updatableFile)) {
    res(
      'deps-update-automation',
      'na',
      'Nothing for Dependabot or Renovate to update: no dependency files or workflows',
    );
  } else if (dynFailed !== null) {
    res(
      'deps-update-automation',
      'unknown',
      `No Dependabot or Renovate configuration, and active Dependabot updates couldn't be checked (HTTP ${dynFailed})`,
    );
  } else {
    res('deps-update-automation', 'fail', 'No Dependabot or Renovate configuration');
  }
  const npmrc = files.includes('.npmrc') ? await read('.npmrc') : '';
  const pyproj = files.includes('pyproject.toml') && ecos.includes('pypi') ? await read('pyproject.toml') : '';
  cooldown = cooldown || search(NPM_COOLDOWN, npmrc || '') !== null || search(UV_COOLDOWN, pyproj || '') !== null;
  // Any of the files read for a cooldown could have set one.
  const cooldownUnread = [dbot[0], reno[0], '.npmrc', 'pyproject.toml'].find((p) => unread.has(p));
  if (!cooldown && cooldownUnread) {
    res('deps-cooldown', 'unknown', couldNotRead(cooldownUnread), fileLink(cooldownUnread));
  } else {
    res(
      'deps-cooldown',
      cooldown ? 'pass' : dbot.length || reno.length ? 'fail' : 'info',
      cooldown ? 'A dependency cooldown is configured' : 'No cooldown: new releases are adopted immediately',
    );
  }
  if (ecos.includes('npm') && unread.has('.npmrc')) {
    res('deps-no-install-scripts', 'unknown', couldNotRead('.npmrc'), fileLink('.npmrc'));
  } else if (ecos.includes('npm')) {
    const ign = search(IGNORE_SCRIPTS, npmrc || '') !== null;
    res(
      'deps-no-install-scripts',
      ign ? 'pass' : 'fail',
      ign ? '.npmrc sets ignore-scripts=true' : 'npm lifecycle scripts run on install (no ignore-scripts in .npmrc)',
    );
  } else {
    res('deps-no-install-scripts', 'na', 'Not an npm project');
  }
  res(
    'deps-review',
    tools.has('dependency_review') ? 'pass' : 'fail',
    tools.has('dependency_review') ? 'Dependency review runs on PRs' : 'No dependency review on PRs',
  );
  const denyToml = find(DENY_TOML).length > 0;
  res(
    'deps-audit-tools',
    tools.has('dep_audit') || denyToml ? 'pass' : 'info',
    tools.has('dep_audit')
      ? 'Dependency audit in CI'
      : denyToml
        ? 'cargo-deny configured'
        : 'No dependency audit tool in CI (optional with Dependabot alerts)',
  );
  const locks: Record<string, boolean> = {};
  for (const e of ecos) if (Object.hasOwn(LOCKFILES, e)) locks[e] = find(LOCKFILES[e]).length > 0;
  const lockList = Object.entries(locks);
  res(
    'deps-lockfiles',
    lockList.length && lockList.every(([, v]) => v) ? 'pass' : lockList.length ? 'warn' : 'info',
    lockList.length
      ? 'Lockfiles: ' + lockList.map(([e, v]) => `${e} ${v ? 'yes' : 'no'}`).join(', ')
      : 'No lockfile-based ecosystem detected',
    null,
    locks,
  );

  // ---- releases
  const gr = find(GORELEASER);
  const grBody = gr.length ? await read(gr[0]) : '';
  const grSbom = search(GORELEASER_SBOMS, grBody || '') !== null;
  const grSign = search(GORELEASER_SIGNS, grBody || '') !== null;
  // A GoReleaser config that couldn't be read may set up the SBOMs and signing.
  const grUnread = gr.find((p) => unread.has(p));
  if (!publishes && !gr.length) {
    for (const it of NO_RELEASE_ITEMS) res(it, 'na', 'No release/publish workflow detected');
  } else {
    const sbom = tools.has('sbom') || grSbom;
    if (!sbom && grUnread) {
      res('rel-sbom', 'unknown', couldNotRead(grUnread), fileLink(grUnread));
    } else {
      res('rel-sbom', sbom ? 'pass' : 'fail', sbom ? 'SBOMs generated for releases' : 'No SBOM generation found');
    }
    const attest = tools.has('attest');
    res(
      'rel-provenance',
      attest ? 'pass' : 'fail',
      attest ? 'Build provenance attestations' : 'No provenance attestations',
    );
    const signs = tools.has('signing') || grSign;
    if (!signs && grUnread) {
      res('rel-signing', 'unknown', couldNotRead(grUnread), fileLink(grUnread));
    } else {
      res(
        'rel-signing',
        signs ? 'pass' : 'info',
        signs ? 'Releases are signed' : 'No signing step found (attestations may cover this)',
      );
    }
    const tp = wfs.filter((w) => w.id_token_write && TRUSTED_TOOLS.some((t) => w.tools.includes(t))).map((w) => w.path);
    const reg = REGISTRY_TOOLS.some((t) => tools.has(t));
    res(
      'rel-trusted-publishing',
      tp.length ? 'pass' : reg ? 'fail' : 'na',
      tp.length
        ? 'Registry publishing uses OIDC (trusted publishing)'
        : reg
          ? 'Publishes to a registry with a long-lived token'
          : 'Releases are published, but not to a registry with trusted publishing (PyPI, npm, crates.io, RubyGems)',
      tp.length ? fileLink(tp[0]) : [],
    );
  }

  // ---- fuzzing (folders count here: a fuzz/ folder holds fuzz targets, and .clusterfuzzlite/ is a folder)
  const fz = findAny(FUZZ_PATH).filter((p) => search(FUZZ_EXCLUDE, p) === null);
  // OSS-Fuzz builds public repositories only, so a private repo is neither looked up nor guessed at.
  const oss: string[] = privateRepo ? [] : ossFuzzLookup ? ossFuzzLookup(repo) : await ossFuzzGuess(http, owner, name);
  const cfl = findAny(CLUSTERFUZZLITE).length > 0;
  res(
    'fuzz-harnesses',
    fz.length ? 'pass' : 'fail',
    fz.length ? `Fuzz targets in repo (e.g. ${fz[0]})` : 'No fuzz targets found',
    fz.length ? fileLink(fz[0]) : [],
  );
  const cont = [
    ...(truthy(oss) ? ['OSS-Fuzz: ' + pyJoin(', ', oss)] : []),
    ...(cfl ? ['ClusterFuzzLite'] : []),
    ...(tools.has('fuzz') ? ['fuzzing in CI'] : []),
  ];
  res(
    'fuzz-continuous',
    cont.length ? 'pass' : 'fail',
    cont.length ? cont.join('; ') : 'Not fuzzed continuously',
    truthy(oss)
      ? [
          {
            label: `OSS-Fuzz ${pyStr(oss[0])}`,
            url: `https://github.com/google/oss-fuzz/tree/master/projects/${pyStr(oss[0])}`,
          },
        ]
      : [],
  );

  // ---- Anthropic's OSS Scanner (new in 0.4.0, so not from the Python port). No requests for a private repo, or below
  // its size cue.
  const ossScanner = await ossScannerCheck(http, {
    owner,
    name,
    full: repo,
    private: privateRepo,
    stars: get(meta, 'stargazers_count', 0),
    dependents,
  });
  res('sast-oss-scanner', ossScanner.status, ossScanner.summary, ossScanner.evidence, ossScanner.details);

  // ---- posture. The Scorecard status comes from the repo's own workflows; a public score only adds to the summary.
  // A private repo isn't looked up, so its summary has no score.
  const sc = !privateRepo && got.scorecard[0] === 200 ? got.scorecard[1] : null;
  if (isDict(sc)) {
    const checks = pyIter(get(sc, 'checks', []));
    rep.scorecard = {
      score: get(sc, 'score'),
      date: pySlice(pyOr(get(sc, 'date'), ''), 0, 10),
      checks: Object.fromEntries(checks.map((c) => [item(c, 'name'), get(c, 'score')])),
      reasons: Object.fromEntries(checks.map((c) => [item(c, 'name'), get(c, 'reason')])),
    };
  }
  const scorecardCi = tools.get('scorecard');
  res(
    'posture-scorecard',
    scorecardCi ? 'pass' : 'fail',
    scorecardCi
      ? 'OpenSSF Scorecard runs in CI' + (rep.scorecard ? ` (score ${pyStr(rep.scorecard.score)})` : '')
      : 'Scorecard action not set up' + (rep.scorecard ? ` (public score ${pyStr(rep.scorecard.score)})` : ''),
    scorecardCi ? fileLink(scorecardCi[0]) : [],
  );
  const bp: any[] =
    !privateRepo && got.bestpractices[0] === 200 && Array.isArray(got.bestpractices[1]) ? got.bestpractices[1] : [];
  if (privateRepo) {
    res('posture-best-practices-badge', 'na', 'The OpenSSF Best Practices badge is for open source (public) projects');
  } else if (bp.length) {
    const lvl = pyOr(get(bp[0], 'badge_level'), get(bp[0], 'badge_percentage_0'));
    res(
      'posture-best-practices-badge',
      pyIn(get(bp[0], 'badge_level'), ['passing', 'silver', 'gold']) ? 'pass' : 'warn',
      `OpenSSF Best Practices badge: ${pyStr(lvl)}`,
      [{ label: 'Badge', url: `https://www.bestpractices.dev/projects/${pyStr(get(bp[0], 'id'))}` }],
    );
  } else {
    res('posture-best-practices-badge', 'fail', 'No OpenSSF Best Practices badge');
  }
  const agents = find(AGENT_FILES);
  if (agents.length) {
    // any() stops at the first file with security rules, so later files aren't read.
    let secOk = false;
    for (const p of agents.slice(0, 4)) {
      if (search(SECURITY_RULES, (await read(p)) || '')) {
        secOk = true;
        break;
      }
    }
    // Any file that couldn't be read may hold the rules.
    const agentUnread = secOk ? undefined : agents.slice(0, 4).find((p) => unread.has(p));
    if (agentUnread) {
      res('ai-agent-instructions', 'unknown', couldNotRead(agentUnread), fileLink(agentUnread));
    } else {
      res(
        'ai-agent-instructions',
        secOk ? 'pass' : 'warn',
        `${agents[0]}` + (secOk ? ' includes security rules' : ' has no security rules'),
        fileLink(agents[0]),
      );
    }
  } else {
    res('ai-agent-instructions', 'na', 'No AI agent instruction files');
  }

  // ---- private layer (admin-only settings)
  if (admin) {
    await privateLayer(http, rep, repo, owner, branch, meta, res, finding, noBlock, rulesetsFailed);
  } else {
    for (const [it, why] of NEEDS_PRIVATE_LAYER) {
      if (!Object.hasOwn(R, it)) res(it, 'unknown', `${why}: needs the private layer (admin token) or the GitHub App`);
    }
  }
  if (http.rateLimited) rep.errors.push(RATE_LIMITED);
  rep.summary = Object.fromEntries(
    STATUSES.map((s) => [s, Object.values(R).filter((r) => r.status === s).length]),
  ) as Record<Status, number>;
  rep.api_calls = http.calls;
  log(`done: ${pyRepr(rep.summary)} (${http.calls} requests)`);
  return rep;
}

/** From this day GitHub gave new personal repositories (and new organizations) a read-only GITHUB_TOKEN by default. */
const READ_ONLY_DEFAULT_SINCE = '2023-02-02';

/**
 * What the token of a workflow without a permissions block can do, as far as a public scan can tell. It gets the
 * repository's default, a setting only an admin can read. A personal repository created since GitHub made that
 * read-only starts read-only, an older one kept read and write, and an organization's repository starts with what the
 * organization sets. Any of them may have been changed since.
 */
function tokenDefault(
  ownerType: unknown,
  createdAt: unknown,
): { severity: Finding['severity']; title: string; readOnly: boolean } {
  const gets = 'No permissions block, so the token gets the repository default';
  const created = typeof createdAt === 'string' && /^\d{4}-\d\d-\d\d/.test(createdAt) ? createdAt.slice(0, 10) : null;
  if (ownerType === 'User' && created && created >= READ_ONLY_DEFAULT_SINCE) {
    return {
      severity: 'low',
      title: `${gets}: read-only for this repository unless that setting was changed`,
      readOnly: true,
    };
  }
  if (ownerType === 'User' && created) {
    return {
      severity: 'medium',
      title: `${gets}: read and write for repositories created before February 2023, unless that setting was changed`,
      readOnly: false,
    };
  }
  if (ownerType === 'Organization') {
    return {
      severity: 'medium',
      title: `${gets}: whatever the organization sets, which can allow write access`,
      readOnly: false,
    };
  }
  // Without the owner's type or the creation date, all that's sure is that the default can allow write access.
  return { severity: 'medium', title: `${gets}, which can allow write access`, readOnly: false };
}

/** How many of the n workflows have no permissions block and what that means, or that they all have one. */
function tokenSummary(missing: number, n: number): string {
  if (!missing) {
    if (n === 1) return 'The only workflow declares permissions';
    return n === 2 ? 'Both workflows declare permissions' : `All ${n} workflows declare permissions`;
  }
  const lack = n === 1 ? 'The only workflow has' : `${missing} of ${n} workflows ${missing === 1 ? 'has' : 'have'}`;
  return `${lack} no permissions block, so ${missing === 1 ? 'it gets' : 'they get'} the repository's default token access`;
}

/** Check likely OSS-Fuzz project names; confirm via main_repo in project.yaml. */
async function ossFuzzGuess(http: Http, owner: string, name: string): Promise<string[]> {
  const found: string[] = [];
  const lower = name.toLowerCase();
  const candidates = new Set([lower, lower.replaceAll('-', '_'), lower.replaceAll('_', '-'), owner.toLowerCase()]);
  // Compiled only once a project.yaml is found, as in Python (`body and re.search(...)`).
  let mainRepo: RegExp | undefined;
  for (const cand of candidates) {
    const [, body] = await http.text(
      `https://raw.githubusercontent.com/google/oss-fuzz/master/projects/${quote(cand)}/project.yaml`,
      { auth: false },
    );
    if (!body) continue;
    mainRepo ??= re(
      String.raw`(?im)^main_repo:\s*["\']?https?://github\.com/` +
        `${reEscape(owner)}/${reEscape(name)}` +
        String.raw`(\.git)?/?["\']?\s*$`,
      '',
      false,
    );
    if (search(mainRepo, body)) found.push(cand);
  }
  return found;
}
