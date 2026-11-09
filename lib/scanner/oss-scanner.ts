// Is the repo enrolled in Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner)? A project enrolls with a
// pull request that adds projects/<name>/project.yaml there, and it picks <name> itself. So the check lists the project
// folders, tries the few whose names look like this repo's, and confirms one by the repo: URL in its project.yaml.
// This check is new in 0.4.0, with no Python original, so it's plain TypeScript rather than a port.
import type { Http } from './http.ts';
import type { Evidence, Status } from './types.ts';

/** This guide's cue for when to look (Anthropic decides case by case): more stars or more dependents than these. */
export const OSS_SCANNER_STARS = 1000;
export const OSS_SCANNER_DEPENDENTS = 200;
const OSS_SCANNER = 'anthropics/oss-scanner';
/** How many candidate folders are tried at most. */
const CANDIDATES = 8;

export interface OssScannerResult {
  status: Status;
  summary: string;
  evidence: Evidence[];
  details: Record<string, unknown>;
}

/** Names as the matching sees them: lower case, with "_" and "." read as "-". */
const norm = (s: string) => s.toLowerCase().replace(/[_.]/g, '-');
const order = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The project folders (from `dirs`) that may be OWNER/NAME's, most likely first, at most `limit`. A folder ranks by the
 * first rule it meets: it is the name; it is the owner; it is owner-name or name-owner; it starts with name- or ends
 * with -name; it contains the name (a name of 4+ characters); the name contains it (a folder of 4+); it starts or ends
 * with the owner (an owner of 4+). Ties go to the shorter folder, then to alphabetical order.
 */
export function ossScannerCandidates(
  dirs: readonly string[],
  owner: string,
  name: string,
  limit = CANDIDATES,
): string[] {
  const o = norm(owner);
  const n = norm(name);
  const rules: ((d: string) => boolean)[] = [
    (d) => d === n,
    (d) => d === o,
    (d) => d === `${o}-${n}` || d === `${n}-${o}`,
    (d) => d.startsWith(`${n}-`) || d.endsWith(`-${n}`),
    (d) => n.length >= 4 && d.includes(n),
    (d) => d.length >= 4 && n.includes(d),
    (d) => o.length >= 4 && (d.startsWith(o) || d.endsWith(o)),
  ];
  return dirs
    .map((dir) => {
      const key = norm(dir);
      return { dir, key, rank: rules.findIndex((matches) => matches(key)) };
    })
    .filter((c) => c.rank >= 0)
    .sort((a, b) => a.rank - b.rank || a.key.length - b.key.length || order(a.key, b.key) || order(a.dir, b.dir))
    .slice(0, Math.max(0, limit))
    .map((c) => c.dir);
}

/**
 * The OWNER/NAME that a project.yaml's top-level repo: names, or null unless it's an
 * http(s)://(www.)github.com/OWNER/NAME URL. The value loses its quotes, a # comment, a #branch, .git and a trailing
 * slash first.
 */
export function ossScannerRepo(yaml: string): string | null {
  const line = /^repo[ \t]*:(.*)$/m.exec(yaml);
  if (!line) return null;
  const value = line[1]
    .replace(/\s#.*$/, '') // a comment: "#" after whitespace
    .trim()
    .replace(/^(["'])(.*)\1$/, '$2')
    .trim()
    .replace(/#.*$/, '') // a #branch or #tag
    .replace(/\/+$/, '')
    .replace(/\.git$/i, '')
    .replace(/\/+$/, '');
  const m = /^https?:\/\/(?:www\.)?github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)$/i.exec(value);
  return m ? `${m[1]}/${m[2]}` : null;
}

/** Whether a project.yaml pauses its reports: a top-level disabled: true, yes or on, in any case, maybe quoted. */
export function ossScannerDisabled(yaml: string): boolean {
  return /^disabled[ \t]*:[ \t]*(["']?)(?:true|yes|on)\1(?:[ \t]+#.*|[ \t]*\r?)$/im.test(yaml);
}

/** Whether a repo is big enough to look for: strictly more stars or dependents than the cue (a missing count is 0). */
export function ossScannerEligible(stars?: number | null, dependents?: number | null): boolean {
  return (stars || 0) > OSS_SCANNER_STARS || (dependents || 0) > OSS_SCANNER_DEPENDENTS;
}

const count = (n: number, unit: string) => `${n.toLocaleString('en-US')} ${unit}${n === 1 ? '' : 's'}`;
const result = (status: Status, summary: string, evidence: Evidence[] = [], details = {}): OssScannerResult => ({
  status,
  summary,
  evidence,
  details,
});

/**
 * The sast-oss-scanner result for OWNER/NAME (as GitHub spells it). A private repo, whatever its size, or a repo below
 * the cue gets na and costs no request; a bigger public one costs 2 API calls (the project folders) and one raw
 * project.yaml per candidate, up to the first match.
 */
export async function ossScannerCheck(
  http: Http,
  repo: {
    owner: string;
    name: string;
    full: string;
    private?: boolean;
    stars?: number | null;
    dependents?: number | null;
  },
): Promise<OssScannerResult> {
  // OSS Scanner takes public repositories only, so a private one is never looked up.
  if (repo.private) return result('na', 'Only for public repositories');
  const stars = repo.stars || 0;
  const dependents = repo.dependents || 0;
  if (!ossScannerEligible(stars, dependents)) {
    return result(
      'na',
      `For projects with over ${count(OSS_SCANNER_STARS, 'star')} or ${count(OSS_SCANNER_DEPENDENTS, 'dependent')} ` +
        `(this one has ${count(stars, 'star')} and ${count(dependents, 'dependent')})`,
    );
  }
  const unreadable = (status: number) =>
    result('unknown', `Couldn't read ${OSS_SCANNER} (${status === 200 ? 'unexpected answer' : `HTTP ${status}`})`);
  const [rootStatus, root] = await http.json(`/repos/${OSS_SCANNER}/git/trees/main`);
  const projects = Array.isArray(root?.tree)
    ? root.tree.find((t: any) => t?.path === 'projects' && t?.type === 'tree')
    : null;
  if (rootStatus !== 200 || !/^[0-9a-f]{40,64}$/i.test(projects?.sha ?? '')) return unreadable(rootStatus);
  const [listStatus, list] = await http.json(`/repos/${OSS_SCANNER}/git/trees/${projects.sha}`);
  if (listStatus !== 200 || !Array.isArray(list?.tree)) return unreadable(listStatus);
  const dirs: string[] = list.tree
    .filter((t: any) => t?.type === 'tree' && typeof t.path === 'string')
    .map((t: any) => t.path);

  let trouble: { dir: string; status: number } | null = null;
  for (const dir of ossScannerCandidates(dirs, repo.owner, repo.name)) {
    const path = `projects/${encodeURIComponent(dir)}`;
    const yamlUrl = `https://raw.githubusercontent.com/${OSS_SCANNER}/main/${path}/project.yaml`;
    const [status, body] = await http.text(yamlUrl, { auth: false });
    if (body !== null && ossScannerRepo(body)?.toLowerCase() === repo.full.toLowerCase()) {
      const evidence = [{ label: `OSS Scanner ${dir}`, url: `https://github.com/${OSS_SCANNER}/tree/main/${path}` }];
      return ossScannerDisabled(body)
        ? result(
            'warn',
            `Enrolled in Anthropic's OSS Scanner (projects/${dir}), but reports are paused (disabled: true)`,
            evidence,
            { project: dir, disabled: true },
          )
        : result('pass', `Enrolled in Anthropic's OSS Scanner (projects/${dir})`, evidence, { project: dir });
    }
    // 404 is a folder that has no project.yaml. Anything else (a network error, a 5xx, a rate limit) means a folder
    // that may be this repo's went unread, so "not enrolled" can't be said.
    if (status !== 200 && status !== 404) trouble ??= { dir, status };
  }
  if (trouble) {
    return result(
      'unknown',
      `Couldn't read projects/${trouble.dir}/project.yaml in ${OSS_SCANNER} (HTTP ${trouble.status})`,
    );
  }
  return result('fail', "Not enrolled in Anthropic's OSS Scanner");
}
