/**
 * Build the index of GitHub repos that have an OSS-Fuzz project, from each project's main_repo in google/oss-fuzz.
 * It reads about 1,300 files, so it's far too slow for a request: the site ships a copy (lib/ossfuzz.json), which
 * `npm run ossfuzz` refreshes, and a long-running server refreshes its own copy once a day (lib/ossfuzz.ts).
 * No JSON imports here, so plain `node` can run it.
 */
import { mapLimit } from './pool.ts';

export type OssFuzzIndex = Record<string, string[]>;

/** Map 'owner/repo' (lower case) to its OSS-Fuzz project names. */
export async function buildIndex(token?: string | null): Promise<OssFuzzIndex> {
  const headers: Record<string, string> = { Accept: 'application/vnd.github+json', 'User-Agent': 'sosf-guide' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const get = async (url: string) => {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    return r.json();
  };
  const root = await get('https://api.github.com/repos/google/oss-fuzz/git/trees/master');
  const projects = root.tree.find((t: { path: string }) => t.path === 'projects');
  const names: string[] = (await get(`https://api.github.com/repos/google/oss-fuzz/git/trees/${projects.sha}`)).tree
    .filter((t: { type: string }) => t.type === 'tree')
    .map((t: { path: string }) => t.path);
  const repos = await mapLimit(names, 16, async (name) => {
    try {
      const r = await fetch(`https://raw.githubusercontent.com/google/oss-fuzz/master/projects/${name}/project.yaml`, {
        headers: { 'User-Agent': 'sosf-guide' },
        signal: AbortSignal.timeout(30_000),
      });
      const m = r.ok ? /^main_repo:\s*["']?([^\s"']+)/m.exec(await r.text()) : null;
      return m ? m[1] : '';
    } catch {
      return '';
    }
  });
  const index: OssFuzzIndex = {};
  names.forEach((name, i) => {
    const m = /github\.com[/:]([^/]+)\/([^/.\s]+)/.exec(repos[i]);
    if (m) (index[`${m[1]}/${m[2]}`.toLowerCase()] ??= []).push(name);
  });
  const keys = Object.keys(index).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return Object.fromEntries(keys.map((k) => [k, index[k].sort()]));
}

/** The index as one entry per line (the shipped file's format, which keeps refresh diffs small). */
export function formatIndex(index: OssFuzzIndex): string {
  const entries = Object.entries(index).map(
    ([repo, names]) => `${JSON.stringify(repo)}: [\n${names.map((n) => JSON.stringify(n)).join(',\n')}\n]`,
  );
  return `{\n${entries.join(',\n')}\n}\n`;
}
