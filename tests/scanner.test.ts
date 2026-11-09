// Tests for lib/scanner. The expected values in tests/fixtures/scanner/expected.json were recorded from the Python
// scanner it replaced (scanner/sosf_scan.py in commit a55738d), so they started as a parity check. They're now the
// scanner's reference behavior: when you change what it reports on purpose, update the matching values there.
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, delimiter, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from '../lib/scanner/cli.ts';
import { decodeReplace } from '../lib/scanner/http.ts';
import {
  ECOSYSTEM_FILES,
  Http,
  OSS_SCANNER_DEPENDENTS,
  OSS_SCANNER_STARS,
  SCHEMA,
  TIERS,
  VERSION,
  analyzeWorkflow,
  envVarHint,
  findToken,
  ossScannerCandidates,
  ossScannerDisabled,
  ossScannerEligible,
  ossScannerRepo,
  parentKey,
  parentKeys,
  scan,
  splitLines,
  stepBlock,
  tierFor,
} from '../lib/scanner/index.ts';
import type { Report } from '../lib/scanner/index.ts';
import { COMPILED, match, pyLen, quote, re, search } from '../lib/scanner/py.ts';

const FIXTURES = new URL('./fixtures/scanner/', import.meta.url);
const fixtureText = (rel: string) => readFileSync(new URL(rel, FIXTURES), 'utf8');
const fixtureBytes = (rel: string) => new Uint8Array(readFileSync(new URL(rel, FIXTURES)));
const expected = JSON.parse(fixtureText('expected.json'));
const scenarios = JSON.parse(fixtureText('fake-github.json')).scenarios;

/** JSON text, so a comparison also checks key order (the browser code and the Python output share it). */
const json = (v: unknown) => JSON.stringify(v, null, 1);

function normalize(rep: Report): any {
  const copy = JSON.parse(JSON.stringify(rep));
  delete copy.scanned_at;
  delete copy.tool.version;
  return copy;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

// ------------------------------------------------------------------------------------------ fake GitHub
type Route = { status?: number; json?: unknown; text?: string; file?: string; headers?: Record<string, string> };
type Call = [string, string | null, string | null, string | null];

function routesFor(name: string): Record<string, Route | Route[]> {
  const s = scenarios[name];
  return { ...(s.routes_from ? routesFor(s.routes_from) : {}), ...(s.routes ?? {}) };
}

function bodyOf(route: Route): Uint8Array {
  if (route.json !== undefined) return new TextEncoder().encode(JSON.stringify(route.json));
  if (route.text !== undefined) return new TextEncoder().encode(route.text);
  if (route.file !== undefined) return fixtureBytes(route.file);
  return new Uint8Array();
}

/** Serve canned responses through a stubbed global fetch. */
function stubFetch(routes: Record<string, Route | Route[]>): Call[] {
  const calls: Call[] = [];
  const seen = new Map<string, number>();
  vi.stubGlobal('fetch', async (input: string | URL, init: RequestInit = {}) => {
    const url = String(input);
    const h = new Headers(init.headers);
    calls.push([url, h.get('accept'), h.get('authorization'), h.get('x-github-api-version')]);
    let route = routes[url];
    if (Array.isArray(route)) {
      const n = seen.get(url) ?? 0;
      seen.set(url, n + 1);
      route = route[Math.min(n, route.length - 1)];
    }
    const r: Route = route ?? { status: 404, json: { message: 'Not Found' } };
    const status = r.status ?? 200;
    if (status === 0) throw new TypeError('fetch failed');
    const body = status === 204 || status === 304 ? null : bodyOf(r);
    return new Response(body as BodyInit | null, {
      status,
      headers: r.headers ?? { 'content-type': 'application/json' },
    });
  });
  return calls;
}

const sortCalls = (calls: Call[]) =>
  [...calls].sort((a, b) =>
    JSON.stringify(a) < JSON.stringify(b) ? -1 : JSON.stringify(a) > JSON.stringify(b) ? 1 : 0,
  );

/** scan() one of the fake-github.json scenarios, with any of its routes replaced. */
async function scanScenario(name: string, replace: Record<string, Route | Route[]> = {}) {
  const s = scenarios[name];
  const o = s.options ?? {};
  const calls = stubFetch({ ...routesFor(name), ...replace });
  const logs: string[] = [];
  const rep = await scan(s.repo, {
    token: o.token ?? null,
    layer: o.layer ?? 'private',
    log: (msg) => logs.push(msg),
    ossFuzzLookup: o.oss_fuzz_lookup ? (r) => o.oss_fuzz_lookup[r] ?? [] : null,
    assumeAdmin: o.assume_admin ?? false,
    allowPrivate: o.allow_private ?? true,
  });
  return { rep, calls, logs };
}

/** A workflow file from its lines. */
const workflow = (lines: string[]) => lines.join('\n') + '\n';
const PIN = 'b4ffde65f46336ab88eb53be808477a3936bae11';

// ------------------------------------------------------------------------------------------ public API
describe('public API', () => {
  it('exports the constants the server and browser code rely on', () => {
    expect(VERSION).toBe('0.4.2');
    expect(SCHEMA).toBe('sosf-scan/1');
    expect(TIERS.map((t) => t.name)).toEqual(expected.tier_names.map((t: { name: string }) => t.name));
    expect(ECOSYSTEM_FILES.map(([, eco]) => eco)).toEqual([
      'npm',
      'pypi',
      'go',
      'cargo',
      'maven',
      'rubygems',
      'composer',
      'nuget',
      'swift',
    ]);
    expect(ECOSYSTEM_FILES[0][0].test('web/package.json')).toBe(true);
    expect(ECOSYSTEM_FILES[0][0].test('mypackage.json')).toBe(false);
  });

  it('tierFor matches tier_for on a grid of stars and dependents', () => {
    const { stars, dependents, ids } = expected.tiers;
    const got = stars.map((s: number | null) => dependents.map((d: number | null) => tierFor(s, d).id));
    expect(got).toEqual(ids);
    expect(tierFor()).toEqual({ id: 0, name: 'Just you' });
    expect(tierFor(25000, null)).toEqual({ id: 7, name: 'Critical infrastructure' });
  });

  it('splitLines matches str.splitlines()', () => {
    for (const [s, lines] of expected.splitlines) expect([s, splitLines(s)]).toEqual([s, lines]);
  });

  it('quote matches urllib.parse.quote()', () => {
    for (const [s, q] of expected.quote) expect([s, quote(s)]).toEqual([s, q]);
  });

  it('envVarHint matches env_var_hint()', () => {
    for (const [e, hint] of expected.env_var_hint) expect(envVarHint(e)).toBe(hint);
  });

  it('decodes bytes like bytes.decode("utf-8", "replace")', () => {
    for (const [hex, text] of expected.decode)
      expect([hex, decodeReplace(Buffer.from(hex, 'hex'))]).toEqual([hex, text]);
  });
});

// ------------------------------------------------------------------------------------------- workflows
describe('analyzeWorkflow, parentKey and stepBlock give the recorded results', () => {
  for (const [variant, w] of Object.entries<any>(expected.workflows)) {
    it(variant, () => {
      let text = fixtureText(w.file);
      if (w.crlf) text = text.replaceAll('\n', '\r\n');
      const name = basename(w.file, '.yml.txt');
      const lines = splitLines(text);
      expect(lines.length).toBe(w.line_count);
      expect(json(analyzeWorkflow(`.github/workflows/${name}.yml`, text))).toBe(json(w.analysis));
      expect(lines.map((_, i) => parentKey(lines, i))).toEqual(w.parent_keys);
      expect(parentKeys(lines)).toEqual(w.parent_keys);
      const blocks = w.step_blocks.map((id: number) => expected.step_block_texts[id]);
      expect(lines.map((_, i) => stepBlock(lines, i).join('\n'))).toEqual(blocks);
    });
  }

  it('flags the tricky cases', () => {
    const wf = expected.workflows;
    // ${{ github.event.issue.title }} in run: and in an actions/github-script script: is risky; in env: it isn't.
    const risky = wf.injection.analysis.risky_lines.map((r: { line: number }) => r.line);
    expect(risky).toContain(17);
    expect(risky).toContain(33);
    expect(risky).not.toContain(14);
    expect(risky).not.toContain(37);
    // Line 39 has two different untrusted expressions, and both count.
    expect(wf.injection.analysis.risky_lines.filter((r: { line: number }) => r.line === 39)).toEqual([
      { line: 39, expr: '${{ github.event.head_commit.author.email }}' },
      { line: 39, expr: '${{ github.event.workflow_run.head_branch }}' },
    ]);
    // The run: key is searched for up to the top of the file, so an expression deep in a long script is found.
    expect(wf.long_run.analysis.risky_lines.map((r: { line: number }) => r.line)).toEqual([133, 134]);
    expect(wf.long_run.parent_keys[132]).toBe('run');
    // A uses: line inside a run: script is text in the script, not an action reference.
    expect(wf.injection.analysis.uses).not.toContain('actions/fake@v1');
    expect(wf.checkout.analysis.uses).not.toContain('./.github/actions/local');
    expect(wf.prt.analysis.prt_checks_out_pr).toEqual([10, 17]);
    expect(wf.prt.analysis.write_all).toBe(true);
    expect(wf.jobs_all.analysis.job_permissions_all).toBe(true);
    expect(wf.jobs_some.analysis.job_permissions_all).toBe(false);
    expect(wf.workflow_run.analysis.workflow_run_untrusted).toBe(true);
    expect(wf['checkout-crlf'].analysis).toEqual(wf.checkout.analysis);
    // Line 30 is "- uses: actions/checkout@v3" inside a run: heredoc: not a checkout either.
    expect(wf.checkout.analysis.checkouts_no_persist).toEqual([7, 25, 38]);
    expect(wf.checkout.analysis.pull_request).toBe(true);
  });

  it('tells a pull_request trigger from pull_request_target and pull_request_review', () => {
    const triggers: [string, boolean][] = [
      ['on: [push, pull_request]', true],
      ['on: pull_request', true],
      ['on:\n  pull_request:\n    branches: [main]', true],
      ['on:\n  - push\n  - pull_request', true],
      ['on: [pull_request_target]', false],
      ['on:\n  pull_request_target:', false],
      ['on:\n  - pull_request_target', false],
      ['on:\n  pull_request_review:', false],
      ['on: push', false],
    ];
    for (const [on, want] of triggers) {
      expect([on, analyzeWorkflow('.github/workflows/x.yml', `${on}\n`).pull_request]).toEqual([on, want]);
    }
  });

  it('reads workflow_run guards in if: conditions as safe, and a ref or artifact from the triggering run as not', () => {
    const untrusted = (body: string[]) =>
      analyzeWorkflow(
        '.github/workflows/report.yml',
        workflow(['on:', '  workflow_run:', '    workflows: [Build]', ...body]),
      ).workflow_run_untrusted ?? false;
    // A job-level if: over several lines, a step-level one and a comment only mention the triggering run.
    expect(
      untrusted([
        'jobs:',
        '  report:',
        '    if: >-',
        '      github.event.workflow_run.head_repository.full_name == github.repository &&',
        "      github.event.workflow_run.head_branch == 'main'",
        '    runs-on: ubuntu-latest',
        '    steps:',
        "      # Never actions/download-artifact here: github.event.workflow_run.head_sha may be a fork's.",
        `      - uses: actions/checkout@${PIN}`,
        '        with:',
        '          ref: main',
        "      - if: github.event.workflow_run.head_branch == 'main'",
        '        run: echo ok',
      ]),
    ).toBe(false);
    // Checking out the run's commit, or downloading its artifacts, takes in what a pull request may have changed.
    const steps = ['jobs:', '  report:', '    runs-on: ubuntu-latest', '    steps:'];
    expect(
      untrusted([
        ...steps,
        `      - uses: actions/checkout@${PIN}`,
        '        with:',
        '          ref: ${{ github.event.workflow_run.head_sha }}',
      ]),
    ).toBe(true);
    expect(untrusted([...steps, '      - uses: actions/download-artifact@v4'])).toBe(true);
  });

  it('reads a uses: line inside a run: or script: block as script text, not a step', () => {
    const text = workflow([
      'on: push',
      'permissions: {}',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      `      - uses: actions/checkout@${PIN} # v4`,
      '        with:',
      '          persist-credentials: false',
      '      - run: |',
      "          cat > action.yml <<'EOF'",
      '          - uses: actions/checkout@v4',
      '          EOF',
      `      - uses: actions/github-script@${PIN} # v7`,
      '        with:',
      '          script: |',
      '            core.info(`',
      '            uses: octo/fake@v1',
      '            `)',
    ]);
    const a = analyzeWorkflow('.github/workflows/build.yml', text);
    expect(a.uses).toEqual([`actions/checkout@${PIN}`, `actions/github-script@${PIN}`]);
    expect(a.unpinned).toEqual([]);
    expect([a.checkouts, a.checkouts_no_persist]).toEqual([1, []]);
  });

  it('finds an expression however far down a long run: script it is, in time linear in the length', () => {
    // 20,000 script lines. A search limited to 119 lines finds only the first 119 expressions; an unlimited search
    // from each line in turn takes over half a minute here.
    const n = 20_000;
    const script = Array.from({ length: n }, (_, i) => `          echo "\${{ github.event.issue.title }}" ${i}`);
    const text = workflow([
      'on: issues',
      'jobs:',
      '  a:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
    ]);
    const long = text + script.join('\n') + '\n';
    const lines = splitLines(long);
    expect(parentKey(lines, lines.length - 1)).toBe('run');
    const t0 = performance.now();
    const a = analyzeWorkflow('.github/workflows/long.yml', long);
    expect(performance.now() - t0).toBeLessThan(2000);
    expect(a.risky_lines.length).toBe(n);
    expect(a.risky_lines.at(-1)).toEqual({ line: n + 6, expr: '${{ github.event.issue.title }}' });
  });

  it('parentKeys() gives what parentKey() gives, line by line', () => {
    const atoms = [
      'run: |',
      'script: |',
      '- run: echo',
      '- uses: a/b@v1',
      'env:',
      'K: ${{ github.head_ref }}',
      'steps:',
      '- name: x',
      'echo hi',
      '# comment',
      '',
      '-',
      '- - x:',
      '\tTAB: y',
    ];
    let seed = 7;
    const next = (n: number) => (seed = (seed * 1103515245 + 12345) % 2 ** 31) % n;
    for (let file = 0; file < 2000; file++) {
      const lines = Array.from({ length: next(30) }, () => ' '.repeat(next(10)) + atoms[next(atoms.length)]);
      expect(parentKeys(lines)).toEqual(lines.map((_, i) => parentKey(lines, i)));
    }
  });

  it('reports each distinct untrusted expression on a line', () => {
    const text = workflow([
      'on: issue_comment',
      'jobs:',
      '  a:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "${{ github.head_ref }}" "${{ github.event.comment.body }}" "${{github.head_ref}}"',
    ]);
    // The same expression twice, even spaced differently, is one problem with one fix.
    expect(analyzeWorkflow('.github/workflows/a.yml', text).risky_lines).toEqual([
      { line: 6, expr: '${{ github.head_ref }}' },
      { line: 6, expr: '${{ github.event.comment.body }}' },
    ]);
  });

  it('raises on a line index past the end, like Python', () => {
    expect(() => parentKey(['a: 1'], 1)).toThrow(RangeError);
    expect(() => stepBlock(['a: 1'], 1)).toThrow(RangeError);
    expect(stepBlock(['- a: 1'], -1)).toEqual([]);
    expect(parentKey(['x', '  run: echo'], -1)).toBe('run');
  });
});

// ---------------------------------------------------------------------------------------------- regexes
function buildProbes(spec: { base: string[]; swaps: string[][] }): string[] {
  const swap = ([kind, ...args]: string[], s: string): string => {
    if (kind === 'upper') return s.toUpperCase();
    if (kind === 'append') return s + args[0];
    if (kind === 'prepend') return args[0] + s;
    for (let i = 0; i < args.length; i += 2) s = s.replaceAll(args[i], args[i + 1]);
    return s;
  };
  const all = [...spec.base, ...spec.swaps.flatMap((sw) => spec.base.map((b) => swap(sw, b)))];
  return [...new Set(all)];
}

describe('regexes keep their Python meaning', () => {
  it('compiles exactly the recorded patterns', () => {
    const key = (p: { source: string; flags: string }) => JSON.stringify([p.source, p.flags]);
    const ours = new Set(COMPILED.map(key));
    const python = new Set<string>(expected.patterns.map(key));
    expect([...ours].filter((k) => !python.has(k))).toEqual([]);
    expect([...python].filter((k) => !ours.has(k))).toEqual([]);
  });

  it('matches every probe exactly as Python re does', () => {
    const probes = buildProbes(expected.probes);
    expect(probes.length).toBe(expected.probes.count);
    expect(createHash('sha256').update(probes.join('\0'), 'utf8').digest('hex')).toBe(expected.probes.sha256);
    const cp = (s: string, index: number) => pyLen(s.slice(0, index));
    const wrong: unknown[] = [];
    for (const p of expected.patterns) {
      const rx = re(p.source, p.flags, false);
      for (const kind of ['search', 'match'] as const) {
        if (!p[kind]) continue;
        const want = new Map<number, unknown[]>(p[kind].map((hit: unknown[]) => [hit[0], hit.slice(1)]));
        probes.forEach((s, i) => {
          const m = kind === 'search' ? search(rx, s) : match(rx, s);
          const got = m ? [cp(s, m.index), cp(s, m.index) + pyLen(m[0]), ...m.slice(1).map((g) => g ?? null)] : null;
          if (JSON.stringify(got) !== JSON.stringify(want.get(i) ?? null)) {
            wrong.push({ pattern: p.source, kind, probe: s, got, python: want.get(i) ?? null });
          }
        });
      }
    }
    expect(wrong.slice(0, 5)).toEqual([]);
  });

  it('refuses Python syntax it cannot translate exactly, instead of guessing', () => {
    expect(() => re('(?x)a b', '', false)).toThrow();
    expect(() => re('a*+', '', false)).toThrow();
    expect(() => re('(?i)\u00e9', '', false)).toThrow();
    expect(() => re('[\\S]', '', false)).toThrow();
    expect(search(re('a{,2}b', '', false), 'xaab')?.[0]).toBe('aab');
    expect(search(re('a{}', '', false), 'a{}')?.[0]).toBe('a{}');
    expect(search(re('(?P<q>["\'])x(?P=q)', '', false), `'x'`)?.groups?.q).toBe("'");
  });
});

// ----------------------------------------------------------------------------------------------- Http
describe('Http', () => {
  it('sends the token only to api.github.com and raw.githubusercontent.com, and the API version only to the API', async () => {
    const calls = stubFetch({});
    const http = new Http('tok');
    await http.json('/repos/a/b');
    await http.text('https://raw.githubusercontent.com/a/b/main/x');
    await http.text('https://github.com/a/b/network/dependents');
    await http.text('https://raw.githubusercontent.com/a/b/main/y', { auth: false });
    await http.json('https://api.securityscorecards.dev/projects/github.com/a/b');
    expect(calls).toEqual([
      ['https://api.github.com/repos/a/b', 'application/vnd.github+json', 'Bearer tok', '2022-11-28'],
      ['https://raw.githubusercontent.com/a/b/main/x', '*/*', 'Bearer tok', null],
      ['https://github.com/a/b/network/dependents', '*/*', null, null],
      ['https://raw.githubusercontent.com/a/b/main/y', '*/*', null, null],
      ['https://api.securityscorecards.dev/projects/github.com/a/b', 'application/vnd.github+json', null, null],
    ]);
  });

  it('sets the User-Agent', async () => {
    let ua: string | null = null;
    vi.stubGlobal('fetch', async (_: string, init: RequestInit) => {
      ua = new Headers(init.headers).get('user-agent');
      return new Response('{}');
    });
    await new Http().json('/x');
    expect(ua).toBe(`sosf-scan/${VERSION} (+security self-check)`);
  });

  it('retries once on a 5xx or a network error, and reports a network failure as status 0', async () => {
    stubFetch({
      'https://api.github.com/flaky': [{ status: 502 }, { json: { ok: 1 } }],
      'https://api.github.com/down': [{ status: 500 }, { status: 503, json: { message: 'busy' } }],
      'https://api.github.com/gone': { status: 0 },
      'https://api.github.com/missing': [{ status: 404, json: { message: 'Not Found' } }, { json: { ok: 1 } }],
    });
    const http = new Http('tok');
    expect((await http.json('/flaky')).slice(0, 2)).toEqual([200, { ok: 1 }]);
    expect((await http.json('/down')).slice(0, 2)).toEqual([503, { message: 'busy' }]);
    expect((await http.json('/gone')).slice(0, 2)).toEqual([0, null]);
    expect((await http.json('/missing')).slice(0, 2)).toEqual([404, { message: 'Not Found' }]);
    expect(http.calls).toBe(7);
  });

  it('text() is null unless the status is 200; json() parses any status and returns the headers', async () => {
    stubFetch({
      'https://x.test/created': { status: 201, text: 'made' },
      'https://x.test/err': { status: 422, json: { message: 'bad' }, headers: { 'x-thing': '1' } },
    });
    const http = new Http();
    expect(await http.text('https://x.test/created')).toEqual([201, null]);
    expect(await http.json('https://x.test/err')).toEqual([422, { message: 'bad' }, { 'x-thing': '1' }]);
  });

  it('parses JSON bodies like json.loads() on bytes', async () => {
    const http = new Http();
    for (const [hex, value] of expected.json) {
      vi.stubGlobal('fetch', async () => new Response(Buffer.from(hex, 'hex')));
      expect([hex, (await http.json('https://x.test/'))[1]]).toEqual([hex, value]);
    }
  });

  it('follows redirects as one call, dropping the token when a redirect leaves the GitHub token hosts', async () => {
    const calls = stubFetch({
      'https://api.github.com/repos/old/name': {
        status: 301,
        headers: { location: 'https://raw.githubusercontent.com/new/name/main/x' },
      },
      'https://raw.githubusercontent.com/new/name/main/x': {
        status: 302,
        headers: { location: 'https://elsewhere.test/x' },
      },
      'https://elsewhere.test/x': { text: 'hi' },
    });
    const http = new Http('tok');
    expect(await http.text('https://api.github.com/repos/old/name')).toEqual([200, 'hi']);
    expect(calls.map((c) => c[2])).toEqual(['Bearer tok', 'Bearer tok', null]);
    expect(http.calls).toBe(1);
  });

  it('gives up on a redirect loop and returns the redirect status', async () => {
    stubFetch({
      'https://x.test/a': { status: 302, headers: { location: '/b' } },
      'https://x.test/b': { status: 302, headers: { location: '/a' } },
    });
    expect((await new Http().text('https://x.test/a'))[0]).toBe(302);
  });

  it('times out an idle request and retries it once', async () => {
    let n = 0;
    vi.stubGlobal(
      'fetch',
      (_: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          n++;
          init.signal!.addEventListener('abort', () => reject(init.signal!.reason));
        }),
    );
    const http = new Http(null, 0.05);
    expect((await http.json('/slow')).slice(0, 2)).toEqual([0, null]);
    expect(n).toBe(2);
  });

  it("refuses a URL Python's http.client would refuse", async () => {
    stubFetch({});
    await expect(new Http().json('/repos/\u00fc/x')).rejects.toThrow();
    await expect(new Http().json('/repos/a b/x')).rejects.toThrow();
  });
});

// ------------------------------------------------------------------------------------------- findToken
describe('findToken', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sosf-gh-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('prefers --token, then GITHUB_TOKEN, then GH_TOKEN', () => {
    vi.stubEnv('GITHUB_TOKEN', 'from-github-token');
    vi.stubEnv('GH_TOKEN', 'from-gh-token');
    expect(findToken('explicit')).toBe('explicit');
    expect(findToken()).toBe('from-github-token');
    vi.stubEnv('GITHUB_TOKEN', '');
    expect(findToken('')).toBe('from-gh-token');
  });

  it.skipIf(process.platform === 'win32')('falls back to `gh auth token`, and to null without gh', () => {
    vi.stubEnv('GITHUB_TOKEN', '');
    vi.stubEnv('GH_TOKEN', '');
    vi.stubEnv('PATH', dir);
    expect(findToken()).toBeNull();
    const gh = join(dir, 'gh');
    writeFileSync(gh, '#!/bin/sh\n[ "$1 $2" = "auth token" ] && printf "  gho_fake \\n"\n');
    chmodSync(gh, 0o755);
    expect(findToken()).toBe('gho_fake');
    writeFileSync(gh, '#!/bin/sh\necho "not logged in" >&2\nexit 1\n');
    expect(findToken()).toBeNull();
    vi.stubEnv('PATH', [dir, process.env.PATH].join(delimiter));
  });
});

// ---------------------------------------------------------------------------------------------- scan()
describe('scan() against a fake GitHub gives the recorded report', () => {
  for (const [name, want] of Object.entries<any>(expected.scans)) {
    it(name, async () => {
      const { rep, calls, logs } = await scanScenario(name);
      expect(rep.tool).toEqual({ name: 'sosf-scan', version: VERSION });
      expect(rep.scanned_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
      expect(json(normalize(rep))).toBe(json(want.report ?? expected.scans[want.report_same_as].report));
      expect(sortCalls(calls)).toEqual(want.calls);
      expect(logs).toEqual(want.logs);
    });
  }

  it('covers a public scan, a refused private repo and a missing repo', () => {
    expect(expected.scans.public.report.layer).toBe('public');
    expect(expected.scans.refused.report.errors).toEqual([
      'This is a private repository. Scan it with the downloadable scanner and your own token instead.',
    ]);
    expect(expected.scans['not-found'].report.errors).toEqual([
      'repo lookup failed: HTTP 404 (private repo? pass a token)',
    ]);
    expect(expected.scans['admin-org'].report.layer).toBe('private');
  });

  it('throws on a repo without a slash, like the Python unpacking', async () => {
    stubFetch({});
    await expect(scan('nope')).rejects.toThrow();
  });

  it('flags a self-hosted runner on pull_request in a public repo, not only on pull_request_target', async () => {
    const { rep } = await scanScenario('fixes');
    // pr.yml (on: [push, pull_request]) and review.yml (on: pull_request:) run PRs from forks; push.yml doesn't.
    expect(rep.findings.filter((f) => f.item_id === 'ci-runner-hardening').map((f) => [f.title, f.path])).toEqual([
      ['Self-hosted runner in a public repo workflow', '.github/workflows/pr.yml'],
      ['Self-hosted runner in a public repo workflow', '.github/workflows/review.yml'],
    ]);
  });

  it('looks for a file among the files: a security/ folder is not a SECURITY.md', async () => {
    const { rep, calls } = await scanScenario('fixes');
    const r = rep.results;
    expect([r['disc-security-md'].status, r['disc-security-md'].summary]).toEqual([
      'fail',
      'No SECURITY.md in the root, .github/ or docs/',
    ]);
    // Nor is a folder fetched as if it were a file: the only files read are the workflows.
    const reads = calls.map(([url]) => url).filter((url) => url.startsWith('https://raw.githubusercontent.com/octo/'));
    expect(reads.filter((url) => !url.includes('/.github/workflows/'))).toEqual([]);
    // Where a folder (or a submodule) is what the check looks for, it still counts.
    expect(r['fuzz-harnesses'].summary).toBe('Fuzz targets in repo (e.g. fuzz)');
    expect(r['plan-threat-model'].summary).toBe('threat-model found');
  });

  it('counts a workflow with both pull_request_target and workflow_run once', async () => {
    const { rep } = await scanScenario('fixes');
    const r = rep.results['ci-dangerous-triggers'];
    expect([r.status, r.summary]).toEqual(['fail', '1 privileged workflow(s) handle untrusted PR code or artifacts']);
    expect(r.evidence.map((e) => e.label)).toEqual(['.github/workflows/both.yml']);
    const unsafe = rep.findings.filter((f) => f.title === 'allow-unsafe-pr-checkout: true in a privileged workflow');
    expect(unsafe.map((f) => f.path)).toEqual(['.github/workflows/both.yml']);
    // Without the unsafe checkout it's a warning, still counting and listing the workflow once (it has both triggers).
    const url = 'https://raw.githubusercontent.com/octo/fixes/main/.github/workflows/both.yml';
    const safe = (routesFor('fixes')[url] as Route).text!.replace('          allow-unsafe-pr-checkout: true\n', '');
    const warned = (await scanScenario('fixes', { [url]: { text: safe } })).rep.results['ci-dangerous-triggers'];
    expect([warned.status, warned.summary]).toEqual([
      'warn',
      '1 privileged workflow(s) to review (pull_request_target: 1, workflow_run: 1)',
    ]);
    expect(warned.evidence.map((e) => e.label)).toEqual(['.github/workflows/both.yml']);
  });

  it('names the other SAST tools it finds, with the workflows that run them as evidence', async () => {
    const r = (await scanScenario('fixes')).rep.results['sast-other-tools'];
    expect(r.summary).toBe('Other SAST in CI: gosec, Semgrep, Bandit');
    expect(r.evidence).toEqual([
      { label: '.github/workflows/go.yml', url: 'https://github.com/octo/fixes/blob/main/.github/workflows/go.yml' },
      {
        label: '.github/workflows/python.yml',
        url: 'https://github.com/octo/fixes/blob/main/.github/workflows/python.yml',
      },
    ]);
  });

  it('reports an admin-only item it cannot read as unknown, with the HTTP status, instead of dropping it', async () => {
    const { rep } = await scanScenario('admin-denied');
    const items = [
      'deps-alerts',
      'sast-fix-backlog',
      'secrets-rotate-leaked',
      'ci-fork-pr-approval',
      'rel-gated-release',
      'acct-least-privilege',
      'ci-secrets-hygiene',
    ];
    const got = Object.fromEntries(items.map((id) => [id, rep.results[id]]));
    const unknown = (summary: string) => ({ status: 'unknown', summary, evidence: [], details: {}, layer: 'private' });
    expect(got).toEqual({
      'deps-alerts': unknown('Could not read the Dependabot alerts setting (HTTP 403)'),
      'sast-fix-backlog': unknown('Could not read the open code scanning alerts (HTTP 403)'),
      'secrets-rotate-leaked': unknown('Could not read the open secret scanning alerts (HTTP 404)'),
      'ci-fork-pr-approval': unknown('Could not read the fork PR approval policy (HTTP 403)'),
      'rel-gated-release': unknown('Could not read the environment protection rules (HTTP 403)'),
      'acct-least-privilege': unknown('Could not read the accounts with admin on this repo (HTTP 403)'),
      'ci-secrets-hygiene': unknown('Could not read the repository Actions secrets (HTTP 403)'),
    });
  });

  it('counts an advisory without a publication date, and takes the newest date of the others', async () => {
    const r = (await scanScenario('fixes')).rep.results['disc-advisories-cves'];
    expect([r.summary, r.details]).toEqual([
      '4 published security advisories, newest 2025-03-04',
      { count: 4, with_cve: 2 },
    ]);
    const url = 'https://api.github.com/repos/octo/fixes/security-advisories?state=published&per_page=100';
    const undated = { json: [{ ghsa_id: 'GHSA-1111-1111-1111', cve_id: null, published_at: null }] };
    const one = (await scanScenario('fixes', { [url]: undated })).rep.results['disc-advisories-cves'];
    expect([one.summary, one.details]).toEqual(['1 published security advisories', { count: 1, with_cve: 0 }]);
  });

  it("says CodeQL and dependency updates don't apply where there's nothing to scan or update", async () => {
    const treeUrl = 'https://api.github.com/repos/octo/empty/git/trees/main?recursive=1';
    const statuses = async (paths: string[], truncated = false) => {
      const tree = { json: { truncated, tree: paths.map((path) => ({ path, type: 'blob' })) } };
      const r = (await scanScenario('empty-repo', { [treeUrl]: tree })).rep;
      return [r.results['sast-codeql'].status, r.results['deps-update-automation'].status, `${r.meta.ecosystems}`];
    };
    expect(await statuses(['README.md', 'LICENSE', 'notes/plan.sh'])).toEqual(['na', 'na', '']);
    // A requirements file or a Pipfile makes a Python project, with code to scan and packages to update.
    expect(await statuses(['README.md', 'requirements-dev.txt'])).toEqual(['fail', 'fail', 'pypi']);
    expect(await statuses(['Pipfile'])).toEqual(['fail', 'fail', 'pypi']);
    // Code with no manifest has nothing to update; a container image or a dev container has no code to scan.
    expect(await statuses(['tools/build.py'])).toEqual(['fail', 'na', '']);
    expect(await statuses(['Dockerfile'])).toEqual(['na', 'fail', '']);
    expect(await statuses(['.devcontainer/devcontainer.json'])).toEqual(['na', 'fail', '']);
    // A list the API cut short proves nothing is missing.
    expect(await statuses(['README.md'], true)).toEqual(['fail', 'fail', '']);
  });

  it("takes SECURITY.md from the account's public .github repo when the repo has none, as GitHub does", async () => {
    const policy =
      'Please report security vulnerabilities privately through a GitHub security advisory. ' +
      'We aim to answer within three days, and we credit reporters in the advisory once a fix ships. '.repeat(2);
    const policyUrl = 'https://raw.githubusercontent.com/octo/.github/trunk/.github/SECURITY.md';
    const account = {
      'https://api.github.com/repos/octo/.github': { json: { private: false, default_branch: 'trunk' } },
      'https://api.github.com/repos/octo/.github/git/trees/trunk?recursive=1': {
        json: {
          tree: [
            { path: 'docs/SECURITY.md', type: 'blob' },
            { path: 'profile/README.md', type: 'blob' },
            { path: '.github', type: 'tree' },
            { path: '.github/SECURITY.md', type: 'blob' },
          ],
        },
      },
      // GitHub looks in the .github folder first, so that's the policy it shows.
      [policyUrl]: { text: policy },
    };
    const r = (await scanScenario('fixes', account)).rep.results['disc-security-md'];
    expect([r.status, r.summary, r.evidence]).toEqual([
      'pass',
      ".github/SECURITY.md in octo/.github found, the account's default for repos without their own",
      [
        {
          label: '.github/SECURITY.md in octo/.github',
          url: 'https://github.com/octo/.github/blob/trunk/.github/SECURITY.md',
        },
      ],
    ]);
    // A private .github repo provides no defaults.
    const hidden = { json: { private: true, default_branch: 'trunk' } };
    const none = await scanScenario('fixes', { ...account, 'https://api.github.com/repos/octo/.github': hidden });
    expect(none.rep.results['disc-security-md'].status).toBe('fail');

    // Any email address, or a bug bounty program, is a way to report privately (as Vercel's and GitHub's are).
    const statusOf = async (text: string) =>
      (await scanScenario('fixes', { ...account, [policyUrl]: { text } })).rep.results['disc-security-md'].status;
    const filler = ' We investigate every report and fix confirmed problems as quickly as we can.'.repeat(3);
    expect(await statusOf('Please send vulnerability reports to responsible.disclosure@example.com.' + filler)).toBe(
      'pass',
    );
    expect(await statusOf('Submit security issues through our bug bounty program on HackerOne.' + filler)).toBe('pass');
    expect(await statusOf('Open a GitHub issue describing the problem and how to reproduce it.' + filler)).toBe('warn');
  });

  it("leaves OpenSSF Scorecard's results out of the code scanning backlog", async () => {
    const url = 'https://api.github.com/repos/acme/secret/code-scanning/alerts?state=open&per_page=100';
    const alert = (tool: string, sev: string) => ({ tool: { name: tool }, rule: { security_severity_level: sev } });
    const backlog = async (alerts: unknown[]) => {
      const r = (await scanScenario('admin-org', { [url]: { json: alerts } })).rep.results['sast-fix-backlog'];
      return [r.status, r.summary];
    };
    const notCounted = (n: number) =>
      `, not counting ${n} OpenSSF Scorecard results, which grade settings rather than code`;
    expect(await backlog([alert('Scorecard', 'high'), alert('Scorecard', 'high'), alert('Scorecard', 'low')])).toEqual([
      'pass',
      '0 open code scanning alerts (0 critical/high)' + notCounted(3),
    ]);
    expect(await backlog([alert('Scorecard', 'high'), alert('CodeQL', 'medium')])).toEqual([
      'warn',
      '1 open code scanning alerts (0 critical/high)' + notCounted(1),
    ]);
    expect(await backlog([alert('zizmor', 'high')])).toEqual(['fail', '1 open code scanning alerts (1 critical/high)']);
  });
});

// ------------------------------------------------------------------------------------------ OSS Scanner
describe("Anthropic's OSS Scanner check", () => {
  /** Some of the real project folders in anthropics/oss-scanner (November 2026). */
  const REAL = [
    'airflow',
    'apache-apisix',
    'autogpt',
    'bdk_wallet',
    'bitcoin-core',
    'body-parser',
    'curl',
    'django-ninja',
    'express',
    'openssl',
    'rust-bitcoin',
    'social-app-django',
  ];
  const TREES = 'https://api.github.com/repos/anthropics/oss-scanner/git/trees';
  const PROJECTS = `${TREES}/0a55ca7700000000000000000000000000000003`;
  const yamlOf = (dir: string) =>
    `https://raw.githubusercontent.com/anthropics/oss-scanner/main/projects/${dir}/project.yaml`;
  const ossCalls = (calls: Call[]) => calls.filter(([url]) => url.includes('oss-scanner'));
  const result = (status: string, summary: string, evidence: unknown[] = [], details = {}) => ({
    status,
    summary,
    evidence,
    details,
    layer: 'public',
  });
  const demoCore = [
    { label: 'OSS Scanner demo-core', url: 'https://github.com/anthropics/oss-scanner/tree/main/projects/demo-core' },
  ];

  it('ranks the real folders of repos enrolled under other names first', () => {
    expect(ossScannerCandidates(REAL, 'Significant-Gravitas', 'AutoGPT')).toEqual(['autogpt']);
    expect(ossScannerCandidates(REAL, 'bitcoin', 'bitcoin')).toEqual(['bitcoin-core', 'rust-bitcoin']);
    expect(ossScannerCandidates(REAL, 'apache', 'apisix')).toEqual(['apache-apisix']);
    expect(ossScannerCandidates(REAL, 'apache', 'airflow')).toEqual(['airflow', 'apache-apisix']);
    expect(ossScannerCandidates(REAL, 'expressjs', 'body-parser')).toEqual(['body-parser']);
    expect(ossScannerCandidates(REAL, 'bitcoindevkit', 'bdk_wallet')).toEqual(['bdk_wallet']);
    expect(ossScannerCandidates(REAL, 'torvalds', 'linux')).toEqual([]);
  });

  it('ranks by the first rule a folder meets, then the shorter name, then alphabetically, and keeps 8', () => {
    const dirs = [
      'zlib',
      'ser',
      'parser',
      'fast',
      'octo-org-tools',
      'myfastparserlib',
      'fastparser-core',
      'go-fastparser',
      'fastparser-octo-org',
      'octo-org-fastparser',
      'octo-org',
      'fastparser',
    ];
    const ranked = [
      'fastparser', // the name
      'octo-org', // the owner
      'fastparser-octo-org', // name-owner and owner-name, the same length
      'octo-org-fastparser',
      'go-fastparser', // name- or -name
      'fastparser-core',
      'myfastparserlib', // contains the name
      'fast', // inside the name
      'parser',
      'octo-org-tools', // starts with the owner
    ];
    expect(ossScannerCandidates(dirs, 'octo-org', 'fastparser', 20)).toEqual(ranked);
    expect(ossScannerCandidates(dirs, 'octo-org', 'fastparser')).toEqual(ranked.slice(0, 8));
    expect(ossScannerCandidates(dirs, 'octo-org', 'fastparser', 3)).toEqual(ranked.slice(0, 3));
  });

  it('ignores case and reads _ and . as -, but returns the folder names as they are', () => {
    expect(ossScannerCandidates(['socket.io-client', 'socketio', 'Socket_IO'], 'socketio', 'socket.io')).toEqual([
      'Socket_IO',
      'socketio',
      'socket.io-client',
    ]);
  });

  it('matches by containing only when the name, folder or owner has 4 characters or more', () => {
    // A 2-letter name matches itself or with a dash, not inside other words.
    expect(ossScannerCandidates(['jq', 'jq-tools', 'jquery', 'ajq'], 'stedolan', 'jq')).toEqual(['jq', 'jq-tools']);
    // A 3-letter folder inside the name doesn't count; a 4-letter one does.
    expect(ossScannerCandidates(['git', 'libg', 'libgit'], 'libgit2', 'libgit2')).toEqual(['libg', 'libgit']);
    // A folder that starts with a 3-letter owner doesn't count; with a 4-letter owner it does.
    expect(ossScannerCandidates(['abc-tools', 'abc'], 'abc', 'thing')).toEqual(['abc']);
    expect(ossScannerCandidates(['abcd-tools'], 'abcd', 'thing')).toEqual(['abcd-tools']);
  });

  it("reads project.yaml's repo: as OWNER/NAME, for github.com URLs only", () => {
    const cases: [string, string | null][] = [
      ['repo: https://github.com/Significant-Gravitas/AutoGPT#dev\n', 'Significant-Gravitas/AutoGPT'],
      ['repo: https://github.com/example/project    # required: the git repository to scan\n', 'example/project'],
      ['repo: https://github.com/elsewhere/demo#main\n', 'elsewhere/demo'],
      ['repo: "https://github.com/a/b.git"\n', 'a/b'],
      ["repo: 'https://github.com/a/b/'   # quoted, then a comment\n", 'a/b'],
      ['repo: https://github.com/a/b.git/\n', 'a/b'],
      ['repo: https://github.com/a/b.git#v1.2.3 # a tag\n', 'a/b'],
      ['repo: https://www.github.com/a/b\n', 'a/b'],
      ['repo: http://github.com/a/b\n', 'a/b'],
      ['repo: HTTPS://GitHub.COM/Octo/Demo\n', 'Octo/Demo'],
      ['primary_contact: x@example.org\r\nrepo: https://github.com/a/socket.io\r\n', 'a/socket.io'],
      ['repo: https://gitlab.com/a/b\n', null],
      ['repo: git@github.com:a/b.git\n', null],
      ['repo: https://github.com/a/b/tree/main\n', null],
      ['repo: https://github.com/a\n', null],
      ['repo: https://github.com.evil.example/a/b\n', null],
      ['repo: https://evil.example/github.com/a/b\n', null],
      ['repo:\n', null],
      ['  repo: https://github.com/a/b\n', null],
      ['# repo: https://github.com/a/b\nhomepage: https://github.com/a/b\n', null],
      ['', null],
    ];
    for (const [yaml, want] of cases) expect([yaml, ossScannerRepo(yaml)]).toEqual([yaml, want]);
  });

  it('reads a top-level disabled: true, yes or on, in any case and maybe quoted, as paused', () => {
    const paused = [
      'disabled: true',
      'disabled: True',
      'disabled: TRUE',
      'disabled: yes',
      'disabled: on',
      'disabled: "true"',
      "disabled: 'Yes'   # until the release",
      'disabled : on',
      'repo: https://github.com/a/b\r\ndisabled: true\r\nhomepage: https://b.example\r\n',
    ];
    const active = [
      'disabled: false',
      'disabled: no',
      'disabled: off',
      'disabled:',
      '',
      '  disabled: true',
      '# disabled: true',
      'disabled: trueish',
      'disabled: true, for now',
      `disabled: "true'`,
      'not_disabled: true',
    ];
    for (const y of paused) expect([y, ossScannerDisabled(y)]).toEqual([y, true]);
    for (const y of active) expect([y, ossScannerDisabled(y)]).toEqual([y, false]);
  });

  it('looks only at repos with more than 1,000 stars or more than 200 dependents', () => {
    expect([OSS_SCANNER_STARS, OSS_SCANNER_DEPENDENTS]).toEqual([1000, 200]);
    expect(ossScannerEligible(1000, 200)).toBe(false);
    expect(ossScannerEligible(1001, 0)).toBe(true);
    expect(ossScannerEligible(0, 201)).toBe(true);
    expect(ossScannerEligible(null, null)).toBe(false);
    expect(ossScannerEligible(undefined, 201)).toBe(true);
  });

  it('finds a repo enrolled under a folder name of its own, confirmed by its repo: URL', async () => {
    const { rep, calls } = await scanScenario('public');
    expect(rep.results['sast-oss-scanner']).toEqual(
      result('pass', "Enrolled in Anthropic's OSS Scanner (projects/demo-core)", demoCore, { project: 'demo-core' }),
    );
    // The folder named demo is another repo's, so demo-core is read next, and the search stops there. The folder
    // lists come from the API with the token; the project.yaml files are read without it.
    expect(ossCalls(calls).map(([url, , auth]) => [url, auth])).toEqual([
      [`${TREES}/main`, 'Bearer test-token'],
      [PROJECTS, 'Bearer test-token'],
      [yamlOf('demo'), null],
      [yamlOf('demo-core'), null],
    ]);
  });

  it('warns when the enrollment is paused with disabled: true', async () => {
    const r = (await scanScenario('oss-scanner-paused')).rep.results['sast-oss-scanner'];
    expect(r).toEqual(
      result(
        'warn',
        "Enrolled in Anthropic's OSS Scanner (projects/demo-core), but reports are paused (disabled: true)",
        demoCore,
        { project: 'demo-core', disabled: true },
      ),
    );
  });

  it('fails when none of the likely folders is this repo, after reading each one once', async () => {
    const { rep, calls } = await scanScenario('oss-scanner-not-enrolled');
    expect(rep.results['sast-oss-scanner']).toEqual(result('fail', "Not enrolled in Anthropic's OSS Scanner"));
    // demo-core names a repo of the same name on gitlab.com, which doesn't count. airflow and zlib aren't candidates.
    expect(ossCalls(calls).map(([url]) => url)).toEqual([
      `${TREES}/main`,
      PROJECTS,
      ...['demo', 'demo-core', 'demolition', 'pandemonium', 'octopus'].map(yamlOf),
    ]);
  });

  it('skips a repo at the size cue without a request, and looks at one just above it', async () => {
    const { rep, calls } = await scanScenario('oss-scanner-small');
    expect([rep.meta.stars, rep.meta.dependents_total]).toEqual([1000, 200]);
    expect(rep.results['sast-oss-scanner']).toEqual(
      result(
        'na',
        'For projects with over 1,000 stars or 200 dependents (this one has 1,000 stars and 200 dependents)',
      ),
    );
    expect(ossCalls(calls)).toEqual([]);
    const meta = 'https://api.github.com/repos/Octo/Demo';
    const deps = 'https://github.com/octo/demo/network/dependents';
    const withStars = (n: number) => {
      const route = structuredClone(routesFor('oss-scanner-small')[meta]) as Route;
      (route.json as { stargazers_count: number }).stargazers_count = n;
      return route;
    };
    const starred = await scanScenario('oss-scanner-small', { [meta]: withStars(1001) });
    expect(starred.rep.results['sast-oss-scanner'].status).toBe('pass');
    const depended = await scanScenario('oss-scanner-small', {
      [deps]: { text: '<b>151</b> Repositories 50 Packages' },
    });
    expect([depended.rep.meta.dependents_total, depended.rep.results['sast-oss-scanner'].status]).toEqual([
      201,
      'pass',
    ]);
    const tiny = await scanScenario('oss-scanner-small', { [meta]: withStars(1), [deps]: { text: '1 Repositories' } });
    expect(tiny.rep.results['sast-oss-scanner'].summary).toBe(
      'For projects with over 1,000 stars or 200 dependents (this one has 1 star and 1 dependent)',
    );
    expect(ossCalls(tiny.calls)).toEqual([]);
  });

  it("says unknown, with the status, when anthropics/oss-scanner can't be listed", async () => {
    const down = await scanScenario('oss-scanner-down');
    expect(down.rep.results['sast-oss-scanner']).toEqual(
      result('unknown', "Couldn't read anthropics/oss-scanner (HTTP 503)"),
    );
    // Retried once, like every request, and then nothing else is read.
    expect(ossCalls(down.calls).map(([url]) => url)).toEqual([`${TREES}/main`, `${TREES}/main`]);
    const list = await scanScenario('public', { [PROJECTS]: { status: 404, json: { message: 'Not Found' } } });
    expect(list.rep.results['sast-oss-scanner']).toEqual(
      result('unknown', "Couldn't read anthropics/oss-scanner (HTTP 404)"),
    );
    const moved = await scanScenario('public', {
      [`${TREES}/main`]: { json: { sha: 'x', tree: [{ path: 'README.md', type: 'blob' }] } },
    });
    expect(moved.rep.results['sast-oss-scanner']).toEqual(
      result('unknown', "Couldn't read anthropics/oss-scanner (unexpected answer)"),
    );
  });

  it('says unknown, not "not enrolled", when a likely folder could not be read', async () => {
    const offline = await scanScenario('oss-scanner-not-enrolled', { [yamlOf('demolition')]: { status: 0 } });
    expect(offline.rep.results['sast-oss-scanner']).toEqual(
      result('unknown', "Couldn't read projects/demolition/project.yaml in anthropics/oss-scanner (HTTP 0)"),
    );
    const busy = await scanScenario('oss-scanner-not-enrolled', { [yamlOf('octopus')]: { status: 503 } });
    expect(busy.rep.results['sast-oss-scanner'].summary).toBe(
      "Couldn't read projects/octopus/project.yaml in anthropics/oss-scanner (HTTP 503)",
    );
    // An unreadable folder doesn't matter once a later one is this repo.
    const later = await scanScenario('public', { [yamlOf('demo')]: { status: 502 } });
    expect(later.rep.results['sast-oss-scanner'].status).toBe('pass');
  });
});

// ------------------------------------------------------------------------------------- program lookups
describe('Scorecard, the Best Practices badge, OSS-Fuzz and OSS Scanner are looked up for public repos only', () => {
  /** Where each program is asked about a repo: its own host, or its repository on GitHub (raw files or the API). */
  const PROGRAMS: Record<string, string> = {
    Scorecard: 'https://api.securityscorecards.dev/',
    'Best Practices badge': 'https://www.bestpractices.dev/',
    'OSS-Fuzz': '/google/oss-fuzz/',
    'OSS Scanner': '/anthropics/oss-scanner/',
  };
  const programUrls = (calls: Call[]) =>
    calls.map(([url]) => url).filter((url) => Object.values(PROGRAMS).some((p) => url.includes(p)));
  const programsAsked = (calls: Call[]) =>
    Object.entries(PROGRAMS)
      .filter(([, p]) => calls.some(([url]) => url.includes(p)))
      .map(([program]) => program);
  const ITEMS = ['sast-oss-scanner', 'posture-best-practices-badge', 'posture-scorecard', 'fuzz-continuous'];
  const pick = (rep: Report) => Object.fromEntries(ITEMS.map((id) => [id, rep.results[id]]));
  const result = (status: string, summary: string, evidence: unknown[] = [], details = {}) => ({
    status,
    summary,
    evidence,
    details,
    layer: 'public',
  });
  const scorecardYml = {
    label: '.github/workflows/scorecard.yml',
    url: 'https://github.com/octo/vault/blob/main/.github/workflows/scorecard.yml',
  };

  it('never asks about a private repo, however big it is', async () => {
    const { rep, calls } = await scanScenario('private-large');
    // Over 1,000 stars, so a public repo this size would be looked up everywhere (see the next test).
    expect([rep.meta.private, rep.meta.stars]).toEqual([true, 4321]);
    expect(ossScannerEligible(rep.meta.stars, rep.meta.dependents_total)).toBe(true);
    expect(programUrls(calls)).toEqual([]);
    // Nothing but GitHub hears about it: the repo's own API routes, its dependents page, and the account's public
    // .github repo (asked for the SECURITY.md GitHub shows in a repo without its own).
    const elsewhere = calls
      .map(([url]) => url)
      .filter(
        (url) =>
          !/^https:\/\/api\.github\.com\/repos\/octo\/vault([/?]|$)/.test(url) &&
          url !== 'https://github.com/octo/vault/network/dependents' &&
          url !== 'https://api.github.com/repos/octo/.github',
      );
    expect(elsewhere).toEqual([]);
    expect(pick(rep)).toEqual({
      'sast-oss-scanner': result('na', 'Only for public repositories'),
      'posture-best-practices-badge': result(
        'na',
        'The OpenSSF Best Practices badge is for open source (public) projects',
      ),
      // The Scorecard workflow still counts; there's just no public score.
      'posture-scorecard': result('pass', 'OpenSSF Scorecard runs in CI', [scorecardYml]),
      // ClusterFuzzLite and fuzzing in CI still count; OSS-Fuzz is neither looked up nor guessed at.
      'fuzz-continuous': result('pass', 'ClusterFuzzLite; fuzzing in CI'),
    });
    expect(rep.scorecard).toBeNull();
  });

  it('says so before the size cue, for a small private repo too', async () => {
    const { rep, calls } = await scanScenario('admin-org');
    expect([rep.meta.private, rep.meta.stars]).toEqual([true, 0]);
    expect(rep.results['sast-oss-scanner'].summary).toBe('Only for public repositories');
    expect(programUrls(calls)).toEqual([]);
  });

  it('still asks about public repos, and the answers the private scan never asked for are there', async () => {
    expect(programsAsked((await scanScenario('public')).calls)).toEqual(Object.keys(PROGRAMS));
    const { rep, calls } = await scanScenario('private-large-made-public');
    expect(programsAsked(calls)).toEqual(Object.keys(PROGRAMS));
    expect(pick(rep)).toEqual({
      'sast-oss-scanner': result(
        'pass',
        "Enrolled in Anthropic's OSS Scanner (projects/vault)",
        [{ label: 'OSS Scanner vault', url: 'https://github.com/anthropics/oss-scanner/tree/main/projects/vault' }],
        { project: 'vault' },
      ),
      'posture-best-practices-badge': result('pass', 'OpenSSF Best Practices badge: passing', [
        { label: 'Badge', url: 'https://www.bestpractices.dev/projects/9001' },
      ]),
      'posture-scorecard': result('pass', 'OpenSSF Scorecard runs in CI (score 8.1)', [scorecardYml]),
      'fuzz-continuous': result('pass', 'OSS-Fuzz: vault; ClusterFuzzLite; fuzzing in CI', [
        { label: 'OSS-Fuzz vault', url: 'https://github.com/google/oss-fuzz/tree/master/projects/vault' },
      ]),
    });
    expect(rep.scorecard?.score).toBe(8.1);
  });

  it("doesn't consult the server's OSS-Fuzz list about a private repo either", async () => {
    // As the GitHub App's admin check scans (app/api/app/check/route.ts).
    const lookup = vi.fn((repo: string) => (repo === 'octo/vault' ? ['vault'] : []));
    const opts = { token: 'app-token', layer: 'private' as const, assumeAdmin: true, ossFuzzLookup: lookup };
    const hidden = stubFetch(routesFor('private-large'));
    const rep = await scan('octo/vault', opts);
    expect(lookup).not.toHaveBeenCalled();
    expect(rep.results['fuzz-continuous'].summary).toBe('ClusterFuzzLite; fuzzing in CI');
    expect(programUrls(hidden)).toEqual([]);
    // The same repo, public, gets its project from the list instead of a guess.
    const shown = stubFetch(routesFor('private-large-made-public'));
    const pub = await scan('octo/vault', opts);
    expect(lookup).toHaveBeenCalledWith('octo/vault');
    expect(pub.results['fuzz-continuous'].summary).toBe('OSS-Fuzz: vault; ClusterFuzzLite; fuzzing in CI');
    expect(programsAsked(shown)).toEqual(['Scorecard', 'Best Practices badge', 'OSS Scanner']);
  });

  it('reports no score and no badge when those lookups fail for a public repo', async () => {
    const scorecard = 'https://api.securityscorecards.dev/projects/github.com/octo/demo';
    const badge = 'https://www.bestpractices.dev/projects.json?url=https%3A//github.com/octo/demo';
    const { rep, calls } = await scanScenario('public', {
      [scorecard]: { status: 0 },
      [badge]: { status: 500, text: 'oops' },
    });
    expect(rep.scorecard).toBeNull();
    expect([rep.results['posture-scorecard'].status, rep.results['posture-scorecard'].summary]).toEqual([
      'pass',
      'OpenSSF Scorecard runs in CI',
    ]);
    expect([
      rep.results['posture-best-practices-badge'].status,
      rep.results['posture-best-practices-badge'].summary,
    ]).toEqual(['fail', 'No OpenSSF Best Practices badge']);
    // Each was tried twice, like every request.
    expect(calls.filter(([url]) => url === scorecard || url === badge).length).toBe(4);
  });
});

// ------------------------------------------------------------------------------------------------- CLI
describe('CLI', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sosf-cli-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  async function run(argv: string[]) {
    let stdout = '';
    let stderr = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stdout += String(chunk);
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr += String(chunk);
      return true;
    });
    const code = await main(argv);
    vi.restoreAllMocks();
    const prog = basename(process.argv[1] ?? 'sosf-scan.mjs');
    return { code, stdout: stdout.replaceAll(prog, '<PROG>'), stderr: stderr.replaceAll(prog, '<PROG>') };
  }

  for (const [name, want] of Object.entries<any>(expected.cli.runs)) {
    it(`prints the recorded output: ${name}`, async () => {
      vi.stubEnv('GITHUB_TOKEN', 'test-token');
      vi.stubEnv('GH_TOKEN', '');
      const calls = stubFetch(routesFor('public'));
      const out = join(dir, `${name}.json`);
      const got = await run([...want.argv, '--out', out]);
      expect(got.code).toBe(want.code);
      expect(got.stdout.replaceAll(out, '<OUT>')).toBe(want.stdout);
      expect(got.stderr).toBe(want.stderr);
      expect(calls.length).toBe(want.calls);
      const report = JSON.parse(readFileSync(out, 'utf8'));
      expect(json(normalize(report))).toBe(json(want.report ?? expected.scans[want.report_same_as].report));
    });
  }

  for (const [name, want] of Object.entries<any>(expected.cli.usage)) {
    it(`handles arguments like argparse: ${name}`, async () => {
      const calls = stubFetch({});
      const got = await run(want.argv);
      expect(got).toEqual({ code: want.code, stdout: want.stdout, stderr: want.stderr });
      expect(calls.length).toBe(want.calls);
    });
  }

  it('refuses a repo name that is not ASCII letters, digits, ".", "_" and "-", as a usage error', async () => {
    const usageError = { code: 2, stdout: '', stderr: expected.cli.usage['bad-repo'].stderr };
    // Including ones a looser pattern would cut down to a different repo (üa/x to a/x, a b/c to b/c).
    for (const arg of ['ünïcode/repo', 'owner/répo', 'üa/x', 'a b/c', 'owner/..', './repo']) {
      const calls = stubFetch({});
      expect([arg, await run([arg])]).toEqual([arg, usageError]);
      expect(calls).toEqual([]);
    }
    // The URL forms still work.
    vi.stubEnv('GITHUB_TOKEN', 'test-token');
    const out = join(dir, 'ssh.json');
    stubFetch(routesFor('public'));
    expect((await run(['git@github.com:Octo/Demo.git', '--quiet', '--out', out])).code).toBe(0);
    expect(JSON.parse(readFileSync(out, 'utf8')).repo).toBe('octo/demo');
  });
});
