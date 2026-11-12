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
import { fundFromGuide } from '../lib/fund-data.ts';
import { fundEntry, sharingResult, trainingResult } from '../lib/scanner/fund.ts';
import { Hops } from '../lib/scanner/hops.ts';
import { actionMajor, readWorkflow } from '../lib/scanner/jobs.ts';
import { securityConfiguration, smsTwoFactor } from '../lib/scanner/private-layer.ts';
import { cacheOf, publishOf, releaseCacheCheck } from '../lib/scanner/release-caches.ts';
import { bestBadge } from '../lib/scanner/scan.ts';
import { customQueries, licenseGate, memorySafety, refreshBacklog, tracedSecrets } from '../lib/scanner/self-checks.ts';
import { howToReport, mentions, readPolicy, sameRepoLink, sections } from '../lib/scanner/policy.ts';
import {
  cellSpec,
  covers,
  endDate,
  readSupport,
  releaseLine,
  statusOf as cellStatus,
  supportTable,
  supportVerdict,
  targetRelease,
} from '../lib/scanner/versions.ts';
import { parseYaml } from '../lib/scanner/yaml-lite.ts';
import type { YNode } from '../lib/scanner/yaml-lite.ts';
import YAML from 'yaml';
// The page's browser module (allowJs lets TypeScript read it; it isn't type-checked).
import * as sg from '../public/shared/core.js';

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
    expect(VERSION).toBe('0.5.1');
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
      // The app has no "Secrets: read" permission, so its 403 points to the CLI instead of a retry.
      'ci-secrets-hygiene': unknown(
        "The GitHub App can't read the names of Actions secrets; the CLI with an admin's token can check them",
      ),
    });
    // The CLI with an admin's token that GitHub refuses keeps the plain message.
    const solo = structuredClone(routesFor('admin-denied')['https://api.github.com/repos/solo/tool']) as Route;
    Object.assign(solo.json as object, { permissions: { admin: true } });
    const cli = scenarios['admin-denied'];
    stubFetch({ ...routesFor('admin-denied'), 'https://api.github.com/repos/solo/tool': solo });
    const viaCli = await scan(cli.repo, { token: 'admin-token', ossFuzzLookup: () => [] });
    expect([viaCli.layer, viaCli.results['ci-secrets-hygiene']]).toEqual([
      'private',
      unknown('Could not read the repository Actions secrets (HTTP 403)'),
    ]);
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
    // Nor do HTML pages: CodeQL default setup finds no language in them (ntindle/arctic-blower has just these two).
    expect(await statuses(['README.md', 'index.html'])).toEqual(['na', 'na', '']);
    expect(await statuses(['docs/about.htm', 'index.html'])).toEqual(['na', 'na', '']);
    // Beside JavaScript, their scripts are analyzed with it.
    expect(await statuses(['index.html', 'app.js'])).toEqual(['fail', 'na', '']);
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
      ".github/SECURITY.md in octo/.github found, the account's default for repos without their own; it says to report through GitHub's private vulnerability reporting",
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

    // Any email address, or a bug bounty program, is a way to report privately (as Vercel's and GitHub's are). An
    // address at a domain that can't receive mail (example.com) is a template's placeholder, not a way to report.
    const statusOf = async (text: string) =>
      (await scanScenario('fixes', { ...account, [policyUrl]: { text } })).rep.results['disc-security-md'].status;
    const filler = ' We investigate every report and fix confirmed problems as quickly as we can.'.repeat(3);
    expect(
      await statusOf('Please send vulnerability reports to responsible.disclosure@octo-project.org.' + filler),
    ).toBe('pass');
    expect(await statusOf('Please send vulnerability reports to responsible.disclosure@example.com.' + filler)).toBe(
      'warn',
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

// ---------------------------------------------------------------------------- GITHUB_TOKEN permissions
describe('GITHUB_TOKEN permissions', () => {
  const REPO = 'https://api.github.com/repos/octo/fixes';
  const wf = (name: string) => `https://raw.githubusercontent.com/octo/fixes/main/.github/workflows/${name}.yml`;
  // No permissions block anywhere, so the job gets the repository's default token.
  const noBlock = {
    text: workflow([
      'on: [push]',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: make test',
    ]),
  };
  // octo/fixes declares permissions in all six of its workflows; four of them lose their block here.
  const fourWithout = Object.fromEntries(['go', 'pr', 'push', 'python'].map((w) => [wf(w), noBlock]));
  /** octo/fixes, owned by this type of account and created then (GitHub always says when; the fixture doesn't). */
  const ownedBy = (type: string, createdAt: string) => {
    const route = structuredClone(routesFor('fixes')[REPO]) as Route;
    Object.assign(route.json as object, { owner: { login: 'octo', type }, created_at: createdAt });
    return { [REPO]: route };
  };
  /** The check's status and summary, with its findings as [severity, title, path]. */
  const tokenCheck = async (scenario: string, replace: Record<string, Route | Route[]> = {}) => {
    const { rep } = await scanScenario(scenario, replace);
    const r = rep.results['ci-token-permissions'];
    const findings = rep.findings
      .filter((f) => f.item_id === 'ci-token-permissions')
      .map((f) => [f.severity, f.title, f.path]);
    return { status: r.status, summary: r.summary, findings };
  };
  const READ_ONLY =
    'No permissions block, so the token gets the repository default: read-only for this repository unless that ' +
    'setting was changed';
  const PERMS = 'https://api.github.com/repos/acme/secret/actions/permissions/workflow';
  const defaults = (dflt: string, canApprove: boolean) => ({
    [PERMS]: { json: { default_workflow_permissions: dflt, can_approve_pull_request_reviews: canApprove } },
  });

  it('calls a missing block low in a personal repository created since February 2023: its default is read-only', async () => {
    expect(await tokenCheck('fixes', { ...ownedBy('User', '2023-02-02T00:00:00Z'), [wf('go')]: noBlock })).toEqual({
      status: 'warn',
      summary: "1 of 6 workflows has no permissions block, so it gets the repository's default token access",
      findings: [['low', READ_ONLY, '.github/workflows/go.yml']],
    });
    // However many workflows lack a block, a read-only token is all they get: partly done, not missing.
    const most = await tokenCheck('fixes', { ...ownedBy('User', '2025-06-01T12:00:00Z'), ...fourWithout });
    expect([most.status, most.summary, most.findings.length]).toEqual([
      'warn',
      "4 of 6 workflows have no permissions block, so they get the repository's default token access",
      4,
    ]);
  });

  it('calls it medium in an older personal repository, which kept read and write', async () => {
    const old = await tokenCheck('fixes', { ...ownedBy('User', '2023-02-01T23:59:59Z'), [wf('go')]: noBlock });
    expect([old.status, old.findings]).toEqual([
      'warn',
      [
        [
          'medium',
          'No permissions block, so the token gets the repository default: read and write for repositories created ' +
            'before February 2023, unless that setting was changed',
          '.github/workflows/go.yml',
        ],
      ],
    ]);
    // With most workflows lacking a block, the check is missing, as before.
    expect((await tokenCheck('fixes', { ...ownedBy('User', '2019-05-01T12:00:00Z'), ...fourWithout })).status).toBe(
      'fail',
    );
  });

  it("calls it medium in an organization's repository, whose default the organization sets", async () => {
    const org = await tokenCheck('fixes', { ...ownedBy('Organization', '2025-06-01T12:00:00Z'), [wf('go')]: noBlock });
    expect([org.status, org.findings]).toEqual([
      'warn',
      [
        [
          'medium',
          'No permissions block, so the token gets the repository default: whatever the organization sets, which can ' +
            'allow write access',
          '.github/workflows/go.yml',
        ],
      ],
    ]);
    // Without a creation date, all it can say is that the default can allow write access.
    expect((await tokenCheck('fixes', { [wf('go')]: noBlock })).findings).toEqual([
      [
        'medium',
        'No permissions block, so the token gets the repository default, which can allow write access',
        '.github/workflows/go.yml',
      ],
    ]);
  });

  it('keeps permissions: write-all a high finding, next to the job that has no block', async () => {
    const mixed = workflow([
      'on: [push]',
      'jobs:',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    permissions: write-all',
      '    steps:',
      '      - run: make release',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: make test',
    ]);
    const { rep } = await scanScenario('fixes', {
      ...ownedBy('User', '2025-06-01T12:00:00Z'),
      [wf('go')]: { text: mixed },
    });
    expect(
      rep.findings.filter((f) => f.item_id === 'ci-token-permissions').map((f) => [f.severity, f.title, f.hint]),
    ).toEqual([
      ['low', READ_ONLY, 'Add "permissions: {}" at the top and grant per job, e.g. contents: read'],
      ['high', 'permissions: write-all', 'Replace write-all with the scopes each job needs, e.g. contents: read'],
    ]);
  });

  it('passes when every workflow declares permissions', async () => {
    expect(await tokenCheck('fixes', ownedBy('User', '2019-05-01T12:00:00Z'))).toEqual({
      status: 'pass',
      summary: 'All 6 workflows declare permissions',
      findings: [],
    });
    const ci = 'https://api.github.com/repos/acme/secret/contents/.github/workflows/ci.yml?ref=release/2.x';
    const declared = workflow([
      'on: [push]',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: make test',
    ]);
    expect(await tokenCheck('admin-org', { [ci]: { text: declared } })).toEqual({
      status: 'pass',
      summary:
        "Default GITHUB_TOKEN: read-only; Actions can't approve pull requests. Both workflows declare permissions",
      findings: [],
    });
  });

  it('with an admin token, calls it low when the real default is read-only', async () => {
    // acme/secret belongs to an organization, so the public layer could only say its default may allow write access.
    expect((await tokenCheck('admin-org-public-layer')).findings.map(([severity]) => severity)).toEqual(['medium']);
    expect(await tokenCheck('admin-org')).toEqual({
      status: 'warn',
      summary:
        "Default GITHUB_TOKEN: read-only; Actions can't approve pull requests. 1 of 2 workflows has no permissions " +
        "block, so it gets the repository's default token access",
      findings: [
        [
          'low',
          'No permissions block: the token is read-only today through the repository default, and declaring ' +
            'permissions keeps it that way if the default changes',
          '.github/workflows/ci.yml',
        ],
      ],
    });
    // Letting Actions approve pull requests doesn't widen a read-only token, but the check still doesn't pass.
    const approve = await tokenCheck('admin-org', defaults('read', true));
    expect([approve.status, approve.summary, approve.findings.map(([severity]) => severity)]).toEqual([
      'fail',
      'Default GITHUB_TOKEN: read-only; Actions can approve pull requests. 1 of 2 workflows has no permissions ' +
        "block, so it gets the repository's default token access",
      ['low'],
    ]);
  });

  it('with an admin token, calls it high when the real default is read and write', async () => {
    expect(await tokenCheck('admin-org', defaults('write', false))).toEqual({
      status: 'fail',
      summary:
        "Default GITHUB_TOKEN: read and write; Actions can't approve pull requests. 1 of 2 workflows has no " +
        "permissions block, so it gets the repository's default token access",
      findings: [
        [
          'high',
          "No permissions block, so this workflow's token gets the repository's read-and-write default",
          '.github/workflows/ci.yml',
        ],
      ],
    });
  });

  it("shows the deeper scan's findings on the page, not the public scan's guess", async () => {
    const pub = (await scanScenario('admin-org-public-layer')).rep;
    const app = { ...(await scanScenario('admin-org')).rep, layer: 'app' as const };
    const merged = sg.mergeReports([pub, app])!;
    const severities = (r: { findings: { item_id: string; severity: string }[] }) =>
      r.findings.filter((f) => f.item_id === 'ci-token-permissions').map((f) => f.severity);
    expect([severities(pub), severities(app), severities(merged)]).toEqual([['medium'], ['low'], ['low']]);
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

// ---------------------------------------------------------------------------------------- API failures
describe('API failures', () => {
  /** GitHub's answer once a token has used up its hourly requests. */
  const RATE_LIMITED: Route = {
    status: 403,
    json: { message: 'API rate limit exceeded for user ID 1.' },
    headers: { 'content-type': 'application/json', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1794336615' },
  };
  const SERVER_ERROR: Route = { status: 500, text: 'Internal Server Error' };
  const OFFLINE: Route = { status: 0 };
  const NOTICE = 'GitHub rate-limited this scan, so some checks may be wrong. Try again in a few minutes.';
  const FIXES = 'https://api.github.com/repos/octo/fixes';
  const DEFAULTS = 'https://api.github.com/repos/octo/.github';
  /** Each item's status and summary. */
  const pick = (rep: Report, ids: string[]) =>
    Object.fromEntries(ids.map((id) => [id, [rep.results[id].status, rep.results[id].summary]]));

  it('says unknown, not "not protected", when the branch lookups fail', async () => {
    const branch = `${FIXES}/branches/main`;
    const rules = `${FIXES}/rules/branches/main`;
    const items = ['repo-branch-protection', 'repo-signed-commits'];
    const both = await scanScenario('fixes', { [branch]: RATE_LIMITED, [rules]: SERVER_ERROR });
    expect(pick(both.rep, items)).toEqual({
      'repo-branch-protection': ['unknown', 'Could not read whether the default branch (main) is protected (HTTP 403)'],
      'repo-signed-commits': ['unknown', 'Could not read whether signed commits are required (HTTP 500)'],
    });
    // No ruleset rules doesn't rule out the classic protection the branch lookup would have shown.
    const noBranch = await scanScenario('fixes', { [branch]: OFFLINE, [rules]: { json: [] } });
    expect(pick(noBranch.rep, items)).toEqual({
      'repo-branch-protection': ['unknown', 'Could not read whether the default branch (main) is protected (HTTP 0)'],
      'repo-signed-commits': ['info', 'Signed commits are not required (optional)'],
    });
    // The branch's protected flag counts rulesets too, so it answers on its own, though not which kind of protection.
    const unprotected = { json: { name: 'main', protected: false } };
    const flagOnly = await scanScenario('fixes', { [branch]: unprotected, [rules]: OFFLINE });
    expect(pick(flagOnly.rep, items)['repo-branch-protection']).toEqual([
      'fail',
      'The default branch (main) is not protected',
    ]);
    const isProtected = { json: { name: 'main', protected: true } };
    const protectedOnly = await scanScenario('fixes', { [branch]: isProtected, [rules]: OFFLINE });
    expect(pick(protectedOnly.rep, items)['repo-branch-protection']).toEqual(['pass', 'Default branch is protected']);
    // A 404 is an answer: no such branch, and no rules.
    expect(pick((await scanScenario('fixes')).rep, items)['repo-branch-protection']).toEqual([
      'fail',
      'The default branch (main) is not protected',
    ]);
  });

  it("says unknown when the account's .github repo can't be read for a default SECURITY.md", async () => {
    const tree = `${DEFAULTS}/git/trees/main?recursive=1`;
    const security = async (replace: Record<string, Route>) => {
      const r = (await scanScenario('fixes', replace)).rep.results['disc-security-md'];
      return [r.status, r.summary, r.evidence];
    };
    const notChecked = (status: number) => [
      'unknown',
      `No SECURITY.md in this repository, and the account's default couldn't be checked (HTTP ${status})`,
      [],
    ];
    expect(await security({ [DEFAULTS]: RATE_LIMITED })).toEqual(notChecked(403));
    const account = { [DEFAULTS]: { json: { private: false, default_branch: 'main' } } };
    expect(await security({ ...account, [tree]: SERVER_ERROR })).toEqual(notChecked(500));
    // A policy its tree lists but that can't be read.
    const listed = { ...account, [tree]: { json: { tree: [{ path: 'SECURITY.md', type: 'blob' }] } } };
    const policy = 'https://raw.githubusercontent.com/octo/.github/main/SECURITY.md';
    expect(await security({ ...listed, [policy]: OFFLINE })).toEqual([
      'unknown',
      "Could not read the account's default, SECURITY.md in octo/.github (HTTP 0)",
      [{ label: 'SECURITY.md in octo/.github', url: 'https://github.com/octo/.github/blob/main/SECURITY.md' }],
    ]);
    // An empty .github repo has no files to provide.
    const empty = { status: 409, json: { message: 'Git Repository is empty.' } };
    expect((await security({ ...account, [tree]: empty }))[0]).toBe('fail');
  });

  it('still fails when the account has no .github repo (404)', async () => {
    const { rep } = await scanScenario('fixes');
    expect(pick(rep, ['disc-security-md'])).toEqual({
      'disc-security-md': ['fail', 'No SECURITY.md in the root, .github/ or docs/'],
    });
    expect(rep.errors).toEqual([]);
  });

  it('says once, in errors, that GitHub rate-limited the scan', async () => {
    const limited = await scanScenario('fixes', {
      [DEFAULTS]: RATE_LIMITED,
      [`${FIXES}/branches/main`]: RATE_LIMITED,
      [`${FIXES}/rules/branches/main`]: { status: 429, text: 'Too Many Requests' },
    });
    expect(limited.rep.errors).toEqual([NOTICE]);
    // A refused repo lookup ends the scan, and the notice says why.
    expect((await scanScenario('fixes', { [FIXES]: RATE_LIMITED })).rep.errors).toEqual([
      'repo lookup failed: HTTP 403',
      NOTICE,
    ]);
    // Other failures aren't rate limits.
    const failing = await scanScenario('fixes', { [DEFAULTS]: SERVER_ERROR, [`${FIXES}/branches/main`]: OFFLINE });
    expect(failing.rep.errors).toEqual([]);
  });

  it("says, in errors, when it couldn't list the repository's files, but not for an empty repository", async () => {
    const tree = `${FIXES}/git/trees/main?recursive=1`;
    const errors = async (route: Route) => (await scanScenario('fixes', { [tree]: route })).rep.errors;
    const note = (status: number) =>
      `Could not read the repository's files (HTTP ${status}), so the file checks may be wrong`;
    expect(await errors(SERVER_ERROR)).toEqual([note(500)]);
    expect(await errors(OFFLINE)).toEqual([note(0)]);
    expect(await errors(RATE_LIMITED)).toEqual([note(403), NOTICE]);
    // GitHub answers 409 for a repository with no commits yet (the empty-repo scenario), which has no files to miss.
    const empty = { status: 409, json: { message: 'Git Repository is empty.' } };
    expect(await errors(empty)).toEqual([]);
    expect((await scanScenario('empty-repo')).rep.errors).toEqual([]);
  });

  it('tells a rate limit from other refusals, without changing any answer', async () => {
    const url = `${FIXES}/rulesets?includes_parents=true`;
    const rateLimited = async (route: Route, at = url) => {
      stubFetch({ [at]: route });
      const http = new Http('tok');
      const [status] = await http.json(at);
      return [status, http.rateLimited];
    };
    // The hourly limit, a secondary limit (a Retry-After, or a message that says so), and any 429.
    expect(await rateLimited(RATE_LIMITED)).toEqual([403, true]);
    expect(
      await rateLimited({ status: 403, json: { message: 'Forbidden' }, headers: { 'retry-after': '60' } }),
    ).toEqual([403, true]);
    const secondary = { message: 'You have exceeded a secondary rate limit. Please wait a few minutes.' };
    expect(await rateLimited({ status: 403, json: secondary })).toEqual([403, true]);
    expect(await rateLimited({ status: 429, text: 'Too Many Requests' })).toEqual([429, true]);
    // A 403 for anything else, a 5xx, a network failure, and the last request of the hour, which still succeeds.
    const denied = { message: 'Resource not accessible by integration' };
    expect(await rateLimited({ status: 403, json: denied, headers: { 'x-ratelimit-remaining': '4999' } })).toEqual([
      403,
      false,
    ]);
    expect(await rateLimited({ status: 403, json: { message: 'Upgrade to GitHub Pro' } })).toEqual([403, false]);
    expect(await rateLimited(SERVER_ERROR)).toEqual([500, false]);
    expect(await rateLimited(OFFLINE)).toEqual([0, false]);
    expect(await rateLimited({ json: [], headers: { 'x-ratelimit-remaining': '0' } })).toEqual([200, false]);
    // The notice blames GitHub, so another host's limit doesn't count.
    const scorecard = 'https://api.securityscorecards.dev/projects/github.com/octo/fixes';
    expect(await rateLimited({ status: 429, text: 'Too Many Requests' }, scorecard)).toEqual([429, false]);
  });

  it("doesn't report CodeQL or Dependabot missing when the workflows list fails", async () => {
    const list = `${FIXES}/actions/workflows?per_page=100`;
    const items = ['sast-codeql', 'sast-codeql-actions', 'deps-update-automation'];
    // octo/fixes has code and workflows, but no CodeQL workflow and no Dependabot or Renovate configuration.
    expect(pick((await scanScenario('fixes')).rep, items)).toEqual({
      'sast-codeql': ['fail', 'No CodeQL code scanning found'],
      'sast-codeql-actions': ['fail', 'Workflows are not scanned by CodeQL'],
      'deps-update-automation': ['fail', 'No Dependabot or Renovate configuration'],
    });
    // The list is where CodeQL default setup and Dependabot's update runs show.
    const dynamic = ['dynamic/github-code-scanning/codeql', 'dynamic/dependabot/dependabot-updates'];
    const shown = await scanScenario('fixes', { [list]: { json: { workflows: dynamic.map((path) => ({ path })) } } });
    expect(pick(shown.rep, items)).toEqual({
      'sast-codeql': ['pass', 'CodeQL default setup is on'],
      'sast-codeql-actions': ['unknown', 'CodeQL default setup is on; its languages need the private scan'],
      'deps-update-automation': ['pass', 'Dependabot version updates are active'],
    });
    for (const [route, status] of [
      [SERVER_ERROR, 500],
      [RATE_LIMITED, 403],
      [OFFLINE, 0],
    ] as const) {
      expect(pick((await scanScenario('fixes', { [list]: route })).rep, items)).toEqual({
        'sast-codeql': ['unknown', `No CodeQL workflow, and CodeQL default setup couldn't be checked (HTTP ${status})`],
        'sast-codeql-actions': [
          'unknown',
          `No CodeQL workflow scans the 'actions' language, and CodeQL default setup couldn't be checked (HTTP ${status})`,
        ],
        'deps-update-automation': [
          'unknown',
          `No Dependabot or Renovate configuration, and active Dependabot updates couldn't be checked (HTTP ${status})`,
        ],
      });
    }
  });

  it('says unknown when the release, ruleset or advisory lookups fail', async () => {
    const tags = 'repo-tag-release-protection';
    // octo/demo's latest release, v1.2.3, isn't immutable, and a tag ruleset is what protects it.
    const rulesets = 'https://api.github.com/repos/octo/demo/rulesets?includes_parents=true';
    expect(pick((await scanScenario('public', { [rulesets]: SERVER_ERROR })).rep, [tags])).toEqual({
      [tags]: [
        'unknown',
        "Latest release v1.2.3 is not immutable, and the tag rulesets couldn't be checked (HTTP 500)",
      ],
    });
    // octo/fixes has no releases (a 404), so without the lookup it can't say so.
    expect(pick((await scanScenario('fixes', { [`${FIXES}/releases/latest`]: OFFLINE })).rep, [tags])).toEqual({
      [tags]: ['unknown', 'Could not read the latest release (HTTP 0)'],
    });
    const advisories = `${FIXES}/security-advisories?state=published&per_page=100`;
    expect(pick((await scanScenario('fixes', { [advisories]: RATE_LIMITED })).rep, ['disc-advisories-cves'])).toEqual({
      'disc-advisories-cves': ['unknown', 'Could not read the published security advisories (HTTP 403)'],
    });
  });

  it("doesn't let the admin scan say no tag ruleset exists when the rulesets lookup failed", async () => {
    const tags = 'repo-tag-release-protection';
    // acme/secret is private on a plan without rulesets, which GitHub says with a 403: there are none.
    expect(pick((await scanScenario('admin-org')).rep, [tags])).toEqual({
      [tags]: ['fail', 'Immutable releases are off and no tag ruleset protects release tags'],
    });
    const rulesets = 'https://api.github.com/repos/acme/secret/rulesets?includes_parents=true';
    expect(pick((await scanScenario('admin-org', { [rulesets]: RATE_LIMITED })).rep, [tags])).toEqual({
      [tags]: ['unknown', "Immutable releases are off, and the tag rulesets couldn't be checked (HTTP 403)"],
    });
  });

  it("says unknown, not missing or empty, for a file the tree lists that can't be read", async () => {
    const raw = 'https://raw.githubusercontent.com/octo/demo/main';
    const { rep } = await scanScenario('public', {
      [`${raw}/SECURITY.md`]: SERVER_ERROR,
      [`${raw}/.github/CODEOWNERS`]: OFFLINE,
      [`${raw}/.github/dependabot.yml`]: RATE_LIMITED,
      [`${raw}/.npmrc`]: SERVER_ERROR,
      [`${raw}/pyproject.toml`]: SERVER_ERROR,
      [`${raw}/CLAUDE.md`]: OFFLINE,
      [`${raw}/.github/workflows/codeql.yml`]: SERVER_ERROR,
    });
    const items = [
      'disc-security-md',
      'repo-codeowners',
      'deps-update-automation',
      'deps-cooldown',
      'deps-no-install-scripts',
      'ai-agent-instructions',
    ];
    expect(pick(rep, items)).toEqual({
      'disc-security-md': ['unknown', 'Could not read SECURITY.md (HTTP 500)'],
      'repo-codeowners': ['unknown', 'Could not read .github/CODEOWNERS (HTTP 0)'],
      'deps-update-automation': ['unknown', 'Could not read .github/dependabot.yml (HTTP 403)'],
      'deps-cooldown': ['unknown', 'Could not read .github/dependabot.yml (HTTP 403)'],
      'deps-no-install-scripts': ['unknown', 'Could not read .npmrc (HTTP 500)'],
      // AGENTS.md was read and has no security rules; CLAUDE.md, which has them, wasn't.
      'ai-agent-instructions': ['unknown', 'Could not read CLAUDE.md (HTTP 0)'],
    });
    // Nothing is found in a file no one read.
    expect(rep.findings.filter((f) => ['repo-codeowners', 'deps-update-automation'].includes(f.item_id))).toEqual([]);
    // A workflow that couldn't be read is left out of the checks, so the errors say so (missing.yml is a 404 here).
    expect(rep.errors).toEqual([
      'Could not read 2 workflow files, such as .github/workflows/codeql.yml (HTTP 500), so the checks skipped them',
      NOTICE,
    ]);
    // A private repo's files come from the contents API, under the same rule.
    const policy = 'https://api.github.com/repos/acme/secret/contents/.github/SECURITY.md?ref=release/2.x';
    expect(pick((await scanScenario('admin-org', { [policy]: SERVER_ERROR })).rep, ['disc-security-md'])).toEqual({
      'disc-security-md': ['unknown', 'Could not read .github/SECURITY.md (HTTP 500)'],
    });
    // octo/fixes publishes nothing from CI, so its .goreleaser.yaml is all the release checks have to go on.
    const treeUrl = `${FIXES}/git/trees/main?recursive=1`;
    const tree = structuredClone(routesFor('fixes')[treeUrl]) as Route;
    (tree.json as { tree: unknown[] }).tree.push({ path: '.goreleaser.yaml', type: 'blob' });
    const goreleaser = 'https://raw.githubusercontent.com/octo/fixes/main/.goreleaser.yaml';
    const gr = await scanScenario('fixes', { [treeUrl]: tree, [goreleaser]: OFFLINE });
    expect(pick(gr.rep, ['rel-sbom', 'rel-signing'])).toEqual({
      'rel-sbom': ['unknown', 'Could not read .goreleaser.yaml (HTTP 0)'],
      'rel-signing': ['unknown', 'Could not read .goreleaser.yaml (HTTP 0)'],
    });
  });

  it("labels a check it couldn't read, on the page, as one to try again rather than one for a deeper scan", async () => {
    const shown = async (scenario: string, replace: Record<string, Route> = {}) => {
      const merged = sg.mergeReports((await scanScenario(scenario, replace)).rep);
      return (id: string) => sg.statusLabel(sg.itemStatus({ id }, merged, merged.repo));
    };
    const raw = 'https://raw.githubusercontent.com/octo/demo/main';
    const advisories = 'https://api.github.com/repos/octo/demo/security-advisories?state=published&per_page=100';
    const label = await shown('public', { [`${raw}/SECURITY.md`]: SERVER_ERROR, [advisories]: RATE_LIMITED });
    expect([label('disc-security-md'), label('disc-advisories-cves')]).toEqual([
      'Couldn’t check, try again',
      'Couldn’t check, try again',
    ]);
    // An unknown that only a deeper scan settles keeps its label, and the other statuses theirs.
    expect([label('secrets-push-protection'), label('disc-private-reporting')]).toEqual([
      'Needs a deeper scan',
      'Done',
    ]);
    // The private layer fails that way for want of a permission too, which another try doesn't fix.
    expect((await shown('admin-denied'))('deps-alerts')).toBe('Couldn’t check');
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

  it("ends with what got in the scan's way, such as GitHub's rate limit, unless --quiet", async () => {
    vi.stubEnv('GITHUB_TOKEN', 'test-token');
    const limited = { status: 403, json: { message: 'API rate limit exceeded for user ID 1.' } };
    const routes = { ...routesFor('public'), 'https://api.github.com/repos/octo/demo/branches/main': limited };
    stubFetch(routes);
    const loud = await run(['Octo/Demo', '--out', join(dir, 'loud.json')]);
    expect(loud.stderr.split('\n').slice(-3)).toEqual([
      'warning: Could not read .github/workflows/missing.yml (HTTP 404), so the checks skipped it',
      'warning: GitHub rate-limited this scan, so some checks may be wrong. Try again in a few minutes.',
      '',
    ]);
    stubFetch(routes);
    expect(await run(['Octo/Demo', '--quiet', '--out', join(dir, 'quiet.json')])).toEqual({
      code: 0,
      stdout: '',
      stderr: '',
    });
  });

  it.skipIf(process.platform === 'win32')(
    'says why it scans without a token: --public leaves it out, or none was found',
    async () => {
      const firstLine = async (argv: string[]) => {
        const calls = stubFetch(routesFor('public'));
        const { stderr } = await run([...argv, '--out', join(dir, 'report.json')]);
        return { line: stderr.split('\n')[0], tokens: new Set(calls.map(([, , auth]) => auth)) };
      };
      // The machine has a token, and --public scans as anyone would without it.
      vi.stubEnv('GITHUB_TOKEN', 'test-token');
      vi.stubEnv('GH_TOKEN', '');
      expect(await firstLine(['Octo/Demo', '--public'])).toEqual({
        line:
          '--public: scanning without a token, as anyone would see it ' +
          '(GitHub allows 60 requests an hour; pass --token to raise that)',
        tokens: new Set([null]),
      });
      // A token passed with --public is used, and there's nothing to say.
      const passed = await firstLine(['Octo/Demo', '--public', '--token', 'tok']);
      expect([passed.line, passed.tokens.has('Bearer tok')]).toEqual(['scanning octo/demo (public layer)', true]);
      // Without --public, only a missing token is worth a line: no variable, no --token and no gh.
      vi.stubEnv('GITHUB_TOKEN', '');
      vi.stubEnv('PATH', dir);
      expect(await firstLine(['Octo/Demo'])).toEqual({
        line:
          'no token found: running the public checks only, at 60 requests an hour. ' +
          'Set GITHUB_TOKEN, pass --token, or sign in with `gh auth login`',
        tokens: new Set([null]),
      });
    },
  );
});

// --------------------------------------------------------------------------- 0.5.0: checks that were self-checks
const TINY = 'https://api.github.com/repos/octo/tiny';
const TINY_RAW = 'https://raw.githubusercontent.com/octo/tiny/main/';

/** A small public repository on the fake GitHub: its files, more tree entries, API answers and repository fields. */
function tiny(
  files: Record<string, string>,
  api: Record<string, Route | Route[]> = {},
  { meta = {}, tree = [] as { path: string; type: string }[], truncated = false } = {},
): Record<string, Route | Route[]> {
  return {
    [TINY]: {
      json: {
        name: 'tiny',
        full_name: 'octo/tiny',
        owner: { login: 'octo', type: 'User' },
        default_branch: 'main',
        private: false,
        stargazers_count: 3,
        created_at: '2025-01-01T00:00:00Z',
        ...meta,
      },
    },
    [`${TINY}/git/trees/main?recursive=1`]: {
      json: { truncated, tree: [...Object.keys(files).map((path) => ({ path, type: 'blob' })), ...tree] },
    },
    ...Object.fromEntries(Object.entries(files).map(([p, text]) => [TINY_RAW + p, { text }])),
    ...Object.fromEntries(Object.entries(api).map(([k, v]) => [k.startsWith('http') ? k : TINY + k, v])),
  };
}

async function scanTiny(routes: Record<string, Route | Route[]>) {
  const calls = stubFetch(routes);
  const rep = await scan('octo/tiny', { token: 't', ossFuzzLookup: () => [] });
  return { rep, calls };
}

/** A check's status and summary, or null when the scan left it out. */
const statusOf = (rep: Report, id: string) =>
  rep.results[id] ? [rep.results[id].status, rep.results[id].summary] : null;

/** The release cache check over in-memory workflows (file names under .github/workflows) and other files. */
async function cacheCheck(
  workflows: Record<string, string[]>,
  files: Record<string, string | null> = {},
  extra: { unread?: { path: string; status: number }[]; treeRead?: boolean } = {},
) {
  const all: Record<string, string | null> = {
    ...Object.fromEntries(Object.entries(workflows).map(([n, l]) => [`.github/workflows/${n}`, workflow(l)])),
    ...files,
  };
  const read = async (p: string) => all[p] ?? null;
  return releaseCacheCheck({
    workflows: Object.entries(workflows).map(([n, l]) => ({ path: `.github/workflows/${n}`, text: workflow(l) })),
    unread: extra.unread ?? [],
    files: Object.keys(all),
    treeRead: extra.treeRead ?? true,
    read,
    hops: new Hops(Object.keys(all), read),
  });
}

describe('yaml-lite reads workflows as the yaml package does', () => {
  const norm = (s: string) => s.replace(/\s+/g, ' ').trim();
  const mine = (n: YNode | null): unknown => {
    if (!n) return '';
    if (n.kind === 'scalar') return norm(n.text);
    if (n.kind === 'seq') return n.items.map(mine);
    return Object.fromEntries(n.entries.map((e) => [e.key, mine(e.value)]));
  };
  const theirs = (v: unknown): unknown => {
    if (v === null || v === undefined) return '';
    if (Array.isArray(v)) return v.map(theirs);
    if (typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, theirs(x)]));
    return norm(String(v));
  };
  const same = (text: string) => expect(mine(parseYaml(text))).toEqual(theirs(YAML.parse(text, { merge: true })));

  it('on every workflow fixture', () => {
    for (const w of Object.values<any>(expected.workflows)) {
      const text = fixtureText(w.file);
      let valid = true;
      try {
        YAML.parse(text);
      } catch {
        // A fixture that isn't valid YAML (one tests how the line reader copes) is only read without throwing.
        valid = false;
      }
      if (valid) same(text);
      else expect(() => parseYaml(text)).not.toThrow();
    }
  });

  it('with anchors, merge keys, block scalars, flow collections, quoted keys and comments', () => {
    same(
      workflow([
        "'on':",
        '  push:',
        '    tags: [ "v*", \'r*\' ]  # releases',
        'x-defaults: &defaults',
        '  runs-on: ubuntu-latest',
        '  timeout-minutes: 5',
        'jobs:',
        '  a:',
        '    <<: *defaults',
        '    steps:',
        '    - &checkout',
        '      uses: actions/checkout@v4',
        '      with: { persist-credentials: false, fetch-depth: 0 }',
        '    - run: |-',
        '        echo "a: b"',
        '',
        '        # not a comment',
        '      env:',
        '        LONG: "one \\',
        '          two"',
        '    - *checkout',
        '    - name: >',
        '        folded',
        '        text',
        '      run: echo hi # trailing',
        '  b:',
        '    needs:',
        '    - a',
        '    matrix: {',
        '      os: [linux, macos], # a comment inside',
        '      py: ["3.12"] }',
      ]),
    );
  });

  it('never throws on text that is not YAML', () => {
    for (const bad of ['', ':', '- - -', '{[', '"unclosed', 'a: [1, 2', 'key: |\n', '\t- x\n  y: [']) {
      expect(() => parseYaml(bad)).not.toThrow();
    }
  });

  it('reads a commit pin with its version comment', () => {
    const wf = readWorkflow(
      '.github/workflows/x.yml',
      workflow([
        'on: push',
        'jobs:',
        '  a:',
        '    steps:',
        `      - uses: actions/setup-node@${PIN} # v5.0.0`,
        '      - uses: actions/setup-node@v4.2.1',
        `      - uses: astral-sh/setup-uv@${PIN}`,
      ]),
    );
    expect(wf.jobs[0].steps.map(actionMajor)).toEqual([5, 4, null]);
  });
});

describe('ci-untrusted-artifacts-caches', () => {
  const publishJob = (steps: string[], extra: string[] = []) => [
    'on:',
    '  release:',
    '    types: [published]',
    'jobs:',
    '  publish:',
    '    runs-on: ubuntu-latest',
    ...extra,
    '    steps:',
    ...steps,
  ];

  it('fails when the publishing job restores a cache, with the line in the findings', async () => {
    // mockoon's release-libs.yml: npm run publish, whose package.json script runs npm publish.
    const pkg = JSON.stringify({ scripts: { publish: 'npm publish --workspace=@octo/core --workspace=@octo/cli' } });
    const r = await cacheCheck(
      {
        'release-libs.yml': [
          'on:',
          '  push:',
          "    tags: ['libs-v*']",
          'permissions:',
          '  contents: read',
          'jobs:',
          '  npm-publish:',
          '    runs-on: ubuntu-latest',
          '    permissions:',
          '      id-token: write',
          '    steps:',
          `      - uses: actions/checkout@${PIN} # v7.0.1`,
          `      - uses: actions/setup-node@${PIN} # v7.1.0`,
          '        with:',
          '          node-version: "24"',
          '          cache: npm',
          '      - run: npm ci',
          '      - name: NPM publish',
          '        run: |',
          '          npm run publish',
        ],
      },
      { 'package.json': pkg },
    );
    expect([r.status, r.summary]).toEqual([
      'fail',
      'Publishing job npm-publish in .github/workflows/release-libs.yml restores a cache (actions/setup-node with cache: npm)',
    ]);
    expect(r.findings).toEqual([
      {
        severity: 'medium',
        title: 'Restores a cache in publishing job npm-publish: actions/setup-node with cache: npm',
        path: '.github/workflows/release-libs.yml',
        line: 13,
        hint: "Set cache-mode: none on the job and turn off the action's own cache input (for setup-node, package-manager-cache: false)",
      },
    ]);
  });

  it('follows artifacts back through one job in between, and leaves out caches in jobs that feed nothing published', async () => {
    // aiohttp's ci-cd.yml: a cached llhttp build goes into the dists that deploy publishes; test caches pip.
    const r = await cacheCheck({
      'ci-cd.yml': [
        'on:',
        '  push:',
        "    tags: ['v*']",
        'jobs:',
        '  gen-llhttp:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/cache@v6',
        '        with:',
        '          path: vendor/llhttp/build',
        '          key: llhttp',
        '      - uses: actions/upload-artifact@v7',
        '        with:',
        '          name: llhttp',
        '          path: vendor/llhttp/build',
        '  build:',
        '    needs: gen-llhttp',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/download-artifact@v8',
        '        with:',
        '          name: llhttp',
        '      - run: python -m build',
        '      - uses: actions/upload-artifact@v7',
        '        with:',
        '          name: dist-pure',
        '          path: dist',
        '  test:',
        '    needs: build',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/setup-python@v6',
        '        with:',
        '          cache: pip',
        '      - uses: actions/upload-artifact@v7',
        '        with:',
        '          name: coverage',
        '          path: .coverage',
        '  deploy:',
        '    needs: [build, test]',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/download-artifact@v8',
        '        with:',
        '          pattern: dist-*',
        '          merge-multiple: true',
        '      - uses: pypa/gh-action-pypi-publish@release/v1',
      ],
    });
    expect([r.status, r.summary]).toEqual([
      'fail',
      'Job gen-llhttp in .github/workflows/ci-cd.yml restores a cache (actions/cache) and builds artifact llhttp, ' +
        'which goes into what deploy publishes',
    ]);
    expect(r.findings.map((f) => [f.path, f.line, f.severity])).toEqual([['.github/workflows/ci-cd.yml', 8, 'medium']]);
  });

  it('links a job of a local reusable workflow to the job that publishes its artifact', async () => {
    const r = await cacheCheck({
      'release.yml': [
        'on:',
        '  push:',
        "    tags: ['v*']",
        'jobs:',
        '  build:',
        '    uses: ./.github/workflows/build.yml',
        '  publish:',
        '    needs: build',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/download-artifact@v8',
        '        with:',
        '          name: dist',
        '      - run: gh release upload "$GITHUB_REF_NAME" dist/*',
      ],
      'build.yml': [
        'on: workflow_call',
        'jobs:',
        '  compile:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: Swatinem/rust-cache@v2',
        '      - uses: actions/upload-artifact@v7',
        '        with:',
        '          name: dist',
      ],
    });
    expect([r.status, r.findings.map((f) => [f.path, f.line])]).toEqual(['fail', [['.github/workflows/build.yml', 6]]]);
  });

  it('reads local composite actions, and says when it could not', async () => {
    const steps = ['      - uses: ./.github/actions/setup', '      - run: pnpm publish -r'];
    const action = ['runs:', '  using: composite', '  steps:', '    - uses: actions/setup-node@v6', '      with:'];
    const read = await cacheCheck(
      { 'release.yml': publishJob(steps) },
      { '.github/actions/setup/action.yml': workflow([...action, '        cache: pnpm']) },
    );
    expect([read.status, read.findings.map((f) => [f.path, f.line])]).toEqual([
      'fail',
      [['.github/actions/setup/action.yml', 4]],
    ]);
    const unreadable = await cacheCheck(
      { 'release.yml': publishJob(steps) },
      { '.github/actions/setup/action.yml': null },
    );
    expect([unreadable.status, unreadable.summary]).toEqual([
      'info',
      "Publishing job publish in .github/workflows/release.yml uses ./.github/actions/setup, which the scan couldn't " +
        'read. The publishing jobs it can read restore no caches',
    ]);
  });

  it('follows one hop into a package.json script', async () => {
    const r = await cacheCheck(
      {
        'release.yml': publishJob([
          '      - uses: actions/setup-node@v4',
          '        with:',
          '          cache: npm',
          '      - run: npm run release',
        ]),
      },
      { 'package.json': JSON.stringify({ scripts: { release: 'npm publish --access public' } }) },
    );
    expect([r.status, r.details]).toEqual([
      'fail',
      {
        publishing_jobs: [
          { workflow: '.github/workflows/release.yml', job: 'publish', why: 'npm run release, which runs npm publish' },
        ],
      },
    ]);
  });

  it('warns on a cache that depends on the project or the run, and on artifacts from another run', async () => {
    const node5 = await cacheCheck({
      'release.yml': publishJob(['      - uses: actions/setup-node@v5', '      - run: npm stage publish']),
    });
    expect([node5.status, node5.findings.map((f) => f.severity)]).toEqual(['warn', ['low']]);
    expect(node5.summary).toContain('which from v5 caches npm packages unless package-manager-cache is false');
    // From v10, setup-uv no longer caches unless enable-cache says so.
    const uv = (v: string) =>
      cacheCheck({ 'release.yml': publishJob([`      - uses: astral-sh/setup-uv@${v}`, '      - run: uv publish']) });
    expect([(await uv('v6')).status, (await uv('v10.3.3')).status]).toEqual(['warn', 'pass']);
    const tagGuard = await cacheCheck({
      'release.yml': publishJob([
        '      - uses: actions/cache@v6',
        "        if: github.ref_type != 'tag'",
        '      - run: cargo publish',
      ]),
    });
    expect(tagGuard.status).toBe('warn');
    const otherRun = await cacheCheck({
      'release.yml': publishJob([
        '      - uses: actions/download-artifact@v8',
        '        with:',
        '          run-id: ${{ inputs.run_id }}',
        '          github-token: ${{ github.token }}',
        '      - run: twine upload dist/*',
      ]),
    });
    expect([otherRun.status, otherRun.summary]).toEqual([
      'warn',
      'Publishing job publish in .github/workflows/release.yml downloads artifacts from another workflow run',
    ]);
    // In a workflow_run workflow that's ci-dangerous-triggers' to report.
    const wr = await cacheCheck({
      'publish.yml': [
        'on:',
        '  workflow_run:',
        '    workflows: [CI]',
        'jobs:',
        '  publish:',
        '    steps:',
        '      - uses: actions/download-artifact@v8',
        '        with:',
        '          run-id: ${{ github.event.workflow_run.id }}',
        '      - run: npm publish',
      ],
    });
    expect(wr.status).toBe('pass');
  });

  it("warns on an artifact it can't trace when another job in the run restores a cache", async () => {
    const r = await cacheCheck({
      'release.yml': [
        'on:',
        '  release:',
        'jobs:',
        '  build:',
        '    steps:',
        '      - uses: actions/setup-go@v6',
        '      - uses: actions/upload-artifact@v7',
        '        with:',
        '          name: bin-${{ matrix.os }}',
        '  publish:',
        '    needs: build',
        '    steps:',
        '      - uses: actions/download-artifact@v8',
        '        with:',
        '          name: ${{ inputs.artifact }}',
        '      - run: gh release create v1 bin/*',
      ],
    });
    expect([r.status, r.findings.map((f) => f.title)]).toEqual([
      'warn',
      ["Publishing job publish downloads an artifact the scan can't trace to the job that built it"],
    ]);
  });

  it('passes when no publishing job restores a cache, also with cache-mode: none, unless an action ignores it', async () => {
    const clean = await cacheCheck({
      'release.yml': publishJob([
        '      - uses: actions/setup-node@v6',
        '        with:',
        '          package-manager-cache: false',
        '          registry-url: https://registry.npmjs.org',
        '      - run: npm stage publish',
      ]),
    });
    expect([clean.status, clean.summary]).toEqual([
      'pass',
      'Publishing job publish in .github/workflows/release.yml restores no cache',
    ]);
    const none = await cacheCheck({
      'release.yml': publishJob(
        ['      - uses: actions/setup-node@v6', '        with:', '          cache: npm', '      - run: npm publish'],
        ['    cache-mode: none'],
      ),
    });
    expect([none.status, none.summary]).toEqual([
      'pass',
      'Publishing job publish in .github/workflows/release.yml restores no cache (cache-mode: none)',
    ]);
    const sccache = await cacheCheck({
      'release.yml': publishJob(
        [
          '      - uses: PyO3/maturin-action@v1',
          '        with:',
          "          sccache: 'true'",
          '          command: upload',
        ],
        ['    cache-mode: none'],
      ),
    });
    expect([sccache.status, sccache.findings[0].title]).toEqual([
      'warn',
      'May restore a cache in publishing job publish: PyO3/maturin-action with sccache: true, which may ignore cache-mode: none',
    ]);
  });

  it("says what it can't see, and when nothing publishes", async () => {
    const remote = await cacheCheck({
      'release.yml': [
        'on:',
        '  push:',
        "    tags: ['v*']",
        'jobs:',
        '  release:',
        '    uses: octo/shared/.github/workflows/release.yml@v1',
      ],
    });
    expect([remote.status, remote.summary]).toEqual([
      'info',
      "Release workflow .github/workflows/release.yml calls octo/shared/.github/workflows/release.yml@v1, which the scan can't read",
    ]);
    const ci = await cacheCheck({
      'ci.yml': [
        'on: [push, pull_request]',
        'jobs:',
        '  test:',
        '    steps:',
        '      - uses: actions/setup-go@v6',
        '      - run: go test ./...',
      ],
    });
    expect([ci.status, ci.summary]).toEqual(['na', 'No publishing job or release workflow']);
    expect(
      (
        await releaseCacheCheck({
          workflows: [],
          unread: [],
          files: [],
          treeRead: true,
          read: async () => null,
          hops: new Hops([], async () => null),
        })
      ).status,
    ).toBe('na');
    // A workflow it couldn't read, or a file list it couldn't get, may hold what it didn't find.
    const unread = await cacheCheck(
      { 'release.yml': publishJob(['      - run: cargo publish']) },
      {},
      {
        unread: [{ path: '.github/workflows/other.yml', status: 500 }],
      },
    );
    expect([unread.status, unread.summary]).toEqual([
      'unknown',
      'Could not read .github/workflows/other.yml (HTTP 500)',
    ]);
    expect((await cacheCheck({}, {}, { treeRead: false })).status).toBe('unknown');
  });

  it('knows which actions restore caches and which steps publish', () => {
    const step = (uses: string, w: Record<string, string> = {}, comment = '') =>
      ({
        file: 'x',
        line: 1,
        usesLine: 1,
        runLine: 1,
        runFirst: 1,
        uses,
        comment,
        with: w,
        env: {},
        run: null,
        shell: null,
        if: null,
        all: '',
      }) as const;
    const level = (uses: string, w: Record<string, string> = {}, comment = '') =>
      cacheOf(step(uses, w, comment))?.level ?? null;
    expect([
      level('actions/cache@v4'),
      level('actions/cache@v4', { 'lookup-only': 'true' }),
      level('actions/cache/save@v4'),
      level('actions/setup-go@v5'),
      level('actions/setup-go@v5', { cache: 'false' }),
      level('actions/setup-node@v4'),
      level(`actions/setup-node@${PIN}`, {}, 'v4.4.0'),
      level(`actions/setup-node@${PIN}`),
      level('actions/setup-node@v4', { cache: '${{ matrix.pm }}' }),
      level('actions/setup-python@v6', { cache: 'pip' }),
      level('ruby/setup-ruby@v1', { 'bundler-cache': 'true' }),
      level('gradle/actions/setup-gradle@v4'),
      level('docker/build-push-action@v6', { 'cache-from': 'type=gha' }),
      level('docker/setup-buildx-action@v3'),
      level('docker/setup-buildx-action@v3', { version: 'v0.23.0' }),
      level('actions/checkout@v5'),
    ]).toEqual(['on', null, null, 'on', null, null, null, 'maybe', 'maybe', 'on', 'on', 'on', 'on', null, 'on', null]);
    const pub = (uses: string, w: Record<string, string> = {}) => publishOf(step(uses, w));
    expect([
      pub('goreleaser/goreleaser-action@v6', { args: 'release --clean' }),
      pub('goreleaser/goreleaser-action@v6', { args: 'release --snapshot --clean' }),
      pub('docker/build-push-action@v6', { push: 'false' }),
      pub('docker/build-push-action@v6', { push: "${{ github.event_name != 'pull_request' }}" }),
      pub('changesets/action@v1', { publish: 'pnpm release' }),
      pub('changesets/action@v1', { version: 'pnpm version' }),
      pub('PyO3/maturin-action@v1', { command: 'upload' }),
      pub('PyO3/maturin-action@v1', { command: 'build' }),
    ]).toEqual([
      'goreleaser/goreleaser-action',
      null,
      null,
      'docker/build-push-action with push',
      'changesets/action with publish',
      null,
      'pyo3/maturin-action with command: upload',
      null,
    ]);
    const runs = (run: string) => publishOf({ ...step('x'), uses: null, run });
    expect(
      [
        'npm publish --dry-run',
        'goreleaser release --snapshot',
        'mvn -Dmaven.deploy.skip=true install',
        'echo build',
        '# npm publish',
      ].map(runs),
    ).toEqual([null, null, null, null, null]);
    expect(
      ['npm stage publish --tag next', 'cd pkg && npm publish', './mvnw -B deploy', 'sbt ci-release'].map(runs),
    ).toEqual(['npm stage publish', 'npm publish', 'mvnw -B deploy', 'sbt ci-release']);
  });

  it('is a scan result with its findings, as the other workflow checks are', async () => {
    const wf = publishJob([
      '      - uses: actions/setup-go@v6',
      '      - uses: goreleaser/goreleaser-action@v6',
      '        with:',
      '          args: release --clean',
    ]);
    const { rep } = await scanTiny(tiny({ '.github/workflows/release.yml': workflow(wf) }));
    expect(statusOf(rep, 'ci-untrusted-artifacts-caches')).toEqual([
      'fail',
      'Publishing job publish in .github/workflows/release.yml restores a cache (actions/setup-go, which caches by default)',
    ]);
    expect(rep.results['ci-untrusted-artifacts-caches'].evidence).toEqual([
      {
        label: '.github/workflows/release.yml',
        url: 'https://github.com/octo/tiny/blob/main/.github/workflows/release.yml',
      },
    ]);
    expect(rep.findings.filter((f) => f.item_id === 'ci-untrusted-artifacts-caches').map((f) => f.url)).toEqual([
      'https://github.com/octo/tiny/blob/main/.github/workflows/release.yml#L8',
    ]);
  });
});

describe('rel-security-support', () => {
  const policy = (rows: string[], extra = '') =>
    [
      '# Security Policy',
      '',
      '## Supported Versions',
      '',
      '| Version | Supported |',
      '| ------- | --------- |',
      ...rows,
      '',
    ]
      .concat(['## Reporting a Vulnerability', '', 'Email security@example.com, or use a private advisory.', extra])
      .join('\n');
  const releases = (...tags: (string | [string, boolean])[]) => ({
    json: tags.map((t) =>
      Array.isArray(t) ? { tag_name: t[0], prerelease: t[1] } : { tag_name: t, prerelease: false },
    ),
  });
  const check = async (security: string | null, api: Record<string, Route> = {}) => {
    const files: Record<string, string> = security === null ? {} : { 'SECURITY.md': security };
    const { rep, calls } = await scanTiny(tiny(files, api));
    return { r: statusOf(rep, 'rel-security-support'), calls };
  };

  it('passes when a supported row covers the highest stable version among the latest releases', async () => {
    // mastodon publishes several lines at once, so the newest release can be on an old line.
    const { r } = await check(policy(['| 4.7.x | :white_check_mark: |', '| 4.6.x | ✅ |', '| < 4.6 | :x: |']), {
      '/releases?per_page=10': releases('v4.4.28', 'v4.7.5', 'v4.6.11', ['v4.8.0-beta.1', true], 'v4.8.0-rc.1'),
    });
    expect(r).toEqual(['pass', 'SECURITY.md lists 4.7.x as supported, which covers the newest release, v4.7.5']);
  });

  it('warns on a table that no longer covers the newest release, and on the unedited template', async () => {
    const stale = await check(policy(['| 1.0.x | ✅ |', '| 0.16.x | ✅ |', '| < 0.14 | ❌ |']), {
      '/releases?per_page=10': releases('v1.1.0', 'v1.0.9'),
    });
    expect(stale.r).toEqual(['warn', 'SECURITY.md lists 1.0.x, 0.16.x as supported, but the newest release is v1.1.0']);
    const template = [
      '# Security Policy',
      '',
      '## Supported Versions',
      '',
      'Use this section to tell people about which versions of your project are',
      'currently being supported with security updates.',
      '',
      '| Version | Supported          |',
      '| ------- | ------------------ |',
      '| 5.1.x   | :white_check_mark: |',
      '| 5.0.x   | :x:                |',
      '| 4.0.x   | :white_check_mark: |',
      '| < 4.0   | :x:                |',
    ].join('\n');
    expect((await check(template, { '/releases?per_page=10': releases('v5.1.2') })).r).toEqual([
      'warn',
      "SECURITY.md still has the versions table from GitHub's template (5.1.x, 5.0.x, 4.0.x)",
    ]);
  });

  it('gives info for words without a table, or for no statement, and never fails', async () => {
    const words = ['# Security', '', '## Supported Versions', '', 'Only the latest release gets security fixes.'].join(
      '\n',
    );
    expect((await check(words, { '/releases?per_page=10': releases('v2.3.0') })).r).toEqual([
      'info',
      'SECURITY.md says which versions get fixes in words, not a table: check it covers v2.3.0',
    ]);
    const none = 'Please report vulnerabilities privately through a GitHub security advisory. '.repeat(4);
    expect((await check(none, { '/releases?per_page=10': releases('v2.3.0') })).r).toEqual([
      'info',
      "SECURITY.md doesn't say which versions get security fixes",
    ]);
    expect((await check(null, { '/releases?per_page=10': releases('v2.3.0') })).r).toEqual([
      'info',
      'No SECURITY.md to say which versions get security fixes',
    ]);
  });

  it('compares with the tags when there are no releases, and does not apply without releases, tags or publishing', async () => {
    const table = policy(['| 2.3.x | ✅ |']);
    const tagged = await check(table, {
      '/releases?per_page=10': { json: [] },
      '/tags?per_page=100': { json: [{ name: 'v2.3.0' }, { name: 'v2.2.1' }] },
    });
    expect(tagged.r).toEqual(['pass', 'SECURITY.md lists 2.3.x as supported, which covers the newest release, v2.3.0']);
    expect(tagged.calls.map(([u]) => u)).toContain(`${TINY}/tags?per_page=100`);
    const nothing = await check(table, { '/releases?per_page=10': { json: [] }, '/tags?per_page=100': { json: [] } });
    expect(nothing.r).toEqual(['na', 'No releases, tags or publishing workflow']);
  });

  it("says unknown when it couldn't read the releases to compare the table with", async () => {
    const { r } = await check(policy(['| 2.3.x | ✅ |']), { '/releases?per_page=10': { status: 500, text: 'oops' } });
    expect(r).toEqual(['unknown', 'Could not read the releases to compare with the table in SECURITY.md (HTTP 500)']);
  });

  it('reads the version cells the research found tables use', () => {
    const v = (s: string) => s.split('.').map(Number);
    const cases: [string, string, boolean | null][] = [
      ['2.latest', '2.9.1', true],
      ['0.2.x+', '0.3.1', true],
      ['2.0.X', '2.0.7', true],
      ['2.0.latest', '2.1.0', false],
      ['>= 1.2', '1.10.0', true],
      ['< 4.0', '4.0.1', false],
      ['latest', '9.9', true],
      ['4.28.2', '4.29.5', false],
      // mastodon's table names each line by its first release.
      ['4.7.0', '4.7.5', true],
      ['4.7.0', '4.8.0', false],
      ['3.11', '3.11.2', true],
      ['main', '1.0', null],
    ];
    for (const [cell, ver, want] of cases) expect([cell, covers(cell, v(ver))]).toEqual([cell, want]);
    const t = supportTable(
      policy(['| [v6.x](https://example.com) | ✅ |', '| 3.20.x (LTS) | ✅ |', '| 5.x | until 2020-01-01 |']),
    );
    expect(t.rows).toEqual([
      { version: 'v6.x', supported: true },
      { version: '3.20.x (LTS)', supported: true },
      { version: '5.x', supported: false },
    ]);
    expect(targetRelease([{ tag: 'curl-8_11_0' }, { tag: 'curl-8_10_1' }])).toEqual({
      tag: 'curl-8_11_0',
      version: [8, 11, 0],
    });
  });
});

describe('deps-refresh', () => {
  const ago = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
  const pr = (n: number, days: number, login = 'dependabot[bot]') => ({
    number: n,
    created_at: ago(days),
    user: { login },
    html_url: `https://github.com/octo/tiny/pull/${n}`,
  });
  const PULLS = '/pulls?state=open&sort=created&direction=asc&per_page=100';
  const dependabot = (limit = '') =>
    [
      'version: 2',
      'updates:',
      '  - package-ecosystem: npm',
      '    directory: /',
      limit,
      '  - package-ecosystem: github-actions',
      '    directory: /',
    ]
      .filter((l) => l !== '')
      .join('\n');
  const refresh = async (pulls: Route, yml = dependabot()) =>
    statusOf((await scanTiny(tiny({ '.github/dependabot.yml': yml }, { [PULLS]: pulls }))).rep, 'deps-refresh');

  it('warns when the oldest update pull request is over 90 days old', async () => {
    expect(await refresh({ json: [pr(7, 3, 'octocat'), pr(3, 120), pr(9, 2)] })).toEqual([
      'warn',
      'The oldest open Dependabot pull request, #3, is 120 days old',
    ]);
    const renovate = await scanTiny(
      tiny({ 'renovate.json': '{}' }, { [PULLS]: { json: [pr(1, 200, 'renovate[bot]')] } }),
    );
    expect(statusOf(renovate.rep, 'deps-refresh')).toEqual([
      'warn',
      'The oldest open Renovate pull request, #1, is 200 days old',
    ]);
  });

  it('adds nothing for fresh pull requests, however many, or when they could not be listed', async () => {
    expect(await refresh({ json: [pr(1, 10), pr(2, 40)] })).toBeNull();
    // A queue at dependabot.yml's open-pull-requests-limit isn't a warning: security updates count toward the open
    // pull requests but not toward that limit, so the count can't show it was reached.
    const six = { json: [1, 2, 3, 4, 5, 6].map((n) => pr(n, n)) };
    expect(await refresh(six, dependabot('    open-pull-requests-limit: 1'))).toBeNull();
    expect(await refresh({ status: 403, json: { message: 'Forbidden' } })).toBeNull();
    // A full page that has no bot pull request says nothing about the ones after it.
    expect(refreshBacklog(Array.from({ length: 100 }, (_, i) => pr(i, 300, 'octocat')))).toBeNull();
  });
});

describe('code-memory-safety', () => {
  const memory = async (languages: Route, files: Record<string, string>, opts: Parameters<typeof tiny>[2] = {}) =>
    statusOf((await scanTiny(tiny(files, { '/languages': languages }, opts))).rep, 'code-memory-safety');

  it("doesn't apply when no code is in a language without memory safety", async () => {
    expect(await memory({ json: { TypeScript: 50000, JavaScript: 1200, Shell: 90 } }, { 'src/index.ts': 'x' })).toEqual(
      ['na', 'No C, C++ or other code without memory safety, and no submodules'],
    );
  });

  it('adds nothing when any guard fires: native bytes, a native file, a submodule, a cut-short tree, a failed lookup', async () => {
    // aiohttp: GitHub counts Cython and a little C, and llhttp is a submodule.
    expect(await memory({ json: { Python: 3450007, Cython: 50039, C: 170 } }, { 'aiohttp/web.py': 'x' })).toBeNull();
    const js = { json: { JavaScript: 1200 } };
    expect(await memory(js, { 'index.js': 'x' }, { tree: [{ path: 'vendor/llhttp', type: 'commit' }] })).toBeNull();
    expect(await memory(js, { 'index.js': 'x', 'third_party/zlib/inflate.c': 'x' })).toBeNull();
    expect(await memory(js, { 'index.js': 'x' }, { truncated: true })).toBeNull();
    expect(await memory({ status: 403, json: {} }, { 'index.js': 'x' })).toBeNull();
    expect(memorySafety({ 'Unix Assembly': 10 }, [], [], true)).toBeNull();
    expect(memorySafety({ WebAssembly: 10 }, [], [], true)?.status).toBe('na');
  });
});

describe('the admin checks of an organization (0.5.0)', () => {
  const ORG = 'https://api.github.com/orgs/acme';
  const SMS = `${ORG}/members?filter=2fa_insecure&per_page=100`;
  const CONFIG = 'https://api.github.com/repos/acme/secret/code-security-configuration';
  const DEFAULTS = `${ORG}/code-security/configurations/defaults`;
  const pick = (rep: Report) => ({
    sms: statusOf(rep, 'acct-phishing-resistant-2fa'),
    config: statusOf(rep, 'repo-org-security-config'),
  });

  it('counts the members with SMS 2FA without naming them, and never reads a refusal as a count', async () => {
    const warned = (await scanScenario('admin-org', { [SMS]: { json: [{ login: 'ada' }, { login: 'bo' }] } })).rep;
    expect(pick(warned).sms).toEqual([
      'warn',
      '2 org members still have SMS for 2FA; turn on "Only allow secure two-factor methods" in the org\'s ' +
        'authentication settings',
    ]);
    expect(JSON.stringify(warned.results['acct-phishing-resistant-2fa'])).not.toMatch(/ada|"bo"/);
    expect(pick((await scanScenario('admin-org', { [SMS]: { json: [] } })).rep).sms?.[0]).toBe('info');
    for (const refusal of [
      { status: 422, json: { message: 'Only owners can use this filter.' } },
      { status: 403, json: { message: 'Resource not accessible by integration' } },
      { status: 404, json: { message: 'Not Found' } },
      { json: { message: 'not a list' } },
    ]) {
      const r = pick((await scanScenario('admin-org', { [SMS]: refusal })).rep).sms;
      expect(r?.[0]).toBe('unknown');
    }
    // A personal account has no members to count.
    expect(pick((await scanScenario('assume-admin')).rep).sms).toBeNull();
  });

  it("grades the org's security configuration for the repo and for new repos", async () => {
    const attached = { json: { status: 'attached', configuration: { name: 'GitHub recommended' } } };
    const config = async (cfg: Route, defaults: Route = { json: [] }) =>
      pick((await scanScenario('admin-org', { [CONFIG]: cfg, [DEFAULTS]: defaults })).rep).config;
    expect(await config({ status: 204 })).toEqual(['fail', 'No security configuration is applied to this repository']);
    expect(await config({ json: { status: 'removed', configuration: { name: 'Org default' } } })).toEqual([
      'warn',
      '"Org default" no longer manages this repository (status: removed), so its settings may have drifted',
    ]);
    expect(await config(attached)).toEqual([
      'warn',
      '"GitHub recommended" is attached here, but new private repositories get no configuration by default',
    ]);
    // acme/secret is private: a default for public repositories doesn't cover it.
    const forPublic = { json: [{ default_for_new_repos: 'public', configuration: { name: 'Public' } }] };
    expect((await config(attached, forPublic))?.[0]).toBe('warn');
    const forAll = { json: [{ default_for_new_repos: 'private_and_internal', configuration: { name: 'Private' } }] };
    expect(await config(attached, forAll)).toEqual([
      'pass',
      '"GitHub recommended" is attached here, and new private repositories get "Private" by default',
    ]);
    expect((await config({ status: 404, json: { message: 'Not Found' } }))?.[0]).toBe('unknown');
    expect(await config(attached, { status: 403, json: { message: 'Forbidden' } })).toEqual([
      'unknown',
      '"GitHub recommended" is attached here, but the org\'s defaults for new repositories couldn\'t be read (HTTP 403)',
    ]);
  });

  it("says a personal account has no configurations, and the public scan doesn't say anything", async () => {
    expect(pick((await scanScenario('assume-admin')).rep).config).toEqual([
      'na',
      'Personal accounts have no security configurations',
    ]);
    const pub = (await scanScenario('admin-org-public-layer')).rep;
    expect([pub.results['repo-org-security-config'], pub.results['acct-phishing-resistant-2fa']]).toEqual([
      undefined,
      undefined,
    ]);
    const seen: unknown[] = [];
    smsTwoFactor([200, [{ login: 'x' }], {}], (...a) => seen.push(a.slice(0, 2)));
    securityConfiguration([204, null, {}], [200, [], {}], {}, (...a) => seen.push(a.slice(0, 2)));
    expect(seen).toEqual([
      ['acct-phishing-resistant-2fa', 'warn'],
      ['repo-org-security-config', 'fail'],
    ]);
  });
});

describe('deps-licenses', () => {
  const ci = (steps: string[]) =>
    workflow(['on: pull_request', 'jobs:', '  check:', '    runs-on: ubuntu-latest', '    steps:', ...steps]);
  const gate = async (files: Record<string, string>) => statusOf((await scanTiny(tiny(files))).rep, 'deps-licenses');

  it('passes on dependency review with a license list, inline or in its config file', async () => {
    expect(
      await gate({
        '.github/workflows/review.yml': ci([
          '      - uses: actions/dependency-review-action@v4',
          '        with:',
          '          allow-licenses: MIT, Apache-2.0',
        ]),
      }),
    ).toEqual(['pass', 'Dependency review checks the licenses of new dependencies on pull requests']);
    expect(
      await gate({
        '.github/workflows/review.yml': ci([
          '      - uses: actions/dependency-review-action@v4',
          '        with:',
          '          config-file: ./.github/dependency-review-config.yml',
        ]),
        '.github/dependency-review-config.yml': 'fail-on-severity: high\nallow-licenses:\n  - MIT\n  - BSD-3-Clause\n',
      }),
    ).toEqual([
      'pass',
      'Dependency review checks the licenses of new dependencies (.github/dependency-review-config.yml)',
    ]);
    // Without a license list, dependency review gates vulnerabilities only (deps-review counts it).
    expect(
      await gate({ '.github/workflows/review.yml': ci(['      - uses: actions/dependency-review-action@v4']) }),
    ).toBeNull();
  });

  it("passes on cargo-deny when it checks licenses and deny.toml has an allow list, and on other checkers' allow lists", async () => {
    const deny = '[advisories]\nyanked = "deny"\n\n[licenses]\nallow = ["MIT", "Apache-2.0"]\n';
    expect(
      await gate({ '.github/workflows/deny.yml': ci(['      - run: cargo deny check']), 'deny.toml': deny }),
    ).toEqual(['pass', 'cargo-deny checks dependency licenses in CI']);
    expect(
      await gate({
        '.github/workflows/deny.yml': ci(['      - run: cargo deny check advisories bans']),
        'deny.toml': deny,
      }),
    ).toBeNull();
    expect(
      await gate({
        '.github/workflows/deny.yml': ci(['      - run: cargo deny check']),
        'deny.toml': '[advisories]\n',
      }),
    ).toBeNull();
    expect(
      await gate({
        '.github/workflows/deny.yml': ci([
          '      - uses: EmbarkStudios/cargo-deny-action@v2',
          '        with:',
          '          command: check licenses',
        ]),
        'deny.toml': deny,
      }),
    ).toEqual(['pass', 'cargo-deny checks dependency licenses in CI']);
    expect(await gate({ '.github/workflows/go.yml': ci(['      - run: go-licenses check ./...']) })).toEqual([
      'pass',
      'go-licenses checks dependency licenses in CI',
    ]);
    // One hop into package.json, as evcc's check does.
    expect(
      await gate({
        '.github/workflows/ci.yml': ci(['      - run: npm run licenses']),
        'package.json': JSON.stringify({ scripts: { licenses: 'license-checker --production --onlyAllow "MIT;ISC"' } }),
      }),
    ).toEqual(['pass', 'license-checker checks dependency licenses in CI']);
    expect(await gate({ '.github/workflows/ci.yml': ci(['      - run: npx license-checker --summary']) })).toBeNull();
    expect(licenseGate).toBeTypeOf('function');
  });
});

describe('sast-custom-queries', () => {
  const pack = {
    '.github/codeql/queries/qlpack.yml': 'name: octo/tiny-queries\nversion: 0.0.1\n',
    '.github/codeql/queries/unsafe-eval.ql': 'import javascript\nselect 1',
  };
  const codeql = (lines: string[]) => workflow(['on: push', 'jobs:', '  analyze:', '    steps:', ...lines]);
  const queries = async (files: Record<string, string>) =>
    statusOf((await scanTiny(tiny(files))).rep, 'sast-custom-queries');

  it("passes when a CodeQL config, an init input or a reusable workflow runs the repository's own pack", async () => {
    expect(
      await queries({
        ...pack,
        '.github/codeql/config.yml': 'queries:\n  - uses: ./.github/codeql/queries\n  - uses: security-extended\n',
        '.github/workflows/codeql.yml': codeql([
          '      - uses: github/codeql-action/init@v4',
          '        with:',
          '          config-file: ./.github/codeql/config.yml',
        ]),
      }),
    ).toEqual(['pass', "CI runs this repository's own CodeQL queries (./.github/codeql/queries)"]);
    // virtualenv passes its queries to a reusable workflow.
    expect(
      await queries({
        ...pack,
        '.github/workflows/codeql.yml': workflow([
          'on: push',
          'jobs:',
          '  codeql:',
          '    uses: tox-dev/github-workflows/.github/workflows/codeql.yaml@v1',
          '    with:',
          '      queries: +./.github/codeql/queries',
        ]),
      }),
    ).toEqual(['pass', "CI runs this repository's own CodeQL queries (./.github/codeql/queries)"]);
    expect(
      await queries({
        ...pack,
        '.github/workflows/codeql.yml': codeql([
          '      - uses: github/codeql-action/init@v4',
          '        with:',
          '          packs: octo/tiny-queries',
        ]),
      }),
    ).toEqual(['pass', "CI runs this repository's own CodeQL queries (octo/tiny-queries)"]);
  });

  it("adds nothing for built-in suites, GitHub's packs (codeql-action/pr-diff-range too) or a vendored pack", async () => {
    const builtIn = codeql([
      '      - uses: github/codeql-action/init@v4',
      '        with:',
      '          queries: security-extended',
      '          packs: codeql/python-queries, codeql-action/pr-diff-range',
    ]);
    expect(await queries({ ...pack, '.github/workflows/codeql.yml': builtIn })).toBeNull();
    // Default setup doesn't run query files from the repo.
    expect(await queries(pack)).toBeNull();
    const vendored = { 'vendor/lib/qlpack.yml': 'name: x/y\n', 'vendor/lib/q.ql': 'select 1' };
    expect(
      await customQueries({
        workflows: [
          {
            path: '.github/workflows/c.yml',
            text: codeql([
              '      - uses: github/codeql-action/init@v4',
              '        with:',
              '          queries: ./vendor/lib',
            ]),
          },
        ],
        files: Object.keys(vendored),
        read: async (p) => vendored[p as keyof typeof vendored] ?? null,
      }),
    ).toBeNull();
  });
});

describe('code-secret-handling', () => {
  it('warns on a step that traces its commands while it has a secret, with the line', async () => {
    const text = workflow([
      'on: push',
      'jobs:',
      '  deploy:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - name: Deploy',
      '        env:',
      '          TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
      '        run: |',
      '          set -ex',
      '          ./deploy.sh "$TOKEN"',
      '      - name: Lint',
      '        run: |',
      '          set -x',
      '          make lint',
      '      - name: Quiet',
      '        env:',
      '          TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
      '        run: |',
      '          set +x',
      '          ./upload.sh',
      '      - name: Traced shell',
      '        shell: bash -x {0}',
      '        run: echo "${{ secrets.X }}" | ./login.sh',
    ]);
    const { rep } = await scanTiny(tiny({ '.github/workflows/deploy.yml': text }));
    expect(statusOf(rep, 'code-secret-handling')).toEqual([
      'warn',
      '2 workflow steps trace their commands with set -x while using a secret',
    ]);
    // The Lint step traces without a secret, as zitadel's does: that's no leak.
    expect(rep.findings.filter((f) => f.item_id === 'code-secret-handling').map((f) => [f.line, f.severity])).toEqual([
      [10, 'low'],
      [24, 'low'],
    ]);
    expect(
      tracedSecrets([
        { path: 'w.yml', text: workflow(['on: push', 'jobs:', '  a:', '    steps:', '      - run: set -x']) },
      ]),
    ).toEqual([]);
  });
});

describe('ai-assisted-security', () => {
  it('passes on a Copilot code review rule for the default branch, and adds nothing otherwise', async () => {
    const rules = (json: unknown) => scanTiny(tiny({}, { '/rules/branches/main': { json } }));
    const on = (
      await rules([
        { type: 'pull_request', ruleset_id: 1 },
        { type: 'copilot_code_review', ruleset_id: 9, parameters: { review_on_push: true } },
      ])
    ).rep;
    expect(statusOf(on, 'ai-assisted-security')).toEqual([
      'pass',
      'A ruleset has Copilot review the pull requests to the default branch',
    ]);
    expect(on.results['ai-assisted-security'].details).toEqual({ ruleset_id: 9 });
    expect(statusOf((await rules([{ type: 'pull_request', ruleset_id: 1 }])).rep, 'ai-assisted-security')).toBeNull();
  });
});

describe("GitHub's Secure Open Source Fund (people-security-training, people-share-learnings)", () => {
  const guide = JSON.parse(readFileSync(new URL('../public/data/guide.json', import.meta.url), 'utf8'));

  it('ships a Fund list made from guide.json, so the two never drift', () => {
    const shipped = JSON.parse(readFileSync(new URL('../lib/scanner/fund.json', import.meta.url), 'utf8'));
    expect(shipped).toEqual(fundFromGuide(guide));
    expect(shipped.repos).toHaveLength(guide.teams.length);
  });

  it('matches a repository exactly, ignoring case', () => {
    expect(fundEntry('Actix/Actix-Web')?.repo).toBe('actix/actix-web');
    expect(fundEntry('actix/actix-web-extras')).toBeNull();
    expect(fundEntry('actix/actix')).toBeNull();
    expect(fundEntry('nope/nope', 'actix/actix-web')?.repo).toBe('actix/actix-web');
  });

  it('passes training until two years after the latest session, and sharing for a team with a post', () => {
    const entry = { repo: 'a/b', sessions: ['1-2', '3'], posts: [] };
    expect(trainingResult(entry, new Date('2027-08-31T00:00:00Z'))?.summary).toBe(
      'Took part in the GitHub Secure Open Source Fund (sessions 1-2 and 3), three weeks of security training with ' +
        'GitHub Security Lab',
    );
    // Session 3 started in September 2025.
    expect(trainingResult(entry, new Date('2027-09-01T00:00:00Z'))).toBeNull();
    expect(trainingResult({ ...entry, sessions: ['9'] }, new Date('2040-01-01T00:00:00Z'))?.status).toBe('pass');
    expect(trainingResult(null)).toBeNull();
    expect(sharingResult(entry)).toBeNull();
    const post = { title: 'What we changed', url: 'https://example.com/post', date: '2026-08-14' };
    expect(sharingResult({ ...entry, posts: [post] })).toEqual({
      status: 'pass',
      summary: 'Wrote about its Fund work: "What we changed" (2026-08-14)',
      evidence: [{ label: 'What we changed', url: 'https://example.com/post' }],
      details: { posts: 1 },
    });
  });

  it("credits a Fund repository's scan, and sends nothing anywhere to look it up", async () => {
    const fundRepo = guide.teams.find(
      (t: { posts: { tier: string }[]; sessions: string[] }) =>
        t.posts.some((p) => p.tier === 'primary') && t.sessions.includes('4'),
    );
    const [owner, name] = fundRepo.repo.split('/');
    const { rep, calls } = await scanTiny(
      tiny({}, {}, { meta: { full_name: fundRepo.repo, name, owner: { login: owner, type: 'Organization' } } }),
    );
    expect([rep.results['people-security-training'].status, rep.results['people-share-learnings'].status]).toEqual([
      'pass',
      'pass',
    ]);
    // GitHub's own hosts: the domain itself or a subdomain of it, never a host that merely ends in its name.
    const onGitHub = (h: string) => ['github.com', 'githubusercontent.com'].some((d) => h === d || h.endsWith(`.${d}`));
    expect(calls.map(([u]) => new URL(u).host).filter((h) => !onGitHub(h))).toEqual([
      'api.securityscorecards.dev',
      'www.bestpractices.dev',
    ]);
    expect(statusOf((await scanTiny(tiny({}))).rep, 'people-security-training')).toBeNull();
  });
});

describe('scanner bugs fixed in 0.5.0', () => {
  it('reports the Best Practices badge of this repository, then the best one (bug 1)', async () => {
    // warpgate: an old in_progress entry whose repo_url ends in .git comes first, then the passing one.
    const warpgate = [
      {
        id: 10110,
        badge_level: 'in_progress',
        badge_percentage_0: 15,
        repo_url: 'https://github.com/octo/demo.git',
        updated_at: '2025-03-01',
      },
      {
        id: 12773,
        badge_level: 'passing',
        badge_percentage_0: 100,
        repo_url: 'https://github.com/octo/demo',
        updated_at: '2026-05-01',
      },
    ];
    expect(bestBadge(warpgate, 'octo/demo').id).toBe(12773);
    const ohmyzsh = [
      { id: 1, badge_level: 'in_progress', badge_percentage_0: 84, repo_url: 'https://github.com/octo/demo' },
      { id: 2, badge_level: 'in_progress', badge_percentage_0: 87, repo_url: 'https://github.com/octo/demo' },
    ];
    expect(bestBadge(ohmyzsh, 'octo/demo').id).toBe(2);
    // Another project's passing badge doesn't beat this repository's own.
    const other = [
      { id: 3, badge_level: 'passing', repo_url: 'https://github.com/someone/else' },
      { id: 4, badge_level: 'in_progress', badge_percentage_0: 40, repo_url: 'http://www.github.com/Octo/Demo/' },
    ];
    expect(bestBadge(other, 'octo/demo').id).toBe(4);
    const badge = 'https://www.bestpractices.dev/projects.json?url=https%3A//github.com/octo/demo';
    const r = (await scanScenario('public', { [badge]: { json: warpgate } })).rep.results[
      'posture-best-practices-badge'
    ];
    expect([r.status, r.summary, r.evidence[0].url]).toEqual([
      'pass',
      'OpenSSF Best Practices badge: passing',
      'https://www.bestpractices.dev/projects/12773',
    ]);
  });

  const publishWorkflow = (run: string) =>
    workflow([
      'on:',
      '  release:',
      'permissions:',
      '  id-token: write',
      'jobs:',
      '  publish:',
      '    steps:',
      `      - run: ${run}`,
    ]);
  /** Whether the scan counts the workflow as publishing, and what rel-trusted-publishing makes of it. */
  const publishing = async (run: string, files: Record<string, string> = {}) => {
    const { rep } = await scanTiny(tiny({ '.github/workflows/publish.yml': publishWorkflow(run), ...files }));
    return [rep.meta.publishes_from_ci, rep.results['rel-trusted-publishing'].status];
  };
  const scripts = (publish: string) => ({ 'package.json': JSON.stringify({ name: 'demo', scripts: { publish } }) });

  it('counts npm stage publish as publishing (bug 5)', async () => {
    expect(await publishing('npm stage publish --tag next')).toEqual([true, 'pass']);
  });

  it("counts npm run publish only when package.json's publish script publishes", async () => {
    // mockoon's script: npm publish for each workspace.
    expect(await publishing('npm run publish', scripts('npm publish --workspace=@octo/core'))).toEqual([true, 'pass']);
    // A tool that publishes counts too, from pnpm or yarn.
    expect(await publishing('pnpm run publish', scripts('changeset publish'))).toEqual([true, 'pass']);
    expect(await publishing('yarn run publish', scripts('np --no-tests'))).toEqual([true, 'pass']);
    // A script that does something else, a dry run, or no package.json to read: it doesn't count.
    expect(await publishing('npm run publish', scripts('gh-pages -d dist'))).toEqual([false, 'na']);
    expect(await publishing('npm run publish', scripts('npm publish --dry-run'))).toEqual([false, 'na']);
    expect(await publishing('npm run publish')).toEqual([false, 'na']);
    const tools = (run: string) =>
      analyzeWorkflow('.github/workflows/x.yml', `on: push\njobs:\n  a:\n    steps:\n      - run: ${run}\n`).tools;
    expect([tools('npm run publish'), tools('npm run publish:docs')]).toEqual([[], []]);
  });

  it('follows npm run publish into package.json for the release cache check too', async () => {
    const release = (files: Record<string, string>) =>
      cacheCheck(
        {
          'release.yml': [
            'on:',
            '  push:',
            "    tags: ['v*']",
            'jobs:',
            '  publish:',
            '    steps:',
            '      - uses: actions/setup-node@v4',
            '        with:',
            '          cache: npm',
            '      - run: npm run publish',
          ],
        },
        files,
      );
    expect((await release(scripts('npm publish'))).status).toBe('fail');
    // Not a publishing job: the release workflow runs a script that doesn't publish.
    expect(await release(scripts('gh-pages -d dist'))).toMatchObject({
      status: 'info',
      summary: 'Release workflow .github/workflows/release.yml has no step the scan recognizes as publishing',
    });
    // Without package.json the script can't be followed, so it isn't a publishing job, and its cache is named.
    expect(await release({})).toMatchObject({
      status: 'info',
      summary:
        "Job publish in .github/workflows/release.yml runs npm run publish, which the scan couldn't follow, and a " +
        'cache is restored on its way (actions/setup-node with cache: npm)',
    });
  });

  it("doesn't count a dynamic workflow GitHub lists as disabled (bug 7)", async () => {
    const list = 'https://api.github.com/repos/octo/fixes/actions/workflows?per_page=100';
    const codeql = async (state?: string) => {
      const json = { workflows: [{ path: 'dynamic/github-code-scanning/codeql', ...(state ? { state } : {}) }] };
      return statusOf((await scanScenario('fixes', { [list]: { json } })).rep, 'sast-codeql');
    };
    expect(await codeql('active')).toEqual(['pass', 'CodeQL default setup is on']);
    expect(await codeql()).toEqual(['pass', 'CodeQL default setup is on']);
    for (const state of ['disabled_manually', 'disabled_inactivity', 'deleted']) {
      expect(await codeql(state)).toEqual(['fail', 'No CodeQL code scanning found']);
    }
  });

  it("tells the page a self-check isn't something no scanner can see", () => {
    const st = sg.itemStatus(
      { id: 'people-share-learnings', layer: 'manual' },
      { repo: 'octo/tiny', results: {} },
      'octo/tiny',
    );
    expect([st.status, st.summary]).toEqual(['manual', "The scan can't settle this. Tick it off when it's done."]);
  });
});

// ------------------------------------------------------------------- 0.5.1: security policies in any format
describe('security policies in any format', () => {
  const POLICIES = new URL('policies/', FIXTURES);
  const fixturePolicy = (name: string) => readFileSync(new URL(name, POLICIES), 'utf8');
  const releases = (...tags: (string | [string, boolean])[]) => ({
    json: tags.map((t) =>
      Array.isArray(t) ? { tag_name: t[0], prerelease: t[1] } : { tag_name: t, prerelease: false },
    ),
  });
  const REL = { '/releases?per_page=10': releases('v2.3.0') };
  /** Both checks for one policy file in the repo, at path. */
  const both = async (files: Record<string, string>, api: Record<string, Route> = REL) => {
    const { rep, calls } = await scanTiny(tiny(files, api));
    return { disc: statusOf(rep, 'disc-security-md'), rel: statusOf(rep, 'rel-security-support'), rep, calls };
  };

  it('says how each format reports, and reads its versions table', async () => {
    const cases: [string, string, string[], string[]][] = [
      [
        'email-short.md',
        'SECURITY.md',
        ['pass', 'SECURITY.md found; it says to report by email (security@octo-project.org)'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'obfuscated.md',
        'SECURITY.md',
        ['pass', 'SECURITY.md found; it says to report by email (security@octo-project.org)'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'pointer-page.md',
        'SECURITY.md',
        ['pass', 'SECURITY.md found; it points to https://octo-project.org/security/ for how to report'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'platform.md',
        'SECURITY.md',
        ['pass', "SECURITY.md found; it says to report through Tidelift's security contact"],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'button.md',
        '.github/SECURITY.md',
        ['pass', ".github/SECURITY.md found; it says to report through GitHub's private vulnerability reporting"],
        ['info', ".github/SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'chat.md',
        'SECURITY.md',
        ['pass', 'SECURITY.md found; it says to report by private message'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'zh-email.md',
        'SECURITY.md',
        ['pass', 'SECURITY.md found; it says to report by email (security@octo-project.org)'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'ja-pvr.md',
        'SECURITY.md',
        ['pass', "SECURITY.md found; it says to report through GitHub's private vulnerability reporting"],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'security.txt',
        'security.txt',
        [
          'pass',
          "security.txt found (GitHub's Security tab shows only a SECURITY.md); it says to report by email (security@octo-project.org)",
        ],
        ['info', "security.txt doesn't say which versions get security fixes"],
      ],
      [
        'SECURITY.rst',
        'SECURITY.rst',
        [
          'pass',
          "SECURITY.rst found (GitHub's Security tab shows only a SECURITY.md); it says to report by email (security@octo-project.org)",
        ],
        ['pass', 'SECURITY.rst lists 2.3.x as supported, which covers the newest release, v2.3.0'],
      ],
      [
        'SECURITY.adoc',
        'SECURITY.adoc',
        [
          'pass',
          "SECURITY.adoc found (GitHub's Security tab shows only a SECURITY.md); it says to report through GitHub's private vulnerability reporting",
        ],
        ['pass', 'SECURITY.adoc lists 2.3.x as supported, which covers the newest release, v2.3.0'],
      ],
      [
        'html-table.md',
        'docs/SECURITY.md',
        ['pass', 'docs/SECURITY.md found; it says to report by email (security@octo-project.org)'],
        ['pass', 'docs/SECURITY.md lists >= 2.0 as supported, which covers the newest release, v2.3.0'],
      ],
      // Warnings, each for something the text says or plainly lacks.
      [
        'template.md',
        'SECURITY.md',
        ['warn', "SECURITY.md found but it still has GitHub's template text where it should say how to report"],
        ['warn', "SECURITY.md still has the versions table from GitHub's template (5.1.x, 5.0.x, 4.0.x)"],
      ],
      [
        'public-issues.md',
        'SECURITY.md',
        ['warn', 'SECURITY.md found but it only says to report in public issues, not privately'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'reporting-off.md',
        'SECURITY.md',
        ['warn', 'SECURITY.md found but it only says to report in public issues, not privately'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'no-address.md',
        'SECURITY.md',
        ['warn', 'SECURITY.md found but it asks for reports by email or message without giving an address'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      // A comment isn't read: its table and its address are hidden from readers too.
      [
        'commented.md',
        'SECURITY.md',
        ['warn', 'SECURITY.md found but it does not say how to report privately'],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      // What the scan can't read gives info.
      [
        'pointer-elsewhere.md',
        'SECURITY.md',
        [
          'info',
          "SECURITY.md found; it points to https://octo-project.org/handbook, which the scan doesn't follow: check that page says how to report privately",
        ],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
      [
        'zh-none.md',
        'SECURITY.md',
        [
          'info',
          "SECURITY.md found, but it isn't in English and the scan found no email address or link in it to report to",
        ],
        ['info', "SECURITY.md doesn't say which versions get security fixes"],
      ],
    ];
    for (const [name, path, disc, rel] of cases) {
      const got = await both({ [path]: fixturePolicy(name) });
      expect([name, got.disc]).toEqual([name, disc]);
      expect([name, got.rel]).toEqual([name, rel]);
    }
  });

  it('reads the policy GitHub shows first: a SECURITY.md in .github/, the root, then docs/', async () => {
    const email = (who: string) => `Report problems to ${who}@octo-project.org.`;
    const pick = async (files: Record<string, string>) => (await both(files)).disc;
    expect(await pick({ 'SECURITY.adoc': email('adoc'), 'SECURITY.md': email('md') })).toEqual([
      'pass',
      'SECURITY.md found; it says to report by email (md@octo-project.org)',
    ]);
    expect(
      await pick({
        'docs/SECURITY.md': email('docs'),
        'SECURITY.md': email('root'),
        '.github/SECURITY.md': email('github'),
      }),
    ).toEqual(['pass', '.github/SECURITY.md found; it says to report by email (github@octo-project.org)']);
    // GitHub shows a SECURITY with no extension; a .markdown file it doesn't show still counts as a policy.
    expect(await pick({ SECURITY: email('bare') })).toEqual([
      'pass',
      'SECURITY found; it says to report by email (bare@octo-project.org)',
    ]);
    expect(await pick({ '.github/SECURITY.markdown': email('markdown') })).toEqual([
      'pass',
      ".github/SECURITY.markdown found (GitHub's Security tab shows only a SECURITY.md); it says to report by email (markdown@octo-project.org)",
    ]);
  });

  it('follows one link to another file in the same repository, and nothing outside GitHub', async () => {
    const short = 'Our full policy is in [docs/security-policy.md](docs/security-policy.md).';
    const full = '# Security policy\n\nEmail security@octo-project.org with the details.\n';
    const { disc, calls, rep } = await both({ 'SECURITY.md': short, 'docs/security-policy.md': full });
    expect(disc).toEqual([
      'pass',
      'SECURITY.md found; it points to docs/security-policy.md, which says to report by email (security@octo-project.org)',
    ]);
    expect(rep.results['disc-security-md'].details).toEqual({
      path: 'SECURITY.md',
      length: pyLen(short),
      report: ['email'],
      followed: 'docs/security-policy.md',
    });
    expect(calls.filter(([u]) => u === `${TINY_RAW}docs/security-policy.md`)).toHaveLength(1);
    // The same link as a full GitHub URL, and a symlink (raw.githubusercontent.com serves its target's path).
    const url = 'See https://github.com/octo/tiny/blob/main/docs/security-policy.md for how to report.';
    expect((await both({ 'SECURITY.md': url, 'docs/security-policy.md': full })).disc?.[0]).toBe('pass');
    expect((await both({ 'SECURITY.md': 'docs/security-policy.md\n', 'docs/security-policy.md': full })).disc).toEqual([
      'pass',
      'SECURITY.md found; it points to docs/security-policy.md, which says to report by email (security@octo-project.org)',
    ]);
    // A link elsewhere is named, never fetched.
    const away = await both({ 'SECURITY.md': fixturePolicy('pointer-elsewhere.md') });
    const hosts = new Set(away.calls.map(([u]) => new URL(u).host));
    expect(
      [...hosts].filter(
        (h) =>
          !/^(api\.github\.com|raw\.githubusercontent\.com|github\.com|api\.securityscorecards\.dev|www\.bestpractices\.dev)$/.test(
            h,
          ),
      ),
    ).toEqual([]);
    // A policy that already says how to report doesn't send the scan anywhere.
    const enough = await both({
      'SECURITY.md': `${fixturePolicy('email-short.md')}\nMore in [docs](docs/security-policy.md).`,
    });
    expect(enough.calls.some(([u]) => u.endsWith('docs/security-policy.md'))).toBe(false);
  });

  it("reads the account's default too when GitHub shows it instead of the repository's .rst or .adoc", async () => {
    const account = {
      'https://api.github.com/repos/octo/.github': { json: { private: false, default_branch: 'main' } },
      'https://api.github.com/repos/octo/.github/git/trees/main?recursive=1': {
        json: { tree: [{ path: 'SECURITY.md', type: 'blob' }] },
      },
      'https://raw.githubusercontent.com/octo/.github/main/SECURITY.md': { text: 'Email security@octo-project.org.' },
    };
    const doc = '= Security\n\nThis page explains how the tool stores keys.\n';
    const { rep } = await scanTiny(tiny({ 'docs/security.adoc': doc }, { ...REL, ...account }));
    expect(statusOf(rep, 'disc-security-md')).toEqual([
      'pass',
      "docs/security.adoc found (GitHub's Security tab shows the account's default, SECURITY.md in octo/.github, instead); that one says to report by email (security@octo-project.org)",
    ]);
  });

  it('reads headings, links, addresses and tables in every format', () => {
    const md = readPolicy(
      [
        '---',
        'title: front matter',
        '---',
        'Security Policy',
        '===============',
        '',
        '**Supported versions**',
        '',
        '| Version | Supported |',
        '|---|---|',
        '| 2.x | Yes |',
        '',
        'REPORTING',
        '',
        'Write to [the team](mailto:team@octo-project.org), see [ref] or <https://octo-project.org/security>.',
        '',
        '[ref]: https://octo-project.org/policy',
        '```',
        '## not a heading',
        '```',
      ].join('\n'),
      'SECURITY.md',
    );
    expect(md.headings.map((h) => [h.text, h.level])).toEqual([
      ['Security Policy', 1],
      ['Supported versions', 7],
      ['REPORTING', 8],
    ]);
    expect(md.links.map((l) => l.url)).toEqual([
      'mailto:team@octo-project.org',
      'https://octo-project.org/policy',
      'https://octo-project.org/security',
    ]);
    expect(md.emails).toEqual(['team@octo-project.org']);
    expect(md.tables).toEqual([{ header: ['Version', 'Supported'], rows: [['2.x', 'Yes']], line: 8, kind: 'pipe' }]);
    const rst = readPolicy(
      [
        'Policy',
        '======',
        '',
        '.. list-table::',
        '   :header-rows: 1',
        '',
        '   * - Version',
        '     - Supported',
        '   * - 2.x',
        '     - Yes',
        '',
        '=======  =========',
        'Version  Supported',
        '=======  =========',
        '1.x      No',
        '=======  =========',
        '',
        '.. csv-table::',
        '   :header: "Version", "Supported"',
        '',
        '   "3.x", "Yes"',
      ].join('\n'),
      'SECURITY.rst',
    );
    expect(rst.tables.map((t) => [t.kind, t.header, t.rows])).toEqual([
      ['list', ['Version', 'Supported'], [['2.x', 'Yes']]],
      ['simple', ['Version', 'Supported'], [['1.x', 'No']]],
      ['csv', ['Version', 'Supported'], [['3.x', 'Yes']]],
    ]);
    // Addresses written so bots can't read them.
    const spelled = readPolicy(
      [
        'a [at] octo-project [dot] org',
        'b(at)octo-project.org',
        'c AT octo-project.org',
        'security at octo-project dot org',
        'Email: d at octo-project.org',
        'e @ octo-project.org',
        'f at gmail com.',
        'g "at" octo-project.org',
        'h [at] octo - project [dot] org',
      ].join('\n\n'),
      'SECURITY.md',
    );
    expect(spelled.emails).toEqual([
      'a@octo-project.org',
      'b@octo-project.org',
      'h@octo-project.org',
      'security@octo-project.org',
      'c@octo-project.org',
      'f@gmail.com',
      'd@octo-project.org',
      'e@octo-project.org',
      'g@octo-project.org',
    ]);
    // A URL's user, a Kerberos principal, placeholders and remotes aren't inboxes; a mailto: in the text is.
    expect(
      readPolicy('postgres://app:secret@db.octo-project.org/x\n--principal ann@CORP.OCTO-PROJECT.ORG', 'SECURITY.md')
        .emails,
    ).toEqual([]);
    expect(readPolicy('Contact: mailto:security@octo-project.org', 'security.txt').emails).toEqual([
      'security@octo-project.org',
    ]);
    expect(
      readPolicy('security@example.com, git@github.com:octo/tiny.git, x@users.noreply.github.com', 'SECURITY.md')
        .emails,
    ).toEqual([]);
  });

  it('tells a private way to report from a public one, in more than one language', () => {
    const how = (text: string) => {
      const r = howToReport(readPolicy(text, 'SECURITY.md'), 'octo/tiny');
      return { kinds: r.channels.map((c) => c.kind), publicIssues: r.publicIssues, noAddress: r.noAddress };
    };
    expect(
      how('Open a [draft security advisory](https://github.com/octo/tiny/security/advisories/new).').kinds,
    ).toEqual(['github', 'github']);
    expect(how('Use the [Report a vulnerability](../../security/advisories/new) form.').kinds).toEqual([
      'github',
      'github',
    ]);
    expect(how('Submit it through our bug bounty program on HackerOne.').kinds).toEqual(['platform']);
    expect(how('Contact @octo-maint privately, or ping them on Matrix: @octo:matrix.org.').kinds).toEqual([
      'chat',
      'maintainer',
    ]);
    expect(
      how('If you find a vulnerability, report it to our [lead maintainer](https://octo-person.dev/).').kinds,
    ).toEqual(['page']);
    // A maintainer's GitHub profile, linked by name, in a sentence an initial would cut short.
    expect(how('To report a vulnerability, please contact [Ann B. Example](https://github.com/annb).').kinds).toEqual([
      'maintainer',
    ]);
    expect(how('Please report it [here](https://forms.gle/abc123).').kinds).toEqual(['form']);
    // Not ways to report privately: published advisories, a public issue, a CVE database, a chat server's invite.
    expect(how('We publish security advisories on GitHub after a fix. Please open an issue.')).toEqual({
      kinds: [],
      publicIssues: true,
      noAddress: false,
    });
    expect(
      how(
        'See [CVE-2020-1234](https://nvd.nist.gov/vuln/detail/CVE-2020-1234) and [our Discord](https://discord.gg/abc).',
      ).kinds,
    ).toEqual([]);
    expect(how('Do not open an issue. Reach out to us by email instead.')).toEqual({
      kinds: [],
      publicIssues: false,
      noAddress: true,
    });
    // In another language an address or a link is enough.
    expect(
      how('Bitte melde Sicherheitslücken über die [GitHub Security Advisories](../../security/advisories/new).').kinds,
    ).toEqual(['github', 'github']);
    expect(
      how('Envie uma mensagem direta para o mantenedor: [@octo-maint](https://github.com/octo-maint).').kinds,
    ).toEqual(['maintainer']);
  });

  it('reads the status words, dates and version cells tables use', () => {
    const now = new Date('2026-11-11T00:00:00Z');
    const cases: [string, string][] = [
      ['✅', 'yes'],
      [':white_check_mark: till 2027 April 30', 'yes'],
      ['Security fixes only', 'yes'],
      ['Critical fixes only', 'yes'],
      ['LTS', 'yes'],
      ['Ja', 'yes'],
      ['支持', 'yes'],
      ['❌ (no new releases, critical fixes may still be backported)', 'no'],
      ['No, please upgrade', 'no'],
      ['End of Life', 'no'],
      ['不支持', 'no'],
      ['Nicht unterstützt', 'no'],
      ['until 2020-01-01', 'no'],
      // A word the scan doesn't know is unknown, never unsupported.
      ['Best-effort', 'unknown'],
      ['Life Support', 'unknown'],
      ['Deprecated', 'unknown'],
      [':warning:', 'unknown'],
      ['x', 'unknown'],
    ];
    for (const [cell, want] of cases) expect([cell, cellStatus(cell, now)]).toEqual([cell, want]);
    const day = (cell: string) => endDate(cell)?.toISOString().slice(0, 10) ?? null;
    expect(
      [
        '2027-06-30',
        '30.06.2029',
        'April 12, 2023',
        '1st Jun 2022',
        'June 2026',
        'Q3 2026',
        '2025 (est)',
        '2026 April 30',
        'TBD',
      ].map(day),
    ).toEqual([
      '2027-06-30',
      '2029-06-30',
      '2023-04-12',
      '2022-06-01',
      '2026-06-30',
      '2026-09-30',
      '2025-12-31',
      '2026-04-30',
      null,
    ]);
    const v = (s: string) => s.split('.').map(Number);
    const cells: [string, string, boolean | null][] = [
      ['1.0 - 1.5', '1.5.3', true],
      ['1.0 - 1.5', '1.6.0', false],
      ['1.x and 2.x', '2.4.0', true],
      ['8.2, 8.3', '8.3.1', true],
      ['11.x and older', '9.0.0', true],
      ['11.x and older', '12.0.0', false],
      ['3.x.y', '3.2.1', true],
      ['PHPUnit 13', '13.4.6', true],
      ['Latest 3.x', '4.0.29', false],
      ['latest', '4.0.29', true],
      ['Stable', '1.13.3', true],
      ['All versions', '26081109', true],
      ['Older releases', '1.0.0', false],
      ['< latest', '1.0.0', false],
      ['main', '1.0.0', null],
      ['`main` (latest release)', '1.0.0', true],
      ['master (0.5.7)', '0.5.7', true],
      ['https://crates.io/crates/octo', '0.20.1', true],
      ['<SEMVER>', '1.0.0', null],
    ];
    for (const [cell, ver, want] of cells) expect([cell, ver, covers(cell, v(ver))]).toEqual([cell, ver, want]);
    expect(cellSpec('main').kind).toBe('branch');
  });

  it("compares a monorepo's table with its main package's releases only", () => {
    const line = (tags: string[], repo = 'tiny') => {
      const l = releaseLine(
        tags.map((tag) => ({ tag })),
        repo,
      );
      return l.target ? l.target.tag : l.mixed;
    };
    expect(line(['web_adapter_v2.2.2', 'tiny_v5.11.1', 'http2_adapter_v2.9.0'])).toBe('tiny_v5.11.1');
    expect(line(['@octo/tiny-cli@3.0.0', '@octo/tiny@2.4.1', '@octo/plugin@9.0.0'])).toBe('@octo/tiny@2.4.1');
    expect(line(['api/v0.9.0', 'v1.2.0', 'experimental/v0.3.0'])).toBe('v1.2.0');
    expect(line(['plane-4.6.1', 'copter-4.6.2', 'rover-4.6.0'])).toEqual(['plane', 'copter', 'rover']);
    // Development builds and generic prefixes.
    expect(line(['nightly-1794384896', 'v2.3.1-nightly', 'v2.3.0'])).toBe('v2.3.0');
    expect(line(['REL_17_2', 'release-16.6', 'rel_17_1'])).toBe('REL_17_2');
    expect(line(['releases/tiny/9.7.0', 'releases/tiny/9.6.1'])).toBe('releases/tiny/9.7.0');
    expect(targetRelease([{ tag: 'curl-8_11_0' }, { tag: 'curl-8_10_1' }])).toEqual({
      tag: 'curl-8_11_0',
      version: [8, 11, 0],
    });
  });

  it('warns only on a plain table that leaves out the newest release; anything it cannot read gives info', () => {
    const table = (rows: string[], extra: string[] = [], header = '| Version | Supported |') =>
      ['## Supported Versions', '', ...extra, header, '| --- | --- |', ...rows].join('\n');
    const verdict = (text: string, tags: string[], repo = 'tiny') =>
      (({ status, summary }) => [status, summary])(
        supportVerdict(
          readSupport(readPolicy(text, 'SECURITY.md'), new Date('2026-11-11T00:00:00Z')),
          releaseLine(
            tags.map((tag) => ({ tag })),
            repo,
          ),
          'SECURITY.md',
          null,
          repo,
        ),
      );
    expect(verdict(table(['| 1.x | ✅ |', '| < 1.0 | ❌ |']), ['v2.0.0'])).toEqual([
      'warn',
      'SECURITY.md lists 1.x as supported, but the newest release is v2.0.0',
    ]);
    expect(verdict(table(['| 2.x | ✅ |']), ['v2.0.0'])).toEqual([
      'pass',
      'SECURITY.md lists 2.x as supported, which covers the newest release, v2.0.0',
    ]);
    // Columns by their headers: a component column, compatibility columns, a column of end dates.
    expect(
      verdict(
        table(['| tiny-core | >= 1.3.0 | 2023 | ✅ |'], [], '| Component | Version | Released | Security support |'),
        ['1.3.13'],
      )[0],
    ).toBe('pass');
    expect(
      verdict(
        table(['| 5.x | 8.3 | |', '| 4.x | 8.1 | April 2026 |'], [], '| Version | PHP | Security fixes until |'),
        ['v5.6.1'],
      ),
    ).toEqual(['pass', 'SECURITY.md lists 5.x as supported, which covers the newest release, v5.6.1']);
    expect(verdict(table(['| v6.x | TBD |'], [], '| Version | End-of-life |'), ['v6.2.17'])[0]).toBe('pass');
    // Info, never a warning: a status word it doesn't know, a branch, an example, another numbering, packages it
    // can't tie to the table, a table ahead of the releases, a range that starts after the newest release, and a
    // table without a status column.
    const infos: [string, string[]][] = [
      [table(['| 2.x | Best-effort |']), ['v2.0.0']],
      [table(['| main | ✅ |', '| < main | ❌ |']), ['v0.4.0']],
      [
        table(['| 28 | ✅ |', '| 27 | ✅ |'], ['For example, if the latest release is 28, we support:', '']),
        ['OTP-29.1.2'],
      ],
      [table(['| 9.2.x | ✅ |']), ['2026-11-10']],
      [table(['| > 1.0.x | ✅ |']), ['@octo/react/v0.2.3', '@octo/design/v0.2.1']],
      [table(['| 1.x | ✅ |', '| 0.0.x | ❌ |']), ['0.0.9']],
      [table(['| >8.0.0 | ✅ |']), ['v8.0.0']],
      [
        table(['| 9.0-10.0 | Releases within the previous twelve months |'], [], '| CVSS v3.0 | Supported Versions |'),
        ['25.1.3'],
      ],
      [table(['| LTS | ✅ |']), ['v1.13.3']],
      [table(['| <SEMVER> | ✅ |']), ['v0.4.4']],
    ];
    for (const [text, tags] of infos) expect([text, verdict(text, tags)[0]]).toEqual([text, 'info']);
  });

  it('never fails or warns on a policy the scan cannot read', async () => {
    const odd = [
      '',
      '\u{1F512}',
      '<html><body><p>Security</p></body></html>',
      '..\n   just an RST comment',
      '////\nan AsciiDoc comment\n////',
      '| a | b |\n|---|---|\n| ✅ | ❌ |',
      '## Supported Versions\n\n| Version | Supported |\n| --- | --- |\n| ??? | ??? |',
      '安全策略：请联系我们。',
      'Безопасность: свяжитесь с нами.',
      'See https://octo-project.org.',
    ];
    for (const text of odd) {
      const got = await both({ 'SECURITY.md': text }, { '/releases?per_page=10': releases('v2.3.0') });
      expect([text, got.rel?.[0]]).toEqual([text, 'info']);
      // The reporting check warns only when it read the policy in English and found no way to report.
      if (got.disc?.[0] === 'warn') expect(readPolicy(text, 'SECURITY.md').english).toBe(true);
      expect(got.disc?.[0]).not.toBe('fail');
    }
  });

  it('gives the coming text checks sections, sentences and links to search', () => {
    const p = readPolicy(
      [
        '# Security',
        '',
        '## Response times',
        '',
        'We acknowledge reports within 2 business days. We aim to fix critical issues in 30 days.',
        '',
        '### Embargo',
        '',
        'We notify downstream distributions under embargo.',
        '',
        '## Post-mortems',
        '',
        'Read [the 2025 incident review](https://github.com/octo/tiny/blob/main/docs/incident-2025.md).',
      ].join('\n'),
      'SECURITY.md',
    );
    expect(sections(p, /response/i).map((s) => [s.heading.text, s.text.trim()])).toEqual([
      [
        'Response times',
        'We acknowledge reports within 2 business days. We aim to fix critical issues in 30 days.\n\nEmbargo\n\nWe notify downstream distributions under embargo.',
      ],
    ]);
    expect(mentions(p, /\b\d+ business days\b/)).toEqual([
      { heading: 'Response times', sentence: 'We acknowledge reports within 2 business days.' },
    ]);
    expect(mentions(p, /embargo/i).map((m) => m.heading)).toEqual(['Embargo']);
    expect(p.links).toEqual([
      { text: 'the 2025 incident review', url: 'https://github.com/octo/tiny/blob/main/docs/incident-2025.md' },
    ]);
    // The one file in the same repository a check may read next.
    expect(
      sameRepoLink(
        readPolicy('Full policy: [here](docs/policy.md)', 'SECURITY.md'),
        'Full policy: [here](docs/policy.md)',
        'octo/tiny',
        { report: true, versions: false },
      ),
    ).toBe('docs/policy.md');
    expect(
      sameRepoLink(
        readPolicy('Full policy: [here](https://github.com/other/repo/blob/main/SECURITY.md)', 'SECURITY.md'),
        '',
        'octo/tiny',
        { report: true, versions: true },
      ),
    ).toBeNull();
  });
});
