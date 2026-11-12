// The scanner reads files anyone can write (workflows, composite actions, configs, manifests, Makefiles), and public
// scans run on our server, where a slow pattern or parser blocks every other request. So nothing it does with them may
// take more than linear time, or it must stop at a cap. These tests run every pattern lib/scanner compiles outside the
// policy reader (tests/policy-speed.test.ts has those) on 256 KB of text built to be slow, and every parser and check
// on 1 MB files built to be slow: the shapes an independent audit tried, and the ones that were slow.
//
// The limits are far from what a loaded CI runner takes, and close to nothing slow: 500 ms for a pattern on 256 KB
// (the mildest of round 2's patterns that took time squared took 4.7 s), 5 s for a parser on 1 MB (those took over a
// minute), and work that takes over 100 ms on 1 MB may take at most 8 times what it takes on 256 KB (linear work takes
// 4 times as long, work that takes time squared 16).
import { describe, expect, it } from 'vitest';

// The policy reader's patterns first, so the rest of COMPILED is everything else the scanner compiles.
const { COMPILED, re } = await import('../lib/scanner/py.ts');
await import('../lib/scanner/policy.ts');
await import('../lib/scanner/versions.ts');
const READER = COMPILED.length;
await import('../lib/scanner/index.ts');
const { analyzeWorkflow } = await import('../lib/scanner/workflow.ts');
const { readCompositeSteps, readWorkflow } = await import('../lib/scanner/jobs.ts');
const { parseYaml, readYaml, TooComplex } = await import('../lib/scanner/yaml-lite.ts');
const { globMatch, releaseCacheCheck } = await import('../lib/scanner/release-caches.ts');
const { customQueries, licenseGate, reviewWorkflows, tracedSecrets } = await import('../lib/scanner/self-checks.ts');
const { Hops } = await import('../lib/scanner/hops.ts');
const { releaseLine } = await import('../lib/scanner/versions.ts');
const { readPolicy } = await import('../lib/scanner/policy.ts');
const { disclosureTerms, drillNote, releasesNaming, responseTarget } = await import('../lib/scanner/advisories.ts');

const KB = 1024;
const MB = 1024 * KB;
const fill = (unit: string, size: number) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
const lines = (n: number, make: (i: number) => string) => Array.from({ length: n }, (_, i) => make(i)).join('\n');

const PATTERN_LIMIT = 500;
const PARSER_LIMIT = 5000;

/** How long one run of fn takes, in milliseconds. */
async function once(fn: () => unknown): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

/**
 * How long fn takes, in milliseconds: the faster of two runs when the first is over the limit. Something slow is slow
 * every time; a pause for garbage collection, or another test file running alongside, isn't.
 */
async function time(fn: () => unknown, limit: number): Promise<number> {
  const first = await once(fn);
  return first <= limit ? first : Math.min(first, await once(fn));
}

/**
 * Why work is too slow, or null: big (the work on the larger input) takes over limit, or over 100 ms and more than 8
 * times what small (the same on a quarter of it) takes. While the ratio is over 8 each runs again, up to three times,
 * and the faster counts: under load one run can be slow.
 */
async function slowness(small: () => unknown, big: () => unknown, limit: number): Promise<string | null> {
  let tb = await time(big, limit);
  if (tb > limit) return `${Math.round(tb)} ms`;
  if (tb <= 100) return null;
  let ts = await once(small);
  for (let k = 0; tb > 8 * ts && k < 2; k++) {
    tb = Math.min(tb, await once(big));
    ts = Math.min(ts, await once(small));
  }
  return tb > 8 * ts ? `${Math.round(tb)} ms, ${(tb / ts).toFixed(1)} times what a quarter of the input takes` : null;
}

/** Repeated units for the patterns: runs of space and lines, and the words the workflow and config patterns look for. */
const UNITS = [
  ' ',
  '\t',
  ' \t',
  '\n',
  ' \n',
  '\r\n',
  '\u00a0',
  '- ',
  ' - ',
  '-\n',
  'aaaa',
  'a-b_',
  'a:',
  'a: ',
  'a,',
  '1,',
  '12',
  '<a>',
  '<',
  '<a',
  '"',
  "'",
  '[',
  '{',
  '${{',
  '${{ ',
  '${{ secrets',
  'secrets ',
  'env.',
  'uses: ',
  '- uses: ',
  'runs-on: ',
  'runs-on:\n',
  'self-hosted',
  'permissions: ',
  'permissions:\n',
  'pull_request ',
  'workflow_run ',
  'language: ',
  'languages: [',
  'languages: ',
  'actions ',
  '- actions ',
  'cooldown ',
  'ignore-scripts ',
  '.github/',
  '* ',
  'fuzz',
  '_fuzz',
  'a/',
  '_test.go',
  'docker buildx build ',
  'goreleaser release ',
  'mvn ',
  'gradle ',
  'sbt ',
  'npm ',
  'npm publish ',
  'npm -x ',
  'npm --x ',
  'make --x ',
  'make ',
  'pnpm run ',
  'license-checker ',
  'license-compliance ',
  'cargo deny ',
  'set -x ',
  'bash -x ',
  './a.sh ',
  'a.b/',
  '[a]\n',
  'a = 1\n',
  'a b ',
  'a:\n\t',
  'persist-credentials: ',
  'ref: ${{ ',
  'refs/pull/',
  'actions/checkout@',
  '@v1 ',
  '# ',
  'x'.repeat(40),
];

/** Text that starts and ends with something, around a repeated unit. */
const FRAMED: [string, string, string][] = [
  ['on:\n', ' ', 'x'],
  ['on:\n', '\n', 'pull_request_target'],
  ['on:\n', '  \n', 'x'],
  ['- ', ' ', 'x'],
  ['uses:', ' ', 'x'],
  ['languages: [', 'a, ', 'x'],
  ['languages: [', 'actions, ', ''],
  ['languages:', ' ', 'x'],
  ['language: ', ' ', 'x'],
  ['${{', ' ', 'x'],
  ['${{', 'a ', 'secrets'],
  ['runs-on:', ' ', 'x'],
  ['runs-on:', '\n', 'x'],
  ['permissions:', ' ', 'x'],
  ['permissions:', '\n', 'write'],
  ['cooldown', ' ', 'x'],
  ['ignore-scripts', ' ', '='],
  ['a', ' ', ':'],
  ['a', 'a', 'x'],
  ['1', ',', 'x'],
  ['1 ', '<a> ', 'x'],
  ['docker buildx build', ' x', ''],
  ['goreleaser release', ' x', ''],
  ['mvn', ' x', ''],
  ['npm publish', ' x', ''],
  ['license-checker', ' x', ''],
  ['make', ' x', ''],
  ['a', '/', 'b'],
  ['', 'fuzz/', '_test.go'],
  ['', 'a/', 'x_fuzzer.cc'],
  ['[', 'a', ''],
  ['a', ' ', '='],
  // Options that -{1,2}[\w-]+ could read two ways, which doubled the time with each one.
  ['npm', ' --a', ' !'],
  ['npm', ' --a=b', ' !'],
  ['make', ' --a', ' !'],
  ['pnpm run', ' -a', ''],
  ['docker buildx build', ' --a', ''],
];

describe('the scanner takes linear time on files built to be slow', () => {
  it('runs every pattern it compiles on 256 KB of text built to be slow in under 500 ms, growing linearly', async () => {
    const shapes: [string, string, string][] = [...UNITS.map((u): [string, string, string] => ['', u, '']), ...FRAMED];
    const at = (size: number) => shapes.map(([before, unit, after]) => before + fill(unit, size) + after);
    const [texts, big] = [at(256 * KB), at(MB)];
    const patterns = COMPILED.slice(READER);
    expect(patterns.length).toBeGreaterThan(100);
    const slow: string[] = [];
    for (const { source, flags } of patterns) {
      const rx = re(source, flags, false);
      const g = new RegExp(rx.source, rx.flags + 'g');
      const scan = (text: string) => () => {
        g.lastIndex = 0;
        for (let m: RegExpExecArray | null; (m = g.exec(text));) if (m[0] === '') g.lastIndex++;
      };
      for (const [k, text] of texts.entries()) {
        const ms = await time(scan(text), PATTERN_LIMIT);
        const name = `${source.slice(0, 80)} on ${JSON.stringify(text.slice(0, 16))}...`;
        if (ms > PATTERN_LIMIT) slow.push(`${name}: ${Math.round(ms)} ms`);
        // Work that could take over 100 ms on 1 MB if it grew faster than linear: how it grows.
        else if (ms > 6) {
          const why = await slowness(scan(text), scan(big[k]), Infinity);
          if (why) slow.push(`${name} on 1 MB: ${why}`);
        }
      }
    }
    expect(slow).toEqual([]);
  }, 600_000);

  /** 1 MB files built to be slow: what each is, the function it's for, and the file. */
  function hostile(size: number): [string, string, string][] {
    const n = (per: number) => Math.max(1, Math.floor(size / per));
    const header = 'name: ci\non: [push]\njobs:\n';
    const job = (i: number) =>
      `  j${i}:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n` +
      `      - run: echo \${{ github.event.issue.title }}\n`;
    let deep = '';
    for (let d = 0; deep.length < size; d++) deep += ' '.repeat(d) + 'a:\n';
    let stairs = 'on: pull_request_target\njobs:\n';
    for (let d = 0; stairs.length < size; d++) stairs += ' '.repeat(d) + '- uses: actions/checkout@v4\n';
    // Ten aliases of the level before at each level: 10^levels nodes in a few hundred bytes.
    const laughs = (levels: number) => {
      let s = 'on: push\njobs:\n  j:\n    runs-on: x\n    x0: &l0\n' + lines(10, () => '      - lol') + '\n';
      for (let l = 1; l <= levels; l++) s += `    x${l}: &l${l}\n` + lines(10, () => `      - *l${l - 1}`) + '\n';
      return s + '    steps:\n      - run: echo hi\n';
    };
    let chained = 'k0: &k0\n  x0: 1\n';
    for (let i = 1; chained.length < size; i++) chained += `k${i}: &k${i}\n  <<: *k${i - 1}\n  x${i}: 1\n`;
    let aliasChain = 'l0: &l0 [a]\n';
    for (let i = 1; aliasChain.length < size; i++) aliasChain += `l${i}: &l${i}\n  - *l${i - 1}\n`;
    return [
      ['many jobs', 'workflow', header + lines(n(150), job)],
      [
        'many steps',
        'workflow',
        header + '  j:\n    steps:\n' + lines(n(60), (i) => `      - run: echo \${{ secrets.T${i} }}`),
      ],
      ['deep nesting', 'workflow', deep.slice(0, size)],
      ['deep flow nesting', 'workflow', 'x: ' + fill('[', size / 2) + fill(']', size / 2)],
      ['an unclosed flow over many lines', 'workflow', 'x: [\n' + fill('  a,\n', size)],
      ['an unclosed double quote over many lines', 'workflow', 'x: "\n' + fill('  a\n', size)],
      ['a double-quoted line ending in a backslash, many times', 'workflow', 'x: "\n' + fill('  a\\\n', size)],
      ['an unclosed single quote over many lines', 'workflow', "x: '\n" + fill('  a\n', size)],
      ['a huge flow mapping', 'workflow', 'x: {' + fill('a: b, ', size) + '}'],
      ['a huge flow sequence', 'workflow', 'x: [' + fill('a, ', size) + ']'],
      ['one long line', 'workflow', 'x: ' + fill('a', size)],
      ['a long line of spaces', 'workflow', 'x:' + fill(' ', size) + 'y'],
      ['a plain scalar over many lines', 'workflow', 'x: a\n' + fill('  b\n', size)],
      [
        'a block scalar over many lines',
        'workflow',
        header + '  j:\n    steps:\n      - run: |\n' + fill('          echo ${{ github.head_ref }}\n', size),
      ],
      [
        'many anchors and aliases',
        'workflow',
        header + '  j:\n    steps:\n' + lines(n(40), (i) => `      - &a${i} {run: echo ${i}}\n      - *a${i}`),
      ],
      ['merge keys', 'workflow', 'base: &b {a: 1, b: 2, c: 3}\n' + lines(n(30), (i) => `k${i}:\n  <<: *b\n  d: ${i}`)],
      ['merge keys of merge keys', 'workflow', chained],
      ['an alias of an alias of an alias...', 'workflow', aliasChain],
      ['billion laughs, 7 levels', 'workflow', laughs(7)],
      ['billion laughs, 9 levels', 'workflow', laughs(9)],
      [
        'tabs and odd indentation',
        'workflow',
        lines(n(12), (i) => '\t'.repeat(i % 7) + ' '.repeat(i % 3) + `k${i}: v`),
      ],
      ['many dashes', 'workflow', fill('- ', size)],
      ['nested dashes on each line', 'workflow', lines(n(40), (i) => '  '.repeat(i % 20) + '- - - - a')],
      ['long quoted keys', 'workflow', lines(n(1000), (i) => `"${'k'.repeat(990)}${i}": v`)],
      ['comment lines', 'workflow', fill('# comment\n', size)],
      ['blank lines', 'workflow', 'on: push\n' + fill('\n', size)],
      [
        'blank lines and a checkout',
        'workflow',
        'on: pull_request_target\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n' + fill('\n', size),
      ],
      ['whitespace-only lines', 'workflow', 'on: push\n' + fill('    \n', size)],
      ['one line of spaces', 'workflow', 'on: push\n' + fill(' ', size)],
      ['one line of spaces and dashes', 'workflow', 'on: push\n' + fill(' - ', size)],
      [
        'many uses lines',
        'workflow',
        header + '  j:\n    steps:\n' + fill('      - uses: actions/checkout@v4\n', size),
      ],
      [
        'checkouts in one step',
        'workflow',
        header + '  j:\n    steps:\n      - name: x\n' + fill('        uses: actions/checkout@v4\n', size),
      ],
      ['checkouts in steps nested ever deeper', 'workflow', stairs],
      [
        'risky expressions',
        'workflow',
        header + '  j:\n    steps:\n      - run: |\n' + fill('          echo ${{ github.event.issue.title }}\n', size),
      ],
      [
        'an unclosed expression',
        'workflow',
        header + '  j:\n    steps:\n      - run: echo ' + fill('${{ github.event.', size),
      ],
      ['many job keys', 'workflow', 'jobs:\n' + fill('  j:\n    permissions:\n', size)],
      ['CRLF line ends', 'workflow', (header + lines(n(150), job)).replaceAll('\n', '\r\n')],
      ['CR line ends', 'workflow', (header + lines(n(150), job)).replaceAll('\n', '\r')],
      [
        'many steps of a composite action',
        'action',
        'runs:\n  using: composite\n  steps:\n' + fill('    - run: echo hi\n      shell: bash\n', size),
      ],
    ];
  }

  it('reads and analyzes each 1 MB workflow built to be slow in under 5 s, growing linearly, or stops at a cap', async () => {
    // Warm up, as a running server is.
    for (const [, kind, text] of hostile(4 * KB)) {
      try {
        if (kind === 'workflow') readWorkflow('.github/workflows/x.yml', text);
        else readCompositeSteps('action.yml', text);
      } catch {
        // Stopped at a cap.
      }
    }
    const slow: string[] = [];
    const stopped: string[] = [];
    const read = (name: string, kind: string, text: string) => async () => {
      const file = { path: '.github/workflows/x.yml', text };
      analyzeWorkflow(file.path, text);
      parseYaml(text);
      try {
        if (kind === 'action') readCompositeSteps('action.yml', text);
        else {
          readWorkflow(file.path, text);
          tracedSecrets([file]);
          reviewWorkflows([file]);
          await licenseGate({
            workflows: [file],
            files: [],
            read: async () => null,
            hops: new Hops([], async () => null),
          });
          await customQueries({ workflows: [file], files: [], read: async () => null });
          await releaseCacheCheck({
            workflows: [file],
            unread: [],
            files: [],
            treeRead: true,
            read: async () => null,
            hops: new Hops([], async () => null),
          });
        }
      } catch (e) {
        if (!(e instanceof TooComplex)) throw e;
        stopped.push(name);
      }
    };
    const quarter = hostile(256 * KB);
    for (const [k, [name, kind, text]] of hostile(MB).entries()) {
      const why = await slowness(read(name, kind, quarter[k][2]), read(name, kind, text), PARSER_LIMIT);
      if (why) slow.push(`${name}: ${why}`);
    }
    expect(slow).toEqual([]);
    // What's too deep, or too big with its aliases expanded, is too complex to read.
    expect([...new Set(stopped)]).toEqual([
      'deep nesting',
      'deep flow nesting',
      'merge keys of merge keys',
      'an alias of an alias of an alias...',
      'billion laughs, 7 levels',
      'billion laughs, 9 levels',
      'many dashes',
    ]);
  }, 300_000);

  it('stops at a document too deep, or too big with its aliases expanded, and says why', () => {
    const laughs = (levels: number) => {
      let s = 'x0: &l0\n' + lines(10, () => '  - lol') + '\n';
      for (let l = 1; l <= levels; l++) s += `x${l}: &l${l}\n` + lines(10, () => `  - *l${l - 1}`) + '\n';
      return s;
    };
    expect(() => readYaml(laughs(3))).not.toThrow();
    expect(() => readYaml(laughs(9))).toThrow('its aliases or merge keys expand too far');
    expect(() => readYaml('x: ' + '['.repeat(300) + ']'.repeat(300))).toThrow('it nests more than 200 deep');
    expect(() => readYaml(lines(300, (d) => ' '.repeat(d) + 'a:'))).toThrow('it nests more than 200 deep');
    // A real workflow's 20 levels are fine; the lenient reader gives null where the strict one throws.
    expect(() => readYaml(lines(20, (d) => ' '.repeat(d) + 'a:'))).not.toThrow();
    expect(parseYaml(laughs(9))).toBeNull();
    expect(() => readWorkflow('.github/workflows/x.yml', laughs(9))).toThrow(TooComplex);
  });

  it('matches globs in linear time, as the old exponential matcher did', async () => {
    for (const [glob, name, want] of [
      ['*', '', true],
      ['*', 'abc', true],
      ['a*c', 'abc', true],
      ['a*c', 'ab', false],
      ['a?c', 'abc', true],
      ['a?c', 'ac', false],
      ['*a*b', 'xaxb', true],
      ['*a*b', 'xbxa', false],
      ['**', 'x', true],
      ['dist-*-*', 'dist-linux-x64', true],
      ['', '', true],
      ['', 'a', false],
    ] as const) {
      expect([glob, name, globMatch(glob, name)]).toEqual([glob, name, want]);
    }
    // Twenty stars took longer than a minute.
    for (const k of [12, 16, 20, 1000]) {
      expect(await time(() => globMatch('*a'.repeat(k) + 'b', 'a'.repeat(k * 3)), PATTERN_LIMIT)).toBeLessThan(
        PATTERN_LIMIT,
      );
    }
  });

  /** Release workflows built to make the cache check's job graph slow, with the files they use. */
  function releases(size: number): [string, Record<string, string>][] {
    const release = 'on:\n  release:\n    types: [published]\njobs:\n';
    let chain = release;
    for (let i = 0; chain.length < size; i++) {
      chain +=
        `  j${i}:\n    runs-on: x\n` +
        (i ? `    needs: [j${i - 1}]\n` : '') +
        `    steps:\n      - uses: actions/upload-artifact@v4\n        with:\n          name: a${i}\n` +
        `      - uses: actions/download-artifact@v4\n        with:\n          pattern: a*\n      - run: cargo publish\n`;
    }
    const n = 3000;
    let fan = release;
    for (let i = 0; i < n; i++)
      fan += `  u${i}:\n    steps:\n      - uses: actions/upload-artifact@v4\n        with: {name: "${'*a'.repeat(5)}${i}"}\n`;
    fan += `  pub:\n    needs: [${Array.from({ length: n }, (_, i) => `u${i}`).join(', ')}]\n    steps:\n`;
    while (fan.length < size)
      fan += `      - uses: actions/download-artifact@v4\n        with: {pattern: "${'*a'.repeat(5)}*"}\n`;
    fan += '      - run: cargo publish\n';
    let env = release + '  pub:\n    env:\n' + lines(20000, (i) => `      E${i}: v${i}`) + '\n    steps:\n';
    for (let i = 0; env.length < size; i++)
      env += `      - uses: actions/upload-artifact@v4\n        env: {X${i}: y}\n        with: {name: "\${{ env.E${i % 20000} }}"}\n`;
    env += '      - run: cargo publish\n';
    const make = release + '  pub:\n    steps:\n      - run: |\n' + fill('          make release\n', size);
    const makefile = 'release:\n' + fill('\techo 1 && docker buildx build . --push=false\n', size);
    const uses = release + '  pub:\n    steps:\n' + fill('      - uses: ./.github/actions/a\n', size);
    const action = 'runs:\n  using: composite\n  steps:\n' + fill('    - run: echo hi\n      shell: bash\n', size);
    return [
      ['jobs that each need the one before', { '.github/workflows/r.yml': chain }],
      ['a job that downloads thousands of artifacts from thousands of jobs', { '.github/workflows/r.yml': fan }],
      ['artifact names from an env of thousands of names', { '.github/workflows/r.yml': env }],
      ['a Makefile target run thousands of times', { '.github/workflows/r.yml': make, Makefile: makefile }],
      [
        'a composite action of thousands of steps, used thousands of times',
        { '.github/workflows/r.yml': uses, '.github/actions/a/action.yml': action },
      ],
    ];
  }

  it('checks release workflows built to be slow in under 5 s, growing linearly, or stops with unknown', async () => {
    const slow: string[] = [];
    const statuses: string[] = [];
    // Each run reads the files afresh (Hops keeps what it read).
    const check = (files: Record<string, string>) => async () => {
      const read = async (p: string) => files[p] ?? null;
      const workflows = Object.entries(files)
        .filter(([p]) => p.startsWith('.github/workflows/'))
        .map(([path, text]) => ({ path, text }));
      const hops = new Hops(Object.keys(files), read);
      const r = await releaseCacheCheck({
        workflows,
        unread: [],
        files: Object.keys(files),
        treeRead: true,
        read,
        hops,
      });
      statuses.push(r.status);
      await licenseGate({ workflows, files: Object.keys(files), read, hops });
      tracedSecrets(workflows);
    };
    const quarter = releases(256 * KB);
    for (const [k, [name, files]] of releases(MB).entries()) {
      const why = await slowness(check(quarter[k][1]), check(files), PARSER_LIMIT);
      if (why) slow.push(`${name}: ${why}`);
    }
    expect(slow).toEqual([]);
    expect(statuses.filter((s) => !['pass', 'info', 'unknown'].includes(s))).toEqual([]);
  }, 300_000);

  it('reads hostile Makefiles, package.json files and tags in under 5 s, growing linearly', async () => {
    const cases = (size: number): [string, string, string][] => [
      ['Makefile', 'many targets', lines(size / 20, (i) => `t${i}: dep\n\techo ${i}`)],
      ['Makefile', 'one long target line', fill('a ', size) + ':'],
      ['Makefile', 'a long line of spaces', 'a' + fill(' ', size) + 'b'],
      ['package.json', 'a huge script', JSON.stringify({ scripts: { release: fill('npm publish ', size) } })],
      [
        'package.json',
        'many scripts',
        JSON.stringify({
          scripts: Object.fromEntries(
            lines(size / 30, (i) => `s${i}`)
              .split('\n')
              .map((k) => [k, 'x']),
          ),
        }),
      ],
    ];
    // Each run reads the file afresh (Hops keeps what it read), and asks for 1000 targets or scripts.
    const ask = (file: string, text: string) => async () => {
      const hops = new Hops([file], async () => text);
      for (let k = 0; k < 1000; k++) await hops.body(file === 'Makefile' ? 'make' : 'npm', k % 2 ? 'release' : `t${k}`);
    };
    const slow: string[] = [];
    const quarter = cases(256 * KB);
    for (const [k, [file, name, text]] of cases(MB).entries()) {
      const why = await slowness(ask(file, quarter[k][2]), ask(file, text), PARSER_LIMIT);
      if (why) slow.push(`${file}, ${name}: ${why}`);
    }
    const tags = [
      Array.from({ length: 100 }, (_, i) => ({ tag: `v${'1.'.repeat(120)}${i}` })),
      Array.from({ length: 100 }, (_, i) => ({ tag: `${'9'.repeat(200)}.${i}` })),
    ];
    for (const t of tags) {
      const ms = await time(() => releaseLine(t, 'x'), PARSER_LIMIT);
      if (ms > PARSER_LIMIT) slow.push(`tags: ${Math.round(ms)} ms`);
    }
    expect(slow).toEqual([]);
  }, 300_000);

  it('reads hostile policies, plans and release notes for response times, disclosure and drills in under 5 s, growing linearly', async () => {
    const texts = (size: number): [string, string][] => [
      ['times without a word for answering', fill('1 day ', size)],
      ['ranges', fill('1 - 2 - 3 days ', size)],
      ['dashes after a number', '1' + fill(' -', size)],
      ['a word for answering, then times far off', 'respond ' + fill('x ', size / 2) + fill('2 days ', size / 2)],
      ['times beside words that almost answer', fill('responsible 48 hours ', size)],
      ['many short sentences', fill('We wait 3 days. ', size)],
      ['one long sentence', fill('we wait about 12 working days and more ', size)],
      ['articles', fill('a a an an ', size)],
      ['number words', fill('forty-eight seventy-two ', size)],
      ['an embargo everywhere', fill('embargo ', size)],
      ['downstream without telling anyone', fill('downstream ', size)],
      ['dates without a drill', fill('2026-03-04 March 4, 2026 ', size)],
      ['drills without a date', fill('tabletop drill dry run ', size)],
      ['months', fill('March March May ', size)],
      ['table rows', '| Step | Target |\n| --- | --- |\n' + fill('| Acknowledge | x |\n', size)],
    ];
    const own = Array.from({ length: 100 }, (_, i) => ({
      ghsa_id: `GHSA-aaaa-bbbb-${i}xyz`,
      cve_id: `CVE-2026-${10000 + i}`,
    }));
    const notes = (size: number): [string, string][] => [
      ['advisory IDs', fill('GHSA-abcd-efgh-ijkl ', size)],
      ['CVE IDs', fill('CVE-2026-1234567 ', size)],
      ['ID prefixes', fill('ghsa-', size)],
      ['CVE prefixes', fill('CVE-', size)],
    ];
    const read = (text: string) => () => {
      const p = readPolicy(text, 'SECURITY.md');
      responseTarget(p);
      disclosureTerms(p);
      drillNote(p);
    };
    const named = (body: string) => () => releasesNaming(own, [{ tag_name: 'v1', body }]);
    const slow: string[] = [];
    const [quarter, quarterNotes] = [texts(256 * KB), notes(256 * KB)];
    for (const [k, [name, text]] of texts(MB).entries()) {
      const why = await slowness(read(quarter[k][1]), read(text), PARSER_LIMIT);
      if (why) slow.push(`${name}: ${why}`);
    }
    for (const [k, [name, body]] of notes(MB).entries()) {
      const why = await slowness(named(quarterNotes[k][1]), named(body), PARSER_LIMIT);
      if (why) slow.push(`release notes, ${name}: ${why}`);
    }
    expect(slow).toEqual([]);
  }, 300_000);
});
