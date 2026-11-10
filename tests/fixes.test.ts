/** Click-to-fix pull requests (lib/fixes.ts), against a fake GitHub. No network. */
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import {
  apply,
  clearRefCache,
  dependabotBlocks,
  fill,
  FixError,
  friendly,
  guideItems,
  pinText,
  plan,
  type Plan,
  preview,
  resolver,
  unifiedDiff,
} from '@/lib/fixes.ts';
import { FakeGitHub, repoRoutes, SHA_A, SHA_B, SHA_C, useTestEnv } from './helpers.ts';

useTestEnv();

async function planFor(gh: FakeGitHub, itemId: string, login = 'octo'): Promise<Plan> {
  const p = await plan(gh.call, 'octo/demo', itemId, login);
  if ('existing' in p) throw new Error('expected a plan');
  return p;
}

async function refusal(work: Promise<unknown>): Promise<FixError> {
  try {
    await work;
  } catch (e) {
    if (e instanceof FixError) return e;
    throw e;
  }
  throw new Error('expected a FixError');
}

// ------------------------------------------------------------------------------------------------ fill
describe('fill', () => {
  it('matches core.js for every template', async () => {
    // The page's own browser module (allowJs lets TypeScript read it; it isn't type-checked).
    const core = await import('../public/shared/core.js');
    const items = Object.values(guideItems());
    const templates = items.filter((i) => i.new_file).map((i) => i.new_file!.template);
    templates.push(...items.flatMap((i) => (i.snippets || []).map((s) => s.code)).slice(0, 40));
    const ctxs = [
      { owner: 'octo', repo: 'demo', full: 'octo/demo', branch: 'trunk', ownerType: 'User', ecosystems: ['npm', 'go'] },
      {
        owner: 'acme',
        repo: 'lib',
        full: 'acme/lib',
        branch: 'main',
        ownerType: 'Organization',
        ecosystems: ['pypi', 'unknown'],
      },
      {},
      // A scan that counted the workflows: none leaves GitHub Actions out of dependabot.yml.
      { owner: 'octo', repo: 'site', full: 'octo/site', ecosystems: ['cargo'], workflowCount: 0 },
      { ecosystems: ['npm'], workflowCount: 3 },
      { workflowCount: 0 },
    ];
    expect(templates.length).toBeGreaterThan(10);
    for (const t of templates) for (const c of ctxs) expect(fill(t, c)).toBe(core.fill(t, c));
  });

  it('names a person, not an org', () => {
    const t = 'lead: {person}; owners: {maintainer}';
    expect(fill(t, { owner: 'acme', ownerType: 'Organization' })).toBe(
      'lead: (name a maintainer); owners: @acme/maintainers',
    );
    expect(fill(t, { owner: 'octo', ownerType: 'User' })).toBe('lead: @octo; owners: @octo');
    expect(fill(t, { owner: 'acme', ownerType: 'Organization', maintainer: '@me' }).endsWith('owners: @me')).toBe(true);
  });
});

it('writes dependabot blocks for the root, subfolders and gradle, skipping vendored code', () => {
  const out = dependabotBlocks([
    'package.json',
    'web/package.json',
    'tools/go.mod',
    'android/build.gradle.kts',
    'vendor/x/go.mod',
    'testdata/pyproject.toml',
  ]);
  expect(out).toContain('package-ecosystem: npm\n    directory: /\n');
  expect(out).toContain('package-ecosystem: gomod\n    directories:\n      - "/tools"\n');
  expect(out).toContain('package-ecosystem: gradle');
  expect(out).toContain('/android');
  expect(out).not.toContain('vendor');
  expect(out).not.toContain('pip');
  expect(out.split('cooldown:').length - 1).toBe(3);
});

// ------------------------------------------------------------------------------------------------ pins
const WORKFLOW = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: "actions/setup-node@v4.1.0" # keep node in step
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.20
      - uses: github/codeql-action/upload-sarif@v3
      - uses: owner/already@${SHA_C}
      - uses: owner/expr@\${{ inputs.ref }}
      - run: |
          echo "uses: not/a-step@v1"
  reuse:
    uses: org/workflows/.github/workflows/build.yml@main
`;

const PINS: Record<string, string> = {
  'actions/checkout@v4': SHA_A,
  'actions/setup-node@v4.1.0': SHA_B,
  'github/codeql-action@v3': SHA_C,
  'org/workflows@main': SHA_A,
};
const fakeResolve = (owner: string, repo: string, ref: string) => PINS[`${owner}/${repo}@${ref}`];

describe('pinText', () => {
  it('rewrites only real unpinned steps', () => {
    const [out, changes] = pinText(WORKFLOW, fakeResolve);
    expect(out).toContain(`      - uses: actions/checkout@${SHA_A} # v4\n`);
    expect(out).toContain(`      - uses: "actions/setup-node@${SHA_B}" # v4.1.0 # keep node in step\n`);
    expect(out).toContain(`      - uses: github/codeql-action/upload-sarif@${SHA_C} # v3\n`);
    expect(out).toContain(`    uses: org/workflows/.github/workflows/build.yml@${SHA_A} # main\n`);
    for (const untouched of [
      './.github/actions/local',
      'docker://alpine:3.20',
      `owner/already@${SHA_C}`,
      '${{ inputs.ref }}',
      'echo "uses: not/a-step@v1"',
    ]) {
      expect(out).toContain(untouched);
    }
    expect(changes.map((c) => c.action)).toEqual([
      'actions/checkout',
      'actions/setup-node',
      'github/codeql-action/upload-sarif',
      'org/workflows/.github/workflows/build.yml',
    ]);
    expect(changes.map((c) => c.branch)).toEqual([false, false, false, true]);
  });

  it('keeps CRLF and leaves unknown refs alone', () => {
    const text = 'steps:\r\n  - uses: actions/checkout@v4\r\n  - uses: nobody/missing@v1\r\n';
    const [out, changes] = pinText(text, fakeResolve);
    expect(out).toBe(`steps:\r\n  - uses: actions/checkout@${SHA_A} # v4\r\n  - uses: nobody/missing@v1\r\n`);
    expect(changes[1].sha).toBeNull();
  });
});

it('asks GitHub for the SHA once, then caches it', async () => {
  clearRefCache();
  const gh = new FakeGitHub({ 'GET /repos/actions/checkout/commits/v4': [200, `${SHA_A}\n`] });
  const resolve = resolver(gh.call);
  expect(await resolve('actions', 'checkout', 'v4')).toBe(SHA_A);
  expect(await resolve('actions', 'checkout', 'v4')).toBe(SHA_A);
  expect(gh.calls).toHaveLength(1);
  expect(gh.calls[0][1]).toBe('/repos/actions/checkout/commits/v4');
});

// ----------------------------------------------------------------------------------------------- plans
describe('plan', () => {
  it('fills the SECURITY.md template and flags reporting that is off', async () => {
    const gh = new FakeGitHub({
      ...repoRoutes({ tree: ['README.md'] }),
      'GET /repos/octo/demo/private-vulnerability-reporting': [200, { enabled: false }],
    });
    const p = await planFor(gh, 'disc-security-md');
    expect(p.files).toHaveLength(1);
    const [f] = p.files;
    expect(f.path).toBe('SECURITY.md');
    expect(f.before).toBeNull();
    expect(f.content).toContain('https://github.com/octo/demo/security/advisories/new');
    expect(f.content.replaceAll('{}', '')).not.toContain('{');
    expect(p.notes.some((n) => n.includes('Private vulnerability reporting is off'))).toBe(true);
    expect(p.head).toBe('sosf/disc-security-md');
    expect(p.base_sha).toBe(SHA_A);
    const view = preview(p);
    expect(view.files[0].change).toBe('add');
    expect(view.body).toContain('Nothing changes until someone merges');
  });

  it('refuses when the file exists elsewhere', async () => {
    const gh = new FakeGitHub(repoRoutes({ tree: ['.github/security.md'] }));
    expect((await refusal(plan(gh.call, 'octo/demo', 'disc-security-md', 'octo'))).message).toContain(
      'already has .github/security.md',
    );
  });

  it('names the admin in CODEOWNERS for an org without a maintainers team', async () => {
    const gh = new FakeGitHub(repoRoutes({ ownerType: 'Organization', tree: ['README.md'] }));
    const p = await planFor(gh, 'repo-codeowners', 'alice');
    expect(p.files[0].content).toContain('/.github/        @alice');
    expect(p.notes.some((n) => n.includes('no @octo/maintainers team'))).toBe(true);
  });

  it('points dependabot at the repo folders', async () => {
    const gh = new FakeGitHub(repoRoutes({ tree: ['go.mod', 'site/package.json', '.github/workflows/ci.yml'] }));
    const { content } = (await planFor(gh, 'deps-update-automation')).files[0];
    expect(content).toContain('package-ecosystem: github-actions');
    expect(content).toContain('package-ecosystem: gomod\n    directory: /');
    expect(content).toContain('- "/site"');
  });

  it('updates GitHub Actions only in a repo with workflows, since Dependabot calls the entry an error without', async () => {
    const updates = async (opts: { tree: string[]; truncated?: boolean }) => {
      const { content } = (await planFor(new FakeGitHub(repoRoutes(opts)), 'deps-update-automation')).files[0];
      return YAML.parse(content).updates.map((u: Record<string, unknown>) => u['package-ecosystem']);
    };
    expect(await updates({ tree: ['go.mod', '.github/workflows/ci.yaml'] })).toEqual(['github-actions', 'gomod']);
    // A workflow is a .yml or .yaml file right in .github/workflows, not in a folder under it.
    expect(await updates({ tree: ['go.mod', '.github/workflows/scripts/x.yml'] })).toEqual(['gomod']);
    // A list GitHub cut short may have left the workflows out, so the entry stays.
    expect(await updates({ tree: ['go.mod'], truncated: true })).toEqual(['github-actions', 'gomod']);
    // With neither, the file would update nothing, so no pull request is offered.
    const gh = new FakeGitHub(repoRoutes({ tree: ['Dockerfile', 'README.md'] }));
    const err = await refusal(plan(gh.call, 'octo/demo', 'deps-update-automation', 'octo'));
    expect([err.status, err.message]).toEqual([
      409,
      'octo/demo has no workflows and no package manifests the template covers, so its dependabot.yml would update ' +
        'nothing. Write one by hand for what the repository uses, such as Docker images.',
    ]);
  });

  it('handles public-only, archived, existing and unknown fixes', async () => {
    const msg = async (gh: FakeGitHub, id: string) => (await refusal(plan(gh.call, 'octo/demo', id, 'octo'))).message;
    expect(await msg(new FakeGitHub(repoRoutes({ isPrivate: true })), 'posture-scorecard')).toContain(
      'public repository',
    );
    expect(await msg(new FakeGitHub(repoRoutes({ archived: true })), 'disc-security-md')).toContain('archived');
    expect(
      (await refusal(plan(new FakeGitHub(repoRoutes()).call, 'octo/demo', 'acct-2fa-required', 'octo'))).status,
    ).toBe(422);
    const gh = new FakeGitHub({
      ...repoRoutes(),
      'GET /repos/octo/demo/pulls': [200, [{ html_url: 'https://github.com/octo/demo/pull/7', number: 7 }]],
    });
    expect(await plan(gh.call, 'octo/demo', 'disc-security-md', 'octo')).toEqual({
      existing: { url: 'https://github.com/octo/demo/pull/7', number: 7 },
    });
  });

  it('pins every workflow and reports what it missed', async () => {
    clearRefCache();
    const gh = new FakeGitHub({
      ...repoRoutes({ tree: ['.github/workflows/ci.yml', '.github/workflows/done.yml', 'README.md'] }),
      'GET /repos/octo/demo/contents/\\.github/workflows/ci\\.yml': [
        200,
        'steps:\n  - uses: actions/checkout@v4\n  - uses: nobody/missing@v1\n',
      ],
      'GET /repos/octo/demo/contents/\\.github/workflows/done\\.yml': [
        200,
        `steps:\n  - uses: actions/checkout@${SHA_C} # v4\n`,
      ],
      'GET /repos/actions/checkout/commits/v4': [200, SHA_A],
    });
    const p = await planFor(gh, 'ci-pin-actions');
    expect(p.files.map((f) => f.path)).toEqual(['.github/workflows/ci.yml']);
    expect(p.title).toBe('Pin 1 GitHub Action to commit SHAs');
    expect(p.notes.some((n) => n.includes('nobody/missing@v1'))).toBe(true);
    const diff = (preview(p).files[0] as { diff: string }).diff;
    expect(diff).toContain(`+  - uses: actions/checkout@${SHA_A} # v4`);
    expect(diff).toContain('-  - uses: actions/checkout@v4');
  });

  it('says so when there is nothing to pin', async () => {
    const gh = new FakeGitHub({
      ...repoRoutes({ tree: ['.github/workflows/ci.yml'] }),
      'GET /repos/octo/demo/contents/\\.github/workflows/ci\\.yml': [
        200,
        `steps:\n  - uses: actions/checkout@${SHA_C}\n`,
      ],
    });
    expect((await refusal(plan(gh.call, 'octo/demo', 'ci-pin-actions', 'octo'))).message).toContain('already pinned');
  });
});

// ----------------------------------------------------------------------------------------------- apply
async function planned(): Promise<Plan> {
  return planFor(
    new FakeGitHub({
      ...repoRoutes({ tree: ['README.md'] }),
      'GET /repos/octo/demo/private-vulnerability-reporting': [200, { enabled: true }],
    }),
    'disc-security-md',
  );
}

describe('apply', () => {
  it('creates the tree, commit, branch and pull request', async () => {
    const p = await planned();
    const taken = new Set(['sosf/disc-security-md']);
    const gh = new FakeGitHub({
      ...repoRoutes(),
      'POST /repos/octo/demo/git/trees': [201, { sha: 'tree1' }],
      'POST /repos/octo/demo/git/commits': [201, { sha: 'commit1' }],
      'POST /repos/octo/demo/git/refs': (_path, body) =>
        taken.has(body.ref.replace(/^refs\/heads\//, '')) ? [422, { message: 'Reference already exists' }] : [201, {}],
      'POST /repos/octo/demo/pulls': [201, { html_url: 'https://github.com/octo/demo/pull/9', number: 9 }],
    });
    expect(await apply(gh.call, p)).toEqual({
      url: 'https://github.com/octo/demo/pull/9',
      number: 9,
      branch: 'sosf/disc-security-md-2',
    });
    const [tree] = gh.made('POST', '/repos/octo/demo/git/trees');
    expect(tree[2].base_tree).toBe(SHA_B);
    expect(tree[2].tree[0].path).toBe('SECURITY.md');
    const [commit] = gh.made('POST', '/repos/octo/demo/git/commits');
    expect(commit[2].parents).toEqual([SHA_A]);
    expect(commit[2]).not.toHaveProperty('author');
    const [pr] = gh.made('POST', '/repos/octo/demo/pulls');
    expect(pr[2]).toMatchObject({ base: 'main', head: 'sosf/disc-security-md-2' });
    expect(gh.made('PUT', '/')).toHaveLength(0);
    expect(gh.made('PATCH', '/')).toHaveLength(0);
  });

  it('refuses when the branch moved since the preview', async () => {
    const p = await planned();
    const gh = new FakeGitHub({
      ...repoRoutes(),
      'GET /repos/octo/demo/git/ref/heads/main': [200, { object: { sha: SHA_C } }],
    });
    expect((await refusal(apply(gh.call, p))).message).toContain('new commits since the preview');
    expect(gh.made('POST', '/')).toHaveLength(0);
  });

  it('cleans up the branch when the pull request fails', async () => {
    const p = await planned();
    const gh = new FakeGitHub({
      ...repoRoutes(),
      'POST /repos/octo/demo/git/trees': [201, { sha: 'tree1' }],
      'POST /repos/octo/demo/git/commits': [201, { sha: 'commit1' }],
      'POST /repos/octo/demo/git/refs': [201, {}],
      'POST /repos/octo/demo/pulls': [403, { message: 'Resource not accessible by integration' }],
    });
    expect((await refusal(apply(gh.call, p))).message).toContain("isn't allowed to open a pull request");
    expect(gh.made('DELETE', '/repos/octo/demo/git/refs/heads/sosf/disc-security-md')).toHaveLength(1);
  });
});

it('says when the Workflows permission is missing', () => {
  const err = friendly(
    403,
    {
      message:
        'refusing to allow a GitHub App to create or update workflow `.github/workflows/zizmor.yml` without `workflows` permission',
    },
    'add files',
  );
  expect(err.message).toContain('Workflows permission');
  expect(err.status).toBe(403);
});

it("formats diffs like Python's difflib", () => {
  // Expected output from difflib.unified_diff(a, b, 'a/f', 'b/f', n=0).
  expect(unifiedDiff('a\nb\nc\n', 'a\nB\nc\n', 'a/f', 'b/f')).toBe('--- a/f\n+++ b/f\n@@ -2 +2 @@\n-b\n+B\n');
  expect(unifiedDiff('a\nb\nc\n', 'x\na\nb\nc\n', 'a/f', 'b/f')).toBe('--- a/f\n+++ b/f\n@@ -0,0 +1 @@\n+x\n');
  expect(unifiedDiff('a\nb\nc\n', 'a\nc\n', 'a/f', 'b/f')).toBe('--- a/f\n+++ b/f\n@@ -2 +1,0 @@\n-b\n');
  expect(unifiedDiff('same\n', 'same\n', 'a/f', 'b/f')).toBe('');
});
