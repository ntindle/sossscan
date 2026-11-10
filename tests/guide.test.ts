/** The guide data (public/data/guide.json, built by build/build_guide.py) through the page's own core.js. No network. */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { OSS_SCANNER_DEPENDENTS, OSS_SCANNER_STARS } from '@/lib/scanner/index.ts';
// The page's browser module (allowJs lets TypeScript read it; it isn't type-checked).
import * as sg from '../public/shared/core.js';

const guide = JSON.parse(readFileSync(new URL('../public/data/guide.json', import.meta.url), 'utf8'));

describe("the OSS Scanner item (sast-oss-scanner, the scanner's result for it)", () => {
  const item = guide.items.find((i: { id: string }) => i.id === 'sast-oss-scanner');
  // What the page knows after scanning octo/demo.
  const ctx = sg.ctxFromReport({ repo: 'octo/demo', meta: { default_branch: 'main', owner_type: 'Organization' } });
  const projectYaml = [
    'repo: https://github.com/octo/demo',
    'primary_contact: security@example.org   # your published security contact; this file is public',
    'homepage: https://github.com/octo/demo',
    'disabled: false',
    'dockerfile: .oss-scanner/Dockerfile',
    'threat_model: .oss-scanner/threat_model.md',
    '',
  ].join('\n');

  it('is in the guide, at the tier where eligible repos start', () => {
    expect(item).toMatchObject({
      title: "Enroll in Anthropic's OSS Scanner",
      category: 'sast',
      tier: 4,
      effort: 2,
      impact: 3,
      layer: 'public',
      stage: 'code',
      attacks: ['code-bug'],
      week: 'W2',
      tags: [],
    });
    // More than 1,000 stars is tier 5, and more than 200 dependents is tier 4 or higher.
    const tier = (stars: number, dependents: number) => sg.tierFor(stars, dependents, guide.tiers).id;
    expect([tier(OSS_SCANNER_STARS + 1, 0), tier(0, OSS_SCANNER_DEPENDENTS + 1)]).toEqual([5, 4]);
  });

  it('links to an enrollment pull request prefilled with the project.yaml the snippet shows', () => {
    const links = sg.settingsLinks(item, ctx);
    const start = links.find((l: { label: string }) => l.label === 'Start the enrollment pull request');
    const url = new URL(start!.url);
    expect(url.origin + url.pathname).toBe('https://github.com/anthropics/oss-scanner/new/main');
    expect([...url.searchParams.keys()]).toEqual(['filename', 'value']);
    expect(url.searchParams.get('filename')).toBe('projects/demo/project.yaml');
    expect(url.searchParams.get('value')).toBe(projectYaml);
    const snippet = item.snippets.find((s: { label: string }) => s.label.startsWith('projects/<name>/project.yaml'));
    expect(sg.fill(snippet.code, ctx)).toBe(projectYaml);
    // Before a scan there's no repo to name, so only the FAQ link is offered.
    expect(sg.settingsLinks(item, sg.ctxFromReport(null))).toEqual([
      { label: 'OSS Scanner FAQ', url: 'https://red.anthropic.com/oss-scanner/#faq' },
    ]);
  });

  it("says the size cue is this guide's, not Anthropic's rule", () => {
    expect(item.why).toContain('over 1,000 stars or 200 dependents');
    expect(item.why).toContain("that cue is this guide's, not Anthropic's rule");
    expect([OSS_SCANNER_STARS, OSS_SCANNER_DEPENDENTS]).toEqual([1000, 200]);
  });

  it('gives an AI agent a code prompt that tests the image offline and leaves enrolling to a maintainer', () => {
    expect(sg.promptKind(item)).toBe('code');
    const prompt = sg.agentPrompt(item, { ctx });
    expect(prompt).toContain('docker run --rm --network none oss-scanner-test');
    expect(prompt).toContain('Don’t open the enrollment pull request to anthropics/oss-scanner');
    expect(prompt).toContain('repo: https://github.com/octo/demo');
    // In a prompt for several checks, its rule is listed once, with the others'.
    const other = guide.items.find((i: { id: string }) => i.id === 'fuzz-harnesses');
    const many = sg.agentPromptMany([item, other], { ctx }) ?? '';
    expect(many.split('Don’t open the enrollment pull request').length - 1).toBe(1);
  });

  it('has its docs on https', () => {
    expect(item.docs.length).toBeGreaterThan(0);
    for (const d of item.docs) expect(d.url).toMatch(/^https:\/\//);
  });
});

describe('the dependabot.yml template (deps-update-automation)', () => {
  const item = guide.items.find((i: { id: string }) => i.id === 'deps-update-automation');
  /** A report on octo/demo whose scan counted this many workflows, or didn't count them. */
  const scanned = (workflowCount?: number) => ({
    repo: 'octo/demo',
    meta: { default_branch: 'main', ecosystems: ['npm'], workflow_count: workflowCount },
  });
  const updates = (text: string) =>
    YAML.parse(text).updates.map((u: Record<string, unknown>) => u['package-ecosystem']);
  const filled = (report: unknown) => sg.fill(item.new_file.template, sg.ctxFromReport(report));

  it('updates GitHub Actions only where the scan found workflows: Dependabot calls the entry an error without', () => {
    expect(updates(filled(scanned(2)))).toEqual(['github-actions', 'npm']);
    expect(updates(filled(scanned(0)))).toEqual(['npm']);
    // The prefilled "Create .github/dependabot.yml" link carries the same file.
    const url = new URL(sg.newFileUrl(item, sg.ctxFromReport(scanned(0)))!);
    expect(url.searchParams.get('value')).toBe(filled(scanned(0)));
  });

  it('keeps the entry when nothing has counted the workflows', () => {
    expect(updates(filled(null))).toEqual(['github-actions']);
    expect(updates(filled(scanned()))).toEqual(['github-actions', 'npm']);
  });

  it("leaves other templates' github-actions entries alone", () => {
    const pins = guide.items.find((i: { id: string }) => i.id === 'ci-pin-actions');
    const snippet = pins.snippets.find((s: { code: string }) => s.code.includes('github-actions'));
    expect(sg.fill(snippet.code, sg.ctxFromReport(scanned(0)))).toBe(snippet.code);
  });
});

describe('the support programs item (people-support-programs, no scanner check)', () => {
  const item = guide.items.find((i: { id: string }) => i.id === 'people-support-programs');

  it('is a manual item with no AI prompt: nothing in the repo changes, and nobody checks who is in a program', () => {
    expect(item).toMatchObject({ title: 'Apply for free support programs', layer: 'manual', stage: 'people' });
    expect(sg.promptKind(item)).toBeNull();
    const status = sg.itemStatus(item, { repo: 'octo/demo', results: {} }, 'octo/demo');
    expect(status.status).toBe('manual');
  });

  it("links each program's official page", () => {
    expect(item.links.map((l: { url: string }) => new URL(l.url).hostname)).toEqual([
      'github.com',
      'claude.com',
      'developers.openai.com',
      'www.sovereign.tech',
    ]);
    const text = JSON.stringify(item);
    for (const name of [
      'Secure Open Source Fund',
      'Claude for Open Source',
      'Codex for Open Source',
      'Sovereign Tech Resilience',
    ]) {
      expect(text).toContain(name);
    }
  });

  it("keeps Anthropic's Claude for Open Source apart from its OSS Scanner check", () => {
    const claude = item.steps.find((s: string) => s.startsWith('Claude for Open Source'));
    expect(claude).toContain("separate from Anthropic's OSS Scanner");
    expect(guide.items.some((i: { id: string }) => i.id === 'sast-oss-scanner')).toBe(true);
  });
});
