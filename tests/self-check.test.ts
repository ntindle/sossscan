/**
 * Self-checks on the page, through its own core.js: the "Check it yourself" block's contents, the mark and when a
 * check that repeats comes due again, and where such a check stands on the map. No browser: localStorage is a
 * stand-in, and the dates are fixed.
 */
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
// The page's browser module (allowJs lets TypeScript read it; it isn't type-checked).
import * as core from '../public/shared/core.js';

// TypeScript guesses core.js's parameter types from their defaults, so its functions are called untyped here.
const sg: any = core;
const guide = JSON.parse(readFileSync(new URL('../public/data/guide.json', import.meta.url), 'utf8'));
const byId = (id: string) => guide.items.find((i: { id: string }) => i.id === id);
const REPO = 'octo/demo';

/** A localStorage stand-in. */
function memory() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
  };
}

/** Marks a check done, or not, in the stand-in, as of a date. */
function mark(id: string, done: boolean, at: string) {
  const key = `sg:progress:${REPO}`;
  const all = JSON.parse(localStorage.getItem(key) || '{}');
  all[id] = { ...(all[id] || {}), done, at };
  localStorage.setItem(key, JSON.stringify(all));
}

const report = (results: Record<string, unknown> = {}) => ({ repo: REPO, layer: 'public', meta: {}, results });
const at = (iso: string) => new Date(iso).getTime();

beforeEach(() => {
  vi.stubGlobal('localStorage', memory());
  vi.stubGlobal('document', { dispatchEvent: () => true });
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('when a self-check that repeats comes due again', () => {
  const drill = byId('plan-irp-exercise'); // every 12 months
  const review = byId('repo-settings-review'); // every 6 months
  const training = byId('people-share-learnings'); // no cadence

  it('moves by calendar months, and stays in a short month', () => {
    const plus = (iso: string, n: number) => {
      const d = sg.addMonths(new Date(iso), n);
      return [d.getFullYear(), d.getMonth() + 1, d.getDate()];
    };
    expect(plus('2026-03-10T12:00:00', 12)).toEqual([2027, 3, 10]);
    expect(plus('2026-08-31T12:00:00', 6)).toEqual([2027, 2, 28]);
    expect(plus('2027-08-31T12:00:00', 6)).toEqual([2028, 2, 29]);
    expect(plus('2026-01-31T12:00:00', 1)).toEqual([2026, 2, 28]);
    expect(plus('2026-11-12T12:00:00', 6)).toEqual([2027, 5, 12]);
  });

  it('is done, with the date it was done and the date it is due again', () => {
    mark(drill.id, true, '2026-03-10T12:00:00Z');
    const now = at('2026-11-12T12:00:00Z');
    const st = sg.itemStatus(drill, report(), REPO, now);
    expect([st.status, st.source]).toEqual(['done', 'self']);
    const view = sg.selfCheckView(drill, report(), REPO, now);
    expect(view.mark).toMatchObject({ done: true, overdue: false });
    const due = sg.addMonths(new Date('2026-03-10T12:00:00Z'), 12);
    expect(view.mark.due.getTime()).toBe(due.getTime());
    expect(view.when).toBe(`Done on ${sg.dateText(new Date('2026-03-10T12:00:00Z'))}, due again ${sg.dateText(due)}.`);
  });

  it('is open again once the due date passes, and says when it was done', () => {
    mark(review.id, true, '2026-03-10T12:00:00Z');
    const done = new Date('2026-03-10T12:00:00Z');
    const due = sg.addMonths(done, 6);
    // The day before it's due, it's still done.
    expect(sg.itemStatus(review, report(), REPO, due.getTime() - 1).status).toBe('done');
    for (const now of [due.getTime(), at('2027-11-12T12:00:00Z')]) {
      const st = sg.itemStatus(review, report(), REPO, now);
      expect(st).toMatchObject({ status: 'manual', source: 'self', due: true, layer: 'manual' });
      expect(st.summary).toBe(`Done on ${sg.dateText(done)}. It’s due again.`);
      const view = sg.selfCheckView(review, report(), REPO, now);
      // The box isn't ticked: ticking it marks it done again, today.
      expect(view.mark).toMatchObject({ done: false, overdue: true });
      expect(view.when).toBe(st.summary);
    }
    // A pass from the scan still wins: the scan saw a review closed in the last 6 months.
    const passed = report({
      [review.id]: { status: 'pass', summary: 'An issue labeled settings-review was closed', evidence: [] },
    });
    expect(sg.itemStatus(review, passed, REPO, at('2027-11-12T12:00:00Z')).status).toBe('pass');
  });

  it("never comes due without a cadence, and says how often one repeats before it's marked", () => {
    mark(training.id, true, '2020-01-01T12:00:00Z');
    expect(training.recurs_months).toBeNull();
    expect(sg.itemStatus(training, report(), REPO, at('2036-01-01T12:00:00Z')).status).toBe('done');
    expect(sg.selfCheckView(training, report(), REPO).when).toBe(
      `Done on ${sg.dateText(new Date('2020-01-01T12:00:00Z'))}.`,
    );
    // Not marked: a check that repeats says how often, and one that doesn't says nothing.
    expect(sg.selfCheckView(review, report(), REPO).when).toBe('Repeats every 6 months.');
    expect(sg.selfCheckView(drill, report(), REPO).when).toBe('Repeats every year.');
    expect(sg.selfCheckView(byId('plan-postmortem'), report(), REPO).when).toBe('');
    // Unticked, it's open.
    mark(review.id, false, '2026-11-12T12:00:00Z');
    expect(sg.itemStatus(review, report(), REPO).status).toBe('manual');
    // A mark without a readable date stays done.
    expect(sg.doneState(review, { done: true }, at('2036-01-01T12:00:00Z'))).toEqual({
      done: true,
      at: null,
      due: null,
      overdue: false,
    });
  });

  it('counts the time from when it was marked, not from a pull request the app opened later', () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-03-10T12:00:00Z'));
      sg.store.set(REPO, review.id, { done: true });
      vi.setSystemTime(new Date('2026-09-01T12:00:00Z'));
      sg.store.set(REPO, review.id, { pr: { url: 'https://github.com/octo/demo/pull/4', number: 4 } });
      expect(sg.store.get(REPO, review.id)).toEqual({
        done: true,
        at: '2026-03-10T12:00:00.000Z',
        pr: { url: 'https://github.com/octo/demo/pull/4', number: 4 },
      });
      vi.setSystemTime(new Date('2026-09-02T12:00:00Z'));
      sg.store.set(REPO, review.id, { done: false });
      expect(sg.store.get(REPO, review.id).at).toBe('2026-09-02T12:00:00.000Z');
    } finally {
      vi.useRealTimers();
    }
  });

  it('stands on the map like an open self-check: counted open, still to check, never "fix this first"', () => {
    mark(review.id, true, '2025-01-01T12:00:00Z'); // due again since July 2025
    mark(drill.id, true, '2026-10-01T12:00:00Z'); // done until October 2027
    const rep = report();
    const ctx = sg.ctxFromReport(rep);
    expect(sg.checkRow(review, rep, ctx, 7).bucket).toBe('open');
    expect(sg.checkRow(drill, rep, ctx, 7).bucket).toBe('done');
    expect(sg.progress([review, drill], rep, REPO)).toMatchObject({ pass: 1, open: 1, total: 2 });
    // "Fix this first" and "Prompt to fix" take only what's missing or partly done.
    const rows = [review, drill].map((i) => sg.checkRow(i, rep, ctx, 7));
    expect(rows.filter((r) => sg.NEEDS_WORK.has(r.bucket))).toEqual([]);
    expect(sg.promptChoices(rows)).toBeNull();
  });
});

describe('what the "Check it yourself" block says the scan saw', () => {
  const triage = byId('disc-triage-sla'); // the scan can sometimes settle it
  const input = byId('code-untrusted-input'); // the scan never reads it

  it("shows the scan's own result when there is one, with its links", () => {
    const evidence = [{ label: 'SECURITY.md', url: 'https://github.com/fastify/fastify/blob/main/SECURITY.md' }];
    const said = 'Looks done: SECURITY.md says "We will acknowledge your report within 5 days."';
    const rep = report({ [triage.id]: { status: 'info', summary: said, evidence, layer: 'public' } });
    const view = sg.selfCheckView(triage, rep, REPO);
    expect(view.saw).toEqual({ kind: 'scan', status: 'info', text: said, evidence });
    expect([view.check, view.habit]).toEqual([triage.check, triage.habit]);
    // A warning and a refused lookup show the same way.
    const warn = report({
      [triage.id]: { status: 'warn', summary: '1 private vulnerability report has waited 20 days', evidence: [] },
    });
    expect(sg.selfCheckView(triage, warn, REPO).saw.kind).toBe('scan');
  });

  it('says what the scan looks for and didn’t find, for a check it can sometimes settle', () => {
    const view = sg.selfCheckView(triage, report(), REPO);
    expect(view.saw).toEqual({ kind: 'none', text: 'The scan found no response time in SECURITY.md.', evidence: [] });
    // Before any scan there's nothing it saw.
    expect(sg.selfCheckView(triage, null, REPO).saw).toBeNull();
  });

  it("says the scan doesn't check one it never reads, with a scan or without", () => {
    for (const rep of [report(), null]) {
      expect(sg.selfCheckView(input, rep, REPO).saw).toEqual({
        kind: 'unseen',
        text: 'The scan doesn’t check this.',
        evidence: [],
      });
    }
  });

  it('is there only for a self-check the scan has not passed or found not applicable', () => {
    expect(sg.selfCheckView(byId('disc-security-md'), report(), REPO)).toBeNull();
    const memory = byId('code-memory-safety');
    expect(
      sg.selfCheckView(memory, report({ [memory.id]: { status: 'na', summary: 'No C', evidence: [] } }), REPO),
    ).toBeNull();
    expect(
      sg.selfCheckView(triage, report({ [triage.id]: { status: 'pass', summary: 'x', evidence: [] } }), REPO),
    ).toBeNull();
    // Marked done, the block stays, so the mark can be undone and the date read.
    mark(triage.id, true, '2026-11-12T12:00:00Z');
    expect(sg.selfCheckView(triage, report(), REPO).mark.done).toBe(true);
  });
});

describe("the copy's links and code", () => {
  it('fills in a link for the repository, and keeps it as text until the page knows which one', () => {
    const text = byId('disc-triage-sla').check;
    const ctx = sg.ctxFromReport(report());
    const parts = sg.richParts(text, ctx);
    expect(parts.find((p: { url?: string }) => p.url)).toEqual({
      text: 'reports in triage',
      url: 'https://github.com/octo/demo/security/advisories?state=triage',
    });
    expect(parts.map((p: { text?: string }) => p.text).join('')).toBe(text.replace(/\[([^\]]+)\]\([^)]+\)/, '$1'));
    const before = sg.richParts(text, sg.ctxFromReport(null));
    expect(before.some((p: { url?: string }) => p.url)).toBe(false);
    // A link with nothing to fill works before a scan too, and code is code.
    expect(sg.richParts(byId('acct-phishing-resistant-2fa').check, {})[1]).toEqual({
      text: 'Password and authentication',
      url: 'https://github.com/settings/security',
    });
    expect(sg.richParts('Run `npm outdated`: done.', {})).toEqual([
      { text: 'Run ' },
      { code: 'npm outdated' },
      { text: ': done.' },
    ]);
  });
});
