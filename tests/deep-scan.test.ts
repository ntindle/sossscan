/**
 * Deep scan's trip to GitHub and back, through the page's own core.js: what the page saves before it sends someone to
 * sign in or install the app (the intent), and when it carries on with it after GitHub sends them back. No network
 * and no browser: the functions take their storage, and location and history are stubbed where they're read.
 */
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
// The page's browser module (allowJs lets TypeScript read it; it isn't type-checked).
import * as core from '../public/shared/core.js';

// TypeScript guesses the types of core.js's parameters from their defaults (an item of null, options with only `now`, a
// browser Storage), so its functions are called untyped here.
const sg: any = core;

const MIN = 60_000;
const NOW = Date.parse('2026-11-11T12:00:00Z');
const intent = (o: Record<string, unknown>) => JSON.stringify(o);
const deep = (at = NOW - MIN, repo = 'octo/demo') => intent({ repo, item: null, at });

/** A sessionStorage stand-in. */
function memory(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init));
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    has: (k: string) => m.has(k),
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('a saved intent (readIntent)', () => {
  it('reads back what saveIntent wrote', () => {
    const store = memory();
    sg.saveIntent('octo/demo', 'ci-pin-actions', { store, now: NOW });
    expect(JSON.parse(store.getItem(sg.INTENT_KEY)!)).toEqual({ repo: 'octo/demo', item: 'ci-pin-actions', at: NOW });
    expect(sg.readIntent(store.getItem(sg.INTENT_KEY), NOW)).toEqual({
      repo: 'octo/demo',
      item: 'ci-pin-actions',
      at: NOW,
    });
    sg.saveIntent('octo/demo', null, { store, now: NOW });
    expect(sg.readIntent(store.getItem(sg.INTENT_KEY), NOW)).toEqual({ repo: 'octo/demo', item: null, at: NOW });
  });

  it('lasts 15 minutes', () => {
    expect(sg.INTENT_TTL).toBe(15 * MIN);
    expect(sg.readIntent(deep(NOW - 15 * MIN + 1), NOW)).not.toBeNull();
    expect(sg.readIntent(deep(NOW - 15 * MIN), NOW)).toBeNull();
    expect(sg.readIntent(deep(NOW - 60 * MIN), NOW)).toBeNull();
    expect(sg.readIntent(deep(NOW + MIN), NOW)).toBeNull(); // from the future: the clock moved, so don't trust it
  });

  it('checks the repository with parseRepoInput, and the check id', () => {
    expect(sg.readIntent(intent({ repo: 'https://github.com/octo/demo', at: NOW }), NOW)).toEqual({
      repo: 'octo/demo',
      item: null,
      at: NOW,
    });
    for (const repo of [
      '',
      'octo',
      'octo/..',
      '../../etc/passwd',
      'octo/demo extra',
      'javascript:alert(1)//a/b',
      42,
      null,
    ]) {
      expect(sg.readIntent(intent({ repo, at: NOW }), NOW), String(repo)).toBeNull();
    }
    for (const item of ['', 'CI-PIN', 'ci pin', '../x', 'x'.repeat(65), '<img>', 7, {}]) {
      expect(sg.readIntent(intent({ repo: 'octo/demo', item, at: NOW }), NOW), JSON.stringify(item)).toBeNull();
    }
  });

  it('ignores anything that is not one', () => {
    for (const raw of [
      null,
      '',
      'not json',
      '"octo/demo"',
      '[]',
      '{}',
      intent({ repo: 'octo/demo' }),
      intent({ repo: 'octo/demo', at: 'now' }),
    ]) {
      expect(sg.readIntent(raw, NOW), String(raw)).toBeNull();
    }
  });
});

describe('carrying on after GitHub sends someone back (resumeIntent)', () => {
  it('carries on after a sign-in or an install that went well', () => {
    for (const app of ['signed-in', 'installed']) {
      expect(sg.resumeIntent(deep(), { app, repo: 'octo/demo', now: NOW })).toEqual({
        repo: 'octo/demo',
        item: null,
        at: NOW - MIN,
      });
    }
  });

  it('never carries on without ?app=, as when someone comes back with the Back button', () => {
    for (const app of [null, undefined, ''])
      expect(sg.resumeIntent(deep(), { app, repo: 'octo/demo', now: NOW })).toBeNull();
  });

  it('drops it when the sign-in was cancelled or failed, or after signing out', () => {
    for (const app of ['signin-cancelled', 'signin-failed', 'signin-expired', 'signed-out', 'something-else']) {
      expect(sg.resumeIntent(deep(), { app, repo: 'octo/demo', now: NOW }), app).toBeNull();
    }
  });

  it('only for the repository the page comes back to', () => {
    expect(sg.resumeIntent(deep(), { app: 'signed-in', repo: 'Octo/Demo', now: NOW })).not.toBeNull();
    expect(sg.resumeIntent(deep(), { app: 'signed-in', repo: 'octo/other', now: NOW })).toBeNull();
    expect(sg.resumeIntent(deep(), { app: 'signed-in', repo: '', now: NOW })).toBeNull();
  });

  it('not once it is 15 minutes old', () => {
    expect(sg.resumeIntent(deep(NOW - 16 * MIN), { app: 'installed', repo: 'octo/demo', now: NOW })).toBeNull();
  });

  it('keeps the check, so the page can open its fix again', () => {
    const raw = intent({ repo: 'octo/demo', item: 'secrets-push-protection', at: NOW - MIN });
    expect(sg.resumeIntent(raw, { app: 'installed', repo: 'octo/demo', now: NOW })).toMatchObject({
      item: 'secrets-push-protection',
    });
  });
});

describe('taking it when the page loads (takeIntent)', () => {
  it('carries on once: the page takes it out of storage', () => {
    const store = memory({ [sg.INTENT_KEY]: deep() });
    expect(sg.takeIntent({ app: 'signed-in', repo: 'octo/demo', store, now: NOW })).toMatchObject({
      repo: 'octo/demo',
    });
    expect(store.has(sg.INTENT_KEY)).toBe(false);
    expect(sg.takeIntent({ app: 'signed-in', repo: 'octo/demo', store, now: NOW })).toBeNull();
  });

  it('deletes it on every other load too: used, cancelled, stale or for another repository', () => {
    const cases: [string, Record<string, unknown>][] = [
      [deep(), { app: null }], // the Back button, or any load without ?app=
      [deep(), { app: 'signin-cancelled' }],
      [deep(NOW - 20 * MIN), { app: 'signed-in' }],
      [deep(NOW - MIN, 'someone/else'), { app: 'installed' }],
      ['garbage', { app: 'signed-in' }],
    ];
    for (const [raw, opts] of cases) {
      const store = memory({ [sg.INTENT_KEY]: raw });
      expect(sg.takeIntent({ repo: 'octo/demo', store, now: NOW, ...opts }), raw).toBeNull();
      expect(store.has(sg.INTENT_KEY), raw).toBe(false);
    }
  });

  it('works with no storage at all (blocked)', () => {
    expect(sg.takeIntent({ app: 'signed-in', repo: 'octo/demo', store: null, now: NOW })).toBeNull();
    expect(() => sg.saveIntent('octo/demo', null, { store: null })).not.toThrow();
  });
});

describe('the address to come back to (backTo) and the notice (takeAppNotice)', () => {
  function at(url: string) {
    const u = new URL(url, 'https://site.invalid');
    const replaced: string[] = [];
    vi.stubGlobal('location', u);
    vi.stubGlobal('history', {
      state: null,
      replaceState: (_s: unknown, _t: string, next: string) => replaced.push(next),
    });
    return replaced;
  }

  it('names the repository and keeps the check that is open, and nothing else', () => {
    at('/?app=signin-failed#hop=repo&fix=secrets-push-protection');
    expect(sg.backTo('octo/demo')).toBe('/?repo=octo%2Fdemo#hop=repo&fix=secrets-push-protection');
    at(`/?repo=other/one&utm_source=${'x'.repeat(400)}`);
    expect(sg.backTo('octo/demo')).toBe('/?repo=octo%2Fdemo');
    expect(sg.app.loginUrl(sg.backTo('octo/demo'))).toBe('/app/login?next=%2F%3Frepo%3Docto%252Fdemo');
  });

  it('stays within the 300 characters /app/login takes, for the longest repository and check', () => {
    at(`/#hop=disclosure&fix=${'a'.repeat(64)}`);
    const next = sg.backTo(`${'o'.repeat(39)}/${'r'.repeat(100)}`);
    expect(next.length).toBeLessThanOrEqual(300);
    expect(readFileSync(new URL('../app/app/login/route.ts', import.meta.url), 'utf8')).toContain(
      "'next', { max: 300 }",
    );
  });

  it("says how GitHub's round trip went, and takes ?app= out of the address", () => {
    const replaced = at('/?repo=octo%2Fdemo&app=signed-in#hop=ci');
    expect(sg.takeAppNotice()).toEqual({ key: 'signed-in', text: 'You’re signed in with GitHub.', error: false });
    expect(replaced).toEqual(['/?repo=octo%2Fdemo#hop=ci']);
    at('/?app=signin-failed');
    expect(sg.takeAppNotice()).toMatchObject({ key: 'signin-failed', error: true });
    at('/');
    expect(sg.takeAppNotice()).toBeNull();
  });

  it('has no words for a value it does not know, even one that names a property of every object', () => {
    for (const key of ['nonsense', 'constructor', '__proto__', 'toString']) {
      at(`/?app=${key}`);
      expect(sg.takeAppNotice(), key).toEqual({ key, text: null, error: false });
    }
  });
});

describe('names', () => {
  it('calls the app layer Deep scan, and sends admin-only checks to it', () => {
    expect(sg.LAYER_LABEL.app).toBe('Deep scan');
    expect(sg.CHECKED_BY.private).toBe('Deep scan or private scan');
    expect(sg.CHECKED_BY.public).toBe('Public scan');
  });

  it('starts the home page with "Scan privately" closed, where "Three ways to scan" was', () => {
    const index = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
    expect(index).toContain('<details class="private" id="private"><summary>Scan privately</summary></details>');
    expect(index).not.toMatch(/Three ways to scan/i);
  });
});
