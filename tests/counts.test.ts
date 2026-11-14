/**
 * Counting visits (lib/counts.ts, app/api/count, public/shared/count.js and visit.js), checked against the privacy
 * page's "Counting visits":
 * - what reaches PostHog: the event's name, its own details, a new random ID, and the flags that keep PostHog from
 *   making a person or looking up a location; and what never does: the IP address, user agent, cookies, repository;
 * - when nothing is counted: no project token, Do Not Track, Global Privacy Control, crawlers;
 * - /api/count: only the page's events, only their own details, its header check, size cap and rate limit;
 * - the page's module: when it may count, and how it tells first visits apart without an ID;
 * - that the privacy page names every event the code counts, and the code counts each one somewhere.
 */
import fs from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { count, DEFAULT_HOST, fromBrowser, isCrawler, optedOut, pageEvent } from '@/lib/counts.ts';
import { HttpError } from '@/lib/http.ts';
import { pageMarkdown } from '@/lib/pages.ts';
// The page's browser modules (allowJs lets TypeScript read them; they aren't type-checked).
import * as core from '../public/shared/core.js';
import * as countJs from '../public/shared/count.js';
import { Browser, H, useTestEnv } from './helpers.ts';
import { serve } from './site.ts';

vi.mock('@/lib/public-scan.ts', async (original) => ({
  ...(await original<typeof import('@/lib/public-scan.ts')>()),
  scanOr404: async (repo: string) => ({ repo, results: { x: {} }, cached: false }),
}));

const env = useTestEnv();
const page: any = countJs;
const sg: any = core;
const ROOT = process.cwd();
const read = (file: string) => fs.readFileSync(path.join(ROOT, file), 'utf8');
const TOKEN = 'phc_testtoken123';

type Json = Record<string, any>;
/** What PostHog received: each request's address and body. */
const sent: Json[] = [];
let posthogDown = false;

beforeEach(() => {
  sent.length = 0;
  posthogDown = false;
  const github = env.world().fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (/^https:\/\/(us|eu)\.i\.posthog\.com\//.test(url)) {
      if (posthogDown) throw new TypeError('fetch failed');
      sent.push({ url, ...JSON.parse(String(init!.body)) });
      return Response.json({ status: 'Ok' });
    }
    return github(input, init);
  });
});

/** Counting on, with the test token. */
function turnOn(): void {
  process.env.POSTHOG_KEY = TOKEN;
}

/** Wait for the counts a response has sent after it (they don't hold the response up). */
async function counted(n: number): Promise<Json[]> {
  await vi.waitFor(() => expect(sent).toHaveLength(n));
  return sent;
}

/** Give a count that shouldn't happen the time it would have taken. */
async function nothingCounted(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 25));
  expect(sent).toEqual([]);
}

/** A request with everything a browser says about the person behind it. */
const IDENTIFYING = {
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15',
  'x-vercel-forwarded-for': '203.0.113.7',
  'x-forwarded-for': '203.0.113.7',
  cookie: '__Host-sosf_session=sealed-secret-value',
  referer: 'https://sossscan.ntindle.com/?repo=octo/secret-plans',
};

const request = (headers: Record<string, string> = {}) =>
  new Request('https://sossscan.ntindle.com/api/scan', { headers });

// ------------------------------------------------------------------------------------------- the server
describe('count', () => {
  it('sends nothing without a project token', async () => {
    expect(count(request(), 'deep_scan', {})).toBeNull();
    process.env.POSTHOG_KEY = '   ';
    expect(count(request(), 'deep_scan', {})).toBeNull();
    await nothingCounted();
  });

  it('refuses a personal API key, and a host that is not https', async () => {
    process.env.POSTHOG_KEY = 'phx_personalsecret';
    expect(count(request(), 'deep_scan', {})).toBeNull();
    turnOn();
    process.env.POSTHOG_HOST = 'http://us.i.posthog.com';
    expect(count(request(), 'deep_scan', {})).toBeNull();
    await nothingCounted();
  });

  it("sends the event's name and its own details, a new random ID, no person and no location", async () => {
    turnOn();
    await count(request(IDENTIFYING), 'api_scan', { refresh: true });
    await count(request(IDENTIFYING), 'api_scan', { refresh: false });
    const [first, second] = sent;
    expect(first.url).toBe(`${DEFAULT_HOST}/i/v0/e/`);
    expect(Object.keys(first).sort()).toEqual(['api_key', 'distinct_id', 'event', 'properties', 'timestamp', 'url']);
    expect(first).toMatchObject({ api_key: TOKEN, event: 'api_scan' });
    expect(first.properties).toEqual({
      refresh: true,
      $process_person_profile: false,
      $geoip_disable: true,
      $lib: 'sossscan',
    });
    expect(first.distinct_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(second.distinct_id).not.toBe(first.distinct_id); // nothing links one count to the next
    // Nothing from the request goes along: not the address, the browser, the cookie or the page it came from.
    const everything = JSON.stringify(sent);
    for (const part of ['203.0.113.7', 'Safari', 'sealed-secret-value', 'secret-plans', 'Macintosh']) {
      expect(everything).not.toContain(part);
    }
  });

  it('sends to the host the operator names', async () => {
    turnOn();
    process.env.POSTHOG_HOST = 'https://eu.i.posthog.com/';
    await count(request(), 'signed_in', {});
    expect(sent.map((s) => s.url)).toEqual(['https://eu.i.posthog.com/i/v0/e/']);
  });

  it('counts nothing when the browser sends Do Not Track or Global Privacy Control', async () => {
    turnOn();
    expect(count(request({ dnt: '1' }), 'deep_scan', {})).toBeNull();
    expect(count(request({ 'sec-gpc': '1' }), 'deep_scan', {})).toBeNull();
    expect(optedOut(new Headers({ dnt: '0' }))).toBe(false);
    await nothingCounted();
  });

  it.each([
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
    'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; moto g power (2022)) AppleWebKit/537.36 Chrome-Lighthouse',
    'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
  ])('skips the crawler %s', (ua) => {
    expect(isCrawler(ua)).toBe(true);
  });

  it.each([
    'curl/8.5.0',
    'python-requests/2.32.3',
    'node',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; CUBOT X30) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36',
  ])('counts a program or a person: %s', (ua) => {
    expect(isCrawler(ua)).toBe(false);
  });

  it('gives up quietly when PostHog does not answer', async () => {
    turnOn();
    posthogDown = true;
    await expect(count(request(), 'deep_scan', {})).resolves.toBeUndefined();
  });

  it('tells a browser from a program by Sec-Fetch-Site', () => {
    expect(fromBrowser(new Headers({ 'sec-fetch-site': 'same-origin' }))).toBe(true);
    expect(fromBrowser(new Headers({ 'user-agent': 'curl/8.5.0' }))).toBe(false);
  });
});

// -------------------------------------------------------------------------------------- what's counted
describe('what the server counts', () => {
  it("counts a program's scan through the API, and leaves the page's own to the page", async () => {
    turnOn();
    const program = new Browser({ 'user-agent': 'python-requests/2.32.3' });
    expect((await program.get('/api/scan/octo/demo')).status).toBe(200);
    expect((await program.post('/api/scan', { repo: 'octo/demo', refresh: true }, {})).status).toBe(200);
    const [get, post] = await counted(2);
    expect([get.event, get.properties.refresh, post.event, post.properties.refresh]).toEqual([
      'api_scan',
      false,
      'api_scan',
      true,
    ]);
    // The page's fetch sends Sec-Fetch-Site; the page counts that scan itself (scan, from core.js).
    sent.length = 0;
    const browser = new Browser({ 'sec-fetch-site': 'same-origin' });
    expect((await browser.get('/api/scan/octo/demo')).status).toBe(200);
    await nothingCounted();
  });

  it('counts an MCP tool call by the tool, and nothing else about it', async () => {
    turnOn();
    const res = await serve('/mcp', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
        'user-agent': 'claude-code/2.0',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_checks' } }),
    });
    expect(res.status).toBe(200);
    const [call] = await counted(1);
    expect(call.event).toBe('mcp_tool_call');
    expect(call.properties).toMatchObject({ tool: 'list_checks' });
    expect(Object.keys(call.properties).sort()).toEqual(['$geoip_disable', '$lib', '$process_person_profile', 'tool']);
    expect(JSON.stringify(call)).not.toContain('claude-code');
  });

  it('counts an installation of the app', async () => {
    turnOn();
    const res = await new Browser({ 'sec-fetch-site': 'cross-site' }).get('/app/installed');
    expect(res.status).toBe(303);
    expect((await counted(1))[0].event).toBe('app_installed');
  });
});

// ---------------------------------------------------------------------------------------- /api/count
describe('/api/count', () => {
  const VISIT = {
    event: 'page_view',
    page: '/docs',
    referrer: 'news.ycombinator.com',
    new_day: true,
    new_week: false,
    new_month: false,
  };

  it('passes on what the page counts, and answers with nothing that anyone may keep', async () => {
    turnOn();
    const res = await new Browser(IDENTIFYING).post('/api/count', VISIT);
    expect([res.status, res.headers.get('cache-control'), await res.text()]).toEqual([204, 'no-store', '']);
    const [visit] = await counted(1);
    expect(visit.event).toBe('page_view');
    expect(visit.properties).toEqual({
      page: '/docs',
      referrer: 'news.ycombinator.com',
      new_day: true,
      new_week: false,
      new_month: false,
      $process_person_profile: false,
      $geoip_disable: true,
      $lib: 'sossscan',
    });
  });

  it('answers the same when counting is off, or the browser opted out, and passes nothing on', async () => {
    expect((await new Browser().post('/api/count', VISIT)).status).toBe(204);
    turnOn();
    expect((await new Browser().post('/api/count', VISIT, { ...H, dnt: '1' })).status).toBe(204);
    expect((await new Browser().post('/api/count', VISIT, { ...H, 'sec-gpc': '1' })).status).toBe(204);
    await nothingCounted();
  });

  it("takes events only from the page's own script", async () => {
    turnOn();
    const res = await new Browser().post('/api/count', VISIT, {});
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe('missing_header');
    await nothingCounted();
  });

  it('refuses an event the page does not count, and one without its details', async () => {
    turnOn();
    for (const body of [{ event: 'purchase' }, { event: 'page_view', page: '/' }, { event: 'scan' }, ['page_view']]) {
      const res = await new Browser().post('/api/count', body);
      expect(res.status, JSON.stringify(body)).toBe(422);
      expect((await res.json()).error.code).toBe('invalid_request');
    }
    await nothingCounted();
  });

  it('refuses a body over 2 KiB', async () => {
    turnOn();
    const res = await new Browser().post('/api/count', { ...VISIT, padding: 'x'.repeat(2100) });
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toBe('The request body is over 2 KiB.');
    await nothingCounted();
  });

  it('takes 60 counts a minute from one address', async () => {
    const c = new Browser();
    const codes = [];
    for (let i = 0; i < 61; i++) codes.push((await c.post('/api/count', { event: 'prompt_copied' })).status);
    expect(codes.filter((s) => s === 204)).toHaveLength(60);
    expect(codes.at(-1)).toBe(429);
  });
});

describe('pageEvent', () => {
  it('keeps only the details each event may carry', () => {
    expect(
      pageEvent({
        event: 'page_view',
        page: '/about',
        referrer: 'Example.org',
        new_day: false,
        new_week: false,
        new_month: true,
        repo: 'octo/demo',
        ip: '203.0.113.7',
      }),
    ).toEqual([
      'page_view',
      { page: '/about', referrer: 'example.org', new_day: false, new_week: false, new_month: true },
    ]);
    expect(pageEvent({ event: 'scan', rescan: true, repo: 'octo/demo' })).toEqual(['scan', { rescan: true }]);
    expect(pageEvent({ event: 'report_loaded', report: { repo: 'octo/demo' } })).toEqual(['report_loaded', {}]);
  });

  it('counts any address that is not one of the pages as "other", and /index.html as the home page', () => {
    const flags = { new_day: true, new_week: true, new_month: true };
    const pageOf = (p: unknown) => (pageEvent({ event: 'page_view', page: p, ...flags })[1] as { page: string }).page;
    expect(['/', '/docs/mcp', '/index.html', '/octo/demo', '/privacy/', 42].map(pageOf)).toEqual([
      '/',
      '/docs/mcp',
      '/',
      'other',
      'other',
      'other',
    ]);
  });

  it("keeps a referrer only as another site's host name", () => {
    const flags = { new_day: true, new_week: true, new_month: true };
    const ref = (r: unknown) =>
      (pageEvent({ event: 'page_view', page: '/', referrer: r, ...flags })[1] as Json).referrer;
    process.env.SITE_BASE_URL = 'https://sossscan.ntindle.com';
    expect(ref('github.com')).toBe('github.com');
    expect(ref('sossscan.ntindle.com')).toBeNull();
    expect(ref('https://github.com/octo/demo')).toBeNull();
    expect(ref('a b')).toBeNull();
    expect(ref(null)).toBeNull();
  });

  it('throws an HttpError for anything else', () => {
    expect(() => pageEvent({ event: 'scan', rescan: 'yes' })).toThrow(HttpError);
  });
});

// ------------------------------------------------------------------------------------ the page's module
describe("the page's count.js", () => {
  const browser = { document: {} };

  it('counts only in a browser whose person has not opted out, and not in one a program drives', () => {
    expect(page.mayCount({}, undefined)).toBe(false); // no window: the server, or these tests
    expect(page.mayCount({}, browser)).toBe(true);
    expect(page.mayCount({ doNotTrack: '1' }, browser)).toBe(false);
    expect(page.mayCount({ msDoNotTrack: '1' }, browser)).toBe(false);
    expect(page.mayCount({}, { ...browser, doNotTrack: '1' })).toBe(false);
    expect(page.mayCount({ globalPrivacyControl: true }, browser)).toBe(false);
    expect(page.mayCount({ webdriver: true }, browser)).toBe(false);
    expect(page.mayCount({ doNotTrack: '0', globalPrivacyControl: false }, browser)).toBe(true);
  });

  it.each([
    [new Date(2026, 10, 13), '2026-11-13', '2026-W46', '2026-11'],
    [new Date(2026, 0, 1), '2026-01-01', '2026-W01', '2026-01'],
    [new Date(2027, 0, 1), '2027-01-01', '2026-W53', '2027-01'], // a Friday: the last week of 2026
    [new Date(2024, 11, 30), '2024-12-30', '2025-W01', '2024-12'], // a Monday: the first week of 2025
    [new Date(2023, 0, 1), '2023-01-01', '2022-W52', '2023-01'], // a Sunday
  ])('dates %s as day %s, ISO week %s and month %s', (now, day, week, month) => {
    expect(page.calendar(now)).toEqual({ day, week, month });
  });

  it('tells first visits of the day, week and month apart from what it kept last time', () => {
    const at = (d: number) => page.visitFlags(page.calendar(new Date(2026, 10, 13)), new Date(2026, 10, d)).flags;
    expect(page.visitFlags(null, new Date(2026, 10, 13)).flags).toEqual({
      new_day: true,
      new_week: true,
      new_month: true,
    });
    expect(page.visitFlags('garbage', new Date(2026, 10, 13)).flags).toEqual({
      new_day: true,
      new_week: true,
      new_month: true,
    });
    expect(at(13)).toEqual({ new_day: false, new_week: false, new_month: false }); // again the same day
    expect(at(15)).toEqual({ new_day: true, new_week: false, new_month: false }); // Sunday, the same week
    expect(at(16)).toEqual({ new_day: true, new_week: true, new_month: false }); // the next Monday
    expect(page.visitFlags(page.calendar(new Date(2026, 10, 30)), new Date(2026, 11, 1)).flags).toEqual({
      new_day: true,
      new_week: false,
      new_month: true,
    });
    expect(page.visitFlags(null, new Date(2026, 10, 13)).keep).toEqual(page.calendar(new Date(2026, 10, 13)));
  });

  it("keeps a referrer's host name, and only another site's", () => {
    expect(page.referrerHost('https://news.ycombinator.com/item?id=1', 'sossscan.ntindle.com')).toBe(
      'news.ycombinator.com',
    );
    expect(page.referrerHost('https://sossscan.ntindle.com/docs', 'sossscan.ntindle.com')).toBeNull();
    expect(page.referrerHost('', 'sossscan.ntindle.com')).toBeNull();
    expect(page.referrerHost('not a url', 'sossscan.ntindle.com')).toBeNull();
  });

  it('sends nothing where there is no page, as in these tests', async () => {
    page.count('scan', { rescan: false });
    page.countVisit();
    await nothingCounted();
  });

  it('is told by core.js what to count, with a page event, so core.js imports nothing', async () => {
    const heard: Event[] = [];
    vi.stubGlobal('document', { dispatchEvent: (e: Event) => heard.push(e) });
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => {}, removeItem: () => {} });
    vi.stubGlobal('fetch', async () => Response.json({ repo: 'octo/demo', layer: 'public', results: {} }));
    await sg.scanPublic('octo/demo');
    await sg.scanPublic('octo/demo', { refresh: true });
    expect(heard.map((e) => [e.type, (e as CustomEvent).detail])).toEqual([
      ['sg:count', { event: 'scan', details: { rescan: false } }],
      ['sg:count', { event: 'scan', details: { rescan: true } }],
    ]);
    expect(read('public/shared/visit.js')).toContain(
      "document.addEventListener('sg:count', (e) => count(e.detail.event, e.detail.details));",
    );
  });

  it('is loaded on every page, ahead of the home page script', () => {
    const index = read('public/index.html');
    expect(index.indexOf('<script type="module" src="/shared/visit.js">')).toBeGreaterThan(0);
    expect(index.indexOf('src="/shared/visit.js"')).toBeLessThan(index.indexOf('src="/pipeline/pipeline.js"'));
    expect(read('lib/pages.ts')).toContain('<script type="module" src="/shared/visit.js"></script>');
  });
});

// --------------------------------------------------------------------------------- the privacy page
describe('the privacy page', () => {
  const privacy = pageMarkdown('/privacy');
  /** Each event in lib/counts.ts, and what the privacy page calls it. */
  const NAMED: Record<string, string> = {
    page_view: 'a page opening',
    scan: 'a public scan it shows you',
    report_loaded: 'a CLI report you open in it',
    prompt_copied: 'a prompt for an AI coding agent you copy',
    api_scan: 'a scan that a program asks the API for',
    mcp_tool_call: "an MCP tool call with the tool's name",
    deep_scan: 'a deep scan',
    settings_fix: 'a settings fix with whether GitHub took it',
    fix_previewed: 'a pull request fix built for you to review',
    fix_pr_opened: 'and one opened',
    signed_in: 'a sign-in with GitHub',
    app_installed: 'an installation of the app',
  };

  /** The events lib/counts.ts declares in one of its types: ServerEvents or PageEvents. */
  function declared(type: 'ServerEvents' | 'PageEvents'): string[] {
    const body = new RegExp(`export type ${type} = \\{([\\s\\S]*?)\\n\\};`).exec(read('lib/counts.ts'))![1];
    return [...body.matchAll(/^ {2}(\w+): /gm)].map((m) => m[1]);
  }

  it('names every event the code counts', () => {
    expect([...declared('ServerEvents'), ...declared('PageEvents')].sort()).toEqual(Object.keys(NAMED).sort());
    for (const phrase of Object.values(NAMED)) expect(privacy).toContain(phrase);
  });

  it('describes each one as the code makes it', () => {
    const server = read('lib/counts.ts');
    const code = ['app', 'lib']
      .flatMap((dir) =>
        fs
          .readdirSync(path.join(ROOT, dir), { recursive: true, encoding: 'utf8' })
          .filter((f) => f.endsWith('.ts'))
          .map((f) => read(path.join(dir, f))),
      )
      .join('\n');
    const pageCode = read('public/shared/core.js') + read('public/shared/count.js');
    for (const event of declared('ServerEvents')) expect(code, event).toContain(`count(req, '${event}'`);
    for (const event of declared('PageEvents')) expect(pageCode, event).toMatch(new RegExp(`count(ed)?\\('${event}'`));
    // What the page says about the details, ID, region and opt-outs, beside the code that does it.
    expect(server).toContain('$process_person_profile: false, $geoip_disable: true');
    expect(server).toContain('distinct_id: randomUUID()');
    expect(privacy).toContain('each one gets a new random ID, and PostHog keeps no profile of anyone');
    expect(privacy).toContain('The site asks PostHog not to look up a location');
    expect(DEFAULT_HOST).toBe('https://us.i.posthog.com');
    expect(privacy).toContain('an analytics service in the US');
    expect(privacy).toContain('If your browser sends Do Not Track or Global Privacy Control, nothing is counted');
    expect(privacy).toContain('Your browser never talks to PostHog');
    expect(privacy).not.toContain('There are no analytics');
  });
});
