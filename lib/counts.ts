/**
 * Counting how the site is used, without knowing who uses it (the privacy page's "Counting visits" says the same for
 * visitors). A count is an event's name and a few coarse details. The server sends it to PostHog when the operator sets
 * POSTHOG_KEY, and only the server talks to PostHog: the page reports its events to /api/count, and the server passes
 * them on with its own.
 *
 * A count carries no IP address, user agent, cookie, repository or GitHub name, and nothing that links it to another
 * count: each gets a fresh random distinct_id, PostHog makes no person of it, and it asks PostHog not to look up a
 * location. First visits are told apart in the page (public/shared/count.js), which sends only yes or no. Do Not Track
 * and Global Privacy Control turn counting off, on the page and here, and crawlers aren't counted.
 */
import { randomUUID } from 'node:crypto';
import { after } from 'next/server';
import { siteUrl } from './env.ts';
import { HttpError } from './http.ts';
import { PAGES } from './pages.ts';

/** PostHog's US Cloud, where the site's counts go unless POSTHOG_HOST names another. */
export const DEFAULT_HOST = 'https://us.i.posthog.com';

/** A PostHog project token. A personal API key (phx_) is a secret and has no place here. */
const PROJECT_TOKEN = /^phc_[A-Za-z0-9]+$/;

/** What the server counts itself, and the details each count carries. */
export type ServerEvents = {
  /** A public scan through the API by a program (the page's own scans are counted by the page, as scan). */
  api_scan: { refresh: boolean };
  /** A tool call to the MCP server. */
  mcp_tool_call: { tool: string };
  deep_scan: Record<never, never>;
  /** A settings fix, and whether GitHub took it. */
  settings_fix: { ok: boolean };
  /** A pull request fix built for review, and whether an AI agent wrote it. */
  fix_previewed: { agent: boolean };
  fix_pr_opened: Record<never, never>;
  signed_in: Record<never, never>;
  app_installed: Record<never, never>;
};

/** What the page counts and reports to /api/count. */
export type PageEvents = {
  /** A page opened: which one, the other site it came from (its domain only), and whether it's a first visit. */
  page_view: { page: string; referrer: string | null; new_day: boolean; new_week: boolean; new_month: boolean };
  /** A public scan shown on the page, cached ones included, and whether it was a rescan. */
  scan: { rescan: boolean };
  /** A report from the CLI opened in the page. */
  report_loaded: Record<never, never>;
  /** A prompt for an AI coding agent copied. */
  prompt_copied: Record<never, never>;
};

export type Events = ServerEvents & PageEvents;
export type EventName = keyof Events;

/** The project token and where to send counts, or null when the operator didn't set a usable token. */
function settings(): { token: string; host: string } | null {
  const token = (process.env.POSTHOG_KEY || '').trim();
  if (!PROJECT_TOKEN.test(token)) return null;
  const host = (process.env.POSTHOG_HOST || DEFAULT_HOST).trim().replace(/\/+$/, '');
  return host.startsWith('https://') ? { token, host } : null;
}

/** Whether counting is on: there's a project token to send counts with. */
export function counting(): boolean {
  return settings() !== null;
}

/** The browser asked not to be tracked: Do Not Track or Global Privacy Control. */
export function optedOut(headers: Headers): boolean {
  return headers.get('dnt') === '1' || headers.get('sec-gpc') === '1';
}

/** Search engines, link previews and other automated visitors, by what they call themselves. */
const CRAWLER = /(?<!cu)bot\b|bot[/_-]|crawl|spider|slurp|headlesschrome|lighthouse|facebookexternalhit/i;

export function isCrawler(userAgent: string | null): boolean {
  return CRAWLER.test(userAgent || '');
}

/** A request a browser made. Browsers send Sec-Fetch-Site with every request, and programs don't. */
export function fromBrowser(headers: Headers): boolean {
  return headers.has('sec-fetch-site');
}

/** Send one count, and give up quietly: nothing waits on a count, and nothing retries one. */
async function send(cfg: { token: string; host: string }, event: string, details: object): Promise<void> {
  try {
    await fetch(`${cfg.host}/i/v0/e/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        api_key: cfg.token,
        event,
        distinct_id: randomUUID(),
        timestamp: new Date().toISOString(),
        properties: { ...details, $process_person_profile: false, $geoip_disable: true, $lib: 'sossscan' },
      }),
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    // PostHog didn't answer: the count is dropped.
  }
}

/**
 * Count an event for this request, unless counting is off, the browser opted out or a crawler sent it. The count goes
 * out after the response (next/server's after), so it never slows an answer down. Outside a request (the tests), it's
 * sent at once, and the promise says when it's done. Returns null when nothing is counted.
 */
export function count<E extends EventName>(req: Request, event: E, details: Events[E]): Promise<void> | null {
  const cfg = settings();
  if (!cfg || optedOut(req.headers) || isCrawler(req.headers.get('user-agent'))) return null;
  const task = () => send(cfg, event, details);
  try {
    after(task);
    return Promise.resolve();
  } catch {
    return task();
  }
}

// ---------------------------------------------------------------------------------------- the page's events
/** The pages a count may name. Any other address (a 404, say) is counted as "other". */
const PAGE_PATHS = new Set(['/', ...PAGES.map((p) => p.path)]);

/** A host name as a referrer gives it: letters, digits, dots and hyphens, at most 253 characters. */
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;

/** The other site a visitor came from, as its host name, or null for none, this site, or anything malformed. */
function referrerHost(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const host = value.toLowerCase();
  if (!HOST.test(host) || host === new URL(siteUrl()).hostname) return null;
  return host;
}

function badEvent(message: string): HttpError {
  return new HttpError(422, 'invalid_request', message, "Send one of the events the site's page counts.");
}

function flag(body: Record<string, unknown>, key: string): boolean {
  const value = body[key];
  if (typeof value !== 'boolean') throw badEvent(`${key} is missing, or isn't true or false.`);
  return value;
}

/**
 * One event from the page's report to /api/count, with only the details that event may carry: anything else in the
 * body is dropped, never passed on. A page that isn't one of the site's own is counted as "other".
 */
export function pageEvent(
  body: Record<string, unknown>,
): { [E in keyof PageEvents]: [E, PageEvents[E]] }[keyof PageEvents] {
  switch (body.event) {
    case 'page_view': {
      const asked = body.page === '/index.html' ? '/' : body.page;
      const page = typeof asked === 'string' && PAGE_PATHS.has(asked) ? asked : 'other';
      return [
        'page_view',
        {
          page,
          referrer: referrerHost(body.referrer),
          new_day: flag(body, 'new_day'),
          new_week: flag(body, 'new_week'),
          new_month: flag(body, 'new_month'),
        },
      ];
    }
    case 'scan':
      return ['scan', { rescan: flag(body, 'rescan') }];
    case 'report_loaded':
      return ['report_loaded', {}];
    case 'prompt_copied':
      return ['prompt_copied', {}];
    default:
      throw badEvent("The page doesn't count an event by that name.");
  }
}
