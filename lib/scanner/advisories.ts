// Reports, drills and coordinated disclosure (new in 0.5.2): what a repository's security advisories, its security
// policy and its incident response plan say about three self-checks, disc-triage-sla, plan-irp-exercise and
// disc-coordinated-disclosure. Each reports only on a sure sign, so a check without one stays for people to tick off.
//
// Unpublished advisories (private vulnerability reports, drafts and closed ones) are other people's private reports.
// The admin checks read them for counts and dates only: advisoryFacts reduces each list GitHub returns to those at
// once, so no title, description, reporter, identifier, severity or weakness of one can reach a result.
import { sentences } from './policy.ts';
import type { Policy } from './policy.ts';
import { finditer, isDict, re, search } from './py.ts';
import type { Evidence } from './types.ts';

export type Answer = [number, any, Record<string, string>];

const DAY = 86_400_000;

/**
 * A sentence to quote in a summary: on one line, without control or bidirectional formatting characters (it may be
 * printed in a terminal), and at most 200 characters.
 */
export function quoteOf(s: string): string {
  const t = s
    .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (t.length <= 200) return t;
  let cut = t.slice(0, 200);
  const space = cut.lastIndexOf(' ');
  if (space > 120) cut = cut.slice(0, space);
  else if (/[\ud800-\udbff]$/.test(cut)) cut = cut.slice(0, -1);
  return `${cut}…`;
}

// ------------------------------------------------------------------------------- response times (public)
/** A time to answer in: 48 hours, 3 business days, 1-2 weeks, a week, 72h. */
export const RESPONSE_TIME = re(
  String.raw`(?i)\b(?:[1-9]\d{0,2}(?:[ \t]*(?:-|–|to)[ \t]*[1-9]\d{0,2})?|an?|one|two|three|four|five|six|seven|` +
    String.raw`eight|nine|ten|eleven|twelve|fourteen|fifteen|twenty|thirty|forty-eight|seventy-two)[ \t-]*` +
    String.raw`(?:(?:business|working|calendar)[ \t-]+)?(?:hours?|hrs?|days?|weeks?)\b|\b[1-9]\d{0,2}[ \t]?h\b`,
);
/** A word for answering a report: acknowledge, respond, reply, answer, triage, assess, confirm, hear back. */
export const RESPOND_WORD = re(
  String.raw`(?i)\b(?:acknowledg(?:e|es|ed|ing|ements?|ments?)|respond(?:s|ed|ing)?|responses?|` +
    String.raw`repl(?:y|ies|ied|ying)|answer(?:s|ed|ing)?|triag(?:e|es|ed|ing)|assess(?:es|ed|ing|ments?)?|confirm(?:s|ing|ation)?|` +
    String.raw`get[ \t]+back|hear[ \t]+(?:back|from)|contact[ \t]+you|follow[ \t-]?up|reach[ \t]+(?:back[ \t]+)?out)\b`,
);

/**
 * The sentence of a policy that says how soon reports get an answer: a time (48 hours, 3 business days) with a word
 * for answering within 90 characters of it. A fix or disclosure deadline alone ("we disclose after 90 days") isn't one.
 */
export function responseTarget(p: Policy): string | null {
  for (const { sentence } of sentences(p)) {
    for (const m of finditer(RESPONSE_TIME, sentence)) {
      const near = sentence.slice(Math.max(0, m.index - 90), m.index + m[0].length + 90);
      if (search(RESPOND_WORD, near)) return quoteOf(sentence);
    }
  }
  return null;
}

// ------------------------------------------------------------------------- disclosure terms (public)
const EMBARGO = re(String.raw`(?i)\bembargo`);
const ADVANCE_NOTICE = re(
  String.raw`(?i)\badvance[ \t]+(?:notices?|notifications?|warnings?)\b|\bpre-?(?:notif\w*|announce\w*)`,
);
const DOWNSTREAM = re(String.raw`(?i)\bdownstream\b`);
const TELL = re(String.raw`(?i)\b(?:notif\w*|inform(?:s|ed|ing)?\b|coordinat\w*|heads[ \t-]up)`);
const COORDINATED = re(String.raw`(?i)\bcoordinated[ \t]+(?:vulnerability[ \t]+)?(?:disclosure|release)s?\b`);

/**
 * The sentence of a policy that says it coordinates disclosure: an embargo, advance notice, telling downstream users,
 * or coordinated disclosure, in that order of preference. "Responsible disclosure" alone isn't one.
 */
export function disclosureTerms(p: Policy): string | null {
  const all = sentences(p).map((s) => s.sentence);
  const kinds: ((s: string) => boolean)[] = [
    (s) => search(EMBARGO, s) !== null,
    (s) => search(ADVANCE_NOTICE, s) !== null,
    (s) => search(DOWNSTREAM, s) !== null && search(TELL, s) !== null,
    (s) => search(COORDINATED, s) !== null,
  ];
  for (const kind of kinds) {
    const hit = all.find(kind);
    if (hit) return quoteOf(hit);
  }
  return null;
}

/** Credits for the people who found or reported the issue, which a published advisory shows. */
const REPORTER_CREDITS = new Set(['reporter', 'finder']);

/** How many of the published advisories credit someone who reported or found the issue. */
export function creditedCount(published: unknown[]): number {
  return published.filter(
    (a) =>
      isDict(a) &&
      Array.isArray(a.credits_detailed) &&
      a.credits_detailed.some((c: unknown) => isDict(c) && REPORTER_CREDITS.has(c.type) && c.state !== 'declined'),
  ).length;
}

/** A GitHub advisory ID or a CVE ID. */
export const ADVISORY_ID = re(String.raw`(?i)\b(?:ghsa(?:-[0-9a-z]{4}){3}|cve-\d{4}-\d{4,7})\b`);

/**
 * The releases whose notes name one of the repository's own published advisories, by its GHSA or CVE ID: a CVE in a
 * dependency, which release notes often name, doesn't count.
 */
export function releasesNaming(published: unknown[], releases: unknown[]): { tag: string; url: string | null }[] {
  const own = new Set<string>();
  for (const a of published) {
    if (!isDict(a)) continue;
    for (const id of [a.ghsa_id, a.cve_id]) if (typeof id === 'string' && id) own.add(id.toLowerCase());
  }
  if (!own.size) return [];
  return releases
    .filter(isDict)
    .filter((r) => typeof r.body === 'string' && finditer(ADVISORY_ID, r.body).some((m) => own.has(m[0].toLowerCase())))
    .map((r) => ({ tag: String(r.tag_name ?? r.name ?? ''), url: typeof r.html_url === 'string' ? r.html_url : null }));
}

// ---------------------------------------------------------------- drills in the incident plan (public)
const DRILL_TEXT = re(
  String.raw`(?i)\b(?:drill(?:s|ed)?|table[ \t-]?top|dry[ \t-]runs?|rehears(?:als?|e|ed))\b|` +
    String.raw`\b(?:last|was|were)[ \t]+(?:tested|exercised|practi[cs]ed)\b`,
);
const MONTH =
  String.raw`(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|` +
  String.raw`oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b\.?`;
/** A date: 2026-03-04, 2026-03, March 4, 2026, March 2026, 4 March 2026. */
const A_DATE = re(
  String.raw`(?i)\b(?:19|20)\d\d-[01]\d(?:-[0-3]\d)?\b|` +
    String.raw`\b${MONTH}[ \t]+(?:[0-3]?\d(?:st|nd|rd|th)?,?[ \t]+)?(?:19|20)\d\d\b|` +
    String.raw`\b[0-3]?\d(?:st|nd|rd|th)?[ \t]+${MONTH},?[ \t]+(?:19|20)\d\d\b`,
);

/** The sentence of an incident response plan that dates a drill: a drill, tabletop or rehearsal, and a date. */
export function drillNote(p: Policy): string | null {
  const hit = sentences(p).find(
    ({ heading, sentence }) =>
      search(A_DATE, sentence) !== null &&
      (search(DRILL_TEXT, sentence) !== null || (heading !== null && search(DRILL_TEXT, heading) !== null)),
  );
  return hit ? quoteOf(hit.sentence) : null;
}

// --------------------------------------------------------------------- unpublished advisories (admin)
/** A practice advisory, as the guide's drill card has people title it. */
export const DRILL = re(String.raw`\bDRILL\b`);

/**
 * What the admin checks keep of an unpublished advisory, and nothing else: when it was opened and closed, how many
 * comments it has, whether its title marks it as a drill, whether the maintainers brought in collaborators, and
 * whether it has a temporary private fork.
 */
export interface Facts {
  created: number | null;
  closed: number | null;
  comments: number | null;
  drill: boolean;
  collaborators: boolean;
  fork: boolean;
}

const when = (v: unknown): number | null => {
  const t = typeof v === 'string' ? Date.parse(v) : NaN;
  return Number.isNaN(t) ? null : t;
};

/**
 * Whether an advisory has collaborators besides the one who opened it: GitHub adds the reporter of a private report
 * as one, so that one doesn't show anyone was brought in. A team always does.
 */
function broughtIn(a: Record<string, any>): boolean {
  if (Array.isArray(a.collaborating_teams) && a.collaborating_teams.length) return true;
  if (!Array.isArray(a.collaborating_users)) return false;
  const author = isDict(a.author) && typeof a.author.login === 'string' ? a.author.login : null;
  // Without its author, a report's collaborators may be just its reporter.
  if (author === null && a.submission) return false;
  return a.collaborating_users.some((u: unknown) => isDict(u) && typeof u.login === 'string' && u.login !== author);
}

/**
 * The advisories GitHub listed for one state, each reduced at once to its facts, or null when the answer isn't a list.
 * One in another state is left out.
 */
export function advisoryFacts([status, body]: Answer, state: string): Facts[] | null {
  if (status !== 200 || !Array.isArray(body)) return null;
  return body
    .filter((a) => isDict(a) && (a.state === state || a.state === undefined || a.state === null))
    .map((a) => ({
      created: when(a.created_at),
      closed: when(a.closed_at),
      comments: typeof a.comments === 'number' ? a.comments : null,
      drill: typeof a.summary === 'string' && search(DRILL, a.summary) !== null,
      collaborators: broughtIn(a),
      fork: isDict(a.private_fork),
    }));
}

/**
 * Whether GitHub listed an unpublished advisory in that state, which shows the token can read them: a token that
 * can't gets an empty list.
 */
export function showsUnpublished([status, body]: Answer, state: string): boolean {
  return status === 200 && Array.isArray(body) && body.some((a) => isDict(a) && a.state === state);
}

/**
 * Whether the token can read unpublished advisories, from what's known about it: a GitHub App installation token's
 * permissions (repository_advisories), or a classic token's scopes (repo, or repository_advisories:read) for an admin.
 * null when neither is known, as for a fine-grained token: a list it gets may be the empty one anyone gets.
 */
export function canReadUnpublished(
  grants: Record<string, string> | null | undefined,
  scopes: string[] | null | undefined,
): boolean | null {
  if (grants) return grants.repository_advisories === 'read' || grants.repository_advisories === 'write';
  if (scopes)
    return scopes.some((s) => ['repo', 'repository_advisories:read', 'repository_advisories:write'].includes(s));
  return null;
}

/** The reports in triage that have waited over 14 days with no comment: how many, and how many days the oldest has. */
export function waitingReports(triage: Facts[], now: Date): { waiting: number; oldest: number } {
  let waiting = 0;
  let oldest = 0;
  for (const f of triage) {
    if (f.created === null || f.comments !== 0) continue;
    const days = Math.floor((now.getTime() - f.created) / DAY);
    if (days <= 14) continue;
    waiting++;
    oldest = Math.max(oldest, days);
  }
  return { waiting, oldest };
}

/** When the newest drill advisory was closed (as YYYY-MM-DD), and whether that was within the last 12 months. */
export function lastDrill(closed: Facts[], now: Date): { date: string; recent: boolean } | null {
  const times = closed.filter((f) => f.drill && f.closed !== null).map((f) => f.closed!);
  if (!times.length) return null;
  const newest = Math.max(...times);
  const yearAgo = new Date(now.getTime());
  yearAgo.setUTCFullYear(yearAgo.getUTCFullYear() - 1);
  return {
    date: new Date(newest).toISOString().slice(0, 10),
    recent: newest >= yearAgo.getTime() && newest <= now.getTime(),
  };
}

/** A link to the repository's advisories, or to those in one state. Only its admins see the unpublished ones. */
export function advisoriesLink(repo: string, state: 'triage' | 'closed' | null = null): Evidence {
  const url = `https://github.com/${repo}/security/advisories`;
  if (state === 'triage') return { label: 'Reports in triage (admins only)', url: `${url}?state=triage` };
  if (state === 'closed') return { label: 'Closed advisories (admins only)', url: `${url}?state=closed` };
  return { label: 'Advisories', url };
}
