// people-security-training and people-share-learnings (new in 0.5.0), for the repositories in GitHub's Secure Open
// Source Fund. Taking part means training with GitHub Security Lab, and a team's post about it shares what it
// learned. The list ships with the scanner (fund.json, made from the guide's teams by scripts/fund-refresh.ts), so
// looking a repository up sends nothing anywhere.
import fund from './fund.json' with { type: 'json' };
import type { Evidence, Status } from './types.ts';

export interface FundEntry {
  repo: string;
  sessions: string[];
  posts: { title: string; url: string; date: string }[];
}

/** How long a session's training counts, in months. */
export const TRAINING_MONTHS = 24;

/** The Fund entry for a repository, matched exactly but ignoring case, under any of the names given. */
export function fundEntry(...names: string[]): FundEntry | null {
  const want = new Set(names.map((n) => n.toLowerCase()));
  return (fund.repos as FundEntry[]).find((r) => want.has(r.repo.toLowerCase())) ?? null;
}

/** "session 3", "sessions 1-2 and 3": the sessions as the guide labels them. */
function sessionWords(sessions: string[]): string {
  return sessions.length === 1 ? `session ${sessions[0]}` : `sessions ${sessions.join(' and ')}`;
}

/** The month the latest of the entry's sessions started, as a date, or null when the list doesn't say. */
export function lastSessionStart(entry: FundEntry): Date | null {
  const starts = entry.sessions
    .map((s) => (fund.session_starts as Record<string, string>)[s])
    .filter((d): d is string => typeof d === 'string');
  if (!starts.length) return null;
  return new Date(`${starts.sort().at(-1)}-01T00:00:00Z`);
}

interface Outcome {
  status: Status;
  summary: string;
  evidence: Evidence[];
  details: Record<string, unknown>;
}

/** people-security-training: a pass for a Fund repository, until TRAINING_MONTHS after its latest session. */
export function trainingResult(entry: FundEntry | null, now: Date = new Date()): Outcome | null {
  if (!entry) return null;
  const start = lastSessionStart(entry);
  if (start) {
    const until = new Date(start);
    until.setUTCMonth(until.getUTCMonth() + TRAINING_MONTHS);
    if (now >= until) return null;
  }
  return {
    status: 'pass',
    summary:
      `Took part in the GitHub Secure Open Source Fund (${sessionWords(entry.sessions)}), ` +
      'three weeks of security training with GitHub Security Lab',
    evidence: [{ label: `Secure Open Source Fund, ${sessionWords(entry.sessions)}`, url: fund.program }],
    details: { sessions: entry.sessions },
  };
}

/** people-share-learnings: a pass for a Fund team that published a post about its work. */
export function sharingResult(entry: FundEntry | null): Outcome | null {
  if (!entry || !entry.posts.length) return null;
  const [first] = entry.posts;
  return {
    status: 'pass',
    summary:
      `Wrote about its Fund work: "${first.title}" (${first.date})` +
      (entry.posts.length > 1 ? ` and ${entry.posts.length - 1} more` : ''),
    evidence: entry.posts.slice(0, 3).map((p) => ({ label: p.title, url: p.url })),
    details: { posts: entry.posts.length },
  };
}
