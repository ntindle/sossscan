/**
 * How lib/scanner/fund.json is made from public/data/guide.json (scripts/fund-refresh.ts writes it, and a test checks
 * the two still agree). It keeps what the scanner needs: each Fund repository, its sessions, and the team's primary
 * posts about the program.
 */

/**
 * When each session started (year and month), so a pass for training can age out. guide.json has only the session
 * labels; the dates are from GitHub's announcements. "1-2" is a team that was in session 1 or 2, so it takes the
 * earlier one.
 */
export const SESSION_STARTS: Record<string, string> = {
  '1': '2025-01',
  '1-2': '2025-01',
  '2': '2025-06',
  '3': '2025-09',
  '4': '2026-04',
  '5': '2026-09',
};

export const FUND_URL = 'https://github.com/open-source/github-secure-open-source-fund';

export interface FundPost {
  title: string;
  url: string;
  date: string;
}

export interface FundRepo {
  repo: string;
  sessions: string[];
  posts: FundPost[];
}

export interface FundData {
  _comment: string;
  program: string;
  session_starts: Record<string, string>;
  repos: FundRepo[];
}

/** The scanner's Fund list from the guide's teams: one entry per repository, in the guide's order. */
export function fundFromGuide(guide: {
  teams: { repo: string; sessions: string[]; posts: { title: string; url: string; date: string; tier: string }[] }[];
}): FundData {
  return {
    _comment:
      'Made from public/data/guide.json by scripts/fund-refresh.ts (npm run fund). The GitHub Secure Open Source ' +
      'Fund repositories, their sessions and their primary posts, for people-security-training and ' +
      'people-share-learnings. Session starts are year and month.',
    program: FUND_URL,
    session_starts: SESSION_STARTS,
    repos: guide.teams
      .filter((t) => typeof t.repo === 'string' && t.repo.includes('/'))
      .map((t) => ({
        repo: t.repo,
        sessions: [...t.sessions],
        posts: t.posts.filter((p) => p.tier === 'primary').map((p) => ({ title: p.title, url: p.url, date: p.date })),
      })),
  };
}
