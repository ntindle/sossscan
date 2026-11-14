// count.js — what the page counts, for the site to pass on without anything about who you are (lib/counts.ts).
// Plain ES module, no build step, and nothing runs on import: visit.js counts a page's visit.
//
// The page tells this site, never anyone else. A count is the event's name and a few coarse details. Nothing is counted
// when the browser sends Do Not Track or Global Privacy Control, or in a browser a program drives. First visits are told
// apart without an ID: the page keeps the day, week and month of the last visit it counted (pl:visit), and sends only
// whether this visit is the first of each.

export const VISIT_KEY = 'pl:visit';

// Whether the page may count: in a browser, whose person hasn't asked not to be tracked.
export function mayCount(nav = globalThis.navigator, win = globalThis.window) {
  if (!win || !win.document || !nav || nav.webdriver) return false;
  const dnt = nav.doNotTrack ?? win.doNotTrack ?? nav.msDoNotTrack;
  return !(dnt === '1' || dnt === 'yes' || nav.globalPrivacyControl === true);
}

const pad = (n) => String(n).padStart(2, '0');

// The local day (YYYY-MM-DD), its ISO week (YYYY-Www: weeks start on Monday, and week 1 holds the year's first
// Thursday) and its month (YYYY-MM).
export function calendar(now = new Date()) {
  const day = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  const thursday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - ((now.getDay() + 6) % 7) + 3);
  const jan1 = new Date(thursday.getFullYear(), 0, 1);
  const week = 1 + Math.floor(Math.round((thursday - jan1) / 86_400_000) / 7);
  return { day, week: `${thursday.getFullYear()}-W${pad(week)}`, month: day.slice(0, 7) };
}

// Whether this visit is the first of its day, week and month, given the last one counted, and what to keep for the next.
export function visitFlags(last, now = new Date()) {
  const keep = calendar(now);
  const prev = last && typeof last === 'object' ? last : {};
  return {
    flags: { new_day: prev.day !== keep.day, new_week: prev.week !== keep.week, new_month: prev.month !== keep.month },
    keep,
  };
}

// The other site you came from, as its host name only; null when you came from this site, or from nowhere.
export function referrerHost(referrer = document.referrer, here = location.hostname) {
  try {
    const host = new URL(referrer).hostname.toLowerCase();
    return host && host !== here ? host : null;
  } catch {
    return null;
  }
}

// Report one event. Counting never gets in the page's way: a count that fails is dropped.
export function count(event, details = {}) {
  if (!mayCount()) return;
  try {
    fetch('/api/count', {
      method: 'POST',
      keepalive: true,
      headers: { 'content-type': 'application/json', 'x-requested-with': 'sosf' },
      body: JSON.stringify({ event, ...details }),
    }).catch(() => {});
  } catch {
    /* no fetch */
  }
}

// Count this page's visit. With storage blocked, a visit counts as a first one when it didn't come from this site.
export function countVisit() {
  if (!mayCount()) return;
  let flags;
  try {
    const { flags: f, keep } = visitFlags(JSON.parse(localStorage.getItem(VISIT_KEY) || 'null'));
    localStorage.setItem(VISIT_KEY, JSON.stringify(keep));
    flags = f;
  } catch {
    const first = !document.referrer || referrerHost() !== null;
    flags = { new_day: first, new_week: first, new_month: first };
  }
  count('page_view', { page: location.pathname, referrer: referrerHost(), ...flags });
}
