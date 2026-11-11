// rel-security-support (new in 0.5.0): does SECURITY.md's supported-versions table cover the newest release line?
// The table is read from the section under a heading such as "Supported Versions". The release it's compared with is
// the highest stable version among the latest releases, not /releases/latest alone: a project that ships several
// lines at once (4.7.5 and 4.4.28 the same day) can have "latest" on an old line.
import { finditer, match, re, search, splitLines } from './py.ts';

/** A heading (Markdown, bold, or a plain line, as in reStructuredText) that starts the supported-versions section. */
export const SUPPORT_HEADING = re(
  String.raw`(?im)^[ \t]*(?:#{1,6}[ \t]*|\*\*)?[ \t]*(?:supported[ \t]+versions?|versions?[ \t]+support(?:ed)?|` +
    String.raw`security[ \t]+(?:updates|support|fixes|releases)|maintained[ \t]+versions?|` +
    String.raw`support(?:ed)?[ \t]+(?:policy|releases?|lifecycle)|end[- ]of[- ]life|long[- ]term[ \t]+support)\b`,
);
/** The next heading after the section starts: Markdown, or a line underlined with = or - (reStructuredText). */
const NEXT_HEADING = re(String.raw`(?m)^[ \t]*#{1,6}[ \t]|^[=\-~^]{3,}[ \t]*$`);
/** A sentence about which versions get fixes, for a policy without a table. */
const SUPPORT_PROSE = re(
  String.raw`(?i)\b(?:only|just)\s+(?:the\s+)?(?:latest|most\s+recent|current|newest|last)\s+(?:stable\s+)?` +
    String.raw`(?:minor\s+|major\s+)?(?:release|version|major|minor|line)|\blatest\s+(?:release|version)s?\s+` +
    String.raw`(?:is|are|will\s+be|gets?|receives?)\b|security\s+(?:fixes|patches|updates)\s+(?:are\s+)?` +
    String.raw`(?:only\s+)?(?:land|go|released|applied|provided|backported)|\bsupport(?:ed)?\s+(?:only\s+)?the\s+` +
    String.raw`(?:latest|current)\b`,
);
/** The sentence in GitHub's SECURITY.md template, which a project that kept the template still has. */
const TEMPLATE_SENTENCE = re(String.raw`(?i)use this section to tell people about which versions of your project`);
/** A row marked unsupported. Checked before SUPPORTED, so "not supported" isn't read as supported. */
const UNSUPPORTED = re(
  String.raw`(?i):x:|❌|:no_entry(?:_sign)?:|⛔|✗|✘|\bno\b|\bnot\s+supported\b|\bunsupported\b|\bend[- ]of[- ]life\b|` +
    String.raw`\beol\b|\bended\b|\bdeprecated\b|\bnone\b`,
);
const SUPPORTED = re(
  String.raw`(?i):white_check_mark:|:heavy_check_mark:|✅|✔|☑|\byes\b|\bsupported\b|\buntil\b|\bactive\b`,
);
/** A date after "until": supported until then. */
const UNTIL_DATE = re(String.raw`(?i)\buntil\s+(\d{4}-\d\d(?:-\d\d)?)`);
/** A version in a table cell: an optional comparison, then numbers, maybe with x, * or latest, maybe with +. */
const VERSION_SPEC = re(
  String.raw`^(>=|<=|=>|=<|≥|≤|>|<|=|\^|~)?\s*v?(\d+(?:\.\d+)*)(?:\.(?:x|X|\*|latest))*` +
    String.raw`(\.?\+|\s*and\s+(?:above|later|newer)|\s*or\s+(?:later|newer|higher))?`,
);
/** A table's header row (Version | Supported) and its separator row (| --- |). */
const HEADER_CELL = re(String.raw`(?i)^(?:versions?|releases?|branch(?:es)?|series|lines?)\b`);
const SEPARATOR_CELL = re(String.raw`^:?-{2,}:?$`);
/** A row that means "the latest release" in words. */
const LATEST_WORDS = re(
  String.raw`(?i)^(?:the\s+)?(?:latest|current|newest|most\s+recent)(?:\s+(?:stable\s+)?(?:release|version|major))?\b`,
);
/** A tag's version: a prefix (v, release-, name-v), numbers separated by dots or underscores, and the rest. */
const TAG_VERSION = re(String.raw`^(.*?)(\d+(?:[._]\d+)*)(.*)$`);
/** What follows the numbers in a pre-release tag (1.2.0-rc.1, 1.2.0b2, 2.0.0-beta). */
const PRERELEASE = re(String.raw`(?i)^[-._]?(?:a|b|rc|alpha|beta|pre|preview|dev|next|canary|nightly|snapshot|m)\d*\b`);
/** Markdown links and inline markup in a cell. */
const MD_LINK = re(String.raw`\[([^\]]*)\]\([^)]*\)`);

export type Version = number[];

export function compareVersions(a: Version, b: Version): number {
  for (let k = 0; k < Math.max(a.length, b.length); k++) {
    const d = (a[k] ?? 0) - (b[k] ?? 0);
    if (d) return d;
  }
  return 0;
}

/** A tag's prefix and version, and whether it's a stable release; null when it has no version. */
export function tagVersion(tag: string): { prefix: string; version: Version; stable: boolean } | null {
  const m = match(TAG_VERSION, tag.trim());
  if (!m) return null;
  const version = m[2].replaceAll('_', '.').split('.').map(Number);
  return { prefix: m[1].toLowerCase(), version, stable: !search(PRERELEASE, m[3]) };
}

/**
 * The release to compare the table with: of the given releases (newest first), the stable ones with the commonest
 * tag prefix (the newest one's on a tie), and of those the highest version.
 */
export function targetRelease(tags: { tag: string; prerelease?: boolean }[]): { tag: string; version: Version } | null {
  const stable = tags
    .filter((t) => !t.prerelease)
    .map((t) => ({ tag: t.tag, v: tagVersion(t.tag) }))
    .filter((t): t is { tag: string; v: NonNullable<ReturnType<typeof tagVersion>> } => !!t.v && t.v.stable);
  if (!stable.length) return null;
  const count = new Map<string, number>();
  for (const t of stable) count.set(t.v.prefix, (count.get(t.v.prefix) ?? 0) + 1);
  const best = Math.max(...count.values());
  const prefix = stable.find((t) => count.get(t.v.prefix) === best)!.v.prefix;
  const line = stable.filter((t) => t.v.prefix === prefix);
  const top = line.reduce((a, b) => (compareVersions(b.v.version, a.v.version) > 0 ? b : a));
  return { tag: top.tag, version: top.v.version };
}

/** A table cell without links, parenthetical notes such as (LTS), and markup. */
function clean(cell: string): string {
  let out = '';
  let depth = 0;
  // A link keeps its text: [v6.x](url) is v6.x.
  let unlinked = '';
  let last = 0;
  for (const m of finditer(MD_LINK, cell)) {
    unlinked += cell.slice(last, m.index) + m[1];
    last = m.index + m[0].length;
  }
  unlinked += cell.slice(last);
  for (const c of unlinked) {
    if (c === '(') depth++;
    else if (c === ')') depth = Math.max(0, depth - 1);
    else if (!depth && !'`*_'.includes(c)) out += c;
  }
  return out.trim();
}

export interface Row {
  /** The version cell as written, cleaned. */
  version: string;
  supported: boolean;
}

/** Whether a row's version covers v. Null when the cell isn't a version the scan can read. */
export function covers(cell: string, v: Version): boolean | null {
  if (search(LATEST_WORDS, cell)) return true;
  const m = match(VERSION_SPEC, cell);
  if (!m) return null;
  const [, op, nums, plus] = m;
  const spec = nums.split('.').map(Number);
  const cmp = compareVersions(v, spec);
  if (plus) return cmp >= 0;
  switch (op) {
    case '>=':
    case '=>':
    case '≥':
      return cmp >= 0;
    case '>':
      return cmp > 0;
    case '<=':
    case '=<':
    case '≤':
      return cmp <= 0;
    case '<':
      return cmp < 0;
    case '^':
      return v[0] === spec[0] && cmp >= 0;
    case '~':
      return v[0] === spec[0] && (v[1] ?? 0) === (spec[1] ?? 0) && cmp >= 0;
  }
  // 5.1.x, 5.1.*, 5.latest and a bare 5.1 cover their whole line, and so does 4.7.0, which tables use for the 4.7
  // line (mastodon's lists 4.7.0 while it ships 4.7.5). An exact patch such as 1.0.5 covers only itself.
  const line = spec.length >= 3 && spec[spec.length - 1] === 0 ? spec.slice(0, -1) : spec;
  return line.every((n, k) => (v[k] ?? 0) === n);
}

/** The supported-versions section: its rows, and whether it exists at all. */
export function supportTable(
  text: string,
  now: Date = new Date(),
): { section: boolean; rows: Row[]; template: boolean } {
  const head = search(SUPPORT_HEADING, text);
  const template = !!search(TEMPLATE_SENTENCE, text);
  if (!head) return { section: false, rows: [], template };
  let rest = text.slice(head.index + head[0].length);
  // The rest of the heading's own line, then up to the next heading.
  const eol = rest.indexOf('\n');
  rest = eol < 0 ? '' : rest.slice(eol + 1);
  const next = search(NEXT_HEADING, rest);
  const section = (next ? rest.slice(0, next.index) : rest).slice(0, 4000);
  const rows: Row[] = [];
  for (const line of splitLines(section)) {
    const t = line.trim();
    if (!t.startsWith('|')) continue;
    const inner = t.endsWith('|') && t.length > 1 ? t.slice(1, -1) : t.slice(1);
    const cells = inner.split('|').map((c) => c.trim());
    if (cells.length < 2 || search(SEPARATOR_CELL, cells[0]) || search(HEADER_CELL, clean(cells[0]))) continue;
    const version = clean(cells[0]);
    const status = cells.slice(1).join(' | ');
    let supported = !search(UNSUPPORTED, status) && !!search(SUPPORTED, status);
    const until = search(UNTIL_DATE, status);
    if (supported && until && new Date(until[1]) < now) supported = false;
    rows.push({ version, supported });
  }
  return { section: true, rows, template };
}

/** Whether the rows are GitHub's template's (5.1.x, 5.0.x, 4.0.x and < 4.0). */
export function templateRows(rows: Row[]): boolean {
  const v = rows.map((r) => r.version);
  return ['5.1.x', '5.0.x', '4.0.x', '< 4.0'].every((x) => v.includes(x));
}

/** Whether the policy says which versions get fixes in a sentence, without a table. */
export function supportProse(text: string): boolean {
  return !!search(SUPPORT_PROSE, text);
}

/** The version cells of the rows marked supported. */
export function supportedCells(rows: Row[]): string[] {
  return rows.filter((r) => r.supported).map((r) => r.version);
}
