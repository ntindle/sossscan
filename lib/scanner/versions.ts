// rel-security-support (new in 0.5.0): does SECURITY.md's supported-versions table cover the newest release line?
// Since 0.5.1 the policy is read by policy.ts, so the table can be Markdown, HTML, reStructuredText or AsciiDoc, and
// it can sit under any kind of heading. A table the scan can't read never gives a warning: a status word it doesn't
// know is unknown, not unsupported, and releases it can't tie to the table give info. The release it's compared
// with is the highest stable version among the latest releases of the repository's main package, not
// /releases/latest alone: a project that ships several lines at once (4.7.5 and 4.4.28 the same day) can have
// "latest" on an old line, and a monorepo's latest release can be another package's.
import { finditer, match, re, search } from './py.ts';
import { readPolicy, sections } from './policy.ts';
import type { Policy, Table } from './policy.ts';

/**
 * A heading that starts the supported-versions section, in English or a few other languages. A lifecycle is one of
 * versions, releases, support, a product or maintenance ("Support lifecycle", "Lifecycle policy"), never "Lifecycle
 * scripts".
 */
export const SUPPORT_HEADING = re(
  String.raw`(?i)\bsupported[ \t]+(?:versions?|releases?|branches|lines|platforms)\b|\bversions?[ \t]+(?:support(?:ed)?|policy|lifecycle)\b|\bsecurity[ \t]+(?:updates|support|fixes|releases|patches|maintenance)\b|\bmaintained[ \t]+(?:versions?|releases?|branches)\b|\bsupport(?:ed)?[ \t]+(?:policy|releases?|lifecycle|status|matrix|period|window|timeline|schedule)\b|\bend[- ]of[- ](?:life|support)\b|\blong[- ]term[ \t]+support\b|\brelease[ \t]+(?:support|lines|lifecycle)\b|\b(?:product|maintenance)[ \t]+lifecycle\b|\blifecycle[ \t]+policy\b|^(?:versions?|releases|support)$|\bLTS\b`,
);
/** The same, for headings with letters (?i) can't fold: German, Spanish, Portuguese, French, and scripts without case. */
const SUPPORT_HEADING_OTHER = re(
  String.raw`[Uu]nterst[üÜ]tzte[ \t]+[Vv]ersionen|[Vv]ersiones[ \t]+(?:[Ss]oportadas|[Cc]ompatibles|con[ \t]+soporte)|[Vv]ersões[ \t]+(?:[Ss]uportadas|[Cc]ompatíveis)|[Vv]ersions[ \t]+(?:[Ss]upportées|prises[ \t]+en[ \t]+charge|[Mm]aintenues)|[Vv]ersioni[ \t]+[Ss]upportate|支持的?版本|版本支持|受支持的版本|サポート(?:対象|され)|サポートバージョン|지원(?:되는)?[ \t]*버전|[Пп]оддерживаемые[ \t]+версии|[Dd]esteklenen[ \t]+[Ss]ürümler|[Pp]hiên[ \t]+bản[ \t]+được[ \t]+hỗ[ \t]+trợ`,
);
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
/** A table given as an illustration ("For example, if the latest release is OTP 28, we support: ..."). */
const EXAMPLE = re(
  String.raw`(?i)\b(?:for[ \t]+example|for[ \t]+instance|e\.g\.|example:|such[ \t]+as[ \t]+the[ \t]+following)`,
);

// ------------------------------------------------------------------------------------------- columns
// Each kind of header is two patterns: one that ignores case, and one for letters (?i) can't fold.
const VERSION_HEADER = [
  re(
    String.raw`(?i)\b(?:versions?|releases?|branch(?:es)?|series|lines?|majors?|minors?|channels?|editions?|tags?|ver|versi(?:on|one|yon))\b`,
  ),
  re(String.raw`版本|バージョン|버전|[Vv]ers(?:ión|iones|ão|ões)|[Вв]ерси|[Ss]ürüm|[Pp]hiên[ \t]+bản`),
];
const COMPONENT_HEADER = re(
  String.raw`(?i)^(?:components?|packages?|modules?|crates?|librar(?:y|ies)|products?|plugins?|projects?|artifacts?|sdks?|images?|charts?|tools?|apps?|services?)\b`,
);
const SECURITY_HEADER = [
  re(String.raw`(?i)secur|sicherheit|seguridad|seguran`),
  re(String.raw`[Ss]écurité|安全|セキュリティ|보안|[Бб]езопасн|[Gg]üvenlik`),
];
const SUPPORTED_HEADER = [
  re(String.raw`(?i)support|maintain|unterst|soport|suport|patch|\bfix|updates?\b|destek`),
  re(String.raw`支持|サポート|지원|[Пп]оддерж|hỗ[ \t]+trợ|维护|対応`),
];
const STATUS_HEADER = [
  re(String.raw`(?i)\b(?:status|state|phase|stage|statut|estado|stato|durum)\b`),
  re(String.raw`状态|状況|ステータス|상태|[Сс]татус`),
];
const UNTIL_HEADER = [
  re(String.raw`(?i)until|\btill\b|\bends?\b|end[ -]of|\beol\b|expir|\bbis\b|\bfin\b`),
  re(String.raw`kết[ \t]+thúc|まで|截止|结束|终止|(?<!\w)[Дд]о(?!\w)`),
];
const OTHER_HEADER = [
  re(
    String.raw`(?i)\b(?:start|starts|started|since|from|released?|release[ \t]+date|first|initial|notes?|comments?|remarks?|description|details|php|python|node(?:\.?js)?|java|\.net|go|rust|ruby|typo3|laravel|django|kubernetes|k8s|android|ios|jellyfin|compat\w*|requires?|required|minimum|tested|date|platform|os|bug[ \t]?fix(?:es)?|anmerkungen?|hinweise?)\b`,
  ),
  re(String.raw`备注|说明|[Пп]римечание`),
];
const NOTES_HEADER = [
  re(String.raw`(?i)\b(?:notes?|comments?|remarks?|details|anmerkungen?|hinweise?)\b`),
  re(String.raw`备注|说明|[Пп]римечание`),
];
/** Whether any of the patterns finds something in s. */
const hit = (rxs: RegExp[], s: string) => rxs.some((rx) => search(rx, s) !== null);

// ------------------------------------------------------------------------------------------ statuses
const YES_MARK = re(
  String.raw`✅|✔|✓|☑|🟢|:white_check_mark:|:heavy_check_mark:|:ballot_box_with_check:|:green_circle:|:check(?:mark)?:`,
);
const NO_MARK = re(
  String.raw`❌|✗|✘|⛔|🚫|🔴|❎|✖|:x:|:no_entry(?:_sign)?:|:red_circle:|:heavy_multiplication_x:|:negative_squared_cross_mark:`,
);
const YES_WORD = re(
  String.raw`(?i)^(?:yes|ja|si|sim|oui|ok|true|y)\b|\b(?:supported|maintained|active(?:ly)?|lts|current|receiving|provided|full[ \t]+support|active[ \t]+support|security[ \t]+(?:fixes|patches|updates|support)|critical[ \t]+(?:fixes|security|patches|bug[ \t]?fixes|issues)|bug[ \t]?fix(?:es)?|maintenance|backports?|until|till|aktiv|aktif|correctifs)\b`,
);
const YES_WORD_OTHER = re(
  String.raw`^(?:Sí|sí|Có|có|Да|да|是)(?![\w])|[Uu]nterst[üÜ]tzt|[Ss]oportad[ao]|[Ss]oporte[ \t]+(?:completo|LTS|activo)|[Ss]uportad[ao]|[Ss]upport[ée]e?\b|[Пп]оддерживается|[Аа]ктивн|[Dd]esteklen(?:iyor|ir)\b|积极维护|接受安全更新|长期支持|安全补丁|关键问题修复|当前维护|支持|サポート中|サポート対象|지원[ \t]*중|지원됨|^지원$|[Pp]atches[ \t]+de[ \t]+seguran|[Cc]orre[cç][õo]es[ \t]+de[ \t]+seguran`,
);
const NO_WORD = re(
  String.raw`(?i)^(?:no|nein|non|nao|none|false|n|nope)\b|\b(?:not[ \t-]+(?:[\w']+[ \t-]+){0,2}?(?:supported|maintained|provided|receiving)|unsupported|unmaintained|no[ \t]+longer|no[ \t]+(?:security[ \t]+)?(?:support|updates|fixes|patches)|end[ -]of[ -](?:life|support)|eol|ended|retired|superseded|obsolete|out[ \t]+of[ \t]+support|discontinued|archived|dropped|expired)\b`,
);
const NO_WORD_OTHER = re(
  String.raw`^(?:Não|não)\b|[Nn]icht[ \t]+(?:mehr[ \t]+)?unterst|[Ss]in[ \t]+soporte|[Nn]o[ \t]+soportad|[Ff]in[ \t]+de[ \t]+vi[de]a?|[Nn]ão[ \t]+suportad|[Нн]е[ \t]+поддерж|прекращен|[Dd]esteklenmiyor|否|不支持|不再|停止|サポート外|サポート終了|미지원|지원[ \t]*안|지원[ \t]*종료|지원[ \t]*중단|지원하지[ \t]*않|않음`,
);
/** The no-words that are an end of life, which a date to come makes a "yes, until then" ("EOL 2028"). */
const EOL_WORD = re(String.raw`(?i)\b(?:end[ -]of[ -](?:life|support)|eol|superseded|retired|discontinued|sunset)\b`);
/** An end of life to come without a date: "superseded soon", "EOL in 6 months". */
const SOON = re(
  String.raw`(?i)\b(?:soon|planned|scheduled|upcoming|expected|next)\b|\bin[ \t]+(?:\d+|an?|one|two|three|four|six|twelve|a[ \t]+few)[ \t]+(?:days?|weeks?|months?|quarters?|years?)\b`,
);
/**
 * An end of life that isn't set, or hasn't come: "No EOL planned", "Not yet EOL", "EOL not announced", "No
 * end-of-life date yet". The version is still supported.
 */
const NO_EOL = re(
  String.raw`(?i)\b(?:no|not[ \t]+yet|without[ \t]+an?)[ \t]+(?:eol|end[ -]of[ -](?:life|support))\b(?:[ \t]+(?:date|planned|scheduled|set|announced|yet))*|\b(?:eol|end[ -]of[ -](?:life|support))(?:[ \t]+date)?[ \t]+(?:is[ \t]+)?(?:not[ \t]+(?:yet[ \t]+)?(?:announced|planned|scheduled|set|decided|determined|known|defined)|tb[ad]|to[ \t]+be[ \t]+(?:announced|determined|decided))\b`,
);
/** A date after "until" (or "till", "bis") in a status cell: supported until then. */
const UNTIL_DATE = re(String.raw`(?i)\b(?:until|till|bis|through)[ \t]+(?:at[ \t]+least[ \t]+)?([^;,()|]{4,40})`);
/** A cell that means no end date has been set yet, in a column of end dates. */
const NO_END = re(
  String.raw`(?i)^(?:tb[ad]|to[ \t]+be[ \t]+(?:announced|determined|decided)|not[ \t]+(?:announced|defined|yet|set|planned|scheduled)|n/?a|none|ongoing|open|-+|—|–|\?+|unknown|future|later)$`,
);

// --------------------------------------------------------------------------------------------- dates
const ISO_DATE = re(String.raw`\b(\d{4})-(\d{1,2})(?:-(\d{1,2}))?\b`);
const DOTTED_DATE = re(String.raw`\b(\d{1,2})\.(\d{1,2})\.(\d{4})\b`);
const SLASH_DATE = re(String.raw`\b(\d{1,2})/(\d{4})\b`);
const MONTH_DAY_YEAR = re(
  String.raw`(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?[ \t]+(\d{1,2})(?:st|nd|rd|th)?,?[ \t]+(\d{4})\b`,
);
const DAY_MONTH_YEAR = re(
  String.raw`(?i)\b(\d{1,2})(?:st|nd|rd|th)?[ \t]+(?:of[ \t]+)?(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?[ \t]+(\d{4})\b`,
);
const YEAR_MONTH_DAY = re(
  String.raw`(?i)\b(\d{4})[ \t]+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?[ \t]+(\d{1,2})\b`,
);
const MONTH_YEAR = re(String.raw`(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?[ \t]+(\d{4})\b`);
const QUARTER_YEAR = re(String.raw`(?i)\b(?:Q([1-4])|H([12]))[ \t/-]*(\d{4})\b`);
const YEAR = re(String.raw`(?<![\d.])((?:19|20|21)\d\d)(?![\d.])`);
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

/** The last day a cell's date covers ("June 2026" runs to June 30), or null when it has no date. */
export function endDate(cell: string): Date | null {
  let m: RegExpExecArray | null;
  const day = (y: number, mo: number, d: number) => new Date(Date.UTC(y, mo - 1, d, 23, 59, 59));
  const monthEnd = (y: number, mo: number) => new Date(Date.UTC(y, mo, 0, 23, 59, 59));
  if ((m = search(ISO_DATE, cell))) return m[3] ? day(+m[1], +m[2], +m[3]) : monthEnd(+m[1], +m[2]);
  if ((m = search(DOTTED_DATE, cell))) return day(+m[3], +m[2], +m[1]);
  if ((m = search(MONTH_DAY_YEAR, cell))) return day(+m[3], MONTHS.indexOf(m[1].toLowerCase()) + 1, +m[2]);
  if ((m = search(DAY_MONTH_YEAR, cell))) return day(+m[3], MONTHS.indexOf(m[2].toLowerCase()) + 1, +m[1]);
  if ((m = search(YEAR_MONTH_DAY, cell))) return day(+m[1], MONTHS.indexOf(m[2].toLowerCase()) + 1, +m[3]);
  if ((m = search(MONTH_YEAR, cell))) return monthEnd(+m[2], MONTHS.indexOf(m[1].toLowerCase()) + 1);
  if ((m = search(SLASH_DATE, cell))) return monthEnd(+m[2], +m[1]);
  if ((m = search(QUARTER_YEAR, cell))) return monthEnd(+m[3], m[1] ? +m[1] * 3 : +m[2] * 6);
  if ((m = search(YEAR, cell))) return day(+m[1], 12, 31);
  return null;
}

export type Status = 'yes' | 'no' | 'unknown';

/** A cell's yes and no signals: marks, and words (the words for no read first and set aside). */
function signals(cell: string): { yes: boolean; no: boolean; eolOnly: boolean } {
  const yesMark = !!search(YES_MARK, cell);
  const noMark = !!search(NO_MARK, cell);
  // "not supported" is a no, and isn't read as "supported" as well.
  const noWords = finditer(NO_WORD, cell);
  let rest = '';
  let last = 0;
  for (const m of noWords) {
    rest += cell.slice(last, m.index) + ' ';
    last = m.index + m[0].length;
  }
  rest += cell.slice(last);
  const noOther = !!search(NO_WORD_OTHER, cell);
  return {
    yes: yesMark || !!search(YES_WORD, rest) || (!noOther && !!search(YES_WORD_OTHER, rest)),
    no: noMark || noWords.length > 0 || noOther,
    eolOnly: !noMark && !noOther && noWords.length > 0 && noWords.every((m) => !!search(EOL_WORD, m[0])),
  };
}

/** A cell without what's in brackets: "❌ (critical fixes may still be backported)" is a ❌ with a note. */
function outsideBrackets(cell: string): string {
  let out = '';
  let depth = 0;
  for (const c of cell) {
    if (c === '(' || c === '[') depth++;
    else if ((c === ')' || c === ']') && depth > 0) depth--;
    else if (!depth) out += c;
  }
  return out;
}

/**
 * What a status cell says: supported, not supported, or something the scan can't read as either. A cell with words
 * (or marks) for both, such as "Current, EOL 2028" or "❌ security fixes only", goes by its date if it has one; without
 * one, by what's outside its brackets ("Supported (no longer in beta)"), and is unknown if that has both too. An end
 * of life with a date to come ("EOL 2028") is supported until then.
 */
export function statusOf(cell: string, now: Date = new Date()): Status {
  // An end of life not set yet says nothing against the version: the rest of the cell decides, and is a yes alone.
  if (search(NO_EOL, cell)) {
    let rest = '';
    let last = 0;
    for (const m of finditer(NO_EOL, cell)) {
      rest += cell.slice(last, m.index) + ' ';
      last = m.index + m[0].length;
    }
    const left = statusOf(rest + cell.slice(last), now);
    return left === 'unknown' ? 'yes' : left;
  }
  const { yes, no, eolOnly } = signals(cell);
  let st: Status = 'unknown';
  if (yes && no) {
    const end = endDate(cell);
    if (end) st = end < now ? 'no' : 'yes';
    else {
      const main = signals(outsideBrackets(cell));
      st = main.yes && !main.no ? 'yes' : main.no && !main.yes ? 'no' : 'unknown';
    }
  } else if (no) {
    const end = eolOnly ? endDate(cell) : null;
    st = end ? (end < now ? 'no' : 'yes') : eolOnly && search(SOON, cell) ? 'unknown' : 'no';
  } else if (yes) st = 'yes';
  if (st === 'yes') {
    const until = search(UNTIL_DATE, cell);
    const end = until ? endDate(until[1]) : null;
    if (end && end < now) st = 'no';
  }
  return st;
}

/** What a cell in a column of end dates says: a date to come or none set yet is supported, a past one isn't. */
function untilStatus(cell: string, now: Date): Status {
  const marked = statusOf(cell, now);
  if (marked === 'no') return 'no';
  const end = endDate(cell);
  if (end) return end < now ? 'no' : 'yes';
  if (!cell.trim() || search(NO_END, cell.trim())) return 'yes';
  return marked;
}

// ------------------------------------------------------------------------------------------ versions
export type Version = number[];

export function compareVersions(a: Version, b: Version): number {
  for (let k = 0; k < Math.max(a.length, b.length); k++) {
    const d = (a[k] ?? 0) - (b[k] ?? 0);
    if (d) return d;
  }
  return 0;
}

/**
 * A version in a table cell: an optional comparison, numbers maybe with x, *, y or latest, then a range or a +. The
 * spaces around its parts are at most three and a version has at most seven parts, so the pattern stays linear on a
 * cell of spaces or of 1.2.3.4.5... (a pattern with unbounded ones takes time squared there).
 */
const VERSION_TOKEN = re(
  String.raw`(?i)(>=|<=|=>|=<|≥|≤|>|<|=|\^|~)?[ \t]{0,3}(?<![\w.])v?(\d+(?:\.(?:\d+|x|\*|latest|y|z)){0,6})(?![\w.]*[a-wz])` +
    String.raw`(?:([ \t]{0,3}\.?\+)|[ \t]{0,3}(?:and|or|&|und|et|ou|y)[ \t]{1,3}(above|later|newer|higher|up|greater|older|earlier|below|lower|prior|before)\b|[ \t]{0,3}(?:-|–|—|to|through|thru|\.\.)[ \t]{0,3}v?(\d+(?:\.(?:\d+|x|\*|y|z)){0,6})(?![\w.]*[a-wz]))?`,
);
const LATEST_CELL = re(
  String.raw`(?i)\b(?:latest|current|newest|most[ \t]+recent|recent|last[ \t]+(?:(?:two|three|four|\d+)[ \t]+)?(?:stable[ \t]+)?(?:releases?|versions?|minors?|majors?|lines?))\b`,
);
const LATEST_CELL_OTHER = re(
  String.raw`最新|当前|現在|최신|[Пп]оследн|[Aa]ktuell|[Nn]eueste|[Úú]ltima|[Dd]erni[èe]re|\b[Aa]ctual\b|[Gg]üncel`,
);
/** A cell that is only "Stable" (or "current stable", "stable release"): the current stable release. */
const STABLE_CELL = re(
  String.raw`(?i)^(?:the[ \t]+)?(?:current[ \t]+|latest[ \t]+)?stable(?:[ \t]+(?:release|version|branch|line))?$`,
);
/** A link that stands for the current version: GitHub's latest release, or the package's page on a registry. */
const LATEST_LINK = re(
  String.raw`(?i)^https?://(?:github\.com/[\w.-]+/[\w.-]+/releases(?:/latest)?|crates\.io/crates/[\w-]+|(?:www\.)?npmjs\.com/package/[@\w./-]+|pypi\.org/project/[\w.-]+|rubygems\.org/gems/[\w.-]+|packagist\.org/packages/[\w./-]+|(?:www\.)?nuget\.org/packages/[\w.-]+|hex\.pm/packages/[\w-]+|pkg\.go\.dev/\S+)/?$`,
);
const ALL_CELL = re(
  String.raw`(?i)^(?:all|any|every)[ \t]+(?:supported[ \t]+)?(?:versions?|releases?)\b|^(?:all|any|\*)$|^(?:todas|alle|tous|toutes)\b`,
);
const OLDER_CELL = re(
  String.raw`(?i)^[<≤][ \t]*(?:the[ \t]+)?(?:latest|current)|\b(?:older|earlier|previous|prior|past|legacy|other|old|anything[ \t]+(?:else|older))\b`,
);
const OLDER_CELL_OTHER = re(
  String.raw`旧|更早|以前|以下|[ÄäAa]ltere|[Aa]nteriores|[Aa]nciennes|[Сс]тарые|[Ee]ski|その他|이전`,
);
const BRANCH_CELL = re(
  String.raw`(?i)\b(?:main|master|develop(?:ment)?|dev|trunk|head|default[ \t]+branch|nightly|edge|canary|next|unstable|rolling|beta|alpha|preview|rc|snapshot)\b`,
);

export type Spec =
  | { kind: 'versions'; test: (v: Version) => boolean; nums: Version[] }
  | { kind: 'latest' | 'all' | 'older' | 'branch' | 'unknown' };

function lineOf(nums: string): { spec: Version; wild: boolean } {
  const parts = nums.split('.');
  const spec: Version = [];
  let wild = false;
  for (const p of parts) {
    if (/^\d+$/.test(p)) spec.push(Number(p));
    else {
      wild = true;
      break;
    }
  }
  return { spec, wild };
}

/** Whether v is in the line a version names: 5.1.x, 5.1 and 5 name lines; 4.7.0 names the 4.7 line too. */
function inLine(v: Version, spec: Version, wild: boolean): boolean {
  // mastodon's table lists 4.7.0 while it ships 4.7.5: a .0 patch names its line. An exact patch such as 1.0.5
  // covers only itself.
  const line = !wild && spec.length >= 3 && spec[spec.length - 1] === 0 ? spec.slice(0, -1) : spec;
  return line.every((n, k) => (v[k] ?? 0) === n);
}

function tokenTest(m: RegExpExecArray): ((v: Version) => boolean) | null {
  const [, op, nums, plus, word, upper] = m;
  const { spec, wild } = lineOf(nums);
  if (!spec.length) return null;
  if (upper) {
    const hi = lineOf(upper);
    if (!hi.spec.length) return null;
    return (v) => compareVersions(v, spec) >= 0 && (compareVersions(v, hi.spec) <= 0 || inLine(v, hi.spec, hi.wild));
  }
  const below = word && /^(?:older|earlier|below|lower|prior|before)$/i.test(word);
  if (plus || (word && !below)) return (v) => compareVersions(v, spec) >= 0 || inLine(v, spec, wild);
  if (below) return (v) => compareVersions(v, spec) <= 0 || inLine(v, spec, wild);
  switch (op) {
    case '>=':
    case '=>':
    case '≥':
      return (v) => compareVersions(v, spec) >= 0;
    case '>':
      // "> 9.x.x" means after the 9 line.
      return wild ? (v) => compareVersions(v, spec) > 0 && !inLine(v, spec, wild) : (v) => compareVersions(v, spec) > 0;
    case '<=':
    case '=<':
    case '≤':
      return (v) => compareVersions(v, spec) <= 0 || inLine(v, spec, wild);
    case '<':
      return (v) => compareVersions(v, spec) < 0 && !inLine(v, spec, wild && spec.length < 2);
    case '^':
      return (v) => v[0] === spec[0] && compareVersions(v, spec) >= 0;
    case '~':
      // ~1.2 stays on 1.2; ~20.x.x stays on 20.
      return spec.length < 2
        ? (v) => v[0] === spec[0] && compareVersions(v, spec) >= 0
        : (v) => v[0] === spec[0] && (v[1] ?? 0) === spec[1] && compareVersions(v, spec) >= 0;
  }
  return (v) => inLine(v, spec, wild);
}

/** A version cell, read: one or more versions or ranges, or words for the latest, all, older or a branch. */
export function cellSpec(cell: string): Spec {
  const notes: string[] = [];
  let main = '';
  let depth = 0;
  let note = '';
  for (const c of cell) {
    if (c === '(' || c === '[') {
      depth++;
      if (depth === 1) {
        note = '';
        continue;
      }
    } else if ((c === ')' || c === ']') && depth > 0) {
      depth--;
      if (depth === 0) {
        notes.push(note);
        continue;
      }
    }
    if (depth) note += c;
    else main += c;
  }
  const versions = (s: string): Spec | null => {
    const tests: ((v: Version) => boolean)[] = [];
    const nums: Version[] = [];
    for (const m of finditer(VERSION_TOKEN, s)) {
      const t = tokenTest(m);
      if (t) {
        tests.push(t);
        nums.push(lineOf(m[2]).spec);
      }
    }
    return tests.length ? { kind: 'versions', test: (v) => tests.some((t) => t(v)), nums } : null;
  };
  const rest = notes.join(' ');
  if (search(OLDER_CELL, main) && /^[<≤]/.test(main.trim())) return { kind: 'older' };
  const own = versions(main);
  if (own) return own;
  const noted = versions(rest);
  if (noted) return noted;
  if (search(LATEST_CELL, main) || search(LATEST_CELL_OTHER, main)) return { kind: 'latest' };
  if (search(ALL_CELL, main.trim())) return { kind: 'all' };
  if (search(STABLE_CELL, main.trim())) return { kind: 'latest' };
  // A version badge links to the latest release on GitHub or to the package's page on a registry.
  if (search(LATEST_LINK, main.trim())) return { kind: 'latest' };
  if (search(OLDER_CELL, main) || search(OLDER_CELL_OTHER, main)) return { kind: 'older' };
  if (search(LATEST_CELL, rest) || search(LATEST_CELL_OTHER, rest)) return { kind: 'latest' };
  if (search(BRANCH_CELL, main) || search(BRANCH_CELL, rest)) return { kind: 'branch' };
  return { kind: 'unknown' };
}

/** Whether a version cell covers v. Null when the cell isn't one the scan can read (a branch, a word it doesn't know). */
export function covers(cell: string | Spec, v: Version): boolean | null {
  const s = typeof cell === 'string' ? cellSpec(cell) : cell;
  if (s.kind === 'versions') return s.test(v);
  if (s.kind === 'latest' || s.kind === 'all') return true;
  if (s.kind === 'older') return false;
  return null;
}

/** How a version is numbered: semantic-style, a calendar year (2025.10), or a date or build number (20250814, b6123). */
export function scheme(v: Version): 'semver' | 'calendar' | 'build' {
  if (v[0] >= 1990 && v[0] <= 2200) return 'calendar';
  if (v[0] >= 10000 || (v.length === 1 && v[0] >= 1000)) return 'build';
  return 'semver';
}

// -------------------------------------------------------------------------------------------- tables
export interface Row {
  /** The version cell as written. */
  version: string;
  spec: Spec;
  status: Status;
  /** The status cell the verdict came from, as written. */
  statusText: string;
  component: string | null;
  /** Whether the table is given as an example. */
  example: boolean;
}

interface Columns {
  version: number;
  component: number | null;
  /** Status columns, most telling first, each marked when it holds end dates or is about security. */
  status: { index: number; until: boolean; security?: boolean }[];
}

function columnsOf(header: string[] | null, width: number): Columns {
  if (!header) {
    return {
      version: 0,
      component: null,
      status: [...Array(Math.max(width - 1, 0)).keys()].map((k) => ({ index: k + 1, until: false })),
    };
  }
  const first = search(COMPONENT_HEADER, header[0] ?? '') ? 1 : 0;
  let version = header.findIndex((h, k) => k >= first && hit(VERSION_HEADER, h) && !hit(SECURITY_HEADER, h));
  if (version < 0) version = header.findIndex((h) => hit(VERSION_HEADER, h) && !hit(SECURITY_HEADER, h));
  const component = first && version > 0 ? 0 : null;
  if (version < 0) version = 0;
  const ranked: { index: number; until: boolean; rank: number }[] = [];
  header.forEach((h, k) => {
    if (k === version || k === component) return;
    const until = !!hit(UNTIL_HEADER, h);
    let rank: number;
    if (hit(SECURITY_HEADER, h) && !hit(NOTES_HEADER, h)) rank = 1;
    else if (hit(OTHER_HEADER, h) && !until) rank = hit(NOTES_HEADER, h) ? 5 : -1;
    else if (hit(SUPPORTED_HEADER, h)) rank = 2;
    else if (hit(STATUS_HEADER, h)) rank = 3;
    else if (until) rank = 4;
    else rank = -1;
    if (rank > 0) ranked.push({ index: k, until, rank });
  });
  ranked.sort((a, b) => a.rank - b.rank || a.index - b.index);
  return {
    version,
    component,
    status: ranked.map(({ index, until, rank }) => ({ index, until, security: rank === 1 })),
  };
}

/** Whether a headerless table's first row is its header (Version | Supported). */
function looksLikeHeader(row: string[]): boolean {
  return (
    !!hit(VERSION_HEADER, row[0] ?? '') &&
    row.slice(1).some((c) => hit(SUPPORTED_HEADER, c) || hit(STATUS_HEADER, c) || hit(UNTIL_HEADER, c))
  );
}

function rowsOf(t: Table, example: boolean, now: Date): Row[] {
  let header = t.header;
  let body = t.rows;
  if (!header && body.length && looksLikeHeader(body[0])) [header, body] = [body[0], body.slice(1)];
  let width = header?.length ?? 0;
  for (const r of body) width = Math.max(width, r.length);
  const cols = columnsOf(header, width);
  const out: Row[] = [];
  for (const r of body) {
    const version = (r[cols.version] ?? '').trim();
    if (!version || /^:?-+:?$/.test(version)) continue;
    let status: Status = 'unknown';
    let statusText = '';
    const untilPast = cols.status.some(
      (c) => c.until && untilStatus(r[c.index] ?? '', now) === 'no' && endDate(r[c.index] ?? ''),
    );
    let bySecurity = false;
    for (const c of cols.status) {
      const cell = (r[c.index] ?? '').trim();
      const st = c.until ? untilStatus(cell, now) : statusOf(cell, now);
      if (!statusText && cell) statusText = cell;
      if (st !== 'unknown') {
        status = st;
        statusText = cell || statusText;
        bySecurity = !!c.security;
        break;
      }
    }
    // A past end date in another column overrides a stale "yes", but not a security column's own answer: in
    // "| 8.3 | Active support until 2025 | Security support until 2027 |" the security column decides.
    if (status === 'yes' && untilPast && !bySecurity) status = 'no';
    out.push({
      version,
      spec: cellSpec(version),
      status,
      statusText,
      component: cols.component !== null ? (r[cols.component] ?? '').trim() : null,
      example,
    });
  }
  return out;
}

/** Whether a table's header (or headerless first row) is a versions table's: a version column and a status column. */
function versionsTable(t: Table): boolean {
  const head = t.header ?? t.rows[0] ?? [];
  return (
    head.some((h) => hit(VERSION_HEADER, h)) &&
    head.some((h) => hit(SUPPORTED_HEADER, h) || hit(STATUS_HEADER, h) || hit(UNTIL_HEADER, h))
  );
}

export interface Support {
  /** A supported-versions section, or a versions table outside one. */
  section: boolean;
  /** The rows of its tables, readable or not. */
  rows: Row[];
  /** It still has the versions table from GitHub's template. */
  template: boolean;
  /** It says which versions get fixes in a sentence. */
  prose: boolean;
  /** It has a table in the section, but no row the scan could read. */
  unreadTable: boolean;
}

/**
 * Whether text has a sentence that says what follows is an example: one that starts with "For example" (or "e.g.")
 * or ends with a colon. "Patches go to the latest minor, for example 2.4." gives an example of a number, not a table.
 */
function givesExample(text: string): boolean {
  if (!search(EXAMPLE, text)) return false;
  for (const m of finditer(EXAMPLE, text)) {
    const before = text.slice(0, m.index);
    const lead = before.slice(
      Math.max(before.lastIndexOf('. '), before.lastIndexOf('! '), before.lastIndexOf('? ')) + 1,
    );
    const rest = text.slice(m.index + m[0].length).split(/(?<=[.!?])\s/)[0];
    if (!/[\p{L}\p{N}]/u.test(lead) || rest.trimEnd().endsWith(':')) return true;
  }
  return false;
}

/** The supported-versions section of a policy, read. */
export function readSupport(p: Policy, now: Date = new Date()): Support {
  const secs = [...sections(p, SUPPORT_HEADING), ...sections(p, SUPPORT_HEADING_OTHER)].sort(
    (a, b) => a.start - b.start,
  );
  const tables: { t: Table; example: boolean }[] = [];
  const seen = new Set<number>();
  // The lines that say what follows is an example ("For example, ..."), anywhere in the section before a table.
  const examples: number[] = [];
  p.lines.forEach((l, i) => {
    if (givesExample(l) || (i + 1 < p.lines.length && givesExample(`${l} ${p.lines[i + 1]}`))) examples.push(i);
  });
  const exampleBefore = (t: Table, from: number) => {
    let lo = 0;
    let hi = examples.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (examples[mid] < from) lo = mid + 1;
      else hi = mid;
    }
    return lo < examples.length && examples[lo] < t.line;
  };
  for (const s of secs) {
    for (const t of s.tables) {
      if (seen.has(t.line)) continue;
      seen.add(t.line);
      tables.push({ t, example: exampleBefore(t, s.start) });
    }
  }
  for (const t of p.tables) {
    if (seen.has(t.line) || !versionsTable(t)) continue;
    seen.add(t.line);
    // A table outside a supported-versions section: the section it's in starts at the heading above it.
    let lo = 0;
    let hi = p.headings.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (p.headings[mid].line < t.line) lo = mid + 1;
      else hi = mid;
    }
    tables.push({ t, example: exampleBefore(t, lo > 0 ? p.headings[lo - 1].line + 1 : 0) });
  }
  const rows = tables.flatMap(({ t, example }) => rowsOf(t, example, now));
  const readable = rows.filter((r) => r.spec.kind !== 'unknown');
  const template =
    !!search(TEMPLATE_SENTENCE, p.text) &&
    ['5.1.x', '5.0.x', '4.0.x', '< 4.0'].every((x) => rows.some((r) => r.version === x));
  return {
    section: secs.length > 0 || tables.length > 0,
    rows,
    template,
    prose: !!search(SUPPORT_PROSE, p.text),
    unreadTable: tables.length > 0 && !readable.length,
  };
}

/** The supported-versions section of a policy's text: kept for callers that have the text, not a Policy. */
export function supportTable(
  text: string,
  now: Date = new Date(),
  path = 'SECURITY.md',
): { section: boolean; rows: { version: string; supported: boolean }[]; template: boolean } {
  const s = readSupport(readPolicy(text, path), now);
  return {
    section: s.section,
    rows: s.rows.map((r) => ({ version: r.version, supported: r.status === 'yes' })),
    template: s.template,
  };
}

// ------------------------------------------------------------------------------------------ releases
/** A tag's version: a prefix (v, release-, name-v, @scope/pkg@), numbers separated by dots or underscores, the rest. */
const TAG_VERSION = re(String.raw`^(.*?)(\d+(?:[._]\d+)*)(.*)$`);
/** What follows the numbers in a pre-release tag (1.2.0-rc.1, 1.2.0b2, 2.0.0-beta). */
const PRERELEASE = re(
  String.raw`(?i)^[-._+]?(?:a|b|rc|alpha|beta|pre|preview|dev|next|canary|nightly|snapshot|m|insiders|experimental|unstable|test|ea)\d*\b`,
);
/** A prefix that marks a tag as a build of a development line (nightly-1794384896, canary-20250101). */
const PRERELEASE_PREFIX = re(
  String.raw`(?i)(?:^|[-_./@])(?:nightly|canary|edge|snapshot|weekly|daily|preview|insiders|unstable|experimental|dev|test|beta|alpha|rc|next|pre)(?:$|[-_./@])`,
);
/** Prefixes that say nothing about which package a tag is for. */
const GENERIC = new Set(['', 'v', 'version', 'ver', 'release', 'releases', 'rel', 'r', 'tag', 'tags', 'stable']);

/** A tag prefix without separators, a trailing v and generic path parts: "dio_v" is dio, "releases/solr/" is solr. */
export function packageOf(prefix: string): string {
  let p = prefix.toLowerCase().trim();
  p = p.replace(/(?:^|[-_./@ ])v$/, '').replace(/[-_./@= ]+$/, '');
  const parts = p.split('/').filter((x) => x && !GENERIC.has(x));
  const joined = parts.join('/');
  return GENERIC.has(joined.replace(/[-_.]+$/, '')) ? '' : joined;
}

/** A tag's package, version, and whether it's a stable release; null when it has no version. */
export function tagVersion(tag: string): { prefix: string; version: Version; stable: boolean } | null {
  const m = match(TAG_VERSION, tag.trim());
  if (!m) return null;
  const version = m[2].replaceAll('_', '.').split('.').map(Number);
  const prefix = packageOf(m[1]);
  // A label with a date (community-baseline-2026-10, pga-2026-11-09) marks a snapshot, not a release's version.
  const dated = !!prefix && /^(?:19|20)\d\d$/.test(m[2]) && /^-\d\d(?:-\d\d)?(?!\d)/.test(m[3]);
  return {
    prefix,
    version,
    stable: !dated && !search(PRERELEASE, m[3]) && !search(PRERELEASE_PREFIX, m[1]),
  };
}

const canon = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

export interface Target {
  tag: string;
  version: Version;
  /** The package the release is for ('' for a bare version tag). */
  prefix: string;
}

/**
 * The release to compare the table with: among the given releases (newest first), the stable ones of the repository's
 * main package, and of those the highest version. The main package is the only one, or the one with bare version
 * tags (v1.2.3) or the repository's name (dio_v5.11.1 in cfug/dio). When both are there, they are one project whose
 * tags changed when their highest releases have the same major version (grub's 2.02 and grub-2.16, dubbo's
 * dubbo-3.3.6 and 3.3.7), and the highest counts; otherwise two (LibreChat's v0.8.8 and its Helm chart's
 * librechat-1.8.9, kepler.gl's v3.2.6 and its Python package's keplergl==0.4.0), and the one with more releases is
 * the main one. When the releases are for several packages and none is the main one, `mixed` lists them.
 */
export function releaseLine(
  tags: { tag: string; prerelease?: boolean }[],
  repoName = '',
): { target: Target | null; mixed: string[] | null } {
  const stable = tags
    .filter((t) => !t.prerelease)
    .map((t) => ({ tag: t.tag, v: tagVersion(t.tag) }))
    .filter((t): t is { tag: string; v: NonNullable<ReturnType<typeof tagVersion>> } => !!t.v && t.v.stable);
  if (!stable.length) return { target: null, mixed: null };
  const packages = [...new Set(stable.map((t) => t.v.prefix))];
  const name = canon(repoName);
  const main = (p: string) => p === '' || (!!name && (canon(p) === name || canon(p.split('/').pop() ?? '') === name));
  const mains = packages.filter(main);
  const of = (p: string) => stable.filter((t) => t.v.prefix === p);
  const highest = (ts: typeof stable) => ts.reduce((a, b) => (compareVersions(b.v.version, a.v.version) > 0 ? b : a));
  let line = packages.length === 1 ? stable : stable.filter((t) => main(t.v.prefix));
  if (packages.length > 1 && mains.length > 1 && new Set(mains.map((p) => highest(of(p)).v.version[0])).size > 1) {
    const best = mains.reduce((a, b) => (of(b).length > of(a).length ? b : a));
    line = of(best);
  }
  if (!line.length) return { target: null, mixed: packages };
  const top = line.reduce((a, b) => (compareVersions(b.v.version, a.v.version) > 0 ? b : a));
  return { target: { tag: top.tag, version: top.v.version, prefix: top.v.prefix }, mixed: null };
}

/** The release to compare the table with (see releaseLine), or null. */
export function targetRelease(
  tags: { tag: string; prerelease?: boolean }[],
  repoName = '',
): { tag: string; version: Version } | null {
  const t = releaseLine(tags, repoName).target;
  return t ? { tag: t.tag, version: t.version } : null;
}

// ------------------------------------------------------------------------------------------- verdict
export interface Verdict {
  status: 'pass' | 'warn' | 'info' | 'unknown';
  summary: string;
  details: Record<string, unknown>;
}

/** A status cell cut to a readable length for a summary. */
const short = (s: string) => (s.length > 60 ? s.slice(0, 57).trimEnd() + '...' : s);

/** Up to three version cells for a summary; a link to the latest release reads as words. */
const list = (xs: string[]) =>
  [...new Set(xs.map((x) => (search(LATEST_LINK, x.trim()) ? 'the latest release' : x)))].slice(0, 3).join(', ');

/**
 * rel-security-support's result for a policy's support section and the releases. label names the policy;
 * releasesTrouble is the HTTP status when the releases couldn't be read.
 */
export function supportVerdict(
  s: Support,
  line: { target: Target | null; mixed: string[] | null },
  label: string,
  releasesTrouble: number | null,
  repoName = '',
): Verdict {
  const { target, mixed } = line;
  const check = target ? `check it covers ${target.tag}` : 'check it covers your current release';
  const templateTable = (['5.1.x:yes', '5.0.x:no', '4.0.x:yes', '< 4.0:no'] as const).every((x) => {
    const [v, st] = x.split(':');
    return s.rows.some((r) => r.version === v && r.status === st);
  });
  if (s.template || (templateTable && !(target && (target.version[0] === 4 || target.version[0] === 5)))) {
    return {
      status: 'warn',
      summary: `${label} still has the versions table from GitHub's template (5.1.x, 5.0.x, 4.0.x)`,
      details: {},
    };
  }
  const readable = s.rows.filter((r) => r.spec.kind !== 'unknown');
  const statusless = readable.length > 0 && readable.every((r) => r.status === 'unknown' && !r.statusText);
  if (!readable.length || statusless) {
    if (s.unreadTable || statusless) {
      return {
        status: 'info',
        summary: `${label} has a supported-versions table the scan can't read: ${check}`,
        details: {},
      };
    }
    if (s.section || s.prose) {
      return {
        status: 'info',
        summary: `${label} says which versions get fixes in words, not a table: ${check}`,
        details: {},
      };
    }
    return { status: 'info', summary: `${label} doesn't say which versions get security fixes`, details: {} };
  }
  if (!target) {
    if (mixed) {
      return {
        status: 'info',
        summary: `The latest releases are for several packages (${list(mixed)}), and the scan can't tell which one the table in ${label} is for`,
        details: { packages: mixed },
      };
    }
    if (releasesTrouble !== null) {
      return {
        status: 'unknown',
        summary: `Could not read the releases to compare with the table in ${label} (HTTP ${releasesTrouble})`,
        details: {},
      };
    }
    return {
      status: 'info',
      summary: `${label} has a supported-versions table, but there's no stable release to compare it with`,
      details: {},
    };
  }
  // A table with a component column: the rows for the main package, or all of them when they agree.
  let rows = readable;
  const components = [...new Set(readable.map((r) => r.component).filter((c): c is string => !!c))];
  if (components.length > 1) {
    const name = canon(target.prefix || repoName);
    const mine = readable.filter(
      (r) => r.component && (canon(r.component) === name || /^(?:all|core|main)$/i.test(r.component)),
    );
    if (mine.length) rows = mine;
    else {
      const verdicts = new Set(readable.filter((r) => r.status === 'yes').map((r) => covers(r.spec, target.version)));
      if (verdicts.size > 1) {
        return {
          status: 'info',
          summary: `The table in ${label} lists components (${list(components)}) the scan can't tie to the releases: ${check}`,
          details: { target: target.tag },
        };
      }
    }
  }
  const supported = rows.filter((r) => r.status === 'yes');
  const versioned = supported.filter(
    (r) => r.spec.kind === 'versions' || r.spec.kind === 'latest' || r.spec.kind === 'all',
  );
  const covering = versioned.find((r) => covers(r.spec, target.version));
  const details = { target: target.tag, supported: supported.map((r) => r.version) };
  if (covering) {
    return {
      status: 'pass',
      summary: `${label} lists ${list([covering.version])} as supported, which covers the newest release, ${target.tag}`,
      details,
    };
  }
  // From here on the table doesn't plainly cover the newest release; only a plain, readable table that names other
  // versions of the same numbering may warn.
  const unknownCovering = rows.find((r) => r.status === 'unknown' && covers(r.spec, target.version));
  if (unknownCovering) {
    const said = unknownCovering.statusText ? `"${short(unknownCovering.statusText)}"` : 'without a status';
    return {
      status: 'info',
      summary: `${label} marks ${unknownCovering.version} ${said}, which the scan can't read as supported or not: ${check}`,
      details,
    };
  }
  if (!versioned.length) {
    const branches = supported.filter((r) => r.spec.kind === 'branch').map((r) => r.version);
    if (branches.length) {
      return {
        status: 'info',
        summary: `${label} lists ${list(branches)} as supported, a branch rather than a release: ${check}`,
        details,
      };
    }
    const unread = rows.find((r) => r.status === 'unknown' && r.statusText);
    if (unread) {
      return {
        status: 'info',
        summary: `${label} marks ${unread.version} "${short(unread.statusText)}", which the scan can't read as supported or not: ${check}`,
        details,
      };
    }
    const words = s.rows.filter((r) => r.status === 'yes').map((r) => r.version);
    if (words.length) {
      return {
        status: 'info',
        summary: `${label} lists ${list(words)} as supported, which the scan can't tie to a release: ${check}`,
        details,
      };
    }
    return { status: 'info', summary: `${label} marks no version in its table as supported: ${check}`, details };
  }
  // "> 8.0.0" when the newest release is 8.0.0: the table starts its range at that release, so it can't say.
  const edge = versioned.find(
    (r) =>
      /^>\s*v?(\d[\d.]*)/.exec(r.version.trim())?.[1].split('.').map(Number).join('.') === target.version.join('.'),
  );
  if (edge) {
    return {
      status: 'info',
      summary: `${label} lists ${edge.version} as supported, which starts just after the newest release, ${target.tag}: ${check}`,
      details,
    };
  }
  if (rows.some((r) => r.example)) {
    return { status: 'info', summary: `${label} gives its versions table as an example: ${check}`, details };
  }
  const nums = versioned.flatMap((r) => (r.spec.kind === 'versions' ? r.spec.nums : []));
  if (nums.length && !nums.some((n) => scheme(n) === scheme(target.version))) {
    return {
      status: 'info',
      summary: `${label} numbers versions differently from the releases (${list(versioned.map((r) => r.version))} against ${target.tag}): ${check}`,
      details,
    };
  }
  // A supported line newer than the newest release says the releases on GitHub aren't the whole story (a version
  // published elsewhere, or a table written ahead of the release).
  if (nums.some((n) => compareVersions(n, target.version) > 0)) {
    return {
      status: 'info',
      summary: `${label} lists ${list(versioned.map((r) => r.version))} as supported, newer than the newest release on GitHub, ${target.tag}`,
      details,
    };
  }
  return {
    status: 'warn',
    summary: `${label} lists ${list(versioned.map((r) => r.version))} as supported, but the newest release is ${target.tag}`,
    details,
  };
}
