// Reading a security policy (new in 0.5.1). There's no standard for SECURITY.md, so the checks that read one share
// this reader: Markdown, HTML, reStructuredText, AsciiDoc and plain text all become plain text lines with headings,
// links, email addresses and tables. disc-security-md asks it how to report (howToReport), rel-security-support
// reads its tables (versions.ts), and checks that look for response times or disclosure terms can search its
// sections. Nothing here fetches anything: a link to another file in the same repository is only named
// (sameRepoLink), and the scan decides whether to read it.
import { finditer, match, re, search } from './py.ts';

export type Format = 'markdown' | 'rst' | 'asciidoc';

export interface Link {
  text: string;
  url: string;
  /** The lines it's on (indexes into Policy.lines). */
  lines?: number[];
}

export interface Heading {
  text: string;
  /** 1 to 6 for real headings (Markdown #, RST and AsciiDoc titles), 7 for a bold line, 8 for a plain-text line. */
  level: number;
  line: number;
}

export interface Table {
  /** The header row, or null when the table has none the reader could tell. */
  header: string[] | null;
  rows: string[][];
  /** The line the table starts on (an index into Policy.lines). */
  line: number;
  kind: 'pipe' | 'html' | 'grid' | 'simple' | 'list' | 'csv' | 'asciidoc';
}

export interface Section {
  heading: Heading;
  /** The lines after the heading up to the next heading at its level or above: [start, end). */
  start: number;
  end: number;
  text: string;
  tables: Table[];
}

export interface Policy {
  path: string;
  format: Format;
  /** The policy's lines as plain text: markup, comments and table borders removed, one entry per source line. */
  lines: string[];
  text: string;
  headings: Heading[];
  links: Link[];
  emails: string[];
  tables: Table[];
  /** Words outside links and code. */
  words: number;
  /** Whether it reads as English (or has English in it), so a missing phrase means something. */
  english: boolean;
  /** The lines that start a list item, which end the sentence before them. */
  items: number[];
  /** The file was longer than MAX_POLICY, and the reader looked only at its start. */
  truncated: boolean;
}

// ------------------------------------------------------------------------------------------- markup
const FRONT_MATTER = re(String.raw`(?s)\A---[ \t]*\n.*?\n---[ \t]*\n`);
const HTML_COMMENT = re(String.raw`(?s)<!--.*?(?:-->|\Z)`);
const ADOC_BLOCK_COMMENT = re(String.raw`(?ms)^////+[ \t]*\n.*?(?:^////+[ \t]*$|\Z)`);
const ADOC_LINE_COMMENT = re(String.raw`(?m)^//(?!/)[^\n]*$`);
/** An AsciiDoc attribute (:repo-url: https://...) and a reference to one ({repo-url}). */
const ADOC_ATTR_DEF = re(String.raw`(?m)^:([\w-]+):[ \t]+(\S[^\n]*)$`);
const ADOC_ATTR_REF = re(String.raw`\{([\w-]+)\}`);
/** An RST comment: two dots that don't start a directive, a link target, a substitution or a footnote. */
const RST_COMMENT = re(String.raw`^\.\.(?:[ \t]+(?![_|\[])(?!\S+::)[^\n]*)?$`);
const RST_SNIFF = re(
  String.raw`(?m)^\.\. [\w-]+::|^\.\. _[^:\n]+:|^[=\-~^"'*+#]{3,}[ \t]*\n[^\n]+\n[=\-~^"'*+#]{3,}[ \t]*$`,
);
const ADOC_SNIFF = re(String.raw`(?m)^=[ \t]+\S|^\|===[ \t]*$|^\[(?:cols|options|source|NOTE|WARNING)\b`);
const FENCE = re(String.raw`^ {0,3}(` + '```' + String.raw`+|~~~+)`);
// The patterns here run on text anyone can write, so none may take more than linear time: no two quantifiers that can
// match the same characters side by side, and no lazy match followed by optional spaces before the end of the line.
// Trailing spaces and closing marks are trimmed in code instead.
const ATX = re(String.raw`^ {0,3}(#{1,6})(?:[ \t]+(.*))?$`);
const SETEXT = re(String.raw`^ {0,3}(=+|-+)[ \t]*$`);
const RST_LINE = re(String.raw`^([=\-~^"'` + '`' + String.raw`#*+.:_<>!])\1{2,}[ \t]*$`);
const ADOC_TITLE = re(String.raw`^(={1,6})[ \t]+(\S.*)$`);
const BOLD_LINE = re(String.raw`^[ \t]*(?:\*\*|__)(?!\s)([^*_\n]{2,90}?)(?:\*\*|__)[ \t]*(?::[ \t]*)?$`);
const HTML_HEADING_OPEN = re(String.raw`(?i)<h([1-6])\b[^<>]*>`);
const HTML_HEADING_CLOSE = re(String.raw`(?i)</h[1-6][ \t]*>`);
/** A short line that ends with a colon, or one in capitals, which plain-text policies use as headings. */
const PLAIN_HEADING = re(String.raw`^[ \t]*(?:[A-Z][^\n.!?]{1,58}:|[A-Z][A-Z0-9 &/'-]{3,58})[ \t]*$`);
const LIST_ITEM = re(String.raw`^[ \t]*(?:[-*+]|\d+[.)])[ \t]`);

const MD_IMAGE = re(String.raw`!\[[^\[\]\n]*\]\([^()\n]*\)`);
const MD_LINK = re(
  String.raw`\[((?:[^\[\]\n]|\[[^\[\]\n]*\])*)\]\(\s*<?([^\s<>()]+(?:\([^\s()]*\)[^\s<>()]*)*)>?(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?\s*\)`,
);
const MD_REF_DEF = re(
  String.raw`(?m)^ {0,3}\[([^\]\n]+)\]:[ \t]*<?(\S+?)>?(?:[ \t]+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?[ \t]*$`,
);
const MD_REF_USE = re(String.raw`\[([^\[\]\n]+)\](?:\[([^\[\]\n]*)\])?`);
const AUTOLINK = re(String.raw`<((?:https?|mailto):[^\s<>]+)>`);
const ANGLE_EMAIL = re(String.raw`<([\w.%+-]+@[\w-]+(?:\.[\w-]+)+)>`);
const BARE_URL = re(
  String.raw`\bhttps?://[^\s<>"'` + '`' + String.raw`\]\[(){}|\\^]+(?:\([^\s<>"'()]*\)[^\s<>"'()\]\[]*)*`,
);
/** An HTML link: the <a> tag's attributes (where HREF finds the target) and its content. */
const HTML_A = re(String.raw`(?is)<a\b([^<>]*)>((?:(?!<a\b).)*?)</a[ \t]*>`);
const HREF = re(String.raw`(?i)\bhref[ \t]*=[ \t]*["']([^"'<>]+)["']`);
/** An HTML tag. <at> and <dot> aren't: they spell out an email address. */
const HTML_TAG = re(String.raw`(?s)</?(?!(?:at|dot|AT|DOT)>)[A-Za-z][\w:-]*(?:\s[^<>]*)?/?>`);
const HTML_BREAK = re(
  String.raw`(?i)<br\s*/?>|</?(?:p|div|li|tr|table|thead|tbody|ul|ol|h[1-6]|details|summary|blockquote)\b[^<>]*>`,
);
const ENTITY = re(String.raw`&(#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z]{2,8});`);
/** `text <url>`_ (group 1 keeps the spaces before the <, which the code trims). */
const RST_LINK = re(
  String.raw`` +
    '`' +
    String.raw`([^` +
    '`' +
    String.raw`<\n]*)<([^` +
    '`' +
    String.raw`<>\n]+)>` +
    '`' +
    String.raw`__?`,
);
const RST_TARGET = re(String.raw`(?m)^\.\.[ \t]+_([^:\n]+):[ \t]*(\S+)[ \t]*$`);
const RST_NAMED_REF = re('`' + String.raw`([^` + '`' + String.raw`\n]+)` + '`' + String.raw`_(?!_)`);
/** :role:`text`, which starts where a run of colons and names starts (so a long run of them is read once). */
const RST_ROLE = re(
  String.raw`(?<![\w:-]):[\w-]+(?::[\w-]+)*:` + '`' + String.raw`([^` + '`' + String.raw`\n]*)` + '`',
);
/**
 * link:url[text], url[text], mailto:addr[text] and xref:file[text]. It starts only after a space or one of the marks a
 * target can't hold, so no match starts inside another's target and a long run of "link:link:link:" is read once.
 */
const ADOC_LINK = re(
  String.raw`(?<![^\s(<>"'|*,;])(?:(?:link|mailto|xref):)?((?:https?://|mailto:)[^\s\[\](<>"'|*,;]+|(?<=link:)[^\s\[\](<>"'|*,;]+|(?<=xref:)[^\s\[\](<>"'|*,;]+)\[([^\[\]\n]*)\]`,
);
const ADOC_XREF = re(String.raw`<<([^,<>\n]+)(?:,([^<>\n]*))?>>`);
const EMPHASIS = re(String.raw`(?<![\w*])(\*{1,3}|_{1,3})(?=\S)([^*_\n]*?\S)\1(?![\w*])`);
const STRIKE = re(String.raw`~~(.*?)~~`);
const ADMONITION = re(String.raw`^[ \t]*(?:>[ \t]*)+(?:\[!(?:NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*)?`);
const LIST_MARK = re(String.raw`^[ \t]*(?:[-*+]|\d+[.)])[ \t]+`);
const ADOC_ATTR_LINE = re(
  String.raw`^\[[^\]\n]*\][ \t]*$|^:[\w-]+:.*$|^(?:----|\.\.\.\.|\+\+\+\+|____|\*\*\*\*)[ \t]*$`,
);
const RST_DIRECTIVE = re(String.raw`^[ \t]*\.\.[ \t]+[\w-]+::[ \t]*`);
const RST_FIELD = re(String.raw`^[ \t]*:[\w -]+:[ \t]*`);

// -------------------------------------------------------------------------------------------- tables
const PIPE_SEPARATOR = re(String.raw`^[ \t]*(?:\|[ \t]*)?:?-+:?[ \t]*(?:\|[ \t]*:?-+:?[ \t]*)*(?:\|[ \t]*)?$`);
const GRID_BORDER = re(String.raw`^[ \t]*\+(?:[-=]+\+)+[ \t]*$`);
const SIMPLE_BORDER = re(String.raw`^[ \t]*=+(?:[ \t]+=+)+[ \t]*$`);
const LIST_TABLE = re(String.raw`^[ \t]*\.\.[ \t]+list-table::`);
const CSV_TABLE = re(String.raw`^[ \t]*\.\.[ \t]+csv-table::`);
const HEADER_ROWS = re(String.raw`^[ \t]*:header-rows:[ \t]*(\d+)`);
const CSV_HEADER = re(String.raw`^[ \t]*:header:[ \t]*(.*)$`);
const LIST_ROW = re(String.raw`^([ \t]*)\*[ \t]+-[ \t]*(.*)$`);
const LIST_CELL = re(String.raw`^([ \t]*)-[ \t]+(.*)$`);
const ADOC_FENCE = re(String.raw`^[ \t]*\|===[ \t]*$`);
const ADOC_TABLE_ATTRS = re(String.raw`^\[(.*)\][ \t]*$`);
const ADOC_COLS = re(String.raw`cols[ \t]*=[ \t]*"([^"]*)"`);
const ADOC_HEADER_OPTION = re(String.raw`options[ \t]*=[ \t]*"[^"]*header|%header`);
const ADOC_CELL = re(String.raw`(?:^|(?<=\s))(?:\d+(?:\.\d+)?\+|\d+\*)?[<^>]?(?:\.[<^>])?[ademhlsv]?\|`);
const HTML_TABLE_OPEN = re(String.raw`(?i)<table\b`);
const HTML_TABLE_CLOSE = re(String.raw`(?i)</table\s*>`);
const HTML_ROW = re(String.raw`(?is)<tr\b[^<>]*>(.*?)(?=<tr\b|</tbody|</thead|</table|$)`);
const HTML_CELL = re(String.raw`(?is)<t([hd])\b[^<>]*>(.*?)(?=<t[hd]\b|</tr|$)`);
const HTML_THEAD = re(String.raw`(?is)<thead\b`);
const HTML_THEAD_END = re(String.raw`(?i)</thead`);

// ------------------------------------------------------------------------------------- addresses
/** An email address. One right after : or / is a URL's user (postgres://user:password@host), not an address. */
const EMAIL = re(
  String.raw`(?<![\w.%+:/-])([A-Za-z0-9][\w.%+-]*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24})(?![\w@-])`,
);
/** An address after mailto: written out in the text, without a link. */
const MAILTO_TEXT = re(String.raw`(?i)\bmailto:([\w.%+-]+@[\w-]+(?:\.[\w-]+)+)`);
/** An address written so bots can't read it: name [at] example [dot] org, name AT example.org, name(@)example.org. */
const OBFUSCATED_EMAIL = re(
  String.raw`(?i)(?<![\w.+-])([a-z0-9][\w.+-]*)[ \t]*(?:[\[({<][ \t]*(?:at|@)[ \t]*[\])}>]|\uff20)[ \t]*([a-z0-9][\w-]*(?:[ \t]+-[ \t]+[a-z0-9][\w-]*)*(?:[ \t]*(?:[\[({<][ \t]*(?:dot|\.)[ \t]*[\])}>]|\.)[ \t]*[a-z0-9][\w-]*)+)`,
);
/** name at example dot org, or name AT example.org: the bare word "at" needs a "dot" or capitals to count. */
const SPELLED_EMAIL = re(
  String.raw`(?<![\w.+-])([A-Za-z0-9][\w.+-]*)[ \t]+(?:AT|at)[ \t]+([A-Za-z0-9][\w-]*(?:[ \t]+(?:DOT|dot)[ \t]+[A-Za-z0-9][\w-]*)+)(?![\w-])`,
);
/** name AT example.org, in capitals, or security at example.org when the name is an inbox's. */
const SPELLED_AT = re(
  String.raw`(?<![\w.+-])([A-Za-z0-9][\w.+-]*)[ \t]+AT[ \t]+([A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+)(?![\w-])|(?<![\w.+-])(?=[\w.+-]*?(?:secur|vuln|abuse|psirt|cert|info|contact|support|report|disclos|admin|team|hello|maint|oss))([\w.+-]+)[ \t]+at[ \t]+([A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+)(?![\w-])`,
);
/** reported to: name at example.org, or a line that is only name at example.org. */
const SPELLED_TO = re(
  String.raw`(?im)(?:\b(?:to|e-?mail|mail|contact)[: \t]+|^[ \t]*)([A-Za-z0-9][\w.+-]*)[ \t]+at[ \t]+([A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+)(?:[ \t]*$|(?=[ \t]*[.,;)]))`,
);
/** name @ example.org, with spaces around the @. */
const SPACED_AT = re(
  String.raw`(?<![\w.+-])([A-Za-z0-9][\w.+-]*)[ \t]+@[ \t]+([A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+)`,
);
/** name at gmail com: a common provider or top-level domain after spaces instead of dots. */
const SPELLED_SPACED = re(
  String.raw`(?<![\w.+-])([A-Za-z0-9][\w.+-]*)[ \t]+(?:at|AT)[ \t]+([A-Za-z0-9][\w-]*)[ \t]+(com|org|net|io|dev|de|fr|nl|uk|eu|ch|me|info)\b(?!\.\w|@)`,
);
/** name ``at'' example.com, or name "at" example.com: an "at" in quotes. */
const QUOTED_AT = re(
  String.raw`(?<![\w.+-])([A-Za-z0-9][\w.+-]*)[ \t]*[\x60'"\u2018\u2019\u201c\u201d]+[ \t]*(?:at|AT)[ \t]*[\x60'"\u2018\u2019\u201c\u201d]+[ \t]*([A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+)`,
);
/** An address with a one-word domain (name@host), which counts only in a sentence about reports. */
const SHORT_EMAIL = re(String.raw`(?<![\w.%+-])([A-Za-z0-9][\w.%+-]*@[A-Za-z][A-Za-z0-9-]{2,})(?![\w@-])(?!\.\w)`);
/** Addresses that can't receive mail (RFC 2606) or aren't an inbox: a template's placeholder, a git remote. */
const NOT_AN_INBOX = re(
  String.raw`(?i)@(?:[\w-]+\.)*(?:example\.(?:com|org|net)|[\w-]+\.(?:example|test|invalid|localhost)|localhost|(?:your|my)-?(?:domain|company|email|project)[\w.-]*|domain\.(?:com|tld)|email\.com)$|^git@(?:github|gitlab|bitbucket)\.(?:com|org)$|^(?:noreply|no-reply|donotreply)@|@users\.noreply\.github\.com$|\.(?:png|jpe?g|gif|svg|webp)$`,
);

const ENGLISH = re(
  String.raw`(?i)\b(?:the|and|please|report|reports|reporting|security|vulnerabilit(?:y|ies)|we|you|your|issue|issues|version|versions|supported|email|contact|with|this|that|will|not|for)\b`,
);

const ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  mdash: '—',
  ndash: '–',
  hellip: '…',
  rsquo: '’',
  lsquo: '‘',
  rdquo: '”',
  ldquo: '“',
  copy: '©',
};

/** Replace every match of rx in s with what fn returns (re.sub with a function). */
function replaceAll(rx: RegExp, s: string, fn: (m: RegExpExecArray) => string): string {
  let out = '';
  let last = 0;
  for (const m of finditer(rx, s)) {
    out += s.slice(last, m.index) + fn(m);
    last = m.index + m[0].length;
  }
  return out + s.slice(last);
}

/** The same text with each match blanked out, keeping its line breaks so line numbers don't move. */
function blank(rx: RegExp, s: string): string {
  return replaceAll(rx, s, (m) => m[0].replace(/[^\n]/g, ''));
}

/** s without the characters in chars at its end (a loop: /[.,]+$/ takes time squared on a long run of them). */
function trimEndOf(s: string, chars: string): string {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1])) end--;
  return s.slice(0, end);
}

/**
 * Each code span (`code`, ``code``) replaced with what fn returns for its content. A span closes at the next run of
 * exactly as many backticks, as in CommonMark; found by a scan instead of a pattern, which would take time squared on
 * a long run of backticks.
 */
function codeSpans(t: string, fn: (code: string) => string): string {
  if (!t.includes('`')) return t;
  const runs: { at: number; len: number }[] = [];
  for (let i = 0; i < t.length;) {
    if (t[i] !== '`') {
      i++;
      continue;
    }
    let j = i;
    while (j < t.length && t[j] === '`') j++;
    runs.push({ at: i, len: j - i });
    i = j;
  }
  // For each run, the next run of the same length.
  const next = new Array<number>(runs.length).fill(-1);
  const seen = new Map<number, number>();
  for (let k = runs.length - 1; k >= 0; k--) {
    next[k] = seen.get(runs[k].len) ?? -1;
    seen.set(runs[k].len, k);
  }
  let out = '';
  let pos = 0;
  for (let k = 0; k < runs.length;) {
    const close = next[k];
    if (close < 0) {
      k++;
      continue;
    }
    const open = runs[k];
    out += t.slice(pos, open.at) + fn(t.slice(open.at + open.len, runs[close].at));
    pos = runs[close].at + runs[close].len;
    k = close + 1;
  }
  return out + t.slice(pos);
}

/** An ATX heading's text without its closing #s (## Title ##) or a {#id} after it. */
function atxText(s: string): string {
  let t = s.trimEnd();
  let k = t.length;
  while (k > 0 && t[k - 1] === '#') k--;
  if (k < t.length && (k === 0 || t[k - 1] === ' ' || t[k - 1] === '\t')) t = t.slice(0, k).trimEnd();
  if (t.endsWith('}')) {
    const open = t.lastIndexOf('{#');
    if (open >= 0 && /^[\w-]+$/.test(t.slice(open + 2, -1))) t = t.slice(0, open).trimEnd();
  }
  return t;
}

/** The first HTML heading on a line (<h2>Supported versions</h2>): its level and its content. */
function htmlHeading(line: string): { level: number; inner: string } | null {
  const open = search(HTML_HEADING_OPEN, line);
  if (!open) return null;
  const from = open.index + open[0].length;
  const close = search(HTML_HEADING_CLOSE, line.slice(from));
  if (!close) return null;
  return { level: Number(open[1]), inner: line.slice(from, from + close.index) };
}

function decodeEntities(s: string): string {
  return replaceAll(ENTITY, s, (m) => {
    const e = m[1];
    if (e.startsWith('#x') || e.startsWith('#X'))
      return String.fromCodePoint(Math.min(parseInt(e.slice(2), 16), 0x10ffff));
    if (e.startsWith('#')) return String.fromCodePoint(Math.min(parseInt(e.slice(1), 10), 0x10ffff));
    return ENTITIES[e.toLowerCase()] ?? m[0];
  });
}

/** The policy's format, from its extension, or from its content for .txt and no extension. */
export function formatOf(path: string, text: string): Format {
  const name = path.slice(path.lastIndexOf('/') + 1).toLowerCase();
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : '';
  if (ext === 'md' || ext === 'markdown') return 'markdown';
  if (ext === 'rst') return 'rst';
  if (ext === 'adoc' || ext === 'asciidoc') return 'asciidoc';
  if (search(RST_SNIFF, text)) return 'rst';
  if (search(ADOC_SNIFF, text)) return 'asciidoc';
  // Plain text reads fine as Markdown.
  return 'markdown';
}

/** Comments and front matter removed (as blank lines), line endings normalized. */
function prepare(raw: string, format: Format): string {
  let s = raw.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  s = blank(FRONT_MATTER, s);
  s = blank(HTML_COMMENT, s);
  if (format === 'asciidoc') {
    s = blank(ADOC_BLOCK_COMMENT, s);
    s = blank(ADOC_LINE_COMMENT, s);
    const attrs = new Map(finditer(ADOC_ATTR_DEF, s).map((m) => [m[1], m[2].trimEnd()]));
    if (attrs.size) s = replaceAll(ADOC_ATTR_REF, s, (m) => attrs.get(m[1]) ?? m[0]);
  }
  if (format === 'rst') {
    const lines = s.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (!match(RST_COMMENT, lines[i])) continue;
      lines[i] = '';
      // The comment goes on through the indented lines after it.
      for (let j = i + 1; j < lines.length && (lines[j] === '' || /^[ \t]/.test(lines[j])); j++) {
        if (lines[j] === '' && (j + 1 >= lines.length || !/^[ \t]/.test(lines[j + 1]))) break;
        lines[j] = '';
        i = j;
      }
    }
    s = lines.join('\n');
  }
  return s;
}

/** A line's text without markup: links keep their text, HTML tags and emphasis go. */
export function inline(s: string, format: Format = 'markdown'): string {
  // Each pattern runs only when the text has the character it starts with: most lines have no markup at all.
  // Backslash-escaped punctuation is literal: set it aside so no markup pattern reads it, and put it back after.
  let t = s.includes('\\')
    ? s.replace(/\\([\\`*_{}[\]()#+\-.!|<>~])/g, (_, c: string) => String.fromCharCode(0xe000 + c.charCodeAt(0)))
    : s;
  const tick = t.includes('`');
  const lt = t.includes('<');
  if (format === 'rst' && tick) {
    t = replaceAll(RST_LINK, t, (m) => m[1].trim() || m[2]);
    t = replaceAll(RST_ROLE, t, (m) => m[1].replace(/<[^<>]*>$/, '').trimEnd());
    t = replaceAll(RST_NAMED_REF, t, (m) => m[1]);
  }
  if (format === 'asciidoc') {
    if (t.includes('[')) {
      t = replaceAll(ADOC_LINK, t, (m) =>
        m[2] ? m[2].replace(/\^$/, '').split(',')[0] : m[1].replace(/^mailto:/, ''),
      );
    }
    if (t.includes('<<')) t = replaceAll(ADOC_XREF, t, (m) => m[2] || m[1]);
  }
  if (t.includes('![')) t = replaceAll(MD_IMAGE, t, () => '');
  if (t.includes('](')) t = replaceAll(MD_LINK, t, (m) => (m[1].trim() ? m[1] : m[2].replace(/^mailto:/i, '')));
  if (lt) {
    t = replaceAll(AUTOLINK, t, (m) => m[1].replace(/^mailto:/i, ''));
    t = replaceAll(ANGLE_EMAIL, t, (m) => m[1]);
    t = replaceAll(HTML_A, t, (m) => (search(HREF, m[1]) ? m[2] : m[0]));
    t = replaceAll(HTML_BREAK, t, () => ' ');
    t = replaceAll(HTML_TAG, t, () => '');
  }
  if (t.includes('&')) t = decodeEntities(t);
  t = codeSpans(t, (code) => code);
  if (t.includes('~~')) t = replaceAll(STRIKE, t, (m) => m[1]);
  if (t.includes('*') || t.includes('_')) for (let k = 0; k < 2; k++) t = replaceAll(EMPHASIS, t, (m) => m[2]);
  t = t.replace(/[\ue000-\ue07f]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xe000));
  return t.replace(/[ \t\u00a0]+/g, ' ').trim();
}

// ------------------------------------------------------------------------------------------ headings
function headingsOf(src: string[], format: Format, code: boolean[]): { headings: Heading[]; underline: Set<number> } {
  const headings: Heading[] = [];
  const underline = new Set<number>();
  const rstStyles: string[] = [];
  const rstLevel = (style: string) => {
    if (!rstStyles.includes(style)) rstStyles.push(style);
    return Math.min(rstStyles.indexOf(style) + 1, 6);
  };
  for (let i = 0; i < src.length; i++) {
    if (code[i] || underline.has(i)) continue;
    const line = src[i];
    const t = line.trim();
    if (!t) continue;
    const next = i + 1 < src.length && !code[i + 1] ? src[i + 1] : '';
    let m: RegExpExecArray | null;
    if (format === 'asciidoc' && (m = match(ADOC_TITLE, line))) {
      headings.push({ text: inline(m[2].trimEnd(), format), level: m[1].length, line: i });
      continue;
    }
    if ((m = match(ATX, line)) && format !== 'rst') {
      const text = inline(atxText(m[2] ?? ''), format);
      if (text) headings.push({ text, level: m[1].length, line: i });
      continue;
    }
    if (format === 'rst' && match(RST_LINE, line) && next.trim() && i + 2 < src.length && match(RST_LINE, src[i + 2])) {
      // A title with an overline and an underline.
      headings.push({ text: inline(next, format), level: rstLevel('o' + line.trim()[0]), line: i + 1 });
      underline.add(i);
      underline.add(i + 2);
      i += 2;
      continue;
    }
    const isBorder = match(RST_LINE, line) || match(SETEXT, line);
    if (!isBorder && !t.startsWith('|') && !match(LIST_ITEM, line) && !search(GRID_BORDER, line)) {
      const um = format === 'rst' ? match(RST_LINE, next) : match(SETEXT, next);
      if (um && next.trim().length >= Math.min(3, t.length)) {
        const level = format === 'rst' ? rstLevel('u' + next.trim()[0]) : next.trim()[0] === '=' ? 1 : 2;
        headings.push({ text: inline(t, format), level, line: i });
        underline.add(i + 1);
        continue;
      }
    }
    const h = htmlHeading(line);
    if (h) {
      const text = inline(h.inner, format);
      if (text) headings.push({ text, level: h.level, line: i });
      continue;
    }
    if ((m = match(BOLD_LINE, line))) {
      headings.push({ text: inline(m[1], format), level: 7, line: i });
      continue;
    }
    const prevBlank = i === 0 || !src[i - 1].trim();
    if (prevBlank && match(PLAIN_HEADING, line) && !match(LIST_ITEM, line) && t.split(/\s+/).length <= 7) {
      headings.push({ text: inline(t.replace(/:$/, ''), format), level: 8, line: i });
    }
  }
  return { headings, underline };
}

// -------------------------------------------------------------------------------------------- tables
/** Whether a line is a pipe table's separator row (| --- | :-: |). */
function separator(line: string): boolean {
  return line.includes('-') && !!match(PIPE_SEPARATOR, line);
}

function splitPipes(line: string): string[] {
  let t = line.trim();
  if (t.startsWith('|')) t = t.slice(1);
  if (t.endsWith('|') && !t.endsWith('\\|')) t = t.slice(0, -1);
  const cells: string[] = [];
  let cur = '';
  let tick = false;
  for (let k = 0; k < t.length; k++) {
    const c = t[k];
    if (c === '\\' && t[k + 1] === '|') {
      cur += '|';
      k++;
    } else if (c === '`') {
      tick = !tick;
      cur += c;
    } else if (c === '|' && !tick) {
      cells.push(cur);
      cur = '';
    } else cur += c;
  }
  cells.push(cur);
  return cells.map((c) => c.trim());
}

function tablesOf(src: string[], format: Format, code: boolean[], used: Set<number>): Table[] {
  const tables: Table[] = [];
  const cell = (s: string) => inline(s, format);
  for (let i = 0; i < src.length; i++) {
    if (code[i] || used.has(i)) continue;
    const line = src[i];
    // Markdown pipe table: a row of cells, then a separator row.
    if (line.includes('|') && i + 1 < src.length && separator(src[i + 1])) {
      const sep = src[i + 1];
      if (sep.includes('|') || line.trim().startsWith('|')) {
        const header = splitPipes(line).map(cell);
        const rows: string[][] = [];
        let j = i + 2;
        for (; j < src.length && src[j].includes('|') && src[j].trim() && !code[j]; j++) {
          if (separator(src[j])) continue;
          rows.push(splitPipes(src[j]).map(cell));
        }
        tables.push({ header, rows, line: i, kind: 'pipe' });
        for (let k = i; k < j; k++) used.add(k);
        i = j - 1;
        continue;
      }
    }
    // Lines that start with a pipe but have no separator row: read as rows without a header.
    if (format !== 'asciidoc' && line.trim().startsWith('|') && line.trim().length > 1 && !search(GRID_BORDER, line)) {
      const rows: string[][] = [];
      let j = i;
      for (; j < src.length && src[j].trim().startsWith('|') && !code[j] && !search(GRID_BORDER, src[j]); j++) {
        rows.push(splitPipes(src[j]).map(cell));
      }
      if (rows.length && rows.some((r) => r.length > 1)) {
        tables.push({ header: null, rows, line: i, kind: 'pipe' });
        for (let k = i; k < j; k++) used.add(k);
        i = j - 1;
        continue;
      }
      // Not a table. Skip the rest of these lines (reading them again from each one takes time squared), but stop at
      // one that heads a table with a separator row.
      let k = i + 1;
      while (k < j && !(k + 1 < src.length && separator(src[k + 1]))) k++;
      i = k - 1;
      continue;
    }
    // reStructuredText grid table.
    if (match(GRID_BORDER, line)) {
      const cuts: number[] = [];
      for (let k = 0; k < line.length; k++) if (line[k] === '+') cuts.push(k);
      const rows: string[][] = [];
      let header: string[] | null = null;
      let cur: string[] | null = null;
      let j = i + 1;
      for (; j < src.length; j++) {
        const l = src[j];
        if (match(GRID_BORDER, l)) {
          if (cur) rows.push(cur.map(cell));
          cur = null;
          if (l.includes('=') && !header && rows.length) header = rows.pop()!;
          continue;
        }
        if (!l.trim().startsWith('|')) break;
        const parts = cuts.slice(0, -1).map((c, k) => l.slice(c + 1, cuts[k + 1]).trim());
        cur = cur ? cur.map((c, k) => (c + ' ' + (parts[k] ?? '')).trim()) : parts;
      }
      if (cur) rows.push(cur.map(cell));
      tables.push({ header, rows, line: i, kind: 'grid' });
      for (let k = i; k < j; k++) used.add(k);
      i = j - 1;
      continue;
    }
    // reStructuredText simple table: columns under runs of =.
    if (format === 'rst' && match(SIMPLE_BORDER, line)) {
      const starts: number[] = [];
      for (let k = 0; k < line.length; k++) if (line[k] === '=' && (k === 0 || line[k - 1] !== '=')) starts.push(k);
      const blocks: string[][][] = [[]];
      let j = i + 1;
      let borders = 1;
      for (; j < src.length; j++) {
        const l = src[j];
        if (match(SIMPLE_BORDER, l)) {
          borders++;
          // The closing border is followed by a blank line or the end.
          if (j + 1 >= src.length || !src[j + 1].trim()) {
            j++;
            break;
          }
          blocks.push([]);
          continue;
        }
        if (!l.trim()) continue;
        blocks[blocks.length - 1].push(starts.map((s, k) => cell(l.slice(s, starts[k + 1] ?? l.length))));
      }
      if (borders >= 2) {
        const header = blocks.length > 1 && blocks[0].length === 1 ? blocks[0][0] : null;
        const rows = (header ? blocks.slice(1) : blocks).flat();
        tables.push({ header, rows, line: i, kind: 'simple' });
        for (let k = i; k < j; k++) used.add(k);
        i = j - 1;
      }
      continue;
    }
    // reStructuredText list table and CSV table.
    if (format === 'rst' && (match(LIST_TABLE, line) || match(CSV_TABLE, line))) {
      const isList = !!match(LIST_TABLE, line);
      let headerRows = 0;
      let csvHeader: string[] | null = null;
      const rows: string[][] = [];
      let j = i + 1;
      for (; j < src.length; j++) {
        const l = src[j];
        if (l.trim() && !/^[ \t]/.test(l)) break;
        let m: RegExpExecArray | null;
        if ((m = match(HEADER_ROWS, l))) headerRows = Number(m[1]);
        else if (!isList && (m = match(CSV_HEADER, l))) csvHeader = splitCsv(m[1]).map(cell);
        else if (isList && (m = match(LIST_ROW, l))) rows.push([cell(m[2])]);
        else if (isList && (m = match(LIST_CELL, l)) && rows.length) rows[rows.length - 1].push(cell(m[2]));
        else if (!isList && l.trim() && !l.trim().startsWith(':')) rows.push(splitCsv(l.trim()).map(cell));
        else if (isList && l.trim() && rows.length && !l.trim().startsWith(':')) {
          const r = rows[rows.length - 1];
          r[r.length - 1] = (r[r.length - 1] + ' ' + cell(l)).trim();
        }
      }
      const header = csvHeader ?? (headerRows > 0 && rows.length ? rows.shift()! : null);
      tables.push({ header, rows, line: i, kind: isList ? 'list' : 'csv' });
      for (let k = i; k < j; k++) used.add(k);
      i = j - 1;
      continue;
    }
    // AsciiDoc table between |=== lines.
    if (match(ADOC_FENCE, line)) {
      const attrs = i > 0 ? match(ADOC_TABLE_ATTRS, src[i - 1].trim()) : null;
      const cols = attrs ? search(ADOC_COLS, attrs[1]) : null;
      let width = cols ? colCount(cols[1]) : 0;
      let implicitHeader = !!attrs && !!search(ADOC_HEADER_OPTION, attrs[1]);
      const cells: string[] = [];
      let j = i + 1;
      let firstLine: number | null = null;
      for (; j < src.length && !match(ADOC_FENCE, src[j]); j++) {
        const l = src[j];
        if (!l.trim()) {
          if (firstLine !== null && cells.length && j === firstLine + 1 && !attrs) implicitHeader = true;
          continue;
        }
        const parts = adocCells(l);
        if (parts === null) {
          // A line that continues the previous cell.
          if (cells.length) cells[cells.length - 1] += ' ' + l.trim();
          continue;
        }
        if (firstLine === null) {
          firstLine = j;
          if (!width && parts.length > 1) width = parts.length;
        }
        cells.push(...parts);
      }
      if (width < 1) width = 1;
      const rows: string[][] = [];
      for (let k = 0; k < cells.length; k += width) rows.push(cells.slice(k, k + width).map(cell));
      const header = implicitHeader && rows.length ? rows.shift()! : null;
      tables.push({ header, rows, line: i, kind: 'asciidoc' });
      for (let k = i - (attrs ? 1 : 0); k <= j; k++) used.add(k);
      i = j;
      continue;
    }
  }
  return tables;
}

function splitCsv(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === '"') {
      if (quoted && s[k + 1] === '"') {
        cur += '"';
        k++;
      } else quoted = !quoted;
    } else if (c === ',' && !quoted) {
      out.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  out.push(cur.trim());
  return out;
}

/** How many columns an AsciiDoc cols attribute gives: "1,2,1", "3*", "a,a". */
function colCount(spec: string): number {
  const star = /^(\d+)\*/.exec(spec.trim());
  if (star) return Number(star[1]);
  return spec.split(',').length;
}

/** The cells on one line of an AsciiDoc table, or null when the line doesn't start a cell. */
function adocCells(line: string): string[] | null {
  const t = line.trim();
  const first = match(ADOC_CELL, t);
  if (!first) return null;
  const marks = finditer(ADOC_CELL, t);
  const out: string[] = [];
  for (let k = 0; k < marks.length; k++) {
    const start = marks[k].index + marks[k][0].length;
    const end = k + 1 < marks.length ? marks[k + 1].index : t.length;
    out.push(t.slice(start, end).trim());
  }
  return out;
}

/**
 * The HTML tables in the text, as [start, end) offsets: each <table> up to its </table>. Found by a scan, since a
 * pattern for the whole table takes time squared when tables don't close.
 */
function htmlTableSpans(src: string): [number, number][] {
  const out: [number, number][] = [];
  const open = new RegExp(HTML_TABLE_OPEN.source, HTML_TABLE_OPEN.flags + 'g');
  const close = new RegExp(HTML_TABLE_CLOSE.source, HTML_TABLE_CLOSE.flags + 'g');
  let from = 0;
  for (;;) {
    open.lastIndex = from;
    const o = open.exec(src);
    if (!o) break;
    close.lastIndex = o.index;
    const c = close.exec(src);
    // No </table> after this one means none after any later one either.
    if (!c) break;
    out.push([o.index, c.index + c[0].length]);
    from = c.index + c[0].length;
  }
  return out;
}

function htmlTables(
  src: string,
  spans: [number, number][],
  startLine: (offset: number) => number,
  format: Format,
): Table[] {
  const out: Table[] = [];
  for (const [start, end] of spans) {
    const body = src.slice(start, end);
    const rows: string[][] = [];
    let headerRow: string[] | null = null;
    const thead = search(HTML_THEAD, body);
    const theadEnd = thead ? (search(HTML_THEAD_END, body)?.index ?? 0) : 0;
    for (const r of finditer(HTML_ROW, body)) {
      const cells = finditer(HTML_CELL, r[1]);
      if (!cells.length) continue;
      const texts = cells.map((c) => inline(c[2], format));
      const allTh = cells.every((c) => c[1].toLowerCase() === 'h');
      if (!headerRow && !rows.length && (allTh || (thead && r.index < theadEnd))) {
        headerRow = texts;
      } else rows.push(texts);
    }
    out.push({ header: headerRow, rows, line: startLine(start), kind: 'html' });
  }
  return out;
}

// --------------------------------------------------------------------------------------------- links
/** A function from an offset in s to its line number: s keeps the source's line breaks (see blank()). */
function lineFinder(s: string): (offset: number) => number {
  const starts = [0];
  for (let k = s.indexOf('\n'); k >= 0; k = s.indexOf('\n', k + 1)) starts.push(k + 1);
  return (o) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= o) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
}

function linksOf(src: string, format: Format): Link[] {
  const byKey = new Map<string, Set<number>>();
  const out: Link[] = [];
  const lineSets: Set<number>[] = [];
  const add = (text: string, url: string, line: number) => {
    const u = trimEndOf(url.trim(), '.,;:!?\'"');
    if (!u || u.startsWith('#')) return;
    const key = u + '\u0000' + text;
    const had = byKey.get(key);
    if (had) {
      had.add(line);
      return;
    }
    const lines = new Set([line]);
    byKey.set(key, lines);
    lineSets.push(lines);
    out.push({ text: inline(text, format), url: u });
  };
  const srcLine = lineFinder(src);
  const defs = new Map<string, { url: string; line: number }>();
  for (const m of finditer(MD_REF_DEF, src)) defs.set(m[1].trim().toLowerCase(), { url: m[2], line: srcLine(m.index) });
  for (const m of finditer(RST_TARGET, src)) defs.set(m[1].trim().toLowerCase(), { url: m[2], line: srcLine(m.index) });
  let rest = blank(MD_IMAGE, src);
  let at = lineFinder(rest);
  for (const m of finditer(MD_LINK, rest)) add(m[1], m[2], at(m.index));
  rest = blank(MD_LINK, rest);
  at = lineFinder(rest);
  for (const m of finditer(MD_REF_USE, rest)) {
    const key = (m[2] || m[1]).trim().toLowerCase();
    const def = defs.get(key);
    if (def) add(m[1], def.url, at(m.index));
  }
  for (const m of finditer(HTML_A, rest)) {
    const href = search(HREF, m[1]);
    if (href) add(m[2], href[1], at(m.index));
  }
  if (format === 'rst') {
    for (const m of finditer(RST_LINK, rest)) add(m[1].trim() || m[2], m[2], at(m.index));
    for (const m of finditer(RST_NAMED_REF, rest)) {
      const def = defs.get(m[1].trim().toLowerCase());
      if (def) add(m[1], def.url, at(m.index));
    }
  }
  if (format === 'asciidoc') {
    for (const m of finditer(ADOC_LINK, rest)) add(m[2] || m[1], m[1], at(m.index));
  }
  for (const m of finditer(AUTOLINK, rest)) add(m[1], m[1], at(m.index));
  // Bare URLs, outside the forms above.
  let bare = blank(HTML_A, blank(AUTOLINK, rest));
  bare = blank(MD_REF_DEF, bare);
  if (format === 'rst') bare = blank(RST_LINK, blank(RST_TARGET, bare));
  if (format === 'asciidoc') bare = blank(ADOC_LINK, bare);
  at = lineFinder(bare);
  for (const m of finditer(BARE_URL, bare)) add(m[0], m[0], at(m.index));
  const urls = new Set(out.map((l) => l.url));
  for (const [, def] of defs) if (!urls.has(def.url)) add(def.url, def.url, def.line);
  out.forEach((l, k) => (l.lines = [...lineSets[k]].sort((a, b) => a - b)));
  return out;
}

/** Email addresses in the text, written plainly, in a mailto: link, or spelled out (name [at] example [dot] org). */
function emailsOf(text: string, links: Link[]): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  const add = (e: string) => {
    const addr = trimEndOf(e.replace(/^mailto:/i, '').split('?')[0], '.,;:');
    const [local, domain = ''] = addr.split('@');
    // user@EXAMPLE.COM, a lower-case name at a domain in capitals, is a Kerberos principal, not an inbox.
    if (/[a-z]/.test(local) && /[A-Z]/.test(domain) && !/[a-z]/.test(domain)) return;
    if (search(NOT_AN_INBOX, addr) || seen.has(addr.toLowerCase())) return;
    seen.add(addr.toLowerCase());
    found.push(addr);
  };
  for (const l of links) if (/^mailto:/i.test(l.url)) add(l.url);
  for (const m of finditer(EMAIL, text)) add(m[1]);
  for (const m of finditer(MAILTO_TEXT, text)) add(m[1]);
  // The spelled-out dots of a domain ([dot], (.), " dot ") become dots.
  const dots = (d: string) =>
    d
      .replace(/[ \t]+/g, ' ')
      .replace(/ - /g, '-')
      .replace(/ ?(?:[[({<] ?(?:dot|\.) ?[\])}>]|\bdot\b|\.) ?/gi, '.');
  for (const m of finditer(OBFUSCATED_EMAIL, text)) add(`${m[1]}@${dots(m[2])}`);
  for (const m of finditer(SPELLED_EMAIL, text)) add(`${m[1]}@${dots(m[2])}`);
  for (const m of finditer(SPELLED_AT, text)) add(m[1] ? `${m[1]}@${m[2]}` : `${m[3]}@${m[4]}`);
  for (const m of finditer(SPELLED_SPACED, text)) add(`${m[1]}@${m[2]}.${m[3]}`);
  for (const m of finditer(SPELLED_TO, text)) add(`${m[1]}@${m[2]}`);
  for (const m of finditer(SPACED_AT, text)) add(`${m[1]}@${m[2]}`);
  for (const m of finditer(QUOTED_AT, text)) add(`${m[1]}@${m[2]}`);
  return found;
}

// ---------------------------------------------------------------------------------------------- read
/**
 * How much of a policy the reader looks at: 256 KB (in characters), well above any real one, so a huge file can't make a
 * scan slow. Past that the reader takes the first 256 KB, and the policy says it did (truncated).
 */
export const MAX_POLICY = 256 * 1024;

/** Read a policy file: its path names the format (SECURITY.md, SECURITY.rst, SECURITY.adoc, SECURITY.txt, SECURITY). */
export function readPolicy(raw: string, path: string): Policy {
  const truncated = raw.length > MAX_POLICY;
  const body = truncated ? raw.slice(0, MAX_POLICY) : raw;
  const format = formatOf(path, body);
  const src = prepare(body, format);
  const srcLines = src.split('\n');
  // Code fences and literal blocks: their lines are text, but no headings or tables start there.
  const code = srcLines.map(() => false);
  let fence: string | null = null;
  for (let i = 0; i < srcLines.length; i++) {
    const m = match(FENCE, srcLines[i]);
    if (fence) {
      code[i] = true;
      if (m && m[1][0] === fence[0] && m[1].length >= fence.length) fence = null;
    } else if (m) {
      fence = m[1];
      code[i] = true;
    }
  }
  const { headings, underline } = headingsOf(srcLines, format, code);
  const used = new Set<number>(underline);
  const lineAt = lineFinder(src);
  const spans = htmlTableSpans(src);
  const html = htmlTables(src, spans, lineAt, format);
  for (const [start, end] of spans) for (let k = lineAt(start); k <= lineAt(end - 1); k++) used.add(k);
  const tables = [...tablesOf(srcLines, format, code, used), ...html].sort((a, b) => a.line - b.line);
  const links = linksOf(src, format);
  const headingAt = new Map(headings.map((h) => [h.line, h]));
  const items = srcLines.flatMap((l, i) => (!code[i] && match(LIST_MARK, l) ? [i] : []));
  const lines = srcLines.map((l, i) => {
    if (underline.has(i)) return '';
    const h = headingAt.get(i);
    if (h) return h.text;
    if (l.includes('|') && separator(l)) return '';
    if (match(GRID_BORDER, l) || (format === 'rst' && match(SIMPLE_BORDER, l))) return '';
    if (format === 'asciidoc' && (match(ADOC_FENCE, l) || match(ADOC_ATTR_LINE, l.trim()))) return '';
    let t = l;
    if (format === 'rst') t = t.replace(RST_DIRECTIVE, '').replace(RST_FIELD, '');
    if (format === 'asciidoc' && t.trim().startsWith('|')) t = t.replace(/(?:^|\s)[a-z]?\|/g, ' ');
    if (t.trim().startsWith('|') || (used.has(i) && t.includes('|'))) t = splitPipes(t).join(' ');
    t = t.replace(ADMONITION, '').replace(LIST_MARK, '');
    return inline(t, format);
  });
  const text = lines.join('\n');
  const emails = emailsOf(text, links);
  // Words outside links: a word that is a URL, or one of the links' targets, isn't one.
  const urls = new Set(links.map((l) => l.url));
  const prose = text.replace(/\S+/g, (w) =>
    w.includes('://') || urls.has(w) || urls.has(trimEndOf(w, ').,;:!?\'">]')) ? ' ' : w,
  );
  const latin = (prose.match(/[A-Za-z]{2,}/g) ?? []).length;
  // Chinese, Japanese and Korean words are about two characters long; Cyrillic, Greek, Hebrew, Arabic, Hindi or Thai
  // ones about six.
  const cjk = (prose.match(/[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af\uf900-\ufaff]/g) ?? []).length;
  const other =
    cjk / 2 + (prose.match(/[\u0370-\u03ff\u0400-\u04ff\u0590-\u06ff\u0900-\u097f\u0e00-\u0e7f]/g) ?? []).length / 6;
  const words = Math.round(latin + other);
  const hits = finditer(ENGLISH, prose).length;
  // A policy of a few words (a link and "see") is too short to tell its language: it's read as English.
  const english = (latin < 6 && other < 3) || (hits >= 2 && hits >= 0.08 * latin && latin >= 0.3 * other);
  return { path, format, lines, text, headings, links, emails, tables, words, english, items, truncated };
}

const endsCache = new WeakMap<Policy, number[]>();
/** Where each heading's section ends: the line of the next heading at its level or above (one pass, with a stack). */
function sectionEnds(p: Policy): number[] {
  let ends = endsCache.get(p);
  if (ends) return ends;
  ends = p.headings.map(() => p.lines.length);
  const open: number[] = [];
  p.headings.forEach((h, k) => {
    while (open.length && p.headings[open[open.length - 1]].level >= h.level) ends![open.pop()!] = h.line;
    open.push(k);
  });
  endsCache.set(p, ends);
  return ends;
}

/** The sections whose heading matches rx, each up to the next heading at its level or above. */
export function sections(p: Policy, rx: RegExp): Section[] {
  const out: Section[] = [];
  const ends = sectionEnds(p);
  p.headings.forEach((h, k) => {
    if (!search(rx, h.text)) return;
    const end = ends[k];
    // The tables are in line order: the first one after the heading, then those before the end.
    let lo = 0;
    let hi = p.tables.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (p.tables[mid].line > h.line) hi = mid;
      else lo = mid + 1;
    }
    const tables: Table[] = [];
    for (let t = lo; t < p.tables.length && p.tables[t].line < end; t++) tables.push(p.tables[t]);
    out.push({ heading: h, start: h.line + 1, end, text: p.lines.slice(h.line + 1, end).join('\n'), tables });
  });
  return out;
}

/** The text's sentences that match rx, each with the heading it sits under: evidence a check can quote. */
export function mentions(p: Policy, rx: RegExp): { heading: string | null; sentence: string }[] {
  const out: { heading: string | null; sentence: string }[] = [];
  let heading: string | null = null;
  const headingAt = new Map(p.headings.map((h) => [h.line, h.text]));
  p.lines.forEach((l, i) => {
    if (headingAt.has(i)) {
      heading = headingAt.get(i)!;
      return;
    }
    for (const s of l.split(/(?<=[.!?。！？])\s+/)) if (search(rx, s)) out.push({ heading, sentence: s.trim() });
  });
  return out;
}

// ------------------------------------------------------------------------------------- how to report
export type ChannelKind = 'github' | 'email' | 'platform' | 'form' | 'chat' | 'maintainer' | 'page';

export interface Channel {
  kind: ChannelKind;
  /** What to show: the address, the link, or the name of the way to report. */
  label: string;
}

export interface Reporting {
  /** The private ways to report, best first. A 'page' channel is a link to a security page or policy elsewhere. */
  channels: Channel[];
  /** It sends reporters to public issues (and offers nothing private). */
  publicIssues: boolean;
  /** It mentions email or a private message, but gives no address. */
  noAddress: boolean;
  /** It still has the reporting paragraph of GitHub's template. */
  template: boolean;
  /** A link the scan can't follow, when the policy is mostly that link. */
  pointer: Link | null;
  /** It says the contact is on a website it doesn't link to. */
  elsewhere: boolean;
}

/** GitHub's private vulnerability reporting: the Security tab, its advisories page or the "Report a vulnerability" form. */
const GITHUB_REPORTING_URL = re(
  String.raw`(?i)^https?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+/security(?:/advisories(?:/new)?)?/?(?:[?#]\S*)?$|^(?:\.\./)+security/advisories(?:/new)?/?$|^/[\w.-]+/[\w.-]+/security/advisories(?:/new)?/?$`,
);
/** The feature's names, which a policy in another language uses as they are: a mention is enough there. */
const GITHUB_REPORTING_NAME = re(
  String.raw`(?i)(?<![a-z])(?:security[ \t]+advisor(?:y|ies)|private[ \t]+vulnerability[ \t]+report(?:ing)?|report[ \t]+a[ \t]+vulnerability|security[\x60"'*_ \t]+(?:tab|page))(?![a-z])`,
);
/** A handle after "GitHub" (GitHub: @name), a contact in a policy in another language. */
const GITHUB_HANDLE = re(String.raw`(?i)github[^\n]{0,30}?(?<![\w.])@[A-Za-z0-9][\w-]{0,38}(?![\w@])`);
/** A Matrix user (@name:example.org), a private contact. */
const MATRIX_ID = re(String.raw`(?<![\w.])@[\w.=-]+:[\w-]+(?:\.[\w-]+)+\b`);
/** An issue only maintainers see: GitLab's confidential issues. */
const CONFIDENTIAL_ISSUE = re(
  String.raw`(?i)\bconfidential\b[^.\n]{0,60}\bissues?\b|\bissues?\b[^.\n]{0,60}\bconfidential\b`,
);
const GITHUB_REPORTING_TEXT = re(
  String.raw`(?i)\bprivate(?:ly)?[ \t]+(?:vulnerability[ \t]+)?report(?:ing)?\b|\b(?:click(?:ing)?|use|using|choose|select|press|via|through|under|the)[ \t]+(?:on[ \t]+)?["'\u201c\u2018]?report[ \t]+a[ \t]+vulnerability\b|\bsecurity["'\u201d\u2019]?[ \t]*(?:tab[ \t]*)?(?:\u2192|->|>|\u203a|\u00bb|/)[ \t]*(?:advisories[ \t]*(?:\u2192|->|>|\u203a|\u00bb|/)[ \t]*)?["'\u201c\u2018]?report[ \t]+a[ \t]+vulnerability\b|\breport[ \t]+a[ \t]+vulnerability["'\u201d\u2019]?[ \t]+(?:button|tab|form|link|feature|option|menu|page)\b|\bsecurity["'\u201d\u2019*_ \t]+(?:tab|page)\b|\b(?:report|draft|new|private|open|opening|create|submit|file|raise|start|use)[ \t]+(?:a[ \t]+|an[ \t]+)?(?:new[ \t]+|private[ \t]+|draft[ \t]+)?(?:github[ \t]+)?security[ \t]+advisor(?:y|ies)\b|\b(?:via|through|using|with)[ \t]+(?:the[ \t]+|a[ \t]+)?(?:github(?:'s)?[ \t]+)?(?:private[ \t]+)?security[ \t]+advisor(?:y|ies)\b(?![ \t]+(?:will|are|is|were|was|published|database)\b)|\bgithub(?:'s)?[ \t]+(?:private[ \t]+)?advisor(?:y|ies)\b|\b(?:open|create|draft|submit|file|start)[ \t]+(?:a|an)[ \t]+(?:new[ \t]+|private[ \t]+|draft[ \t]+)?advisory\b`,
);
/** Bug bounty and disclosure platforms, Tidelift's security contact, and the big vendors' report pages. */
const PLATFORM_URL = re(
  String.raw`(?i)^https?://(?:[\w-]+\.)*(?:hackerone\.com|bugcrowd\.com|intigriti\.com|yeswehack\.(?:com|ninja)|huntr\.(?:dev|com)|openbugbounty\.org|immunefi\.com|hackenproof\.com|zerocopter\.com|federacy\.com|bughunters\.google\.com|msrc\.microsoft\.com|cantina\.xyz)(?:[/?#]\S*)?$|^https?://(?:www\.)?tidelift\.com/(?:security|docs/security)|^https?://g\.co/vulnz|^https?://aka\.ms/(?:security|opensource/security)|^https?://(?:www\.)?facebook\.com/whitehat`,
);
const PLATFORM_TEXT = re(
  String.raw`(?i)\b(?:hackerone|bugcrowd|intigriti|yeswehack|huntr(?:\.dev)?|open[ \t]+bug[ \t]+bounty|immunefi|hackenproof|tidelift(?:'s)?[ \t]+(?:security[ \t]+contact|coordinated[ \t]+disclosure)|node[ \t]+security[ \t]+project|bug[ \t]+bounty[ \t]+program(?:me)?|vulnerability[ \t]+(?:reward|disclosure)[ \t]+program(?:me)?)\b`,
);
const FORM_URL = re(
  String.raw`(?i)^https?://(?:[\w-]+\.)*(?:forms\.gle|typeform\.com|jotform\.com|blocksurvey\.io|formspree\.io|tally\.so|forms\.office\.com|forms\.microsoft\.com|cryptpad\.fr/form|airtable\.com/shr)\S*|^https?://docs\.google\.com/forms\S*`,
);
const FORM_TEXT = re(
  String.raw`(?i)\b(?:contact|report(?:ing)?|security|disclosure|vulnerability|issue|encrypted|submission)[ \t]+form\b|\bform\b`,
);
/** A private chat: a Signal or Matrix user, or a direct message to someone on a chat server. */
const CHAT_URL = re(
  String.raw`(?i)^https?://(?:signal\.me/|matrix\.to/#/@|keybase\.io/[\w-]+/?$|threema\.id/|wa\.me/|t\.me/[\w]{4,}/?$|(?:[\w-]+\.)?linkedin\.com/in/)`,
);
/** A link to someone's GitHub profile, written as their handle ([@name](https://github.com/name)). */
const PROFILE_URL = re(
  String.raw`(?i)^https?://(?:www\.)?github\.com/([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})/?$`,
);
const CHAT_TEXT = re(
  String.raw`(?i)\b(?:signal|threema|session|wire|keybase|element)\b[^.\n]{0,40}(?:@[\w.-]+|\+\d[\d \t-]{6,}|\busername\b|\bnumber\b)|@[\w.-]+:[\w-]+(?:\.[\w-]+)+\b|\b(?:dm|mp|direct[ \t]+message|private[ \t]+message|privately[ \t]+message|message[ \t]+(?:me|us|them|him|her|one[ \t]+of[ \t]+(?:us|the[ \t]+maintainers))[ \t]+privately|pm|private(?:ly)?)\b[^\n]{0,80}\b(?:discord|zulip|slack|matrix|gitter|telegram|mastodon|twitter|irc|libera|wechat|qq)\b|\b(?:discord|zulip|slack|matrix|gitter|telegram|mastodon|irc|wechat|qq)\b[^.\n]{0,80}\b(?:dm|mp|pm|direct[ \t]+message|private[ \t]+message|privately)\b|\b(?:discord|zulip|slack|telegram|gitter|wechat|qq|keybase)\b[^.\n]{0,40}(?:@[\w.-]{2,}|\b[\w.]{2,32}#\d{4}\b|` +
    '`' +
    String.raw`[\w.#-]{2,32}` +
    '`' +
    String.raw`)`,
);
/** A named maintainer to contact privately: @handle, or the address on someone's profile. */
const MAINTAINER_TEXT = re(
  String.raw`(?i)\b(?:contact(?:ing)?|e-?mail|message|reach[ \t]+out[ \t]+to|ping|write[ \t]+to|notify|tell|send[ \t]+(?:it|them|a[ \t]+report)[ \t]+to)\b[^.\n]{0,80}?(?<![\w.])@[A-Za-z0-9](?:[A-Za-z0-9_]|-(?=[A-Za-z0-9])){0,38}(?![\w@-])(?!\.[\w])|\b(?:e-?mail|contact)?[ \t]*address(?:es)?[ \t]+(?:listed[ \t]+|shown[ \t]+|given[ \t]+|found[ \t]+)?(?:on|in)[ \t]+(?:the[ \t]+|their[ \t]+|his[ \t]+|her[ \t]+|my[ \t]+|our[ \t]+|\S+'s[ \t]+)?(?:github[ \t]+)?(?:profiles?|readme)\b|\b(?:contact|e-?mail|address)[^.\n]{0,40}\b(?:in|on)[ \t]+(?:the[ \t]+|our[ \t]+|my[ \t]+)?(?:readme|github[ \t]+profile)\b|\b(?:git[ \t]+history|commit[ \t]+history|commits|authors(?:\.md)?|maintainers(?:\.md)?)\b[^.\n]{0,60}\be-?mail[ \t]+address(?:es)?\b|\be-?mail[ \t]+address(?:es)?[^.\n]{0,40}\b(?:git[ \t]+history|commit[ \t]+history|commits|authors(?:\.md)?|maintainers(?:\.md)?)\b`,
);
/** The README (in the same repository) as where the contact is: "see the README for how to submit them". */
const README_CONTACT = re(
  String.raw`(?i)\b(?:see|read|check|consult|refer[ \t]+to|listed[ \t]+in|found[ \t]+in|given[ \t]+in|in|or)[ \t]+(?:the[ \t]+|our[ \t]+|its[ \t]+)?readme\b`,
);
/** A contact the policy says is on a website, which the scan doesn't read. */
const CONTACT_ELSEWHERE = re(
  String.raw`(?i)\b(?:contact|e-?mail|reach|write|report)\w*\b[^.\n]{0,80}\b(?:on|at|in|via|through)[ \t]+(?:the[ \t]+|our[ \t]+|its[ \t]+)?(?:project(?:'s)?[ \t]+)?(?:web[ \t]?(?:site|page)|homepage|site)\b`,
);
/** A link to where reports go, or to a security policy elsewhere: how to report is there. */
const REPORTING_LINK = re(
  String.raw`(?i)report|disclos|vulnerab|psirt|bug-?bount|bounty|whitehat|security[-_ ]?polic|secpolicy|security[-_ ]?(?:contact|team|response|center|centre)|security\.(?:txt|md|html)|cve-process|\bcontact|hackerone|bugcrowd|intigriti|yeswehack|huntr`,
);
/** Link text that says it's where reports go (the URL can say so with REPORTING_LINK; "DBIR Report" doesn't). */
const REPORTING_TEXT = re(
  String.raw`(?i)report(?:ing)?[ \t]+(?:a[ \t]+|an[ \t]+)?(?:security|vulnerab|issue|bug|problem)|vulnerab|disclos|security[ \t]+(?:polic|contact|team|page|issue|response|center|centre)|bug[ \t]?bount|\bcontact|psirt|whitehat|hackerone|bugcrowd|intigriti|yeswehack|huntr`,
);
/** A link about security: where reports go only when the policy is short or a sentence says so. */
const SECURITY_LINK = re(String.raw`(?i)secur`);
/** A sentence about sending a report, so a link in it is where reports go. */
const REPORT_SENTENCE = re(
  String.raw`(?i)\b(?:report|submit|disclos|notify|send|contact|reach|e-?mail|write[ \t]+to|message)\w*\b`,
);
/** What a sentence (or its heading) needs to be about for a link in it to be where reports go. */
const VULN_CONTEXT = re(
  String.raw`(?i)vulnerab|disclos|exploit|security[ \t]+(?:issues?|bugs?|problems?|flaws?|concerns?|reports?|contact)|report(?:ing)?[ \t]+(?:a[ \t]+|an[ \t]+)?(?:security|vulnerab|issue|bug|problem)|\breporting\b`,
);
/** The words just before a link that make it the place to report: report it to [...], contact [...], use [...]. */
const LINK_LEAD = re(
  String.raw`(?i)(?:\bto|\bat|\bvia|\bthrough|\busing|\buse|\bvisit|\bsee|\bcontact(?:ing)?|\be-?mail|\bmessage|\breach(?:[ \t]+out)?(?:[ \t]+to)?|\bwrite[ \t]+to|\bping|\bon|\bwith|\bin)[ \t]+(?:(?:our|the|us|me|him|her|them|my|its|this|a|an)[ \t]*)?[(\["'*_]*$|\b(?:link|url|here|portal|platform|form|page)[ \t]*:[ \t]*$`,
);
/** Link text that names a place to report on its own: [here], [contact us], [security team]. */
const LINK_NAMES_PLACE = re(
  String.raw`(?i)^(?:here|this[ \t]+(?:link|form|page)|contact|report|security[ \t]+(?:team|contact|page)|the[ \t]+form)`,
);
/** Links about security that aren't a place to report: CVE and weakness databases, general advice, audits, lists. */
const NOT_A_CHANNEL = re(
  String.raw`(?i)^https?://(?:[\w-]+\.)*(?:cve\.mitre\.org|cve\.org|nvd\.nist\.gov|cwe\.mitre\.org|owasp\.org|wikipedia\.org|first\.org|osv\.dev|snyk\.io|cvedetails\.com|semver\.org|shields\.io|securityscorecards\.dev|scorecard\.dev|bestpractices\.(?:dev|coreinfrastructure\.org)|openssf\.org|cisa\.gov|deps\.dev|socket\.dev|transparencyreport\.google\.com|example\.(?:com|org|net)|your-?domain\.\w+|google\.\w+/search|bing\.com/search|duckduckgo\.com)(?:[/:?#]\S*)?$|^https?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+/security/advisories/GHSA-|^https?://(?:www\.)?github\.com/advisories\b|^https?://github\.com/[\w.-]+/[\w.-]+/(?:pulls|discussions)\b|\.pdf(?:[?#]|$)|pentest|audit|announce|/feed\b|/rss\b|\brss\b|/news\b|/blog\b`,
);
/** An invitation to a chat server or room, which isn't a private message to anyone. */
const INVITE = re(
  String.raw`(?i)^https?://(?:discord\.gg/|(?:www\.)?discord(?:app)?\.com/invite/|t\.me/(?:joinchat/|\+)|join\.slack\.com/|[\w-]+\.slack\.com/?$|gitter\.im/|matrix\.to/#/#)`,
);
/** GitHub's docs on private vulnerability reporting, which a policy links to when it says to use it. */
const GITHUB_REPORTING_DOCS = re(String.raw`(?i)^https?://docs\.github\.com/\S*privately-reporting`);
const ISSUES_URL = re(
  String.raw`(?i)^https?://(?:www\.)?(?:github\.com|gitlab\.com|codeberg\.org)/[\w.-]+/[\w.-]+/(?:-/)?issues(?:/new\b\S*|/?(?:[?#]\S*)?)$|^\.\./\.\./issues/?(?:new\b\S*)?$`,
);
const PUBLIC_ISSUE_TEXT = re(
  String.raw`(?i)\b(?:open|opening|create|creating|file|filing|submit|submitting|raise|raising|post|log|use|using|report(?:ing)?[ \t]+(?:(?:it|them|this|vulnerabilities|issues|bugs)[ \t]+)?(?:as|in|via|on|through|to))[ \t]+(?:an?[ \t]+|the[ \t]+|our[ \t]+)?(?:new[ \t]+|public[ \t]+)?(?:github[ \t]+|gitlab[ \t]+)?(?:issues?|bug[ \t]+reports?|tickets?|pull[ \t]+requests?|discussions?)\b|\bissue[ \t]+tracker\b`,
);
/** A phrase right after a name that says it isn't there: "... is not currently enabled". */
const NOT_AFTER = re(
  String.raw`(?i)^[^.\n]{0,25}?\b(?:(?:is|are)[ \t]+(?:not|n't)|isn't|aren't)[ \t]+(?:currently[ \t]+|yet[ \t]+)?(?:enabled|available|active|supported|set[ \t]+up|turned[ \t]+on|configured)\b|^[^.\n]{0,25}?\b(?:is|are)[ \t]+(?:currently[ \t]+)?(?:disabled|unavailable|off)\b`,
);
const NEGATION = re(
  String.raw`(?i)\b(?:not|never|don't|do[ \t]+not|avoid|instead[ \t]+of|rather[ \t]+than|n't|no[ \t]+public|refrain|non-?security|non-?sensitive|non-?critical|feature[ \t]+requests?|regular[ \t]+bugs?|general[ \t]+bugs?|other[ \t]+bugs?|ordinary[ \t]+bugs?|low[- ]severity)\b`,
);
const ASKS_FOR_MAIL = re(
  String.raw`(?i)\b(?:e-?mail|mail[ \t]+(?:us|me|the)|private[ \t]+message|direct[ \t]+message|contact(?:ing)?[ \t]+(?:us|me|the[ \t]+(?:maintainers?|team|author|owner|developers?|project))|reach[ \t]+out[ \t]+to[ \t]+(?:us|me|the|a|one|our|any)|report\w*[ \t]+(?:\w+[ \t]+){0,3}privately|privately[ \t]+to[ \t]+the)\b`,
);
/** Words that make a sentence about reporting a problem. */
const REPORT_WORD = re(String.raw`(?i)\b(?:report|vulnerab|secur|issue|bug|disclos|problem|flaw|exploit)`);
const TEMPLATE_REPORTING = re(String.raw`(?i)use this section to tell people how to report a vulnerability`);

const ORDER: ChannelKind[] = ['github', 'email', 'platform', 'form', 'chat', 'maintainer', 'page'];

/** The policy's paragraphs: lines joined up to a blank line or a heading, so a wrapped sentence reads whole. */
export function paragraphs(p: Policy): string[] {
  return blocks(p).map((b) => b.text);
}

interface Block {
  text: string;
  heading: string | null;
  /** Its lines: [start, end). */
  start: number;
  end: number;
}

const blockCache = new WeakMap<Policy, Block[]>();
/** The policy's paragraphs with the heading each sits under and the lines they span. */
function blocks(p: Policy): Block[] {
  const cached = blockCache.get(p);
  if (cached) return cached;
  const heads = new Map(p.headings.map((h) => [h.line, h.text]));
  const items = new Set(p.items);
  const out: Block[] = [];
  let heading: string | null = null;
  let cur: string[] = [];
  let start = 0;
  const flush = (end: number) => {
    if (cur.length) out.push({ text: cur.join(' '), heading, start, end });
    cur = [];
  };
  p.lines.forEach((l, i) => {
    if (heads.has(i)) {
      flush(i);
      heading = heads.get(i)!;
      out.push({ text: l, heading, start: i, end: i + 1 });
    } else if (!l.trim()) flush(i);
    else {
      // A list item starts a paragraph of its own: "1. Don't open an issue 2. Email us" is two instructions.
      if (items.has(i)) flush(i);
      if (!cur.length) start = i;
      cur.push(l.trim());
    }
  });
  flush(p.lines.length);
  blockCache.set(p, out);
  return out;
}

/**
 * Whether a link to a GitHub profile is a contact: written as a handle (@name), or, in a policy in another language,
 * named something other than the account (a link to someone's profile in a list of credits isn't a contact).
 */
function profileContact(l: Link, english: boolean): boolean {
  const text = l.text.trim();
  if (text.startsWith('@')) return true;
  if (english || !text || text.length > 40 || /\s{2,}|\n/.test(text)) return false;
  const user = (match(PROFILE_URL, l.url)?.[1] ?? '').toLowerCase();
  return text.toLowerCase() !== user && !text.includes('/');
}

/** Whether a URL is a page of the repository itself on GitHub (its releases, its tree, the repository). */
function sameRepoUrl(url: string, repo: string): boolean {
  const m = match(REPO_URL, url);
  return !!m && `${m[1]}/${m[2]}`.toLowerCase() === repo.toLowerCase();
}

/** How the policy says to report a vulnerability. repo (owner/name) tells its own links from others'. */
export function howToReport(p: Policy, repo: string): Reporting {
  const found: Channel[] = [];
  const have = new Set<string>();
  const add = (kind: ChannelKind, label: string) => {
    const key = kind + '\u0000' + label;
    if (have.has(key)) return;
    have.add(key);
    found.push({ kind, label });
  };
  for (const e of p.emails) add('email', e);
  let issues = false;
  const others: Link[] = [];
  const weak: Link[] = [];
  const own = (u: string) => (!!sameRepoUrl(u, repo) && !/\/wiki\b/i.test(u)) || !!repoPath(u, repo, p.path);
  for (const l of p.links) {
    const u = l.url;
    if (/^mailto:/i.test(u)) continue;
    if (search(GITHUB_REPORTING_URL, u) && !/\/security\/policy\b/i.test(u)) add('github', u);
    else if (search(GITHUB_REPORTING_DOCS, u)) add('github', "GitHub's private vulnerability reporting");
    else if (search(PLATFORM_URL, u)) add('platform', u);
    else if (search(FORM_URL, u)) add('form', u);
    else if (search(CHAT_URL, u)) add('chat', u);
    else if (search(ISSUES_URL, u)) issues = true;
    else if (search(PROFILE_URL, u) && profileContact(l, p.english)) add('maintainer', l.text.trim() || u);
    else if (search(NOT_A_CHANNEL, u) || !/^https?:/i.test(u) || search(INVITE, u)) continue;
    else if (/security\.txt$/i.test(u)) add('page', u);
    else if (own(u)) continue;
    else if (search(FORM_TEXT, l.text)) add('form', u);
    else if (search(REPORTING_LINK, u.split(/[?#]/)[0]) || search(REPORTING_TEXT, l.text)) add('page', u);
    else if (search(SECURITY_LINK, u) || search(SECURITY_LINK, l.text)) weak.push(l);
    else others.push(l);
  }
  // A security link is where reports go in a short policy that is little more than the link.
  if (p.words <= 40 && !issues) for (const l of weak) add('page', l.url);
  const paras = paragraphs(p);
  const sentences = paras.flatMap((para) => para.split(/(?<=[.!?。！？])\s+/));
  let publicIssues = issues;
  let noAddress = false;
  let elsewhere = false;
  for (const s of sentences) {
    if (search(GITHUB_REPORTING_TEXT, s) && !negated(s, GITHUB_REPORTING_TEXT, true))
      add('github', "GitHub's private vulnerability reporting");
    // In another language the verbs around it can't be read, so the feature's name is enough.
    if (!p.english && search(GITHUB_REPORTING_NAME, s) && !negated(s, GITHUB_REPORTING_NAME, true))
      add('github', "GitHub's private vulnerability reporting");
    if (!p.english && search(GITHUB_HANDLE, s)) add('maintainer', 'a maintainer named in it');
    if (search(MATRIX_ID, s)) add('chat', search(MATRIX_ID, s)![0]);
    if (search(CONFIDENTIAL_ISSUE, s) && !negated(s, CONFIDENTIAL_ISSUE)) add('platform', 'confidential issue');
    const pm = search(PLATFORM_TEXT, s);
    if (pm) add('platform', pm[0].replace(/\s+/g, ' '));
    if (search(MAINTAINER_TEXT, s)) add('maintainer', 'a maintainer named in it');
    if (search(README_CONTACT, s) && search(REPORT_SENTENCE, s) && search(REPORT_WORD, s)) add('page', 'its README');
    if (search(REPORT_WORD, s)) for (const m of finditer(SHORT_EMAIL, s)) add('email', m[1]);
    if (search(PUBLIC_ISSUE_TEXT, s) && !negated(s, PUBLIC_ISSUE_TEXT)) publicIssues = true;
    if (search(CONTACT_ELSEWHERE, s) && search(REPORT_WORD, s)) elsewhere = true;
  }
  // The links each line holds, so a paragraph looks only at its own.
  const byLine = new Map<number, Link[]>();
  for (const l of [...weak, ...others]) {
    for (const n of l.lines ?? []) {
      const at = byLine.get(n);
      if (at) at.push(l);
      else byLine.set(n, [l]);
    }
  }
  for (const b of blocks(p)) {
    const para = b.text;
    // The heading a paragraph sits under says what it's about ("Reporting a vulnerability").
    const heading = b.heading ?? '';
    const context = `${heading} ${para}`;
    if (search(CHAT_TEXT, para) && search(REPORT_WORD, context)) add('chat', 'a private message');
    if (search(ASKS_FOR_MAIL, para) && search(REPORT_WORD, context)) noAddress = true;
    // At most 50 links per paragraph: no real one has more, and each is looked for in the whole paragraph.
    const near = new Set<Link>();
    for (let n = b.start; n < b.end && near.size < 50; n++) {
      for (const l of byLine.get(n) ?? []) if (near.size < 50) near.add(l);
    }
    if (!near.size) continue;
    // Links on lines of their own in a section about reporting are that section's ways to report.
    if (search(VULN_CONTEXT, heading)) {
      const inPara = [...near].filter((l) => l.text.trim() && para.includes(l.text.trim()));
      let rest = para;
      for (const l of inPara) rest = rest.split(l.text.trim()).join(' ');
      if (inPara.length && !/[\p{L}\p{N}]/u.test(rest)) for (const l of inPara) add('page', l.url);
    }
    // A link in a sentence about sending reports is where they go: "report it to [our maintainer](...)",
    // "use [this link](...) to submit your report". A link that's only mentioned there isn't.
    for (const l of near) {
      const name = l.text.trim();
      const at = name.length >= 3 ? para.indexOf(name) : -1;
      if (at < 0) continue;
      // The words around the link (a sentence may hold an initial, as in "Ralf D. Mueller").
      const around = para.slice(Math.max(0, at - 120), at + name.length + 60);
      const about = search(VULN_CONTEXT, heading) || (search(REPORT_SENTENCE, around) && search(VULN_CONTEXT, around));
      if (!about) continue;
      if (search(LINK_NAMES_PLACE, name) || search(LINK_LEAD, para.slice(Math.max(0, at - 40), at))) {
        if (search(PROFILE_URL, l.url)) add('maintainer', name);
        else add('page', l.url);
      }
    }
  }
  const strength = (c: Channel) => (c.kind === 'page' && !search(REPORTING_LINK, c.label) ? 1 : 0);
  found.sort((a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind) || strength(a) - strength(b));
  const labels = new Set(found.map((c) => c.label));
  const rest = [...weak, ...others].filter((l) => !labels.has(l.url));
  const pointer = !found.length && rest.length && p.words <= 60 ? rest[0] : null;
  return {
    channels: found,
    publicIssues: !found.length && publicIssues,
    noAddress: !found.length && noAddress,
    template: !!search(TEMPLATE_REPORTING, p.text),
    pointer,
    elsewhere: !found.length && elsewhere,
  };
}

const PLATFORM_NAMES: [RegExp, string][] = [
  [re(String.raw`(?i)hackerone`), 'HackerOne'],
  [re(String.raw`(?i)bugcrowd`), 'Bugcrowd'],
  [re(String.raw`(?i)intigriti`), 'Intigriti'],
  [re(String.raw`(?i)yeswehack`), 'YesWeHack'],
  [re(String.raw`(?i)huntr`), 'huntr'],
  [re(String.raw`(?i)open[ \t]*bug[ \t]*bounty`), 'Open Bug Bounty'],
  [re(String.raw`(?i)immunefi`), 'Immunefi'],
  [re(String.raw`(?i)hackenproof`), 'HackenProof'],
  [re(String.raw`(?i)tidelift`), "Tidelift's security contact"],
  [re(String.raw`(?i)bughunters\.google|g\.co/vulnz`), "Google's bug hunters program"],
  [re(String.raw`(?i)msrc|aka\.ms`), "Microsoft's security response center"],
  [re(String.raw`(?i)facebook\.com/whitehat`), "Meta's bug bounty program"],
];

/** A channel in words, for a summary: "by email (security@example.org)". */
export function describeChannel(c: Channel): string {
  switch (c.kind) {
    case 'github':
      return "through GitHub's private vulnerability reporting";
    case 'email':
      return `by email (${c.label})`;
    case 'platform': {
      const named = PLATFORM_NAMES.find(([rx]) => search(rx, c.label));
      return `through ${named ? named[1] : c.label.startsWith('http') ? c.label : `a ${c.label.toLowerCase().replace(/^an? /, '')}`}`;
    }
    case 'form':
      return `through a form (${c.label})`;
    case 'chat':
      return c.label.startsWith('http') ? `by private message (${c.label})` : 'by private message';
    case 'maintainer':
      return 'privately to a maintainer it names';
    case 'page':
      return `as ${c.label} says`;
  }
}

export interface ReportVerdict {
  status: 'pass' | 'warn' | 'info';
  /** What follows the file's name in the summary. */
  says: string;
  channels: ChannelKind[];
}

/**
 * disc-security-md's verdict on a policy (and on the one file it led to, if the scan read it). A policy passes when
 * it gives a private way to report, or points to a security page or policy elsewhere. It warns only when the scan
 * could read it and found no such way; a policy in a language the scan doesn't read, or one that only links somewhere
 * the scan won't follow, gives info.
 */
export function reportVerdict(
  p: Policy,
  r: Reporting,
  followed: { path: string; policy: Policy; reporting: Reporting } | null,
): ReportVerdict {
  const kinds = (x: Reporting) => [...new Set(x.channels.map((c) => c.kind))];
  if (r.channels.length) {
    const c = r.channels[0];
    const says =
      c.kind === 'page' ? `; it points to ${c.label} for how to report` : `; it says to report ${describeChannel(c)}`;
    return { status: 'pass', says, channels: kinds(r) };
  }
  if (followed && followed.reporting.channels.length) {
    const c = followed.reporting.channels[0];
    const how = c.kind === 'page' ? `which points to ${c.label}` : `which says to report ${describeChannel(c)}`;
    return { status: 'pass', says: `; it points to ${followed.path}, ${how}`, channels: kinds(followed.reporting) };
  }
  const own = followed ? followed.reporting : r;
  const doc = followed ? followed.policy : p;
  if (own.template || r.template) {
    return {
      status: 'warn',
      says: " but it still has GitHub's template text where it should say how to report",
      channels: [],
    };
  }
  if (!doc.english && !p.english) {
    return {
      status: 'info',
      says: ", but it isn't in English and the scan found no email address or link in it to report to",
      channels: [],
    };
  }
  if ((own.publicIssues || r.publicIssues) && (own.noAddress || r.noAddress)) {
    return {
      status: 'warn',
      says: ' but it says to report in public issues, and gives no address for private reports',
      channels: [],
    };
  }
  if (own.publicIssues || r.publicIssues) {
    return { status: 'warn', says: ' but it only says to report in public issues, not privately', channels: [] };
  }
  if (r.pointer || own.pointer) {
    const l = (r.pointer ?? own.pointer)!;
    return {
      status: 'info',
      says: `; it points to ${l.url}, which the scan doesn't follow: check that page says how to report privately`,
      channels: [],
    };
  }
  if (own.elsewhere || r.elsewhere) {
    return {
      status: 'info',
      says: "; it says the contact is on a website it doesn't link to: check that page says how to report privately",
      channels: [],
    };
  }
  if (own.noAddress || r.noAddress) {
    return {
      status: 'warn',
      says: ' but it asks for reports by email or message without giving an address',
      channels: [],
    };
  }
  return { status: 'warn', says: ' but it does not say how to report privately', channels: [] };
}

/** Whether the phrase rx finds in a sentence is negated there ("do not open an issue"). */
function negated(sentence: string, rx: RegExp, after = false): boolean {
  const m = search(rx, sentence);
  if (!m) return false;
  if (search(NEGATION, sentence.slice(0, m.index))) return true;
  return after && !!search(NOT_AFTER, sentence.slice(m.index + m[0].length));
}

// --------------------------------------------------------------------------------------- following
/** A policy that's only a path to another file: raw.githubusercontent.com serves a symlink as its target's path. */
const SYMLINK_TEXT = re(String.raw`^[ \t]*(\.{0,2}/?(?:[\w.-]+/)*[\w.-]+\.(?:md|markdown|rst|adoc|txt))[ \t]*\n?\Z`);
const GITHUB_FILE = re(
  String.raw`(?i)^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)/(?:blob|raw)/[^/\s]+/([^\s?#]+)|^https?://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/[^/\s]+/([^\s?#]+)`,
);
const REPO_URL = re(String.raw`(?i)^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/?#]|$)`);
const DOC_FILE = re(String.raw`(?i)\.(?:md|markdown|rst|adoc|asciidoc|txt)$|(?:^|/)security$`);
const POLICY_WORDS = re(String.raw`(?i)secur|vulnerab|disclos|polic|report|advisor|cve|incident|bounty`);
const VERSION_WORDS = re(
  String.raw`(?i)support(?:ed)?[ \t_-]*(?:versions?|tiers?|polic(?:y|ies)|matrix|life.?cycle|releases?)|\bversions?\b|\blts\b|life.?cycle|end.of.life|\beol\b`,
);

/** A link's target as a path in the same repository (owner/name), or null for anything else. */
export function repoPath(url: string, repo: string, from: string): string | null {
  const m = match(GITHUB_FILE, url);
  if (m) {
    const [owner, name, path] = m[1] ? [m[1], m[2], m[3]] : [m[4], m[5], m[6]];
    if (`${owner}/${name}`.toLowerCase() !== repo.toLowerCase()) return null;
    return safePath(decodeURIComponent(path));
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('//')) return null;
  const clean = url.split(/[?#]/)[0];
  if (!clean) return null;
  const base = clean.startsWith('/') ? '' : from.includes('/') ? from.slice(0, from.lastIndexOf('/') + 1) : '';
  return safePath(base + clean.replace(/^\/+/, ''));
}

/** A repository path with . and .. resolved, or null when it climbs out of the repository. */
function safePath(p: string): string | null {
  const out: string[] = [];
  for (const part of p.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (!out.length) return null;
      out.pop();
    } else out.push(part);
  }
  return out.length ? out.join('/') : null;
}

/**
 * The one other file in the same repository worth reading for this policy, or null. A policy that is only a path
 * (a symlink served as text) names it; otherwise it's a linked document that looks like the full policy, when this
 * one says neither how to report nor which versions get fixes.
 */
export function sameRepoLink(
  p: Policy,
  raw: string,
  repo: string,
  needs: { report: boolean; versions: boolean },
): string | null {
  const sym = raw.length < 1024 ? match(SYMLINK_TEXT, raw) : null;
  if (sym) return repoPath(sym[1], repo, p.path);
  if (!needs.report && !needs.versions) return null;
  for (const l of p.links) {
    const path = repoPath(l.url, repo, p.path);
    if (!path || path.toLowerCase() === p.path.toLowerCase() || !search(DOC_FILE, path)) continue;
    const words = `${l.text} ${path}`;
    if ((needs.report && search(POLICY_WORDS, words)) || (needs.versions && search(VERSION_WORDS, words))) return path;
  }
  return null;
}
