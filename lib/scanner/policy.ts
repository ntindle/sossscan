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
  /** The line the table starts on (an index into Policy.lines), and the line after its last. */
  line: number;
  end: number;
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
  /** Words outside links. */
  words: number;
  /** Whether it reads as English (or has English in it), so a missing phrase means something. */
  english: boolean;
  /** The lines that start a list item, which end the sentence before them. */
  items: number[];
  /** What each line is. */
  kinds?: LineKind[];
  /** XMPP addresses it gives for a private message. */
  xmpp?: string[];
  /** Of the email addresses, those to escalate to or for something else (permission to test, a PGP key's). */
  backup?: string[];
  /** The file was longer than MAX_POLICY, and the reader looked only at its start. */
  truncated?: boolean;
  /** It's mostly characters the scan can't read: a binary file, or an encoding it can't tell. */
  garbled?: boolean;
  /** The policy is only a path to another file (a symlink, which raw.githubusercontent.com serves as its target). */
  symlink?: string | null;
}

export type LineKind = 'text' | 'heading' | 'table' | 'code' | 'blank';

// ------------------------------------------------------------------------------------------- markup
const FRONT_MATTER = re(String.raw`(?s)\A---[ \t]*\n.*?\n---[ \t]*\n`);
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
/**
 * An email address. One right after / is part of a URL; one right after a URL's user (postgres://user:password@host)
 * is too, which the code checks (URL_USER), so "Email:security@example.org" still counts.
 */
const EMAIL = re(
  String.raw`(?<![\w.%+/-])([A-Za-z0-9][\w.%+-]*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24})(?![\w@-])`,
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
/** A word before "open issue" that makes it an issue that is open: "no open issue", "an open issue". */
const OPEN_ADJECTIVE = /\b(?:no|an?|the|any|all|each|every|existing|other|some|many|several|current)[ \t]+$/i;
/** An article or a possessive right before a word: "the team", "our security team". */
const ARTICLE_BEFORE = /\b(?:the|a|an|our|your|their|this|that|my)[ \t]+$/i;
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
/**
 * An address with a one-word domain (name@host), which counts only in a sentence about reports. Not in a URL's path,
 * as in ".../release.yml@refs/tags/...".
 */
const SHORT_EMAIL = re(String.raw`(?<![\w.%+/-])([A-Za-z0-9][\w.%+-]*@[A-Za-z][A-Za-z0-9-]{2,})(?![\w@/-])(?!\.\w)`);
/** Addresses that can't receive mail (RFC 2606) or aren't an inbox: a template's placeholder, a git remote. */
const NOT_AN_INBOX = re(
  String.raw`(?i)@(?:[\w-]+\.)*(?:example\.(?:com|org|net)|[\w-]+\.(?:example|test|invalid|localhost)|localhost|(?:your|my)-?(?:domain|company|email|project)[\w.-]*|(?:our|your|my|the)[-_]?(?:company|org|organi[sz]ation|project|domain|team|site|product|app)(?:[-_]?name)?\.[a-z]+|(?:company|org|project|domain|product)[-_]?name\.[a-z]+|domain\.(?:com|tld)|email\.com)$|^git@(?:github|gitlab|bitbucket)\.(?:com|org)$|^(?:noreply|no-reply|donotreply)@|@users\.noreply\.github\.com$|\.(?:png|jpe?g|gif|svg|webp)$`,
);

/** Just before an address, a URL's user and password (https://user:token@github.com): not an address. */
const URL_USER = re(String.raw`://[^\s/@]*:$`);
/** Words that make a sentence one about writing to someone, which a spelled-out address ("team at github.com") needs. */
const CONTACT_VERB = re(
  String.raw`(?i)\b(?:e-?mail(?:ing|ed)?|mail|contact(?:ing)?|write|writing|send|sending|reach(?:ing)?|message|notify|ping|address)\b|\breport\w*\b[^.\n]{0,40}?\bto\b`,
);
/** Mail providers, whose names in "name at gmail com" make it an address. */
const MAIL_PROVIDER = re(
  String.raw`(?i)^(?:gmail|googlemail|yahoo|outlook|hotmail|live|protonmail|proton|pm|icloud|me|gmx|mail|yandex|qq|163|126|fastmail|zoho|posteo|tutanota|tuta|aol|web|mailbox)$`,
);
/** A public list or forum, or an address for questions: not a private way to report. */
const PUBLIC_LIST = re(
  String.raw`(?i)\b(?:public|open|announce(?:ments?)?|users?|discussion|general|community)[ \t]+(?:mailing[ \t]+)?(?:list|forum|group)\b|\bjoin[ \t]+(?:our|the)[ \t]+(?:[\w-]+[ \t]+){0,2}?(?:mailing[ \t]+)?list\b|\bfor[ \t]+(?:general[ \t]+|any[ \t]+)?questions\b|\bsubscribe\b|\bwhere[ \t]+(?:everyone|anyone)[ \t]+can[ \t]+(?:see|read)\b|\bpublicly[ \t]+archived\b`,
);
const PRIVATE_WORD = re(String.raw`(?i)\bprivate(?:ly)?\b|\bconfidential(?:ly)?\b|\bencrypt`);
/** An address to go to only when the first gets no answer, or for something other than a report (permission to test). */
const ESCALATION = re(
  String.raw`(?i)\bescalat|\bpermission\b|\bauthori[sz]ation\b|\bif[ \t]+you[ \t]+(?:do[ \t]+not|don't|cannot|can't|haven't|have[ \t]+not)[ \t]+(?:receive|hear|get)\b|\bno[ \t]+(?:response|reply|answer)\b|\bbackup\b|\bas[ \t]+a[ \t]+last[ \t]+resort\b|\bcc\b|\bcopy[ \t]+(?:in|to)\b`,
);
/** XMPP (Jabber): its addresses look like email addresses. */
const XMPP_WORD = re(String.raw`(?i)\b(?:xmpp|jabber)\b`);
/** A chat room, which anyone can join, rather than a person. */
const CHAT_ROOM = re(String.raw`(?i)\bchat[ \t]?rooms?\b|\bmuc\b|\bgroup[ \t]+chat\b|\brooms?\b|\bchannels?\b`);
const ROOM_DOMAIN = re(String.raw`(?i)@(?:conference|muc|chat|rooms?|chatrooms?)\.`);
/** Just before an address: a PGP key's ID or user ID, which isn't where reports go. */
const KEY_ID = re(
  String.raw`(?i)\b(?:key[ \t]+id|uid|user[ \t]+id|fingerprint|pgp[ \t]+key|gpg[ \t]+key|public[ \t]+key)\b[^.\n]{0,25}$`,
);
/** user@EXAMPLE.COM is a Kerberos principal in a policy that's about Kerberos. */
const KERBEROS = re(String.raw`(?i)\bkerberos\b|\bkinit\b|\bkeytab|\bkrb5?\b|\bprincipals?\b|\brealms?\b`);

/**
 * Common English words that aren't names of anything (a policy in another language keeps "Report a vulnerability",
 * "Security" or "issue" in English, so those don't count), and that other languages don't use ("in", "is", "a").
 */
const ENGLISH = re(
  String.raw`(?i)\b(?:the|and|please|you|your|we|us|our|with|this|that|these|those|which|should|would|could|have|has|been|from|they|their|there|about|into|than|then|them|also|only|will|not|for|are|if|any|when|what|who|how|its)\b`,
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
function codeSpans(t: string, fn: (code: string) => string, range?: (start: number, end: number) => void): string {
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
    range?.(open.at, runs[close].at + runs[close].len);
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

/** Zero-width characters, which can sit unseen inside an address (secu\u200brity@example.org). */
const ZERO_WIDTH = /[\u200b\u200c\u200d\u2060\ufeff]/g;

/**
 * Text that was UTF-16 but was read as UTF-8, so every other character is a NUL: the NULs and the byte-order mark are
 * dropped, which keeps its ASCII. (scan.ts decodes a policy's bytes properly; this is for callers that have text.)
 */
function fromUtf16(s: string): string {
  const head = s.slice(0, 2000);
  let nul = 0;
  for (let k = 0; k < head.length; k++) if (head.charCodeAt(k) === 0) nul++;
  if (head.length < 8 || nul < head.length * 0.2) return s;
  return s.replace(/^\uFFFD{1,2}/, '').replace(/\u0000/g, '');
}

/** Whether text is mostly characters that can't be read (a binary file, or text in an encoding the scan can't tell). */
function garbled(s: string): boolean {
  const head = s.slice(0, 4000);
  if (!head.trim()) return false;
  let bad = 0;
  for (let k = 0; k < head.length; k++) {
    const c = head.charCodeAt(k);
    if (c === 0xfffd || (c < 0x20 && c !== 9 && c !== 10 && c !== 13 && c !== 12)) bad++;
  }
  return bad > head.length * 0.1;
}

/** The [start, end) offsets of the code spans on a line, found as codeSpans() finds them. */
function codeRanges(line: string): [number, number][] {
  const out: [number, number][] = [];
  if (!line.includes('`')) return out;
  codeSpans(
    line,
    () => '',
    (start, end) => out.push([start, end]),
  );
  return out;
}

const HIDDEN_OPEN = re(String.raw`(?i)<!--|<script\b|<style\b|\{%|\{\{`);
const SCRIPT_CLOSE = re(String.raw`(?i)</script[ \t]*>`);
const STYLE_CLOSE = re(String.raw`(?i)</style[ \t]*>`);

/** Where the last match of rx in s starts, or -1. */
function lastMatch(rx: RegExp, s: string): number {
  const g = new RegExp(rx.source, rx.flags + 'g');
  let last = -1;
  for (let m = g.exec(s); m; m = g.exec(s)) last = m.index;
  return last;
}

/**
 * What a reader doesn't see, blanked out (keeping line breaks): HTML comments, scripts and styles, and Liquid template
 * tags ({% ... %}, {{ ... }}). Only outside code: a `<!--` in a code span or a fenced block is text. A comment runs to
 * its -->, across lines; one that never closes hides the rest of the file only when it starts a line. A script or a
 * style is hidden only as GitHub hides one, as an HTML block: it starts a line (after at most 3 spaces) and closes
 * later. In a sentence ("we strip <script> tags") GitHub shows the tag as text, and the words after it.
 */
function stripHidden(s: string): string {
  if (!search(HIDDEN_OPEN, s)) return s;
  const opens = new RegExp(HIDDEN_OPEN.source, HIDDEN_OPEN.flags + 'g');
  const lines = s.split('\n');
  const lastClose = s.lastIndexOf('-->');
  const lastScript = lastMatch(SCRIPT_CLOSE, s);
  const lastStyle = lastMatch(STYLE_CLOSE, s);
  let offset = 0;
  let fence: string | null = null;
  /** What closes the hidden part we're in, if we're in one. */
  let until: RegExp | 'comment' | null = null;
  for (let i = 0; i < lines.length; offset += lines[i].length + 1, i++) {
    const line = lines[i];
    if (!until) {
      const f = match(FENCE, line);
      if (fence) {
        if (f && f[1][0] === fence[0] && f[1].length >= fence.length) fence = null;
        continue;
      }
      if (f) {
        fence = f[1];
        continue;
      }
    }
    const code = until ? [] : codeRanges(line);
    let c = 0;
    let out = '';
    let from = 0;
    for (;;) {
      if (until) {
        // Inside something hidden: look for its end.
        let end = -1;
        if (until === 'comment') {
          const k = line.indexOf('-->', from);
          if (k >= 0) end = k + 3;
        } else {
          const close = new RegExp(until.source, until.flags + 'g');
          close.lastIndex = from;
          const m = close.exec(line);
          if (m) end = m.index + m[0].length;
        }
        if (end < 0) break;
        from = end;
        until = null;
        continue;
      }
      opens.lastIndex = from;
      const m = opens.exec(line);
      if (!m) {
        out += line.slice(from);
        break;
      }
      const at = m.index;
      while (c < code.length && code[c][1] <= at) c++;
      const opener = m[0].toLowerCase();
      const inCode = c < code.length && code[c][0] <= at;
      const unclosed =
        opener === '{%' || opener === '{{'
          ? line.indexOf(opener === '{%' ? '%}' : '}}', at + 2) < 0
          : opener === '<!--'
            ? lastClose < offset + at + 4 && !!line.slice(0, at).trim()
            : !/^ {0,3}$/.test(line.slice(0, at)) || (opener === '<script' ? lastScript : lastStyle) < offset + at;
      if (inCode || unclosed) {
        // Text: a code span, a template opener without its end, a comment opener that never closes after text, or a
        // script or style tag that isn't an HTML block.
        out += line.slice(from, at + m[0].length);
        from = at + m[0].length;
        continue;
      }
      out += line.slice(from, at);
      if (opener === '{%' || opener === '{{') {
        from = line.indexOf(opener === '{%' ? '%}' : '}}', at + 2) + 2;
        continue;
      }
      until = opener === '<!--' ? 'comment' : opener === '<script' ? SCRIPT_CLOSE : STYLE_CLOSE;
      from = at + m[0].length;
    }
    lines[i] = out;
  }
  return lines.join('\n');
}

/** Comments, scripts, template tags and front matter removed (as blank lines), line endings normalized. */
function prepare(raw: string, format: Format): string {
  let s = raw
    .replace(/^\uFEFF/, '')
    .replace(/\r\n?/g, '\n')
    .replace(ZERO_WIDTH, '');
  s = blank(FRONT_MATTER, s);
  s = stripHidden(s);
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
  // Curly apostrophes become straight ones, so "don’t" reads as "don't" everywhere.
  return t
    .replace(/[\u2018\u2019\u02bc]/g, "'")
    .replace(/[ \t\u00a0]+/g, ' ')
    .trim();
}

// ------------------------------------------------------------------------------------------ headings
/** The characters an RST title's line (or a Markdown setext underline) is made of. */
const BORDER_CHARS = '=-~^"\'`#*+.:_<>!';

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
    // Each pattern runs only when the line starts with what it needs.
    if (format === 'asciidoc' && t[0] === '=' && (m = match(ADOC_TITLE, line))) {
      headings.push({ text: inline(m[2].trimEnd(), format), level: m[1].length, line: i });
      continue;
    }
    if (format !== 'rst' && t[0] === '#' && (m = match(ATX, line))) {
      const text = inline(atxText(m[2] ?? ''), format);
      if (text) headings.push({ text, level: m[1].length, line: i });
      continue;
    }
    const border = BORDER_CHARS.includes(line[0] ?? '\n');
    if (
      format === 'rst' &&
      border &&
      match(RST_LINE, line) &&
      next.trim() &&
      i + 2 < src.length &&
      match(RST_LINE, src[i + 2])
    ) {
      // A title with an overline and an underline.
      headings.push({ text: inline(next, format), level: rstLevel('o' + line.trim()[0]), line: i + 1 });
      underline.add(i);
      underline.add(i + 2);
      i += 2;
      continue;
    }
    const isBorder = (border && match(RST_LINE, line)) || ((t[0] === '=' || t[0] === '-') && match(SETEXT, line));
    const underlined = format === 'rst' ? BORDER_CHARS.includes(next[0] ?? '\n') : /^ {0,3}[=-]/.test(next);
    if (underlined && !isBorder && !t.startsWith('|') && !match(LIST_ITEM, line) && !search(GRID_BORDER, line)) {
      const um = format === 'rst' ? match(RST_LINE, next) : match(SETEXT, next);
      if (um && next.trim().length >= Math.min(3, t.length)) {
        const level = format === 'rst' ? rstLevel('u' + next.trim()[0]) : next.trim()[0] === '=' ? 1 : 2;
        headings.push({ text: inline(t, format), level, line: i });
        underline.add(i + 1);
        continue;
      }
    }
    const h = line.includes('<') ? htmlHeading(line) : null;
    if (h) {
      const text = inline(h.inner, format);
      if (text) headings.push({ text, level: h.level, line: i });
      continue;
    }
    if ((t.startsWith('**') || t.startsWith('__')) && (m = match(BOLD_LINE, line))) {
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
        tables.push({ header, rows, line: i, end: j, kind: 'pipe' });
        for (let k = i; k < j; k++) used.add(k);
        i = j - 1;
        continue;
      }
    }
    // Lines that start with a pipe but have no separator row: read as rows without a header.
    if (format !== 'asciidoc' && line.trim().startsWith('|') && line.trim().length > 1 && !search(GRID_BORDER, line)) {
      const split: string[][] = [];
      let j = i;
      for (; j < src.length && src[j].trim().startsWith('|') && !code[j] && !search(GRID_BORDER, src[j]); j++) {
        split.push(splitPipes(src[j]));
      }
      if (split.some((r) => r.length > 1)) {
        // Only a table's cells are read as text (a run of "|a" lines isn't one).
        const rows = split.map((r) => r.map(cell));
        tables.push({ header: null, rows, line: i, end: j, kind: 'pipe' });
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
      tables.push({ header, rows, line: i, end: j, kind: 'grid' });
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
        tables.push({ header, rows, line: i, end: j, kind: 'simple' });
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
      tables.push({ header, rows, line: i, end: j, kind: isList ? 'list' : 'csv' });
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
      tables.push({ header, rows, line: i, end: j + 1, kind: 'asciidoc' });
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
    out.push({ header: headerRow, rows, line: startLine(start), end: startLine(end - 1) + 1, kind: 'html' });
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

/** A mailto: link's target or a found address, as an address: decoded, without a name around it or a ?subject. */
function addressOf(e: string): string | null {
  let a = e.replace(/^mailto:/i, '');
  if (a.includes('%')) {
    try {
      a = decodeURIComponent(a);
    } catch {
      // Not valid percent-encoding: kept as it is.
    }
  }
  const angle = /<([^<>]*)>/.exec(a);
  if (angle) a = angle[1];
  a = trimEndOf(a.split(/[?\\]/)[0].trim(), '.,;:');
  const at = a.indexOf('@');
  if (at < 1 || /[\s<>"]/.test(a) || !a.slice(at + 1).includes('.')) return null;
  return a;
}

/**
 * The email addresses in a policy, written plainly, in a mailto: link, or spelled out (name [at] example [dot] org),
 * the main ones first; and the XMPP addresses it gives for private messages. Read paragraph by paragraph, so an
 * address split across lines counts. An address in a supported-versions table, on a public list or for questions,
 * in a URL, for a chat room, or spelled out with ordinary words and no word about writing to it, isn't one.
 */
function addressesOf(
  paras: Block[],
  links: Link[],
  text: string,
): { emails: string[]; xmpp: string[]; backup: string[] } {
  const kerberos = !!search(KERBEROS, text);
  const found: { addr: string; rank: number; order: number }[] = [];
  const xmpp: string[] = [];
  const seen = new Set<string>();
  /** Where an address is (its paragraph, then its place in it), so the first one given comes first. */
  let order = 0;
  /** What a sentence says about the addresses in it, read once for all of them. */
  type Context = { xmpp: boolean; room: boolean; public: boolean; escalation: boolean };
  const contextOf = (sentence: string, heading: string): Context => {
    const list = search(PUBLIC_LIST, sentence);
    return {
      xmpp: !!search(XMPP_WORD, sentence),
      room: !!search(CHAT_ROOM, sentence),
      // A public list, unless the sentence says not to use it ("you don't want to report on a public mailing list").
      public: !!list && !search(PRIVATE_WORD, sentence) && !search(NEGATION, sentence.slice(0, list.index)),
      escalation: !!search(ESCALATION, `${heading} ${sentence}`),
    };
  };
  /** Where the sentence (or link) being read starts, as an order: an address's place in it is added to this. */
  let base = 0;
  const add = (raw: string, ctx: Context, at = 0, before = '') => {
    const addr = addressOf(raw);
    if (!addr) return;
    order = base + at;
    const [local, domain = ''] = addr.split('@');
    // user@EXAMPLE.COM, a lower-case name at a domain in capitals, is a Kerberos principal in a policy about Kerberos.
    if (kerberos && /[a-z]/.test(local) && /[A-Z]/.test(domain) && !/[a-z]/.test(domain)) return;
    if (search(NOT_AN_INBOX, addr) || seen.has(addr.toLowerCase())) return;
    // A chat room's address, or an announcement list's, which anyone can join.
    if (search(ROOM_DOMAIN, addr) || /announce/i.test(local)) return;
    if (ctx.xmpp) {
      // An XMPP address: a person's is a private message, a room's isn't.
      seen.add(addr.toLowerCase());
      if (!ctx.room) xmpp.push(addr);
      return;
    }
    if (ctx.public) return;
    seen.add(addr.toLowerCase());
    // An address to escalate to, or a PGP key's ("Key ID: name@example.org"), comes after the main one.
    found.push({ addr, rank: ctx.escalation || search(KEY_ID, before.slice(-40)) ? 1 : 0, order });
  };
  // The paragraph each line is in, for the links.
  const paraAt = new Map<number, Block>();
  for (const b of paras) for (let n = b.start; n < b.end; n++) paraAt.set(n, b);
  const versionsRow = (b: Block | undefined) => !!b && b.kind === 'table' && !!b.table && versionsTable(b.table);
  // The spelled-out dots of a domain ([dot], (.), " dot ") become dots.
  const dots = (d: string) =>
    d
      .replace(/[ \t]+/g, ' ')
      .replace(/ - /g, '-')
      .replace(/ ?(?:[[({<] ?(?:dot|\.) ?[\])}>]|\bdot\b|\.) ?/gi, '.');
  const index = new Map(paras.map((b, k) => [b, k]));
  for (const l of links) {
    if (!/^mailto:/i.test(l.url)) continue;
    const b = paraAt.get(l.lines?.[0] ?? -1);
    if (versionsRow(b)) continue;
    const name = l.text.trim();
    const sentence = b ? (sentencesOf(b.text).find((x) => name && x.includes(name)) ?? b.text) : '';
    const at = b ? Math.max(0, b.text.indexOf(name)) : 0;
    base = b ? index.get(b)! * 1e6 : 0;
    add(l.url, contextOf(sentence, b?.heading ?? ''), at, b ? b.text.slice(0, at) : '');
  }
  paras.forEach((b, k) => {
    // Headings too: a bold line with only an address in it reads as one.
    if (versionsRow(b)) return;
    const heading = b.heading ?? '';
    let at = 0;
    for (const raw of sentencesOf(b.text)) {
      at = b.text.indexOf(raw, at);
      base = k * 1e6 + at;
      // Emphasis that opens on one line and closes on the next (__name [at] example\n[dot] org__) is still there.
      // The marks become spaces (same length), which keep an address apart from what follows ("com**으로").
      const s = raw
        .replace(/(^|[^\w*])([*_]{1,3})(?=[A-Za-z0-9])/g, (_, a: string, m: string) => a + ' '.repeat(m.length))
        .replace(/([A-Za-z0-9])([*_]{1,3})(?=$|[^\w*])/g, (_, a: string, m: string) => a + ' '.repeat(m.length));
      // Each pattern runs only when the sentence has an @, an "at" or a ＠: most sentences have none.
      const atSign = s.includes('@');
      const atWord = /\bat\b/i.test(s);
      if (!atSign && !atWord && !s.includes('\uff20')) continue;
      const ctx = contextOf(s, heading);
      if (atSign) {
        for (const m of finditer(EMAIL, s)) {
          if (!search(URL_USER, s.slice(Math.max(0, m.index - 200), m.index)))
            add(m[1], ctx, m.index, s.slice(0, m.index));
        }
        for (const m of finditer(MAILTO_TEXT, s)) add(m[1], ctx, m.index, s.slice(0, m.index));
        for (const m of finditer(SPACED_AT, s)) add(`${m[1]}@${m[2]}`, ctx, m.index, s.slice(0, m.index));
      }
      for (const m of finditer(OBFUSCATED_EMAIL, s)) add(`${m[1]}@${dots(m[2])}`, ctx, m.index, s.slice(0, m.index));
      if (!atWord) continue;
      // An "at" in plain words needs a word about writing to someone in the sentence (or its heading).
      const verb = !!search(CONTACT_VERB, `${heading} ${s}`);
      // "name at example dot org": the spelled-out dot is enough.
      for (const m of finditer(SPELLED_EMAIL, s)) add(`${m[1]}@${dots(m[2])}`, ctx, m.index);
      for (const m of finditer(SPELLED_AT, s)) {
        if (m[1]) add(`${m[1]}@${m[2]}`, ctx, m.index);
        // "contact the team at github.com" says where the team is: an article makes the name a word, not an inbox.
        else if (verb && !ARTICLE_BEFORE.test(s.slice(Math.max(0, m.index - 12), m.index))) {
          add(`${m[3]}@${m[4]}`, ctx, m.index);
        }
      }
      for (const m of finditer(SPELLED_SPACED, s)) {
        if (verb || /[ \t]AT[ \t]/.test(m[0]) || search(MAIL_PROVIDER, m[2])) {
          add(`${m[1]}@${m[2]}.${m[3]}`, ctx, m.index);
        }
      }
      for (const m of finditer(SPELLED_TO, s)) add(`${m[1]}@${m[2]}`, ctx, m.index);
      for (const m of finditer(QUOTED_AT, s)) add(`${m[1]}@${m[2]}`, ctx, m.index);
    }
  });
  found.sort((a, b) => a.rank - b.rank || a.order - b.order);
  return { emails: found.map((f) => f.addr), xmpp, backup: found.filter((f) => f.rank).map((f) => f.addr) };
}

/** A paragraph's sentences. */
function sentencesOf(para: string): string[] {
  return para.split(/(?<=[.!?。！？])\s+/);
}

/** Whether a table is a supported-versions table: a column for versions or releases. */
function versionsTable(t: Table): boolean {
  const head = t.header ?? t.rows[0] ?? [];
  return head.some((h) => /\b(?:versions?|releases?|branch(?:es)?|series)\b|版本|バージョン|버전/i.test(h));
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
  const body = fromUtf16(truncated ? raw.slice(0, MAX_POLICY) : raw);
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
    const first = l.trimStart()[0] ?? '';
    if (format === 'rst' && (first === '.' || first === ':')) t = t.replace(RST_DIRECTIVE, '').replace(RST_FIELD, '');
    if (format === 'asciidoc' && first === '|') t = t.replace(/(?:^|\s)[a-z]?\|/g, ' ');
    if (t.trim().startsWith('|') || (used.has(i) && t.includes('|'))) t = splitPipes(t).join(' ');
    if (first === '>') t = t.replace(ADMONITION, '');
    if (first === '-' || first === '*' || first === '+' || (first >= '0' && first <= '9')) t = t.replace(LIST_MARK, '');
    return inline(t, format);
  });
  // What each line is: headings, table rows and code are left out when telling the language.
  const tableAt = new Map<number, Table>();
  for (const t of tables) for (let k = t.line; k < t.end; k++) if (!tableAt.has(k)) tableAt.set(k, t);
  const kinds: LineKind[] = lines.map((l, i) =>
    headingAt.has(i) || underline.has(i)
      ? 'heading'
      : code[i]
        ? 'code'
        : tableAt.has(i) || used.has(i)
          ? 'table'
          : l.trim()
            ? 'text'
            : 'blank',
  );
  // Words, without URLs; and the words of each line of prose, without code spans either.
  const urls = new Set(links.map((l) => l.url));
  const noUrls = (t: string) =>
    /[:/.@]/.test(t)
      ? t.replace(/\S+/g, (w) => (w.includes('://') || urls.has(w) || urls.has(trimEndOf(w, ').,;:!?\'">]')) ? ' ' : w))
      : t;
  const prose = lines.map((l, i) => {
    if (kinds[i] !== 'text') return '';
    return noUrls(
      srcLines[i].includes('`')
        ? inline(
            codeSpans(srcLines[i], () => ' '),
            format,
          )
        : l,
    );
  });
  const text = lines.join('\n');
  const paras = blocksOf(lines, headings, items, kinds, tableAt, prose);
  const { emails, xmpp, backup } = addressesOf(paras, links, text);
  const all = prose.join('\n');
  const lang = languageOf(all, true);
  const sym = symlinkTarget(body);
  const p: Policy = {
    path,
    format,
    lines,
    text,
    headings,
    links,
    emails,
    xmpp,
    backup,
    tables,
    words: wordCount(noUrls(text)),
    // A policy of a few words (a link and "see") is too short to tell its language: it's read as English.
    english: lang !== 'other',
    items,
    kinds,
    truncated,
    garbled: garbled(body),
    symlink: sym,
  };
  blockCache.set(p, paras);
  return p;
}

/** How many words a text has: Latin ones, and Chinese, Japanese, Korean or other scripts' counted by length. */
function wordCount(t: string): number {
  const { latin, other } = scripts(t);
  return Math.round(latin + other);
}

function scripts(t: string): { latin: number; other: number } {
  const latin = (t.match(/[A-Za-z]{2,}/g) ?? []).length;
  if (!/[\u0370-\uffff]/.test(t)) return { latin, other: 0 };
  // Chinese, Japanese and Korean words are about two characters long; Cyrillic, Greek, Hebrew, Arabic, Hindi or Thai
  // ones about six.
  const cjk = (t.match(/[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af\uf900-\ufaff]/g) ?? []).length;
  const rest = (t.match(/[\u0370-\u03ff\u0400-\u04ff\u0590-\u06ff\u0900-\u097f\u0e00-\u0e7f]/g) ?? []).length;
  return { latin, other: cjk / 2 + rest / 6 };
}

export type Language = 'english' | 'other' | 'unknown';

/**
 * Whether prose reads as English: enough common English words among its words. Another language needs evidence:
 * mostly another script, or common words of another language. A paragraph of Latin words that are neither (a list of
 * advisory IDs, code) is unknown; so is one too short to tell. A whole policy of many words with no English ones isn't
 * English (whole).
 */
function languageOf(t: string, whole = false): Language {
  const { latin, other } = scripts(t);
  if (other >= 3 && latin < 0.3 * other) return 'other';
  const hits = finditer(ENGLISH, t).length;
  if (hits >= 2 && hits >= 0.08 * latin) return 'english';
  if (other >= 3) return 'other';
  const foreign = (t.match(FOREIGN_WORDS) ?? []).length;
  if (latin >= 4 && foreign >= 2 && foreign > hits) return 'other';
  if (latin < 12) return 'unknown';
  // Terse English ("Vulnerability reports: GitHub issues. Scope: core library") has the words of a policy instead,
  // and hardly a letter outside ASCII: Turkish or German that borrows "issue" and "security advisory" has ü and ş.
  if (!whole || hits >= 0.03 * latin) return 'unknown';
  const policyWords = new Set(finditer(ENGLISH_POLICY, t).map((m) => m[0].toLowerCase()));
  const accented = (t.match(/[\u00c0-\u024f]/g) ?? []).length;
  const ascii = (t.match(/[A-Za-z]/g) ?? []).length;
  return policyWords.size >= 3 && accented <= 0.005 * (ascii + accented) ? 'unknown' : 'other';
}

/** Words of security policies in English, which terse English has where it lacks the common words. */
const ENGLISH_POLICY = re(
  String.raw`(?i)\b(?:reports?|reporting|vulnerability|vulnerabilities|security|issues?|response|scope|supported|versions?|contact|email|disclosure|fix(?:es|ed)?|patch(?:es|ed)?|maintainers?|privately|advisory|advisories|bugs?|releases?)\b`,
);

/**
 * Common words of other languages written in Latin letters (German, Dutch, French, Spanish, Portuguese, Italian,
 * Scandinavian, Polish, Czech, Hungarian, Romanian, Turkish, Indonesian, Vietnamese): evidence that a paragraph isn't
 * English. Plain JavaScript (it decides nothing on its own), with Unicode letters as word boundaries.
 */
const FOREIGN_WORDS =
  /(?<!\p{L})(?:de|la|le|les|des|du|une|et|est|pour|que|qui|pas|avec|sur|dans|nous|vous|votre|merci|mais|el|los|las|del|en|para|por|una|es|lo|se|su|sus|al|como|pero|favor|usted|und|der|die|das|den|dem|ein|eine|einen|nicht|mit|für|ist|sie|auf|bei|zu|über|bitte|wir|ihr|sich|oder|auch|wenn|nur|vom|zum|zur|im|aus|durch|ohne|het|een|van|niet|voor|dat|il|di|che|della|delle|dei|gli|em|um|uma|não|na|ao|à|é|você|seu|sua|och|att|är|inte|för|på|og|ikke|til|jest|nie|się|je|že|nebo|és|az|egy|hogy|nem|și|în|pentru|este|ve|bir|bu|için|ile|yang|untuk|dengan|tidak|ini|itu|atau|dari|pada|và|của|các|là|có|không|được|cho|này|một|những|với|bạn)(?!\p{L})/giu;

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
  /** For GitHub's form: the other repository it's in, when it isn't this one's. */
  repo?: string;
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
  /** It says how to report is in the README, which the scan doesn't read. */
  readme?: boolean;
  /** The part of it about reporting (or all of it) isn't in English, so a missing phrase means nothing. */
  foreign?: boolean;
  /** The file in the same repository it points to for how to report (or is a link to), when it says nothing itself. */
  local?: string | null;
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
/**
 * GitHub's private vulnerability reporting, in an English sentence: its names, the button and the steps to it, an
 * advisory the reporter opens, or reporting privately through GitHub. (MAINTAINER_STEP and the like rule out the
 * maintainers' own steps: "we will open a security advisory".)
 */
const GITHUB_REPORTING_TEXT = re(
  String.raw`(?i)` +
    [
      String.raw`\bprivate(?:ly)?[ \t]+(?:vulnerability[ \t]+report(?:s|ing)?|security[ \t]+reporting)\b`,
      String.raw`\bgithub\b[^.\n]{0,60}?\bprivate[ \t]+reporting\b|\bprivate[ \t]+reporting\b[^.\n]{0,60}?\bgithub\b`,
      String.raw`\breport[ \t]+a[ \t]+vulnerability["'\u201d*_]*[ \t]+(?:button|tab|form|link|feature|option|menu|page)\b`,
      String.raw`\b(?:click(?:ing)?|use|using|choose|choosing|select|selecting|press|pressing|hit|via|through|under|the)[ \t]+(?:on[ \t]+)?["'\u201c*_]*report[ \t]+a[ \t]+vulnerability\b`,
      String.raw`\bsecurity["'\u201d*_]*[ \t]*(?:tab[ \t]*)?(?:\u2192|->|>|\u203a|\u00bb|/)[ \t]*(?:advisories[ \t]*(?:\u2192|->|>|\u203a|\u00bb|/)[ \t]*)?["'\u201c*_]*report[ \t]+a[ \t]+vulnerability\b`,
      String.raw`\bsecurity["'\u201d*_]*(?:[ \t]+tab)?[,;]?[ \t]+(?:and[ \t]+)?then[ \t]+(?:(?:click|select|choose|press)[ \t]+(?:on[ \t]+)?)?["'\u201c*_]*report[ \t]+a[ \t]+vulnerability\b`,
      String.raw`\b(?:the|github(?:'s)?|repository(?:'s)?|repo(?:'s)?|project(?:'s)?|its|our|to|open|under|in|on|via|through|from|click(?:[ \t]+on)?|select)[ \t]+["'*_]*security["'\u201d*_ \t]+tab\b`,
      String.raw`\b(?:github|repository|repo)(?:'s)?[ \t]+["'*_]*security["'\u201d*_ \t]+(?:page|section)\b`,
      String.raw`\bsecurity[ \t]+(?:page|section)[ \t]+(?:of|on|in|for)[ \t]+(?:the[ \t]+|this[ \t]+|our[ \t]+)?(?:github[ \t]+)?(?:repository|repo)\b`,
      String.raw`\b(?:open|opening|create|creating|draft|drafting|submit|submitting|file|filing|raise|raising|start|starting|use|using|report|new|private)[ \t]+(?:a[ \t]+|an[ \t]+|the[ \t]+)?(?:(?:new|private|draft)[ \t]+)*(?:github[ \t]+)?(?:repository[ \t]+)?security[ \t]+advisor(?:y|ies)\b`,
      String.raw`\b(?:via|through|using|with)[ \t]+(?:the[ \t]+|a[ \t]+)?(?:github(?:'s)?[ \t]+)?(?:private[ \t]+)?security[ \t]+advisor(?:y|ies)\b(?![ \t]+(?:will|are|is|were|was|published|database)\b)`,
      String.raw`\bgithub(?:'s)?[ \t]+(?:private[ \t]+)?advisor(?:y|ies)\b`,
      String.raw`\b(?:open|opening|create|creating|draft|drafting|submit|submitting|file|filing|start|starting)[ \t]+(?:a|an)[ \t]+(?:(?:new|private|draft)[ \t]+)*advisory\b`,
      String.raw`\bprivate(?:ly)?\b(?:(?!\bnot\b|n't\b|\bnever\b)[^.\n]){0,40}?\b(?:via|through|using|on|with|in)[ \t]+(?:the[ \t]+)?github\b(?![ \t]+(?:issues?|discussions?|pull)\b)`,
    ].join('|'),
);
/** Before a mention of GitHub's advisories: the maintainers as the ones who act ("we will", "the team will"). */
const MAINTAINER_STEP = re(
  String.raw`(?i)\b(?:we|i|they|maintainers?|the[ \t]+(?:[\w-]+[ \t]+){0,3}?(?:team|maintainers?|developers?|project|owners?|staff)|our[ \t]+(?:[\w-]+[ \t]+){0,2}?(?:team|maintainers?|developers?))\b[^.\n]{0,40}?(?:\b(?:will|would|shall|may|might|can|could|then)\b|'ll\b)`,
);
/** After the maintainers as subject, words that make it the reporter's step after all ("we ask that you open..."). */
const REPORTER_WORD = re(
  String.raw`(?i)\b(?:you|your|please)\b|\b(?:accept|receiv|welcome|prefer|recommend|ask|encourag|review|handl|triag)\w*`,
);
/** After a mention of an advisory: it's done to it ("a draft advisory will be created"), so it's the maintainers' step. */
const ADVISORY_PASSIVE = re(
  String.raw`(?i)^[^.\n]{0,20}?\b(?:will|would|shall|is|are|gets?|was|were|may|can)[ \t]+(?:then[ \t]+|also[ \t]+)?(?:be[ \t]+|been[ \t]+|get[ \t]+)?(?:created|drafted|opened|published|issued|filed|released|used|made)\b`,
);
/** Before a mention of GitHub's advisories: where advisories are published or listed, not where reports go. */
const PUBLISHED = re(String.raw`(?i)\b(?:publish\w*|appears?|listed|subscribe|watch\w*)\b`);
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
  String.raw`(?i)\b(?:contact|e-?mail|reach|write|report|see|visit|check|read|consult|find)\w*\b[^.\n]{0,80}\b(?:on|at|in|via|through)[ \t]+(?:the[ \t]+|our[ \t]+|its[ \t]+)?(?:project(?:'s)?[ \t]+)?(?:web[ \t]?(?:site|page)|homepage|site)\b`,
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
  String.raw`(?i)^[^.\n]{0,25}?\b(?:(?:is|are)[ \t]+(?:not|n't)|isn't|aren't)[ \t]+(?:currently[ \t]+|yet[ \t]+)?(?:enabled|available|active|supported|set[ \t]+up|turned[ \t]+on|configured)\b|^[^.\n]{0,25}?\b(?:is|are|was|were|has[ \t]+been|have[ \t]+been)[ \t]+(?:now[ \t]+|currently[ \t]+|temporarily[ \t]+)?(?:disabled|unavailable|off|closed|paused|suspended|discontinued|ended|retired|inactive|shut[ \t]+down)\b`,
);
const NEGATION = re(
  String.raw`(?i)\b(?:not|never|don't|do[ \t]+not|avoid|instead[ \t]+of|rather[ \t]+than|n't|no[ \t]+public|refrain|non-?security|non-?sensitive|non-?critical|feature[ \t]+requests?|regular[ \t]+bugs?|general[ \t]+bugs?|other[ \t]+bugs?|ordinary[ \t]+bugs?|low[- ]severity)\b`,
);
const ASKS_FOR_MAIL = re(
  String.raw`(?i)\b(?:e-?mail|mail[ \t]+(?:us|me|the)|private[ \t]+message|direct[ \t]+message|contact(?:ing)?[ \t]+(?:us|me|the[ \t]+(?:maintainers?|team|author|owner|developers?|project))|reach[ \t]+out[ \t]+to[ \t]+(?:us|me|the|a|one|our|any)|report\w*[ \t]+(?:\w+[ \t]+){0,3}privately|privately[ \t]+to[ \t]+the)\b`,
);
/** Words that make a sentence about reporting a problem. */
const REPORT_WORD = re(String.raw`(?i)\b(?:report|vulnerab|secur|issue|bug|disclos|problem|flaw|exploit)`);
/** The reporting paragraph of GitHub's template, in English or as GitHub's template is often translated. */
const TEMPLATE_REPORTING = re(
  String.raw`(?i)use[ \t]+this[ \t]+section[ \t]+to[ \t]+tell[ \t]+people[ \t]+how[ \t]+to[ \t]+report[ \t]+a[ \t]+vulnerability|gunakan[ \t]+bagian[ \t]+ini[ \t]+untuk[ \t]+memberi[ \t]+tahu[ \t]+orang(?:-orang)?[ \t]+(?:tentang[ \t]+)?cara[ \t]+melaporkan`,
);
/** The heading of a part about reporting: where a missing way to report matters, and where links on their own count. */
const REPORT_HEADING = re(
  String.raw`(?i)\breport|disclos|\bcontact|\bsubmit|security[ \t]+(?:issues?|bugs?|problems?|concerns?|reports?|team)`,
);
/** A chat handle given for a platform: Discord @name, Telegram: @name, Discord name#1234. */
const CHAT_HANDLE = re(
  String.raw`(?i)\b(discord|telegram|slack|matrix|signal|wechat|qq|keybase|element|session|threema|zulip|gitter)\b[^.\n]{0,30}?(?:(?<![\w.])@[\w.-]{2,}|\b[\w.]{2,32}#\d{4}\b)`,
);
/** A request to write on a chat platform: "tell me on Discord", "message us via Telegram". */
const CHAT_REQUEST = re(
  String.raw`(?i)\b(?:tell|message|ping|contact|reach|dm|pm|write|notify|let[ \t]+(?:me|us)[ \t]+know)\b[^.\n]{0,30}?\b(?:on|via|through|in|over|using)[ \t]+(discord|telegram|slack|matrix|signal|wechat|qq|keybase|element|session|threema|zulip|gitter)\b`,
);
const CHAT_PLATFORM = re(
  String.raw`(?i)\b(?:discord|slack|zulip|telegram|matrix|gitter|mastodon|irc|wechat|qq|keybase|signal|element)\b`,
);
/** A direct message to someone ("DM a maintainer", "message one of us"). */
const CHAT_DM = re(
  String.raw`(?i)\b(?:dm|direct[ \t]+message|private[ \t]+message|privately[ \t]+message|message[ \t]+(?:me|us|them|any|one|a)\b)`,
);
/** A chat channel, group or room, which anyone can read. */
const CHAT_PUBLIC = re(
  String.raw`(?i)\b(?:channels?|groups?|community|communities|chat[ \t]?rooms?|rooms?|forums?|servers?|news|announcements?)\b`,
);
const CHAT_PRIVATE = re(
  String.raw`(?i)\b(?:dm|pm|direct[ \t]+message|private(?:ly)?|message[ \t]+(?:me|us)|contact[ \t]+me|write[ \t]+(?:to[ \t]+)?me)\b`,
);

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
  /** A heading, a paragraph, a table row or a block of code. */
  kind: 'heading' | 'text' | 'table' | 'code';
  /** The table a row is in. */
  table: Table | null;
  /** The words of its prose, for telling its language (langOf). */
  prose: string;
  lang?: Language;
}

/** A paragraph's language, worked out when first asked for. */
function langOf(b: Block): Language {
  if (b.lang === undefined) b.lang = b.kind === 'text' ? languageOf(b.prose) : 'unknown';
  return b.lang;
}

const blockCache = new WeakMap<Policy, Block[]>();
/** The policy's paragraphs (blocks): headings, paragraphs, table rows and code blocks, each with its heading. */
function blocks(p: Policy): Block[] {
  let b = blockCache.get(p);
  if (!b) {
    // A Policy built by hand rather than by readPolicy.
    const kinds = p.kinds ?? p.lines.map((l): LineKind => (l.trim() ? 'text' : 'blank'));
    b = blocksOf(p.lines, p.headings, p.items, kinds, new Map(), p.lines);
    blockCache.set(p, b);
  }
  return b;
}

function blocksOf(
  lines: string[],
  headings: Heading[],
  items: number[],
  kinds: LineKind[],
  tableAt: Map<number, Table>,
  prose: string[],
): Block[] {
  const heads = new Map(headings.map((h) => [h.line, h.text]));
  const itemSet = new Set(items);
  const out: Block[] = [];
  let heading: string | null = null;
  let cur: string[] = [];
  let curKind: Block['kind'] = 'text';
  let start = 0;
  const flush = (end: number) => {
    if (cur.length) {
      const words = curKind === 'text' ? prose.slice(start, end).join(' ') : '';
      out.push({ text: cur.join(' '), heading, start, end, kind: curKind, table: null, prose: words });
    }
    cur = [];
  };
  lines.forEach((l, i) => {
    const kind = kinds[i];
    if (heads.has(i)) {
      flush(i);
      heading = heads.get(i)!;
      out.push({ text: l, heading, start: i, end: i + 1, kind: 'heading', table: null, prose: '' });
    } else if (!l.trim()) flush(i);
    else if (kind === 'table') {
      // Each row of a table is a block of its own: its cells aren't sentences of a paragraph.
      flush(i);
      out.push({
        text: l.trim(),
        heading,
        start: i,
        end: i + 1,
        kind: 'table',
        table: tableAt.get(i) ?? null,
        prose: '',
      });
    } else {
      const k = kind === 'code' ? 'code' : 'text';
      // A list item starts a paragraph of its own: "1. Don't open an issue 2. Email us" is two instructions.
      if ((cur.length && k !== curKind) || itemSet.has(i)) flush(i);
      if (!cur.length) {
        start = i;
        curKind = k;
      }
      cur.push(l.trim());
    }
  });
  flush(lines.length);
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

/**
 * How the policy says to report a vulnerability. repo (owner/name) tells its own links from others'; scanned is the
 * repository being scanned, when the policy is its account's default (owner/.github): a link to its form is its own.
 */
export function howToReport(p: Policy, repo: string, scanned = repo): Reporting {
  const found: Channel[] = [];
  const have = new Set<string>();
  const add = (kind: ChannelKind, label: string, other?: string) => {
    const key = kind + '\u0000' + label;
    if (have.has(key)) return;
    have.add(key);
    found.push(other ? { kind, label, repo: other } : { kind, label });
  };
  for (const e of p.emails) add('email', e);
  for (const x of p.xmpp ?? []) add('chat', x);
  /** Links to the issue tracker: public issues, unless their sentence says not to use them. */
  const issueLinks: Link[] = [];
  const others: Link[] = [];
  const weak: Link[] = [];
  /** Links to a repository's Security tab or its list of advisories: a way to report when a sentence says so. */
  const githubPages: Link[] = [];
  /** Telegram links: a person is a private message; a channel or a group isn't. */
  const telegram: Link[] = [];
  const own = (u: string) => (!!sameRepoUrl(u, repo) && !/\/wiki\b/i.test(u)) || !!repoPath(u, repo, p.path);
  const elsewhereRepo = (u: string) => {
    const m = match(REPO_URL, u);
    const other = m ? `${m[1]}/${m[2]}` : '';
    return other && ![repo, scanned].some((r) => r.toLowerCase() === other.toLowerCase()) ? other : undefined;
  };
  for (const l of p.links) {
    const u = l.url;
    if (/^mailto:/i.test(u)) continue;
    if (search(GITHUB_REPORTING_URL, u) && !/\/security\/policy\b/i.test(u)) {
      if (/\/advisories\/new\/?(?:[?#]|$)/i.test(u)) add('github', u, elsewhereRepo(u));
      else githubPages.push(l);
    } else if (search(GITHUB_REPORTING_DOCS, u)) add('github', "GitHub's private vulnerability reporting");
    else if (search(PLATFORM_URL, u)) add('platform', u);
    else if (search(FORM_URL, u)) add('form', u);
    else if (search(CHAT_URL, u)) {
      if (/^https?:\/\/t\.me\//i.test(u)) telegram.push(l);
      else add('chat', u);
    } else if (search(ISSUES_URL, u)) issueLinks.push(l);
    else if (search(PROFILE_URL, u) && profileContact(l, p.english)) add('maintainer', l.text.trim() || u);
    else if (search(NOT_A_CHANNEL, u) || !/^https?:/i.test(u) || search(INVITE, u)) continue;
    else if (/security\.txt$/i.test(u)) add('page', u);
    else if (own(u)) continue;
    else if (search(FORM_TEXT, l.text)) add('form', u);
    else if (search(REPORTING_LINK, u.split(/[?#]/)[0]) || search(REPORTING_TEXT, l.text)) add('page', u);
    else if (search(SECURITY_LINK, u) || search(SECURITY_LINK, l.text)) weak.push(l);
    else others.push(l);
  }
  // A link to the issues counts unless its sentence says not to report there ("Please do not report security bugs in
  // our [public issue tracker](...)").
  const blockAt = new Map<number, Block>();
  if (issueLinks.length) for (const b of blocks(p)) for (let n = b.start; n < b.end; n++) blockAt.set(n, b);
  const issues = issueLinks.some((l) => {
    const b = blockAt.get(l.lines?.[0] ?? -1);
    const name = l.text.trim();
    const sentence = b && name ? sentencesOf(b.text).find((x) => x.includes(name)) : undefined;
    return !sentence || !search(NEGATION, sentence.slice(0, sentence.indexOf(name)));
  });
  // A security link is where reports go in a short policy that is little more than the link.
  if (p.words <= 40 && !issues) for (const l of weak) add('page', l.url);
  // The links on each line, so a paragraph looks only at its own; and the lines with any link.
  const byLine = new Map<number, Link[]>();
  const linkLines = new Set<number>();
  for (const l of p.links) for (const n of l.lines ?? []) linkLines.add(n);
  for (const l of [...weak, ...others, ...githubPages, ...telegram]) {
    for (const n of l.lines ?? []) {
      const at = byLine.get(n);
      if (at) at.push(l);
      else byLine.set(n, [l]);
    }
  }
  // The chat platforms it gives a handle on, anywhere: "Discord @name" here and "tell me on Discord" there.
  const handles = new Set(finditer(CHAT_HANDLE, p.text).map((m) => m[1].toLowerCase()));
  /** Public issues, from a sentence that says so (in English, so a "don't" before it can be read). */
  let publicIssues = false;
  let noAddress = false;
  let elsewhere = false;
  let readme = false;
  /** A request to write on a chat platform it gives a handle on. */
  let chatRequest = false;
  for (const b of blocks(p)) {
    const para = b.text;
    // The heading a paragraph sits under says what it's about ("Reporting a vulnerability").
    const heading = b.heading ?? '';
    const context = `${heading} ${para}`;
    // Whether the paragraph is in English (or too short to tell, in an English policy), worked out when needed.
    const english = () => langOf(b) === 'english' || (langOf(b) === 'unknown' && p.english);
    // The same for one sentence, which can be in another language than the paragraph ("Please do not open public
    // issues. 请通过 GitHub Security Advisory 私下报告漏洞").
    const englishSentence = (s: string) => {
      const l = languageOf(s);
      return l === 'english' || (l === 'unknown' && english());
    };
    let linked = /@/.test(para);
    for (let n = b.start; n < b.end && !linked; n++) linked = linkLines.has(n);
    if (b.kind !== 'code') {
      for (const s of sentencesOf(para)) {
        // Each pattern runs only when the sentence has a word it needs: most sentences have none.
        const at = s.includes('@');
        if (TRIGGER.github.test(s) && githubText(s, englishSentence(s)))
          add('github', "GitHub's private vulnerability reporting");
        if (at && search(GITHUB_HANDLE, s) && !englishSentence(s)) add('maintainer', 'a maintainer named in it');
        if (at && s.includes(':') && search(MATRIX_ID, s)) add('chat', search(MATRIX_ID, s)![0]);
        if (TRIGGER.confidential.test(s) && search(CONFIDENTIAL_ISSUE, s) && !negated(s, CONFIDENTIAL_ISSUE)) {
          add('platform', 'confidential issue');
        }
        // A platform the sentence doesn't say it isn't on ("we do not have a bug bounty program"); a generic "bug
        // bounty program" counts only with a link or an address with it.
        for (const pm of TRIGGER.platform.test(s) ? finditer(PLATFORM_TEXT, s) : []) {
          if (negatedNear(s, pm.index, pm[0].length) || platformGone(s, pm.index, pm[0].length)) continue;
          if (GENERIC_PROGRAM.test(pm[0]) && !linked) continue;
          add('platform', pm[0].replace(/\s+/g, ' '));
          break;
        }
        if ((at || TRIGGER.maintainer.test(s)) && search(MAINTAINER_TEXT, s))
          add('maintainer', 'a maintainer named in it');
        const word = !!search(REPORT_WORD, s);
        if (word && TRIGGER.readme.test(s) && search(README_CONTACT, s) && search(REPORT_SENTENCE, s)) readme = true;
        if (word && at) for (const m of finditer(SHORT_EMAIL, s)) add('email', m[1]);
        // "No open issue tracks it" or "an open issue" is an issue that is open, not a request to open one.
        const pi = TRIGGER.issues.test(s)
          ? finditer(PUBLIC_ISSUE_TEXT, s).find(
              (m) => !/^open\b/i.test(m[0]) || !OPEN_ADJECTIVE.test(s.slice(Math.max(0, m.index - 12), m.index)),
            )
          : undefined;
        // Public issues count unless the sentence is about something else: "please submit a pull request" with
        // suggestions for the policy, or an issue for questions.
        if (pi && !negatedAt(s, pi.index, pi[0].length)) {
          const rest = s.slice(0, pi.index) + ' ' + s.slice(pi.index + pi[0].length);
          const other = search(NOT_ABOUT_REPORTS, rest) || search(NOT_ABOUT_REPORTS, heading);
          if (!other || search(REPORT_WORD, rest)) publicIssues = true;
        }
        if (word && TRIGGER.site.test(s) && search(CONTACT_ELSEWHERE, s)) elsewhere = true;
        // Asking for an email or a message without an address; not in a table, and not when it names GitHub.
        if (b.kind !== 'table' && TRIGGER.mail.test(s) && search(ASKS_FOR_MAIL, s) && search(REPORT_WORD, context)) {
          if (!/\bgithub\b/i.test(s)) noAddress = true;
        }
        const cr = handles.size && TRIGGER.chat.test(s) ? search(CHAT_REQUEST, s) : null;
        if (cr && handles.has(cr[1].toLowerCase())) chatRequest = true;
      }
    }
    // A private message on a chat platform; not a channel, group or community, which anyone can read. The platform
    // and the direct message can be in different sentences ("... our Discord server. Just direct message a member").
    if (TRIGGER.chat.test(para) && search(REPORT_WORD, context)) {
      const dm = search(CHAT_TEXT, para) || (search(CHAT_PLATFORM, para) && search(CHAT_DM, para));
      if (dm && (!search(CHAT_PUBLIC, para) || search(CHAT_PRIVATE, para))) add('chat', 'a private message');
    }
    // At most 50 links per paragraph: no real one has more, and each is looked for in the whole paragraph.
    const near = new Set<Link>();
    for (let n = b.start; n < b.end && near.size < 50; n++) {
      for (const l of byLine.get(n) ?? []) if (near.size < 50) near.add(l);
    }
    if (!near.size) continue;
    const reportingHeading = !!search(REPORT_HEADING, heading);
    for (const l of near) {
      const name = l.text.trim();
      const at = name ? para.indexOf(name) : -1;
      const sentence = at < 0 ? para : (sentencesOf(para).find((x) => x.includes(name)) ?? para);
      if (telegram.includes(l)) {
        // A Telegram link is a person to message unless the paragraph calls it a channel, group or community.
        if (!search(CHAT_PUBLIC, para) && (name.startsWith('@') || search(CHAT_PRIVATE, para))) add('chat', l.url);
        continue;
      }
      if (githubPages.includes(l)) {
        // The Security tab or the advisories list: a way to report when the sentence is about reporting there, not
        // about advisories already published.
        const linkOnly = !/[\p{L}\p{N}]/u.test(para.split(name).join(' '));
        // In another language the words around it can't be read, so the link is enough (unless it's to the list of
        // published advisories).
        const published = !!search(PUBLISHED, sentence) || /[?&]state=published/i.test(l.url);
        const reporting =
          (search(REPORT_SENTENCE, sentence) && !published) ||
          search(REPORTING_TEXT, name) ||
          (linkOnly && reportingHeading) ||
          (search(VULN_CONTEXT, heading) && !published) ||
          (!english() && !published);
        if (reporting) add('github', l.url, elsewhereRepo(l.url));
        continue;
      }
    }
    const plain = [...near].filter((l) => !telegram.includes(l) && !githubPages.includes(l));
    // Links on lines of their own in a section about reporting are that section's ways to report.
    if (reportingHeading) {
      const inPara = plain.filter((l) => l.text.trim() && para.includes(l.text.trim()));
      let rest = para;
      for (const l of inPara) rest = rest.split(l.text.trim()).join(' ');
      if (inPara.length && !/[\p{L}\p{N}]/u.test(rest)) for (const l of inPara) add('page', l.url);
    }
    // A link in a sentence about sending reports is where they go: "report it to [our maintainer](...)",
    // "use [this link](...) to submit your report". A link that's only mentioned there isn't.
    for (const l of plain) {
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
      } else if (search(REPORT_SENTENCE, around) && search(FORM_TEXT, around)) {
        // "... via the submission form at the end of the [page](...)": the link is where the form is.
        add('form', l.url);
      }
    }
  }
  if (chatRequest && !found.some((c) => c.kind === 'chat')) add('chat', 'a private message');
  // A link to GitHub's form says which repository it's in, so it comes before the feature named in words; a page
  // whose link doesn't say it's about reports comes after those that do.
  // A labeled chat (a link or an address) comes before "a private message".
  const strength = (c: Channel) =>
    c.kind === 'github'
      ? c.label.includes('/')
        ? 0
        : 1
      : c.kind === 'chat'
        ? c.label === 'a private message'
          ? 1
          : 0
        : c.kind === 'page' && !search(REPORTING_LINK, c.label)
          ? 1
          : 0;
  // An address only to escalate to comes after the other ways to report (HackerOne first, its escalation after).
  const backups = new Set(p.backup ?? []);
  const kindRank = (c: Channel) =>
    c.kind === 'email' && backups.has(c.label) ? ORDER.indexOf('form') + 0.5 : ORDER.indexOf(c.kind);
  found.sort((a, b) => kindRank(a) - kindRank(b) || strength(a) - strength(b));
  const labels = new Set(found.map((c) => c.label));
  const rest = [...weak, ...others].filter((l) => !labels.has(l.url));
  const pointer = !found.length && rest.length && p.words <= 60 ? rest[0] : null;
  const other = !found.length && foreign(p);
  return {
    channels: found,
    // A link to the issues counts too, unless the policy is in a language whose "don't" the scan can't read.
    publicIssues: !found.length && (publicIssues || (issues && !other)),
    noAddress: !found.length && noAddress,
    template: !!search(TEMPLATE_REPORTING, p.text),
    pointer,
    elsewhere: !found.length && elsewhere,
    readme: !found.length && readme,
    foreign: other,
    local: found.length ? null : localPolicy(p, repo),
  };
}

/**
 * Quick tests for the words a pattern needs (plain JavaScript, not Python patterns: they only decide whether to run
 * one), so the patterns run only on sentences that could match.
 */
const TRIGGER = {
  github: /securi|advisor|vulnerab|privat|github/i,
  confidential: /confidential/i,
  platform: /hacker|bugcrowd|intigriti|yeswehack|huntr|bount|immunefi|hackenproof|tidelift|node[ \t]+security|program/i,
  maintainer: /address|profile|readme|commit|history|authors|maintainers/i,
  readme: /readme/i,
  issues: /issue|ticket|pull|discussion|bug[ \t]+report/i,
  site: /site|page/i,
  mail: /mail|message|contact|reach|privately/i,
  chat: /signal|threema|session|wire|keybase|element|discord|zulip|slack|matrix|gitter|telegram|mastodon|twitter|irc|libera|wechat|qq|@/i,
};

/** What a sentence or heading is about when it isn't reports: comments on the policy, questions, contributions. */
const NOT_ABOUT_REPORTS = re(
  String.raw`(?i)\b(?:comments?|feedback|suggestions?|improve\w*|questions?|feature[ \t]+requests?|contribut\w*|this[ \t]+(?:policy|document|process))\b`,
);

/** "Publish" in a few other languages, for a feature's name in a sentence the scan can't otherwise read. */
const LOOSE_PUBLISHED =
  /veröffentlich|publica|publié|publie|publiceer|gepubliceerd|pubblica|发布|發佈|公布|опубликов|публику|yayınla|diterbitkan|publikowa/i;

/** A generic bug bounty or disclosure program, rather than a platform by name. */
const GENERIC_PROGRAM = /^(?:bug[ \t]+bounty|vulnerability[ \t]+(?:reward|disclosure))[ \t]+program/i;

/**
 * Whether a sentence (in English, or in another language when english is false) says to report through GitHub's
 * private vulnerability reporting: a mention that isn't negated and isn't the maintainers' own step.
 */
function githubText(s: string, english: boolean): boolean {
  // Not in a sentence about something else: "for questions, @ me privately on GitHub".
  if (search(NOT_ABOUT_REPORTS, s) && !search(REPORT_WORD, s)) return false;
  for (const m of finditer(GITHUB_REPORTING_TEXT, s)) {
    if (negatedAt(s, m.index, m[0].length, true)) continue;
    const before = s.slice(0, m.index);
    if (search(ADVISORY_PASSIVE, s.slice(m.index + m[0].length)) || search(PUBLISHED, before)) continue;
    // The maintainers as the subject ("we will create a draft advisory") make it their step, unless the reporter
    // comes after them ("we ask that you open one").
    const steps = finditer(MAINTAINER_STEP, before);
    const last = steps[steps.length - 1];
    if (last && !search(REPORTER_WORD, before.slice(last.index + last[0].length))) continue;
    return true;
  }
  if (english) return false;
  // In another language the verbs around it can't be read, so the feature's name is enough, unless it's only a
  // gloss in brackets ("... (Security Advisory)").
  // Nor where it says advisories are published ("veröffentlicht ein Security Advisory").
  if (LOOSE_PUBLISHED.test(s)) return false;
  for (const m of finditer(GITHUB_REPORTING_NAME, s)) {
    if (negatedAt(s, m.index, m[0].length, true)) continue;
    const glossed =
      /[(（][ \t]*(?:github[ \t]+)?$/i.test(s.slice(0, m.index)) && /^[ \t]*[)）]/.test(s.slice(m.index + m[0].length));
    if (!glossed) return true;
  }
  return false;
}

/** Whether the part of a policy about reporting (or all of it, when no heading says) isn't in English. */
function foreign(p: Policy): boolean {
  const langs = blocks(p)
    .filter((b) => b.kind === 'text' && b.heading && search(REPORT_SECTION, b.heading))
    .map(langOf);
  if (langs.includes('english')) return false;
  if (langs.includes('other')) return true;
  return !p.english;
}
const REPORT_SECTION = re(
  String.raw`(?i)\breport|disclos|vulnerab|\bcontact|security[ \t]+(?:issues?|bugs?|problems?)`,
);

/**
 * The file in the same repository that a policy which says nothing itself points to: the target of a symlink, or a
 * linked document that looks like the full policy. Null when there's none.
 */
function localPolicy(p: Policy, repo: string): string | null {
  if (p.symlink) return repoPath(p.symlink, repo, p.path);
  for (const l of p.links) {
    const path = repoPath(l.url, repo, p.path);
    if (!path || path.toLowerCase() === p.path.toLowerCase() || !search(DOC_FILE, path)) continue;
    if (reportingLink(p, linkWords(l, path))) return path;
  }
  return null;
}

/** A link's words: its text, its path, and the part of the page it goes to (CONTRIBUTING.md#reporting-security). */
function linkWords(l: Link, path: string): string {
  const hash = l.url.indexOf('#');
  return `${l.text} ${path} ${hash < 0 ? '' : l.url.slice(hash + 1)}`;
}

/**
 * Whether a link (its words) is to where a policy says how to report: about security, vulnerabilities, disclosure
 * or reports, or, from a short policy that is little more than the link, about a policy. Not a privacy policy, terms
 * or a code of conduct.
 */
function reportingLink(p: Policy, words: string): boolean {
  if (search(POLICY_WORDS, words)) return true;
  return p.words <= 60 && /polic/i.test(words) && !/privacy|cookie|terms|conduct|licen[cs]e|acceptable/i.test(words);
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
      return c.repo
        ? `through GitHub's private vulnerability reporting for ${c.repo}`
        : "through GitHub's private vulnerability reporting";
    case 'email':
      return `by email (${c.label})`;
    case 'platform': {
      const named = PLATFORM_NAMES.find(([rx]) => search(rx, c.label));
      return `through ${named ? named[1] : c.label.startsWith('http') ? c.label : `a ${c.label.toLowerCase().replace(/^an? /, '')}`}`;
    }
    case 'form':
      return `through a form (${c.label})`;
    case 'chat':
      return c.label.startsWith('http') || /^[^\s@]+@[^\s@]+$/.test(c.label)
        ? `by private message (${c.label})`
        : 'by private message';
    case 'maintainer':
      return 'privately to a maintainer it names';
    case 'page':
      return `as ${c.label} says`;
  }
}

export interface ReportVerdict {
  status: 'pass' | 'warn' | 'info' | 'unknown';
  /** What follows the file's name in the summary. */
  says: string;
  channels: ChannelKind[];
}

/** The file a policy led to: read, or not (with the HTTP status). */
export type Followed = { path: string; policy: Policy; reporting: Reporting } | { path: string; status: number };

/**
 * disc-security-md's verdict on a policy (and on the one file it led to, if the scan read it). A policy passes when
 * it gives a private way to report, or points to a security page or policy elsewhere. It warns only when the scan
 * could read it and found no such way; a policy in a language the scan doesn't read, one that only links somewhere
 * the scan won't follow or couldn't read, or one that isn't text, gives info (or unknown, when a read failed).
 */
export function reportVerdict(p: Policy, r: Reporting, followed: Followed | null): ReportVerdict {
  const v = verdictOf(p, r, followed);
  // Past MAX_POLICY the reader looked only at the start, which matters only when it found no way to report: the rest
  // may give one, so that's info, not a warning.
  if (p.truncated && v.status === 'warn') {
    return {
      status: 'info',
      says: ', but the scan read only the first 256 KB of it and found no private way to report there: check the rest says how',
      channels: v.channels,
    };
  }
  if (p.truncated && v.status !== 'pass') v.says += ' (the scan read only the first 256 KB of it)';
  return v;
}

function verdictOf(p: Policy, r: Reporting, followed: Followed | null): ReportVerdict {
  const kinds = (x: Reporting) => [...new Set(x.channels.map((c) => c.kind))];
  if (p.garbled && !r.channels.length) {
    return {
      status: 'info',
      says: ", but it isn't text the scan can read (a binary file, or an encoding it can't tell): check that it's a text file",
      channels: [],
    };
  }
  if (r.channels.length) {
    const c = r.channels[0];
    const says =
      c.kind === 'page' ? `; it points to ${c.label} for how to report` : `; it says to report ${describeChannel(c)}`;
    return { status: 'pass', says, channels: kinds(r) };
  }
  const read = followed && 'policy' in followed ? followed : null;
  // The file it led to counts when it gives a way to report, or when it's about reporting and points somewhere: a
  // list of other pages in a file about something else doesn't.
  const direct = read && read.reporting.channels.some((c) => c.kind !== 'page');
  if (read && read.reporting.channels.length && (direct || aboutReporting(read.policy))) {
    const c = read.reporting.channels[0];
    const how = c.kind === 'page' ? `which points to ${c.label}` : `which says to report ${describeChannel(c)}`;
    return { status: 'pass', says: `; it points to ${read.path}, ${how}`, channels: kinds(read.reporting) };
  }
  if (read && read.policy.symlink) {
    return {
      status: 'info',
      says: `; it's a link to ${read.path}, which is itself a link (to ${read.policy.symlink}), and the scan follows only one: check that file says how to report privately`,
      channels: [],
    };
  }
  const own = read ? read.reporting : r;
  if (own.template || r.template) {
    return {
      status: 'warn',
      says: " but it still has GitHub's template text where it should say how to report",
      channels: [],
    };
  }
  // It says how to report is in the README (the maintainers it lists): the scan can't tell, even beside public issues.
  if (own.readme || r.readme) {
    return {
      status: 'info',
      says: "; it says how to report is in the README, which the scan doesn't read: check the README says how to report privately",
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
  if (r.foreign && (!read || own.foreign)) {
    return {
      status: 'info',
      says: ", but it isn't in English and the scan found no email address or link in it to report to",
      channels: [],
    };
  }
  if (r.pointer || own.pointer) {
    const l = (r.pointer ?? own.pointer)!;
    return {
      status: 'info',
      says: `; it points to ${l.url}, which the scan doesn't follow: check that page says how to report privately`,
      channels: [],
    };
  }
  // It points to a file the scan didn't try to read (a caller that doesn't follow links).
  if (!followed && r.local) {
    return {
      status: 'info',
      says: p.symlink
        ? `; it's a link to ${r.local}, which the scan didn't read: check that file says how to report privately`
        : `; it points to ${r.local}, which the scan didn't read: check that file says how to report privately`,
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
  // The file it points to couldn't be read, and the policy says nothing else.
  if (followed && !read) {
    const { path, status } = followed as { path: string; status: number };
    if (status === 404) {
      return {
        status: 'info',
        says: `; it points to ${path}, which isn't in the repository (HTTP 404): check the link, and that the policy says how to report privately`,
        channels: [],
      };
    }
    return {
      status: 'unknown',
      says: `; it points to ${path}, which the scan couldn't read (HTTP ${status})`,
      channels: [],
    };
  }
  return { status: 'warn', says: ' but it does not say how to report privately', channels: [] };
}

/**
 * Whether a file reads like a security policy rather than a page about security features: it gives a way to report
 * (other than a link), or a heading is about reporting vulnerabilities or a security policy.
 */
export function looksLikePolicy(p: Policy, r: Reporting): boolean {
  return r.channels.some((c) => c.kind !== 'page') || p.headings.some((h) => !!search(POLICY_HEADING, h.text));
}
/** A heading of a security policy. "Content Security Policy" (CSP, a web page's script rules) isn't one. */
const POLICY_HEADING = re(
  String.raw`(?i)\breport(?:ing)?[ \t]+(?:a[ \t]+|an[ \t]+)?(?:security|vulnerab)|\bvulnerabilit(?:y|ies)[ \t]+(?:report|disclos)|(?<!\bcontent[ \t])\bsecurity[ \t]+(?:policy|contacts?|issues?|reports?)\b|\bresponsible[ \t]+disclosure\b|\bdisclosure[ \t]+policy\b`,
);

/** Whether a policy is about reporting: a heading or a sentence about reporting vulnerabilities. */
function aboutReporting(p: Policy): boolean {
  return p.headings.some((h) => search(REPORT_SECTION, h.text)) || !!search(VULN_CONTEXT, p.text);
}

/** Whether the phrase rx finds in a sentence is negated there ("do not open an issue"). */
function negated(sentence: string, rx: RegExp, after = false): boolean {
  const m = search(rx, sentence);
  return !!m && negatedAt(sentence, m.index, m[0].length, after);
}

/** Whether the phrase at [at, at + len) in a sentence is negated: a "not" before it, or (after) "is not enabled". */
function negatedAt(sentence: string, at: number, len: number, after = false): boolean {
  if (search(NEGATION, sentence.slice(0, at))) return true;
  return after && !!search(NOT_AFTER, sentence.slice(at + len));
}

/**
 * The same, with only the clause before the phrase counting: "if you don't hear back, use HackerOne" isn't negated,
 * "we do not have a bug bounty program" is.
 */
function negatedNear(sentence: string, at: number, len: number): boolean {
  const before = sentence.slice(0, at);
  const clause = before.slice(Math.max(before.lastIndexOf(','), before.lastIndexOf(';'), before.lastIndexOf(':')) + 1);
  return !!search(NEGATION, clause) || !!search(NOT_AFTER, sentence.slice(at + len));
}

/** Before a platform's name, in its clause: the project was on it, or isn't ("We left HackerOne", "No HackerOne"). */
const PLATFORM_LEFT = re(
  String.raw`(?i)\b(?:left|leaving|formerly|previously|used[ \t]+to|no[ \t]+longer|stopped|moved[ \t]+(?:away[ \t]+)?(?:from|off)|migrated[ \t]+(?:away[ \t]+)?(?:from|off)|switched[ \t]+(?:away[ \t]+)?from|dropped|retired|discontinued)\b|\bno[ \t]+(?:[\w-]+[ \t]+)?$`,
);
/** After it: "isn't used", "is not monitored", "are no longer accepted", ": not applicable". */
const PLATFORM_OFF = re(
  String.raw`(?i)^[^.\n]{0,30}?(?:\b(?:is|are|was|were)[ \t]+(?:not|no[ \t]+longer)|\b(?:isn't|aren't|wasn't|weren't))[ \t]+(?:[\w-]+[ \t]+)?(?:used|monitored|accepted|in[ \t]+use|available|active|maintained|checked|supported|applicable|run)\b|^[^.\n]{0,30}?\bno[ \t]+longer\b|^[ \t]*[:\-–—][ \t]*(?:not[ \t]+applicable|n/a|none)\b`,
);

/** Whether a sentence says the project isn't on the platform named at [at, at + len) any more, or never was. */
function platformGone(sentence: string, at: number, len: number): boolean {
  const before = sentence.slice(0, at);
  const clause = before.slice(Math.max(before.lastIndexOf(','), before.lastIndexOf(';'), before.lastIndexOf(':')) + 1);
  return !!search(PLATFORM_LEFT, clause) || !!search(PLATFORM_OFF, sentence.slice(at + len));
}

// --------------------------------------------------------------------------------------- following
/** A policy that's only a path to another file: raw.githubusercontent.com serves a symlink as its target's path. */
const SYMLINK_TEXT = re(
  String.raw`^[ \t]*(\.{0,2}/?(?:[\w.-]+/)*[\w.-]+\.(?:md|markdown|rst|adoc|asciidoc|txt)|\.{0,2}/?(?:[\w.-]+/)+[\w.-]+)[ \t]*\n?\Z`,
);

/**
 * The path a policy that is a symlink points to, or null. A path without an extension must start with ./ or ../, or
 * end in a policy's name ("docs/SECURITY"): "N/A" and "and/or" are words, not links.
 */
function symlinkTarget(body: string): string | null {
  const m = body.length < 1024 ? match(SYMLINK_TEXT, body) : null;
  if (!m) return null;
  const path = m[1];
  const last = path.slice(path.lastIndexOf('/') + 1);
  if (/\.(?:md|markdown|rst|adoc|asciidoc|txt)$/.test(last) || /^\.{1,2}\//.test(path)) return path;
  return /secur|polic|vulnerab|disclos/i.test(last) ? path : null;
}
const GITHUB_FILE = re(
  String.raw`(?i)^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)/(?:blob|raw)/[^/\s]+/([^\s?#]+)|^https?://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/[^/\s]+/([^\s?#]+)`,
);
const REPO_URL = re(String.raw`(?i)^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/?#]|$)`);
const DOC_FILE = re(String.raw`(?i)\.(?:md|markdown|rst|adoc|asciidoc|txt)$|(?:^|/)security$`);
/** Words in a link (its text or path) that make it about security reports: the only links worth following. */
const POLICY_WORDS = re(String.raw`(?i)secur|vulnerab|disclos|report|advisor|bounty`);
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
  const sym = symlinkTarget(raw);
  if (sym) return repoPath(sym, repo, p.path);
  if (!needs.report && !needs.versions) return null;
  for (const l of p.links) {
    const path = repoPath(l.url, repo, p.path);
    if (!path || path.toLowerCase() === p.path.toLowerCase() || !search(DOC_FILE, path)) continue;
    const words = linkWords(l, path);
    if ((needs.report && reportingLink(p, words)) || (needs.versions && search(VERSION_WORDS, words))) return path;
  }
  return null;
}
