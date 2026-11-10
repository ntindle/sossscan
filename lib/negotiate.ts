/**
 * Content negotiation for the site's pages. The home page and each text page come as HTML and as Markdown from the same
 * URL, and the request's Accept header picks one, as https://acceptmarkdown.com describes:
 * - each media range has a weight, q, from 0 to 1 (1 when it has none), and q=0 means "not this";
 * - for each representation, the most specific range that matches it sets its weight (RFC 9110, section 12.5.1), so
 *   text/markdown;q=0 rules out Markdown even when *\/* accepts anything;
 * - the representation with the higher weight wins. Between equal weights, a range that names the type beats a
 *   wildcard, then the range listed first wins: "text/markdown, text/html, *\/*", which Claude Code and Copilot send,
 *   asks for Markdown first;
 * - a tie the header can't break, such as *\/* or text/* alone, goes to HTML, and so does a request with no Accept
 *   header, or one with nothing in it that parses;
 * - when the header rules out both, the answer is 406 Not Acceptable.
 * proxy.ts uses it to send Markdown requests to the page's Markdown twin, and the 404 handler (app/[...path]/route.ts)
 * to choose its body. It's plain functions with no imports, so the proxy bundle stays small.
 */

export type Representation = 'html' | 'markdown';

/** The two media types every page comes in. HTML first: it wins a tie the header can't break. */
const OFFERED: readonly { representation: Representation; type: string; subtype: string }[] = [
  { representation: 'html', type: 'text', subtype: 'html' },
  { representation: 'markdown', type: 'text', subtype: 'markdown' },
];

export const HTML_TYPE = 'text/html; charset=utf-8';
export const MARKDOWN_TYPE = 'text/markdown; charset=utf-8';

export type MediaRange = {
  type: string;
  subtype: string;
  /** Media type parameters (before q), names in lowercase. */
  params: Map<string, string>;
  q: number;
  /** Position in the header, which breaks ties. */
  index: number;
};

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const QVALUE = /^(?:0(?:\.\d*)?|1(?:\.0*)?)$/;

/** Split on a separator, except inside a quoted string. */
function split(text: string, separator: string): string[] {
  const parts: string[] = [];
  let part = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quoted && c === '\\' && i + 1 < text.length) {
      part += c + text[i + 1];
      i += 1;
      continue;
    }
    if (c === '"') quoted = !quoted;
    if (c === separator && !quoted) {
      parts.push(part);
      part = '';
    } else {
      part += c;
    }
  }
  parts.push(part);
  return parts;
}

function unquote(value: string): string {
  return value.startsWith('"') && value.endsWith('"') && value.length >= 2
    ? value.slice(1, -1).replace(/\\(.)/g, '$1')
    : value;
}

/**
 * The media ranges in an Accept header, in order. A range that doesn't parse (no type/subtype, a weight outside 0 to
 * 1, a parameter without a value) is left out rather than guessed at.
 */
export function parseAccept(header: string): MediaRange[] {
  const ranges: MediaRange[] = [];
  split(header, ',').forEach((entry, index) => {
    const [range, ...rawParams] = split(entry, ';').map((s) => s.trim());
    const slash = range.indexOf('/');
    const type = range.slice(0, slash).toLowerCase();
    const subtype = range.slice(slash + 1).toLowerCase();
    if (slash < 1 || !TOKEN.test(type) || !TOKEN.test(subtype) || (type === '*' && subtype !== '*')) return;
    const params = new Map<string, string>();
    let q = 1;
    let weighted = false;
    for (const param of rawParams) {
      if (!param) continue;
      const eq = param.indexOf('=');
      const name = param.slice(0, eq).trim().toLowerCase();
      const value = unquote(param.slice(eq + 1).trim());
      if (eq < 1 || !TOKEN.test(name) || !value) return;
      if (name === 'q') {
        if (!QVALUE.test(value)) return;
        q = Number(value);
        weighted = true;
      } else if (!weighted) {
        params.set(name, value); // anything after q isn't a media type parameter (RFC 9110 has nothing there)
      }
    }
    ranges.push({ type, subtype, params, q, index });
  });
  return ranges;
}

/** Higher is more specific: a full type beats type/*, which beats *\/*, and each parameter adds a little. */
function specificity(range: MediaRange): number {
  return (range.type === '*' ? 0 : range.subtype === '*' ? 1 : 2) * 100 + range.params.size;
}

/** Whether a range covers one of our types. Both are sent as UTF-8, so charset=utf-8 is the only parameter they have. */
function covers(range: MediaRange, offer: (typeof OFFERED)[number]): boolean {
  if (range.type !== '*' && range.type !== offer.type) return false;
  if (range.subtype !== '*' && range.subtype !== offer.subtype) return false;
  for (const [name, value] of range.params) {
    if (name !== 'charset' || value.toLowerCase() !== 'utf-8') return false;
  }
  return true;
}

/**
 * Which representation to send for this Accept header, or null when it rules out both (answer 406). A missing or empty
 * header means no preference, which gets HTML.
 */
export function negotiate(accept: string | null | undefined): Representation | null {
  const ranges = parseAccept(accept ?? '');
  if (!ranges.length) return 'html';
  // Positive when range a beats range b: a higher weight, then naming the type over a wildcard, then coming first.
  const beats = (a: MediaRange, b: MediaRange) => a.q - b.q || specificity(a) - specificity(b) || b.index - a.index;
  let best: { representation: Representation; range: MediaRange } | null = null;
  for (const offer of OFFERED) {
    // The most specific range that covers this type sets its weight; the first one listed, if two are as specific.
    let range: MediaRange | null = null;
    for (const r of ranges) if (covers(r, offer) && (!range || specificity(r) > specificity(range))) range = r;
    if (!range || range.q === 0) continue;
    // Strictly better, so a tie the header can't break keeps the type offered first, HTML.
    if (!best || beats(range, best.range) > 0) best = { representation: offer.representation, range };
  }
  return best ? best.representation : null;
}

/** Where a page's Markdown twin is: /about is /about.md, and the home page, which has no file name, is /index.md. */
export function markdownPath(urlPath: string): string {
  return urlPath === '/' ? '/index.md' : `${urlPath}.md`;
}

/** The answer when Accept rules out both types (RFC 9110, section 15.5.7): what the page does come in. */
export const NOT_ACCEPTABLE =
  "406 Not Acceptable: this page comes as text/html or text/markdown, and the request's Accept header rules out both.\n";
