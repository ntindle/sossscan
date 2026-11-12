// A small reader for the YAML that GitHub Actions workflows and composite actions use: block mappings and sequences,
// plain, quoted and block scalars, and flow collections. New in 0.5.0, for the checks that need a workflow's jobs and
// steps rather than its lines; there's no Python original. It never throws on bad input: what it can't read becomes
// a scalar, or is skipped, so a check reading the tree finds less, never more.
//
// Anyone can write the files it reads, and public scans read them on our server, so it takes time in proportion to
// the text, and stops at a document that nests too deep or that aliases and merge keys make too big (TooComplex).
import { splitLines } from './py.ts';

/**
 * A document too deep, or too big with its aliases and merge keys expanded, to read: each alias holds a whole node
 * again, so a few lines of them can stand for billions of nodes. What needs the document can't be checked.
 */
export class TooComplex extends Error {
  constructor(why: string) {
    super(why);
    this.name = 'TooComplex';
  }
}

/** How deep a document may nest. A real workflow nests less than 20 deep. */
export const MAX_DEPTH = 200;
/**
 * How big a document may be with its aliases and merge keys expanded, counting each character of a key or a scalar
 * and each node: 4 times the text, and 256K more. A real workflow, aliases and all, comes to about its own size.
 */
export const maxExpanded = (text: string) => 262_144 + 4 * text.length;
/** How many entries merge keys may copy: 64K, and one for each 8 characters. A real file copies a few hundred. */
const maxMerged = (text: string) => 65_536 + (text.length >> 3);

export interface YScalar {
  kind: 'scalar';
  /** The 0-based line the value starts on, and the line after its last one. */
  line: number;
  end: number;
  text: string;
  quoted: boolean;
}
export interface YSeq {
  kind: 'seq';
  line: number;
  end: number;
  items: YNode[];
}
export interface YMap {
  kind: 'map';
  line: number;
  end: number;
  entries: { key: string; line: number; value: YNode }[];
}
export type YNode = YScalar | YSeq | YMap;

const scalar = (line: number, text = '', quoted = false, end = line + 1): YScalar => ({
  kind: 'scalar',
  line,
  end,
  text,
  quoted,
});

const isBlank = (c: string | undefined) => c === ' ' || c === '\t';

/** A sequence entry: "-" alone, or followed by a space or a tab. */
function isDash(text: string): boolean {
  return text === '-' || (text[0] === '-' && isBlank(text[1]));
}

/** Where a plain scalar's comment starts (a # after whitespace, or at the start), or the length if it has none. */
function commentAt(text: string): number {
  for (let k = 0; k < text.length; k++) {
    if (text[k] === '#' && (k === 0 || isBlank(text[k - 1]))) return k;
  }
  return text.length;
}

/** The end of a quoted string that opens at text[start] (the index after its closing quote), or -1 if unclosed. */
function quoteEnd(text: string, start: number): number {
  const q = text[start];
  for (let k = start + 1; k < text.length; k++) {
    if (q === '"' && text[k] === '\\') k++;
    else if (text[k] === q) {
      if (q === "'" && text[k + 1] === "'") k++;
      else return k + 1;
    }
  }
  return -1;
}

const ESCAPES: Record<string, string> = { n: '\n', t: '\t', '"': '"', '\\': '\\', '/': '/' };

function unquote(raw: string): string {
  const q = raw[0];
  const body = raw.slice(1, -1);
  if (q === "'") return body.replaceAll("''", "'");
  let out = '';
  for (let k = 0; k < body.length; k++) {
    if (body[k] !== '\\' || k + 1 >= body.length) {
      out += body[k];
      continue;
    }
    const c = body[++k];
    const width = c === 'x' ? 2 : c === 'u' ? 4 : c === 'U' ? 8 : 0;
    const digits = body.slice(k + 1, k + 1 + width);
    const hex = digits.length === width && [...digits].every((d) => '0123456789abcdefABCDEF'.includes(d));
    const code = hex ? Number.parseInt(digits, 16) : NaN;
    if (width && hex && code <= 0x10ffff) {
      out += String.fromCodePoint(code);
      k += width;
    } else out += ESCAPES[c] ?? c;
  }
  return out;
}

/** A mapping key at the start of text, with where its value starts, or null when the text isn't "key: ...". */
function keyOf(text: string): { key: string; rest: number } | null {
  if (!text || isDash(text) || '#[{|>?&*!%@`'.includes(text[0])) return null;
  let k: number;
  let key: string;
  if (text[0] === '"' || text[0] === "'") {
    const e = quoteEnd(text, 0);
    if (e < 0) return null;
    key = unquote(text.slice(0, e));
    k = e;
    while (isBlank(text[k])) k++;
    if (text[k] !== ':') return null;
  } else {
    const hash = commentAt(text);
    k = -1;
    for (let j = 0; j < hash; j++) {
      if (text[j] === ':' && (j + 1 === text.length || isBlank(text[j + 1]))) {
        k = j;
        break;
      }
    }
    if (k < 0) return null;
    key = text.slice(0, k).trim();
    if (!key) return null;
  }
  if (k + 1 < text.length && !isBlank(text[k + 1])) return null;
  return { key, rest: k + 1 };
}

/** Parse a flow collection or scalar ("[a, b]", "{k: v}") that starts at text[i]. Returns the node and the end. */
function parseFlow(text: string, i: number, line: number, depth = 0): [YNode, number] {
  if (depth > MAX_DEPTH) throw new TooComplex(`it nests more than ${MAX_DEPTH} deep`);
  const skip = (k: number) => {
    while (k < text.length && (isBlank(text[k]) || text[k] === '\n')) k++;
    return k;
  };
  i = skip(i);
  if (text[i] === '[') {
    const items: YNode[] = [];
    i = skip(i + 1);
    while (i < text.length && text[i] !== ']') {
      const [node, k] = parseFlow(text, i, line, depth + 1);
      items.push(node);
      i = skip(k);
      if (text[i] === ',') i = skip(i + 1);
      else if (text[i] !== ']') break;
    }
    return [{ kind: 'seq', line, end: line + 1, items }, Math.min(text.length, i + 1)];
  }
  if (text[i] === '{') {
    const entries: YMap['entries'] = [];
    i = skip(i + 1);
    while (i < text.length && text[i] !== '}') {
      const [k, ki] = parseFlow(text, i, line, depth + 1);
      i = skip(ki);
      let value: YNode = scalar(line);
      if (text[i] === ':') [value, i] = parseFlow(text, i + 1, line, depth + 1);
      i = skip(i);
      if (k.kind === 'scalar') entries.push({ key: k.text, line, value });
      if (text[i] === ',') i = skip(i + 1);
      else if (text[i] !== '}') break;
    }
    return [{ kind: 'map', line, end: line + 1, entries }, Math.min(text.length, i + 1)];
  }
  if (text[i] === '"' || text[i] === "'") {
    const e = quoteEnd(text, i);
    if (e < 0) return [scalar(line, text.slice(i + 1)), text.length];
    return [scalar(line, unquote(text.slice(i, e)), true), e];
  }
  // A plain scalar ends at a flow indicator, or at a colon that ends a key.
  let k = i;
  while (k < text.length && !',[]{}'.includes(text[k])) {
    if (text[k] === ':' && (k + 1 === text.length || ' \t\n,]}'.includes(text[k + 1]))) break;
    k++;
  }
  return [scalar(line, text.slice(i, k).trim()), k];
}

/**
 * The open and close brackets of a flow collection, outside quotes, as its lines come: positive while it's still
 * open. Each new part is scanned once, keeping the quote it's inside and whether a comment ended the scan (a # at
 * the start or after a space or tab). Rescanning the whole text for every line took time squared on a collection
 * that never closes.
 */
class FlowScan {
  private depth = 0;
  /** The quote the scan is inside, and whether the character before was a backslash in a double-quoted string. */
  private quote: string | null = null;
  private escaped = false;
  private stopped = false;
  private prev: string | undefined = undefined;

  feed(part: string): number {
    for (let k = 0; k < part.length && !this.stopped; k++) {
      const c = part[k];
      if (this.quote) {
        if (this.escaped) this.escaped = false;
        else if (this.quote === '"' && c === '\\') this.escaped = true;
        else if (c === this.quote) {
          // '' inside a single-quoted string is a quote; at the end of the text it closes the string, as quoteEnd says.
          if (this.quote === "'" && part[k + 1] === "'") k++;
          else this.quote = null;
        }
      } else if (c === '"' || c === "'") this.quote = c;
      else if (c === '[' || c === '{') this.depth++;
      else if (c === ']' || c === '}') this.depth--;
      else if (c === '#' && (this.prev === undefined || isBlank(this.prev))) this.stopped = true;
      this.prev = part[k];
    }
    return this.depth;
  }
}

/**
 * Whether a quoted string closes, fed its lines one at a time: quoteEnd() on the joined text, scanning each line once.
 * A backslash at the end of a double-quoted line escapes what comes next, unless the caller drops it.
 */
class QuoteScan {
  closed = false;
  /** A backslash ended the last part, so the next character is escaped. */
  escaped = false;
  private q: string;
  constructor(quote: string) {
    this.q = quote;
  }

  feed(part: string): boolean {
    for (let k = 0; k < part.length && !this.closed; k++) {
      if (this.escaped) this.escaped = false;
      else if (this.q === '"' && part[k] === '\\') this.escaped = true;
      else if (part[k] === this.q) {
        if (this.q === "'" && part[k + 1] === "'") k++;
        else this.closed = true;
      }
    }
    return this.closed;
  }
}

/** text without a trailing comment, outside quotes (for the lines of a flow collection). */
function dropComment(text: string): string {
  for (let k = 0; k < text.length; k++) {
    const c = text[k];
    if (c === '"' || c === "'") {
      const e = quoteEnd(text, k);
      if (e < 0) return text;
      k = e - 1;
    } else if (c === '#' && (k === 0 || isBlank(text[k - 1]))) return text.slice(0, k);
  }
  return text;
}

/** The anchor (&name) or tag (!tag) that starts text, and the text after it. */
function property(text: string): [string, string] {
  let k = 0;
  while (k < text.length && !isBlank(text[k])) k++;
  return [text.slice(0, k), text.slice(k).trimStart()];
}

class Reader {
  lines: string[];
  n: number;
  /** Nodes by anchor name, for the aliases (*name) after them. */
  anchors = new Map<string, YNode>();
  /** How deep block() is, and how many more entries merge keys may copy. */
  depth = 0;
  work: number;
  max: number;
  constructor(text: string) {
    this.lines = splitLines(text);
    this.n = this.lines.length;
    this.max = maxExpanded(text);
    this.work = maxMerged(text);
  }

  /** The node an alias names, placed where the alias is, or an empty scalar for an unknown name. */
  alias(name: string, line: number): YNode {
    const node = this.anchors.get(name);
    return node ? { ...node, line, end: line + 1 } : scalar(line);
  }

  /** Add the entries a merge key (<<: *defaults) brings in, after the mapping's own entries. */
  merge(node: YMap): YMap {
    const merged = node.entries.filter((e) => e.key === '<<');
    if (!merged.length) return node;
    const own = node.entries.filter((e) => e.key !== '<<');
    const keys = new Set(own.map((e) => e.key));
    for (const m of merged) {
      const sources = m.value.kind === 'seq' ? m.value.items : [m.value];
      for (const src of sources) {
        if (src.kind !== 'map') continue;
        // Merge keys that merge maps built by merge keys copy more each time, which a chain of them makes squared.
        this.work -= src.entries.length;
        if (this.work < 0) throw new TooComplex('its merge keys copy too many entries');
        for (const e of src.entries) {
          if (!keys.has(e.key)) {
            keys.add(e.key);
            own.push(e);
          }
        }
      }
    }
    return { ...node, entries: own };
  }

  indent(i: number): number {
    const s = this.lines[i];
    let k = 0;
    while (k < s.length && isBlank(s[k])) k++;
    return k;
  }

  /** A line that holds structure: not blank, not only a comment, not a document marker. */
  significant(i: number): boolean {
    const t = this.lines[i].trim();
    return t !== '' && t[0] !== '#' && t !== '---' && t !== '...';
  }

  nextSignificant(i: number): number {
    while (i < this.n && !this.significant(i)) i++;
    return i;
  }

  document(): YNode | null {
    const i = this.nextSignificant(0);
    if (i >= this.n) return null;
    const col = this.indent(i);
    const doc = this.block(i, col, this.lines[i].slice(col))[0];
    measure(doc, this.max);
    return doc;
  }

  /** The node at line i, column col, whose text (from col) is text. Returns it and the line after it. */
  block(i: number, col: number, text: string): [YNode, number] {
    if (++this.depth > MAX_DEPTH) throw new TooComplex(`it nests more than ${MAX_DEPTH} deep`);
    try {
      return this.blockAt(i, col, text);
    } finally {
      this.depth--;
    }
  }

  blockAt(i: number, col: number, text: string): [YNode, number] {
    if (text[0] === '&' || text[0] === '!') {
      const [prop, rest] = property(text);
      const at = col + (text.length - rest.length);
      // "&name" alone: the node is on the next lines.
      const [node, next] = rest && rest[0] !== '#' ? this.block(i, at, rest) : this.value(i, col - 1, '');
      if (prop[0] === '&') this.anchors.set(prop.slice(1), node);
      return [node, next];
    }
    if (isDash(text)) return this.seq(i, col, text);
    if (keyOf(text)) return this.map(i, col, text);
    return this.value(i, col - 1, text);
  }

  /** Skip lines indented deeper than col that nothing claimed (bad YAML), to the next one at col or less. */
  resume(j: number, col: number): number {
    j = this.nextSignificant(j);
    while (j < this.n && this.indent(j) > col) j = this.nextSignificant(j + 1);
    return j;
  }

  map(i: number, col: number, first: string): [YMap, number] {
    const entries: YMap['entries'] = [];
    let line = i;
    let text = first;
    let end = i + 1;
    for (;;) {
      const k = keyOf(text)!;
      const [value, next] = this.value(line, col, text.slice(k.rest));
      entries.push({ key: k.key, line, value });
      end = Math.max(end, value.end, line + 1);
      const j = this.resume(next, col);
      const t = j < this.n ? this.lines[j].slice(col) : '';
      if (j >= this.n || this.indent(j) !== col || !keyOf(t)) {
        return [this.merge({ kind: 'map', line: i, end, entries }), j];
      }
      line = j;
      text = t;
    }
  }

  seq(i: number, col: number, first: string): [YSeq, number] {
    const items: YNode[] = [];
    let line = i;
    let text = first;
    let end = i + 1;
    for (;;) {
      let k = 1;
      while (isBlank(text[k])) k++;
      const itemCol = col + k;
      const item = text.slice(k);
      let node: YNode;
      let next: number;
      if (item === '' || item[0] === '#') {
        const j = this.nextSignificant(line + 1);
        if (j < this.n && this.indent(j) > col) {
          [node, next] = this.block(j, this.indent(j), this.lines[j].slice(this.indent(j)));
        } else {
          [node, next] = [scalar(line), line + 1];
        }
      } else {
        [node, next] = this.block(line, itemCol, item);
      }
      items.push(node);
      end = Math.max(end, node.end, line + 1);
      const j = this.resume(next, col);
      const t = j < this.n ? this.lines[j].slice(col) : '';
      if (j >= this.n || this.indent(j) !== col || !isDash(t)) return [{ kind: 'seq', line: i, end, items }, j];
      line = j;
      text = t;
    }
  }

  /**
   * The value after a key (or a sequence dash) on line i: raw is the rest of the line. A value on the next lines must
   * be indented deeper than col, the key's column, except a sequence, which may start at col.
   */
  value(i: number, col: number, raw: string): [YNode, number] {
    let rest = raw.trimStart();
    // An anchor or a tag before the value: the anchor names the node parsed after it.
    let anchor: string | null = null;
    while (rest[0] === '&' || rest[0] === '!') {
      const [prop, after] = property(rest);
      if (prop[0] === '&') anchor = prop.slice(1);
      rest = after;
    }
    if (anchor !== null) {
      const got = this.value(i, col, rest);
      this.anchors.set(anchor, got[0]);
      return got;
    }
    if (rest[0] === '*') {
      const [name] = property(rest);
      return [this.alias(name.slice(1), i), i + 1];
    }
    if (rest === '' || rest[0] === '#') {
      const j = this.nextSignificant(i + 1);
      if (j < this.n) {
        const ind = this.indent(j);
        const t = this.lines[j].slice(ind);
        if (ind > col) return this.block(j, ind, t);
        if (ind === col && isDash(t)) return this.seq(j, col, t);
      }
      return [scalar(i), i + 1];
    }
    if (rest[0] === '|' || rest[0] === '>') return this.blockScalar(i, col, rest);
    if (rest[0] === '[' || rest[0] === '{') {
      let text = dropComment(rest);
      let j = i;
      const scan = new FlowScan();
      let depth = scan.feed(text);
      while (depth > 0 && j + 1 < this.n) {
        j++;
        const more = '\n' + dropComment(this.lines[j]);
        text += more;
        depth = scan.feed(more);
      }
      const [node] = parseFlow(text, 0, i);
      node.end = j + 1;
      return [node, j + 1];
    }
    if (rest[0] === '"' || rest[0] === "'") {
      // The string's lines, joined by spaces. Each is scanned once for the closing quote, and kept apart until the end
      // (cutting a backslash off the joined text on every line took time squared).
      const parts = [rest];
      const scan = new QuoteScan(rest[0]);
      scan.feed(rest.slice(1));
      let j = i;
      while (!scan.closed && j + 1 < this.n) {
        if (this.lines[j + 1].trim() !== '' && this.indent(j + 1) <= col) break;
        j++;
        // A double-quoted line that ends in a backslash goes on without a space (and without the backslash).
        let last = parts[parts.length - 1];
        const before = last.length > 1 ? last[last.length - 2] : parts[parts.length - 2]?.at(-1);
        const line = this.lines[j].trim();
        if (rest[0] === '"' && last.endsWith('\\') && before !== '\\') {
          last = last.slice(0, -1);
          scan.escaped = false;
          if (last) parts[parts.length - 1] = last;
          else parts.pop();
          if (line) parts.push(line);
          scan.feed(line);
        } else {
          parts.push(' ' + line);
          scan.feed(' ' + line);
        }
      }
      const text = parts.join('');
      const e = quoteEnd(text, 0);
      if (e < 0) return [scalar(i, text.slice(1), true, j + 1), j + 1];
      return [scalar(i, unquote(text.slice(0, e)), true, j + 1), j + 1];
    }
    // A plain scalar, which may go on over more deeply indented lines.
    let text = rest.slice(0, commentAt(rest)).trim();
    let j = i + 1;
    let end = i + 1;
    while (j < this.n) {
      if (!this.significant(j)) {
        j++;
        continue;
      }
      if (this.indent(j) <= col) break;
      const more = this.lines[j].trim();
      text += ' ' + more.slice(0, commentAt(more)).trim();
      end = j + 1;
      j++;
    }
    return [scalar(i, text, false, end), end];
  }

  /** A literal (|) or folded (>) scalar: the lines after i indented deeper than col. Both keep their line breaks. */
  blockScalar(i: number, col: number, header: string): [YScalar, number] {
    // An indentation indicator (a digit next to | or >, before or after the chomping + or -) fixes the indentation.
    const digit = [header[1], header[2]].find((c) => c !== undefined && c >= '1' && c <= '9');
    let blockInd = digit ? col + Number(digit) : -1;
    const out: string[] = [];
    let last = i;
    let j = i + 1;
    for (; j < this.n; j++) {
      const s = this.lines[j];
      if (s.trim() === '') {
        out.push('');
        continue;
      }
      const ind = this.indent(j);
      if (ind <= col || (blockInd >= 0 && ind < blockInd)) break;
      if (blockInd < 0) blockInd = ind;
      out.push(s.slice(blockInd));
      last = j;
    }
    const text = out.slice(0, last - i).join('\n');
    return [scalar(i, text, false, last + 1), last + 1];
  }
}

/**
 * Throw TooComplex when a document, its aliases expanded, nests deeper than MAX_DEPTH or holds more than max
 * characters and nodes. Each node is visited once however many aliases share it, with a stack of its own (an alias
 * of an alias of an alias... would overflow the call stack).
 */
function measure(root: YNode | null, max: number): void {
  if (!root || root.kind === 'scalar') return;
  type Kids = YNode[] | YMap['entries'];
  const kids = (n: YNode): Kids | null => (n.kind === 'seq' ? n.items : n.kind === 'map' ? n.entries : null);
  const valueOf = (k: YNode | YMap['entries'][number]): YNode => ('kind' in k ? k : k.value);
  // The size and depth of the nodes done so far, by their list of items or entries (an alias shares its anchor's).
  const done = new Map<Kids, { size: number; depth: number }>();
  const stack: { list: Kids; next: number }[] = [{ list: kids(root)!, next: 0 }];
  while (stack.length) {
    const top = stack[stack.length - 1];
    if (top.next < top.list.length) {
      const child = kids(valueOf(top.list[top.next++]));
      if (child && !done.has(child)) {
        if (stack.length >= MAX_DEPTH) throw new TooComplex(`it nests more than ${MAX_DEPTH} deep`);
        stack.push({ list: child, next: 0 });
      }
      continue;
    }
    let size = 1;
    let depth = 0;
    for (const k of top.list) {
      const v = valueOf(k);
      const got = v.kind === 'scalar' ? { size: 1 + v.text.length, depth: 0 } : done.get(kids(v)!)!;
      size += got.size + ('key' in k ? k.key.length : 0);
      depth = Math.max(depth, got.depth);
    }
    if (size > max) throw new TooComplex('its aliases or merge keys expand too far');
    if (depth + 1 > MAX_DEPTH) throw new TooComplex(`it nests more than ${MAX_DEPTH} deep`);
    done.set(top.list, { size, depth: depth + 1 });
    stack.pop();
  }
}

/**
 * The YAML document in text, or null when it holds none. Throws TooComplex for a document too deep, or too big with
 * its aliases expanded, to read.
 */
export function readYaml(text: string): YNode | null {
  try {
    return new Reader(text).document();
  } catch (e) {
    if (e instanceof TooComplex) throw e;
    // The reader nests a call for each level (MAX_DEPTH keeps it well within the stack), so this is a safety net.
    if (e instanceof RangeError) throw new TooComplex(String(e));
    throw e;
  }
}

/** The YAML document in text, or null when it holds none, or is too deep or too big to read (see readYaml). */
export function parseYaml(text: string): YNode | null {
  try {
    return readYaml(text);
  } catch {
    return null;
  }
}

/** The value under key in a mapping, or null (for anything that isn't a mapping too). */
export function at(node: YNode | null | undefined, key: string): YNode | null {
  if (!node || node.kind !== 'map') return null;
  for (const e of node.entries) if (e.key === key) return e.value;
  return null;
}

/** The entry for key in a mapping, with the line it's on, or null. */
export function entry(node: YNode | null | undefined, key: string): YMap['entries'][number] | null {
  if (!node || node.kind !== 'map') return null;
  return node.entries.find((e) => e.key === key) ?? null;
}

/** A scalar's text, or null for a missing value, a mapping or a sequence. */
export function text(node: YNode | null | undefined): string | null {
  return node && node.kind === 'scalar' ? node.text : null;
}

/** A scalar as a list of one, a sequence's scalar items, or nothing. */
export function list(node: YNode | null | undefined): string[] {
  if (!node) return [];
  if (node.kind === 'scalar') return node.text ? [node.text] : [];
  if (node.kind === 'seq') return node.items.map(text).filter((t): t is string => t !== null && t !== '');
  return [];
}

/** A mapping's scalar values by key (a nested mapping or sequence is left out). */
export function strings(node: YNode | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (node && node.kind === 'map') {
    for (const e of node.entries) {
      const t = text(e.value);
      if (t !== null) out[e.key] = t;
    }
  }
  return out;
}
