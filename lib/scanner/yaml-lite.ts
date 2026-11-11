// A small reader for the YAML that GitHub Actions workflows and composite actions use: block mappings and sequences,
// plain, quoted and block scalars, and flow collections. New in 0.5.0, for the checks that need a workflow's jobs and
// steps rather than its lines; there's no Python original. It never throws on bad input: what it can't read becomes
// a scalar, or is skipped, so a check reading the tree finds less, never more.
import { splitLines } from './py.ts';

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
function parseFlow(text: string, i: number, line: number): [YNode, number] {
  const skip = (k: number) => {
    while (k < text.length && (isBlank(text[k]) || text[k] === '\n')) k++;
    return k;
  };
  i = skip(i);
  if (text[i] === '[') {
    const items: YNode[] = [];
    i = skip(i + 1);
    while (i < text.length && text[i] !== ']') {
      const [node, k] = parseFlow(text, i, line);
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
      const [k, ki] = parseFlow(text, i, line);
      i = skip(ki);
      let value: YNode = scalar(line);
      if (text[i] === ':') [value, i] = parseFlow(text, i + 1, line);
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

/** The open and close brackets of a flow collection, outside quotes: positive while it's still open. */
function flowDepth(text: string): number {
  let depth = 0;
  for (let k = 0; k < text.length; k++) {
    const c = text[k];
    if (c === '"' || c === "'") {
      const e = quoteEnd(text, k);
      if (e < 0) return depth;
      k = e - 1;
    } else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
    else if (c === '#' && (k === 0 || isBlank(text[k - 1]))) break;
  }
  return depth;
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
  constructor(text: string) {
    this.lines = splitLines(text);
    this.n = this.lines.length;
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
    return this.block(i, col, this.lines[i].slice(col))[0];
  }

  /** The node at line i, column col, whose text (from col) is text. Returns it and the line after it. */
  block(i: number, col: number, text: string): [YNode, number] {
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
      while (flowDepth(text) > 0 && j + 1 < this.n) {
        j++;
        text += '\n' + dropComment(this.lines[j]);
      }
      const [node] = parseFlow(text, 0, i);
      node.end = j + 1;
      return [node, j + 1];
    }
    if (rest[0] === '"' || rest[0] === "'") {
      let text = rest;
      let j = i;
      while (quoteEnd(text, 0) < 0 && j + 1 < this.n) {
        if (this.lines[j + 1].trim() !== '' && this.indent(j + 1) <= col) break;
        j++;
        // A double-quoted line that ends in a backslash goes on without a space.
        const joined = rest[0] === '"' && text.endsWith('\\') && !text.endsWith('\\\\');
        text = (joined ? text.slice(0, -1) : text + ' ') + this.lines[j].trim();
      }
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

/** The YAML document in text, or null when it holds none. */
export function parseYaml(text: string): YNode | null {
  try {
    return new Reader(text).document();
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
