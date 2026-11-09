/**
 * The bits of Python the scanner relies on, reproduced exactly, so the TypeScript port gave byte-for-byte the same
 * report as the Python scanner it replaced (scanner/sosf_scan.py, which commit a55738d still has) until 0.3.0 fixed
 * that scanner's bugs.
 *
 * Regexes are written in Python syntax (copied verbatim from the Python scanner) and translated by `re()`. The
 * translation keeps Python's meaning, not just its syntax:
 * - \s is str.isspace() (it includes \x1c-\x1f and \x85, but not U+FEFF); \w is Unicode letters, numbers and _;
 *   \d is any Unicode decimal digit; \b uses that \w.
 * - ^ and $ with (?m) break lines only at \n (JS also breaks at \r, U+2028 and U+2029); a plain $ also matches
 *   before a final \n; . excludes only \n.
 * - (?i) on ASCII letters folds exactly as Python does, including İ and ı for i, ſ for s and the Kelvin sign for k.
 * - A { that doesn't start a repeat is a literal, as in Python.
 * Anything the translator can't reproduce exactly throws when the pattern is compiled, so a gap fails loudly in
 * tests instead of silently changing a result. The only remaining difference is the Unicode version behind \w and
 * \d: Node's (17.0 in Node 24) is newer than Python 3.12's (15.0), so letters added after 15.0 count as word
 * characters here and not there.
 */

// ---------------------------------------------------------------------------------------------- strings

/** The characters str.isspace() accepts, which are also what Python's re treats as \s. */
const SPACE = String.raw`\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000`;
/** Python's \w for str patterns: str.isalnum() or "_", which is exactly the Unicode L and N categories plus _. */
const WORD = String.raw`\p{L}\p{N}_`;
const LEADING_SPACE = new RegExp(`^[${SPACE}]+`, 'u');
const TRAILING_SPACE = new RegExp(`[${SPACE}]+$`, 'u');
const LINE_BREAK = /\r\n|[\n\v\f\r\x1c-\x1e\x85\u2028\u2029]/u;

/** str.splitlines(): every Unicode line boundary, CRLF as one, and no empty string after a final line break. */
export function splitLines(text: string): string[] {
  const lines = text.split(LINE_BREAK);
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** str.lstrip() with no arguments. */
export function pyLstrip(s: string): string {
  return s.replace(LEADING_SPACE, '');
}

/** str.strip() with no arguments. */
export function pyStrip(s: string): string {
  return s.replace(LEADING_SPACE, '').replace(TRAILING_SPACE, '');
}

/** len() of a str: code points, not UTF-16 units. */
export function pyLen(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

/** s[start:end] on a str (code points, negative indexes count from the end). Non-strings raise, as in Python. */
export function pySlice(s: unknown, start?: number, end?: number): string {
  if (typeof s !== 'string') throw new TypeError(`'${pyType(s)}' object is not subscriptable`);
  return Array.from(s).slice(start, end).join('');
}

/** sep.join(items): every item must be a str, as in Python. */
export function pyJoin(sep: string, items: readonly unknown[]): string {
  items.forEach((x, i) => {
    if (typeof x !== 'string') throw new TypeError(`sequence item ${i}: expected str instance, ${pyType(x)} found`);
  });
  return items.join(sep);
}

/** Compare strings by code point, as Python does (JS's default sort compares UTF-16 units). */
export function comparePy(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.codePointAt(i)!;
    const y = b.codePointAt(i)!;
    if (x !== y) return x - y;
    if (x > 0xffff) i++;
  }
  return a.length - b.length;
}

/** sorted() of a list of str. Python can't order a str against None (or None against None), so neither can this. */
export function pySorted(items: readonly unknown[]): string[] {
  if (items.length > 1 && items.some((x) => typeof x !== 'string')) {
    throw new TypeError("'<' not supported between instances of these types");
  }
  return [...(items as string[])].sort(comparePy);
}

/** The bytes urllib.parse.quote() leaves alone (its default safe="/" included). */
const QUOTE_SAFE = /^[A-Za-z0-9_.~/-]$/;

/** urllib.parse.quote(s): percent-encode the UTF-8 bytes of everything but letters, digits and _.-~/ */
export function quote(s: unknown): string {
  if (typeof s !== 'string') throw new TypeError('quote() expected str, bytes or bytearray');
  if (!s.isWellFormed()) throw new TypeError("'utf-8' codec can't encode a lone surrogate");
  let out = '';
  for (const b of new TextEncoder().encode(s)) {
    const ch = String.fromCharCode(b);
    out += b < 0x80 && QUOTE_SAFE.test(ch) ? ch : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

const DECIMAL = /^\p{Nd}$/u;

/** int(s) for a string of decimal digits; like Python it accepts any Unicode digits and rejects an empty string. */
export function pyInt(s: string): number {
  if (!s || ![...s].every((c) => DECIMAL.test(c))) throw new Error(`invalid literal for int() with base 10: '${s}'`);
  let digits = '';
  for (const c of s) {
    const cp = c.codePointAt(0)!;
    // Unicode encodes each set of decimal digits as one run of ten, 0 to 9, so a digit's value is its offset into
    // the run of digits around it.
    let start = cp;
    while (start > 0 && DECIMAL.test(String.fromCodePoint(start - 1))) start--;
    digits += String((cp - start) % 10);
  }
  return Number(digits);
}

// ------------------------------------------------------------------------------------- Python values

/** Python's name for the type of a JSON value, for error messages. */
function pyType(v: unknown): string {
  if (v === null || v === undefined) return 'NoneType';
  if (typeof v === 'boolean') return 'bool';
  if (typeof v === 'number') return Number.isInteger(v) ? 'int' : 'float';
  if (typeof v === 'string') return 'str';
  if (Array.isArray(v)) return 'list';
  return 'dict';
}

/** A JSON object (a Python dict), not an array or null. */
export function isDict(v: unknown): v is Record<string, any> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Python truthiness: None, False, 0, "", [] and {} are false. */
export function truthy(v: unknown): boolean {
  if (v === null || v === undefined || v === false || v === 0 || v === '') return false;
  if (Array.isArray(v)) return v.length > 0;
  if (isDict(v)) return Object.keys(v).length > 0;
  return true;
}

/** Python's `a or b`. */
export function pyOr<A, B>(a: A, b: B): A | B {
  return truthy(a) ? a : b;
}

/** dict.get(key, default): the default only when the key is missing, not when its value is null. */
export function get(o: unknown, key: string, dflt: unknown = null): any {
  if (!isDict(o)) throw new TypeError(`'${pyType(o)}' object has no attribute 'get'`);
  return Object.hasOwn(o, key) ? o[key] : dflt;
}

/** o[key] on a dict: a missing key raises KeyError instead of quietly giving undefined. */
export function item(o: unknown, key: string): any {
  if (!isDict(o)) throw new TypeError(`'${pyType(o)}' object is not subscriptable by '${key}'`);
  if (!Object.hasOwn(o, key)) throw new Error(`KeyError: '${key}'`);
  return o[key];
}

/** lines[i] with Python's negative indexes and IndexError. */
export function at<T>(list: readonly T[], i: number): T {
  const j = i < 0 ? list.length + i : i;
  if (j < 0 || j >= list.length) throw new RangeError('list index out of range');
  return list[j];
}

/** What `for x in v` visits: a list's items, a dict's keys, a str's characters. None isn't iterable. */
export function pyIter(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (isDict(v)) return Object.keys(v);
  if (typeof v === 'string') return Array.from(v);
  throw new TypeError(`'${pyType(v)}' object is not iterable`);
}

/** len() of a JSON value. */
export function pyLenOf(v: unknown): number {
  if (typeof v === 'string') return pyLen(v);
  return pyIter(v).length;
}

/** Python's `x in container` for a list, a dict (its keys) or a str (a substring). */
export function pyIn(x: unknown, container: unknown): boolean {
  if (typeof container === 'string') {
    if (typeof x !== 'string') throw new TypeError("'in <string>' requires string as left operand");
    return container.includes(x);
  }
  if (isDict(container)) return typeof x === 'string' && Object.hasOwn(container, x);
  return pyIter(container).some((y) => y === x);
}

/** repr() of a float: the shortest round-trip digits, in scientific notation below 1e-4 or from 1e16. */
function floatRepr(n: number): string {
  if (Number.isNaN(n)) return 'nan';
  if (!Number.isFinite(n)) return n > 0 ? 'inf' : '-inf';
  const [mantissa, expPart] = n.toExponential().split('e');
  const exp = Number(expPart);
  const sign = mantissa.startsWith('-') ? '-' : '';
  const digits = mantissa.replace('-', '').replace('.', '');
  if (exp < -4 || exp >= 16) {
    const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    return `${sign}${m}e${exp < 0 ? '-' : '+'}${String(Math.abs(exp)).padStart(2, '0')}`;
  }
  if (exp < 0) return `${sign}0.${'0'.repeat(-exp - 1)}${digits}`;
  if (digits.length <= exp + 1) return `${sign}${digits}${'0'.repeat(exp + 1 - digits.length)}.0`;
  return `${sign}${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
}

const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

/** repr() of a str. */
function strRepr(s: string): string {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = q;
  for (const c of s) {
    const cp = c.codePointAt(0)!;
    if (c === q || c === '\\') out += '\\' + c;
    else if (c === '\n') out += '\\n';
    else if (c === '\r') out += '\\r';
    else if (c === '\t') out += '\\t';
    else if (c !== ' ' && UNPRINTABLE.test(c)) {
      const hex = cp.toString(16);
      out +=
        cp < 0x100
          ? `\\x${hex.padStart(2, '0')}`
          : cp < 0x10000
            ? `\\u${hex.padStart(4, '0')}`
            : `\\U${hex.padStart(8, '0')}`;
    } else out += c;
  }
  return out + q;
}

/** repr() of a JSON value (JSON numbers without a fraction are Python ints). */
export function pyRepr(v: unknown): string {
  if (v === null || v === undefined) return 'None';
  if (v === true) return 'True';
  if (v === false) return 'False';
  if (typeof v === 'number') return Number.isInteger(v) && Math.abs(v) < 2 ** 63 ? String(v) : floatRepr(v);
  if (typeof v === 'string') return strRepr(v);
  if (Array.isArray(v)) return `[${v.map(pyRepr).join(', ')}]`;
  if (isDict(v))
    return `{${Object.entries(v)
      .map(([k, x]) => `${strRepr(k)}: ${pyRepr(x)}`)
      .join(', ')}}`;
  return String(v);
}

/** str() of a JSON value, which is what an f-string prints: None, True and False come out as in Python. */
export function pyStr(v: unknown): string {
  return typeof v === 'string' ? v : pyRepr(v);
}

// --------------------------------------------------------------------------------------------- regexes

interface Flags {
  i: boolean;
  m: boolean;
  s: boolean;
}

/** Every pattern compiled at module load, with its Python source, so tests can check the port against the original. */
export const COMPILED: { source: string; flags: string }[] = [];

/** How (?i) folds each ASCII letter in Python: İ and ı also match i, ſ matches s, and the Kelvin sign matches k. */
const FOLD_EXTRA: Record<string, string> = { i: '\u0130\u0131', k: '\u212a', s: '\u017f' };
const SYNTAX = new Set('^$\\.*+?()[]{}|/');
const IN_CLASS_SPECIAL = new Set('\\]-^[');

function caseVariants(c: string): string {
  const lower = c.toLowerCase();
  return lower + lower.toUpperCase() + (FOLD_EXTRA[lower] ?? '');
}

function isAsciiLetter(c: string): boolean {
  return /^[A-Za-z]$/.test(c);
}

/** True for a character that has another case, which (?i) would fold. */
function isCased(c: string): boolean {
  return c.toLowerCase() !== c.toUpperCase();
}

function hex(cp: number): string {
  return `\\u{${cp.toString(16)}}`;
}

/** A literal outside a character class, escaped for a JS `u` regex. */
function literal(c: string, f: Flags, src: string): string {
  if (f.i && isAsciiLetter(c)) return `[${caseVariants(c)}]`;
  if (f.i && isCased(c)) throw new Error(`can't translate (?i) on non-ASCII ${c} in ${src}`);
  if (SYNTAX.has(c)) return '\\' + c;
  const cp = c.codePointAt(0)!;
  return cp < 0x20 || cp === 0x7f ? hex(cp) : c;
}

/** A literal inside a character class. */
function classLiteral(cp: number): string {
  const c = String.fromCodePoint(cp);
  if (IN_CLASS_SPECIAL.has(c)) return '\\' + c;
  return cp < 0x20 || cp >= 0x7f ? hex(cp) : c;
}

const SIMPLE_ESCAPES: Record<string, number> = { n: 10, t: 9, r: 13, f: 12, v: 11, a: 7 };

/** Read the escape at cps[i] (a backslash) as a single code point, or return null if it isn't one. */
function escapedCodePoint(cps: string[], i: number, src: string, inClass: boolean): [number, number] | null {
  const c = cps[i + 1];
  if (c === undefined) throw new Error(`bad escape (end of pattern) in ${src}`);
  if (c in SIMPLE_ESCAPES) return [SIMPLE_ESCAPES[c], i + 2];
  if (inClass && c === 'b') return [8, i + 2];
  const width = c === 'x' ? 2 : c === 'u' ? 4 : c === 'U' ? 8 : 0;
  if (width) {
    const digits = cps.slice(i + 2, i + 2 + width).join('');
    if (!new RegExp(`^[0-9a-fA-F]{${width}}$`).test(digits)) throw new Error(`bad escape \\${c} in ${src}`);
    return [parseInt(digits, 16), i + 2 + width];
  }
  if (/^[A-Za-z0-9]$/.test(c)) return null;
  return [c.codePointAt(0)!, i + 2];
}

/** Translate the character class starting at cps[i] ("["). Returns the JS class and the index after it. */
function translateClass(cps: string[], i: number, f: Flags, src: string): [string, number] {
  let j = i + 1;
  let negate = false;
  if (cps[j] === '^') {
    negate = true;
    j++;
  }
  let body = '';
  const extra = new Set<string>();
  let first = true;
  const addLetters = (lo: number, hi: number) => {
    if (!f.i) return;
    for (let cp = lo; cp <= hi && cp <= 0x7f; cp++) {
      const c = String.fromCodePoint(cp);
      if (isAsciiLetter(c)) for (const v of caseVariants(c)) extra.add(v);
    }
    if (hi > 0x7f) {
      for (let cp = Math.max(lo, 0x80); cp <= hi; cp++) {
        if (isCased(String.fromCodePoint(cp))) throw new Error(`can't translate (?i) on a non-ASCII range in ${src}`);
      }
    }
  };
  for (;;) {
    const c = cps[j];
    if (c === undefined) throw new Error(`unterminated character set in ${src}`);
    if (c === ']' && !first) {
      j++;
      break;
    }
    first = false;
    // One atom: a class escape (\s, \w, \d), or a single code point that may start a range.
    let cp: number;
    if (c === '\\') {
      const e = cps[j + 1];
      if (e === 's' || e === 'w' || e === 'd' || e === 'D') {
        body += e === 's' ? SPACE : e === 'w' ? WORD : e === 'd' ? String.raw`\p{Nd}` : String.raw`\P{Nd}`;
        j += 2;
        continue;
      }
      const got = escapedCodePoint(cps, j, src, true);
      if (!got) throw new Error(`can't translate \\${e} inside a character class in ${src}`);
      [cp, j] = got;
    } else {
      cp = c.codePointAt(0)!;
      j++;
    }
    if (cps[j] === '-' && cps[j + 1] !== undefined && cps[j + 1] !== ']') {
      let hi: number;
      if (cps[j + 1] === '\\') {
        const got = escapedCodePoint(cps, j + 1, src, true);
        if (!got) throw new Error(`bad character range in ${src}`);
        [hi, j] = got;
      } else {
        hi = cps[j + 1].codePointAt(0)!;
        j += 2;
      }
      if (hi < cp) throw new Error(`bad character range in ${src}`);
      body += `${classLiteral(cp)}-${classLiteral(hi)}`;
      addLetters(cp, hi);
    } else {
      body += classLiteral(cp);
      addLetters(cp, cp);
    }
  }
  for (const v of extra) body += classLiteral(v.codePointAt(0)!);
  return [`[${negate ? '^' : ''}${body}]`, j];
}

/** Translate a whole Python pattern (without its leading inline flags) to the source of a JS `u` regex. */
function translate(src: string, f: Flags, whole: string): string {
  const cps = Array.from(src);
  const wordAt = `[${WORD}]`;
  let out = '';
  let i = 0;
  while (i < cps.length) {
    const c = cps[i];
    if (c === '\\') {
      const e = cps[i + 1];
      const named: Record<string, string> = {
        s: `[${SPACE}]`,
        S: `[^${SPACE}]`,
        w: wordAt,
        W: `[^${WORD}]`,
        d: String.raw`\p{Nd}`,
        D: String.raw`\P{Nd}`,
        b: `(?:(?<=${wordAt})(?!${wordAt})|(?<!${wordAt})(?=${wordAt}))`,
        B: `(?:(?<=${wordAt})(?=${wordAt})|(?<!${wordAt})(?!${wordAt}))`,
        A: String.raw`(?<![\s\S])`,
        Z: String.raw`(?![\s\S])`,
      };
      if (e !== undefined && e in named) {
        out += named[e];
        i += 2;
        continue;
      }
      if (e !== undefined && /^[1-9]$/.test(e)) {
        const ref = /^[1-9][0-9]?/.exec(cps.slice(i + 1, i + 3).join(''))![0];
        out += '\\' + ref;
        i += 1 + ref.length;
        continue;
      }
      const got = escapedCodePoint(cps, i, whole, false);
      if (!got) throw new Error(`can't translate \\${e} in ${whole}`);
      out += literal(String.fromCodePoint(got[0]), f, whole);
      i = got[1];
      continue;
    }
    if (c === '[') {
      const [cls, next] = translateClass(cps, i, f, whole);
      out += cls;
      i = next;
      continue;
    }
    if (c === '(') {
      if (cps[i + 1] !== '?') {
        out += '(';
        i++;
        continue;
      }
      const rest = cps.slice(i + 2).join('');
      let m: RegExpExecArray | null;
      if (rest.startsWith(':') || rest.startsWith('=') || rest.startsWith('!')) {
        out += '(?' + rest[0];
        i += 3;
      } else if (rest.startsWith('<=') || rest.startsWith('<!')) {
        out += '(?' + rest.slice(0, 2);
        i += 4;
      } else if ((m = /^P<([A-Za-z_]\w*)>/.exec(rest))) {
        out += `(?<${m[1]}>`;
        i += 2 + m[0].length;
      } else if ((m = /^P=([A-Za-z_]\w*)\)/.exec(rest))) {
        out += `\\k<${m[1]}>`;
        i += 2 + m[0].length;
      } else if ((m = /^#[^)]*\)/.exec(rest))) {
        i += 2 + m[0].length;
      } else {
        throw new Error(`can't translate the group (?${rest.slice(0, 3)}...) in ${whole}`);
      }
      continue;
    }
    if (c === '{') {
      // Python reads {m}, {m,}, {,n} and {m,n} as repeats and any other { as a literal.
      const m = /^\{(\d*)(?:(,)(\d*))?\}/.exec(cps.slice(i).join(''));
      if (m && m[0] !== '{}') {
        const lo = m[1] || '0';
        out += m[2] ? `{${lo},${m[3]}}` : `{${lo}}`;
        i += m[0].length;
        if (cps[i] === '+') throw new Error(`can't translate a possessive repeat in ${whole}`);
      } else {
        out += '\\{';
        i++;
      }
      continue;
    }
    if (c === '*' || c === '+' || c === '?') {
      out += c;
      i++;
      if (cps[i] === '+') throw new Error(`can't translate a possessive repeat in ${whole}`);
      if (cps[i] === '?') {
        out += '?';
        i++;
      }
      continue;
    }
    if (c === '.') out += f.s ? String.raw`[\s\S]` : String.raw`[^\n]`;
    else if (c === '^') out += f.m ? String.raw`(?<![^\n])` : '^';
    else if (c === '$') out += f.m ? String.raw`(?![^\n])` : String.raw`(?=\n?(?![\s\S]))`;
    else if (c === '|' || c === ')') out += c;
    else out += literal(c, f, whole);
    i++;
  }
  return out;
}

/**
 * Compile a Python regex. `flags` takes Python flag letters (i, m, s) for patterns that get them as an argument,
 * e.g. re.search(p, text, re.IGNORECASE); inline (?ims) at the start of the pattern works too.
 */
export function re(pattern: string, flags = '', register = true): RegExp {
  const f: Flags = { i: flags.includes('i'), m: flags.includes('m'), s: flags.includes('s') };
  let src = pattern;
  let m: RegExpExecArray | null;
  while ((m = /^\(\?([a-zA-Z]+)\)/.exec(src))) {
    for (const c of m[1]) {
      if (c === 'i' || c === 'm' || c === 's') f[c] = true;
      else if (c !== 'u') throw new Error(`can't translate the flag (?${c}) in ${pattern}`);
    }
    src = src.slice(m[0].length);
  }
  const out = new RegExp(translate(src, f, pattern), 'u');
  if (register) COMPILED.push({ source: pattern, flags });
  return out;
}

const variants = new WeakMap<RegExp, Map<string, RegExp>>();

function withFlag(rx: RegExp, flag: 'g' | 'y'): RegExp {
  let byFlag = variants.get(rx);
  if (!byFlag) variants.set(rx, (byFlag = new Map()));
  let out = byFlag.get(flag);
  if (!out) byFlag.set(flag, (out = new RegExp(rx.source, rx.flags + flag)));
  return out;
}

/** re.search: the first match anywhere. */
export function search(rx: RegExp, s: string): RegExpExecArray | null {
  if (rx.global || rx.sticky) throw new Error('search() takes a regex without the g or y flag');
  return rx.exec(s);
}

/** re.match: a match that starts at the beginning of the string (it may end anywhere). */
export function match(rx: RegExp, s: string): RegExpExecArray | null {
  const sticky = withFlag(rx, 'y');
  sticky.lastIndex = 0;
  return sticky.exec(s);
}

/** re.fullmatch: a match covering the whole string. */
export function fullmatch(rx: RegExp, s: string): RegExpExecArray | null {
  const m = match(new RegExp(String.raw`(?:${rx.source})(?![\s\S])`, rx.flags), s);
  return m;
}

function* matches(rx: RegExp, s: string): Generator<RegExpExecArray> {
  const g = withFlag(rx, 'g');
  g.lastIndex = 0;
  for (let m: RegExpExecArray | null; (m = g.exec(s));) {
    // Python and JS resume differently after an empty match; none of the scanner's patterns can match empty.
    if (m[0] === '') throw new Error(`empty match for ${rx.source}: Python and JS would differ`);
    yield m;
  }
}

/** re.finditer: every match, left to right, each with its groups and index. */
export function finditer(rx: RegExp, s: string): RegExpExecArray[] {
  return Array.from(matches(rx, s));
}

/** re.findall for a pattern with at most one group: the group (or whole match) of each match, '' for no match. */
export function findall(rx: RegExp, s: string): string[] {
  return Array.from(matches(rx, s), (m) => {
    if (m.length > 2) throw new Error('findall() with several groups: use findallTuples()');
    return (m.length === 2 ? m[1] : m[0]) ?? '';
  });
}

/** re.findall for a pattern with several groups: one tuple of groups per match, '' for a group that didn't match. */
export function findallTuples(rx: RegExp, s: string): string[][] {
  return Array.from(matches(rx, s), (m) => m.slice(1).map((g) => g ?? ''));
}

/** re.sub with a plain replacement string (no group references). */
export function sub(rx: RegExp, repl: string, s: string): string {
  if (repl.includes('\\')) throw new Error('sub() takes a plain replacement; backslash escapes are not translated');
  let out = '';
  let last = 0;
  for (const m of matches(rx, s)) {
    out += s.slice(last, m.index) + repl;
    last = m.index + m[0].length;
  }
  return out + s.slice(last);
}

/** re.escape (Python 3.7+): backslash every character that is special in a pattern. */
export function reEscape(s: string): string {
  return s.replace(/[()[\]{}?*+\-|^$\\.&~# \t\n\r\v\f]/g, '\\$&');
}
