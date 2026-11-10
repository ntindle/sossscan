/**
 * Content negotiation (lib/negotiate.ts): which representation an Accept header gets, by
 * https://acceptmarkdown.com/guides/accept-parsing and RFC 9110, section 12.5.1.
 */
import { describe, expect, it } from 'vitest';
import { markdownPath, negotiate, parseAccept } from '@/lib/negotiate.ts';

describe('negotiate', () => {
  // The test vectors from acceptmarkdown.com, for a server that has both representations.
  it.each([
    ['text/markdown', 'markdown'],
    ['text/markdown, text/html;q=0.8', 'markdown'],
    ['text/html', 'html'],
    ['text/markdown;q=0, text/html', 'html'],
    [undefined, 'html'],
    ['*/*', 'html'],
  ])('follows acceptmarkdown.com for %j', (accept, expected) => {
    expect(negotiate(accept)).toBe(expected);
  });

  // What real clients send (https://acceptmarkdown.com/status, and the browsers' defaults).
  it.each([
    ['Claude Code, Copilot CLI', 'text/markdown, text/html, */*', 'markdown'],
    [
      'Copilot Chat',
      'text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.9, application/xml;q=0.8, */*;q=0.7',
      'markdown',
    ],
    ['Cursor', 'text/markdown, text/plain;q=0.9, */*;q=0.8', 'markdown'],
    ['OpenClaw', 'text/markdown, text/html;q=0.9, */*;q=0.1', 'markdown'],
    [
      'OpenCode',
      'text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1',
      'markdown',
    ],
    [
      'Chrome',
      'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'html',
    ],
    ['Firefox and Safari', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'html'],
    ['curl', '*/*', 'html'],
  ])('gives %s what it prefers', (_client, accept, expected) => {
    expect(negotiate(accept)).toBe(expected);
  });

  it('goes by weight first', () => {
    expect(negotiate('text/html;q=0.5, text/markdown;q=0.6')).toBe('markdown');
    expect(negotiate('text/markdown;q=0.5, text/html;q=0.6')).toBe('html');
    expect(negotiate('text/markdown;q=0.001')).toBe('markdown');
    expect(negotiate('text/html;q=0.1, */*;q=0.2')).toBe('markdown'); // text/html sets HTML's weight, not */*
  });

  it('lets the most specific range set a type weight, so q=0 rules a type out', () => {
    expect(negotiate('text/markdown;q=0, */*')).toBe('html');
    expect(negotiate('text/html;q=0, */*')).toBe('markdown');
    expect(negotiate('text/*;q=0.5, text/markdown;q=0')).toBe('html');
    expect(negotiate('*/*;q=0.1, text/markdown')).toBe('markdown');
  });

  it('breaks a tie in weight by the range that names the type, then by order, and otherwise sends HTML', () => {
    expect(negotiate('*/*, text/markdown')).toBe('markdown'); // named beats a wildcard
    expect(negotiate('text/*, text/markdown')).toBe('markdown');
    expect(negotiate('text/markdown, text/html')).toBe('markdown'); // listed first
    expect(negotiate('text/html, text/markdown')).toBe('html');
    expect(negotiate('text/markdown;q=0.5, text/html;q=0.5')).toBe('markdown');
    expect(negotiate('text/*')).toBe('html'); // one range covers both: HTML
    expect(negotiate('*/*;q=0.3')).toBe('html');
    expect(negotiate('text/*, */*')).toBe('html');
  });

  it('treats a missing, empty or unreadable header as no preference', () => {
    for (const accept of [null, undefined, '', '   ', ',', 'garbage', 'text', 'text/', '/markdown', '*/markdown']) {
      expect(negotiate(accept), String(accept)).toBe('html');
    }
  });

  it('answers 406 (null) only when the header rules out both', () => {
    for (const accept of [
      'application/json',
      'application/pdf',
      'image/*',
      'text/plain',
      'text/markdown;q=0',
      'text/markdown;q=0, text/html;q=0',
      '*/*;q=0',
      'text/*;q=0',
    ]) {
      expect(negotiate(accept), accept).toBeNull();
    }
  });

  it('ignores case and white space, and reads quoted parameters', () => {
    expect(negotiate('  TEXT/Markdown ;  Q=0.9 , text/html ; q = 0.5')).toBe('markdown');
    expect(negotiate('text/html;foo="a, b";q=0.5, text/markdown')).toBe('markdown');
  });

  it('matches parameters, as RFC 9110 does: both types are sent as UTF-8 and have no other parameter', () => {
    expect(negotiate('text/markdown;charset=utf-8')).toBe('markdown');
    expect(negotiate('text/markdown;charset=UTF-8, text/html;q=0.5')).toBe('markdown');
    expect(negotiate('text/markdown;variant=GFM')).toBeNull();
    expect(negotiate('text/markdown;charset=iso-8859-1, text/html;q=0.5')).toBe('html');
  });

  it('drops a range with a weight it cannot read, rather than guessing one', () => {
    for (const q of ['2', '-1', '1.5', 'abc', '', '0.5.5']) {
      expect(parseAccept(`text/markdown;q=${q}`), q).toEqual([]);
    }
    expect(negotiate('text/markdown;q=2, text/html;q=0.5')).toBe('html');
  });
});

describe('parseAccept', () => {
  it('keeps each range in order, with its weight and parameters', () => {
    const ranges = parseAccept('text/html;level=1;q=0.7, Text/Markdown, */*;q=0');
    expect(ranges.map(({ type, subtype, q, index }) => [type, subtype, q, index])).toEqual([
      ['text', 'html', 0.7, 0],
      ['text', 'markdown', 1, 1],
      ['*', '*', 0, 2],
    ]);
    expect([...ranges[0].params]).toEqual([['level', '1']]);
  });

  it('splits on commas outside quoted strings only', () => {
    const ranges = parseAccept('text/html;foo="a, \\"b\\"";q=0.5, text/markdown');
    expect(ranges.map((r) => `${r.type}/${r.subtype}`)).toEqual(['text/html', 'text/markdown']);
    expect(ranges[0].params.get('foo')).toBe('a, "b"');
    expect(ranges[0].q).toBe(0.5);
  });
});

describe('markdownPath', () => {
  it("puts a page's Markdown at its address with .md, and the home page's at /index.md", () => {
    expect(markdownPath('/')).toBe('/index.md');
    expect(markdownPath('/about')).toBe('/about.md');
    expect(markdownPath('/docs/api')).toBe('/docs/api.md');
  });
});
