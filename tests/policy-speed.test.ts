// A security policy is text anyone can write, and public scans run on our server, so no reader of it may take more
// than linear time: a hostile SECURITY.md must not be able to hang a scan. These tests run every reader on 1 MB
// policies built to be slow, and every pattern the readers compile on 256 KB of such text, and fail on anything slow.
// This file imports only the readers, so COMPILED holds exactly their patterns.
import { describe, expect, it } from 'vitest';
import { COMPILED, re } from '../lib/scanner/py.ts';
import {
  howToReport,
  MAX_POLICY,
  mentions,
  paragraphs,
  readPolicy,
  reportVerdict,
  sameRepoLink,
  sections,
} from '../lib/scanner/policy.ts';
import { readSupport, releaseLine, supportVerdict } from '../lib/scanner/versions.ts';

const fill = (unit: string, size: number) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size);

/** Policies built to be slow, each 1 MB: the kinds an independent audit tried, and the shapes that were slow. */
function policies(size: number): Record<string, string> {
  const f = (unit: string) => fill(unit, size);
  const numbered = (n: number, make: (i: number) => string) =>
    Array.from({ length: n }, (_, i) => make(i))
      .join(' ')
      .slice(0, size);
  return {
    plain_words: f('please report security issues to the maintainers privately. '),
    many_headings: f('# a\n'),
    many_support_headings: f('## Supported Versions\n'),
    many_bold_headings: f('\n**Heading text**\n'),
    many_plain_headings: f('\nREPORTING:\n'),
    many_links: f('[report](https://example.org/r) '),
    many_distinct_links: numbered(40000, (i) => `[security ${i}](https://acme.org/security/${i})`),
    many_bare_urls: numbered(40000, (i) => `https://acme.org/x${i}`),
    many_emails: numbered(40000, (i) => `u${i}@acme.org`),
    many_table_rows: '| Version | Supported |\n| --- | --- |\n' + f('| 1.2.x | :white_check_mark: |\n'),
    many_tables: f('\n| Version | Supported |\n| --- | --- |\n| 1.x | yes |\n'),
    many_tables_in_section: '## Supported Versions\n' + f('\n| Version | Supported |\n| --- | --- |\n| 1.x | yes |\n'),
    one_huge_line_pipes: f('|a'),
    pipe_lines: f('|a\n'),
    unclosed_comment: '<!--' + f('a '),
    many_comment_openers: f('`<!--` '),
    many_paragraphs: f('Report it to [the team](https://acme.org/team).\n\n'),
    many_list_items: f('- report to security team\n'),
    near_email: f('a.a.a.a.a.a.a.a.a.a@a.a.a.a.a.a.a.a.a.a.'),
    near_obfuscated: f('alice [at] acme [dot] '),
    near_spelled: f('security at acme at '),
    nested_brackets: f('[[[[[[[[[['),
    open_link_parens: f('[x]((((((('),
    html_tags: f('<a href="x" '),
    html_hrefs: '<a href="x" ' + f('href="'),
    html_link_open: '<a href="x">' + f('text '),
    html_headings_open: f('<h1>'),
    html_table_unclosed: '<table>' + f('<tr><td>1.x<td>yes'),
    html_tables_unclosed: f('<table>'),
    html_breaks_open: f('<p'),
    html_tag_spaces: '<b' + f(' ') + 'x',
    emphasis: f('*_*_*_*_ '),
    backticks: f('`a'),
    backtick_run: f('`'),
    images_open: f('!['),
    versions_cell: '| Version | Supported |\n| --- | --- |\n| ' + f('1.2.3.4.5.6.7.8.9.0.') + 'a | yes |\n',
    rst_like: f('====\nTitle\n====\n'),
    adoc_like: f(':attr-a: value {attr-a}\n'),
    crlf_mix: f('Report\r\nto\r\n\r\n'),
    nbsp: f('a '),
    cjk: f('漏洞报告请发送邮件'),
    heading_spaces: '# a' + f(' ') + 'b',
    separator_tabs: '- ' + f('\t') + 'x',
    spaces_then_word: f(' ') + 'x',
    attribute_spaces: ':a: x' + f(' ') + 'y',
    title_spaces: '= a' + f(' ') + 'b',
    bold_spaces: '**ab**' + f(' ') + 'x',
    role_spaces: ':ref:`' + f(' ') + 'x`',
    colons: f(':'),
    roles: f(':a'),
    xref_open: f('<'),
    link_macros: f('link:'),
    url_dots: 'https://a/' + f('.') + 'b',
    team_word: f('team'),
    report_tabs: 'Report ' + f('\t') + 'x',
    utf16_as_utf8: f('S\u0000E\u0000C\u0000'),
  };
}

/** The repeated units an independent audit timed every pattern on (its perf/ inputs), and a few more. */
const UNITS = [
  'a.b-c+d@e-f.g-h.',
  'x@y ',
  'a@b.c@',
  'aaaa@',
  'a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.',
  'a-a-a-a-a-a-a@a',
  'a [at] b [dot] c [dot] ',
  'a (at) b (dot) ',
  'a at b dot c dot d dot ',
  'security at a.b.c.d.e.',
  'a @ b.c.d.e.f',
  'a `at` b.',
  'a at b c d e f ',
  'to: a at b.c.d ',
  '[a](b c d e f ',
  '[[a]](',
  '](',
  '[a]: <',
  '<http://a',
  '<a href="',
  "<a href='x'>yyy",
  'https://a.b/c(d)e(f',
  '<!--',
  '<a',
  '<b c=d ',
  '&#1234567',
  '<table><tr><td>',
  '<h1>',
  '**a',
  '__a',
  '*a*a*a',
  '`a`a`',
  '~~a',
  '> > > >',
  '#####',
  '| a | b |',
  ':-:|:-:|',
  '+--+--+',
  '=== ===',
  '1. 1. 1. ',
  '1.2.3.4.5.6.7',
  'v1.x.y.z.',
  '>=1.2 - 3.4 - ',
  '1.2.3 and later and ',
  '20250101 ',
  'Jan 1, 2020 Jan ',
  '1st of January 1st ',
  '2020-01-01-',
  'Q1 2020 Q',
  'report a vulnerability via ',
  'private vulnerability report ',
  'security advisory security advisory ',
  'contact contact contact @',
  'discord discord @',
  'not not not supported ',
  'github github @',
  'issue issue issue tracker ',
  'email email email address ',
  'secur vuln report ',
  'dm pm privately ',
  'signal signal +1 ',
  ' \t \t',
  '  ',
  '\n\n\n',
  'a\n',
  ' \n',
  '\\\\',
  '((((',
  '{{{{',
  '@@@@',
  '::::',
  '....',
  '----',
  'aaaa',
  '    ',
  'a.',
  '日本語',
  '_a_',
  'A ',
  'AT ',
  // More, from shapes that were slow before 0.5.1's reader was made linear.
  'team',
  'secur',
  '![',
  '<p',
  '<tr',
  '<td',
  'link:',
  ':a',
  '`',
  '<',
  'href="',
  '1.',
  '|a',
  'a ',
];

/** Text that starts and ends with something, around a repeated unit: a heading's #, a table's pipe, a cell's text. */
const FRAMED: [string, string, string][] = [
  ['# a', ' ', 'b'],
  ['## a ', '\t', 'x'],
  ['- ', '\t', 'x'],
  ['| ', ' ', 'x'],
  ['`', ' ', 'x'],
  [':a: x', ' ', 'y'],
  ['= a', ' ', 'b'],
  ['**ab**', ' ', 'x'],
  ['<b', ' ', 'x'],
  ['<a href="x" ', 'href="', 'x'],
  ['https://a/', '.', 'b'],
  [':ref:`', ' ', 'x'],
  ['Report ', '\t', 'x'],
  ['contact ', ' ', 'x'],
  ['Email ', ' ', ')'],
  ['', '1.', '1a'],
  ['|', '<', ''],
  ['+', 'link:', 'x'],
  ['a [at] b', ' ', 'x'],
  ['security at a', ' ', 'x'],
  ['>= 1', ' ', 'x'],
  ['[a](b', ' ', 'x'],
];

/**
 * How long fn takes, in milliseconds: the faster of two runs when the first is over the limit. Something slow is slow
 * every time; a pause for garbage collection, or another test file running alongside, isn't.
 */
function time(fn: () => void, limit: number): number {
  const once = () => {
    const t0 = performance.now();
    fn();
    return performance.now() - t0;
  };
  const first = once();
  return first <= limit ? first : Math.min(first, once());
}

describe('reading a security policy takes linear time', () => {
  it('reads at most MAX_POLICY characters of a file, and says it cut it', () => {
    const p = readPolicy('# Security\n\n' + fill('word ', MAX_POLICY * 2), 'SECURITY.md');
    expect(p.truncated).toBe(true);
    expect(p.text.length).toBeLessThanOrEqual(MAX_POLICY);
    expect(readPolicy('# Security\n\nEmail security@example.org.', 'SECURITY.md').truncated).toBe(false);
  });

  it('runs every reader on each 1 MB policy built to be slow in under 250 ms', () => {
    // Warm up: compile the patterns and the code, as a running server has.
    for (const text of Object.values(policies(4000))) {
      const p = readPolicy(text, 'SECURITY.md');
      howToReport(p, 'acme/widget');
      readSupport(p);
    }
    const tags = [{ tag: 'v1.2.3' }];
    const slow: string[] = [];
    for (const [name, text] of Object.entries(policies(1_000_000))) {
      for (const path of ['SECURITY.md', 'SECURITY.rst', 'SECURITY.adoc']) {
        const ms = time(() => {
          const p = readPolicy(text, path);
          const r = howToReport(p, 'acme/widget');
          const s = readSupport(p);
          sameRepoLink(p, text, 'acme/widget', { report: true, versions: true });
          reportVerdict(p, r, null);
          supportVerdict(s, releaseLine(tags, 'widget'), path, null, 'widget');
          paragraphs(p);
          mentions(p, /report/);
          sections(p, /./);
        }, 250);
        if (ms > 250) slow.push(`${name} as ${path}: ${Math.round(ms)} ms`);
      }
    }
    expect(slow).toEqual([]);
  }, 300_000);

  it('runs every pattern the readers compile on 256 KB of text built to be slow in under 50 ms', () => {
    const size = 256 * 1024;
    const texts = [
      ...UNITS.map((u) => fill(u, size)),
      ...FRAMED.map(([before, unit, after]) => before + fill(unit, size) + after),
    ];
    expect(COMPILED.length).toBeGreaterThan(150);
    const slow: string[] = [];
    for (const { source, flags } of COMPILED) {
      const rx = re(source, flags, false);
      const g = new RegExp(rx.source, rx.flags + 'g');
      for (const text of texts) {
        const run = () => {
          g.lastIndex = 0;
          for (let m: RegExpExecArray | null; (m = g.exec(text));) if (m[0] === '') g.lastIndex++;
        };
        const ms = time(run, 50);
        if (ms > 50)
          slow.push(`${source.slice(0, 80)} on ${JSON.stringify(text.slice(0, 12))}...: ${Math.round(ms)} ms`);
      }
    }
    expect(slow).toEqual([]);
  }, 300_000);
});
