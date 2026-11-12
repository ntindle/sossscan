// Supported-versions tables as people write them: cells with words for both yes and no, columns of end dates beside a
// security column, and tables given as an example. Cases an independent audit found the reader got wrong.
import { describe, expect, it } from 'vitest';
import { readPolicy } from '../lib/scanner/policy.ts';
import { readSupport, releaseLine, statusOf, supportVerdict } from '../lib/scanner/versions.ts';

/** The day the audit's dates were written against: "EOL 2028" is to come, "31 Dec 2025" is past. */
const NOW = new Date('2026-11-11T00:00:00Z');

/** rel-security-support's verdict on a policy's table against releases with these tags. */
function versions(text: string, tags: string[], path = 'SECURITY.md') {
  const s = readSupport(readPolicy(text, path), NOW);
  return supportVerdict(
    s,
    releaseLine(
      tags.map((tag) => ({ tag })),
      'tiny',
    ),
    path,
    null,
    'tiny',
  );
}

describe('supported-versions tables as they are written', () => {
  it('reads a cell with words for both yes and no by its date, or as unknown', () => {
    const cases: [string, string][] = [
      ['Current, EOL 2028', 'yes'],
      ['Current (EOL 2020)', 'no'],
      ['Supported until end of life in 2028', 'yes'],
      ['Supported (no longer in beta)', 'yes'],
      ['❌ security fixes only', 'unknown'],
      ['❌ (no new releases, critical fixes may still be backported)', 'no'],
      ['Active LTS (EOL 2027-04-30)', 'yes'],
      ['EOL 2028', 'yes'],
      ['EOL', 'no'],
      ['superseded soon', 'unknown'],
      ['Not normally supported', 'no'],
      ['Not actively supported', 'no'],
      ['Not yet supported', 'no'],
    ];
    for (const [cell, want] of cases) expect([cell, statusOf(cell, NOW)]).toEqual([cell, want]);
  });

  it("lets a security column decide over another column's end date (PHP-style tables)", () => {
    const table =
      '## Supported Versions\n\n| Version | Active support until | Security support until |\n| --- | --- | --- |\n| 8.3 | 31 Dec 2025 | 31 Dec 2027 |\n| 8.2 | 31 Dec 2024 | 31 Dec 2026 |\n';
    expect(versions(table, ['v8.3.4']).status).toBe('pass');
  });

  it('reads "for example" anywhere in the section before a table as an example', () => {
    const text = [
      '## Supported Versions',
      '',
      'We support the latest minor release and the one before it. For example, when the latest is 2.0:',
      '',
      '- 2.0 gets every fix',
      '- 1.9 gets security fixes',
      '- older lines get none',
      '',
      'In table form:',
      '',
      '| Version | Supported |',
      '| --- | --- |',
      '| 2.0 | ✅ |',
      '| 1.9 | ✅ |',
    ].join('\n');
    expect(versions(text, ['v5.0.0'])).toMatchObject({ status: 'info' });
  });
});
