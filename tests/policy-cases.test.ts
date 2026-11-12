// Security policies as people write them. An independent audit tried the reader on 627 repositories it hadn't seen and
// on 135 policies it wrote to be hard; these tests run all 135 (tests/fixtures/scanner/policies/audit-cases.json, the
// auditor's text), and a short policy in the manner of each real repository it found the reader got wrong.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeReplace } from '../lib/scanner/http.ts';
import { howToReport, readPolicy, reportVerdict, sameRepoLink } from '../lib/scanner/policy.ts';
import { readSupport, releaseLine, statusOf, supportVerdict } from '../lib/scanner/versions.ts';

const REPO = 'octo/tiny';
/** The day the audit's dates were written against: "EOL 2028" is to come, "31 Dec 2025" is past. */
const NOW = new Date('2026-11-11T00:00:00Z');

/** disc-security-md's verdict on a policy read on its own (no other file followed). */
function verdict(text: string, path = 'SECURITY.md', repo = REPO) {
  const p = readPolicy(text, path);
  const r = howToReport(p, repo);
  const v = reportVerdict(p, r, null);
  return { status: v.status, says: v.says, kinds: r.channels.map((c) => c.kind), r };
}

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

type Case = { id: string; path?: string; text?: string; b64?: string; tags?: string[]; disc?: string; rel?: string };
const cases: Case[] = JSON.parse(
  readFileSync(new URL('./fixtures/scanner/policies/audit-cases.json', import.meta.url), 'utf8'),
);

describe("the audit's 135 policies", () => {
  it.each(cases.map((c) => [c.id, c] as const))('%s', (_, c) => {
    const path = c.path ?? 'SECURITY.md';
    // Bytes are read as the scan's plain text reads them (UTF-8); the reader recovers a UTF-16 one.
    const text = c.b64 ? decodeReplace(Buffer.from(c.b64, 'base64')) : c.text!;
    const p = readPolicy(text, path);
    if (c.disc) expect(c.disc.split('|')).toContain(reportVerdict(p, howToReport(p, 'acme/widget'), null).status);
    if (c.rel && c.tags) {
      const rel = supportVerdict(
        readSupport(p, NOW),
        releaseLine(
          c.tags.map((tag) => ({ tag })),
          'widget',
        ),
        path,
        null,
        'widget',
      );
      expect(c.rel.split('|')).toContain(rel.status);
    }
  });
});

describe('policies like the real ones the audit found misread', () => {
  it('reads an address split across lines, and a pull request about the policy as not a way to report (erlyaws/yaws)', () => {
    const v = verdict(
      [
        '## Reporting a Vulnerability',
        '',
        'To report a vulnerability, please do not create a public issue. Instead,',
        'email the lead developer __ann [at] octo-project',
        "[dot] org__ and you'll get an answer within 48 hours.",
        '',
        '## Comments on this Policy',
        '',
        'If you have suggestions on how this process could be improved please',
        'submit a pull request.',
      ].join('\n'),
    );
    expect([v.status, v.says]).toEqual(['pass', '; it says to report by email (ann@octo-project.org)']);
  });

  it("reads GitHub's reporting however it's phrased (Netflix, QuipNetwork, claude-warden)", () => {
    const github = "; it says to report through GitHub's private vulnerability reporting";
    expect(verdict('Please report vulnerabilities through GitHub private security reporting.').says).toBe(github);
    expect(
      verdict(
        'Report a vulnerability privately through GitHub:\n\n1. Open the repository.\n2. Select **Security**, then **Report a vulnerability**.\n',
      ).says,
    ).toBe(github);
    expect(verdict('1. Prefer filing a **GitHub Security Advisory** (private disclosure).').says).toBe(github);
    expect(
      verdict('Use the [GitHub Security Advisory](https://github.com/octo/tiny/security/advisories) feature.').says,
    ).toBe(github);
  });

  it('reads the language of each part, leaving out headings, tables and code (ASIA-BOT, jsencrypt)', () => {
    const thai = [
      '# Security Policy',
      '',
      '| Version | Supported |',
      '| --- | --- |',
      '| main | ✅ |',
      '',
      '## Reporting a Vulnerability',
      '',
      'หากพบช่องโหว่ กรุณาแจ้งผู้ดูแลผ่าน GitHub Security Advisory',
      '',
      '## Scope',
      '',
      'The admin panel, the API and the bot are in scope for this policy.',
    ].join('\n');
    expect(verdict(thai).kinds).toEqual(['github']);
    // An English page that is mostly code is English: it gets the warn, not "isn't in English".
    const code = ['# Security Best Practices', '', 'Use keys of 2048 bits or more.', '', '```js'];
    for (let k = 0; k < 40; k++) code.push(`const key${k} = new JSEncrypt({ default_key_size: 2048 }).getKey();`);
    code.push('```', '', 'Rotate your keys when someone leaves the team, and store them in a vault.');
    expect(verdict(code.join('\n'), 'docs/security.md')).toMatchObject({
      status: 'warn',
      says: ' but it does not say how to report privately',
    });
  });

  it('reads a chat handle and a request to use it in different paragraphs (better-vest)', () => {
    const v = verdict(
      '## Who makes it\n\nMe, Ann (Discord **@ann-dev**).\n\nIf you find something that looks wrong, tell me on Discord.\n',
    );
    expect([v.status, v.says]).toEqual(['pass', '; it says to report by private message']);
  });

  it("gives the right reason: a table cell isn't a request for email, and don’t is don't (capkz, FractalShark)", () => {
    const design =
      '| Boundary | Protection |\n| --- | --- |\n| Sign-in | Email + master password, passed only in memory |\n';
    expect(verdict(design).says).toBe(' but it does not say how to report privately');
    expect(
      verdict(
        'If you find a security issue, please report it privately to the repository owner.\n\nPlease don’t open a public issue until it’s fixed.',
      ).says,
    ).toBe(' but it asks for reports by email or message without giving an address');
  });

  it("reads an address right after a colon, but not a URL's user (SilFopma4h2/weer)", () => {
    expect(verdict('Verstuur bij voorkeur een e-mail naar:security@octo-project.org').kinds).toEqual(['email']);
    expect(readPolicy('Clone https://ann:token@octo-project.org/tiny.git', 'SECURITY.md').emails).toEqual([]);
  });

  it("doesn't take a Telegram channel, a public list or an address for questions as private (skycoin, openai)", () => {
    expect(
      verdict(
        'Reach the maintainers on our technical channel [@tinychat](https://t.me/tinychat), or open an issue at <https://github.com/octo/tiny/issues>.',
      ).says,
    ).toBe(' but it only says to report in public issues, not privately');
    expect(verdict('Message me on Telegram: [@ann](https://t.me/annsmith)').says).toBe(
      '; it says to report by private message (https://t.me/annsmith)',
    );
    const openai = verdict(
      'Please report vulnerabilities privately through [our disclosure policy](https://octo-project.org/policies/disclosure). For questions about that process, contact disclosure@octo-project.org.',
    );
    expect(openai.says).toBe('; it points to https://octo-project.org/policies/disclosure for how to report');
  });

  it("follows only links about reports, and doesn't count a list of links in a file about something else (sakala-api)", () => {
    const text =
      'Laporkan kerentanan secara pribadi kepada pengelola. Lihat juga [Kebijakan Retensi Log](docs/LOG_RETENTION.md) untuk data yang disimpan.';
    const p = readPolicy(text, 'SECURITY.md');
    expect(sameRepoLink(p, text, REPO, { report: true, versions: false })).toBeNull();
    expect(verdict(text).status).toBe('info');
    // A short pointer to "the full policy" is still followed.
    const short = 'Our full policy: [here](docs/policy.md)';
    expect(sameRepoLink(readPolicy(short, 'SECURITY.md'), short, REPO, { report: true, versions: false })).toBe(
      'docs/policy.md',
    );
  });

  it("ignores an address in a versions table, and knows GitHub's template in Indonesian (KodeQr)", () => {
    const v = verdict(
      [
        '# Kebijakan keamanan',
        '',
        '| Version | Supported | Owner |',
        '| ------- | --------- | ----- |',
        '| 5.1.x | :white_check_mark: | ann@octo-project.org |',
        '',
        '## Melaporkan Kerentanan',
        '',
        'Gunakan bagian ini untuk memberi tahu orang cara melaporkan kerentanan.',
      ].join('\n'),
    );
    expect([v.status, v.says]).toEqual([
      'warn',
      " but it still has GitHub's template text where it should say how to report",
    ]);
  });

  it("names the other repository a link to GitHub's form is in (V2Ray-Checker, anvomidav)", () => {
    expect(verdict('Report it [here](https://github.com/ann/other-tool/security/advisories/new).').says).toBe(
      "; it says to report through GitHub's private vulnerability reporting for ann/other-tool",
    );
    expect(verdict('Report it [here](https://github.com/octo/tiny/security/advisories/new).').says).toBe(
      "; it says to report through GitHub's private vulnerability reporting",
    );
  });

  it("doesn't take the maintainers' own steps or published advisories for GitHub reporting (allstar, docker, openhab, datahub, dart-lang)", () => {
    const email = (addr: string) => `; it says to report by email (${addr})`;
    expect(
      verdict(
        'To report a security issue, please email\n[oss@octo-project.org](mailto:oss@octo-project.org).\nIf the issue is confirmed, we will open a\nSecurity Advisory and credit you.',
      ).says,
    ).toBe(email('oss@octo-project.org'));
    expect(
      verdict(
        'Send your report privately to security@octo-project.org. Once confirmed, a draft security advisory will be created on GitHub.',
      ).says,
    ).toBe(email('security@octo-project.org'));
    expect(
      verdict(
        'Write to security@octo-project.org. If the report is accepted, the security response team will draft an advisory on GitHub.',
      ).says,
    ).toBe(email('security@octo-project.org'));
    expect(
      verdict(
        'Send a report to security@octo-project.org. We maintain [Security Advisories](https://github.com/octo/tiny/security/advisories) on GitHub.',
      ).says,
    ).toBe(email('security@octo-project.org'));
    expect(
      verdict(
        '## Reporting vulnerabilities\nTo report one, see [https://octo-project.org/security](https://octo-project.org/security).\n\n## Published security advisories\nSee [security advisories](https://github.com/octo/tiny/security/advisories?state=published).',
      ).says,
    ).toBe('; it points to https://octo-project.org/security for how to report');
    // Advisories published in German are the maintainers' too.
    expect(
      verdict('Bitte melde es an security@octo-project.org. Das Team veröffentlicht danach ein Security Advisory.')
        .kinds,
    ).toEqual(['email']);
  });

  it("doesn't take a private report, a security page or a negated platform for a way to report (Lidprex, eclipse-vertx, rubyforgood)", () => {
    expect(verdict('Send a private report to the maintainers.').status).toBe('warn');
    expect(verdict('See the security page on our website for how to report vulnerabilities.').status).toBe('info');
    expect(verdict('We do not have any bug bounty program. Please open an issue.').status).toBe('warn');
    expect(verdict('Our HackerOne program is closed. Please open a public issue.').status).toBe('warn');
    // A platform named after a generic program counts.
    expect(verdict('Submit it through our bug bounty program on HackerOne.').says).toBe(
      '; it says to report through HackerOne',
    );
  });

  it("decodes a mailto: link's address, and keeps the main address before one to escalate to (python, edex-ui, NativeScript)", () => {
    expect(
      readPolicy(
        'To reach us, email <a href="mailto:%73%65%63%75%72%69%74%79%40%6F%63%74%6F%2D%70%72%6F%6A%65%63%74%2E%6F%72%67">security\nat octo-project dot org</a>.',
        'SECURITY.md',
      ).emails,
    ).toEqual(['security@octo-project.org']);
    expect(
      readPolicy(
        '[Email us](mailto:%22Ann%20Smith%22%20%3Cann%40octo-project.org%3E?subject=%5BSECURITY%5D)',
        'SECURITY.md',
      ).emails,
    ).toEqual(['ann@octo-project.org']);
    expect(readPolicy('[mail](mailto:ann@octo-project.org\\subject=Security)', 'SECURITY.md').emails).toEqual([
      'ann@octo-project.org',
    ]);
    expect(
      verdict(
        'Instead, please send an email to support[@]octo-project.org.\n\n## Escalation\n\nIf you get no answer within 6 days, escalate to `cna@octo-foundation.org`.',
      ).says,
    ).toBe('; it says to report by email (support@octo-project.org)');
    // An address only for permission to test comes after the platform.
    expect(
      verdict(
        'Report security bugs via [HackerOne](https://hackerone.com/octo). Contact tsc@octo-project.org for permission to test.',
      ).says,
    ).toBe('; it says to report through HackerOne');
  });

  it("calls an XMPP address a private message, and doesn't count a chat room's (movim)", () => {
    const v = verdict(
      'Join our XMPP chatroom at `tiny@conference.octo-project.org`. For a direct threat, send a XMPP message to `ann` at `octo-project.org`.',
    );
    expect([v.status, v.says]).toEqual(['pass', '; it says to report by private message (ann@octo-project.org)']);
  });

  it('gives a placeholder, a spelled-out phrase and a security file without a link to one as no address (atrocore, csoh.org)', () => {
    expect(readPolicy('Email security@OUR-COMPANY-NAME.com with the details.', 'SECURITY.md').emails).toEqual([]);
    expect(
      readPolicy('Issues are triaged at the org level, by the security team at github.com.', 'SECURITY.md').emails,
    ).toEqual([]);
    // A <!-- in code doesn't hide the rest of the policy.
    expect(
      verdict('Our sanitizer strips `<!--` comment openers.\n\n## Disclosure\n\n- **Email:** admin@octo-project.org')
        .kinds,
    ).toEqual(['email']);
  });
});

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
