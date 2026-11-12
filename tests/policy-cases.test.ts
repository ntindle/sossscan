// Security policies as people write them. An independent audit tried the reader on 627 repositories it hadn't seen and
// on 135 policies it wrote to be hard; these tests run all 135 (tests/fixtures/scanner/policies/audit-cases.json, the
// auditor's text), the 78 of its second round (audit-cases-r2.json, and the four of over 256 KB built here), the 14
// of its third (audit-cases-r3.json), and a short policy in the manner of each real repository it found the reader
// got wrong.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeReplace, decodeText } from '../lib/scanner/http.ts';
import { howToReport, readPolicy, reportVerdict, sameRepoLink, sameRepoLinkFor } from '../lib/scanner/policy.ts';
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

type Case2 = Case & { files?: Record<string, string | number> };
/** The second round's four policies of over 256 KB: a long changelog table, or a long comment, before the policy. */
function bigCases(): Case2[] {
  const rows = Array.from(
    { length: 4000 },
    (_, i) => `| ${i}.0.${i % 10} | Fixed a rendering bug in the ${i}th widget variant and improved its docs. |`,
  ).join('\n');
  const head = '# Security Policy\n\n## Changelog of security fixes\n\n| Version | Change |\n| --- | --- |\n';
  const reporting =
    '# Security Policy\n\n## Reporting a Vulnerability\n\nEmail security@acme-widgets.org with details.\n\n';
  return [
    {
      id: 'T01 address-past-256kb',
      disc: 'info|pass',
      text: `${head}${rows}\n\n\n## Reporting a Vulnerability\n\nEmail security@acme-widgets.org.\n`,
    },
    {
      id: 'T02 table-past-256kb',
      rel: 'info|pass',
      tags: ['v3.1.0'],
      text: `${head}${rows}\n\n\n## Supported Versions\n\n| Version | Supported |\n| ------- | --------- |\n| 3.x | :white_check_mark: |\n`,
    },
    { id: 'T03 comment-past-256kb', disc: 'info|pass', text: `<!--\n${'old notes '.repeat(30000)}\n-->\n${reporting}` },
    { id: 'T04 address-first-then-filler', disc: 'pass', text: `${reporting}${rows}\n` },
  ];
}
const fixture = (name: string) =>
  JSON.parse(readFileSync(new URL(`./fixtures/scanner/policies/${name}`, import.meta.url), 'utf8'));
const cases2: Case2[] = [...fixture('audit-cases-r2.json'), ...bigCases(), ...fixture('audit-cases-r3.json')];

describe("the audit's second and third rounds of policies", () => {
  it.each(cases2.map((c) => [c.id, c] as const))('%s', (_, c) => {
    const path = c.path ?? 'SECURITY.md';
    // Bytes are read as a policy is (decodeText: UTF-16, or Windows-1252 when it isn't UTF-8).
    const text = c.b64 ? decodeText(new Uint8Array(Buffer.from(c.b64, 'base64'))) : c.text!;
    const p = readPolicy(text, path);
    const r = howToReport(p, 'acme/widget', 'acme/widget');
    const s = readSupport(p, NOW);
    // The one file the policy leads to, from the case's files: its text, or the HTTP status it gives. As in the
    // scan, a file it leads to for the supported versions says nothing about how to report.
    const link = sameRepoLinkFor(p, text, 'acme/widget', { report: !r.channels.length, versions: !s.section });
    const next = link?.path;
    const file = next && c.files ? c.files[next] : undefined;
    const fp = typeof file === 'string' ? readPolicy(file, next!) : null;
    const followed =
      next && c.files
        ? fp
          ? { path: next, policy: fp, reporting: howToReport(fp, 'acme/widget') }
          : { path: next, status: typeof file === 'number' ? file : 404 }
        : null;
    if (c.disc) expect(c.disc.split('|')).toContain(reportVerdict(p, r, link?.report ? followed : null).status);
    if (c.rel && c.tags) {
      const there = fp ? readSupport(fp, NOW) : null;
      const rel = supportVerdict(
        !s.section && there?.section ? there : s,
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

describe("the audit's third round: what the reader got wrong", () => {
  it('never reads a git login, or an address in an ssh or git command, as an inbox', () => {
    for (const text of [
      'If port 22 is blocked, clone with `ssh -p 443 git@ssh.github.com`.',
      'Our mirror is at git@codeberg.org:acme/widget.git',
      'Patches: git@git.sr.ht:~acme/widget',
      'Clone: git@git.acme-widgets.org:acme/widget.git',
      'Deploy with ssh -i deploy.pem admin@build.acme-widgets.org and scp files to ops@acme-widgets.org:/srv.',
      'Run git clone deploy@acme-widgets.org:widget.git first.',
    ]) {
      const p = readPolicy(`## Reporting a Vulnerability\n\nDo not open public issues. ${text}`, 'SECURITY.md');
      expect([text, p.emails, verdict(p.text).kinds]).toEqual([text, [], []]);
    }
    // A real address is still one, in the same sentence as a login or after an ssh command that failed.
    expect(readPolicy('Email security@acme-widgets.org, not git@codeberg.org.', 'SECURITY.md').emails).toEqual([
      'security@acme-widgets.org',
    ]);
    expect(readPolicy('If ssh fails, email ops@acme-widgets.org.', 'SECURITY.md').emails).toEqual([
      'ops@acme-widgets.org',
    ]);
    // git@ is an inbox when the policy asks to mail it, as abiosoft/colima's does ("send an email to git[@]abiosoft.com").
    for (const text of [
      'Instead, please send an email to git[@]abiosoft.com.',
      'Please send an email to git@abiosoft.com.',
    ]) {
      expect([text, readPolicy(text, 'SECURITY.md').emails]).toEqual([text, ['git@abiosoft.com']]);
    }
  });

  it('follows a link for how to report only when it is about security, and never reports from a link for the versions (navikt/cplt)', () => {
    // cplt links its known impacts (#...-depends-on-the-agent-version) before a security page.
    const cplt = readPolicy(
      '# Security\n\nSee [Linux keyring access](docs/known-impacts.md#keyring-access-depends-on-the-agent-version), and the [gh guard security boundaries](docs/gh-guard.md#security-boundaries).',
      'SECURITY.md',
    );
    expect(sameRepoLinkFor(cplt, '', REPO, { report: true, versions: true })).toEqual({
      path: 'docs/gh-guard.md',
      report: true,
    });
    // One version, or "lifecycle" alone, isn't about which versions get fixes; "supported versions" is, and that link
    // is followed for the versions only.
    const notes = readPolicy(
      '# Security\n\nEmail security@acme-widgets.org. See [notes](docs/notes.md#pin-the-agent-version) and [hooks](docs/notes.md#lifecycle-scripts).',
      'SECURITY.md',
    );
    expect(sameRepoLinkFor(notes, '', REPO, { report: false, versions: true })).toBeNull();
    const versions = readPolicy('# Security\n\nSee [supported versions](docs/versions.md).', 'SECURITY.md');
    expect(sameRepoLinkFor(versions, '', REPO, { report: true, versions: true })).toEqual({
      path: 'docs/versions.md',
      report: false,
    });
  });

  it('reads a lifecycle heading as the supported versions only when it is the lifecycle of versions or support', () => {
    // A table that isn't one of versions, as cplt's lifecycle scripts have, so only the heading can make it one.
    const table = '\n\n| Operation | Impact |\n| --- | --- |\n| `npm install` | ✅ Works |\n';
    for (const [heading, section] of [
      ['## Lifecycle scripts (postinstall hooks)', false],
      ['## Lifecycle', false],
      ['## Support lifecycle', true],
      ['## Release lifecycle', true],
      ['## Version lifecycle', true],
      ['## Lifecycle policy', true],
    ] as const) {
      const s = readSupport(readPolicy(`# Notes\n\n${heading}${table}`, 'SECURITY.md'), NOW);
      expect([heading, !!s.section]).toEqual([heading, section]);
    }
  });
});

describe("the audit's second round: what the reader got wrong", () => {
  it('gives info, not a warning, when it found nothing in the first 256 KB of a longer policy (j-256/guildcontrol)', () => {
    const v = verdict(
      '# Security\n\n' + 'Our release notes. '.repeat(20000) + '\n\n## Reporting\n\nEmail security@octo.org.',
    );
    expect([v.status, v.says]).toEqual([
      'info',
      ', but the scan read only the first 256 KB of it and found no private way to report there: check the rest says how',
    ]);
  });

  it('hides a script or style only as an HTML block, as GitHub does, not as a tag in a sentence', () => {
    const report = '\n\n## Reporting a Vulnerability\n\nEmail security@octo-project.org.';
    expect(verdict('We strip <script> tags from user input.' + report).kinds).toEqual(['email']);
    expect(verdict('The UI never injects <style> elements.' + report).kinds).toEqual(['email']);
    // A block that starts a line and closes is hidden, the address in it too; one that never closes is text.
    expect(verdict('<script>\nvar a = "admin@octo-project.org";\n</script>\n\nSee the docs.').kinds).toEqual([]);
    expect(verdict('<style>\n.x { color: red }' + report).kinds).toEqual(['email']);
  });

  it('reads "N/A" and "and/or" as words, not as links to files', () => {
    for (const text of ['N/A', 'and/or']) {
      const p = readPolicy(text, 'SECURITY.md');
      expect([text, p.symlink, verdict(text).status]).toEqual([text, null, 'warn']);
      expect(sameRepoLink(p, text, REPO, { report: true, versions: true })).toBeNull();
    }
    // A path to a policy is still a symlink, with an extension or a policy's name, or one that starts with ./ or ../.
    for (const [text, path] of [
      ['docs/SECURITY.md', 'docs/SECURITY.md'],
      ['../SECURITY', '../SECURITY'],
      ['.github/security', '.github/security'],
      ['./policies/report', './policies/report'],
    ]) {
      expect(readPolicy(text, 'docs/SECURITY.md').symlink).toBe(path);
    }
  });

  it('follows a link to the part of a file about reporting (CONTRIBUTING.md#reporting-security-issues)', () => {
    const p = readPolicy('# Security\n\nSee [CONTRIBUTING](CONTRIBUTING.md#reporting-security-issues).', 'SECURITY.md');
    expect(sameRepoLink(p, '', REPO, { report: true, versions: false })).toBe('CONTRIBUTING.md');
  });

  it("doesn't follow a link to a privacy policy, terms or a code of conduct", () => {
    for (const name of ['Privacy Policy', 'Cookie Policy', 'Terms of Service and Policy', 'Code of Conduct policy']) {
      const p = readPolicy(`# Security\n\nWe take security seriously. Read our [${name}](POLICY.md).`, 'SECURITY.md');
      expect([name, sameRepoLink(p, '', REPO, { report: true, versions: false })]).toEqual([name, null]);
    }
    const p = readPolicy('# Security\n\nRead our [policy](docs/POLICY.md).', 'SECURITY.md');
    expect(sameRepoLink(p, '', REPO, { report: true, versions: false })).toBe('docs/POLICY.md');
  });

  it("doesn't take a platform the policy left, or says it doesn't use, for a way to report", () => {
    const issue = ' Please open a GitHub issue.';
    for (const s of [
      "HackerOne isn't used for this project;",
      'We left HackerOne in 2023.',
      'No HackerOne program exists for this project.',
      'HackerOne: not applicable.',
      'Reports through HackerOne are no longer accepted.',
      'Formerly on Bugcrowd; now',
      "Tidelift's security contact is not monitored for this project.",
      'We used to run a bug bounty on HackerOne.',
    ]) {
      const v = verdict(`## Reporting a Vulnerability\n\n${s}${issue}`);
      expect([s, v.kinds, v.status]).toEqual([s, [], 'warn']);
    }
    // A platform the policy uses is still one, and "if you get no reply" isn't about it.
    for (const s of [
      'Report it through HackerOne.',
      'If you get no reply in a week, use HackerOne.',
      'We moved to HackerOne in 2023: report there.',
    ]) {
      expect([s, verdict(`## Reporting a Vulnerability\n\n${s}`).kinds]).toEqual([s, ['platform']]);
    }
  });

  it("doesn't read a URL's path as an address, or a team at a website as one (BackendStack21/odek)", () => {
    const odek =
      '## Reporting\n\nThe certificate identity is exactly `https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/<tag>`, which ' +
      'the verifier checks before it reports success.';
    expect(verdict(odek).kinds).toEqual([]);
    const team = verdict(
      '## Reporting a Vulnerability\n\nFor security issues, open a GitHub issue. For anything else, contact the team at github.com.',
    );
    expect([team.kinds, team.status, team.says]).toEqual([
      [],
      'warn',
      ' but it only says to report in public issues, not privately',
    ]);
    // An inbox's name at a domain still is one: "email security at octo-project.org".
    expect(readPolicy('Email security at octo-project.org with the details.', 'SECURITY.md').emails).toEqual([
      'security@octo-project.org',
    ]);
  });

  it("doesn't read an open issue, or an issue tracker it says not to use, as public issues (navikt/cplt)", () => {
    const cplt = verdict(
      '## Reporting a Vulnerability\n\nDo not open a public issue: email security@octo-project.org.\n\n## Notes\n\n' +
        'It is a documented residual: [#366](https://github.com/octo/tiny/issues/366) closed, and no open issue tracks changing it.',
    );
    expect([cplt.status, cplt.r.publicIssues]).toEqual(['pass', false]);
    const open = verdict('## Notes\n\nNo open issue tracks this, and an open issue about the cache is fine.');
    expect(open.r.publicIssues).toBe(false);
    const tracker = verdict(
      '## Reporting a Vulnerability\n\nPlease do not report security bugs in our [public issue tracker](https://github.com/octo/tiny/issues). Instead, contact the maintainers privately.',
    );
    expect([tracker.status, tracker.says]).toEqual([
      'warn',
      ' but it asks for reports by email or message without giving an address',
    ]);
    // A link to the issues in a sentence that asks for them still is public issues.
    expect(
      verdict('## Reporting\n\nPlease report it in our [issue tracker](https://github.com/octo/tiny/issues).').r
        .publicIssues,
    ).toBe(true);
  });

  it('reads the language of each sentence: English and Chinese in one paragraph or on two lines', () => {
    const zh = '请通过 GitHub Security Advisory 私下报告漏洞，我们会尽快回复。';
    for (const sep of [' ', '\n']) {
      const v = verdict(
        `# Security Policy\n\n## Reporting a Vulnerability\n\nPlease do not open public issues for vulnerabilities.${sep}${zh}`,
      );
      expect([JSON.stringify(sep), v.status, v.kinds]).toEqual([JSON.stringify(sep), 'pass', ['github']]);
    }
  });

  it('reads terse English as English, without its common words', () => {
    const p = readPolicy(
      '# Security\n\n## Reporting\n\nVulnerability reports: GitHub issues. Response time: best effort. Scope: core library, CLI tools, Docker images, Helm charts, documentation site.\n',
      'SECURITY.md',
    );
    expect(p.english).toBe(true);
    // A policy in another language still isn't read as English, the words it borrows from English too (Ahmetshbzz).
    const tr = readPolicy(
      "# Güvenlik\n\n## Güvenlik açığı bildirimi\n\nLütfen herkese açık issue açma. GitHub Security Advisories üzerinden özel olarak bildir; o mümkün değilse maintainer'a özel kanaldan ulaş. Bildirimde etkilenen versiyon, commit ve fix önerisi olsun.",
      'SECURITY.md',
    );
    expect([tr.english, verdict(tr.text).status]).toEqual([false, 'pass']);
    expect(
      readPolicy(
        '# Sicherheit\n\nBitte melden Sie Sicherheitslücken nicht öffentlich, sondern per E-Mail an das Team. Wir antworten innerhalb von drei Tagen und veröffentlichen dann eine Korrektur.',
        'SECURITY.md',
      ).english,
    ).toBe(false);
  });

  it('reads a policy saved in a Windows code page (a curly apostrophe as one byte)', () => {
    const bytes = new Uint8Array([
      ...Buffer.from('## Reporting a Vulnerability\n\nPlease don', 'latin1'),
      0x92,
      ...Buffer.from('t open a public issue. Report it privately to the maintainers.', 'latin1'),
    ]);
    const text = decodeText(bytes);
    expect(text).toContain('don’t open');
    expect(verdict(text).says).toBe(' but it asks for reports by email or message without giving an address');
    // UTF-8 stays UTF-8, a bad byte or two included.
    expect(decodeText(new Uint8Array([...Buffer.from('日本 ', 'utf8'), 0xff]))).toBe('日本 \uFFFD');
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

  it('reads "for example" before a table as an example only where a sentence introduces one', () => {
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
    // "for example 2.4" gives an example of a number: the table after it is the real one, and out of date.
    const stale = [
      '## Supported Versions',
      '',
      'Patches go to the latest minor, for example 2.4 when 2.4 is the newest.',
      '',
      '| Version | Supported |',
      '| --- | --- |',
      '| 1.x | :white_check_mark: |',
      '| < 1.0 | :x: |',
    ].join('\n');
    expect(versions(stale, ['v2.4.0'])).toMatchObject({ status: 'warn' });
  });

  it('reads an end of life not set yet as supported, and one months away as unknown', () => {
    for (const cell of [
      'No EOL planned',
      'Not yet EOL',
      'EOL not announced',
      'No end-of-life date yet',
      'Supported, no EOL planned',
    ]) {
      expect([cell, statusOf(cell, NOW)]).toEqual([cell, 'yes']);
    }
    for (const cell of ['EOL in 6 months', 'End of life in a few weeks'])
      expect([cell, statusOf(cell, NOW)]).toEqual([cell, 'unknown']);
    for (const cell of ['EOL', 'No', 'EOL 2020-01-01', '❌ No EOL planned'])
      expect([cell, statusOf(cell, NOW)]).toEqual([cell, 'no']);
  });

  it('compares with the main version scheme, not a Helm chart, and not a dated snapshot (LibreChat, PaynEat)', () => {
    const line = (tags: string[], name: string) =>
      releaseLine(
        tags.map((tag) => ({ tag })),
        name,
      ).target?.tag ?? null;
    // Two schemes that both look like the main one: tags that changed in one project (the same major version) give
    // the highest; two products (another major) give the one with more releases.
    expect(line(['v0.8.9-rc1', 'v0.8.8', 'v0.8.7', 'librechat-1.8.9', 'chart-3.0.0'], 'LibreChat')).toBe('v0.8.8');
    expect(line(['v3.3.0-alpha.1', 'keplergl==0.4.0', 'v3.2.6', 'v3.2.5'], 'kepler.gl')).toBe('v3.2.6');
    expect(line(['grub-2.16', 'grub-2.14', '2.02', 'grub-2.12', '2.00'], 'grub')).toBe('grub-2.16');
    expect(line(['3.3.7', 'dubbo-3.2.20', 'dubbo-3.3.6'], 'dubbo')).toBe('3.3.7');
    expect(line(['community-baseline-2026-10', 'demo'], 'PaynEat')).toBeNull();
    expect(line(['pga-2026-11-09', 'pga-2026-10-01'], 'pga-versions')).toBeNull();
    // A package of the repository's name on its own, or another single package, is still the line.
    expect(line(['dio_v5.11.1', 'dio_v5.11.0'], 'dio')).toBe('dio_v5.11.1');
    expect(line(['core@13.4.0', 'core@13.3.0'], 'insomnia')).toBe('core@13.4.0');
  });
});
